//! High-level WASM Source engine (mirrors idr.h ABI ops).
//!
//! All exported methods take `&self` (not `&mut self`). wasm-bindgen holds
//! `&mut self` across `.await` points, which re-enters when JS host callbacks
//! call `pushPeerEvent` / `pushSignalingMessage` during connect.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{Arc, Mutex as StdMutex};

use idr_core::error::{IdrError, IdrErrorKind, Result as IdrResult};
use idr_core::session::PeerSession;
use idr_core::stream::LogicalStream;
use idr_protocol::discovery::parse_discovery_document;
use idr_protocol::webrtc_signaling::SourceAuthMode;
use idr_signaling::place_wss_servers;
use idr_signaling::SignalingMessage;
use idr_source::{SourceRuntime, SourceSession};
use idr_webrtc::transport::PeerEvent;
use js_sys::Function;
use tokio::sync::mpsc;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::host::peer::{parse_peer_event, JsPeerHost, JsPeerTransport};
use crate::host::signaling::{parse_signaling_message, JsSignalingClient, JsSignalingHost};

#[cfg(target_arch = "wasm32")]
use wasmtimer::tokio::timeout as async_timeout;
#[cfg(not(target_arch = "wasm32"))]
use tokio::time::timeout as async_timeout;

type PeerTxSlot = Arc<StdMutex<Option<mpsc::UnboundedSender<PeerEvent>>>>;
type SigInbox = Arc<StdMutex<Option<mpsc::UnboundedSender<SignalingMessage>>>>;

struct SessionSlot {
    session: SourceSession,
    streams: HashMap<u32, Box<dyn LogicalStream>>,
    next_stream: u32,
}

/// Browser Source engine — Rust owns connect/mux; JS hosts WebRTC + WSS.
#[wasm_bindgen]
pub struct WasmEngine {
    source_id: String,
    source_region: String,
    auth_token: String,
    discovery_url: String,
    peer_host: RefCell<Option<JsPeerHost>>,
    signaling_host: RefCell<Option<JsSignalingHost>>,
    fetch_discovery: RefCell<Option<Function>>,
    peer_tx: PeerTxSlot,
    signaling_inbox: RefCell<Option<SigInbox>>,
    session: Rc<RefCell<Option<SessionSlot>>>,
}

fn js_err(e: IdrError) -> JsValue {
    JsValue::from_str(&format!("{}: {}", e.kind.as_str(), e.message))
}

fn require_fn(obj: &JsValue, name: &str) -> Result<Function, JsValue> {
    let v = js_sys::Reflect::get(obj, &JsValue::from_str(name))?;
    v.dyn_into::<Function>()
        .map_err(|_| JsValue::from_str(&format!("host.{name} must be a function")))
}

#[wasm_bindgen]
impl WasmEngine {
    #[wasm_bindgen(constructor)]
    pub fn new(
        source_id: String,
        auth_token: String,
        discovery_url: String,
        source_region: Option<String>,
    ) -> WasmEngine {
        console_error_panic_hook::set_once();
        WasmEngine {
            source_id,
            source_region: source_region.unwrap_or_else(|| "browser".into()),
            auth_token,
            discovery_url,
            peer_host: RefCell::new(None),
            signaling_host: RefCell::new(None),
            fetch_discovery: RefCell::new(None),
            peer_tx: Arc::new(StdMutex::new(None)),
            signaling_inbox: RefCell::new(None),
            session: Rc::new(RefCell::new(None)),
        }
    }

    /// Register JS peer host: `{ start, createLocalDescription, setRemoteDescription,
    /// addRemoteCandidate, sendBinary, close }`.
    #[wasm_bindgen(js_name = setPeerHost)]
    pub fn set_peer_host(&self, host: JsValue) -> Result<(), JsValue> {
        *self.peer_host.borrow_mut() = Some(JsPeerHost {
            start: require_fn(&host, "start")?,
            create_local_description: require_fn(&host, "createLocalDescription")?,
            set_remote_description: require_fn(&host, "setRemoteDescription")?,
            add_remote_candidate: require_fn(&host, "addRemoteCandidate")?,
            set_ice_servers: require_fn(&host, "setIceServers")?,
            send_binary: require_fn(&host, "sendBinary")?,
            close: require_fn(&host, "close")?,
        });
        Ok(())
    }

    /// Register JS signaling host: `{ beginSession, sendJson, close }`.
    #[wasm_bindgen(js_name = setSignalingHost)]
    pub fn set_signaling_host(&self, host: JsValue) -> Result<(), JsValue> {
        let preconnect = js_sys::Reflect::get(&host, &JsValue::from_str("preconnect"))
            .ok()
            .and_then(|v| v.dyn_into::<Function>().ok());
        *self.signaling_host.borrow_mut() = Some(JsSignalingHost {
            preconnect,
            begin_session: require_fn(&host, "beginSession")?,
            send_json: require_fn(&host, "sendJson")?,
            close: require_fn(&host, "close")?,
        });
        Ok(())
    }

    /// Optional: `async (url: string) => discoveryJsonString`.
    #[wasm_bindgen(js_name = setFetchDiscovery)]
    pub fn set_fetch_discovery(&self, f: Function) {
        *self.fetch_discovery.borrow_mut() = Some(f);
    }

    /// JS → Rust: inject a peer event (`{ kind, ... }`).
    #[wasm_bindgen(js_name = pushPeerEvent)]
    pub fn push_peer_event(&self, event: JsValue) -> Result<(), JsValue> {
        let ev = parse_peer_event(&event).map_err(js_err)?;
        let guard = self
            .peer_tx
            .lock()
            .map_err(|_| JsValue::from_str("peer_tx lock poisoned"))?;
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(ev);
        }
        Ok(())
    }

    /// JS → Rust: inject a raw Presence WSS text frame.
    #[wasm_bindgen(js_name = pushSignalingMessage)]
    pub fn push_signaling_message(&self, raw: String) -> Result<(), JsValue> {
        let Some(msg) = parse_signaling_message(&raw).map_err(js_err)? else {
            return Ok(());
        };
        let Some(inbox) = self.signaling_inbox.borrow().clone() else {
            return Ok(());
        };
        let guard = inbox
            .lock()
            .map_err(|_| JsValue::from_str("signaling inbox lock poisoned"))?;
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(msg);
        }
        Ok(())
    }

    /// Connect to Target FQHN via placement + Presence WSS + WebRTC.
    pub async fn connect(&self, target_fqhn: String) -> Result<(), JsValue> {
        let peer_host = self
            .peer_host
            .borrow()
            .clone()
            .ok_or_else(|| JsValue::from_str("setPeerHost required"))?;
        let signaling_host = self
            .signaling_host
            .borrow()
            .clone()
            .ok_or_else(|| JsValue::from_str("setSignalingHost required"))?;
        let fetch = self
            .fetch_discovery
            .borrow()
            .clone()
            .ok_or_else(|| JsValue::from_str("setFetchDiscovery required"))?;

        let doc_json = {
            let p = fetch
                .call1(&JsValue::NULL, &JsValue::from_str(&self.discovery_url))
                .map_err(|e| JsValue::from_str(&format!("fetchDiscovery: {e:?}")))?;
            let v = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(p))
                .await
                .map_err(|e| JsValue::from_str(&format!("fetchDiscovery promise: {e:?}")))?;
            v.as_string()
                .ok_or_else(|| JsValue::from_str("fetchDiscovery must return a string"))?
        };

        let doc = parse_discovery_document(doc_json.as_bytes())
            .map_err(|e| JsValue::from_str(&format!("discovery json: {e}")))?;

        let servers = place_wss_servers(&doc, &target_fqhn).map_err(js_err)?;

        let mut last_err: Option<IdrError> = None;
        for server in servers {
            match self
                .try_connect_one(
                    &target_fqhn,
                    &server.wss_url,
                    peer_host.clone(),
                    signaling_host.clone(),
                )
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) => last_err = Some(e),
            }
        }
        Err(js_err(last_err.unwrap_or_else(|| {
            IdrError::new(IdrErrorKind::SignalingFailed, "no Presence server reachable")
        })))
    }

    async fn try_connect_one(
        &self,
        target_fqhn: &str,
        wss_url: &str,
        peer_host: JsPeerHost,
        signaling_host: JsSignalingHost,
    ) -> IdrResult<()> {
        if let Some(pre) = signaling_host.preconnect.as_ref() {
            let p = pre
                .call1(&JsValue::NULL, &JsValue::from_str(wss_url))
                .map_err(|e| {
                    IdrError::new(
                        IdrErrorKind::SignalingFailed,
                        format!("preconnect: {e:?}"),
                    )
                })?;
            if !p.is_undefined() && !p.is_null() {
                let _ = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(p))
                    .await
                    .map_err(|e| {
                        IdrError::new(
                            IdrErrorKind::SignalingFailed,
                            format!("preconnect promise: {e:?}"),
                        )
                    })?;
            }
        }

        let peer_tx_slot = self.peer_tx.clone();
        let signaling = JsSignalingClient::new(signaling_host, wss_url);
        *self.signaling_inbox.borrow_mut() = Some(signaling.inbox_slot());

        let peer_factory = {
            let peer_host = peer_host.clone();
            let peer_tx_slot = peer_tx_slot.clone();
            move || {
                let peer = JsPeerTransport::new(peer_host.clone());
                if let Ok(mut g) = peer_tx_slot.lock() {
                    *g = Some(peer.event_sender());
                }
                Box::new(peer) as Box<dyn idr_webrtc::PeerTransport>
            }
        };

        let mut runtime = SourceRuntime::with_auth(
            Box::new(signaling),
            peer_factory,
            self.source_id.clone(),
            self.source_region.clone(),
            SourceAuthMode::Bearer,
            Some(self.auth_token.clone()),
        );

        let session = runtime.connect(target_fqhn).await?;
        *self.session.borrow_mut() = Some(SessionSlot {
            session,
            streams: HashMap::new(),
            next_stream: 1,
        });
        Ok(())
    }

    /// JSON array of structured catalog entries.
    #[wasm_bindgen(js_name = listServicesJson)]
    pub async fn list_services_json(&self) -> Result<String, JsValue> {
        let mut slot = self
            .session
            .borrow_mut()
            .take()
            .ok_or_else(|| JsValue::from_str("not connected"))?;
        let already_have_catalog = !slot.session.catalog_entries().is_empty()
            || !slot.session.named_services().is_empty();
        if !already_have_catalog {
            if let Err(e) = slot.session.refresh_named_services().await {
                if slot.session.catalog_entries().is_empty()
                    && slot.session.named_services().is_empty()
                {
                    *self.session.borrow_mut() = Some(slot);
                    return Err(js_err(e));
                }
            }
        }
        let entries = if !slot.session.catalog_entries().is_empty() {
            slot.session.catalog_entries().to_vec()
        } else {
            slot.session
                .named_services()
                .iter()
                .map(|n| idr_protocol::stream_mux::ServiceCatalogEntry::name_only(n.clone()))
                .collect()
        };
        let json = serde_json::to_string(&entries).map_err(|e| JsValue::from_str(&e.to_string()))?;
        *self.session.borrow_mut() = Some(slot);
        Ok(json)
    }

    /// Open a named Target service; returns stream handle id.
    #[wasm_bindgen(js_name = openStream)]
    pub async fn open_stream(&self, service: String) -> Result<u32, JsValue> {
        let mut slot = self
            .session
            .borrow_mut()
            .take()
            .ok_or_else(|| JsValue::from_str("not connected"))?;
        let result = slot.session.open_named_stream(&service).await;
        match result {
            Ok(stream) => {
                let id = slot.next_stream;
                slot.next_stream += 1;
                slot.streams.insert(id, stream);
                *self.session.borrow_mut() = Some(slot);
                Ok(id)
            }
            Err(e) => {
                *self.session.borrow_mut() = Some(slot);
                Err(js_err(e))
            }
        }
    }

    /// Write bytes to a stream; returns bytes accepted.
    #[wasm_bindgen(js_name = streamWrite)]
    pub async fn stream_write(
        &self,
        stream_id: u32,
        data: js_sys::Uint8Array,
    ) -> Result<u32, JsValue> {
        let mut buf = vec![0u8; data.length() as usize];
        data.copy_to(&mut buf);
        let mut slot = self
            .session
            .borrow_mut()
            .take()
            .ok_or_else(|| JsValue::from_str("not connected"))?;
        let result = match slot.streams.get_mut(&stream_id) {
            Some(stream) => stream.write(&buf).await,
            None => {
                *self.session.borrow_mut() = Some(slot);
                return Err(JsValue::from_str("unknown stream"));
            }
        };
        *self.session.borrow_mut() = Some(slot);
        Ok(result.map_err(js_err)? as u32)
    }

    /// Read up to `max_len` bytes.
    /// Empty `Uint8Array` means no data yet (would-block) or EOF — callers must retry
    /// with a streak (same as Dart `IdrServiceHttpClient`), not treat one empty as done.
    #[wasm_bindgen(js_name = streamRead)]
    pub async fn stream_read(
        &self,
        stream_id: u32,
        max_len: u32,
    ) -> Result<js_sys::Uint8Array, JsValue> {
        let mut slot = self
            .session
            .borrow_mut()
            .take()
            .ok_or_else(|| JsValue::from_str("not connected"))?;

        if !slot.streams.contains_key(&stream_id) {
            *self.session.borrow_mut() = Some(slot);
            return Err(JsValue::from_str("unknown stream"));
        }

        let mut buf = vec![0u8; max_len.max(1) as usize];
        // Keep pumping while waiting — DC frames only reach stream inboxes via pump_once.
        // Match native FFI: many short pumps, not a deaf multi-second read.
        #[cfg(target_arch = "wasm32")]
        let deadline = wasmtimer::std::Instant::now() + std::time::Duration::from_secs(2);
        #[cfg(not(target_arch = "wasm32"))]
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);

        let n = loop {
            let _ = async_timeout(
                std::time::Duration::from_millis(25),
                slot.session.pump_once(),
            )
            .await;

            let stream = slot
                .streams
                .get_mut(&stream_id)
                .ok_or_else(|| JsValue::from_str("unknown stream"))?;
            match async_timeout(std::time::Duration::from_millis(50), stream.read(&mut buf)).await
            {
                Ok(Ok(n)) => break n, // data (n>0) or real EOF (n==0)
                Ok(Err(e)) => {
                    *self.session.borrow_mut() = Some(slot);
                    return Err(js_err(e));
                }
                Err(_) => {
                    #[cfg(target_arch = "wasm32")]
                    let timed_out = wasmtimer::std::Instant::now() >= deadline;
                    #[cfg(not(target_arch = "wasm32"))]
                    let timed_out = tokio::time::Instant::now() >= deadline;
                    if timed_out {
                        break 0; // would-block — JS retries
                    }
                }
            }
        };

        let out = js_sys::Uint8Array::new_with_length(n as u32);
        if n > 0 {
            out.copy_from(&buf[..n]);
        }
        *self.session.borrow_mut() = Some(slot);
        Ok(out)
    }

    #[wasm_bindgen(js_name = streamHalfClose)]
    pub async fn stream_half_close(&self, stream_id: u32) -> Result<(), JsValue> {
        let mut slot = self
            .session
            .borrow_mut()
            .take()
            .ok_or_else(|| JsValue::from_str("not connected"))?;
        let result = match slot.streams.get_mut(&stream_id) {
            Some(stream) => stream.half_close().await,
            None => {
                *self.session.borrow_mut() = Some(slot);
                return Err(JsValue::from_str("unknown stream"));
            }
        };
        *self.session.borrow_mut() = Some(slot);
        result.map_err(js_err)
    }

    pub async fn close(&self) -> Result<(), JsValue> {
        if let Some(mut slot) = self.session.borrow_mut().take() {
            let _ = slot.session.close().await;
        }
        if let Ok(mut g) = self.peer_tx.lock() {
            *g = None;
        }
        *self.signaling_inbox.borrow_mut() = None;
        Ok(())
    }

    /// Canonical `{host}--{entity}.idr.to` (appends `.idr.to` when missing).
    #[wasm_bindgen(js_name = canonicalizeFqhn)]
    /// Canonical `{host}--{entity}.idr.to` (appends `.idr.to` when missing).
    pub fn canonicalize_fqhn(fqhn: String) -> Result<String, JsValue> {
        idr_protocol::fqhn::canonicalize(&fqhn).map_err(|e| JsValue::from_str(&e.to_string()))
    }

    /// Dual-mod placement servers JSON for a discovery document + FQHN.
    #[wasm_bindgen(js_name = placeServersJson)]
    pub fn place_servers_json(
        discovery_json: String,
        target_fqhn: String,
    ) -> Result<String, JsValue> {
        let doc = parse_discovery_document(discovery_json.as_bytes())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        let servers = place_wss_servers(&doc, &target_fqhn).map_err(js_err)?;
        serde_json::to_string(&servers).map_err(|e| JsValue::from_str(&e.to_string()))
    }
}

impl Clone for JsPeerHost {
    fn clone(&self) -> Self {
        Self {
            start: self.start.clone(),
            create_local_description: self.create_local_description.clone(),
            set_remote_description: self.set_remote_description.clone(),
            add_remote_candidate: self.add_remote_candidate.clone(),
            set_ice_servers: self.set_ice_servers.clone(),
            send_binary: self.send_binary.clone(),
            close: self.close.clone(),
        }
    }
}

impl Clone for JsSignalingHost {
    fn clone(&self) -> Self {
        Self {
            preconnect: self.preconnect.clone(),
            begin_session: self.begin_session.clone(),
            send_json: self.send_json.clone(),
            close: self.close.clone(),
        }
    }
}

//! PeerTransport backed by browser RTCPeerConnection (JS host).

use async_trait::async_trait;
use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_webrtc::transport::{PeerConnectRequest, PeerEvent, PeerTransport};
use js_sys::Function;
use tokio::sync::mpsc;
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;

pub struct JsPeerHost {
    pub start: Function,
    pub create_local_description: Function,
    pub set_remote_description: Function,
    pub add_remote_candidate: Function,
    pub set_ice_servers: Function,
    pub send_binary: Function,
    pub close: Function,
}

pub struct JsPeerTransport {
    host: JsPeerHost,
    events: mpsc::UnboundedReceiver<PeerEvent>,
    /// Kept so the engine can clone a sender for JS injectors.
    event_tx: mpsc::UnboundedSender<PeerEvent>,
}

// Browser is single-threaded; mark Send so Arc/Mutex/SourceRuntime bounds work.
unsafe impl Send for JsPeerTransport {}
unsafe impl Sync for JsPeerTransport {}
unsafe impl Send for JsPeerHost {}
unsafe impl Sync for JsPeerHost {}

impl JsPeerTransport {
    pub fn new(host: JsPeerHost) -> Self {
        let (event_tx, events) = mpsc::unbounded_channel();
        Self {
            host,
            events,
            event_tx,
        }
    }

    pub fn event_sender(&self) -> mpsc::UnboundedSender<PeerEvent> {
        self.event_tx.clone()
    }
}

async fn call0_value(f: &Function) -> Result<JsValue> {
    let p = f
        .call0(&JsValue::NULL)
        .map_err(|e| IdrError::new(IdrErrorKind::InternalError, format!("js call: {e:?}")))?;
    if p.is_undefined() || p.is_null() {
        return Ok(JsValue::UNDEFINED);
    }
    JsFuture::from(js_sys::Promise::from(p))
        .await
        .map_err(|e| IdrError::new(IdrErrorKind::InternalError, format!("js promise: {e:?}")))
}

async fn call1(f: &Function, a0: &JsValue) -> Result<()> {
    let p = f
        .call1(&JsValue::NULL, a0)
        .map_err(|e| IdrError::new(IdrErrorKind::InternalError, format!("js call: {e:?}")))?;
    if p.is_undefined() || p.is_null() {
        return Ok(());
    }
    JsFuture::from(js_sys::Promise::from(p))
        .await
        .map_err(|e| IdrError::new(IdrErrorKind::InternalError, format!("js promise: {e:?}")))?;
    Ok(())
}

async fn call2(f: &Function, a0: &JsValue, a1: &JsValue) -> Result<()> {
    let p = f
        .call2(&JsValue::NULL, a0, a1)
        .map_err(|e| IdrError::new(IdrErrorKind::InternalError, format!("js call: {e:?}")))?;
    if p.is_undefined() || p.is_null() {
        return Ok(());
    }
    JsFuture::from(js_sys::Promise::from(p))
        .await
        .map_err(|e| IdrError::new(IdrErrorKind::InternalError, format!("js promise: {e:?}")))?;
    Ok(())
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl PeerTransport for JsPeerTransport {
    async fn start(&mut self, request: PeerConnectRequest) -> Result<()> {
        let role = match request.role {
            idr_webrtc::transport::PeerRole::Offerer => "offerer",
            idr_webrtc::transport::PeerRole::Answerer => "answerer",
        };
        let ice = request
            .ice_servers_json
            .unwrap_or_else(|| "null".to_string());
        call2(
            &self.host.start,
            &JsValue::from_str(role),
            &JsValue::from_str(&ice),
        )
        .await
    }

    async fn set_remote_description(&mut self, sdp_type: &str, sdp: &str) -> Result<()> {
        call2(
            &self.host.set_remote_description,
            &JsValue::from_str(sdp_type),
            &JsValue::from_str(sdp),
        )
        .await
    }

    async fn create_local_description(&mut self) -> Result<()> {
        let value = call0_value(&self.host.create_local_description).await?;
        if value.is_undefined() || value.is_null() {
            return Ok(());
        }
        let sdp_type = js_sys::Reflect::get(&value, &JsValue::from_str("sdp_type"))
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_else(|| "offer".into());
        let sdp = js_sys::Reflect::get(&value, &JsValue::from_str("sdp"))
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_default();
        if sdp.is_empty() {
            return Err(IdrError::new(
                IdrErrorKind::IceFailed,
                "createLocalDescription returned empty SDP",
            ));
        }
        // Inject directly — avoids a lost pushPeerEvent race that would block
        // forever before Presence WSS is opened.
        let _ = self.event_tx.send(PeerEvent::LocalDescription { sdp_type, sdp });
        Ok(())
    }

    fn add_remote_candidate(&mut self, candidate: &str, mid: &str) -> Result<()> {
        self.host
            .add_remote_candidate
            .call2(
                &JsValue::NULL,
                &JsValue::from_str(candidate),
                &JsValue::from_str(mid),
            )
            .map_err(|e| IdrError::new(IdrErrorKind::IceFailed, format!("add candidate: {e:?}")))?;
        Ok(())
    }

    fn set_ice_servers_json(&mut self, json: &str) -> Result<()> {
        self.host
            .set_ice_servers
            .call1(&JsValue::NULL, &JsValue::from_str(json))
            .map_err(|e| {
                IdrError::new(
                    IdrErrorKind::IceFailed,
                    format!("set ice servers: {e:?}"),
                )
            })?;
        Ok(())
    }

    fn send_binary(&mut self, message: &[u8]) -> Result<()> {
        let arr = js_sys::Uint8Array::new_with_length(message.len() as u32);
        arr.copy_from(message);
        self.host
            .send_binary
            .call1(&JsValue::NULL, &arr.into())
            .map_err(|e| {
                IdrError::new(IdrErrorKind::TransportClosed, format!("send_binary: {e:?}"))
            })?;
        Ok(())
    }

    async fn next_event(&mut self) -> Result<PeerEvent> {
        self.events.recv().await.ok_or_else(|| {
            IdrError::new(IdrErrorKind::TransportClosed, "peer event channel closed")
        })
    }

    fn close(&mut self) {
        let _ = self.host.close.call0(&JsValue::NULL);
    }
}

/// Parse a peer event JSON object from JS into PeerEvent.
pub fn parse_peer_event(value: &JsValue) -> Result<PeerEvent> {
    let obj = js_sys::Object::from(value.clone());
    let kind = js_sys::Reflect::get(&obj, &JsValue::from_str("kind"))
        .ok()
        .and_then(|v| v.as_string())
        .unwrap_or_default();
    match kind.as_str() {
        "local_description" => {
            let sdp_type = js_sys::Reflect::get(&obj, &JsValue::from_str("sdp_type"))
                .ok()
                .and_then(|v| v.as_string())
                .unwrap_or_else(|| "offer".into());
            let sdp = js_sys::Reflect::get(&obj, &JsValue::from_str("sdp"))
                .ok()
                .and_then(|v| v.as_string())
                .unwrap_or_default();
            Ok(PeerEvent::LocalDescription { sdp_type, sdp })
        }
        "local_candidate" => {
            let candidate = js_sys::Reflect::get(&obj, &JsValue::from_str("candidate"))
                .ok()
                .and_then(|v| v.as_string())
                .unwrap_or_default();
            let mid = js_sys::Reflect::get(&obj, &JsValue::from_str("mid"))
                .ok()
                .and_then(|v| v.as_string())
                .unwrap_or_else(|| "0".into());
            Ok(PeerEvent::LocalCandidate { candidate, mid })
        }
        "gathering_complete" => Ok(PeerEvent::GatheringComplete),
        "datachannel_open" => Ok(PeerEvent::DataChannelOpen),
        "datachannel_closed" => Ok(PeerEvent::DataChannelClosed),
        "connection_failed" => Ok(PeerEvent::ConnectionFailed),
        "closed" => Ok(PeerEvent::Closed),
        "binary" => {
            let data = js_sys::Reflect::get(&obj, &JsValue::from_str("data")).map_err(|e| {
                IdrError::new(IdrErrorKind::ProtocolError, format!("binary data: {e:?}"))
            })?;
            let arr: js_sys::Uint8Array = data
                .dyn_into()
                .map_err(|_| IdrError::new(IdrErrorKind::ProtocolError, "binary data not Uint8Array"))?;
            let mut buf = vec![0u8; arr.length() as usize];
            arr.copy_to(&mut buf);
            Ok(PeerEvent::BinaryMessage(buf))
        }
        other => Err(IdrError::new(
            IdrErrorKind::ProtocolError,
            format!("unknown peer event kind: {other}"),
        )),
    }
}

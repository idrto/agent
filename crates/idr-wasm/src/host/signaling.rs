//! WebRtcSignalingClient backed by browser WebSocket (JS host).

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_protocol::webrtc_ice::SessionIceConfig;
use idr_protocol::webrtc_signaling::{
    WebRtcAnswer, WebRtcIceCandidate, WebRtcSessionRequest, WebRtcSessionResultCode,
};
use idr_signaling::ephemeral::{
    EphemeralSignaling, SessionPending, SignalingMessage, WebRtcSignalingClient,
};
use js_sys::Function;
use tokio::sync::mpsc;
use uuid::Uuid;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;

pub struct JsSignalingHost {
    /// async (wssUrl: string) => void — handshake only, overlaps offer SDP.
    pub preconnect: Option<Function>,
    /// async (wssUrl: string, requestJson: string) => void
    pub begin_session: Function,
    pub send_json: Function,
    pub close: Function,
}

pub struct JsSignalingClient {
    host: JsSignalingHost,
    wss_url: String,
    /// Shared with the active ephemeral channel so JS can inject messages.
    inbox_tx: Arc<Mutex<Option<mpsc::UnboundedSender<SignalingMessage>>>>,
}

unsafe impl Send for JsSignalingClient {}
unsafe impl Sync for JsSignalingClient {}
unsafe impl Send for JsSignalingHost {}
unsafe impl Sync for JsSignalingHost {}

impl JsSignalingClient {
    pub fn new(host: JsSignalingHost, wss_url: impl Into<String>) -> Self {
        Self {
            host,
            wss_url: wss_url.into(),
            inbox_tx: Arc::new(Mutex::new(None)),
        }
    }

    pub fn set_wss_url(&mut self, url: impl Into<String>) {
        self.wss_url = url.into();
    }

    pub fn push_message(&self, msg: SignalingMessage) -> Result<()> {
        let guard = self.inbox_tx.lock().map_err(|_| {
            IdrError::new(IdrErrorKind::InternalError, "signaling inbox lock poisoned")
        })?;
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(msg);
        }
        Ok(())
    }

    pub fn inbox_slot(&self) -> Arc<Mutex<Option<mpsc::UnboundedSender<SignalingMessage>>>> {
        self.inbox_tx.clone()
    }
}

struct JsEphemeral {
    rx: mpsc::UnboundedReceiver<SignalingMessage>,
    send_json: Function,
    close: Function,
    inbox_slot: Arc<Mutex<Option<mpsc::UnboundedSender<SignalingMessage>>>>,
}

unsafe impl Send for JsEphemeral {}
unsafe impl Sync for JsEphemeral {}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl WebRtcSignalingClient for JsSignalingClient {
    async fn begin_session(
        &mut self,
        request: WebRtcSessionRequest,
    ) -> Result<Box<dyn EphemeralSignaling>> {
        let (tx, rx) = mpsc::unbounded_channel();
        {
            let mut guard = self.inbox_tx.lock().map_err(|_| {
                IdrError::new(IdrErrorKind::InternalError, "signaling inbox lock poisoned")
            })?;
            *guard = Some(tx);
        }

        let json = serde_json::to_string(&request).map_err(|e| {
            IdrError::new(IdrErrorKind::ProtocolError, format!("encode session request: {e}"))
        })?;

        let p = self
            .host
            .begin_session
            .call2(
                &JsValue::NULL,
                &JsValue::from_str(&self.wss_url),
                &JsValue::from_str(&json),
            )
            .map_err(|e| {
                IdrError::new(IdrErrorKind::SignalingFailed, format!("begin_session: {e:?}"))
            })?;
        if !p.is_undefined() && !p.is_null() {
            JsFuture::from(js_sys::Promise::from(p))
                .await
                .map_err(|e| {
                    IdrError::new(
                        IdrErrorKind::SignalingFailed,
                        format!("begin_session promise: {e:?}"),
                    )
                })?;
        }

        Ok(Box::new(JsEphemeral {
            rx,
            send_json: self.host.send_json.clone(),
            close: self.host.close.clone(),
            inbox_slot: self.inbox_tx.clone(),
        }))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl EphemeralSignaling for JsEphemeral {
    async fn next_message(&mut self) -> Result<SignalingMessage> {
        self.rx.recv().await.ok_or_else(|| {
            IdrError::new(IdrErrorKind::SignalingFailed, "signaling channel closed")
        })
    }

    async fn send_ice(&mut self, candidate: WebRtcIceCandidate) -> Result<()> {
        let json = serde_json::to_string(&candidate).map_err(|e| {
            IdrError::new(IdrErrorKind::ProtocolError, format!("encode ice: {e}"))
        })?;
        self.send_json
            .call1(&JsValue::NULL, &JsValue::from_str(&json))
            .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, format!("send_ice: {e:?}")))?;
        Ok(())
    }

    async fn send_json(&mut self, json: &str) -> Result<()> {
        self.send_json
            .call1(&JsValue::NULL, &JsValue::from_str(json))
            .map_err(|e| {
                IdrError::new(IdrErrorKind::SignalingFailed, format!("send_json: {e:?}"))
            })?;
        Ok(())
    }

    async fn close(&mut self) -> Result<()> {
        let _ = self.close.call0(&JsValue::NULL);
        if let Ok(mut guard) = self.inbox_slot.lock() {
            *guard = None;
        }
        Ok(())
    }
}

/// Parse a Presence signaling JSON string into SignalingMessage.
pub fn parse_signaling_message(raw: &str) -> Result<Option<SignalingMessage>> {
    let value: serde_json::Value = serde_json::from_str(raw).map_err(|e| {
        IdrError::new(IdrErrorKind::ProtocolError, format!("signaling json: {e}"))
    })?;
    let msg_type = value
        .get("message_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    match msg_type {
        "presence_error" => Ok(Some(SignalingMessage::Error {
            message: value
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("presence error")
                .to_string(),
        })),
        "webrtc_session_pending" | "session_pending" => {
            let session_id = parse_uuid(value.get("session_id"))?;
            let ice: Option<SessionIceConfig> =
                serde_json::from_value(value.get("ice").cloned().unwrap_or(serde_json::Value::Null))
                    .ok();
            Ok(Some(SignalingMessage::Pending(SessionPending {
                session_id,
                ice,
            })))
        }
        "webrtc_answer" => {
            let ans: WebRtcAnswer = serde_json::from_value(value).map_err(|e| {
                IdrError::new(IdrErrorKind::ProtocolError, format!("webrtc_answer: {e}"))
            })?;
            Ok(Some(SignalingMessage::Answer(ans)))
        }
        "webrtc_ice_candidate" => {
            let c: WebRtcIceCandidate = serde_json::from_value(value).map_err(|e| {
                IdrError::new(IdrErrorKind::ProtocolError, format!("ice candidate: {e}"))
            })?;
            Ok(Some(SignalingMessage::IceCandidate(c)))
        }
        "webrtc_ice_complete" => {
            let session_id = parse_uuid(value.get("session_id"))?;
            Ok(Some(SignalingMessage::IceComplete { session_id }))
        }
        "webrtc_session_ack" => {
            let session_id = parse_uuid(value.get("session_id"))?;
            let result_str = value
                .get("result")
                .and_then(|v| v.as_str())
                .unwrap_or("failed");
            let result = match result_str.to_ascii_lowercase().as_str() {
                "active" => WebRtcSessionResultCode::Active,
                "negotiating" => WebRtcSessionResultCode::Negotiating,
                "received" => WebRtcSessionResultCode::Received,
                "expired" => WebRtcSessionResultCode::Expired,
                "busy" => WebRtcSessionResultCode::Busy,
                _ => WebRtcSessionResultCode::Failed,
            };
            let detail = value
                .get("detail")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            Ok(Some(SignalingMessage::SessionAck {
                session_id,
                result,
                detail,
            }))
        }
        _ => Ok(None),
    }
}

fn parse_uuid(v: Option<&serde_json::Value>) -> Result<Uuid> {
    let s = v.and_then(|x| x.as_str()).ok_or_else(|| {
        IdrError::new(IdrErrorKind::ProtocolError, "missing session_id")
    })?;
    Uuid::parse_str(s)
        .map_err(|e| IdrError::new(IdrErrorKind::ProtocolError, format!("session_id: {e}")))
}

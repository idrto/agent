//! WebRTC responder session: SDP/ICE signaling + DataChannel mux bridge.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use uuid::Uuid;

use crate::config::{NginxConfig, WebRtcPolicyConfig};
use crate::identity::TargetIdentity;
use crate::presence::outbox::PresenceSignalingOutbox;
use crate::webrtc::mux::{decode_datachannel_message, encode_datachannel_message};
use crate::webrtc::peer::{NativePeerSession, PeerConfig, PeerEvent};
use crate::webrtc::session_manager::{
    PeerIceInbox, RemoteIceMsg, SessionState, WebRtcSessionManager,
};
use idr_core::error::IdrErrorKind;
use idr_protocol::signaling::SignalingMessageType;
use idr_protocol::stream_mux::{OpenErrorCode, StreamFrame, StreamKind, StreamOpenMeta};
use idr_protocol::webrtc_ice::IceServer;
use idr_protocol::webrtc_signaling::{
    SessionDescription, WebRtcAnswer, WebRtcAnswerUnsigned, WebRtcIceCandidate, WebRtcIceComplete,
    WebRtcSessionAck, WebRtcSessionOffer, WebRtcSessionResultCode,
};
use idr_protocol::PROTOCOL_VERSION;

enum Outbound {
    Frame(Vec<u8>),
    Stop,
}

pub struct SessionRuntime {
    pub offer: WebRtcSessionOffer,
    pub ice_servers: Vec<IceServer>,
    pub ice_transport_policy: idr_protocol::webrtc_ice::IceTransportPolicy,
    pub outbox: PresenceSignalingOutbox,
    pub identity: TargetIdentity,
    pub sessions: Arc<WebRtcSessionManager>,
    pub nginx: NginxConfig,
    pub policy: WebRtcPolicyConfig,
    pub fqhn: String,
    pub connectors: Arc<idr_core::ConnectorRegistry>,
}

pub async fn run_responder_session(rt: SessionRuntime) -> anyhow::Result<()> {
    let session_id = rt.offer.session_id;
    tracing::info!(
        %session_id,
        sdp_len = rt.offer.sdp.sdp.len(),
        ice_servers = rt.ice_servers.len(),
        "webrtc responder starting"
    );
    let (inbox, mut ice_rx) = PeerIceInbox::channel(64);
    rt.sessions.register_ice_inbox(session_id, inbox);

    // Any failure before the event loop used to return without notifying Presence
    // (only offer_ack Received was already sent) → Source waited 60s for nothing.
    let ice_servers = rt.ice_servers.clone();
    let ice_transport_policy = rt.ice_transport_policy;
    let offer_sdp = rt.offer.sdp.sdp.clone();
    let setup = tokio::task::spawn_blocking(move || {
        let mut peer = NativePeerSession::new(PeerConfig {
            ice_servers,
            ice_transport_policy,
            ..PeerConfig::default()
        })?;
        peer.set_remote_offer(&offer_sdp)?;
        peer.create_answer()?;
        Ok::<_, anyhow::Error>(peer)
    });
    let mut peer = match tokio::time::timeout(std::time::Duration::from_secs(20), setup).await {
        Ok(Ok(Ok(peer))) => {
            tracing::info!(%session_id, "webrtc peer setup OK; waiting for local SDP");
            peer
        }
        Ok(Ok(Err(e))) => {
            let _ = send_session_ack(
                &rt.outbox,
                session_id,
                WebRtcSessionResultCode::Failed,
                Some(format!("webrtc setup: {e}")),
            )
            .await;
            rt.sessions.end_session(session_id);
            return Err(e);
        }
        Ok(Err(e)) => {
            let msg = format!("webrtc setup join error: {e}");
            let _ = send_session_ack(
                &rt.outbox,
                session_id,
                WebRtcSessionResultCode::Failed,
                Some(msg.clone()),
            )
            .await;
            rt.sessions.end_session(session_id);
            return Err(anyhow::anyhow!(msg));
        }
        Err(_) => {
            let msg = "webrtc peer setup timed out (peer new / set_remote / create_answer)";
            let _ = send_session_ack(
                &rt.outbox,
                session_id,
                WebRtcSessionResultCode::Failed,
                Some(msg.into()),
            )
            .await;
            rt.sessions.end_session(session_id);
            return Err(anyhow::anyhow!(msg));
        }
    };
    rt.sessions
        .set_state(session_id, SessionState::IceConnecting);

    let (out_tx, mut out_rx) = mpsc::channel::<Outbound>(128);
    let mut writers: HashMap<u32, OwnedWriteHalf> = HashMap::new();
    let mut dc_open = false;
    let mut answered = false;
    let answer_deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(15);

    let result = loop {
        tokio::select! {
            event = peer.next_event() => {
                match event? {
                    PeerEvent::LocalDescription(desc) => {
                        if answered {
                            continue;
                        }
                        answered = true;
                        tracing::info!(
                            %session_id,
                            sdp_type = %desc.sdp_type,
                            sdp_len = desc.sdp.len(),
                            "local answer SDP ready; sending to Presence"
                        );
                        let answer = WebRtcAnswer::sign(
                            WebRtcAnswerUnsigned {
                                version: PROTOCOL_VERSION,
                                message_type: SignalingMessageType::WebRtcAnswer,
                                message_id: Uuid::new_v4(),
                                session_id,
                                sdp: SessionDescription {
                                    sdp_type: desc.sdp_type,
                                    sdp: desc.sdp,
                                },
                                signature: String::new(),
                            },
                            rt.identity.signing_key(),
                        )?;
                        let json = serde_json::to_string(&answer)?;
                        rt.outbox.send_json(&json).await?;
                    }
                    PeerEvent::LocalCandidate(c) => {
                        let msg = WebRtcIceCandidate {
                            version: PROTOCOL_VERSION,
                            message_type: SignalingMessageType::WebRtcIceCandidate,
                            message_id: Uuid::new_v4(),
                            session_id,
                            candidate: c.candidate,
                            mid: c.mid,
                            signature: None,
                        };
                        rt.outbox.send_json(&serde_json::to_string(&msg)?).await?;
                    }
                    PeerEvent::GatheringComplete => {
                        let msg = WebRtcIceComplete {
                            version: PROTOCOL_VERSION,
                            message_type: SignalingMessageType::WebRtcIceComplete,
                            message_id: Uuid::new_v4(),
                            session_id,
                        };
                        let _ = rt.outbox.send_json(&serde_json::to_string(&msg)?).await;
                    }
                    PeerEvent::DataChannelOpen => {
                        dc_open = true;
                        rt.sessions.set_state(session_id, SessionState::DataChannelOpen);
                        send_session_ack(
                            &rt.outbox,
                            session_id,
                            WebRtcSessionResultCode::Active,
                            None,
                        )
                        .await?;
                    }
                    PeerEvent::BinaryMessage(bytes) => {
                        if let Err(e) = handle_mux_message(
                            &bytes,
                            &rt,
                            session_id,
                            &mut writers,
                            out_tx.clone(),
                        )
                        .await
                        {
                            warn!(error = %e, %session_id, "mux frame handling failed");
                        }
                    }
                    PeerEvent::DataChannelClosed => {
                        break Err(anyhow::anyhow!("data channel closed"));
                    }
                    PeerEvent::ConnectionFailed(reason) => {
                        break Err(anyhow::anyhow!("connection failed: {reason}"));
                    }
                    PeerEvent::Error(err) => {
                        warn!(%err, %session_id, "peer error");
                        if !dc_open {
                            break Err(anyhow::anyhow!(err));
                        }
                    }
                }
            }
            ice = ice_rx.recv() => {
                match ice {
                    Some(RemoteIceMsg::Candidate { candidate, mid }) => {
                        if let Err(e) = peer.add_remote_candidate(&candidate, &mid) {
                            warn!(error = %e, "add remote ICE failed");
                        }
                    }
                    Some(RemoteIceMsg::End) | None => {}
                }
            }
            outbound = out_rx.recv() => {
                match outbound {
                    Some(Outbound::Frame(bytes)) => {
                        if let Err(e) = peer.send_binary(&bytes) {
                            warn!(error = %e, "dc send failed");
                        } else {
                            rt.sessions.touch(session_id);
                        }
                    }
                    Some(Outbound::Stop) | None => {
                        if outbound.is_none() {
                            break Err(anyhow::anyhow!("outbound channel closed"));
                        }
                    }
                }
            }
            _ = tokio::time::sleep_until(answer_deadline), if !answered => {
                break Err(anyhow::anyhow!(
                    "timed out waiting for local WebRTC answer SDP (create_answer produced no on_description)"
                ));
            }
        }
    };

    writers.clear();
    peer.close();
    rt.sessions.clear_ice_inbox(session_id);

    match result {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = send_session_ack(
                &rt.outbox,
                session_id,
                WebRtcSessionResultCode::Failed,
                Some(e.to_string()),
            )
            .await;
            rt.sessions.end_session(session_id);
            Err(e)
        }
    }
}

async fn send_session_ack(
    outbox: &PresenceSignalingOutbox,
    session_id: Uuid,
    result: WebRtcSessionResultCode,
    detail: Option<String>,
) -> anyhow::Result<()> {
    let ack = WebRtcSessionAck {
        version: PROTOCOL_VERSION,
        message_type: SignalingMessageType::WebRtcSessionAck,
        message_id: Uuid::new_v4(),
        session_id,
        result,
        detail,
    };
    outbox.send_json(&serde_json::to_string(&ack)?).await
}

async fn handle_mux_message(
    bytes: &[u8],
    rt: &SessionRuntime,
    session_id: Uuid,
    writers: &mut HashMap<u32, OwnedWriteHalf>,
    out_tx: mpsc::Sender<Outbound>,
) -> anyhow::Result<()> {
    let frame = decode_datachannel_message(bytes)?;
    match frame {
        StreamFrame::Open {
            stream_id,
            kind,
            meta,
        } => {
            if writers.contains_key(&stream_id) {
                anyhow::bail!("duplicate stream_id {stream_id}");
            }
            let open_result = open_via_registry(rt, kind, &meta).await;
            let tcp = match open_result {
                Ok(tcp) => tcp,
                Err((code, message)) => {
                    // Log full detail on Target only; Source must not see secrets.
                    warn!(
                        %session_id,
                        stream_id,
                        ?code,
                        error = %message,
                        "OPEN failed (detail stays on Target)"
                    );
                    let err = StreamFrame::OpenError {
                        stream_id,
                        code: code as u16,
                        message: sanitize_open_error_for_source(code, &message),
                    };
                    if let Ok(bytes) = encode_datachannel_message(&err) {
                        let _ = out_tx.send(Outbound::Frame(bytes)).await;
                    }
                    return Ok(());
                }
            };
            let (mut read_half, write_half) = tcp.into_split();
            writers.insert(stream_id, write_half);
            rt.sessions.stream_opened(session_id);
            rt.sessions.set_state(session_id, SessionState::Active);
            debug!(%session_id, stream_id, ?kind, service = ?meta.service_name, "webrtc mux stream opened");
            tracing::info!(
                %session_id,
                stream_id,
                service = ?meta.service_name,
                "mux stream OpenOk → Source"
            );
            let out_tx_reader = out_tx.clone();
            let sessions = rt.sessions.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match read_half.read(&mut buf).await {
                        Ok(0) => {
                            let frame = StreamFrame::HalfClose { stream_id };
                            if let Ok(bytes) = encode_datachannel_message(&frame) {
                                let _ = out_tx_reader.send(Outbound::Frame(bytes)).await;
                            }
                            break;
                        }
                        Ok(n) => {
                            let frame = StreamFrame::Data {
                                stream_id,
                                bytes: buf[..n].to_vec(),
                            };
                            match encode_datachannel_message(&frame) {
                                Ok(bytes) => {
                                    if out_tx_reader.send(Outbound::Frame(bytes)).await.is_err() {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    warn!(error = %e, "encode data frame failed");
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, stream_id, "tcp read failed");
                            let frame = StreamFrame::Reset {
                                stream_id,
                                reason: 1,
                            };
                            if let Ok(bytes) = encode_datachannel_message(&frame) {
                                let _ = out_tx_reader.send(Outbound::Frame(bytes)).await;
                            }
                            break;
                        }
                    }
                }
                sessions.stream_closed(session_id);
            });
            let ok = StreamFrame::OpenOk {
                stream_id,
                initial_window: idr_protocol::stream_mux::INITIAL_STREAM_WINDOW,
            };
            if let Ok(bytes) = encode_datachannel_message(&ok) {
                let _ = out_tx.send(Outbound::Frame(bytes)).await;
            }
        }
        StreamFrame::Data { stream_id, bytes } => {
            if let Some(w) = writers.get_mut(&stream_id) {
                w.write_all(&bytes).await?;
                rt.sessions.touch(session_id);
            }
        }
        StreamFrame::HalfClose { stream_id } => {
            if let Some(mut w) = writers.remove(&stream_id) {
                let _ = w.shutdown().await;
                rt.sessions.stream_closed(session_id);
            }
        }
        StreamFrame::Reset { stream_id, .. } => {
            writers.remove(&stream_id);
            rt.sessions.stream_closed(session_id);
        }
        StreamFrame::WindowUpdate { .. } => {
            // Credit applied when Target enforces read pacing (Phase 4 basic: accept/ignore).
            rt.sessions.touch(session_id);
        }
        StreamFrame::Ping { opaque } => {
            let pong = StreamFrame::Pong { opaque };
            if let Ok(bytes) = encode_datachannel_message(&pong) {
                let _ = out_tx.send(Outbound::Frame(bytes)).await;
            }
        }
        StreamFrame::Pong { .. } => {
            rt.sessions.touch(session_id);
        }
        StreamFrame::GoAway { .. } => {
            debug!(%session_id, "peer sent GoAway");
        }
        StreamFrame::OpenOk { .. } | StreamFrame::OpenError { .. } => {
            // Source→Target open acks are not expected on the answerer path.
        }
        StreamFrame::AuthRefresh { .. } => {}
        StreamFrame::Hello {
            version,
            features,
            conn_window,
        } => {
            let ack = StreamFrame::HelloAck {
                version: version.min(idr_protocol::stream_mux::STREAM_MUX_VERSION),
                features: idr_protocol::stream_mux::MuxProfile::from_features(&features)
                    .advertised_features(),
                conn_window: conn_window.min(idr_protocol::stream_mux::INITIAL_CONN_WINDOW),
            };
            if let Ok(bytes) = encode_datachannel_message(&ack) {
                let _ = out_tx.send(Outbound::Frame(bytes)).await;
            }
        }
        StreamFrame::HelloAck { .. } => {}
        StreamFrame::ServicesCatalogRequest => {
            let services = rt.connectors.service_names();
            let entries = rt.connectors.catalog_entries();
            let catalog = StreamFrame::ServicesCatalog { services };
            if let Ok(bytes) = encode_datachannel_message(&catalog) {
                let _ = out_tx.send(Outbound::Frame(bytes)).await;
            }
            let detailed = StreamFrame::ServicesCatalogDetailed { entries };
            if let Ok(bytes) = encode_datachannel_message(&detailed) {
                let _ = out_tx.send(Outbound::Frame(bytes)).await;
            }
        }
        StreamFrame::ServicesCatalog { .. } | StreamFrame::ServicesCatalogDetailed { .. } => {
            // Source→Target catalogs are not expected.
        }
    }
    Ok(())
}

async fn open_via_registry(
    rt: &SessionRuntime,
    kind: StreamKind,
    meta: &StreamOpenMeta,
) -> Result<tokio::net::TcpStream, (OpenErrorCode, String)> {
    let claimed = idr_protocol::fqhn::canonicalize(&meta.target_fqhn)
        .unwrap_or_else(|_| meta.target_fqhn.to_ascii_lowercase());
    if claimed != rt.fqhn {
        return Err((OpenErrorCode::FqhnMismatch, "StreamOpen FQHN mismatch".into()));
    }

    let service = meta
        .service_name
        .as_deref()
        .or(match kind {
            StreamKind::HttpPassthrough => Some("http"),
            StreamKind::TlsPassthrough => Some("https"),
            StreamKind::TcpConnect => None,
        });

    let Some(service_name) = service else {
        return Err((
            OpenErrorCode::InvalidArgument,
            "OPEN requires service_name (or http/https kind)".into(),
        ));
    };

    let (svc, connector) = rt.connectors.resolve(service_name).map_err(|e| {
        (
            OpenErrorCode::ServiceNotFound,
            e.to_string(),
        )
    })?;

    let connect_kind = if svc.kind != kind { svc.kind } else { kind };
    connector
        .connect(connect_kind, meta)
        .await
        .map_err(|e| {
            let code = match e.kind() {
                IdrErrorKind::InvalidArgument => OpenErrorCode::InvalidArgument,
                IdrErrorKind::ServiceNotFound => OpenErrorCode::ServiceNotFound,
                IdrErrorKind::AuthorizationDenied | IdrErrorKind::AuthenticationFailed => {
                    OpenErrorCode::Unauthorized
                }
                IdrErrorKind::ResourceExhausted => OpenErrorCode::ResourceExhausted,
                _ => OpenErrorCode::ConnectionRefused,
            };
            (code, e.to_string())
        })
}

/// Messages on OpenError are visible to Source — never include secrets, paths, or env names.
fn sanitize_open_error_for_source(code: OpenErrorCode, detail: &str) -> String {
    let lower = detail.to_ascii_lowercase();
    if lower.contains("inject header")
        || lower.contains("secret unavailable")
        || lower.contains("from_env")
        || lower.contains("hf_")
        || lower.contains("bearer ")
        || lower.contains("api_key")
        || lower.contains("api-key")
    {
        return match code {
            OpenErrorCode::Unauthorized | OpenErrorCode::InvalidArgument => {
                "Target service auth/config error".into()
            }
            OpenErrorCode::ServiceNotFound => "service not found on Target".into(),
            OpenErrorCode::ConnectionRefused => "Target upstream connection refused".into(),
            OpenErrorCode::ResourceExhausted => "Target resource exhausted".into(),
            OpenErrorCode::FqhnMismatch => "FQHN mismatch".into(),
            OpenErrorCode::Unspecified => "Target open failed".into(),
        };
    }
    let mut msg: String = detail.chars().take(160).collect();
    // Belt-and-suspenders: scrub accidental HF token substrings.
    loop {
        let lower_msg = msg.to_ascii_lowercase();
        let Some(idx) = lower_msg.find("hf_") else {
            break;
        };
        let rest = &msg[idx..];
        let end = rest
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
            .map(|i| idx + i)
            .unwrap_or(msg.len());
        msg.replace_range(idx..end, "[redacted]");
    }
    msg
}

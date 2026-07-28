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
use idr_protocol::signaling::SignalingMessageType;
use idr_protocol::stream_mux::StreamFrame;
use idr_protocol::webrtc_ice::IceServer;
use idr_protocol::webrtc_signaling::{
    SessionDescription, WebRtcAnswer, WebRtcAnswerUnsigned, WebRtcIceCandidate, WebRtcIceComplete,
    WebRtcSessionAck, WebRtcSessionOffer, WebRtcSessionResultCode,
};
use idr_protocol::PROTOCOL_VERSION;
use crate::webrtc::bridge;
use crate::webrtc::mux::{decode_datachannel_message, encode_datachannel_message};
use crate::webrtc::peer::{NativePeerSession, PeerConfig, PeerEvent};
use crate::webrtc::session_manager::{
    PeerIceInbox, RemoteIceMsg, SessionState, WebRtcSessionManager,
};

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
}

pub async fn run_responder_session(rt: SessionRuntime) -> anyhow::Result<()> {
    let session_id = rt.offer.session_id;
    let (inbox, mut ice_rx) = PeerIceInbox::channel(64);
    rt.sessions.register_ice_inbox(session_id, inbox);

    let mut peer = NativePeerSession::new(PeerConfig {
        ice_servers: rt.ice_servers,
        ice_transport_policy: rt.ice_transport_policy,
        ..PeerConfig::default()
    })?;
    peer.set_remote_offer(&rt.offer.sdp.sdp)?;
    peer.create_answer()?;
    rt.sessions
        .set_state(session_id, SessionState::IceConnecting);

    let (out_tx, mut out_rx) = mpsc::channel::<Outbound>(128);
    let mut writers: HashMap<u32, OwnedWriteHalf> = HashMap::new();
    let mut dc_open = false;
    let mut answered = false;

    let result = loop {
        tokio::select! {
            event = peer.next_event() => {
                match event? {
                    PeerEvent::LocalDescription(desc) => {
                        if answered {
                            continue;
                        }
                        answered = true;
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
                        rt.outbox.send_json(&serde_json::to_string(&answer)?).await?;
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
            let tcp = bridge::open_upstream(kind, meta, &rt.nginx, &rt.policy, &rt.fqhn).await?;
            let (mut read_half, write_half) = tcp.into_split();
            writers.insert(stream_id, write_half);
            rt.sessions.stream_opened(session_id);
            rt.sessions.set_state(session_id, SessionState::Active);
            debug!(%session_id, stream_id, ?kind, "webrtc mux stream opened");
            let out_tx = out_tx.clone();
            let sessions = rt.sessions.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match read_half.read(&mut buf).await {
                        Ok(0) => {
                            let frame = StreamFrame::HalfClose { stream_id };
                            if let Ok(bytes) = encode_datachannel_message(&frame) {
                                let _ = out_tx.send(Outbound::Frame(bytes)).await;
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
                                    if out_tx.send(Outbound::Frame(bytes)).await.is_err() {
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
                                let _ = out_tx.send(Outbound::Frame(bytes)).await;
                            }
                            break;
                        }
                    }
                }
                sessions.stream_closed(session_id);
            });
            let _ = kind;
            // FlowControlV1: acknowledge open with initial window credit.
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
    }
    Ok(())
}

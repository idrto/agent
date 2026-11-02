//! WebRTC responder session: SDP/ICE signaling + DataChannel mux bridge.

use std::sync::Arc;

use tracing::{debug, warn};
use uuid::Uuid;

use crate::config::{NginxConfig, WebRtcPolicyConfig};
use crate::identity::TargetIdentity;
use crate::presence::outbox::PresenceSignalingOutbox;
use crate::webrtc::mux::{decode_datachannel_message, encode_datachannel_message};
use crate::webrtc::local::{is_local_service, IoStream, LocalStream, SessionLocal, TransferEndpoint};
use crate::webrtc::mux_streams::MuxStreams;
use crate::webrtc::peer::{NativePeerSession, PeerConfig, PeerEvent};
use crate::webrtc::session_manager::{
    PeerIceInbox, RemoteIceMsg, SessionState, WebRtcSessionManager,
};
use idr_core::error::IdrErrorKind;
use idr_core::{StreamPriority, BULK_LOW_WATER};
use idr_protocol::signaling::SignalingMessageType;
use idr_protocol::stream_mux::{OpenErrorCode, StreamFrame, StreamKind, StreamOpenMeta};
use idr_protocol::webrtc_ice::IceServer;
use idr_protocol::webrtc_signaling::{
    SessionDescription, WebRtcAnswer, WebRtcAnswerUnsigned, WebRtcIceCandidate, WebRtcIceComplete,
    WebRtcSessionAck, WebRtcSessionOffer, WebRtcSessionResultCode,
};
use idr_protocol::PROTOCOL_VERSION;

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
    /// Peer binding and file transfer; None disables both (`idr.bind` /
    /// `idr.transfer` opens are refused).
    pub transfers: Option<Arc<TransferEndpoint>>,
}

pub async fn run_responder_session(rt: SessionRuntime) -> anyhow::Result<()> {
    let rt = Arc::new(rt);
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

    let (out, mut out_rx) = idr_core::mux_out(128);
    let mut streams = MuxStreams::new(out);
    let mut dc_open = false;
    let mut answer_sdp = String::new();
    let mut local: Option<SessionLocal> = None;
    let mut answered = false;
    let answer_deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(15);

    let result = loop {
        // Bulk waits while the DataChannel holds more than the low-water mark;
        // BufferedAmountLow (or the poll below) re-opens it.
        let bulk_open = peer.buffered_amount() < BULK_LOW_WATER;
        tokio::select! {
            event = peer.next_event() => {
                match event? {
                    PeerEvent::LocalDescription(desc) => {
                        if answered {
                            continue;
                        }
                        answered = true;
                        answer_sdp = desc.sdp.clone();
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
                        if let Some(ep) = &rt.transfers {
                            let fp = idr_protocol::peer_bind::sdp_fingerprint;
                            let ctx = idr_protocol::peer_bind::BindContext {
                                session_id: session_id.to_string(),
                                target_fqhn: rt.fqhn.clone(),
                                offerer_fingerprint: fp(&rt.offer.sdp.sdp).unwrap_or_default(),
                                answerer_fingerprint: fp(&answer_sdp).unwrap_or_default(),
                                path: peer.ice_path(),
                            };
                            let attested = rt.offer.source.policy.as_ref().map(|p| p.ski.clone());
                            local = Some(ep.start_session(ctx, attested));
                        }
                        rt.sessions.set_state(session_id, SessionState::DataChannelOpen);
                        if let Some((path, local_type, remote_type)) = peer.selected_ice_summary() {
                            let via = match path.as_str() {
                                "host" => "host (LAN/P2P)",
                                "stun" => "stun",
                                "turn" => "turn (relay)",
                                other => other,
                            };
                            tracing::info!(
                                %session_id,
                                ice_path = %path,
                                local_type = %local_type,
                                remote_type = %remote_type,
                                "WebRTC connected via {via}"
                            );
                        } else {
                            tracing::info!(
                                %session_id,
                                ice_path = "unknown",
                                "WebRTC connected (selected ICE pair not available yet)"
                            );
                        }
                        send_session_ack(
                            &rt.outbox,
                            session_id,
                            WebRtcSessionResultCode::Active,
                            None,
                        )
                        .await?;
                    }
                    PeerEvent::BinaryMessage(bytes) => {
                        match handle_mux_message(&bytes, &rt, session_id, &mut streams, local.as_ref()).await
                        {
                            Ok(replies) => {
                                for frame in replies {
                                    match encode_datachannel_message(&frame) {
                                        Ok(b) => {
                                            if let Err(e) = peer.send_binary(&b) {
                                                warn!(error = %e, "dc send failed");
                                            }
                                        }
                                        Err(e) => warn!(error = %e, "encode reply failed"),
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, %session_id, "mux frame handling failed");
                            }
                        }
                    }
                    PeerEvent::BufferedAmountLow => {}
                    PeerEvent::DataChannelClosed => {
                        if dc_open {
                            tracing::info!(%session_id, "WebRTC data channel closed");
                            break Ok(());
                        }
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
            // Target-initiated stream (e.g. sending a file to the Source).
            Some((service, priority, reply)) = async {
                match local.as_mut() {
                    Some(l) => l.opens.recv().await,
                    None => std::future::pending().await,
                }
            } => {
                match streams.open_local(&service, priority).await {
                    Ok(pending) => {
                        tokio::spawn(async move {
                            let r = match pending.await {
                                Ok(Ok(io)) => Ok(IoStream::new(0, io)),
                                Ok(Err(m)) => Err(m),
                                Err(_) => Err("session closed".to_string()),
                            };
                            let _ = reply.send(r);
                        });
                    }
                    Err(m) => {
                        let _ = reply.send(Err(m.to_string()));
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
            outbound = out_rx.next(bulk_open) => {
                match outbound {
                    Some(bytes) => {
                        if let Err(e) = peer.send_binary(&bytes) {
                            warn!(error = %e, "dc send failed");
                        } else {
                            rt.sessions.touch(session_id);
                        }
                    }
                    None => break Err(anyhow::anyhow!("outbound channel closed")),
                }
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(5)), if !bulk_open => {}
            _ = tokio::time::sleep_until(answer_deadline), if !answered => {
                break Err(anyhow::anyhow!(
                    "timed out waiting for local WebRTC answer SDP (create_answer produced no on_description)"
                ));
            }
        }
    };

    drop(streams);
    if let (Some(ep), Some(_)) = (&rt.transfers, &local) {
        ep.end_session(session_id);
    }
    peer.close();
    rt.sessions.clear_ice_inbox(session_id);
    rt.sessions.end_session(session_id);

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
    rt: &Arc<SessionRuntime>,
    session_id: Uuid,
    streams: &mut MuxStreams,
    local: Option<&SessionLocal>,
) -> anyhow::Result<Vec<StreamFrame>> {
    let frame = decode_datachannel_message(bytes)?;
    match frame {
        StreamFrame::Open {
            stream_id,
            kind,
            meta,
        } => {
            if let Err((code, message)) = streams.admit_open(stream_id) {
                warn!(%session_id, stream_id, ?code, %message, "OPEN refused");
                return Ok(vec![StreamFrame::OpenError {
                    stream_id,
                    code: code as u16,
                    message,
                }]);
            }
            if let Some(service) = meta.service_name.as_deref().filter(|s| is_local_service(s)) {
                return Ok(open_local_service(rt, stream_id, service, &meta, streams, local));
            }
            // Connect off the session loop; DATA is buffered until it completes.
            let rt2 = rt.clone();
            let connect = async move {
                match open_via_registry(&rt2, kind, &meta).await {
                    Ok(tcp) => {
                        rt2.sessions.stream_opened(session_id);
                        rt2.sessions.set_state(session_id, SessionState::Active);
                        debug!(%session_id, stream_id, ?kind, service = ?meta.service_name, "webrtc mux stream opened");
                        Ok(tcp)
                    }
                    Err((code, message)) => {
                        // Log full detail on Target only; Source must not see secrets.
                        warn!(
                            %session_id,
                            stream_id,
                            ?code,
                            error = %message,
                            "OPEN failed (detail stays on Target)"
                        );
                        Err((code, sanitize_open_error_for_source(code, &message)))
                    }
                }
            };
            let sessions = rt.sessions.clone();
            streams.open_with(stream_id, StreamPriority::Interactive, connect, move || {
                sessions.stream_closed(session_id)
            });
        }
        StreamFrame::Data { stream_id, bytes } => {
            rt.sessions.touch(session_id);
            return Ok(streams.on_data(stream_id, bytes).await);
        }
        StreamFrame::HalfClose { stream_id } => {
            if streams.on_half_close(stream_id) {
                rt.sessions.stream_closed(session_id);
            }
        }
        StreamFrame::Reset { stream_id, .. } => {
            streams.on_reset(stream_id);
            rt.sessions.stream_closed(session_id);
        }
        StreamFrame::WindowUpdate { stream_id, credit } => {
            streams.on_window_update(stream_id, credit);
            rt.sessions.touch(session_id);
        }
        StreamFrame::Ping { opaque } => return Ok(vec![StreamFrame::Pong { opaque }]),
        StreamFrame::Pong { .. } => {
            rt.sessions.touch(session_id);
        }
        StreamFrame::GoAway { .. } => {
            debug!(%session_id, "peer sent GoAway");
        }
        // Replies to Target-initiated opens.
        StreamFrame::OpenOk {
            stream_id,
            initial_window,
        } => streams.on_open_ok(stream_id, initial_window),
        StreamFrame::OpenError {
            stream_id, message, ..
        } => streams.on_open_error(stream_id, message),
        StreamFrame::AuthRefresh { .. } => {}
        StreamFrame::Hello {
            version,
            features,
            conn_window,
        } => {
            return Ok(vec![streams.on_hello(version, &features, conn_window)]);
        }
        StreamFrame::HelloAck { .. } => {}
        StreamFrame::ServicesCatalogRequest => {
            // A Source only sees the services its policy lets it open.
            let (policy, require) = (
                rt.offer.source.policy.as_ref(),
                rt.policy.require_source_policy,
            );
            let services = crate::webrtc::source_policy::visible(
                policy,
                require,
                rt.connectors.service_names(),
                |n: &String| n.as_str(),
            );
            let entries = crate::webrtc::source_policy::visible(
                policy,
                require,
                rt.connectors.catalog_entries(),
                |e| e.name.as_str(),
            );
            return Ok(vec![
                StreamFrame::ServicesCatalog { services },
                StreamFrame::ServicesCatalogDetailed { entries },
            ]);
        }
        StreamFrame::ServicesCatalog { .. } | StreamFrame::ServicesCatalogDetailed { .. } => {
            // Source→Target catalogs are not expected.
        }
    }
    Ok(Vec::new())
}

/// Accept a stream for `idr.bind` / `idr.transfer` into this Target's endpoint.
fn open_local_service(
    rt: &SessionRuntime,
    stream_id: u32,
    service: &str,
    meta: &StreamOpenMeta,
    streams: &mut MuxStreams,
    local: Option<&SessionLocal>,
) -> Vec<StreamFrame> {
    let refuse = |code: OpenErrorCode, message: &str| {
        vec![StreamFrame::OpenError {
            stream_id,
            code: code as u16,
            message: message.into(),
        }]
    };
    let claimed = idr_protocol::fqhn::canonicalize(&meta.target_fqhn)
        .unwrap_or_else(|_| meta.target_fqhn.to_ascii_lowercase());
    if claimed != rt.fqhn {
        return refuse(OpenErrorCode::FqhnMismatch, "StreamOpen FQHN mismatch");
    }
    let Some(local) = local else {
        return refuse(OpenErrorCode::ServiceNotFound, "file transfer not enabled");
    };
    let transfer = service == idr_protocol::transfer::TRANSFER_SERVICE;
    if transfer && local.peer.borrow().is_none() {
        return refuse(OpenErrorCode::Unauthorized, "peer identity not verified");
    }
    if !transfer && rt.offer.source.policy.is_none() {
        return refuse(OpenErrorCode::Unauthorized, "Source identity not attested");
    }
    let priority = if transfer { StreamPriority::Bulk } else { StreamPriority::Interactive };
    let (mine, theirs) = tokio::io::duplex(64 * 1024);
    if local
        .streams
        .try_send(LocalStream {
            service: service.to_string(),
            stream: IoStream::new(stream_id, mine),
        })
        .is_err()
    {
        return refuse(OpenErrorCode::ResourceExhausted, "busy");
    }
    streams.open_with(stream_id, priority, async { Ok(theirs) }, || {});
    Vec::new()
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

    let source_policy = rt.offer.source.policy.as_ref();
    if let Err(reason) = crate::webrtc::source_policy::service_allowed(
        source_policy,
        rt.policy.require_source_policy,
        service_name,
    ) {
        warn!(
            session_id = %rt.offer.session_id,
            service = service_name,
            zone = ?source_policy.and_then(|p| p.zone.as_deref()),
            ski = ?source_policy.map(|p| p.ski.as_str()),
            "stream refused by Source policy"
        );
        return Err((OpenErrorCode::Unauthorized, reason.into()));
    }

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

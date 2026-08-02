//! WebRTC signaling protocol roundtrips (no native stack required).

use chrono::{Duration, Utc};
use idr_target::protocol::crypto::KeyPair;
use idr_target::protocol::signaling::PresenceRole;
use idr_target::protocol::signaling::SignalingMessageType;
use idr_target::protocol::webrtc_ice::{
    build_rtc_ice_servers, IceRelayMode, SessionIceConfig, StunPolicy,
};
use idr_target::protocol::webrtc_signaling::{
    ProbeMethod, SourceAgentIdentity, TurnProbeCandidates, TurnProbeReport,
    TurnProbeReportUnsigned, TurnProbeResult, WebRtcSessionOffer, WebRtcSessionRequest,
};
use idr_target::protocol::PROTOCOL_VERSION;
use uuid::Uuid;

#[test]
fn turn_probe_report_sign_verify_roundtrip() {
    let target = KeyPair::generate();
    let unsigned = TurnProbeReportUnsigned {
        version: PROTOCOL_VERSION,
        message_type: SignalingMessageType::TurnProbeReport,
        message_id: Uuid::new_v4(),
        probe_generation: 1,
        target_fqhn: "device.example.idr.to".into(),
        role: PresenceRole::Primary,
        agent_region: "eu".into(),
        results: vec![TurnProbeResult {
            turn_node_id: "turn-a".into(),
            latency_ms: 12,
            reachable: true,
            address_family: idr_target::protocol::webrtc_signaling::AddressFamily::Ipv4,
            error: None,
        }],
        probed_at: Utc::now(),
        signature: String::new(),
    };
    let report = TurnProbeReport::sign(unsigned, &target.signing_key).unwrap();
    report.verify(&target.verifying_key).unwrap();
    let snapshot = report.to_snapshot();
    assert_eq!(snapshot.ordered_node_ids, vec!["turn-a"]);
}

#[test]
fn platform_ice_merge_includes_turn() {
    let ice = SessionIceConfig {
        relay_mode: IceRelayMode::Platform,
        stun_policy: StunPolicy::GoogleAndIdr,
        stun_servers: None,
        turn: Some(idr_target::protocol::webrtc_ice::TurnAllocation {
            turn_node_id: "turn-a".into(),
            region: "eu".into(),
            servers: vec![idr_target::protocol::webrtc_ice::IceServer {
                urls: vec!["turn:turn.example:3478".into()],
                username: Some("user".into()),
                credential: Some("pass".into()),
            }],
        }),
        byor: None,
        ice_transport_policy: idr_target::protocol::webrtc_ice::IceTransportPolicy::All,
        p2p_only: false,
    };
    let merged = build_rtc_ice_servers(&ice, &[]).unwrap();
    assert!(merged
        .iter()
        .any(|s| s.urls.iter().any(|u| u.starts_with("turn:"))));
}

#[test]
fn session_request_and_offer_types_parse() {
    let req = WebRtcSessionRequest {
        version: PROTOCOL_VERSION,
        message_type: SignalingMessageType::WebRtcSessionRequest,
        message_id: Uuid::new_v4(),
        session_id: Uuid::new_v4(),
        target_fqhn: "device.example.idr.to".into(),
        source: SourceAgentIdentity {
            auth_mode: idr_target::protocol::webrtc_signaling::SourceAuthMode::Anonymous,
            source_id: Some("src-1".into()),
            sdk_version: None,
        },
        source_region: "us".into(),
        sdp: idr_target::protocol::webrtc_signaling::SessionDescription {
            sdp_type: "offer".into(),
            sdp: "v=0".into(),
        },
        ice_transport_policy: Default::default(),
        signature: None,
    };
    let json = serde_json::to_string(&req).unwrap();
    let _: WebRtcSessionRequest = serde_json::from_str(&json).unwrap();

    let candidates = TurnProbeCandidates {
        version: PROTOCOL_VERSION,
        message_type: SignalingMessageType::TurnProbeCandidates,
        message_id: Uuid::new_v4(),
        probe_generation: 2,
        issued_at: Utc::now(),
        candidates: vec![idr_target::protocol::webrtc_signaling::TurnProbeCandidate {
            turn_node_id: "turn-a".into(),
            region: "eu".into(),
            ipv4: Some("1.2.3.4".into()),
            ipv6: None,
            port: 3478,
            probe_method: ProbeMethod::StunBinding,
        }],
        signature: "test".into(),
    };
    let json = serde_json::to_string(&candidates).unwrap();
    let _: TurnProbeCandidates = serde_json::from_str(&json).unwrap();

    let _offer = WebRtcSessionOffer {
        version: PROTOCOL_VERSION,
        message_type: SignalingMessageType::WebRtcSessionOffer,
        message_id: Uuid::new_v4(),
        session_id: req.session_id,
        target_fqhn: req.target_fqhn.clone(),
        source: req.source.clone(),
        sdp: req.sdp.clone(),
        ice: SessionIceConfig {
            relay_mode: IceRelayMode::Platform,
            stun_policy: StunPolicy::GoogleAndIdr,
            stun_servers: None,
            turn: None,
            byor: None,
            ice_transport_policy: idr_target::protocol::webrtc_ice::IceTransportPolicy::All,
            p2p_only: false,
        },
        session_token: "tok".into(),
        issued_at: Utc::now(),
        expires_at: Utc::now() + Duration::minutes(5),
        presence_generation: 1,
        signature: "sig".into(),
    };
}

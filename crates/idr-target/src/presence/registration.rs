use crate::config::{Config, WebRtcByorServerConfig};
use crate::identity::TargetIdentity;
use idr_protocol::crypto;
use idr_protocol::signaling::{PresenceRole, SignalingMessageType, TargetRegistration};
use idr_protocol::webrtc_ice::IceRelayMode;
use idr_protocol::webrtc_signaling::{
    default_webrtc_capabilities, BringYourOwnRelay, ByorIceServer, TargetWebRtcRegistration,
};
use idr_protocol::PROTOCOL_VERSION;

pub fn build_registration(
    identity: &TargetIdentity,
    fqhn: &str,
    connection_epoch: u64,
    discovery_generation: u64,
    role: PresenceRole,
    cfg: &Config,
    named_services: &[String],
) -> anyhow::Result<TargetRegistration> {
    let mut supported_transports = vec!["quic".into(), "ipv4".into(), "ipv6".into()];
    // Only advertise webrtc when the native feature is compiled in. Protocol/registration
    // types still compile without the feature so Presence/tests can exercise signaling.
    let webrtc = if cfg.webrtc.enabled && cfg!(feature = "webrtc") {
        supported_transports.push("webrtc".into());
        Some(build_webrtc_registration(cfg, named_services)?)
    } else {
        None
    };

    let entitlement_jwt = cfg.resolve_entitlement_jwt()?;

    let mut reg = TargetRegistration {
        version: PROTOCOL_VERSION,
        message_type: SignalingMessageType::RegisterTarget,
        target_fqhn: fqhn.to_string(),
        target_identity: identity.public_key_base64url(),
        connection_epoch,
        discovery_generation,
        role,
        supported_transports,
        using_party: cfg.billing_party.using_party.clone(),
        paying_party: cfg.billing_party.paying_party.clone(),
        entitlement_jwt,
        webrtc,
        signature: String::new(),
    };
    let value = serde_json::to_value(&reg)?;
    reg.signature = crypto::sign_json_canonical(&value, identity.signing_key())?;
    Ok(reg)
}

fn build_webrtc_registration(
    cfg: &Config,
    named_services: &[String],
) -> anyhow::Result<TargetWebRtcRegistration> {
    let relay_mode = cfg.webrtc.relay_mode();
    let byor = match relay_mode {
        IceRelayMode::Byor | IceRelayMode::Hybrid => {
            cfg.webrtc.byor.as_ref().map(build_byor).transpose()?
        }
        IceRelayMode::Platform => None,
    };

    if relay_mode == IceRelayMode::Byor && byor.is_none() {
        anyhow::bail!("[webrtc.byor] is required when relay_mode = \"byor\"");
    }

    let mut capabilities = default_webrtc_capabilities(cfg.webrtc.max_sessions);
    capabilities.named_services = named_services.to_vec();

    Ok(TargetWebRtcRegistration {
        agent_region: cfg.target.agent_region.clone(),
        relay_mode,
        stun_policy: cfg.webrtc.stun_policy(),
        capabilities,
        byor,
        turn_probe_supported: cfg.webrtc.turn_probe_enabled,
        ice_transport_policy: Default::default(),
    })
}

fn build_byor(byor: &crate::config::WebRtcByorConfig) -> anyhow::Result<BringYourOwnRelay> {
    if byor.turn_servers.is_empty() {
        anyhow::bail!("[webrtc.byor] requires at least one turn_servers entry");
    }
    Ok(BringYourOwnRelay {
        tenant_id: byor.tenant_id.clone(),
        stun_servers: byor.stun_servers.iter().map(map_byor_server).collect(),
        turn_servers: byor.turn_servers.iter().map(map_byor_server).collect(),
    })
}

fn map_byor_server(server: &WebRtcByorServerConfig) -> ByorIceServer {
    ByorIceServer {
        urls: server.urls.clone(),
        username: server.username.clone(),
        credential: server.credential.clone(),
        region: server.region.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::io::Write;

    #[test]
    fn registration_includes_webrtc_when_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("target.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        write!(
            f,
            r#"
[target]
fqhn = "host.idr.to"
agent_region = "eu-central"

[presence]
discovery_url = "https://example.com/idr-presence.json"
discovery_key = ""

[webrtc]
enabled = true
"#
        )
        .unwrap();
        let cfg = Config::load(&path).unwrap();
        let identity = TargetIdentity::load_or_generate(None).unwrap();
        let reg = build_registration(
            &identity,
            "host.idr.to",
            1,
            1,
            PresenceRole::Primary,
            &cfg,
            &[],
        )
        .unwrap();
        assert!(!reg.supported_transports.contains(&"webrtc".into()) || cfg!(feature = "webrtc"));
        if cfg!(feature = "webrtc") {
            assert!(reg.webrtc.is_some());
        } else {
            // Without native feature, do not advertise webrtc even if config.enabled.
            assert!(reg.webrtc.is_none());
        }
        reg.verify().unwrap();
    }
}

//! Convert protocol ICE servers into libdatachannel `RtcConfig` URL strings.

use idr_protocol::webrtc_ice::{IceServer, IceTransportPolicy};

/// Build ICE URL list for `RtcConfig::new`. TURN entries with username/credential
/// are rewritten to `turn:` / `turns:` URLs with embedded userinfo.
pub fn ice_servers_to_urls(servers: &[IceServer]) -> Vec<String> {
    let mut out = Vec::new();
    for server in servers {
        for url in &server.urls {
            out.push(embed_credentials(
                url,
                server.username.as_deref(),
                server.credential.as_deref(),
            ));
        }
    }
    out
}

pub fn transport_policy_to_native(policy: IceTransportPolicy) -> &'static str {
    match policy {
        IceTransportPolicy::All => "all",
        IceTransportPolicy::Relay => "relay",
    }
}

fn embed_credentials(url: &str, username: Option<&str>, credential: Option<&str>) -> String {
    let (Some(user), Some(pass)) = (username, credential) else {
        return url.to_string();
    };
    if url.contains('@') {
        return url.to_string();
    }
    let (scheme, rest) = if let Some(r) = url.strip_prefix("turns:") {
        ("turns", r)
    } else if let Some(r) = url.strip_prefix("turn:") {
        ("turn", r)
    } else {
        return url.to_string();
    };
    // Percent-encode minimal set for userinfo.
    let user = encode_userinfo(user);
    let pass = encode_userinfo(pass);
    format!("{scheme}:{user}:{pass}@{rest}")
}

fn encode_userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embeds_turn_credentials() {
        let servers = vec![IceServer {
            urls: vec!["turn:turn.example:3478".into()],
            username: Some("user".into()),
            credential: Some("pass".into()),
        }];
        let urls = ice_servers_to_urls(&servers);
        assert_eq!(urls[0], "turn:user:pass@turn.example:3478");
    }

    #[test]
    fn leaves_stun_alone() {
        let servers = vec![IceServer {
            urls: vec!["stun:stun.l.google.com:19302".into()],
            username: None,
            credential: None,
        }];
        assert_eq!(
            ice_servers_to_urls(&servers)[0],
            "stun:stun.l.google.com:19302"
        );
    }
}

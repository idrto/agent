//! Per-stream enforcement of the Source policy Presence verified and signed.
//!
//! The policy rides in the Presence-signed offer (`source.policy`), which the
//! Target already verified, so no billing call happens here.

use idr_protocol::webrtc_signaling::SourcePolicy;

/// Whether a stream to `service` may open. `require` is
/// `[webrtc.policy].require_source_policy`: Sources without a verified
/// policy are refused. A policy allows `service` when it lists it or `"*"`.
pub fn service_allowed(
    policy: Option<&SourcePolicy>,
    require: bool,
    service: &str,
) -> Result<(), &'static str> {
    match policy {
        None if require => Err("this Target only serves verified, enrolled Sources"),
        None => Ok(()),
        Some(p) if p.allowed_services.iter().any(|s| s == "*" || s == service) => Ok(()),
        Some(_) => Err("service not allowed for this Source's zone"),
    }
}

/// The catalog names a Source may see (same rule as opening).
pub fn visible<T>(
    policy: Option<&SourcePolicy>,
    require: bool,
    items: Vec<T>,
    name: impl Fn(&T) -> &str,
) -> Vec<T> {
    items
        .into_iter()
        .filter(|item| service_allowed(policy, require, name(item)).is_ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zone(services: &[&str]) -> SourcePolicy {
        SourcePolicy {
            ski: "member".into(),
            zone: Some("zone-a".into()),
            allowed_services: services.iter().map(|s| s.to_string()).collect(),
            policy_version: 2,
        }
    }

    #[test]
    fn zone_policy_allows_only_its_services() {
        let p = zone(&["ollama"]);
        assert!(service_allowed(Some(&p), true, "ollama").is_ok());
        assert!(service_allowed(Some(&p), true, "lmstudio").is_err());
        assert!(
            service_allowed(Some(&p), false, "lmstudio").is_err(),
            "a policy always applies"
        );
        assert!(
            service_allowed(Some(&p), true, "http").is_err(),
            "passthrough is a service too"
        );
        assert!(service_allowed(Some(&zone(&["*"])), true, "anything").is_ok());
    }

    #[test]
    fn unverified_sources_depend_on_require_source_policy() {
        assert!(service_allowed(None, false, "ollama").is_ok());
        assert!(service_allowed(None, true, "ollama").is_err());
    }

    #[test]
    fn catalog_lists_only_allowed_services() {
        let p = zone(&["ollama"]);
        let names = vec!["ollama".to_string(), "lmstudio".to_string()];
        assert_eq!(
            visible(Some(&p), true, names.clone(), |n| n),
            vec!["ollama"]
        );
        assert_eq!(visible(None, false, names.clone(), |n| n), names);
        assert!(visible(None, true, names, |n| n).is_empty());
    }
}

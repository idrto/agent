//! In-band `dp.credential.v1` AuthZ frame (matches `@2key/dp-presentation`).

use dp_rust::CapabilityCredential;
use serde::{Deserialize, Serialize};

use crate::identity::DpIdentityError;

/// Wire type for the first application frame after PEP transport AuthN.
pub const DP_CREDENTIAL_FRAME_TYPE: &str = "dp.credential.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DpCredentialFrame {
    #[serde(rename = "type")]
    pub frame_type: String,
    pub credential: CapabilityCredential,
}

/// Encode CapabilityCredential as UTF-8 JSON `dp.credential.v1` bytes.
pub fn encode_credential_frame(
    credential: &CapabilityCredential,
) -> Result<Vec<u8>, DpIdentityError> {
    let frame = DpCredentialFrame {
        frame_type: DP_CREDENTIAL_FRAME_TYPE.into(),
        credential: credential.clone(),
    };
    serde_json::to_vec(&frame).map_err(|e| DpIdentityError::Json(e.to_string()))
}

/// Parse an in-band credential frame; `None` if not `dp.credential.v1`.
pub fn parse_credential_frame(bytes: &[u8]) -> Option<DpCredentialFrame> {
    let parsed: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let ty = parsed.get("type")?.as_str()?;
    if ty != DP_CREDENTIAL_FRAME_TYPE {
        return None;
    }
    serde_json::from_value(parsed).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use dp_rust::{Capability, CredentialKind};

    fn sample_cred() -> CapabilityCredential {
        CapabilityCredential {
            version: 1,
            kind: CredentialKind::Machine,
            entity_id: "acme.example".into(),
            ski: "ski1".into(),
            public_jwk: serde_json::json!({"kty":"OKP","crv":"Ed25519","x":"x"}),
            permissions: vec![Capability {
                action: "machine.connect".into(),
                scope: serde_json::json!({"name":"db1"}),
                delegable: false,
            }],
            zone: None,
            host: Some("db1--acme.example".into()),
            issuer_ski: "issuer".into(),
            not_before: "2026-01-01T00:00:00.000Z".into(),
            not_after: "2027-01-01T00:00:00.000Z".into(),
            package: None,
            platform_cosign: None,
            signature: "hdr.payload.sig".into(),
        }
    }

    #[test]
    fn roundtrips_credential_frame() {
        let bytes = encode_credential_frame(&sample_cred()).unwrap();
        let frame = parse_credential_frame(&bytes).unwrap();
        assert_eq!(frame.frame_type, DP_CREDENTIAL_FRAME_TYPE);
        assert_eq!(frame.credential.ski, "ski1");
    }

    #[test]
    fn rejects_other_types() {
        let junk = br#"{"type":"other","credential":{}}"#;
        assert!(parse_credential_frame(junk).is_none());
    }
}

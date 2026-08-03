//! Offline `CapabilityCredential` issuance (Ed25519 compact JWS).
//!
//! Mirrors `issueCredential` in
//! `packages/better-auth/src/plugins/delegate-permissions/pki/credential.ts`
//! byte-for-byte for the canonical signing payload, so credentials minted
//! here (e.g. `identity enroll --local`, `cert approve`) verify against
//! `verifyCredentialSignature` on a Better Auth `delegate-permissions`
//! deployment without ever sending the issuer's private key over the wire.
//!
//! Requires `serde_json`'s `preserve_order` feature (enabled by this crate)
//! so JSON object keys serialize in insertion order like `JSON.stringify`,
//! not alphabetically.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use dp_rust::{Capability, CapabilityCredential, CredentialKind, EntityPackage};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("issuer private JWK missing Ed25519 d parameter")]
    MissingIssuerKey,
    #[error("invalid base64 in issuer JWK: {0}")]
    Base64(String),
    #[error("invalid Ed25519 key length")]
    BadKeyLength,
    #[error("json: {0}")]
    Json(String),
}

/// Inputs for [`issue_credential`]. Mirrors `issueCredential`'s TS input
/// shape; `subject_ski`/`subject_public_jwk` replace `subject: KeyPairMaterial`
/// since the private half never needs to be here.
pub struct IssueCredentialParams<'a> {
    pub kind: CredentialKind,
    pub entity_id: &'a str,
    pub subject_ski: &'a str,
    pub subject_public_jwk: Value,
    pub permissions: Vec<Capability>,
    pub issuer_ski: &'a str,
    pub issuer_private_jwk: &'a Value,
    pub zone: Option<&'a str>,
    pub host: Option<&'a str>,
    pub package: Option<EntityPackage>,
    /// Defaults to now.
    pub not_before: Option<DateTime<Utc>>,
    /// Defaults to 365 days.
    pub ttl_seconds: Option<i64>,
}

fn signing_key_from_jwk(jwk: &Value) -> Result<SigningKey, CredentialError> {
    let d = jwk
        .get("d")
        .and_then(|v| v.as_str())
        .ok_or(CredentialError::MissingIssuerKey)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(d)
        .map_err(|e| CredentialError::Base64(e.to_string()))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| CredentialError::BadKeyLength)?;
    Ok(SigningKey::from_bytes(&seed))
}

fn credential_kind_str(kind: &CredentialKind) -> &'static str {
    match kind {
        CredentialKind::EntityRoot => "entity_root",
        CredentialKind::RootAdmin => "root_admin",
        CredentialKind::InterimAdmin => "interim_admin",
        CredentialKind::ZoneAuthority => "zone_authority",
        CredentialKind::Machine => "machine",
    }
}

fn package_str(pkg: &EntityPackage) -> &'static str {
    match pkg {
        EntityPackage::Personal => "personal",
        EntityPackage::Enterprise => "enterprise",
    }
}

fn iso_millis(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

#[allow(clippy::too_many_arguments)]
fn canonical_payload(
    kind: &CredentialKind,
    entity_id: &str,
    ski: &str,
    public_jwk: &Value,
    permissions: &[Capability],
    zone: Option<&str>,
    host: Option<&str>,
    issuer_ski: &str,
    not_before: &str,
    not_after: &str,
    package: Option<&EntityPackage>,
) -> Result<Vec<u8>, CredentialError> {
    let mut ordered = Map::new();
    ordered.insert("version".into(), Value::from(1));
    ordered.insert("kind".into(), Value::from(credential_kind_str(kind)));
    ordered.insert("entityId".into(), Value::from(entity_id));
    ordered.insert("ski".into(), Value::from(ski));
    ordered.insert("publicJwk".into(), public_jwk.clone());
    let perms =
        serde_json::to_value(permissions).map_err(|e| CredentialError::Json(e.to_string()))?;
    ordered.insert("permissions".into(), perms);
    ordered.insert("zone".into(), zone.map(Value::from).unwrap_or(Value::Null));
    ordered.insert("host".into(), host.map(Value::from).unwrap_or(Value::Null));
    ordered.insert("issuerSki".into(), Value::from(issuer_ski));
    ordered.insert("notBefore".into(), Value::from(not_before));
    ordered.insert("notAfter".into(), Value::from(not_after));
    ordered.insert(
        "package".into(),
        package
            .map(package_str)
            .map(Value::from)
            .unwrap_or(Value::Null),
    );
    serde_json::to_vec(&Value::Object(ordered)).map_err(|e| CredentialError::Json(e.to_string()))
}

/// Sign a `CapabilityCredential` for `subject` with `issuer_private_jwk`,
/// producing the same compact-JWS `signature` field a Better Auth
/// `delegate-permissions` server would (via `issueCredential`).
pub fn issue_credential(
    params: IssueCredentialParams<'_>,
) -> Result<CapabilityCredential, CredentialError> {
    let now = Utc::now();
    let not_before = params.not_before.unwrap_or(now);
    let ttl = params.ttl_seconds.unwrap_or(365 * 24 * 60 * 60);
    let not_after = not_before + Duration::seconds(ttl);
    let not_before_s = iso_millis(not_before);
    let not_after_s = iso_millis(not_after);

    let payload = canonical_payload(
        &params.kind,
        params.entity_id,
        params.subject_ski,
        &params.subject_public_jwk,
        &params.permissions,
        params.zone,
        params.host,
        params.issuer_ski,
        &not_before_s,
        &not_after_s,
        params.package.as_ref(),
    )?;

    let signing_key = signing_key_from_jwk(params.issuer_private_jwk)?;
    let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA"}"#);
    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let compact = format!("{signing_input}.{sig_b64}");

    Ok(CapabilityCredential {
        version: 1,
        kind: params.kind,
        entity_id: params.entity_id.to_string(),
        ski: params.subject_ski.to_string(),
        public_jwk: params.subject_public_jwk,
        permissions: params.permissions,
        zone: params.zone.map(str::to_string),
        host: params.host.map(str::to_string),
        issuer_ski: params.issuer_ski.to_string(),
        not_before: not_before_s,
        not_after: not_after_s,
        package: params.package,
        platform_cosign: None,
        signature: compact,
    })
}

/// Sign an arbitrary payload as a compact JWS with header `{"alg":"EdDSA"}`.
pub fn sign_compact_eddsa(private_jwk: &Value, payload: &[u8]) -> Result<String, CredentialError> {
    let signing_key = signing_key_from_jwk(private_jwk)?;
    let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA"}"#);
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    Ok(format!("{signing_input}.{sig_b64}"))
}

/// RFC 7638 JWK thumbprint for an OKP/Ed25519 public JWK, matching
/// `dp_rust_mtls`'s internal `ski_from_public_jwk_parts` (and thus any SKI a
/// sibling `generate_key_and_csr` call already embedded in a CSR's SAN).
pub fn ski_from_public_jwk(public_jwk: &Value) -> String {
    let kty = public_jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .unwrap_or("OKP");
    let crv = public_jwk
        .get("crv")
        .and_then(|v| v.as_str())
        .unwrap_or("Ed25519");
    let x = public_jwk.get("x").and_then(|v| v.as_str()).unwrap_or("");
    let material = format!(
        "{{\"kty\":{},\"crv\":{},\"x\":{}}}",
        serde_json::to_string(kty).unwrap_or_default(),
        serde_json::to_string(crv).unwrap_or_default(),
        serde_json::to_string(x).unwrap_or_default(),
    );
    let digest = Sha256::digest(material.as_bytes());
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()[..32]
        .to_string()
}

/// Build a public JWK from a raw 32-byte Ed25519 public key (e.g. extracted
/// from a CSR by `idr-enroll`'s minimal CSR parser).
pub fn public_jwk_from_raw_ed25519(pubkey: &[u8; 32]) -> Value {
    serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode(pubkey),
        "alg": "EdDSA",
    })
}

/// Minimal fallback `machine.connect` capability, scoped to `host`, used only
/// when neither `--permissions` nor a reachable
/// `/delegate-permissions/enroll-machine-permissions` admin endpoint is
/// available. Prefer the catalog-driven default in real deployments.
pub fn default_machine_capability(entity_id: &str, host: &str) -> Vec<Capability> {
    vec![Capability {
        action: "machine.connect".into(),
        scope: serde_json::json!({ "entity": entity_id, "name": host }),
        delegable: false,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use ed25519_dalek::VerifyingKey;

    fn issuer_jwk() -> (Value, SigningKey) {
        let signing = SigningKey::from_bytes(&[3u8; 32]);
        let d = B64.encode(signing.to_bytes());
        let x = B64.encode(signing.verifying_key().to_bytes());
        (
            serde_json::json!({"kty":"OKP","crv":"Ed25519","d": d, "x": x, "alg":"EdDSA"}),
            signing,
        )
    }

    #[test]
    fn issues_and_self_verifies_machine_credential() {
        let (issuer_priv, issuer_signing) = issuer_jwk();
        let issuer_ski = ski_from_public_jwk(&serde_json::json!({
            "kty":"OKP","crv":"Ed25519","x": B64.encode(issuer_signing.verifying_key().to_bytes())
        }));
        let subject_signing = SigningKey::from_bytes(&[9u8; 32]);
        let subject_pub = subject_signing.verifying_key().to_bytes();
        let subject_public_jwk = public_jwk_from_raw_ed25519(&subject_pub);
        let subject_ski = ski_from_public_jwk(&subject_public_jwk);

        let credential = issue_credential(IssueCredentialParams {
            kind: CredentialKind::Machine,
            entity_id: "acme.example",
            subject_ski: &subject_ski,
            subject_public_jwk: subject_public_jwk.clone(),
            permissions: default_machine_capability("acme.example", "db1--acme.example"),
            issuer_ski: &issuer_ski,
            issuer_private_jwk: &issuer_priv,
            zone: None,
            host: Some("db1--acme.example"),
            package: None,
            not_before: None,
            ttl_seconds: None,
        })
        .expect("issue_credential");

        assert_eq!(credential.ski, subject_ski);
        assert_eq!(credential.host.as_deref(), Some("db1--acme.example"));
        assert_eq!(credential.signature.matches('.').count(), 2);

        // Re-verify the compact JWS ourselves (mirrors verifyCredentialSignature).
        let mut parts = credential.signature.split('.');
        let header_b64 = parts.next().unwrap();
        let payload_b64 = parts.next().unwrap();
        let sig_b64 = parts.next().unwrap();
        assert_eq!(
            String::from_utf8(B64.decode(header_b64).unwrap()).unwrap(),
            r#"{"alg":"EdDSA"}"#
        );
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig_bytes = B64.decode(sig_b64).unwrap();
        let signature = ed25519_dalek::Signature::from_slice(&sig_bytes).unwrap();
        let verifying: VerifyingKey = issuer_signing.verifying_key();
        verifying
            .verify_strict(signing_input.as_bytes(), &signature)
            .expect("issuer signature verifies");

        let expected_payload = canonical_payload(
            &CredentialKind::Machine,
            "acme.example",
            &subject_ski,
            &subject_public_jwk,
            &credential.permissions,
            None,
            Some("db1--acme.example"),
            &issuer_ski,
            &credential.not_before,
            &credential.not_after,
            None,
        )
        .unwrap();
        assert_eq!(B64.decode(payload_b64).unwrap(), expected_payload);
    }

    #[test]
    fn compact_eddsa_signs_the_exact_payload() {
        let (private_jwk, signing) = issuer_jwk();
        let payload = br#"{"ski":"device-1","ts":1735689600}"#;
        let compact = sign_compact_eddsa(&private_jwk, payload).unwrap();
        let parts: Vec<_> = compact.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(B64.decode(parts[0]).unwrap(), br#"{"alg":"EdDSA"}"#);
        assert_eq!(B64.decode(parts[1]).unwrap(), payload);

        let signature =
            ed25519_dalek::Signature::from_slice(&B64.decode(parts[2]).unwrap()).unwrap();
        signing
            .verifying_key()
            .verify_strict(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn compact_eddsa_rejects_non_seed_private_keys() {
        let bad = serde_json::json!({
            "d": B64.encode([7_u8; 31])
        });
        assert!(matches!(
            sign_compact_eddsa(&bad, b"payload"),
            Err(CredentialError::BadKeyLength)
        ));
    }
}

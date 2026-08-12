//! Ed25519 / CSR helpers for Target SDK (`IdrCrypto` shape).

use dp_rust_mtls::{
    build_csr_from_private_pem, ca_cert_pem_from_private_jwk, generate_ed25519,
    sign_client_cert_from_csr, sign_json_b64url, sign_message_b64url, ski_from_csr_pem,
    ski_from_public_b64url, GeneratedEd25519, MtlsError, SignClientCertFromCsrParams,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DpCryptoError {
    #[error(transparent)]
    Mtls(#[from] MtlsError),
    #[error("json: {0}")]
    Json(String),
}

/// PEM + JWK key material matching Dart `Ed25519KeyMaterial`.
#[derive(Debug, Clone, Serialize)]
pub struct Ed25519KeyMaterialJson {
    pub private_pem: String,
    pub public_pem: String,
    pub public_b64url: String,
    pub public_jwk: serde_json::Value,
    pub ski: String,
}

impl From<GeneratedEd25519> for Ed25519KeyMaterialJson {
    fn from(g: GeneratedEd25519) -> Self {
        Self {
            private_pem: g.private_pem,
            public_pem: g.public_pem,
            public_b64url: g.public_b64url,
            public_jwk: g.public_jwk,
            ski: g.ski,
        }
    }
}

/// Issued leaf + chain PEMs from CSR signing.
#[derive(Debug, Clone, Serialize)]
pub struct SignedLeafJson {
    pub leaf_pem: String,
    pub chain_pem: String,
}

pub fn generate_ed25519_material() -> Result<Ed25519KeyMaterialJson, DpCryptoError> {
    Ok(generate_ed25519()?.into())
}

pub fn build_csr(private_pem: &str, fqhn: &str) -> Result<String, DpCryptoError> {
    Ok(build_csr_from_private_pem(private_pem, fqhn)?)
}

pub fn sign(private_pem: &str, message: &[u8]) -> Result<String, DpCryptoError> {
    Ok(sign_message_b64url(private_pem, message)?)
}

pub fn sign_json(private_pem: &str, json: &str) -> Result<String, DpCryptoError> {
    Ok(sign_json_b64url(private_pem, json)?)
}

pub fn ski(public_b64url: &str) -> String {
    ski_from_public_b64url(public_b64url)
}

pub fn generate_ed25519_json() -> Result<String, DpCryptoError> {
    let mat = generate_ed25519_material()?;
    serde_json::to_string(&mat).map_err(|e| DpCryptoError::Json(e.to_string()))
}

/// Sign CSR with CA private JWK. Re-derives CA cert using common_name (= issuer_ski by convention).
pub fn sign_csr_with_ca_jwk(
    csr_pem: &str,
    ca_private_jwk_json: &str,
    issuer_ski: &str,
    host: Option<&str>,
) -> Result<SignedLeafJson, DpCryptoError> {
    let ca_private_jwk: serde_json::Value = serde_json::from_str(ca_private_jwk_json)
        .map_err(|e| DpCryptoError::Json(e.to_string()))?;
    let ca_cert_pem = ca_cert_pem_from_private_jwk(&ca_private_jwk, issuer_ski)?;
    let leaf_ski = ski_from_csr_pem(csr_pem)?;
    let signed = sign_client_cert_from_csr(SignClientCertFromCsrParams {
        csr_pem,
        ca_cert_pem: &ca_cert_pem,
        ca_private_jwk: &ca_private_jwk,
        ca_common_name: issuer_ski,
        ski: &leaf_ski,
        host,
        not_after_days: None,
    })?;
    Ok(SignedLeafJson {
        leaf_pem: signed.leaf_pem,
        chain_pem: signed.chain_pem,
    })
}

pub fn sign_csr_with_ca_jwk_json(
    csr_pem: &str,
    ca_private_jwk_json: &str,
    issuer_ski: &str,
    host: Option<&str>,
) -> Result<String, DpCryptoError> {
    let signed = sign_csr_with_ca_jwk(csr_pem, ca_private_jwk_json, issuer_ski, host)?;
    serde_json::to_string(&signed).map_err(|e| DpCryptoError::Json(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dp_rust_mtls::create_self_signed_ca;

    #[test]
    fn keygen_csr_ski_sign_roundtrip() {
        let mat = generate_ed25519_material().expect("keygen");
        assert!(mat.private_pem.contains("PRIVATE KEY"));
        assert!(!mat.public_b64url.is_empty());
        assert_eq!(ski(&mat.public_b64url), mat.ski);
        let csr = build_csr(&mat.private_pem, "smoke.test.idrto.local").expect("csr");
        assert!(csr.contains("CERTIFICATE REQUEST"));
        let sig = sign(&mat.private_pem, b"hello").expect("sign");
        assert!(!sig.is_empty());
        let sig_j = sign_json(&mat.private_pem, r#"{"a":1}"#).expect("sign_json");
        assert!(!sig_j.is_empty());
    }

    #[test]
    fn sign_csr_with_ca_jwk_issues_leaf_and_chain() {
        let ca = create_self_signed_ca("unused-cn").expect("ca");
        let mat = generate_ed25519_material().expect("device");
        let csr = build_csr(&mat.private_pem, "device--acme.example").expect("csr");
        let jwk = serde_json::to_string(&ca.private_jwk).expect("jwk json");
        // Helper re-derives CA with common_name = issuer_ski.
        let signed = sign_csr_with_ca_jwk(&csr, &jwk, &ca.ski, Some("device--acme.example"))
            .expect("sign_csr");
        assert!(signed.leaf_pem.contains("BEGIN CERTIFICATE"));
        assert!(signed.chain_pem.contains(&signed.leaf_pem.trim()));
        assert!(signed.chain_pem.contains("BEGIN CERTIFICATE"));
        let json = sign_csr_with_ca_jwk_json(&csr, &jwk, &ca.ski, None).expect("json");
        assert!(json.contains("leaf_pem"));
        assert!(json.contains("chain_pem"));
    }
}

//! Auth.idr.to agent entitlement JWT mint client.

use anyhow::{Context, Result};
use idr_dp::{sign_compact_eddsa, DeviceIdentity};
use serde::{Deserialize, Serialize};

/// Runtime config for minting Presence entitlement JWTs.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct AuthConfig {
    /// Better Auth mount, e.g. `https://auth.idr.to/api/auth`.
    #[serde(default = "default_auth_url")]
    pub url: String,
    /// Path under `url` for agent token mint (default `/agent/token`).
    #[serde(default = "default_token_path")]
    pub token_path: String,
    /// When true (default), fail Presence connect if mint fails.
    /// When false, register without JWT (Presence must have auth.enabled=false).
    #[serde(default = "default_required")]
    pub required: bool,
}

fn default_auth_url() -> String {
    "https://auth.idr.to/api/auth".into()
}

fn default_token_path() -> String {
    "/agent/token".into()
}

fn default_required() -> bool {
    true
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            url: default_auth_url(),
            token_path: default_token_path(),
            required: default_required(),
        }
    }
}

impl AuthConfig {
    pub fn token_url(&self) -> String {
        let base = self.url.trim_end_matches('/');
        let path = if self.token_path.starts_with('/') {
            self.token_path.clone()
        } else {
            format!("/{}", self.token_path)
        };
        format!("{base}{path}")
    }
}

#[derive(Debug, Serialize)]
struct MintRequest<'a> {
    credential: &'a serde_json::Value,
    proof: MintProof,
    #[serde(rename = "targetIdentity", skip_serializing_if = "Option::is_none")]
    target_identity: Option<&'a str>,
    #[serde(rename = "usingParty", skip_serializing_if = "Option::is_none")]
    using_party: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct MintProof {
    ts: i64,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct MintSuccessEnvelope {
    #[serde(default)]
    success: Option<bool>,
    data: Option<MintTokenData>,
    /// Some deployments may return the token at the top level.
    token: Option<String>,
    #[serde(rename = "expiresIn")]
    expires_in: Option<u64>,
}

fn parse_mint_response(text: &str) -> Result<(String, Option<u64>)> {
    let parsed: MintSuccessEnvelope =
        serde_json::from_str(text).with_context(|| format!("decode mint response: {text}"))?;
    if parsed.success == Some(false) {
        anyhow::bail!("agent token mint returned success=false: {text}");
    }
    let result = if let Some(data) = parsed.data {
        (data.token, data.expires_in.or(parsed.expires_in))
    } else if let Some(token) = parsed.token {
        (token, parsed.expires_in)
    } else {
        anyhow::bail!("mint response missing token: {text}");
    };
    if result.0.trim().is_empty() {
        anyhow::bail!("mint response contains an empty token");
    }
    Ok(result)
}

#[derive(Debug, Deserialize)]
struct MintTokenData {
    token: String,
    #[serde(rename = "expiresIn")]
    expires_in: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct AgentEntitlementToken {
    pub token: String,
    pub expires_in: Option<u64>,
    pub using_party: Option<String>,
    pub paying_party: Option<String>,
}

/// Mint a Presence entitlement JWT using DeviceIdentity proof-of-possession.
pub async fn mint_agent_token(
    auth: &AuthConfig,
    identity: &DeviceIdentity,
    target_identity: Option<&str>,
    using_party: Option<&str>,
) -> Result<AgentEntitlementToken> {
    let ts = chrono::Utc::now().timestamp();
    let proof_payload = serde_json::to_vec(&serde_json::json!({
        "ski": identity.ski,
        "ts": ts,
    }))
    .context("serialize PoP payload")?;
    let signature = sign_compact_eddsa(&identity.private_jwk, &proof_payload)
        .map_err(|e| anyhow::anyhow!("PoP sign failed: {e}"))?;

    let credential =
        serde_json::to_value(&identity.credential).context("serialize CapabilityCredential")?;

    let body = MintRequest {
        credential: &credential,
        proof: MintProof { ts, signature },
        target_identity,
        using_party,
    };

    let url = auth.token_url();
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .context("build agent token HTTP client")?;
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("agent token mint failed ({status}): {text}");
    }

    let (token, expires_in) = parse_mint_response(&text)?;
    let expires_in =
        expires_in.or_else(|| decode_token_expires_in(&token, chrono::Utc::now().timestamp()));

    // Best-effort decode claims for local party fields (Presence trusts JWT).
    let (using_party, paying_party) = decode_party_claims(&token);

    Ok(AgentEntitlementToken {
        token,
        expires_in,
        using_party,
        paying_party,
    })
}

fn decode_party_claims(token: &str) -> (Option<String>, Option<String>) {
    let Some(value) = decode_jwt_payload(token) else {
        return (None, None);
    };
    (
        value
            .get("using_party")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        value
            .get("paying_party")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    )
}

fn decode_jwt_payload(token: &str) -> Option<serde_json::Value> {
    let parts: Vec<&str> = token.split('.').collect();
    let payload = (parts.len() == 3).then_some(parts[1])?;
    use base64::Engine;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn decode_token_expires_in(token: &str, now: i64) -> Option<u64> {
    let exp = decode_jwt_payload(token)?.get("exp")?.as_i64()?;
    u64::try_from(exp.checked_sub(now)?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_is_required_by_default() {
        assert!(AuthConfig::default().required);
        let parsed: AuthConfig = toml::from_str("").unwrap();
        assert!(parsed.required);
    }

    #[test]
    fn mint_request_matches_billing_json_contract() {
        let credential = serde_json::json!({
            "ski": "device-ski",
            "kind": "machine",
            "entityId": "acme.example",
            "publicJwk": {"kty": "OKP", "crv": "Ed25519", "x": "abc"}
        });
        let body = MintRequest {
            credential: &credential,
            proof: MintProof {
                ts: 1_735_689_600,
                signature: "header.payload.signature".into(),
            },
            target_identity: Some("target-key"),
            using_party: Some("alice@acme.example"),
        };

        assert_eq!(
            serde_json::to_value(body).unwrap(),
            serde_json::json!({
                "credential": credential,
                "proof": {
                    "ts": 1_735_689_600_i64,
                    "signature": "header.payload.signature"
                },
                "targetIdentity": "target-key",
                "usingParty": "alice@acme.example"
            })
        );
    }

    #[test]
    fn parses_billing_success_envelope() {
        let (token, expires_in) = parse_mint_response(
            r#"{"success":true,"data":{"token":"jwt","expiresIn":3600,"token_type":"Bearer"}}"#,
        )
        .unwrap();
        assert_eq!(token, "jwt");
        assert_eq!(expires_in, Some(3600));
    }

    #[test]
    fn rejects_explicit_unsuccessful_envelope() {
        let err = parse_mint_response(r#"{"success":false,"token":"jwt"}"#).unwrap_err();
        assert!(err.to_string().contains("success=false"));
    }

    #[test]
    fn derives_expiry_from_standard_jwt_claim() {
        use base64::Engine;
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"exp":2000}"#);
        let token = format!("header.{payload}.signature");
        assert_eq!(decode_token_expires_in(&token, 1000), Some(1000));
        assert_eq!(decode_token_expires_in(&token, 2001), None);
    }
}

//! HTTP client for the Better Auth `delegate-permissions` enroll/admin API.
//!
//! Endpoint shapes mirror
//! `packages/better-auth/src/plugins/delegate-permissions/{enroll,credentials}.ts`.
//! `base_url` should be the Better Auth mount point, e.g.
//! `http://127.0.0.1:3000/api/auth` — this client posts to
//! `{base_url}/delegate-permissions/<path>`.

use dp_rust::CapabilityCredential;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnrollClientError {
    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("delegate-permissions API error ({status}): {body}")]
    Api { status: u16, body: String },
    #[error("could not decode response: {0}")]
    Decode(String),
}

/// Better Auth session credentials for admin-only endpoints
/// (`enroll-list`/`enroll-approve`/`enroll-reject`/`enroll-instant`/
/// `enroll-machine-permissions`/`kickstart-entity`, all behind `sessionMiddleware`).
#[derive(Debug, Clone, Default)]
pub struct AuthOptions {
    /// Raw `Cookie` header value, e.g. `better-auth.session_token=...`.
    pub cookie: Option<String>,
    /// Bearer token, when the deployment uses Better Auth's bearer plugin.
    pub bearer: Option<String>,
}

impl AuthOptions {
    pub fn is_empty(&self) -> bool {
        self.cookie.is_none() && self.bearer.is_none()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrollCreateRequest<'a> {
    #[serde(rename = "entityId")]
    pub entity_id: &'a str,
    pub host: &'a str,
    pub role: &'a str,
    #[serde(rename = "csrPem")]
    pub csr_pem: &'a str,
    #[serde(rename = "publicJwk")]
    pub public_jwk: &'a Value,
    #[serde(rename = "subjectSki", skip_serializing_if = "Option::is_none")]
    pub subject_ski: Option<&'a str>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnrollCreateResponse {
    #[serde(rename = "enrollId")]
    pub enroll_id: String,
    #[serde(rename = "pullToken")]
    pub pull_token: String,
    #[serde(rename = "subjectSki")]
    pub subject_ski: String,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnrollSummary {
    #[serde(rename = "enrollId")]
    pub enroll_id: String,
    pub host: String,
    pub role: String,
    #[serde(rename = "subjectSki")]
    pub subject_ski: String,
    pub status: String,
    #[serde(rename = "createdAt")]
    pub created_at: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnrollListResponse {
    pub enrollments: Vec<EnrollSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrollApproveRequest<'a> {
    #[serde(rename = "enrollId")]
    pub enroll_id: &'a str,
    #[serde(rename = "leafPem")]
    pub leaf_pem: &'a str,
    #[serde(rename = "chainPem")]
    pub chain_pem: &'a str,
    pub credential: &'a CapabilityCredential,
    #[serde(rename = "issuerSki")]
    pub issuer_ski: &'a str,
    #[serde(rename = "payingPartyId", skip_serializing_if = "Option::is_none")]
    pub paying_party_id: Option<&'a str>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnrollApproveResponse {
    #[serde(rename = "enrollId")]
    pub enroll_id: String,
    pub status: String,
    #[serde(rename = "pullToken")]
    pub pull_token: String,
    #[serde(rename = "seatId")]
    pub seat_id: Option<String>,
    #[serde(rename = "platformCertCosign")]
    pub platform_cert_cosign: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrollRejectRequest<'a> {
    #[serde(rename = "enrollId")]
    pub enroll_id: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnrollRejectResponse {
    #[serde(rename = "enrollId")]
    pub enroll_id: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrollPullRequest<'a> {
    #[serde(rename = "pullToken")]
    pub pull_token: &'a str,
}

/// Flattened union of the `enroll-pull` pending/rejected/approved response
/// shapes; only fields relevant to `status` are populated.
#[derive(Debug, Clone, Deserialize)]
pub struct EnrollPullResponse {
    pub status: String,
    #[serde(rename = "enrollId")]
    pub enroll_id: String,
    pub host: Option<String>,
    pub role: Option<String>,
    pub ski: Option<String>,
    #[serde(rename = "publicJwk")]
    pub public_jwk: Option<Value>,
    #[serde(rename = "certPem")]
    pub cert_pem: Option<String>,
    #[serde(rename = "chainPem")]
    pub chain_pem: Option<String>,
    pub credential: Option<CapabilityCredential>,
    #[serde(rename = "platformCertCosign")]
    pub platform_cert_cosign: Option<Value>,
    #[serde(rename = "seatId")]
    pub seat_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrollInstantRequest<'a> {
    #[serde(rename = "entityId")]
    pub entity_id: &'a str,
    pub host: &'a str,
    pub role: &'a str,
    #[serde(rename = "csrPem")]
    pub csr_pem: &'a str,
    #[serde(rename = "publicJwk")]
    pub public_jwk: &'a Value,
    #[serde(rename = "subjectSki", skip_serializing_if = "Option::is_none")]
    pub subject_ski: Option<&'a str>,
    #[serde(rename = "leafPem")]
    pub leaf_pem: &'a str,
    #[serde(rename = "chainPem")]
    pub chain_pem: &'a str,
    pub credential: &'a CapabilityCredential,
    #[serde(rename = "issuerSki")]
    pub issuer_ski: &'a str,
    #[serde(rename = "payingPartyId", skip_serializing_if = "Option::is_none")]
    pub paying_party_id: Option<&'a str>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnrollInstantResponse {
    #[serde(rename = "enrollId")]
    pub enroll_id: String,
    pub status: String,
    pub ski: String,
    pub host: String,
    #[serde(rename = "certPem")]
    pub cert_pem: String,
    #[serde(rename = "chainPem")]
    pub chain_pem: String,
    pub credential: CapabilityCredential,
    #[serde(rename = "platformCertCosign")]
    pub platform_cert_cosign: Option<Value>,
    #[serde(rename = "seatId")]
    pub seat_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrollMachinePermissionsRequest<'a> {
    #[serde(rename = "entityId")]
    pub entity_id: &'a str,
    pub host: &'a str,
    pub role: &'a str,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnrollMachinePermissionsResponse {
    pub permissions: Vec<dp_rust::Capability>,
    #[serde(rename = "nameKey")]
    pub name_key: String,
    #[serde(rename = "entityId")]
    pub entity_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct KickstartEntityRequest<'a> {
    #[serde(rename = "entityId")]
    pub entity_id: &'a str,
    pub package: &'a str,
}

/// The `kickstart-entity` response shape depends on server-keygen vs
/// client-keyed mode; left as raw JSON for callers to pick fields from.
pub type KickstartEntityResponse = Value;

#[derive(Clone)]
pub struct EnrollClient {
    http: reqwest::Client,
    base_url: String,
}

impl EnrollClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            http: reqwest::Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}/delegate-permissions/{}", self.base_url, path)
    }

    fn with_auth(&self, mut req: reqwest::RequestBuilder, auth: &AuthOptions) -> reqwest::RequestBuilder {
        if let Some(cookie) = &auth.cookie {
            req = req.header(reqwest::header::COOKIE, cookie.clone());
        }
        if let Some(bearer) = &auth.bearer {
            req = req.bearer_auth(bearer);
        }
        req
    }

    async fn send<R: DeserializeOwned>(&self, req: reqwest::RequestBuilder) -> Result<R, EnrollClientError> {
        let res = req.send().await?;
        let status = res.status();
        let text = res.text().await?;
        if !status.is_success() {
            return Err(EnrollClientError::Api {
                status: status.as_u16(),
                body: text,
            });
        }
        serde_json::from_str(&text).map_err(|e| EnrollClientError::Decode(format!("{e} (body: {text})")))
    }

    pub async fn enroll_create(
        &self,
        body: &EnrollCreateRequest<'_>,
    ) -> Result<EnrollCreateResponse, EnrollClientError> {
        let req = self.http.post(self.url("enroll-create")).json(body);
        self.send(req).await
    }

    pub async fn enroll_list(
        &self,
        entity_id: &str,
        status: &str,
        auth: &AuthOptions,
    ) -> Result<EnrollListResponse, EnrollClientError> {
        let req = self
            .http
            .get(self.url("enroll-list"))
            .query(&[("entityId", entity_id), ("status", status)]);
        self.send(self.with_auth(req, auth)).await
    }

    pub async fn enroll_approve(
        &self,
        body: &EnrollApproveRequest<'_>,
        auth: &AuthOptions,
    ) -> Result<EnrollApproveResponse, EnrollClientError> {
        let req = self.http.post(self.url("enroll-approve")).json(body);
        self.send(self.with_auth(req, auth)).await
    }

    pub async fn enroll_reject(
        &self,
        enroll_id: &str,
        auth: &AuthOptions,
    ) -> Result<EnrollRejectResponse, EnrollClientError> {
        let body = EnrollRejectRequest { enroll_id };
        let req = self.http.post(self.url("enroll-reject")).json(&body);
        self.send(self.with_auth(req, auth)).await
    }

    pub async fn enroll_pull(&self, pull_token: &str) -> Result<EnrollPullResponse, EnrollClientError> {
        let body = EnrollPullRequest { pull_token };
        let req = self.http.post(self.url("enroll-pull")).json(&body);
        self.send(req).await
    }

    pub async fn enroll_instant(
        &self,
        body: &EnrollInstantRequest<'_>,
        auth: &AuthOptions,
    ) -> Result<EnrollInstantResponse, EnrollClientError> {
        let req = self.http.post(self.url("enroll-instant")).json(body);
        self.send(self.with_auth(req, auth)).await
    }

    pub async fn enroll_machine_permissions(
        &self,
        body: &EnrollMachinePermissionsRequest<'_>,
        auth: &AuthOptions,
    ) -> Result<EnrollMachinePermissionsResponse, EnrollClientError> {
        let req = self
            .http
            .post(self.url("enroll-machine-permissions"))
            .json(body);
        self.send(self.with_auth(req, auth)).await
    }

    pub async fn kickstart_entity(
        &self,
        body: &KickstartEntityRequest<'_>,
        auth: &AuthOptions,
    ) -> Result<KickstartEntityResponse, EnrollClientError> {
        let req = self.http.post(self.url("kickstart-entity")).json(body);
        self.send(self.with_auth(req, auth)).await
    }
}

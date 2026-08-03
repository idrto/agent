//! High-level enroll/cert/entity command implementations shared by the
//! `source-agent` and `target-agent` CLIs. Each function maps ~1:1 to a CLI
//! subcommand; callers own argument parsing and result printing.

use std::path::{Path, PathBuf};

use dp_rust::{Capability, CredentialKind};
use dp_rust_mtls::{DeviceIdentity, SignClientCertFromCsrParams};
use idr_dp::{DeviceIdentityJson, FileSecretStore, IssueCredentialParams, SecretStore};
use serde_json::Value;
use thiserror::Error;

use crate::client::{
    AuthOptions, EnrollApproveRequest, EnrollClient, EnrollClientError,
    EnrollCreateRequest, EnrollInstantRequest, EnrollMachinePermissionsRequest, EnrollSummary,
    KickstartEntityRequest,
};
use crate::csr::extract_ed25519_public_key;
use crate::keyfile::AdminKeyFile;
use crate::state::PendingIdentity;

#[derive(Debug, Error)]
pub enum FlowError {
    #[error(transparent)]
    Client(#[from] EnrollClientError),
    #[error(transparent)]
    Credential(#[from] idr_dp::CredentialError),
    #[error(transparent)]
    Dp(#[from] idr_dp::DpIdentityError),
    #[error(transparent)]
    Mtls(#[from] dp_rust_mtls::MtlsError),
    #[error(transparent)]
    Csr(#[from] crate::csr::CsrError),
    #[error("io: {0}")]
    Io(String),
    #[error("json: {0}")]
    Json(String),
    #[error("{0}")]
    Message(String),
}

fn generate_csr(common_name: Option<&str>, host: &str) -> Result<dp_rust_mtls::GeneratedKeyAndCsr, FlowError> {
    dp_rust_mtls::generate_key_and_csr(common_name.unwrap_or(host), Some(host)).map_err(FlowError::from)
}

// --- identity init ---------------------------------------------------------

pub struct InitParams<'a> {
    pub role: &'a str,
    pub host: &'a str,
    pub entity_id: Option<&'a str>,
    pub common_name: Option<&'a str>,
    pub pending_path: &'a Path,
}

pub struct InitResult {
    pub ski: String,
    pub csr_pem: String,
    pub pending_path: PathBuf,
}

/// `identity init` — generate an Ed25519 keypair + CSR entirely offline.
pub fn identity_init(params: InitParams<'_>) -> Result<InitResult, FlowError> {
    let generated = generate_csr(params.common_name, params.host)?;
    let pending = PendingIdentity {
        ski: generated.ski.clone(),
        private_jwk: generated.private_jwk.clone(),
        public_jwk: generated.public_jwk.clone(),
        csr_pem: generated.csr_pem.clone(),
        host: params.host.to_string(),
        role: params.role.to_string(),
        entity_id: params.entity_id.map(str::to_string),
        enroll_id: None,
        pull_token: None,
    };
    pending.save(params.pending_path)?;
    Ok(InitResult {
        ski: pending.ski,
        csr_pem: pending.csr_pem,
        pending_path: params.pending_path.to_path_buf(),
    })
}

// --- identity enroll (remote, queued) --------------------------------------

pub struct EnrollParams<'a> {
    pub auth_url: &'a str,
    pub entity_id: &'a str,
    pub host: &'a str,
    pub role: &'a str,
    pub common_name: Option<&'a str>,
    pub pending_path: &'a Path,
}

pub struct EnrollResult {
    pub enroll_id: String,
    pub pull_token: String,
    pub subject_ski: String,
}

/// `identity enroll` — POST the (existing or freshly generated) CSR to
/// `enroll-create`; the result is queued until an admin runs `cert approve`.
pub async fn identity_enroll(params: EnrollParams<'_>) -> Result<EnrollResult, FlowError> {
    let mut pending = match PendingIdentity::load(params.pending_path)? {
        Some(p) => p,
        None => {
            let generated = generate_csr(params.common_name, params.host)?;
            PendingIdentity {
                ski: generated.ski,
                private_jwk: generated.private_jwk,
                public_jwk: generated.public_jwk,
                csr_pem: generated.csr_pem,
                host: params.host.to_string(),
                role: params.role.to_string(),
                entity_id: Some(params.entity_id.to_string()),
                enroll_id: None,
                pull_token: None,
            }
        }
    };
    pending.entity_id = Some(params.entity_id.to_string());

    let client = EnrollClient::new(params.auth_url);
    let resp = client
        .enroll_create(&EnrollCreateRequest {
            entity_id: params.entity_id,
            host: &pending.host,
            role: &pending.role,
            csr_pem: &pending.csr_pem,
            public_jwk: &pending.public_jwk,
            subject_ski: Some(&pending.ski),
        })
        .await?;

    pending.enroll_id = Some(resp.enroll_id.clone());
    pending.pull_token = Some(resp.pull_token.clone());
    pending.save(params.pending_path)?;

    Ok(EnrollResult {
        enroll_id: resp.enroll_id,
        pull_token: resp.pull_token,
        subject_ski: resp.subject_ski,
    })
}

// --- identity pull -----------------------------------------------------------

pub struct PullParams<'a> {
    pub auth_url: &'a str,
    pub pending_path: &'a Path,
    pub identity_path: &'a Path,
}

pub enum PullOutcome {
    Pending,
    Rejected,
    Approved {
        ski: String,
        identity_path: PathBuf,
    },
}

/// `identity pull` — POST the queued `pullToken` to `enroll-pull`; on
/// approval, persists the final `DeviceIdentity` (with issued cert/chain).
pub async fn identity_pull(params: PullParams<'_>) -> Result<PullOutcome, FlowError> {
    let pending = PendingIdentity::load(params.pending_path)?.ok_or_else(|| {
        FlowError::Message(
            "no pending identity found; run `identity init` / `identity enroll` first".into(),
        )
    })?;
    let pull_token = pending.pull_token.clone().ok_or_else(|| {
        FlowError::Message("pending identity has no pullToken; run `identity enroll` first".into())
    })?;

    let client = EnrollClient::new(params.auth_url);
    let resp = client.enroll_pull(&pull_token).await?;

    match resp.status.as_str() {
        "pending" => Ok(PullOutcome::Pending),
        "rejected" => {
            let _ = std::fs::remove_file(params.pending_path);
            Ok(PullOutcome::Rejected)
        }
        "approved" => {
            let credential = resp
                .credential
                .ok_or_else(|| FlowError::Message("approved enroll-pull missing credential".into()))?;
            let cert_pem = resp
                .cert_pem
                .ok_or_else(|| FlowError::Message("approved enroll-pull missing certPem".into()))?;
            let identity_json = DeviceIdentityJson {
                ski: pending.ski.clone(),
                private_jwk: pending.private_jwk.clone(),
                credential,
                public_jwk: Some(pending.public_jwk.clone()),
                fqhn: Some(pending.host.clone()),
                cert_pem: Some(cert_pem),
                chain_pem: resp.chain_pem,
            };
            let device_identity = DeviceIdentity::try_from(identity_json)?;
            FileSecretStore::new(params.identity_path).save_identity(&device_identity)?;
            let _ = std::fs::remove_file(params.pending_path);
            Ok(PullOutcome::Approved {
                ski: pending.ski,
                identity_path: params.identity_path.to_path_buf(),
            })
        }
        other => Err(FlowError::Message(format!(
            "unexpected enroll-pull status: {other}"
        ))),
    }
}

// --- identity enroll --local (localhost instant path) -----------------------

pub struct LocalEnrollParams<'a> {
    pub entity_id: &'a str,
    pub host: &'a str,
    pub role: &'a str,
    pub common_name: Option<&'a str>,
    pub ca_key: &'a AdminKeyFile,
    pub ca_cert_pem: &'a str,
    pub issuer_ski: &'a str,
    pub issuer_private_jwk: &'a Value,
    pub permissions: Option<Vec<Capability>>,
    pub not_after_days: Option<i64>,
    pub paying_party_id: Option<&'a str>,
    /// When set, also registers with the server via `enroll-instant` so the
    /// platform co-signs the leaf cert + credential and a seat is bound.
    /// When `None`, this is a fully offline dev signing (no co-sign, no seat).
    pub auth_url: Option<&'a str>,
    pub auth: AuthOptions,
    pub pending_path: &'a Path,
    pub identity_path: &'a Path,
}

pub struct LocalEnrollResult {
    pub ski: String,
    pub identity_path: PathBuf,
    pub registered_with_server: bool,
    pub seat_id: Option<String>,
}

/// `identity enroll --local` — generate CSR if needed, sign the leaf with a
/// locally-held CA key, mint + self-sign a `CapabilityCredential` with the
/// issuer key, optionally register with `enroll-instant`, and save the
/// identity. No queue wait: usable when admin CA/issuer keys live on the
/// same host as the device (dev boxes, single-operator setups, CI).
pub async fn identity_enroll_local(params: LocalEnrollParams<'_>) -> Result<LocalEnrollResult, FlowError> {
    let ca_common_name = params.ca_key.common_name.as_deref().ok_or_else(|| {
        FlowError::Message("--ca-key file is missing \"common_name\" (see `cert init-ca`)".into())
    })?;

    let pending_existing = PendingIdentity::load(params.pending_path)?;
    let (ski, private_jwk, public_jwk, csr_pem) = match pending_existing {
        Some(p) => (p.ski, p.private_jwk, p.public_jwk, p.csr_pem),
        None => {
            let generated = generate_csr(params.common_name, params.host)?;
            (
                generated.ski,
                generated.private_jwk,
                generated.public_jwk,
                generated.csr_pem,
            )
        }
    };

    let signed = dp_rust_mtls::sign_client_cert_from_csr(SignClientCertFromCsrParams {
        csr_pem: &csr_pem,
        ca_cert_pem: params.ca_cert_pem,
        ca_private_jwk: &params.ca_key.private_jwk,
        ca_common_name,
        ski: &ski,
        host: Some(params.host),
        not_after_days: params.not_after_days,
    })?;

    let permissions = resolve_permissions(
        params.permissions,
        params.auth_url,
        &params.auth,
        params.entity_id,
        params.host,
        params.role,
    )
    .await;

    let mut credential = idr_dp::issue_credential(IssueCredentialParams {
        kind: CredentialKind::Machine,
        entity_id: params.entity_id,
        subject_ski: &ski,
        subject_public_jwk: public_jwk.clone(),
        permissions,
        issuer_ski: params.issuer_ski,
        issuer_private_jwk: params.issuer_private_jwk,
        zone: None,
        host: Some(params.host),
        package: None,
        not_before: None,
        ttl_seconds: params.not_after_days.map(|d| d * 86_400),
    })?;

    let mut cert_pem = signed.leaf_pem.clone();
    let mut chain_pem = Some(signed.chain_pem.clone());
    let mut registered = false;
    let mut seat_id = None;

    if let Some(auth_url) = params.auth_url {
        let client = EnrollClient::new(auth_url);
        let resp = client
            .enroll_instant(
                &EnrollInstantRequest {
                    entity_id: params.entity_id,
                    host: params.host,
                    role: params.role,
                    csr_pem: &csr_pem,
                    public_jwk: &public_jwk,
                    subject_ski: Some(&ski),
                    leaf_pem: &signed.leaf_pem,
                    chain_pem: &signed.chain_pem,
                    credential: &credential,
                    issuer_ski: params.issuer_ski,
                    paying_party_id: params.paying_party_id,
                },
                &params.auth,
            )
            .await?;
        credential = resp.credential;
        cert_pem = resp.cert_pem;
        chain_pem = Some(resp.chain_pem);
        seat_id = resp.seat_id;
        registered = true;
    }

    let identity_json = DeviceIdentityJson {
        ski: ski.clone(),
        private_jwk,
        credential,
        public_jwk: Some(public_jwk),
        fqhn: Some(params.host.to_string()),
        cert_pem: Some(cert_pem),
        chain_pem,
    };
    let device_identity = DeviceIdentity::try_from(identity_json)?;
    FileSecretStore::new(params.identity_path).save_identity(&device_identity)?;
    let _ = std::fs::remove_file(params.pending_path);

    Ok(LocalEnrollResult {
        ski,
        identity_path: params.identity_path.to_path_buf(),
        registered_with_server: registered,
        seat_id,
    })
}

async fn resolve_permissions(
    explicit: Option<Vec<Capability>>,
    auth_url: Option<&str>,
    auth: &AuthOptions,
    entity_id: &str,
    host: &str,
    role: &str,
) -> Vec<Capability> {
    if let Some(perms) = explicit {
        return perms;
    }
    if let Some(auth_url) = auth_url {
        if !auth.is_empty() {
            let client = EnrollClient::new(auth_url);
            match client
                .enroll_machine_permissions(
                    &EnrollMachinePermissionsRequest {
                        entity_id,
                        host,
                        role,
                    },
                    auth,
                )
                .await
            {
                Ok(resp) => return resp.permissions,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "enroll-machine-permissions failed; falling back to built-in default capability"
                    );
                }
            }
        }
    }
    idr_dp::default_machine_capability(entity_id, host)
}

// --- cert list / approve / reject -------------------------------------------

pub async fn cert_list(
    auth_url: &str,
    auth: &AuthOptions,
    entity_id: &str,
    status: &str,
) -> Result<Vec<EnrollSummary>, FlowError> {
    let client = EnrollClient::new(auth_url);
    Ok(client.enroll_list(entity_id, status, auth).await?.enrollments)
}

pub struct ApproveParams<'a> {
    pub auth_url: &'a str,
    pub auth: AuthOptions,
    pub enroll_id: &'a str,
    pub csr_pem: &'a str,
    pub subject_ski: &'a str,
    pub entity_id: &'a str,
    pub host: &'a str,
    pub role: &'a str,
    pub ca_key: &'a AdminKeyFile,
    pub ca_cert_pem: &'a str,
    pub issuer_ski: &'a str,
    pub issuer_private_jwk: &'a Value,
    pub permissions: Option<Vec<Capability>>,
    pub not_after_days: Option<i64>,
    pub paying_party_id: Option<&'a str>,
}

pub struct ApproveResult {
    pub enroll_id: String,
    pub status: String,
    pub seat_id: Option<String>,
}

/// `cert approve <enrollId>` — admin signs the device's CSR (obtained
/// out-of-band; `enroll-list` intentionally doesn't leak raw CSRs) with a
/// locally-held CA key + issuer key, then calls `enroll-approve`.
pub async fn cert_approve(params: ApproveParams<'_>) -> Result<ApproveResult, FlowError> {
    let ca_common_name = params.ca_key.common_name.as_deref().ok_or_else(|| {
        FlowError::Message("--ca-key file is missing \"common_name\" (see `cert init-ca`)".into())
    })?;

    let pubkey = extract_ed25519_public_key(params.csr_pem)?;
    let public_jwk = idr_dp::public_jwk_from_raw_ed25519(&pubkey);

    let signed = dp_rust_mtls::sign_client_cert_from_csr(SignClientCertFromCsrParams {
        csr_pem: params.csr_pem,
        ca_cert_pem: params.ca_cert_pem,
        ca_private_jwk: &params.ca_key.private_jwk,
        ca_common_name,
        ski: params.subject_ski,
        host: Some(params.host),
        not_after_days: params.not_after_days,
    })?;

    let permissions = resolve_permissions(
        params.permissions,
        Some(params.auth_url),
        &params.auth,
        params.entity_id,
        params.host,
        params.role,
    )
    .await;

    let credential = idr_dp::issue_credential(IssueCredentialParams {
        kind: CredentialKind::Machine,
        entity_id: params.entity_id,
        subject_ski: params.subject_ski,
        subject_public_jwk: public_jwk,
        permissions,
        issuer_ski: params.issuer_ski,
        issuer_private_jwk: params.issuer_private_jwk,
        zone: None,
        host: Some(params.host),
        package: None,
        not_before: None,
        ttl_seconds: params.not_after_days.map(|d| d * 86_400),
    })?;

    let client = EnrollClient::new(params.auth_url);
    let resp = client
        .enroll_approve(
            &EnrollApproveRequest {
                enroll_id: params.enroll_id,
                leaf_pem: &signed.leaf_pem,
                chain_pem: &signed.chain_pem,
                credential: &credential,
                issuer_ski: params.issuer_ski,
                paying_party_id: params.paying_party_id,
            },
            &params.auth,
        )
        .await?;

    Ok(ApproveResult {
        enroll_id: resp.enroll_id,
        status: resp.status,
        seat_id: resp.seat_id,
    })
}

pub async fn cert_reject(auth_url: &str, auth: &AuthOptions, enroll_id: &str) -> Result<String, FlowError> {
    let client = EnrollClient::new(auth_url);
    Ok(client.enroll_reject(enroll_id, auth).await?.status)
}

// --- cert init-ca (bonus: bootstrap a dev/local Entity CA) -------------------

pub struct InitCaResult {
    pub ski: String,
    pub common_name: String,
    pub key_path: PathBuf,
    pub cert_path: PathBuf,
}

/// `cert init-ca` — create a self-signed Ed25519 CA for `identity enroll
/// --local` / `cert approve` to sign device leaf certs with. Dev/test only;
/// production deployments should use a real Entity CA ceremony.
pub fn cert_init_ca(common_name: &str, key_path: &Path, cert_path: &Path) -> Result<InitCaResult, FlowError> {
    let ca = dp_rust_mtls::create_self_signed_ca(common_name)?;
    let key_file = AdminKeyFile {
        ski: Some(ca.ski.clone()),
        private_jwk: ca.private_jwk.clone(),
        public_jwk: Some(ca.public_jwk.clone()),
        common_name: Some(ca.common_name.clone()),
    };
    key_file.save(key_path)?;
    if let Some(parent) = cert_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| FlowError::Io(e.to_string()))?;
        }
    }
    std::fs::write(cert_path, &ca.ca_cert_pem).map_err(|e| FlowError::Io(e.to_string()))?;
    Ok(InitCaResult {
        ski: ca.ski,
        common_name: ca.common_name,
        key_path: key_path.to_path_buf(),
        cert_path: cert_path.to_path_buf(),
    })
}

// --- entity kickstart --------------------------------------------------------

pub struct KickstartParams<'a> {
    pub auth_url: &'a str,
    pub auth: AuthOptions,
    pub entity_id: &'a str,
    pub package: &'a str,
}

pub struct KickstartResult {
    pub entity_id: String,
    pub package: String,
    pub root: Option<AdminKeyFile>,
    pub root_admin: Option<AdminKeyFile>,
    pub raw: Value,
}

/// `entity kickstart` — server-keygen mode: POSTs `{entityId, package}` to
/// `kickstart-entity`, expecting the deployment to run with
/// `allowServerKeygen: true` (the "instant localhost" happy path). For a
/// fully client-sovereign root/admin key ceremony (client-generated keys +
/// a real catalog-driven permission set), build the request with
/// [`crate::client::KickstartEntityRequest`] directly instead.
pub async fn entity_kickstart(params: KickstartParams<'_>) -> Result<KickstartResult, FlowError> {
    let client = EnrollClient::new(params.auth_url);
    let raw = client
        .kickstart_entity(
            &KickstartEntityRequest {
                entity_id: params.entity_id,
                package: params.package,
            },
            &params.auth,
        )
        .await?;

    let extract = |branch: &str| -> Option<AdminKeyFile> {
        let node = raw.get(branch)?;
        let credential = node.get("credential")?;
        let ski = credential.get("ski")?.as_str()?.to_string();
        let private_jwk = node.get("privateJwk")?.clone();
        let public_jwk = credential.get("publicJwk").cloned();
        Some(AdminKeyFile {
            ski: Some(ski),
            private_jwk,
            public_jwk,
            common_name: None,
        })
    };

    Ok(KickstartResult {
        entity_id: params.entity_id.to_string(),
        package: params.package.to_string(),
        root: extract("root"),
        root_admin: extract("rootAdmin"),
        raw,
    })
}

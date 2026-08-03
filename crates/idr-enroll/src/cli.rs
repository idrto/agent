//! Shared `clap` arg structs + dispatch for `identity`/`cert`/`entity`
//! subcommands, used by both the `source-agent` and `target-agent` binaries
//! (and mirrored thinly by the Dart `idr_cli`).
//!
//! Binaries own top-level config/`--identity` resolution and just call
//! `dispatch_identity` / `dispatch_cert` / `dispatch_entity` with a resolved
//! identity path and a per-binary default `--role`.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Args, Subcommand};
use dp_rust::Capability;
use serde_json::Value;

use crate::client::AuthOptions;
use crate::keyfile::AdminKeyFile;
use crate::state::pending_path_for;
use crate::{flows, PullOutcome};

#[derive(Args, Debug)]
pub struct IdentityArgs {
    #[command(subcommand)]
    pub command: IdentityCommand,
}

#[derive(Subcommand, Debug)]
pub enum IdentityCommand {
    /// Generate an Ed25519 key + CSR offline (no network call).
    Init(IdentityInitArgs),
    /// Send the CSR to a delegate-permissions server (queued or --local instant).
    Enroll(IdentityEnrollArgs),
    /// Pull an approved enrollment and save the final DeviceIdentity.
    Pull(IdentityPullArgs),
}

#[derive(Args, Debug)]
pub struct IdentityInitArgs {
    /// "target" or "source"; defaults to this binary's role.
    #[arg(long)]
    pub role: Option<String>,
    /// Fully-qualified machine host, e.g. `db1.us-east--acme`.
    #[arg(long)]
    pub host: String,
    #[arg(long)]
    pub entity: Option<String>,
    /// CSR subject common name; defaults to `--host`.
    #[arg(long)]
    pub common_name: Option<String>,
    /// Override the pending-state file path (default `<identity>.pending.json`).
    #[arg(long)]
    pub pending: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct IdentityEnrollArgs {
    /// Localhost instant path: sign the leaf + credential locally (admin CA
    /// and issuer keys on this host) instead of queuing for admin approval.
    #[arg(long)]
    pub local: bool,

    /// Better Auth base URL mounting delegate-permissions, e.g.
    /// `http://127.0.0.1:3000/api/auth`. Required unless `--local` is used
    /// fully offline (no server registration).
    #[arg(long, env = "IDR_AUTH_URL")]
    pub auth_url: Option<String>,
    #[arg(long)]
    pub entity: Option<String>,
    #[arg(long)]
    pub host: Option<String>,
    #[arg(long)]
    pub role: Option<String>,
    #[arg(long)]
    pub common_name: Option<String>,
    #[arg(long, env = "IDR_AUTH_COOKIE")]
    pub cookie: Option<String>,
    #[arg(long, env = "IDR_AUTH_BEARER")]
    pub bearer: Option<String>,
    #[arg(long)]
    pub pending: Option<PathBuf>,

    /// --local only: JSON file with the Entity CA's `{private_jwk,
    /// common_name}` (see `cert init-ca`).
    #[arg(long)]
    pub ca_key: Option<PathBuf>,
    /// --local only: the CA's self-signed cert PEM.
    #[arg(long)]
    pub ca_cert: Option<PathBuf>,
    /// --local only: SKI of the credential issuer (e.g. the entity's Root Admin).
    #[arg(long)]
    pub issuer_ski: Option<String>,
    /// --local only: JSON file with the issuer's `{private_jwk}`.
    #[arg(long)]
    pub issuer_key: Option<PathBuf>,
    /// --local only: CapabilitySet JSON file; defaults to
    /// `enroll-machine-permissions` (if `--auth-url`+session given) or a
    /// minimal built-in `machine.connect` capability.
    #[arg(long)]
    pub permissions: Option<PathBuf>,
    #[arg(long)]
    pub paying_party_id: Option<String>,
    #[arg(long)]
    pub not_after_days: Option<i64>,
}

#[derive(Args, Debug)]
pub struct IdentityPullArgs {
    #[arg(long, env = "IDR_AUTH_URL")]
    pub auth_url: String,
    #[arg(long)]
    pub pending: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct CertArgs {
    #[command(subcommand)]
    pub command: CertCommand,
}

#[derive(Subcommand, Debug)]
pub enum CertCommand {
    /// List enrollment requests for an entity.
    List(CertListArgs),
    /// Sign a device's CSR and approve its enrollment.
    Approve(CertApproveArgs),
    /// Reject a pending enrollment.
    Reject(CertRejectArgs),
    /// Bootstrap a self-signed dev/local Entity CA for `--ca-key`/`--ca-cert`.
    InitCa(CertInitCaArgs),
}

#[derive(Args, Debug)]
pub struct CertListArgs {
    #[arg(long, env = "IDR_AUTH_URL")]
    pub auth_url: String,
    #[arg(long, env = "IDR_AUTH_COOKIE")]
    pub cookie: Option<String>,
    #[arg(long, env = "IDR_AUTH_BEARER")]
    pub bearer: Option<String>,
    #[arg(long)]
    pub entity: String,
    /// Shorthand for `--status pending` (the default).
    #[arg(long)]
    pub pending: bool,
    #[arg(long)]
    pub status: Option<String>,
}

#[derive(Args, Debug)]
pub struct CertApproveArgs {
    /// enrollId from `cert list`.
    pub enroll_id: String,
    #[arg(long, env = "IDR_AUTH_URL")]
    pub auth_url: String,
    #[arg(long, env = "IDR_AUTH_COOKIE")]
    pub cookie: Option<String>,
    #[arg(long, env = "IDR_AUTH_BEARER")]
    pub bearer: Option<String>,
    /// CSR PEM obtained out-of-band from the device (`enroll-list` does not
    /// return raw CSRs); the device's `identity enroll` output prints it.
    #[arg(long)]
    pub csr: PathBuf,
    /// subjectSki from `cert list` for this enrollId.
    #[arg(long)]
    pub subject_ski: String,
    #[arg(long)]
    pub entity: String,
    #[arg(long)]
    pub host: String,
    #[arg(long, default_value = "target")]
    pub role: String,
    #[arg(long)]
    pub ca_key: PathBuf,
    #[arg(long)]
    pub ca_cert: PathBuf,
    #[arg(long)]
    pub issuer_ski: String,
    #[arg(long)]
    pub issuer_key: PathBuf,
    #[arg(long)]
    pub permissions: Option<PathBuf>,
    #[arg(long)]
    pub paying_party_id: Option<String>,
    #[arg(long)]
    pub not_after_days: Option<i64>,
}

#[derive(Args, Debug)]
pub struct CertRejectArgs {
    pub enroll_id: String,
    #[arg(long, env = "IDR_AUTH_URL")]
    pub auth_url: String,
    #[arg(long, env = "IDR_AUTH_COOKIE")]
    pub cookie: Option<String>,
    #[arg(long, env = "IDR_AUTH_BEARER")]
    pub bearer: Option<String>,
}

#[derive(Args, Debug)]
pub struct CertInitCaArgs {
    #[arg(long)]
    pub common_name: String,
    #[arg(long)]
    pub out_key: PathBuf,
    #[arg(long)]
    pub out_cert: PathBuf,
}

#[derive(Args, Debug)]
pub struct EntityArgs {
    #[command(subcommand)]
    pub command: EntityCommand,
}

#[derive(Subcommand, Debug)]
pub enum EntityCommand {
    /// Create Entity Root + Root Admin credentials (server-keygen mode).
    Kickstart(EntityKickstartArgs),
}

#[derive(Args, Debug)]
pub struct EntityKickstartArgs {
    #[arg(long, env = "IDR_AUTH_URL")]
    pub auth_url: String,
    #[arg(long, env = "IDR_AUTH_COOKIE")]
    pub cookie: Option<String>,
    #[arg(long, env = "IDR_AUTH_BEARER")]
    pub bearer: Option<String>,
    #[arg(long)]
    pub entity: String,
    #[arg(long)]
    pub package: String,
    #[arg(long)]
    pub out_root: Option<PathBuf>,
    #[arg(long)]
    pub out_admin: Option<PathBuf>,
}

fn auth_options(cookie: Option<String>, bearer: Option<String>) -> AuthOptions {
    AuthOptions { cookie, bearer }
}

fn load_permissions(path: &Path) -> Result<Vec<Capability>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read permissions file {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("parse permissions file {}", path.display()))
}

pub async fn dispatch_identity(
    cmd: IdentityCommand,
    default_role: &str,
    identity_path: &Path,
) -> Result<()> {
    let pending_default = pending_path_for(identity_path);
    match cmd {
        IdentityCommand::Init(args) => {
            let pending_path = args.pending.unwrap_or(pending_default);
            let role = args.role.as_deref().unwrap_or(default_role);
            let result = flows::identity_init(flows::InitParams {
                role,
                host: &args.host,
                entity_id: args.entity.as_deref(),
                common_name: args.common_name.as_deref(),
                pending_path: &pending_path,
            })?;
            println!("ski={}", result.ski);
            println!("pending={}", result.pending_path.display());
            println!("csr_pem:\n{}", result.csr_pem);
            Ok(())
        }
        IdentityCommand::Enroll(args) => {
            let pending_path = args.pending.clone().unwrap_or(pending_default);
            let role = args.role.clone().unwrap_or_else(|| default_role.to_string());

            if args.local {
                let entity = args.entity.context("--entity is required for --local")?;
                let host = args
                    .host
                    .clone()
                    .or_else(|| {
                        crate::state::PendingIdentity::load(&pending_path)
                            .ok()
                            .flatten()
                            .map(|p| p.host)
                    })
                    .context("--host is required (or run `identity init --host ...` first)")?;
                let ca_key_path = args.ca_key.context("--ca-key is required for --local")?;
                let ca_cert_path = args.ca_cert.context("--ca-cert is required for --local")?;
                let issuer_ski = args.issuer_ski.context("--issuer-ski is required for --local")?;
                let issuer_key_path = args
                    .issuer_key
                    .context("--issuer-key is required for --local")?;

                let ca_key = AdminKeyFile::load(&ca_key_path)?;
                let ca_cert_pem = std::fs::read_to_string(&ca_cert_path)
                    .with_context(|| format!("read {}", ca_cert_path.display()))?;
                let issuer_key = AdminKeyFile::load(&issuer_key_path)?;
                let permissions = args
                    .permissions
                    .as_deref()
                    .map(load_permissions)
                    .transpose()?;

                let result = flows::identity_enroll_local(flows::LocalEnrollParams {
                    entity_id: &entity,
                    host: &host,
                    role: &role,
                    common_name: args.common_name.as_deref(),
                    ca_key: &ca_key,
                    ca_cert_pem: &ca_cert_pem,
                    issuer_ski: &issuer_ski,
                    issuer_private_jwk: &issuer_key.private_jwk,
                    permissions,
                    not_after_days: args.not_after_days,
                    paying_party_id: args.paying_party_id.as_deref(),
                    auth_url: args.auth_url.as_deref(),
                    auth: auth_options(args.cookie, args.bearer),
                    pending_path: &pending_path,
                    identity_path,
                })
                .await?;

                println!("ski={}", result.ski);
                println!("identity={}", result.identity_path.display());
                println!("registered_with_server={}", result.registered_with_server);
                if let Some(seat) = result.seat_id {
                    println!("seat_id={seat}");
                }
                if !result.registered_with_server {
                    println!(
                        "note: offline dev signing only (no --auth-url); no platform co-sign, no seat"
                    );
                }
                Ok(())
            } else {
                let auth_url = args
                    .auth_url
                    .context("--auth-url is required (or set IDR_AUTH_URL)")?;
                let entity = args.entity.context("--entity is required")?;
                let host = args
                    .host
                    .clone()
                    .or_else(|| {
                        crate::state::PendingIdentity::load(&pending_path)
                            .ok()
                            .flatten()
                            .map(|p| p.host)
                    })
                    .context("--host is required (or run `identity init --host ...` first)")?;

                let result = flows::identity_enroll(flows::EnrollParams {
                    auth_url: &auth_url,
                    entity_id: &entity,
                    host: &host,
                    role: &role,
                    common_name: args.common_name.as_deref(),
                    pending_path: &pending_path,
                })
                .await?;

                println!("enroll_id={}", result.enroll_id);
                println!("pull_token={}", result.pull_token);
                println!("subject_ski={}", result.subject_ski);
                println!("status=pending (ask an entity admin to run `cert approve {}`)", result.enroll_id);
                Ok(())
            }
        }
        IdentityCommand::Pull(args) => {
            let pending_path = args.pending.unwrap_or(pending_default);
            let outcome = flows::identity_pull(flows::PullParams {
                auth_url: &args.auth_url,
                pending_path: &pending_path,
                identity_path,
            })
            .await?;
            match outcome {
                PullOutcome::Pending => {
                    println!("status=pending");
                    println!("note: not yet approved; retry after an admin runs `cert approve`");
                }
                PullOutcome::Rejected => {
                    println!("status=rejected");
                }
                PullOutcome::Approved { ski, identity_path } => {
                    println!("status=approved");
                    println!("ski={ski}");
                    println!("identity={}", identity_path.display());
                }
            }
            Ok(())
        }
    }
}

pub async fn dispatch_cert(cmd: CertCommand) -> Result<()> {
    match cmd {
        CertCommand::List(args) => {
            // `--pending` is a documented no-op alias: `status` already
            // defaults to "pending" (matching the server's own default).
            let _ = args.pending;
            let status = args.status.unwrap_or_else(|| "pending".into());
            let auth = auth_options(args.cookie, args.bearer);
            let enrollments = flows::cert_list(&args.auth_url, &auth, &args.entity, &status).await?;
            if enrollments.is_empty() {
                println!("(no enrollments with status={status})");
            }
            for e in enrollments {
                println!(
                    "{}\thost={}\trole={}\tsubject_ski={}\tstatus={}\tcreated_at={}",
                    e.enroll_id, e.host, e.role, e.subject_ski, e.status, e.created_at
                );
            }
            Ok(())
        }
        CertCommand::Approve(args) => {
            let ca_key = AdminKeyFile::load(&args.ca_key)?;
            let ca_cert_pem = std::fs::read_to_string(&args.ca_cert)
                .with_context(|| format!("read {}", args.ca_cert.display()))?;
            let issuer_key = AdminKeyFile::load(&args.issuer_key)?;
            let csr_pem = std::fs::read_to_string(&args.csr)
                .with_context(|| format!("read {}", args.csr.display()))?;
            let permissions = args
                .permissions
                .as_deref()
                .map(load_permissions)
                .transpose()?;
            let auth = auth_options(args.cookie, args.bearer);

            let result = flows::cert_approve(flows::ApproveParams {
                auth_url: &args.auth_url,
                auth,
                enroll_id: &args.enroll_id,
                csr_pem: &csr_pem,
                subject_ski: &args.subject_ski,
                entity_id: &args.entity,
                host: &args.host,
                role: &args.role,
                ca_key: &ca_key,
                ca_cert_pem: &ca_cert_pem,
                issuer_ski: &args.issuer_ski,
                issuer_private_jwk: &issuer_key.private_jwk,
                permissions,
                not_after_days: args.not_after_days,
                paying_party_id: args.paying_party_id.as_deref(),
            })
            .await?;

            println!("enroll_id={}", result.enroll_id);
            println!("status={}", result.status);
            if let Some(seat) = result.seat_id {
                println!("seat_id={seat}");
            }
            Ok(())
        }
        CertCommand::Reject(args) => {
            let auth = auth_options(args.cookie, args.bearer);
            let status = flows::cert_reject(&args.auth_url, &auth, &args.enroll_id).await?;
            println!("enroll_id={}", args.enroll_id);
            println!("status={status}");
            Ok(())
        }
        CertCommand::InitCa(args) => {
            let result = flows::cert_init_ca(&args.common_name, &args.out_key, &args.out_cert)?;
            println!("ski={}", result.ski);
            println!("common_name={}", result.common_name);
            println!("key={}", result.key_path.display());
            println!("cert={}", result.cert_path.display());
            Ok(())
        }
    }
}

pub async fn dispatch_entity(cmd: EntityCommand) -> Result<()> {
    match cmd {
        EntityCommand::Kickstart(args) => {
            if args.package != "personal" && args.package != "enterprise" {
                bail!("--package must be \"personal\" or \"enterprise\"");
            }
            let auth = auth_options(args.cookie, args.bearer);
            let result = flows::entity_kickstart(flows::KickstartParams {
                auth_url: &args.auth_url,
                auth,
                entity_id: &args.entity,
                package: &args.package,
            })
            .await?;

            let out_root = args
                .out_root
                .unwrap_or_else(|| PathBuf::from(format!("{}.root.json", args.entity)));
            let out_admin = args
                .out_admin
                .unwrap_or_else(|| PathBuf::from(format!("{}.admin.json", args.entity)));

            match &result.root {
                Some(root) => {
                    root.save(&out_root)?;
                    println!("root_ski={}", root.ski.clone().unwrap_or_default());
                    println!("root_key={}", out_root.display());
                }
                None => println!(
                    "warning: no root.privateJwk in response; server-keygen may be disabled \
                     (allowServerKeygen: true) — see raw response below"
                ),
            }
            match &result.root_admin {
                Some(admin) => {
                    admin.save(&out_admin)?;
                    println!("root_admin_ski={}", admin.ski.clone().unwrap_or_default());
                    println!("root_admin_key={}", out_admin.display());
                }
                None => println!("warning: no rootAdmin.privateJwk in response"),
            }
            if result.root.is_none() || result.root_admin.is_none() {
                println!(
                    "raw_response={}",
                    serde_json::to_string_pretty(&result.raw as &Value)?
                );
            }
            println!(
                "note: run `cert init-ca --common-name ... --out-key ... --out-cert ...` \
                 separately to get an mTLS Entity CA for `identity enroll --local` / `cert approve`"
            );
            Ok(())
        }
    }
}

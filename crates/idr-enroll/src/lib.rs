//! CSR enroll / instant-issue client for the Better Auth `delegate-permissions`
//! admin API, shared by the `source-agent` and `target-agent` CLIs.
//!
//! Three enroll paths, mirroring `packages/better-auth/.../delegate-permissions/enroll.ts`:
//! - **Queued**: `identity init` → `identity enroll` → (admin) `cert approve` → `identity pull`.
//! - **Instant / localhost**: `identity enroll --local` (admin CA + issuer keys on the same host).
//! - **Admin bootstrap**: `entity kickstart`, `cert init-ca`.

mod client;
mod csr;
mod keyfile;
mod state;

mod flows;

pub mod cli;

pub use client::{
    AuthOptions, EnrollApproveRequest, EnrollApproveResponse, EnrollClient, EnrollClientError,
    EnrollCreateRequest, EnrollCreateResponse, EnrollInstantRequest, EnrollInstantResponse,
    EnrollListResponse, EnrollMachinePermissionsRequest, EnrollMachinePermissionsResponse,
    EnrollPullRequest, EnrollPullResponse, EnrollRejectRequest, EnrollRejectResponse,
    EnrollSummary, KickstartEntityRequest, KickstartEntityResponse,
};
pub use csr::{extract_ed25519_public_key, CsrError};
pub use keyfile::AdminKeyFile;
pub use state::{pending_path_for, PendingIdentity};

pub use flows::{
    cert_approve, cert_init_ca, cert_list, cert_reject, entity_kickstart, identity_enroll,
    identity_enroll_local, identity_init, identity_pull, ApproveParams, ApproveResult,
    EnrollParams, EnrollResult, FlowError, InitCaResult, InitParams, InitResult,
    KickstartParams, KickstartResult, LocalEnrollParams, LocalEnrollResult, PullOutcome,
    PullParams,
};

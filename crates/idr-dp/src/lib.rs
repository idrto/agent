//! Delegate Permissions helpers for IDR Source/Target agents.
//!
//! Wraps [`dp_rust`] / [`dp_rust_mtls`]. Persistence stays host-owned
//! (Dart: `flutter_secure_storage`; Rust service: inject identity at start).

mod credential;
mod frame;
mod identity;
mod store;

pub use dp_rust::{
    Capability, CapabilityCredential, CredentialKind, EntityPackage, PlatformCosign,
};
pub use dp_rust_mtls::{
    create_self_signed_ca, generate_key_and_csr, load_client_auth, materialize_mtls_client,
    sign_client_cert_from_csr, ski_san_uri, DeviceIdentity, GeneratedKeyAndCsr, LoadedClientAuth,
    MtlsClientMaterial, MtlsError, SelfSignedCa, SignClientCertFromCsrParams, SignedClientCert,
};

pub use credential::{
    default_machine_capability, issue_credential, public_jwk_from_raw_ed25519, sign_compact_eddsa,
    ski_from_public_jwk, CredentialError, IssueCredentialParams,
};
pub use frame::{
    encode_credential_frame, parse_credential_frame, DpCredentialFrame, DP_CREDENTIAL_FRAME_TYPE,
};
pub use identity::{
    device_identity_from_json, device_identity_to_json, DeviceIdentityJson, DpIdentityError,
};
pub use store::{FileSecretStore, InMemorySecretStore, SecretStore};

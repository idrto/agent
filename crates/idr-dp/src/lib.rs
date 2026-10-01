//! Delegate Permissions helpers for IDR Source/Target agents.
//!
//! Wraps [`dp_rust`] / [`dp_rust_mtls`]. Persistence stays host-owned
//! (Dart: `flutter_secure_storage`; Rust service: inject identity at start).

mod crypto;
mod frame;
mod identity;
mod store;

pub use dp_rust::{
    Capability, CapabilityCredential, CredentialKind, EntityPackage, PlatformCosign,
};
pub use dp_rust_mtls::{
    load_client_auth, materialize_mtls_client, ski_san_uri, DeviceIdentity, LoadedClientAuth,
    MtlsClientMaterial, MtlsError,
};

pub use crypto::{
    build_csr, ca_cert_pem_from_jwk_json, generate_ed25519_json, generate_ed25519_material, sign,
    sign_csr_with_ca_jwk, sign_csr_with_ca_jwk_json, sign_json, ski, DpCryptoError,
    Ed25519KeyMaterialJson, SignedLeafJson,
};
pub use frame::{
    encode_credential_frame, parse_credential_frame, DpCredentialFrame, DP_CREDENTIAL_FRAME_TYPE,
};
pub use identity::{
    device_identity_from_json, device_identity_to_json, DeviceIdentityJson, DpIdentityError,
};
pub use store::{FileSecretStore, InMemorySecretStore, SecretStore};

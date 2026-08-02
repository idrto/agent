//! Host-owned secret store ports. Dart hosts use `flutter_secure_storage`;
//! Rust desktop services inject identity via file/env at process start.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use dp_rust_mtls::DeviceIdentity;

use crate::identity::{device_identity_from_json, device_identity_to_json, DpIdentityError};

/// Persist / load DP machine identity (app-owned; not inside dp-sdk).
pub trait SecretStore: Send + Sync {
    fn load_identity(&self) -> Result<Option<DeviceIdentity>, DpIdentityError>;
    fn save_identity(&self, identity: &DeviceIdentity) -> Result<(), DpIdentityError>;
    fn clear_identity(&self) -> Result<(), DpIdentityError>;
}

/// JSON file store for headless desktop services / tests.
pub struct FileSecretStore {
    path: PathBuf,
}

impl FileSecretStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl SecretStore for FileSecretStore {
    fn load_identity(&self) -> Result<Option<DeviceIdentity>, DpIdentityError> {
        if !self.path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&self.path).map_err(|e| DpIdentityError::Io(e.to_string()))?;
        Ok(Some(device_identity_from_json(&raw)?))
    }

    fn save_identity(&self, identity: &DeviceIdentity) -> Result<(), DpIdentityError> {
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|e| DpIdentityError::Io(e.to_string()))?;
            }
        }
        let json = device_identity_to_json(identity)?;
        fs::write(&self.path, json).map_err(|e| DpIdentityError::Io(e.to_string()))
    }

    fn clear_identity(&self) -> Result<(), DpIdentityError> {
        if self.path.exists() {
            fs::remove_file(&self.path).map_err(|e| DpIdentityError::Io(e.to_string()))?;
        }
        Ok(())
    }
}

/// In-memory store for unit tests.
#[derive(Default)]
pub struct InMemorySecretStore {
    inner: Mutex<Option<DeviceIdentity>>,
}

impl SecretStore for InMemorySecretStore {
    fn load_identity(&self) -> Result<Option<DeviceIdentity>, DpIdentityError> {
        Ok(self.inner.lock().expect("lock").clone())
    }

    fn save_identity(&self, identity: &DeviceIdentity) -> Result<(), DpIdentityError> {
        *self.inner.lock().expect("lock") = Some(identity.clone());
        Ok(())
    }

    fn clear_identity(&self) -> Result<(), DpIdentityError> {
        *self.inner.lock().expect("lock") = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentityJson;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use dp_rust::{Capability, CapabilityCredential, CredentialKind};
    use ed25519_dalek::SigningKey;

    fn sample_identity() -> DeviceIdentity {
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let d = URL_SAFE_NO_PAD.encode(signing.to_bytes());
        let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes());
        let ski = "testski0123456789abcdef012345".to_string();
        let json = DeviceIdentityJson {
            ski: ski.clone(),
            private_jwk: serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "d": d,
                "x": x,
                "alg": "EdDSA"
            }),
            credential: CapabilityCredential {
                version: 1,
                kind: CredentialKind::Machine,
                entity_id: "acme.example".into(),
                ski,
                public_jwk: serde_json::json!({"kty":"OKP","crv":"Ed25519","x": x}),
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
            },
            public_jwk: None,
            fqhn: None,
        };
        DeviceIdentity::try_from(json).unwrap()
    }

    #[test]
    fn memory_roundtrip() {
        let store = InMemorySecretStore::default();
        let id = sample_identity();
        store.save_identity(&id).unwrap();
        let loaded = store.load_identity().unwrap().unwrap();
        assert_eq!(loaded.ski, id.ski);
        store.clear_identity().unwrap();
        assert!(store.load_identity().unwrap().is_none());
    }
}

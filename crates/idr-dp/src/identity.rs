//! JSON load/save for [`DeviceIdentity`] (in-memory only after load).

use dp_rust_mtls::DeviceIdentity;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DpIdentityError {
    #[error("json: {0}")]
    Json(String),
    #[error("io: {0}")]
    Io(String),
    #[error("missing field: {0}")]
    Missing(&'static str),
}

/// On-disk / IPC shape for a DP machine identity (never log `private_jwk`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentityJson {
    pub ski: String,
    pub private_jwk: serde_json::Value,
    pub credential: dp_rust::CapabilityCredential,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_jwk: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fqhn: Option<String>,
}

impl From<&DeviceIdentity> for DeviceIdentityJson {
    fn from(id: &DeviceIdentity) -> Self {
        Self {
            ski: id.ski.clone(),
            private_jwk: id.private_jwk.clone(),
            credential: id.credential.clone(),
            public_jwk: id.private_jwk.get("x").map(|x| {
                serde_json::json!({
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": x,
                    "alg": "EdDSA"
                })
            }),
            fqhn: id.credential.host.clone(),
        }
    }
}

impl TryFrom<DeviceIdentityJson> for DeviceIdentity {
    type Error = DpIdentityError;

    fn try_from(value: DeviceIdentityJson) -> Result<Self, Self::Error> {
        if value.ski.is_empty() {
            return Err(DpIdentityError::Missing("ski"));
        }
        if value
            .private_jwk
            .get("d")
            .and_then(|v| v.as_str())
            .is_none()
        {
            return Err(DpIdentityError::Missing("private_jwk.d"));
        }
        Ok(DeviceIdentity {
            ski: value.ski,
            private_jwk: value.private_jwk,
            credential: value.credential,
        })
    }
}

pub fn device_identity_from_json(s: &str) -> Result<DeviceIdentity, DpIdentityError> {
    let parsed: DeviceIdentityJson =
        serde_json::from_str(s).map_err(|e| DpIdentityError::Json(e.to_string()))?;
    DeviceIdentity::try_from(parsed)
}

pub fn device_identity_to_json(identity: &DeviceIdentity) -> Result<String, DpIdentityError> {
    let wrapped = DeviceIdentityJson::from(identity);
    serde_json::to_string_pretty(&wrapped).map_err(|e| DpIdentityError::Json(e.to_string()))
}

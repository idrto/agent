//! Loader for admin/CA/issuer key material passed to `--ca-key`/`--issuer-key`.
//!
//! Deliberately permissive: a plain `{ ski, private_jwk, common_name }` file
//! (written by `cert init-ca` / `entity kickstart`) and a full
//! `DeviceIdentityJson` (written by `identity pull`) both parse fine here —
//! unknown fields (e.g. `credential`, `cert_pem`) are ignored.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::FlowError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminKeyFile {
    #[serde(default)]
    pub ski: Option<String>,
    pub private_jwk: Value,
    #[serde(default)]
    pub public_jwk: Option<Value>,
    /// Required when used as `--ca-key`: must equal the common name the
    /// self-signed CA cert (`--ca-cert`) was created with.
    #[serde(default)]
    pub common_name: Option<String>,
}

impl AdminKeyFile {
    pub fn load(path: &Path) -> Result<Self, FlowError> {
        let raw = fs::read_to_string(path)
            .map_err(|e| FlowError::Io(format!("read {}: {e}", path.display())))?;
        serde_json::from_str(&raw)
            .map_err(|e| FlowError::Json(format!("parse {}: {e}", path.display())))
    }

    pub fn save(&self, path: &Path) -> Result<(), FlowError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| FlowError::Io(format!("mkdir {}: {e}", parent.display())))?;
            }
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| FlowError::Json(format!("serialize key file: {e}")))?;
        fs::write(path, json).map_err(|e| FlowError::Io(format!("write {}: {e}", path.display())))
    }
}

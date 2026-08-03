//! On-disk state for an in-flight enrollment: the device-local keypair/CSR
//! plus, once known, the entity/host/role and `enroll-create` result.
//!
//! Lives beside the eventual identity file as `<identity>.pending.json` and
//! is deleted once `identity pull` / `identity enroll --local` produces a
//! final `DeviceIdentity`.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::FlowError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingIdentity {
    pub ski: String,
    pub private_jwk: Value,
    pub public_jwk: Value,
    pub csr_pem: String,
    pub host: String,
    pub role: String,
    #[serde(default)]
    pub entity_id: Option<String>,
    #[serde(default)]
    pub enroll_id: Option<String>,
    #[serde(default)]
    pub pull_token: Option<String>,
}

impl PendingIdentity {
    pub fn load(path: &Path) -> Result<Option<Self>, FlowError> {
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(path)
            .map_err(|e| FlowError::Io(format!("read {}: {e}", path.display())))?;
        let parsed = serde_json::from_str(&raw)
            .map_err(|e| FlowError::Json(format!("parse {}: {e}", path.display())))?;
        Ok(Some(parsed))
    }

    pub fn save(&self, path: &Path) -> Result<(), FlowError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|e| FlowError::Io(format!("mkdir {}: {e}", parent.display())))?;
            }
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| FlowError::Json(format!("serialize pending identity: {e}")))?;
        fs::write(path, json).map_err(|e| FlowError::Io(format!("write {}: {e}", path.display())))
    }
}

/// Default pending-state path for a given identity path: `<identity>.pending.json`.
pub fn pending_path_for(identity_path: &Path) -> PathBuf {
    let mut os: OsString = identity_path.as_os_str().to_os_string();
    os.push(".pending.json");
    PathBuf::from(os)
}

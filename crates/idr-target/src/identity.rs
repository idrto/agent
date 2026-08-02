use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::VerifyingKey;

use idr_protocol::crypto::KeyPair;

#[derive(Clone)]
pub struct TargetIdentity {
    keypair: KeyPair,
    key_path: Option<std::path::PathBuf>,
}

impl TargetIdentity {
    pub fn load_or_generate(key_path: Option<&Path>) -> Result<Self> {
        if let Some(path) = key_path {
            if path.exists() {
                let bytes = fs::read(path)
                    .with_context(|| format!("read identity key {}", path.display()))?;
                let keypair: KeyPair =
                    serde_json::from_slice(&bytes).context("parse identity key JSON")?;
                return Ok(Self {
                    keypair,
                    key_path: Some(path.to_path_buf()),
                });
            }
            let keypair = KeyPair::generate();
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)
                        .with_context(|| format!("create identity dir {}", parent.display()))?;
                }
            }
            let json = serde_json::to_vec_pretty(&keypair).context("serialize identity key")?;
            fs::write(path, json)
                .with_context(|| format!("write identity key {}", path.display()))?;
            return Ok(Self {
                keypair,
                key_path: Some(path.to_path_buf()),
            });
        }
        Ok(Self {
            keypair: KeyPair::generate(),
            key_path: None,
        })
    }

    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }

    pub fn public_key_base64url(&self) -> String {
        self.keypair.public_key_base64url()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.keypair.verifying_key
    }

    pub fn signing_key(&self) -> &ed25519_dalek::SigningKey {
        &self.keypair.signing_key
    }
}

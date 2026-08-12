use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{SigningKey, VerifyingKey};

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
                let keypair = if looks_like_pem(&bytes) {
                    let pem = std::str::from_utf8(&bytes).with_context(|| {
                        format!("identity key {} is not valid UTF-8 PEM", path.display())
                    })?;
                    let signing_key = SigningKey::from_pkcs8_pem(pem.trim()).with_context(|| {
                        format!("parse identity PEM {}", path.display())
                    })?;
                    let verifying_key = signing_key.verifying_key();
                    KeyPair {
                        signing_key,
                        verifying_key,
                    }
                } else {
                    serde_json::from_slice(&bytes).context("parse identity key JSON")?
                };
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

fn looks_like_pem(bytes: &[u8]) -> bool {
    let Ok(s) = std::str::from_utf8(bytes) else {
        return false;
    };
    s.trim_start_matches('\u{feff}')
        .trim_start()
        .starts_with("-----BEGIN")
}

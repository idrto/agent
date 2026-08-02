use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::errors::{ProtocolError, Result};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyPair {
    #[serde(with = "signing_key_bytes")]
    pub signing_key: SigningKey,
    #[serde(with = "verifying_key_bytes")]
    pub verifying_key: VerifyingKey,
}

mod signing_key_bytes {
    use ed25519_dalek::SigningKey;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(key: &SigningKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(key.as_bytes())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SigningKey, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(d)?;
        Ok(SigningKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| serde::de::Error::custom("invalid signing key length"))?,
        ))
    }
}

mod verifying_key_bytes {
    use ed25519_dalek::VerifyingKey;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(key: &VerifyingKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(key.as_bytes())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<VerifyingKey, D::Error> {
        let bytes: Vec<u8> = Deserialize::deserialize(d)?;
        VerifyingKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| serde::de::Error::custom("invalid verifying key length"))?,
        )
        .map_err(|e| serde::de::Error::custom(format!("invalid verifying key: {e}")))
    }
}

impl KeyPair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn public_key_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.verifying_key.as_bytes())
    }

    pub fn from_base64url_public(public: &str) -> Result<VerifyingKey> {
        let bytes = URL_SAFE_NO_PAD
            .decode(public)
            .map_err(|e| ProtocolError::MalformedDocument(e.to_string()))?;
        VerifyingKey::from_bytes(
            bytes
                .as_slice()
                .try_into()
                .map_err(|_| ProtocolError::MalformedDocument("bad public key length".into()))?,
        )
        .map_err(|e| ProtocolError::MalformedDocument(e.to_string()))
    }
}

pub fn sign_json_canonical(value: &serde_json::Value, key: &SigningKey) -> Result<String> {
    let canonical = canonical_json(value)?;
    let sig = key.sign(canonical.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

pub fn verify_json_canonical(
    value: &serde_json::Value,
    signature_b64: &str,
    key: &VerifyingKey,
) -> Result<()> {
    let canonical = canonical_json(value)?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|e| ProtocolError::MalformedDocument(e.to_string()))?;
    let sig = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| ProtocolError::InvalidSignature)?,
    );
    key.verify(canonical.as_bytes(), &sig)
        .map_err(|_| ProtocolError::InvalidSignature)
}

/// Produce deterministic JSON for signing (sorted keys, no whitespace).
pub fn canonical_json(value: &serde_json::Value) -> Result<String> {
    fn write_sorted(val: &serde_json::Value, out: &mut String) -> Result<()> {
        match val {
            serde_json::Value::Object(map) => {
                out.push('{');
                let mut keys: Vec<_> = map.keys().collect();
                keys.sort();
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push('"');
                    out.push_str(k);
                    out.push_str("\":");
                    write_sorted(&map[*k], out)?;
                }
                out.push('}');
            }
            serde_json::Value::Array(arr) => {
                out.push('[');
                for (i, item) in arr.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_sorted(item, out)?;
                }
                out.push(']');
            }
            serde_json::Value::String(s) => {
                out.push_str(
                    &serde_json::to_string(s)
                        .map_err(|e| ProtocolError::Serialization(e.to_string()))?,
                );
            }
            serde_json::Value::Number(n) => out.push_str(&n.to_string()),
            serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            serde_json::Value::Null => out.push_str("null"),
        }
        Ok(())
    }

    let mut out = String::new();
    write_sorted(value, &mut out)?;
    Ok(out)
}

pub fn content_digest(value: &serde_json::Value) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let canonical = canonical_json(value).unwrap_or_default();
    Sha256::digest(canonical.as_bytes()).into()
}

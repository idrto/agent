use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use idr_protocol::crypto::{self, KeyPair};
use idr_protocol::discovery::{parse_discovery_document, PresenceDiscoveryDocument};
use reqwest::Client;
use tracing::{info, warn};

use crate::config::PresenceConfig;
use crate::storage::models::PresenceDiscoveryCacheRow;
use crate::storage::writer::{StorageCommand, StorageWriter};
use crate::storage::Storage;

pub struct DiscoveryService {
    cfg: PresenceConfig,
    client: Client,
    discovery_key: Option<VerifyingKey>,
    storage: Storage,
    writer: StorageWriter,
    cached: parking_lot::RwLock<Option<PresenceDiscoveryDocument>>,
}

impl DiscoveryService {
    pub fn new(
        cfg: PresenceConfig,
        discovery_key: Option<VerifyingKey>,
        storage: Storage,
        writer: StorageWriter,
    ) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .context("build HTTP client")?;
        let svc = Self {
            cfg,
            client,
            discovery_key,
            storage,
            writer,
            cached: parking_lot::RwLock::new(None),
        };
        svc.load_cache();
        Ok(svc)
    }

    /// `None` = skip signature verify (local / insecure_dev with empty key).
    pub fn discovery_key_from_config(cfg: &PresenceConfig) -> Result<Option<VerifyingKey>> {
        if cfg.discovery_key.is_empty() {
            if cfg.insecure_dev {
                warn!("discovery_key empty + insecure_dev: skipping discovery signature verify");
                return Ok(None);
            }
            anyhow::bail!(
                "presence.discovery_key is required unless presence.insecure_dev = true"
            );
        }
        Ok(Some(KeyPair::from_base64url_public(&cfg.discovery_key).map_err(
            |e| anyhow::anyhow!("invalid discovery key: {e}"),
        )?))
    }

    fn load_cache(&self) {
        if let Ok(Some(row)) = self.storage.load_discovery_cache() {
            match parse_discovery_document(&row.canonical_json) {
                Ok(doc) => {
                    if self.discovery_key.is_none() || Utc::now() <= doc.valid_until {
                        *self.cached.write() = Some(doc);
                    }
                }
                Err(err) => warn!(error = %err, "discovery cache unusable"),
            }
        }
    }

    pub async fn fetch(&self) -> Result<PresenceDiscoveryDocument> {
        match self.fetch_remote().await {
            Ok(doc) => {
                *self.cached.write() = Some(doc.clone());
                Ok(doc)
            }
            Err(err) => {
                warn!(error = %err, "discovery fetch failed, using cache if valid");
                if let Some(doc) = self.cached.read().clone() {
                    if Utc::now() <= doc.valid_until {
                        return Ok(doc);
                    }
                }
                Err(err)
            }
        }
    }

    async fn fetch_remote(&self) -> Result<PresenceDiscoveryDocument> {
        let bytes = self
            .client
            .get(&self.cfg.discovery_url)
            .send()
            .await
            .context("discovery HTTP request")?
            .error_for_status()
            .context("discovery HTTP status")?
            .bytes()
            .await
            .context("discovery HTTP body")?;

        if let Some(key) = &self.discovery_key {
            if let Err(err) = verify_discovery_signature(&bytes, key) {
                if self.cfg.insecure_dev {
                    // Live CDN doc can diverge from the pinned example key while IPs stay valid.
                    warn!(error = %err, "discovery signature verify failed; insecure_dev continuing");
                } else {
                    return Err(err).context("discovery verify failed");
                }
            }
        }

        let doc = parse_discovery_document(&bytes)
            .map_err(|e| anyhow::anyhow!("parse discovery document: {e}"))?;

        // Cache the runtime (possibly expanded) document so reloads stay schema-stable.
        let cached_json = serde_json::to_vec(&doc).context("serialize discovery cache")?;
        let row = PresenceDiscoveryCacheRow {
            generation: doc.generation,
            valid_until: doc.valid_until,
            canonical_json: cached_json,
            signature: doc.signature.as_bytes().to_vec(),
            fetched_at: Utc::now(),
        };
        let _ = self
            .writer
            .send(StorageCommand::UpsertDiscoveryCache(row))
            .await;

        info!(
            generation = doc.generation,
            servers = doc.presence_servers.len(),
            "discovery document fetched"
        );
        Ok(doc)
    }

    pub fn cached(&self) -> Option<PresenceDiscoveryDocument> {
        self.cached.read().clone()
    }
}

fn verify_discovery_signature(bytes: &[u8], key: &VerifyingKey) -> Result<()> {
    // Full schema: verify via typed document (includes valid_until expiry).
    if let Ok(doc) = serde_json::from_slice::<PresenceDiscoveryDocument>(bytes) {
        return doc
            .verify(key)
            .map_err(|e| anyhow::anyhow!("{e}"));
    }

    // Live slim schema: try empty-string signature field, then omitted field.
    let mut value: serde_json::Value =
        serde_json::from_slice(bytes).context("parse discovery JSON for verify")?;
    let sig = value
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    if sig.is_empty() {
        anyhow::bail!("discovery signature missing");
    }

    let mut with_empty = value.clone();
    if let Some(obj) = with_empty.as_object_mut() {
        obj.insert("signature".into(), serde_json::Value::String(String::new()));
    }
    if crypto::verify_json_canonical(&with_empty, &sig, key).is_ok() {
        return Ok(());
    }

    if let Some(obj) = value.as_object_mut() {
        obj.remove("signature");
    }
    crypto::verify_json_canonical(&value, &sig, key).map_err(|e| anyhow::anyhow!("{e}"))
}

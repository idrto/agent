use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use reqwest::Client;
use tracing::{info, warn};

use crate::config::PresenceConfig;
use idr_protocol::crypto::KeyPair;
use idr_protocol::discovery::PresenceDiscoveryDocument;
use crate::storage::models::PresenceDiscoveryCacheRow;
use crate::storage::Storage;
use crate::storage::writer::{StorageCommand, StorageWriter};

pub struct DiscoveryService {
    cfg: PresenceConfig,
    client: Client,
    discovery_key: VerifyingKey,
    storage: Storage,
    writer: StorageWriter,
    cached: parking_lot::RwLock<Option<PresenceDiscoveryDocument>>,
}

impl DiscoveryService {
    pub fn new(
        cfg: PresenceConfig,
        discovery_key: VerifyingKey,
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

    pub fn discovery_key_from_config(cfg: &PresenceConfig) -> Result<VerifyingKey> {
        if cfg.discovery_key.is_empty() {
            // Dev fallback: generate ephemeral key; documents must be signed with matching key in demo.
            let kp = KeyPair::generate();
            return Ok(kp.verifying_key);
        }
        KeyPair::from_base64url_public(&cfg.discovery_key)
            .map_err(|e| anyhow::anyhow!("invalid discovery key: {e}"))
    }

    fn load_cache(&self) {
        if let Ok(Some(row)) = self.storage.load_discovery_cache() {
            if let Ok(doc) = serde_json::from_slice::<PresenceDiscoveryDocument>(&row.canonical_json) {
                if doc.verify(&self.discovery_key).is_ok() {
                    *self.cached.write() = Some(doc);
                }
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
                    if doc.verify(&self.discovery_key).is_ok() && Utc::now() <= doc.valid_until {
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

        let doc: PresenceDiscoveryDocument =
            serde_json::from_slice(&bytes).context("parse discovery document")?;
        doc.verify(&self.discovery_key)
            .map_err(|e| anyhow::anyhow!("discovery verify failed: {e}"))?;

        let row = PresenceDiscoveryCacheRow {
            generation: doc.generation,
            valid_until: doc.valid_until,
            canonical_json: bytes.to_vec(),
            signature: doc.signature.as_bytes().to_vec(),
            fetched_at: Utc::now(),
        };
        let _ = self
            .writer
            .send(StorageCommand::UpsertDiscoveryCache(row))
            .await;

        info!(generation = doc.generation, servers = doc.presence_servers.len(), "discovery document fetched");
        Ok(doc)
    }

    pub fn cached(&self) -> Option<PresenceDiscoveryDocument> {
        self.cached.read().clone()
    }
}

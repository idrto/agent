use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use reqwest::Client;
use tracing::{info, warn};

use crate::config::PresenceConfig;
use crate::storage::models::PresenceDiscoveryCacheRow;
use crate::storage::writer::{StorageCommand, StorageWriter};
use crate::storage::Storage;
use idr_protocol::crypto::KeyPair;
use idr_protocol::discovery::PresenceDiscoveryDocument;

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

    fn verify_doc(&self, doc: &PresenceDiscoveryDocument) -> Result<()> {
        match &self.discovery_key {
            Some(key) => doc
                .verify(key)
                .map_err(|e| anyhow::anyhow!("discovery verify failed: {e}")),
            None => Ok(()),
        }
    }

    fn load_cache(&self) {
        if let Ok(Some(row)) = self.storage.load_discovery_cache() {
            if let Ok(doc) =
                serde_json::from_slice::<PresenceDiscoveryDocument>(&row.canonical_json)
            {
                if self.verify_doc(&doc).is_ok() {
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
                    if self.verify_doc(&doc).is_ok() && Utc::now() <= doc.valid_until {
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
        self.verify_doc(&doc)?;

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

//! HTTP discovery fetch + verify (no SQLite).

use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_protocol::crypto::KeyPair;
use idr_protocol::discovery::PresenceDiscoveryDocument;
use idr_protocol::fqhn;
use idr_protocol::placement::{ModuloPlacement, PresencePlacement};
use reqwest::Client;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    pub discovery_url: String,
    /// Empty = skip signature verify (dev only).
    pub discovery_key_b64: String,
    pub timeout: Duration,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            discovery_url: "https://public.idr.to/.well-known/idr-presence.json".into(),
            discovery_key_b64: String::new(),
            timeout: Duration::from_secs(15),
        }
    }
}

pub struct DiscoveryClient {
    cfg: DiscoveryConfig,
    client: Client,
    discovery_key: Option<VerifyingKey>,
    cached: Option<PresenceDiscoveryDocument>,
}

impl DiscoveryClient {
    pub fn new(cfg: DiscoveryConfig) -> Result<Self> {
        let client = Client::builder()
            .timeout(cfg.timeout)
            .build()
            .map_err(|e| IdrError::new(IdrErrorKind::InternalError, e.to_string()))?;
        let discovery_key = if cfg.discovery_key_b64.is_empty() {
            None
        } else {
            Some(
                KeyPair::from_base64url_public(&cfg.discovery_key_b64).map_err(|e| {
                    IdrError::new(IdrErrorKind::InvalidArgument, format!("discovery key: {e}"))
                })?,
            )
        };
        Ok(Self {
            cfg,
            client,
            discovery_key,
            cached: None,
        })
    }

    pub async fn fetch(&mut self) -> Result<PresenceDiscoveryDocument> {
        match self.fetch_remote().await {
            Ok(doc) => {
                self.cached = Some(doc.clone());
                Ok(doc)
            }
            Err(err) => {
                warn!(error = %err, "discovery fetch failed");
                if let Some(doc) = &self.cached {
                    return Ok(doc.clone());
                }
                Err(err)
            }
        }
    }

    async fn fetch_remote(&self) -> Result<PresenceDiscoveryDocument> {
        let resp = self
            .client
            .get(&self.cfg.discovery_url)
            .send()
            .await
            .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, e.to_string()))?;
        if !resp.status().is_success() {
            return Err(IdrError::new(
                IdrErrorKind::SignalingFailed,
                format!("discovery HTTP {}", resp.status()),
            ));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, e.to_string()))?;
        let doc: PresenceDiscoveryDocument = serde_json::from_slice(&bytes)
            .map_err(|e| IdrError::new(IdrErrorKind::ProtocolError, e.to_string()))?;
        if let Some(key) = &self.discovery_key {
            doc.verify(key)?;
        }
        Ok(doc)
    }

    /// Pick primary + secondary Presence indexes for a Target FQHN.
    ///
    /// Dual-mod placement (`hash%N`, `hash%(N-1)`, bump secondary on collide).
    /// Requires at least two servers in `doc`. Dial Primary first, then Secondary
    /// on miss/unreachable so append-epoch skew still finds a registered Target.
    pub fn place(
        &self,
        doc: &PresenceDiscoveryDocument,
        target_fqhn: &str,
    ) -> Result<(usize, Option<usize>)> {
        let fqhn = fqhn::canonicalize(target_fqhn)
            .map_err(|e| IdrError::new(IdrErrorKind::InvalidArgument, e.to_string()))?;
        ModuloPlacement
            .primary_secondary(&fqhn, &doc.presence_servers)
            .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, e.to_string()))
    }

    /// Ordered dial list: Primary then Secondary Presence servers.
    pub fn place_servers<'a>(
        &self,
        doc: &'a PresenceDiscoveryDocument,
        target_fqhn: &str,
    ) -> Result<Vec<&'a idr_protocol::discovery::PresenceServer>> {
        let (primary, secondary) = self.place(doc, target_fqhn)?;
        let mut out = vec![&doc.presence_servers[primary]];
        if let Some(sec) = secondary {
            out.push(&doc.presence_servers[sec]);
        }
        Ok(out)
    }
}

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::config::RelayConnectionsConfig;
use crate::network::NetworkCapabilities;
use crate::quic::QuicClient;
use crate::quic::RelayQuicConnection;
use crate::relay::descriptor::{ConnectionAuthorization, StableRelayDescriptor};
use crate::relay::endpoint_selection::{
    choice_family, family_label, parse_endpoints, select_endpoint, EndpointChoice,
};
use crate::storage::Storage;
use crate::telemetry::Metrics;

pub struct RelayConnector {
    quic: Arc<QuicClient>,
    storage: Storage,
    network: Arc<Mutex<NetworkCapabilities>>,
    cfg: RelayConnectionsConfig,
    metrics: Metrics,
}

impl RelayConnector {
    pub fn new(
        quic: Arc<QuicClient>,
        storage: Storage,
        network: NetworkCapabilities,
        cfg: RelayConnectionsConfig,
        metrics: Metrics,
    ) -> Self {
        Self {
            quic,
            storage,
            network: Arc::new(Mutex::new(network)),
            cfg,
            metrics,
        }
    }

    pub fn update_network_caps(&self, caps: NetworkCapabilities) -> bool {
        let mut guard = self.network.lock().expect("network caps lock");
        let changed = *guard != caps;
        *guard = caps;
        changed
    }

    pub fn current_network_caps(&self) -> NetworkCapabilities {
        *self.network.lock().expect("network caps lock")
    }

    pub fn rebind_for_network_change(&self) -> Result<()> {
        let caps = self.current_network_caps();
        self.quic.rebind_for_caps(caps)
    }

    pub async fn connect(
        &self,
        descriptor: &StableRelayDescriptor,
        auth: &ConnectionAuthorization,
    ) -> Result<(Arc<RelayQuicConnection>, SocketAddr, i32)> {
        let history = self
            .storage
            .load_relay_history(&descriptor.relay_id)
            .context("load relay history")?;

        let network = *self.network.lock().expect("network caps lock");
        let primary = select_endpoint(descriptor, history.as_ref(), self.cfg.prefer_ipv6);
        let (v4, v6) = parse_endpoints(descriptor);

        let mut attempts: Vec<EndpointChoice> = Vec::new();
        match primary {
            Some(EndpointChoice::Ipv6(addr)) => {
                if network.ipv6 {
                    attempts.push(EndpointChoice::Ipv6(addr));
                }
                if let Some(v4) = v4 {
                    if network.ipv4 {
                        attempts.push(EndpointChoice::Ipv4(v4));
                    }
                }
            }
            Some(EndpointChoice::Ipv4(addr)) => {
                if network.ipv4 {
                    attempts.push(EndpointChoice::Ipv4(addr));
                }
                if let Some(v6) = v6 {
                    if network.ipv6 {
                        attempts.push(EndpointChoice::Ipv6(v6));
                    }
                }
            }
            None => anyhow::bail!("no relay endpoints available"),
        }

        if attempts.is_empty() {
            anyhow::bail!("no compatible network endpoints for relay");
        }

        let mut last_err = None;
        for (i, choice) in attempts.into_iter().enumerate() {
            if i > 0 {
                tokio::time::sleep(self.cfg.ipv4_fallback_delay()).await;
            }
            let addr = match choice {
                EndpointChoice::Ipv4(a) => a,
                EndpointChoice::Ipv6(a) => a,
            };
            let family = family_label(choice);
            debug!(relay_id = %descriptor.relay_id, %addr, family, "attempting relay QUIC connect");
            match timeout(
                self.cfg.connect_timeout(),
                self.quic.connect(descriptor, addr, auth),
            )
            .await
            {
                Ok(Ok(conn)) => {
                    self.metrics.inc_connection_attempt("success", family);
                    let fam = choice_family(choice);
                    return Ok((conn, addr, fam));
                }
                Ok(Err(e)) => {
                    warn!(relay_id = %descriptor.relay_id, error = %e, family, "relay connect failed");
                    self.metrics.inc_connection_attempt("failed", family);
                    last_err = Some(e);
                }
                Err(_) => {
                    self.metrics.inc_connection_attempt("timeout", family);
                    last_err = Some(anyhow::anyhow!("connect timeout"));
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("all relay connect attempts failed")))
    }
}

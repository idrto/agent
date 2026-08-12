//! Build the Target [`ConnectorRegistry`] from config + generic services.

use std::sync::Arc;

use idr_core::connector::ConnectorRegistry;

use crate::adapters::{NginxBridgeConnector, ServiceGatewayConnector};
use crate::config::Config;

/// Construct the live registry of named services for WebRTC OPEN routing.
pub fn build_connector_registry(cfg: &Config, fqhn: &str) -> ConnectorRegistry {
    let mut registry = ConnectorRegistry::new();

    if cfg.plugins.http {
        for (svc, connector) in NginxBridgeConnector::default_services(
            cfg.nginx.clone(),
            cfg.webrtc.policy.clone(),
            fqhn,
        ) {
            registry.register(svc, connector);
        }
    }

    for mut svc_cfg in cfg.services.clone() {
        if !svc_cfg.enabled {
            continue;
        }
        if let Err(e) = svc_cfg.validate() {
            tracing::warn!(error = %e, name = %svc_cfg.name, "skipping invalid [[services]] entry");
            continue;
        }
        svc_cfg.target_fqhn = Some(fqhn.to_string());
        let (svc, connector) = ServiceGatewayConnector::named_service(svc_cfg);
        registry.register(svc, connector);
    }

    registry
}

/// Catalog of service names for Presence WebRTC capabilities advertisement.
pub fn catalog_service_names(registry: &ConnectorRegistry) -> Vec<String> {
    registry.service_names()
}

/// Helper so callers can share one registry instance.
pub type SharedConnectorRegistry = Arc<ConnectorRegistry>;

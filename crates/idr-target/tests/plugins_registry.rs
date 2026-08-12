//! Registry wiring for generic [[services]] gateway + DB credential catalog.

use idr_core::ConnectorRegistry;
use idr_protocol::stream_mux::{CredentialMode, ServiceTransportKind};
use idr_target::adapters::ServiceGatewayConnector;
use idr_target::config::{
    GatewayCredentialMode, GatewayServiceConfig, GatewayServiceType,
};

#[test]
fn gateway_registers_named_http_service() {
    let mut reg = ConnectorRegistry::new();
    let cfg = GatewayServiceConfig {
        name: "ollama".into(),
        service_type: GatewayServiceType::Http,
        base_url: Some("http://127.0.0.1:11434".into()),
        host: None,
        port: None,
        enabled: true,
        inject_headers: vec![],
        credential_mode: GatewayCredentialMode::Target,
        require_upstream_tls: None,
        target_fqhn: Some("host.idr.to".into()),
    };
    let (svc, c) = ServiceGatewayConnector::named_service(cfg);
    reg.register(svc, c);
    assert!(reg.service_names().contains(&"ollama".to_string()));
    let (svc, _) = reg.resolve("ollama").unwrap();
    assert_eq!(svc.name, "ollama");
}

#[test]
fn gateway_registers_tcp_service() {
    let mut reg = ConnectorRegistry::new();
    let cfg = GatewayServiceConfig {
        name: "redis".into(),
        service_type: GatewayServiceType::Tcp,
        base_url: None,
        host: Some("127.0.0.1".into()),
        port: Some(6379),
        enabled: true,
        inject_headers: vec![],
        credential_mode: GatewayCredentialMode::Source,
        require_upstream_tls: Some(false),
        target_fqhn: Some("host.idr.to".into()),
    };
    cfg.validate().unwrap();
    let (svc, c) = ServiceGatewayConnector::named_service(cfg);
    reg.register(svc, c);
    assert!(reg.resolve("redis").is_ok());
}

#[test]
fn postgres_catalog_defaults_source_and_tls() {
    let mut reg = ConnectorRegistry::new();
    let cfg = GatewayServiceConfig {
        name: "postgres".into(),
        service_type: GatewayServiceType::Tcp,
        base_url: None,
        host: Some("127.0.0.1".into()),
        port: Some(5432),
        enabled: true,
        inject_headers: vec![],
        credential_mode: GatewayCredentialMode::Source,
        require_upstream_tls: None, // derive default → true for postgres
        target_fqhn: Some("host.idr.to".into()),
    };
    let (svc, c) = ServiceGatewayConnector::named_service(cfg);
    reg.register(svc, c);
    let entries = reg.catalog_entries();
    assert_eq!(entries.len(), 1);
    let e = &entries[0];
    assert_eq!(e.name, "postgres");
    assert_eq!(e.kind, ServiceTransportKind::Tcp);
    assert_eq!(e.credential_mode, CredentialMode::Source);
    assert!(e.require_upstream_tls);
}

#[test]
fn postgres_explicit_tls_false_respected() {
    let cfg = GatewayServiceConfig {
        name: "postgres".into(),
        service_type: GatewayServiceType::Tcp,
        base_url: None,
        host: Some("127.0.0.1".into()),
        port: Some(5432),
        enabled: true,
        inject_headers: vec![],
        credential_mode: GatewayCredentialMode::Source,
        require_upstream_tls: Some(false),
        target_fqhn: None,
    };
    assert!(!cfg.effective_require_upstream_tls());
}

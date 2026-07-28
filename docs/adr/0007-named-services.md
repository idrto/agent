# ADR-0007: Named Target services

## Context
Arbitrary host:port egress is dangerous by default.

## Decision
Source requests `service_name` (e.g. `https`, `http`). Target maps names via `Connector` / `ConnectorRegistry`. Default nginx TLS/HTTP connectors provided. Unrestricted TcpConnect remains policy-gated.

## Alternatives
- Always pass host:port
- Overlay network IPs

## Consequences
Service catalog must be configured on Target; Source default map is a temporary convenience.

## Migration impact
`NginxBridgeConnector` adapter in Phase 2/3.

## Unresolved
Dynamic service advertisement over Presence.

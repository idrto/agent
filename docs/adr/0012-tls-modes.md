# ADR-0012: TLS trust modes (mTLS / LE / Leg 2 self-signed)

## Context
Different account types need different certificate models.

## Decision
- Personal/enterprise: mTLS with entity CA-Root issued endpoint certs.
- Service providers: custom domain + Let’s Encrypt on Target.
- `*.idr.to` Leg 2 Relay↔Target: may use shared self-signed when not on Source path.

## Alternatives
- Single TLS policy for all tenants

## Consequences
Auth and Relay/Target config must distinguish modes; Source P2P still uses WebRTC DTLS + app TLS to Target terminator.

## Migration impact
Documented in security-model; enforcement phased with `idr-auth`.

## Unresolved
Exact Presence distribution of entity CA roots to Sources.

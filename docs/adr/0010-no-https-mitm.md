# ADR-0010: No transparent HTTPS interception on Source

## Context
Users expect E2E TLS to Target services when using CONNECT / SDK tunnels.

## Decision
Source never terminates application TLS or holds Target service private keys. Bytes are relayed on logical streams. WebRTC provides transport encryption separately.

## Alternatives
- Enterprise MITM with installed CA (rejected for default product)

## Consequences
CONNECT returns 200 after remote stream ready; TLS bytes opaque to Source.

## Migration impact
Aligns with security model docs.

## Unresolved
None for default mode.

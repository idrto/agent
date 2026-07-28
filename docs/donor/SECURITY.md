# Security Policy

Report vulnerabilities privately to the IDR security team.

## Secrets

Never commit:

- Private signing keys
- Connection tokens
- TLS private keys

## Logging

Production deployments must not log bearer tokens, session secrets, or raw authentication proofs.

## Trust model (v1)

- Discovery document signed by pinned Ed25519 key
- Relay signaling commands signed by relay identity
- QUIC TLS server authentication
- Short-lived connection tokens bound to target, relay, session, epoch

See [docs/SECURITY.md](docs/SECURITY.md).

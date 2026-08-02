# IDR packages (agent view)

Canonical: Billing [`IDR_BILLING_PACKAGES.md`](https://github.com/2keyapp/billing/blob/delegate_permissions/IDR_BILLING_PACKAGES.md), Presence `docs/IDR_BILLING_PACKAGES.md`.

| Package | Source | Target notes |
|---------|--------|--------------|
| Personal | **mTLS required** | ≤5 Targets; same-entity; single-label host |
| Enterprise | **mTLS required** | ≤5 Targets; hierarchy / multi-admin / SCIM |
| Service Provider | **Anonymous Sources allowed** | Per-Target; optional CNAME / LE |
| Data Transfer | N/A | Target pays Relay/TURN to+from bytes |

Agent wiring:

- Target: `[billing_party]` + optional DP identity for Presence mTLS; package from Billing seat.
- Source: `SourceAuthMode::Mtls` when Personal/Enterprise; anonymous only for SP Targets.
- TURN inventory points at [idrto/turn](https://github.com/idrto/turn) coturn nodes.

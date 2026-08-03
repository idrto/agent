# IDR packages (agent view)

Canonical: Billing [`IDR_BILLING_PACKAGES.md`](https://github.com/2keyapp/billing/blob/delegate_permissions/IDR_BILLING_PACKAGES.md), Presence `docs/IDR_BILLING_PACKAGES.md`.

| Package | Source | Target notes |
|---------|--------|--------------|
| Personal | **mTLS required** | ≤5 Targets; same-entity; single-label host |
| Enterprise | **mTLS required** | ≤5 Targets; hierarchy / multi-admin / SCIM |
| Service Provider | **Anonymous Sources allowed** | Per-Target; optional CNAME / LE |
| Data Transfer | N/A | Target pays Relay/TURN to+from bytes |

Agent wiring:

- Target: DeviceIdentity enroll + `[auth].url` mint → `entitlement_jwt` on `register_target`; optional `[billing_party]` as mint hint / local-dev fallback.
- Source: `SourceAuthMode::Mtls` when Personal/Enterprise; anonymous only for SP Targets.
- Package / parties come from JWT claims when Presence `[auth].enabled`; otherwise wire `using_party` / `paying_party`.
- TURN inventory points at [idrto/turn](https://github.com/idrto/turn) coturn nodes.
- `register_target_ack`: logs when platform TURN mint is unavailable (`webrtc_fallback=p2p_only`).
- Exhausted Data Transfer: Presence omits TURN; relay-only Targets/Sources get `payment_required`.
- Relay/TURN interim usage: 1 GiB or 24h (configurable), idempotent HTTP reports to Billing (`POST /api/v1/usage/report`).

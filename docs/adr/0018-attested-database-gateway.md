# ADR-0018: Attested database gateway (confidential computing)

## Status

Proposed (Phase 2 spike)

## Context

ADR-0017 ships usable DB access with Source-held credentials and optional
TLS-in-stream. The Target still **controls the TCP dial**. A compromised or
malicious Target can:

1. Dial a listener it owns, terminate TLS, and steal Source passwords / queries
2. Dump pre-TLS bytes if Source misconfigures SSL

True confidential computing requires the Source to verify that bridging code
is measured and may only dial the sealed endpoint.

## Decision (spike scope)

Pick **one** Target attestation platform first (implementation kickoff chooses
based on supported Target OS):

- Azure / AMD SEV-SNP, or
- Intel TDX, or
- A sealed local enclave process for the connector only

### Required properties

1. **Attested gateway path** — DB bridging runs inside the measured environment.
2. **Remote attestation to Source** — Before DB `openStream` auth, Source verifies
   a quote bound to:
   - gateway binary measurement
   - allowed dial endpoint (`host:port` from sealed config)
   - WebRTC / session identity
3. **Sealed dial policy** — Attested code may only dial the configured upstream;
   config hash is in attestation claims so the Target UI cannot silently retarget.
4. **Optional sealed Target secrets** — For `credential_mode=target`, unwrap secrets
   only inside attested code.
5. **Fail closed** — Modified binary or retargeted dial fails attestation; Source
   refuses the session.

```text
Source  --verify quote-->  Attested gateway  --fixed dial-->  Database
        \-- TLS inside mux (Source↔DB or Source↔enclave) --/
```

## Non-goals (this ADR)

- Multi-cloud TEE matrix in the first spike
- Homomorphic / encrypted-query databases
- Changing ADR-0016’s generic gateway shape (attestation wraps the same TCP bridge)

## Consequences

- Phase 1 remains shippable without TEE hardware.
- Protocol will need an attestation frame or pre-open handshake (append-only mux
  evolution, same rules as `idr-stream-v1`).
- Source policy store for accepted measurements is required (product decision).

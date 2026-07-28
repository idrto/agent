# ADR-0003: libdatachannel as initial WebRTC backend

## Context
Need DataChannels on desktop and mobile; Target already uses `datachannel-rs` (libdatachannel).

## Decision
Keep libdatachannel as the native backend. Public code uses `idr_webrtc::PeerTransport` only — no C++ types in Source/Dart APIs.

## Alternatives
- webrtc-rs
- Browser-only WebRTC

## Consequences
Native build needs cmake/C++; feature-gated; mock/recording transports for tests without cmake.

## Migration impact
Lift `NativePeerSession` behind `PeerTransport` incrementally (adapter in Target first).

## Unresolved
Offerer API parity in native peer for Source production builds.

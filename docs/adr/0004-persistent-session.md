# ADR-0004: Persistent peer connection per Source–Target session

## Context
Creating a PeerConnection per HTTP/TCP flow is expensive and breaks multiplexing goals.

## Decision
One persistent WebRTC session per Source–Target pair; many logical streams on DataChannel(s).

## Alternatives
- One PC per stream
- QUIC-only Source path

## Consequences
Session lifecycle, ICE restart, and failure semantics must be explicit (no silent TCP replay).

## Migration impact
Matches existing Target answerer session manager.

## Unresolved
Multiple payload DataChannels (interactive vs bulk) timing.

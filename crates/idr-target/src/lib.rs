//! IDR Target Agent library (Presence, Relay QUIC, tunnels, ACME, WebRTC answerer).

pub use idr_protocol as protocol;

pub mod acme;
pub mod adapters;
pub mod config;
pub mod identity;
pub mod network;
pub mod plugins;
pub mod presence;
pub mod quic;
pub mod relay;
pub mod shutdown;
pub mod storage;
pub mod telemetry;
pub mod tunnel;
pub mod webrtc;

//! Pure Presence placement helpers (no HTTP / sockets).
//!
//! Used by native DiscoveryClient and by the browser WASM host after JS fetch.

use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_protocol::discovery::{PresenceDiscoveryDocument, PresenceServer};
use idr_protocol::fqhn;
use idr_protocol::placement::{ModuloPlacement, PresencePlacement};

/// Pick primary + secondary Presence indexes for a Target FQHN.
///
/// Dual-mod placement (`hash%N`, `hash%(N-1)`, bump secondary on collide).
/// Dial Primary first, then Secondary when discovery lists ≥2 servers.
pub fn place(
    doc: &PresenceDiscoveryDocument,
    target_fqhn: &str,
) -> Result<(usize, Option<usize>)> {
    let fqhn = fqhn::canonicalize(target_fqhn)
        .map_err(|e| IdrError::new(IdrErrorKind::InvalidArgument, e.to_string()))?;
    ModuloPlacement
        .primary_secondary(&fqhn, &doc.presence_servers)
        .map_err(|e| IdrError::new(IdrErrorKind::SignalingFailed, e.to_string()))
}

/// Ordered dial list: Primary then Secondary Presence servers.
pub fn place_servers<'a>(
    doc: &'a PresenceDiscoveryDocument,
    target_fqhn: &str,
) -> Result<Vec<&'a PresenceServer>> {
    let (primary, secondary) = place(doc, target_fqhn)?;
    let mut out = vec![&doc.presence_servers[primary]];
    if let Some(sec) = secondary {
        out.push(&doc.presence_servers[sec]);
    }
    Ok(out)
}

/// Servers with a usable WSS URL, in placement order (primary then secondary).
pub fn place_wss_servers(
    doc: &PresenceDiscoveryDocument,
    target_fqhn: &str,
) -> Result<Vec<PresenceServer>> {
    let ordered = place_servers(doc, target_fqhn)?;
    let with_wss: Vec<PresenceServer> = ordered
        .into_iter()
        .filter(|s| !s.wss_url.trim().is_empty())
        .cloned()
        .collect();
    if with_wss.is_empty() {
        return Err(IdrError::new(
            IdrErrorKind::SignalingFailed,
            "no Presence server with wss_url after placement",
        ));
    }
    Ok(with_wss)
}

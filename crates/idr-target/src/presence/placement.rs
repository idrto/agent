use idr_protocol::discovery::PresenceServer;
use idr_protocol::placement::{ModuloPlacement, PresencePlacement};

pub fn select_primary_secondary(
    fqhn: &str,
    servers: &[PresenceServer],
) -> idr_protocol::errors::Result<(usize, Option<usize>)> {
    ModuloPlacement.primary_secondary(fqhn, servers)
}

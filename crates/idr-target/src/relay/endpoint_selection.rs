use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use crate::network::AddressFamily;
use crate::relay::descriptor::StableRelayDescriptor;
use crate::storage::models::RelayConnectionHistoryRow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointChoice {
    Ipv6(SocketAddr),
    Ipv4(SocketAddr),
}

pub fn parse_endpoints(
    descriptor: &StableRelayDescriptor,
) -> (Option<SocketAddr>, Option<SocketAddr>) {
    let v4 = descriptor
        .ipv4
        .as_ref()
        .and_then(|ip| parse_addr(ip, descriptor.port, false));
    let v6 = descriptor
        .ipv6
        .as_ref()
        .and_then(|ip| parse_addr(ip, descriptor.port, true));
    (v4, v6)
}

fn parse_addr(ip: &str, port: u16, v6: bool) -> Option<SocketAddr> {
    if v6 {
        Ipv6Addr::from_str(ip)
            .ok()
            .map(|a| SocketAddr::new(IpAddr::V6(a), port))
    } else {
        Ipv4Addr::from_str(ip)
            .ok()
            .map(|a| SocketAddr::new(IpAddr::V4(a), port))
    }
}

pub fn select_endpoint(
    descriptor: &StableRelayDescriptor,
    history: Option<&RelayConnectionHistoryRow>,
    prefer_ipv6: bool,
) -> Option<EndpointChoice> {
    let (v4, v6) = parse_endpoints(descriptor);

    if let Some(row) = history {
        if row.last_success_family == Some(6) {
            if let Some(v6) = v6 {
                return Some(EndpointChoice::Ipv6(v6));
            }
        }
        if row.last_success_family == Some(4) {
            if let Some(v4) = v4 {
                return Some(EndpointChoice::Ipv4(v4));
            }
        }
    }

    if prefer_ipv6 {
        if let Some(v6) = v6 {
            return Some(EndpointChoice::Ipv6(v6));
        }
    }
    v4.map(EndpointChoice::Ipv4)
        .or_else(|| v6.map(EndpointChoice::Ipv6))
}

pub fn family_label(choice: EndpointChoice) -> &'static str {
    match choice {
        EndpointChoice::Ipv4(_) => "ipv4",
        EndpointChoice::Ipv6(_) => "ipv6",
    }
}

pub fn choice_family(choice: EndpointChoice) -> i32 {
    match choice {
        EndpointChoice::Ipv4(_) => AddressFamily::Ipv4 as i32,
        EndpointChoice::Ipv6(_) => AddressFamily::Ipv6 as i32,
    }
}

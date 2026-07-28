use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use tracing::debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum AddressFamily {
    Ipv4 = 4,
    Ipv6 = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkCapabilities {
    pub ipv4: bool,
    pub ipv6: bool,
}

impl NetworkCapabilities {
    pub fn detect() -> Self {
        let ipv4 = probe_udp(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let ipv6 = probe_udp(IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        debug!(ipv4, ipv6, "detected network capabilities");
        Self { ipv4, ipv6 }
    }

    pub fn dual_stack(&self) -> bool {
        self.ipv4 && self.ipv6
    }

    pub fn preferred_family(&self, prefer_ipv6: bool) -> Option<AddressFamily> {
        if prefer_ipv6 && self.ipv6 {
            Some(AddressFamily::Ipv6)
        } else if self.ipv4 {
            Some(AddressFamily::Ipv4)
        } else if self.ipv6 {
            Some(AddressFamily::Ipv6)
        } else {
            None
        }
    }
}

/// Wildcard UDP bind for QUIC endpoints; prefers IPv6 when available.
pub fn quic_bind_addr(caps: NetworkCapabilities) -> SocketAddr {
    if caps.ipv6 {
        "[::]:0".parse().expect("ipv6 wildcard")
    } else {
        "0.0.0.0:0".parse().expect("ipv4 wildcard")
    }
}

fn probe_udp(bind: IpAddr) -> bool {
    UdpSocket::bind(SocketAddr::new(bind, 0)).is_ok()
}

pub async fn probe_reachability(cap: NetworkCapabilities) -> NetworkCapabilities {
    let mut caps = cap;
    if caps.ipv4 {
        caps.ipv4 = udp_send_probe(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))).await;
    }
    if caps.ipv6 {
        caps.ipv6 = udp_send_probe(IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888))).await;
    }
    caps
}

async fn udp_send_probe(remote: IpAddr) -> bool {
    tokio::task::spawn_blocking(move || {
        let socket = match UdpSocket::bind(match remote {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        }) {
            Ok(s) => s,
            Err(_) => return false,
        };
        socket.set_read_timeout(Some(Duration::from_millis(200))).ok();
        let dest = SocketAddr::new(remote, 53);
        socket.send_to(b"idr-probe", dest).is_ok()
    })
    .await
    .unwrap_or(false)
}

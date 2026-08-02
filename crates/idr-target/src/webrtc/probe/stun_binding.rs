//! UDP STUN binding RTT measurement for TURN probe ranking.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use rand::RngCore;
use tokio::net::UdpSocket;

const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

pub async fn measure_stun_binding_rtt(
    target: SocketAddr,
    samples: usize,
    timeout: Duration,
) -> Option<u32> {
    let bind = match target.ip() {
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind).await.ok()?;
    let mut rtts = Vec::new();
    for _ in 0..samples {
        if let Some(rtt) = single_sample(&socket, target, timeout).await {
            rtts.push(rtt);
        }
    }
    if rtts.is_empty() {
        return None;
    }
    rtts.sort_unstable();
    Some(rtts[rtts.len() / 2])
}

async fn single_sample(socket: &UdpSocket, target: SocketAddr, timeout: Duration) -> Option<u32> {
    let mut txn = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut txn);
    let mut req = [0u8; 20];
    req[0] = 0x00;
    req[1] = 0x01; // Binding Request
    req[2] = 0x00;
    req[3] = 0x00; // length
    req[4..8].copy_from_slice(&MAGIC_COOKIE);
    req[8..20].copy_from_slice(&txn);

    let start = Instant::now();
    socket.send_to(&req, target).await.ok()?;
    let mut buf = [0u8; 512];
    match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
        Ok(Ok((n, from))) if n >= 20 && from == target => {
            // Binding Success Response = 0x0101, matching magic + transaction id
            if buf[0] == 0x01 && buf[1] == 0x01 && buf[4..8] == MAGIC_COOKIE && buf[8..20] == txn {
                Some(start.elapsed().as_millis() as u32)
            } else {
                None
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unreachable_host_times_out() {
        let addr: SocketAddr = "127.0.0.1:9".parse().unwrap();
        let rtt = measure_stun_binding_rtt(addr, 1, Duration::from_millis(100)).await;
        assert!(rtt.is_none());
    }
}

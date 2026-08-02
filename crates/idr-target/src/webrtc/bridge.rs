//! Bridge mux streams to nginx or outbound TCP.

use tokio::net::TcpStream;
use tracing::debug;

use crate::config::{NginxConfig, WebRtcPolicyConfig};
use idr_protocol::stream_mux::{StreamFrame, StreamKind, StreamOpenMeta};

pub async fn handle_stream_open(
    frame: StreamFrame,
    nginx: &NginxConfig,
    expected_fqhn: &str,
    policy: &WebRtcPolicyConfig,
) -> anyhow::Result<TcpStream> {
    let StreamFrame::Open {
        kind,
        meta,
        stream_id,
    } = frame
    else {
        anyhow::bail!("expected StreamFrame::Open");
    };
    let tcp = open_upstream(kind, meta, nginx, policy, expected_fqhn).await?;
    debug!(stream_id, ?kind, "webrtc stream bridge connected");
    Ok(tcp)
}

fn validate_open(
    meta: &StreamOpenMeta,
    expected_fqhn: &str,
    _policy: &WebRtcPolicyConfig,
) -> anyhow::Result<()> {
    let claimed = idr_protocol::fqhn::canonicalize(&meta.target_fqhn)
        .unwrap_or_else(|_| meta.target_fqhn.to_ascii_lowercase());
    if claimed != expected_fqhn {
        anyhow::bail!("StreamOpen FQHN mismatch");
    }
    Ok(())
}

async fn connect_upstream(
    kind: StreamKind,
    meta: StreamOpenMeta,
    nginx: &NginxConfig,
    policy: &WebRtcPolicyConfig,
) -> anyhow::Result<TcpStream> {
    match kind {
        StreamKind::TlsPassthrough => TcpStream::connect(nginx.tls_upstream)
            .await
            .map_err(Into::into),
        StreamKind::HttpPassthrough => TcpStream::connect(nginx.http_upstream)
            .await
            .map_err(Into::into),
        StreamKind::TcpConnect => {
            let host = meta
                .host
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("TcpConnect missing host"))?;
            let port = meta
                .port
                .ok_or_else(|| anyhow::anyhow!("TcpConnect missing port"))?;
            if policy.deny_private_ips && is_private_host(host) {
                anyhow::bail!("TcpConnect to private host denied");
            }
            if !policy.allowed_tcp_connect_suffixes.is_empty()
                && !policy
                    .allowed_tcp_connect_suffixes
                    .iter()
                    .any(|suffix| host.ends_with(suffix))
            {
                anyhow::bail!("TcpConnect host not allowed");
            }
            TcpStream::connect((host, port)).await.map_err(Into::into)
        }
    }
}

fn is_private_host(host: &str) -> bool {
    let host = host
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".localhost") || host == "::1" {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || (v6.segments()[0] & 0xfe00) == 0xfc00 // ULA
                    || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local
            }
        };
    }
    // Hostname literals that look like RFC1918 (best-effort before DNS).
    host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.starts_with("172.16.")
        || host.starts_with("172.17.")
        || host.starts_with("172.18.")
        || host.starts_with("172.19.")
        || host.starts_with("172.2")
        || host.starts_with("172.30.")
        || host.starts_with("172.31.")
}

/// Connect upstream and return the live TCP stream for the caller to pipe.
pub async fn open_upstream(
    kind: StreamKind,
    meta: StreamOpenMeta,
    nginx: &NginxConfig,
    policy: &WebRtcPolicyConfig,
    expected_fqhn: &str,
) -> anyhow::Result<TcpStream> {
    validate_open(&meta, expected_fqhn, policy)?;
    connect_upstream(kind, meta, nginx, policy).await
}

pub async fn pipe_bidirectional(
    mut left_read: impl tokio::io::AsyncRead + Unpin,
    mut left_write: impl tokio::io::AsyncWrite + Unpin,
    mut tcp: TcpStream,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut tcp_read, mut tcp_write) = tcp.split();
    let c1 = async {
        let n = tokio::io::copy(&mut left_read, &mut tcp_write).await?;
        let _ = tcp_write.shutdown().await;
        Ok::<_, anyhow::Error>(n)
    };
    let c2 = async {
        let n = tokio::io::copy(&mut tcp_read, &mut left_write).await?;
        let _ = left_write.shutdown().await;
        Ok::<_, anyhow::Error>(n)
    };
    let (_, _) = tokio::join!(c1, c2);
    Ok(())
}

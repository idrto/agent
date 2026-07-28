//! Accept opaque tunnel streams from Relay and bridge to local nginx.
//!
//! Design fix: full-duplex copy with half-close (not `select!`) so a client FIN
//! does not truncate the nginx response. See docs/TLS_PASSTHROUGH.md § Design fixes.

use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::config::NginxConfig;
use idr_protocol::MAX_FRAME_BYTES;
use idr_protocol::tunnel::{TunnelOpen, TunnelStreamKind};
use crate::relay::arena::RelayConnection;

/// Accept opaque tunnel streams from Relay and bridge to local nginx.
pub fn spawn_acceptor(
    conn: quinn::Connection,
    nginx: Arc<NginxConfig>,
    expected_fqhn: String,
    relay_conn: Arc<RelayConnection>,
) {
    tokio::spawn(async move {
        loop {
            match conn.accept_bi().await {
                Ok((send, recv)) => {
                    let nginx = nginx.clone();
                    let expected_fqhn = expected_fqhn.clone();
                    let relay_conn = relay_conn.clone();
                    relay_conn.stream_opened();
                    tokio::spawn(async move {
                        let result =
                            handle_tunnel_stream(send, recv, &nginx, &expected_fqhn).await;
                        relay_conn.stream_closed();
                        if let Err(e) = result {
                            debug!(error = %e, "tunnel stream ended");
                        }
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed(_))
                | Err(quinn::ConnectionError::LocallyClosed) => break,
                Err(e) => {
                    warn!(error = %e, "tunnel accept error — closing QUIC so supervisor can reconnect");
                    conn.close(0u32.into(), b"tunnel accept failure");
                    break;
                }
            }
        }
    });
}

async fn handle_tunnel_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    nginx: &NginxConfig,
    expected_fqhn: &str,
) -> Result<()> {
    let open = read_tunnel_open(&mut recv).await?;
    let claimed = idr_protocol::fqhn::canonicalize(&open.target_fqhn)
        .unwrap_or_else(|_| open.target_fqhn.to_ascii_lowercase());
    if claimed != expected_fqhn {
        anyhow::bail!(
            "TunnelOpen FQHN mismatch: claimed={claimed} expected={expected_fqhn}"
        );
    }
    let upstream = match open.kind {
        TunnelStreamKind::TlsPassthrough => nginx.tls_upstream,
        TunnelStreamKind::HttpPassthrough => nginx.http_upstream,
    };
    debug!(?open.kind, %upstream, "tunnel bridge to nginx");
    let tcp = TcpStream::connect(upstream)
        .await
        .with_context(|| format!("connect nginx upstream {upstream}"))?;
    pipe_quic_tcp(recv, send, tcp).await
}

async fn read_tunnel_open(recv: &mut RecvStream) -> Result<TunnelOpen> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        anyhow::bail!("TunnelOpen frame too large: {len} > {MAX_FRAME_BYTES}");
    }
    let mut payload = vec![0u8; len];
    recv.read_exact(&mut payload).await?;
    let mut frame = len_buf.to_vec();
    frame.extend_from_slice(&payload);
    TunnelOpen::decode(&frame).map_err(|e| anyhow::anyhow!("{e}"))
}

/// Full-duplex pipe: each direction runs to completion with half-close on EOF.
async fn pipe_quic_tcp(
    mut recv: RecvStream,
    mut send: SendStream,
    tcp: TcpStream,
) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let quic_to_tcp = async {
        let mut buf = [0u8; 8192];
        loop {
            match recv.read(&mut buf).await? {
                Some(0) | None => break,
                Some(n) => tcp_write.write_all(&buf[..n]).await?,
            }
        }
        let _ = tcp_write.shutdown().await;
        Ok::<(), anyhow::Error>(())
    };
    let tcp_to_quic = async {
        let mut buf = [0u8; 8192];
        loop {
            let n = tcp_read.read(&mut buf).await?;
            if n == 0 {
                let _ = send.finish();
                break;
            }
            send.write_all(&buf[..n]).await?;
        }
        Ok::<(), anyhow::Error>(())
    };
    let (a, b) = tokio::join!(quic_to_tcp, tcp_to_quic);
    a?;
    b?;
    Ok(())
}

/// Spawn stream acceptor on an established relay QUIC connection.
pub fn spawn_on_connection(
    quic: Arc<crate::quic::RelayQuicConnection>,
    nginx: Arc<NginxConfig>,
    expected_fqhn: String,
    relay_conn: Arc<RelayConnection>,
) {
    spawn_acceptor(
        quic.connection().clone(),
        nginx,
        expected_fqhn,
        relay_conn,
    );
}

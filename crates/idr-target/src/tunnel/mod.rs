//! Accept opaque tunnel streams from Relay and bridge to local nginx.
//!
//! Native `*.idr.to` after Relay wildcard terminate uses `HttpPassthrough` →
//! `http_upstream` (default loopback `:80`). Leg 2 encryption is the QUIC TLS
//! session to the Relay identity only — do not nest TLS into nginx (ADR-0012).
//!
//! Design fix: full-duplex copy with half-close (not `select!`) so a client FIN
//! does not truncate the nginx response. See docs/TLS_PASSTHROUGH.md § Design fixes.

use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::{RecvStream, SendStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::config::NginxConfig;
use crate::relay::arena::RelayConnection;
use idr_protocol::tunnel::{TunnelOpen, TunnelStreamKind};
use idr_protocol::MAX_FRAME_BYTES;

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
                        let result = handle_tunnel_stream(send, recv, &nginx, &expected_fqhn).await;
                        relay_conn.stream_closed();
                        if let Err(e) = result {
                            warn!(error = %e, "tunnel stream ended");
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
    send: SendStream,
    mut recv: RecvStream,
    nginx: &NginxConfig,
    expected_fqhn: &str,
) -> Result<()> {
    let open = read_tunnel_open(&mut recv).await?;
    let claimed = idr_protocol::fqhn::canonicalize(&open.target_fqhn)
        .unwrap_or_else(|_| open.target_fqhn.to_ascii_lowercase());
    if claimed != expected_fqhn {
        anyhow::bail!("TunnelOpen FQHN mismatch: claimed={claimed} expected={expected_fqhn}");
    }
    let (upstream, head) = match open.kind {
        TunnelStreamKind::TlsPassthrough => (nginx.tls_upstream, Vec::new()),
        TunnelStreamKind::HttpPassthrough => {
            // ACME HTTP-01 for our own orders is answered here (no nginx needed).
            let head = read_request_line(&mut recv).await?;
            if let Some(body) = acme_token(&head).and_then(crate::acme::http01_key_authorization) {
                info!("tunnel answered ACME HTTP-01 challenge");
                return write_http01(send, &body).await;
            }
            (nginx.http_upstream, head)
        }
    };
    debug!(?open.kind, %upstream, "tunnel bridge to nginx");
    let mut tcp = TcpStream::connect(upstream)
        .await
        .with_context(|| format!("connect nginx upstream {upstream}"))?;
    tcp.write_all(&head).await?;
    info!(?open.kind, %upstream, "tunnel bridged to upstream");
    pipe_quic_tcp(recv, send, tcp).await
}

/// Max bytes read while looking for the HTTP request line.
const MAX_REQUEST_LINE: usize = 8192;

/// Bytes up to and including the first `\r\n` (or 8 KiB / EOF). Anything read
/// past the line is kept and replayed to the upstream.
async fn read_request_line(recv: &mut RecvStream) -> Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    while head.len() < MAX_REQUEST_LINE && !head.windows(2).any(|w| w == b"\r\n") {
        match recv.read(&mut buf).await? {
            Some(n) if n > 0 => head.extend_from_slice(&buf[..n]),
            _ => break,
        }
    }
    Ok(head)
}

/// `GET /.well-known/acme-challenge/<token> HTTP/1.1` → `<token>`.
fn acme_token(head: &[u8]) -> Option<&str> {
    let line = std::str::from_utf8(head.split(|b| *b == b'\r').next()?).ok()?;
    let mut parts = line.split(' ');
    let (method, path) = (parts.next()?, parts.next()?);
    if method != "GET" {
        return None;
    }
    let token = path.strip_prefix(idr_protocol::tunnel::ACME_WELL_KNOWN_PREFIX)?;
    (!token.is_empty() && !token.contains('/')).then_some(token)
}

async fn write_http01(mut send: SendStream, body: &str) -> Result<()> {
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    send.write_all(resp.as_bytes()).await?;
    let _ = send.finish();
    Ok(())
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
async fn pipe_quic_tcp(mut recv: RecvStream, mut send: SendStream, tcp: TcpStream) -> Result<()> {
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
    spawn_acceptor(quic.connection().clone(), nginx, expected_fqhn, relay_conn);
}

#[cfg(test)]
mod tests {
    use super::acme_token;

    #[test]
    fn finds_acme_tokens_in_get_request_lines() {
        let req =
            b"GET /.well-known/acme-challenge/tok_en-1 HTTP/1.1\r\nHost: app.customer.com\r\n";
        assert_eq!(acme_token(req), Some("tok_en-1"));
        assert_eq!(acme_token(b"GET /index.html HTTP/1.1\r\n"), None);
        assert_eq!(
            acme_token(b"POST /.well-known/acme-challenge/t HTTP/1.1\r\n"),
            None
        );
        assert_eq!(
            acme_token(b"GET /.well-known/acme-challenge/ HTTP/1.1\r\n"),
            None
        );
        assert_eq!(
            acme_token(b"GET /.well-known/acme-challenge/a/b HTTP/1.1\r\n"),
            None
        );
    }
}

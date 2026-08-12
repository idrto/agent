//! Generic named service gateway — HTTP reverse proxy or raw TCP forward.
//!
//! Config-driven; no application-specific (Ollama/HF/…) logic.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use idr_core::connector::{Connector, NamedService};
use idr_core::error::{IdrError, IdrErrorKind, Result};
use idr_protocol::stream_mux::{StreamKind, StreamOpenMeta};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

use crate::config::{
    GatewayCredentialMode, GatewayServiceConfig, GatewayServiceType, InjectHeaderConfig,
};

/// One registered `[[services]]` entry as a Connector.
pub struct ServiceGatewayConnector {
    cfg: GatewayServiceConfig,
    http: reqwest::Client,
}

impl ServiceGatewayConnector {
    pub fn new(cfg: GatewayServiceConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(180))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest");
        Self { cfg, http }
    }

    pub fn named_service(cfg: GatewayServiceConfig) -> (NamedService, Arc<dyn Connector>) {
        let name = cfg.name.clone();
        let fqhn = cfg.target_fqhn.clone().unwrap_or_default();
        let transport = match cfg.service_type {
            GatewayServiceType::Http => {
                idr_protocol::stream_mux::ServiceTransportKind::Http
            }
            GatewayServiceType::Tcp => idr_protocol::stream_mux::ServiceTransportKind::Tcp,
        };
        // HTTP + inject_headers implies Target-held secrets unless explicitly overridden.
        let mut mode = cfg.credential_mode;
        if mode == GatewayCredentialMode::Source
            && cfg.service_type == GatewayServiceType::Http
            && !cfg.inject_headers.is_empty()
        {
            mode = GatewayCredentialMode::Target;
        }
        let require_tls = cfg.effective_require_upstream_tls();
        let connector: Arc<dyn Connector> = Arc::new(Self::new(cfg));
        (
            NamedService::new(
                name.clone(),
                StreamKind::TcpConnect,
                StreamOpenMeta {
                    target_fqhn: fqhn,
                    service_name: Some(name),
                    host: None,
                    port: None,
                },
            )
            .with_credential_policy(mode.into(), require_tls)
            .with_transport_kind(transport),
            connector,
        )
    }

    fn tcp_addr(&self) -> Result<String> {
        self.cfg.tcp_endpoint().map_err(|e| {
            IdrError::new(IdrErrorKind::InvalidArgument, format!("service {}: {e}", self.cfg.name))
        })
    }

    fn resolve_inject_headers(&self) -> Result<HashMap<String, String>> {
        let mut out = HashMap::new();
        for inj in &self.cfg.inject_headers {
            let value = resolve_inject_value(inj)?;
            out.insert(inj.name.clone(), value);
        }
        Ok(out)
    }
}

fn resolve_inject_value(inj: &InjectHeaderConfig) -> Result<String> {
    let raw = if let Some(_env) = &inj.from_env {
        std::env::var(_env).map_err(|_| {
            // Never include the env var name or value — Source sees OpenError text.
            IdrError::new(
                IdrErrorKind::InvalidArgument,
                format!("inject header {}: secret unavailable", inj.name),
            )
        })?
    } else if let Some(_path) = &inj.from_file {
        std::fs::read_to_string(_path).map_err(|_| {
            IdrError::new(
                IdrErrorKind::InvalidArgument,
                format!("inject header {}: secret unavailable", inj.name),
            )
        })?
    } else {
        return Err(IdrError::new(
            IdrErrorKind::InvalidArgument,
            format!("inject header {}: secret unavailable", inj.name),
        ));
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(IdrError::new(
            IdrErrorKind::InvalidArgument,
            format!("inject header {}: secret unavailable", inj.name),
        ));
    }
    let prefix = inj.prefix.as_deref().unwrap_or("");
    Ok(format!("{prefix}{raw}"))
}

#[async_trait]
impl Connector for ServiceGatewayConnector {
    fn name(&self) -> &str {
        &self.cfg.name
    }

    fn supported_kinds(&self) -> &[StreamKind] {
        &[StreamKind::TcpConnect, StreamKind::HttpPassthrough]
    }

    async fn connect(&self, _kind: StreamKind, _meta: &StreamOpenMeta) -> Result<TcpStream> {
        match self.cfg.service_type {
            GatewayServiceType::Tcp => {
                let addr = self.tcp_addr()?;
                debug!(service = %self.cfg.name, %addr, "gateway tcp connect");
                TcpStream::connect(&addr).await.map_err(|e| {
                    IdrError::new(
                        IdrErrorKind::ConnectionRefused,
                        format!("service {}: {e}", self.cfg.name),
                    )
                })
            }
            GatewayServiceType::Http => self.connect_http_proxy().await,
        }
    }
}

impl ServiceGatewayConnector {
    async fn connect_http_proxy(&self) -> Result<TcpStream> {
        let listener = TcpListener::bind("127.0.0.1:0").await.map_err(|e| {
            IdrError::new(
                IdrErrorKind::ConnectionRefused,
                format!("service {} bind: {e}", self.cfg.name),
            )
        })?;
        let addr = listener.local_addr().map_err(|e| {
            IdrError::new(
                IdrErrorKind::ConnectionRefused,
                format!("service {} local_addr: {e}", self.cfg.name),
            )
        })?;

        let cfg = self.cfg.clone();
        let http = self.http.clone();
        let inject = self.resolve_inject_headers()?;
        tokio::spawn(async move {
            match listener.accept().await {
                Ok((peer, _)) => {
                    if let Err(e) = http_proxy_connection(peer, cfg, http, inject).await {
                        warn!(error = %e, "gateway http proxy failed");
                    }
                }
                Err(e) => warn!(error = %e, "gateway http accept failed"),
            }
        });

        debug!(service = %self.cfg.name, %addr, "gateway http loopback proxy");
        TcpStream::connect(addr).await.map_err(|e| {
            IdrError::new(
                IdrErrorKind::ConnectionRefused,
                format!("service {} connect: {e}", self.cfg.name),
            )
        })
    }
}

async fn http_proxy_connection(
    mut peer: TcpStream,
    cfg: GatewayServiceConfig,
    http: reqwest::Client,
    inject: HashMap<String, String>,
) -> anyhow::Result<()> {
    let req = read_http_request(&mut peer).await?;
    let base = cfg.base_url_parsed()?;
    let path_q = if req.path.starts_with('/') {
        req.path.clone()
    } else {
        format!("/{}", req.path)
    };
    let url = format!(
        "{}{}",
        base.trim_end_matches('/'),
        path_q
    );

    let host_header = host_header_for(&base);

    let mut builder = http
        .request(
            reqwest::Method::from_bytes(req.method.as_bytes())
                .unwrap_or(reqwest::Method::GET),
            &url,
        )
        .header("Host", &host_header)
        .header("Connection", "close");

    // Forward selected client headers (skip hop-by-hop / Host / Content-Length).
    for (k, v) in &req.headers {
        let lower = k.to_ascii_lowercase();
        if lower == "host"
            || lower == "connection"
            || lower == "content-length"
            || lower == "transfer-encoding"
            || inject.keys().any(|ik| ik.eq_ignore_ascii_case(k))
        {
            continue;
        }
        builder = builder.header(k, v);
    }
    for (k, v) in &inject {
        builder = builder.header(k, v);
    }
    if !req.body.is_empty() {
        let ct = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone());
        if let Some(ct) = ct {
            builder = builder.header("Content-Type", ct);
        }
        builder = builder.body(req.body);
    }

    debug!(service = %cfg.name, %url, "gateway forwarding http");
    let mut resp = builder.send().await?;
    let status = resp.status().as_u16();
    let content_length = resp.content_length();
    let mut resp_headers: Vec<(String, String)> = Vec::new();
    for (k, v) in resp.headers().iter() {
        let name = k.as_str();
        if name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("connection")
            || name.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        if let Ok(val) = v.to_str() {
            resp_headers.push((name.to_string(), val.to_string()));
        }
    }
    // Stream body as chunks arrive (required for Ollama/OpenAI stream:true).
    let head = build_http_response_head(status, &resp_headers, content_length);
    peer.write_all(&head).await?;
    peer.flush().await?;
    while let Some(chunk) = resp.chunk().await? {
        if chunk.is_empty() {
            continue;
        }
        peer.write_all(&chunk).await?;
        peer.flush().await?;
    }
    peer.shutdown().await.ok();
    Ok(())
}

fn host_header_for(base_url: &str) -> String {
    // http://127.0.0.1:11434/ -> 127.0.0.1:11434
    let without = base_url
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .trim_end_matches('/');
    without.split('/').next().unwrap_or(without).to_string()
}

struct ClientHttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

async fn read_http_request(stream: &mut TcpStream) -> anyhow::Result<ClientHttpRequest> {
    let mut buf = Vec::with_capacity(8 * 1024);
    let mut tmp = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            anyhow::bail!("client closed before HTTP headers complete");
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        if buf.len() > 256 * 1024 {
            anyhow::bail!("HTTP headers too large");
        }
    }

    let header_text = std::str::from_utf8(&buf[..header_end])?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut headers = HashMap::new();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = val.parse().unwrap_or(0);
            }
            headers.insert(key, val);
        }
    }

    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
        if body.len() > 32 * 1024 * 1024 {
            anyhow::bail!("HTTP body too large");
        }
    }
    body.truncate(content_length);

    Ok(ClientHttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn build_http_response_head(
    status: u16,
    headers: &[(String, String)],
    content_length: Option<u64>,
) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        410 => "Gone",
        422 => "Unprocessable Entity",
        502 => "Bad Gateway",
        _ if (200..300).contains(&status) => "OK",
        _ => "Error",
    };
    let mut out = format!("HTTP/1.1 {status} {reason}\r\n").into_bytes();
    for (k, v) in headers {
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if let Some(len) = content_length {
        out.extend_from_slice(format!("Content-Length: {len}\r\n").as_bytes());
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    out
}

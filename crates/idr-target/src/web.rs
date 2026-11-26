//! Browser web gateway: serve `[[services]]` that set `web_path` to browsers.
//!
//! Custom domains arrive as opaque TLS (`TlsPassthrough`): the agent terminates
//! TLS with the ACME certificate in `acme.cert_dir/<domain>/`. Native `*.idr.to`
//! arrive as HTTP after Relay terminate (`HttpPassthrough`). Both then route by
//! longest path prefix to the service upstream.
//!
//! `web_access = "private"` (default) needs the Target's `[web].access_key`:
//! cookie `idr_key`, `Authorization: Bearer <key>`, or a one-time `?idr_key=`
//! link that sets the cookie. `public` is open. Without any `web_path` service
//! the gateway is off and tunnels keep bridging to `[nginx]` upstreams.

use std::collections::HashMap;
use std::convert::Infallible;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result};
use bytes::Bytes;
use http::header::{self, HeaderName, HeaderValue};
use http::{Request, Response, StatusCode, Uri};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use idr_telemetry::Secret;
use parking_lot::Mutex;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

use crate::config::{Config, GatewayServiceType, WebAccess};

type Body = BoxBody<Bytes, hyper::Error>;

const KEY_PARAM: &str = "idr_key";

/// One browser route: path prefix → loopback HTTP service.
#[derive(Debug)]
struct WebRoute {
    name: String,
    /// `/` or `/name` (no trailing slash).
    prefix: String,
    /// `host:port` of the upstream (http only).
    authority: String,
    public: bool,
    inject: Vec<(HeaderName, HeaderValue)>,
}

pub struct WebGateway {
    routes: Vec<WebRoute>,
    access_key: Option<Secret<String>>,
    tls: Arc<rustls::ServerConfig>,
}

impl std::fmt::Debug for WebGateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebGateway")
            .field("routes", &self.routes)
            .finish_non_exhaustive()
    }
}

impl WebGateway {
    /// `None` when no service sets `web_path` (gateway off, old behavior).
    pub fn from_config(cfg: &Config) -> Option<Arc<Self>> {
        let mut routes = Vec::new();
        for s in &cfg.services {
            let Some(path) = s.web_path.as_deref() else {
                continue;
            };
            match web_route(s, path) {
                Ok(r) => routes.push(r),
                Err(e) => {
                    warn!(event = "target.web_route_skipped", route = %s.name, error.message = %e)
                }
            }
        }
        if routes.is_empty() {
            return None;
        }
        // Longest prefix first.
        routes.sort_by_key(|r| std::cmp::Reverse(r.prefix.len()));
        let access_key = cfg
            .web
            .access_key
            .as_ref()
            .map(|k| k.expose_str().trim())
            .filter(|k| k.len() >= 16)
            .map(|k| Secret::new(k.to_string()));
        if access_key.is_none() && routes.iter().any(|r| !r.public) {
            warn!(event = "target.web_access_key_missing");
        }
        let domains = cfg
            .acme
            .domains
            .iter()
            .map(|d| d.trim().to_ascii_lowercase())
            .collect();
        info!(event = "target.web_gateway_enabled", count = routes.len());
        Some(Arc::new(Self::new(
            routes,
            access_key,
            cfg.acme.cert_dir.clone(),
            domains,
        )))
    }

    fn new(
        routes: Vec<WebRoute>,
        access_key: Option<Secret<String>>,
        cert_dir: PathBuf,
        domains: Vec<String>,
    ) -> Self {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let resolver = Arc::new(DirCertResolver {
            dir: cert_dir,
            domains,
            provider: provider.clone(),
            cache: Mutex::new(HashMap::new()),
        });
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("aws-lc-rs supports the default TLS versions")
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Self {
            routes,
            access_key,
            tls: Arc::new(tls),
        }
    }

    /// Custom domain: terminate TLS here, then serve HTTP.
    pub async fn serve_tls<S>(self: Arc<Self>, io: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let tls = tokio_rustls::TlsAcceptor::from(self.tls.clone())
            .accept(io)
            .await
            .context("web TLS handshake")?;
        self.serve_http(tls).await
    }

    /// Plain HTTP (native `*.idr.to` after Relay terminate).
    pub async fn serve_http<S>(self: Arc<Self>, io: S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        hyper::server::conn::http1::Builder::new()
            .serve_connection(
                TokioIo::new(io),
                service_fn(move |req| {
                    let gw = self.clone();
                    async move { Ok::<_, Infallible>(gw.handle(req).await) }
                }),
            )
            .with_upgrades()
            .await
            .context("web HTTP connection")
    }

    async fn handle(&self, req: Request<Incoming>) -> Response<Body> {
        let path = req.uri().path().to_string();
        let Some(route) = self
            .routes
            .iter()
            .find(|r| matches_prefix(&r.prefix, &path))
        else {
            return text(StatusCode::NOT_FOUND, "Not found\n");
        };
        // `/ollama` → `/ollama/` so relative links resolve under the prefix.
        if route.prefix != "/" && path == route.prefix {
            let q = req
                .uri()
                .query()
                .map(|q| format!("?{q}"))
                .unwrap_or_default();
            return redirect(&format!("{path}/{q}"), None);
        }
        if !route.public {
            match self.check_access(&req) {
                Access::Granted => {}
                Access::Link(location, cookie) => return redirect(&location, Some(&cookie)),
                Access::Denied => {
                    info!(event = "target.web_request_denied", route = %route.name, reason = "access_key");
                    return login_page();
                }
            }
        }
        match self.proxy(route, req).await {
            Ok(r) => r,
            Err(e) => {
                warn!(event = "target.web_upstream_failed", route = %route.name, error.message = %e);
                text(
                    StatusCode::BAD_GATEWAY,
                    "Service not reachable on this machine\n",
                )
            }
        }
    }

    fn check_access(&self, req: &Request<Incoming>) -> Access {
        let Some(key) = &self.access_key else {
            return Access::Denied;
        };
        let key = key.expose().as_bytes();
        if let Some(q) = req.uri().query() {
            let (given, rest): (Vec<_>, Vec<_>) =
                q.split('&').partition(|p| p.starts_with("idr_key="));
            if let Some(v) = given.first().map(|p| &p[KEY_PARAM.len() + 1..]) {
                if ct_eq(v.as_bytes(), key) {
                    let rest = rest.join("&");
                    let loc = if rest.is_empty() {
                        req.uri().path().to_string()
                    } else {
                        format!("{}?{rest}", req.uri().path())
                    };
                    let cookie = format!(
                        "{KEY_PARAM}={v}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000"
                    );
                    return Access::Link(loc, cookie);
                }
            }
        }
        let bearer = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        if bearer.is_some_and(|b| ct_eq(b.trim().as_bytes(), key)) {
            return Access::Granted;
        }
        let cookie_ok = req
            .headers()
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(';'))
            .filter_map(|c| c.trim().strip_prefix("idr_key="))
            .any(|v| ct_eq(v.as_bytes(), key));
        if cookie_ok {
            Access::Granted
        } else {
            Access::Denied
        }
    }

    async fn proxy(&self, route: &WebRoute, mut req: Request<Incoming>) -> Result<Response<Body>> {
        // Path under the prefix, query kept.
        let path = req.uri().path();
        let rest = if route.prefix == "/" {
            path
        } else {
            &path[route.prefix.len()..]
        };
        let rest = if rest.is_empty() { "/" } else { rest };
        let pq = match req.uri().query() {
            Some(q) => format!("{rest}?{q}"),
            None => rest.to_string(),
        };
        *req.uri_mut() = Uri::try_from(pq).context("rewrite URI")?;
        let headers = req.headers_mut();
        // Apps such as Ollama only accept their own Host.
        headers.insert(header::HOST, HeaderValue::from_str(&route.authority)?);
        // Never hand our access key to the upstream.
        if let (Some(key), Some(auth)) = (&self.access_key, headers.get(header::AUTHORIZATION)) {
            if auth.as_bytes() == format!("Bearer {}", key.expose()).as_bytes() {
                headers.remove(header::AUTHORIZATION);
            }
        }
        for (k, v) in &route.inject {
            headers.insert(k.clone(), v.clone());
        }

        // ponytail: one loopback TCP connection per request; pool if it shows up in profiles.
        let tcp = TcpStream::connect(&route.authority)
            .await
            .with_context(|| format!("connect {}", route.authority))?;
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tcp)).await?;
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        let client_upgrade = hyper::upgrade::on(&mut req);
        let mut resp = sender.send_request(req).await?;
        if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
            // WebSocket and other upgrades: splice both sides.
            let upstream_upgrade = hyper::upgrade::on(&mut resp);
            tokio::spawn(async move {
                if let (Ok(a), Ok(b)) = (client_upgrade.await, upstream_upgrade.await) {
                    let _ =
                        tokio::io::copy_bidirectional(&mut TokioIo::new(a), &mut TokioIo::new(b))
                            .await;
                }
            });
        }
        debug!(event = "target.web_request_routed", route = %route.name);
        Ok(resp.map(|b| b.boxed()))
    }
}

enum Access {
    Granted,
    /// Valid `?idr_key=` link: redirect to the clean URL, set the cookie.
    Link(String, String),
    Denied,
}

fn web_route(s: &crate::config::GatewayServiceConfig, path: &str) -> Result<WebRoute> {
    if s.service_type != GatewayServiceType::Http {
        anyhow::bail!("web_path needs an http service");
    }
    let prefix = normalize_prefix(path)?;
    let base = s.base_url_parsed()?;
    let authority = base
        .strip_prefix("http://")
        // ponytail: http upstreams only; add a TLS client when a local app needs https.
        .ok_or_else(|| anyhow::anyhow!("web_path needs an http:// base_url"))?
        .split('/')
        .next()
        .unwrap_or_default()
        .to_string();
    let mut inject = Vec::new();
    for inj in &s.inject_headers {
        let v = crate::adapters::gateway::resolve_inject_value(inj)
            .map_err(|_| anyhow::anyhow!("inject header {}: secret unavailable", inj.name))?;
        inject.push((
            HeaderName::try_from(inj.name.as_str())?,
            HeaderValue::from_str(&v)?,
        ));
    }
    Ok(WebRoute {
        name: s.name.clone(),
        prefix,
        authority,
        public: s.web_access == WebAccess::Public,
        inject,
    })
}

/// `"ollama"`, `"/ollama/"` → `"/ollama"`; `""`, `"/"` → `"/"`.
fn normalize_prefix(p: &str) -> Result<String> {
    let t = p.trim().trim_matches('/');
    if t.is_empty() {
        return Ok("/".into());
    }
    if !t
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
        || t.split('/').any(|s| s.is_empty() || s == "." || s == "..")
    {
        anyhow::bail!("web_path must be like /name");
    }
    Ok(format!("/{t}"))
}

fn matches_prefix(prefix: &str, path: &str) -> bool {
    prefix == "/"
        || path == prefix
        || (path.starts_with(prefix) && path.as_bytes().get(prefix.len()) == Some(&b'/'))
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn full(s: impl Into<Bytes>) -> Body {
    Full::new(s.into()).map_err(|never| match never {}).boxed()
}

fn text(status: StatusCode, body: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full(body))
        .expect("static response")
}

fn redirect(location: &str, cookie: Option<&str>) -> Response<Body> {
    let mut b = Response::builder()
        .status(StatusCode::SEE_OTHER)
        .header(header::LOCATION, location)
        .header(header::CACHE_CONTROL, "no-store");
    if let Some(c) = cookie {
        b = b.header(header::SET_COOKIE, c);
    }
    b.body(full(""))
        .unwrap_or_else(|_| text(StatusCode::BAD_REQUEST, "Bad request\n"))
}

fn login_page() -> Response<Body> {
    const PAGE: &str = "<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width\">\
<title>Private service</title><body style=\"font:16px system-ui;max-width:28rem;margin:15vh auto;padding:0 16px\">\
<h1 style=\"font-size:1.3rem\">This service is private</h1>\
<p>Enter the access key from the IDR Target app.</p>\
<form method=get><input name=idr_key type=password autofocus required style=\"width:100%;padding:.5rem;font:inherit\">\
<button style=\"margin-top:.75rem;padding:.5rem 1rem;font:inherit\">Open</button></form></body>";
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(full(PAGE))
        .expect("static response")
}

/// Loads `dir/<sni>/{fullchain,privkey}.pem` for configured custom domains,
/// reloading when ACME renews the files.
#[derive(Debug)]
struct DirCertResolver {
    dir: PathBuf,
    domains: Vec<String>,
    provider: Arc<rustls::crypto::CryptoProvider>,
    cache: Mutex<HashMap<String, (SystemTime, Arc<CertifiedKey>)>>,
}

impl DirCertResolver {
    fn load(&self, domain: &str) -> Option<Arc<CertifiedKey>> {
        let dir = self.dir.join(domain);
        let (cert_path, key_path) = (dir.join("fullchain.pem"), dir.join("privkey.pem"));
        let mtime = std::fs::metadata(&cert_path)
            .and_then(|m| m.modified())
            .ok()?;
        if let Some((t, ck)) = self.cache.lock().get(domain) {
            if *t == mtime {
                return Some(ck.clone());
            }
        }
        let certs = rustls_pemfile::certs(&mut std::fs::read(&cert_path).ok()?.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        let key =
            rustls_pemfile::private_key(&mut std::fs::read(&key_path).ok()?.as_slice()).ok()??;
        let signer = self.provider.key_provider.load_private_key(key).ok()?;
        let ck = Arc::new(CertifiedKey::new(certs, signer));
        self.cache
            .lock()
            .insert(domain.to_string(), (mtime, ck.clone()));
        Some(ck)
    }
}

impl ResolvesServerCert for DirCertResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // Only configured domains: the SNI never becomes an arbitrary path.
        let sni = hello.server_name()?.to_ascii_lowercase();
        if !self.domains.contains(&sni) {
            return None;
        }
        self.load(&sni)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_normalize_and_match() {
        assert_eq!(normalize_prefix("").unwrap(), "/");
        assert_eq!(normalize_prefix("/").unwrap(), "/");
        assert_eq!(normalize_prefix("ollama/").unwrap(), "/ollama");
        assert!(normalize_prefix("/../x").is_err());
        assert!(normalize_prefix("/a b").is_err());
        assert!(matches_prefix("/", "/anything"));
        assert!(matches_prefix("/ollama", "/ollama"));
        assert!(matches_prefix("/ollama", "/ollama/api/tags"));
        assert!(!matches_prefix("/ollama", "/ollamax"));
    }

    /// Upstream that echoes `<Host> <path>`; gateway served over an in-memory pipe.
    #[tokio::test]
    async fn routes_private_and_public_services() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = up.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            loop {
                let (mut s, _) = up.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap();
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let path = req.split(' ').nth(1).unwrap_or("").to_string();
                    let host = req
                        .lines()
                        .find_map(|l| l.strip_prefix("host: ").or(l.strip_prefix("Host: ")))
                        .unwrap_or("")
                        .to_string();
                    let auth = req.to_ascii_lowercase().contains("authorization:");
                    let body = format!("{host} {path} auth={auth}");
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        let route = |name: &str, prefix: &str, public| WebRoute {
            name: name.into(),
            prefix: prefix.into(),
            authority: authority.clone(),
            public,
            inject: vec![],
        };
        let key = "k".repeat(32);
        let gw = Arc::new(WebGateway::new(
            vec![route("ollama", "/ollama", false), route("site", "/", true)],
            Some(Secret::new(key.clone())),
            PathBuf::new(),
            vec![],
        ));

        let get = |path: String, extra: Option<(&'static str, String)>| {
            let gw = gw.clone();
            async move {
                let (client, server) = tokio::io::duplex(64 * 1024);
                tokio::spawn(gw.serve_http(server));
                let (mut tx, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client))
                    .await
                    .unwrap();
                tokio::spawn(conn);
                let mut b = Request::get(path).header("host", "go.example.com");
                if let Some((k, v)) = extra {
                    b = b.header(k, v);
                }
                let resp = tx
                    .send_request(b.body(Full::new(Bytes::new())).unwrap())
                    .await
                    .unwrap();
                let status = resp.status();
                let cookie = resp
                    .headers()
                    .get(header::SET_COOKIE)
                    .map(|v| v.to_str().unwrap().to_string());
                let loc = resp
                    .headers()
                    .get(header::LOCATION)
                    .map(|v| v.to_str().unwrap().to_string());
                let body = resp.into_body().collect().await.unwrap().to_bytes();
                (
                    status,
                    String::from_utf8_lossy(&body).to_string(),
                    cookie,
                    loc,
                )
            }
        };

        // Public site: open, Host rewritten, path kept.
        let (s, body, ..) = get("/index.html".into(), None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(body, format!("{authority} /index.html auth=false"));

        // Private without key: login page.
        let (s, ..) = get("/ollama/api/tags".into(), None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        let (s, ..) = get(
            "/ollama/api/tags".into(),
            Some(("authorization", "Bearer nope".into())),
        )
        .await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);

        // Bearer key: prefix stripped, key not forwarded.
        let (s, body, ..) = get(
            "/ollama/api/tags".into(),
            Some(("authorization", format!("Bearer {key}"))),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(body, format!("{authority} /api/tags auth=false"));

        // One-time link: cookie set, redirected to the clean URL; cookie then works.
        let (s, _, cookie, loc) = get(format!("/ollama/?a=1&idr_key={key}"), None).await;
        assert_eq!(s, StatusCode::SEE_OTHER);
        assert_eq!(loc.as_deref(), Some("/ollama/?a=1"));
        let cookie = cookie.unwrap();
        assert!(cookie.contains("HttpOnly") && cookie.contains("Secure"));
        let (s, body, ..) = get(
            "/ollama/?a=1".into(),
            Some(("cookie", format!("x=1; idr_key={key}"))),
        )
        .await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(body, format!("{authority} /?a=1 auth=false"));

        // Bare prefix redirects to the slash form.
        let (s, _, _, loc) = get("/ollama".into(), None).await;
        assert_eq!(s, StatusCode::SEE_OTHER);
        assert_eq!(loc.as_deref(), Some("/ollama/"));
    }

    /// Custom-domain path: cert loaded from `cert_dir/<sni>/`, unknown SNI refused.
    #[tokio::test]
    async fn terminates_tls_with_the_domain_certificate() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["go.example.com".into()]).unwrap();
        let dom = dir.path().join("go.example.com");
        std::fs::create_dir_all(&dom).unwrap();
        std::fs::write(dom.join("fullchain.pem"), cert.cert.pem()).unwrap();
        std::fs::write(dom.join("privkey.pem"), cert.key_pair.serialize_pem()).unwrap();

        let up = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let authority = up.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let (mut s, _) = up.accept().await.unwrap();
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf).await;
            let _ = s
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
        });
        let gw = Arc::new(WebGateway::new(
            vec![WebRoute {
                name: "site".into(),
                prefix: "/".into(),
                authority,
                public: true,
                inject: vec![],
            }],
            None,
            dir.path().to_path_buf(),
            vec!["go.example.com".into()],
        ));

        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.cert.der().clone()).unwrap();
        let client_cfg = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        );
        let connect = |sni: &'static str| {
            let gw = gw.clone();
            let client_cfg = client_cfg.clone();
            async move {
                let (client, server) = tokio::io::duplex(64 * 1024);
                tokio::spawn(gw.serve_tls(server));
                let name = rustls::pki_types::ServerName::try_from(sni).unwrap();
                tokio_rustls::TlsConnector::from(client_cfg).connect(name, client).await
            }
        };

        assert!(connect("other.example.com").await.is_err());
        let mut tls = connect("go.example.com").await.unwrap();
        tls.write_all(b"GET / HTTP/1.1\r\nHost: go.example.com\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        let mut out = Vec::new();
        let _ = tls.read_to_end(&mut out).await;
        let out = String::from_utf8_lossy(&out);
        assert!(out.starts_with("HTTP/1.1 200"), "{out}");
        assert!(out.ends_with("ok"), "{out}");
    }

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }
}

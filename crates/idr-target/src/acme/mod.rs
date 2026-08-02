//! Let's Encrypt ACME HTTP-01 — **custom domains only**.
//!
//! Native `*.idr.to` FQHNs use the Relay wildcard certificate (edge terminate).
//! This manager issues and renews certificates solely for customer CNAME domains
//! configured in `[acme].domains`. Challenges are served via Relay → Target nginx webroot.
//!
//! Design notes (see docs/TLS_PASSTHROUGH.md):
//! - Persist ACME account credentials (avoid rate-limit burn)
//! - Renew only when `notAfter - renew_before_days` is reached
//! - Wait for Relay QUIC readiness before `set_challenge_ready`
//! - Atomic cert+key install before nginx reload
//! - Per-domain cert dirs under `cert_dir/<domain>/`

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
    NewAccount, NewOrder, OrderStatus,
};
use rcgen::{CertificateParams, DnType, KeyPair};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{info, warn};

use crate::config::AcmeConfig;
use crate::relay::readiness::RelayReadiness;
use idr_protocol::fqhn;

/// Suffix reserved for IDR native Host-Identity FQHNs (Relay wildcard / edge terminate).
const NATIVE_FQHN_SUFFIX: &str = ".idr.to";

#[derive(Debug)]
pub struct AcmeManager {
    cfg: AcmeConfig,
    /// Canonical custom domains (never `*.idr.to`).
    domains: Vec<String>,
    readiness: Arc<RelayReadiness>,
}

impl AcmeManager {
    pub fn new(cfg: AcmeConfig, readiness: Arc<RelayReadiness>) -> Result<Self> {
        let domains = validate_custom_domains(&cfg.domains)?;
        if cfg.enabled {
            if domains.is_empty() {
                anyhow::bail!(
                    "ACME enabled but [acme].domains is empty — Let's Encrypt is only allowed for custom domains (not *.idr.to)"
                );
            }
            if cfg.email.is_empty()
                || cfg.email.contains("example.com")
                || cfg.email == "admin@idr.to"
            {
                if !cfg.staging {
                    anyhow::bail!(
                        "ACME production requires a real contact email (got {:?})",
                        cfg.email
                    );
                }
                warn!(email = %cfg.email, "ACME email looks like a placeholder — use staging only");
            }
        }
        Ok(Self {
            cfg,
            domains,
            readiness,
        })
    }

    pub fn spawn(self) {
        if !self.cfg.enabled {
            info!("ACME disabled");
            return;
        }
        if self.domains.is_empty() {
            warn!("ACME enabled but no custom domains configured — manager not started");
            return;
        }
        info!(domains = ?self.domains, "ACME manager starting (custom domains only)");
        tokio::spawn(async move {
            if let Err(e) = self.run_loop().await {
                warn!(error = %e, "ACME manager exited");
            }
        });
    }

    async fn run_loop(self) -> Result<()> {
        fs::create_dir_all(&self.cfg.webroot)
            .await
            .with_context(|| format!("create ACME webroot {}", self.cfg.webroot.display()))?;
        fs::create_dir_all(&self.cfg.cert_dir)
            .await
            .with_context(|| format!("create cert dir {}", self.cfg.cert_dir.display()))?;

        let mut backoff = Duration::from_secs(30);
        loop {
            let mut any_issued = false;
            let mut any_err = None;
            for domain in &self.domains {
                match self.ensure_certificate(domain).await {
                    Ok(EnsureOutcome::Issued) => any_issued = true,
                    Ok(EnsureOutcome::NotDue) => {}
                    Err(e) => {
                        warn!(domain = %domain, error = %e, "ACME attempt failed");
                        any_err = Some(e);
                    }
                }
            }

            if any_err.is_some() && !any_issued {
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(6 * 3600));
                continue;
            }

            backoff = Duration::from_secs(3600);
            let sleep_for = self.sleep_until_renew_window().await;
            info!(?sleep_for, "ACME sleeping until renew window");
            tokio::time::sleep(sleep_for).await;
        }
    }

    pub async fn ensure_certificate(&self, domain: &str) -> Result<EnsureOutcome> {
        if !self.certificate_needs_renewal(domain).await? {
            info!(%domain, "ACME: certificate still valid — skip renew");
            return Ok(EnsureOutcome::NotDue);
        }

        info!(%domain, "ACME: waiting for Relay QUIC before HTTP-01");
        if !self.readiness.wait_ready(Duration::from_secs(120)).await {
            anyhow::bail!("no active Relay QUIC within 120s — cannot serve HTTP-01 via edge");
        }

        info!(%domain, "ACME: requesting certificate for custom domain");
        let directory = if self.cfg.staging {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        };

        let account = self.load_or_create_account(directory).await?;

        let identifiers = [Identifier::Dns(domain.to_string())];
        let mut order = account
            .new_order(&NewOrder {
                identifiers: &identifiers,
            })
            .await
            .context("create ACME order")?;

        let authorizations = order
            .authorizations()
            .await
            .context("fetch authorizations")?;
        let mut challenge_tokens = Vec::new();
        for authz in &authorizations {
            if authz.status == AuthorizationStatus::Valid {
                continue;
            }
            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Http01)
                .ok_or_else(|| anyhow::anyhow!("no http-01 challenge"))?;
            let key_auth = order.key_authorization(challenge);
            self.write_http01_token(&challenge.token, key_auth.as_str())
                .await
                .context("write http-01 token")?;
            challenge_tokens.push(challenge.token.clone());
            info!(
                token = %challenge.token,
                %domain,
                "ACME token written — LE validates via Relay:80 → nginx webroot (custom domain Host)"
            );
            order
                .set_challenge_ready(&challenge.url)
                .await
                .context("set challenge ready")?;
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            order.refresh().await?;
            let auths = order.authorizations().await?;
            if auths.iter().all(|a| a.status == AuthorizationStatus::Valid) {
                break;
            }
            if auths
                .iter()
                .any(|a| a.status == AuthorizationStatus::Invalid)
            {
                anyhow::bail!(
                    "ACME authorization invalid for {domain} (CNAME + Presence alias + Relay :80 required)"
                );
            }
            if tokio::time::Instant::now() > deadline {
                anyhow::bail!("ACME authorization timed out");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        for token in &challenge_tokens {
            self.remove_http01_token(token).await.ok();
        }

        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            order.refresh().await?;
            match order.state().status {
                OrderStatus::Ready => break,
                OrderStatus::Invalid => anyhow::bail!("ACME order invalid"),
                _ if tokio::time::Instant::now() > deadline => {
                    anyhow::bail!("ACME order not ready in time")
                }
                _ => tokio::time::sleep(Duration::from_secs(2)).await,
            }
        }

        let key_pair = KeyPair::generate().context("generate certificate key")?;
        let mut params =
            CertificateParams::new([domain.to_string()]).context("certificate params")?;
        params.distinguished_name.push(DnType::CommonName, domain);
        let csr = params
            .serialize_request(&key_pair)
            .context("serialize CSR")?
            .der()
            .to_vec();

        order.finalize(&csr).await.context("finalize order")?;

        let cert_deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        let cert_pem = loop {
            order.refresh().await?;
            if let Some(cert) = order.certificate().await.context("fetch certificate")? {
                break cert;
            }
            if order.state().status == OrderStatus::Invalid {
                anyhow::bail!("certificate order invalid");
            }
            if tokio::time::Instant::now() > cert_deadline {
                anyhow::bail!("certificate fetch timed out");
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        };

        self.install_certificate_pair(domain, &cert_pem, key_pair.serialize_pem().as_bytes())
            .await?;
        info!(
            path = %self.domain_cert_dir(domain).join("fullchain.pem").display(),
            %domain,
            "ACME certificate installed"
        );
        self.reload_nginx().await?;
        Ok(EnsureOutcome::Issued)
    }

    fn domain_cert_dir(&self, domain: &str) -> PathBuf {
        self.cfg.cert_dir.join(domain)
    }

    async fn load_or_create_account(&self, directory: &str) -> Result<Account> {
        let path = self.account_credentials_path();
        if path.exists() {
            let raw = fs::read_to_string(&path)
                .await
                .with_context(|| format!("read {}", path.display()))?;
            let creds: AccountCredentials =
                serde_json::from_str(&raw).context("parse ACME account credentials")?;
            match Account::from_credentials(creds).await {
                Ok(account) => {
                    info!(path = %path.display(), "ACME: restored account credentials");
                    return Ok(account);
                }
                Err(e) => {
                    warn!(error = %e, "ACME: stored credentials unusable — creating new account");
                }
            }
        }

        let contact = format!("mailto:{}", self.cfg.email);
        let (account, creds) = Account::create(
            &NewAccount {
                contact: &[contact.as_str()],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory,
            None,
        )
        .await
        .context("create ACME account")?;
        let json = serde_json::to_string_pretty(&creds).context("serialize ACME credentials")?;
        atomic_write(&path, json.as_bytes()).await?;
        info!(path = %path.display(), "ACME: created and persisted account");
        Ok(account)
    }

    fn account_credentials_path(&self) -> PathBuf {
        let env = if self.cfg.staging { "staging" } else { "prod" };
        self.cfg.cert_dir.join(format!("acme-account-{env}.json"))
    }

    async fn certificate_needs_renewal(&self, domain: &str) -> Result<bool> {
        let path = self.domain_cert_dir(domain).join("fullchain.pem");
        if !path.exists() {
            return Ok(true);
        }
        let pem = fs::read(&path).await.context("read fullchain.pem")?;
        let Some(not_after) = leaf_not_after(&pem)? else {
            return Ok(true);
        };
        let renew_at = not_after - chrono::Duration::days(self.cfg.renew_before_days as i64);
        Ok(chrono::Utc::now() >= renew_at)
    }

    async fn sleep_until_renew_window(&self) -> Duration {
        let mut soonest = Duration::from_secs(86_400);
        for domain in &self.domains {
            let path = self.domain_cert_dir(domain).join("fullchain.pem");
            let Ok(pem) = fs::read(&path).await else {
                return Duration::from_secs(60);
            };
            let Ok(Some(not_after)) = leaf_not_after(&pem) else {
                return Duration::from_secs(60);
            };
            let renew_at = not_after - chrono::Duration::days(self.cfg.renew_before_days as i64);
            let now = chrono::Utc::now();
            if now >= renew_at {
                return Duration::from_secs(60);
            }
            let secs = (renew_at - now).num_seconds().max(60) as u64;
            soonest = soonest.min(Duration::from_secs(secs.min(86_400)));
        }
        soonest
    }

    async fn install_certificate_pair(
        &self,
        domain: &str,
        cert_pem: &str,
        key_pem: &[u8],
    ) -> Result<()> {
        let dir = self.domain_cert_dir(domain);
        fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("create {}", dir.display()))?;
        let fullchain = dir.join("fullchain.pem");
        let privkey = dir.join("privkey.pem");
        atomic_write(&fullchain, cert_pem.as_bytes()).await?;
        atomic_write(&privkey, key_pem).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            fs::set_permissions(&privkey, perms)
                .await
                .context("chmod privkey.pem")?;
        }
        Ok(())
    }

    async fn write_http01_token(&self, token: &str, body: &str) -> Result<()> {
        validate_acme_token(token)?;
        let dir = self.cfg.webroot.join(".well-known").join("acme-challenge");
        fs::create_dir_all(&dir).await?;
        let path = dir.join(token);
        atomic_write(&path, body.as_bytes()).await?;
        Ok(())
    }

    async fn remove_http01_token(&self, token: &str) -> Result<()> {
        validate_acme_token(token)?;
        let path = self
            .cfg
            .webroot
            .join(".well-known")
            .join("acme-challenge")
            .join(token);
        fs::remove_file(path).await?;
        Ok(())
    }

    async fn reload_nginx(&self) -> Result<()> {
        if let Some(cmd) = &self.cfg.nginx_reload_command {
            info!(command = %cmd, "reloading nginx");
            let parts: Vec<_> = cmd.split_whitespace().collect();
            if parts.is_empty() {
                return Ok(());
            }
            let status = tokio::process::Command::new(parts[0])
                .args(&parts[1..])
                .status()
                .await
                .context("nginx reload")?;
            if !status.success() {
                anyhow::bail!("nginx reload failed: {status:?}");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsureOutcome {
    Issued,
    NotDue,
}

/// True when `host` is an IDR native FQHN (Let's Encrypt not allowed).
pub fn is_native_idr_fqhn(host: &str) -> bool {
    host.trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .ends_with(NATIVE_FQHN_SUFFIX)
}

fn validate_custom_domains(raw: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(raw.len());
    for d in raw {
        let canonical = fqhn::canonicalize(d)
            .map_err(|e| anyhow::anyhow!("invalid ACME custom domain {d:?}: {e}"))?;
        if is_native_idr_fqhn(&canonical) {
            anyhow::bail!(
                "ACME domain {canonical:?} is a native *.idr.to FQHN — Let's Encrypt is only allowed for custom domains; use the Relay wildcard cert instead"
            );
        }
        if !out.iter().any(|x: &String| x == &canonical) {
            out.push(canonical);
        }
    }
    Ok(out)
}

fn validate_acme_token(token: &str) -> Result<()> {
    if token.is_empty()
        || token.len() > 255
        || !token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        anyhow::bail!("invalid ACME token filename");
    }
    Ok(())
}

async fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let mut tmp_os = path.as_os_str().to_owned();
    tmp_os.push(".tmp");
    let tmp_path = PathBuf::from(tmp_os);
    {
        let mut f = fs::File::create(&tmp_path)
            .await
            .with_context(|| format!("create {}", tmp_path.display()))?;
        f.write_all(data).await?;
        f.flush().await?;
    }
    fs::rename(&tmp_path, path)
        .await
        .with_context(|| format!("rename {} -> {}", tmp_path.display(), path.display()))?;
    Ok(())
}

fn leaf_not_after(pem: &[u8]) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    let mut cursor = std::io::Cursor::new(pem);
    let mut certs = rustls_pemfile::certs(&mut cursor);
    let Some(der) = certs.next() else {
        return Ok(None);
    };
    let der = der.context("parse certificate PEM")?;
    parse_not_after_from_cert_der(der.as_ref())
}

/// Extract notAfter from an X.509 certificate DER (RFC 5280 TBSCertificate.validity).
fn parse_not_after_from_cert_der(der: &[u8]) -> Result<Option<chrono::DateTime<chrono::Utc>>> {
    let tbs = der_expect_sequence(der)?;
    let mut tbs_body = der_expect_sequence(tbs)?;
    if let Some((tag, _)) = der_peek_tag(tbs_body) {
        if tag == 0xa0 {
            let (_, after) = der_take_tlv(tbs_body)?;
            tbs_body = after;
        }
    }
    let (_, after) = der_take_tlv(tbs_body)?;
    tbs_body = after;
    let (_, after) = der_take_tlv(tbs_body)?;
    tbs_body = after;
    let (_, after) = der_take_tlv(tbs_body)?;
    tbs_body = after;
    let validity = der_expect_sequence(tbs_body)?;
    let (_, after_nb) = der_take_tlv(validity)?;
    let (not_after_tlv, _) = der_take_tlv(after_nb)?;
    let (tag, value) = der_split_tlv(not_after_tlv)?;
    let dt = match tag {
        0x17 => parse_utc_time(value)?,
        0x18 => parse_generalized_time(value)?,
        _ => anyhow::bail!("unexpected notAfter tag {tag:#x}"),
    };
    Ok(Some(dt))
}

fn der_expect_sequence(input: &[u8]) -> Result<&[u8]> {
    let (tag, value, _rest) = der_read_tlv(input)?;
    if tag != 0x30 {
        anyhow::bail!("expected SEQUENCE");
    }
    Ok(value)
}

fn der_peek_tag(input: &[u8]) -> Option<(u8, &[u8])> {
    input.first().map(|t| (*t, input))
}

fn der_take_tlv(input: &[u8]) -> Result<(&[u8], &[u8])> {
    let (_tag, _value, rest) = der_read_tlv(input)?;
    let tlv_len = input.len() - rest.len();
    Ok((&input[..tlv_len], rest))
}

fn der_split_tlv(tlv: &[u8]) -> Result<(u8, &[u8])> {
    let (tag, value, _) = der_read_tlv(tlv)?;
    Ok((tag, value))
}

fn der_read_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    if input.len() < 2 {
        anyhow::bail!("truncated DER");
    }
    let tag = input[0];
    let (len, hdr) = if input[1] & 0x80 == 0 {
        (input[1] as usize, 2usize)
    } else {
        let n = (input[1] & 0x7f) as usize;
        if n == 0 || n > 4 || input.len() < 2 + n {
            anyhow::bail!("bad DER length");
        }
        let mut len = 0usize;
        for b in &input[2..2 + n] {
            len = (len << 8) | (*b as usize);
        }
        (len, 2 + n)
    };
    if input.len() < hdr + len {
        anyhow::bail!("truncated DER value");
    }
    Ok((tag, &input[hdr..hdr + len], &input[hdr + len..]))
}

fn parse_utc_time(value: &[u8]) -> Result<chrono::DateTime<chrono::Utc>> {
    let s = std::str::from_utf8(value).context("UTCTime utf8")?;
    let s = s.trim_end_matches('Z');
    if s.len() < 12 {
        anyhow::bail!("UTCTime too short");
    }
    let yy: i32 = s[0..2].parse()?;
    let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
    let month: u32 = s[2..4].parse()?;
    let day: u32 = s[4..6].parse()?;
    let hour: u32 = s[6..8].parse()?;
    let min: u32 = s[8..10].parse()?;
    let sec: u32 = s[10..12].parse()?;
    chrono::NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|d| d.and_hms_opt(hour, min, sec))
        .map(|n| n.and_utc())
        .ok_or_else(|| anyhow::anyhow!("invalid UTCTime"))
}

fn parse_generalized_time(value: &[u8]) -> Result<chrono::DateTime<chrono::Utc>> {
    let s = std::str::from_utf8(value).context("GeneralizedTime utf8")?;
    let s = s.trim_end_matches('Z');
    if s.len() < 14 {
        anyhow::bail!("GeneralizedTime too short");
    }
    let year: i32 = s[0..4].parse()?;
    let month: u32 = s[4..6].parse()?;
    let day: u32 = s[6..8].parse()?;
    let hour: u32 = s[8..10].parse()?;
    let min: u32 = s[10..12].parse()?;
    let sec: u32 = s[12..14].parse()?;
    chrono::NaiveDate::from_ymd_opt(year, month, day)
        .and_then(|d| d.and_hms_opt(hour, min, sec))
        .map(|n| n.and_utc())
        .ok_or_else(|| anyhow::anyhow!("invalid GeneralizedTime"))
}

/// Example nginx for a **custom domain** (E2E TLS). Native `*.idr.to` uses Relay terminate.
pub fn nginx_example_config(webroot: &PathBuf, custom_domain: &str, cert_dir: &Path) -> String {
    let domain_certs = cert_dir.join(custom_domain);
    format!(
        r#"# nginx: custom-domain E2E TLS at Target; ACME http-01 via Relay → port 80
# Native *.idr.to hosts are NOT issued here — Relay serves the wildcard cert.
#
# Bootstrap: start with HTTP-only until ACME writes certs under cert_dir/<domain>/.

server {{
    listen 80;
    server_name {domain};
    location /.well-known/acme-challenge/ {{
        root {webroot};
    }}
    location / {{
        return 301 https://$host$request_uri;
    }}
}}

server {{
    listen 443 ssl;
    server_name {domain};
    ssl_certificate     {domain_certs}/fullchain.pem;
    ssl_certificate_key {domain_certs}/privkey.pem;
    ssl_session_cache shared:IDR:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets on;
    location / {{
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }}
}}
"#,
        domain = custom_domain,
        webroot = webroot.display(),
        domain_certs = domain_certs.display()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_tokens() {
        assert!(validate_acme_token("../etc/passwd").is_err());
        assert!(validate_acme_token("ok-token_1").is_ok());
    }

    #[test]
    fn rejects_native_fqhn_domains() {
        assert!(is_native_idr_fqhn("host--entity.idr.to"));
        assert!(!is_native_idr_fqhn("cam.example.com"));
        let err = validate_custom_domains(&["cam.example.com".into(), "x.idr.to".into()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("native"), "{err}");
        let ok = validate_custom_domains(&["Cam.Example.COM".into()]).unwrap();
        assert_eq!(ok, vec!["cam.example.com"]);
    }

    #[test]
    fn enabled_requires_custom_domains() {
        let mut cfg = AcmeConfig::default();
        cfg.enabled = true;
        cfg.staging = true;
        cfg.email = "ops@example.com".into();
        let err = AcmeManager::new(cfg, RelayReadiness::new())
            .unwrap_err()
            .to_string();
        assert!(err.contains("custom domains"), "{err}");
    }
}

use crate::errors::{ProtocolError, Result};

const IDR_TO_SUFFIX: &str = ".idr.to";

/// Canonicalize a Target FQHN for product / Presence identity.
///
/// `host--entity` locators always become `{host}--{entity}.idr.to` (email `@`
/// allowed in entity). Missing `.idr.to` is appended; an existing suffix is kept.
/// Classic dotted DNS names are unchanged. DEF encode is **not** applied here —
/// only in [`fqhn_digest`] for Presence server index placement.
pub fn canonicalize(fqhn: &str) -> Result<String> {
    let trimmed = fqhn.trim();
    if trimmed.is_empty() {
        return Err(ProtocolError::InvalidFqhn("empty".into()));
    }
    if trimmed.contains("://") || trimmed.contains('/') {
        return Err(ProtocolError::InvalidFqhn(
            "must not include scheme or path".into(),
        ));
    }
    // Port (`host:443`) is rejected; email `user@domain` has no `:`.
    if trimmed.contains(':') {
        return Err(ProtocolError::InvalidFqhn(
            "must not include port".into(),
        ));
    }
    let mut canonical = trimmed.to_ascii_lowercase();
    if canonical.ends_with('.') {
        canonical.pop();
    }
    if canonical.is_empty() {
        return Err(ProtocolError::InvalidFqhn(
            "empty after canonicalization".into(),
        ));
    }

    if let Some((host, entity)) = split_host_entity_locator(&canonical) {
        validate_host_path(host)?;
        if entity.is_empty() || entity.contains("--") {
            return Err(ProtocolError::InvalidFqhn(
                "invalid entity in host--entity".into(),
            ));
        }
        if !entity
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '@' | '.'))
        {
            return Err(ProtocolError::InvalidFqhn(format!(
                "invalid chars in entity: {entity}"
            )));
        }
        return Ok(format!("{host}--{entity}{IDR_TO_SUFFIX}"));
    }

    validate_dns_labels(&canonical)?;
    Ok(canonical)
}

/// DEF-encode when needed, then SHA-256 — used only for Presence placement index.
pub fn fqhn_digest(fqhn: &str) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let logical = canonicalize(fqhn)?;
    let key = placement_hash_input(&logical);
    Ok(Sha256::digest(key.as_bytes()).into())
}

/// DNS-safe string hashed for dual-mod placement (encode only if not already safe).
fn placement_hash_input(logical: &str) -> String {
    if is_dns_profile_safe(logical) {
        logical.to_string()
    } else {
        dns_encoded_format::encode_body(logical)
    }
}

fn split_host_entity_locator(fqhn: &str) -> Option<(&str, &str)> {
    if !fqhn.contains("--") {
        return None;
    }
    let body = fqhn.strip_suffix(IDR_TO_SUFFIX).unwrap_or(fqhn);
    split_host_entity(body)
}

fn split_host_entity(fqhn: &str) -> Option<(&str, &str)> {
    let idx = fqhn.find("--")?;
    let host = &fqhn[..idx];
    let entity = &fqhn[idx + 2..];
    if host.is_empty() || entity.is_empty() || entity.contains("--") {
        return None;
    }
    Some((host, entity))
}

fn validate_host_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(ProtocolError::InvalidFqhn("empty host path".into()));
    }
    for label in path.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ProtocolError::InvalidFqhn(format!(
                "invalid host path label: {label}"
            )));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(ProtocolError::InvalidFqhn(format!(
                "invalid chars in host path: {label}"
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ProtocolError::InvalidFqhn(format!(
                "invalid host path edges: {label}"
            )));
        }
    }
    Ok(())
}

fn validate_dns_labels(fqhn: &str) -> Result<()> {
    for label in fqhn.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(ProtocolError::InvalidFqhn(format!(
                "invalid label: {label}"
            )));
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(ProtocolError::InvalidFqhn(format!(
                "invalid chars in {label}"
            )));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(ProtocolError::InvalidFqhn(format!(
                "invalid label edges: {label}"
            )));
        }
    }
    Ok(())
}

fn is_dns_profile_safe(s: &str) -> bool {
    !s.is_empty()
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_basic() {
        assert_eq!(
            canonicalize("Device-01.Example.IDR.to.").unwrap(),
            "device-01.example.idr.to"
        );
    }

    #[test]
    fn canonicalize_logical_email_entity() {
        assert_eq!(
            canonicalize("laptop67--muzamiltest9@gmail.com").unwrap(),
            "laptop67--muzamiltest9@gmail.com.idr.to"
        );
        assert_eq!(
            canonicalize("laptop67--muzamiltest9@gmail.com.idr.to").unwrap(),
            "laptop67--muzamiltest9@gmail.com.idr.to"
        );
    }

    #[test]
    fn digest_encodes_email_for_placement() {
        let digest = fqhn_digest("laptop67--muzamiltest9@gmail.com").unwrap();
        let encoded = "laptop67--muzamiltest9-40gmail-2ecom-2eidr-2eto";
        use sha2::{Digest, Sha256};
        let expected: [u8; 32] = Sha256::digest(encoded.as_bytes()).into();
        assert_eq!(digest, expected);
        assert_eq!(
            digest,
            fqhn_digest("laptop67--muzamiltest9@gmail.com.idr.to").unwrap()
        );
    }

    #[test]
    fn digest_keeps_dotted_dns_unencoded() {
        let digest = fqhn_digest("device-01.example.idr.to").unwrap();
        use sha2::{Digest, Sha256};
        let expected: [u8; 32] = Sha256::digest(b"device-01.example.idr.to").into();
        assert_eq!(digest, expected);
    }

    #[test]
    fn rejects_scheme() {
        assert!(canonicalize("https://bad.example").is_err());
    }
}

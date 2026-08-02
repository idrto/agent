use crate::errors::{ProtocolError, Result};

/// Canonicalize a Target FQHN per IDR rules:
/// lowercase ASCII, no trailing dot, no scheme/port/path.
pub fn canonicalize(fqhn: &str) -> Result<String> {
    let trimmed = fqhn.trim();
    if trimmed.is_empty() {
        return Err(ProtocolError::InvalidFqhn("empty".into()));
    }
    if trimmed.contains("://") || trimmed.contains('/') || trimmed.contains(':') {
        return Err(ProtocolError::InvalidFqhn(
            "must not include scheme, port, or path".into(),
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
    for label in canonical.split('.') {
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
    Ok(canonical)
}

pub fn fqhn_digest(fqhn: &str) -> Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let canonical = canonicalize(fqhn)?;
    Ok(Sha256::digest(canonical.as_bytes()).into())
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
    fn rejects_scheme() {
        assert!(canonicalize("https://bad.example").is_err());
    }
}

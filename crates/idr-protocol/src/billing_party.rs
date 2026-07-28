//! Billing party pair: using_party (SSO/login) + paying_party (payer login).

use serde::{Deserialize, Serialize};

use crate::errors::{ProtocolError, Result};

pub const MAX_PARTY_ID_BYTES: usize = 320;

/// Identifies who uses a Target and who pays for its traffic/signaling.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BillingPartyPair {
    /// SSO / login of the party using the Target.
    pub using_party: String,
    /// Login of the party paying (may equal `using_party`).
    pub paying_party: String,
}

impl BillingPartyPair {
    pub fn new(using_party: impl Into<String>, paying_party: Option<String>) -> Result<Self> {
        let using_party = normalize_party_id(using_party.into())?;
        let paying_party = match paying_party {
            Some(p) if !p.trim().is_empty() => normalize_party_id(p)?,
            _ => using_party.clone(),
        };
        Ok(Self {
            using_party,
            paying_party,
        })
    }

    pub fn same_party(login: impl Into<String>) -> Result<Self> {
        Self::new(login, None)
    }
}

fn normalize_party_id(raw: String) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ProtocolError::MalformedDocument(
            "billing party id must be non-empty".into(),
        ));
    }
    if trimmed.len() > MAX_PARTY_ID_BYTES {
        return Err(ProtocolError::MalformedDocument(format!(
            "billing party id exceeds {MAX_PARTY_ID_BYTES} bytes"
        )));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paying_defaults_to_using() {
        let p = BillingPartyPair::new("alice@acme.com", None).unwrap();
        assert_eq!(p.using_party, "alice@acme.com");
        assert_eq!(p.paying_party, "alice@acme.com");
    }

    #[test]
    fn distinct_paying_party() {
        let p = BillingPartyPair::new("alice@acme.com", Some("billing@acme.com".into())).unwrap();
        assert_eq!(p.paying_party, "billing@acme.com");
    }

    #[test]
    fn rejects_empty() {
        assert!(BillingPartyPair::new("  ", None).is_err());
    }
}

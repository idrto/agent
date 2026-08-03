//! Minimal PKCS#10 CSR parsing: extract just the raw Ed25519 public key.
//!
//! `dp_rust_mtls::sign_client_cert_from_csr` already parses + signature-checks
//! the CSR internally, but only returns the issued cert PEMs — admin flows
//! (`cert approve`, `identity enroll --local`) also need the subject's raw
//! public key to build the `CapabilityCredential.publicJwk` field. This is a
//! trimmed copy of the same minimal DER walker (Ed25519-only CSRs), kept
//! local because `dp_rust_mtls::parse_ed25519_csr` is a private fn.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CsrError {
    #[error("pem parse failed: {0}")]
    Pem(String),
}

fn pem_to_der(pem: &str, label: &str) -> Result<Vec<u8>, CsrError> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem
        .find(&begin)
        .ok_or_else(|| CsrError::Pem(format!("missing {begin}")))?
        + begin.len();
    let stop = pem[start..]
        .find(&end)
        .ok_or_else(|| CsrError::Pem(format!("missing {end}")))?
        + start;
    let body: String = pem[start..stop]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    STANDARD
        .decode(body)
        .map_err(|e| CsrError::Pem(format!("base64: {e}")))
}

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

fn read_tlv(input: &[u8]) -> Result<(Tlv<'_>, usize), CsrError> {
    if input.len() < 2 {
        return Err(CsrError::Pem("truncated DER TLV".into()));
    }
    let tag = input[0];
    let mut idx = 1usize;
    let len_byte = input[idx];
    idx += 1;
    let len = if len_byte & 0x80 == 0 {
        len_byte as usize
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 4 || input.len() < idx + n {
            return Err(CsrError::Pem("invalid DER length".into()));
        }
        let mut len = 0usize;
        for b in &input[idx..idx + n] {
            len = (len << 8) | *b as usize;
        }
        idx += n;
        len
    };
    if input.len() < idx + len {
        return Err(CsrError::Pem("truncated DER value".into()));
    }
    Ok((
        Tlv {
            tag,
            value: &input[idx..idx + len],
        },
        idx + len,
    ))
}

const ED25519_SPKI_ALG: [u8; 7] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

/// Extract the raw 32-byte Ed25519 public key from a PKCS#10 CSR PEM.
pub fn extract_ed25519_public_key(csr_pem: &str) -> Result<[u8; 32], CsrError> {
    let der = pem_to_der(csr_pem, "CERTIFICATE REQUEST")?;

    let (outer, outer_total) = read_tlv(&der)?;
    if outer.tag != 0x30 || outer_total != der.len() {
        return Err(CsrError::Pem("CSR is not a single DER SEQUENCE".into()));
    }
    let body = outer.value;

    let (cri, _cri_total) = read_tlv(body)?;
    if cri.tag != 0x30 {
        return Err(CsrError::Pem(
            "CSR missing certificationRequestInfo".into(),
        ));
    }

    let (_version, v_total) = read_tlv(cri.value)?;
    let after_version = &cri.value[v_total..];
    let (_subject, s_total) = read_tlv(after_version)?;
    let after_subject = &after_version[s_total..];
    let (spki, _) = read_tlv(after_subject)?;
    if spki.tag != 0x30 {
        return Err(CsrError::Pem("CSR missing subjectPKInfo".into()));
    }
    let (alg, alg_total) = read_tlv(spki.value)?;
    if alg.tag != 0x30 || spki.value[..alg_total] != ED25519_SPKI_ALG {
        return Err(CsrError::Pem("CSR public key is not Ed25519".into()));
    }
    let after_alg = &spki.value[alg_total..];
    let (pk_bits, _) = read_tlv(after_alg)?;
    if pk_bits.tag != 0x03 || pk_bits.value.is_empty() || pk_bits.value[0] != 0 {
        return Err(CsrError::Pem(
            "CSR public key is not a byte-aligned BIT STRING".into(),
        ));
    }
    let pk_bytes = &pk_bits.value[1..];
    if pk_bytes.len() != 32 {
        return Err(CsrError::Pem(
            "CSR public key must be 32 bytes (Ed25519)".into(),
        ));
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(pk_bytes);
    Ok(public_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_public_key_matching_generated_csr() {
        let generated =
            dp_rust_mtls::generate_key_and_csr("device-1", Some("db1--acme.example")).unwrap();
        let pubkey = extract_ed25519_public_key(&generated.csr_pem).unwrap();
        let x_expected = generated.public_jwk.get("x").unwrap().as_str().unwrap();
        let x_actual = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(pubkey);
        assert_eq!(x_actual, x_expected);
    }
}

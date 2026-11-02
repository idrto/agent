//! In-band mutual proof that binds each peer's DP device identity to this exact
//! WebRTC session.
//!
//! After the DataChannel opens, both peers exchange a fresh 32-byte nonce, then
//! each signs a transcript with its DP device Ed25519 key and sends its
//! certificate chain. The transcript covers the signer's and the verifier's
//! roles, the session id, the Target FQHN, both DTLS fingerprints (from the SDP
//! that libdatachannel verified the handshake against) and both nonces, so a
//! proof can't be replayed into another session, onto another fingerprint, or
//! under the other role. The verifier checks the chain to a trusted entity root,
//! including every certificate's validity period.
//!
//! The DER handling mirrors Presence's `tls::ed25519_cert` / `tls::dp_san`
//! (Ed25519 device certificates only); keep them in sync.

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const BIND_DOMAIN: &str = "idr-peer-bind/v1";
/// Mux service name for the binding stream.
pub const BIND_SERVICE: &str = "idr.bind";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindRole {
    /// The WebRTC offerer (the Source today).
    Offerer,
    /// The WebRTC answerer (the Target today).
    Answerer,
}

impl BindRole {
    fn label(self) -> &'static str {
        match self {
            Self::Offerer => "offerer",
            Self::Answerer => "answerer",
        }
    }

    pub fn peer(self) -> Self {
        match self {
            Self::Offerer => Self::Answerer,
            Self::Answerer => Self::Offerer,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BindMsg {
    Hello { version: u16, nonce: [u8; 32] },
    Proof { ski: String, chain_pem: String, signature: Vec<u8> },
}

/// Session facts both peers already agree on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindContext {
    pub session_id: String,
    pub target_fqhn: String,
    /// `a=fingerprint` values from the offer and answer SDP (see [`sdp_fingerprint`]).
    pub offerer_fingerprint: String,
    pub answerer_fingerprint: String,
    /// Observed locally from the selected ICE pair; not part of the transcript.
    pub path: Option<crate::webrtc_ice::IcePath>,
}

/// The exact bytes `signer` signs.
pub fn transcript(
    ctx: &BindContext,
    signer: BindRole,
    offerer_nonce: &[u8; 32],
    answerer_nonce: &[u8; 32],
) -> Vec<u8> {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    format!(
        "{BIND_DOMAIN}\nsigner={}\nverifier={}\nsession={}\nfqhn={}\nfp_offerer={}\nfp_answerer={}\nnonce_offerer={}\nnonce_answerer={}",
        signer.label(),
        signer.peer().label(),
        ctx.session_id,
        ctx.target_fqhn.to_ascii_lowercase(),
        ctx.offerer_fingerprint,
        ctx.answerer_fingerprint,
        hex(offerer_nonce),
        hex(answerer_nonce),
    )
    .into_bytes()
}

pub fn sign(key: &SigningKey, transcript: &[u8]) -> Vec<u8> {
    key.sign(transcript).to_bytes().to_vec()
}

/// `sha-256 AB:CD:...` from the first `a=fingerprint:` line, normalized.
pub fn sdp_fingerprint(sdp: &str) -> Option<String> {
    sdp.lines().find_map(|l| {
        let v = l.trim().strip_prefix("a=fingerprint:")?;
        let (alg, fp) = v.split_once(' ')?;
        Some(format!("{} {}", alg.to_ascii_lowercase(), fp.trim().to_ascii_uppercase()))
    })
}

// ---- Verification ----------------------------------------------------------

/// What the verifier requires of the peer.
#[derive(Debug, Clone, Default)]
pub struct TrustPolicy {
    /// DER entity root certificates the peer's chain must end at.
    pub roots: Vec<Vec<u8>>,
    /// The peer's SKI must equal this (Target: the Presence-attested `policy.ski`).
    pub require_ski: Option<String>,
    /// The peer's leaf must carry this `dNSName` SAN (Source: the Target FQHN it dialled).
    pub require_dns: Option<String>,
    /// Verification time, seconds since the Unix epoch.
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPeer {
    pub ski: String,
    pub role: BindRole,
    /// Earliest `notAfter` in the chain: the identity is not valid past this.
    pub not_after: i64,
    /// How this session reaches the peer (direct or relayed), if known.
    pub path: Option<crate::webrtc_ice::IcePath>,
}

/// Stable reasons; detail stays local.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindError {
    ChainInvalid,
    Untrusted,
    Expired,
    SkiMismatch,
    HostMismatch,
    SignatureInvalid,
}

/// Verify the `peer`'s proof over the transcript it was supposed to sign.
pub fn verify(
    peer: BindRole,
    ski: &str,
    chain_pem: &str,
    signature: &[u8],
    transcript: &[u8],
    trust: &TrustPolicy,
) -> Result<VerifiedPeer, BindError> {
    use BindError::*;
    let chain = pem_certs(chain_pem).ok_or(ChainInvalid)?;
    let leaf = chain.first().ok_or(ChainInvalid)?;
    if ski_from_leaf(leaf).as_deref() != Some(ski) {
        return Err(SkiMismatch);
    }
    if trust.require_ski.as_deref().is_some_and(|want| want != ski) {
        return Err(SkiMismatch);
    }
    if let Some(host) = &trust.require_dns {
        if !dns_names(leaf).iter().any(|n| n.eq_ignore_ascii_case(host)) {
            return Err(HostMismatch);
        }
    }
    // Each certificate is signed by the next; the last by (or equal to) a root.
    let mut not_after = i64::MAX;
    let mut anchored = false;
    for (i, cert) in chain.iter().enumerate() {
        let (nb, na) = validity(cert).ok_or(ChainInvalid)?;
        if trust.now < nb || trust.now > na {
            return Err(Expired);
        }
        not_after = not_after.min(na);
        if trust.roots.iter().any(|r| r == cert) {
            anchored = true;
            break;
        }
        match chain.get(i + 1) {
            Some(issuer) => {
                // An issuer must be a CA: an enrolled device's own key can't mint
                // certificates (e.g. one naming another device's host).
                if !signed_by(cert, issuer) || !is_ca(issuer) {
                    return Err(ChainInvalid);
                }
            }
            None => {
                let root = trust.roots.iter().find(|r| signed_by(cert, r)).ok_or(Untrusted)?;
                let (rnb, rna) = validity(root).ok_or(ChainInvalid)?;
                if trust.now < rnb || trust.now > rna {
                    return Err(Expired);
                }
                not_after = not_after.min(rna);
                anchored = true;
            }
        }
    }
    if !anchored {
        return Err(Untrusted);
    }
    let key = ed25519_public_key(leaf)
        .and_then(|k| VerifyingKey::from_bytes(&k).ok())
        .ok_or(ChainInvalid)?;
    let sig = Signature::from_slice(signature).map_err(|_| SignatureInvalid)?;
    key.verify_strict(transcript, &sig)
        .map_err(|_| SignatureInvalid)?;
    Ok(VerifiedPeer {
        ski: ski.to_string(),
        role: peer,
        not_after,
        path: None,
    })
}

/// The self-signed root at the end of `chain_pem`, if the chain carries one.
pub fn root_of_chain(chain_pem: &str) -> Option<Vec<u8>> {
    let last = pem_certs(chain_pem)?.pop()?;
    signed_by(&last, &last).then_some(last)
}

// ---- Minimal DER for Ed25519 device certificates ---------------------------

const ED25519_ALG: [u8; 5] = [0x06, 0x03, 0x2b, 0x65, 0x70];
const SAN_OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x11];

/// DER certificates in a PEM bundle, in order.
pub fn pem_certs(pem: &str) -> Option<Vec<Vec<u8>>> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find(BEGIN) {
        let body_start = start + BEGIN.len();
        let end = rest[body_start..].find(END)? + body_start;
        let b64: String = rest[body_start..end].split_whitespace().collect();
        out.push(STANDARD.decode(b64).ok()?);
        rest = &rest[end + END.len()..];
    }
    (!out.is_empty()).then_some(out)
}

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

fn read_tlv(input: &[u8]) -> Option<(Tlv<'_>, usize)> {
    if input.len() < 2 {
        return None;
    }
    let tag = input[0];
    let mut idx = 2;
    let len = if input[1] & 0x80 == 0 {
        input[1] as usize
    } else {
        let n = (input[1] & 0x7f) as usize;
        if n == 0 || n > 4 || input.len() < 2 + n {
            return None;
        }
        idx += n;
        input[2..2 + n].iter().fold(0usize, |l, b| (l << 8) | *b as usize)
    };
    if input.len() < idx + len {
        return None;
    }
    Some((Tlv { tag, value: &input[idx..idx + len] }, idx + len))
}

/// TBSCertificate fields after the optional version: serial, signature,
/// issuer, validity, subject, spki, then optional extensions.
fn tbs_fields(cert: &[u8]) -> Option<Vec<Tlv<'_>>> {
    let (outer, total) = read_tlv(cert)?;
    if outer.tag != 0x30 || total != cert.len() {
        return None;
    }
    let (tbs, _) = read_tlv(outer.value)?;
    if tbs.tag != 0x30 {
        return None;
    }
    let mut rest = tbs.value;
    let mut fields = Vec::new();
    while !rest.is_empty() {
        let (f, n) = read_tlv(rest)?;
        rest = &rest[n..];
        if fields.is_empty() && f.tag == 0xa0 {
            continue; // version
        }
        fields.push(f);
    }
    (fields.len() >= 6).then_some(fields)
}

fn split_signed(cert: &[u8]) -> Option<(&[u8], [u8; 64])> {
    let (outer, _) = read_tlv(cert)?;
    let body = outer.value;
    let (_, tbs_total) = read_tlv(body)?;
    let rest = &body[tbs_total..];
    let (alg, alg_total) = read_tlv(rest)?;
    if alg.tag != 0x30 || !alg.value.starts_with(&ED25519_ALG) {
        return None;
    }
    let (sig, _) = read_tlv(&rest[alg_total..])?;
    if sig.tag != 0x03 || sig.value.len() != 65 || sig.value[0] != 0 {
        return None;
    }
    Some((&body[..tbs_total], sig.value[1..].try_into().ok()?))
}

pub fn ed25519_public_key(cert: &[u8]) -> Option<[u8; 32]> {
    let fields = tbs_fields(cert)?;
    let spki = &fields[5];
    let (alg, n) = read_tlv(spki.value)?;
    if spki.tag != 0x30 || alg.tag != 0x30 || !alg.value.starts_with(&ED25519_ALG) {
        return None;
    }
    let (key, _) = read_tlv(&spki.value[n..])?;
    if key.tag != 0x03 || key.value.len() != 33 || key.value[0] != 0 {
        return None;
    }
    key.value[1..].try_into().ok()
}

pub fn signed_by(cert: &[u8], issuer: &[u8]) -> bool {
    let (Some((tbs, sig)), Some(key)) = (split_signed(cert), ed25519_public_key(issuer)) else {
        return false;
    };
    VerifyingKey::from_bytes(&key)
        .map(|k| k.verify_strict(tbs, &Signature::from_bytes(&sig)).is_ok())
        .unwrap_or(false)
}

/// `(notBefore, notAfter)` as seconds since the Unix epoch.
pub fn validity(cert: &[u8]) -> Option<(i64, i64)> {
    let fields = tbs_fields(cert)?;
    let v = &fields[3];
    if v.tag != 0x30 {
        return None;
    }
    let (nb, n) = read_tlv(v.value)?;
    let (na, _) = read_tlv(&v.value[n..])?;
    Some((asn1_time(&nb)?, asn1_time(&na)?))
}

/// UTCTime (`YYMMDDHHMMSSZ`) or GeneralizedTime (`YYYYMMDDHHMMSSZ`).
fn asn1_time(t: &Tlv<'_>) -> Option<i64> {
    let s = std::str::from_utf8(t.value).ok()?.strip_suffix('Z')?;
    let num = |a: usize, b: usize| s.get(a..b)?.parse::<i64>().ok();
    let (year, rest) = match (t.tag, s.len()) {
        (0x17, 12) => {
            let yy = num(0, 2)?;
            (if yy >= 50 { 1900 + yy } else { 2000 + yy }, 2)
        }
        (0x18, 14) => (num(0, 4)?, 4),
        _ => return None,
    };
    let (mo, d, h, mi, se) = (
        num(rest, rest + 2)?,
        num(rest + 2, rest + 4)?,
        num(rest + 4, rest + 6)?,
        num(rest + 6, rest + 8)?,
        num(rest + 8, rest + 10)?,
    );
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    // Days from civil (proleptic Gregorian), as in Howard Hinnant's algorithm.
    let y = if mo <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + se)
}

const BASIC_CONSTRAINTS_OID: [u8; 5] = [0x06, 0x03, 0x55, 0x1d, 0x13];

/// `(oid TLV bytes, extnValue contents)` for each extension.
fn extensions(cert: &[u8]) -> Vec<(&[u8], &[u8])> {
    let mut out = Vec::new();
    let Some(fields) = tbs_fields(cert) else { return out };
    let Some(ext) = fields.iter().find(|f| f.tag == 0xa3) else { return out };
    let Some((seq, _)) = read_tlv(ext.value) else { return out };
    let mut rest = seq.value;
    while let Some((e, n)) = read_tlv(rest) {
        rest = &rest[n..];
        let mut body = e.value;
        let Some((_, oid_n)) = read_tlv(body) else { continue };
        let oid = &body[..oid_n];
        body = &body[oid_n..];
        if let Some((b, bn)) = read_tlv(body) {
            if b.tag == 0x01 {
                body = &body[bn..];
            }
        }
        if let Some((octets, _)) = read_tlv(body) {
            if octets.tag == 0x04 {
                out.push((oid, octets.value));
            }
        }
    }
    out
}

/// `basicConstraints` present with `cA = TRUE`.
pub fn is_ca(cert: &[u8]) -> bool {
    extensions(cert).into_iter().any(|(oid, value)| {
        oid == BASIC_CONSTRAINTS_OID
            && read_tlv(value)
                .filter(|(seq, _)| seq.tag == 0x30)
                .and_then(|(seq, _)| read_tlv(seq.value))
                .is_some_and(|(b, _)| b.tag == 0x01 && b.value.first().is_some_and(|v| *v != 0))
    })
}

fn san_names(cert: &[u8]) -> Vec<(u8, String)> {
    let mut out = Vec::new();
    for (oid, value) in extensions(cert) {
        if oid != SAN_OID {
            continue;
        }
        let Some((names, _)) = read_tlv(value) else { continue };
        let mut r = names.value;
        while let Some((name, nn)) = read_tlv(r) {
            r = &r[nn..];
            if let Ok(s) = std::str::from_utf8(name.value) {
                out.push((name.tag, s.to_string()));
            }
        }
    }
    out
}

/// SKI from the leaf's `urn:dp:ski:` URI SAN.
pub fn ski_from_leaf(cert: &[u8]) -> Option<String> {
    san_names(cert)
        .into_iter()
        .find_map(|(tag, v)| (tag == 0x86).then(|| v.strip_prefix("urn:dp:ski:").map(String::from)).flatten())
}

fn dns_names(cert: &[u8]) -> Vec<String> {
    san_names(cert)
        .into_iter()
        .filter_map(|(tag, v)| (tag == 0x82).then_some(v))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asn1_times() {
        let t = |tag, s: &str| asn1_time(&Tlv { tag, value: s.as_bytes() });
        assert_eq!(t(0x17, "700101000000Z"), Some(0));
        assert_eq!(t(0x17, "260102030405Z"), Some(1_767_323_045));
        assert_eq!(t(0x18, "20491231235959Z"), Some(2_524_607_999));
        assert_eq!(t(0x17, "261302030405Z"), None);
        assert_eq!(t(0x17, "2601020304Z"), None);
    }

    #[test]
    fn fingerprint_from_sdp() {
        let sdp = "v=0\r\na=group:BUNDLE 0\r\na=fingerprint:SHA-256 ab:cd:ef\r\n";
        assert_eq!(sdp_fingerprint(sdp).as_deref(), Some("sha-256 AB:CD:EF"));
        assert_eq!(sdp_fingerprint("v=0"), None);
    }

    #[test]
    fn transcript_names_both_roles() {
        let ctx = BindContext {
            session_id: "s".into(),
            target_fqhn: "Host--E.idr.to".into(),
            offerer_fingerprint: "o".into(),
            answerer_fingerprint: "a".into(),
            path: None,
        };
        let t = String::from_utf8(transcript(&ctx, BindRole::Offerer, &[1; 32], &[2; 32])).unwrap();
        assert!(t.contains("signer=offerer\nverifier=answerer"));
        assert!(t.contains("fqhn=host--e.idr.to"));
        assert_ne!(
            transcript(&ctx, BindRole::Offerer, &[1; 32], &[2; 32]),
            transcript(&ctx, BindRole::Answerer, &[1; 32], &[2; 32])
        );
    }
}

//! IDs and W3C trace context (docs/observability/02).

use rand::RngCore;
use uuid::Uuid;

/// A new lowercase-hyphenated UUIDv7 string. The only sanctioned way to mint correlation IDs.
pub fn new_id() -> String {
    Uuid::now_v7().hyphenated().to_string()
}

/// True for a lowercase hyphenated UUID (any version), the only accepted ID text form.
pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, &c)| match i {
            8 | 13 | 18 | 23 => c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
        })
}

/// W3C trace context: 16-byte trace id, 8-byte parent span id, sampled flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceContext {
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    pub sampled: bool,
}

impl TraceContext {
    /// A fresh root context (random non-zero ids, sampled).
    pub fn new_root() -> Self {
        Self {
            trace_id: new_trace_id(),
            span_id: new_span_id(),
            sampled: true,
        }
    }

    /// Parses a `traceparent` header value; `None` when invalid (vectors/ids.json).
    pub fn parse(tp: &str) -> Option<Self> {
        let b = tp.as_bytes();
        if b.len() < 55 || b[2] != b'-' || b[35] != b'-' || b[52] != b'-' {
            return None;
        }
        let version = hex_byte(&b[0..2])?;
        if version == 0xff {
            return None;
        }
        // Version 00 is exactly 55 chars; future versions may append "-…".
        if (version == 0 && b.len() != 55) || (version != 0 && b.len() > 55 && b[55] != b'-') {
            return None;
        }
        let mut trace_id = [0u8; 16];
        for (i, out) in trace_id.iter_mut().enumerate() {
            *out = hex_byte(&b[3 + 2 * i..5 + 2 * i])?;
        }
        let mut span_id = [0u8; 8];
        for (i, out) in span_id.iter_mut().enumerate() {
            *out = hex_byte(&b[36 + 2 * i..38 + 2 * i])?;
        }
        let flags = hex_byte(&b[53..55])?;
        if trace_id == [0; 16] || span_id == [0; 8] {
            return None;
        }
        Some(Self {
            trace_id,
            span_id,
            sampled: flags & 1 == 1,
        })
    }

    pub fn to_traceparent(&self) -> String {
        format!(
            "00-{}-{}-{}",
            self.trace_id_hex(),
            self.span_id_hex(),
            if self.sampled { "01" } else { "00" }
        )
    }

    pub fn trace_id_hex(&self) -> String {
        hex(&self.trace_id)
    }

    pub fn span_id_hex(&self) -> String {
        hex(&self.span_id)
    }
}

pub(crate) fn new_trace_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    while id == [0; 16] {
        rand::rngs::OsRng.fill_bytes(&mut id);
    }
    id
}

pub(crate) fn new_span_id() -> [u8; 8] {
    let mut id = [0u8; 8];
    while id == [0; 8] {
        rand::rngs::OsRng.fill_bytes(&mut id);
    }
    id
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

/// Lowercase hex only (W3C forbids uppercase).
fn hex_byte(two: &[u8]) -> Option<u8> {
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    Some(nib(two[0])? << 4 | nib(two[1])?)
}

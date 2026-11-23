//! Redaction of free-form strings. The rules and their order are the spec in
//! `spec/telemetry/vectors/redaction.json`; keep this file and that file identical in meaning.

use regex::{Regex, RegexBuilder};
use std::borrow::Cow;
use std::net::Ipv6Addr;
use std::sync::LazyLock;

struct Rule {
    re: Regex,
    replace: &'static str,
}

fn rule(pattern: &str, ci: bool, replace: &'static str) -> Rule {
    let re = RegexBuilder::new(pattern)
        .case_insensitive(ci)
        .build()
        .expect("redaction rule");
    Rule { re, replace }
}

/// Rules before the IPv6 scan, then IPv4 (order matters; see redaction.json).
static BEFORE_IPV6: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        rule(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
            false,
            "[REDACTED PRIVATE KEY]",
        ),
        rule(r"v=0(?:\r?\n[a-z]=[^\r\n]*)+", false, "[REDACTED SDP]"),
        rule(r#"(candidate:)[^\r\n"']+"#, false, "${1}[REDACTED]"),
        rule(r#"(a=fingerprint:)[^\r\n"']+"#, false, "${1}[REDACTED]"),
        rule(
            r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
            false,
            "[REDACTED JWT]",
        ),
        rule(r"(Bearer\s+)[A-Za-z0-9._~+/=-]+", true, "${1}[REDACTED]"),
        rule(
            r#"(https?://[^\s?#"'<>]+)\?[^\s#"'<>]*"#,
            true,
            "${1}?[REDACTED]",
        ),
        rule(
            r#"([?&](?:token|ott|code|access_token|refresh_token|key|secret|signature|password)=)[^&\s"]+"#,
            true,
            "${1}[REDACTED]",
        ),
        rule(
            r#"("(?:token|accessToken|access_token|refreshToken|refresh_token|sessionCookie|cookie|privateKey|private_key|private_jwk|secret|client_secret|password|api_key|apiKey|authorization|session_token|connection_token|auth_token|credential|d)"\s*:\s*")[^"]*""#,
            false,
            "${1}[REDACTED]\"",
        ),
        rule(r"((?:set-)?cookie:\s*)[^\r\n]+", true, "${1}[REDACTED]"),
        rule(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+",
            false,
            "[REDACTED EMAIL]",
        ),
        rule(r#"\b[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s"']+"#, true, "~"),
        rule(r#"(^|[\s"'=(:])/(?:home|Users)/[^/\s"']+"#, false, "${1}~"),
    ]
});

static IPV4: LazyLock<Rule> = LazyLock::new(|| {
    rule(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b",
        false,
        "[REDACTED IP]",
    )
});

/// Masks secrets, personal data and addresses in `text`. Idempotent.
pub fn redact(text: &str) -> Cow<'_, str> {
    let mut out = Cow::Borrowed(text);
    for r in BEFORE_IPV6.iter() {
        if let Cow::Owned(s) = r.re.replace_all(&out, r.replace) {
            out = Cow::Owned(s);
        }
    }
    if let Some(s) = redact_ipv6(&out) {
        out = Cow::Owned(s);
    }
    if let Cow::Owned(s) = IPV4.re.replace_all(&out, IPV4.replace) {
        out = Cow::Owned(s);
    }
    out
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '.' | '%')
}

/// Word scan from redaction.json rule `ipv6`. Returns `None` when nothing changed.
fn redact_ipv6(text: &str) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    let mut changed = false;
    let mut rest = text;
    while let Some(start) = rest.find(is_word_char) {
        out.push_str(&rest[..start]);
        let after = &rest[start..];
        let end = after
            .find(|c: char| !is_word_char(c))
            .unwrap_or(after.len());
        let word = &after[..end];
        let (addr, tail) = match word.find('%') {
            Some(p) => (&word[..p], &word[p..]),
            None if word.ends_with(['.', ':']) => word.split_at(word.len() - 1),
            None => (word, ""),
        };
        let candidate = !addr.is_empty()
            && addr
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
            && addr.matches(':').count() >= 2
            && addr.chars().any(|c| c.is_ascii_hexdigit());
        if candidate && addr.parse::<Ipv6Addr>().is_ok() {
            out.push_str("[REDACTED IP]");
            out.push_str(tail);
            changed = true;
        } else {
            out.push_str(word);
        }
        rest = &after[end..];
    }
    out.push_str(rest);
    changed.then_some(out)
}

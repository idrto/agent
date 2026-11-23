//! `idr.log/1` record: redaction of every string, fixed key order, 8 KiB cap (03 §1).

use crate::redact::redact;
use serde_json::Value as J;
use std::fmt::Write as _;

pub const MAX_RECORD_BYTES: usize = 8 * 1024;
pub const MAX_CRASH_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Trace => "TRACE",
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
            Level::Fatal => "FATAL",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "trace" => Level::Trace,
            "debug" => Level::Debug,
            "info" => Level::Info,
            "warn" | "warning" => Level::Warn,
            "error" => Level::Error,
            "fatal" => Level::Fatal,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Log,
    Span,
    Crash,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Str(String),
    I64(i64),
    U64(u64),
    F64(f64),
    Bool(bool),
    StrList(Vec<String>),
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ErrorInfo {
    pub kind: String,
    pub message: Option<String>,
    pub code: Option<i64>,
    pub stack: Option<String>,
    pub cause: Option<Box<ErrorInfo>>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    pub kind: Kind,
    pub ts: String,
    pub seq: u64,
    pub level: Level,
    pub event: String,
    pub msg: Option<String>,
    pub service: String,
    pub service_version: String,
    pub component: String,
    pub app_session_id: String,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub links: Vec<(String, String)>,
    pub start_ts: Option<String>,
    pub duration_ms: Option<f64>,
    pub status: Option<&'static str>,
    pub session_id: Option<String>,
    pub connection_id: Option<String>,
    pub transfer_id: Option<String>,
    pub operation_id: Option<String>,
    pub report_id: Option<String>,
    pub error: Option<ErrorInfo>,
    pub attrs: Vec<(String, Value)>,
}

impl Record {
    pub fn new(kind: Kind, level: Level, event: impl Into<String>) -> Self {
        Self {
            kind,
            ts: String::new(),
            seq: 0,
            level,
            event: event.into(),
            msg: None,
            service: String::new(),
            service_version: String::new(),
            component: String::new(),
            app_session_id: String::new(),
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            links: Vec::new(),
            start_ts: None,
            duration_ms: None,
            status: None,
            session_id: None,
            connection_id: None,
            transfer_id: None,
            operation_id: None,
            report_id: None,
            error: None,
            attrs: Vec::new(),
        }
    }

    pub fn attr(mut self, key: &str, v: Value) -> Self {
        self.attrs.push((key.to_string(), v));
        self
    }

    /// Redacts every free-form string (msg, error tree, string attrs) — 04 §5.2 step 3.
    pub fn redact_in_place(&mut self) {
        fn r(s: &mut String) {
            if let std::borrow::Cow::Owned(o) = redact(s) {
                *s = o;
            }
        }
        if let Some(m) = &mut self.msg {
            r(m);
        }
        let mut e = self.error.as_mut();
        while let Some(err) = e {
            if let Some(m) = &mut err.message {
                r(m);
            }
            if let Some(s) = &mut err.stack {
                r(s);
            }
            e = err.cause.as_deref_mut();
        }
        for (_, v) in &mut self.attrs {
            match v {
                Value::Str(s) => r(s),
                Value::StrList(l) => l.iter_mut().for_each(r),
                _ => {}
            }
        }
    }

    /// Serializes in the fixed key order (vectors/records.json). `dropped`/`flushed` are
    /// appended by the writer with [`with_tail`].
    pub fn to_line(&self) -> String {
        let mut o = String::with_capacity(512);
        o.push('{');
        let mut first = true;
        let mut key = |o: &mut String, k: &str| {
            if !first {
                o.push(',');
            }
            first = false;
            o.push('"');
            o.push_str(k);
            o.push_str("\":");
        };
        let s = |o: &mut String, v: &str| o.push_str(&J::from(v).to_string());
        key(&mut o, "schema");
        s(&mut o, crate::SCHEMA);
        key(&mut o, "kind");
        s(
            &mut o,
            match self.kind {
                Kind::Log => "log",
                Kind::Span => "span",
                Kind::Crash => "crash",
            },
        );
        key(&mut o, "ts");
        s(&mut o, &self.ts);
        key(&mut o, "seq");
        let _ = write!(o, "{}", self.seq);
        key(&mut o, "level");
        s(&mut o, self.level.as_str());
        key(&mut o, "event");
        s(&mut o, &self.event);
        if let Some(m) = &self.msg {
            key(&mut o, "msg");
            s(&mut o, m);
        }
        for (k, v) in [
            ("service", &self.service),
            ("service_version", &self.service_version),
            ("component", &self.component),
            ("app_session_id", &self.app_session_id),
        ] {
            key(&mut o, k);
            s(&mut o, v);
        }
        for (k, v) in [
            ("trace_id", &self.trace_id),
            ("span_id", &self.span_id),
            ("parent_span_id", &self.parent_span_id),
        ] {
            if let Some(v) = v {
                key(&mut o, k);
                s(&mut o, v);
            }
        }
        if !self.links.is_empty() {
            key(&mut o, "links");
            o.push('[');
            for (i, (t, sp)) in self.links.iter().enumerate() {
                if i > 0 {
                    o.push(',');
                }
                let _ = write!(o, "{{\"trace_id\":\"{t}\",\"span_id\":\"{sp}\"}}");
            }
            o.push(']');
        }
        if let Some(v) = &self.start_ts {
            key(&mut o, "start_ts");
            s(&mut o, v);
        }
        if let Some(d) = self.duration_ms {
            key(&mut o, "duration_ms");
            o.push_str(&J::from(d).to_string());
        }
        if let Some(st) = self.status {
            key(&mut o, "status");
            s(&mut o, st);
        }
        for (k, v) in [
            ("session_id", &self.session_id),
            ("connection_id", &self.connection_id),
            ("transfer_id", &self.transfer_id),
            ("operation_id", &self.operation_id),
            ("report_id", &self.report_id),
        ] {
            if let Some(v) = v {
                key(&mut o, k);
                s(&mut o, v);
            }
        }
        if let Some(e) = &self.error {
            key(&mut o, "error");
            write_error(&mut o, e);
        }
        if !self.attrs.is_empty() {
            key(&mut o, "attrs");
            o.push('{');
            for (i, (k, v)) in self.attrs.iter().enumerate() {
                if i > 0 {
                    o.push(',');
                }
                o.push_str(&J::from(k.as_str()).to_string());
                o.push(':');
                o.push_str(&value_json(v));
            }
            o.push('}');
        }
        o.push('}');
        o
    }

    /// Serialized line within `cap` bytes: trims stack, then string-list attrs, then the
    /// longest string; if still too big, a `diag.record.oversized` replacement.
    pub fn to_capped_line(&mut self, cap: usize) -> String {
        let line = self.to_line();
        if line.len() <= cap {
            return line;
        }
        if let Some(e) = &mut self.error {
            if let Some(st) = &mut e.stack {
                *st = st.lines().take(32).collect::<Vec<_>>().join("\n");
            }
        }
        // Each step removes something; stop when it fits or nothing is left to trim.
        loop {
            let line = self.to_line();
            if line.len() <= cap {
                return line;
            }
            let over = line.len() - cap + 32;
            // 1. Oldest entries of string lists (stderr_tail).
            if let Some(l) = self.attrs.iter_mut().find_map(|(_, v)| match v {
                Value::StrList(l) if !l.is_empty() => Some(l),
                _ => None,
            }) {
                l.remove(0);
                continue;
            }
            // 2. The longest string attribute, then msg, then error.message.
            let longest = self
                .attrs
                .iter_mut()
                .filter_map(|(_, v)| match v {
                    Value::Str(s) => Some(s),
                    _ => None,
                })
                .chain(self.msg.as_mut())
                .chain(self.error.as_mut().and_then(|e| e.message.as_mut()))
                .filter(|s| s.len() > 64)
                .max_by_key(|s| s.len());
            match longest {
                Some(s) => truncate(s, over),
                None => break,
            }
        }
        let bytes = self.to_line().len() as u64;
        let mut rep = Record::new(Kind::Log, Level::Warn, "diag.record.oversized");
        rep.ts = std::mem::take(&mut self.ts);
        rep.seq = self.seq;
        rep.service = std::mem::take(&mut self.service);
        rep.service_version = std::mem::take(&mut self.service_version);
        rep.component = std::mem::take(&mut self.component);
        rep.app_session_id = std::mem::take(&mut self.app_session_id);
        rep.trace_id = self.trace_id.take();
        rep.span_id = self.span_id.take();
        rep.error = Some(ErrorInfo {
            kind: "oversized".into(),
            ..Default::default()
        });
        rep.attrs = vec![
            (
                "event.name".into(),
                Value::Str(std::mem::take(&mut self.event)),
            ),
            ("bytes".into(), Value::U64(bytes)),
        ];
        *self = rep;
        self.to_line()
    }
}

fn truncate(s: &mut String, remove: usize) {
    let keep = s.len().saturating_sub(remove);
    let mut cut = keep;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    let dropped = s.len() - cut;
    s.truncate(cut);
    let _ = write!(s, "…[truncated {dropped}]");
}

fn value_json(v: &Value) -> String {
    match v {
        Value::Str(s) => J::from(s.as_str()).to_string(),
        Value::I64(i) => i.to_string(),
        Value::U64(u) => u.to_string(),
        Value::F64(f) => J::from(*f).to_string(),
        Value::Bool(b) => b.to_string(),
        Value::StrList(l) => J::from(l.clone()).to_string(),
    }
}

fn write_error(o: &mut String, e: &ErrorInfo) {
    let _ = write!(o, "{{\"type\":{}", J::from(e.kind.as_str()));
    if let Some(m) = &e.message {
        let _ = write!(o, ",\"message\":{}", J::from(m.as_str()));
    }
    if let Some(c) = e.code {
        let _ = write!(o, ",\"code\":{c}");
    }
    if let Some(s) = &e.stack {
        let _ = write!(o, ",\"stack\":{}", J::from(s.as_str()));
    }
    if let Some(c) = &e.cause {
        o.push_str(",\"cause\":");
        write_error(o, c);
    }
    o.push('}');
}

/// Appends the writer-owned tail fields (`dropped`, `flushed`) before the closing brace.
pub fn with_tail(line: &str, dropped: u64, flushed: bool) -> String {
    if dropped == 0 && !flushed {
        return line.to_string();
    }
    let mut s = String::with_capacity(line.len() + 32);
    s.push_str(&line[..line.len() - 1]);
    if dropped > 0 {
        let _ = write!(s, ",\"dropped\":{dropped}");
    }
    if flushed {
        s.push_str(",\"flushed\":true");
    }
    s.push('}');
    s
}

/// RFC 3339 UTC with microseconds.
pub fn format_ts(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

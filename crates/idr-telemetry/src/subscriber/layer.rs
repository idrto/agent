//! `tracing` layer: W3C span IDs, correlation inheritance through span scope, `idr.log/1`
//! records for events, span ends and persisted span starts (01 §2.3, 03 §1–3).

use super::pipeline::{Pipeline, Route};
use super::record::{format_ts, ErrorInfo, Kind, Level, Record, Value};
use super::Shared;
use crate::fields;
use crate::ids::{hex, is_uuid, new_span_id, new_trace_id, TraceContext};
use chrono::Utc;
use std::fmt;
use std::sync::Arc;
use std::time::Instant;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record as SpanValues};
use tracing::{Event, Metadata, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// `IDR_LOG` directives: `info,idr_target::webrtc=debug`.
#[derive(Clone, Debug)]
pub struct Directives {
    default: Level,
    targets: Vec<(String, Level)>,
}

impl Directives {
    pub fn parse(s: &str) -> Self {
        let mut d = Self {
            default: Level::Info,
            targets: Vec::new(),
        };
        for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            match part.split_once('=') {
                Some((t, l)) => {
                    if let Some(l) = Level::parse(l.trim()) {
                        d.targets.push((t.trim().to_string(), l));
                    }
                }
                None => {
                    if let Some(l) = Level::parse(part) {
                        d.default = l;
                    }
                }
            }
        }
        d.targets.sort_by_key(|t| std::cmp::Reverse(t.0.len())); // longest prefix first
        d
    }

    pub fn level_for(&self, target: &str) -> Level {
        self.targets
            .iter()
            .find(|(t, _)| target.starts_with(t.as_str()))
            .map_or(self.default, |(_, l)| *l)
    }

    fn most_verbose(&self) -> Level {
        self.targets
            .iter()
            .map(|(_, l)| *l)
            .chain([self.default])
            .min()
            .unwrap_or(Level::Info)
    }
}

pub(crate) fn level_of(meta: &Metadata<'_>) -> Level {
    match *meta.level() {
        tracing::Level::TRACE => Level::Trace,
        tracing::Level::DEBUG => Level::Debug,
        tracing::Level::INFO => Level::Info,
        tracing::Level::WARN => Level::Warn,
        tracing::Level::ERROR => Level::Error,
    }
}

pub(crate) fn component_of(target: &str) -> String {
    let c: String = target
        .replace("::", ".")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' {
                c.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect();
    if c.starts_with(|ch: char| ch.is_ascii_lowercase()) {
        c
    } else {
        format!("x{c}")
    }
}

#[derive(Clone, Default)]
struct Corr {
    session_id: Option<String>,
    connection_id: Option<String>,
    transfer_id: Option<String>,
    operation_id: Option<String>,
    report_id: Option<String>,
}

/// Per-span state stored in the registry's extensions.
pub(crate) struct SpanData {
    pub trace_id: [u8; 16],
    pub span_id: [u8; 8],
    parent_span_id: Option<[u8; 8]>,
    links: Vec<(String, String)>,
    start_wall: chrono::DateTime<Utc>,
    start: Instant,
    corr: Corr,
    attrs: Vec<(String, Value)>,
    error: Option<ErrorInfo>,
    failed: bool,
}

impl SpanData {
    pub(crate) fn context(&self) -> TraceContext {
        TraceContext {
            trace_id: self.trace_id,
            span_id: self.span_id,
            sampled: true,
        }
    }
    pub(crate) fn session_id(&self) -> Option<&str> {
        self.corr.session_id.as_deref()
    }
    pub(crate) fn operation_id(&self) -> Option<&str> {
        self.corr.operation_id.as_deref()
    }
    pub(crate) fn transfer_id(&self) -> Option<&str> {
        self.corr.transfer_id.as_deref()
    }
}

/// Collects fields into the record parts.
#[derive(Default)]
struct Fields {
    event: Option<String>,
    msg: Option<String>,
    corr: Corr,
    remote_parent: Option<TraceContext>,
    links: Vec<(String, String)>,
    persist_start: bool,
    failed: bool,
    error: Option<ErrorInfo>,
    attrs: Vec<(String, Value)>,
}

impl Fields {
    fn error_mut(&mut self) -> &mut ErrorInfo {
        self.error.get_or_insert_with(|| ErrorInfo {
            kind: "unspecified".into(),
            ..Default::default()
        })
    }

    fn put_str(&mut self, name: &str, v: String) {
        match name {
            fields::EVENT => self.event = Some(v),
            fields::MESSAGE => self.msg = Some(v),
            fields::SESSION_ID
            | fields::CONNECTION_ID
            | fields::TRANSFER_ID
            | fields::OPERATION_ID
            | fields::REPORT_ID => {
                if is_uuid(&v) {
                    let slot = match name {
                        fields::SESSION_ID => &mut self.corr.session_id,
                        fields::CONNECTION_ID => &mut self.corr.connection_id,
                        fields::TRANSFER_ID => &mut self.corr.transfer_id,
                        fields::OPERATION_ID => &mut self.corr.operation_id,
                        _ => &mut self.corr.report_id,
                    };
                    *slot = Some(v);
                }
            }
            fields::TRACEPARENT => self.remote_parent = TraceContext::parse(&v),
            fields::LINK => {
                if let Some(t) = TraceContext::parse(&v) {
                    self.links.push((t.trace_id_hex(), t.span_id_hex()));
                }
            }
            fields::STATUS => self.failed = v == "error",
            fields::ERROR_TYPE => {
                self.error_mut().kind = v;
                self.failed = true;
            }
            fields::ERROR_MESSAGE => self.error_mut().message = Some(v),
            fields::ERROR_STACK => self.error_mut().stack = Some(v),
            _ => self.attrs.push((name.to_string(), Value::Str(v))),
        }
    }
}

impl Visit for Fields {
    fn record_str(&mut self, f: &Field, v: &str) {
        self.put_str(f.name(), v.to_string());
    }
    fn record_debug(&mut self, f: &Field, v: &dyn fmt::Debug) {
        self.put_str(f.name(), format!("{v:?}"));
    }
    fn record_i64(&mut self, f: &Field, v: i64) {
        match f.name() {
            fields::ERROR_CODE => self.error_mut().code = Some(v),
            n => self.attrs.push((n.into(), Value::I64(v))),
        }
    }
    fn record_u64(&mut self, f: &Field, v: u64) {
        match f.name() {
            fields::ERROR_CODE => self.error_mut().code = i64::try_from(v).ok(),
            n => self.attrs.push((n.into(), Value::U64(v))),
        }
    }
    fn record_f64(&mut self, f: &Field, v: f64) {
        self.attrs.push((f.name().into(), Value::F64(v)));
    }
    fn record_bool(&mut self, f: &Field, v: bool) {
        match f.name() {
            fields::PERSIST_START => self.persist_start = v,
            n => self.attrs.push((n.into(), Value::Bool(v))),
        }
    }
    fn record_error(&mut self, f: &Field, v: &(dyn std::error::Error + 'static)) {
        if f.name() != "error" {
            return self.put_str(f.name(), v.to_string());
        }
        // `error = &e as &dyn Error`: message plus the source chain as causes.
        let e = self.error_mut();
        e.message = Some(v.to_string());
        let mut slot = &mut e.cause;
        let mut src = v.source();
        while let Some(s) = src {
            *slot = Some(Box::new(ErrorInfo {
                kind: "cause".into(),
                message: Some(s.to_string()),
                ..Default::default()
            }));
            slot = &mut slot.as_mut().unwrap().cause;
            src = s.source();
        }
        self.failed = true;
    }
}

pub struct IdrLayer {
    shared: Arc<Shared>,
    pipeline: Arc<Pipeline>,
    out: Directives,
    recorder: bool,
    recorder_prefixes: Vec<String>,
}

impl IdrLayer {
    pub(crate) fn new(
        shared: Arc<Shared>,
        pipeline: Arc<Pipeline>,
        out: Directives,
        recorder: bool,
        recorder_prefixes: Vec<String>,
    ) -> Self {
        Self {
            shared,
            pipeline,
            out,
            recorder,
            recorder_prefixes,
        }
    }

    fn ring_eligible(&self, target: &str, level: Level) -> bool {
        self.recorder
            && level >= Level::Debug
            && self
                .recorder_prefixes
                .iter()
                .any(|p| target.starts_with(p.as_str()))
    }

    fn route(&self, target: &str, level: Level) -> Route {
        let out = level >= self.out.level_for(target);
        Route {
            to_ring: self.ring_eligible(target, level),
            to_file: out,
            to_stdout: out,
        }
    }

    fn base(&self, kind: Kind, level: Level, event: String, target: &str) -> Record {
        let mut r = Record::new(kind, level, event);
        r.ts = format_ts(Utc::now());
        r.service.clone_from(&self.shared.service);
        r.service_version.clone_from(&self.shared.service_version);
        r.app_session_id.clone_from(&self.shared.app_session_id);
        r.component = component_of(target);
        r
    }
}

fn apply_corr(r: &mut Record, c: &Corr) {
    r.session_id.clone_from(&c.session_id);
    r.connection_id.clone_from(&c.connection_id);
    r.transfer_id.clone_from(&c.transfer_id);
    r.operation_id.clone_from(&c.operation_id);
    r.report_id.clone_from(&c.report_id);
}

fn merge_corr(base: &mut Corr, over: Corr) {
    for (b, o) in [
        (&mut base.session_id, over.session_id),
        (&mut base.connection_id, over.connection_id),
        (&mut base.transfer_id, over.transfer_id),
        (&mut base.operation_id, over.operation_id),
        (&mut base.report_id, over.report_id),
    ] {
        if o.is_some() {
            *b = o;
        }
    }
}

impl<S> Layer<S> for IdrLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn enabled(&self, meta: &Metadata<'_>, _ctx: Context<'_, S>) -> bool {
        let level = level_of(meta);
        level >= self.out.level_for(meta.target()) || self.ring_eligible(meta.target(), level)
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        let most = if self.recorder {
            self.out.most_verbose().min(Level::Debug)
        } else {
            self.out.most_verbose()
        };
        Some(match most {
            Level::Trace => tracing::level_filters::LevelFilter::TRACE,
            Level::Debug => tracing::level_filters::LevelFilter::DEBUG,
            Level::Info => tracing::level_filters::LevelFilter::INFO,
            Level::Warn => tracing::level_filters::LevelFilter::WARN,
            Level::Error | Level::Fatal => tracing::level_filters::LevelFilter::ERROR,
        })
    }

    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut f = Fields::default();
        attrs.record(&mut f);
        let parent = span.parent();
        let parent_ext = parent.as_ref().map(|p| p.extensions());
        let parent_data = parent_ext.as_ref().and_then(|e| e.get::<SpanData>());
        let (trace_id, parent_span_id, mut corr) = match (f.remote_parent, parent_data) {
            (Some(remote), _) => (
                remote.trace_id,
                Some(remote.span_id),
                parent_data.map(|p| p.corr.clone()).unwrap_or_default(),
            ),
            (None, Some(p)) => (p.trace_id, Some(p.span_id), p.corr.clone()),
            (None, None) => (new_trace_id(), None, Corr::default()),
        };
        drop(parent_ext);
        merge_corr(&mut corr, std::mem::take(&mut f.corr));
        let data = SpanData {
            trace_id,
            span_id: new_span_id(),
            parent_span_id,
            links: std::mem::take(&mut f.links),
            start_wall: Utc::now(),
            start: Instant::now(),
            corr,
            attrs: std::mem::take(&mut f.attrs),
            error: f.error.take(),
            failed: f.failed,
        };
        let meta = span.metadata();
        self.shared.span_opened(id.into_u64(), meta.name(), &data);
        if f.persist_start {
            let level = Level::Info;
            let mut r = self.base(
                Kind::Log,
                level,
                format!("{}.started", meta.name()),
                meta.target(),
            );
            r.trace_id = Some(hex(&data.trace_id));
            r.span_id = Some(hex(&data.span_id));
            r.parent_span_id = data.parent_span_id.map(|p| hex(&p));
            apply_corr(&mut r, &data.corr);
            r.attrs = data.attrs.clone();
            self.pipeline.submit(r, self.route(meta.target(), level));
        }
        span.extensions_mut().insert(data);
    }

    fn on_record(&self, id: &Id, values: &SpanValues<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut f = Fields::default();
        values.record(&mut f);
        let mut ext = span.extensions_mut();
        if let Some(d) = ext.get_mut::<SpanData>() {
            merge_corr(&mut d.corr, f.corr);
            d.attrs.extend(f.attrs);
            d.links.extend(f.links);
            d.failed |= f.failed;
            if f.error.is_some() {
                d.error = f.error;
            }
        }
    }

    fn on_follows_from(&self, id: &Id, follows: &Id, ctx: Context<'_, S>) {
        let other = ctx.span(follows).and_then(|s| {
            s.extensions()
                .get::<SpanData>()
                .map(|d| (hex(&d.trace_id), hex(&d.span_id)))
        });
        if let (Some(span), Some(link)) = (ctx.span(id), other) {
            if let Some(d) = span.extensions_mut().get_mut::<SpanData>() {
                d.links.push(link);
            }
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        let meta = event.metadata();
        let level = level_of(meta);
        let route = self.route(meta.target(), level);
        if !(route.to_ring || route.to_file) {
            return;
        }
        let mut f = Fields::default();
        event.record(&mut f);
        let name = f
            .event
            .take()
            .unwrap_or_else(|| "diag.log.unstructured".into());
        let mut r = self.base(Kind::Log, level, name, meta.target());
        r.msg = f.msg.take();
        if let Some(span) = ctx.event_span(event) {
            if let Some(d) = span.extensions().get::<SpanData>() {
                r.trace_id = Some(hex(&d.trace_id));
                r.span_id = Some(hex(&d.span_id));
                apply_corr(&mut r, &d.corr);
            }
        }
        let event_corr = std::mem::take(&mut f.corr);
        let mut c = Corr {
            session_id: r.session_id.take(),
            connection_id: r.connection_id.take(),
            transfer_id: r.transfer_id.take(),
            operation_id: r.operation_id.take(),
            report_id: r.report_id.take(),
        };
        merge_corr(&mut c, event_corr);
        apply_corr(&mut r, &c);
        r.error = f.error.take();
        if level >= Level::Warn && r.error.is_none() {
            r.error = Some(ErrorInfo {
                kind: "unspecified".into(),
                ..Default::default()
            });
        }
        r.attrs = f.attrs;
        self.pipeline.submit(r, route);
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        self.shared.span_closed(id.into_u64());
        let meta = span.metadata();
        let mut ext = span.extensions_mut();
        let Some(d) = ext.remove::<SpanData>() else {
            return;
        };
        let ok_level = level_of(meta);
        let level = if d.failed {
            ok_level.max(Level::Warn)
        } else {
            ok_level
        };
        let route = self.route(meta.target(), level);
        let mut r = self.base(Kind::Span, level, meta.name().to_string(), meta.target());
        r.trace_id = Some(hex(&d.trace_id));
        r.span_id = Some(hex(&d.span_id));
        r.parent_span_id = d.parent_span_id.map(|p| hex(&p));
        r.links = d.links;
        r.start_ts = Some(format_ts(d.start_wall));
        r.duration_ms = Some((d.start.elapsed().as_secs_f64() * 100_000.0).round() / 100.0);
        r.status = Some(if d.failed { "error" } else { "ok" });
        apply_corr(&mut r, &d.corr);
        r.error = d.error;
        r.attrs = d.attrs;
        self.pipeline.submit(r, route);
    }
}

//! Local context (`ctx_json`) carried across FFI, isolates and IPC (docs/observability/01 §4.2).

use crate::ids::{is_uuid, TraceContext};
use serde_json::Value;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LocalContext {
    pub trace: Option<TraceContext>,
    pub session_id: Option<String>,
    pub operation_id: Option<String>,
    pub transfer_id: Option<String>,
}

impl LocalContext {
    /// Parses `ctx_json`. Invalid fields are dropped individually and named in the second
    /// value (`"ctx"` when the whole input is not a JSON object). Empty input is no context.
    pub fn parse(json: &str) -> (Self, Vec<&'static str>) {
        let mut invalid = Vec::new();
        let mut ctx = Self::default();
        if json.trim().is_empty() {
            return (ctx, invalid);
        }
        let Ok(Value::Object(map)) = serde_json::from_str::<Value>(json) else {
            invalid.push("ctx");
            return (ctx, invalid);
        };
        match map.get("traceparent") {
            None | Some(Value::Null) => {}
            Some(v) => match v.as_str().and_then(TraceContext::parse) {
                Some(t) => ctx.trace = Some(t),
                None => invalid.push("traceparent"),
            },
        }
        for (key, slot) in [
            ("session_id", &mut ctx.session_id),
            ("operation_id", &mut ctx.operation_id),
            ("transfer_id", &mut ctx.transfer_id),
        ] {
            match map.get(key) {
                None | Some(Value::Null) => {}
                Some(Value::String(s)) if is_uuid(s) => *slot = Some(s.clone()),
                Some(_) => invalid.push(key),
            }
        }
        (ctx, invalid)
    }

    /// Serializes with null fields omitted, keys in the fixed order.
    pub fn to_json(&self) -> String {
        let tp = self.trace.map(|t| t.to_traceparent());
        let parts: Vec<String> = [
            ("traceparent", tp.as_ref()),
            ("session_id", self.session_id.as_ref()),
            ("operation_id", self.operation_id.as_ref()),
            ("transfer_id", self.transfer_id.as_ref()),
        ]
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| format!("\"{k}\":{}", Value::from(v.as_str()))))
        .collect();
        format!("{{{}}}", parts.join(","))
    }
}

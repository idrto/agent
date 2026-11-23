/// IDR unified logging, tracing and diagnostics (`idr.log/1`) for pure Dart.
///
/// Design: `docs/observability/`. Rules: `docs/observability/07-rules-and-enforcement.md`.
/// Call [Telemetry.init] once at the composition point (app/CLI `main`); libraries only
/// create [IdrLog]s and spans.
library;

export 'src/bundle.dart' show DiagnosticBundle;
export 'src/ctx.dart' show LocalContext;
export 'src/files.dart' show cleanupRuns, recoverRuns, runState, FileSink, RunKey, RunState, Exit, Recovered;
export 'src/ids.dart' show newId, isUuid, TraceContext;
export 'src/log_root.dart' show defaultLogRoot;
export 'src/pipeline.dart' show Limits, Directives;
export 'src/record.dart' show Level, Kind, Record, ErrorInfo, maxRecordBytes, schema, withTail, formatTs;
export 'src/redact.dart' show redact;
export 'src/secret.dart' show Secret;
export 'src/telemetry.dart'
    show
        Telemetry,
        TelemetryConfig,
        TelemetryLink,
        IdrLog,
        Span,
        currentSpan,
        currentTrace,
        currentTraceparent,
        currentContext,
        currentContextJson,
        withIds,
        withContext,
        runGuarded,
        recordFromJson;

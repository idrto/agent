# 04: Local Storage, Flight Recorder, Crashes, Diagnostics, Privacy, Performance, Central Collection

**Release scope:**
- **V1:** §1–§3, §4.1–§4.2 (local bundle export), §5, §6.
- **V2:** §4.3–§4.4 (upload, `diag-ingest`) and §7 (central collection).

## 1. Local storage and rotation (clients)

### 1.1 Log root, per OS

| OS | Log root |
|---|---|
| Windows | `%LOCALAPPDATA%\idr.to\logs\` |
| macOS | `~/Library/Logs/IDR/` |
| Linux | `$XDG_STATE_HOME/idr/logs/` (fallback `~/.local/state/idr/logs/`) |
| Android / iOS | `<app support dir>/logs/` (`path_provider`) |
| Browser (wasm) | no files; in-memory ring (2 MiB), exportable |

### 1.2 Layout

```text
<log root>/
├── idr_target_app/   2026-11-21T10-00-00Z_<app_session_id>_000.jsonl       ← segment (highest NNN may be open)
│                     2026-11-21T10-00-00Z_<app_session_id>_000.rust.jsonl  ← in-process Rust producer
│                     2026-11-21T10-00-00Z_<app_session_id>.jsonl.lock      ← held by the owning process for its lifetime
│                     2026-11-21T10-00-00Z_<app_session_id>.jsonl.ended     ← written once by recovery: {"exit":"clean|unclean|crash"}
├── idrs/             …
├── target-agent/     …
├── source-agent/     …
├── crash/            <app_session_id>_<UTC>.crash.json
└── reports/          <report_id>.zip                                       ← locally built bundles
```

- **File names contain the full `app_session_id`**, never a prefix. UUIDv7 prefixes are timestamp bits and would collide between processes that start in the same millisecond.
- The `_NNN` suffix is the segment number within the run.

### 1.3 Rotation, ownership and retention

- **Run.** A *run* is one producer of one process: the pair (`app_session_id`, producer), where the producer is `jsonl` or `rust.jsonl`. A run owns:
  - its segments `…_<app_session_id>_NNN.<producer>`
  - one lock file `…_<app_session_id>.<producer>.lock`
  - after it ends, one sidecar `…_<app_session_id>.<producer>.ended`
- **Segments.** A file is rotated at **10 MiB**. The writer closes segment `NNN`, then opens `NNN+1`, so the highest-numbered segment of a run is the only one that can be open.
- **Run ownership (lock).**
  - The writer takes an **exclusive, non-blocking OS lock** on the run's lock file at init (`LockFileEx` on Windows, `flock` on POSIX). It holds the lock for the life of the process, whether or not it writes anything, so an idle process stays owned.
  - The OS releases the lock automatically on any exit, crashes included.
- **Ownership states.** Another process determines a run's state by trying the same lock without blocking:

  | Lock attempt | Run state | Meaning |
  |---|---|---|
  | lock acquired (then released at once) | **ended** | No process owns it |
  | "would block" | **active** | A live process owns it |
  | any other error (unsupported filesystem, I/O or permission error), or the lock file is missing while segments exist | **unknown** | Ownership cannot be established |

- **What may be deleted.**

  | Run state | Deletable segments |
  |---|---|
  | **ended**, and its `.ended` sidecar exists (recovery has classified it, §3.3) | all of its segments |
  | **active** | all **except the highest-numbered** segment. Lower segments are closed by construction (rotation closes before it opens). |
  | **unknown** | **nothing.** The run is skipped entirely. There is no fallback on modification time, because an idle owner can leave its active file untouched indefinitely. The library emits `diag.sink.degraded{reason: ownership_unknown, run}` once per run. |

- **Retention:**
  - Enforced by every process over **deletable segments only**, its own lower segments included, so a long-running agent's old segments count toward the cap. **Each implementation manages only runs of its own producer type** (Dart: `jsonl`; in-process Rust: `rust.jsonl`; a Rust binary: `jsonl` in its own service directory). Lock primitives differ between languages on POSIX (`fcntl` in Dart, `flock` in Rust) and do not see each other, so ownership is only ever tested by the implementation that takes it.
  - The cap is **100 MiB of deletable segments per producer per service directory, or 7 days**, whichever is reached first; a GUI directory with an in-process engine can therefore hold up to 2 × 100 MiB. The oldest segment is deleted first.
  - An unknown run can make the directory exceed the cap. The disk guard below still protects the disk.
  - When every segment of an ended run is gone, its lock file and sidecar are deleted too.
  - `crash/` keeps 20 records; `reports/` keeps 5 bundles.
  - At init, recovery (§3.3) runs **before** cleanup. Cleanup then runs after each rotation and every hour.
- **Disk guard.** If free disk space is below 500 MiB, writers stop file output (ring only) and emit `diag.sink.unavailable{reason: low_disk}` once.
- **Concurrency.** Each producer writes only its own files, so no two writers ever append to the same file.
- **Permissions:**
  - Directories are user-only: `0700` on POSIX, and the default per-user ACL under `%LOCALAPPDATA%` on Windows.
  - Files are `0600`.
- **Failure handling.** If the log root cannot be written, the library emits `diag.sink.unavailable` to stderr once and continues ring-only. The app keeps running.
- **Spawned agents** receive `IDR_LOG_DIR` from their parent, so the GUI and its agent share one root, which the bundle collector needs. A daemon started by hand uses the same OS default.
- **Clock.**
  - `ts` is the wall clock.
  - Within a producer, ordering uses `seq`. Across producers it uses `ts` ([03 §1.3](03-log-schema-and-events.md)).
  - Cross-host alignment uses `app.clock.offset_measured`, which compares against the `Date` header of the first Billing response.

## 2. Flight recorder

- **What it holds.** Every process keeps an in-memory ring of the most recent DEBUG+ records.
  - It is **byte-capped at 3 MiB** (1 MiB on mobile and wasm).
  - When full, the oldest records are evicted first.
  - The 8 KiB per-record cap applies.
- **DEBUG stays live, for IDR code only.** While the recorder is on, DEBUG call sites **of IDR crates and packages** stay enabled even when the file sink is at INFO. The file layer filters; the ring does not. Third-party DEBUG (rustls, quinn, …) is not bounded per operation, so it is captured only when `IDR_LOG` enables it explicitly (`recorder_prefixes`, default `idr*`, the agent and server binaries). TRACE is never recorded.
- **Records are already redacted** before they enter the ring (§5.2).
- **Flush triggers.** The ring is written to the file, with `"flushed": true` in each record, when:
  - an ERROR or FATAL record is emitted (debounced: at most once per 30 s per `trace_id`)
  - a registered stall or timeout event fires (`transfer.stalled`, `*.timed_out`)
  - a diagnostic bundle is built (the caller waits for its drain to finish, §2.1 step 7)
  - a crash occurs. The crash handler instead copies the last 200 ring records synchronously into the crash record; no drain is involved.

- **Effect.** Production files stay at INFO volume, and every failure still arrives with its DEBUG prologue.
- **Cost.** Keeping DEBUG live costs the construction of DEBUG records. This is why DEBUG must stay bounded per operation, and per-frame, per-message or per-chunk detail is TRACE ([03 §2](03-log-schema-and-events.md)).

### 2.1 Drain: how a flush survives the queue limit

A flush **never** goes through the normal enqueue path. The writer queue (1 MiB) is smaller than the ring (3 MiB), so pushing the ring through it would drop the evidence being captured. The writer drains the ring itself. Everything below is per producer, because each producer has its own ring, queue and writer.

**Persistence tracking.**
- Each record is one shared object, `Arc` in Rust and a single object reference in Dart, referenced by the ring **and**, if it passes the file level, by the queue.
- The object carries a `persisted` flag. Only the writer sets it, after the record's bytes have been handed to the file (the same moment it counts as written).
- A record dropped by the queue, or never queued because it is below the file level, keeps `persisted = false`.
- **Whether a record was saved is decided by this flag, never by its severity.**
- Each record also carries its producer `seq`, assigned at creation.

1. **Trigger.**
   - The producer that hits a trigger enqueues one small control message: `Flush{id, watermark_seq, scope{trace_ids, session_ids}}`. `watermark_seq` is the `seq` of the triggering record.
   - The control message is **exempt from the byte cap**. The triggering record is created and offered to the queue before the `Flush`, so its `seq` is never above the watermark.
   - The `Flush` also holds a **direct reference to the triggering record**. If the queue dropped it **and** a burst of DEBUG evicted it from the ring before the writer arrived, it is still written in step 5.
   - The producer never blocks.
2. **Snapshot by split at the watermark.**
   - When the writer reaches the `Flush` message, every record enqueued before it (all of them have `seq ≤ watermark_seq`) has already been written or dropped.
   - The ring is ordered by `seq`. Under the ring's lock, the writer **detaches only the prefix with `seq ≤ watermark_seq`** as the snapshot.
   - Records with `seq > watermark_seq`, created between the trigger and the split, **stay in the live ring**, in order. Producers keep appending behind them.
   - The split is O(1): a cut at an index found by binary search on `seq`, with no record copied. Producers are never stalled.
   - The live ring's byte accounting is reduced by the detached bytes. The remaining records stay under its 3 MiB cap and its oldest-first eviction, exactly like any other ring record.
3. **Select.** From the snapshot, the writer takes every record with `persisted == false`:
   - DEBUG records (below the file level)
   - **any INFO+ record the queue dropped, including the triggering ERROR**

   Records above the watermark are not in the snapshot. They remain in the live ring, so a **later drain** (a follow-up from step 6, or the next trigger) can still select them if they are still unpersisted when it runs. If they are in flight in the queue, normal queue handling applies, and a record dropped there keeps `persisted == false`.
4. **Scope filter.**
   - Selected records **sharing a scoped `trace_id` or `session_id`** are written first, then the rest of the last 60 s.
   - Older non-scoped records are discarded.
   - **The triggering record is always written, whatever the filter.**
5. **Direct write.**
   - The writer writes the selection **straight to the producer's current segment**, with `"flushed": true`, in 256 KiB batches, rotating segments as needed. It sets `persisted` on each record it writes.
   - It then frees the snapshot.
   - The selection is **not** subject to queue limits and is never dropped. The only exceptions are a disk error or the disk guard, which produce `diag.records.dropped{reason: disk}`.
   - Normal records keep queueing meanwhile (1 MiB, drop-incoming, counted). Readers order everything by `ts`/`seq`.
6. **Triggers during a drain create a follow-up drain.**
   - The records relevant to a trigger that arrives **during** a drain are in the *live* ring, so adding its scope to the current snapshot would capture nothing.
   - **States:** at most one drain is *active* and at most one is *pending*.
   - **Merging:** a trigger that arrives while a drain is active is merged into the **pending** drain. Its scope is added, and `watermark_seq` takes the maximum. A trigger that arrives while nothing is active simply becomes the active drain.
   - **Start:** the pending drain starts only **after** the active drain's snapshot has been freed. It performs its own split at its own (maximum) watermark, so it captures both:
     - the records the earlier split left above *its* watermark
     - everything appended since
   - **Eviction can still win.** A record kept in the live ring can still be evicted oldest-first if a DEBUG burst larger than the ring arrives before the follow-up runs. This is the ring's normal bounded behaviour, and it is counted in `diag.records.dropped{reason: ring_evicted_unflushed}`.
   - **Pacing:** a follow-up starts no sooner than 1 s after the previous drain ended, to bound drain churn under an error storm. Triggers keep merging into it during that second.
   - The per-`trace_id` debounce (30 s) applies at trigger time, before merging.
7. **Bundle builds wait for the right drain.**
   - A bundle request is a trigger with a completion handle.
   - Its watermark is the producer's current `seq` at request time.
   - It is attached to **the first drain that has not yet split**: the pending drain (whose watermark becomes the maximum), or a new one if none is pending. It is never attached to a drain that has already split.
   - The bundle is collected only after that drain's direct write has finished, and the file is synced.

**Peak memory during a drain:**

| Platform | Ring | Snapshot | Queue | Peak |
|---|---|---|---|---|
| Desktop | 3 MiB | 3 MiB | 1 MiB | **7 MiB** |
| Mobile / wasm | 1 MiB | 1 MiB | 1 MiB | **3 MiB** |

- **One snapshot at a time.** A pending drain does not split until the active snapshot is freed, so at most one snapshot exists.
- **The snapshot and the live ring together never exceed ring cap + snapshot.** The snapshot is a detached prefix of the ring, and the live ring keeps its own 3 MiB cap, so the peak stays 7 MiB.
- **Shared objects cost nothing extra.** A record referenced by both the ring and the queue is counted against both caps (the conservative choice), but it occupies memory once.

**Dart.** The file sink runs in the same isolate, so the drain is the sink's async task writing the selection in 256 KiB chunks. Normal records are buffered in the 1 MiB queue meanwhile. The semantics are the same as in Rust, including the `persisted` flag, the watermark, follow-up drains and bundle completion.

## 3. Crash capture and recovery

### 3.1 Capture paths

| Crash type | Capture path | Writes | Evidence quality |
|---|---|---|---|
| Dart uncaught (any isolate) | `runGuarded` (zone) + `Isolate.addErrorListener` + Flutter `FlutterError.onError` / `PlatformDispatcher.onError` | `kind:"crash"` record to `crash/` (synchronous write), FATAL in the log | complete |
| Flutter framework error that is not fatal | `FlutterError.onError` | ERROR record `ui.framework.error` (rate-limited) | complete |
| Rust panic in `idr-c-api` / `idr-dp-ffi` exports | `ffi_guard` (`catch_unwind`) around **every** `extern "C"` function, plus `install_panic_hook` | crash record; the export returns `IDR_ERR_PANIC`; the engine is marked poisoned (later calls fail fast with `ffi.engine_poisoned`) instead of aborting the Flutter host | complete: the open spans are known in-process |
| Rust panic in a tokio task (embedded or agent) | panic hook (process-wide) + `JoinHandle` error logging | crash record, ERROR; the task supervisor decides whether to restart | complete |
| Rust panic in an agent binary main thread | panic hook | crash record, then exit code 101 | complete |
| Native abort (libdatachannel, segfault) | Not catchable in-process. The parent detects it: `agent.process.exited{signal}` plus `stderr_tail` (redacted). For the in-process engine there is no record ([D6](09-decisions-risks-approval.md)). | parent's log | **Best effort.** In-memory state, unflushed batches (up to ~50 ms) and the ring are lost. What survives on disk: the persisted `*.started` records ([03 §3.2](03-log-schema-and-events.md)) and the INFO events written before the fault. |
| Hang (no crash) | Watchdog: the main isolate and the agent runtime emit `app.heartbeat` to the ring every 10 s; a stall over 30 s produces `app.unresponsive` WARN plus a recorder flush | | complete |

### 3.2 Crash record contents

- the crash `error` (type, message, stack, all redacted)
- `thread` or `isolate`
- the **open spans**, with their IDs and attributes
- the last 200 ring records
- resource fields
- `app_session_id`

### 3.3 Recovery on the next start

Recovery works **per run, never per segment**. Rotated segments of a healthy run never contain `app.stopping`, so a single segment says nothing about how the run ended.

1. **Find candidate runs.** At init, the library groups the files in its service directory by run (§1.3). Candidates are runs that have no `.ended` sidecar.
2. **Check ownership.** It tries each candidate's lock (§1.3):
   - **active:** the process is alive; skip the run.
   - **unknown:** skip the run; nothing is claimed.
   - **ended:** continue to step 3.
3. **Inspect shutdown evidence** of the ended run:
   - the last 64 KiB of its **highest-numbered** segment
   - `crash/` records with the same `app_session_id`
   - its `*.started` records without a matching span end, in its **highest-numbered segment** (best effort: bounded startup cost, and older segments may already be deleted)

   `app.stopping` is written synchronously as the producer's final record during an orderly shutdown.
4. **Classify** the run:
   - **clean:** the last segment ends with `app.stopping`
   - **crash:** a crash record exists for the run (checked first: a panicking binary may still write `app.stopping` while unwinding)
   - **unclean:** neither is present. The cause is unknown: OS kill, power loss, forced shutdown, or a native crash. A crash is claimed **only** when a crash record exists.
5. **Claim it exactly once.** The library creates the `.ended` sidecar with exclusive create (`O_EXCL` / `CREATE_NEW`). Only the process whose create succeeds continues, so two processes starting together never report the same run twice.
6. **Report** crash or unclean runs with `app.previous_exit_unclean{previous_app_session_id, crash_record, open_operations}` at WARN. One event is emitted per process, covering both producers: the Dart `jsonl` run and the in-process `rust.jsonl` run.
3. The UI responds:
   - **GUI:** a non-blocking banner. With a crash record it says *"IDR closed unexpectedly. Create a report?"*; without one it says *"IDR did not shut down cleanly. Create a report?"*
   - **CLI:** a one-line hint pointing to `idrs diag report`.
4. Nothing leaves the device without the user's action (§4).

## 4. Diagnostic bundles

### 4.1 Bundle (`<report_id>.zip`), V1

```text
manifest.json         report_id (full UUID), created_at, user_note (optional, user-typed),
                      app & agent versions, OS, app_session_ids included, time window,
                      session/connection/transfer/operation/trace IDs found (index),
                      redaction_version, files list + sha256
logs/<service>/*.jsonl   records in window (default: last 2 h; user can pick 24 h)
crash/*.crash.json       crash records in window
state/summary.json    current redacted state snapshot: signed-in (bool), plan code, device enrolled (bool),
                      agent running, Presence transport, active sessions/transfers (IDs + state only)
checks/doctor.json    output of existing doctor/diagnostics reachability checks
```

### 4.2 Building and sharing a bundle, V1

- **Builder:** `DiagnosticBundle.collect()` in `idr_telemetry`.
  - **GUI:** the "Report an issue" screen builds the bundle, shows a summary (size, time range, included categories), and offers "Show in folder".
  - **CLI:** `idrs diag report` / `idr diag report` (`--window 2h`, `--note`, `--out <path>`) prints the path and the `report_id`.
  - Spawned agents are asked over IPC to flush first: `{"cmd":"diag.flush"}`.
- **Redaction runs again** over every string at build time, using the current redactor version, so bugs fixed since the logs were written are applied.
- **V1 has no upload.** The user attaches the zip to their support message or issue themselves and quotes the `report_id`. Building a bundle never sends anything.

### 4.2a Report an issue by email, V1 (Target GUI first; decision D15)

The "Report an issue" screen of `idr_target_app` is also the V1 support channel. The user describes the problem, the app builds the bundle (§4.1), and the app opens the user's own email program with a prefilled message. **The app never sends or uploads anything.** The user attaches the ZIP and presses Send themselves.

**Flow**

1. **Entry points.** Settings/Diagnostics → "Report an issue", and the unclean-exit banner ("The app closed unexpectedly. Report it?").
2. **Describe.** A text box (what happened, what you expected; required, max 2000 characters) and a time-window choice: last 2 h (default) or last 24 h.
3. **Build.** `DiagnosticBundle.collect()` after the writer-controlled drain (§2.1 step 7), with re-redaction (§4.2). The screen shows the result before anything leaves it: size, time range, included categories, `report_id`, and "View contents" (opens the unpacked list; every file can be read).
4. **Open the email program** with the button "Open email". The app builds a `mailto:` link and launches it with `url_launcher`.
   - **To:** `dev10@advcomm.ca` (a constant in the app, not user input).
   - **Subject:** `IDR issue report <report_id>`, e.g. `IDR issue report 01a20908-3a1d-706f-9566-176d8947efbf`.
   - **Body (plain text):** the user's description, then a short fixed block: app version and flavor, OS name and version, CPU architecture, `report_id`, bundle file name and size, and the line "Please attach the ZIP file named above." It holds **no** logs, no FQHN, no email address, no account or device identifiers, and nothing that is not in the preview shown to the user.
   - **Attachment:** none. `mailto:` cannot attach files, and the app does not try to (no MAPI or scripting of the mail client). The app instead **shows the ZIP in its folder** (`reveal` in Explorer/Finder) next to a "Copy path" button, with the text "Attach this file to the email, then send it."
5. **Nothing happens until the user acts.** Closing the screen sends nothing. The user can still delete the bundle (button "Delete report").

**Size limits.** `mailto:` links are limited (about 2000 characters on Windows mail clients). The app keeps the whole link under 1800 characters after percent-encoding: the description is truncated in the link (with "(truncated; full text in the ZIP)") and always stored in full in `manifest.json` → `user_note`. The ZIP is capped at 25 MiB, the common mail-attachment limit: if the 2 h window is larger, the app lowers the DEBUG/INFO tail first and tells the user which part was left out.

**Fallback when no email program works** (no default handler, the launch fails, or the user uses webmail):

- The screen always offers, whether or not the launch worked:
  - "Copy email address", "Copy subject", "Copy message" (the same text as the body above), and "Copy path of the ZIP".
  - "Show in folder".
  - A short instruction: "Send an email to dev10@advcomm.ca with this subject and message, and attach the ZIP."
- If `launchUrl` returns false or throws, the app says so plainly ("No email program was found") and expands the same copy actions. It records `diag.report.mail_launch_failed` (no address or text in the record).

**Privacy protection**

- **Consent is the gesture.** The bundle stays on the device. Nothing is attached or sent by the app; the user sees the ZIP and the message before they send it (R-PRIV-6).
- **Description screening.** The user's text is redacted with the normal redactor before it goes into the link or `manifest.json`, but it is the user's own words, so the screen also warns: "Do not include passwords or tokens." Redaction of tokens, emails and paths still applies.
- **Minimal body.** Only the fixed block above is added. Version, OS and architecture are public-class values (§5.1).
- **No personal identifiers in the email text.** The sender's address comes from their own mail program, which is theirs to control. Account, FQHN and device IDs appear only inside the ZIP, as pseudonymous records already allowed in bundles (§5.1), and the preview lists them.
- **ZIP contents** follow §4.1; nothing is added for email. Personal-class and secret-class values never reach a bundle (§5.2).
- **Local cleanup.** Reports older than 7 days are deleted at start-up; at most 5 are kept (§1.3).
- **Recipient is fixed.** No other address can be entered in this flow; the constant is in one place and changed only by a reviewed commit.

**Events (registered in `spec/telemetry/events.yaml`):** `diag.report.started`, `diag.report.built{bytes, files, window_s}`, `diag.report.mail_opened`, `diag.report.mail_launch_failed{reason}`, `diag.report.deleted`. None carries the description, address or path.

**Later surfaces.** The same flow reuses `DiagnosticBundle` for the Source CLI (`idrs diag report` prints the same subject, body and address, since a CLI cannot reliably open a mail client) and a Source GUI. They are not in the first slice.

### 4.3 Upload and consent, V2

1. **Preview.** The bundle summary and "view contents" are shown, as in V1.
2. **Explicit consent per bundle.** The user presses "Send". The CLI asks for confirmation, or accepts `--yes`.
   - There is no silent or automatic upload.
   - An enterprise policy flag can disable uploads ([D13](09-decisions-risks-approval.md)).
3. **Upload.**
   - The bundle goes over HTTPS to `diag-ingest` ([D4](09-decisions-risks-approval.md)), authenticated with the user's billing session.
   - The upload runs under `operation_id` (kind `diag.upload`) and retries with backoff.
   - **Size cap: 25 MiB compressed.** The client trims the oldest DEBUG records first.
4. **Result.** The server returns the **display code** ([02 report_id](02-identifiers.md)), checked for collisions. The UI shows it with "copy".
5. **Deletion.**
   - The user can delete local bundles.
   - Uploaded bundles are deleted after 30 days, or on request.

### 4.4 `diag-ingest` (V2)

- Stores the zip in object storage.
- Indexes the `manifest.json` IDs into a small table: `report_id → display code, app_session_ids, session_ids, connection_ids, trace_ids, time window, versions`.
- Optionally pushes the JSONL lines into Loki with the structured metadata `report_id`.

## 5. Privacy and redaction

### 5.1 Privacy classes (every attribute in `attributes.yaml` has one)

| Class | Definition | Examples | Allowed in logs? |
|---|---|---|---|
| `public` | Not identifying | event names, versions, `error.type`, `candidate.type`, durations, byte counts | yes |
| `id` | Random correlation IDs | all IDs in [02](02-identifiers.md) | yes |
| `pseudonymous` | Stable but not directly identifying | `device.ski`, `target.fqhn`, `presence.id`, entity ID, hashed email (`user.hash`) | yes. Server logs and bundles. |
| `network` | IP addresses and ports | client and peer IPs | **servers**: truncated (`/24` IPv4, `/48` IPv6) at INFO, full at DEBUG only behind a per-host security opt-in. **Clients**: never. |
| `personal` | Directly identifying | email, name, hostname, file names, file paths with the user name, URLs with query strings | **no**. Use `hash_pii()` or omit. Paths are logged relative with the user's home directory replaced by `~`. |
| `secret` | Credentials and material | private keys, JWTs, bearer tokens, cookies, TURN credentials, `connection_token`, `session_token`, `auth_token`, upstream API keys typed by the user, SDP bodies, invite tokens | **never**. `Secret<T>`; lint-enforced. |

A registered `string` type with class `public` **does not make the content safe**. Free-form strings are always redacted (§5.2 step 3).

### 5.2 Mechanisms (defence in depth)

1. **Types.**
   - `Secret<T>` (Rust and Dart) serializes transparently on the wire, but it cannot be formatted (`[REDACTED]`) and cannot be recorded as a telemetry field. It is read only through `expose()` ([01 §2.3](01-architecture.md)).
   - Secret-bearing structs get a **hand-written `Debug`**.
2. **Attribute registry.** An attribute whose class is `personal` or `secret` cannot be registered for logging.
3. **Redaction at record creation, before any sink.**
   - It runs inside the library, after the record is built and **before** it is handed to the ring, the file, stdout, or a crash record.
   - It applies to **every string value**: `msg`; `error.message`, `error.stack` and every nested `error.cause`; and every string or string-array attribute (`stderr_tail`, `panic.message`, `config.effective`, `reason`, …).
   - Rules: it starts from the `idr_cli_core` `redact()` rules (PEM private keys, JWTs, Bearer values, query secrets, JSON secret fields, cookies) and adds:
     - email → `[REDACTED EMAIL]` (use `hash_pii()` explicitly when a stable pseudonym is needed)
     - IPv4 and IPv6 addresses
     - Windows and Unix user-home paths
     - ICE `candidate:` lines
     - `a=fingerprint`
     - `sdp` blobs
     - URL query strings
   - The exact ordered rules and vectors are in `spec/telemetry/vectors/redaction.json`; both languages run them.
   - **Every rule must run in linear time** in both engines: Rust `regex` is linear by construction, Dart `RegExp` backtracks. A pattern that starts with a repeated character class (the email rule) is implemented as a scan in Dart. Both test suites assert a time budget on adversarial inputs.
4. **Bundle-time re-redaction** with the latest redactor (§4.2).
5. **Collector-side redaction** (Alloy, V2) as a last net for server stdout.

### 5.3 `hash_pii`

- Algorithm: HMAC-SHA256 with a **per-installation random key** stored next to the logs (`<log root>/.pii_key`), truncated to 16 hex characters.
- Within one installation, the same email gives the same hash.
- Across installations, or on the server, hashes cannot be correlated or reversed. That is intentional.
- **Server-side user correlation** uses the billing user ID or the device SKI, which are pseudonymous, never email.

### 5.4 Error bodies

- HTTP clients must not embed the raw response body in an exception message.
- They parse `{code, message}`, keep `http.response.status_code`, `error.type` and `http.request_id`, and attach a body excerpt of 256 characters or fewer, redacted, only at DEBUG.
- This applies to:
  - the Target SDK clients
  - `dp-rust-sdk::Error::Http`
  - the usage-reporter

### 5.5 Errors returned to remote parties

- Servers return a stable `error.type` plus the server's `trace_id` instead of `e.to_string()`. This covers Presence `presence_error` and the Relay 502 body.
- In V1 the `trace_id` is server-minted. Support can search for it in the server logs.

## 6. Performance budget and techniques

| Budget | Target |
|---|---|
| Call filtered out at every layer (TRACE when not enabled) | ≤ 20 ns Rust (`tracing` callsite cache), ≤ 100 ns Dart (level check before closure evaluation) |
| DEBUG record while the recorder is on (built, redacted, pushed to the ring) | ≤ 3 µs p99 Rust, ≤ 15 µs p99 Dart |
| Enabled INFO record end-to-end on the calling thread | ≤ 5 µs p99 Rust, ≤ 20 µs p99 Dart (serialization and redaction on the caller; I/O on the writer) |
| Steady-state client volume | ≤ 1 INFO record/s average; ≤ 10 MiB/day at INFO |
| CPU overhead | < 1 % in the transfer benchmark at 1 Gbps |
| Memory per process | **byte caps:** ring 3 MiB (mobile 1 MiB) + writer queue 1 MiB; record ≤ 8 KiB. Steady state ≤ 4 MiB; **peak ≤ 7 MiB** (mobile 3 MiB) during a drain (§2.1). |

**Drop policies.** These differ on purpose, one per buffer:

| Buffer | When full | Why |
|---|---|---|
| Writer queue (1 MiB) | **drop the incoming (newest) record**; count it in `dropped` on the next written record and in `diag.records.dropped{bytes, reason: queue_full}` | The queue is what goes to disk. Keeping the records already queued preserves the sequence that led up to the overload and keeps the file contiguous. The caller is never blocked. |
| Flight-recorder ring (3 MiB) | **evict the oldest record** | The ring is a rolling window, and its value is the most recent context |
| Drain selection (§2.1) | **never dropped** (disk error excepted); includes INFO+ records the queue dropped (`persisted == false`) | It is the evidence being captured, including the triggering record |
| Control messages (`Flush`) | exempt from the byte cap; at most one active + one pending drain; later triggers merge into the pending one | A flush must not be lost to the overload it is explaining |

**Techniques:**
- The byte-capped asynchronous writer queue and the ring use the policies above.
- **Oversized records** are trimmed, then replaced, per [03 §1.3](03-log-schema-and-events.md).
- **Level gating before argument construction.** Dart APIs take attribute maps lazily (`log.debug(() => {...})`).
- **No per-packet, per-frame or per-chunk records** above TRACE. Progress is sampled (every 5 s at DEBUG, every 25 % at INFO).
- **Rate limiting:**
  - Identical `(event, error.type)` pairs within 1 s are collapsed into one record with `attrs.repeat`.
  - A per-callsite token bucket on servers covers handshake-failure floods.
- **Servers:** INFO is per session or connection, never per message. The current ICE-candidate INFO logs in Presence move to TRACE.
- **Benchmarks** are part of CI ([07](07-rules-and-enforcement.md)).

## 7. Server-side centralized collection (V2)

**V1 servers.**
- JSON goes to stdout (`IDR_LOG_FORMAT=json` default), captured by journald/podman.
- Developers search it with `journalctl -o cat | jq 'select(.connection_id=="…")'` or `idr_diag merge`.

### 7.1 Pipeline, V2

- **Grafana Alloy** runs on each host ([D5](09-decisions-risks-approval.md)). It:
  - reads the journal or container logs
  - parses JSON
  - parses coturn text with a regex stage into `idr.log/1` fields: `service=turn`, and `connection_id` extracted from the username `exp:<connection_id>:…`
  - drops DEBUG **unless** the record has `flushed: true` (recorder flushes are always kept) or the host is flagged for debug
  - applies the redaction stage
  - pushes to **Loki**

### 7.2 Loki labels

- Labels (low cardinality only): `service`, `env`, `host`, `level`.
- **All IDs go in structured metadata**, never in labels: `trace_id`, `session_id`, `connection_id`, `transfer_id`, `app_session_id`, `report_id`.

### 7.3 Retention and access

- **Retention:** 14 days for INFO+ and flushed records, 3 days for DEBUG (when enabled), 30 days for bundles ([D7](09-decisions-risks-approval.md)).
- **Access:** Grafana with SSO. Only the on-call and engineering groups have access. Queries are audited.

### 7.4 Saved queries and dashboards

- "Investigate report", which takes a `report_id` or display code and expands its IDs.
- "Trace timeline", which takes a `trace_id`.
- "Target health", which takes a `target.fqhn`.
- Existing Prometheus metrics stay as they are. Dashboards link from a metric spike to the Loki query for the same time and service.

### 7.5 Automatic detection

- Alerts fire on log-derived rates:
  - `connection.attempt.failed` by `error.type`
  - `entitlement.token.rejected`
  - `ffi.panic`
  - `agent.process.crash_budget_exceeded`
  - `relay.wake.timed_out`
- Uploaded bundles carrying crash records raise a "new crash signature" alert, grouped by `error.type` plus the top stack frame.

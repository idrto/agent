# IDR File Transfer Protocol v1

**Wire label:** mux service `idr.transfer`, version `1`
**Canonical Rust:** `idr-protocol::transfer` (types), `idr-transfer` (engine)
**Transport:** two mux streams per transfer over the existing DataChannel (`idr-stream-v1`). Never Presence or Relay.

## Streams

The sender opens both streams (Source→Target or Target→Source; with `peer_open_v1` either side can).

| Stream | Opened | Carries |
|---|---|---|
| control | first | `ControlFrame` envelopes, both directions |
| data | after `Accept` | `DataRecord`s, sender → receiver; bulk priority |

Every record is `[u32 BE len][postcard]`. A stream starts with `StreamHeader { magic "IDRT", version, transfer_id, role }`. A receiver delivers a data stream only to an accepted transfer id; otherwise it resets the stream before reading data.

## Control messages

`ControlFrame { msg_type: u16, mandatory: bool, body }`. An unknown **optional** type is skipped; an unknown **mandatory** type fails the transfer (`protocol_violation`).

| Type | Message | Direction | Notes |
|---:|---|---|---|
| 1 | `Offer { digest, manifest_len, entry_count, resume }` | S→R | limits checked before any manifest byte is read |
| 2 | `ManifestChunk { bytes }` | S→R | ≤ 32 KiB each; exactly `manifest_len` total |
| 3 | `Accept { resume: [ResumePoint] }` | R→S | per entry: verified bytes, or complete |
| 4 | `Reject { code }` | R→S | |
| 5 / 6 | `Pause` / `Resume` | both | idempotent |
| 7 | `Cancel { code }` | both | idempotent; the receiver removes partial data and staging |
| 8 | `EntryResult { entry, code? }` | R→S | per file, after verification |
| 9 | `Done { code? }` | R→S | after every `EntryResult`; `None` = completed |

## Manifest

`Manifest { kind: Files | Folder, entries: [ManifestEntry { id, kind: Dir | File, path: [component], size, mtime?, mime? }] }`.

- Ids equal positions; parents come before children; a folder manifest has one root component; empty directories are explicit entries.
- Selection is sender-side: the manifest holds exactly the selected entries plus their parents.
- No hashes. `digest = SHA-256(postcard(manifest))` binds resume state and authorization. The manifest is immutable after `Accept`; resuming with another digest under the same id is `conflicting_manifest`.
- The receiver validates the whole manifest before consent: ids, components (empty, `.`, `..`, `/`, `\`, NUL, control characters, length), depth, path length, duplicates, file-versus-directory conflicts, a single root, sizes and counts.

## Data records

| Record | Rule |
|---|---|
| `Chunk { entry, offset, bytes }` | file entries only; `offset` == bytes received so far (strictly sequential); 1..=48 KiB |
| `EntryEnd { entry, size, sha256 }` | the receiver commits only if `size` matches the manifest and the bytes received, and the SHA-256 matches |
| `EntryAbort { entry, code }` | the sender gave up on one entry (e.g. `changed_during_transfer`) |

An unknown entry, a directory entry, a wrong offset, an oversized or empty chunk, or data for an already-verified entry is a `protocol_violation`: the transfer fails and nothing unverified is committed. Bytes beyond an entry's declared size fail that entry (`size_mismatch`) and cut it off.

## Resume

The receiver checkpoints each file every `checkpoint_bytes` (default 4 MiB) and advertises only checkpointed bytes. On resume, the sender sends the same manifest with `resume = true`. The receiver answers with its resume points: complete entries are skipped, and partial entries continue from their checkpoint. Both sides re-hash the prefix, so the final SHA-256 always covers the whole file.

## Outcomes and error kinds

Outcomes: `Completed`, `CompletedWithErrors { failed }`, `Failed(kind)`, `Cancelled`, `Rejected(kind)`, `Interrupted(kind)` (resumable).

`TransferErrorKind` (stable `u32`, append only): 1 `protocol_violation`, 2 `incompatible_version`, 3 `manifest_invalid`, 4 `limit_exceeded`, 5 `rejected`, 6 `cancelled`, 7 `hash_mismatch`, 8 `size_mismatch`, 9 `changed_during_transfer`, 10 `name_incompatible`, 11 `storage_failed`, 12 `stalled`, 13 `transport_closed`, 14 `authorization_expired`, 15 `conflicting_manifest`, 16 `source_read_failed`, 17 `unauthorized`, 18 `completed_with_errors`, 19 `timeout`.

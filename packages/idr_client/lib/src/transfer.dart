import 'dart:async';

import 'package:idr_core_ffi/idr_core_ffi.dart';

import 'errors.dart';
import 'ffi_isolate.dart';

/// The transfer layer refused a call; [kind] is the stable name (e.g. `unauthorized`).
class IdrTransferException extends IdrException {
  IdrTransferException(int code, String message) : super(idrTransferErrorBase + code, message);

  int get kindCode => code - idrTransferErrorBase;
  String get kind => kindCode < idrTransferErrorNames.length ? idrTransferErrorNames[kindCode] : 'error_$kindCode';

  @override
  String toString() => 'IdrTransferException($kind)';
}

/// How this app receives and keeps transfers. Paths are local directories.
class IdrTransferConfig {
  const IdrTransferConfig({
    required this.dataDir,
    required this.receiveDir,
    this.entityRootPem,
    this.interactive = true,
    this.anyDestination = true,
    this.leaseMinutes = 0,
    this.offerExpirySeconds = 0,
  });

  /// Outbox of agent-owned transfers; reuse it across launches to resume.
  final String dataDir;

  /// Default destination for accepted incoming transfers.
  final String receiveDir;

  /// Entity root PEM; null = the root at the end of this device's chain.
  final String? entityRootPem;

  /// Offers wait for [IdrTransfers.accept] / [IdrTransfers.reject].
  final bool interactive;

  /// [IdrTransfers.accept] may name any directory (the user picked it).
  final bool anyDestination;

  /// 0 = 15 minutes; minimum 5.
  final int leaseMinutes;

  /// 0 = 300 seconds.
  final int offerExpirySeconds;

  Map<String, Object?> toMap() => {
        'dataDir': dataDir,
        'receiveDir': receiveDir,
        'entityRootPem': entityRootPem,
        'interactive': interactive,
        'anyDestination': anyDestination,
        'leaseMinutes': leaseMinutes,
        'offerExpirySeconds': offerExpirySeconds,
      };
}

enum IdrTransferEventKind {
  offered,
  awaitingDecision,
  accepted,
  progress,
  entryFailed,
  renamed,
  leaseExpiring,
  paused,
  resumed,
  finished,
  interrupted,
  resync,
  unknown,
}

enum IdrTransferOutcome { completed, completedWithErrors, failed, cancelled, rejected }

class IdrTransferProgress {
  const IdrTransferProgress({
    required this.bytesDone,
    required this.bytesTotal,
    required this.filesDone,
    required this.filesTotal,
    required this.filesFailed,
    required this.bytesPerSec,
  });

  factory IdrTransferProgress.fromJson(Map<String, dynamic> j) => IdrTransferProgress(
        bytesDone: (j['bytes_done'] as num?)?.toInt() ?? 0,
        bytesTotal: (j['bytes_total'] as num?)?.toInt() ?? 0,
        filesDone: (j['files_done'] as num?)?.toInt() ?? 0,
        filesTotal: (j['files_total'] as num?)?.toInt() ?? 0,
        filesFailed: (j['files_failed'] as num?)?.toInt() ?? 0,
        bytesPerSec: (j['bytes_per_sec'] as num?)?.toInt() ?? 0,
      );

  final int bytesDone;
  final int bytesTotal;
  final int filesDone;
  final int filesTotal;
  final int filesFailed;
  final int bytesPerSec;

  double get fraction => bytesTotal == 0 ? 0 : bytesDone / bytesTotal;
}

/// One drained event (progress already coalesced in Rust).
class IdrTransferEvent {
  IdrTransferEvent.fromMap(Map<dynamic, dynamic> m)
      : kind = _kind(m['kind'] as int),
        code = m['code'] as int,
        transferId = m['id'] as String,
        entry = m['entry'] as int,
        progress = IdrTransferProgress(
          bytesDone: m['bytesDone'] as int,
          bytesTotal: m['bytesTotal'] as int,
          filesDone: m['filesDone'] as int,
          filesTotal: m['filesTotal'] as int,
          filesFailed: m['filesFailed'] as int,
          bytesPerSec: m['bytesPerSec'] as int,
        );

  final IdrTransferEventKind kind;
  final int code;
  final String transferId;
  final int entry;
  final IdrTransferProgress progress;

  /// For [IdrTransferEventKind.finished].
  IdrTransferOutcome? get outcome => kind == IdrTransferEventKind.finished && code < IdrTransferOutcome.values.length
      ? IdrTransferOutcome.values[code]
      : null;

  /// Stable error name: the failure of a finished, interrupted or entry-failed event.
  String? get error {
    final k = switch (kind) {
      IdrTransferEventKind.finished => entry,
      IdrTransferEventKind.interrupted || IdrTransferEventKind.entryFailed => code,
      _ => 0,
    };
    return k > 0 && k < idrTransferErrorNames.length ? idrTransferErrorNames[k] : null;
  }

  static IdrTransferEventKind _kind(int k) => switch (k) {
        idrTevOffered => IdrTransferEventKind.offered,
        idrTevAwaitingDecision => IdrTransferEventKind.awaitingDecision,
        idrTevAccepted => IdrTransferEventKind.accepted,
        idrTevProgress => IdrTransferEventKind.progress,
        idrTevEntryFailed => IdrTransferEventKind.entryFailed,
        idrTevRenamed => IdrTransferEventKind.renamed,
        idrTevLeaseExpiring => IdrTransferEventKind.leaseExpiring,
        idrTevPaused => IdrTransferEventKind.paused,
        idrTevResumed => IdrTransferEventKind.resumed,
        idrTevFinished => IdrTransferEventKind.finished,
        idrTevInterrupted => IdrTransferEventKind.interrupted,
        idrTevResync => IdrTransferEventKind.resync,
        _ => IdrTransferEventKind.unknown,
      };
}

class IdrOfferSummary {
  IdrOfferSummary.fromJson(Map<String, dynamic> j)
      : files = (j['files'] as num).toInt(),
        dirs = (j['dirs'] as num).toInt(),
        totalBytes = (j['total_bytes'] as num).toInt(),
        topLevel = (j['top_level'] as List).cast<String>(),
        moreTopLevel = (j['more_top_level'] as num).toInt();

  final int files;
  final int dirs;
  final int totalBytes;
  final List<String> topLevel;
  final int moreTopLevel;

  /// A single-file offer needs no folder or tree UI.
  bool get isSingleFile => files == 1 && dirs == 0;
}

class IdrTransferInfo {
  IdrTransferInfo.fromJson(Map<String, dynamic> j)
      : id = j['id'] as String,
        incoming = j['direction'] == 'incoming',
        peer = j['peer'] as String,
        state = j['state'] as String,
        path = j['path'] as String?,
        connection = j['connection'] as String? ?? 'unknown',
        summary = j['summary'] == null ? null : IdrOfferSummary.fromJson(Map<String, dynamic>.from(j['summary'] as Map)),
        progress = IdrTransferProgress.fromJson(Map<String, dynamic>.from(j['progress'] as Map));

  final String id;
  final bool incoming;

  /// The verified peer: the Target FQHN its certificate names.
  final String peer;

  /// `queued`, `running`, `paused`, `pending`, `waiting:<error>`, `completed`, or an error name.
  final String state;

  /// `host` / `stun` (direct) or `turn` (relayed); null when unknown.
  final String? path;

  /// `direct`, `relayed` or `unknown`: unknown is never reported as direct.
  final String connection;
  final IdrOfferSummary? summary;
  final IdrTransferProgress progress;

  bool get isPending => state == 'pending';
  bool get isRelayed => connection == 'relayed';
  bool get isDirect => connection == 'direct';
}

class IdrTransferEntry {
  IdrTransferEntry.fromJson(Map<String, dynamic> j)
      : entry = (j['entry'] as num).toInt(),
        path = j['path'] as String,
        isDir = j['kind'] == 'dir',
        size = (j['size'] as num).toInt(),
        failed = j['failed'] as String?,
        storedAs = j['stored_as'] as String?;

  final int entry;

  /// Relative, `/`-separated.
  final String path;
  final bool isDir;
  final int size;
  final String? failed;
  final String? storedAs;
}

class IdrEntryPage {
  IdrEntryPage.fromJson(Map<String, dynamic> j)
      : total = (j['total'] as num).toInt(),
        first = (j['first'] as num).toInt(),
        entries = (j['entries'] as List)
            .map((e) => IdrTransferEntry.fromJson(Map<String, dynamic>.from(e as Map)))
            .toList();

  final int total;
  final int first;
  final List<IdrTransferEntry> entries;
}

/// File transfer through the embedded engine. All file I/O and event draining
/// run on the FFI isolate; this side only sees results and coalesced events.
class IdrTransfers {
  IdrTransfers(this._ffi);

  final IdrFfiIsolate _ffi;

  /// Requires `IdrRuntime.setDpIdentity` (an enrolled device).
  Future<void> enable(IdrTransferConfig config) => _ffi.transfer('transferEnable', config.toMap());

  Future<String> sendFiles(String target, List<String> paths) async =>
      await _ffi.transfer('transferSend', {'target': target, 'paths': paths}) as String;

  Future<String> sendFolder(String target, String dir) => sendFiles(target, [dir]);

  /// [selected]: `/`-separated paths relative to [folder].
  Future<String> sendSelection(String target, String folder, List<String> selected) async =>
      await _ffi.transfer('transferSendSelection', {'target': target, 'folder': folder, 'selected': selected}) as String;

  /// [outDir]: where to store it (null = the configured receive directory).
  Future<void> accept(String id, {String? outDir}) => _cmd('accept', id, outDir: outDir);
  Future<void> reject(String id) => _cmd('reject', id);
  Future<void> pause(String id) => _cmd('pause', id);
  Future<void> resume(String id) => _cmd('resume', id);
  Future<void> cancel(String id) => _cmd('cancel', id);
  Future<void> retryFailed(String id) => _cmd('retryFailed', id);

  Future<List<IdrTransferInfo>> list() async {
    final v = await _ffi.transfer('transferList', const {}) as List;
    return v.map((e) => IdrTransferInfo.fromJson(Map<String, dynamic>.from(e as Map))).toList();
  }

  Future<IdrTransferInfo> status(String id) async =>
      IdrTransferInfo.fromJson(Map<String, dynamic>.from(await _ffi.transfer('transferStatus', {'tid': id}) as Map));

  /// At most 256 entries per call.
  Future<IdrEntryPage> entries(String id, {int first = 0, int max = 256}) async => IdrEntryPage.fromJson(
      Map<String, dynamic>.from(await _ffi.transfer('transferEntries', {'tid': id, 'first': first, 'max': max}) as Map));

  /// Every event, as drained from the engine.
  Stream<IdrTransferEvent> get events => _ffi.transferEvents.map(IdrTransferEvent.fromMap);

  /// Incoming offers waiting for accept/reject (with sender, summary).
  Stream<IdrTransferInfo> get incomingOffers =>
      events.where((e) => e.kind == IdrTransferEventKind.awaitingDecision).asyncMap((e) => status(e.transferId));

  /// Progress of one transfer until it finishes.
  Stream<IdrTransferProgress> progress(String id) => events
      .where((e) => e.transferId == id)
      .takeWhile((e) => e.kind != IdrTransferEventKind.finished)
      .where((e) => e.kind == IdrTransferEventKind.progress)
      .map((e) => e.progress);

  Future<void> _cmd(String cmd, String id, {String? outDir}) =>
      _ffi.transfer('transferCmd', {'cmd': cmd, 'tid': id, 'outDir': outDir});
}

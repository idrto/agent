import 'dart:ffi';
import 'dart:io';

import 'package:idr_client/idr_client.dart';
import 'package:idr_core_ffi/idr_core_ffi.dart';
import 'package:test/test.dart';

/// `agents_engine/agent/crates/idr-c-api/include/idr.h` from this package.
String _header() => File('${Directory.current.path}/../../crates/idr-c-api/include/idr.h').readAsStringSync();

int _hval(String h, String name) {
  final line = h.split('\n').firstWhere(
      (l) => RegExp('^\\s*(#define\\s+)?$name\\b').hasMatch(l),
      orElse: () => throw StateError('$name missing from idr.h'));
  final code = line.split('/*').first;
  return int.parse(RegExp(r'(\d+)\s*,?\s*$').firstMatch(code.trim())!.group(1)!);
}

void main() {
  group('ABI parity with idr.h', () {
    final h = _header();

    test('struct layouts', () {
      expect(sizeOf<IdrTransferEventNative>(), 64);
      expect(sizeOf<IdrTransferConfigNative>(), 48);
    });

    test('constants', () {
      expect(_hval(h, 'IDR_ABI_VERSION'), idrAbiVersion);
      expect(_hval(h, 'IDR_TRANSFER_ERROR_BASE'), idrTransferErrorBase);
      final kinds = {
        'IDR_TEV_OFFERED': idrTevOffered,
        'IDR_TEV_AWAITING_DECISION': idrTevAwaitingDecision,
        'IDR_TEV_ACCEPTED': idrTevAccepted,
        'IDR_TEV_PROGRESS': idrTevProgress,
        'IDR_TEV_ENTRY_FAILED': idrTevEntryFailed,
        'IDR_TEV_RENAMED': idrTevRenamed,
        'IDR_TEV_LEASE_EXPIRING': idrTevLeaseExpiring,
        'IDR_TEV_PAUSED': idrTevPaused,
        'IDR_TEV_RESUMED': idrTevResumed,
        'IDR_TEV_FINISHED': idrTevFinished,
        'IDR_TEV_INTERRUPTED': idrTevInterrupted,
        'IDR_TEV_RESYNC': idrTevResync,
        'IDR_OUTCOME_COMPLETED': idrOutcomeCompleted,
        'IDR_OUTCOME_COMPLETED_WITH_ERRORS': idrOutcomeCompletedWithErrors,
        'IDR_OUTCOME_FAILED': idrOutcomeFailed,
        'IDR_OUTCOME_CANCELLED': idrOutcomeCancelled,
        'IDR_OUTCOME_REJECTED': idrOutcomeRejected,
      };
      kinds.forEach((n, v) => expect(_hval(h, n), v, reason: n));
      for (var k = 1; k < idrTransferErrorNames.length; k++) {
        expect(_hval(h, 'IDR_TERR_${idrTransferErrorNames[k].toUpperCase()}'), k,
            reason: idrTransferErrorNames[k]);
      }
      expect(h.contains('IDR_TERR_') && !h.contains('= ${idrTransferErrorNames.length},'), isTrue,
          reason: 'idr.h has a transfer error kind Dart does not know');
    });
  });

  group('models', () {
    test('transfer info from the engine JSON', () {
      final i = IdrTransferInfo.fromJson({
        'id': '00112233445566778899aabbccddeeff',
        'direction': 'incoming',
        'peer': 'tgt.idr.to',
        'state': 'pending',
        'path': 'turn',
        'connection': 'relayed',
        'summary': {'files': 1, 'dirs': 0, 'total_bytes': 5, 'top_level': ['a.txt'], 'more_top_level': 0},
        'progress': {'bytes_done': 0, 'bytes_total': 5, 'files_done': 0, 'files_total': 1, 'files_failed': 0, 'bytes_per_sec': 0},
      });
      expect(i.incoming, isTrue);
      expect(i.isPending, isTrue);
      expect(i.isRelayed, isTrue);
      expect(i.summary!.isSingleFile, isTrue, reason: 'single file: no folder UI');
    });

    test('events map outcome and error names', () {
      Map<String, Object> ev(int kind, int code, int entry) => {
            'kind': kind, 'code': code, 'id': 'ff' * 16, 'entry': entry, 'filesDone': 0,
            'filesTotal': 0, 'filesFailed': 2, 'bytesDone': 0, 'bytesTotal': 0, 'bytesPerSec': 0,
          };
      final done = IdrTransferEvent.fromMap(ev(idrTevFinished, idrOutcomeCompletedWithErrors, 18));
      expect(done.kind, IdrTransferEventKind.finished);
      expect(done.outcome, IdrTransferOutcome.completedWithErrors);
      expect(done.error, 'completed_with_errors');
      final cut = IdrTransferEvent.fromMap(ev(idrTevInterrupted, 14, 0));
      expect((cut.outcome, cut.error), (null, 'authorization_expired'));
      expect(IdrTransferEvent.fromMap(ev(99, 0, 0)).kind, IdrTransferEventKind.unknown);
    });

    test('entry pages', () {
      final p = IdrEntryPage.fromJson({
        'total': 2,
        'first': 0,
        'entries': [
          {'entry': 0, 'path': 'Project', 'kind': 'dir', 'size': 0, 'failed': null, 'stored_as': null},
          {'entry': 1, 'path': 'Project/a.txt', 'kind': 'file', 'size': 3, 'failed': 'hash_mismatch', 'stored_as': 'Project/a (2).txt'},
        ],
      });
      expect(p.entries[0].isDir, isTrue);
      expect(p.entries[1].failed, 'hash_mismatch');
      expect(p.entries[1].storedAs, 'Project/a (2).txt');
    });

    test('transfer exception names', () {
      final e = IdrTransferException(17, 'unauthorized');
      expect((e.kind, e.code), ('unauthorized', 117));
    });
  });

  group('live engine (mock backend)', () {
    late IdrRuntime rt;
    setUp(() async => rt = await IdrRuntime.create(authToken: 't', useMock: true));
    tearDown(() => rt.dispose());

    test('calls before enable fail with not_initialized, off the UI isolate', () async {
      expect(() => rt.transfers.list(),
          throwsA(isA<IdrException>().having((e) => e.code, 'code', IdrErrorCode.notInitialized)));
    });

    test('enable without a DP identity is refused', () async {
      final dir = await Directory.systemTemp.createTemp('idr-ft');
      addTearDown(() => dir.delete(recursive: true));
      expect(
          () => rt.transfers.enable(IdrTransferConfig(dataDir: dir.path, receiveDir: '${dir.path}/in')),
          throwsA(isA<IdrException>().having((e) => e.code, 'code', IdrErrorCode.notInitialized)));
    });

    test('malformed ids are rejected in Dart before reaching native code', () async {
      expect(() => rt.transfers.pause('nope'),
          throwsA(isA<IdrException>().having((e) => e.code, 'code', IdrErrorCode.invalidArgument)));
    });
  });
}

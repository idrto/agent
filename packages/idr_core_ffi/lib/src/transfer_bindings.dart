import 'dart:ffi';

import 'package:ffi/ffi.dart';

/// `idr_transfer_config_t` (ABI 3).
final class IdrTransferConfigNative extends Struct {
  @Uint32()
  external int abiVersion;

  @Uint32()
  external int structSize;

  external Pointer<Utf8> dataDir;

  external Pointer<Utf8> receiveDir;

  external Pointer<Utf8> entityRootPem;

  @Uint32()
  external int interactive;

  @Uint32()
  external int anyDestination;

  @Uint32()
  external int leaseMinutes;

  @Uint32()
  external int offerExpirySeconds;
}

/// `idr_transfer_event_t` (64 bytes).
final class IdrTransferEventNative extends Struct {
  @Uint32()
  external int kind;

  @Uint32()
  external int code;

  @Array(16)
  external Array<Uint8> transferId;

  @Uint32()
  external int entry;

  @Uint32()
  external int filesDone;

  @Uint32()
  external int filesTotal;

  @Uint32()
  external int filesFailed;

  @Uint64()
  external int bytesDone;

  @Uint64()
  external int bytesTotal;

  @Uint64()
  external int bytesPerSec;
}

typedef TransferEnableC = Int32 Function(Pointer<Void>, Pointer<IdrTransferConfigNative>);
typedef TransferEnableDart = int Function(Pointer<Void>, Pointer<IdrTransferConfigNative>);

typedef TransferSendC = Int32 Function(
    Pointer<Void>, Pointer<Utf8>, Pointer<Pointer<Utf8>>, IntPtr, Pointer<Uint8>);
typedef TransferSendDart = int Function(
    Pointer<Void>, Pointer<Utf8>, Pointer<Pointer<Utf8>>, int, Pointer<Uint8>);

typedef TransferSendSelectionC = Int32 Function(Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>,
    Pointer<Pointer<Utf8>>, IntPtr, Pointer<Uint8>);
typedef TransferSendSelectionDart = int Function(
    Pointer<Void>, Pointer<Utf8>, Pointer<Utf8>, Pointer<Pointer<Utf8>>, int, Pointer<Uint8>);

typedef TransferAcceptC = Int32 Function(Pointer<Void>, Pointer<Uint8>, Pointer<Utf8>);
typedef TransferAcceptDart = int Function(Pointer<Void>, Pointer<Uint8>, Pointer<Utf8>);

typedef TransferCmdC = Int32 Function(Pointer<Void>, Pointer<Uint8>);
typedef TransferCmdDart = int Function(Pointer<Void>, Pointer<Uint8>);

typedef TransferListC = Int32 Function(Pointer<Void>, Pointer<Utf8>, IntPtr);
typedef TransferListDart = int Function(Pointer<Void>, Pointer<Utf8>, int);

typedef TransferStatusC = Int32 Function(Pointer<Void>, Pointer<Uint8>, Pointer<Utf8>, IntPtr);
typedef TransferStatusDart = int Function(Pointer<Void>, Pointer<Uint8>, Pointer<Utf8>, int);

typedef TransferEntriesC = Int32 Function(
    Pointer<Void>, Pointer<Uint8>, Uint32, Uint32, Pointer<Utf8>, IntPtr);
typedef TransferEntriesDart = int Function(
    Pointer<Void>, Pointer<Uint8>, int, int, Pointer<Utf8>, int);

typedef TransferPollC = Int32 Function(
    Pointer<Void>, Pointer<IdrTransferEventNative>, IntPtr, Pointer<IntPtr>);
typedef TransferPollDart = int Function(
    Pointer<Void>, Pointer<IdrTransferEventNative>, int, Pointer<IntPtr>);

/// `idr_transfer_*` symbols.
class IdrTransferBindings {
  IdrTransferBindings(DynamicLibrary lib)
      : enable = lib.lookupFunction<TransferEnableC, TransferEnableDart>('idr_transfer_enable'),
        send = lib.lookupFunction<TransferSendC, TransferSendDart>('idr_transfer_send'),
        sendSelection = lib.lookupFunction<TransferSendSelectionC, TransferSendSelectionDart>(
            'idr_transfer_send_selection'),
        accept = lib.lookupFunction<TransferAcceptC, TransferAcceptDart>('idr_transfer_accept'),
        reject = lib.lookupFunction<TransferCmdC, TransferCmdDart>('idr_transfer_reject'),
        pause = lib.lookupFunction<TransferCmdC, TransferCmdDart>('idr_transfer_pause'),
        resume = lib.lookupFunction<TransferCmdC, TransferCmdDart>('idr_transfer_resume'),
        cancel = lib.lookupFunction<TransferCmdC, TransferCmdDart>('idr_transfer_cancel'),
        retryFailed =
            lib.lookupFunction<TransferCmdC, TransferCmdDart>('idr_transfer_retry_failed'),
        list = lib.lookupFunction<TransferListC, TransferListDart>('idr_transfer_list'),
        status = lib.lookupFunction<TransferStatusC, TransferStatusDart>('idr_transfer_status'),
        entries =
            lib.lookupFunction<TransferEntriesC, TransferEntriesDart>('idr_transfer_entries'),
        pollEvents =
            lib.lookupFunction<TransferPollC, TransferPollDart>('idr_transfer_poll_events');

  final TransferEnableDart enable;
  final TransferSendDart send;
  final TransferSendSelectionDart sendSelection;
  final TransferAcceptDart accept;
  final TransferCmdDart reject;
  final TransferCmdDart pause;
  final TransferCmdDart resume;
  final TransferCmdDart cancel;
  final TransferCmdDart retryFailed;
  final TransferListDart list;
  final TransferStatusDart status;
  final TransferEntriesDart entries;
  final TransferPollDart pollEvents;
}

/// Optional helper: open the Target `http` named service and exchange raw bytes.
///
/// This is intentionally not a drop-in `HttpClient`. Apps that need full HTTP
/// semantics should speak HTTP/1.1 on the stream themselves, or use a dedicated
/// HTTP stack on top of [IdrStream].
library idr_http;

import 'dart:convert';
import 'dart:typed_data';

import 'package:idr_client/idr_client.dart';

class IdrHttpTunnel {
  IdrHttpTunnel(this.session);

  final IdrSession session;

  /// Opens the Target `http` service (nginx bridge / passthrough).
  Future<IdrStream> open() => session.openStream('http');

  /// Convenience: write a UTF-8 string and read one response chunk.
  Future<String> exchangeUtf8(String request, {int maxLen = 65536}) async {
    final stream = await open();
    await stream.write(Uint8List.fromList(utf8.encode(request)));
    final resp = await stream.read(maxLen: maxLen);
    await stream.halfClose();
    return utf8.decode(resp);
  }
}

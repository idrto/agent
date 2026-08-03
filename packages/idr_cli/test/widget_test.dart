import 'package:flutter_test/flutter_test.dart';
import 'package:idr_cli/agent_host.dart';
import 'package:idr_cli/main.dart';
import 'package:idr_secure_storage/idr_secure_storage.dart';

void main() {
  testWidgets('Target host shows brand and Doctor', (tester) async {
    final store = DpSecretStore(store: MemoryKvStore());
    final host = AgentHost(store: store);

    await tester.pumpWidget(TargetAgentApp(host: host));
    await tester.pumpAndSettle();

    expect(find.text('IDR'), findsOneWidget);
    expect(find.text('Target Agent'), findsOneWidget);
    expect(find.text('Doctor'), findsOneWidget);
    expect(find.text('Start target-agent'), findsOneWidget);
  });
}

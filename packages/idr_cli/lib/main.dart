import 'dart:async';

import 'package:flutter/material.dart';
import 'package:idr_secure_storage/idr_secure_storage.dart';

import 'agent_host.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  final store = DpSecretStore(
    store: FlutterSecureKvStore(),
    prefix: 'idr.dp',
  );
  final host = AgentHost(store: store);

  runApp(TargetAgentApp(host: host));
}

class TargetAgentApp extends StatelessWidget {
  const TargetAgentApp({super.key, required this.host});

  final AgentHost host;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'IDR Target Agent',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF0F6E56),
          brightness: Brightness.light,
        ),
        useMaterial3: true,
      ),
      home: TargetHostPage(host: host),
    );
  }
}

class TargetHostPage extends StatefulWidget {
  const TargetHostPage({super.key, required this.host});

  final AgentHost host;

  @override
  State<TargetHostPage> createState() => _TargetHostPageState();
}

class _TargetHostPageState extends State<TargetHostPage> {
  late final TextEditingController _binaryCtrl;
  late final TextEditingController _configCtrl;
  late final TextEditingController _identityCtrl;
  late final TextEditingController _hostCtrl;
  late final TextEditingController _entityCtrl;
  final _logCtrl = TextEditingController();
  final _logScroll = ScrollController();

  DpIdentityBundle? _bundle;
  bool _busy = false;
  bool _running = false;
  String? _detectedBinary;

  StreamSubscription<String>? _logSub;
  bool _disposed = false;

  AgentHost get host => widget.host;

  @override
  void initState() {
    super.initState();
    _binaryCtrl = TextEditingController(text: host.agentBinary);
    _configCtrl = TextEditingController(text: host.configPath);
    _identityCtrl = TextEditingController(text: host.identityPath);
    _hostCtrl = TextEditingController(text: 'db1.us-east--acme');
    _entityCtrl = TextEditingController();
    _logSub = host.logs.listen(_appendLog);
    _bootstrap();
  }

  Future<void> _bootstrap() async {
    final detected = await host.detectBinary();
    final bundle = await host.store.loadIdentity();
    if (!mounted || _disposed) return;
    setState(() {
      _detectedBinary = detected;
      if (detected != null) {
        _binaryCtrl.text = detected;
      }
      _bundle = bundle;
    });
    if (detected == null) {
      _appendLog(
        'target-agent not found yet. Build from the agent repo root:\n'
        '  cargo build -p target-agent\n'
        'Then tap Detect, or set IDR_AGENT_BINARY.',
      );
    } else {
      _appendLog('using agent binary: $detected');
    }
  }

  void _syncPaths() {
    host.agentBinary = _binaryCtrl.text.trim();
    host.configPath = _configCtrl.text.trim();
    host.identityPath = _identityCtrl.text.trim();
  }

  void _appendLog(String line) {
    if (!mounted || _disposed) return;
    final next = _logCtrl.text.isEmpty ? line : '${_logCtrl.text}\n$line';
    _logCtrl.value = TextEditingValue(
      text: next,
      selection: TextSelection.collapsed(offset: next.length),
    );
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (!mounted || _disposed || !_logScroll.hasClients) return;
      _logScroll.jumpTo(_logScroll.position.maxScrollExtent);
    });
    setState(() => _running = host.isRunning);
  }

  Future<void> _withBusy(Future<void> Function() fn) async {
    if (_busy || _disposed) return;
    setState(() => _busy = true);
    try {
      _syncPaths();
      await fn();
      if (!mounted || _disposed) return;
      final bundle = await host.store.loadIdentity();
      if (mounted && !_disposed) setState(() => _bundle = bundle);
    } finally {
      if (mounted && !_disposed) setState(() => _busy = false);
    }
  }

  @override
  void dispose() {
    _disposed = true;
    _logSub?.cancel();
    _binaryCtrl.dispose();
    _configCtrl.dispose();
    _identityCtrl.dispose();
    _hostCtrl.dispose();
    _entityCtrl.dispose();
    _logCtrl.dispose();
    _logScroll.dispose();
    // Do not dispose [host] here — tests / callers may own the AgentHost.
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Scaffold(
      body: Row(
        children: [
          SizedBox(
            width: 420,
            child: Material(
              color: theme.colorScheme.surfaceContainerLow,
              child: SingleChildScrollView(
                padding: const EdgeInsets.fromLTRB(24, 28, 24, 24),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Text(
                      'IDR',
                      style: theme.textTheme.displaySmall?.copyWith(
                        fontWeight: FontWeight.w700,
                        letterSpacing: -1,
                      ),
                    ),
                    Text(
                      'Target Agent',
                      style: theme.textTheme.titleLarge?.copyWith(
                        color: theme.colorScheme.primary,
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Desktop host for the native target-agent CLI: identity, doctor, and Presence/Relay run.',
                      style: theme.textTheme.bodyMedium?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                    const SizedBox(height: 24),
                    _statusChip(theme),
                    const SizedBox(height: 20),
                    _pathField(
                      label: 'target-agent binary',
                      controller: _binaryCtrl,
                      trailing: TextButton(
                        onPressed: _busy
                            ? null
                            : () => _withBusy(() async {
                                  final d = await host.detectBinary();
                                  setState(() {
                                    _detectedBinary = d;
                                    if (d != null) _binaryCtrl.text = d;
                                  });
                                  _appendLog(
                                    d == null
                                        ? 'detect: not found'
                                        : 'detect: $d',
                                  );
                                }),
                        child: const Text('Detect'),
                      ),
                    ),
                    _pathField(
                      label: 'config TOML',
                      controller: _configCtrl,
                    ),
                    _pathField(
                      label: 'identity JSON',
                      controller: _identityCtrl,
                    ),
                    const SizedBox(height: 12),
                    Text('Identity CLI', style: theme.textTheme.titleSmall),
                    const SizedBox(height: 8),
                    TextField(
                      controller: _hostCtrl,
                      decoration: const InputDecoration(
                        labelText: 'host (FQHN / machine host)',
                        border: OutlineInputBorder(),
                        isDense: true,
                      ),
                    ),
                    const SizedBox(height: 8),
                    TextField(
                      controller: _entityCtrl,
                      decoration: const InputDecoration(
                        labelText: 'entity (optional)',
                        border: OutlineInputBorder(),
                        isDense: true,
                      ),
                    ),
                    const SizedBox(height: 16),
                    Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      children: [
                        FilledButton(
                          onPressed: _busy
                              ? null
                              : () => _withBusy(() async {
                                    await host.ensureConfigExists();
                                    await host.doctor();
                                  }),
                          child: const Text('Doctor'),
                        ),
                        OutlinedButton(
                          onPressed: _busy
                              ? null
                              : () => _withBusy(host.version),
                          child: const Text('Version'),
                        ),
                        OutlinedButton(
                          onPressed: _busy
                              ? null
                              : () => _withBusy(() async {
                                    final h = _hostCtrl.text.trim();
                                    if (h.isEmpty) {
                                      _appendLog(
                                          'host is required for identity init');
                                      return;
                                    }
                                    await host.identityInit(
                                      host: h,
                                      entity: _entityCtrl.text.trim().isEmpty
                                          ? null
                                          : _entityCtrl.text.trim(),
                                    );
                                  }),
                          child: const Text('Identity init'),
                        ),
                        OutlinedButton(
                          onPressed: _busy
                              ? null
                              : () => _withBusy(host.importIdentityFromFile),
                          child: const Text('Import → secure storage'),
                        ),
                        OutlinedButton(
                          onPressed: _busy
                              ? null
                              : () => _withBusy(host.exportIdentityToFile),
                          child: const Text('Export ← secure storage'),
                        ),
                        OutlinedButton(
                          onPressed: _busy
                              ? null
                              : () => _withBusy(() async {
                                    await host.store.clearIdentity();
                                    _appendLog('secure storage cleared');
                                  }),
                          child: const Text('Clear storage'),
                        ),
                      ],
                    ),
                    const SizedBox(height: 20),
                    Text('Service', style: theme.textTheme.titleSmall),
                    const SizedBox(height: 8),
                    Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      children: [
                        FilledButton.tonal(
                          onPressed: _busy || _running
                              ? null
                              : () => _withBusy(host.startTargetService),
                          child: const Text('Start target-agent'),
                        ),
                        OutlinedButton(
                          onPressed: !_running
                              ? null
                              : () => _withBusy(host.stopTargetService),
                          child: const Text('Stop'),
                        ),
                      ],
                    ),
                    if (_detectedBinary == null) ...[
                      const SizedBox(height: 16),
                      Text(
                        'Native CLI binary missing — Flutter UI runs, but Target CLI actions need a built target-agent.exe.',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.error,
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),
          ),
          Expanded(
            child: Padding(
              padding: const EdgeInsets.all(20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Text('CLI output', style: theme.textTheme.titleMedium),
                  const SizedBox(height: 8),
                  Expanded(
                    child: DecoratedBox(
                      decoration: BoxDecoration(
                        color: const Color(0xFF111827),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: TextField(
                        controller: _logCtrl,
                        scrollController: _logScroll,
                        readOnly: true,
                        maxLines: null,
                        expands: true,
                        style: const TextStyle(
                          fontFamily: 'Consolas',
                          fontSize: 12.5,
                          color: Color(0xFFE5E7EB),
                          height: 1.4,
                        ),
                        decoration: const InputDecoration(
                          border: InputBorder.none,
                          contentPadding: EdgeInsets.all(16),
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _statusChip(ThemeData theme) {
    final ski = _bundle?.ski;
    final running = _running;
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        border: Border.all(color: theme.colorScheme.outlineVariant),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            running ? 'Service: running' : 'Service: stopped',
            style: theme.textTheme.labelLarge?.copyWith(
              color: running
                  ? theme.colorScheme.primary
                  : theme.colorScheme.onSurfaceVariant,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            ski == null
                ? 'Secure storage: (no identity)'
                : 'Secure storage SKI: $ski',
            style: theme.textTheme.bodySmall,
          ),
          if (_bundle?.fqhn != null)
            Text('FQHN: ${_bundle!.fqhn}', style: theme.textTheme.bodySmall),
        ],
      ),
    );
  }

  Widget _pathField({
    required String label,
    required TextEditingController controller,
    Widget? trailing,
  }) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(
            child: TextField(
              controller: controller,
              decoration: InputDecoration(
                labelText: label,
                border: const OutlineInputBorder(),
                isDense: true,
              ),
            ),
          ),
          if (trailing != null) ...[
            const SizedBox(width: 4),
            trailing,
          ],
        ],
      ),
    );
  }
}

/// Structured Target service catalog entry (from ServicesCatalogDetailed).
class NamedServiceInfo {
  const NamedServiceInfo({
    required this.name,
    this.kind = 'tcp',
    this.credentialMode = 'source',
    this.requireUpstreamTls = false,
  });

  final String name;
  /// `http` | `tcp`
  final String kind;
  /// `source` | `target`
  final String credentialMode;
  final bool requireUpstreamTls;

  bool get sourceProvidesCredentials => credentialMode == 'source';

  factory NamedServiceInfo.fromJson(Map<String, dynamic> json) {
    return NamedServiceInfo(
      name: (json['name'] as String?) ?? '',
      kind: (json['kind'] as String?) ?? 'tcp',
      credentialMode: (json['credential_mode'] as String?) ?? 'source',
      requireUpstreamTls: json['require_upstream_tls'] as bool? ?? false,
    );
  }

  Map<String, dynamic> toJson() => {
        'name': name,
        'kind': kind,
        'credential_mode': credentialMode,
        'require_upstream_tls': requireUpstreamTls,
      };
}

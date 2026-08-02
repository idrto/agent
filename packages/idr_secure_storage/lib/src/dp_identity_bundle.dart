/// In-memory bundle loaded from [DpSecretStore] — feed into agent FFI; do not log.
class DpIdentityBundle {
  const DpIdentityBundle({
    required this.ski,
    required this.privateJwk,
    required this.credential,
    this.publicJwk,
    this.fqhn,
  });

  final String ski;
  final Map<String, dynamic> privateJwk;
  final Map<String, dynamic> credential;
  final Map<String, dynamic>? publicJwk;
  final String? fqhn;

  /// JSON accepted by native `idr_engine_set_dp_identity`.
  Map<String, dynamic> toNativeJson() => {
        'ski': ski,
        'private_jwk': privateJwk,
        'credential': credential,
        if (publicJwk != null) 'public_jwk': publicJwk,
        if (fqhn != null) 'fqhn': fqhn,
      };
}

/// Ed25519 key material as produced by `idr_dp_generate_ed25519`.
class Ed25519KeyMaterial {
  const Ed25519KeyMaterial({
    required this.privatePem,
    required this.publicPem,
    required this.publicB64url,
    required this.publicJwk,
    this.ski = '',
  });

  /// Accepts the Rust snake_case shape; `ski` is optional for stored copies.
  factory Ed25519KeyMaterial.fromJson(Map<String, dynamic> j) {
    return Ed25519KeyMaterial(
      privatePem: j['private_pem'] as String,
      publicPem: j['public_pem'] as String? ?? '',
      publicB64url: j['public_b64url'] as String,
      publicJwk: Map<String, dynamic>.from(j['public_jwk'] as Map? ?? const {}),
      ski: j['ski'] as String? ?? '',
    );
  }

  final String privatePem;
  final String publicPem;
  final String publicB64url;
  final Map<String, dynamic> publicJwk;
  final String ski;

  Map<String, dynamic> toJson() => {
        'private_pem': privatePem,
        'public_pem': publicPem,
        'public_b64url': publicB64url,
        'public_jwk': publicJwk,
        'ski': ski,
      };
}

/// Leaf + chain PEM from `idr_dp_sign_csr`.
typedef SignedLeaf = ({String leafPem, String chainPem});

/// Native crypto failure (`idr_dp_last_error` text + return code).
class IdrDpException implements Exception {
  const IdrDpException(this.code, this.message);

  final int code;
  final String message;

  @override
  String toString() => 'IdrDpException($code): $message';
}

/// Crypto surface used by Source / Target enrollment and PoP.
abstract interface class IdrCrypto {
  Ed25519KeyMaterial generateEd25519();

  String ski(String publicB64url);

  String buildCsr({required String privatePem, required String fqhn});

  /// base64url signature over raw [message] bytes.
  String sign({required String privatePem, required List<int> message});

  /// base64url signature over UTF-8 [json].
  String signJson({required String privatePem, required String json});

  /// Self-signed CA cert PEM from the CA private JWK; [commonName] = CA SKI by convention.
  String caCertPemFromPrivateJwk({
    required Map<String, dynamic> privateJwk,
    required String commonName,
  });

  SignedLeaf signCsr({
    required String csrPem,
    required Map<String, dynamic> caPrivateJwk,
    required String issuerSki,
    String? host,
  });
}

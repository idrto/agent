#pragma once

/* C ABI for idr-dp crypto (desktop Target FFI).
 *
 * Windows: idr_dp.dll
 * macOS:   libidr_dp.dylib
 * Linux:   libidr_dp.so
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void idr_dp_string_free(char *ptr);
const char *idr_dp_last_error(void);

int idr_dp_generate_ed25519(char **out_json);
int idr_dp_build_csr(const char *private_pem, const char *fqhn, char **out_pem);
int idr_dp_sign(const char *private_pem, const unsigned char *msg, size_t msg_len,
                char **out_b64);
int idr_dp_sign_json(const char *private_pem, const char *json, char **out_b64);
int idr_dp_ski(const char *public_b64url, char **out_ski);
/* Self-signed CA cert PEM from CA private JWK JSON + CN (= CA SKI by convention). */
int idr_dp_ca_cert_pem_from_jwk(const char *ca_private_jwk_json, const char *common_name,
                                char **out_pem);
/* host may be NULL. out_json is {"leaf_pem":"...","chain_pem":"..."}. */
int idr_dp_sign_csr(const char *csr_pem, const char *ca_private_jwk_json,
                    const char *issuer_ski, const char *host, char **out_json);

#ifdef __cplusplus
}
#endif

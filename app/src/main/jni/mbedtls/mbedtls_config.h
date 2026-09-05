/*
 * mbedtls_config.h — the smallest mbedTLS that satisfies ngtcp2's crypto
 * backend.
 *
 * QUIC needs exactly four things: the two AEADs a TLS 1.3 cipher suite can
 * name, the two block/stream ciphers header protection is built from, the two
 * hashes those suites use, and HKDF. Nothing here enables X.509, TLS, PSA or
 * any asymmetric primitive — the TLS handshake itself is Kotlin, and this is
 * only the record-protection half.
 */

#ifndef MBEDTLS_CONFIG_H
#define MBEDTLS_CONFIG_H

/* AEADs: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305. */
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_CHACHA20_C
#define MBEDTLS_POLY1305_C
#define MBEDTLS_CHACHAPOLY_C

/*
 * Header protection uses a bare AES-ECB block and a bare ChaCha20 block, which
 * is what the AES and ChaCha20 modules above already expose. No mode module is
 * needed for either.
 */

/* Hashes for the TLS 1.3 suites, and HKDF over them. */
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_MD_C
#define MBEDTLS_HKDF_C

/* Error strings cost a few KB and make a failure legible in a log. */
#define MBEDTLS_ERROR_C

/*
 * No filesystem, no time, no network, no entropy source: the backend is handed
 * every key it uses and asks the platform for randomness through ngtcp2.
 */
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_DEPRECATED_REMOVED

#endif /* MBEDTLS_CONFIG_H */

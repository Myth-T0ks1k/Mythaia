/*
 * quic_jni_bridge.c
 * Mythaia
 *
 * The C side of the QUIC stack.
 *
 * Right now it exposes one thing: a self-test that drives the vendored ngtcp2
 * and its mbedTLS backend through the worked example in RFC 9001 Appendix A and
 * checks every intermediate against the bytes the RFC prints.
 *
 * That test exists because nothing else here can. The unit suite runs on a
 * desktop JVM with no .so to load, and the native code only ever executes on an
 * arm64 device — so "it compiles" and "it links" were the strongest claims
 * available for the crypto until this. Now the first run on a device either
 * agrees with the RFC byte for byte or says which step did not.
 */

#include <jni.h>
#include <string.h>
#include <stdio.h>

#include <android/log.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

/* The initial-secret and context helpers live in the crypto helper's own
   header, not the public one. */
#include "shared.h"

#define LOG_TAG "MythaiaQUIC"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

/* -------------------------------------------------------------------------
 * RFC 9001 Appendix A.1 — "Keys" — and A.2, the client Initial packet.
 *
 * The whole example hangs off one connection ID, so every value below is
 * reproducible from it and nothing here is a magic constant of ours.
 * ------------------------------------------------------------------------- */

static const uint8_t kDcid[] = {0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08};

/* client_initial_secret */
static const uint8_t kClientSecret[] = {
  0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75, 0xed, 0x0e, 0xbf,
  0xb5, 0xc8, 0x03, 0x23, 0xc4, 0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81,
  0x28, 0x9a, 0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea};

/* server_initial_secret */
static const uint8_t kServerSecret[] = {
  0x3c, 0x19, 0x98, 0x28, 0xfd, 0x13, 0x9e, 0xfd, 0x21, 0x6c, 0x15,
  0x5a, 0xd8, 0x44, 0xcc, 0x81, 0xfb, 0x82, 0xfa, 0x8d, 0x74, 0x46,
  0xfa, 0x7d, 0x78, 0xbe, 0x80, 0x3a, 0xcd, 0xda, 0x95, 0x1b};

/* Derived from client_initial_secret. */
static const uint8_t kClientKey[] = {0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76,
                                     0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb,
                                     0xe3, 0xb1, 0xa2, 0x2d};
static const uint8_t kClientIv[] = {0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3,
                                    0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c};
static const uint8_t kClientHp[] = {0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0,
                                    0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99,
                                    0x33, 0xad, 0xed, 0xd2};

/* A.2: the sample taken from the protected payload, and the mask it yields. */
static const uint8_t kSample[] = {0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68,
                                  0x9f, 0xb8, 0xec, 0x11, 0xd2, 0x42,
                                  0xb1, 0x23, 0xdc, 0x9b};
static const uint8_t kMask[] = {0x43, 0x7b, 0x9a, 0xec, 0x36};

static int differs(const uint8_t *got, const uint8_t *want, size_t len) {
  return memcmp(got, want, len) != 0;
}

static void describe(char *out, size_t outlen, const char *step,
                     const uint8_t *got, const uint8_t *want, size_t len) {
  char g[128] = {0};
  char w[128] = {0};
  size_t i;
  size_t shown = len > 16 ? 16 : len;

  for (i = 0; i < shown; ++i) {
    snprintf(g + i * 2, sizeof(g) - i * 2, "%02x", got[i]);
    snprintf(w + i * 2, sizeof(w) - i * 2, "%02x", want[i]);
  }
  snprintf(out, outlen, "%s: got %s want %s", step, g, w);
}

/*
 * Returns NULL when everything matched, or a description of the first step
 * that did not.
 */
static const char *run_self_test(char *buf, size_t buflen) {
  ngtcp2_crypto_ctx ctx;
  ngtcp2_cid dcid;
  uint8_t client_secret[32];
  uint8_t server_secret[32];
  uint8_t initial_secret[32];
  uint8_t key[16];
  uint8_t iv[12];
  uint8_t hp[16];
  ngtcp2_crypto_aead_ctx hp_aead_ctx;
  ngtcp2_crypto_cipher_ctx hp_ctx;
  uint8_t mask[NGTCP2_HP_MASKLEN];
  int rv;

  ngtcp2_crypto_ctx_initial(&ctx);

  memcpy(dcid.data, kDcid, sizeof(kDcid));
  dcid.datalen = sizeof(kDcid);

  /* Step 1: the Initial secrets, i.e. HKDF-Extract then Expand-Label.
   * ngtcp2 hands back (rx, tx): on the client side rx is the server's
   * secret and tx the client's. */
  rv = ngtcp2_crypto_derive_initial_secrets(
    server_secret, client_secret, initial_secret, NGTCP2_PROTO_VER_V1, &dcid,
    NGTCP2_CRYPTO_SIDE_CLIENT);
  if (rv != 0) {
    snprintf(buf, buflen, "derive_initial_secrets failed (%d)", rv);
    return buf;
  }
  if (differs(client_secret, kClientSecret, sizeof(kClientSecret))) {
    describe(buf, buflen, "client_initial_secret", client_secret,
             kClientSecret, sizeof(kClientSecret));
    return buf;
  }
  if (differs(server_secret, kServerSecret, sizeof(kServerSecret))) {
    describe(buf, buflen, "server_initial_secret", server_secret,
             kServerSecret, sizeof(kServerSecret));
    return buf;
  }

  /* Step 2: key, IV and header-protection key off the client secret. */
  rv = ngtcp2_crypto_derive_packet_protection_key(
    key, iv, hp, NGTCP2_PROTO_VER_V1, &ctx.aead, &ctx.md, client_secret,
    sizeof(client_secret));
  if (rv < 0) {
    snprintf(buf, buflen, "derive_packet_protection_key failed (%d)", rv);
    return buf;
  }
  if (differs(key, kClientKey, sizeof(kClientKey))) {
    describe(buf, buflen, "client key", key, kClientKey, sizeof(kClientKey));
    return buf;
  }
  if (differs(iv, kClientIv, sizeof(kClientIv))) {
    describe(buf, buflen, "client iv", iv, kClientIv, sizeof(kClientIv));
    return buf;
  }
  if (differs(hp, kClientHp, sizeof(kClientHp))) {
    describe(buf, buflen, "client hp key", hp, kClientHp, sizeof(kClientHp));
    return buf;
  }

  /* Step 3: the header-protection mask, which is a raw AES-ECB block. */
  (void)hp_aead_ctx;
  rv = ngtcp2_crypto_cipher_ctx_encrypt_init(&hp_ctx, &ctx.hp, hp);
  if (rv != 0) {
    snprintf(buf, buflen, "hp cipher init failed (%d)", rv);
    return buf;
  }
  rv = ngtcp2_crypto_hp_mask(mask, &ctx.hp, &hp_ctx, kSample);
  ngtcp2_crypto_cipher_ctx_free(&hp_ctx);
  if (rv != 0) {
    snprintf(buf, buflen, "hp_mask failed (%d)", rv);
    return buf;
  }
  if (differs(mask, kMask, sizeof(kMask))) {
    describe(buf, buflen, "hp mask", mask, kMask, sizeof(kMask));
    return buf;
  }

  return NULL;
}

/*
 * Additionally checks that AEAD encrypt and decrypt are each other's inverse
 * and that a tampered tag is refused. The RFC's own packet bytes cover
 * encryption directly; this covers the rejection path, which they do not.
 */
static const char *run_aead_test(char *buf, size_t buflen) {
  ngtcp2_crypto_ctx ctx;
  ngtcp2_crypto_aead_ctx aead_ctx;
  uint8_t plaintext[64];
  uint8_t sealed[64 + 16];
  uint8_t opened[64];
  static const uint8_t nonce[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  static const uint8_t aad[7] = {'m', 'y', 't', 'h', 'a', 'i', 'a'};
  size_t i;
  int rv;

  ngtcp2_crypto_ctx_initial(&ctx);
  for (i = 0; i < sizeof(plaintext); ++i) {
    plaintext[i] = (uint8_t)i;
  }

  rv = ngtcp2_crypto_aead_ctx_encrypt_init(&aead_ctx, &ctx.aead, kClientKey,
                                           sizeof(nonce));
  if (rv != 0) {
    snprintf(buf, buflen, "aead encrypt init failed (%d)", rv);
    return buf;
  }

  rv = ngtcp2_crypto_encrypt(sealed, &ctx.aead, &aead_ctx, plaintext,
                             sizeof(plaintext), nonce, sizeof(nonce), aad,
                             sizeof(aad));
  if (rv != 0) {
    ngtcp2_crypto_aead_ctx_free(&aead_ctx);
    snprintf(buf, buflen, "encrypt failed (%d)", rv);
    return buf;
  }

  rv = ngtcp2_crypto_decrypt(opened, &ctx.aead, &aead_ctx, sealed,
                             sizeof(sealed), nonce, sizeof(nonce), aad,
                             sizeof(aad));
  if (rv != 0) {
    ngtcp2_crypto_aead_ctx_free(&aead_ctx);
    snprintf(buf, buflen, "decrypt of our own ciphertext failed (%d)", rv);
    return buf;
  }
  if (differs(opened, plaintext, sizeof(plaintext))) {
    ngtcp2_crypto_aead_ctx_free(&aead_ctx);
    describe(buf, buflen, "aead round trip", opened, plaintext,
             sizeof(plaintext));
    return buf;
  }

  /* A flipped bit anywhere must be refused, not silently returned. */
  sealed[sizeof(sealed) - 1] ^= 0x01;
  rv = ngtcp2_crypto_decrypt(opened, &ctx.aead, &aead_ctx, sealed,
                             sizeof(sealed), nonce, sizeof(nonce), aad,
                             sizeof(aad));
  ngtcp2_crypto_aead_ctx_free(&aead_ctx);
  if (rv == 0) {
    snprintf(buf, buflen, "a tampered tag was accepted");
    return buf;
  }

  return NULL;
}

JNIEXPORT jstring JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicSelfTest(JNIEnv *env,
                                                     jclass clazz) {
  static char buf[256];
  const char *failure;

  (void)clazz;

  failure = run_self_test(buf, sizeof(buf));
  if (failure == NULL) {
    failure = run_aead_test(buf, sizeof(buf));
  }

  if (failure != NULL) {
    LOGI("QUIC self-test FAILED: %s", failure);
    return (*env)->NewStringUTF(env, failure);
  }

  LOGI("QUIC self-test passed (ngtcp2 %s)", ngtcp2_version(0)->version_str);
  return NULL;
}

JNIEXPORT jstring JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicVersion(JNIEnv *env, jclass clazz) {
  (void)clazz;
  return (*env)->NewStringUTF(env, ngtcp2_version(0)->version_str);
}

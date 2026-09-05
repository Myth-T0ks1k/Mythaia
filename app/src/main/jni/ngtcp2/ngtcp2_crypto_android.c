/*
 * ngtcp2_crypto_android.c
 * Mythaia
 *
 * The backend half of ngtcp2's crypto helper, on mbedTLS.
 *
 * Upstream splits that helper in two: `shared.c` is backend-agnostic glue and
 * is vendored stock, while one file per TLS stack supplies the primitives. This
 * is that file. See ngtcp2/UPSTREAM_MAP.md for how the two halves divide, and
 * for the nm command that re-derives what this file owes after an upgrade.
 *
 * What it does NOT do is run the handshake. The four functions at the bottom
 * are deliberately inert: TLS 1.3 lives in Kotlin, and the managed layer drives
 * ngtcp2 by calling ngtcp2_conn_install_*_key and
 * ngtcp2_conn_submit_crypto_data itself. Everything above them is packet
 * protection, which has to be in C — it runs on every packet, and a JNI
 * crossing per packet would cost more than the cipher.
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <ngtcp2/ngtcp2_crypto.h>

#include "ngtcp2_macro.h"
#include "shared.h"

#include <mbedtls/chachapoly.h>
#include <mbedtls/chacha20.h>
#include <mbedtls/aes.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>

/* bionic has had arc4random_buf, seeded from the kernel, since API 21. */
#include <stdlib.h>

/* --------------------------------------------------------------------------
 * Algorithm tags
 *
 * ngtcp2 identifies an algorithm by an opaque `native_handle`. These statics
 * are those handles: their addresses are the identity, and the enum inside
 * says which one it is.
 * -------------------------------------------------------------------------- */

typedef enum {
  MQ_AEAD_AES_128_GCM,
  MQ_AEAD_AES_256_GCM,
  MQ_AEAD_CHACHA20_POLY1305,
} mq_aead_type;

typedef struct {
  mq_aead_type type;
  size_t keylen;
  size_t noncelen;
  size_t taglen;
} mq_aead;

static const mq_aead aead_aes_128_gcm = {MQ_AEAD_AES_128_GCM, 16, 12, 16};
static const mq_aead aead_aes_256_gcm = {MQ_AEAD_AES_256_GCM, 32, 12, 16};
static const mq_aead aead_chacha20_poly1305 = {MQ_AEAD_CHACHA20_POLY1305, 32,
                                               12, 16};

typedef enum {
  MQ_HP_AES_128,
  MQ_HP_AES_256,
  MQ_HP_CHACHA20,
} mq_hp_type;

typedef struct {
  mq_hp_type type;
  size_t keylen;
} mq_hp;

static const mq_hp hp_aes_128 = {MQ_HP_AES_128, 16};
static const mq_hp hp_aes_256 = {MQ_HP_AES_256, 32};
static const mq_hp hp_chacha20 = {MQ_HP_CHACHA20, 32};

typedef struct {
  mbedtls_md_type_t md;
  size_t hashlen;
} mq_md;

static const mq_md md_sha256 = {MBEDTLS_MD_SHA256, 32};
static const mq_md md_sha384 = {MBEDTLS_MD_SHA384, 48};

/* --------------------------------------------------------------------------
 * Live contexts
 *
 * A context is created once per key and used for every packet under it, so the
 * cipher schedule is computed here rather than per packet.
 * -------------------------------------------------------------------------- */

typedef struct {
  mq_aead_type type;
  union {
    mbedtls_gcm_context gcm;
    mbedtls_chachapoly_context chachapoly;
  } ctx;
} mq_aead_ctx;

typedef struct {
  mq_hp_type type;
  /* AES header protection is a single ECB block; ChaCha20 needs the key. */
  mbedtls_aes_context aes;
  uint8_t key[32];
} mq_hp_ctx;

/* --------------------------------------------------------------------------
 * Algorithm selection
 * -------------------------------------------------------------------------- */

ngtcp2_crypto_aead *ngtcp2_crypto_aead_aes_128_gcm(ngtcp2_crypto_aead *aead) {
  return ngtcp2_crypto_aead_init(aead, (void *)&aead_aes_128_gcm);
}

ngtcp2_crypto_md *ngtcp2_crypto_md_sha256(ngtcp2_crypto_md *md) {
  md->native_handle = (void *)&md_sha256;
  return md;
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_init(ngtcp2_crypto_aead *aead,
                                            void *aead_native_handle) {
  aead->native_handle = aead_native_handle;
  aead->max_overhead = ((const mq_aead *)aead_native_handle)->taglen;
  return aead;
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_retry(ngtcp2_crypto_aead *aead) {
  return ngtcp2_crypto_aead_init(aead, (void *)&aead_aes_128_gcm);
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_initial(ngtcp2_crypto_ctx *ctx) {
  /* RFC 9001 §5.2: Initial packets are always AES-128-GCM with SHA-256. */
  ngtcp2_crypto_aead_init(&ctx->aead, (void *)&aead_aes_128_gcm);
  ctx->md.native_handle = (void *)&md_sha256;
  ctx->hp.native_handle = (void *)&hp_aes_128;
  ctx->max_encryption = 0;
  ctx->max_decryption_failure = 0;
  return ctx;
}

size_t ngtcp2_crypto_md_hashlen(const ngtcp2_crypto_md *md) {
  return ((const mq_md *)md->native_handle)->hashlen;
}

size_t ngtcp2_crypto_aead_keylen(const ngtcp2_crypto_aead *aead) {
  return ((const mq_aead *)aead->native_handle)->keylen;
}

size_t ngtcp2_crypto_aead_noncelen(const ngtcp2_crypto_aead *aead) {
  return ((const mq_aead *)aead->native_handle)->noncelen;
}

/* --------------------------------------------------------------------------
 * HKDF
 * -------------------------------------------------------------------------- */

int ngtcp2_crypto_hkdf_extract(uint8_t *dest, const ngtcp2_crypto_md *md,
                               const uint8_t *secret, size_t secretlen,
                               const uint8_t *salt, size_t saltlen) {
  const mq_md *m = md->native_handle;
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(m->md);

  if (info == NULL) {
    return -1;
  }
  if (mbedtls_hkdf_extract(info, salt, saltlen, secret, secretlen, dest) != 0) {
    return -1;
  }
  return 0;
}

int ngtcp2_crypto_hkdf_expand(uint8_t *dest, size_t destlen,
                              const ngtcp2_crypto_md *md, const uint8_t *secret,
                              size_t secretlen, const uint8_t *info,
                              size_t infolen) {
  const mq_md *m = md->native_handle;
  const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_type(m->md);

  if (mdinfo == NULL) {
    return -1;
  }
  if (mbedtls_hkdf_expand(mdinfo, secret, secretlen, info, infolen, dest,
                          destlen) != 0) {
    return -1;
  }
  return 0;
}

int ngtcp2_crypto_hkdf(uint8_t *dest, size_t destlen,
                       const ngtcp2_crypto_md *md, const uint8_t *secret,
                       size_t secretlen, const uint8_t *salt, size_t saltlen,
                       const uint8_t *info, size_t infolen) {
  const mq_md *m = md->native_handle;
  const mbedtls_md_info_t *mdinfo = mbedtls_md_info_from_type(m->md);

  if (mdinfo == NULL) {
    return -1;
  }
  if (mbedtls_hkdf(mdinfo, salt, saltlen, secret, secretlen, info, infolen,
                   dest, destlen) != 0) {
    return -1;
  }
  return 0;
}

/* --------------------------------------------------------------------------
 * AEAD contexts
 * -------------------------------------------------------------------------- */

static int aead_ctx_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                         const ngtcp2_crypto_aead *aead, const uint8_t *key) {
  const mq_aead *a = aead->native_handle;
  mq_aead_ctx *ctx = calloc(1, sizeof(mq_aead_ctx));

  if (ctx == NULL) {
    return -1;
  }
  ctx->type = a->type;

  switch (a->type) {
  case MQ_AEAD_AES_128_GCM:
  case MQ_AEAD_AES_256_GCM:
    mbedtls_gcm_init(&ctx->ctx.gcm);
    /* One key schedule, reused for every packet under this key. GCM is
       symmetric, so the same context serves both directions. */
    if (mbedtls_gcm_setkey(&ctx->ctx.gcm, MBEDTLS_CIPHER_ID_AES, key,
                           (unsigned int)(a->keylen * 8)) != 0) {
      mbedtls_gcm_free(&ctx->ctx.gcm);
      free(ctx);
      return -1;
    }
    break;
  case MQ_AEAD_CHACHA20_POLY1305:
    mbedtls_chachapoly_init(&ctx->ctx.chachapoly);
    if (mbedtls_chachapoly_setkey(&ctx->ctx.chachapoly, key) != 0) {
      mbedtls_chachapoly_free(&ctx->ctx.chachapoly);
      free(ctx);
      return -1;
    }
    break;
  default:
    free(ctx);
    return -1;
  }

  aead_ctx->native_handle = ctx;
  return 0;
}

int ngtcp2_crypto_aead_ctx_encrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *key, size_t noncelen) {
  (void)noncelen;
  return aead_ctx_init(aead_ctx, aead, key);
}

int ngtcp2_crypto_aead_ctx_decrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *key, size_t noncelen) {
  (void)noncelen;
  return aead_ctx_init(aead_ctx, aead, key);
}

void ngtcp2_crypto_aead_ctx_free(ngtcp2_crypto_aead_ctx *aead_ctx) {
  mq_aead_ctx *ctx;

  if (aead_ctx == NULL || aead_ctx->native_handle == NULL) {
    return;
  }
  ctx = aead_ctx->native_handle;

  switch (ctx->type) {
  case MQ_AEAD_AES_128_GCM:
  case MQ_AEAD_AES_256_GCM:
    mbedtls_gcm_free(&ctx->ctx.gcm);
    break;
  case MQ_AEAD_CHACHA20_POLY1305:
    mbedtls_chachapoly_free(&ctx->ctx.chachapoly);
    break;
  }

  free(ctx);
  aead_ctx->native_handle = NULL;
}

/* --------------------------------------------------------------------------
 * Header-protection contexts
 * -------------------------------------------------------------------------- */

int ngtcp2_crypto_cipher_ctx_encrypt_init(ngtcp2_crypto_cipher_ctx *cipher_ctx,
                                          const ngtcp2_crypto_cipher *cipher,
                                          const uint8_t *key) {
  const mq_hp *h = cipher->native_handle;
  mq_hp_ctx *ctx = calloc(1, sizeof(mq_hp_ctx));

  if (ctx == NULL) {
    return -1;
  }
  ctx->type = h->type;

  switch (h->type) {
  case MQ_HP_AES_128:
  case MQ_HP_AES_256:
    mbedtls_aes_init(&ctx->aes);
    /* Header protection is a raw ECB *encryption* in both directions — the
       mask is generated, then XORed, so there is no decrypt schedule. */
    if (mbedtls_aes_setkey_enc(&ctx->aes, key, (unsigned int)(h->keylen * 8)) !=
        0) {
      mbedtls_aes_free(&ctx->aes);
      free(ctx);
      return -1;
    }
    break;
  case MQ_HP_CHACHA20:
    memcpy(ctx->key, key, h->keylen);
    break;
  default:
    free(ctx);
    return -1;
  }

  cipher_ctx->native_handle = ctx;
  return 0;
}

void ngtcp2_crypto_cipher_ctx_free(ngtcp2_crypto_cipher_ctx *cipher_ctx) {
  mq_hp_ctx *ctx;

  if (cipher_ctx == NULL || cipher_ctx->native_handle == NULL) {
    return;
  }
  ctx = cipher_ctx->native_handle;

  if (ctx->type == MQ_HP_AES_128 || ctx->type == MQ_HP_AES_256) {
    mbedtls_aes_free(&ctx->aes);
  }

  ngtcp2_secure_clear(ctx, sizeof(*ctx));
  free(ctx);
  cipher_ctx->native_handle = NULL;
}

/* --------------------------------------------------------------------------
 * Packet protection
 * -------------------------------------------------------------------------- */

int ngtcp2_crypto_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const ngtcp2_crypto_aead_ctx *aead_ctx,
                          const uint8_t *plaintext, size_t plaintextlen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *aad, size_t aadlen) {
  mq_aead_ctx *ctx = aead_ctx->native_handle;
  const mq_aead *a = aead->native_handle;

  /* ngtcp2's contract is ciphertext followed by tag, in one buffer. */
  switch (ctx->type) {
  case MQ_AEAD_AES_128_GCM:
  case MQ_AEAD_AES_256_GCM:
    if (mbedtls_gcm_crypt_and_tag(&ctx->ctx.gcm, MBEDTLS_GCM_ENCRYPT,
                                  plaintextlen, nonce, noncelen, aad, aadlen,
                                  plaintext, dest, a->taglen,
                                  dest + plaintextlen) != 0) {
      return -1;
    }
    return 0;
  case MQ_AEAD_CHACHA20_POLY1305:
    if (noncelen != 12) {
      return -1;
    }
    if (mbedtls_chachapoly_encrypt_and_tag(&ctx->ctx.chachapoly, plaintextlen,
                                           nonce, aad, aadlen, plaintext, dest,
                                           dest + plaintextlen) != 0) {
      return -1;
    }
    return 0;
  }

  return -1;
}

int ngtcp2_crypto_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const ngtcp2_crypto_aead_ctx *aead_ctx,
                          const uint8_t *ciphertext, size_t ciphertextlen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *aad, size_t aadlen) {
  mq_aead_ctx *ctx = aead_ctx->native_handle;
  const mq_aead *a = aead->native_handle;
  size_t bodylen;

  /* A failure here is just "not ours": callers test for non-zero and turn it
     into NGTCP2_ERR_DECRYPT themselves. The NGTCP2_CRYPTO_ERR_* codes belong to
     shared.c, one layer up, and must not be raised from a backend. */

  if (ciphertextlen < a->taglen) {
    return -1;
  }
  bodylen = ciphertextlen - a->taglen;

  switch (ctx->type) {
  case MQ_AEAD_AES_128_GCM:
  case MQ_AEAD_AES_256_GCM:
    /* auth_decrypt checks the tag in constant time and writes nothing on
       failure, which is what makes a forged packet cost nothing. */
    if (mbedtls_gcm_auth_decrypt(&ctx->ctx.gcm, bodylen, nonce, noncelen, aad,
                                 aadlen, ciphertext + bodylen, a->taglen,
                                 ciphertext, dest) != 0) {
      return -1;
    }
    return 0;
  case MQ_AEAD_CHACHA20_POLY1305:
    if (noncelen != 12) {
      return -1;
    }
    if (mbedtls_chachapoly_auth_decrypt(&ctx->ctx.chachapoly, bodylen, nonce,
                                        aad, aadlen, ciphertext + bodylen,
                                        ciphertext, dest) != 0) {
      return -1;
    }
    return 0;
  }

  return -1;
}

int ngtcp2_crypto_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                          const ngtcp2_crypto_cipher_ctx *hp_ctx,
                          const uint8_t *sample) {
  mq_hp_ctx *ctx = hp_ctx->native_handle;
  uint8_t block[16];

  (void)hp;

  switch (ctx->type) {
  case MQ_HP_AES_128:
  case MQ_HP_AES_256:
    /* RFC 9001 §5.4.3: mask = AES-ECB(hp_key, sample)[0..5]. */
    if (mbedtls_aes_crypt_ecb(&ctx->aes, MBEDTLS_AES_ENCRYPT, sample, block) !=
        0) {
      return -1;
    }
    memcpy(dest, block, NGTCP2_HP_MASKLEN);
    return 0;
  case MQ_HP_CHACHA20: {
    /* RFC 9001 §5.4.4: the sample is a 4-byte counter then a 12-byte nonce,
       and the mask is ChaCha20 keystream over five zero bytes. */
    mbedtls_chacha20_context cc;
    uint32_t counter;
    static const uint8_t zeros[NGTCP2_HP_MASKLEN] = {0};
    int rv;

    counter = ((uint32_t)sample[0]) | ((uint32_t)sample[1] << 8) |
              ((uint32_t)sample[2] << 16) | ((uint32_t)sample[3] << 24);

    mbedtls_chacha20_init(&cc);
    rv = mbedtls_chacha20_setkey(&cc, ctx->key);
    if (rv == 0) {
      rv = mbedtls_chacha20_starts(&cc, sample + 4, counter);
    }
    if (rv == 0) {
      rv = mbedtls_chacha20_update(&cc, NGTCP2_HP_MASKLEN, zeros, dest);
    }
    mbedtls_chacha20_free(&cc);
    return rv == 0 ? 0 : -1;
  }
  }

  return -1;
}

int ngtcp2_crypto_random(uint8_t *data, size_t datalen) {
  /* Seeded from the kernel CSPRNG and reseeded across fork; the one source on
     bionic that needs no file descriptor and cannot fail. */
  arc4random_buf(data, datalen);
  return 0;
}

/* --------------------------------------------------------------------------
 * TLS handoff
 *
 * The handshake is Kotlin's. `tls_native_handle` carries a cipher suite as an
 * integer rather than a pointer to a TLS object, because there is no C-side TLS
 * object to point at.
 * -------------------------------------------------------------------------- */

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls(ngtcp2_crypto_ctx *ctx,
                                         void *tls_native_handle) {
  uintptr_t suite;

  if (tls_native_handle == NULL) {
    return NULL;
  }
  suite = (uintptr_t)tls_native_handle;

  switch (suite) {
  case 0x1301: /* TLS_AES_128_GCM_SHA256 */
    ngtcp2_crypto_aead_init(&ctx->aead, (void *)&aead_aes_128_gcm);
    ctx->md.native_handle = (void *)&md_sha256;
    ctx->hp.native_handle = (void *)&hp_aes_128;
    ctx->max_encryption = NGTCP2_CRYPTO_MAX_ENCRYPTION_AES_GCM;
    ctx->max_decryption_failure = NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_AES_GCM;
    break;
  case 0x1302: /* TLS_AES_256_GCM_SHA384 */
    ngtcp2_crypto_aead_init(&ctx->aead, (void *)&aead_aes_256_gcm);
    ctx->md.native_handle = (void *)&md_sha384;
    ctx->hp.native_handle = (void *)&hp_aes_256;
    ctx->max_encryption = NGTCP2_CRYPTO_MAX_ENCRYPTION_AES_GCM;
    ctx->max_decryption_failure = NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_AES_GCM;
    break;
  case 0x1303: /* TLS_CHACHA20_POLY1305_SHA256 */
    ngtcp2_crypto_aead_init(&ctx->aead, (void *)&aead_chacha20_poly1305);
    ctx->md.native_handle = (void *)&md_sha256;
    ctx->hp.native_handle = (void *)&hp_chacha20;
    ctx->max_encryption = NGTCP2_CRYPTO_MAX_ENCRYPTION_CHACHA20_POLY1305;
    ctx->max_decryption_failure =
      NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_CHACHA20_POLY1305;
    break;
  default:
    return NULL;
  }

  return ctx;
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls_early(ngtcp2_crypto_ctx *ctx,
                                               void *tls_native_handle) {
  return ngtcp2_crypto_ctx_tls(ctx, tls_native_handle);
}

int ngtcp2_crypto_set_remote_transport_params(ngtcp2_conn *conn, void *tls) {
  /* The managed layer reads the peer's parameters out of the TLS extension it
     already parses, and calls ngtcp2_conn_decode_and_set_remote_transport_params
     directly. */
  (void)conn;
  (void)tls;
  return 0;
}

int ngtcp2_crypto_set_local_transport_params(void *tls, const uint8_t *buf,
                                             size_t len) {
  /* Likewise outbound: the encoded parameters are handed up and put into the
     ClientHello by the Kotlin TLS client. */
  (void)tls;
  (void)buf;
  (void)len;
  return 0;
}

int ngtcp2_crypto_read_write_crypto_data(
  ngtcp2_conn *conn, ngtcp2_encryption_level encryption_level,
  const uint8_t *data, size_t datalen) {
  /* Never reached: this is the entry point a C-side TLS stack would drive the
     handshake through, and there is not one. */
  (void)conn;
  (void)encryption_level;
  (void)data;
  (void)datalen;
  return -1;
}

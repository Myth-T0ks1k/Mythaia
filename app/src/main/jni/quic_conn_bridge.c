/*
 * quic_conn_bridge.c
 * Mythaia
 *
 * A QUIC connection, as much of one as belongs in C.
 *
 * ngtcp2 is a state machine, not a socket: it is fed the datagrams that
 * arrived, asked for the datagrams to send, and told when its timer expired.
 * Everything around that — the UDP socket, the event loop, the TLS handshake —
 * is somebody else's job. Here that somebody is Kotlin, so this file is the
 * translation layer: a handle, a dozen entry points, and four callbacks going
 * back up.
 *
 * The handshake deliberately does *not* live here. ngtcp2 asks its embedder for
 * TLS through `client_initial` and `recv_crypto_data`, and answering those from
 * C would mean a second TLS implementation next to the Kotlin one this app
 * already has. Instead both callbacks hand the bytes up, and Kotlin submits the
 * replies and installs the keys through the entry points below.
 *
 * Derived in structure from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */

#include <jni.h>
#include <stdlib.h>
#include <string.h>

#include <android/log.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

/* derive_and_install_initial_key is declared in the crypto helper's own
   header, not the public one. */
#include "shared.h"

#define LOG_TAG "MythaiaQUIC"
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

/* One datagram. Anything larger than this cannot leave the interface intact,
   and ngtcp2 is told the same number so it never builds one that would. */
#define MAX_DATAGRAM 1452

typedef struct {
  ngtcp2_crypto_conn_ref conn_ref; /* must stay first: ngtcp2 casts to it */
  ngtcp2_conn *conn;

  JavaVM *vm;
  jobject callback; /* global ref to the Kotlin QuicCallback */
  jmethodID on_crypto_data;
  jmethodID on_stream_data;
  jmethodID on_stream_close;
  jmethodID on_handshake_done;
  jmethodID on_datagram;

  struct sockaddr_storage local_addr;
  struct sockaddr_storage remote_addr;
  ngtcp2_socklen local_len;
  ngtcp2_socklen remote_len;

  uint8_t out[MAX_DATAGRAM];
} quic_conn;

/* ------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* ------------------------------------------------------------------------- */

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *ref) {
  return ((quic_conn *)ref)->conn;
}

static uint64_t timestamp_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * NGTCP2_SECONDS + (uint64_t)ts.tv_nsec;
}

/* Attaching on every callback rather than caching a JNIEnv: ngtcp2 calls back
   from whichever thread drove it, and a JNIEnv belongs to one thread only. */
static JNIEnv *attach(quic_conn *qc, int *attached) {
  JNIEnv *env = NULL;
  *attached = 0;
  if ((*qc->vm)->GetEnv(qc->vm, (void **)&env, JNI_VERSION_1_6) == JNI_OK) {
    return env;
  }
  if ((*qc->vm)->AttachCurrentThread(qc->vm, &env, NULL) == JNI_OK) {
    *attached = 1;
    return env;
  }
  return NULL;
}

static void detach(quic_conn *qc, int attached) {
  if (attached) {
    (*qc->vm)->DetachCurrentThread(qc->vm);
  }
}

static jbyteArray to_java_bytes(JNIEnv *env, const uint8_t *data, size_t len) {
  jbyteArray array = (*env)->NewByteArray(env, (jsize)len);
  if (array == NULL) {
    return NULL;
  }
  (*env)->SetByteArrayRegion(env, array, 0, (jsize)len, (const jbyte *)data);
  return array;
}

/* -------------------------------------------------------------------------
 * Encryption levels
 *
 * The app names three levels and this maps them onto ngtcp2's enum. They are
 * translated rather than cast because the enum has been renumbered before:
 * `ngtcp2_crypto_level` ordered them initial, early, handshake, app, and
 * `ngtcp2_encryption_level` orders them initial, handshake, 1-RTT, 0-RTT. A
 * cast that silently survived that change installs handshake keys as 1-RTT
 * keys, and nothing reports it.
 * ------------------------------------------------------------------------- */

#define APP_LEVEL_INITIAL 0
#define APP_LEVEL_HANDSHAKE 1
#define APP_LEVEL_APPLICATION 2

static int to_ngtcp2_level(jint level, ngtcp2_encryption_level *out) {
  switch (level) {
  case APP_LEVEL_INITIAL:
    *out = NGTCP2_ENCRYPTION_LEVEL_INITIAL;
    return 0;
  case APP_LEVEL_HANDSHAKE:
    *out = NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE;
    return 0;
  case APP_LEVEL_APPLICATION:
    *out = NGTCP2_ENCRYPTION_LEVEL_1RTT;
    return 0;
  default:
    return -1;
  }
}

static jint from_ngtcp2_level(ngtcp2_encryption_level level) {
  switch (level) {
  case NGTCP2_ENCRYPTION_LEVEL_INITIAL:
    return APP_LEVEL_INITIAL;
  case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
    return APP_LEVEL_HANDSHAKE;
  case NGTCP2_ENCRYPTION_LEVEL_1RTT:
    return APP_LEVEL_APPLICATION;
  default:
    return -2; /* 0-RTT, which this client never offers. */
  }
}

/* ------------------------------------------------------------------------- */
/* ngtcp2 callbacks                                                           */
/* ------------------------------------------------------------------------- */

/* The handshake starts. Kotlin is asked for the ClientHello; it comes back
   through nativeSubmitCrypto before this returns, so the connection has
   something to put in its first Initial packet. */
static int on_client_initial(ngtcp2_conn *conn, void *user_data) {
  quic_conn *qc = (quic_conn *)user_data;

  /* Replacing ngtcp2's own client_initial callback means taking on what it
     did. Deriving the Initial keys is the part that is easy to miss and fatal
     to miss: without them conn->in_pktns->crypto.tx.ckm stays NULL, and the
     very first Initial packet dereferences it while building its nonce. The
     assert that would catch it is compiled out of a release build. */
  if (ngtcp2_crypto_derive_and_install_initial_key(
        conn, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        ngtcp2_conn_get_client_chosen_version2(conn),
        ngtcp2_conn_get_dcid2(conn)) != 0) {
    LOGW("could not install the Initial keys");
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  int attached = 0;
  JNIEnv *env = attach(qc, &attached);
  if (env == NULL) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  /* A null payload means "there is no data, produce the first flight". */
  (*env)->CallVoidMethod(env, qc->callback, qc->on_crypto_data,
                         APP_LEVEL_INITIAL, NULL);
  int failed = (*env)->ExceptionCheck(env);
  if (failed) {
    (*env)->ExceptionDescribe(env);
    (*env)->ExceptionClear(env);
  }
  detach(qc, attached);

  return failed ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}

/* Handshake bytes arrived at some encryption level. They are handed up
   verbatim; the TLS state machine is Kotlin's. */
static int on_recv_crypto_data(ngtcp2_conn *conn,
                               ngtcp2_encryption_level level,
                               uint64_t offset, const uint8_t *data,
                               size_t datalen, void *user_data) {
  quic_conn *qc = (quic_conn *)user_data;
  (void)conn;
  (void)offset;

  int attached = 0;
  JNIEnv *env = attach(qc, &attached);
  if (env == NULL) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  jint app_level = from_ngtcp2_level(level);
  if (app_level < 0) {
    /* 0-RTT, which this client never offers, so there is nothing to hand up. */
    detach(qc, attached);
    return 0;
  }

  jbyteArray bytes = to_java_bytes(env, data, datalen);
  int failed = 0;
  if (bytes == NULL) {
    failed = 1;
  } else {
    (*env)->CallVoidMethod(env, qc->callback, qc->on_crypto_data, app_level,
                           bytes);
    failed = (*env)->ExceptionCheck(env);
    if (failed) {
      (*env)->ExceptionDescribe(env);
      (*env)->ExceptionClear(env);
    }
    (*env)->DeleteLocalRef(env, bytes);
  }
  detach(qc, attached);

  return failed ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}

static int on_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                               int64_t stream_id, uint64_t offset,
                               const uint8_t *data, size_t datalen,
                               void *user_data, void *stream_user_data) {
  quic_conn *qc = (quic_conn *)user_data;
  (void)conn;
  (void)offset;
  (void)stream_user_data;

  int attached = 0;
  JNIEnv *env = attach(qc, &attached);
  if (env == NULL) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  jbyteArray bytes = to_java_bytes(env, data, datalen);
  int failed = 0;
  if (bytes == NULL) {
    failed = 1;
  } else {
    jboolean fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? JNI_TRUE : JNI_FALSE;
    (*env)->CallVoidMethod(env, qc->callback, qc->on_stream_data,
                           (jlong)stream_id, bytes, fin);
    failed = (*env)->ExceptionCheck(env);
    if (failed) {
      (*env)->ExceptionDescribe(env);
      (*env)->ExceptionClear(env);
    }
    (*env)->DeleteLocalRef(env, bytes);
  }
  detach(qc, attached);

  return failed ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}

static int on_stream_close(ngtcp2_conn *conn, uint32_t flags,
                           int64_t stream_id, uint64_t app_error_code,
                           void *user_data, void *stream_user_data) {
  quic_conn *qc = (quic_conn *)user_data;
  (void)conn;
  (void)flags;
  (void)stream_user_data;

  int attached = 0;
  JNIEnv *env = attach(qc, &attached);
  if (env == NULL) {
    return 0;
  }
  (*env)->CallVoidMethod(env, qc->callback, qc->on_stream_close,
                         (jlong)stream_id, (jlong)app_error_code);
  if ((*env)->ExceptionCheck(env)) {
    (*env)->ExceptionClear(env);
  }
  detach(qc, attached);
  return 0;
}

/*
 * A DATAGRAM frame arrived.
 *
 * QUIC datagrams are unreliable and unordered by design — they are not a
 * stream, and nothing retransmits them. TUIC uses them for heartbeats and for
 * its native UDP relay mode, where losing one is exactly what UDP means.
 */
static int on_recv_datagram(ngtcp2_conn *conn, uint32_t flags,
                            const uint8_t *data, size_t datalen,
                            void *user_data) {
  quic_conn *qc = (quic_conn *)user_data;
  (void)conn;
  (void)flags;

  if (qc->on_datagram == NULL) {
    return 0;
  }

  int attached = 0;
  JNIEnv *env = attach(qc, &attached);
  if (env == NULL) {
    return 0;
  }

  jbyteArray bytes = to_java_bytes(env, data, datalen);
  if (bytes != NULL) {
    (*env)->CallVoidMethod(env, qc->callback, qc->on_datagram, bytes);
    if ((*env)->ExceptionCheck(env)) {
      (*env)->ExceptionClear(env);
    }
    (*env)->DeleteLocalRef(env, bytes);
  }
  detach(qc, attached);
  return 0;
}

static int on_handshake_completed(ngtcp2_conn *conn, void *user_data) {
  quic_conn *qc = (quic_conn *)user_data;
  (void)conn;

  int attached = 0;
  JNIEnv *env = attach(qc, &attached);
  if (env == NULL) {
    return 0;
  }
  (*env)->CallVoidMethod(env, qc->callback, qc->on_handshake_done);
  if ((*env)->ExceptionCheck(env)) {
    (*env)->ExceptionClear(env);
  }
  detach(qc, attached);
  return 0;
}

/* ngtcp2 needs randomness for padding and probes; it is not key material, but
   there is no reason to feed it anything weaker than the system source. */
static void on_rand(uint8_t *dest, size_t destlen,
                    const ngtcp2_rand_ctx *rand_ctx) {
  (void)rand_ctx;
  arc4random_buf(dest, destlen);
}

/*
 * Data for a PATH_CHALLENGE frame.
 *
 * The vendored crypto backend does not compile the helper upstream provides for
 * this, and the requirement is only that the bytes be unpredictable — which is
 * the same requirement `on_rand` already satisfies.
 */
static int on_get_path_challenge_data(ngtcp2_conn *conn,
                                      ngtcp2_path_challenge_data *data,
                                      void *user_data) {
  (void)conn;
  (void)user_data;
  arc4random_buf(data->data, NGTCP2_PATH_CHALLENGE_DATALEN);
  return 0;
}

static int on_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen,
                                    void *user_data) {
  (void)conn;
  (void)user_data;
  arc4random_buf(cid->data, cidlen);
  cid->datalen = cidlen;
  arc4random_buf(token, NGTCP2_STATELESS_RESET_TOKENLEN);
  return 0;
}

/* ------------------------------------------------------------------------- */
/* Lifecycle                                                                  */
/* ------------------------------------------------------------------------- */

static int parse_sockaddr(const char *ip, uint16_t port,
                          struct sockaddr_storage *out, ngtcp2_socklen *len) {
  memset(out, 0, sizeof(*out));

  struct in6_addr v6;
  if (inet_pton(AF_INET6, ip, &v6) == 1) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = htons(port);
    sin6->sin6_addr = v6;
    *len = sizeof(struct sockaddr_in6);
    return 0;
  }

  struct in_addr v4;
  if (inet_pton(AF_INET, ip, &v4) == 1) {
    struct sockaddr_in *sin = (struct sockaddr_in *)out;
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    sin->sin_addr = v4;
    *len = sizeof(struct sockaddr_in);
    return 0;
  }

  return -1;
}

JNIEXPORT jlong JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicConnCreate(
  JNIEnv *env, jclass clazz, jstring remote_ip, jint remote_port,
  jstring local_ip, jint local_port, jlongArray tuning, jobject callback) {
  (void)clazz;

  quic_conn *qc = calloc(1, sizeof(quic_conn));
  if (qc == NULL) {
    return 0;
  }

  const char *remote = (*env)->GetStringUTFChars(env, remote_ip, NULL);
  const char *local = (*env)->GetStringUTFChars(env, local_ip, NULL);
  int addr_ok = remote != NULL && local != NULL &&
                parse_sockaddr(remote, (uint16_t)remote_port, &qc->remote_addr,
                               &qc->remote_len) == 0 &&
                parse_sockaddr(local, (uint16_t)local_port, &qc->local_addr,
                               &qc->local_len) == 0;
  if (remote != NULL) {
    (*env)->ReleaseStringUTFChars(env, remote_ip, remote);
  }
  if (local != NULL) {
    (*env)->ReleaseStringUTFChars(env, local_ip, local);
  }
  if (!addr_ok) {
    free(qc);
    return 0;
  }

  if ((*env)->GetJavaVM(env, &qc->vm) != JNI_OK) {
    free(qc);
    return 0;
  }
  qc->callback = (*env)->NewGlobalRef(env, callback);
  if (qc->callback == NULL) {
    free(qc);
    return 0;
  }

  jclass cb = (*env)->GetObjectClass(env, callback);
  qc->on_crypto_data = (*env)->GetMethodID(env, cb, "onCryptoData", "(I[B)V");
  qc->on_stream_data = (*env)->GetMethodID(env, cb, "onStreamData", "(J[BZ)V");
  qc->on_stream_close = (*env)->GetMethodID(env, cb, "onStreamClose", "(JJ)V");
  qc->on_handshake_done =
    (*env)->GetMethodID(env, cb, "onHandshakeComplete", "()V");
  qc->on_datagram = (*env)->GetMethodID(env, cb, "onDatagram", "([B)V");
  if (qc->on_crypto_data == NULL || qc->on_stream_data == NULL ||
      qc->on_stream_close == NULL || qc->on_handshake_done == NULL) {
    (*env)->DeleteGlobalRef(env, qc->callback);
    free(qc);
    return 0;
  }

  ngtcp2_cid dcid, scid;
  dcid.datalen = 18;
  arc4random_buf(dcid.data, dcid.datalen);
  scid.datalen = 17;
  arc4random_buf(scid.data, scid.datalen);

  ngtcp2_callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.client_initial = on_client_initial;
  callbacks.recv_crypto_data = on_recv_crypto_data;
  callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
  callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
  callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
  callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
  callbacks.update_key = ngtcp2_crypto_update_key_cb;
  callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  callbacks.delete_crypto_cipher_ctx =
    ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  callbacks.get_path_challenge_data2 = on_get_path_challenge_data;
  callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
  callbacks.recv_stream_data = on_recv_stream_data;
  callbacks.stream_close = on_stream_close;
  callbacks.handshake_completed = on_handshake_completed;
  callbacks.rand = on_rand;
  callbacks.get_new_connection_id = on_get_new_connection_id;
  callbacks.recv_datagram = on_recv_datagram;

  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);
  settings.initial_ts = timestamp_ns();
  /* The ceiling, not the starting point. Shaping stays on so ngtcp2 begins at
     the 1200 bytes every path must carry and grows towards this through PMTU
     discovery — forcing the ceiling from the first packet makes the Initial
     datagram undeliverable on any path with a smaller MTU, and there is no
     fallback once it has been ruled out. */
  settings.max_tx_udp_payload_size = MAX_DATAGRAM;

  /* The limits come from the caller's tuning profile rather than being fixed
     here: HTTP/3 requires the server to open a control stream, so a profile
     for it must grant unidirectional credit, while a plain tunnel grants none
     and treats an attempt as a connection error. Order matches
     QuicTuning.toNativeArray. */
  jlong values[7] = {0};
  if (tuning != NULL && (*env)->GetArrayLength(env, tuning) >= 7) {
    (*env)->GetLongArrayRegion(env, tuning, 0, 7, values);
  }

  ngtcp2_transport_params params;
  ngtcp2_transport_params_default(&params);
  params.initial_max_data = (uint64_t)values[0];
  params.initial_max_stream_data_bidi_local = (uint64_t)values[1];
  params.initial_max_stream_data_bidi_remote = (uint64_t)values[2];
  params.initial_max_stream_data_uni = (uint64_t)values[3];
  params.initial_max_streams_bidi = (uint64_t)values[4];
  params.initial_max_streams_uni = (uint64_t)values[5];
  params.max_idle_timeout = (ngtcp2_duration)values[6];
  params.active_connection_id_limit = 4;
  /* Without this the peer may not send DATAGRAM frames at all — the extension
     is opt-in per direction, and a zero here disables it silently. */
  params.max_datagram_frame_size = MAX_DATAGRAM;

  ngtcp2_path path;
  path.local.addr = (struct sockaddr *)&qc->local_addr;
  path.local.addrlen = qc->local_len;
  path.remote.addr = (struct sockaddr *)&qc->remote_addr;
  path.remote.addrlen = qc->remote_len;
  path.user_data = NULL;

  qc->conn_ref.get_conn = get_conn;
  qc->conn_ref.user_data = qc;

  int rv = ngtcp2_conn_client_new(&qc->conn, &dcid, &scid, &path,
                                  NGTCP2_PROTO_VER_V1, &callbacks, &settings,
                                  &params, NULL, qc);
  if (rv != 0) {
    LOGW("ngtcp2_conn_client_new failed: %s", ngtcp2_strerror(rv));
    (*env)->DeleteGlobalRef(env, qc->callback);
    free(qc);
    return 0;
  }

  /* The TLS native handle is deliberately left unset until the cipher suite is
     known. This backend does not point it at a TLS object — there is no C-side
     TLS object — it reads it back as the negotiated suite, so setting it to
     anything else makes ngtcp2_crypto_ctx_tls return NULL and every key
     installation fail. See nativeQuicSetCipherSuite. */
  return (jlong)(intptr_t)qc;
}

JNIEXPORT void JNICALL Java_com_mythaia_vpn_NativeBridge_nativeQuicConnFree(
  JNIEnv *env, jclass clazz, jlong handle) {
  (void)clazz;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL) {
    return;
  }
  if (qc->conn != NULL) {
    ngtcp2_conn_del(qc->conn);
  }
  if (qc->callback != NULL) {
    (*env)->DeleteGlobalRef(env, qc->callback);
  }
  free(qc);
}

/* ------------------------------------------------------------------------- */
/* Packet I/O                                                                 */
/* ------------------------------------------------------------------------- */

JNIEXPORT jint JNICALL Java_com_mythaia_vpn_NativeBridge_nativeQuicConnRead(
  JNIEnv *env, jclass clazz, jlong handle, jbyteArray packet, jint length) {
  (void)clazz;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL || qc->conn == NULL) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  jbyte *bytes = (*env)->GetByteArrayElements(env, packet, NULL);
  if (bytes == NULL) {
    return NGTCP2_ERR_NOMEM;
  }

  ngtcp2_path path;
  path.local.addr = (struct sockaddr *)&qc->local_addr;
  path.local.addrlen = qc->local_len;
  path.remote.addr = (struct sockaddr *)&qc->remote_addr;
  path.remote.addrlen = qc->remote_len;
  path.user_data = NULL;

  ngtcp2_pkt_info pi;
  memset(&pi, 0, sizeof(pi));

  int rv = ngtcp2_conn_read_pkt(qc->conn, &path, &pi, (const uint8_t *)bytes,
                                (size_t)length, timestamp_ns());

  if (rv < 0 && rv != NGTCP2_ERR_RETRY && rv != NGTCP2_ERR_DROP_CONN) {
    /* The peer's CONNECTION_CLOSE, or our own reason for giving up: without
       this a failed handshake is just "draining" with nothing to go on. */
    const ngtcp2_ccerr *ce = ngtcp2_conn_get_ccerr(qc->conn);
    if (ce != NULL) {
      LOGW("read_pkt %d: close type=%d code=0x%llx frame=0x%llx reason=%.*s", rv,
           (int)ce->type, (unsigned long long)ce->error_code,
           (unsigned long long)ce->frame_type, (int)(ce->reasonlen > 200 ? 200 : ce->reasonlen),
           ce->reason == NULL ? "" : (const char *)ce->reason);
    } else {
      LOGW("read_pkt failed: %d", rv);
    }
  }

  (*env)->ReleaseByteArrayElements(env, packet, bytes, JNI_ABORT);
  return rv;
}

/*
 * The local transport parameters as the ClientHello must carry them.
 *
 * Encoded by ngtcp2 rather than by Kotlin so the list matches what the
 * connection was created with and carries what only ngtcp2 knows: the
 * initial_source_connection_id, which every peer requires (RFC 9000 18.2)
 * and which a hand-built list left out.
 */
JNIEXPORT jbyteArray JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicLocalTransportParams(JNIEnv *env, jclass clazz,
                                                                 jlong handle) {
  (void)clazz;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL || qc->conn == NULL) {
    return NULL;
  }
  uint8_t buf[1024];
  ngtcp2_ssize n = ngtcp2_conn_encode_local_transport_params2(qc->conn, buf, sizeof(buf));
  if (n < 0) {
    LOGW("encode_local_transport_params failed: %s", ngtcp2_strerror((int)n));
    return NULL;
  }
  jbyteArray out = (*env)->NewByteArray(env, (jsize)n);
  if (out == NULL) {
    return NULL;
  }
  (*env)->SetByteArrayRegion(env, out, 0, (jsize)n, (const jbyte *)buf);
  return out;
}

/*
 * The next datagram to send, or null when there is nothing.
 *
 * One at a time rather than a batch: ngtcp2 decides how much it may send from
 * its own pacing and congestion state, and the caller loops until this returns
 * null, which is exactly how the library expects to be drained.
 */
JNIEXPORT jbyteArray JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicConnWrite(JNIEnv *env, jclass clazz,
                                                      jlong handle) {
  (void)clazz;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL || qc->conn == NULL) {
    return NULL;
  }

  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);
  ngtcp2_pkt_info pi;

  ngtcp2_ssize written = ngtcp2_conn_write_pkt(qc->conn, &ps.path, &pi, qc->out,
                                               sizeof(qc->out), timestamp_ns());
  if (written <= 0) {
    if (written < 0) {
      LOGD("ngtcp2_conn_write_pkt: %s", ngtcp2_strerror((int)written));
    }
    return NULL;
  }
  return to_java_bytes(env, qc->out, (size_t)written);
}

/*
 * Writes stream data and hands back the datagram it produced.
 *
 * Both halves matter. ngtcp2 serialises a packet into our buffer *and* reports
 * how much of the offered payload went into it, and those are different
 * numbers: returning only the count loses the packet, which then never reaches
 * the wire even though the library has already numbered it and is waiting to
 * have it acknowledged.
 *
 * `accepted_out[0]` receives the byte count. Taking fewer than offered, or
 * none, is ordinary — flow control and congestion both say so — and the caller
 * offers the remainder again.
 */
JNIEXPORT jbyteArray JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicConnWriteStream(
  JNIEnv *env, jclass clazz, jlong handle, jlong stream_id, jbyteArray data,
  jboolean fin, jlongArray accepted_out) {
  (void)clazz;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL || qc->conn == NULL) {
    return NULL;
  }

  jsize len = data == NULL ? 0 : (*env)->GetArrayLength(env, data);
  jbyte *bytes = NULL;
  if (len > 0) {
    bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (bytes == NULL) {
      return NULL;
    }
  }

  ngtcp2_vec vec;
  vec.base = (uint8_t *)bytes;
  vec.len = (size_t)len;

  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);
  ngtcp2_pkt_info pi;

  ngtcp2_ssize accepted = 0;
  /* No WRITE_MORE: nothing here coalesces several streams into one packet,
     which is its only purpose, and it would leave ngtcp2 mid-packet across a
     released lock waiting for a resume call with the same timestamp. */
  uint32_t flags = fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : NGTCP2_WRITE_STREAM_FLAG_NONE;

  ngtcp2_ssize written = ngtcp2_conn_writev_stream(
    qc->conn, &ps.path, &pi, qc->out, sizeof(qc->out), &accepted, flags,
    (int64_t)stream_id, len > 0 ? &vec : NULL, len > 0 ? 1 : 0,
    timestamp_ns());

  if (bytes != NULL) {
    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
  }

  if (accepted_out != NULL) {
    /* -1 means "no STREAM frame went into this packet", which is a normal
       outcome and not an error; reporting it as a byte count would have the
       caller treat a routine backpressure tick as a fatal write failure. */
    jlong reported = written < 0 ? 0 : (accepted < 0 ? 0 : (jlong)accepted);
    (*env)->SetLongArrayRegion(env, accepted_out, 0, 1, &reported);
  }

  if (written <= 0) {
    if (written < 0 && written != NGTCP2_ERR_STREAM_DATA_BLOCKED &&
        written != NGTCP2_ERR_STREAM_SHUT_WR) {
      LOGD("writev_stream: %s", ngtcp2_strerror((int)written));
    }
    return NULL;
  }
  return to_java_bytes(env, qc->out, (size_t)written);
}

/*
 * Tells ngtcp2 the send burst is over, so it can pace the next one.
 *
 * Without this `pacing_interval_m` is never consulted and every window is sent
 * as fast as the socket will take it, which is what congestion control exists
 * to avoid.
 */
JNIEXPORT void JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicConnFlushDone(JNIEnv *env,
                                                          jclass clazz,
                                                          jlong handle) {
  (void)env;
  (void)clazz;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL || qc->conn == NULL) {
    return;
  }
  ngtcp2_conn_update_pkt_tx_time(qc->conn, timestamp_ns());
}

JNIEXPORT jlong JNICALL Java_com_mythaia_vpn_NativeBridge_nativeQuicConnExpiry(
  JNIEnv *env, jclass clazz, jlong handle) {
  (void)env;
  (void)clazz;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL || qc->conn == NULL) {
    return -1;
  }
  return (jlong)ngtcp2_conn_get_expiry(qc->conn);
}

JNIEXPORT jint JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicConnHandleExpiry(JNIEnv *env,
                                                             jclass clazz,
                                                             jlong handle) {
  (void)env;
  (void)clazz;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL || qc->conn == NULL) {
    return NGTCP2_ERR_INVALID_STATE;
  }
  return ngtcp2_conn_handle_expiry(qc->conn, timestamp_ns());
}

/* ------------------------------------------------------------------------- */
/* Handshake, driven from Kotlin                                              */
/* ------------------------------------------------------------------------- */

/*
 * Tells the connection which cipher suite the handshake settled on.
 *
 * The Android crypto backend carries the suite *as* the TLS native handle: an
 * integer where another backend would put a pointer to its TLS object. Nothing
 * can be encrypted before this is set, and the key-installation helpers read it
 * back on every call, so it must land as soon as the ServerHello names it.
 */
JNIEXPORT jint JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicSetCipherSuite(JNIEnv *env,
                                                           jclass clazz,
                                                           jlong handle,
                                                           jint suite) {
  (void)env;
  (void)clazz;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL || qc->conn == NULL) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  ngtcp2_crypto_ctx ctx;
  if (ngtcp2_crypto_ctx_tls(&ctx, (void *)(uintptr_t)suite) == NULL) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  ngtcp2_conn_set_tls_native_handle(qc->conn, (void *)(uintptr_t)suite);
  ngtcp2_conn_set_crypto_ctx(qc->conn, &ctx);
  return 0;
}

JNIEXPORT jint JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicSubmitCrypto(
  JNIEnv *env, jclass clazz, jlong handle, jint level, jbyteArray data) {
  (void)clazz;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL || qc->conn == NULL) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  ngtcp2_encryption_level target;
  if (to_ngtcp2_level(level, &target) != 0) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
  if (bytes == NULL) {
    return NGTCP2_ERR_NOMEM;
  }
  jsize len = (*env)->GetArrayLength(env, data);

  /* ngtcp2 copies the bytes into its own buffer chain (conn_buffer_crypto_data
     ends in ngtcp2_cpymem), so nothing here has to outlive the call. */
  int rv = ngtcp2_conn_submit_crypto_data(qc->conn, target,
                                          (const uint8_t *)bytes, (size_t)len);

  (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
  return rv;
}

JNIEXPORT jint JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicInstallKeys(
  JNIEnv *env, jclass clazz, jlong handle, jint level, jbyteArray rx_secret,
  jbyteArray tx_secret) {
  (void)clazz;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL || qc->conn == NULL) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  jsize rx_len = rx_secret == NULL ? 0 : (*env)->GetArrayLength(env, rx_secret);
  jsize tx_len = tx_secret == NULL ? 0 : (*env)->GetArrayLength(env, tx_secret);

  uint8_t rx[64], tx[64];
  if (rx_len > (jsize)sizeof(rx) || tx_len > (jsize)sizeof(tx)) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }
  if (rx_len > 0) {
    (*env)->GetByteArrayRegion(env, rx_secret, 0, rx_len, (jbyte *)rx);
  }
  if (tx_len > 0) {
    (*env)->GetByteArrayRegion(env, tx_secret, 0, tx_len, (jbyte *)tx);
  }

  ngtcp2_encryption_level target;
  if (to_ngtcp2_level(level, &target) != 0) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  if (ngtcp2_crypto_derive_and_install_rx_key(qc->conn, NULL, NULL, NULL,
                                              target, rx, (size_t)rx_len) != 0) {
    LOGW("could not install the rx key at level %d", (int)level);
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  if (ngtcp2_crypto_derive_and_install_tx_key(qc->conn, NULL, NULL, NULL,
                                              target, tx, (size_t)tx_len) != 0) {
    LOGW("could not install the tx key at level %d", (int)level);
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

/*
 * Hands the peer's transport parameters to ngtcp2.
 *
 * Decoding them in Kotlin is for diagnostics; these are the values ngtcp2
 * enforces, and without this it keeps its own conservative defaults — the
 * peer's stream and flow-control limits are simply never learned.
 */
JNIEXPORT jint JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicSetRemoteParams(JNIEnv *env,
                                                            jclass clazz,
                                                            jlong handle,
                                                            jbyteArray params) {
  (void)clazz;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL || qc->conn == NULL) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  jbyte *bytes = (*env)->GetByteArrayElements(env, params, NULL);
  if (bytes == NULL) {
    return NGTCP2_ERR_NOMEM;
  }
  jsize len = (*env)->GetArrayLength(env, params);

  int rv = ngtcp2_conn_decode_and_set_remote_transport_params(
    qc->conn, (const uint8_t *)bytes, (size_t)len);

  (*env)->ReleaseByteArrayElements(env, params, bytes, JNI_ABORT);
  return rv;
}

/*
 * Tells ngtcp2 the TLS handshake finished.
 *
 * Only ever after the server's Finished has been verified: this is what
 * promotes the connection to carrying application data, and calling it earlier
 * promotes one that has proved nothing.
 */
JNIEXPORT void JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicHandshakeCompleted(JNIEnv *env,
                                                               jclass clazz,
                                                               jlong handle) {
  (void)env;
  (void)clazz;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL || qc->conn == NULL) {
    return;
  }
  ngtcp2_conn_tls_handshake_completed(qc->conn);
}

/* ------------------------------------------------------------------------- */
/* Streams                                                                    */
/* ------------------------------------------------------------------------- */

JNIEXPORT jlong JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicOpenBidiStream(JNIEnv *env,
                                                           jclass clazz,
                                                           jlong handle) {
  (void)env;
  (void)clazz;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL || qc->conn == NULL) {
    return NGTCP2_ERR_INVALID_STATE;
  }
  int64_t stream_id = -1;
  int rv = ngtcp2_conn_open_bidi_stream(qc->conn, &stream_id, NULL);
  return rv == 0 ? (jlong)stream_id : (jlong)rv;
}

/*
 * Offers one QUIC datagram to ngtcp2 and returns the packet it built, if any.
 *
 * status[0] says what became of the datagram: 1 when it is in the returned
 * packet; 0 when there was no room for it yet (congestion window, pacing),
 * so the caller should offer it again later; negative, an ngtcp2 error, when
 * it will never fit (larger than the peer accepts, or no DATAGRAM support).
 *
 * A packet can come back with status 0: ngtcp2 may fill it with other frames
 * (ACKs, retransmissions) and leave the datagram out. That packet is already
 * numbered and must go on the wire. Dropping it, as this function used to,
 * made the server see its ACKs lost, so it cut its own sending rate and
 * queued replies: voice over Hysteria2 and TUIC lost packets and gained
 * hundreds of milliseconds of delay.
 */
JNIEXPORT jbyteArray JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicWriteDatagram(JNIEnv *env,
                                                          jclass clazz,
                                                          jlong handle,
                                                          jbyteArray data,
                                                          jintArray status) {
  (void)clazz;
  jint result = NGTCP2_ERR_INVALID_STATE;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL || qc->conn == NULL) {
    (*env)->SetIntArrayRegion(env, status, 0, 1, &result);
    return NULL;
  }

  jsize len = (*env)->GetArrayLength(env, data);
  jbyte *bytes = (*env)->GetByteArrayElements(env, data, NULL);
  if (bytes == NULL) {
    result = NGTCP2_ERR_NOMEM;
    (*env)->SetIntArrayRegion(env, status, 0, 1, &result);
    return NULL;
  }

  ngtcp2_vec vec;
  vec.base = (uint8_t *)bytes;
  vec.len = (size_t)len;

  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);
  ngtcp2_pkt_info pi;
  int accepted = 0;

  ngtcp2_ssize written = ngtcp2_conn_writev_datagram(
    qc->conn, &ps.path, &pi, qc->out, sizeof(qc->out), &accepted,
    NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 0, &vec, 1, timestamp_ns());

  (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);

  result = written < 0 ? (jint)written : (accepted ? 1 : 0);
  (*env)->SetIntArrayRegion(env, status, 0, 1, &result);
  if (written <= 0) {
    return NULL;
  }
  return to_java_bytes(env, qc->out, (size_t)written);
}

/*
 * The largest datagram payload that fits one packet on the current path, or 0
 * before the peer's transport parameters are known.
 *
 * Bounded by two things: the peer's max_datagram_frame_size, and the path's
 * packet size, which starts at 1200 and grows as path MTU discovery confirms
 * larger packets. From the packet size come off the short header (1 byte, the
 * current destination connection id, a packet number of up to 4 bytes), the
 * AEAD tag, and the DATAGRAM frame's type and length.
 *
 * Hysteria and TUIC split a UDP payload into fragments only above this, as
 * their own clients do. Splitting earlier, at a fixed 1100 bytes, broke every
 * large call packet on servers that do not reassemble fragments (Xray's).
 */
JNIEXPORT jint JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicMaxDatagramPayload(JNIEnv *env,
                                                               jclass clazz,
                                                               jlong handle) {
  (void)env;
  (void)clazz;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL || qc->conn == NULL) {
    return 0;
  }
  const ngtcp2_transport_params *remote =
    ngtcp2_conn_get_remote_transport_params2(qc->conn);
  if (remote == NULL || remote->max_datagram_frame_size <= 3) {
    return 0;
  }
  /* Frame type (1) and a length varint (2 below 16384). */
  uint64_t by_peer = remote->max_datagram_frame_size - 3;

  size_t packet = ngtcp2_conn_get_path_max_tx_udp_payload_size2(qc->conn);
  /* 16: the tag of every QUIC v1 AEAD (AES-GCM, ChaCha20-Poly1305). */
  size_t overhead = 1 + ngtcp2_conn_get_dcid2(qc->conn)->datalen + 4 + 16 + 3;
  if (packet <= overhead) {
    return 0;
  }
  uint64_t by_path = (uint64_t)(packet - overhead);
  uint64_t room = by_peer < by_path ? by_peer : by_path;
  return room > 16000 ? 16000 : (jint)room;
}

JNIEXPORT jlong JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicOpenUniStream(JNIEnv *env,
                                                          jclass clazz,
                                                          jlong handle) {
  (void)env;
  (void)clazz;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL || qc->conn == NULL) {
    return NGTCP2_ERR_INVALID_STATE;
  }
  int64_t stream_id = -1;
  int rv = ngtcp2_conn_open_uni_stream(qc->conn, &stream_id, NULL);
  return rv == 0 ? (jlong)stream_id : (jlong)rv;
}

JNIEXPORT void JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicShutdownStream(
  JNIEnv *env, jclass clazz, jlong handle, jlong stream_id, jlong error_code) {
  (void)env;
  (void)clazz;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL || qc->conn == NULL) {
    return;
  }
  ngtcp2_conn_shutdown_stream(qc->conn, 0, (int64_t)stream_id,
                              (uint64_t)error_code);
}

/*
 * Tells the peer we have consumed [count] bytes of a stream.
 *
 * Without this the peer's flow-control window closes and the transfer stalls
 * partway through with no error anywhere.
 */
JNIEXPORT void JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicExtendOffsets(
  JNIEnv *env, jclass clazz, jlong handle, jlong stream_id, jint count) {
  (void)env;
  (void)clazz;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL || qc->conn == NULL) {
    return;
  }
  ngtcp2_conn_extend_max_stream_offset(qc->conn, (int64_t)stream_id,
                                       (uint64_t)count);
  ngtcp2_conn_extend_max_offset(qc->conn, (uint64_t)count);
}

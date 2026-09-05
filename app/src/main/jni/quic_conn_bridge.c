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

/* ------------------------------------------------------------------------- */
/* ngtcp2 callbacks                                                           */
/* ------------------------------------------------------------------------- */

/* The handshake starts. Kotlin is asked for the ClientHello; it comes back
   through nativeSubmitCrypto before this returns, so the connection has
   something to put in its first Initial packet. */
static int on_client_initial(ngtcp2_conn *conn, void *user_data) {
  quic_conn *qc = (quic_conn *)user_data;
  (void)conn;

  int attached = 0;
  JNIEnv *env = attach(qc, &attached);
  if (env == NULL) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  /* Level -1 means "there is no data, produce the first flight". */
  (*env)->CallVoidMethod(env, qc->callback, qc->on_crypto_data, -1, NULL);
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

  jbyteArray bytes = to_java_bytes(env, data, datalen);
  int failed = 0;
  if (bytes == NULL) {
    failed = 1;
  } else {
    (*env)->CallVoidMethod(env, qc->callback, qc->on_crypto_data, (jint)level,
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
  jstring local_ip, jint local_port, jobject callback) {
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

  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);
  settings.initial_ts = timestamp_ns();
  settings.max_tx_udp_payload_size = MAX_DATAGRAM;
  settings.no_tx_udp_payload_size_shaping = 1;

  ngtcp2_transport_params params;
  ngtcp2_transport_params_default(&params);
  params.initial_max_streams_bidi = 0;
  params.initial_max_streams_uni = 0;
  params.initial_max_stream_data_bidi_local = 1024 * 1024;
  params.initial_max_stream_data_bidi_remote = 1024 * 1024;
  params.initial_max_stream_data_uni = 1024 * 1024;
  params.initial_max_data = 8 * 1024 * 1024;
  params.max_idle_timeout = 30 * NGTCP2_SECONDS;
  params.active_connection_id_limit = 4;

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

  ngtcp2_conn_set_tls_native_handle(qc->conn, &qc->conn_ref);
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

  (*env)->ReleaseByteArrayElements(env, packet, bytes, JNI_ABORT);
  return rv;
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
 * Writes stream data, returning how many bytes ngtcp2 took.
 *
 * It may take fewer than offered, or none, when flow control or congestion
 * says so — the caller keeps the remainder and offers it again.
 */
JNIEXPORT jlong JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicConnWriteStream(
  JNIEnv *env, jclass clazz, jlong handle, jlong stream_id, jbyteArray data,
  jboolean fin) {
  (void)clazz;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL || qc->conn == NULL) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  jsize len = data == NULL ? 0 : (*env)->GetArrayLength(env, data);
  jbyte *bytes = NULL;
  if (len > 0) {
    bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (bytes == NULL) {
      return NGTCP2_ERR_NOMEM;
    }
  }

  ngtcp2_vec vec;
  vec.base = (uint8_t *)bytes;
  vec.len = (size_t)len;

  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);
  ngtcp2_pkt_info pi;

  ngtcp2_ssize accepted = 0;
  uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
  if (fin) {
    flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
  }

  ngtcp2_ssize written = ngtcp2_conn_writev_stream(
    qc->conn, &ps.path, &pi, qc->out, sizeof(qc->out), &accepted, flags,
    (int64_t)stream_id, len > 0 ? &vec : NULL, len > 0 ? 1 : 0,
    timestamp_ns());

  if (bytes != NULL) {
    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
  }

  if (written < 0 && written != NGTCP2_ERR_WRITE_MORE) {
    return (jlong)written;
  }
  return (jlong)accepted;
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

JNIEXPORT jint JNICALL
Java_com_mythaia_vpn_NativeBridge_nativeQuicSubmitCrypto(
  JNIEnv *env, jclass clazz, jlong handle, jint level, jbyteArray data) {
  (void)clazz;
  quic_conn *qc = (quic_conn *)(intptr_t)handle;
  if (qc == NULL || qc->conn == NULL) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  jsize len = (*env)->GetArrayLength(env, data);
  /* ngtcp2 keeps a pointer to this buffer until the data is acknowledged, so
     it has to outlive the call — freed when the connection is. */
  uint8_t *copy = malloc((size_t)len);
  if (copy == NULL) {
    return NGTCP2_ERR_NOMEM;
  }
  (*env)->GetByteArrayRegion(env, data, 0, len, (jbyte *)copy);

  int rv = ngtcp2_conn_submit_crypto_data(
    qc->conn, (ngtcp2_encryption_level)level, copy, (size_t)len);
  if (rv != 0) {
    free(copy);
  }
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

  return ngtcp2_crypto_derive_and_install_rx_key(
           qc->conn, NULL, NULL, NULL, (ngtcp2_encryption_level)level, rx,
           (size_t)rx_len) != 0 ||
             ngtcp2_crypto_derive_and_install_tx_key(
               qc->conn, NULL, NULL, NULL, (ngtcp2_encryption_level)level, tx,
               (size_t)tx_len) != 0
           ? NGTCP2_ERR_CALLBACK_FAILURE
           : 0;
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

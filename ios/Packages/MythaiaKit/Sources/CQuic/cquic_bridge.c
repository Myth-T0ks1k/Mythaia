/*
 * cquic_bridge.c
 * Mythaia
 *
 * A QUIC connection, as much of one as belongs in C.
 *
 * ngtcp2 is a state machine, not a socket: it is fed the datagrams that
 * arrived, asked for the datagrams to send, and told when its timer expired.
 * Everything around that — the UDP socket, the event loop, the TLS handshake —
 * is the Swift side's job, so this file is the translation layer: a handle, a
 * set of entry points, and callbacks going back up through a `void *user`.
 *
 * The handshake deliberately does *not* live here. ngtcp2 asks its embedder for
 * TLS through `client_initial` and `recv_crypto_data`, and answering those from
 * C would mean a second TLS implementation next to the Swift one this app
 * already has. Instead both callbacks hand the bytes up, and Swift submits the
 * replies and installs the keys through the entry points below.
 *
 * Derived in structure from the Anywhere reference implementation (GPL-3.0),
 * Copyright (C) 2026 NodePassProject.
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

/* derive_and_install_initial_key is declared in the crypto helper's own
   header, not the public one. */
#include "shared.h"

#include "cquic.h"

struct cquic_conn {
  ngtcp2_crypto_conn_ref conn_ref; /* must stay first: ngtcp2 casts to it */
  ngtcp2_conn *conn;

  cquic_callbacks callbacks;

  struct sockaddr_storage local_addr;
  struct sockaddr_storage remote_addr;
  ngtcp2_socklen local_len;
  ngtcp2_socklen remote_len;

  uint8_t out[CQUIC_MAX_DATAGRAM];
};

/* ------------------------------------------------------------------------- */
/* Helpers                                                                    */
/* ------------------------------------------------------------------------- */

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *ref) {
  return ((cquic_conn *)ref)->conn;
}

/* CLOCK_MONOTONIC keeps counting while the device sleeps, which is what the
   idle and loss timers measure against; every timestamp ngtcp2 sees comes
   from here, and cquic_conn_expiry_delay hands back differences of it. */
static uint64_t timestamp_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * NGTCP2_SECONDS + (uint64_t)ts.tv_nsec;
}

static void bridge_log(cquic_conn *qc, const char *format, ...) {
  if (qc == NULL || qc->callbacks.log == NULL) {
    return;
  }
  char line[320];
  va_list args;
  va_start(args, format);
  vsnprintf(line, sizeof(line), format, args);
  va_end(args);
  qc->callbacks.log(qc->callbacks.user, line);
}

static void fill_path(cquic_conn *qc, ngtcp2_path *path) {
  path->local.addr = (struct sockaddr *)&qc->local_addr;
  path->local.addrlen = qc->local_len;
  path->remote.addr = (struct sockaddr *)&qc->remote_addr;
  path->remote.addrlen = qc->remote_len;
  path->user_data = NULL;
}

/* -------------------------------------------------------------------------
 * Encryption levels
 *
 * The bridge names three levels and this maps them onto ngtcp2's enum. They
 * are translated rather than cast because the enum has been renumbered before:
 * `ngtcp2_crypto_level` ordered them initial, early, handshake, app, and
 * `ngtcp2_encryption_level` orders them initial, handshake, 1-RTT, 0-RTT. A
 * cast that silently survived that change installs handshake keys as 1-RTT
 * keys, and nothing reports it.
 * ------------------------------------------------------------------------- */

static int to_ngtcp2_level(int level, ngtcp2_encryption_level *out) {
  switch (level) {
  case CQUIC_LEVEL_INITIAL:
    *out = NGTCP2_ENCRYPTION_LEVEL_INITIAL;
    return 0;
  case CQUIC_LEVEL_HANDSHAKE:
    *out = NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE;
    return 0;
  case CQUIC_LEVEL_APPLICATION:
    *out = NGTCP2_ENCRYPTION_LEVEL_1RTT;
    return 0;
  default:
    return -1;
  }
}

static int from_ngtcp2_level(ngtcp2_encryption_level level) {
  switch (level) {
  case NGTCP2_ENCRYPTION_LEVEL_INITIAL:
    return CQUIC_LEVEL_INITIAL;
  case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
    return CQUIC_LEVEL_HANDSHAKE;
  case NGTCP2_ENCRYPTION_LEVEL_1RTT:
    return CQUIC_LEVEL_APPLICATION;
  default:
    return -2; /* 0-RTT, which this client never offers. */
  }
}

static ngtcp2_cc_algo to_ngtcp2_cc(int algo) {
  switch (algo) {
  case CQUIC_CC_RENO:
    return NGTCP2_CC_ALGO_RENO;
  case CQUIC_CC_BBR:
    return NGTCP2_CC_ALGO_BBR;
  default:
    return NGTCP2_CC_ALGO_CUBIC;
  }
}

/* ------------------------------------------------------------------------- */
/* ngtcp2 callbacks                                                           */
/* ------------------------------------------------------------------------- */

/* The handshake starts. Swift is asked for the ClientHello; it comes back
   through cquic_conn_submit_crypto before this returns, so the connection has
   something to put in its first Initial packet. */
static int on_client_initial(ngtcp2_conn *conn, void *user_data) {
  cquic_conn *qc = (cquic_conn *)user_data;

  /* Replacing ngtcp2's own client_initial callback means taking on what it
     did. Deriving the Initial keys is the part that is easy to miss and fatal
     to miss: without them conn->in_pktns->crypto.tx.ckm stays NULL, and the
     very first Initial packet dereferences it while building its nonce. The
     assert that would catch it is compiled out of a release build. */
  if (ngtcp2_crypto_derive_and_install_initial_key(
        conn, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        ngtcp2_conn_get_client_chosen_version2(conn),
        ngtcp2_conn_get_dcid2(conn)) != 0) {
    bridge_log(qc, "could not install the Initial keys");
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }

  if (qc->callbacks.crypto_data == NULL) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  /* A NULL payload means "there is no data, produce the first flight". */
  if (qc->callbacks.crypto_data(qc->callbacks.user, CQUIC_LEVEL_INITIAL, NULL,
                                0) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

/* Handshake bytes arrived at some encryption level. They are handed up
   verbatim; the TLS state machine is Swift's. */
static int on_recv_crypto_data(ngtcp2_conn *conn,
                               ngtcp2_encryption_level level, uint64_t offset,
                               const uint8_t *data, size_t datalen,
                               void *user_data) {
  cquic_conn *qc = (cquic_conn *)user_data;
  (void)conn;
  (void)offset;

  int app_level = from_ngtcp2_level(level);
  if (app_level < 0) {
    /* 0-RTT, which this client never offers, so there is nothing to hand up. */
    return 0;
  }
  if (qc->callbacks.crypto_data == NULL) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  if (qc->callbacks.crypto_data(qc->callbacks.user, app_level, data, datalen) !=
      0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int on_recv_stream_data(ngtcp2_conn *conn, uint32_t flags,
                               int64_t stream_id, uint64_t offset,
                               const uint8_t *data, size_t datalen,
                               void *user_data, void *stream_user_data) {
  cquic_conn *qc = (cquic_conn *)user_data;
  (void)conn;
  (void)offset;
  (void)stream_user_data;

  if (qc->callbacks.stream_data == NULL) {
    return 0;
  }
  int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) ? 1 : 0;
  if (qc->callbacks.stream_data(qc->callbacks.user, stream_id, data, datalen,
                                fin) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

static int on_stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id,
                           uint64_t app_error_code, void *user_data,
                           void *stream_user_data) {
  cquic_conn *qc = (cquic_conn *)user_data;
  (void)conn;
  (void)flags;
  (void)stream_user_data;

  if (qc->callbacks.stream_close != NULL) {
    qc->callbacks.stream_close(qc->callbacks.user, stream_id, app_error_code);
  }
  return 0;
}

/*
 * A peer reset the receiving side of a stream (RESET_STREAM).
 *
 * stream_close fires only once both sides are shut, so a bare RESET_STREAM
 * with no STOP_SENDING would otherwise never reach Swift and a reader would
 * hang forever. This hands the reset up so the stream can fail its receive.
 */
static int on_stream_reset(ngtcp2_conn *conn, int64_t stream_id,
                           uint64_t final_size, uint64_t app_error_code,
                           void *user_data, void *stream_user_data) {
  cquic_conn *qc = (cquic_conn *)user_data;
  (void)conn;
  (void)final_size;
  (void)stream_user_data;

  if (qc->callbacks.stream_reset != NULL) {
    qc->callbacks.stream_reset(qc->callbacks.user, stream_id, app_error_code);
  }
  return 0;
}

/*
 * A DATAGRAM frame arrived.
 *
 * QUIC datagrams are unreliable and unordered by design — they are not a
 * stream, and nothing retransmits them. TUIC uses them for heartbeats and for
 * its native UDP relay mode, Hysteria2 for all of its UDP, where losing one is
 * exactly what UDP means.
 */
static int on_recv_datagram(ngtcp2_conn *conn, uint32_t flags,
                            const uint8_t *data, size_t datalen,
                            void *user_data) {
  cquic_conn *qc = (cquic_conn *)user_data;
  (void)conn;
  (void)flags;

  if (qc->callbacks.datagram != NULL) {
    qc->callbacks.datagram(qc->callbacks.user, data, datalen);
  }
  return 0;
}

static int on_handshake_completed(ngtcp2_conn *conn, void *user_data) {
  cquic_conn *qc = (cquic_conn *)user_data;
  (void)conn;

  if (qc->callbacks.handshake_completed != NULL) {
    qc->callbacks.handshake_completed(qc->callbacks.user);
  }
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

static int fill_sockaddr(const uint8_t *addr, size_t addr_len, uint16_t port,
                         struct sockaddr_storage *out, ngtcp2_socklen *len) {
  memset(out, 0, sizeof(*out));
  if (addr_len == 16) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = htons(port);
    memcpy(&sin6->sin6_addr, addr, 16);
#ifdef __APPLE__
    sin6->sin6_len = sizeof(struct sockaddr_in6);
#endif
    *len = sizeof(struct sockaddr_in6);
    return 0;
  }
  if (addr_len == 4) {
    struct sockaddr_in *sin = (struct sockaddr_in *)out;
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    memcpy(&sin->sin_addr, addr, 4);
#ifdef __APPLE__
    sin->sin_len = sizeof(struct sockaddr_in);
#endif
    *len = sizeof(struct sockaddr_in);
    return 0;
  }
  return -1;
}

cquic_conn *cquic_conn_new(const uint8_t *remote_addr, size_t remote_addr_len,
                           uint16_t remote_port, const uint8_t *local_addr,
                           size_t local_addr_len, uint16_t local_port,
                           const cquic_settings *values,
                           const cquic_callbacks *callbacks) {
  if (remote_addr == NULL || local_addr == NULL || values == NULL ||
      callbacks == NULL || remote_addr_len != local_addr_len) {
    return NULL;
  }

  cquic_conn *qc = calloc(1, sizeof(cquic_conn));
  if (qc == NULL) {
    return NULL;
  }
  if (fill_sockaddr(remote_addr, remote_addr_len, remote_port,
                    &qc->remote_addr, &qc->remote_len) != 0 ||
      fill_sockaddr(local_addr, local_addr_len, local_port, &qc->local_addr,
                    &qc->local_len) != 0) {
    free(qc);
    return NULL;
  }
  qc->callbacks = *callbacks;

  ngtcp2_cid dcid, scid;
  dcid.datalen = 18;
  arc4random_buf(dcid.data, dcid.datalen);
  scid.datalen = 17;
  arc4random_buf(scid.data, scid.datalen);

  ngtcp2_callbacks cb;
  memset(&cb, 0, sizeof(cb));
  cb.client_initial = on_client_initial;
  cb.recv_crypto_data = on_recv_crypto_data;
  cb.encrypt = ngtcp2_crypto_encrypt_cb;
  cb.decrypt = ngtcp2_crypto_decrypt_cb;
  cb.hp_mask = ngtcp2_crypto_hp_mask_cb;
  cb.recv_retry = ngtcp2_crypto_recv_retry_cb;
  cb.update_key = ngtcp2_crypto_update_key_cb;
  cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  cb.get_path_challenge_data2 = on_get_path_challenge_data;
  cb.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
  cb.recv_stream_data = on_recv_stream_data;
  cb.stream_close = on_stream_close;
  cb.stream_reset = on_stream_reset;
  cb.handshake_completed = on_handshake_completed;
  cb.rand = on_rand;
  cb.get_new_connection_id = on_get_new_connection_id;
  cb.recv_datagram = on_recv_datagram;

  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);
  settings.initial_ts = timestamp_ns();
  /* The ceiling, not the starting point. Shaping stays on so ngtcp2 begins at
     the 1200 bytes every path must carry and grows towards this through PMTU
     discovery — forcing the ceiling from the first packet makes the Initial
     datagram undeliverable on any path with a smaller MTU, and there is no
     fallback once it has been ruled out. */
  settings.max_tx_udp_payload_size = CQUIC_MAX_DATAGRAM;

  /* Hysteria's Brutal is not an ngtcp2 algorithm; the Swift side maps it to
     BBR before it reaches here. */
  settings.cc_algo = to_ngtcp2_cc(values->cc_algo);
  /* The ceilings flow-control window auto-tuning may grow to. A nonzero value
     turns auto-tuning on, starting from the initial_max_* below and scaling
     up; zero leaves it off. */
  settings.max_window = values->max_window;
  settings.max_stream_window = values->max_stream_window;
  /* How long the handshake may take. Zero leaves the library default (no
     deadline); a real value abandons a handshake that stalls, which a
     filtered path can do silently. */
  if (values->handshake_timeout_ns > 0) {
    settings.handshake_timeout = (ngtcp2_duration)values->handshake_timeout_ns;
  }

  /* The limits come from the caller's tuning rather than being fixed here:
     HTTP/3 requires the server to open a control stream, so a profile for it
     must grant unidirectional credit, while a plain tunnel grants none and
     treats an attempt as a connection error. */
  ngtcp2_transport_params params;
  ngtcp2_transport_params_default(&params);
  params.initial_max_data = values->initial_max_data;
  params.initial_max_stream_data_bidi_local =
    values->initial_max_stream_data_bidi_local;
  params.initial_max_stream_data_bidi_remote =
    values->initial_max_stream_data_bidi_remote;
  params.initial_max_stream_data_uni = values->initial_max_stream_data_uni;
  params.initial_max_streams_bidi = values->initial_max_streams_bidi;
  params.initial_max_streams_uni = values->initial_max_streams_uni;
  params.max_idle_timeout = (ngtcp2_duration)values->max_idle_timeout_ns;
  params.active_connection_id_limit = 4;
  /* Without this the peer may not send DATAGRAM frames at all — the extension
     is opt-in per direction, and a zero here disables it silently. */
  params.max_datagram_frame_size = CQUIC_MAX_DATAGRAM;

  ngtcp2_path path;
  fill_path(qc, &path);

  qc->conn_ref.get_conn = get_conn;
  qc->conn_ref.user_data = qc;

  int rv = ngtcp2_conn_client_new(&qc->conn, &dcid, &scid, &path,
                                  NGTCP2_PROTO_VER_V1, &cb, &settings, &params,
                                  NULL, qc);
  if (rv != 0) {
    bridge_log(qc, "ngtcp2_conn_client_new failed: %s", ngtcp2_strerror(rv));
    free(qc);
    return NULL;
  }

  /* Keep-alive: ngtcp2 takes this only after the connection object exists,
     not through settings. A nonzero value sends a PING once the connection
     has been idle that long, which is what keeps a server from dropping the
     session on its own idle timer between flows. */
  if (values->keep_alive_timeout_ns > 0) {
    ngtcp2_conn_set_keep_alive_timeout(
      qc->conn, (ngtcp2_duration)values->keep_alive_timeout_ns);
  }

  /* The TLS native handle is deliberately left unset until the cipher suite is
     known. This backend does not point it at a TLS object — there is no C-side
     TLS object — it reads it back as the negotiated suite, so setting it to
     anything else makes ngtcp2_crypto_ctx_tls return NULL and every key
     installation fail. See cquic_conn_set_cipher_suite. */
  return qc;
}

void cquic_conn_free(cquic_conn *qc) {
  if (qc == NULL) {
    return;
  }
  if (qc->conn != NULL) {
    ngtcp2_conn_del(qc->conn);
    qc->conn = NULL;
  }
  free(qc);
}

const uint8_t *cquic_conn_out(const cquic_conn *qc) {
  return qc == NULL ? NULL : qc->out;
}

/*
 * Builds the CONNECTION_CLOSE packet that tells the peer we are leaving.
 *
 * Writes nothing unless the handshake completed and the connection is not
 * already closing or draining — write_connection_close refuses those states,
 * and there is no peer to tell before a handshake. The application error code
 * is 0 (a clean, reasonless shutdown). Best effort: the caller sends the
 * packet if there is one and frees the connection either way.
 */
int64_t cquic_conn_write_close(cquic_conn *qc) {
  if (qc == NULL || qc->conn == NULL) {
    return 0;
  }
  if (!ngtcp2_conn_get_handshake_completed(qc->conn) ||
      ngtcp2_conn_in_closing_period(qc->conn) ||
      ngtcp2_conn_in_draining_period(qc->conn)) {
    return 0;
  }

  ngtcp2_ccerr ccerr;
  ngtcp2_ccerr_default(&ccerr);
  ngtcp2_ccerr_set_application_error(&ccerr, 0, NULL, 0);

  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);
  ngtcp2_pkt_info pi;

  ngtcp2_ssize written = ngtcp2_conn_write_connection_close(
    qc->conn, &ps.path, &pi, qc->out, sizeof(qc->out), &ccerr, timestamp_ns());
  if (written <= 0) {
    return 0;
  }
  return (int64_t)written;
}

/* ------------------------------------------------------------------------- */
/* Packet I/O                                                                 */
/* ------------------------------------------------------------------------- */

int cquic_conn_read(cquic_conn *qc, const uint8_t *packet, size_t len) {
  if (qc == NULL || qc->conn == NULL) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  ngtcp2_path path;
  fill_path(qc, &path);

  ngtcp2_pkt_info pi;
  memset(&pi, 0, sizeof(pi));

  int rv = ngtcp2_conn_read_pkt(qc->conn, &path, &pi, packet, len,
                                timestamp_ns());

  if (rv < 0 && rv != NGTCP2_ERR_RETRY && rv != NGTCP2_ERR_DROP_CONN) {
    /* The peer's CONNECTION_CLOSE, or our own reason for giving up: without
       this a failed handshake is just "draining" with nothing to go on. */
    char reason[200];
    if (cquic_conn_describe_close(qc, reason, sizeof(reason))) {
      bridge_log(qc, "read_pkt %d: %s", rv, reason);
    } else {
      bridge_log(qc, "read_pkt failed: %s", ngtcp2_strerror(rv));
    }
  }
  return rv;
}

/*
 * The local transport parameters as the ClientHello must carry them.
 *
 * Encoded by ngtcp2 rather than by Swift so the list matches what the
 * connection was created with and carries what only ngtcp2 knows: the
 * initial_source_connection_id, which every peer requires (RFC 9000 18.2)
 * and which a hand-built list left out.
 */
int64_t cquic_conn_local_transport_params(cquic_conn *qc, uint8_t *out,
                                          size_t outlen) {
  if (qc == NULL || qc->conn == NULL || out == NULL) {
    return NGTCP2_ERR_INVALID_STATE;
  }
  ngtcp2_ssize n =
    ngtcp2_conn_encode_local_transport_params2(qc->conn, out, outlen);
  if (n < 0) {
    bridge_log(qc, "encode_local_transport_params failed: %s",
               ngtcp2_strerror((int)n));
  }
  return (int64_t)n;
}

/*
 * The next datagram to send, or 0 when there is nothing.
 *
 * One at a time rather than a batch: ngtcp2 decides how much it may send from
 * its own pacing and congestion state, and the caller loops until this returns
 * 0, which is exactly how the library expects to be drained.
 */
int64_t cquic_conn_write(cquic_conn *qc) {
  if (qc == NULL || qc->conn == NULL) {
    return 0;
  }

  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);
  ngtcp2_pkt_info pi;

  ngtcp2_ssize written = ngtcp2_conn_write_pkt(qc->conn, &ps.path, &pi, qc->out,
                                               sizeof(qc->out), timestamp_ns());
  if (written < 0) {
    bridge_log(qc, "write_pkt: %s", ngtcp2_strerror((int)written));
    return (int64_t)written;
  }
  return (int64_t)written;
}

/*
 * Writes stream data and leaves the datagram it produced in the output buffer.
 *
 * Both halves matter. ngtcp2 serialises a packet into our buffer *and* reports
 * how much of the offered payload went into it, and those are different
 * numbers: returning only the count loses the packet, which then never reaches
 * the wire even though the library has already numbered it and is waiting to
 * have it acknowledged.
 *
 * Taking fewer bytes than offered, or none, is ordinary — flow control and
 * congestion both say so — and the caller offers the remainder again.
 */
int64_t cquic_conn_write_stream(cquic_conn *qc, int64_t stream_id,
                                const uint8_t *data, size_t len, int fin,
                                int64_t *accepted) {
  if (qc == NULL || qc->conn == NULL) {
    if (accepted != NULL) {
      *accepted = NGTCP2_ERR_INVALID_STATE;
    }
    return 0;
  }

  ngtcp2_vec vec;
  vec.base = (uint8_t *)data;
  vec.len = len;

  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);
  ngtcp2_pkt_info pi;

  ngtcp2_ssize taken = 0;
  /* No WRITE_MORE: nothing here coalesces several streams into one packet,
     which is its only purpose, and it would leave ngtcp2 mid-packet waiting
     for a resume call with the same timestamp. */
  uint32_t flags =
    fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : NGTCP2_WRITE_STREAM_FLAG_NONE;

  ngtcp2_ssize written = ngtcp2_conn_writev_stream(
    qc->conn, &ps.path, &pi, qc->out, sizeof(qc->out), &taken, flags,
    stream_id, len > 0 ? &vec : NULL, len > 0 ? 1 : 0, timestamp_ns());

  if (accepted != NULL) {
    /* What the caller does next turns on this one number, so the three cases
       are kept distinct rather than all collapsed to zero:
         >= 0  a STREAM frame carrying that many bytes went in (0 with the FIN
               flag means the empty FIN went); offer any remainder again.
         -1    nothing fit this tick — congestion, pacing, a packet full of
               other frames, or a flow-control block; offer the same bytes
               again. STREAM_DATA_BLOCKED is this, not a failure.
         <= -2 terminal: the stream is gone, shut for writing, or the
               connection is closing/draining.
       `written == 0` always means nothing was written, whatever `taken`
       holds — ngtcp2 may leave it untouched — so it maps to -1 even for an
       empty FIN, which is why a FIN is offered until it goes. */
    int64_t reported;
    if (written > 0) {
      reported = taken < 0 ? CQUIC_WRITE_AGAIN : (int64_t)taken;
    } else if (written == 0) {
      reported = CQUIC_WRITE_AGAIN;
    } else if (written == NGTCP2_ERR_WRITE_MORE ||
               written == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
      reported = CQUIC_WRITE_AGAIN;
    } else {
      /* STREAM_NOT_FOUND, STREAM_SHUT_WR, CLOSING, DRAINING, NOMEM,
         CALLBACK_FAILURE, PKT_NUM_EXHAUSTED, … — all far below -1. */
      reported = (int64_t)written;
    }
    *accepted = reported;
  }

  if (written <= 0) {
    if (written < 0 && written != NGTCP2_ERR_STREAM_DATA_BLOCKED &&
        written != NGTCP2_ERR_STREAM_SHUT_WR &&
        written != NGTCP2_ERR_WRITE_MORE) {
      bridge_log(qc, "writev_stream: %s", ngtcp2_strerror((int)written));
    }
    return 0;
  }
  return (int64_t)written;
}

/*
 * Offers one QUIC datagram to ngtcp2 and leaves the packet it built, if any, in
 * the output buffer.
 *
 * A packet can come back with status 0: ngtcp2 may fill it with other frames
 * (ACKs, retransmissions) and leave the datagram out. That packet is already
 * numbered and must go on the wire. Dropping it made the server see its ACKs
 * lost, so it cut its own sending rate and queued replies: voice over
 * Hysteria2 and TUIC lost packets and gained hundreds of milliseconds of delay.
 */
int64_t cquic_conn_write_datagram(cquic_conn *qc, const uint8_t *data,
                                  size_t len, int *status) {
  if (qc == NULL || qc->conn == NULL) {
    if (status != NULL) {
      *status = NGTCP2_ERR_INVALID_STATE;
    }
    return 0;
  }

  ngtcp2_vec vec;
  vec.base = (uint8_t *)data;
  vec.len = len;

  ngtcp2_path_storage ps;
  ngtcp2_path_storage_zero(&ps);
  ngtcp2_pkt_info pi;
  int accepted = 0;

  ngtcp2_ssize written = ngtcp2_conn_writev_datagram(
    qc->conn, &ps.path, &pi, qc->out, sizeof(qc->out), &accepted,
    NGTCP2_WRITE_DATAGRAM_FLAG_NONE, 0, &vec, 1, timestamp_ns());

  if (status != NULL) {
    *status = written < 0 ? (int)written : (accepted ? 1 : 0);
  }
  if (written <= 0) {
    return 0;
  }
  return (int64_t)written;
}

/*
 * Tells ngtcp2 the send burst is over, so it can pace the next one.
 *
 * Without this `pacing_interval_m` is never consulted and every window is sent
 * as fast as the socket will take it, which is what congestion control exists
 * to avoid.
 */
void cquic_conn_flush_done(cquic_conn *qc) {
  if (qc == NULL || qc->conn == NULL) {
    return;
  }
  ngtcp2_conn_update_pkt_tx_time(qc->conn, timestamp_ns());
}

int64_t cquic_conn_expiry_delay(cquic_conn *qc) {
  if (qc == NULL || qc->conn == NULL) {
    return -1;
  }
  ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(qc->conn);
  if (expiry == UINT64_MAX) {
    return -1;
  }
  uint64_t now = timestamp_ns();
  if (expiry <= now) {
    return 0;
  }
  uint64_t delay = expiry - now;
  return delay > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)delay;
}

int cquic_conn_handle_expiry(cquic_conn *qc) {
  if (qc == NULL || qc->conn == NULL) {
    return NGTCP2_ERR_INVALID_STATE;
  }
  int rv = ngtcp2_conn_handle_expiry(qc->conn, timestamp_ns());
  if (rv < 0) {
    char reason[200];
    if (cquic_conn_describe_close(qc, reason, sizeof(reason))) {
      bridge_log(qc, "handle_expiry %d: %s", rv, reason);
    }
  }
  return rv;
}

/* ------------------------------------------------------------------------- */
/* Handshake, driven from Swift                                               */
/* ------------------------------------------------------------------------- */

/*
 * Tells the connection which cipher suite the handshake settled on.
 *
 * The crypto backend carries the suite *as* the TLS native handle: an integer
 * where another backend would put a pointer to its TLS object. Nothing can be
 * encrypted before this is set, and the key-installation helpers read it back
 * on every call, so it must land as soon as the ServerHello names it.
 */
int cquic_conn_set_cipher_suite(cquic_conn *qc, int suite) {
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

int cquic_conn_submit_crypto(cquic_conn *qc, int level, const uint8_t *data,
                             size_t len) {
  if (qc == NULL || qc->conn == NULL) {
    return NGTCP2_ERR_INVALID_STATE;
  }

  ngtcp2_encryption_level target;
  if (to_ngtcp2_level(level, &target) != 0) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  /* ngtcp2 copies the bytes into its own buffer chain (conn_buffer_crypto_data
     ends in ngtcp2_cpymem), so nothing here has to outlive the call. */
  return ngtcp2_conn_submit_crypto_data(qc->conn, target, data, len);
}

int cquic_conn_install_keys(cquic_conn *qc, int level, const uint8_t *rx_secret,
                            size_t rx_len, const uint8_t *tx_secret,
                            size_t tx_len) {
  if (qc == NULL || qc->conn == NULL) {
    return NGTCP2_ERR_INVALID_STATE;
  }
  if (rx_secret == NULL || tx_secret == NULL || rx_len == 0 || tx_len == 0 ||
      rx_len > 64 || tx_len > 64) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  ngtcp2_encryption_level target;
  if (to_ngtcp2_level(level, &target) != 0) {
    return NGTCP2_ERR_INVALID_ARGUMENT;
  }

  /* The traffic secrets, not expanded keys: these helpers run the `quic key`,
     `quic iv` and `quic hp` expansions themselves. */
  if (ngtcp2_crypto_derive_and_install_rx_key(qc->conn, NULL, NULL, NULL,
                                              target, rx_secret, rx_len) != 0) {
    bridge_log(qc, "could not install the rx key at level %d", level);
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  if (ngtcp2_crypto_derive_and_install_tx_key(qc->conn, NULL, NULL, NULL,
                                              target, tx_secret, tx_len) != 0) {
    bridge_log(qc, "could not install the tx key at level %d", level);
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

/*
 * Hands the peer's transport parameters to ngtcp2.
 *
 * Decoding them in Swift is for diagnostics; these are the values ngtcp2
 * enforces, and without this it keeps its own conservative defaults — the
 * peer's stream and flow-control limits are simply never learned.
 */
int cquic_conn_set_remote_params(cquic_conn *qc, const uint8_t *params,
                                 size_t len) {
  if (qc == NULL || qc->conn == NULL) {
    return NGTCP2_ERR_INVALID_STATE;
  }
  return ngtcp2_conn_decode_and_set_remote_transport_params(qc->conn, params,
                                                            len);
}

/*
 * Tells ngtcp2 the TLS handshake finished.
 *
 * Only ever after the server's Finished and certificate have been verified:
 * this is what promotes the connection to carrying application data, and
 * calling it earlier promotes one that has proved nothing.
 */
void cquic_conn_handshake_completed(cquic_conn *qc) {
  if (qc == NULL || qc->conn == NULL) {
    return;
  }
  ngtcp2_conn_tls_handshake_completed(qc->conn);
}

int cquic_conn_is_handshake_completed(cquic_conn *qc) {
  if (qc == NULL || qc->conn == NULL) {
    return 0;
  }
  return ngtcp2_conn_get_handshake_completed(qc->conn);
}

/* ------------------------------------------------------------------------- */
/* Streams                                                                    */
/* ------------------------------------------------------------------------- */

int64_t cquic_conn_open_bidi_stream(cquic_conn *qc) {
  if (qc == NULL || qc->conn == NULL) {
    return NGTCP2_ERR_INVALID_STATE;
  }
  int64_t stream_id = -1;
  int rv = ngtcp2_conn_open_bidi_stream(qc->conn, &stream_id, NULL);
  return rv == 0 ? stream_id : (int64_t)rv;
}

int64_t cquic_conn_open_uni_stream(cquic_conn *qc) {
  if (qc == NULL || qc->conn == NULL) {
    return NGTCP2_ERR_INVALID_STATE;
  }
  int64_t stream_id = -1;
  int rv = ngtcp2_conn_open_uni_stream(qc->conn, &stream_id, NULL);
  return rv == 0 ? stream_id : (int64_t)rv;
}

void cquic_conn_shutdown_stream(cquic_conn *qc, int64_t stream_id,
                                uint64_t error_code) {
  if (qc == NULL || qc->conn == NULL) {
    return;
  }
  ngtcp2_conn_shutdown_stream(qc->conn, 0, stream_id, error_code);
}

/*
 * Tells the peer we have consumed `count` bytes of a stream.
 *
 * Without this the peer's flow-control window closes and the transfer stalls
 * partway through with no error anywhere.
 */
void cquic_conn_extend_offsets(cquic_conn *qc, int64_t stream_id,
                               uint64_t count) {
  if (qc == NULL || qc->conn == NULL || count == 0) {
    return;
  }
  ngtcp2_conn_extend_max_stream_offset(qc->conn, stream_id, count);
  ngtcp2_conn_extend_max_offset(qc->conn, count);
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
int cquic_conn_max_datagram_payload(cquic_conn *qc) {
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
  return room > 16000 ? 16000 : (int)room;
}

int cquic_conn_describe_close(cquic_conn *qc, char *buf, size_t buflen) {
  if (qc == NULL || qc->conn == NULL || buf == NULL || buflen == 0) {
    return 0;
  }
  const ngtcp2_ccerr *ce = ngtcp2_conn_get_ccerr(qc->conn);
  if (ce == NULL) {
    return 0;
  }
  const char *kind;
  switch (ce->type) {
  case NGTCP2_CCERR_TYPE_TRANSPORT:
    kind = "transport";
    break;
  case NGTCP2_CCERR_TYPE_APPLICATION:
    kind = "application";
    break;
  case NGTCP2_CCERR_TYPE_VERSION_NEGOTIATION:
    kind = "version negotiation";
    break;
  case NGTCP2_CCERR_TYPE_IDLE_CLOSE:
    kind = "idle";
    break;
  default:
    kind = "other";
    break;
  }
  int reasonlen = (int)(ce->reasonlen > 120 ? 120 : ce->reasonlen);
  snprintf(buf, buflen, "%s close, code 0x%llx, frame 0x%llx%s%.*s", kind,
           (unsigned long long)ce->error_code,
           (unsigned long long)ce->frame_type, reasonlen > 0 ? ": " : "",
           reasonlen, ce->reason == NULL ? "" : (const char *)ce->reason);
  return 1;
}

/*
 * ngtcp2_conn_get_ccerr reports the CONNECTION_CLOSE received from the peer;
 * when none arrived it holds ngtcp2_ccerr_default, a transport close with
 * NO_ERROR, which is reported as no close at all.
 */
int cquic_conn_close_error(cquic_conn *qc, uint64_t *code) {
  if (code != NULL) {
    *code = 0;
  }
  if (qc == NULL || qc->conn == NULL) {
    return CQUIC_CLOSE_NONE;
  }
  const ngtcp2_ccerr *ce = ngtcp2_conn_get_ccerr(qc->conn);
  if (ce == NULL) {
    return CQUIC_CLOSE_NONE;
  }
  if (code != NULL) {
    *code = ce->error_code;
  }
  switch (ce->type) {
  case NGTCP2_CCERR_TYPE_TRANSPORT:
    return ce->error_code == NGTCP2_NO_ERROR && ce->reasonlen == 0
             ? CQUIC_CLOSE_NONE
             : CQUIC_CLOSE_TRANSPORT;
  case NGTCP2_CCERR_TYPE_APPLICATION:
    return CQUIC_CLOSE_APPLICATION;
  case NGTCP2_CCERR_TYPE_VERSION_NEGOTIATION:
    return CQUIC_CLOSE_VERSION_NEGOTIATION;
  case NGTCP2_CCERR_TYPE_IDLE_CLOSE:
    return CQUIC_CLOSE_IDLE;
  default:
    return CQUIC_CLOSE_OTHER;
  }
}

int cquic_error_kind(int code) {
  switch (code) {
  case NGTCP2_ERR_HANDSHAKE_TIMEOUT:
    return CQUIC_ERROR_HANDSHAKE_TIMEOUT;
  case NGTCP2_ERR_IDLE_CLOSE:
    return CQUIC_ERROR_IDLE_CLOSE;
  case NGTCP2_ERR_CLOSING:
    return CQUIC_ERROR_CLOSING;
  case NGTCP2_ERR_DRAINING:
    return CQUIC_ERROR_DRAINING;
  default:
    return CQUIC_ERROR_OTHER;
  }
}

const char *cquic_strerror(int code) { return ngtcp2_strerror(code); }

int cquic_err_is_fatal(int code) { return ngtcp2_err_is_fatal(code); }

const char *cquic_version(void) { return ngtcp2_version(0)->version_str; }

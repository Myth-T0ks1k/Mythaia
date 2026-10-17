/*
 * cquic.h
 * Mythaia
 *
 * A QUIC connection, as much of one as belongs in C.
 *
 * ngtcp2 is a state machine, not a socket: it is fed the datagrams that
 * arrived, asked for the datagrams to send, and told when its timer expired.
 * The UDP socket, the event loop and the TLS handshake are the Swift side's
 * job; this header is the line between the two. It deliberately includes no
 * ngtcp2 header, so the Swift module that imports it needs none of the
 * vendored include paths.
 *
 * Threading: a connection is not thread-safe. Every call on one handle must
 * come from the same serial context, and the callbacks below run inside those
 * calls, on that context, before the call returns.
 *
 * The packet a call builds lands in the connection's own output buffer
 * (cquic_conn_out); it stays valid until the next call on the same handle.
 */

#ifndef CQUIC_H
#define CQUIC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Encryption levels in the bridge's own numbering, translated to ngtcp2's
 * enum in C. Not ngtcp2's raw values: that enum has been renumbered once
 * already (ngtcp2_crypto_level ordered them initial, early, handshake, app),
 * and a constant that silently survived the change installs handshake keys as
 * 1-RTT keys with nothing to show for it.
 */
#define CQUIC_LEVEL_INITIAL 0
#define CQUIC_LEVEL_HANDSHAKE 1
#define CQUIC_LEVEL_APPLICATION 2

/* Congestion controllers, translated to ngtcp2_cc_algo in C. */
#define CQUIC_CC_RENO 0
#define CQUIC_CC_CUBIC 1
#define CQUIC_CC_BBR 2

/* cquic_conn_write_stream's `accepted`: nothing fit this time, offer again. */
#define CQUIC_WRITE_AGAIN (-1)

/* The largest datagram ngtcp2 is allowed to build. */
#define CQUIC_MAX_DATAGRAM 1452

typedef struct cquic_conn cquic_conn;

/*
 * What ngtcp2 tells the Swift side. `user` is handed back unchanged to every
 * callback; no pointer passed to a callback outlives it.
 *
 * crypto_data: handshake bytes at `level`. A NULL `data` asks for the first
 *   flight (the ClientHello), which must be submitted before the callback
 *   returns. Nonzero fails the connection.
 * stream_data: payload on a stream; `fin` is nonzero on its last bytes.
 *   Nonzero fails the connection.
 * stream_close: both sides of a stream are done.
 * stream_reset: the peer reset the receiving side (RESET_STREAM).
 * handshake_completed: the handshake is confirmed from ngtcp2's side.
 * datagram: an unreliable DATAGRAM frame arrived.
 * log: a line worth logging; optional.
 */
typedef struct cquic_callbacks {
  void *user;
  int (*crypto_data)(void *user, int level, const uint8_t *data,
                     size_t datalen);
  int (*stream_data)(void *user, int64_t stream_id, const uint8_t *data,
                     size_t datalen, int fin);
  void (*stream_close)(void *user, int64_t stream_id, uint64_t app_error_code);
  void (*stream_reset)(void *user, int64_t stream_id, uint64_t app_error_code);
  void (*handshake_completed)(void *user);
  void (*datagram)(void *user, const uint8_t *data, size_t datalen);
  void (*log)(void *user, const char *message);
} cquic_callbacks;

/*
 * The transport limits and engine settings a connection is created with.
 * The first seven are transport parameters the peer is told; the rest are
 * local engine settings the peer never sees. Durations are nanoseconds; a
 * zero timeout or window leaves the library default.
 */
typedef struct cquic_settings {
  uint64_t initial_max_data;
  uint64_t initial_max_stream_data_bidi_local;
  uint64_t initial_max_stream_data_bidi_remote;
  uint64_t initial_max_stream_data_uni;
  uint64_t initial_max_streams_bidi;
  uint64_t initial_max_streams_uni;
  uint64_t max_idle_timeout_ns;
  int cc_algo;
  uint64_t max_window;
  uint64_t max_stream_window;
  uint64_t handshake_timeout_ns;
  uint64_t keep_alive_timeout_ns;
} cquic_settings;

/*
 * A client connection. Addresses are raw IPv4 (4 bytes) or IPv6 (16 bytes);
 * the local and remote families must match. NULL on failure.
 */
cquic_conn *cquic_conn_new(const uint8_t *remote_addr, size_t remote_addr_len,
                           uint16_t remote_port, const uint8_t *local_addr,
                           size_t local_addr_len, uint16_t local_port,
                           const cquic_settings *settings,
                           const cquic_callbacks *callbacks);

void cquic_conn_free(cquic_conn *qc);

/* The connection's output buffer, where the last built packet is. */
const uint8_t *cquic_conn_out(const cquic_conn *qc);

/*
 * The CONNECTION_CLOSE that tells the peer we are leaving, in the output
 * buffer. 0 when there is nobody to tell (no handshake yet, or already
 * closing or draining).
 */
int64_t cquic_conn_write_close(cquic_conn *qc);

/* Feeds one received datagram. 0, or a negative ngtcp2 error. */
int cquic_conn_read(cquic_conn *qc, const uint8_t *packet, size_t len);

/*
 * The local transport parameters as the ClientHello must carry them, encoded
 * by ngtcp2 so they include the initial_source_connection_id. The length, or
 * a negative error.
 */
int64_t cquic_conn_local_transport_params(cquic_conn *qc, uint8_t *out,
                                          size_t outlen);

/* The next datagram to send, in the output buffer: its length, 0 for none. */
int64_t cquic_conn_write(cquic_conn *qc);

/*
 * Writes stream data and builds the packet carrying it, in the output buffer.
 * Returns the packet length (0 when nothing was built). `accepted` receives:
 *   >= 0  that many payload bytes went in (0 with fin: the bare FIN went);
 *   -1    (CQUIC_WRITE_AGAIN) nothing fit this time; offer the same bytes again;
 *   <= -2 terminal: the stream is gone or the connection is closing.
 */
int64_t cquic_conn_write_stream(cquic_conn *qc, int64_t stream_id,
                                const uint8_t *data, size_t len, int fin,
                                int64_t *accepted);

/*
 * Offers one DATAGRAM frame and builds a packet, in the output buffer.
 * `status`: 1 the datagram is in the packet; 0 no room yet, offer it again;
 * negative, it will never fit. A packet can come back with status 0 (other
 * frames filled it), and must be sent all the same.
 */
int64_t cquic_conn_write_datagram(cquic_conn *qc, const uint8_t *data,
                                  size_t len, int *status);

/* The send burst is over, so ngtcp2 can pace the next one. */
void cquic_conn_flush_done(cquic_conn *qc);

/* Nanoseconds until ngtcp2's timer is due (0 when overdue), -1 for none. */
int64_t cquic_conn_expiry_delay(cquic_conn *qc);

/* Runs ngtcp2's timer. 0, or a negative error that ends the connection. */
int cquic_conn_handle_expiry(cquic_conn *qc);

/* The cipher suite the ServerHello named; before any key is installed. */
int cquic_conn_set_cipher_suite(cquic_conn *qc, int suite);

/* Handshake bytes to send at `level`. ngtcp2 copies them. */
int cquic_conn_submit_crypto(cquic_conn *qc, int level, const uint8_t *data,
                             size_t len);

/* The traffic secrets of a level, (rx, tx); ngtcp2 expands them itself. */
int cquic_conn_install_keys(cquic_conn *qc, int level, const uint8_t *rx_secret,
                            size_t rx_len, const uint8_t *tx_secret,
                            size_t tx_len);

/* The peer's quic_transport_parameters extension body. */
int cquic_conn_set_remote_params(cquic_conn *qc, const uint8_t *params,
                                 size_t len);

/* The TLS handshake finished, the server proven; only then. */
void cquic_conn_handshake_completed(cquic_conn *qc);

int cquic_conn_is_handshake_completed(cquic_conn *qc);

/* A new stream's id, or a negative error (no credit). */
int64_t cquic_conn_open_bidi_stream(cquic_conn *qc);
int64_t cquic_conn_open_uni_stream(cquic_conn *qc);

/* Resets a stream in both directions with `error_code`. */
void cquic_conn_shutdown_stream(cquic_conn *qc, int64_t stream_id,
                                uint64_t error_code);

/* Credits `count` consumed bytes back to the stream and the connection. */
void cquic_conn_extend_offsets(cquic_conn *qc, int64_t stream_id,
                               uint64_t count);

/* The largest DATAGRAM payload that fits one packet now; 0 when unknown. */
int cquic_conn_max_datagram_payload(cquic_conn *qc);

/*
 * Why the connection closed, as a line of text, when ngtcp2 knows: the
 * peer's CONNECTION_CLOSE or the local reason. 1 when written, else 0.
 */
int cquic_conn_describe_close(cquic_conn *qc, char *buf, size_t buflen);

/* What a received CONNECTION_CLOSE said. */
#define CQUIC_CLOSE_NONE 0
#define CQUIC_CLOSE_TRANSPORT 1
#define CQUIC_CLOSE_APPLICATION 2
#define CQUIC_CLOSE_VERSION_NEGOTIATION 3
#define CQUIC_CLOSE_IDLE 4
#define CQUIC_CLOSE_OTHER 5

/*
 * The peer's CONNECTION_CLOSE, as a kind and an error code; CQUIC_CLOSE_NONE
 * when none arrived. A transport code 0x100-0x1ff is a TLS alert (0x100 plus
 * the alert), which is how a server refuses a handshake.
 */
int cquic_conn_close_error(cquic_conn *qc, uint64_t *code);

/* How an ngtcp2 error ended things. */
#define CQUIC_ERROR_OTHER 0
#define CQUIC_ERROR_HANDSHAKE_TIMEOUT 1
#define CQUIC_ERROR_IDLE_CLOSE 2
#define CQUIC_ERROR_CLOSING 3
#define CQUIC_ERROR_DRAINING 4

int cquic_error_kind(int code);

const char *cquic_strerror(int code);

/* Whether an error from these calls has ended the connection for good. */
int cquic_err_is_fatal(int code);

/* The vendored ngtcp2's version string. */
const char *cquic_version(void);

/*
 * Drives the crypto backend through RFC 9001 Appendix A and an AEAD round
 * trip. 0 when everything matched; otherwise -1 with the first step that did
 * not in `buf`.
 */
int cquic_self_test(char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* CQUIC_H */

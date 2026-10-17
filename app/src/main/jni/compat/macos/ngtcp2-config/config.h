/*
 * config.h — macOS build configuration for the vendored ngtcp2.
 *
 * desktop/native/macos/CMakeLists.txt puts this directory ahead of ngtcp2/
 * on the include path so that <config.h> resolves here instead of to the
 * Android one. It describes macOS 12+ on arm64 and x86_64, both
 * little-endian; ngtcp2_net.h already has the __APPLE__ branch
 * (libkern/OSByteOrder.h, OSSwapInt64) these switches lead to.
 */

#ifndef NGTCP2_CONFIG_H
#define NGTCP2_CONFIG_H

#define HAVE_ARPA_INET_H 1
#define HAVE_NETINET_IN_H 1
#define HAVE_UNISTD_H 1

/* No <endian.h>, <sys/endian.h> or <byteswap.h> on macOS. */
/* #undef HAVE_ENDIAN_H */
/* #undef HAVE_SYS_ENDIAN_H */
/* #undef HAVE_BYTESWAP_H */
#define HAVE_DECL_BE64TOH 0
#define HAVE_DECL_BSWAP_64 0

/*
 * libc has memset_s, but <string.h> declares it only under
 * __STDC_WANT_LIB_EXT1__, which ngtcp2_str.c does not set. Left undefined,
 * upstream falls back to a memset through a volatile function pointer, which
 * the optimiser may not elide either.
 */
/* #undef HAVE_MEMSET_S */
/* #undef HAVE_EXPLICIT_BZERO */

/* arm64 and x86_64 are little-endian. */
/* #undef WORDS_BIGENDIAN */

/* Brotli is only used by ngtcp2's example tools, which are not vendored. */
/* #undef HAVE_LIBBROTLI */

/* Upstream's assertion and trace output; off in a shipped build. */
/* #undef DEBUGBUILD */

#endif /* NGTCP2_CONFIG_H */

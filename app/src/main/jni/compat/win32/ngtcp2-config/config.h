/*
 * config.h — Windows/MSVC build configuration for the vendored ngtcp2.
 *
 * The desktop CMake puts this directory ahead of ngtcp2/ on the include
 * path so that <config.h> resolves here instead of to the Android one.
 * Everything below describes x64 Windows with the UCRT and Winsock; the
 * ngtcp2 sources themselves already carry the WIN32 branches
 * (_byteswap_uint64, SecureZeroMemory, ws2tcpip.h) that these switches
 * lead to.
 */

#ifndef NGTCP2_CONFIG_H
#define NGTCP2_CONFIG_H

/* No POSIX network headers: ngtcp2.h pulls in ws2tcpip.h under WIN32. */
/* #undef HAVE_ARPA_INET_H */
/* #undef HAVE_NETINET_IN_H */
/* #undef HAVE_UNISTD_H */

/* No <endian.h>, <sys/endian.h> or <byteswap.h>; ngtcp2_net.h then uses
   _byteswap_uint64 on WIN32. */
/* #undef HAVE_ENDIAN_H */
/* #undef HAVE_SYS_ENDIAN_H */
/* #undef HAVE_BYTESWAP_H */
#define HAVE_DECL_BE64TOH 0
#define HAVE_DECL_BSWAP_64 0

/* ngtcp2_str.c uses SecureZeroMemory on WIN32 before it looks at these. */
/* #undef HAVE_MEMSET_S */
/* #undef HAVE_EXPLICIT_BZERO */

/* x64 is little-endian. */
/* #undef WORDS_BIGENDIAN */

/* Brotli is only used by ngtcp2's example tools, which are not vendored. */
/* #undef HAVE_LIBBROTLI */

/* Upstream's assertion and trace output; off in a shipped build. */
/* #undef DEBUGBUILD */

#endif /* NGTCP2_CONFIG_H */

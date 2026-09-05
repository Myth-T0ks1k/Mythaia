/*
 * config.h — Android/bionic build configuration for the vendored ngtcp2.
 *
 * Upstream generates this with autoconf or CMake. We are building the sources
 * directly from a NDK CMakeLists, so it is written by hand; see UPSTREAM_MAP.md
 * for how it is kept in step with an ngtcp2 upgrade.
 *
 * Everything here describes bionic on the ABIs this app ships (arm64-v8a, and
 * the 32-bit and x86_64 ones if they are ever turned on) — all little-endian.
 */

#ifndef NGTCP2_CONFIG_H
#define NGTCP2_CONFIG_H

#define HAVE_ARPA_INET_H 1
#define HAVE_NETINET_IN_H 1
#define HAVE_UNISTD_H 1

/* bionic ships <endian.h> with the be64toh family. */
#define HAVE_ENDIAN_H 1
#define HAVE_DECL_BE64TOH 1

/* No <sys/endian.h> and no <byteswap.h> on bionic. */
/* #undef HAVE_SYS_ENDIAN_H */
/* #undef HAVE_BYTESWAP_H */
#define HAVE_DECL_BSWAP_64 0

/* memset_s is a C11 Annex K function bionic does not provide. */
/* #undef HAVE_MEMSET_S */

/*
 * bionic declares explicit_bzero in <strings.h>, which ngtcp2_str.c does not
 * include — it expects the glibc placement in <string.h>. Rather than patch a
 * stock file, leave this undefined: upstream then falls back to a memset
 * reached through a volatile function pointer, which the optimiser may not
 * elide either. Same guarantee, no divergence from upstream.
 */
/* #undef HAVE_EXPLICIT_BZERO */

/* Every Android ABI this builds for is little-endian. */
/* #undef WORDS_BIGENDIAN */

/* Brotli is only used by ngtcp2's example tools, which are not vendored. */
/* #undef HAVE_LIBBROTLI */

/* Upstream's assertion and trace output; off in a shipped build. */
/* #undef DEBUGBUILD */

#endif /* NGTCP2_CONFIG_H */

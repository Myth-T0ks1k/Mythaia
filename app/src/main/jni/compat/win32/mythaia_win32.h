/*
 * mythaia_win32.h — force-included (cl /FI) into every translation unit of
 * the Windows desktop build that was written against bionic.
 *
 * It exists because two things the bridges rely on cannot be supplied by a
 * header of the same name: <time.h> is a CRT header we must not shadow, and
 * arc4random_buf() lives in bionic's <stdlib.h>. Everything else Windows is
 * missing (<android/log.h>, <arpa/inet.h>, ...) is a real header under
 * compat/win32/ that the include path finds on its own.
 *
 * Nothing in here changes behaviour on Android: this file is never on the
 * NDK build's include path.
 */

#ifndef MYTHAIA_WIN32_H
#define MYTHAIA_WIN32_H

#ifdef _WIN32

/*
 * Only the lean windows.h: with WIN32_LEAN_AND_MEAN it pulls in neither the
 * legacy winsock.h nor wingdi.h (which defines ERROR), and NOMINMAX keeps
 * min/max out of the C sources. Winsock is deliberately NOT included here —
 * this header reaches every lwIP translation unit, and Winsock's
 * `#define s_addr S_un.S_addr` would rewrite lwIP's own identifiers of that
 * name (ip4_addr.c). Code that needs sockets includes <arpa/inet.h> or
 * <sys/socket.h>, whose compat versions bring in winsock2.h/ws2tcpip.h.
 */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef NOGDI
#define NOGDI
#endif
#include <windows.h>
#include <bcrypt.h>

#include <stdint.h>
#include <stdlib.h>
#include <time.h>

/* GCC/clang attributes used by our own headers (compat/os/log.h, the lwIP
   port). MSVC has no equivalent for format-checking, so they drop away. */
#ifndef __attribute__
#define __attribute__(x)
#endif

/* ---------------------------------------------------------------------- */
/* clock_gettime(CLOCK_MONOTONIC) over QueryPerformanceCounter              */
/*                                                                          */
/* The UCRT's <time.h> already declares struct timespec; only the POSIX     */
/* clock API is missing. CLOCK_REALTIME is provided for completeness.       */
/* ---------------------------------------------------------------------- */
#ifndef CLOCK_MONOTONIC
typedef int clockid_t;
#define CLOCK_REALTIME  0
#define CLOCK_MONOTONIC 1

static inline int clock_gettime(clockid_t id, struct timespec *ts) {
  if (id == CLOCK_MONOTONIC) {
    static LARGE_INTEGER freq; /* QPC frequency is fixed after boot */
    LARGE_INTEGER now;
    if (freq.QuadPart == 0) {
      QueryPerformanceFrequency(&freq);
    }
    QueryPerformanceCounter(&now);
    ts->tv_sec = (time_t)(now.QuadPart / freq.QuadPart);
    /* The remainder is < freq, so the scaled value fits in 64 bits for any
       realistic frequency (10 MHz on current Windows). */
    ts->tv_nsec =
      (long)((now.QuadPart % freq.QuadPart) * 1000000000LL / freq.QuadPart);
    return 0;
  }
  if (id == CLOCK_REALTIME) {
    /* 100 ns ticks since 1601-01-01; 116444736000000000 of them to 1970. */
    FILETIME ft;
    ULARGE_INTEGER t;
    GetSystemTimePreciseAsFileTime(&ft);
    t.LowPart = ft.dwLowDateTime;
    t.HighPart = ft.dwHighDateTime;
    t.QuadPart -= 116444736000000000ULL;
    ts->tv_sec = (time_t)(t.QuadPart / 10000000ULL);
    ts->tv_nsec = (long)((t.QuadPart % 10000000ULL) * 100);
    return 0;
  }
  return -1;
}
#endif /* CLOCK_MONOTONIC */

/* ---------------------------------------------------------------------- */
/* arc4random_buf / arc4random over the system CSPRNG                       */
/*                                                                          */
/* bionic's arc4random is kernel-seeded and never fails; BCryptGenRandom    */
/* with the system-preferred RNG is the Windows equivalent. A failure here  */
/* would mean handing QUIC predictable connection IDs, so it aborts rather  */
/* than return weak bytes. Links against bcrypt.lib.                        */
/* ---------------------------------------------------------------------- */
static inline void arc4random_buf(void *buf, size_t n) {
  unsigned char *p = (unsigned char *)buf;
  while (n > 0) {
    ULONG chunk = n > 0x7fffffffUL ? 0x7fffffffUL : (ULONG)n;
    NTSTATUS st =
      BCryptGenRandom(NULL, p, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(st)) {
      abort();
    }
    p += chunk;
    n -= chunk;
  }
}

static inline uint32_t arc4random(void) {
  uint32_t v;
  arc4random_buf(&v, sizeof(v));
  return v;
}

#endif /* _WIN32 */

#endif /* MYTHAIA_WIN32_H */

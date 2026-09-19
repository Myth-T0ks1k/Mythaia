/*
 * sys/time.h — Windows stand-in.
 *
 * Winsock already defines struct timeval. The only POSIX call the tree
 * could want from here is gettimeofday(), which is implemented on top of the
 * CLOCK_REALTIME branch of the clock_gettime shim in mythaia_win32.h.
 */

#ifndef MYTHAIA_COMPAT_SYS_TIME_H
#define MYTHAIA_COMPAT_SYS_TIME_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <time.h>

#include "../mythaia_win32.h"

struct timezone; /* never populated; callers pass NULL */

static inline int gettimeofday(struct timeval *tv, struct timezone *tz) {
  struct timespec ts;
  (void)tz;
  if (tv == NULL) {
    return 0;
  }
  clock_gettime(CLOCK_REALTIME, &ts);
  tv->tv_sec = (long)ts.tv_sec;
  tv->tv_usec = (long)(ts.tv_nsec / 1000);
  return 0;
}

#endif /* MYTHAIA_COMPAT_SYS_TIME_H */

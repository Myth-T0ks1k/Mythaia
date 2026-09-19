/*
 * unistd.h — Windows stand-in.
 *
 * Nothing in the desktop DLL needs a POSIX file or process call; this
 * exists so a stray <unistd.h> resolves instead of failing, and maps the
 * few names that have direct CRT equivalents. ssize_t is provided because
 * it is the one type from here that network code reaches for.
 */

#ifndef MYTHAIA_COMPAT_UNISTD_H
#define MYTHAIA_COMPAT_UNISTD_H

#include <io.h>
#include <process.h>
#include <stddef.h>
#include <BaseTsd.h>

#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
typedef SSIZE_T ssize_t;
#endif

#define getpid _getpid
#define close  _close
#define read   _read
#define write  _write

#endif /* MYTHAIA_COMPAT_UNISTD_H */

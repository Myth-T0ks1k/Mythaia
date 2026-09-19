/*
 * android/log.h — Windows stand-in for the NDK logging API.
 *
 * The bridges log through __android_log_print / __android_log_vprint with
 * the ANDROID_LOG_* priorities. On the desktop JVM there is no logcat, so
 * every line goes to stderr as "<level>/<tag>: <message>", and to the
 * debugger (OutputDebugStringA) when one is attached.
 */

#ifndef MYTHAIA_COMPAT_ANDROID_LOG_H
#define MYTHAIA_COMPAT_ANDROID_LOG_H

#include <stdarg.h>
#include <stdio.h>

/* Lean windows.h only (no winsock.h, no wingdi.h): just IsDebuggerPresent
   and OutputDebugStringA are needed, and Winsock's s_addr macro must not
   leak into files that merely want to log. */
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

/* Same numbering as the NDK, so a stored priority means the same thing. */
typedef enum android_LogPriority {
  ANDROID_LOG_UNKNOWN = 0,
  ANDROID_LOG_DEFAULT,
  ANDROID_LOG_VERBOSE,
  ANDROID_LOG_DEBUG,
  ANDROID_LOG_INFO,
  ANDROID_LOG_WARN,
  ANDROID_LOG_ERROR,
  ANDROID_LOG_FATAL,
  ANDROID_LOG_SILENT,
} android_LogPriority;

static inline int __android_log_vprint(int prio, const char *tag,
                                       const char *fmt, va_list ap) {
  static const char letters[] = "??VDIWEFS";
  char line[1024];
  int n;
  char c = (prio >= 0 && prio < (int)sizeof(letters) - 1) ? letters[prio] : '?';

  n = snprintf(line, sizeof(line), "%c/%s: ", c, tag ? tag : "");
  if (n < 0) {
    return n;
  }
  if ((size_t)n < sizeof(line)) {
    vsnprintf(line + n, sizeof(line) - (size_t)n, fmt, ap);
  }
  fprintf(stderr, "%s\n", line);
  fflush(stderr);
  if (IsDebuggerPresent()) {
    OutputDebugStringA(line);
    OutputDebugStringA("\n");
  }
  return 1;
}

static inline int __android_log_print(int prio, const char *tag,
                                      const char *fmt, ...) {
  va_list ap;
  int r;
  va_start(ap, fmt);
  r = __android_log_vprint(prio, tag, fmt, ap);
  va_end(ap);
  return r;
}

#endif /* MYTHAIA_COMPAT_ANDROID_LOG_H */

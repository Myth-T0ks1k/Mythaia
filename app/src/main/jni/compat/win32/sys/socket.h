/*
 * sys/socket.h — Windows stand-in.
 *
 * The bridges only take struct sockaddr / sockaddr_storage, AF_INET,
 * AF_INET6 and socklen_t from here, and Winsock defines every one of them.
 * No socket is ever opened from C on the desktop: datagrams are handed in
 * and out through the JNI surface, just as on Android.
 */

#ifndef MYTHAIA_COMPAT_SYS_SOCKET_H
#define MYTHAIA_COMPAT_SYS_SOCKET_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#endif /* MYTHAIA_COMPAT_SYS_SOCKET_H */

/*
 * netinet/in.h — Windows stand-in.
 *
 * sockaddr_in, sockaddr_in6, in6_addr, IPPROTO_* and the INADDR_* /
 * IN6ADDR_* constants are all Winsock's. Nothing to add.
 */

#ifndef MYTHAIA_COMPAT_NETINET_IN_H
#define MYTHAIA_COMPAT_NETINET_IN_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#endif /* MYTHAIA_COMPAT_NETINET_IN_H */

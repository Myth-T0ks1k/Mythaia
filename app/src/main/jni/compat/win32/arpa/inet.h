/*
 * arpa/inet.h — Windows stand-in.
 *
 * inet_pton, inet_ntop, htons/ntohs/htonl/ntohl, in_addr and in6_addr all
 * come from Winsock. ws2tcpip.h also defines socklen_t. Callers link ws2_32.
 */

#ifndef MYTHAIA_COMPAT_ARPA_INET_H
#define MYTHAIA_COMPAT_ARPA_INET_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#endif /* MYTHAIA_COMPAT_ARPA_INET_H */

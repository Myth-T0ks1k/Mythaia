/*
 * arch/cc.h — lwIP compiler port for MSVC.
 *
 * Shadows lwip/port/arch/cc.h on the desktop build (this directory is
 * listed before lwip/port on the include path). The two differ only where
 * the Android port leans on GCC:
 *
 *   - struct packing: MSVC has no __attribute__((packed)), so lwIP's
 *     PACK_STRUCT_USE_INCLUDES mechanism wraps each packed struct in
 *     arch/bpstruct.h / arch/epstruct.h, which carry #pragma pack.
 *   - diagnostics: no logcat, so LWIP_PLATFORM_DIAG prints to stdout.
 *   - LWIP_RAND: arc4random() is the shim in mythaia_win32.h, which the
 *     desktop CMake force-includes into every lwIP translation unit.
 */

#ifndef CC_H
#define CC_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* --- Types --- */
typedef uint8_t     u8_t;
typedef int8_t      s8_t;
typedef uint16_t    u16_t;
typedef int16_t     s16_t;
typedef uint32_t    u32_t;
typedef int32_t     s32_t;
typedef uintptr_t   mem_ptr_t;

/* --- Byte order: x64 Windows is little-endian --- */
#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif

/*
 * Do not let lwip/def.h alias htons/ntohs/htonl/ntohl to lwip_htons & co.
 * lwip_bridge.c includes <arpa/inet.h> (= winsock2.h here) after the lwIP
 * headers, and with the macros in place Winsock's own htons prototype would
 * be rewritten into a clashing lwip_htons declaration. lwIP's core uses the
 * lwip_-prefixed names directly, so nothing in the stack needs the aliases;
 * the bridge's htons calls resolve to Winsock's, which needs no WSAStartup.
 */
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS

/* --- Structure packing via #pragma pack (see bpstruct.h / epstruct.h) --- */
#define PACK_STRUCT_USE_INCLUDES
#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_STRUCT
#define PACK_STRUCT_END
#define PACK_STRUCT_FIELD(x) x

/* --- Platform diagnostics --- */
/* lwIP passes double-parenthesized args: LWIP_PLATFORM_DIAG(("fmt", args)) */
#define LWIP_PLATFORM_DIAG(x)   do { printf x; } while(0)
#define LWIP_PLATFORM_ASSERT(x) do { fprintf(stderr, "Assert \"%s\" failed at line %d in %s\n", \
                                     x, __LINE__, __FILE__); abort(); } while(0)

/* --- Compiler hints --- */
#ifndef LWIP_NO_STDDEF_H
#define LWIP_NO_STDDEF_H 0
#endif

#ifndef LWIP_NO_STDINT_H
#define LWIP_NO_STDINT_H 0
#endif

#ifndef LWIP_NO_INTTYPES_H
#define LWIP_NO_INTTYPES_H 0
#endif

/* --- Random number generation --- */
#define LWIP_RAND() ((u32_t)arc4random())

#endif /* CC_H */

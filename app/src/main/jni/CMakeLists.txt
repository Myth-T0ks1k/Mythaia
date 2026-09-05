cmake_minimum_required(VERSION 3.22.1)
project("mythaia_native" C)

# --------------------------------------------------------------------------
# lwIP source files
# --------------------------------------------------------------------------
set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lwip)

set(LWIP_SOURCES
    ${LWIP_DIR}/src/core/init.c
    ${LWIP_DIR}/src/core/def.c
    ${LWIP_DIR}/src/core/ip.c
    ${LWIP_DIR}/src/core/mem.c
    ${LWIP_DIR}/src/core/memp.c
    ${LWIP_DIR}/src/core/netif.c
    ${LWIP_DIR}/src/core/pbuf.c
    ${LWIP_DIR}/src/core/tcp.c
    ${LWIP_DIR}/src/core/tcp_in.c
    ${LWIP_DIR}/src/core/tcp_out.c
    ${LWIP_DIR}/src/core/udp.c
    ${LWIP_DIR}/src/core/inet_chksum.c
    ${LWIP_DIR}/src/core/timeouts.c
    ${LWIP_DIR}/src/core/ipv4/ip4.c
    ${LWIP_DIR}/src/core/ipv4/ip4_addr.c
    ${LWIP_DIR}/src/core/ipv4/ip4_frag.c
    ${LWIP_DIR}/src/core/ipv4/icmp.c
    ${LWIP_DIR}/src/core/ipv6/ip6.c
    ${LWIP_DIR}/src/core/ipv6/ip6_addr.c
    ${LWIP_DIR}/src/core/ipv6/ip6_frag.c
    ${LWIP_DIR}/src/core/ipv6/icmp6.c
    ${LWIP_DIR}/src/core/ipv6/nd6.c
    ${LWIP_DIR}/src/core/ipv6/inet6.c
    ${LWIP_DIR}/port/sys_arch.c
    ${LWIP_DIR}/lwip_bridge.c
)

set(LWIP_INCLUDE_DIRS
    ${LWIP_DIR}/src/include
    ${LWIP_DIR}/port
    ${LWIP_DIR}/port/arch
)

# --------------------------------------------------------------------------
# BLAKE3 source files
# --------------------------------------------------------------------------
set(BLAKE3_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/blake3/blake3.c
    ${CMAKE_CURRENT_SOURCE_DIR}/blake3/blake3_dispatch.c
    ${CMAKE_CURRENT_SOURCE_DIR}/blake3/blake3_portable.c
)

# --------------------------------------------------------------------------
# libyaml
# --------------------------------------------------------------------------
set(LIBYAML_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libyaml)

set(LIBYAML_SOURCES
    ${LIBYAML_DIR}/src/api.c
    ${LIBYAML_DIR}/src/dumper.c
    ${LIBYAML_DIR}/src/emitter.c
    ${LIBYAML_DIR}/src/loader.c
    ${LIBYAML_DIR}/src/parser.c
    ${LIBYAML_DIR}/src/reader.c
    ${LIBYAML_DIR}/src/scanner.c
    ${LIBYAML_DIR}/src/writer.c
)

# --------------------------------------------------------------------------
# ngtcp2 (QUIC)
#
# A flattened vendor copy of upstream 1.25.0 — see ngtcp2/UPSTREAM_MAP.md for
# what is stock and what is ours. `shared.c` is the backend-agnostic half of
# the crypto helper; the backend half is ngtcp2_crypto_android.c.
# --------------------------------------------------------------------------
set(NGTCP2_DIR ${CMAKE_CURRENT_SOURCE_DIR}/ngtcp2)

file(GLOB NGTCP2_SOURCES ${NGTCP2_DIR}/*.c)

# --------------------------------------------------------------------------
# mbedTLS — the primitives behind ngtcp2_crypto_android.c
#
# A minimal subset: the AEADs and hashes a TLS 1.3 suite can name, plus HKDF.
# No X.509, no TLS, no PSA — the handshake is Kotlin's, and this is only the
# record-protection half. See mbedtls_config.h.
# --------------------------------------------------------------------------
set(MBEDTLS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls)

file(GLOB MBEDTLS_SOURCES ${MBEDTLS_DIR}/library/*.c)

# --------------------------------------------------------------------------
# JNI bridge files
# --------------------------------------------------------------------------
set(JNI_BRIDGE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/lwip_jni_bridge.c
    ${CMAKE_CURRENT_SOURCE_DIR}/blake3_jni_bridge.c
    ${CMAKE_CURRENT_SOURCE_DIR}/yaml_jni_bridge.c
    ${CMAKE_CURRENT_SOURCE_DIR}/quic_jni_bridge.c
)

# --------------------------------------------------------------------------
# Vendored libraries are built as separate static targets.
#
# libyaml and ngtcp2 each ship their own `config.h`, and libyaml reaches its
# with a quoted include that falls through to the include path. In one target
# they share that path and whichever directory is listed first wins for both —
# so they get a target each, with the config they mean on a private path.
# --------------------------------------------------------------------------
set(VENDOR_FLAGS -Wall -Wno-unused-variable -Wno-unused-function -O2)

add_library(yaml_static STATIC ${LIBYAML_SOURCES})
target_include_directories(yaml_static PRIVATE ${LIBYAML_DIR}/include)
target_compile_definitions(yaml_static PRIVATE YAML_DECLARE_STATIC HAVE_CONFIG_H)
target_compile_options(yaml_static PRIVATE ${VENDOR_FLAGS})

add_library(mbedcrypto_static STATIC ${MBEDTLS_SOURCES})
target_include_directories(mbedcrypto_static PUBLIC ${MBEDTLS_DIR}/include)
target_include_directories(mbedcrypto_static PRIVATE ${MBEDTLS_DIR}/library)
target_compile_definitions(mbedcrypto_static PUBLIC
    MBEDTLS_CONFIG_FILE="${MBEDTLS_DIR}/mbedtls_config.h"
)
target_compile_options(mbedcrypto_static PRIVATE ${VENDOR_FLAGS})

add_library(ngtcp2_static STATIC ${NGTCP2_SOURCES})
target_include_directories(ngtcp2_static PRIVATE ${NGTCP2_DIR})
target_compile_definitions(ngtcp2_static PRIVATE HAVE_CONFIG_H)
target_link_libraries(ngtcp2_static mbedcrypto_static)
target_compile_options(ngtcp2_static PRIVATE
    ${VENDOR_FLAGS}
    # Upstream is warning-clean under its own build; these two fire only from
    # the way the sources are compiled here and say nothing about the code.
    -Wno-unused-but-set-variable
    -Wno-unreachable-code
)

# --------------------------------------------------------------------------
# Build single shared library
# --------------------------------------------------------------------------
add_library(mythaia_native SHARED
    ${LWIP_SOURCES}
    ${BLAKE3_SOURCES}
    ${JNI_BRIDGE_SOURCES}
)

# --------------------------------------------------------------------------
# Include paths
#
# ngtcp2's directory carries both its public headers (ngtcp2/ngtcp2.h) and its
# private config.h. Nothing outside the vendor tree includes <config.h>, so
# putting it last keeps it from shadowing anything.
# --------------------------------------------------------------------------
# ${NGTCP2_DIR} must come before ${CMAKE_CURRENT_SOURCE_DIR}: this directory
# holds a folder called ngtcp2/, so with the source dir first
# <ngtcp2/ngtcp2_crypto.h> resolves to the vendor tree's *lib-internal*
# ngtcp2_crypto.h instead of the public helper header of the same name — which
# compiles, and then every helper function reads as undeclared.
target_include_directories(mythaia_native PRIVATE
    ${NGTCP2_DIR}
    ${LWIP_INCLUDE_DIRS}
    ${LIBYAML_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/compat
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(mythaia_native PRIVATE
    YAML_DECLARE_STATIC
)

# --------------------------------------------------------------------------
# Link libraries
# --------------------------------------------------------------------------
target_link_libraries(mythaia_native
    yaml_static
    ngtcp2_static
    log
)

# --------------------------------------------------------------------------
# Compiler flags
# --------------------------------------------------------------------------
target_compile_options(mythaia_native PRIVATE
    -Wall
    -Wno-unused-variable
    -Wno-unused-function
    -O2
)

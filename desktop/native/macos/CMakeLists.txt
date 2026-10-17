# ---------------------------------------------------------------------------
# libmythaia_native.dylib — the Android JNI library, built for macOS.
#
# A sibling of app/src/main/jni/CMakeLists.txt (Android) and of
# desktop/native/CMakeLists.txt (Windows): the same sources and vendor
# configs, kept in step by hand. The only macOS-specific inputs are the
# headers under app/src/main/jni/compat/macos/ (an android/log.h that writes
# to stderr, and ngtcp2's config.h).
#
# Usage: desktop/native/macos/build.sh (Release; arm64 + x86_64 in one
# universal dylib; copies it to desktop/native/out/).
# ---------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.22)
project("mythaia_native_macos" C)

if(NOT APPLE)
    message(FATAL_ERROR "desktop/native/macos builds the macOS dylib; "
                        "use app/src/main/jni for Android and desktop/native for Windows.")
endif()

get_filename_component(JNI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../../app/src/main/jni" ABSOLUTE)
set(MAC_COMPAT ${JNI_DIR}/compat/macos)

# --------------------------------------------------------------------------
# JDK headers: JAVA_HOME, as the CI and every JDK installer set it.
# --------------------------------------------------------------------------
if(DEFINED ENV{JAVA_HOME} AND EXISTS "$ENV{JAVA_HOME}/include/jni.h")
    set(JDK_HOME "$ENV{JAVA_HOME}")
else()
    message(FATAL_ERROR "No JDK found: set JAVA_HOME to a JDK with include/jni.h")
endif()
set(JNI_INCLUDE_DIRS ${JDK_HOME}/include ${JDK_HOME}/include/darwin)
message(STATUS "JNI headers: ${JDK_HOME}/include")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
# No build-machine paths in assertion strings or debug info.
add_compile_options("-ffile-prefix-map=${JNI_DIR}/=")

# --------------------------------------------------------------------------
# Source lists — mirror app/src/main/jni/CMakeLists.txt
# --------------------------------------------------------------------------
set(LWIP_DIR ${JNI_DIR}/lwip)
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

set(BLAKE3_SOURCES
    ${JNI_DIR}/blake3/blake3.c
    ${JNI_DIR}/blake3/blake3_dispatch.c
    ${JNI_DIR}/blake3/blake3_portable.c
)

set(LIBYAML_DIR ${JNI_DIR}/libyaml)
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

set(NGTCP2_DIR ${JNI_DIR}/ngtcp2)
file(GLOB NGTCP2_SOURCES ${NGTCP2_DIR}/*.c)

set(MBEDTLS_DIR ${JNI_DIR}/mbedtls)
file(GLOB MBEDTLS_SOURCES ${MBEDTLS_DIR}/library/*.c)

set(JNI_BRIDGE_SOURCES
    ${JNI_DIR}/lwip_jni_bridge.c
    ${JNI_DIR}/blake3_jni_bridge.c
    ${JNI_DIR}/yaml_jni_bridge.c
    ${JNI_DIR}/quic_jni_bridge.c
    ${JNI_DIR}/quic_conn_bridge.c
)

set(VENDOR_FLAGS -Wall -Wno-unused-variable -Wno-unused-function -O2)

# --------------------------------------------------------------------------
# Vendored libraries as static targets (same split as Android: libyaml and
# ngtcp2 each want their own config.h)
# --------------------------------------------------------------------------
add_library(yaml_static STATIC ${LIBYAML_SOURCES})
target_include_directories(yaml_static PRIVATE ${LIBYAML_DIR}/include)
target_compile_definitions(yaml_static PUBLIC YAML_DECLARE_STATIC)
target_compile_definitions(yaml_static PRIVATE HAVE_CONFIG_H)
target_compile_options(yaml_static PRIVATE ${VENDOR_FLAGS})

add_library(mbedcrypto_static STATIC ${MBEDTLS_SOURCES})
target_include_directories(mbedcrypto_static PUBLIC ${MBEDTLS_DIR}/include)
target_include_directories(mbedcrypto_static PRIVATE ${MBEDTLS_DIR}/library)
target_compile_definitions(mbedcrypto_static PUBLIC
    MBEDTLS_CONFIG_FILE="${MBEDTLS_DIR}/mbedtls_config.h"
)
target_compile_options(mbedcrypto_static PRIVATE ${VENDOR_FLAGS})

add_library(ngtcp2_static STATIC ${NGTCP2_SOURCES})
# The macOS config.h must be found before the Android one in ${NGTCP2_DIR}.
target_include_directories(ngtcp2_static PRIVATE
    ${MAC_COMPAT}/ngtcp2-config
    ${NGTCP2_DIR}
)
target_compile_definitions(ngtcp2_static PRIVATE HAVE_CONFIG_H)
target_link_libraries(ngtcp2_static PUBLIC mbedcrypto_static)
target_compile_options(ngtcp2_static PRIVATE
    ${VENDOR_FLAGS}
    -Wno-unused-but-set-variable
    -Wno-unreachable-code
)

# --------------------------------------------------------------------------
# The dylib
# --------------------------------------------------------------------------
add_library(mythaia_native SHARED ${LWIP_SOURCES} ${BLAKE3_SOURCES} ${JNI_BRIDGE_SOURCES})

# ${MAC_COMPAT} first so its android/log.h stands in for the NDK one, then
# the same order as Android: ${NGTCP2_DIR} before ${JNI_DIR} so that
# <ngtcp2/ngtcp2_crypto.h> is the public helper header; ${JNI_DIR}/compat
# supplies the os/log.h the lwIP bridge was written against.
target_include_directories(mythaia_native PRIVATE
    ${MAC_COMPAT}
    ${NGTCP2_DIR}
    ${LWIP_INCLUDE_DIRS}
    ${LIBYAML_DIR}/include
    ${JNI_DIR}/compat
    ${JNI_DIR}
    ${JNI_INCLUDE_DIRS}
)
target_link_libraries(mythaia_native PRIVATE yaml_static ngtcp2_static)
target_compile_options(mythaia_native PRIVATE -Wall -Wno-unused-variable -Wno-unused-function -O2)

# System.load() takes the file by path; the name only has to match AppPaths.
set_target_properties(mythaia_native PROPERTIES
    OUTPUT_NAME "mythaia_native"
    MACOSX_RPATH ON
)

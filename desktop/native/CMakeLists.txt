# ---------------------------------------------------------------------------
# mythaia_native.dll — the Android JNI library, built for x64 Windows / MSVC.
#
# This is a sibling of app/src/main/jni/CMakeLists.txt, not a replacement:
# the Android build is untouched and the two must be kept in step by hand
# (same source lists, same vendor configs). Everything compiled here comes
# from app/src/main/jni; the only Windows-specific inputs are the compat
# headers under app/src/main/jni/compat/win32/.
#
# What the DLL carries:
#   - BLAKE3 JNI, libyaml JNI
#   - the QUIC bridges (quic_jni_bridge.c, quic_conn_bridge.c) with ngtcp2 on
#     the mbedTLS backend
#   - lwIP + its JNI bridge (MYTHAIA_WITH_LWIP, default ON — the port is
#     NO_SYS=1 so it needs no threads; only an MSVC packing shim)
#
# Usage: desktop/native/build.cmd (vcvars64 + Ninja, Release, copies the DLL
# to desktop/native/out/).
# ---------------------------------------------------------------------------
cmake_minimum_required(VERSION 3.22)
cmake_policy(SET CMP0091 NEW) # CMAKE_MSVC_RUNTIME_LIBRARY
project("mythaia_native_desktop" C)

if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "desktop/native is the MSVC/Win64 build of mythaia_native; "
                        "use app/src/main/jni for Android.")
endif()

option(MYTHAIA_WITH_LWIP "Compile lwIP and its JNI bridge into the DLL" ON)

get_filename_component(JNI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../app/src/main/jni" ABSOLUTE)
set(WIN32_COMPAT ${JNI_DIR}/compat/win32)

# --------------------------------------------------------------------------
# JDK headers. JAVA_HOME wins; otherwise the JDK 21 this machine has.
# --------------------------------------------------------------------------
if(DEFINED ENV{JAVA_HOME} AND EXISTS "$ENV{JAVA_HOME}/include/jni.h")
    file(TO_CMAKE_PATH "$ENV{JAVA_HOME}" JDK_HOME)
elseif(EXISTS "C:/Program Files/Java/jdk-21/include/jni.h")
    set(JDK_HOME "C:/Program Files/Java/jdk-21")
else()
    message(FATAL_ERROR "No JDK found: set JAVA_HOME to a JDK with include/jni.h")
endif()
set(JNI_INCLUDE_DIRS ${JDK_HOME}/include ${JDK_HOME}/include/win32)
message(STATUS "JNI headers: ${JDK_HOME}/include")

# --------------------------------------------------------------------------
# Toolchain-wide settings
#
# Static CRT so the DLL has no dependency on a vcruntime redistributable —
# the JVM that loads it may not ship one, and there is nothing to share with
# it anyway.
# --------------------------------------------------------------------------
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_compile_definitions(
    _CRT_SECURE_NO_WARNINGS   # strncpy/sprintf etc. are used deliberately
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)
add_compile_options(/W3 /utf-8)

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

# ${WIN32_COMPAT} is listed on the target before these so that "arch/cc.h"
# resolves to the MSVC port (compat/win32/arch/cc.h) rather than the GCC one
# in lwip/port/arch.
set(LWIP_INCLUDE_DIRS
    ${LWIP_DIR}/src/include
    ${LWIP_DIR}/port
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
    ${JNI_DIR}/blake3_jni_bridge.c
    ${JNI_DIR}/yaml_jni_bridge.c
    ${JNI_DIR}/quic_jni_bridge.c
    ${JNI_DIR}/quic_conn_bridge.c
)
if(MYTHAIA_WITH_LWIP)
    list(APPEND JNI_BRIDGE_SOURCES ${JNI_DIR}/lwip_jni_bridge.c)
endif()

# The bionic-isms (clock_gettime, arc4random_buf, __attribute__) are supplied
# by force-including this header — see its comment for why it is not a
# same-name shadow header like the rest of compat/win32.
set(MYTHAIA_FORCE_INCLUDE "/FI${WIN32_COMPAT}/mythaia_win32.h")

# --------------------------------------------------------------------------
# Vendored libraries as static targets (same split as Android, same reason:
# libyaml and ngtcp2 each want their own config.h)
# --------------------------------------------------------------------------
add_library(yaml_static STATIC ${LIBYAML_SOURCES})
target_include_directories(yaml_static PRIVATE ${LIBYAML_DIR}/include)
target_compile_definitions(yaml_static PUBLIC YAML_DECLARE_STATIC)
target_compile_definitions(yaml_static PRIVATE HAVE_CONFIG_H)

add_library(mbedcrypto_static STATIC ${MBEDTLS_SOURCES})
target_include_directories(mbedcrypto_static PUBLIC ${MBEDTLS_DIR}/include)
target_include_directories(mbedcrypto_static PRIVATE ${MBEDTLS_DIR}/library)
target_compile_definitions(mbedcrypto_static PUBLIC
    MBEDTLS_CONFIG_FILE="${MBEDTLS_DIR}/mbedtls_config.h"
)

add_library(ngtcp2_static STATIC ${NGTCP2_SOURCES})
# The Windows config.h must be found before the Android one in ${NGTCP2_DIR}.
target_include_directories(ngtcp2_static PRIVATE
    ${WIN32_COMPAT}/ngtcp2-config
    ${NGTCP2_DIR}
)
target_compile_definitions(ngtcp2_static PRIVATE HAVE_CONFIG_H)
# Without NGTCP2_STATICLIB, ngtcp2.h on WIN32 marks every API as dllimport.
# PUBLIC so the bridges that include ngtcp2.h see the same declarations.
target_compile_definitions(ngtcp2_static PUBLIC NGTCP2_STATICLIB)
# MSVC's C front end (verified on 19.41) treats `char` and `signed char` as
# one _Generic association and fails with C7700 on the type-dispatching
# macros in ngtcp2_macro.h (ngtcp2_max/min) and ngtcp2_fmt.h (hex, hexw,
# NGTCP2_FMT_WRITE_TYPE). Both are included with quoted paths from their own
# directory, so they cannot be shadowed from the include path. Instead, copies
# with the `signed char:` lines removed are generated here and force-included
# into every ngtcp2 translation unit; the vendored originals then become
# no-ops behind their own include guards. The library never formats or
# compares a `signed char`, and plain `char` keeps its own association.
#
# Generated from the vendored files at configure time so an ngtcp2 upgrade
# cannot leave a stale copy behind.
set(NGTCP2_MSVC_DIR ${CMAKE_BINARY_DIR}/ngtcp2-msvc)
foreach(hdr ngtcp2_macro.h ngtcp2_fmt.h)
    set(_src_path ${NGTCP2_DIR}/${hdr})
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${_src_path})
    file(READ ${_src_path} _src)
    string(REGEX REPLACE "\n[ \t]*signed char: [^\n]*\n" "\n" _out "${_src}")
    if(_out STREQUAL _src)
        message(FATAL_ERROR "${hdr}: no 'signed char:' _Generic association found; "
                            "re-check whether the MSVC workaround is still needed")
    endif()
    file(WRITE ${NGTCP2_MSVC_DIR}/${hdr}
        "/* GENERATED by desktop/native/CMakeLists.txt from ${_src_path}\n"
        "   with the 'signed char:' _Generic associations removed for MSVC. */\n"
        "${_out}")
    target_compile_options(ngtcp2_static PRIVATE "/FI${NGTCP2_MSVC_DIR}/${hdr}")
endforeach()
# Our backend file calls arc4random_buf; the shim resolves it to BCryptGenRandom.
set_source_files_properties(${NGTCP2_DIR}/ngtcp2_crypto_android.c
    PROPERTIES COMPILE_OPTIONS "${MYTHAIA_FORCE_INCLUDE}")
target_link_libraries(ngtcp2_static PUBLIC mbedcrypto_static bcrypt)

# --------------------------------------------------------------------------
# The DLL
# --------------------------------------------------------------------------
set(MYTHAIA_NATIVE_SOURCES ${BLAKE3_SOURCES} ${JNI_BRIDGE_SOURCES})
if(MYTHAIA_WITH_LWIP)
    list(APPEND MYTHAIA_NATIVE_SOURCES ${LWIP_SOURCES})
endif()

add_library(mythaia_native SHARED ${MYTHAIA_NATIVE_SOURCES})

# Order matters, as on Android: ${NGTCP2_DIR} before ${JNI_DIR} so that
# <ngtcp2/ngtcp2_crypto.h> is the public helper header, and ${WIN32_COMPAT}
# first of all so its android/, arpa/, netinet/, sys/ and arch/ shadow the
# missing POSIX headers and the GCC lwIP port.
target_include_directories(mythaia_native PRIVATE
    ${WIN32_COMPAT}
    ${NGTCP2_DIR}
    ${LWIP_INCLUDE_DIRS}
    ${LIBYAML_DIR}/include
    ${JNI_DIR}/compat
    ${JNI_DIR}
    ${JNI_INCLUDE_DIRS}
)

target_compile_options(mythaia_native PRIVATE ${MYTHAIA_FORCE_INCLUDE})

# Java_com_mythaia_vpn_NativeBridge_* are JNIEXPORT (= __declspec(dllexport)
# in the JDK's win32/jni_md.h), so no .def file is needed.
target_link_libraries(mythaia_native PRIVATE
    yaml_static
    ngtcp2_static
    ws2_32    # inet_pton/inet_ntop/htons
    bcrypt    # arc4random shim
)

set_target_properties(mythaia_native PROPERTIES
    OUTPUT_NAME "mythaia_native"   # System.loadLibrary("mythaia_native") -> mythaia_native.dll
    PREFIX ""
)

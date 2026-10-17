#!/bin/sh
# Copies the vendored C that MythaiaKit's CQuic target compiles (ngtcp2 and the
# slice of mbedTLS behind its crypto backend) from the Android app's jni tree
# into ios/Packages/MythaiaKit/Sources/CQuic/vendor/.
#
# The sources live once in the repository, under app/src/main/jni, where the
# Android, Windows and macOS desktop builds already take them from; the copy is
# not committed (ios/.gitignore). Run this once after a checkout, and again
# after the vendored ngtcp2 or mbedTLS changes, before `swift build`,
# `swift test` or `xcodegen`.
#
# Three files differ from a plain copy, each for a reason:
#   - ngtcp2's config.h is the Darwin one (compat/macos/ngtcp2-config), which
#     holds for iOS as well: no <endian.h>, little-endian, memset_s left alone.
#   - mbedTLS's default mbedtls/mbedtls_config.h is replaced by the minimal
#     config the other builds pass as MBEDTLS_CONFIG_FILE. build_info.h falls
#     back to that header when no config file is named, so no quoted -D has
#     to survive SwiftPM's and Xcode's handling of build settings.
#   - mbedTLS's LICENSE and ngtcp2's UPSTREAM_MAP.md are left behind: SwiftPM
#     warns about every file in a target it does not know what to do with.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
jni="$here/../app/src/main/jni"
dest="$here/Packages/MythaiaKit/Sources/CQuic/vendor"

for required in "$jni/ngtcp2/ngtcp2/ngtcp2.h" "$jni/mbedtls/mbedtls_config.h" \
                "$jni/compat/macos/ngtcp2-config/config.h"; do
  if [ ! -f "$required" ]; then
    echo "bootstrap: $required is missing; run this from a full checkout" >&2
    exit 1
  fi
done

rm -rf "$dest"
mkdir -p "$dest/ngtcp2/ngtcp2" "$dest/mbedtls/include" "$dest/mbedtls/library"

# ngtcp2: the flattened library and crypto helper, then its public headers.
cp "$jni"/ngtcp2/*.c "$dest/ngtcp2/"
cp "$jni"/ngtcp2/*.h "$dest/ngtcp2/"
cp "$jni"/ngtcp2/ngtcp2/*.h "$dest/ngtcp2/ngtcp2/"
cp "$jni/compat/macos/ngtcp2-config/config.h" "$dest/ngtcp2/config.h"

# mbedTLS: its headers whole, the library sources, and the minimal config in
# the place build_info.h looks for one by default.
cp -R "$jni/mbedtls/include/." "$dest/mbedtls/include/"
cp "$jni"/mbedtls/library/*.c "$dest/mbedtls/library/"
cp "$jni"/mbedtls/library/*.h "$dest/mbedtls/library/"
cp "$jni/mbedtls/mbedtls_config.h" "$dest/mbedtls/include/mbedtls/mbedtls_config.h"

count=$(find "$dest" -name '*.c' | wc -l | tr -d ' ')
echo "bootstrap: $count C sources in $dest"

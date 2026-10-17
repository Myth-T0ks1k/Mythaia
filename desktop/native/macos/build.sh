#!/bin/sh
# Builds libmythaia_native.dylib for macOS (arm64 and x86_64 in one file)
# and copies it to desktop/native/out/, where the Gradle build picks it up.
# Needs the Xcode command line tools, CMake and a JDK in JAVA_HOME.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
build="$here/../build-macos"
out="$here/../out"

cmake -S "$here" -B "$build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_OSX_ARCHITECTURES="arm64;x86_64" \
    -DCMAKE_OSX_DEPLOYMENT_TARGET=12.0
cmake --build "$build" --config Release --parallel

mkdir -p "$out"
cp "$build/libmythaia_native.dylib" "$out/"
lipo -info "$out/libmythaia_native.dylib"

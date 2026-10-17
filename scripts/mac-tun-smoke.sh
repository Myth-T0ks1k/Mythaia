#!/bin/bash
# The macOS TUN smoke test (desktop/src/test/kotlin/com/mythaia/desktop/tun/MacTunSmoke.kt)
# on a Mac where sudo needs no password, such as a GitHub macOS runner. It
# builds the native library and starts the interop lab when they are not
# there yet, compiles the tests with Gradle as the current user, and runs
# only the test JVM as root, so nothing root-owned ends up in ~/.gradle or
# the build directories. See docs/TESTING.md, section 6.
set -euo pipefail
cd "$(dirname "$0")/.."

[ "$(uname -s)" = Darwin ] || { echo "macOS only" >&2; exit 1; }

[ -f desktop/native/out/libmythaia_native.dylib ] || sh desktop/native/macos/build.sh
if ! { nc -z 127.0.0.1 20013 && nc -z 127.0.0.1 8099; } 2>/dev/null; then
  bash scripts/lab/ci-macos.sh
fi

./gradlew :desktop:writeTestClasspath --console=plain
classpath=$(cat desktop/build/test-classpath.txt)
java_home="${JAVA_HOME:-$(/usr/libexec/java_home -v 21)}"

cd desktop
sudo -H /usr/bin/env MYTHAIA_MAC_TUN_SMOKE=1 MYTHAIA_LAB_OUT="$PWD/../scripts/lab/out" \
  "$java_home/bin/java" \
  -Dmythaia.native.library="$PWD/native/out/libmythaia_native.dylib" \
  -cp "$classpath" \
  org.junit.runner.JUnitCore com.mythaia.desktop.tun.MacTunSmoke

#!/bin/bash
# Starts the interop lab (docs/TESTING.md) on a macOS CI runner: the pinned
# Xray and sing-box reference servers, verified against the SHA-256 digests
# GitHub records for those release assets, a fresh lab certificate, the
# generated configs, and the helper HTTP/UDP servers. Leaves them running.
set -euo pipefail

lab=scripts/lab
out=$lab/out
bin=$(mktemp -d)
mkdir -p "$out"

case "$(uname -m)" in
  arm64)
    xray_asset=Xray-macos-arm64-v8a.zip
    xray_sha=5b63cf477b4281dc0d9d3af4d7b87391ab868a842b430e9ce8957ea0b60ecab7
    sb_asset=sing-box-1.12.12-darwin-arm64
    sb_sha=b85881fdb9a10fbe2bc0dedb6c36a03af9c31aec870654d0bb49bab2b8e1f58a
    ;;
  *)
    xray_asset=Xray-macos-64.zip
    xray_sha=e917da78383b631d2bc7f8d9412f619e648fc3cd73a5a0f62f031425e5330ff1
    sb_asset=sing-box-1.12.12-darwin-amd64
    sb_sha=d01ebfd7c1ad3ea559b89451a3643b662eb90ed4c78bca93bb4ddecdeb2bb01a
    ;;
esac

fetch() {
  curl -fsSL --retry 3 -o "$3" "$1"
  echo "$2  $3" | shasum -a 256 -c -
}

fetch "https://github.com/XTLS/Xray-core/releases/download/v26.6.27/$xray_asset" "$xray_sha" "$bin/xray.zip"
unzip -q -o "$bin/xray.zip" -d "$bin/xray"
fetch "https://github.com/SagerNet/sing-box/releases/download/v1.12.12/$sb_asset.tar.gz" "$sb_sha" "$bin/sb.tgz"
tar -xzf "$bin/sb.tgz" -C "$bin"

openssl="$(brew --prefix openssl@3 2>/dev/null || true)/bin/openssl"
[ -x "$openssl" ] || openssl=openssl
"$openssl" req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
  -subj "/CN=lab.mythaia.test" -addext "subjectAltName=DNS:lab.mythaia.test" \
  -keyout "$out/lab.key" -out "$out/lab.crt" 2>/dev/null

python3 "$lab/gen.py"

python3 "$lab/helpers.py" > "$out/helpers.log" 2>&1 &
"$bin/xray/xray" run -c "$out/xray-lab.json" > "$out/xray.log" 2>&1 &
"$bin/$sb_asset/sing-box" run -c "$out/sb-lab.json" > "$out/sing-box.log" 2>&1 &

for port in 8099 20001 20002 20007 20013 21004 21005 21007; do
  for _ in $(seq 1 60); do
    nc -z 127.0.0.1 "$port" 2>/dev/null && break
    sleep 0.5
  done
  nc -z 127.0.0.1 "$port" || { echo "port $port did not open"; cat "$out"/*.log; exit 1; }
done
echo "lab is up"

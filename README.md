<div align="center">

# Mythaia Pro for Android

**Reach anywhere.**

Mythaia takes its name and mark from Hermes' winged sandal — the WingMark is
three feather strokes fanning out from a single point: one origin, every
direction. The app is a native, zero-dependency proxy client built entirely in
Kotlin, wrapped in a calm, papery, editorial interface — bone and paper
surfaces, ink text, a single azure accent.

No Electron. No WebView. No sing-box wrapper. Pure protocol implementation from the ground up.

</div>

---

## Why Mythaia?

Most Android proxy clients wrap sing-box or Xray-core in a Go/C++ bridge. Mythaia implements the protocol, transport, and routing layers directly in Kotlin, and calls into a small set of vendored C libraries (lwIP, BLAKE3, libyaml) through JNI for the parts that benefit from native code. The result is a smaller binary, lower memory usage, and no Go runtime overhead.

## Features

### Protocols & Security

- **VLESS** with full Vision (XTLS-RPRX-Vision) flow control and adaptive padding
- **Trojan** over TLS with UDP-over-TCP relay
- **Shadowsocks** (AEAD and Shadowsocks 2022)
- **SOCKS5** with optional authentication
- **Naive Proxy** (HTTP/1.1, HTTP/2) with padding negotiation
- **Reality** with X25519 key exchange and TLS 1.3 fingerprint spoofing
- **TLS** with SNI, ALPN, custom trusted certificates, and optional insecure mode
- **Transports:** TCP, WebSocket (with early data), HTTP Upgrade, gRPC, XHTTP (stream-one, stream-up, and packet-up over HTTP/1.1 and HTTP/2)
- **Mux** multiplexing with **XUDP** (GlobalID-based, BLAKE3 keyed hashing)
- **Fingerprints:** Chrome, Firefox, Safari, iOS, Edge

### App

- **ASR™ Smart Routing** — reduce latency while routing through proxy on demand
- **One-tap connect** with animated status UI and real-time traffic stats
- **Proxy chains** — cascade traffic through multiple outbounds
- **Subscription import** with auto-detection, auto-refresh, and profile metadata
- **Deep link support** for quick proxy/subscription import
- **QR code scanner** for instant config import
- **Latency testing** per-configuration
- **Custom routing rule sets** with domain/IP/GeoIP matching (MaxMind GeoLite2)
- **Country bypass** — exclude traffic by destination country
- **Built-in ad blocking** rule set
- **Encrypted DNS** (DNS-over-HTTPS, DNS-over-TLS) with auto-upgrade
- **IPv6** support with configurable behavior
- **Always On** / on-demand VPN
- **Trusted certificate** management for private CAs
- **Xray-core compatible** — works with standard V2Ray/Xray server deployments

### Architecture

- **Minimal dependencies** — Android frameworks, vendored C libraries (lwIP, blake3, libyaml)
- **Native VPN Service** — system-wide VPN via `VpnService` with a userspace TCP/IP stack
- **Fake-IP DNS** — transparent domain-based routing for all apps
- **Vendored native code** — lwIP (TCP/IP), BLAKE3 (keyed hashing), libyaml (Clash parsing); bundled into a single native library
- **Jetpack Compose** UI with Material 3 and the Mythaia "Wing" theme
- **arm64-v8a** native binaries

## Getting Started

### Build from Source

```bash
git clone <your-fork-url>
cd mythaia-android
```

Open the project in Android Studio, sync Gradle, select the `app` configuration, choose your device, and hit Run. Building a release requires a signing keystore configured via `local.properties` (`KEYSTORE_FILE`, `KEYSTORE_PASSWORD`, `KEY_ALIAS`, `KEY_PASSWORD`).

## License

Mythaia is distributed under the **GNU General Public License v3.0** — see
[LICENSE.txt](LICENSE.txt).

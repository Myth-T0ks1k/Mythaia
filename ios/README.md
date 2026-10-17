# Mythaia Pro for iOS

A native Swift app with a packet tunnel extension. The protocol stack
(`Packages/MythaiaKit`) is a Swift port of the Kotlin `core` that the Android
and desktop apps share, so links, subscriptions, Happ metadata, Auto and the
country bypass behave the same everywhere. See [ARCHITECTURE.md](ARCHITECTURE.md).

## What it does

- **Protocols:** VLESS (Vision, REALITY), VMess, Trojan, Shadowsocks (AEAD and
  2022), SOCKS5, AnyTLS, NaiveProxy (HTTP/1.1 and HTTP/2), Hysteria2
  (Salamander, Gecko), TUIC v5, WireGuard and AmneziaWG; TCP and UDP.
- **Transports:** TCP, WebSocket with early data, HTTPUpgrade, gRPC, XHTTP
  (stream-one, stream-up, packet-up over HTTP/1.1 and HTTP/2), QUIC.
- **TLS:** our own TLS 1.3 client with browser fingerprints, REALITY,
  ClientHello fragmentation, pins, trusted certificates; the system TLS for
  plain direct dials.
- **Tunnel:** every app's traffic through lwIP with Fake-IP DNS (TUN mode, the
  default), or only what honours the system proxy (proxy mode).
- **App:** groups per subscription with Auto, latency tests, import from links,
  the clipboard and QR codes, subscriptions with Happ metadata and fronting,
  server and chain editors, routing rules, country bypass, a home-screen
  widget and an iOS 18 Control Center toggle, background refresh, nine
  languages.
- **Not yet:** VLESS Encryption (ML-KEM), Sudoku, Nowhere, HTTPS interception.

Every protocol above is checked on each push against the Xray and sing-box
reference servers of the interop lab (`LabInteropTests`).

## Building

On a Mac with Xcode 16 or newer:

```sh
brew install xcodegen
sh ios/bootstrap.sh                          # copies the vendored C for QUIC into the package
cd ios
cp Config.example.xcconfig Config.xcconfig   # then set DEVELOPMENT_TEAM and the bundle id
xcodegen
open Mythaia.xcodeproj
```

The core alone builds and tests without Xcode's project:

```sh
sh ios/bootstrap.sh
cd ios/Packages/MythaiaKit
swift test
```

The `Apple` workflow (`.github/workflows/apple.yml`) does both on every push
to the `apple` branch, with the interop lab running, and keeps an unsigned
`.ipa` as a build artifact.

## Signing and installing

A VPN app on iOS needs the Network Extensions entitlement, which Apple grants
only to paid developer accounts. Without one the app builds, but iOS will not
let it start a tunnel:

| Route | Tunnel works | Needs |
|---|---|---|
| Xcode with a paid account (99 USD a year) | Yes | Team id in `Config.xcconfig`, bundle ids registered with *App Groups* and *Network Extensions* |
| TestFlight / App Store | Yes | The same account, plus App Store Connect |
| AltStore, Sideloadly with a free Apple ID | No | The free profile drops the Network Extension entitlement |
| TrollStore (devices and iOS versions it supports) | Yes | The unsigned `.ipa` from the workflow |

With a paid account: set `DEVELOPMENT_TEAM`, pick a bundle id you own for
`MYTHAIA_BUNDLE_ID` (the tunnel is `<bundle id>.Tunnel`, the widget
`<bundle id>.Widget`, the App Group `group.<bundle id>`), enable App Groups for
all three ids and Network Extensions (packet tunnel) for the app and the
tunnel in the developer portal, regenerate the project, and run on a device.

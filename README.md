<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/banner-dark.svg">
  <img alt="Mythaia — Reach anywhere." src="docs/assets/banner-light.svg" width="100%">
</picture>

<br>

[![Release](https://img.shields.io/github/v/release/Myth-T0ks1k/Mythaia?style=flat-square&color=24548F&label=release)](https://github.com/Myth-T0ks1k/Mythaia/releases/latest)
[![CI](https://img.shields.io/github/actions/workflow/status/Myth-T0ks1k/Mythaia/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Myth-T0ks1k/Mythaia/actions/workflows/ci.yml)
[![Android](https://img.shields.io/badge/Android-8.0%2B-3DDC84?style=flat-square&logo=android&logoColor=white)](#download)
[![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D4?style=flat-square&logo=windows&logoColor=white)](#download)
[![Kotlin](https://img.shields.io/badge/Kotlin-2.2-7F52FF?style=flat-square&logo=kotlin&logoColor=white)](https://kotlinlang.org)
[![License](https://img.shields.io/badge/license-GPL--3.0-14213A?style=flat-square)](LICENSE.txt)
[![Telegram](https://img.shields.io/badge/Telegram-%40mythaia-26A5E4?style=flat-square&logo=telegram&logoColor=white)](https://t.me/mythaia)
[![Chat](https://img.shields.io/badge/chat-%40mythaia__chat-26A5E4?style=flat-square&logo=telegram&logoColor=white)](https://t.me/mythaia_chat)

**English** · [Русский](docs/readme/README.ru.md) · [Türkmençe](docs/readme/README.tk.md) · [简体中文](docs/readme/README.zh-CN.md) · [فارسی](docs/readme/README.fa.md)

[Website](https://myth-t0ks1k.github.io/Mythaia/) · [Download](#download) · [Features](#features) · [Fronting in one link](#fronting-in-one-link) · [Build](#building-from-source) · [Changelog](CHANGELOG.md)

</div>

---

Mythaia is a proxy client for **Android** and **Windows** with its own protocol stack, written from
the ground up in Kotlin. It speaks VLESS with Reality, Hysteria2, TUIC, Trojan, Shadowsocks,
WireGuard and more without wrapping Xray-core or sing-box, and it is built for networks that filter
hard: domain fronting, ClientHello fragmentation, ECH, automatic server selection and a country
bypass are part of the app, not add-ons.

<div align="center">
  <img src="docs/assets/screenshots/home.png" width="24%" alt="Home screen, connected">
  <img src="docs/assets/screenshots/proxies.png" width="24%" alt="Servers of a subscription">
  <img src="docs/assets/screenshots/add-fronting.png" width="24%" alt="Adding a subscription with fronting">
  <img src="docs/assets/screenshots/settings.png" width="24%" alt="Settings">
</div>

## Why Mythaia

- **One native stack.** Protocols, transports, TLS and routing are Kotlin. A few small vendored C
  libraries (lwIP, BLAKE3, libyaml, ngtcp2, Mbed TLS) cover what native code does best. No Go runtime, no
  bridge, a small APK.
- **Two platforms, one core.** The Android and Windows apps share the same `core` module, so a
  link, a subscription or a fix behaves the same on both.
- **Made for filtered networks.** Subscriptions download through a front, servers are re-measured
  and switched automatically, local traffic stays local, and insecure settings are spelled out in
  red rather than hidden.

## Features

| | |
|---|---|
| **Protocols** | VLESS (Vision, Reality, ML-KEM encryption), VMess, Trojan, Shadowsocks (AEAD and 2022), Hysteria2 (Salamander, Brutal), TUIC v5, AnyTLS, NaiveProxy (HTTP/1.1, HTTP/2), WireGuard, SOCKS5, Sudoku |
| **Transports** | TCP, WebSocket with early data, HTTPUpgrade, gRPC, XHTTP (stream-one, stream-up, packet-up), QUIC |
| **TLS** | Browser fingerprints (Chrome, Firefox, Safari, iOS, Edge), Reality, ECH, ClientHello fragmentation, certificate pinning, per-server *allow insecure* with a visible warning |
| **Routing** | Rule and global modes, rule sets by domain, IP and GeoIP, country bypass, per-app split tunnelling, ad blocking, Fake-IP DNS, DNS over HTTPS and TLS, IPv6 |
| **Servers** | Share links, QR codes, Clash YAML, Xray and sing-box JSON, proxy chains, Mux with XUDP, ping over TCP or, for QUIC servers, UDP; handshake or a real HTTP request; export as links; removal of non-working servers |
| **Subscriptions** | Usage and expiry from the panel, auto refresh, provider announcements and Happ-compatible metadata (new URL, fallback URL, info blocks), Remnawave HWID, **domain fronting for the download**, download through a working server |
| **Auto** | Picks the fastest server of a group, keeps re-measuring and moves only for a clear gain; reconnects on its own when a server is blocked |
| **Android** | Quick Settings tile, home-screen widget, Always-on VPN, Android TV, Wear OS companion, HTTPS interception with your own CA, 9 languages |
| **Windows** | System-proxy mode (SOCKS5 and HTTP on one port) or full TUN mode over Wintun, tray icon, the same servers, subscriptions and Auto |

## Download

Get the latest build from **[Releases](https://github.com/Myth-T0ks1k/Mythaia/releases/latest)**.
New versions are also posted in the Telegram channel [@mythaia](https://t.me/mythaia).

| Platform | File | Notes |
|---|---|---|
| Android | `Mythaia-1.4.1-android-universal.apk` | Every device: arm64, armeabi-v7a, x86, x86_64 |
| Android | `Mythaia-1.4.1-android-arm64-v8a.apk` | Smaller, for modern phones |
| Wear OS | `Mythaia-1.4.1-wear-os.apk` | Companion for the phone app, Wear OS 3 or newer |
| Windows | `Mythaia-Pro-1.4.1-windows-x64-setup.exe` | Installer, per user, no administrator rights needed |
| Windows | `Mythaia-Pro-1.4.1-windows-x64.msi` | The same as an MSI package |
| Windows | `Mythaia-Pro-1.4.1-windows-x64-portable.zip` | Unzip anywhere and run `Mythaia Pro.exe` |

Every release lists the SHA-256 of each file in `SHA256SUMS.txt`. Android 8.0 or newer and Windows
10 or 11 (x64) are required; TUN mode on Windows asks for administrator rights — each time, or once
to install the Mythaia service, which runs from its own copy in Program Files.

On Windows, Scoop installs and updates it too:

```pwsh
scoop bucket add mythaia https://github.com/Myth-T0ks1k/scoop-bucket
scoop install mythaia/mythaia-pro
```

## Fronting in one link

A panel whose domain is blocked can often still be reached through a CDN that is not. Mythaia
downloads the subscription by connecting to the **front** (a CDN address or another domain on it),
sending an innocent **SNI** in the TLS handshake and the panel's real name in the HTTP `Host`
header.

The fronting can travel inside the link, so whoever you share it with adds the subscription in one
step, with nothing to type:

```text
https://panel.example.com/sub/TOKEN#front=104.16.1.1,cdn.example.net:443&sni=www.example.org
```

```text
mythaia://import?url=https://panel.example.com/sub/TOKEN&front=104.16.1.1&sni=www.example.org
```

| Parameter | Meaning |
|---|---|
| `front` | Hosts actually dialled: an IP or a domain, optionally with `:port` (IPv6 as `[addr]:port`). Separate them with commas or repeat the key; they are tried in order. |
| `sni` | The name sent in the TLS handshake (`front-sni` works too). With `sni` alone, the panel's own address is dialled under that name. |
| `name` | Optional name for the group. |

- The first form is an ordinary URL: the part after `#` never reaches the panel, so the same link
  still works in other clients.
- The second form opens Mythaia straight from a browser or a messenger.
- Pasting, scanning or opening either form fills in the **Fronting** fields of the Add sheet, so
  you can check them before anything is downloaded.
- **Subscription settings → Copy link with fronting** turns a subscription you already have into such a
  link, on Android and on Windows.

Happ’s form, where the URL names the front and `host` the panel, works too:

```text
https://cdn.example.net/sub/TOKEN#My%20VPN?resolve-address=104.16.1.1&host=panel.example.com
```

## Subscription metadata

Providers steer a subscription the way they do for Happ. Each key is read from the response headers or, when the header is missing, from a `#key: value` line in the body — above a base64 list or inside it. Text may be plain or `base64:`; a flag is on for `true` or `1`.

```text
#profile-title: base64:TXkgVlBO
#profile-update-interval: 6
#fallback-url: https://backup.example.com/sub/TOKEN
#sub-info-text: Maintenance tonight 02:00–03:00 UTC
#sub-info-color: blue
vless://…
```

| Key | Effect |
|---|---|
| `profile-title`, `subscription-userinfo` | Group name; traffic and expiry |
| `announce`, `support-url`, `profile-web-page-url` | The provider’s message; Support and Account page buttons |
| `sub-info-text`, `sub-info-color` (`red`, `blue`, `green`), `sub-info-button-text`, `sub-info-button-link` | A coloured block with a button |
| `sub-expire` (or `notification-subs-expire`), `sub-expire-button-link` | A warning three days before expiry, with a Renew button |
| `profile-update-interval` | Background refresh interval, in hours |
| `subscription-auto-update-open-enable` | Refresh every time the app opens |
| `subscription-auto-update-enable: 0` | No background refresh for this subscription |
| `subscription-request-timeout` | Seconds to wait for the panel |
| `new-url` | The subscription moves to this URL for good (fronting in its fragment is read too) |
| `new-domain` | The same, keeping the path and query |
| `fallback-url` | Fetched when the main URL returns an error or does not answer within 10 seconds |
| `fronting-target` (or `resolve-address`) | Hosts to dial instead of the panel, comma-separated; `off` turns fronting off |
| `fronting-sni` | The SNI to send |
| `host` | With `resolve-address`: the panel’s real host, as Happ writes it |
| `routing` (`happ://routing/add/…`, `happ://routing/onadd/…`, `happ://routing/off`), `routing-enable` | Routing profile (Direct, Proxy, Block lists and `geosite.dat` / `geoip.dat` files); `happ://routing/…` links also work when opened or pasted |
| `subscription-autoconnect`, `subscription-autoconnect-type` (`lastused`, `lowestdelay`, `random`) | Connect on start using the chosen server from this subscription |
| `subscription-ping-onopen-enabled`, `ping-type` (`proxy`, `proxy-head`, `tcp`, `icmp`), `check-url-via-proxy` | Measure servers when the app opens; how latency is measured and against which URL |
| `change-user-agent` | `User-Agent` sent on future refreshes of this subscription |
| `fragmentation-enable`, `fragmentation-packets`, `fragmentation-length`, `fragmentation-interval`, `fragmentation-maxsplit` | TLS record/TCP fragmentation settings |
| `exclude-routes`, `exclude-routes-set` | Extra CIDRs excluded from the tunnel (`off` clears them) |
| `per-app-proxy-mode` (`off`, `bypass`, `only`), `per-app-proxy-list` | Split tunnelling by app package on Android |
| `app-auto-start` | Start the VPN on Android boot or launch Mythaia at Windows sign-in |
| `subscriptions-sort-type` (`ping`, `alphabet`, `off`), `subscription-pin`, `subscriptions-collapse`, `subscriptions-expand-now` | Server sort order, group pin and collapsed state |
| `hide-settings` | Hide the raw server configuration editor and shareable links for this subscription’s servers |
| `serverDescription` (or `description`) | Short note on a server link’s query or JSON object, shown under the server name |

`new-url`, `new-domain`, `fallback-url`, the fronting keys, routing profiles and the keys that change app settings are taken only from a response that came over verified HTTPS: from a plain-HTTP panel, anyone on the path could redirect the subscription or rewrite settings. A switch in Settings (**Let subscriptions change app settings**) turns remote setting changes off while keeping server lists and notices. When a refresh brings a new `announce` or `sub-info-text`, or when `sub-expire` enters the three-day window, the app also raises a system notification once per message.

When a refresh fails, a bar at the bottom says so and offers **Try through a working server**: the subscription is downloaded through the connected server or the fastest one that answers a quick check, which gets it past a panel blocked outright. The bar goes away on its own.

## Building from source

**Requirements:** JDK 21 and the Android SDK with platform 36. The NDK and CMake are installed by
the Android Gradle Plugin on the first build.

```bash
git clone https://github.com/Myth-T0ks1k/Mythaia.git
cd Mythaia
./gradlew :app:assembleDebug                  # Android debug APK
./gradlew :core:test :app:testDebugUnitTest   # unit tests
```

Release builds are signed with your own key. Put these lines in `local.properties`, which is never
committed, or set them as environment variables:

```properties
KEYSTORE_FILE=/path/to/release.jks
KEYSTORE_PASSWORD=...
KEY_ALIAS=...
KEY_PASSWORD=...
```

`./gradlew :app:assembleRelease` builds an arm64 APK; add `-Pmythaia.universal=true` for every ABI.

<details>
<summary><b>Windows app</b></summary>

<br>

The native library needs Visual Studio 2022 with MSVC, CMake and Ninja; packaging needs a JDK 21
that ships `jmods`, whose path goes into `local.properties` as `desktop.jdk`.

```bat
desktop\native\build.cmd
gradlew :desktop:run
gradlew :desktop:packageExe :desktop:packageMsi
```

The installers need WiX 3.14 on the `PATH`. User data lives in `%APPDATA%\Mythaia`.

</details>

## Project layout

| Module | What it is |
|---|---|
| [`core`](core) | Platform-free Kotlin: models, share links, subscriptions, every protocol and the TLS stack |
| [`app`](app) | Android app: Jetpack Compose UI, `VpnService` and an lwIP-based userspace TCP/IP stack |
| [`wear`](wear) | Wear OS companion: connection status and a one-tap toggle |
| [`desktop`](desktop) | Windows app: Compose for Desktop, system-proxy and Wintun TUN engines |

The `core` module is also published to
[GitHub Packages](https://github.com/Myth-T0ks1k?tab=packages&repo_name=Mythaia) as
`com.mythaia:mythaia-core`.

## Contributing

Bug reports, ideas and pull requests are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md)
first, and report security problems privately as described in [SECURITY.md](SECURITY.md).

Questions and discussion: [@mythaia_chat](https://t.me/mythaia_chat) on Telegram or [GitHub Discussions](https://github.com/Myth-T0ks1k/Mythaia/discussions).

## License

Mythaia is free software under the [GNU General Public License v3.0](LICENSE.txt).

It builds on Anywhere by NodePassProject (GPL-3.0) and includes
[lwIP](https://savannah.nongnu.org/projects/lwip/), [BLAKE3](https://github.com/BLAKE3-team/BLAKE3),
[libyaml](https://github.com/yaml/libyaml), [ngtcp2](https://github.com/ngtcp2/ngtcp2), [Mbed TLS](https://github.com/Mbed-TLS/mbedtls),
[Wintun](https://www.wintun.net), [Bouncy Castle](https://www.bouncycastle.org) and
[Brotli](https://github.com/google/brotli) under their own licenses. Product names in the routing
rule sets belong to their owners.

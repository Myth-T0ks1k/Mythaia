# Changelog

All notable changes to Mythaia are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Mythaia Pro for macOS.** The desktop app runs on macOS 12 or newer, Apple silicon and Intel,
  over the same core as on Android and Windows, with every protocol of it, Hysteria2 and TUIC
  included. It has the two modes of the Windows app: *system proxy* sets the web, secure web and
  SOCKS proxies of every network service and restores them on disconnect; *TUN* brings up a utun
  interface with its routes and DNS, run by a small launch daemon that the app installs with one
  administrator prompt and that runs from its own root-owned copy of the app. It has a menu-bar
  icon and launch at login, and opens `mythaia://` and share links. Releases carry
  `Mythaia-Pro-X.Y.Z-macos-arm64.dmg` and `Mythaia-Pro-X.Y.Z-macos-x64.dmg`. The app is signed
  ad hoc, not notarized, so macOS refuses it on first launch until it is allowed in
  **System Settings → Privacy & Security → Open Anyway** (on macOS 14 and older: right-click →
  **Open**).
- **Mythaia Pro for iOS.** A native Swift app for iOS 16 or newer, on a Swift port of the core:
  VLESS (Vision, Reality, WebSocket, HTTPUpgrade, gRPC, XHTTP), VMess, Trojan, Shadowsocks (AEAD
  and 2022), SOCKS5, AnyTLS, NaiveProxy over HTTP/2, Hysteria2 (Salamander, Gecko), TUIC v5,
  WireGuard and AmneziaWG, over its own TLS 1.3 client with browser fingerprints and ClientHello
  fragmentation. Subscriptions with Happ metadata, fronting and download through a working
  server; Auto; country bypass; routing rules; server and chain editors. The packet tunnel either
  carries every app's traffic (TUN mode, over lwIP) or applies proxy settings. A home-screen
  widget, a Control Center toggle on iOS 18, nine languages. Not yet: VLESS encryption (ML-KEM),
  Sudoku, Nowhere and HTTPS interception. **Not distributed yet:** installing it needs an Apple
  developer account for the Network Extension entitlement, which the project does not have, so
  there is no App Store or TestFlight build. It builds from source (see `ios/README.md`); CI keeps
  an unsigned IPA as a build artifact, which TrollStore can install, while AltStore or Sideloadly
  with a free Apple ID cannot run the tunnel.
- **The interop lab runs on macOS too.** A macOS runner checks the desktop core, the Swift core
  and macOS TUN mode against the lab's reference servers.

## [1.3.0] — 2026-10-16

### Added

- **Subscription metadata, as Happ reads it.** Every key comes from the response headers or, when
  a header is missing, from a `#key: value` line in the body, above a base64 list or inside it, so
  a panel set up for Happ works unchanged. New keys: `new-url` and `new-domain` (the subscription
  moves for good), `fallback-url` (tried when the main URL errs or is silent for 10 seconds),
  `fronting-target`, `fronting-sni` and Happ's `resolve-address` and `host` (fronting set or
  switched off by the panel), `sub-info-*` (a coloured block with a button), `sub-expire` (a
  warning three days before expiry, with a Renew button), `subscription-auto-update-open-enable`
  (refresh whenever the app opens), `subscription-auto-update-enable` and
  `subscription-request-timeout`. The keys that move a subscription are taken only from a response
  that came over verified HTTPS. The README lists them all.
- **Update through a working server.** When a subscription does not update, a bar at the bottom
  says so and offers to try again through a server that works: the connected one, or the first of
  the subscription's own servers (then the others) to answer a fresh check. This gets a
  subscription past a panel that is blocked outright. The bar goes away on its own. A failure in
  the background refresh is remembered and shown the next time the app opens. On Windows too.
- Happ's fronted link form, `https://front/sub#Name?resolve-address=IP&host=panel`, is read
  wherever a subscription is added.

### Changed

- The update-failed dialog on Android is now that bar.
- A refresh that waits on a CDN front which does not answer moves on to the next front instead of
  giving up on all of them.

## [1.2.0] — 2026-10-16

### Changed

- **Android: QR codes are read with ZXing.** Scanning went through Google ML Kit, which lives in
  Google Play services, so on a phone without them it did nothing. ZXing reads the code on the
  phone itself, offline, on every device, and reads light-on-dark codes too.
- **A build without Google Play services.** `-Pmythaia.foss=true` leaves out every Google Play
  services library, and with it the Wear OS bridge, whose Data Layer API is proprietary. This is
  the build F-Droid makes; CI builds it on every change and fails if such a library slips back in.
  The NDK version is pinned, so the native library builds the same everywhere.

### Added

- The website, [myth-t0ks1k.github.io/Mythaia](https://myth-t0ks1k.github.io/Mythaia/), in
  English, Russian, Turkmen, Simplified Chinese and Persian.
- A [Scoop bucket](https://github.com/Myth-T0ks1k/scoop-bucket) for Windows and GitHub
  Discussions for questions.
- Store texts, icon and screenshots in `fastlane/` for app catalogues.

## [1.1.2] — 2026-10-16

### Security

- **Windows: the TUN service runs from Program Files.** The service runs as LocalSystem, and it
  used to run the copy of the app the user had started — a portable folder on the Desktop, a
  per-user install in AppData. Any program under the user's account could replace a file there and
  run as SYSTEM at the next service start. *Install* now copies the app to
  `C:\Program Files\Mythaia Pro Service`, which only administrators can change, and registers the
  service there; *Remove* deletes that copy too. Links and junctions in the app folder are not
  followed when copying.

### Changed

- Windows: an app update does not touch the service's copy, so the settings now say when the
  service is older than the app and offer *Update*, which replaces the copy in one administrator
  prompt.

## [1.1.1] — 2026-10-16

### Fixed

- **Windows: the TUN service installs again.** *Install* in the settings never registered it: the
  command that created the service lost its quotes on the way to `sc`, and the launcher's path —
  `Mythaia Pro.exe` always has a space — reached Windows broken. The app now starts itself once
  with administrator rights and registers the service through the Windows API, so any folder
  works, Cyrillic and spaces included. Installing again over an existing service points it at the
  current copy.
- Windows: a declined administrator prompt, a failed installation and a service that does not
  answer now each say so, instead of one message for all three.
- The Android native library no longer carries the source paths of the machine that built it.

## [1.1.0] — 2026-10-15

### Added

- **Ping (TCP/UDP)** — a button next to the speed test on Android and Windows. Servers on TCP are
  timed by the TCP connect; Hysteria2, TUIC and Nowhere over QUIC by a QUIC probe over UDP, with
  Hysteria2's obfuscation applied; WireGuard by its real handshake.
- **Remove non-working** in the group menu: deletes the servers whose last check failed, after a
  confirmation that says how many.
- **Export as links** on Android: the group's servers as share links, one per line, through the
  share sheet — as text, or as a `.txt` file when the list is long. On Windows, **Save links to a
  file** joins *Copy all links*.

### Changed

- The old TCP ping is now Ping (TCP/UDP). It used to report every Hysteria2 and TUIC server as
  failed, since those listen on UDP only.
- On Windows, removing non-working servers also removes those whose certificate does not verify,
  as on Android.

## [1.0.2] — 2026-10-15

Bulk server lists: tested with a subscription of 10,000 servers.

### Fixed

- **Auto and “Test all” no longer freeze the app** on a big group. Results used to be copied into
  the latency map one server at a time on the main thread, which turned 10,000 servers into an
  “isn't responding” dialog; they now land in batches.
- **Auto measures at most 48 servers per round**: the live one, the fastest of late and a random
  share of the rest, so successive rounds still reach every server. A round of 10,000 used to take
  hours, and recovering from a blocked server waited for all of it.
- **Latency tests close what they open.** Hysteria2, TUIC, AnyTLS, NaiveProxy and Nowhere tests
  left a pooled connection (with its threads and socket) per server; testing thousands of them
  could run the app out of threads and memory. The live tunnel's connection is never touched.
- **Pasting thousands of links** or an Xray JSON with thousands of outbounds is processed in linear
  time and saved in one write, and the Add sheet no longer crashes when it goes to the background
  holding a huge paste.
- **The server store** is saved off the main thread, once per burst of changes, in a compact file,
  and loaded in a single pass: the app starts several times faster with a big list.
- **Refreshing a big subscription** merges the servers in linear time, off the main thread.
- **Routing rules** pick their server from a searchable list that only draws what is on screen.
- A subscription link's `name` works without fronting too.

### Security

- **Only the live server goes around the tunnel.** Every server ever measured used to, so with a
  big CDN-fronted subscription the CDN's shared addresses — and other websites behind them — left
  the tunnel unencrypted.

## [1.0.1] — 2026-10-15

### Fixed

- WebSocket servers: a normal close from the server (`1000`, `1001`, or the empty `1005` a CDN
  often sends) now ends the connection cleanly. It used to be treated as a failure, so the app on
  the other end got a reset instead of the end of the data and the log filled with
  “WebSocket closed (1005)”.
- An empty close frame is answered with an empty one; the reply used to carry the reserved
  code 1005.
- A failed connection to the server is logged once as “TCP connection failed: Connection timed
  out” instead of repeating “Connection failed” three times.

## [1.0.0] — 2026-10-14

The first public release of Mythaia for Android, Wear OS and Windows.

### Added

- **Fronting in one link.** A subscription link can carry its own domain fronting, either in the
  URL fragment (`https://panel/sub#front=…&sni=…`) or as an app link
  (`mythaia://import?url=…&front=…&sni=…`). Opening, pasting or scanning it fills in the Fronting
  fields; *Copy link with fronting* creates one from an existing subscription.
- **Allow insecure for every TLS-based protocol** (VLESS, VMess, Trojan, Hysteria2, TUIC, AnyTLS,
  NaiveProxy and more), shown with a red warning wherever it is on. Pinned certificates are
  always checked, insecure or not.
- The Wear OS companion is now built and signed together with the phone app.
- The `core` library is published to GitHub Packages as `com.mythaia:mythaia-core`.

### Changed

- The country bypass applies in rule mode only. Global mode sends all traffic through the proxy,
  the home country included, on Android and Windows alike.
- A link without `sni` takes its TLS server name from the transport's `Host` (WebSocket,
  HTTPUpgrade, XHTTP) or gRPC authority, as v2rayN and v2rayNG do. Servers saved earlier are
  corrected when they connect.
- Release builds are signed with the project's own release key. Builds installed before 1.0.0 must
  be removed once before installing this version.

### Fixed

- A failed read on a UDP flow, such as an HTTP/2 `421` or a reset stream, ends that one flow
  instead of stopping the whole VPN.
- Addresses answered for country-bypass names keep going direct, so a `.tm` site hosted abroad no
  longer slips into the proxy in rule mode.
- The fronting hint referred to “the SNI above” for a field placed below it.

### Security

- TLS: CertificateVerify is mandatory, TLS 1.2 certificates and key-exchange signatures are
  verified, downgrade sentinels are checked, and the handshake has a hard deadline.
- Reality verifies the server's Finished message.
- Windows: the service no longer runs commands read from a user-writable file.

[Unreleased]: https://github.com/Myth-T0ks1k/Mythaia/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/Myth-T0ks1k/Mythaia/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Myth-T0ks1k/Mythaia/compare/v1.1.2...v1.2.0
[1.1.2]: https://github.com/Myth-T0ks1k/Mythaia/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/Myth-T0ks1k/Mythaia/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/Myth-T0ks1k/Mythaia/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/Myth-T0ks1k/Mythaia/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Myth-T0ks1k/Mythaia/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Myth-T0ks1k/Mythaia/releases/tag/v1.0.0

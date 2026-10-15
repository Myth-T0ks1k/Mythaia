# Changelog

All notable changes to Mythaia are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.1.0]: https://github.com/Myth-T0ks1k/Mythaia/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/Myth-T0ks1k/Mythaia/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Myth-T0ks1k/Mythaia/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Myth-T0ks1k/Mythaia/releases/tag/v1.0.0

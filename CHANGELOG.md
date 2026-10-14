# Changelog

All notable changes to Mythaia are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.1]: https://github.com/Myth-T0ks1k/Mythaia/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Myth-T0ks1k/Mythaia/releases/tag/v1.0.0

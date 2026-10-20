# Changelog

All notable changes to Mythaia are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Windows:** ending the app from Task Manager, or a crash, left the system proxy pointing at it,
  and every program on the PC was offline until the app was started again. A small helper
  (`mythaia-proxy-guard.exe`, no administrator rights, no window) now waits for the app to exit and
  puts the old proxy settings back if the app did not; a sign-in entry does the same after a power
  cut or a blue screen.
- **Windows:** JNA's `jnidispatch.dll` ships with the app instead of being unpacked into `%TEMP%`
  on every start, where antivirus and AppLocker block DLLs and the system proxy, TUN and the
  service then did not work.
- **Windows:** on a PC whose system locale cannot spell the install folder (Turkmen ň, ş or ý under
  a Russian or English locale, often in the user name of a per-user install) the app quit before
  showing anything. The launcher now runs with UTF-8 as its code page (Windows 10 1903 and later).

### Added

- **Updates from inside the app.** Settings → About → Check for updates asks GitHub for the
  latest release. On Android it downloads the APK for the device (arm64-v8a, or universal on
  anything else), checks its SHA-256 against the release's `SHA256SUMS.txt` and its signing
  certificate against the release key, and hands it to the system installer; where GitHub is
  blocked, the download goes through the server the tunnel is on. A daily check can be turned on
  next to it — it is off until you do, so the app never contacts GitHub unasked. The F-Droid build
  points to its store instead, and a copy signed with another key opens the release page.
- **Windows:** the same check downloads the installer, or the zip for a portable copy, verifies its
  checksum, and on request runs the installer and restarts.
- **Servers grouped by country.** The server list on Android and Windows falls into collapsible
  country sections with the flag (or code) and the number of servers. The country comes from the
  name — a flag, an ISO code, or the country or a city written out in English, Russian, Spanish,
  Persian or Chinese — and otherwise from the GeoIP database for an address already known; the
  list never sends a DNS query for it. Each section has its own speed test and an Auto that keeps
  to that country's servers, also in the background. Grouping can be turned off in the list's menu.
- **Android TV home screen.** On a television (`UiModeManager` / leanback), Home opens as a
  two-pane 10-foot layout built for a remote's D-pad: the connect toggle receives focus first,
  groups and chains switch across the top, the server list and its country sections sit beside it
  in large cards with high-contrast focus borders, and Settings is reachable with the D-pad alone.
  Phone and tablet layouts are unchanged.
- **Windows: WireGuard and AmneziaWG.** WireGuard and AmneziaWG (`Jc`, `Jmin`, `Jmax`, `S1`, `S2`,
  `H1`–`H4`) profiles now connect on Windows in TUN mode, both elevated and through the background
  service, with the interface addresses, MTU, DNS and `AllowedIPs` routes from the profile and a
  host route for the peer on the physical gateway that follows network changes. Profiles can be
  added by pasting a `wg-quick` `.conf`, a `wg://` / `wireguard://` link, scanning a QR code, or
  filling in the form.
- **Happ routing profiles.** Subscriptions can ship a routing profile in the `routing` header or
  `#routing:` line (`happ://routing/add/{base64}`, `happ://routing/onadd/{base64}`,
  `happ://routing/off`) and switch routing on or off with `routing-enable`; the same `happ://routing/…`
  links work when opened as a deep link or pasted on Android and Windows. Direct, Proxy and Block
  domain, CIDR and `geosite:` / `geoip:` rules run in the tunnel and local proxy alongside the
  built-in rule sets, and custom `geosite.dat` / `geoip.dat` files named by the profile are
  downloaded and refreshed on its schedule. The active profile is shown in Rule Sets / Settings
  with a button to turn it off.
- **Subscription-managed settings.** Over verified HTTPS, a subscription can set
  `subscription-autoconnect` (`lastused`, `lowestdelay`, `random`),
  `subscription-ping-onopen-enabled`, `ping-type` (`proxy`, `proxy-head`, `tcp`, `icmp`) and
  `check-url-via-proxy`, `change-user-agent`, `fragmentation-*`, `exclude-routes` and
  `exclude-routes-set`, `per-app-proxy-mode` and `per-app-proxy-list` (Android), `app-auto-start`
  (Android boot or Windows sign-in), `subscriptions-sort-type`, `subscription-pin`,
  `subscriptions-collapse` and `subscriptions-expand-now`, `hide-settings` (hides the raw config
  editor and shareable links for that subscription's servers) and per-server `serverDescription`
  (shown under the server name). Settings shows which subscription manages app settings and has a
  **Let subscriptions change app settings** switch to turn remote changes off.
- **Provider notifications.** When a refresh brings a new `announce` or `sub-info-text`, or when
  `sub-expire` is within three days, the app raises a system notification once per message on
  Android (`Provider messages` channel) and Windows (tray notification), without Firebase or Google
  Play services.

## [1.3.1] — 2026-10-18

### Fixed

- **Hysteria2, TUIC and Nowhere could crash the app.** ngtcp2 keeps the stream data it sends and
  reads it again to retransmit a lost packet, but the native bridge freed it as soon as the packet
  was built. On a path that loses packets the next retransmission read freed memory: the app
  closed at once with an access violation in `mythaia_native.dll` (reproduced in seconds with
  uploads over a link dropping 5 % of packets), or, when it did not, sent leftover heap bytes to
  the server inside the stream. The data now stays until the server acknowledges it. Android has
  the same fix.
- A Hysteria2 or TUIC server that stops answering no longer fills the local proxy: dials no longer
  wait in line for one 10-second handshake each, a failed attempt is retried after 3–15 seconds
  instead of by every waiting connection, and every dial through the proxy gives up after 30
  seconds. Sessions are no longer left open behind a server switch or a cancelled test, and UDP
  stops queuing a coroutine per packet while the server is unreachable.
- QUIC sessions credit their shared receive window as data is read, not in each stream's batch,
  so connections that go quiet partway through a download can no longer hold the window shut
  for every other stream on the session.
- **Windows:** copy or paste in a text field while another program held the clipboard (Punto
  Switcher, clipboard managers, remote desktop) closed the window. Any other error inside the
  window is now logged and the window rebuilt instead of closed.
- **Windows:** the app did not start on PCs with Java Access Bridge turned on (screen readers turn
  it on).
- **Windows:** turning TUN on could leave no copy of the app running; the elevated copy now waits
  for the old one to let go, and the UAC prompt no longer freezes the window.
- **Windows:** ending a TUN session could crash the app when the packet reader was preempted at
  the wrong moment; command-line tools that hang no longer block connecting; a blocked
  `jnidispatch.dll` or `wintun.dll` is reported instead of closing the window or leaving TUN stuck
  in "Connecting"; a busy service pipe no longer drops a working service tunnel.
- **Windows:** the local proxy survives a failed `accept()`; direct connections no longer take the
  threads that dials and tests need; Exit no longer freezes the window while disconnecting.
- **Windows:** an Auto round or ping stopped by a reconnect, pin or Disconnect no longer marks
  unmeasured servers Failed, which "Remove failed" then deleted, nor switches away from a server
  just pinned.
- **Windows:** a settings or server file that another program had open at start is no longer
  replaced with empty defaults.
- **Windows:** NIO no longer depends on AF_UNIX sockets, which fail on some PCs.
- **Windows:** with thousands of servers, pasting a list, refreshing a subscription or removing
  duplicates froze the window into "Not responding": each change wrote the whole list (some 30 MB
  for 10,000 servers) on the window's thread, and building every server's link held up every
  click. Saves now go to disk in the background, a burst of changes as one write, links are built
  outside the lock, and `configs.json` is stored without indentation or default values, which
  every version reads.
- **Windows:** the service could fail to start on a slow boot with error 1053; it now answers
  Windows first and sets itself up afterwards, reporting progress while it does.
- **Windows:** a TUN connection the service took more than 30 seconds to bring up was shown as
  failed but left running. The window now asks the service what it did and uses that tunnel, or
  stops it.
- **Windows:** proxy mode did nothing on PCs that go online through a PPPoE, dial-up or VPN
  connection, which have proxy settings of their own; those are now set too, and put back on
  disconnect.
- **Windows:** reading QR codes from the screen never found one on a second monitor, and missed
  small ones at display scales above 100 %.

### Added

- **Windows: crash reports.** Uncaught errors go to `%APPDATA%\Mythaia\logs\mythaia.log` with their
  stack, and the report the JVM writes when it dies in native code is copied there on the next
  start, with the line that names the cause. The first log line now carries the Windows and Java
  versions, the CPU count and the heap size. After a crash in the graphics driver, the app draws
  with the CPU (`render-api` in the data folder; delete it to go back).

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

[1.3.1]: https://github.com/Myth-T0ks1k/Mythaia/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/Myth-T0ks1k/Mythaia/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/Myth-T0ks1k/Mythaia/compare/v1.1.2...v1.2.0
[1.1.2]: https://github.com/Myth-T0ks1k/Mythaia/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/Myth-T0ks1k/Mythaia/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/Myth-T0ks1k/Mythaia/compare/v1.0.2...v1.1.0
[1.0.2]: https://github.com/Myth-T0ks1k/Mythaia/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Myth-T0ks1k/Mythaia/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Myth-T0ks1k/Mythaia/releases/tag/v1.0.0

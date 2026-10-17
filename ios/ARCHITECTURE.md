# Mythaia Pro for iOS — architecture

The iOS app is a Swift port of the Kotlin `core` module (in `../core`) plus a
SwiftUI app modelled on the Android app (`../app`). The Kotlin code is the
reference for every behaviour: when in doubt, do what it does, with the same
names.

## Layout

```
ios/
  project.yml                  XcodeGen spec (the .xcodeproj is generated, not committed)
  Config.example.xcconfig      copy to Config.xcconfig: team id and bundle id
  bootstrap.sh                 copies the vendored C (ngtcp2, Mbed TLS) from app/src/main/jni into CQuic/vendor
  Packages/MythaiaKit/         Swift package: everything that is not UI
    Sources/CQuic/             C bridge over ngtcp2 (QUIC), with function-pointer callbacks
    Sources/MythaiaKit/
      Core/                    ByteStream, StreamReader, MythaiaError, Log, relay, withTimeout
      Model/                   ProxyConfiguration and friends, Subscription, ProxyChain, settings
      Links/                   share links (parse + export), base64 bodies, Clash YAML, Xray/sing-box JSON
      Subscription/            fetcher, Happ metadata, fronting, WorkingServers
      Crypto/                  primitives CryptoKit lacks: SHAKE128, BLAKE2b/2s, BLAKE3, FNV-1a, XChaCha20-Poly1305
      Transport/               TCP (Network.framework), system TLS, WebSocket, HTTPUpgrade, HTTP/2, gRPC, XHTTP
      TLS/                     own TLS 1.3 client (fingerprinted ClientHello, fragmentation) and REALITY
      Protocols/               VLESS (+Vision), Trojan, Shadowsocks, VMess, SOCKS5, AnyTLS, Naive (HTTP/1.1, HTTP/2),
                               QUIC + Hysteria2 + TUIC, WireGuard/AmneziaWG (protocol half); Dialer (TCP and UDP)
      Engine/                  local SOCKS5/HTTP proxy, router, rules database, latency tests, Auto
      Store/                   persistence in the App Group container, shared by app and tunnel
    Tests/MythaiaKitTests/     XCTest; run with `swift test` on a Mac (LabInteropTests against the lab servers)
  Mythaia/                     the iOS app (SwiftUI)
  MythaiaTunnel/               the packet tunnel extension (NEPacketTunnelProvider)
    Tun/                       TUN mode: lwIP (app/src/main/jni/lwip) driven from Swift, Fake-IP DNS
    WireGuard/                 the WireGuard engine (layer 3, instead of the packet stack)
  MythaiaWidget/               home-screen widget and the iOS 18 Control Center toggle
```

## Rules for all code

- Swift 5 language mode, Swift 5.10 or newer, iOS 16 / macOS 13. No third-party
  packages: Foundation, Network, CryptoKit, Security, SQLite3, SwiftUI,
  NetworkExtension, AVFoundation only.
- MythaiaKit must build for macOS too (its tests run there), so no UIKit in it.
- Names mirror the Kotlin core. A Kotlin `data class` becomes a `struct` that is
  `Codable, Hashable`; an `enum class X(val raw: String)` becomes
  `enum X: String, Codable, CaseIterable` whose cases are the lowerCamelCase of
  the Kotlin constants and whose raw values are the Kotlin `raw` strings;
  `UShort` ports are `UInt16`; `ByteArray` is `Data`; `Long` epoch millis stay
  `Int64` millis.
- Public API of MythaiaKit is `public`. Everything else stays internal.
- I/O is async/await over `ByteStream` (see Core/ByteStream.swift). A layer
  wraps the stream below it; it never reaches past it.
- Errors are `MythaiaError` with a message a user can read.
- Comments explain why, as in the Kotlin core. No mention of where code came
  from beyond what the Kotlin file itself says.
- Tests: port the Kotlin tests that hold test vectors (link parsing, crypto,
  framing) to XCTest. A wire format test must check the bytes a peer reads,
  from an independently derived value, not only a round trip.

## Data flow

The app stores servers and subscriptions in the App Group container
(`Store/`), and the advanced settings (allow insecure, trusted certificates,
routing rules, fragmentation) beside them. Connecting saves the chosen server
and the routing settings to the container and starts the tunnel through
`NETunnelProviderManager`. The tunnel reads them and runs one of three
engines:

- TUN mode (the default, `AppSettings.tunnelMode`): the interface takes the
  default routes and DNS; `TunStack` terminates every TCP and UDP flow of the
  device in lwIP and answers DNS from a Fake-IP pool, so flows carry names.
- Proxy mode: no routes; `LocalProxyServer` (one mixed SOCKS5/HTTP port on
  127.0.0.1) and `NEProxySettings` pointing the system at it.
- WireGuard: a layer-3 profile replaces both; its AllowedIPs are the routes.

In the first two, each flow goes through `Router` (rule or global mode, the
user's rules, country bypass from Rules.db) to `Dialer`, which builds the stack
for the server: TCP or QUIC → TLS or REALITY → transport (WebSocket,
HTTPUpgrade, gRPC, XHTTP) → protocol (VLESS, Trojan, ...), chains included.
The app talks to the running tunnel with provider messages (switch server,
stats, log tail, reload, app active), and Auto runs in the tunnel while the
app is away.

The CI (`.github/workflows/apple.yml`) runs `swift test` on macOS with the
interop lab's reference servers up, so every protocol the Dialer supports is
checked against Xray and sing-box on each push.

## Interfaces between modules

These signatures are fixed; the modules were written in parallel against them.

```swift
// Transport/ (Network.framework underneath)
public final class TCPStream: ByteStream {
    public static func connect(host: String, port: UInt16, timeout: Double = 10) async throws -> TCPStream
}
public struct TLSClientOptions {
    public var serverName: String
    public var alpn: [String]
    public var allowInsecure: Bool
    public var pinnedCertSHA256: [Data]          // empty = system trust only
    public var minVersion: TlsVersion?            // Model/ enum, mirrors Kotlin TlsVersion
    public var maxVersion: TlsVersion?
    public init(serverName: String, alpn: [String] = [], allowInsecure: Bool = false,
                pinnedCertSHA256: [Data] = [], minVersion: TlsVersion? = nil, maxVersion: TlsVersion? = nil)
}
public final class SystemTLSStream: ByteStream {   // TLS straight over a new TCP connection
    public static func connect(host: String, port: UInt16, options: TLSClientOptions, timeout: Double = 10) async throws -> SystemTLSStream
    public var negotiatedALPN: String? { get }
}
public enum WebSocketTransport {
    public static func open(over stream: ByteStream, configuration: WebSocketConfiguration, earlyData: Data?) async throws -> ByteStream
}
public enum HTTPUpgradeTransport {
    public static func open(over stream: ByteStream, configuration: HttpUpgradeConfiguration) async throws -> ByteStream
}
public enum GRPCTransport {
    public static func open(over stream: ByteStream, configuration: GrpcConfiguration, authority: String) async throws -> ByteStream
}
public enum XHTTPTransport {
    /// `dial` opens a fresh secured connection to the server; XHTTP may need several.
    public static func open(configuration: XHttpConfiguration, authority: String, alpn: String?,
                            dial: @escaping () async throws -> ByteStream) async throws -> ByteStream
}

// TLS/ (own TLS 1.3 client, needed for REALITY and for TLS inside a chain)
public enum TLSClient {
    public static func handshake(over stream: ByteStream, options: TLSClientOptions,
                                 fingerprint: TlsFingerprint) async throws -> TLSSessionStream
}
public final class TLSSessionStream: ByteStream { public var negotiatedALPN: String? { get } }
public enum RealityClient {
    public static func handshake(over stream: ByteStream, configuration: RealityConfiguration,
                                 alpn: [String]) async throws -> ByteStream
}

// Protocols/
public enum Dialer {
    /// A TCP flow to `target` through `configuration`, its chain included.
    public static func connect(_ configuration: ProxyConfiguration, to target: Endpoint,
                               initialData: Data? = nil, timeout: Double = 15) async throws -> ByteStream
    /// A TCP flow to `target` without a proxy.
    public static func direct(to target: Endpoint, timeout: Double = 10) async throws -> ByteStream
}

// Subscription/ (network access goes through closures so it can run through a server)
public struct SubscriptionFetchResult {
    public var configurations: [ProxyConfiguration]
    public var subscription: Subscription        // metadata already applied
}
public enum SubscriptionFetcher {
    public static func fetch(_ subscription: Subscription, hwid: String?, via: ProxyConfiguration?,
                             timeout: Double?) async throws -> SubscriptionFetchResult
    public static func fetch(url: String, hwid: String?) async throws -> SubscriptionFetchResult
}

// Store/ (App Group container, shared by the app and the tunnel)
public enum AppGroup {
    public static var identifier: String { get }  // Info.plist key MythaiaAppGroup
    public static var containerURL: URL { get }
}
public final class MythaiaStore {
    public static let shared: MythaiaStore
    public init(directory: URL)
    public func loadConfigurations() -> [ProxyConfiguration]
    public func saveConfigurations(_ value: [ProxyConfiguration])
    public func loadSubscriptions() -> [Subscription]
    public func saveSubscriptions(_ value: [Subscription])
    public func loadChains() -> [ProxyChain]
    public func saveChains(_ value: [ProxyChain])
    public func loadSettings() -> AppSettings
    public func saveSettings(_ value: AppSettings)
    public func loadSelection() -> SelectionState
    public func saveSelection(_ value: SelectionState)
    public func saveTunnelStart(_ value: TunnelStartOptions)
    public func loadTunnelStart() -> TunnelStartOptions?
}
public struct AppSettings: Codable, Hashable {        // defaults as on Android
    public var routingMode: RoutingMode               // .rule / .global
    public var bypassCountryCode: String?             // e.g. "TM"; nil = none
    public var themeMode: ThemeMode                   // Model/, mirrors Kotlin
    public var localProxyPort: UInt16                 // 0 = pick a free one
    public var autoRecheckMinutes: Int                // 10
    public var latencyKind: LatencyKind
    public var hwid: String                           // sent as x-hwid to panels that ask
}
public struct SelectionState: Codable, Hashable {
    public var activeGroupId: String                  // "default" or a subscription UUID string
    public var groupPins: [String: UUID]              // no pin = Auto
    public var autoChoices: [String: UUID]
    public var selectedChainId: UUID?
}
public struct TunnelStartOptions: Codable {
    public var configuration: ProxyConfiguration      // chain already resolved into configuration.chain
    public var settings: AppSettings
    public var groupConfigurations: [ProxyConfiguration]  // for Auto inside the tunnel; empty when pinned
}

// Protocols/ — UDP (added after the first round; protocols without UDP throw unsupported)
extension Dialer {
    /// A UDP flow to `target` through `configuration` (VLESS, Trojan, VMess UDP over the stream;
    /// SOCKS5 UDP ASSOCIATE; Shadowsocks UDP). Each packet is one datagram to or from `target`.
    public static func connectUDP(_ configuration: ProxyConfiguration, to target: Endpoint,
                                  timeout: Double = 15) async throws -> DatagramStream
    /// A UDP flow to `target` without a proxy.
    public static func directUDP(to target: Endpoint) async throws -> DatagramStream
}

// MythaiaTunnel/Tun/ — the packet-level tunnel (lwIP), used when the tunnel runs in TUN mode
final class TunStack {
    init(packetFlow: NEPacketTunnelFlow, router: Router, stats: TrafficStats)
    func start()      // reads packets from packetFlow, feeds lwIP, dials flows through Router/Dialer
    func stop()
    func switchConfiguration(_ configuration: ProxyConfiguration)
}

// Engine/
public enum LatencyKind: String, Codable, CaseIterable { case tcp, handshake, http }
public enum LatencyTester {
    public static func measure(_ configuration: ProxyConfiguration, kind: LatencyKind,
                               timeout: Double = 5) async -> Int?   // milliseconds, nil = failed
}
public final class LocalProxyServer {
    public init(router: Router, port: UInt16)
    public func start() throws -> UInt16              // the bound port
    public func stop()
    public var stats: TrafficStats { get }
}
```

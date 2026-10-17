# TUN mode: integrating the packet stack

`Tun/` holds the packet-level tunnel: every TCP connection and UDP flow of
the device enters through `NEPacketTunnelFlow`, lwIP (the same C sources the
Android app builds) terminates it, and `TunStack` routes each one through
`Router` and dials it through `Dialer`. DNS on port 53 is answered from the
fake-IP pool, so connections arrive carrying domain names. It is a port of
`core/.../vpn/tun/TunStack.kt` and the flow classes it drives.

Nothing outside `Tun/` was changed. Three things are needed to switch it on:
the lwIP sources and build settings in `project.yml`, and a TUN branch in
`PacketTunnelProvider`.

## 1. project.yml

In `targets.MythaiaTunnel`, add the lwIP sources after the existing entries
under `sources`, and the settings under `settings.base`:

```yaml
  MythaiaTunnel:
    type: app-extension
    platform: iOS
    sources:
      - path: MythaiaTunnel
        excludes: ["**/*.md"]
      - path: ../app/src/main/assets/Rules.db
        buildPhase: resources
      # lwIP, the userspace TCP/IP stack behind TUN mode: exactly the files
      # app/src/main/jni/CMakeLists.txt compiles (LWIP_SOURCES). Vendored C,
      # so its warnings are silenced.
      - path: ../app/src/main/jni/lwip/src/core
        group: lwIP
        compilerFlags: ["-w"]
      - path: ../app/src/main/jni/lwip/port/sys_arch.c
        group: lwIP
        compilerFlags: ["-w"]
      - path: ../app/src/main/jni/lwip/lwip_bridge.c
        group: lwIP
        compilerFlags: ["-w"]
    dependencies:
      - package: MythaiaKit
      - sdk: NetworkExtension.framework
    settings:
      base:
        # ...the existing keys stay as they are, plus:
        SWIFT_OBJC_BRIDGING_HEADER: MythaiaTunnel/Tun/MythaiaTunnel-Bridging-Header.h
        HEADER_SEARCH_PATHS:
          - $(inherited)
          - $(SRCROOT)/../app/src/main/jni/lwip
          - $(SRCROOT)/../app/src/main/jni/lwip/src/include
          - $(SRCROOT)/../app/src/main/jni/lwip/port
          - $(SRCROOT)/../app/src/main/jni/lwip/port/arch
```

Notes:

- `src/core` holds exactly the `.c` files of CMake's `LWIP_SOURCES` (core,
  `ipv4/`, `ipv6/`); XcodeGen adds the directory recursively. Do not add the
  whole `lwip` folder: it carries `init.h.cmake.in` and `MYTHAIA_PATCHES.md`,
  which XcodeGen would copy as resources.
- The include directories are CMake's `LWIP_INCLUDE_DIRS` plus the folder of
  `lwip_bridge.h` (for the bridging header).
- Do **not** add `app/src/main/jni/compat`: its `os/log.h` is the Android
  stand-in for Apple's. On iOS `lwip_bridge.c` uses the real `<os/log.h>`,
  which it was written against.
- No preprocessor definitions are needed: `lwip/port/lwipopts.h` (found
  through the `port` search path) sets every lwIP option, and CMake defines
  nothing for lwIP either. `port/arch/cc.h` takes the non-Android branch
  (printf diagnostics, `arc4random`).
- The bridging header only includes `lwip_bridge.h`, which needs nothing but
  `<stdint.h>` and `<stddef.h>`.
- App extensions may use a bridging header; the app target needs none.

## 2. PacketTunnelProvider

TUN mode replaces the local proxy for the session: the interface takes the
default routes, DNS goes to the stack, and `TunStack` does what
`LocalProxyServer` does in proxy mode. Which mode to use is the
coordinator's call (for example a new `AppSettings` field); the snippets
below assume a `tunMode` flag and the provider's existing helpers
(`makeRouter`, `withState`, `proxyFailing`, `startAuto`).

```swift
// A stored property next to `server`:
private var tunStack: TunStack?
private var sleptAt: Double?

// In startTunnel, instead of starting LocalProxyServer:
private func startTunMode(_ start: TunnelStartOptions, completionHandler: @escaping (Error?) -> Void) {
    let router = makeRouter(start.settings)
    let configuration = start.configuration
    Task { [weak self] in
        guard let self else { return }
        // The servers' real addresses, while the system's DNS is still its own.
        let servers = await TunNetworkSettings.resolveServers(of: configuration)
        let addresses = TunNetworkSettings.allAddresses(servers)
        let settings = TunNetworkSettings.make(
            remoteAddress: addresses.first ?? "127.0.0.1",
            serverAddresses: addresses
        )
        self.setTunnelNetworkSettings(settings) { error in
            if let error {
                Log.error("Tunnel settings were refused: \(error.localizedDescription)")
                completionHandler(error)
                return
            }
            let stack = TunStack(
                packetFlow: self.packetFlow,
                router: router,
                stats: TrafficStats(),
                configuration: configuration
            )
            stack.seedServerAddresses(servers)
            stack.onProxyFailures = { [weak self] count in
                self?.proxyFailing(count: count)
            }
            stack.start()
            self.withState {
                self.tunStack = stack
                self.options = start
            }
            Log.info("Connected through \(configuration.name), all traffic (TUN)")
            self.startAuto()
            completionHandler(nil)
        }
    }
}

// In stopTunnel: let the stack reset its connections before finishing.
if let stack = withState({ tunStack }) {
    withState { tunStack = nil }
    stack.stop { completionHandler() }
    return
}

// sleep / wake: proxy connections rarely survive a long sleep.
override func sleep(completionHandler: @escaping () -> Void) {
    withState { asleep = true; sleptAt = Date().timeIntervalSince1970 }
    completionHandler()
}
override func wake() {
    let slept = withState { () -> Double? in sleptAt }
    if let slept, Date().timeIntervalSince1970 - slept >= TunConstants.wakeRestartThresholdSec {
        withState { tunStack }?.restart()
    }
    // ...then the existing Auto wake-up.
}
```

Where the provider handles app messages and Auto, the stack stands in for
the proxy server:

| proxy mode                       | TUN mode                                       |
|----------------------------------|------------------------------------------------|
| `proxy.configuration = c`        | `stack.switchConfiguration(c)` (resets flows)   |
| `proxy.configuration`            | `stack.configuration`                           |
| `proxy.router = makeRouter(s)`   | `stack.router = makeRouter(s)`; `stack.restart()` to re-route open flows |
| `proxy.stats`                    | `stack.stats`                                   |
| `proxy.onProxyFailures`          | `stack.onProxyFailures`                         |
| `proxy.boundPort`                | none (report 0)                                 |

The proxy-mode `interfaceAddress` (198.18.0.1) must not be used in TUN mode:
it is the first fake IP the pool hands out, and connections to the
interface's own address never enter the tunnel. `TunNetworkSettings` uses
198.19.0.1/30 and explains why.

Only one `TunStack` should run at a time: lwIP is a single process-wide
instance, driven from one queue (`TunStack.lwipQueue`).

## 3. What `TunNetworkSettings.make` sets

- IPv4 address 198.19.0.1/30; IPv6 fd00::2/64.
- `includedRoutes`: `NEIPv4Route.default()` and `NEIPv6Route.default()`.
- `excludedRoutes`: the networks the Android app keeps off its tunnel
  (loopback, 10/8, 172.16/12, 192.168/16, 100.64/10 and its few service
  ranges), multicast and reserved IPv4, IPv6 link-local and multicast, and
  every proxy server address (/32, /128).
- DNS: 198.18.0.0 (plus fd00::1 when `ipv6Dns`), `matchDomains = [""]`. The
  sentinel is not a public resolver, so the system cannot validate DoT/DoH
  against it and leave port 53; TCP to it is reset by the stack.
- MTU 1500 (lwIP's netif MTU).

## 4. Assumptions about other modules

Written against ARCHITECTURE.md and the MythaiaKit sources present when this
was written; a different signature is a one-line fix at the call site.

- `Router.decide(_ host: String) -> RouteTarget` (unlabeled, as in
  `Engine/Router.swift`), `RouteTarget` with exactly `.proxy`, `.direct`,
  `.block`. `.proxy` means "through the stack's current configuration": the
  stack keeps the server itself, as `LocalProxyServer.configuration` does.
- `TrafficStats` is the value type in `Engine/TrafficStats.swift`
  (`uploadBytes`, `downloadBytes`, its memberwise `init`). `TrafficCounter`
  is internal to MythaiaKit, so the stack counts with its own
  `TunTrafficCounter` and the `stats` passed to `init` is only where the
  totals start.
- `Dialer.connect(_:to:initialData:timeout:)`, `Dialer.direct(to:timeout:)`,
  `Dialer.connectUDP(_:to:timeout:)`, `Dialer.directUDP(to:)` exactly as in
  ARCHITECTURE.md (default timeouts used). Chains and Shadowsocks/VLESS/
  Trojan/VMess UDP framing are the Dialer's business, as is the Vision mux.
- `ProxyConfiguration`: `name`, `serverAddress`, `resolvedIP: String?`,
  `chain: [ProxyConfiguration]?`, `flow: String?`, `outboundProtocol`
  (`handshakeCarriesInitialData`).
- MythaiaKit's `Endpoint`, `ByteStream`, `DatagramStream`, `withTimeout`,
  `Log`.
- The extension's own sockets never enter the tunnel (NetworkExtension
  guarantees this). Whether the extension's own *name lookups* do is not
  relied on: `TunResolver` treats a fake-range answer from the system
  resolver as "went through our DNS" and asks 1.1.1.1 / 8.8.8.8 directly
  over `Dialer.directUDP` instead, and answers for the servers' names come
  from the addresses resolved before the settings were applied.

## 5. Where it differs from the Kotlin core, and why

- Memory budgets the Kotlin core does not need: at most 512 KB per
  connection queued inside lwIP, a 256 KB low-water mark (Kotlin: about
  700 KB), a 12 MB downlink backlog shared by all connections, a 4 MB budget
  for queued datagrams of all UDP flows, 4096 packets waiting for the
  interface, and packets read one batch at a time. See `TunConstants`.
- UDP sends are one batch at a time per flow and replies wait for the lwIP
  queue one by one, instead of a coroutine per datagram.
- The lwIP timer runs every 100 ms (TCP_TMR_INTERVAL in lwipopts.h; the
  Kotlin constant is 100 ms too) while anything is open, and once a second
  when nothing is, to spare the battery.
- The `void *conn` lwIP keeps for each PCB is the connection's numeric id,
  as on Android, not a retained object pointer: a callback that arrives for
  a connection already gone finds nothing instead of freed memory, and no
  retain has to be balanced by hand.
- Direct dials of domain names go through `TunResolver.directTarget` first
  (see the last assumption above).
- Not ported, because the iOS core has no counterpart yet: the MITM hook
  (inert by default in Kotlin), the stack-owned Vision mux and Shadowsocks UDP
  sessions (the Dialer owns those here).
- As in Kotlin, DNS queries other than A/AAAA sent to the sentinel are
  passed on as UDP flows to the sentinel, which is a fake address with no
  pool entry, so they get ICMP port unreachable (MX, TXT, SRV, PTR fail fast).

## 6. Memory note

lwipopts.h sizes lwIP's static pools for Android (2048 pool pbufs, 32768
TCP segments, 512 PCBs); `memp_init` touches all of them, about 5 MB
resident. If the extension runs close to its limit, a smaller iOS-only
`lwipopts.h` placed in a folder listed before `lwip/port` in
`HEADER_SEARCH_PATHS` would shrink that without touching the Android build.

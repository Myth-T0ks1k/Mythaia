import Foundation

/// The packet stack's tuning values, in their natural units, in one place.
///
/// They are the Kotlin core's `TunnelConstants` wherever the two can agree.
/// The few that differ, or that the Kotlin core has no need for, exist
/// because the packet tunnel extension is killed past about 50 MB: those say
/// so, and they bound what many connections together may hold, where the
/// Kotlin values only bound one connection.
enum TunConstants {

    // MARK: Connection timeouts

    /// Inactivity timeout for TCP connections.
    static let connectionIdleTimeoutMs = 300_000

    /// Timeout once the app has finished sending (uplink done).
    static let downlinkOnlyTimeoutMs = 1_000

    /// Timeout once the server has finished sending (downlink done).
    static let uplinkOnlyTimeoutMs = 1_000

    /// Bounds the whole setup of a connection: the ClientHello sniff and the
    /// dial (TCP, TLS, transport, protocol header).
    static let handshakeTimeoutMs = 60_000

    /// How long a real-IP connection waits for a TLS ClientHello before it
    /// takes the IP's route, so server-speaks-first protocols (SSH, SMTP,
    /// FTP) do not stall in the sniff.
    static let sniffDeadlineMs = 500

    /// How long a VLESS or VMess dial waits for the app's first bytes, so the
    /// request header and those bytes leave as one message, as Xray sends
    /// them. Some servers re-send only the first message's payload when they
    /// retry a target; a header sent alone broke HTTPS through them.
    static let firstDataWaitMs = 100

    // MARK: TCP buffers

    /// Most bytes per `tcp_write` call (about 12 segments). Kept in step with
    /// lwipopts.h, as in the Kotlin core.
    static let tcpMaxWriteSize = 16 * 1024

    /// Largest upload chunk handed to the proxy at once: Vision padding
    /// frames carry a 2-byte length.
    static let tcpMaxCoalesceSize = 65_535

    /// Safety cap on the bytes one connection buffers while it sniffs or
    /// dials. lwIP's receive window bounds this already, since nothing is
    /// acknowledged before it is forwarded; the cap only catches runaway
    /// growth (2 x TCP_WND, as in the Kotlin core).
    static let tcpMaxPendingDataSize = 2 * 1024 * 1360

    /// Packets per write to the interface, so one long downlink burst cannot
    /// hold the lwIP queue.
    static let tunnelMaxPacketsPerWrite = 64

    /// Below this many bytes of downlink backlog a connection asks the server
    /// for more while the backlog drains, so the downlink never turns into
    /// stop-and-wait. The Kotlin core uses half of TCP_SND_BUF (about 700 KB);
    /// here it is smaller, because hundreds of connections share 50 MB.
    static let drainLowWaterMark = 256 * 1024

    /// Most downlink bytes one connection may have queued inside lwIP (sent
    /// to the app but not yet acknowledged, or not yet sent). lwIP's own send
    /// buffer is over a megabyte per connection, which a paused video would
    /// otherwise fill; the link to the app is in memory, so a quarter of that
    /// costs no throughput. Not in the Kotlin core.
    static let tcpMaxQueuedInLwip = 512 * 1024

    /// Downlink backlog of all connections together above which no
    /// connection reads more from its server until some of it drains. Not in
    /// the Kotlin core; it is what keeps many slow readers within the
    /// extension's memory limit.
    static let downlinkBacklogBudget = 12 * 1024 * 1024

    /// Packets waiting for the interface above which new ones are dropped
    /// (TCP sends them again). Not in the Kotlin core, whose queue is
    /// unbounded; normally this never holds more than a few batches.
    static let maxPendingOutputPackets = 4096

    // MARK: UDP

    /// Most bytes of datagrams one flow queues while its server connects or
    /// a send is in flight; beyond it datagrams are dropped.
    static let udpMaxBufferSize = 256 * 1024

    /// The same for all flows together. Not in the Kotlin core: 200 flows of
    /// 256 KB each would not fit in the extension.
    static let udpPendingBudget = 4 * 1024 * 1024

    /// Idle timeout for UDP flows, in seconds.
    static let udpIdleTimeoutSec: Double = 60

    // MARK: Timers

    /// How often lwIP's timers run while connections are open. lwipopts.h
    /// sets TCP_TMR_INTERVAL to 100 ms, so polling slower would delay the
    /// TCP fast timer (delayed ACKs, retransmits).
    static let lwipTimeoutIntervalMs = 100

    /// The same with no connection or flow open: only closing and TIME_WAIT
    /// sockets are left, and their timers can run late without harm. Not in
    /// the Kotlin core; it spares the battery ten wake-ups a second while
    /// the phone is idle.
    static let lwipIdleTimeoutIntervalMs = 1_000

    /// How often idle UDP flows are looked for, in seconds.
    static let udpCleanupIntervalSec: Double = 1

    /// Retry delay when a downlink drain made no progress.
    static let drainRetryDelayMs = 250

    /// Shortest sleep after which the provider should call `restart()` on
    /// wake: proxy connections rarely survive a long sleep, and waiting for
    /// their keepalives to fail leaves apps hanging.
    static let wakeRestartThresholdSec: Double = 60

    // MARK: TLS sniffer

    /// Most bytes buffered while looking for the SNI in a ClientHello;
    /// post-quantum key shares make a hello about 4 KB.
    static let tlsSnifferBufferLimit = 8192

    // MARK: Fake-IP pool

    /// 198.18.0.0, the base of the fake range 198.18.0.0/15.
    static let fakeIPPoolBaseIPv4: UInt32 = 0xC612_0000

    /// Usable offsets in the fake-IP pool; bounds the pool's tables.
    static let fakeIPPoolSize = 16_384

    // MARK: DNS sentinel

    /// The DNS server the interface advertises. Not a public resolver, so the
    /// system cannot validate DoT or DoH against it and leave port 53, where
    /// the fake-IP answers come from. It sits at the base of the fake range,
    /// which is routed into the tunnel, and is never an allocated offset.
    static let dnsSentinelV4 = "198.18.0.0"

    /// The IPv6 sentinel, on-link in the interface's fd00::/64.
    static let dnsSentinelV6 = "fd00::1"

    // MARK: Limits

    /// Kept in step with lwipopts.h MEMP_NUM_TCP_PCB.
    static let maxTcpConnections = 512

    static let maxUdpFlows = 200

    /// How long a connection-cap warning is kept quiet after one is logged.
    static let tcpCapWarnIntervalSec: Double = 5
}

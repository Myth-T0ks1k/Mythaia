import Foundation
import MythaiaKit

/// One UDP flow through the tunnel, keyed by its local and remote address
/// and port. Datagrams go through the proxy's UDP support (or straight to
/// the destination) and replies come back through lwIP with the addresses
/// swapped.
///
/// Everything here runs on the lwIP queue. Sends are one batch at a time and
/// replies are delivered one by one, each waiting for the queue, so neither
/// direction can pile up more than `udpMaxBufferSize` bytes or one datagram.
final class LwipUdpFlow: @unchecked Sendable {
    let flowKey: String
    let srcHost: String
    let srcPort: UInt16
    let dstHost: String
    let dstPort: UInt16
    /// The original sender, which replies are addressed to.
    let srcIpBytes: [UInt8]
    /// The original destination, which replies come from.
    let dstIpBytes: [UInt8]
    let isIpv6: Bool
    let configuration: ProxyConfiguration

    private let forceBypass: Bool
    private let stack: TunStack
    private let queue: DispatchQueue

    private(set) var lastActivity: Double

    private var stream: DatagramStream?
    private var connecting = false
    private var connectTask: Task<Void, Never>?
    private var receiveTask: Task<Void, Never>?

    /// Datagrams waiting for the dial, or for the send in flight; their bytes
    /// count against this flow's cap and the stack's budget.
    private var queued: [Data] = []
    private var queuedBytes = 0
    private var sendInFlight = false
    /// One warning per flow is enough to show datagrams are being dropped.
    private var didWarnOverflow = false

    private(set) var closed = false

    init(
        flowKey: String,
        srcHost: String,
        srcPort: UInt16,
        dstHost: String,
        dstPort: UInt16,
        srcIpBytes: [UInt8],
        dstIpBytes: [UInt8],
        isIpv6: Bool,
        configuration: ProxyConfiguration,
        forceBypass: Bool,
        stack: TunStack
    ) {
        self.flowKey = flowKey
        self.srcHost = srcHost
        self.srcPort = srcPort
        self.dstHost = dstHost
        self.dstPort = dstPort
        self.srcIpBytes = srcIpBytes
        self.dstIpBytes = dstIpBytes
        self.isIpv6 = isIpv6
        self.configuration = configuration
        self.forceBypass = forceBypass
        self.stack = stack
        self.queue = stack.queue
        self.lastActivity = TunClock.now()
    }

    /// A datagram from the app.
    func handleReceivedData(_ payload: Data) {
        if closed { return }
        lastActivity = TunClock.now()
        enqueue(payload)
        if stream != nil {
            pumpSends()
        } else if !connecting {
            connectOutbound()
        }
    }

    // MARK: - Dialling

    private func connectOutbound() {
        if connecting || stream != nil || closed { return }

        let direct = forceBypass || stack.shouldBypass(dstHost)
        if !direct {
            // Vision drops UDP/443 unless the flow says otherwise; the app
            // falls back to TCP sooner when the flow ends at once.
            let flow = configuration.flow
            let isVision = flow == "xtls-rprx-vision" || flow == "xtls-rprx-vision-udp443"
            let allowUdp443 = flow == "xtls-rprx-vision-udp443"
            if dstPort == 443 && isVision && !allowUdp443 {
                close()
                stack.removeUdpFlow(self)
                return
            }
        }

        connecting = true
        let config = configuration
        let host = dstHost
        let port = dstPort
        let resolver = stack.resolver
        let queue = self.queue
        connectTask = Task {
            do {
                let datagrams: DatagramStream
                if direct {
                    let target = await resolver.directTarget(host)
                    datagrams = try await Dialer.directUDP(to: Endpoint(host: target, port: port))
                } else {
                    datagrams = try await Dialer.connectUDP(config, to: Endpoint(host: host, port: port))
                }
                queue.async {
                    self.onConnected(datagrams)
                }
            } catch {
                queue.async {
                    self.onConnectFailed(error, direct: direct)
                }
            }
        }
    }

    private func onConnected(_ datagrams: DatagramStream) {
        connecting = false
        connectTask = nil
        if closed {
            datagrams.close()
            return
        }
        stream = datagrams
        pumpSends()
        startReceiving(datagrams)
    }

    private func onConnectFailed(_ error: Error, direct: Bool) {
        connecting = false
        connectTask = nil
        if closed { return }
        Log.error("[UDP] Connect failed: \(flowKey) -> \(Endpoint(host: dstHost, port: dstPort))\(direct ? " (direct)" : ""): \(describeTunError(error))")
        close()
        stack.removeUdpFlow(self)
    }

    // MARK: - Uplink

    private func enqueue(_ payload: Data) {
        let size = payload.count
        let overFlowCap = queuedBytes + size > TunConstants.udpMaxBufferSize
        if overFlowCap || !stack.reserveUdpBytes(size) {
            if !didWarnOverflow {
                didWarnOverflow = true
                Log.warning("[UDP] Buffer full for \(flowKey) (\(queuedBytes) + \(size) bytes), dropping datagrams")
            }
            return
        }
        queued.append(payload)
        queuedBytes += size
    }

    /// Sends everything queued, in order, as one task; what arrives meanwhile
    /// waits for the next pass. Each datagram is sent on its own, so every
    /// protocol frames it its own way.
    private func pumpSends() {
        if sendInFlight || closed || queued.isEmpty { return }
        guard let datagrams = stream else { return }
        let batch = queued
        let batchBytes = queuedBytes
        queued = []
        queuedBytes = 0
        sendInFlight = true
        let key = flowKey
        let queue = self.queue
        Task {
            var firstError: Error? = nil
            for packet in batch {
                do {
                    try await datagrams.send(packet)
                } catch {
                    if firstError == nil {
                        firstError = error
                    }
                }
            }
            if let error = firstError {
                Log.debug("[UDP] Send failed for \(key): \(describeTunError(error))")
            }
            queue.async {
                self.onSendsDone(batchBytes)
            }
        }
    }

    private func onSendsDone(_ bytes: Int) {
        stack.releaseUdpBytes(bytes)
        sendInFlight = false
        pumpSends()
    }

    // MARK: - Downlink

    private func startReceiving(_ datagrams: DatagramStream) {
        let key = flowKey
        let queue = self.queue
        receiveTask = Task {
            do {
                while let packet = try await datagrams.receive() {
                    // One datagram at a time through the queue: a fast server
                    // cannot queue up more than lwIP is taking.
                    let alive: Bool = await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
                        queue.async {
                            continuation.resume(returning: self.deliver(packet))
                        }
                    }
                    if !alive { return }
                }
            } catch {
                Log.debug("[UDP] Receive ended for \(key): \(describeTunError(error))")
            }
            queue.async {
                self.onRemoteEnded()
            }
        }
    }

    /// Writes one reply to the app; false once the flow is closed.
    private func deliver(_ packet: Data) -> Bool {
        if closed { return false }
        if packet.isEmpty { return true }
        lastActivity = TunClock.now()
        // The reply comes from the original destination to the original sender.
        stack.sendUdp(from: dstIpBytes, fromPort: dstPort, to: srcIpBytes, toPort: srcPort, isIpv6: isIpv6, payload: packet)
        return true
    }

    private func onRemoteEnded() {
        if closed { return }
        close()
        stack.removeUdpFlow(self)
    }

    // MARK: - Teardown

    func close() {
        if closed { return }
        closed = true
        connectTask?.cancel()
        connectTask = nil
        receiveTask?.cancel()
        receiveTask = nil
        let datagrams = stream
        stream = nil
        connecting = false
        stack.releaseUdpBytes(queuedBytes)
        queued = []
        queuedBytes = 0
        datagrams?.close()
    }
}

import Foundation
import MythaiaKit

/// One TCP connection through the tunnel: the lwIP PCB on the app's side and
/// a stream through the proxy (or straight to the destination) on the other.
///
/// Everything here runs on the lwIP queue, and every lwIP call on this
/// connection's PCB happens there too. The dial, the sends and the receives
/// run as tasks; their results hop back to the queue before they touch any
/// state. Once `closed` is set the PCB is gone or going and is never
/// touched again.
///
/// Flow control works by acknowledgement. Bytes from the app are not
/// acknowledged to lwIP (`tcp_recved`) until the proxy has taken them, so
/// lwIP's receive window is the uplink's backpressure. Bytes from the proxy
/// are read only while this connection's backlog is below
/// `drainLowWaterMark` and the stack's budget allows, and are handed to lwIP
/// only as fast as its send buffer frees up.
final class LwipTcpConnection: @unchecked Sendable {
    let connId: Int
    let dstPort: UInt16

    /// Where the dial goes: the address the app connected to, the domain its
    /// fake IP stands for, or the SNI once a sniff found one.
    private(set) var dstHost: String

    /// The server this connection is dialled through (when not direct).
    let configuration: ProxyConfiguration

    private let pcb: UnsafeMutableRawPointer
    private let stack: TunStack
    private let queue: DispatchQueue

    /// Downlink bytes handed to lwIP and not yet acknowledged by the app:
    /// what lwIP holds for this connection. Counted here because
    /// `tcp_sndbuf` reads at most 65535 with window scaling on, long before
    /// lwIP's megabyte-plus send buffer is used up.
    private var bytesInLwip = 0

    /// Whether the dial goes straight to the destination. A sniffed SNI may
    /// change it.
    private var bypass: Bool

    private var outbound: ByteStream?
    private var connecting = false
    private var connectTask: Task<Void, Never>?
    /// App bytes that went out inside the protocol's handshake and still
    /// need acknowledging to lwIP once the dial succeeds.
    private var handshakeAckBytes = 0

    /// App bytes held while the connection sniffs or dials.
    private var pendingData = ByteQueue()
    /// App bytes waiting for the proxy; sends are strictly one at a time,
    /// since several protocols cannot interleave writes (Vision padding,
    /// HTTP/2, gRPC framing).
    private var uploadBuffer = ByteQueue()
    private var uploadScheduled = false
    private var uploadInFlight = false

    /// Proxy bytes not yet in lwIP's send buffer. All downlink ordering lives
    /// here, so a receive that lands during a drain cannot overtake it.
    private var pendingWrite = ByteQueue()
    private var receiveInFlight = false
    private var drainRetryScheduled = false

    private(set) var closed = false
    private var sniffer: TlsClientHelloSniffer?
    /// The sniff deadline, or the wait for a whole first TLS record.
    private var sniffDeadline: DispatchWorkItem?
    private var handshakeTimer: DispatchWorkItem?
    private var activityTimer: ActivityTimer?
    private var uplinkDone = false
    private var downlinkDone = false

    init(
        connId: Int,
        pcb: UnsafeMutableRawPointer,
        dstHost: String,
        dstPort: UInt16,
        configuration: ProxyConfiguration,
        forceBypass: Bool,
        sniffSNI: Bool,
        stack: TunStack
    ) {
        self.connId = connId
        self.pcb = pcb
        self.dstHost = dstHost
        self.dstPort = dstPort
        self.configuration = configuration
        self.stack = stack
        self.queue = stack.queue
        self.bypass = forceBypass || stack.shouldBypass(dstHost)
        self.sniffer = sniffSNI ? TlsClientHelloSniffer() : nil
    }

    /// Arms the timers and, unless it sniffs first, starts the dial. Called
    /// from inside lwIP's accept callback, so it must not call into lwIP:
    /// the PCB is not bound to this connection until the callback returns.
    func start() {
        // Covers the sniff and the dial, so a stalled client cannot hold a
        // connection open before anything was ever dialled.
        handshakeTimer = scheduleOnce(on: queue, after: TunConstants.handshakeTimeoutMs) { [weak self] in
            guard let self = self, !self.closed, self.isEstablishing else { return }
            let phase = self.sniffer != nil ? "TLS ClientHello sniff" : "proxy dial"
            Log.error("[TCP] Handshake timeout during \(phase): \(self.endpointDescription)")
            self.abort()
        }

        if sniffer == nil {
            beginConnectingWhenFirstDataReady()
        } else {
            // Protocols where the server speaks first (SSH, SMTP, FTP) never
            // send a ClientHello; past the deadline the IP's route stands.
            sniffDeadline = scheduleOnce(on: queue, after: TunConstants.sniffDeadlineMs) { [weak self] in
                guard let self = self, !self.closed, self.sniffer != nil else { return }
                self.sniffer = nil
                self.beginConnecting()
            }
        }
    }

    private var isEstablishing: Bool {
        connecting || sniffer != nil
    }

    private var endpointDescription: String {
        Endpoint(host: dstHost, port: dstPort).description
    }

    // MARK: - From lwIP

    /// Bytes the app sent.
    func handleReceivedData(_ data: [UInt8]) {
        if closed || data.isEmpty { return }
        activityTimer?.update()

        // Sniff phase: hold the bytes and look for a ClientHello before
        // anything is dialled.
        if let activeSniffer = sniffer {
            let state = activeSniffer.feed(data)
            if !appendPendingData(data) { return }
            switch state {
            case .needMore:
                return
            case .found(let serverName):
                sniffer = nil
                cancelSniffDeadline()
                applySNI(serverName)
                if closed { return }     // a rule may have rejected it
                // The server name can come before the end of the hello.
                beginConnectingWhenFirstDataReady()
                return
            case .notTls, .unavailable:
                sniffer = nil
                cancelSniffDeadline()
                beginConnectingWhenFirstDataReady()
                return
            }
        }

        if connecting {
            _ = appendPendingData(data)
            return
        }

        if outbound != nil {
            // Bytes that arrive while a send is in flight wait here and leave
            // together once it finishes.
            uploadBuffer.append(data)
            scheduleUpload()
        } else {
            // Not dialled yet: the first bytes go out with the request header,
            // once a TLS hello split over segments is whole.
            if !appendPendingData(data) { return }
            beginConnectingWhenFirstDataReady()
        }
    }

    /// The app acknowledged `length` bytes; lwIP's send buffer has room again.
    func handleSent(_ length: Int) {
        if closed { return }
        bytesInLwip = max(0, bytesInLwip - length)
        drainPendingWrite()
    }

    /// The app closed its sending side (FIN).
    func handleRemoteClose() {
        if closed { return }

        // A FIN during the sniff: with nothing received there is nothing to
        // forward; otherwise the IP's route takes what there is.
        if sniffer != nil {
            sniffer = nil
            cancelSniffDeadline()
            if pendingData.isEmpty {
                close()
                return
            }
            beginConnecting()
        }

        uplinkDone = true
        if downlinkDone {
            // Downlink bytes still queued for a slow app go first, so a
            // close-delimited response is not cut short.
            if pendingWrite.isEmpty {
                close()
            } else {
                drainPendingWrite()
            }
        } else {
            activityTimer?.setTimeout(TunConstants.downlinkOnlyTimeoutMs)
        }
    }

    /// lwIP tore the connection down (its PCB is already freed). Logged, as
    /// otherwise the connection would just vanish.
    func handleError(_ err: Int32) {
        let reason = describeLwipError(err)
        if err == -15 {
            Log.debug("[TCP] lwIP closed connection: \(endpointDescription): \(reason)")
        } else if err == -14 {
            Log.debug("[TCP] lwIP peer reset: \(endpointDescription): \(reason)")
        } else if err == -13 && stack.isTearingDown {
            Log.debug("[TCP] lwIP aborted connection (tunnel teardown): \(endpointDescription): \(reason)")
        } else {
            Log.warning("[TCP] lwIP aborted connection: \(endpointDescription): \(reason)")
        }
        if closed { return }
        closed = true
        releaseProtocol()
        stack.removeConnection(connId)
    }

    // MARK: - Routing and dialling

    /// Holds app bytes; aborts past `tcpMaxPendingDataSize` and says so.
    private func appendPendingData(_ data: [UInt8]) -> Bool {
        if pendingData.count + data.count > TunConstants.tcpMaxPendingDataSize {
            Log.warning("[TCP] Pending data cap exceeded for \(endpointDescription) (\(pendingData.count) + \(data.count) bytes), aborting")
            abort()
            return false
        }
        pendingData.append(data)
        return true
    }

    private func cancelSniffDeadline() {
        sniffDeadline?.cancel()
        sniffDeadline = nil
    }

    /// The route a sniffed SNI gives. The dial then goes to the name, so the
    /// route and the request agree.
    private func applySNI(_ serverName: String) {
        let route = stack.route(serverName)
        dstHost = serverName
        switch route {
        case .direct:
            bypass = true
        case .block:
            Log.debug("[TCP] SNI rejected by routing rule: \(serverName):\(dstPort)")
            rejectGracefully()
        case .proxy:
            bypass = stack.shouldBypass(serverName)
        }
    }

    /// Dials now, unless this route's request carries the app's first bytes
    /// (VLESS, VMess, Trojan, Shadowsocks) and those are not all in yet: then
    /// once they are (any non-TLS bytes, or a whole first TLS record), or
    /// after `firstDataWaitMs` without more. That covers a hello split over
    /// segments and, with nothing buffered, servers that speak first.
    private func beginConnectingWhenFirstDataReady() {
        if closed { return }
        let carriesData = configuration.outboundProtocol.handshakeCarriesInitialData
        if !bypass && carriesData && !FirstData.isComplete(header: pendingData.prefix(5), size: pendingData.count) {
            cancelSniffDeadline()
            sniffDeadline = scheduleOnce(on: queue, after: TunConstants.firstDataWaitMs) { [weak self] in
                guard let self = self, !self.closed else { return }
                self.beginConnecting()
            }
            return
        }
        beginConnecting()
    }

    /// Starts the dial with the route as it stands; does nothing once a dial
    /// has started.
    private func beginConnecting() {
        cancelSniffDeadline()
        if closed || connecting || outbound != nil { return }
        connecting = true

        let direct = bypass
        let config = configuration
        let host = dstHost
        let port = dstPort

        // Protocols that put the first bytes inside their request take them
        // now; for the rest they are sent once connected.
        var initialData: Data? = nil
        if !direct && config.outboundProtocol.handshakeCarriesInitialData && !pendingData.isEmpty {
            let bytes = pendingData.takeAll()
            handshakeAckBytes = bytes.count
            initialData = Data(bytes)
        }
        let firstBytes = initialData
        let resolver = stack.resolver
        let queue = self.queue

        connectTask = Task {
            do {
                let stream: ByteStream
                if direct {
                    let target = await resolver.directTarget(host)
                    stream = try await Dialer.direct(to: Endpoint(host: target, port: port))
                } else {
                    stream = try await Dialer.connect(config, to: Endpoint(host: host, port: port), initialData: firstBytes)
                }
                queue.async {
                    self.onConnected(stream, direct: direct)
                }
            } catch {
                queue.async {
                    self.onConnectFailed(error, direct: direct)
                }
            }
        }
    }

    private func onConnected(_ stream: ByteStream, direct: Bool) {
        connecting = false
        connectTask = nil
        if closed {
            stream.close()
            return
        }
        if !direct {
            stack.proxyDialSucceeded()
        }
        outbound = stream
        handshakeTimer?.cancel()
        handshakeTimer = nil
        activityTimer = ActivityTimer(queue: queue, timeoutMs: TunConstants.connectionIdleTimeoutMs) { [weak self] in
            guard let self = self, !self.closed else { return }
            self.close()
        }

        // Bytes that came in during the dial go out next, through the same
        // one-at-a-time path as everything after them.
        if !pendingData.isEmpty {
            uploadBuffer.append(takingAllFrom: &pendingData)
            scheduleUpload()
        }
        // Bytes the handshake carried were never acknowledged; do it now so
        // lwIP's window opens again.
        if handshakeAckBytes > 0 {
            let carried = handshakeAckBytes
            handshakeAckBytes = 0
            ackBytesToLwip(carried)
        }
        tryArmReceive()
    }

    private func onConnectFailed(_ error: Error, direct: Bool) {
        connecting = false
        connectTask = nil
        if closed { return }
        Log.error("[TCP] Connect failed: \(endpointDescription)\(direct ? " (direct)" : ""): \(describeTunError(error))")
        if !direct {
            stack.proxyDialFailed()
        }
        abort()
    }

    // MARK: - Uplink

    /// Sends what is buffered once the current pass over the queue is done,
    /// so the segments of one packet batch leave as one write.
    private func scheduleUpload() {
        if uploadInFlight || uploadScheduled { return }
        uploadScheduled = true
        queue.async { [weak self] in
            self?.pumpUpload()
        }
    }

    private func pumpUpload() {
        uploadScheduled = false
        if closed || uploadInFlight || uploadBuffer.isEmpty { return }
        guard let stream = outbound else { return }
        let chunk = uploadBuffer.take(TunConstants.tcpMaxCoalesceSize)
        let length = chunk.count
        uploadInFlight = true
        let queue = self.queue
        Task {
            do {
                try await stream.send(chunk)
                queue.async {
                    self.onUploadSent(length)
                }
            } catch {
                queue.async {
                    self.onUploadFailed(error)
                }
            }
        }
    }

    private func onUploadSent(_ length: Int) {
        uploadInFlight = false
        if closed { return }
        // Acknowledged per chunk, so lwIP's window opens in step with what
        // the proxy actually takes.
        ackBytesToLwip(length)
        if !uploadBuffer.isEmpty {
            pumpUpload()
        }
    }

    private func onUploadFailed(_ error: Error) {
        uploadInFlight = false
        if closed { return }
        Log.warning("[TCP] Send failed: \(endpointDescription): \(describeTunError(error))")
        abort()
    }

    /// Acknowledges `bytes` to lwIP in 65535-byte steps (the call takes a
    /// UInt16), then sends the window update at once.
    private func ackBytesToLwip(_ bytes: Int) {
        if closed || bytes <= 0 { return }
        var remaining = bytes
        while remaining > 0 {
            let step = min(remaining, 65_535)
            lwip_bridge_tcp_recved(pcb, UInt16(step))
            remaining -= step
        }
        lwip_bridge_tcp_output(pcb)
        stack.flushOutputInline()
    }

    // MARK: - Downlink

    /// Asks the proxy for the next chunk if the backlog is below the
    /// low-water mark and nothing is being read already. Reading while the
    /// backlog drains keeps lwIP's send buffer full; stopping above the mark
    /// is what lets a slow app slow the server down.
    func tryArmReceive() {
        if closed || receiveInFlight || downlinkDone { return }
        if pendingWrite.count >= TunConstants.drainLowWaterMark { return }
        guard let stream = outbound else { return }
        if !stack.mayReadDownlink(connId) { return }

        receiveInFlight = true
        let queue = self.queue
        Task {
            var received: Data? = nil
            var failure: Error? = nil
            do {
                received = try await stream.receive()
            } catch {
                failure = error
            }
            let data = received
            let error = failure
            queue.async {
                self.onReceived(data, error: error)
            }
        }
    }

    private func onReceived(_ data: Data?, error: Error?) {
        receiveInFlight = false
        if closed { return }

        if let error = error {
            Log.warning("[TCP] Receive failed: \(endpointDescription): \(describeTunError(error))")
            abort()
            return
        }

        guard let data = data, !data.isEmpty else {
            downlinkDone = true
            if !pendingWrite.isEmpty {
                // The server is done but bytes are still queued for a slow
                // app; closing now would cut a close-delimited response. The
                // idle timer (each drain step counts) still bounds an app
                // that stopped reading.
                activityTimer?.setTimeout(TunConstants.connectionIdleTimeoutMs)
                drainPendingWrite()
            } else {
                finishDownlinkIfDrained()
            }
            return
        }

        activityTimer?.update()
        writeToLwip(data)
    }

    private func writeToLwip(_ data: Data) {
        if closed || data.isEmpty { return }
        pendingWrite.append(data)
        stack.adjustDownlinkBacklog(data.count)
        drainPendingWrite()
    }

    /// Moves the backlog into lwIP's send buffer and, after progress, reads
    /// more if the backlog fell below the mark. Runs on every ACK from the
    /// app, after every chunk from the proxy, and from a retry timer when
    /// lwIP took nothing.
    private func drainPendingWrite() {
        if closed { return }

        if !pendingWrite.isEmpty {
            let backlog = pendingWrite.count
            let written = feedLwip(retryOnEmpty: true)
            if written < 0 {
                let sendBuffer = lwip_bridge_tcp_sndbuf(pcb)
                Log.error("[TCP] tcp_write failed: \(endpointDescription) (pending \(backlog), sndbuf \(sendBuffer))")
                abort()
                return
            }
            if closed { return }

            if written > 0 {
                // Handing bytes to lwIP is progress: a slow but steady reader
                // is not idle.
                activityTimer?.update()
                pendingWrite.consume(written)
                stack.adjustDownlinkBacklog(-written)
                lwip_bridge_tcp_output(pcb)
                stack.flushOutputInline()
            } else {
                // Nothing fit (send buffer full, zero window). Reading more
                // would only grow the backlog; retry shortly, and the app's
                // next ACK drains sooner anyway.
                scheduleDrainRetry()
                return
            }
        }

        // After the server's EOF the close waits for the backlog to empty.
        if downlinkDone {
            finishDownlinkIfDrained()
            if closed || pendingWrite.isEmpty { return }
        }

        tryArmReceive()
    }

    private func scheduleDrainRetry() {
        if drainRetryScheduled { return }
        drainRetryScheduled = true
        scheduleOnce(on: queue, after: TunConstants.drainRetryDelayMs) { [weak self] in
            guard let self = self else { return }
            self.drainRetryScheduled = false
            if !self.closed {
                self.drainPendingWrite()
            }
        }
    }

    /// After the server's EOF: closes (or starts the uplink-only timeout)
    /// once the backlog is fully in lwIP.
    private func finishDownlinkIfDrained() {
        if closed || !downlinkDone { return }
        if !pendingWrite.isEmpty { return }
        if uplinkDone {
            close()
        } else {
            activityTimer?.setTimeout(TunConstants.uplinkOnlyTimeoutMs)
        }
    }

    /// Writes as much of the backlog into lwIP as it takes, at most
    /// `tcpMaxQueuedInLwip` held there in all. Returns the bytes written, or
    /// -1 on an error other than ERR_MEM (which only means "full for now").
    /// With `retryOnEmpty`, a full send buffer gets one `tcp_output` to free
    /// room before giving up.
    private func feedLwip(retryOnEmpty: Bool) -> Int {
        let target = pcb
        let total = pendingWrite.count
        var offset = 0
        while offset < total {
            var sendBuffer = Int(lwip_bridge_tcp_sndbuf(target))
            if sendBuffer <= 0 {
                if retryOnEmpty {
                    lwip_bridge_tcp_output(target)
                    sendBuffer = Int(lwip_bridge_tcp_sndbuf(target))
                }
                if sendBuffer <= 0 { break }
            }
            let room = TunConstants.tcpMaxQueuedInLwip - bytesInLwip
            if room <= 0 { break }
            let chunk = min(sendBuffer, room, total - offset, TunConstants.tcpMaxWriteSize)
            let result: Int32? = pendingWrite.withBytes(from: offset) { pointer -> Int32 in
                lwip_bridge_tcp_write(target, pointer, UInt16(chunk))
            }
            guard let err = result else { break }
            if err != 0 {
                if err == -1 { break }      // ERR_MEM: full for now
                return -1
            }
            offset += chunk
            bytesInLwip += chunk
        }
        return offset
    }

    // MARK: - Teardown

    /// Closes with a FIN, after a last best-effort push of the backlog.
    func close() {
        if closed { return }
        closed = true
        if !pendingWrite.isEmpty {
            let written = feedLwip(retryOnEmpty: false)
            if written > 0 {
                lwip_bridge_tcp_output(pcb)
            }
        }
        lwip_bridge_tcp_close(pcb)
        releaseProtocol()
        stack.removeConnection(connId)
    }

    /// Ends the connection with a FIN rather than a RST.
    ///
    /// lwIP's `tcp_close` sends a RST whenever bytes were delivered but never
    /// acknowledged with `tcp_recved`, and the sniffed ClientHello is exactly
    /// that. TLS stacks take a RST mid-handshake for a passing failure and
    /// retry hard, which defeats the reject rule; a FIN reads as a deliberate
    /// close and is not retried.
    private func rejectGracefully() {
        if closed { return }
        var remaining = pendingData.count
        while remaining > 0 {
            let step = min(remaining, 65_535)
            lwip_bridge_tcp_recved(pcb, UInt16(step))
            remaining -= step
        }
        close()
    }

    /// Ends the connection with a RST.
    func abort() {
        if closed { return }
        closed = true
        lwip_bridge_tcp_abort(pcb)
        releaseProtocol()
        stack.removeConnection(connId)
    }

    private func releaseProtocol() {
        connectTask?.cancel()
        connectTask = nil
        handshakeTimer?.cancel()
        handshakeTimer = nil
        cancelSniffDeadline()
        sniffer = nil
        activityTimer?.cancel()
        activityTimer = nil

        let stream = outbound
        outbound = nil
        connecting = false
        pendingData.removeAll()
        if !pendingWrite.isEmpty {
            stack.adjustDownlinkBacklog(-pendingWrite.count)
        }
        pendingWrite.removeAll()
        uploadBuffer.removeAll()
        uploadScheduled = false
        receiveInFlight = false
        handshakeAckBytes = 0

        // Closing the stream fails whatever send or receive is still in
        // flight; their results find the connection closed.
        stream?.close()
    }
}

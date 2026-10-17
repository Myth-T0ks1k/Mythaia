import Foundation
import Network
import Security

/// One Network.framework connection as the byte stream the layers above read
/// and write; TCPStream and SystemTLSStream are both this, without and with
/// TLS in the protocol stack.
///
/// Every continuation it hands out is resumed exactly once: by the completion
/// it waits for, or by close() or a failure, whichever comes first. The one
/// that comes second finds nothing left to resume. All Network.framework
/// callbacks run on the connection's own serial queue.
final class TransportNWConnection: @unchecked Sendable {
    /// The most one read asks Network.framework for.
    static let maximumReadLength = 64 * 1024

    let connection: NWConnection
    private let queue: DispatchQueue
    private let what: String
    private let lock = NSLock()

    private var connectContinuation: CheckedContinuation<Void, Error>?
    private var timeoutItem: DispatchWorkItem?
    private var isReady = false
    private var isClosed = false
    private var failure: MythaiaError?
    private var reachedEnd = false
    private var nextToken: UInt64 = 0
    private var pendingReceiveToken: UInt64 = 0
    private var pendingReceive: CheckedContinuation<Data?, Error>?
    private var pendingSends: [UInt64: CheckedContinuation<Void, Error>] = [:]

    /// `what` names the connection in errors and in its queue's label.
    init(host: String, port: UInt16, parameters: NWParameters, what: String) throws {
        guard let endpointPort = NWEndpoint.Port(rawValue: port) else {
            throw MythaiaError.invalidConfiguration("port \(port)")
        }
        self.what = what
        self.queue = DispatchQueue(label: "com.mythaia.transport." + what.lowercased())
        self.connection = NWConnection(host: NWEndpoint.Host(host), port: endpointPort, using: parameters)
    }

    deinit {
        connection.stateUpdateHandler = nil
        connection.cancel()
    }

    /// TCP as every dial wants it: Nagle off, since the protocols above write
    /// small headers that should leave at once, and the connect bounded.
    static func tcpOptions(timeout: Double) -> NWProtocolTCP.Options {
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.connectionTimeout = max(1, Int(timeout.rounded(.up)))
        return tcp
    }

    /// The parameters of every outbound connection, with `tls` when the
    /// system TLS stack should run on it.
    static func outboundParameters(tls: NWProtocolTLS.Options?, timeout: Double) -> NWParameters {
        let parameters = NWParameters(tls: tls, tcp: tcpOptions(timeout: timeout))
        // The tunnel points the system proxy at its own listener; without this its own dials would loop back into it.
        parameters.preferNoProxies = true
        return parameters
    }

    /// Connects, TLS handshake included when the parameters carry TLS. The
    /// whole of it is bounded by `timeout`: the TCP option only covers the
    /// SYN, and a server that accepts and then stalls the handshake would
    /// otherwise hold the dial for ever.
    func start(timeout: Double) async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                self.lock.lock()
                if self.isClosed {
                    self.lock.unlock()
                    continuation.resume(throwing: MythaiaError.closed)
                    return
                }
                self.connectContinuation = continuation
                let item = DispatchWorkItem { [weak self] in
                    self?.connectTimedOut()
                }
                self.timeoutItem = item
                self.lock.unlock()
                self.connection.stateUpdateHandler = { [weak self] state in
                    self?.handle(state)
                }
                self.queue.asyncAfter(deadline: .now() + max(0.1, timeout), execute: item)
                self.connection.start(queue: self.queue)
            }
        } onCancel: {
            self.close()
        }
    }

    private var readyNow: Bool {
        lock.lock()
        defer { lock.unlock() }
        return isReady
    }

    private func handle(_ state: NWConnection.State) {
        switch state {
        case .ready:
            lock.lock()
            isReady = true
            let continuation = connectContinuation
            connectContinuation = nil
            let item = timeoutItem
            timeoutItem = nil
            lock.unlock()
            item?.cancel()
            continuation?.resume()
        case .waiting(let error):
            // Waiting means "not now" (refused, no route, no network). A
            // proxy dial is better off failing at once and letting the caller
            // try the next server than sitting out the whole timeout.
            fail(TransportNWConnection.describe(error, what: what, connecting: true))
        case .failed(let error):
            fail(TransportNWConnection.describe(error, what: what, connecting: !readyNow))
        case .cancelled:
            fail(.closed)
        default:
            break
        }
    }

    private func connectTimedOut() {
        lock.lock()
        let stillConnecting = connectContinuation != nil
        lock.unlock()
        if stillConnecting {
            fail(.timeout("connecting to the server (\(what))"))
        }
    }

    /// Ends the connection with `error`: whatever waits on it gets the error,
    /// and so does every later call.
    private func fail(_ error: MythaiaError) {
        lock.lock()
        if failure == nil && !isClosed {
            failure = error
        }
        let connect = connectContinuation
        connectContinuation = nil
        let item = timeoutItem
        timeoutItem = nil
        let receive = pendingReceive
        pendingReceive = nil
        let sends = Array(pendingSends.values)
        pendingSends.removeAll()
        lock.unlock()
        item?.cancel()
        connect?.resume(throwing: error)
        receive?.resume(throwing: error)
        for send in sends {
            send.resume(throwing: error)
        }
        connection.cancel()
    }

    func send(_ data: Data) async throws {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                self.lock.lock()
                if self.isClosed {
                    self.lock.unlock()
                    continuation.resume(throwing: MythaiaError.closed)
                    return
                }
                if let failure = self.failure {
                    self.lock.unlock()
                    continuation.resume(throwing: failure)
                    return
                }
                if data.isEmpty {
                    self.lock.unlock()
                    continuation.resume()
                    return
                }
                self.nextToken &+= 1
                let token = self.nextToken
                self.pendingSends[token] = continuation
                self.lock.unlock()
                self.connection.send(content: data, completion: .contentProcessed({ [weak self] error in
                    self?.sendCompleted(token: token, error: error)
                }))
            }
        } onCancel: {
            self.close()
        }
    }

    private func sendCompleted(token: UInt64, error: NWError?) {
        lock.lock()
        let continuation = pendingSends.removeValue(forKey: token)
        var mapped: MythaiaError?
        if let error = error {
            let described = TransportNWConnection.describe(error, what: what, connecting: false)
            if failure == nil && !isClosed {
                failure = described
            }
            mapped = described
        }
        lock.unlock()
        guard let continuation = continuation else { return }
        if let mapped = mapped {
            continuation.resume(throwing: mapped)
        } else {
            continuation.resume()
        }
    }

    /// The next chunk the peer sent, at most 64 KiB; nil once it has closed
    /// its side. One read at a time, as ByteStream promises.
    func receive() async throws -> Data? {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data?, Error>) in
                self.lock.lock()
                if self.isClosed {
                    self.lock.unlock()
                    continuation.resume(throwing: MythaiaError.closed)
                    return
                }
                if let failure = self.failure {
                    self.lock.unlock()
                    continuation.resume(throwing: failure)
                    return
                }
                if self.reachedEnd {
                    self.lock.unlock()
                    continuation.resume(returning: nil)
                    return
                }
                if self.pendingReceive != nil {
                    self.lock.unlock()
                    continuation.resume(throwing: MythaiaError.protocolError("two reads at once on one \(self.what) connection"))
                    return
                }
                self.nextToken &+= 1
                let token = self.nextToken
                self.pendingReceiveToken = token
                self.pendingReceive = continuation
                self.lock.unlock()
                self.issueReceive(token: token)
            }
        } onCancel: {
            self.close()
        }
    }

    private func issueReceive(token: UInt64) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: TransportNWConnection.maximumReadLength) {
            [weak self] content, _, isComplete, error in
            self?.receiveCompleted(token: token, content: content, isComplete: isComplete, error: error)
        }
    }

    private func receiveCompleted(token: UInt64, content: Data?, isComplete: Bool, error: NWError?) {
        lock.lock()
        guard let continuation = pendingReceive, pendingReceiveToken == token else {
            // Already resumed by close() or a failure.
            lock.unlock()
            return
        }
        if let content = content, !content.isEmpty {
            pendingReceive = nil
            if isComplete {
                // The data comes first; the next read reports the end.
                reachedEnd = true
            }
            lock.unlock()
            continuation.resume(returning: content)
            return
        }
        if let error = error {
            pendingReceive = nil
            let mapped = TransportNWConnection.describe(error, what: what, connecting: false)
            if failure == nil && !isClosed {
                failure = mapped
            }
            lock.unlock()
            continuation.resume(throwing: mapped)
            return
        }
        if isComplete {
            pendingReceive = nil
            reachedEnd = true
            lock.unlock()
            continuation.resume(returning: nil)
            return
        }
        lock.unlock()
        // Neither data nor an end: ask again rather than hand back an empty chunk.
        issueReceive(token: token)
    }

    /// Safe from any thread, any number of times.
    func close() {
        lock.lock()
        if isClosed {
            lock.unlock()
            return
        }
        isClosed = true
        let connect = connectContinuation
        connectContinuation = nil
        let item = timeoutItem
        timeoutItem = nil
        let receive = pendingReceive
        pendingReceive = nil
        let sends = Array(pendingSends.values)
        pendingSends.removeAll()
        lock.unlock()
        item?.cancel()
        connect?.resume(throwing: MythaiaError.closed)
        receive?.resume(throwing: MythaiaError.closed)
        for send in sends {
            send.resume(throwing: MythaiaError.closed)
        }
        connection.cancel()
    }

    /// The ALPN protocol the TLS handshake settled on, when there is TLS.
    func negotiatedALPN() -> String? {
        guard let metadata = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else {
            return nil
        }
        guard let pointer = sec_protocol_metadata_get_negotiated_protocol(metadata.securityProtocolMetadata) else {
            return nil
        }
        return String(cString: pointer)
    }

    static func describe(_ error: NWError, what: String, connecting: Bool) -> MythaiaError {
        switch error {
        case .posix(let code):
            switch code {
            case .ECONNRESET, .EPIPE, .ENOTCONN, .ECANCELED:
                // Mid-stream these are the peer or the network ending the
                // connection, which the layers above treat as its end.
                return connecting ? .connectFailed(posixMessage(code)) : .closed
            case .ETIMEDOUT:
                return .timeout("\(what) connection")
            default:
                return .connectFailed(posixMessage(code))
            }
        case .tls(let status):
            return .tls(tlsMessage(status))
        case .dns(let code):
            return .connectFailed("DNS lookup failed (\(code))")
        default:
            return .connectFailed(error.debugDescription)
        }
    }

    static func posixMessage(_ code: POSIXErrorCode) -> String {
        String(cString: strerror(code.rawValue))
    }

    static func tlsMessage(_ status: OSStatus) -> String {
        if let text = SecCopyErrorMessageString(status, nil) as String? {
            return text
        }
        return "OSStatus \(status)"
    }
}

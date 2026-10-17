import Foundation

/**
 * A stream to the panel through one of the user's servers, for a
 * subscription whose panel cannot be reached from this network at all.
 *
 * The server dials the panel (its chain included) and TLS runs end to end
 * inside the tunnel, with the panel's — or the front's — name and the
 * system's certificate checks, so the server in between sees only
 * ciphertext. These are the only calls the subscription layer makes into the
 * dialing layers, kept together here.
 */
enum ViaServerHTTP {

    /// `tlsServerName` nil means plain HTTP: the tunnel itself is the stream.
    static func open(
        through server: ProxyConfiguration,
        host: String,
        port: UInt16,
        tlsServerName: String?,
        allowInsecure: Bool,
        timeout: Double,
        opened: FrontedStreams
    ) async throws -> ByteStream {
        let tunnel = try await Dialer.connect(server, to: Endpoint(host: host, port: port), initialData: nil, timeout: timeout)
        opened.add(tunnel)
        guard let serverName = tlsServerName else { return tunnel }
        let options = TLSClientOptions(serverName: serverName, alpn: ["http/1.1"], allowInsecure: allowInsecure)
        let session = try await TLSClient.handshake(over: tunnel, options: options, fingerprint: .chrome133)
        opened.add(session)
        return session
    }
}

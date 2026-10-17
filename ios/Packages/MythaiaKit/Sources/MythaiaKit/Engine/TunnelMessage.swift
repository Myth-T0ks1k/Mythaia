import Foundation

/// What the app asks the running tunnel, sent as JSON through
/// `NETunnelProviderSession.sendProviderMessage`. Each message gets one
/// `TunnelReply`.
public enum TunnelMessage {
    /// New connections go through this server from now on; connections
    /// already relayed finish on the one they were dialled with. Auto in
    /// the tunnel keeps running on its group: send `reload` after saving new
    /// start options to change that.
    case switchConfiguration(ProxyConfiguration)
    /// The traffic counters.
    case stats
    /// The tunnel's recent log lines.
    case logTail
    /// Whether the tunnel is up, and on which server.
    case ping
    /// Re-read the start options from the store (server, routing settings,
    /// Auto group) and apply them without dropping the tunnel. A changed
    /// local port takes effect on the next connect.
    case reload
    /// The app is on screen and runs Auto itself (true), or is gone (false):
    /// the two never measure the same group at once.
    case appActive(Bool)

    private enum CodingKeys: String, CodingKey {
        case type
        case configuration
        case active
    }

    private enum Kind: String {
        case switchConfiguration
        case stats
        case logTail
        case ping
        case reload
        case appActive
    }

    public func encoded() throws -> Data {
        try JSONEncoder().encode(self)
    }

    public static func decode(_ data: Data) throws -> TunnelMessage {
        try JSONDecoder().decode(TunnelMessage.self, from: data)
    }
}

extension TunnelMessage: Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let raw = try container.decode(String.self, forKey: .type)
        guard let kind = Kind(rawValue: raw) else {
            throw DecodingError.dataCorruptedError(
                forKey: .type,
                in: container,
                debugDescription: "Unknown tunnel message \(raw)"
            )
        }
        switch kind {
        case .switchConfiguration:
            self = .switchConfiguration(try container.decode(ProxyConfiguration.self, forKey: .configuration))
        case .stats:
            self = .stats
        case .logTail:
            self = .logTail
        case .ping:
            self = .ping
        case .reload:
            self = .reload
        case .appActive:
            self = .appActive(try container.decode(Bool.self, forKey: .active))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .switchConfiguration(let configuration):
            try container.encode(Kind.switchConfiguration.rawValue, forKey: .type)
            try container.encode(configuration, forKey: .configuration)
        case .stats:
            try container.encode(Kind.stats.rawValue, forKey: .type)
        case .logTail:
            try container.encode(Kind.logTail.rawValue, forKey: .type)
        case .ping:
            try container.encode(Kind.ping.rawValue, forKey: .type)
        case .reload:
            try container.encode(Kind.reload.rawValue, forKey: .type)
        case .appActive(let active):
            try container.encode(Kind.appActive.rawValue, forKey: .type)
            try container.encode(active, forKey: .active)
        }
    }
}

/// The tunnel's answer to a `TunnelMessage`. One shape for every message;
/// the fields a message does not concern stay nil.
public struct TunnelReply: Codable {
    public var ok: Bool
    /// What went wrong, in words for the user, when `ok` is false.
    public var error: String?
    public var stats: TrafficStats?
    public var logLines: [String]?
    /// The server new connections go through.
    public var configurationId: UUID?
    public var configurationName: String?
    /// The local proxy's port.
    public var port: UInt16?

    public init(
        ok: Bool = true,
        error: String? = nil,
        stats: TrafficStats? = nil,
        logLines: [String]? = nil,
        configurationId: UUID? = nil,
        configurationName: String? = nil,
        port: UInt16? = nil
    ) {
        self.ok = ok
        self.error = error
        self.stats = stats
        self.logLines = logLines
        self.configurationId = configurationId
        self.configurationName = configurationName
        self.port = port
    }

    public static func failure(_ message: String) -> TunnelReply {
        TunnelReply(ok: false, error: message)
    }

    public func encoded() throws -> Data {
        try JSONEncoder().encode(self)
    }

    public static func decode(_ data: Data) throws -> TunnelReply {
        try JSONDecoder().decode(TunnelReply.self, from: data)
    }
}

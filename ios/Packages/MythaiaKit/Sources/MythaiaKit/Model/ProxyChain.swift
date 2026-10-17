import Foundation

/**
 * A named, ordered sequence of proxy configurations forming a chain.
 *
 * When selected as the working configuration:
 * - The **last** proxy in `proxyIds` is the exit proxy (talks to the target).
 * - All preceding proxies form the intermediate chain (tunneled through in order).
 */
public struct ProxyChain: Codable, Hashable, Identifiable {
    public var id: UUID
    public var name: String
    public var proxyIds: [UUID]

    public init(id: UUID = UUID(), name: String, proxyIds: [UUID] = []) {
        self.id = id
        self.name = name
        self.proxyIds = proxyIds
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, proxyIds
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID()
        name = try c.decode(String.self, forKey: .name)
        proxyIds = try c.decodeIfPresent([UUID].self, forKey: .proxyIds) ?? []
    }
}

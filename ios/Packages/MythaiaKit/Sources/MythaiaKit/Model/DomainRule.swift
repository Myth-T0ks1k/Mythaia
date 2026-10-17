import Foundation

/**
 * Integer-backed rule type. Legacy string payloads
 * ("domain", "domainKeyword", "domainSuffix", "ipCIDR", "ipCIDR6")
 * are decoded for backward compatibility.
 */
public enum DomainRuleType: Int, Codable, CaseIterable, Hashable {
    case ipCidr = 0
    case ipCidr6 = 1
    case domainSuffix = 2
    case domainKeyword = 3
    /**
     * `geoip:xx` — every address the imported country database places in that
     * country. Matched at lookup time rather than expanded into CIDRs, so a
     * rule stays one entry however many ranges the country owns.
     */
    case geoip = 4

    public static func fromRawValue(_ value: Int) -> DomainRuleType? {
        DomainRuleType(rawValue: value)
    }

    public static func fromLegacyString(_ value: String) -> DomainRuleType? {
        switch value {
        case "ipCIDR": return .ipCidr
        case "ipCIDR6": return .ipCidr6
        case "domain", "domainSuffix": return .domainSuffix
        case "domainKeyword": return .domainKeyword
        case "geoip": return .geoip
        default: return nil
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let number = try? container.decode(Int.self) {
            guard let type = DomainRuleType(rawValue: number) else {
                throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unknown rule type: \(number)")
            }
            self = type
            return
        }
        let text = try container.decode(String.self)
        if let number = Int(text), let type = DomainRuleType(rawValue: number) {
            self = type
            return
        }
        guard let type = DomainRuleType.fromLegacyString(text) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unknown rule type: \(text)")
        }
        self = type
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

public struct DomainRule: Codable, Hashable {
    public var type: DomainRuleType
    public var value: String

    public init(type: DomainRuleType, value: String) {
        self.type = type
        self.value = value
    }
}

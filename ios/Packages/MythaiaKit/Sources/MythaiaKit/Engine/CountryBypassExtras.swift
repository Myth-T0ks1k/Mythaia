import Foundation

/// Rules added on top of the bundled country lists.
///
/// The database ships the operators' IPv4 prefixes and the country TLD; this
/// is where the rest lives — an IPv6 allocation the list predates, a
/// `geoip:` catch-all for a build that has a GeoIP database, and a country's
/// home-grown services that sit on ranges nobody would guess.
public enum CountryBypassExtras {
    public static func rulesFor(_ countryCode: String) -> [DomainRule] {
        switch countryCode.uppercased() {
        case "TM": return turkmenistan
        default: return []
        }
    }

    /// Turkmenistan: Turkmentelecom (AS20661) and the Ashgabat city network
    /// (AS51495, AS205471), Altyn Asyr (AS59974), Turkmen hemrasi (AS204579)
    /// and Tehno Merkez (AS215487). The `Link` messenger answers from
    /// 177.93.143.0/24, Turkmentelecom's one block outside the RIPE space.
    private static let turkmenistan: [DomainRule] = [
        DomainRule(type: .geoip, value: "TM"),
        DomainRule(type: .domainSuffix, value: "tm"),
        DomainRule(type: .ipCidr, value: "177.93.143.0/24"),
        DomainRule(type: .ipCidr, value: "95.85.96.0/19"),
        DomainRule(type: .ipCidr, value: "103.220.0.0/22"),
        DomainRule(type: .ipCidr, value: "119.235.112.0/20"),
        DomainRule(type: .ipCidr, value: "216.250.8.0/21"),
        DomainRule(type: .ipCidr, value: "217.174.224.0/20"),
        DomainRule(type: .ipCidr, value: "93.171.220.0/22"),
        DomainRule(type: .ipCidr, value: "185.69.184.0/22"),
        DomainRule(type: .ipCidr, value: "185.246.72.0/22"),
        DomainRule(type: .ipCidr, value: "77.83.59.0/24"),
        DomainRule(type: .ipCidr, value: "217.65.78.0/24"),
        DomainRule(type: .ipCidr6, value: "2a05:2180::/29"),
    ]
}

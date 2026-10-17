import Foundation
import CryptoKit

/**
 * A WireGuard / AmneziaWG profile as editable fields, for a field-by-field
 * editor.
 *
 * The profile is stored as `wg-quick` INI text (`ProxyConfiguration.wireGuardConfig`)
 * and that stays the source of truth: `fromIni` reads the keys the form shows,
 * keeps every other line (comments, keys a future build understands, peers
 * after the first) and `toIni` writes them back unchanged, so editing a
 * field in the form never loses something the form has no field for.
 */
public struct WireGuardForm: Hashable {
    public var privateKey: String = ""
    public var addresses: String = ""
    public var dns: String = ""
    public var mtu: String = ""
    public var reserved: String = ""
    public var publicKey: String = ""
    public var presharedKey: String = ""
    public var endpoint: String = ""
    public var allowedIps: String = "0.0.0.0/0, ::/0"
    public var keepalive: String = ""
    // AmneziaWG
    public var jc: String = ""
    public var jmin: String = ""
    public var jmax: String = ""
    public var s1: String = ""
    public var s2: String = ""
    public var h1: String = ""
    public var h2: String = ""
    public var h3: String = ""
    public var h4: String = ""
    /// Interface lines the form does not edit, verbatim.
    public var extraInterface: [String] = []
    /// Peer lines the form does not edit, verbatim.
    public var extraPeer: [String] = []
    /// Everything after the first [Peer] section, verbatim.
    public var trailing: [String] = []

    public init() {}

    /// Whether any AmneziaWG obfuscation field is set.
    public var isAmnezia: Bool {
        [jc, jmin, jmax, s1, s2, h1, h2, h3, h4].contains { !LinkText.isBlank($0) }
    }

    public func toIni() -> String {
        var out: [String] = []
        out.append("[Interface]")
        WireGuardForm.line(&out, "PrivateKey", privateKey)
        WireGuardForm.line(&out, "Address", addresses)
        WireGuardForm.line(&out, "DNS", dns)
        WireGuardForm.line(&out, "MTU", mtu)
        WireGuardForm.line(&out, "Reserved", reserved)
        WireGuardForm.line(&out, "Jc", jc)
        WireGuardForm.line(&out, "Jmin", jmin)
        WireGuardForm.line(&out, "Jmax", jmax)
        WireGuardForm.line(&out, "S1", s1)
        WireGuardForm.line(&out, "S2", s2)
        WireGuardForm.line(&out, "H1", h1)
        WireGuardForm.line(&out, "H2", h2)
        WireGuardForm.line(&out, "H3", h3)
        WireGuardForm.line(&out, "H4", h4)
        out.append(contentsOf: extraInterface)
        out.append("")
        out.append("[Peer]")
        WireGuardForm.line(&out, "PublicKey", publicKey)
        WireGuardForm.line(&out, "PresharedKey", presharedKey)
        WireGuardForm.line(&out, "AllowedIPs", allowedIps)
        WireGuardForm.line(&out, "Endpoint", endpoint)
        WireGuardForm.line(&out, "PersistentKeepalive", keepalive)
        out.append(contentsOf: extraPeer)
        if !trailing.isEmpty {
            out.append("")
            out.append(contentsOf: trailing)
        }
        var text = out.joined(separator: "\n")
        while let last = text.unicodeScalars.last, LinkText.isWhitespace(last) {
            text.unicodeScalars.removeLast()
        }
        return text + "\n"
    }

    private static func line(_ out: inout [String], _ key: String, _ value: String) {
        let v = LinkText.trim(value)
        if !v.isEmpty { out.append("\(key) = \(v)") }
    }

    private static let interfaceKeys: Set<String> = [
        "privatekey", "address", "dns", "mtu", "reserved",
        "jc", "jmin", "jmax", "s1", "s2", "h1", "h2", "h3", "h4",
    ]
    private static let peerKeys: Set<String> = ["publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"]

    /// A fresh profile with a new key pair and the usual full-tunnel peer defaults.
    public static func blank() -> WireGuardForm {
        var form = WireGuardForm()
        form.privateKey = generatePrivateKey()
        form.keepalive = "25"
        return form
    }

    public static func fromIni(_ text: String) -> WireGuardForm {
        var form = WireGuardForm()
        form.allowedIps = ""
        var extraInterface: [String] = []
        var extraPeer: [String] = []
        var trailing: [String] = []
        var section = ""
        var peersSeen = 0
        for raw in LinkText.lines(text) {
            let trimmed = LinkText.trim(raw)
            if LinkText.hasPrefix(trimmed, "[") && LinkText.hasSuffix(trimmed, "]") {
                let inner = LinkText.removeSuffix(LinkText.removePrefix(trimmed, "["), "]")
                section = LinkText.trim(inner).lowercased()
                if section == "peer" { peersSeen += 1 }
                if (section == "peer" && peersSeen > 1) || (section != "interface" && section != "peer") {
                    trailing.append(raw)
                }
                continue
            }
            if peersSeen > 1 || (section != "interface" && section != "peer") {
                if !trimmed.isEmpty || !trailing.isEmpty { trailing.append(raw) }
                continue
            }
            if trimmed.isEmpty { continue }
            let bytes = Array(trimmed.utf8)
            var key = ""
            var value = ""
            if let eq = bytes.firstIndex(of: UInt8(ascii: "=")), eq > 0 {
                key = LinkText.trim(LinkText.string(bytes[..<eq])).lowercased()
                value = LinkText.trim(LinkText.string(bytes[(eq + 1)...]))
            }
            if section == "interface" {
                if !interfaceKeys.contains(key) {
                    extraInterface.append(raw)
                    continue
                }
                switch key {
                case "privatekey": form.privateKey = value
                case "address": form.addresses = join(form.addresses, value)
                case "dns": form.dns = join(form.dns, value)
                case "mtu": form.mtu = value
                case "reserved": form.reserved = value
                case "jc": form.jc = value
                case "jmin": form.jmin = value
                case "jmax": form.jmax = value
                case "s1": form.s1 = value
                case "s2": form.s2 = value
                case "h1": form.h1 = value
                case "h2": form.h2 = value
                case "h3": form.h3 = value
                default: form.h4 = value
                }
            } else {
                if !peerKeys.contains(key) {
                    extraPeer.append(raw)
                    continue
                }
                switch key {
                case "publickey": form.publicKey = value
                case "presharedkey": form.presharedKey = value
                case "allowedips": form.allowedIps = join(form.allowedIps, value)
                case "endpoint": form.endpoint = value
                default: form.keepalive = value
                }
            }
        }
        form.extraInterface = extraInterface
        form.extraPeer = extraPeer
        form.trailing = trailing
        return form
    }

    private static func join(_ existing: String, _ more: String) -> String {
        LinkText.isBlank(existing) ? more : "\(existing), \(more)"
    }

    /// A new X25519 private key, base64, as `wg genkey` prints it.
    public static func generatePrivateKey() -> String {
        Curve25519.KeyAgreement.PrivateKey().rawRepresentation.base64EncodedString()
    }

    /// The public key for `privateKey` (base64), or nil when it is not a 32-byte key.
    public static func publicKeyOf(_ privateKey: String) -> String? {
        guard let bytes = LinkText.base64Decode(WireGuardIni.normalizeKey(privateKey), urlSafe: false), bytes.count == 32 else {
            return nil
        }
        guard let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: bytes) else { return nil }
        return key.publicKey.rawRepresentation.base64EncodedString()
    }
}

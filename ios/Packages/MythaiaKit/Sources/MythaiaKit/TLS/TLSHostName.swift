import Foundation

/// Server names as TLS sends and checks them.
enum TLSHostName {

    /// An IPv4 literal (digits and dots) or anything with a colon (IPv6).
    /// Neither goes into SNI.
    static func isIpLiteral(_ name: String) -> Bool {
        if name.isEmpty { return false }
        if name.contains(":") { return true }
        for scalar in name.unicodeScalars {
            let value = scalar.value
            let isDigit = value >= 0x30 && value <= 0x39
            if value != 0x2E && !isDigit { return false }
        }
        return true
    }

    /// The name with every non-ASCII label turned into its A-label
    /// ("bücher.example" becomes "xn--bcher-kva.example"), the form
    /// certificates and servers use. ASCII labels pass through unchanged, as
    /// IDNA's ToASCII leaves them. A label that cannot be encoded leaves the
    /// whole name as it was.
    static func asciiName(_ name: String) -> String {
        let separators: Set<Character> = [".", "\u{3002}", "\u{FF0E}", "\u{FF61}"]
        var labels: [String] = []
        var current = ""
        for character in name {
            if separators.contains(character) {
                labels.append(current)
                current = ""
            } else {
                current.append(character)
            }
        }
        labels.append(current)

        var out: [String] = []
        for label in labels {
            if label.unicodeScalars.allSatisfy({ $0.isASCII }) {
                out.append(label)
                continue
            }
            // Nameprep, as far as it matters for names people type: case
            // folding and compatibility composition.
            let prepared = label.lowercased().precomposedStringWithCompatibilityMapping
            guard let encoded = punycodeEncode(prepared) else { return name }
            out.append("xn--" + encoded)
        }
        return out.joined(separator: ".")
    }

    // Punycode parameters (RFC 3492 §5).
    private static let base = 36
    private static let tMin = 1
    private static let tMax = 26
    private static let skew = 38
    private static let damp = 700
    private static let initialBias = 72
    private static let initialN = 128

    /// RFC 3492 encoding of one label, without the "xn--" prefix.
    static func punycodeEncode(_ input: String) -> String? {
        let codePoints = input.unicodeScalars.map { Int($0.value) }
        var output = ""
        for point in codePoints where point < 0x80 {
            guard let scalar = Unicode.Scalar(point) else { return nil }
            output.unicodeScalars.append(scalar)
        }
        let basicCount = output.unicodeScalars.count
        var handled = basicCount
        if basicCount > 0 { output.append("-") }

        var n = initialN
        var delta = 0
        var bias = initialBias
        while handled < codePoints.count {
            var next = Int.max
            for point in codePoints where point >= n && point < next {
                next = point
            }
            let (product, overflow) = (next - n).multipliedReportingOverflow(by: handled + 1)
            if overflow { return nil }
            delta += product
            n = next
            for point in codePoints {
                if point < n {
                    delta += 1
                }
                if point == n {
                    var q = delta
                    var k = base
                    while true {
                        let t: Int
                        if k <= bias {
                            t = tMin
                        } else if k >= bias + tMax {
                            t = tMax
                        } else {
                            t = k - bias
                        }
                        if q < t { break }
                        output.append(digit(t + (q - t) % (base - t)))
                        q = (q - t) / (base - t)
                        k += base
                    }
                    output.append(digit(q))
                    bias = adapt(delta, numPoints: handled + 1, firstTime: handled == basicCount)
                    delta = 0
                    handled += 1
                }
            }
            delta += 1
            n += 1
        }
        return output
    }

    private static func digit(_ value: Int) -> Character {
        let scalarValue = value < 26 ? 0x61 + value : 0x30 + (value - 26)
        return Character(Unicode.Scalar(UInt8(scalarValue)))
    }

    private static func adapt(_ delta: Int, numPoints: Int, firstTime: Bool) -> Int {
        var d = firstTime ? delta / damp : delta / 2
        d += d / numPoints
        var k = 0
        while d > ((base - tMin) * tMax) / 2 {
            d /= base - tMin
            k += base
        }
        return k + ((base - tMin + 1) * d) / (d + skew)
    }
}

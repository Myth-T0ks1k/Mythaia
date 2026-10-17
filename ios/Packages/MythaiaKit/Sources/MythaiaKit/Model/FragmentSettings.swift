import Foundation

/**
 * Xray's `fragment` with `packets: tlshello`: the TLS ClientHello goes out as
 * several TLS records with a pause between them, so a filter that reads the
 * server name off the first packet does not find it there. Every server
 * reassembles a handshake message across records — the TLS spec requires it —
 * so nothing on the far side has to know.
 *
 * On by default: the product ships to networks where the server name is the
 * first thing a filter looks for, and the cost is a few dozen milliseconds per
 * handshake with the proxy server, once per connection.
 *
 * Two shapes are carried. The simple one — one length range, one interval
 * range — is what the settings screen edits and what the tunnel-wide default
 * is. The full FinalMask one — a length range and a delay range *per piece*,
 * and a cap on the number of pieces — is what panels send in `fm=`, and it
 * is kept as sent so "3 bytes, then the rest, 1 ms apart" means exactly that.
 */
public struct FragmentSettings: Codable, Hashable {
    public var isEnabled: Bool

    /**
     * Bytes of ClientHello per record, drawn at random from this range for each
     * record. Xray's popular `100-200`.
     */
    public var minLength: Int
    public var maxLength: Int

    /**
     * Milliseconds between one record and the next, drawn at random from this
     * range. Xray's popular `10-20`.
     */
    public var minInterval: Int
    public var maxInterval: Int

    /**
     * FinalMask's per-piece `lengths`, as `a` or `a-b` texts: the n-th entry
     * sizes the n-th piece, the last entry every piece after it. Empty means
     * "use minLength...maxLength for every piece".
     */
    public var lengthSteps: [String]

    /// FinalMask's per-piece `delays`, same shape; the n-th entry is the pause after the n-th piece.
    public var delaySteps: [String]

    /// FinalMask's `maxSplit`: at most this many pieces, the last taking the rest. 0 is no cap.
    public var maxSplit: Int

    public static let defaultMinLength = 100
    public static let defaultMaxLength = 200
    public static let defaultMinInterval = 10
    public static let defaultMaxInterval = 20

    public init(
        isEnabled: Bool = true,
        minLength: Int = FragmentSettings.defaultMinLength,
        maxLength: Int = FragmentSettings.defaultMaxLength,
        minInterval: Int = FragmentSettings.defaultMinInterval,
        maxInterval: Int = FragmentSettings.defaultMaxInterval,
        lengthSteps: [String] = [],
        delaySteps: [String] = [],
        maxSplit: Int = 0
    ) {
        self.isEnabled = isEnabled
        self.minLength = minLength
        self.maxLength = maxLength
        self.minInterval = minInterval
        self.maxInterval = maxInterval
        self.lengthSteps = lengthSteps
        self.delaySteps = delaySteps
        self.maxSplit = maxSplit
    }

    private enum CodingKeys: String, CodingKey {
        case isEnabled, minLength, maxLength, minInterval, maxInterval, lengthSteps, delaySteps, maxSplit
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        isEnabled = try c.decodeIfPresent(Bool.self, forKey: .isEnabled) ?? true
        minLength = try c.decodeIfPresent(Int.self, forKey: .minLength) ?? FragmentSettings.defaultMinLength
        maxLength = try c.decodeIfPresent(Int.self, forKey: .maxLength) ?? FragmentSettings.defaultMaxLength
        minInterval = try c.decodeIfPresent(Int.self, forKey: .minInterval) ?? FragmentSettings.defaultMinInterval
        maxInterval = try c.decodeIfPresent(Int.self, forKey: .maxInterval) ?? FragmentSettings.defaultMaxInterval
        lengthSteps = try c.decodeIfPresent([String].self, forKey: .lengthSteps) ?? []
        delaySteps = try c.decodeIfPresent([String].self, forKey: .delaySteps) ?? []
        maxSplit = try c.decodeIfPresent(Int.self, forKey: .maxSplit) ?? 0
    }

    /**
     * The ranges as the fragmenter draws from them: never empty, never below
     * one byte or zero milliseconds, whichever way round the two ends were
     * typed.
     */
    public var lengthRange: ClosedRange<Int> {
        let low = max(1, min(minLength, maxLength))
        return low...max(low, max(minLength, maxLength))
    }

    public var intervalRange: ClosedRange<Int> {
        let low = max(0, min(minInterval, maxInterval))
        return low...max(low, max(minInterval, maxInterval))
    }

    /// One range per piece; the fragmenter repeats the last for the remainder.
    public var lengthRanges: [ClosedRange<Int>] {
        var steps: [ClosedRange<Int>] = []
        for text in lengthSteps {
            guard let range = FragmentSettings.parseRange(text) else { continue }
            steps.append(max(1, range.lowerBound)...max(1, range.upperBound))
        }
        return steps.isEmpty ? [lengthRange] : steps
    }

    /// One pause range per piece boundary; the last repeats.
    public var delayRanges: [ClosedRange<Int>] {
        let steps = delaySteps.compactMap { FragmentSettings.parseRange($0) }
        return steps.isEmpty ? [intervalRange] : steps
    }

    /**
     * The `fragment=` query value of a share link, as Happ and Streisand write
     * it: `length,interval,packets[,maxSplit]`. Emitted with the fixed
     * `tlshello` packets field, which is the only mode this client implements.
     * A per-piece list is written as its first step, which is the piece the
     * filter sees; the rest cannot be said in this form.
     */
    public func toShareLinkValue() -> String {
        let length = FragmentSettings.rangeText(lengthRanges[0])
        let interval = FragmentSettings.rangeText(delayRanges[0])
        let split = maxSplit > 0 ? ",\(maxSplit)" : ""
        return "\(length),\(interval),tlshello\(split)"
    }

    /// The same settings as a FinalMask `fm=` document, which loses nothing.
    public func toFinalMaskJson() -> String {
        let lengths = lengthRanges.map { ImportJSON.string(FragmentSettings.rangeText($0)) }
        let delays = delayRanges.map { ImportJSON.string(FragmentSettings.rangeText($0)) }
        var settings = ImportJSONObject()
        settings.put("packets", "tlshello")
        settings.put("lengths", ImportJSON.array(lengths))
        settings.put("delays", ImportJSON.array(delays))
        if maxSplit > 0 { settings.put("maxSplit", String(maxSplit)) }
        var mask = ImportJSONObject()
        mask.put("type", "fragment")
        mask.put("settings", ImportJSON.object(settings))
        var root = ImportJSONObject()
        root.put("tcp", ImportJSON.array([ImportJSON.object(mask)]))
        return root.serialized()
    }

    private static func rangeText(_ range: ClosedRange<Int>) -> String {
        range.lowerBound == range.upperBound ? "\(range.lowerBound)" : "\(range.lowerBound)-\(range.upperBound)"
    }

    /**
     * Parses the `fragment=` query of a share link:
     * `length,interval,packets[,maxSplit]`, each of the first two a number
     * or an `a-b` range — `3,1,tlshello`, `1-10,5-20,tlshello,2`. Nil
     * when it does not parse.
     *
     * `packets` other than `tlshello` (Xray's `1-3`, raw TCP pieces) are
     * taken as `tlshello` too: cutting the hello into records is safe
     * wherever cutting the stream would have been, and it is the hello a
     * filter is after.
     */
    public static func fromShareLink(_ value: String) -> FragmentSettings? {
        let fields = LinkText.split(value, UInt8(ascii: ",")).map { LinkText.trim($0) }
        if fields.count != 3 && fields.count != 4 { return nil }
        if fields[2].isEmpty { return nil }

        guard let length = parseRange(fields[0]), length.lowerBound >= 1 else { return nil }
        guard let interval = parseRange(fields[1]) else { return nil }
        var maxSplit = 0
        if fields.count == 4 {
            guard let split = parseRange(fields[3]) else { return nil }
            maxSplit = split.upperBound
        }

        return FragmentSettings(
            isEnabled: true,
            minLength: length.lowerBound,
            maxLength: length.upperBound,
            minInterval: interval.lowerBound,
            maxInterval: interval.upperBound,
            maxSplit: maxSplit
        )
    }

    /**
     * Parses Xray FinalMask, as the `fm=` link parameter carries it:
     * `{"tcp":[{"type":"fragment","settings":{"packets":"tlshello",
     * "lengths":["3"],"delays":["1"],"maxSplit":"2"}}], ...}`.
     *
     * Only the `tcp` fragment mask is read; `udp` (Salamander) and
     * `quicParams` belong to the protocols that use them. Nil when there
     * is no fragment mask or it does not parse.
     *
     * Panels write the per-piece lists in two spellings: plural arrays
     * (`"lengths":["3"]`) and a singular value (`"length":"3"`, or a bare
     * number) that means the same one-entry list. Both are read, since
     * one provider's JSON subscription uses each in different entries.
     */
    public static func fromFinalMask(_ json: String) -> FragmentSettings? {
        guard let root = try? ImportJSON.parseObject(json) else { return nil }
        guard let tcp = root.optArray("tcp") else { return nil }
        for element in tcp {
            guard let mask = element.objectValue else { continue }
            if mask.optString("type") != "fragment" { continue }
            guard let settings = mask.optObject("settings") else { continue }
            return fromFinalMaskSettings(settings)
        }
        return nil
    }

    private static func fromFinalMaskSettings(_ settings: ImportJSONObject) -> FragmentSettings? {
        let lengths = rangeTexts(settings.opt("lengths") ?? settings.opt("length"))
        let delays = rangeTexts(settings.opt("delays") ?? settings.opt("delay"))
        guard let firstText = lengths.first, let first = parseRange(firstText) else { return nil }
        let firstDelay = delays.first.flatMap { parseRange($0) } ?? (0...0)
        // Int32Range: "2" or "2-3"; the upper end is the cap that matters.
        let maxSplit = rangeTexts(settings.opt("maxSplit")).first.flatMap { parseRange($0)?.upperBound } ?? 0
        return FragmentSettings(
            isEnabled: true,
            minLength: max(1, first.lowerBound),
            maxLength: max(1, first.upperBound),
            minInterval: firstDelay.lowerBound,
            maxInterval: firstDelay.upperBound,
            lengthSteps: lengths,
            delaySteps: delays,
            maxSplit: maxSplit
        )
    }

    /// A JSON array of range texts, or one range text, as a list.
    private static func rangeTexts(_ value: ImportJSON?) -> [String] {
        guard let value = value else { return [] }
        if let array = value.arrayValue {
            return array.map { $0.text }.filter { !LinkText.isBlank($0) }
        }
        return [value.text].filter { !LinkText.isBlank($0) }
    }

    static func parseRange(_ text: String) -> ClosedRange<Int>? {
        let ends = LinkText.split(LinkText.trim(text), UInt8(ascii: "-"))
        if ends.count != 1 && ends.count != 2 { return nil }
        guard let low = Int(LinkText.trim(ends[0])), low >= 0 else { return nil }
        if ends.count == 1 { return low...low }
        guard let high = Int(LinkText.trim(ends[1])), high >= low else { return nil }
        return low...high
    }
}

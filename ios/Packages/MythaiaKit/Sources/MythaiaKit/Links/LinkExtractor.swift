import Foundation

/**
 * Finds the share links and subscription URLs in whatever was pasted.
 *
 * People paste a whole chat message ("here is your key: vless://… valid till
 * Friday"), a list of links, or another client's import link wrapping the
 * real one (`happ://add/https://…`, `v2rayng://install-config?url=…`). The
 * add screen wants the link and nothing else; this gets it out.
 */
public enum LinkExtractor {

    /// Wrapper schemes other clients put around a subscription or a link.
    private static let wrappers: [String] = [
        "mythaia://add-proxy?link=", "mythaia://import?url=",
        "happ://add/", "happ://import/",
        "v2rayng://install-config?url=", "v2rayn://install-config?url=",
        "hiddify://import/", "hiddify://install-config?url=",
        "sing-box://import-remote-profile?url=", "sing-box://import-remote-profile/?url=",
        "clash://install-config?url=", "clashmeta://install-config?url=",
        "streisand://import/", "karing://install-config?url=", "nekobox://install-config?url=",
    ]

    private static func schemeOf(_ prefix: String) -> String {
        let bytes = Array(prefix.utf8)
        guard let at = LinkText.indexOf(bytes, Array("://".utf8)) else { return prefix }
        return LinkText.string(bytes[..<at]) + "://"
    }

    /// Every scheme a link may start with, as UTF-16 units for the search.
    private static let schemes: [[UInt16]] = {
        var seen = Set<String>()
        var out: [[UInt16]] = []
        let all = ProxyConfiguration.parsableUrlPrefixes + ["http://"] + wrappers.map { schemeOf($0) }
        for scheme in all where !seen.contains(scheme) {
            seen.insert(scheme)
            out.append(Array(scheme.utf16))
        }
        return out
    }()

    /// Characters that end a link when it sits in running text.
    private static let terminators: Set<UInt16> = {
        let text = " \t\n\r\"'<>`«»“”‘’|"
        return Set(text.utf16)
    }()

    /**
     * Every link in `text`, unwrapped and in order, duplicates removed. A link
     * in running text ends at white space or a quote; trailing punctuation a
     * sentence would add (`.`, `,`, `)`) is dropped unless the link needs it.
     */
    public static func extract(_ text: String) -> [String] {
        let units = Array(text.utf16)
        var found: [String] = []
        var seen = Set<String>()
        var i = 0
        while i < units.count {
            guard let start = nextLinkStart(units, from: i) else { break }
            var end = start
            while end < units.count && !terminators.contains(units[end]) { end += 1 }
            let trimmedEnd = trimSentencePunctuation(units, start: start, end: end)
            let link = String(decoding: units[start..<trimmedEnd], as: UTF16.self)
            if let unwrapped = unwrap(link), !seen.contains(unwrapped) {
                seen.insert(unwrapped)
                found.append(unwrapped)
            }
            i = max(end, start + 1)
        }
        return found
    }

    /**
     * Where the first link at or after `from` starts, or nil.
     *
     * Every scheme ends in "://", so only that is searched for, and the
     * schemes are tried against the few characters just before each hit.
     * Searching the text for each scheme in turn rescanned all of the rest
     * of it for every scheme it did not contain, once per link: a paste of
     * a few thousand servers never finished, and the add screen froze.
     */
    private static func nextLinkStart(_ text: [UInt16], from: Int) -> Int? {
        var colon = indexOfSeparator(text, from: from)
        while let c = colon {
            // Several schemes can end at the same "://" (`ss://` inside
            // `vmess://`); the earliest start is the one the link has.
            var start: Int? = nil
            for scheme in schemes {
                let at = c + 3 - scheme.count
                if at < from { continue }
                if let current = start, current <= at { continue }
                if regionMatchesIgnoringCase(text, at: at, scheme) { start = at }
            }
            if let start = start { return start }
            colon = indexOfSeparator(text, from: c + 1)
        }
        return nil
    }

    private static func indexOfSeparator(_ text: [UInt16], from: Int) -> Int? {
        var i = max(0, from)
        while i + 2 < text.count {
            if text[i] == 58 && text[i + 1] == 47 && text[i + 2] == 47 { return i }
            i += 1
        }
        return nil
    }

    /// ASCII case folded in place rather than in a lowercased copy: lowercasing
    /// can change the length (Turkish "İ" becomes two characters), and an
    /// offset found in the copy would land mid-link in the original.
    private static func regionMatchesIgnoringCase(_ text: [UInt16], at: Int, _ scheme: [UInt16]) -> Bool {
        if at < 0 || at + scheme.count > text.count { return false }
        for k in 0..<scheme.count {
            var a = text[at + k]
            var b = scheme[k]
            if a >= 65 && a <= 90 { a += 32 }
            if b >= 65 && b <= 90 { b += 32 }
            if a != b { return false }
        }
        return true
    }

    /// The real link inside another client's import link, or `link` itself.
    public static func unwrap(_ link: String) -> String? {
        // Our own import link may carry fronting beside the URL; it comes out
        // as the URL with the fronting in its fragment, which the add screen reads.
        if LinkText.hasPrefix(link, "mythaia://import?", ignoreCase: true) {
            if let parsed = SubscriptionLink.parse(link) { return parsed.toFragmentLink() }
        }
        for wrapper in wrappers where LinkText.hasPrefix(link, wrapper, ignoreCase: true) {
            let rest = Array(link.utf8.dropFirst(wrapper.utf8.count))
            var inner = rest
            if let cut = LinkText.indexOf(rest, Array("#name=".utf8)) { inner = Array(rest[..<cut]) }
            let innerText = LinkText.string(inner)
            let decoded = LinkText.formDecode(innerText)
            return LinkText.contains(decoded, "://") ? decoded : nil
        }
        let isWrapperScheme = wrappers.contains { LinkText.hasPrefix(link, schemeOf($0), ignoreCase: true) }
        let isProxyScheme = ProxyConfiguration.parsableUrlPrefixes.contains { LinkText.hasPrefix(link, $0, ignoreCase: true) }
        if isWrapperScheme && !isProxyScheme { return nil }
        // Something after the "://", or it is a bare scheme.
        let bytes = Array(link.utf8)
        let separator = LinkText.indexOf(bytes, Array("://".utf8)) ?? -1
        return bytes.count > separator + 3 ? link : nil
    }

    /// The end of the link once the punctuation a sentence put after it is dropped.
    private static func trimSentencePunctuation(_ text: [UInt16], start: Int, end: Int) -> Int {
        let punctuation: Set<UInt16> = Set(".,;:!?)]}".utf16)
        var e = end
        while e > start && punctuation.contains(text[e - 1]) {
            let c = text[e - 1]
            // A closing bracket that the link opened belongs to it.
            if c == 41 && count(text, start, e, 40) >= count(text, start, e, 41) { break }
            if c == 93 && count(text, start, e, 91) >= count(text, start, e, 93) { break }
            e -= 1
        }
        return e
    }

    private static func count(_ text: [UInt16], _ start: Int, _ end: Int, _ unit: UInt16) -> Int {
        var n = 0
        var i = start
        while i < end {
            if text[i] == unit { n += 1 }
            i += 1
        }
        return n
    }
}

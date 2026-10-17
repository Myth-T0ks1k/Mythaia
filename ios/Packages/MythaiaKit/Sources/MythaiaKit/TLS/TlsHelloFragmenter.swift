import Foundation

/// Splits one TLS handshake record into several, each a complete record of
/// its own (the same type and version, its own length, a slice of the
/// handshake bytes), and sends them with a pause between. Xray calls this
/// `fragment` with `packets: tlshello`; see `FragmentSettings` for why it
/// exists. The record layer on the other side reassembles the message, as
/// every TLS implementation must.
enum TlsHelloFragmenter {

    private static let handshakeContentType: UInt8 = 0x16
    private static let headerLength = 5

    /// `record` cut into records whose payloads are `lengths` bytes long, in
    /// order, the last taking whatever remains; `lengths` running out falls
    /// back to its last value. Anything that is not one well-formed handshake
    /// record comes back untouched, as a single piece.
    static func split(_ record: [UInt8], lengths: [Int]) -> [[UInt8]] {
        guard let last = lengths.last else { return [record] }
        if record.count <= headerLength || record[0] != handshakeContentType || last <= 0 {
            return [record]
        }
        let declared = TLSWire.u16(record, 3)
        if headerLength + declared != record.count { return [record] }

        var pieces: [[UInt8]] = []
        var from = headerLength
        var index = 0
        while from < record.count {
            let wanted = index < lengths.count ? lengths[index] : last
            let length = max(1, wanted)
            let to = min(from + length, record.count)
            let payloadLength = to - from
            var piece: [UInt8] = [record[0], record[1], record[2]]
            piece.append(contentsOf: TLSWire.u16Bytes(payloadLength))
            piece.append(contentsOf: record[from..<to])
            pieces.append(piece)
            from = to
            index += 1
        }
        return pieces
    }

    /// The same, with each length drawn from `lengthRange`.
    static func split<G: RandomNumberGenerator>(
        _ record: [UInt8],
        lengthRange: ClosedRange<Int>,
        using generator: inout G
    ) -> [[UInt8]] {
        return split(record, lengthRanges: [lengthRange], maxSplit: 0, using: &generator)
    }

    /// FinalMask's shape: the n-th piece is drawn from the n-th of
    /// `lengthRanges`, the last range serving every piece after it, and with
    /// `maxSplit` > 0 the piece that would be the last allowed takes whatever
    /// remains. `lengths ["3"], maxSplit 2` is therefore "3 bytes, then the
    /// rest" (the classic split), not a hello cut into 3-byte slivers.
    static func split<G: RandomNumberGenerator>(
        _ record: [UInt8],
        lengthRanges: [ClosedRange<Int>],
        maxSplit: Int,
        using generator: inout G
    ) -> [[UInt8]] {
        guard let lastRange = lengthRanges.last else { return [record] }
        let payloadCount = max(0, record.count - headerLength)
        var lengths: [Int] = []
        var covered = 0
        var index = 0
        while covered < payloadCount {
            if maxSplit > 0 && lengths.count == maxSplit - 1 {
                lengths.append(payloadCount - covered)
                break
            }
            let range = lengthRanges[min(index, lengthRanges.count - 1)]
            let length = max(1, nextInRange(range, using: &generator))
            lengths.append(length)
            covered += length
            index += 1
        }
        return split(record, lengths: lengths.isEmpty ? [lastRange.upperBound] : lengths)
    }

    /// Sends `pieces` one write at a time. Each write is awaited before the
    /// pause after it, and the pause after the n-th piece is drawn from the
    /// n-th of `delayRanges` (the last serving every later gap, as FinalMask
    /// defines it). The pause is what keeps the records in separate segments:
    /// without it the kernel would coalesce them and the split would buy
    /// nothing.
    static func send<G: RandomNumberGenerator>(
        _ pieces: [[UInt8]],
        over stream: ByteStream,
        delayRanges: [ClosedRange<Int>],
        using generator: inout G
    ) async throws {
        for index in 0..<pieces.count {
            try await stream.send(Data(pieces[index]))
            if index == pieces.count - 1 { break }
            guard !delayRanges.isEmpty else { continue }
            let range = delayRanges[min(index, delayRanges.count - 1)]
            let pause = nextInRange(range, using: &generator)
            if pause > 0 {
                try await Task.sleep(nanoseconds: UInt64(pause) * 1_000_000)
            }
        }
    }

    /// Cuts the first flight's record as `settings` say and sends it.
    static func send(_ record: [UInt8], over stream: ByteStream, settings: FragmentSettings) async throws {
        var generator = SystemRandomNumberGenerator()
        let pieces = split(record, lengthRanges: settings.lengthRanges, maxSplit: settings.maxSplit, using: &generator)
        try await send(pieces, over: stream, delayRanges: settings.delayRanges, using: &generator)
    }

    /// A value drawn uniformly from `range`; negative ends count as zero.
    static func nextInRange<G: RandomNumberGenerator>(_ range: ClosedRange<Int>, using generator: inout G) -> Int {
        let low = max(0, range.lowerBound)
        let high = max(low, range.upperBound)
        if high == low { return low }
        return Int.random(in: low...high, using: &generator)
    }
}

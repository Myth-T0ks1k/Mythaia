import SwiftUI

/// The live readout: rate first, total underneath, and how long the tunnel
/// has been up. The rate is the headline because it is the number that moves.
struct SessionStatsView: View {
    let downloadSpeed: Int64
    let uploadSpeed: Int64
    let downloadTotal: Int64
    let uploadTotal: Int64
    let connectedDate: Date?

    var body: some View {
        VStack(spacing: 12) {
            HStack(spacing: 12) {
                SpeedTile(
                    systemImage: "arrow.down",
                    title: String(localized: "Download"),
                    bytesPerSecond: downloadSpeed,
                    total: downloadTotal
                )
                SpeedTile(
                    systemImage: "arrow.up",
                    title: String(localized: "Upload"),
                    bytesPerSecond: uploadSpeed,
                    total: uploadTotal
                )
            }
            uptimeRow
        }
    }

    private var uptimeRow: some View {
        HStack(spacing: 8) {
            Image(systemName: "clock")
                .font(.footnote)
                .foregroundColor(Palette.onSurfaceVariant)
            Text("Connected for")
                .font(.footnote.weight(.medium))
                .foregroundColor(Palette.onSurfaceVariant)
            TimelineView(.periodic(from: Date(), by: 1)) { context in
                Text(verbatim: uptime(at: context.date))
                    .font(.subheadline.monospaced().weight(.semibold))
                    .foregroundColor(Palette.onSurface)
            }
        }
        .frame(maxWidth: .infinity)
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .card(radius: 20)
    }

    private func uptime(at date: Date) -> String {
        guard let since = connectedDate else { return Format.uptime(0) }
        return Format.uptime(Int(date.timeIntervalSince(since)))
    }
}

private struct SpeedTile: View {
    let systemImage: String
    let title: String
    let bytesPerSecond: Int64
    let total: Int64

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                Image(systemName: systemImage)
                    .font(.footnote.weight(.semibold))
                    .foregroundColor(Palette.onSurfaceVariant)
                Text(verbatim: title)
                    .font(.footnote.weight(.medium))
                    .foregroundColor(Palette.onSurfaceVariant)
                    .lineLimit(1)
            }
            Text("\(Format.bytes(bytesPerSecond))/s")
                .font(.headline.monospaced())
                .foregroundColor(Palette.onSurface)
                .lineLimit(1)
                .minimumScaleFactor(0.7)
            Text(verbatim: Format.bytes(total))
                .font(.caption.monospaced())
                .foregroundColor(Palette.onSurfaceVariant)
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .card(radius: 20)
    }
}

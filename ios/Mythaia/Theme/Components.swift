import SwiftUI
import MythaiaKit

/// The latency chip: azure for a good time, orange for a fair one, red for a
/// poor one, quiet text for a failure.
struct LatencyBadge: View {
    let result: LatencyResult?

    var body: some View {
        switch result {
        case .testing?:
            ProgressView()
                .controlSize(.small)
        case .success(let ms)?:
            successChip(ms)
        case .failed?:
            Text("timeout")
                .font(.caption.weight(.medium))
                .foregroundColor(Palette.onSurfaceVariant)
                .padding(.horizontal, 8)
                .padding(.vertical, 4)
                .background(Palette.onSurface.opacity(0.06), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        case nil:
            EmptyView()
        }
    }

    private func color(_ ms: Int) -> Color {
        if ms < 300 { return Palette.primary }
        if ms < 600 { return Palette.warning }
        return Palette.error
    }

    private func successChip(_ ms: Int) -> some View {
        let tint = color(ms)
        return HStack(spacing: 6) {
            Circle()
                .fill(tint)
                .frame(width: 6, height: 6)
            Text("\(ms) ms")
                .font(.caption.monospacedDigit().weight(.medium))
                .foregroundColor(tint)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}

/// A tiny label for protocol facts.
struct TagPill: View {
    let text: String
    var critical = false

    var body: some View {
        Text(verbatim: text)
            .font(.caption2.weight(critical ? .bold : .regular))
            .foregroundColor(critical ? Palette.onPrimary : Palette.onSurfaceVariant)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(
                critical ? Palette.error : Palette.onSurface.opacity(0.06),
                in: RoundedRectangle(cornerRadius: 6, style: .continuous)
            )
    }
}

/// A round tile on the brand gradient, for row glyphs.
struct WingIconTile<Content: View>: View {
    var size: CGFloat = 34
    @ViewBuilder var content: () -> Content

    var body: some View {
        ZStack {
            Circle()
                .fill(LinearGradient(
                    colors: [Palette.lightAzure, Palette.azure, Palette.azureDeep],
                    startPoint: .topLeading,
                    endPoint: .bottomTrailing
                ))
            content()
        }
        .frame(width: size, height: size)
    }
}

/// A paper card with a hairline outline.
struct CardBackground: ViewModifier {
    var radius: CGFloat = 20
    var fill: Color = Palette.surface

    func body(content: Content) -> some View {
        content
            .background(fill, in: RoundedRectangle(cornerRadius: radius, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: radius, style: .continuous)
                    .strokeBorder(Palette.outline, lineWidth: 1)
            )
    }
}

extension View {
    func card(radius: CGFloat = 20, fill: Color = Palette.surface) -> some View {
        modifier(CardBackground(radius: radius, fill: fill))
    }
}

/// A share sheet for text.
struct ActivityView: UIViewControllerRepresentable {
    let items: [Any]

    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}

/// Text handed to the share sheet.
struct SharePayload: Identifiable {
    let id = UUID()
    let text: String
}

enum Format {
    /// "1.2 MB", in the reader's locale.
    static func bytes(_ count: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: max(count, 0), countStyle: .binary)
    }

    /// `H:MM:SS`, or `MM:SS` under an hour, in ASCII digits so the
    /// monospaced readout does not shift.
    static func uptime(_ seconds: Int) -> String {
        let safe = max(seconds, 0)
        let hours = safe / 3600
        let minutes = (safe % 3600) / 60
        let secs = safe % 60
        if hours > 0 {
            return String(format: "%ld:%02ld:%02ld", hours, minutes, secs)
        }
        return String(format: "%02ld:%02ld", minutes, secs)
    }

    /// "in 3 days", "2 hours ago".
    static func relative(millis: Int64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(millis) / 1000)
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return formatter.localizedString(for: date, relativeTo: Date())
    }

    static func date(millis: Int64) -> String {
        let date = Date(timeIntervalSince1970: TimeInterval(millis) / 1000)
        return DateFormatter.localizedString(from: date, dateStyle: .medium, timeStyle: .short)
    }

    /// "host:port" with an IPv6 literal bracketed.
    static func endpoint(_ config: ProxyConfiguration) -> String {
        let host = config.serverAddress.contains(":") ? "[\(config.serverAddress)]" : config.serverAddress
        return "\(host):\(config.serverPort)"
    }
}

/// How a latency kind is named in menus and settings.
enum LatencyKindLabel {
    static func title(_ kind: LatencyKind) -> String {
        switch kind {
        case .tcp: return String(localized: "Ping (TCP/UDP)")
        case .handshake: return String(localized: "Handshake time")
        case .http: return String(localized: "Real ping through proxy")
        }
    }

    static func short(_ kind: LatencyKind) -> String {
        switch kind {
        case .tcp: return String(localized: "Ping")
        case .handshake: return String(localized: "handshake")
        case .http: return "HTTP"
        }
    }

    static func systemImage(_ kind: LatencyKind) -> String {
        switch kind {
        case .tcp: return "dot.radiowaves.left.and.right"
        case .handshake: return "hand.wave"
        case .http: return "speedometer"
        }
    }
}

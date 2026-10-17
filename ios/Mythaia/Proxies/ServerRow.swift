import SwiftUI
import MythaiaKit

/// One server: an azure bar down the leading edge while it is the one in
/// use, the name, the endpoint in mono, the protocol facts as small pills,
/// and the latency on the trailing edge. A pin or a bolt says how it got
/// chosen.
struct ServerRow: View {
    let config: ProxyConfiguration
    let selected: Bool
    let pinned: Bool
    let autoPick: Bool
    let latency: LatencyResult?

    var body: some View {
        HStack(spacing: 12) {
            accentBar
            VStack(alignment: .leading, spacing: 4) {
                titleLine
                Text(verbatim: Format.endpoint(config))
                    .font(.caption.monospaced())
                    .foregroundColor(Palette.onSurfaceVariant)
                    .lineLimit(1)
                tags
            }
            Spacer(minLength: 8)
            LatencyBadge(result: latency)
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }

    private var accentBar: some View {
        RoundedRectangle(cornerRadius: 2, style: .continuous)
            .fill(LinearGradient(colors: [Palette.lightAzure, Palette.azure], startPoint: .top, endPoint: .bottom))
            .frame(width: 4, height: 44)
            .opacity(selected ? 1 : 0)
    }

    private var titleLine: some View {
        HStack(spacing: 6) {
            Text(verbatim: config.name)
                .font(.subheadline.weight(.semibold))
                .foregroundColor(Palette.onSurface)
                .lineLimit(2)
            if pinned {
                Image(systemName: "pin.fill")
                    .font(.caption2)
                    .foregroundColor(Palette.primary)
                    .accessibilityLabel(Text("Pinned"))
            } else if autoPick {
                Image(systemName: "bolt.fill")
                    .font(.caption2)
                    .foregroundColor(Palette.primary.opacity(0.7))
                    .accessibilityLabel(Text("Chosen by Auto"))
            }
        }
    }

    private var tags: some View {
        HStack(spacing: 6) {
            TagPill(text: config.outboundProtocol.displayName)
            if let transport = CoreBridge.transportTag(config) {
                TagPill(text: transport)
            }
            if let security = CoreBridge.securityTag(config) {
                TagPill(text: security)
            }
            if CoreBridge.usesVision(config) {
                TagPill(text: "Vision")
            }
            if CoreBridge.skipsCertificateCheck(config) {
                TagPill(text: String(localized: "INSECURE"), critical: true)
            }
        }
    }
}

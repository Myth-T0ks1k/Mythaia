import SwiftUI
import MythaiaKit

/// What a subscription has left: traffic used against the quota, and when
/// it expires. Shows nothing for a panel that reported neither.
struct SubscriptionUsageCard: View {
    let subscription: Subscription

    private var used: Int64 { (subscription.upload ?? 0) + (subscription.download ?? 0) }
    private var total: Int64? { subscription.total.flatMap { $0 > 0 ? $0 : nil } }
    private var expire: Int64? { subscription.expire.flatMap { $0 > 0 ? $0 : nil } }

    var body: some View {
        if total != nil || expire != nil {
            VStack(alignment: .leading, spacing: 10) {
                header
                if let total = total {
                    quota(total)
                }
            }
            .padding(16)
            .card(radius: 20)
        }
    }

    private var fraction: Double {
        guard let total = total else { return 0 }
        return min(max(Double(used) / Double(total), 0), 1)
    }

    private var expired: Bool {
        guard let expire = expire else { return false }
        return expire <= CoreBridge.nowMillis()
    }

    private var accent: Color {
        let week: Int64 = 7 * 24 * 60 * 60 * 1000
        if expired { return Palette.error }
        if total != nil && fraction >= 0.95 { return Palette.error }
        if total != nil && fraction >= 0.8 { return Palette.warning }
        if let expire = expire, expire - CoreBridge.nowMillis() < week { return Palette.warning }
        return Palette.primary
    }

    private var header: some View {
        HStack {
            Text(verbatim: subscription.name)
                .font(.footnote.weight(.medium))
                .foregroundColor(Palette.onSurfaceVariant)
                .lineLimit(1)
            Spacer(minLength: 8)
            if let expire = expire {
                Text(verbatim: expiryText(expire))
                    .font(.footnote.weight(.medium))
                    .foregroundColor(accent)
                    .lineLimit(1)
            }
        }
    }

    private func expiryText(_ expire: Int64) -> String {
        if expired { return String(localized: "Expired") }
        let relative = Format.relative(millis: expire)
        return String(localized: "Expires \(relative)")
    }

    private func quota(_ total: Int64) -> some View {
        VStack(spacing: 8) {
            ProgressView(value: fraction)
                .tint(accent)
            HStack {
                Text("\(Format.bytes(used)) of \(Format.bytes(total))")
                    .font(.caption.monospaced())
                    .foregroundColor(Palette.onSurface)
                Spacer()
                Text(verbatim: "\(Int(fraction * 100))%")
                    .font(.caption.monospaced())
                    .foregroundColor(accent)
            }
        }
    }
}

/// What the provider said: the expiry warning, its coloured notice, the
/// announcement, and where to get help or manage the account.
struct SubscriptionNoticeCard: View {
    let subscription: Subscription
    @Environment(\.openURL) private var openURL

    private var announce: String? {
        guard let text = subscription.announce?.trimmingCharacters(in: .whitespacesAndNewlines), !text.isEmpty else { return nil }
        return text
    }

    var body: some View {
        VStack(spacing: 8) {
            if let warning = subscription.expiryWarning() {
                expiryBlock(warning)
            }
            if let info = CoreBridge.providerInfo(subscription) {
                infoBlock(info)
            }
            if announce != nil || subscription.supportUrl != nil || subscription.webPageUrl != nil {
                announceBlock
            }
        }
    }

    private func expiryBlock(_ warning: Subscription.ExpiryWarning) -> some View {
        let renew = CoreBridge.expireButtonLink(subscription) ?? subscription.webPageUrl
        let text: String
        let isExpired: Bool
        switch warning {
        case .expired:
            text = String(localized: "Your subscription has expired")
            isExpired = true
        case .soon(let days):
            text = String(localized: "Your subscription expires in \(days) days")
            isExpired = false
        }
        return NoticeBlock(
            text: text,
            fill: isExpired ? Palette.errorContainer : Palette.warning.opacity(0.16),
            foreground: isExpired ? Palette.onErrorContainer : Palette.onSurface,
            buttonTitle: renew == nil ? nil : String(localized: "Renew"),
            action: { open(renew) }
        )
    }

    private func infoBlock(_ info: ProviderInfo) -> some View {
        let fill: Color
        let foreground: Color
        switch info.color {
        case "red":
            fill = Palette.errorContainer
            foreground = Palette.onErrorContainer
        case "green":
            fill = Palette.successContainer
            foreground = Palette.onSuccessContainer
        default:
            fill = Palette.primaryContainer
            foreground = Palette.onPrimaryContainer
        }
        let title: String? = info.buttonLink == nil ? nil : (info.buttonText ?? String(localized: "Open"))
        return NoticeBlock(text: info.text, fill: fill, foreground: foreground, buttonTitle: title, action: { open(info.buttonLink) })
    }

    private var announceBlock: some View {
        VStack(alignment: .leading, spacing: 4) {
            if let announce = announce {
                Text(verbatim: announce)
                    .font(.footnote)
                    .foregroundColor(Palette.onSurface)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: 16) {
                if let support = subscription.supportUrl {
                    Button("Support") { open(support) }
                }
                if let web = subscription.webPageUrl {
                    Button("Account page") { open(web) }
                }
            }
            .font(.footnote.weight(.semibold))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(Palette.surfaceLow, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }

    private func open(_ link: String?) {
        guard let link = link, let url = URL(string: link) else { return }
        openURL(url)
    }
}

/// One tinted block: the provider's text and, when it gave a link, a button.
private struct NoticeBlock: View {
    let text: String
    let fill: Color
    let foreground: Color
    let buttonTitle: String?
    let action: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            Text(verbatim: text)
                .font(.footnote)
                .foregroundColor(foreground)
                .frame(maxWidth: .infinity, alignment: .leading)
                .fixedSize(horizontal: false, vertical: true)
            if let title = buttonTitle {
                Button(action: action) {
                    Text(verbatim: title)
                        .font(.footnote.weight(.semibold))
                        .lineLimit(1)
                }
                .foregroundColor(foreground)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(fill, in: RoundedRectangle(cornerRadius: 18, style: .continuous))
    }
}

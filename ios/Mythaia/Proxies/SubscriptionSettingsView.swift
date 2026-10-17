import SwiftUI
import UIKit
import MythaiaKit

/// One subscription's settings: its name and URL, how it updates, the
/// fronting a blocked panel needs, and what the panel reported.
@MainActor
struct SubscriptionSettingsView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL

    let subscription: Subscription
    @State private var draft: SubscriptionDraft
    @State private var copied = false

    private static let intervals = [1, 3, 6, 12, 24, 48, 168]

    init(subscription: Subscription) {
        self.subscription = subscription
        _draft = State(initialValue: SubscriptionDraft(subscription))
    }

    var body: some View {
        NavigationStack {
            Form {
                generalSection
                updatesSection
                frontingSection
                usageSection
                providerSection
                statusSection
            }
            .scrollContentBackground(.hidden)
            .background(Palette.background.ignoresSafeArea())
            .navigationTitle(Text("Subscription settings"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        model.updateSubscriptionSettings(subscription, draft: draft)
                        dismiss()
                    }
                }
            }
        }
    }

    // MARK: Sections

    private var generalSection: some View {
        Section {
            TextField(text: $draft.name) { Text("Name") }
            TextField(text: $draft.url, axis: .vertical) { Text(verbatim: "URL") }
                .lineLimit(1...4)
                .font(.footnote.monospaced())
                .keyboardType(.URL)
                .autocorrectionDisabled(true)
                .textInputAutocapitalization(.never)
        } header: {
            Text("Subscription")
        }
    }

    private var updatesSection: some View {
        Section {
            Toggle("Auto-update", isOn: $draft.autoUpdate)
            if draft.autoUpdate {
                Picker(selection: intervalBinding) {
                    ForEach(SubscriptionSettingsView.intervals, id: \.self) { hours in
                        Text(verbatim: intervalTitle(hours)).tag(hours)
                    }
                } label: {
                    Text("Update interval")
                }
            }
            Toggle("Update when the app opens", isOn: $draft.updateOnOpen)
        } footer: {
            Text("Updates run while the app is open: each time it opens, or once the interval has passed.")
        }
    }

    private var frontingSection: some View {
        Section {
            TextField(text: $draft.frontSni, prompt: Text(verbatim: URL(string: draft.url)?.host ?? "")) {
                Text(verbatim: "SNI")
            }
            .font(.body.monospaced())
            .autocorrectionDisabled(true)
            .textInputAutocapitalization(.never)
            TextField(text: $draft.frontTargets, prompt: Text(verbatim: "cdn.example.net\n203.0.113.10:443"), axis: .vertical) {
                Text("Targets (one per line)")
            }
            .lineLimit(2...6)
            .font(.body.monospaced())
            .autocorrectionDisabled(true)
            .textInputAutocapitalization(.never)
            if hasFronting {
                Button {
                    copyFrontedLink()
                } label: {
                    Label(copied ? String(localized: "Link copied") : String(localized: "Copy link with fronting"),
                          systemImage: copied ? "checkmark" : "doc.on.doc")
                }
            }
        } header: {
            Text("Fronting")
        } footer: {
            Text("The subscription is downloaded by connecting to these hosts instead of the link's own, with the SNI below in the TLS handshake. For panels whose domain is blocked but whose CDN is not.")
        }
    }

    @ViewBuilder
    private var usageSection: some View {
        if hasUsage {
            Section {
                if let upload = subscription.upload {
                    valueRow(String(localized: "Upload"), Format.bytes(upload))
                }
                if let download = subscription.download {
                    valueRow(String(localized: "Download"), Format.bytes(download))
                }
                if let total = subscription.total, total > 0 {
                    valueRow(String(localized: "Total"), Format.bytes(total))
                }
                if let expire = subscription.expire, expire > 0 {
                    valueRow(String(localized: "Expires"), Format.date(millis: expire))
                }
            } header: {
                Text("Usage")
            }
        }
    }

    @ViewBuilder
    private var providerSection: some View {
        let announce = subscription.announce?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if !announce.isEmpty || subscription.supportUrl != nil || subscription.webPageUrl != nil {
            Section {
                if !announce.isEmpty {
                    Text(verbatim: announce)
                        .font(.subheadline)
                        .foregroundColor(Palette.onSurface)
                }
                if let support = subscription.supportUrl {
                    linkRow(String(localized: "Support"), systemImage: "questionmark.bubble", link: support)
                }
                if let web = subscription.webPageUrl {
                    linkRow(String(localized: "Account page"), systemImage: "person.crop.circle", link: web)
                }
            } header: {
                Text("From the provider")
            }
        }
    }

    @ViewBuilder
    private var statusSection: some View {
        if subscription.lastUpdate != nil || subscription.isFailing {
            Section {
                if let last = subscription.lastUpdate {
                    valueRow(String(localized: "Last updated"), Format.date(millis: last))
                }
                if subscription.isFailing {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("The last update failed")
                            .font(.subheadline.weight(.semibold))
                            .foregroundColor(Palette.error)
                        if let message = subscription.lastFailureMessage {
                            Text(verbatim: message)
                                .font(.footnote)
                                .foregroundColor(Palette.onSurfaceVariant)
                        }
                    }
                }
            }
        }
    }

    // MARK: Pieces

    private func valueRow(_ title: String, _ value: String) -> some View {
        HStack {
            Text(verbatim: title)
                .foregroundColor(Palette.onSurface)
            Spacer()
            Text(verbatim: value)
                .font(.subheadline.monospacedDigit())
                .foregroundColor(Palette.onSurfaceVariant)
                .multilineTextAlignment(.trailing)
        }
    }

    private func linkRow(_ title: String, systemImage: String, link: String) -> some View {
        Button {
            if let url = URL(string: link) { openURL(url) }
        } label: {
            Label(title, systemImage: systemImage)
        }
    }

    private var hasUsage: Bool {
        subscription.upload != nil || subscription.download != nil ||
            (subscription.total ?? 0) > 0 || (subscription.expire ?? 0) > 0
    }

    private var hasFronting: Bool {
        !draft.frontSni.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
            !LinkHelpers.splitTargets(draft.frontTargets).isEmpty
    }

    private var intervalBinding: Binding<Int> {
        Binding(
            get: { draft.updateIntervalHours ?? 24 },
            set: { draft.updateIntervalHours = $0 }
        )
    }

    private func intervalTitle(_ hours: Int) -> String {
        switch hours {
        case 24: return String(localized: "Every day")
        case 168: return String(localized: "Every week")
        default: return String(localized: "Every \(hours) hours")
        }
    }

    /// One link with the fronting in it, for another device: opening it
    /// adds the subscription already fronted. It holds the account's token.
    private func copyFrontedLink() {
        let sni = draft.frontSni.trimmingCharacters(in: .whitespacesAndNewlines)
        let link = SubscriptionLink(
            url: draft.url.trimmingCharacters(in: .whitespacesAndNewlines),
            frontSni: sni.isEmpty ? nil : sni,
            frontTargets: LinkHelpers.splitTargets(draft.frontTargets),
            name: nil
        )
        UIPasteboard.general.string = link.toAppLink()
        copied = true
    }
}

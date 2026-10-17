import SwiftUI
import UIKit
import MythaiaKit

/// Adding servers: paste share links or a subscription URL, take them from
/// the clipboard, or scan a QR code. Nothing is added until Add is tapped,
/// so a link that opened the app is always confirmed first.
@MainActor
struct AddSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    @State private var text: String
    @State private var frontingExpanded = false
    @State private var frontSni = ""
    @State private var frontTargets = ""
    /// A group name the link carried, with the URL it belongs to.
    @State private var linkName: String?
    @State private var linkNameUrl = ""
    @State private var serverCount = 0
    @State private var subscriptionCount = 0
    @State private var showingScanner = false
    @State private var errorMessage: String?
    @State private var working = false

    init(initialText: String) {
        _text = State(initialValue: initialText)
    }

    var body: some View {
        NavigationStack {
            Form {
                linkSection
                if hasHttpLink {
                    frontingSection
                }
                if serverCount > 0 || subscriptionCount > 0 {
                    summarySection
                }
            }
            .scrollContentBackground(.hidden)
            .background(Palette.background.ignoresSafeArea())
            .navigationTitle(Text("Add Proxy"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar { toolbarContent }
            .disabled(working)
            .overlay {
                if working {
                    ProgressView()
                        .padding(24)
                        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                }
            }
        }
        .task(id: text) {
            await textChanged()
        }
        .sheet(isPresented: $showingScanner) {
            QRScannerSheet(onFound: { code in
                text = code
            })
        }
        .alert(String(localized: "Import Failed"), isPresented: errorShown) {
            Button(role: .cancel) {} label: { Text("OK") }
        } message: {
            Text(verbatim: errorMessage ?? "")
        }
    }

    // MARK: Sections

    private var linkSection: some View {
        Section {
            TextEditor(text: $text)
                .font(.footnote.monospaced())
                .frame(minHeight: 110)
                .autocorrectionDisabled(true)
                .textInputAutocapitalization(.never)
            let binding = $text
            HStack(spacing: 12) {
                PasteButton(payloadType: String.self) { strings in
                    let pasted = strings.joined(separator: "\n")
                    DispatchQueue.main.async {
                        binding.wrappedValue = pasted
                    }
                }
                .labelStyle(.titleAndIcon)
                .buttonBorderShape(.capsule)
                Spacer()
                Button {
                    showingScanner = true
                } label: {
                    Label("Scan QR code", systemImage: "qrcode.viewfinder")
                }
                .buttonStyle(.bordered)
                .buttonBorderShape(.capsule)
            }
            .listRowBackground(Color.clear)
            .listRowInsets(EdgeInsets(top: 8, leading: 0, bottom: 8, trailing: 0))
        } header: {
            Text("Link")
        } footer: {
            Text("Share links (vless://, vmess://, trojan://, ss:// and more), subscription URLs, Clash files and Xray configs.")
        }
    }

    private var frontingSection: some View {
        Section {
            DisclosureGroup(isExpanded: $frontingExpanded) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("The subscription is downloaded by connecting to these hosts instead of the link's own, with the SNI below in the TLS handshake. For panels whose domain is blocked but whose CDN is not.")
                        .font(.footnote)
                        .foregroundColor(Palette.onSurfaceVariant)
                    Text("Fronting can also come in the link itself: add #front=1.2.3.4&sni=example.org to the URL, or open a mythaia://import link.")
                        .font(.footnote)
                        .foregroundColor(Palette.onSurfaceVariant)
                }
                TextField(text: $frontSni, prompt: Text(verbatim: "www.example.org")) {
                    Text(verbatim: "SNI")
                }
                .font(.body.monospaced())
                .autocorrectionDisabled(true)
                .textInputAutocapitalization(.never)
                TextField(text: $frontTargets, prompt: Text("Targets (one per line)"), axis: .vertical) {
                    Text("Targets (one per line)")
                }
                .lineLimit(2...5)
                .font(.body.monospaced())
                .autocorrectionDisabled(true)
                .textInputAutocapitalization(.never)
            } label: {
                Text("Fronting")
            }
        }
    }

    private var summarySection: some View {
        Section {
            if serverCount > 0 {
                Label {
                    Text("Servers to add: \(serverCount)")
                } icon: {
                    Image(systemName: "server.rack")
                }
            }
            if subscriptionCount > 0 {
                Label {
                    Text("Subscriptions to download: \(subscriptionCount)")
                } icon: {
                    Image(systemName: "arrow.down.circle")
                }
            }
        }
    }

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItem(placement: .cancellationAction) {
            Button("Cancel") { dismiss() }
        }
        ToolbarItem(placement: .confirmationAction) {
            Button("Add") { performImport() }
                .disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || working)
        }
    }

    private var errorShown: Binding<Bool> {
        Binding(
            get: { errorMessage != nil },
            set: { if !$0 { errorMessage = nil } }
        )
    }

    private var hasHttpLink: Bool {
        !ImportText.split(text).subscriptionLinks.isEmpty
    }

    // MARK: Behaviour

    /// Unpacks a link with fronting written in, so the URL shows as the
    /// panel gave it and the fronting can be checked before the download;
    /// then counts what Add would add.
    private func textChanged() async {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty, trimmed.rangeOfCharacter(from: .whitespacesAndNewlines) == nil,
           let link = SubscriptionLink.parse(trimmed), link.isFronted {
            frontSni = link.frontSni ?? ""
            frontTargets = link.frontTargets.joined(separator: "\n")
            linkName = link.name
            linkNameUrl = link.url
            frontingExpanded = true
            text = link.url
            return
        }
        // Counting parses the text; wait for typing to settle.
        try? await Task.sleep(nanoseconds: 350_000_000)
        if Task.isCancelled { return }
        let parts = ImportText.split(text)
        subscriptionCount = parts.subscriptionLinks.count
        let serverText = parts.serverText
        if serverText.isEmpty {
            serverCount = 0
            return
        }
        let count = await Task.detached(priority: .userInitiated) {
            CoreBridge.parseServers(serverText).count
        }.value
        if !Task.isCancelled { serverCount = count }
    }

    private func performImport() {
        let parts = ImportText.split(text)
        if parts.isEmpty {
            errorMessage = String(localized: "Nothing to add was found. Paste a share link or a subscription URL.")
            return
        }
        working = true
        Task {
            let serverText = parts.serverText
            let servers: [ProxyConfiguration]
            if serverText.isEmpty {
                servers = []
            } else {
                servers = await Task.detached(priority: .userInitiated) {
                    ParsedServers(CoreBridge.parseServers(serverText))
                }.value.servers
            }
            if !servers.isEmpty {
                model.addConfigurations(servers)
                model.browsingGroupId = ProxyGroup.defaultId
                // What is added is out of the box, so a retry does not add it twice.
                text = parts.subscriptionLinks.joined(separator: "\n")
            }
            if parts.subscriptionLinks.isEmpty && servers.isEmpty {
                working = false
                errorMessage = String(localized: "No servers were found in this text.")
                return
            }
            let single = parts.subscriptionLinks.count == 1
            for link in parts.subscriptionLinks {
                do {
                    let sni = single ? frontSni.trimmingCharacters(in: .whitespacesAndNewlines) : ""
                    let targets = single ? LinkHelpers.splitTargets(frontTargets) : []
                    let name = (single && linkNameUrl == link) ? linkName : nil
                    try await model.importSubscription(
                        url: link,
                        frontSni: sni.isEmpty ? nil : sni,
                        frontTargets: targets,
                        name: name
                    )
                } catch {
                    working = false
                    errorMessage = AppModel.describe(error)
                    return
                }
            }
            working = false
            dismiss()
        }
    }
}

/// Servers parsed off the main thread, handed back to it.
private final class ParsedServers: @unchecked Sendable {
    let servers: [ProxyConfiguration]

    init(_ servers: [ProxyConfiguration]) {
        self.servers = servers
    }
}

import Foundation
import SwiftUI
import MythaiaKit

/// Advanced settings, as on Android: the certificate check for every
/// server, certificates trusted by fingerprint, and the routing rules.
@MainActor
struct AdvancedSettingsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var confirmInsecure = false

    var body: some View {
        Form {
            securitySection
            routingSection
        }
        .scrollContentBackground(.hidden)
        .background(Palette.background.ignoresSafeArea())
        .navigationTitle(Text("Advanced Settings"))
        .navigationBarTitleDisplayMode(.inline)
        .alert(String(localized: "Allow Insecure"), isPresented: $confirmInsecure) {
            Button(role: .destructive) {
                model.setAllowInsecure(true)
            } label: {
                Text("Allow Anyway")
            }
            Button(role: .cancel) {} label: { Text("Cancel") }
        } message: {
            Text("This will skip TLS certificate validation, making your connections vulnerable to MITM attacks.")
        }
    }

    private var securitySection: some View {
        Section {
            Toggle(isOn: insecureBinding) {
                Label("Allow Insecure", systemImage: "exclamationmark.shield")
            }
            .tint(Palette.error)
            NavigationLink {
                TrustedCertificatesView()
            } label: {
                LabeledContent {
                    Text(verbatim: String(model.advanced.trustedFingerprints.count))
                } label: {
                    Label("Trusted Certificates", systemImage: "checkmark.seal")
                }
            }
        } header: {
            Text("Security")
        } footer: {
            VStack(alignment: .leading, spacing: 4) {
                Text("INSECURE")
                    .font(.footnote.weight(.black))
                    .foregroundColor(Palette.error)
                Text("Applies to every server: no certificate is checked anywhere, except on servers with a pinned certificate (pcs).")
                    .foregroundColor(model.advanced.allowInsecure ? Palette.error : Palette.onSurfaceVariant)
            }
        }
    }

    private var routingSection: some View {
        Section {
            NavigationLink {
                RoutingRulesView()
            } label: {
                LabeledContent {
                    Text(verbatim: String(model.advanced.routeRules.count))
                } label: {
                    Label("Routing Rules", systemImage: "arrow.triangle.branch")
                }
            }
        } header: {
            Text("Routing")
        } footer: {
            Text("Rules apply in rule mode, the first match deciding. Global mode sends everything through the server.")
        }
    }

    /// Turning the check off asks first; turning it back on does not.
    private var insecureBinding: Binding<Bool> {
        Binding(
            get: { model.advanced.allowInsecure },
            set: { on in
                if on {
                    confirmInsecure = true
                } else {
                    model.setAllowInsecure(false)
                }
            }
        )
    }
}

/// Certificates accepted by their SHA-256 fingerprint when no certificate
/// authority vouches for them.
@MainActor
struct TrustedCertificatesView: View {
    @EnvironmentObject private var model: AppModel
    @State private var adding = false
    @State private var newFingerprint = ""
    @State private var problem: String?

    var body: some View {
        content
            .background(Palette.background.ignoresSafeArea())
            .navigationTitle(Text("Trusted Certificates"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        newFingerprint = ""
                        adding = true
                    } label: {
                        Image(systemName: "plus")
                    }
                    .accessibilityLabel(Text("Add Certificate"))
                }
            }
            .alert(String(localized: "Add Certificate"), isPresented: $adding) {
                TextField(text: $newFingerprint) { Text("SHA-256 Fingerprint") }
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled(true)
                Button {
                    add()
                } label: {
                    Text("Add")
                }
                Button(role: .cancel) {} label: { Text("Cancel") }
            } message: {
                Text("Enter the SHA-256 fingerprint (64 hex characters) of the certificate to trust.")
            }
            .alert(String(localized: "Invalid Fingerprint"), isPresented: problemShown) {
                Button(role: .cancel) {} label: { Text("OK") }
            } message: {
                Text(verbatim: problem ?? "")
            }
    }

    @ViewBuilder
    private var content: some View {
        if model.advanced.trustedFingerprints.isEmpty {
            VStack(spacing: 8) {
                Image(systemName: "checkmark.seal")
                    .font(.largeTitle)
                    .foregroundColor(Palette.primary)
                Text("No trusted certificates")
                    .font(.headline)
                    .foregroundColor(Palette.onSurface)
            }
            .padding(32)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            List {
                ForEach(model.advanced.trustedFingerprints, id: \.self) { fingerprint in
                    Text(verbatim: FingerprintText.grouped(fingerprint))
                        .font(.caption.monospaced())
                        .foregroundColor(Palette.onSurface)
                        .textSelection(.enabled)
                }
                .onDelete { offsets in
                    model.removeTrustedFingerprints(at: offsets)
                }
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
        }
    }

    private func add() {
        switch model.trustFingerprint(newFingerprint) {
        case .added:
            break
        case .invalid:
            problem = String(localized: "Invalid fingerprint. Must be a 64-character hex string, or it already exists.")
        case .alreadyTrusted:
            problem = String(localized: "This fingerprint is already trusted.")
        }
    }

    private var problemShown: Binding<Bool> {
        Binding(
            get: { problem != nil },
            set: { if !$0 { problem = nil } }
        )
    }
}

enum FingerprintText {
    /// "ab:cd:…" in pairs, as certificate viewers print it.
    static func grouped(_ hex: String) -> String {
        var pairs: [String] = []
        var current = ""
        for character in hex {
            current.append(character)
            if current.count == 2 {
                pairs.append(current)
                current = ""
            }
        }
        if !current.isEmpty { pairs.append(current) }
        return pairs.joined(separator: ":")
    }
}

/// The user's routing rules: a domain suffix, a keyword or an address
/// range, and where it goes. The first rule that matches decides.
@MainActor
struct RoutingRulesView: View {
    @EnvironmentObject private var model: AppModel
    @State private var editing: RuleDraft?

    var body: some View {
        content
            .background(Palette.background.ignoresSafeArea())
            .navigationTitle(Text("Routing Rules"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItemGroup(placement: .navigationBarTrailing) {
                    if !model.advanced.routeRules.isEmpty {
                        EditButton()
                    }
                    Button {
                        editing = RuleDraft(index: nil, rule: nil)
                    } label: {
                        Image(systemName: "plus")
                    }
                    .accessibilityLabel(Text("Add Rule"))
                }
            }
            .sheet(item: $editing) { draft in
                RuleEditorView(draft: draft)
                    .environmentObject(model)
            }
    }

    @ViewBuilder
    private var content: some View {
        if model.advanced.routeRules.isEmpty {
            VStack(spacing: 8) {
                Image(systemName: "arrow.triangle.branch")
                    .font(.largeTitle)
                    .foregroundColor(Palette.primary)
                Text("No routing rules yet.")
                    .font(.headline)
                    .foregroundColor(Palette.onSurface)
                if model.settings.routingMode == .global {
                    Text("Rules apply in rule mode, the first match deciding. Global mode sends everything through the server.")
                        .font(.subheadline)
                        .foregroundColor(Palette.onSurfaceVariant)
                        .multilineTextAlignment(.center)
                }
            }
            .padding(32)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            List {
                if model.settings.routingMode == .global {
                    Section {
                        Text("Rules apply in rule mode, the first match deciding. Global mode sends everything through the server.")
                            .font(.footnote)
                            .foregroundColor(Palette.warning)
                    }
                }
                Section {
                    ForEach(Array(model.advanced.routeRules.enumerated()), id: \.offset) { index, rule in
                        Button {
                            editing = RuleDraft(index: index, rule: rule)
                        } label: {
                            RuleRow(rule: rule)
                        }
                        .buttonStyle(.plain)
                    }
                    .onDelete { offsets in
                        var rules = model.advanced.routeRules
                        for index in offsets.sorted(by: >) where index < rules.count {
                            rules.remove(at: index)
                        }
                        model.setRouteRules(rules)
                    }
                    .onMove { from, to in
                        var rules = model.advanced.routeRules
                        rules.move(fromOffsets: from, toOffset: to)
                        model.setRouteRules(rules)
                    }
                }
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
        }
    }
}

private struct RuleRow: View {
    let rule: RouteRule

    var body: some View {
        HStack(spacing: 10) {
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: rule.value)
                    .font(.subheadline.monospaced())
                    .foregroundColor(Palette.onSurface)
                    .lineLimit(1)
                Text(verbatim: RuleText.typeName(rule.type))
                    .font(.caption)
                    .foregroundColor(Palette.onSurfaceVariant)
            }
            Spacer(minLength: 8)
            Text(verbatim: RuleText.targetName(rule.action))
                .font(.caption.weight(.semibold))
                .foregroundColor(RuleText.targetColor(rule.action))
                .padding(.horizontal, 8)
                .padding(.vertical, 3)
                .background(RuleText.targetColor(rule.action).opacity(0.12), in: Capsule())
        }
        .contentShape(Rectangle())
    }
}

/// How rule types and targets read on screen.
enum RuleText {
    /// The rule types the editor offers; IPv4 and IPv6 ranges are one choice
    /// and told apart by the address.
    static let editableTypes: [DomainRuleType] = [.domainSuffix, .domainKeyword, .ipCidr]

    static func typeName(_ type: DomainRuleType) -> String {
        switch type {
        case .domainSuffix: return String(localized: "Domain Suffix")
        case .domainKeyword: return String(localized: "Domain Keyword")
        case .ipCidr: return String(localized: "IPv4 CIDR")
        case .ipCidr6: return String(localized: "IPv6 CIDR")
        default: return type == .geoip ? "GeoIP" : String(type.rawValue)
        }
    }

    static func targetName(_ target: RouteTarget) -> String {
        switch target {
        case .proxy: return String(localized: "Through the server")
        case .direct: return String(localized: "Direct")
        case .block: return String(localized: "Block")
        }
    }

    static func targetColor(_ target: RouteTarget) -> Color {
        switch target {
        case .proxy: return Palette.primary
        case .direct: return Palette.onSurfaceVariant
        case .block: return Palette.error
        }
    }

    /// The rule as typed, or nil when the value does not fit the type.
    static func makeRule(type: DomainRuleType, value: String, target: RouteTarget) -> RouteRule? {
        let text = value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !text.isEmpty, !text.contains(" ") else { return nil }
        switch type {
        case .domainSuffix:
            let suffix = text.hasPrefix(".") ? String(text.dropFirst()) : text
            guard !suffix.isEmpty, !suffix.contains("/"), !suffix.contains(":") else { return nil }
            return RouteRule(type: .domainSuffix, value: suffix, action: target)
        case .domainKeyword:
            guard !text.contains("/") else { return nil }
            return RouteRule(type: .domainKeyword, value: text, action: target)
        case .ipCidr, .ipCidr6:
            guard let parsed = parseCidr(text) else { return nil }
            return RouteRule(type: parsed.v6 ? .ipCidr6 : .ipCidr, value: parsed.text, action: target)
        default:
            return nil
        }
    }

    /// "10.0.0.0/8", "2001:db8::/32", or a single address (taken as /32 or /128).
    static func parseCidr(_ text: String) -> (text: String, v6: Bool)? {
        let parts = text.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 1 || parts.count == 2 else { return nil }
        let address = String(parts[0])
        var addr4 = in_addr()
        var addr6 = in6_addr()
        let isV4 = inet_pton(AF_INET, address, &addr4) == 1
        let isV6 = !isV4 && inet_pton(AF_INET6, address, &addr6) == 1
        guard isV4 || isV6 else { return nil }
        let maxPrefix = isV4 ? 32 : 128
        var prefix = maxPrefix
        if parts.count == 2 {
            guard let value = Int(parts[1]), value >= 0, value <= maxPrefix else { return nil }
            prefix = value
        }
        return (address + "/" + String(prefix), isV6)
    }
}

/// A rule being written: a new one, or the one at `index`.
struct RuleDraft: Identifiable {
    let id = UUID()
    var index: Int?
    var rule: RouteRule?
}

@MainActor
private struct RuleEditorView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    let draft: RuleDraft
    @State private var type: DomainRuleType
    @State private var value: String
    @State private var target: RouteTarget

    init(draft: RuleDraft) {
        self.draft = draft
        let existing = draft.rule
        let startType: DomainRuleType = existing?.type == .ipCidr6 ? .ipCidr : (existing?.type ?? .domainSuffix)
        _type = State(initialValue: startType)
        _value = State(initialValue: existing?.value ?? "")
        _target = State(initialValue: existing?.action ?? .direct)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Picker(selection: $type) {
                        ForEach(RuleText.editableTypes, id: \.self) { option in
                            Text(verbatim: option == .ipCidr ? String(localized: "IP CIDR") : RuleText.typeName(option))
                                .tag(option)
                        }
                    } label: {
                        Text("Type")
                    }
                    FieldRow(title: "Value", text: $value, prompt: placeholder, monospaced: true, keyboard: .URL)
                } footer: {
                    if !value.isEmpty && rule == nil {
                        Text("This value does not match the rule type.")
                            .foregroundColor(Palette.error)
                    }
                }
                Section {
                    Picker(selection: $target) {
                        Text(verbatim: RuleText.targetName(.proxy)).tag(RouteTarget.proxy)
                        Text(verbatim: RuleText.targetName(.direct)).tag(RouteTarget.direct)
                        Text(verbatim: RuleText.targetName(.block)).tag(RouteTarget.block)
                    } label: {
                        Text("Route To")
                    }
                    .pickerStyle(.inline)
                    .labelsHidden()
                } header: {
                    Text("Route To")
                }
            }
            .scrollContentBackground(.hidden)
            .background(Palette.background.ignoresSafeArea())
            .navigationTitle(draft.rule == nil ? Text("Add Rule") : Text("Edit"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { save() }
                        .disabled(rule == nil)
                }
            }
        }
    }

    private var placeholder: String {
        switch type {
        case .domainSuffix: return "example.com"
        case .domainKeyword: return "example"
        default: return "10.0.0.0/8"
        }
    }

    private var rule: RouteRule? {
        RuleText.makeRule(type: type, value: value, target: target)
    }

    private func save() {
        guard let rule = rule else { return }
        var rules = model.advanced.routeRules
        if let index = draft.index, index < rules.count {
            rules[index] = rule
        } else {
            rules.append(rule)
        }
        model.setRouteRules(rules)
        dismiss()
    }
}

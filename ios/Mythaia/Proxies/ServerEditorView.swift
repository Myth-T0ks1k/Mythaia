import SwiftUI
import UIKit
import MythaiaKit

/// Adding a server by hand, or changing one: the protocol, the address and
/// the credentials it takes, the transport, and TLS or REALITY, as on the
/// Android editor. Save stays off until the fields make a server.
@MainActor
struct ServerEditorView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    let request: EditorRequest
    @State private var form: ServerForm

    init(request: EditorRequest) {
        self.request = request
        if let config = request.configuration {
            _form = State(initialValue: ServerForm(config))
        } else {
            _form = State(initialValue: ServerForm(protocolKind: .vless))
        }
    }

    var body: some View {
        NavigationStack {
            Form {
                nameSection
                if form.isFullEditor {
                    protocolSection
                } else {
                    limitedSection
                }
                serverSection
                if form.isFullEditor && form.usesStreamTransport {
                    transportSection
                }
                if form.isFullEditor && form.showsTls {
                    tlsSection
                }
                if form.isFullEditor && form.usesReality {
                    realitySection
                }
            }
            .scrollContentBackground(.hidden)
            .background(Palette.background.ignoresSafeArea())
            .navigationTitle(title)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { save() }
                        .disabled(!form.isValid)
                }
            }
        }
    }

    private var title: Text {
        request.mode == .edit ? Text("Edit Configuration") : Text("Add Configuration")
    }

    private func save() {
        let base = request.mode == .new ? nil : request.configuration
        guard let config = form.build(base: base) else { return }
        model.saveFromEditor(config, mode: request.mode)
        dismiss()
    }

    // MARK: Sections

    private var nameSection: some View {
        Section {
            FieldRow(title: "Name", text: $form.name)
        }
    }

    private var limitedSection: some View {
        Section {
            Text("Only the name and address of a \(form.protocolKind.displayName) server can be changed here. Import the link again to change anything else.")
                .font(.footnote)
                .foregroundColor(Palette.onSurfaceVariant)
        }
    }

    private var protocolSection: some View {
        Section {
            Picker(selection: protocolBinding) {
                ForEach(ServerForm.editableProtocols, id: \.self) { kind in
                    Text(verbatim: kind.displayName).tag(kind)
                }
            } label: {
                Text("Protocol")
            }
        }
    }

    private var serverSection: some View {
        Section {
            FieldRow(title: "Address", text: $form.address, prompt: "example.com", monospaced: true, keyboard: .URL)
            FieldRow(title: "Port", text: $form.port, prompt: "443", monospaced: true, keyboard: .numberPad)
            if form.isFullEditor {
                credentialRows
            }
        } header: {
            Text("Server")
        } footer: {
            serverFooter
        }
    }

    @ViewBuilder
    private var serverFooter: some View {
        if !form.port.isEmpty && form.portValue == nil {
            Text("Port must be between 1 and 65535")
                .foregroundColor(Palette.error)
        } else if form.isFullEditor && form.usesUuid && form.uuidValue == nil {
            Text("Not a valid UUID")
                .foregroundColor(Palette.error)
        } else if form.isFullEditor && form.isHysteria {
            Text("Leave both empty for BBR; set both to use Brutal at that rate.")
        }
    }

    @ViewBuilder
    private var credentialRows: some View {
        if form.usesUuid {
            HStack {
                FieldRow(title: "UUID", text: $form.uuid, monospaced: true)
                Button {
                    form.uuid = UUID().uuidString.lowercased()
                } label: {
                    Image(systemName: "arrow.triangle.2.circlepath")
                }
                .buttonStyle(.borderless)
                .accessibilityLabel(Text("Generate"))
            }
        }
        if form.usesUsername {
            FieldRow(title: "Username", text: $form.username)
        }
        if !form.isVless && !form.isVmess {
            FieldRow(title: "Password", text: $form.password, secure: true)
        }
        if form.isShadowsocks {
            Picker(selection: $form.ssMethod) {
                ForEach(ServerForm.shadowsocksMethods, id: \.self) { method in
                    Text(verbatim: method).tag(method)
                }
            } label: {
                Text("Method")
            }
        }
        if form.isVmess {
            Picker(selection: $form.vmessSecurity) {
                ForEach(ServerForm.vmessCiphers, id: \.self) { cipher in
                    Text(verbatim: cipher).tag(cipher)
                }
            } label: {
                Text("Cipher")
            }
        }
        if form.isVless {
            FieldRow(title: "Encryption", text: $form.encryption, prompt: "none", monospaced: true)
        }
        if form.isHysteria {
            hysteriaRows
        }
    }

    @ViewBuilder
    private var hysteriaRows: some View {
        FieldRow(title: "Upload, Mbit/s", text: $form.upMbps, keyboard: .numberPad)
        FieldRow(title: "Download, Mbit/s", text: $form.downMbps, keyboard: .numberPad)
        Picker(selection: $form.obfuscation) {
            Text("None").tag("none")
            Text(verbatim: "Salamander").tag("salamander")
        } label: {
            Text("Obfuscation")
        }
        if form.obfuscation != "none" {
            FieldRow(title: "Obfuscation password", text: $form.obfuscationPassword, secure: true)
        }
    }

    private var transportSection: some View {
        Section {
            Picker(selection: transportBinding) {
                ForEach(ServerForm.transports, id: \.self) { name in
                    Text(verbatim: ServerEditorView.transportName(name)).tag(name)
                }
            } label: {
                Text("Transport")
            }
            transportRows
            if form.showsFlow {
                Picker(selection: $form.flow) {
                    Text("None").tag("")
                    Text(verbatim: "Vision").tag("xtls-rprx-vision")
                    Text(verbatim: "Vision, UDP 443").tag("xtls-rprx-vision-udp443")
                } label: {
                    Text("Flow")
                }
            }
            if form.isVless {
                Toggle(isOn: $form.mux) { Text(verbatim: "Mux") }
                Toggle(isOn: $form.xudp) { Text(verbatim: "XUDP") }
            }
        } header: {
            Text("Transport")
        }
    }

    @ViewBuilder
    private var transportRows: some View {
        switch form.transport {
        case "ws", "httpupgrade":
            FieldRow(title: "Host", text: $form.host, monospaced: true, keyboard: .URL)
            FieldRow(title: "Path", text: $form.path, prompt: "/", monospaced: true, keyboard: .URL)
        case "xhttp":
            FieldRow(title: "Host", text: $form.host, monospaced: true, keyboard: .URL)
            FieldRow(title: "Path", text: $form.path, prompt: "/", monospaced: true, keyboard: .URL)
            Picker(selection: $form.xhttpMode) {
                ForEach(XHttpMode.allCases, id: \.self) { mode in
                    Text(verbatim: mode.displayName).tag(mode)
                }
            } label: {
                Text("Mode")
            }
        case "grpc":
            FieldRow(title: "Service Name", text: $form.grpcServiceName, monospaced: true)
            FieldRow(title: "Authority", text: $form.grpcAuthority, monospaced: true, keyboard: .URL)
            Picker(selection: $form.grpcMultiMode) {
                Text(verbatim: "Gun").tag(false)
                Text(verbatim: "Multi").tag(true)
            } label: {
                Text("Mode")
            }
            FieldRow(title: "User Agent", text: $form.grpcUserAgent)
        default:
            EmptyView()
        }
    }

    private var tlsSection: some View {
        Section {
            if form.tlsOptional {
                Picker(selection: securityBinding) {
                    Text("None").tag("none")
                    Text(verbatim: "TLS").tag("tls")
                    if form.isVless {
                        Text(verbatim: "REALITY").tag("reality")
                    }
                } label: {
                    Text("Security")
                }
            }
            if form.usesTlsFields {
                tlsRows
            }
        } header: {
            Text(verbatim: "TLS")
        } footer: {
            tlsFooter
        }
    }

    @ViewBuilder
    private var tlsRows: some View {
        FieldRow(title: "SNI", text: $form.sni, prompt: form.trimmedAddress, monospaced: true, keyboard: .URL)
        if !form.isNaive {
            FieldRow(title: "ALPN", text: $form.alpn, prompt: "h2,http/1.1", monospaced: true)
            fingerprintPicker
        }
        Toggle(isOn: $form.allowInsecure) {
            Text("Allow Insecure")
        }
        .tint(Palette.error)
        FieldRow(title: "Pinned certificate SHA-256 (pcs)", text: $form.pins, monospaced: true)
        FieldRow(title: "Verify certificate for name (vcn)", text: $form.verifyName, monospaced: true, keyboard: .URL)
        if form.isVless {
            versionPicker(title: "Minimum TLS version", selection: $form.minVersion)
            versionPicker(title: "Maximum TLS version", selection: $form.maxVersion)
        }
    }

    @ViewBuilder
    private var tlsFooter: some View {
        if form.usesTlsFields {
            VStack(alignment: .leading, spacing: 6) {
                if form.allowInsecure {
                    Text("The server certificate is not checked. Anyone on the path (your provider, a public Wi-Fi) can pose as the server and read or change your traffic. Turn this on only for your own server with a self-signed certificate. Safer: enter its fingerprint in “Pinned certificate SHA-256 (pcs)”. A pinned certificate is checked even with this switch on.")
                        .foregroundColor(Palette.error)
                }
                if form.pinsValid {
                    Text("Trusts exactly this certificate, even self-signed. Separate several with commas.")
                } else {
                    Text("Each fingerprint is 64 hex characters")
                        .foregroundColor(Palette.error)
                }
            }
        }
    }

    private var realitySection: some View {
        Section {
            FieldRow(title: "SNI", text: $form.realitySni, monospaced: true, keyboard: .URL)
            FieldRow(title: "Public Key", text: $form.publicKey, monospaced: true)
            FieldRow(title: "Short ID", text: $form.shortId, monospaced: true)
            fingerprintPicker
        } header: {
            Text(verbatim: "REALITY")
        } footer: {
            realityFooter
        }
    }

    @ViewBuilder
    private var realityFooter: some View {
        if !form.publicKey.isEmpty && form.publicKeyData == nil {
            Text("Not a valid public key")
                .foregroundColor(Palette.error)
        } else if !form.shortId.isEmpty && form.shortIdData == nil {
            Text("Hex digits only, up to 16")
                .foregroundColor(Palette.error)
        }
    }

    private var fingerprintPicker: some View {
        Picker(selection: $form.fingerprint) {
            ForEach(TlsFingerprint.pickerFingerprints, id: \.self) { fingerprint in
                Text(verbatim: fingerprint.displayName).tag(fingerprint)
            }
        } label: {
            Text("Fingerprint")
        }
    }

    private func versionPicker(title: LocalizedStringKey, selection: Binding<TlsVersion?>) -> some View {
        Picker(selection: selection) {
            Text("Any").tag(TlsVersion?.none)
            ForEach(TlsVersion.allCases, id: \.self) { version in
                Text(verbatim: version.displayName).tag(TlsVersion?.some(version))
            }
        } label: {
            Text(title)
        }
    }

    // MARK: Bindings

    private var protocolBinding: Binding<OutboundProtocol> {
        Binding(
            get: { form.protocolKind },
            set: { form.changeProtocol(to: $0) }
        )
    }

    private var transportBinding: Binding<String> {
        Binding(
            get: { form.transport },
            set: { value in
                form.transport = value
                if value != "tcp" { form.flow = "" }
            }
        )
    }

    private var securityBinding: Binding<String> {
        Binding(
            get: { form.security },
            set: { value in
                form.security = value
                if value == "none" { form.flow = "" }
            }
        )
    }

    static func transportName(_ raw: String) -> String {
        switch raw {
        case "tcp": return "TCP"
        case "ws": return "WebSocket"
        case "httpupgrade": return "HTTPUpgrade"
        case "xhttp": return "XHTTP"
        case "grpc": return "gRPC"
        default: return raw
        }
    }
}

/// A labelled text field on one row: the label on the leading side, the
/// value on the trailing side.
struct FieldRow: View {
    let title: LocalizedStringKey
    @Binding var text: String
    var prompt: String = ""
    var secure = false
    var monospaced = false
    var keyboard: UIKeyboardType = .default

    var body: some View {
        LabeledContent {
            field
                .multilineTextAlignment(.trailing)
                .font(monospaced ? .body.monospaced() : .body)
                .keyboardType(keyboard)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled(true)
        } label: {
            Text(title)
        }
    }

    @ViewBuilder
    private var field: some View {
        if secure {
            SecureField(text: $text, prompt: Text(verbatim: prompt)) {
                Text(title)
            }
        } else {
            TextField(text: $text, prompt: Text(verbatim: prompt)) {
                Text(title)
            }
        }
    }
}

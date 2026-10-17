import SwiftUI
import UIKit
import MythaiaKit

/// Settings: routing, appearance, how servers are measured, language, logs,
/// about, and a way back to the defaults.
@MainActor
struct SettingsView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.openURL) private var openURL
    @State private var confirmReset = false

    var body: some View {
        NavigationStack {
            Form {
                trafficSection
                routingSection
                appearanceSection
                serversSection
                systemSection
                aboutSection
                resetSection
            }
            .scrollContentBackground(.hidden)
            .background(Palette.background.ignoresSafeArea())
            .navigationTitle(Text("Settings"))
            .confirmationDialog(
                String(localized: "Reset settings?"),
                isPresented: $confirmReset,
                titleVisibility: .visible
            ) {
                Button(role: .destructive) {
                    model.resetSettings()
                } label: {
                    Text("Reset")
                }
                Button(role: .cancel) {} label: { Text("Cancel") }
            } message: {
                Text("Routing, theme and latency test go back to their defaults. Servers and subscriptions stay.")
            }
        }
    }

    // MARK: Sections

    private var trafficSection: some View {
        Section {
            Picker(selection: tunnelModeBinding) {
                Text("All apps").tag(TunnelMode.tun)
                Text("System proxy only").tag(TunnelMode.proxy)
            } label: {
                Label("Traffic", systemImage: "point.3.connected.trianglepath.dotted")
            }
            .pickerStyle(.menu)
        } footer: {
            Text("All apps: every connection of the device goes through the tunnel, Telegram and games included. System proxy only: just the apps that honour the system proxy, such as Safari. A change applies the next time you connect.")
        }
    }

    private var routingSection: some View {
        Section {
            Picker(selection: routingBinding) {
                Text("Rule").tag(RoutingMode.rule)
                Text("Global").tag(RoutingMode.global)
            } label: {
                Label("Mode", systemImage: "arrow.triangle.branch")
            }
            .pickerStyle(.menu)
            if model.settings.routingMode == .rule {
                Picker(selection: bypassBinding) {
                    Text("None").tag("")
                    ForEach(model.countryCodes, id: \.self) { code in
                        Text(verbatim: CountryCatalog.displayName(code)).tag(code)
                    }
                } label: {
                    Label("Country Bypass", systemImage: "globe")
                }
                .pickerStyle(.menu)
            }
        } header: {
            Text("Routing")
        } footer: {
            Text(routingFooter)
        }
    }

    private var routingFooter: LocalizedStringKey {
        if model.settings.routingMode == .global {
            return "Everything goes through the server."
        }
        return "Traffic to your home country goes direct, bypassing the proxy for faster local access. Everything else goes through the server."
    }

    private var appearanceSection: some View {
        Section {
            Picker(selection: themeBinding) {
                Text("System").tag(ThemeMode.system)
                Text("Light").tag(ThemeMode.light)
                Text("Dark").tag(ThemeMode.dark)
            } label: {
                Label("Theme", systemImage: "circle.lefthalf.filled")
            }
            .pickerStyle(.segmented)
        } header: {
            Text("Appearance")
        }
    }

    private var serversSection: some View {
        Section {
            Picker(selection: latencyBinding) {
                ForEach(LatencyKind.allCases, id: \.self) { kind in
                    Text(verbatim: LatencyKindLabel.title(kind)).tag(kind)
                }
            } label: {
                Label("Latency test", systemImage: "speedometer")
            }
            .pickerStyle(.menu)
        } header: {
            Text("Servers")
        } footer: {
            Text("What a server's latency measures by default. Auto always ranks servers by real ping.")
        }
    }

    private var systemSection: some View {
        Section {
            Button {
                if let url = URL(string: UIApplication.openSettingsURLString) {
                    openURL(url)
                }
            } label: {
                Label("App language", systemImage: "character.bubble")
            }
            NavigationLink {
                LogsView()
            } label: {
                Label("Logs", systemImage: "doc.text.magnifyingglass")
            }
            NavigationLink {
                AdvancedSettingsView()
            } label: {
                Label("Advanced Settings", systemImage: "slider.horizontal.3")
            }
        } header: {
            Text("General")
        } footer: {
            Text("The language is chosen in the app's page in the iOS Settings app.")
        }
    }

    private var aboutSection: some View {
        Section {
            NavigationLink {
                AboutView()
            } label: {
                Label("About", systemImage: "info.circle")
            }
            Link(destination: BrandLinks.telegramChat) {
                Label("Join Telegram Group", systemImage: "paperplane")
            }
        }
    }

    private var resetSection: some View {
        Section {
            Button(role: .destructive) {
                confirmReset = true
            } label: {
                Text("Reset settings")
            }
        }
    }

    // MARK: Bindings

    private var tunnelModeBinding: Binding<TunnelMode> {
        Binding(
            get: { model.settings.tunnelMode },
            set: { model.setTunnelMode($0) }
        )
    }

    private var routingBinding: Binding<RoutingMode> {
        Binding(
            get: { model.settings.routingMode },
            set: { model.setRoutingMode($0) }
        )
    }

    private var bypassBinding: Binding<String> {
        Binding(
            get: { model.settings.bypassCountryCode ?? "" },
            set: { model.setBypassCountry($0.isEmpty ? nil : $0) }
        )
    }

    private var themeBinding: Binding<ThemeMode> {
        Binding(
            get: { model.settings.themeMode },
            set: { model.setThemeMode($0) }
        )
    }

    private var latencyBinding: Binding<LatencyKind> {
        Binding(
            get: { model.settings.latencyKind },
            set: { model.setLatencyKind($0) }
        )
    }
}

/// External links shown in the app, kept in one place.
enum BrandLinks {
    static let github = URL(string: "https://github.com/Myth-T0ks1k/Mythaia")!
    static let telegramChannel = URL(string: "https://t.me/mythaia")!
    static let telegramChat = URL(string: "https://t.me/mythaia_chat")!
}

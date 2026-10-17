import SwiftUI
import MythaiaKit

@main
@MainActor
struct MythaiaApp: App {
    @StateObject private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .environmentObject(model.vpn)
        }
    }
}

/// The three tabs, the bar about subscription refreshes above them, and the
/// sheets and alerts any screen can raise.
@MainActor
struct RootView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        TabView(selection: $model.selectedTab) {
            HomeView()
                .tabItem { Label("Home", systemImage: "house") }
                .tag(AppTab.home)
            ProxiesView()
                .tabItem { Label("Proxies", systemImage: "network") }
                .tag(AppTab.proxies)
            SettingsView()
                .tabItem { Label("Settings", systemImage: "gearshape") }
                .tag(AppTab.settings)
        }
        .tint(Palette.primary)
        .overlay(alignment: .bottom) {
            NoticeBar()
                .padding(.horizontal, 12)
                .padding(.bottom, 58)
        }
        .preferredColorScheme(colorScheme)
        .sheet(item: $model.addRequest) { request in
            AddSheet(initialText: request.initialText)
                .environmentObject(model)
        }
        .alert(model.alert?.title ?? "", isPresented: alertShown, presenting: model.alert) { _ in
            Button(role: .cancel) {} label: { Text("OK") }
        } message: { alert in
            Text(verbatim: alert.message)
        }
        .task {
            // The first activation; later ones come through the scene phase.
            model.sceneBecameActive()
        }
        .onOpenURL { url in
            model.handle(url)
        }
        .onChange(of: scenePhase) { phase in
            switch phase {
            case .active:
                model.sceneBecameActive()
            case .background:
                model.sceneWentToBackground()
            default:
                break
            }
        }
    }

    private var colorScheme: ColorScheme? {
        switch model.settings.themeMode {
        case .system: return nil
        case .light: return .light
        case .dark: return .dark
        }
    }

    private var alertShown: Binding<Bool> {
        Binding(
            get: { model.alert != nil },
            set: { if !$0 { model.alert = nil } }
        )
    }
}

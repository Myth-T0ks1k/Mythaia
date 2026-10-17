import SwiftUI
import MythaiaKit

@main
@MainActor
struct MythaiaApp: App {
    @StateObject private var model: AppModel

    init() {
        // Made here rather than on first use: a background refresh starts
        // the app without a window, and needs the model all the same.
        let model = AppModel()
        _model = StateObject(wrappedValue: model)
        BackgroundRefresh.model = model
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(model)
                .environmentObject(model.vpn)
        }
        .backgroundTask(.appRefresh(BackgroundRefresh.identifier)) {
            await BackgroundRefresh.run()
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
        .sheet(item: $model.rootSheet) { sheet in
            switch sheet {
            case .add(let request):
                AddSheet(initialText: request.initialText)
                    .environmentObject(model)
            case .editor(let request):
                ServerEditorView(request: request)
                    .environmentObject(model)
            }
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

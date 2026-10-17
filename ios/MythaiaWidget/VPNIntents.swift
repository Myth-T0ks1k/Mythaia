import AppIntents
import SwiftUI
import WidgetKit

/// Connects or disconnects; the widget's button runs it.
struct ToggleVPNIntent: AppIntent {
    static let title: LocalizedStringResource = "Connect or disconnect"

    init() {}

    func perform() async throws -> some IntentResult {
        try await VPNAccess.toggle()
        WidgetCenter.shared.reloadAllTimelines()
        return .result()
    }
}

/// Turns the VPN on or off; the Control Center control runs it.
@available(iOS 17.0, *)
struct SetVPNIntent: SetValueIntent {
    static let title: LocalizedStringResource = "Turn the VPN on or off"

    @Parameter(title: "Connected")
    var value: Bool

    init() {}

    func perform() async throws -> some IntentResult {
        try await VPNAccess.setConnected(value)
        WidgetCenter.shared.reloadAllTimelines()
        return .result()
    }
}

#if compiler(>=6.0)
/// The Control Center control (iOS 18): a toggle for the VPN.
@available(iOS 18.0, *)
struct VPNControl: ControlWidget {
    static let kind = "MythaiaVPNControl"

    var body: some ControlWidgetConfiguration {
        StaticControlConfiguration(kind: VPNControl.kind, provider: VPNControlValue()) { isOn in
            ControlWidgetToggle("Mythaia Pro", isOn: isOn, action: SetVPNIntent()) { on in
                Label(on ? LocalizedStringKey("Connected") : LocalizedStringKey("Disconnected"),
                      systemImage: on ? "lock.shield.fill" : "lock.shield")
            }
        }
        .displayName("Mythaia Pro")
        .description("Turn the VPN on or off")
    }
}

@available(iOS 18.0, *)
struct VPNControlValue: ControlValueProvider {
    var previewValue: Bool { false }

    func currentValue() async throws -> Bool {
        if let live = await VPNAccess.isConnected() { return live }
        return SharedState.read().connected
    }
}
#endif

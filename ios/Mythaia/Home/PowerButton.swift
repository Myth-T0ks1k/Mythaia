import SwiftUI

/// The connect control, with the WingMark at its heart.
///
/// Idle: a paper circle with a hairline outline and an azure mark.
/// Connected: solid azure with bone feathers. Busy: a spinner in place of
/// the mark. Failed: the outline and the mark turn red for a moment.
struct PowerButton: View {
    let isConnected: Bool
    let isBusy: Bool
    let failed: Bool
    /// What the tunnel is doing, for VoiceOver.
    let statusText: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            ZStack {
                Circle()
                    .fill(isConnected ? Palette.azure : Palette.surface)
                Circle()
                    .strokeBorder(borderColor, lineWidth: failed ? 2 : 1)
                if isBusy {
                    ProgressView()
                        .progressViewStyle(.circular)
                        .tint(markColor)
                        .scaleEffect(1.8)
                } else {
                    WingMarkView(color: markColor)
                        .frame(width: 68, height: 68)
                }
            }
            .frame(width: 140, height: 140)
            .shadow(color: Palette.ink.opacity(isConnected ? 0.25 : 0.06), radius: 18, x: 0, y: 8)
        }
        .buttonStyle(PressScaleStyle())
        .frame(width: 160, height: 160)
        .animation(.easeInOut(duration: 0.6), value: isConnected)
        .animation(.easeInOut(duration: 0.3), value: failed)
        .accessibilityLabel(Text("VPN connection"))
        .accessibilityValue(Text(verbatim: statusText))
    }

    private var markColor: Color {
        if isConnected { return Palette.bone }
        if failed { return Palette.error }
        return Palette.primary
    }

    private var borderColor: Color {
        if isConnected { return Palette.bone.opacity(0.35) }
        if failed { return Palette.error }
        return Palette.outline
    }
}

/// A slight shrink while pressed.
struct PressScaleStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.96 : 1)
            .animation(.easeOut(duration: 0.15), value: configuration.isPressed)
    }
}

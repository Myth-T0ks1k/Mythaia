import AppIntents
import SwiftUI
import UIKit
import WidgetKit

@main
struct MythaiaWidgets: WidgetBundle {
    var body: some Widget {
        StatusWidget()
        #if compiler(>=6.0)
        if #available(iOS 18.0, *) {
            VPNControl()
        }
        #endif
    }
}

struct StatusEntry: TimelineEntry {
    let date: Date
    let connected: Bool
    let server: String?
}

struct StatusProvider: TimelineProvider {
    func placeholder(in context: Context) -> StatusEntry {
        StatusEntry(date: Date(), connected: false, server: nil)
    }

    func getSnapshot(in context: Context, completion: @escaping (StatusEntry) -> Void) {
        completion(StatusProvider.saved())
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<StatusEntry>) -> Void) {
        Task {
            var entry = StatusProvider.saved()
            if let live = await VPNAccess.isConnected() {
                entry = StatusEntry(date: Date(), connected: live, server: entry.server)
            }
            // The app reloads the widget on every change; this is the backstop
            // for a tunnel that went down while the app was closed.
            let next = Date().addingTimeInterval(15 * 60)
            completion(Timeline(entries: [entry], policy: .after(next)))
        }
    }

    static func saved() -> StatusEntry {
        let state = SharedState.read()
        return StatusEntry(date: Date(), connected: state.connected, server: state.server)
    }
}

struct StatusWidget: Widget {
    let kind = "MythaiaStatus"

    var body: some WidgetConfiguration {
        StaticConfiguration(kind: kind, provider: StatusProvider()) { entry in
            StatusWidgetView(entry: entry)
        }
        .configurationDisplayName(Text(verbatim: "Mythaia Pro"))
        .description(Text("Connection status, and one tap to connect or disconnect."))
        .supportedFamilies([.systemSmall])
    }
}

struct StatusWidgetView: View {
    let entry: StatusEntry

    var body: some View {
        if #available(iOS 17.0, *) {
            content
                .containerBackground(for: .widget) {
                    WidgetBackground(connected: entry.connected)
                }
                .widgetURL(URL(string: "mythaia://open"))
        } else {
            content
                .padding()
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(WidgetBackground(connected: entry.connected))
                // No buttons in widgets before iOS 17: a tap opens the app and toggles.
                .widgetURL(URL(string: "mythaia://toggle"))
        }
    }

    private var content: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                WidgetWingMark(color: entry.connected ? WidgetColors.bone : WidgetColors.primary)
                    .frame(width: 26, height: 26)
                Spacer()
                Circle()
                    .fill(entry.connected ? WidgetColors.lightAzure : WidgetColors.idleDot)
                    .frame(width: 8, height: 8)
            }
            Spacer(minLength: 4)
            statusText
            if let server = entry.server, !server.isEmpty {
                Text(verbatim: server)
                    .font(.caption)
                    .foregroundColor(entry.connected ? Color.white.opacity(0.8) : WidgetColors.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 4)
            actionButton
        }
    }

    @ViewBuilder
    private var statusText: some View {
        if entry.connected {
            Text("Connected")
                .font(.headline)
                .foregroundColor(.white)
        } else {
            Text("Disconnected")
                .font(.headline)
                .foregroundColor(WidgetColors.ink)
        }
    }

    @ViewBuilder
    private var actionButton: some View {
        if #available(iOS 17.0, *) {
            Button(intent: ToggleVPNIntent()) {
                buttonLabel
                    .font(.caption.weight(.semibold))
                    .frame(maxWidth: .infinity)
            }
            .tint(entry.connected ? WidgetColors.bone : WidgetColors.primary)
        } else {
            Text("Tap to connect")
                .font(.caption.weight(.semibold))
                .foregroundColor(entry.connected ? WidgetColors.bone : WidgetColors.primary)
        }
    }

    @ViewBuilder
    private var buttonLabel: some View {
        if entry.connected {
            Text("Disconnect")
        } else {
            Text("Connect")
        }
    }
}

private struct WidgetBackground: View {
    let connected: Bool

    var body: some View {
        if connected {
            LinearGradient(colors: [WidgetColors.azure, WidgetColors.inkDeep], startPoint: .topLeading, endPoint: .bottomTrailing)
        } else {
            LinearGradient(colors: [WidgetColors.idleStart, WidgetColors.idleEnd], startPoint: .topLeading, endPoint: .bottomTrailing)
        }
    }
}

/// The few Wing colours the widget draws with, light and dark.
enum WidgetColors {
    static let azure = Color(red: 0x24 / 255, green: 0x54 / 255, blue: 0x8F / 255)
    static let lightAzure = Color(red: 0x8F / 255, green: 0xB0 / 255, blue: 0xDE / 255)
    static let inkDeep = Color(red: 0x16 / 255, green: 0x29 / 255, blue: 0x4D / 255)
    static let bone = Color(red: 0xF6 / 255, green: 0xF3 / 255, blue: 0xEC / 255)
    static let primary = dynamic(light: (0x24, 0x54, 0x8F), dark: (0x8F, 0xB0, 0xDE))
    static let ink = dynamic(light: (0x14, 0x21, 0x3A), dark: (0xF2, 0xEF, 0xE7))
    static let secondary = dynamic(light: (0x4E, 0x55, 0x68), dark: (0xA9, 0xB1, 0xC4))
    static let idleDot = dynamic(light: (0xB8, 0xB3, 0xA6), dark: (0x4E, 0x55, 0x68))
    static let idleStart = dynamic(light: (0xF1, 0xED, 0xE3), dark: (0x14, 0x1F, 0x37))
    static let idleEnd = dynamic(light: (0xE5, 0xE0, 0xD2), dark: (0x0C, 0x13, 0x22))

    private static func dynamic(light: (Int, Int, Int), dark: (Int, Int, Int)) -> Color {
        let lightColor = UIColor(red: CGFloat(light.0) / 255, green: CGFloat(light.1) / 255, blue: CGFloat(light.2) / 255, alpha: 1)
        let darkColor = UIColor(red: CGFloat(dark.0) / 255, green: CGFloat(dark.1) / 255, blue: CGFloat(dark.2) / 255, alpha: 1)
        return Color(uiColor: UIColor { traits in
            traits.userInterfaceStyle == .dark ? darkColor : lightColor
        })
    }
}

/// The WingMark, as the app draws it: three feather strokes from one origin.
struct WidgetWingMark: View {
    var color: Color

    private static let feathers: [(control: CGPoint, end: CGPoint, width: CGFloat)] = [
        (CGPoint(x: 21, y: 32), CGPoint(x: 82, y: 20), 8.5),
        (CGPoint(x: 29, y: 47), CGPoint(x: 69, y: 38), 8.0),
        (CGPoint(x: 36, y: 61), CGPoint(x: 57, y: 55), 7.5),
    ]

    var body: some View {
        GeometryReader { geometry in
            let s = min(geometry.size.width, geometry.size.height) / 100
            ZStack {
                ForEach(0..<WidgetWingMark.feathers.count, id: \.self) { index in
                    feather(index, scale: s)
                }
            }
        }
    }

    private func feather(_ index: Int, scale s: CGFloat) -> some View {
        let item = WidgetWingMark.feathers[index]
        var path = Path()
        path.move(to: CGPoint(x: 20 * s, y: 82 * s))
        path.addQuadCurve(to: CGPoint(x: item.end.x * s, y: item.end.y * s),
                          control: CGPoint(x: item.control.x * s, y: item.control.y * s))
        return path.stroke(color, style: StrokeStyle(lineWidth: item.width * s, lineCap: .round))
    }
}

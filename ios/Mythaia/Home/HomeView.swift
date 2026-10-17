import SwiftUI
import MythaiaKit

/// The home screen: the tunnel switch, the live readout, and the group the
/// tunnel draws from, all on one gradient with the WingMark faint behind it.
@MainActor
struct HomeView: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var vpn: VPNController
    @State private var showingPicker = false

    private var isConnected: Bool { vpn.status == .connected }
    private var failed: Bool { vpn.lastConnectFailed && !isConnected }

    var body: some View {
        ZStack(alignment: .topTrailing) {
            HomeBackground(isConnected: isConnected)
            watermark
            EdgeStickers(visible: isConnected || failed, failed: failed)
            content
        }
        .sheet(isPresented: $showingPicker) {
            GroupPickerSheet()
                .environmentObject(model)
        }
        .task(id: vpn.lastConnectFailed) {
            // The failure shows for a few seconds, then the edges go quiet.
            guard vpn.lastConnectFailed else { return }
            try? await Task.sleep(nanoseconds: 5_000_000_000)
            if !Task.isCancelled { vpn.lastConnectFailed = false }
        }
    }

    private var watermark: some View {
        WingMarkView(color: isConnected ? Palette.lightAzure : Palette.primary)
            .frame(width: 260, height: 260)
            .opacity(isConnected ? 0.10 : 0.06)
            .offset(x: 40, y: -10)
            .allowsHitTesting(false)
            .animation(.easeInOut(duration: 0.6), value: isConnected)
    }

    private var content: some View {
        GeometryReader { geometry in
            ScrollView(showsIndicators: false) {
                VStack(spacing: 0) {
                    HomeHeader(isConnected: isConnected)
                    ModePill(
                        global: model.settings.routingMode == .global,
                        onDarkGround: isConnected,
                        select: { global in model.setRoutingMode(global ? .global : .rule) }
                    )
                    Spacer(minLength: 28)
                    PowerButton(
                        isConnected: isConnected,
                        isBusy: vpn.status.isTransitioning || model.autoSelecting,
                        failed: failed,
                        statusText: statusText,
                        action: { powerTapped() }
                    )
                    Text(verbatim: statusText)
                        .font(.headline)
                        .foregroundColor(statusColor)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                        .padding(.top, 14)
                    if isConnected {
                        ConnectedDetails()
                            .padding(.horizontal, 20)
                            .padding(.top, 18)
                            .transition(.move(edge: .bottom).combined(with: .opacity))
                    }
                    Spacer(minLength: 28)
                    SelectorCard(openPicker: { showingPicker = true })
                        .padding(.horizontal, 20)
                        .padding(.bottom, 20)
                }
                .frame(minHeight: geometry.size.height)
                .animation(.easeInOut(duration: 0.4), value: isConnected)
            }
        }
    }

    private var hasNothing: Bool {
        model.configurations.isEmpty && model.chains.isEmpty
    }

    private func powerTapped() {
        if hasNothing {
            model.openAddSheet()
        } else {
            model.toggleConnection()
        }
    }

    private var statusText: String {
        if model.autoSelecting && !isConnected { return String(localized: "Measuring…") }
        switch vpn.status {
        case .disconnected: return String(localized: "Disconnected")
        case .connecting: return String(localized: "Connecting…")
        case .connected: return String(localized: "Connected")
        case .disconnecting: return String(localized: "Disconnecting…")
        case .reasserting: return String(localized: "Reconnecting…")
        }
    }

    private var statusColor: Color {
        if failed { return Palette.error }
        return isConnected ? Palette.lightAzure : Palette.onSurfaceVariant
    }
}

/// The ground: quiet neutrals, crossfading to azure and ink while connected.
private struct HomeBackground: View {
    let isConnected: Bool

    var body: some View {
        ZStack {
            LinearGradient(colors: [Palette.idleStart, Palette.idleEnd], startPoint: .topLeading, endPoint: .bottomTrailing)
            LinearGradient(colors: [Palette.connectedStart, Palette.connectedEnd], startPoint: .topLeading, endPoint: .bottomTrailing)
                .opacity(isConnected ? 1 : 0)
        }
        .ignoresSafeArea()
        .animation(.easeInOut(duration: 0.6), value: isConnected)
    }
}

private struct HomeHeader: View {
    let isConnected: Bool

    var body: some View {
        HStack(spacing: 10) {
            WingMarkView(color: isConnected ? Palette.lightAzure : Palette.primary)
                .frame(width: 24, height: 24)
            Text(verbatim: "Mythaia Pro")
                .font(.title2.weight(.semibold))
                .foregroundColor(isConnected ? Color.white.opacity(0.92) : Palette.onSurface)
            Spacer()
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 16)
    }
}

/// Rule / Global as one small pill, so the switch reads as a mode.
struct ModePill: View {
    let global: Bool
    let onDarkGround: Bool
    let select: (Bool) -> Void

    var body: some View {
        HStack(spacing: 0) {
            segment(title: String(localized: "Rule"), selected: !global) { select(false) }
            segment(title: String(localized: "Global"), selected: global) { select(true) }
        }
        .padding(3)
        .background(container, in: Capsule())
        .overlay(Capsule().strokeBorder(border, lineWidth: 1))
    }

    private var container: Color { onDarkGround ? Color.white.opacity(0.12) : Palette.surface }
    private var border: Color { onDarkGround ? Color.white.opacity(0.25) : Palette.outline }
    private var active: Color { onDarkGround ? Color.white.opacity(0.22) : Palette.primaryContainer }
    private var activeText: Color { onDarkGround ? Color.white : Palette.onPrimaryContainer }
    private var idleText: Color { onDarkGround ? Color.white.opacity(0.75) : Palette.onSurfaceVariant }

    private func segment(title: String, selected: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(verbatim: title)
                .font(.subheadline.weight(.medium))
                .lineLimit(1)
                .foregroundColor(selected ? activeText : idleText)
                .padding(.horizontal, 16)
                .padding(.vertical, 7)
                .background(selected ? active : Color.clear, in: Capsule())
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

/// The readout shown while connected: speeds, uptime, and what the active
/// subscription has left.
@MainActor
private struct ConnectedDetails: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var vpn: VPNController

    var body: some View {
        VStack(spacing: 12) {
            SessionStatsView(
                downloadSpeed: vpn.downloadSpeed,
                uploadSpeed: vpn.uploadSpeed,
                downloadTotal: vpn.downloadBytes,
                uploadTotal: vpn.uploadBytes,
                connectedDate: vpn.connectedDate
            )
            if let subscription = activeSubscription {
                SubscriptionUsageCard(subscription: subscription)
                SubscriptionNoticeCard(subscription: subscription)
            }
        }
    }

    private var activeSubscription: Subscription? {
        guard model.selection.selectedChainId == nil,
              let subscriptionId = model.selectedConfiguration?.subscriptionId else { return nil }
        return model.subscriptions.first { $0.id == subscriptionId }
    }
}

/// What the tunnel draws from: the group, and Auto or the pin. With nothing
/// added yet it is the way to add something.
@MainActor
private struct SelectorCard: View {
    @EnvironmentObject private var model: AppModel
    @EnvironmentObject private var vpn: VPNController
    let openPicker: () -> Void

    var body: some View {
        if model.configurations.isEmpty && model.chains.isEmpty {
            Button(action: { model.openAddSheet() }) {
                HStack(spacing: 12) {
                    Image(systemName: "plus")
                        .font(.title3)
                        .foregroundColor(Palette.primary)
                    Text("Add a Configuration")
                        .font(.body.weight(.medium))
                        .foregroundColor(Palette.onSurface)
                    Spacer()
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 14)
                .card(radius: 18)
            }
            .buttonStyle(.plain)
        } else {
            Button(action: openPicker) {
                selectorRow
                    .padding(.horizontal, 16)
                    .padding(.vertical, 14)
                    .card(radius: 18)
            }
            .buttonStyle(.plain)
        }
    }

    private var isChain: Bool { model.selection.selectedChainId != nil }

    private var selectorRow: some View {
        HStack(spacing: 12) {
            Image(systemName: iconName)
                .font(.title3)
                .foregroundColor(vpn.status == .connected ? Palette.primary : Palette.onSurfaceVariant)
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: groupTitle)
                    .font(.caption.weight(.medium))
                    .foregroundColor(Palette.onSurfaceVariant)
                    .lineLimit(1)
                Text(verbatim: selectionTitle)
                    .font(.body.weight(.medium))
                    .foregroundColor(Palette.onSurface)
                    .lineLimit(1)
            }
            Spacer(minLength: 8)
            if model.autoSelecting {
                ProgressView().controlSize(.small)
            } else if let id = model.selectedConfigId, !isChain {
                LatencyBadge(result: model.latency[id])
            }
            Image(systemName: "chevron.down")
                .font(.footnote.weight(.semibold))
                .foregroundColor(Palette.onSurfaceVariant.opacity(0.6))
        }
    }

    private var iconName: String {
        if isChain { return "link" }
        return model.activeIsAuto ? "bolt.fill" : "pin.fill"
    }

    private var groupTitle: String {
        if isChain { return String(localized: "Chains") }
        let id = model.activeGroupId
        if id == ProxyGroup.defaultId { return String(localized: "Default") }
        return model.subscription(forGroup: id)?.name ?? String(localized: "Default")
    }

    private var selectionTitle: String {
        if isChain { return model.selectedChain?.name ?? "" }
        let name = model.selectedConfigId.flatMap { model.configsById[$0]?.name }
        if model.activeIsAuto {
            if let name = name { return String(localized: "Auto · \(name)") }
            return String(localized: "Auto · fastest ping")
        }
        return name ?? ""
    }
}

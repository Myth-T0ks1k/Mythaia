import SwiftUI
import UIKit
import MythaiaKit

/// A question the Proxies screen asks before it deletes anything.
private enum Confirmation: Identifiable {
    case deleteServer(ProxyConfiguration)
    case deleteSubscription(Subscription, servers: Int)
    case removeFailed(groupId: String, count: Int, fromSubscription: Bool)
    case removeDuplicates(groupId: String, count: Int)

    var id: String {
        switch self {
        case .deleteServer(let config): return "server-\(config.id)"
        case .deleteSubscription(let subscription, _): return "subscription-\(subscription.id)"
        case .removeFailed(let groupId, _, _): return "failed-\(groupId)"
        case .removeDuplicates(let groupId, _): return "duplicates-\(groupId)"
        }
    }
}

/// The Proxies screen: the groups (Default and each subscription) as pills,
/// Auto at the top of every group, then its servers. A tap on a group makes
/// it the tunnel's group; a tap on a server pins it.
@MainActor
struct ProxiesView: View {
    @EnvironmentObject private var model: AppModel
    @State private var searchText = ""
    @State private var sortByLatency = false
    @State private var confirmation: Confirmation?
    @State private var configuring: Subscription?
    @State private var share: SharePayload?
    @State private var toast: String?

    var body: some View {
        NavigationStack {
            content
                .background(Palette.background.ignoresSafeArea())
                .navigationTitle(Text("Proxies"))
                .toolbar { toolbarContent }
                .searchable(text: $searchText, prompt: Text("Search servers"))
                .safeAreaInset(edge: .top, spacing: 0) {
                    if !model.configurations.isEmpty || !model.subscriptions.isEmpty {
                        GroupPills()
                    }
                }
                .overlay(alignment: .bottom) { toastView }
        }
        .sheet(item: $configuring) { subscription in
            SubscriptionSettingsView(subscription: subscription)
                .environmentObject(model)
        }
        .sheet(item: $share) { payload in
            ActivityView(items: [payload.text])
        }
        .alert(confirmationTitle, isPresented: confirmationShown, presenting: confirmation) { item in
            Button(role: .destructive) {
                confirm(item)
            } label: {
                Text("Delete")
            }
            Button(role: .cancel) {} label: { Text("Cancel") }
        } message: { item in
            Text(verbatim: confirmationMessage(item))
        }
    }

    // MARK: Data

    private var group: ProxyGroup? {
        model.group(model.browsingGroupId) ?? model.groups.first
    }

    private var subscription: Subscription? {
        guard let id = group?.subscriptionId else { return nil }
        return model.subscriptions.first { $0.id == id }
    }

    private var visible: [ProxyConfiguration] {
        guard let group = group else { return [] }
        let query = searchText.trimmingCharacters(in: .whitespaces)
        var list = group.configs
        if !query.isEmpty {
            list = list.filter {
                $0.name.localizedCaseInsensitiveContains(query) || $0.serverAddress.localizedCaseInsensitiveContains(query)
            }
        }
        if sortByLatency {
            let latency = model.latency
            list.sort { (latency[$0.id]?.milliseconds ?? Int.max) < (latency[$1.id]?.milliseconds ?? Int.max) }
        }
        return list
    }

    // MARK: Content

    @ViewBuilder
    private var content: some View {
        if model.configurations.isEmpty && model.subscriptions.isEmpty {
            EmptyProxiesView()
        } else if let group = group {
            serverList(group)
        }
    }

    private func serverList(_ group: ProxyGroup) -> some View {
        let groupIsActive = model.selection.selectedChainId == nil && model.activeGroupId == group.id
        let pinned = model.selection.groupPins[group.id]
        let auto = model.selection.autoChoices[group.id]
        let rows = visible
        // Captured here: the refresh action runs outside the view's actor.
        let appModel = model
        let current = subscription
        return List {
            if let subscription = subscription {
                subscriptionSection(subscription)
            }
            Section {
                Button {
                    model.useAuto(group.id)
                } label: {
                    AutoRow(
                        busy: model.autoSelecting && groupIsActive,
                        subtitle: autoSubtitle(auto),
                        latency: auto.flatMap { model.latency[$0] },
                        kindLabel: LatencyKindLabel.short(model.latencyKindShown)
                    )
                }
                .buttonStyle(.plain)
                .listRowBackground(rowFill(groupIsActive && pinned == nil))
            }
            Section {
                if group.configs.isEmpty {
                    Text("No servers in this group yet.")
                        .font(.subheadline)
                        .foregroundColor(Palette.onSurfaceVariant)
                } else if rows.isEmpty {
                    Text("No servers match your search")
                        .font(.subheadline)
                        .foregroundColor(Palette.onSurfaceVariant)
                }
                ForEach(rows, id: \.id) { config in
                    serverRow(
                        config,
                        selected: groupIsActive && (pinned == config.id || (pinned == nil && model.selectedConfigId == config.id)),
                        pinned: pinned == config.id,
                        autoPick: pinned == nil && auto == config.id
                    )
                }
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .refreshable {
            if let current = current {
                await appModel.refreshSubscriptionNow(current)
            }
        }
    }

    private func subscriptionSection(_ subscription: Subscription) -> some View {
        Section {
            VStack(spacing: 8) {
                SubscriptionUsageCard(subscription: subscription)
                SubscriptionNoticeCard(subscription: subscription)
                if model.updatingSubscriptionId == subscription.id {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Updating…")
                            .font(.footnote.weight(.medium))
                            .foregroundColor(Palette.onSurfaceVariant)
                        Spacer()
                    }
                    .padding(.horizontal, 4)
                }
            }
            .listRowInsets(EdgeInsets())
            .listRowBackground(Color.clear)
        }
    }

    private func serverRow(_ config: ProxyConfiguration, selected: Bool, pinned: Bool, autoPick: Bool) -> some View {
        Button {
            model.pin(config)
        } label: {
            ServerRow(
                config: config,
                selected: selected,
                pinned: pinned,
                autoPick: autoPick,
                latency: model.latency[config.id]
            )
        }
        .buttonStyle(.plain)
        .listRowBackground(rowFill(selected))
        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
            Button(role: .destructive) {
                confirmation = .deleteServer(config)
            } label: {
                Label("Delete", systemImage: "trash")
            }
            Button {
                shareLink(config)
            } label: {
                Label("Share", systemImage: "square.and.arrow.up")
            }
            .tint(Palette.azure)
        }
        .swipeActions(edge: .leading, allowsFullSwipe: true) {
            Button {
                model.testLatency(config)
            } label: {
                Label("Test Latency", systemImage: "speedometer")
            }
            .tint(Palette.azureDeep)
            Button {
                copyLink(config)
            } label: {
                Label("Copy Link", systemImage: "doc.on.doc")
            }
            .tint(Palette.slate)
        }
        .contextMenu {
            Button {
                model.testLatency(config)
            } label: {
                Label("Test Latency", systemImage: "speedometer")
            }
            Button {
                copyLink(config)
            } label: {
                Label("Copy Link", systemImage: "doc.on.doc")
            }
            Button {
                shareLink(config)
            } label: {
                Label("Share", systemImage: "square.and.arrow.up")
            }
            Button(role: .destructive) {
                confirmation = .deleteServer(config)
            } label: {
                Label("Delete", systemImage: "trash")
            }
        }
    }

    private func rowFill(_ selected: Bool) -> Color {
        selected ? Palette.primaryContainer.opacity(0.55) : Palette.surface
    }

    private func autoSubtitle(_ auto: UUID?) -> String {
        if let id = auto, let name = model.configsById[id]?.name {
            return String(localized: "Auto · \(name)")
        }
        return String(localized: "Connects at once, then measures the group by real ping and moves to a clearly faster server; while connected, rechecks every 10 minutes with the screen on.")
    }

    @ViewBuilder
    private var toastView: some View {
        if let toast = toast {
            Text(verbatim: toast)
                .font(.footnote.weight(.medium))
                .foregroundColor(Palette.inverseOnSurface)
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
                .background(Palette.inverseSurface, in: Capsule())
                .padding(.bottom, 16)
                .transition(.opacity)
                .task(id: toast) {
                    try? await Task.sleep(nanoseconds: 2_500_000_000)
                    if self.toast == toast { self.toast = nil }
                }
        }
    }

    // MARK: Toolbar

    @ToolbarContentBuilder
    private var toolbarContent: some ToolbarContent {
        ToolbarItemGroup(placement: .navigationBarTrailing) {
            if let group = group, !model.configurations.isEmpty || !model.subscriptions.isEmpty {
                groupMenu(group)
            }
            Button {
                model.openAddSheet()
            } label: {
                Image(systemName: "plus")
            }
            .accessibilityLabel(Text("Add"))
        }
    }

    private func groupMenu(_ group: ProxyGroup) -> some View {
        Menu {
            Menu {
                ForEach(LatencyKind.allCases, id: \.self) { kind in
                    Button {
                        model.testLatencies(group.configs, kind: kind)
                    } label: {
                        Label(LatencyKindLabel.title(kind), systemImage: LatencyKindLabel.systemImage(kind))
                    }
                }
            } label: {
                Label("Test Latency", systemImage: "speedometer")
            }
            .disabled(group.configs.isEmpty)
            Button {
                let id = group.id
                Task { await model.autoSelectFastest(id) }
            } label: {
                Label("Auto-select", systemImage: "bolt")
            }
            .disabled(model.autoSelecting || model.autoCandidates(group.id).isEmpty)
            Toggle(isOn: $sortByLatency) {
                Label("Sort by latency", systemImage: "arrow.up.arrow.down")
            }
            Divider()
            Button {
                share = SharePayload(text: model.exportLinks(group.configs))
            } label: {
                Label("Export as links", systemImage: "square.and.arrow.up")
            }
            .disabled(group.configs.isEmpty)
            Button(role: .destructive) {
                let count = model.failedIn(group.id).count
                confirmation = .removeFailed(groupId: group.id, count: count, fromSubscription: group.subscriptionId != nil)
            } label: {
                Label("Remove non-working", systemImage: "xmark.bin")
            }
            .disabled(model.failedIn(group.id).isEmpty)
            Button(role: .destructive) {
                confirmation = .removeDuplicates(groupId: group.id, count: model.duplicatesIn(group.id).count)
            } label: {
                Label("Remove duplicates", systemImage: "square.on.square")
            }
            .disabled(model.duplicatesIn(group.id).isEmpty)
            if let subscription = subscription {
                Divider()
                Button {
                    model.refreshSubscription(subscription)
                } label: {
                    Label("Update", systemImage: "arrow.clockwise")
                }
                .disabled(model.updatingSubscriptionId != nil)
                Button {
                    configuring = subscription
                } label: {
                    Label("Subscription settings", systemImage: "slider.horizontal.3")
                }
                Button(role: .destructive) {
                    let count = model.groupConfigs(group.id).count
                    confirmation = .deleteSubscription(subscription, servers: count)
                } label: {
                    Label("Delete subscription", systemImage: "trash")
                }
            }
        } label: {
            Image(systemName: "ellipsis.circle")
        }
        .accessibilityLabel(Text("More options"))
    }

    // MARK: Actions

    private func copyLink(_ config: ProxyConfiguration) {
        guard let link = CoreBridge.shareLink(config) else {
            toast = String(localized: "This server has no link form.")
            return
        }
        UIPasteboard.general.string = link
        toast = String(localized: "Link copied")
    }

    private func shareLink(_ config: ProxyConfiguration) {
        guard let link = CoreBridge.shareLink(config) else {
            toast = String(localized: "This server has no link form.")
            return
        }
        share = SharePayload(text: link)
    }

    private var confirmationShown: Binding<Bool> {
        Binding(
            get: { confirmation != nil },
            set: { if !$0 { confirmation = nil } }
        )
    }

    private var confirmationTitle: String {
        switch confirmation {
        case .deleteServer?: return String(localized: "Delete server?")
        case .deleteSubscription?: return String(localized: "Delete subscription?")
        case .removeFailed?: return String(localized: "Remove non-working servers?")
        case .removeDuplicates?: return String(localized: "Remove duplicate servers?")
        case nil: return ""
        }
    }

    private func confirmationMessage(_ item: Confirmation) -> String {
        switch item {
        case .deleteServer(let config):
            let name = config.name
            return String(localized: "\(name) will be removed.")
        case .deleteSubscription(let subscription, let servers):
            let name = subscription.name
            return String(localized: "\(name) and all of its servers (\(servers)) will be removed.")
        case .removeFailed(_, let count, let fromSubscription):
            let text = String(localized: "\(count) servers did not work on their last check. Remove them from this group?")
            if fromSubscription {
                return text + "\n\n" + String(localized: "The next update of the subscription brings them back.")
            }
            return text
        case .removeDuplicates(_, let count):
            return String(localized: "\(count) servers repeat another server in this group. Remove the repeats?")
        }
    }

    private func confirm(_ item: Confirmation) {
        switch item {
        case .deleteServer(let config):
            model.deleteConfigurations([config])
        case .deleteSubscription(let subscription, _):
            model.deleteSubscription(subscription)
        case .removeFailed(let groupId, _, _):
            let removed = model.removeFailed(groupId)
            toast = String(localized: "Removed \(removed) servers")
        case .removeDuplicates(let groupId, _):
            let removed = model.removeDuplicates(groupId)
            toast = String(localized: "Removed \(removed) servers")
        }
        confirmation = nil
    }
}

/// Default and each subscription as pills, with their server counts; a
/// check marks the group the tunnel draws from.
@MainActor
private struct GroupPills: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(model.groups) { group in
                    GroupChip(
                        title: group.isDefault ? String(localized: "Default") : group.name,
                        count: group.configs.count,
                        selected: model.browsingGroupId == group.id,
                        active: model.selection.selectedChainId == nil && model.activeGroupId == group.id
                    ) {
                        open(group.id)
                    }
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 8)
        }
        .background(Palette.background)
    }

    /// Browsing a group is choosing it.
    private func open(_ id: String) {
        model.browsingGroupId = id
        if model.selection.selectedChainId != nil || model.activeGroupId != id {
            model.selectGroup(id)
        }
    }
}

private struct EmptyProxiesView: View {
    var body: some View {
        VStack(spacing: 8) {
            WingMarkView(color: Palette.primary)
                .frame(width: 64, height: 64)
                .padding(.bottom, 12)
            Text("No Proxies")
                .font(.title2.weight(.semibold))
                .foregroundColor(Palette.onSurface)
            Text("Tap + to add a server or a subscription.")
                .font(.subheadline)
                .foregroundColor(Palette.onSurfaceVariant)
                .multilineTextAlignment(.center)
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

/// The Auto row: the best ping decides, and keeps deciding.
private struct AutoRow: View {
    let busy: Bool
    let subtitle: String
    let latency: LatencyResult?
    let kindLabel: String

    var body: some View {
        HStack(spacing: 12) {
            WingIconTile(size: 38) {
                if busy {
                    ProgressView()
                        .controlSize(.small)
                        .tint(.white)
                } else {
                    Image(systemName: "bolt.fill")
                        .foregroundColor(.white)
                }
            }
            VStack(alignment: .leading, spacing: 2) {
                Text("Auto · fastest ping")
                    .font(.subheadline.weight(.semibold))
                    .foregroundColor(Palette.onSurface)
                Text(verbatim: subtitle)
                    .font(.caption)
                    .foregroundColor(Palette.onSurfaceVariant)
                    .lineLimit(2)
            }
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 2) {
                LatencyBadge(result: latency)
                Text(verbatim: kindLabel)
                    .font(.caption2)
                    .foregroundColor(Palette.onSurfaceVariant.opacity(0.7))
            }
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
    }
}

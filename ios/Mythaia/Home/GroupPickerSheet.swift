import SwiftUI
import MythaiaKit

/// The groups as chips, then what the chosen group offers: Auto first, then
/// its servers. A tap on a server pins it; a tap on Auto lets the group
/// choose again. Choosing a group's chip makes it the tunnel's group.
@MainActor
struct GroupPickerSheet: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    @State private var browsing: String = ""

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                chips
                Divider().opacity(0.4)
                list
            }
            .background(Palette.surface)
            .navigationTitle(Text("Proxies"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
        }
        .presentationDetents([.medium, .large])
        .onAppear {
            if browsing.isEmpty {
                browsing = model.selection.selectedChainId != nil ? ProxyGroup.chainsId : model.activeGroupId
            }
        }
    }

    private var chips: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                ForEach(model.groups) { group in
                    GroupChip(
                        title: groupName(group),
                        count: group.configs.count,
                        selected: browsing == group.id,
                        active: model.selection.selectedChainId == nil && model.activeGroupId == group.id
                    ) {
                        browsing = group.id
                        if model.selection.selectedChainId != nil || model.activeGroupId != group.id {
                            model.selectGroup(group.id)
                        }
                    }
                }
                if !model.chains.isEmpty {
                    GroupChip(
                        title: String(localized: "Chains"),
                        count: model.chains.count,
                        selected: browsing == ProxyGroup.chainsId,
                        active: model.selection.selectedChainId != nil
                    ) {
                        browsing = ProxyGroup.chainsId
                    }
                }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 12)
        }
    }

    @ViewBuilder
    private var list: some View {
        if browsing == ProxyGroup.chainsId {
            chainList
        } else if let group = model.group(browsing) {
            serverList(group)
        } else {
            Spacer()
        }
    }

    private var chainList: some View {
        List {
            ForEach(model.chains, id: \.id) { chain in
                Button {
                    model.selectChain(chain)
                    dismiss()
                } label: {
                    PickerRow(
                        title: chain.name,
                        subtitle: nil,
                        selected: chain.id == model.selection.selectedChainId,
                        leading: AnyView(Image(systemName: "link").foregroundColor(Palette.onSurfaceVariant)),
                        latency: nil
                    )
                }
                .disabled(model.resolve(chain) == nil)
                .listRowBackground(rowBackground(chain.id == model.selection.selectedChainId))
            }
        }
        .listStyle(.plain)
    }

    private func serverList(_ group: ProxyGroup) -> some View {
        let groupIsActive = model.selection.selectedChainId == nil && model.activeGroupId == group.id
        let pinned = model.selection.groupPins[group.id]
        let auto = model.selection.autoChoices[group.id]
        return List {
            Button {
                model.useAuto(group.id)
                dismiss()
            } label: {
                PickerRow(
                    title: String(localized: "Auto · fastest ping"),
                    subtitle: autoSubtitle(auto),
                    selected: groupIsActive && pinned == nil,
                    leading: autoIcon(busy: model.autoSelecting && groupIsActive),
                    latency: auto.flatMap { model.latency[$0] }
                )
            }
            .listRowBackground(rowBackground(groupIsActive && pinned == nil))

            if group.configs.isEmpty {
                Text("No servers in this group yet.")
                    .font(.subheadline)
                    .foregroundColor(Palette.onSurfaceVariant)
                    .listRowBackground(Color.clear)
            }

            ForEach(group.configs, id: \.id) { config in
                let isPinned = groupIsActive && pinned == config.id
                Button {
                    model.pin(config)
                    dismiss()
                } label: {
                    PickerRow(
                        title: config.name,
                        subtitle: Format.endpoint(config),
                        selected: isPinned,
                        leading: serverIcon(pinned: isPinned, autoPick: pinned == nil && auto == config.id),
                        latency: model.latency[config.id]
                    )
                }
                .listRowBackground(rowBackground(isPinned))
            }
        }
        .listStyle(.plain)
    }

    private func groupName(_ group: ProxyGroup) -> String {
        group.isDefault ? String(localized: "Default") : group.name
    }

    private func autoSubtitle(_ auto: UUID?) -> String {
        if let id = auto, let name = model.configsById[id]?.name {
            return String(localized: "Auto · \(name)")
        }
        return String(localized: "Connects at once, then measures the group by real ping and moves to a clearly faster server; while connected, rechecks every 10 minutes with the screen on.")
    }

    private func autoIcon(busy: Bool) -> AnyView {
        if busy { return AnyView(ProgressView().controlSize(.small)) }
        return AnyView(Image(systemName: "bolt.fill").foregroundColor(Palette.primary))
    }

    private func serverIcon(pinned: Bool, autoPick: Bool) -> AnyView {
        if pinned { return AnyView(Image(systemName: "pin.fill").foregroundColor(Palette.primary)) }
        if autoPick { return AnyView(Image(systemName: "bolt").foregroundColor(Palette.primary.opacity(0.6))) }
        return AnyView(Color.clear)
    }

    private func rowBackground(_ selected: Bool) -> Color {
        selected ? Palette.primaryContainer.opacity(0.6) : Palette.surface
    }
}

/// A group as a chip: its name and how many servers it has; a check on the
/// group the tunnel draws from.
struct GroupChip: View {
    let title: String
    let count: Int
    let selected: Bool
    let active: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 6) {
                if active {
                    Image(systemName: "checkmark")
                        .font(.caption.weight(.bold))
                }
                Text(verbatim: title)
                    .font(.subheadline.weight(.medium))
                    .lineLimit(1)
                Text(verbatim: String(count))
                    .font(.caption.monospacedDigit())
                    .opacity(0.7)
            }
            .foregroundColor(selected ? Palette.onPrimary : Palette.onSurface)
            .padding(.horizontal, 14)
            .padding(.vertical, 8)
            .background(selected ? Palette.primary : Palette.surfaceLow, in: Capsule())
            .overlay(Capsule().strokeBorder(Palette.outline, lineWidth: selected ? 0 : 1))
        }
        .buttonStyle(.plain)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

private struct PickerRow: View {
    let title: String
    let subtitle: String?
    let selected: Bool
    let leading: AnyView
    let latency: LatencyResult?

    var body: some View {
        HStack(spacing: 14) {
            leading
                .frame(width: 24, height: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: title)
                    .font(.body)
                    .foregroundColor(Palette.onSurface)
                    .lineLimit(1)
                if let subtitle = subtitle {
                    Text(verbatim: subtitle)
                        .font(.caption)
                        .foregroundColor(Palette.onSurfaceVariant)
                        .lineLimit(2)
                }
            }
            Spacer(minLength: 8)
            LatencyBadge(result: latency)
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

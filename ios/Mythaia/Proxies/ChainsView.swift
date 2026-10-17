import SwiftUI
import MythaiaKit

/// Proxy chains: servers dialled one through another, the last one the
/// exit. A tap uses the chain for the tunnel instead of a group.
@MainActor
struct ChainsView: View {
    @EnvironmentObject private var model: AppModel
    @State private var editing: ChainDraft?
    @State private var deleting: ProxyChain?

    var body: some View {
        content
            .background(Palette.background.ignoresSafeArea())
            .navigationTitle(Text("Chains"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button {
                        editing = ChainDraft(chain: nil)
                    } label: {
                        Image(systemName: "plus")
                    }
                    .accessibilityLabel(Text("New Chain"))
                }
            }
            .sheet(item: $editing) { draft in
                ChainEditorView(draft: draft)
                    .environmentObject(model)
            }
            .alert(String(localized: "Delete"), isPresented: deleteShown, presenting: deleting) { chain in
                Button(role: .destructive) {
                    model.deleteChain(chain)
                    deleting = nil
                } label: {
                    Text("Delete")
                }
                Button(role: .cancel) {} label: { Text("Cancel") }
            } message: { chain in
                Text(verbatim: chain.name)
            }
    }

    @ViewBuilder
    private var content: some View {
        if model.chains.isEmpty {
            VStack(spacing: 8) {
                Image(systemName: "link")
                    .font(.largeTitle)
                    .foregroundColor(Palette.primary)
                    .padding(.bottom, 8)
                Text("No Chains")
                    .font(.title3.weight(.semibold))
                    .foregroundColor(Palette.onSurface)
                Text("Tap + to create a proxy chain.")
                    .font(.subheadline)
                    .foregroundColor(Palette.onSurfaceVariant)
            }
            .padding(32)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            List {
                ForEach(model.chains, id: \.id) { chain in
                    row(chain)
                }
            }
            .listStyle(.insetGrouped)
            .scrollContentBackground(.hidden)
        }
    }

    private func row(_ chain: ProxyChain) -> some View {
        let selected = model.selection.selectedChainId == chain.id
        let valid = model.resolve(chain) != nil
        return Button {
            model.selectChain(chain)
        } label: {
            ChainRow(
                name: chain.name,
                hops: hopNames(chain),
                valid: valid,
                selected: selected,
                latency: model.chainLatency[chain.id]
            )
        }
        .buttonStyle(.plain)
        .disabled(!valid)
        .listRowBackground(selected ? Palette.primaryContainer.opacity(0.55) : Palette.surface)
        .swipeActions(edge: .trailing, allowsFullSwipe: false) {
            Button(role: .destructive) {
                deleting = chain
            } label: {
                Label("Delete", systemImage: "trash")
            }
            Button {
                editing = ChainDraft(chain: chain)
            } label: {
                Label("Edit", systemImage: "pencil")
            }
            .tint(Palette.azure)
        }
        .contextMenu {
            Button {
                model.testChainLatency(chain)
            } label: {
                Label("Test Latency", systemImage: "speedometer")
            }
            .disabled(!valid)
            Button {
                editing = ChainDraft(chain: chain)
            } label: {
                Label("Edit", systemImage: "pencil")
            }
            Button(role: .destructive) {
                deleting = chain
            } label: {
                Label("Delete", systemImage: "trash")
            }
        }
    }

    private func hopNames(_ chain: ProxyChain) -> [String] {
        chain.proxyIds.map { id in model.configsById[id]?.name ?? "?" }
    }

    private var deleteShown: Binding<Bool> {
        Binding(
            get: { deleting != nil },
            set: { if !$0 { deleting = nil } }
        )
    }
}

private struct ChainRow: View {
    let name: String
    let hops: [String]
    let valid: Bool
    let selected: Bool
    let latency: LatencyResult?

    var body: some View {
        HStack(spacing: 12) {
            WingIconTile(size: 34) {
                Image(systemName: "link")
                    .font(.footnote.weight(.semibold))
                    .foregroundColor(.white)
            }
            VStack(alignment: .leading, spacing: 3) {
                Text(verbatim: name)
                    .font(.subheadline.weight(.semibold))
                    .foregroundColor(Palette.onSurface)
                    .lineLimit(1)
                Text(verbatim: hops.joined(separator: " → "))
                    .font(.caption)
                    .foregroundColor(Palette.onSurfaceVariant)
                    .lineLimit(2)
                if !valid {
                    Text("Invalid chain — some proxies are missing")
                        .font(.caption.weight(.medium))
                        .foregroundColor(Palette.error)
                }
            }
            Spacer(minLength: 8)
            if selected {
                Image(systemName: "checkmark")
                    .font(.footnote.weight(.bold))
                    .foregroundColor(Palette.primary)
            }
            LatencyBadge(result: latency)
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

/// A chain being written: a new one, or an existing one's copy.
struct ChainDraft: Identifiable {
    let id = UUID()
    var chain: ProxyChain?
}

/// Name a chain and put servers in order, the first dialled first and the
/// last one the exit. At least two.
@MainActor
struct ChainEditorView: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss

    let draft: ChainDraft
    @State private var name: String
    @State private var hops: [UUID]
    @State private var picking = false

    init(draft: ChainDraft) {
        self.draft = draft
        _name = State(initialValue: draft.chain?.name ?? "")
        _hops = State(initialValue: draft.chain?.proxyIds ?? [])
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    FieldRow(title: "Name", text: $name)
                }
                hopsSection
                if hops.count >= 2 {
                    previewSection
                }
            }
            .scrollContentBackground(.hidden)
            .background(Palette.background.ignoresSafeArea())
            .environment(\.editMode, .constant(.active))
            .navigationTitle(draft.chain == nil ? Text("New Chain") : Text("Edit Chain"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { save() }
                        .disabled(!canSave)
                }
            }
            .sheet(isPresented: $picking) {
                ChainServerPicker(excluded: Set(hops)) { id in
                    hops.append(id)
                }
                .environmentObject(model)
            }
        }
    }

    private var canSave: Bool {
        !name.trimmingCharacters(in: .whitespaces).isEmpty && hops.count >= 2
    }

    private var hopsSection: some View {
        Section {
            ForEach(Array(hops.enumerated()), id: \.element) { index, id in
                HopRow(
                    name: model.configsById[id]?.name ?? "?",
                    detail: model.configsById[id].map { Format.endpoint($0) } ?? "",
                    role: role(at: index)
                )
            }
            .onMove { from, to in
                hops.move(fromOffsets: from, toOffset: to)
            }
            .onDelete { offsets in
                hops.remove(atOffsets: offsets)
            }
            Button {
                picking = true
            } label: {
                Label("Add Proxy", systemImage: "plus.circle")
            }
        } header: {
            Text("Proxies")
        } footer: {
            if hops.count < 2 {
                Text("Add at least 2 proxies to form a chain.")
            }
        }
    }

    private var previewSection: some View {
        Section {
            Text("You → \(hopList) → Target")
                .font(.footnote)
                .foregroundColor(Palette.onSurfaceVariant)
        } header: {
            Text("Route Preview")
        }
    }

    private var hopList: String {
        hops.map { model.configsById[$0]?.name ?? "?" }.joined(separator: " → ")
    }

    private func role(at index: Int) -> String? {
        if index == 0 { return String(localized: "Entry") }
        if index == hops.count - 1 { return String(localized: "Exit") }
        return nil
    }

    private func save() {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        var chain = draft.chain ?? ProxyChain(name: trimmed)
        chain.name = trimmed
        chain.proxyIds = hops
        model.saveChain(chain)
        dismiss()
    }
}

private struct HopRow: View {
    let name: String
    let detail: String
    let role: String?

    var body: some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(verbatim: name)
                    .font(.subheadline)
                    .foregroundColor(Palette.onSurface)
                    .lineLimit(1)
                Text(verbatim: detail)
                    .font(.caption.monospaced())
                    .foregroundColor(Palette.onSurfaceVariant)
                    .lineLimit(1)
            }
            Spacer(minLength: 8)
            if let role = role {
                Text(verbatim: role)
                    .font(.caption2.weight(.semibold))
                    .foregroundColor(Palette.onPrimaryContainer)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Palette.primaryContainer, in: Capsule())
            }
        }
    }
}

/// The servers a chain can take, by group; WireGuard and those already in
/// the chain are left out.
@MainActor
private struct ChainServerPicker: View {
    @EnvironmentObject private var model: AppModel
    @Environment(\.dismiss) private var dismiss
    let excluded: Set<UUID>
    let pick: (UUID) -> Void

    var body: some View {
        NavigationStack {
            content
                .navigationTitle(Text("Select Proxy"))
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .cancellationAction) {
                        Button("Cancel") { dismiss() }
                    }
                }
        }
    }

    @ViewBuilder
    private var content: some View {
        let sections = available
        if sections.isEmpty {
            VStack(spacing: 8) {
                Text("No Proxies Available")
                    .font(.headline)
                Text("All proxies are already in this chain.")
                    .font(.subheadline)
                    .foregroundColor(Palette.onSurfaceVariant)
            }
            .padding(32)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            List {
                ForEach(sections) { group in
                    Section {
                        ForEach(group.configs, id: \.id) { config in
                            Button {
                                pick(config.id)
                                dismiss()
                            } label: {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(verbatim: config.name)
                                        .foregroundColor(Palette.onSurface)
                                    Text(verbatim: Format.endpoint(config))
                                        .font(.caption.monospaced())
                                        .foregroundColor(Palette.onSurfaceVariant)
                                }
                            }
                        }
                    } header: {
                        Text(verbatim: group.isDefault ? String(localized: "Default") : group.name)
                    }
                }
            }
            .listStyle(.insetGrouped)
        }
    }

    private var available: [ProxyGroup] {
        model.groups.compactMap { group in
            let usable = group.configs.filter { !excluded.contains($0.id) && !CoreBridge.isLayer3($0) }
            if usable.isEmpty { return nil }
            return ProxyGroup(id: group.id, name: group.name, subscriptionId: group.subscriptionId, configs: usable)
        }
    }
}

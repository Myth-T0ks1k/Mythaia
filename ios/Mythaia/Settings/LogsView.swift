import SwiftUI
import UIKit

/// The tunnel's recent log, fetched from the running tunnel every couple of
/// seconds while the screen is open.
@MainActor
struct LogsView: View {
    @EnvironmentObject private var vpn: VPNController
    @State private var lines: [String] = []
    @State private var reachable = true
    @State private var share: SharePayload?

    var body: some View {
        Group {
            if lines.isEmpty {
                emptyState
            } else {
                logList
            }
        }
        .background(Palette.background.ignoresSafeArea())
        .navigationTitle(Text("Logs"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItemGroup(placement: .navigationBarTrailing) {
                Button {
                    UIPasteboard.general.string = lines.joined(separator: "\n")
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .accessibilityLabel(Text("Copy"))
                .disabled(lines.isEmpty)
                Button {
                    share = SharePayload(text: lines.joined(separator: "\n"))
                } label: {
                    Image(systemName: "square.and.arrow.up")
                }
                .accessibilityLabel(Text("Share"))
                .disabled(lines.isEmpty)
            }
        }
        .sheet(item: $share) { payload in
            ActivityView(items: [payload.text])
        }
        .task {
            while !Task.isCancelled {
                await refresh()
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 8) {
            Image(systemName: "doc.text")
                .font(.largeTitle)
                .foregroundColor(Palette.onSurfaceVariant)
            Text("No Recent Logs")
                .font(.headline)
                .foregroundColor(Palette.onSurface)
            if !reachable {
                Text("Logs come from the running tunnel. Connect to see them.")
                    .font(.subheadline)
                    .foregroundColor(Palette.onSurfaceVariant)
                    .multilineTextAlignment(.center)
            }
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var logList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 4) {
                    ForEach(Array(lines.enumerated()), id: \.offset) { index, line in
                        Text(verbatim: line)
                            .font(.caption.monospaced())
                            .foregroundColor(color(for: line))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .id(index)
                    }
                }
                .padding(16)
            }
            .onChange(of: lines.count) { count in
                if count > 0 { proxy.scrollTo(count - 1, anchor: .bottom) }
            }
        }
    }

    private func color(for line: String) -> Color {
        if line.contains(" E ") || line.hasPrefix("E ") { return Palette.error }
        if line.contains(" W ") || line.hasPrefix("W ") { return Palette.warning }
        return Palette.onSurface
    }

    private func refresh() async {
        if let fetched = await vpn.fetchLogTail() {
            reachable = true
            if fetched != lines { lines = fetched }
        } else {
            reachable = false
        }
    }
}

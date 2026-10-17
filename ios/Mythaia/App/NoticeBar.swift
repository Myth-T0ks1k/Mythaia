import SwiftUI

/// The bar at the bottom of every screen that says a subscription did not
/// update, with the way out beside it: fetch it again through a server that
/// works. It goes away on its own after a while.
@MainActor
struct NoticeBar: View {
    @EnvironmentObject private var model: AppModel

    var body: some View {
        ZStack {
            if let notice = model.notice {
                NoticeBarContent(
                    notice: notice,
                    retry: { model.refreshThroughWorkingServer(notice.subscriptionId) },
                    close: { model.dismissNotice() }
                )
                .transition(.move(edge: .bottom).combined(with: .opacity))
                .task(id: notice) {
                    guard let seconds = NoticeBar.lifetime(notice) else { return }
                    try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                    if !Task.isCancelled && model.notice == notice {
                        model.notice = nil
                    }
                }
            }
        }
        .animation(.easeInOut(duration: 0.25), value: model.notice)
    }

    /// How long a notice stays; nil while the work it reports is running.
    static func lifetime(_ notice: SubscriptionNotice) -> Double? {
        switch notice {
        case .failed: return 10
        case .retrying: return nil
        case .updatedThrough: return 4
        }
    }
}

private struct NoticeBarContent: View {
    let notice: SubscriptionNotice
    let retry: () -> Void
    let close: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(alignment: .top, spacing: 10) {
                if case .retrying = notice {
                    ProgressView()
                        .controlSize(.small)
                        .tint(Palette.inverseOnSurface)
                }
                Text(verbatim: message)
                    .font(.footnote)
                    .foregroundColor(Palette.inverseOnSurface)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .fixedSize(horizontal: false, vertical: true)
                Button(action: close) {
                    Image(systemName: "xmark")
                        .font(.footnote.weight(.semibold))
                        .foregroundColor(Palette.inverseOnSurface.opacity(0.8))
                }
                .accessibilityLabel(Text("Close"))
            }
            if canRetry {
                Button(action: retry) {
                    Text("Try through a working server")
                        .font(.footnote.weight(.semibold))
                        .foregroundColor(Palette.inversePrimary)
                }
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
        .background(Palette.inverseSurface, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .shadow(color: Color.black.opacity(0.15), radius: 8, x: 0, y: 4)
    }

    private var canRetry: Bool {
        if case .failed(_, _, _, let canRetry) = notice { return canRetry }
        return false
    }

    private var message: String {
        switch notice {
        case .failed(_, let name, let message, _):
            return String(localized: "Couldn’t update “\(name)”: \(message)")
        case .retrying(_, let name):
            return String(localized: "Updating “\(name)” through a working server…")
        case .updatedThrough(_, let name, let server):
            return String(localized: "“\(name)” updated through \(server)")
        }
    }
}

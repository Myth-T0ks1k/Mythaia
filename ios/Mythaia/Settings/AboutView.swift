import SwiftUI

/// The app's name and version, where its source lives, and where its
/// community talks.
struct AboutView: View {
    var body: some View {
        Form {
            Section {
                VStack(spacing: 12) {
                    WingIconTile(size: 72) {
                        WingMarkView(color: Palette.bone)
                            .frame(width: 40, height: 40)
                    }
                    Text(verbatim: "Mythaia Pro")
                        .font(.title2.weight(.semibold))
                        .foregroundColor(Palette.onSurface)
                    Text("Version \(AboutView.version)")
                        .font(.subheadline.monospacedDigit())
                        .foregroundColor(Palette.onSurfaceVariant)
                    Text("An open-source proxy client, free under the GPL-3.0 license.")
                        .font(.footnote)
                        .foregroundColor(Palette.onSurfaceVariant)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
                .listRowBackground(Color.clear)
            }
            Section {
                Link(destination: BrandLinks.github) {
                    Label("Source code on GitHub", systemImage: "chevron.left.forwardslash.chevron.right")
                }
                Link(destination: BrandLinks.telegramChannel) {
                    Label("Telegram channel", systemImage: "megaphone")
                }
                Link(destination: BrandLinks.telegramChat) {
                    Label("Telegram chat", systemImage: "bubble.left.and.bubble.right")
                }
            }
            Section {
                Text("All trademarks, service marks, and company names are the property of their respective owners.")
                    .font(.footnote)
                    .foregroundColor(Palette.onSurfaceVariant)
            }
        }
        .scrollContentBackground(.hidden)
        .background(Palette.background.ignoresSafeArea())
        .navigationTitle(Text("About"))
        .navigationBarTitleDisplayMode(.inline)
    }

    /// "1.4.0 (52)".
    static var version: String {
        let info = Bundle.main.infoDictionary
        let short = info?["CFBundleShortVersionString"] as? String ?? "?"
        let build = info?["CFBundleVersion"] as? String ?? "?"
        return "\(short) (\(build))"
    }
}

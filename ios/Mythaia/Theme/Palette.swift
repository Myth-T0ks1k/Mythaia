import SwiftUI
import UIKit

/// The Wing palette: bone and paper in light mode, deep ink in dark mode,
/// azure as the one accent. Every colour resolves against the current trait
/// collection, so the in-app theme choice (which sets the window's style)
/// repaints everything at once.
enum Palette {
    // Brand constants.
    static let azure = Color(argb: 0xFF24548F)
    static let azureDeep = Color(argb: 0xFF16386B)
    static let lightAzure = Color(argb: 0xFF8FB0DE)
    static let ink = Color(argb: 0xFF14213A)
    static let bone = Color(argb: 0xFFF6F3EC)
    static let paper = Color(argb: 0xFFFDFBF6)
    static let slate = Color(argb: 0xFF4E5568)

    // Roles, light and dark.
    static let primary = Color.dynamic(light: 0xFF24548F, dark: 0xFF8FB0DE)
    static let onPrimary = Color.dynamic(light: 0xFFFDFBF6, dark: 0xFF0D1524)
    static let primaryContainer = Color.dynamic(light: 0xFFD9E3F1, dark: 0xFF22406C)
    static let onPrimaryContainer = Color.dynamic(light: 0xFF16386B, dark: 0xFFD8E4F5)
    static let background = Color.dynamic(light: 0xFFF6F3EC, dark: 0xFF0D1524)
    static let surface = Color.dynamic(light: 0xFFFDFBF6, dark: 0xFF16213A)
    static let surfaceLow = Color.dynamic(light: 0xFFFAF7F0, dark: 0xFF121D33)
    static let surfaceContainer = Color.dynamic(light: 0xFFF3EFE6, dark: 0xFF16213A)
    static let surfaceHigh = Color.dynamic(light: 0xFFEDE9DE, dark: 0xFF1D2A47)
    static let surfaceVariant = Color.dynamic(light: 0xFFECE8DD, dark: 0xFF1D2A47)
    static let onSurface = Color.dynamic(light: 0xFF14213A, dark: 0xFFF2EFE7)
    static let onSurfaceVariant = Color.dynamic(light: 0xFF4E5568, dark: 0xFFA9B1C4)
    static let outline = Color.dynamic(light: 0x1414213A, dark: 0x1AF2EFE7)
    static let error = Color.dynamic(light: 0xFFC4442E, dark: 0xFFE8705B)
    static let errorContainer = Color.dynamic(light: 0xFFF6DAD3, dark: 0xFF5C1A0E)
    static let onErrorContainer = Color.dynamic(light: 0xFF5C1A0E, dark: 0xFFF6DAD3)
    static let warning = Color.dynamic(light: 0xFFE8890C, dark: 0xFFF5A83E)
    static let successContainer = Color.dynamic(light: 0xFFDDEBDD, dark: 0xFF1C3A27)
    static let onSuccessContainer = Color.dynamic(light: 0xFF1F4A2A, dark: 0xFFD0E8D5)
    static let inverseSurface = Color.dynamic(light: 0xFF14213A, dark: 0xFFF2EFE7)
    static let inverseOnSurface = Color.dynamic(light: 0xFFF6F3EC, dark: 0xFF14213A)
    static let inversePrimary = Color.dynamic(light: 0xFF8FB0DE, dark: 0xFF24548F)

    // The home screen's ground: azure into ink while connected, quiet
    // neutrals otherwise.
    static let connectedStart = Color.dynamic(light: 0xFF24548F, dark: 0xFF1E3A63)
    static let connectedEnd = Color.dynamic(light: 0xFF16294D, dark: 0xFF0D1B33)
    static let idleStart = Color.dynamic(light: 0xFFF1EDE3, dark: 0xFF141F37)
    static let idleEnd = Color.dynamic(light: 0xFFE5E0D2, dark: 0xFF0C1322)
}

extension Color {
    /// A colour from `0xAARRGGBB`.
    init(argb: UInt32) {
        self.init(uiColor: UIColor(argb: argb))
    }

    /// One colour for light mode and another for dark, both `0xAARRGGBB`.
    static func dynamic(light: UInt32, dark: UInt32) -> Color {
        let lightColor = UIColor(argb: light)
        let darkColor = UIColor(argb: dark)
        return Color(uiColor: UIColor { traits in
            traits.userInterfaceStyle == .dark ? darkColor : lightColor
        })
    }
}

extension UIColor {
    convenience init(argb: UInt32) {
        let a = CGFloat((argb >> 24) & 0xFF) / 255
        let r = CGFloat((argb >> 16) & 0xFF) / 255
        let g = CGFloat((argb >> 8) & 0xFF) / 255
        let b = CGFloat(argb & 0xFF) / 255
        self.init(red: r, green: g, blue: b, alpha: a)
    }
}

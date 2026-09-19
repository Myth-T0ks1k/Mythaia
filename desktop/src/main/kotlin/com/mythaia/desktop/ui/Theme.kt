package com.mythaia.desktop.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

// The Wing palette, the same values as the Android app's Color.kt.
val Azure = Color(0xFF24548F)
val Ink = Color(0xFF14213A)
val Bone = Color(0xFFF6F3EC)
val Paper = Color(0xFFFDFBF6)
val Slate = Color(0xFF4E5568)
val AzureDeep = Color(0xFF16386B)
val LightAzure = Color(0xFF8FB0DE)
val WarningLight = Color(0xFFE8890C)
val WarningDark = Color(0xFFF5A83E)

private val LightScheme = lightColorScheme(
    primary = Azure,
    onPrimary = Paper,
    primaryContainer = Color(0xFFD9E3F1),
    onPrimaryContainer = AzureDeep,
    inversePrimary = LightAzure,
    secondary = Slate,
    onSecondary = Paper,
    secondaryContainer = Color(0xFFE6E3DB),
    onSecondaryContainer = Ink,
    tertiary = Color(0xFF476A99),
    onTertiary = Paper,
    tertiaryContainer = Color(0xFFDDE6F1),
    onTertiaryContainer = AzureDeep,
    background = Bone,
    onBackground = Ink,
    surface = Paper,
    onSurface = Ink,
    surfaceVariant = Color(0xFFECE8DD),
    onSurfaceVariant = Slate,
    surfaceTint = Azure,
    inverseSurface = Ink,
    inverseOnSurface = Bone,
    error = Color(0xFFC4442E),
    onError = Paper,
    errorContainer = Color(0xFFF6DAD3),
    onErrorContainer = Color(0xFF5C1A0E),
    outline = Color(0x1414213A),
    outlineVariant = Color(0x0D14213A),
    surfaceBright = Color(0xFFFDFBF6),
    surfaceDim = Color(0xFFEFEBE1),
    surfaceContainer = Color(0xFFF3EFE6),
    surfaceContainerHigh = Color(0xFFEDE9DE),
    surfaceContainerHighest = Color(0xFFE7E2D6),
    surfaceContainerLow = Color(0xFFFAF7F0),
    surfaceContainerLowest = Color(0xFFFFFEFA)
)

private val DarkScheme = darkColorScheme(
    primary = LightAzure,
    onPrimary = Color(0xFF0D1524),
    primaryContainer = Color(0xFF22406C),
    onPrimaryContainer = Color(0xFFD8E4F5),
    inversePrimary = Azure,
    secondary = Color(0xFFA9B1C4),
    onSecondary = Color(0xFF16213A),
    secondaryContainer = Color(0xFF2A3550),
    onSecondaryContainer = Color(0xFFDCE0EA),
    tertiary = Color(0xFFA9C2E4),
    onTertiary = Color(0xFF0D1524),
    tertiaryContainer = Color(0xFF1D3050),
    onTertiaryContainer = Color(0xFFD8E4F5),
    background = Color(0xFF0D1524),
    onBackground = Color(0xFFF2EFE7),
    surface = Color(0xFF16213A),
    onSurface = Color(0xFFF2EFE7),
    surfaceVariant = Color(0xFF1D2A47),
    onSurfaceVariant = Color(0xFFA9B1C4),
    surfaceTint = LightAzure,
    inverseSurface = Color(0xFFF2EFE7),
    inverseOnSurface = Ink,
    error = Color(0xFFE8705B),
    onError = Color(0xFF0D1524),
    errorContainer = Color(0xFF5C1A0E),
    onErrorContainer = Color(0xFFF6DAD3),
    outline = Color(0x1AF2EFE7),
    outlineVariant = Color(0x0FF2EFE7),
    surfaceBright = Color(0xFF2A3856),
    surfaceDim = Color(0xFF0D1524),
    surfaceContainer = Color(0xFF16213A),
    surfaceContainerHigh = Color(0xFF1D2A47),
    surfaceContainerHighest = Color(0xFF243354),
    surfaceContainerLow = Color(0xFF121D33),
    surfaceContainerLowest = Color(0xFF0A111D)
)

val LocalDarkTheme = staticCompositionLocalOf { false }

@Composable
fun MythaiaTheme(dark: Boolean, content: @Composable () -> Unit) {
    CompositionLocalProvider(LocalDarkTheme provides dark) {
        MaterialTheme(colorScheme = if (dark) DarkScheme else LightScheme, content = content)
    }
}

package com.mythaia.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.platform.LocalContext

/**
 * Whether [MythaiaTheme] is drawing its dark palette.
 *
 * Read this, not `isSystemInDarkTheme()`, wherever a colour depends on the
 * palette: the user can pin the app to light or dark regardless of the device,
 * and the system flag would then pick the token for the wrong ground.
 */
val LocalMythaiaDarkTheme = staticCompositionLocalOf { false }

private val DarkColorScheme = darkColorScheme(
    primary = LightAzure,
    onPrimary = DeepInk,
    primaryContainer = AzureContainerDark,
    onPrimaryContainer = OnAzureContainerDark,
    inversePrimary = Azure,
    secondary = SlateText,
    onSecondary = InkSurface,
    secondaryContainer = SlateContainerDark,
    onSecondaryContainer = OnSlateContainerDark,
    tertiary = TertiaryDark,
    onTertiary = DeepInk,
    tertiaryContainer = TertiaryContainerDark,
    onTertiaryContainer = OnAzureContainerDark,
    background = DeepInk,
    onBackground = BoneText,
    surface = InkSurface,
    onSurface = BoneText,
    surfaceVariant = InkSurfaceHigh,
    onSurfaceVariant = SlateText,
    surfaceTint = LightAzure,
    inverseSurface = BoneText,
    inverseOnSurface = Ink,
    error = ErrorDark,
    onError = DeepInk,
    errorContainer = ErrorContainerDark,
    onErrorContainer = OnErrorContainerDark,
    outline = OutlineDarkToken,
    outlineVariant = OutlineVariantDarkToken,
    surfaceBright = SurfaceBrightDark,
    surfaceDim = SurfaceDimDark,
    surfaceContainer = SurfaceContainerDark,
    surfaceContainerHigh = SurfaceContainerHighDark,
    surfaceContainerHighest = SurfaceContainerHighestDark,
    surfaceContainerLow = SurfaceContainerLowDark,
    surfaceContainerLowest = SurfaceContainerLowestDark
)

private val LightColorScheme = lightColorScheme(
    primary = Azure,
    onPrimary = Paper,
    primaryContainer = AzureContainerLight,
    onPrimaryContainer = AzureDeep,
    inversePrimary = LightAzure,
    secondary = Slate,
    onSecondary = Paper,
    secondaryContainer = SlateContainerLight,
    onSecondaryContainer = Ink,
    tertiary = TertiaryLight,
    onTertiary = Paper,
    tertiaryContainer = TertiaryContainerLight,
    onTertiaryContainer = AzureDeep,
    background = Bone,
    onBackground = Ink,
    surface = Paper,
    onSurface = Ink,
    surfaceVariant = SurfaceVariantLight,
    onSurfaceVariant = Slate,
    surfaceTint = Azure,
    inverseSurface = Ink,
    inverseOnSurface = Bone,
    error = ErrorLight,
    onError = Paper,
    errorContainer = ErrorContainerLight,
    onErrorContainer = OnErrorContainerLight,
    outline = OutlineLightToken,
    outlineVariant = OutlineVariantLightToken,
    surfaceBright = SurfaceBrightLight,
    surfaceDim = SurfaceDimLight,
    surfaceContainer = SurfaceContainerLight,
    surfaceContainerHigh = SurfaceContainerHighLight,
    surfaceContainerHighest = SurfaceContainerHighestLight,
    surfaceContainerLow = SurfaceContainerLowLight,
    surfaceContainerLowest = SurfaceContainerLowestLight
)

/**
 * Mythaia "Wing" theme. Calm, papery, editorial: bone/paper in light mode,
 * deep-ink surfaces in dark mode, azure as the single accent.
 *
 * Dynamic (wallpaper) color is OFF by default so the brand always shows.
 */
@Composable
fun MythaiaTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }

        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }

    CompositionLocalProvider(LocalMythaiaDarkTheme provides darkTheme) {
        MaterialTheme(
            colorScheme = colorScheme,
            typography = Typography,
            content = content
        )
    }
}

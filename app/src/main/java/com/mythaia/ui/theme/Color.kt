package com.mythaia.ui.theme

import androidx.compose.ui.graphics.Color

// ---------------------------------------------------------------------------
// Mythaia "Wing" brand palette (authoritative, mirrors iOS Theme.swift)
// ---------------------------------------------------------------------------

/** Primary brand color. Connected state, links, CTAs, selection. */
val Azure = Color(0xFF24548F)

/** Headline/primary text in light mode; base of the dark palette. */
val Ink = Color(0xFF14213A)

/** Light-mode app background. Warm, papery — never pure white. */
val Bone = Color(0xFFF6F3EC)

/** Light-mode surfaces: cards, rows, sheets. */
val Paper = Color(0xFFFDFBF6)

/** Secondary text and muted icons. */
val Slate = Color(0xFF4E5568)

// ---------------------------------------------------------------------------
// Derived light-mode tokens
// ---------------------------------------------------------------------------

/** Deep azure — pressed azure, gradient ends, on-container accents. */
val AzureDeep = Color(0xFF16386B)

/** Soft azure wash for containers/selection (light mode). */
val AzureContainerLight = Color(0xFFD9E3F1)

/** Muted azure tertiary (light mode). */
val TertiaryLight = Color(0xFF476A99)

/** Tertiary container (light mode). */
val TertiaryContainerLight = Color(0xFFDDE6F1)

/** Slate-tinted container (light mode). */
val SlateContainerLight = Color(0xFFE6E3DB)

/** Bone-tinted variant surface (light mode). */
val SurfaceVariantLight = Color(0xFFECE8DD)

/** Error red (light mode). */
val ErrorLight = Color(0xFFC4442E)

/** Error container (light mode). */
val ErrorContainerLight = Color(0xFFF6DAD3)

/** On-error-container (light mode). */
val OnErrorContainerLight = Color(0xFF5C1A0E)

/** 1dp hairline border in light mode: ink at 8% alpha. */
val OutlineLightToken = Color(0x1414213A)

/** Softer divider in light mode: ink at 5% alpha. */
val OutlineVariantLightToken = Color(0x0D14213A)

// Light surface-container ladder (papery, warm)
val SurfaceDimLight = Color(0xFFEFEBE1)
val SurfaceBrightLight = Color(0xFFFDFBF6)
val SurfaceContainerLowestLight = Color(0xFFFFFEFA)
val SurfaceContainerLowLight = Color(0xFFFAF7F0)
val SurfaceContainerLight = Color(0xFFF3EFE6)
val SurfaceContainerHighLight = Color(0xFFEDE9DE)
val SurfaceContainerHighestLight = Color(0xFFE7E2D6)

// ---------------------------------------------------------------------------
// Dark-mode "deep ink" palette
// ---------------------------------------------------------------------------

/** Dark-mode app background. */
val DeepInk = Color(0xFF0D1524)

/** Dark-mode surfaces: cards, rows, sheets (ink-tinted, not gray). */
val InkSurface = Color(0xFF16213A)

/** Raised/pressed dark surfaces, chips. */
val InkSurfaceHigh = Color(0xFF1D2A47)

/** Dark-mode primary: lightened azure, accessible on deep ink. */
val LightAzure = Color(0xFF8FB0DE)

/** Dark-mode primary text: bone-ish, never pure white. */
val BoneText = Color(0xFFF2EFE7)

/** Dark-mode secondary text. */
val SlateText = Color(0xFFA9B1C4)

/** Azure-tinted container (dark mode). */
val AzureContainerDark = Color(0xFF22406C)

/** On-azure-container (dark mode). */
val OnAzureContainerDark = Color(0xFFD8E4F5)

/** Slate-tinted container (dark mode). */
val SlateContainerDark = Color(0xFF2A3550)

/** On-slate-container (dark mode). */
val OnSlateContainerDark = Color(0xFFDCE0EA)

/** Tertiary (dark mode). */
val TertiaryDark = Color(0xFFA9C2E4)

/** Tertiary container (dark mode). */
val TertiaryContainerDark = Color(0xFF1D3050)

/** Error red (dark mode). */
val ErrorDark = Color(0xFFE8705B)

/** Error container (dark mode). */
val ErrorContainerDark = Color(0xFF5C1A0E)

/** On-error-container (dark mode). */
val OnErrorContainerDark = Color(0xFFF6DAD3)

/** 1dp hairline border in dark mode: bone text at 10% alpha. */
val OutlineDarkToken = Color(0x1AF2EFE7)

/** Softer divider in dark mode: bone text at 6% alpha. */
val OutlineVariantDarkToken = Color(0x0FF2EFE7)

// Dark surface-container ladder (ink-tinted)
val SurfaceDimDark = Color(0xFF0D1524)
val SurfaceBrightDark = Color(0xFF2A3856)
val SurfaceContainerLowestDark = Color(0xFF0A111D)
val SurfaceContainerLowDark = Color(0xFF121D33)
val SurfaceContainerDark = Color(0xFF16213A)
val SurfaceContainerHighDark = Color(0xFF1D2A47)
val SurfaceContainerHighestDark = Color(0xFF243354)

// ---------------------------------------------------------------------------
// Semantic accents (use sparingly)
// ---------------------------------------------------------------------------

/** Warning/expiring orange, light mode. */
val WarningLight = Color(0xFFE8890C)

/** Warning/expiring orange, dark mode. */
val WarningDark = Color(0xFFF5A83E)

// ---------------------------------------------------------------------------
// Background gradients (names are referenced by HomeScreen/OnboardingScreen —
// keep the names; values are Wing-toned).
// Connected: azure sweeping into deep azure/ink; white/bone content sits on it.
// Disconnected: quiet bone neutrals (light) / deep-ink neutrals (dark).
// ---------------------------------------------------------------------------

val GradientConnectedStartLight = Color(0xFF24548F)
val GradientConnectedEndLight = Color(0xFF16294D)
val GradientConnectedStartDark = Color(0xFF1E3A63)
val GradientConnectedEndDark = Color(0xFF0D1B33)

val GradientDisconnectedStartLight = Color(0xFFF1EDE3)
val GradientDisconnectedEndLight = Color(0xFFE5E0D2)
val GradientDisconnectedStartDark = Color(0xFF141F37)
val GradientDisconnectedEndDark = Color(0xFF0C1322)

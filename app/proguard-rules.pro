# ============================================================================
# NativeBridge — JNI methods called from C and callback interface
# ============================================================================
-keep class com.mythaia.vpn.NativeBridge { *; }
-keep interface com.mythaia.vpn.NativeBridge$LwipCallback { *; }
# quic_conn_bridge.c resolves onCryptoData/onStreamData/onStreamClose/
# onHandshakeComplete/onDatagram by name on whatever object implements this.
-keep interface com.mythaia.vpn.NativeBridge$QuicCallback { *; }
-keep class * implements com.mythaia.vpn.NativeBridge$QuicCallback { <methods>; }

# ============================================================================
# VPN Service + Binder (accessed via reflection by Android framework)
# ============================================================================
-keep class com.mythaia.vpn.MythaiaVpnService { *; }
-keep class com.mythaia.vpn.MythaiaVpnService$LocalBinder { *; }

# ============================================================================
# @Serializable data classes, enums, and custom serializers
# ============================================================================
-keep class com.mythaia.data.model.ProxyConfiguration { *; }
-keep class com.mythaia.data.model.OutboundProtocol { *; }
-keep class com.mythaia.data.model.NaiveProtocol { *; }
-keep class com.mythaia.data.model.ProxyChain { *; }
-keep class com.mythaia.data.model.TlsConfiguration { *; }
-keep class com.mythaia.data.model.RealityConfiguration { *; }
-keep class com.mythaia.data.model.WebSocketConfiguration { *; }
-keep class com.mythaia.data.model.HttpUpgradeConfiguration { *; }
-keep class com.mythaia.data.model.XHttpConfiguration { *; }
-keep class com.mythaia.data.model.XHttpMode { *; }
-keep class com.mythaia.data.model.TlsFingerprint { *; }
-keep class com.mythaia.data.model.Subscription { *; }
-keep class com.mythaia.data.model.DomainRule { *; }
-keep class com.mythaia.data.model.DomainRuleType { *; }

# Custom serializers
-keep class com.mythaia.data.model.UuidSerializer { *; }
-keep class com.mythaia.data.model.Base64UrlByteArraySerializer { *; }
-keep class com.mythaia.data.model.HexByteArraySerializer { *; }

# Generated $$serializer companion classes
-keepclassmembers class com.mythaia.data.model.** {
    *** Companion;
}
-keepclasseswithmembers class com.mythaia.data.model.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# ============================================================================
# Compose Navigation route objects (serialized for type-safe nav)
# ============================================================================
-keep class com.mythaia.ui.navigation.HomeRoute { *; }
-keep class com.mythaia.ui.navigation.ProxiesRoute { *; }
-keep class com.mythaia.ui.navigation.ChainsRoute { *; }
-keep class com.mythaia.ui.navigation.SettingsRoute { *; }

# ============================================================================
# kotlinx.serialization infrastructure
# ============================================================================
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.**
-keepclassmembers class kotlinx.serialization.json.** { *** Companion; }
-keepclasseswithmembers class kotlinx.serialization.json.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# ============================================================================
# Standard enum keepclassmembers
# ============================================================================
-keepclassmembers enum com.mythaia.** {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# ============================================================================
# Crash reporting — preserve source file and line numbers
# ============================================================================
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# ============================================================================
# javax.crypto.KEM (JDK 21 / Android 15+ API 35). Guarded by Build.VERSION
# checks at runtime; not present in compile SDK stubs.
# ============================================================================
-dontwarn javax.crypto.KEM
-dontwarn javax.crypto.KEM$Decapsulator
-dontwarn javax.crypto.KEM$Encapsulator
-dontwarn javax.crypto.KEM$Encapsulated

# ============================================================================
# ML Kit barcode scanner. The AAR ships consumer ProGuard rules, but the
# Play-Services variant loads internal GMS classes by reflected name at
# runtime. Explicit keeps defend against the scanner crashing with
# `NoClassDefFoundError` / `ClassNotFoundException` on release builds.
# ============================================================================
-keep class com.google.mlkit.** { *; }
-keep class com.google.android.gms.internal.mlkit_** { *; }
-keep class com.google.android.gms.vision.** { *; }
-dontwarn com.google.mlkit.**
-dontwarn com.google.android.gms.internal.mlkit_**

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// The platform-free half of Mythaia: models, share links, subscriptions,
// every outbound protocol and the TLS stack. The Android app and the Windows
// desktop app both build on it; nothing here may import android.*.
plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_11)
    }
}

sourceSets {
    main { kotlin.srcDirs("src/main/kotlin") }
    test { kotlin.srcDirs("src/test/kotlin") }
}

dependencies {
    api(libs.kotlinx.serialization.json)
    api(libs.coroutines.core)
    api(libs.bouncycastle.bcprov)
    api(libs.bouncycastle.bcpkix)
    api(libs.brotli.dec)
    // Android ships org.json in the platform; the desktop app adds the jar.
    compileOnly(libs.json)

    testImplementation(libs.junit)
    testImplementation(libs.json)
}

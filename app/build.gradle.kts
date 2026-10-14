import java.util.Properties

val localProperties = Properties().apply {
    val file = rootProject.file("local.properties")
    if (file.exists()) load(file.inputStream())
}

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "com.mythaia"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "com.mythaia"
        minSdk = 26
        targetSdk = 36
        versionCode = 22
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    // Read from local.properties or the environment (CI). A release build with
    // nothing configured fails here, before the NDK and R8 spend minutes on it.
    fun releaseProperty(name: String): String? =
        localProperties.getProperty(name)?.takeIf { it.isNotBlank() }
            ?: System.getenv(name)?.takeIf { it.isNotBlank() }
    val keystorePath = releaseProperty("KEYSTORE_FILE")
    val hasReleaseSigning = keystorePath != null &&
        releaseProperty("KEYSTORE_PASSWORD") != null &&
        releaseProperty("KEY_PASSWORD") != null

    signingConfigs {
        if (hasReleaseSigning) {
            create("release") {
                storeFile = file(keystorePath!!)
                storePassword = releaseProperty("KEYSTORE_PASSWORD")
                keyAlias = releaseProperty("KEY_ALIAS") ?: "release"
                keyPassword = releaseProperty("KEY_PASSWORD")
            }
        }
    }

    // Only this module's release tasks need the key; the Windows app's
    // createReleaseDistributable must not trip the check on a machine (or a
    // CI runner) that has none.
    val wantsRelease = gradle.startParameter.taskNames.any { name ->
        name.contains("Release", ignoreCase = true) && (name.startsWith(":app:") || !name.startsWith(":"))
    }
    if (wantsRelease && !hasReleaseSigning) {
        error(
            "Release signing is not configured. Set KEYSTORE_FILE, KEYSTORE_PASSWORD, " +
                "KEY_ALIAS and KEY_PASSWORD in local.properties or the environment."
        )
    }

    buildTypes {
        // Debug builds also carry x86_64 so they run on the emulator (the
        // test AVD is x86_64); release stays arm64-only.
        debug {
            ndk {
                abiFilters += listOf("x86_64")
            }
        }
        release {
            // `-Pmythaia.releaseX86=true` adds x86_64, so the R8-shrunk build
            // can be tested on the emulator before it reaches a phone.
            if (project.findProperty("mythaia.releaseX86") == "true") {
                ndk { abiFilters += listOf("x86_64") }
            }
            // `-Pmythaia.universal=true` builds one APK for every CPU: older
            // and cheaper phones are still 32-bit ARM.
            if (project.findProperty("mythaia.universal") == "true") {
                ndk { abiFilters += listOf("armeabi-v7a", "x86", "x86_64") }
            }
            isMinifyEnabled = true
            isShrinkResources = true
            if (hasReleaseSigning) signingConfig = signingConfigs.getByName("release")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    lint {
        // Fail the build on anything lint calls an error. Warnings are worked
        // through rather than baselined, so the few that remain are here with
        // a reason.
        warningsAsErrors = false
        abortOnError = true

        disable += setOf(
            // "A newer version exists." True of every dependency, always.
            // Upgrading AGP, Kotlin or a library is a deliberate change with
            // its own testing, not something to be prompted into by a build.
            "GradleDependency",
            "NewerVersionAvailable",
            "AndroidGradlePluginVersion",

            // The app ships arm64-v8a only, which is what every Android phone
            // and TV box this targets runs. Adding x86_64 for ChromeOS would
            // double the native build and the APK for a platform that cannot
            // run a VPN service anyway.
            "ChromeOsAbiSupport",

            // mipmap-anydpi-v26 is where the adaptive icon belongs: dropping
            // the qualifier makes AAPT fail to resolve mipmap/ic_launcher.
            "ObsoleteSdkInt",

            // Fires on an empty checkServerTrusted inside the BouncyCastle
            // bcpkix jar, not our code. We pull bcpkix in only to mint X.509
            // certificates for the MITM authority; our own TLS trust decisions
            // live in TlsPeerVerifier, which this does not touch. Scanning a
            // dependency's bytecode for this is a false positive here.
            "TrustAllX509TrustManager",
        )
    }

    testOptions {
        unitTests {
            // The android.jar on the unit-test classpath is a stub whose every
            // method throws. Returning defaults instead lets code that logs on
            // a branch be tested at all, rather than the logging call itself
            // failing the test.
            isReturnDefaultValues = true
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/jni/CMakeLists.txt")
        }
    }
}

dependencies {
    implementation(project(":core"))
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.extended)
    implementation(libs.navigation.compose)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.camerax.camera2)
    implementation(libs.camerax.lifecycle)
    implementation(libs.camerax.view)
    implementation(libs.mlkit.barcode)
    implementation(libs.play.services.wearable)
    implementation(libs.coroutines.android)
    implementation(libs.bouncycastle.bcprov)
    implementation(libs.bouncycastle.bcpkix)
    implementation(libs.androidx.work.runtime.ktx)
    implementation(libs.brotli.dec)
    testImplementation(libs.junit)
    // android.jar ships org.json as stubs too, and these tests parse real
    // VMess links — so they need an implementation that actually parses.
    testImplementation(libs.json)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
}

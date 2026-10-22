import java.util.Properties

val localProperties = Properties().apply {
    val file = rootProject.file("local.properties")
    if (file.exists()) load(file.inputStream())
}

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.mythaia.wear"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        // The same applicationId as the phone app, which is what pairs the two:
        // installing the phone app offers the watch app on the paired watch.
        applicationId = "com.mythaia"
        minSdk = 30
        targetSdk = 36
        versionCode = 31
        versionName = "1.4.0"
    }

    // The phone app's release key, read the same way (local.properties, then
    // the environment): the Data Layer only pairs a watch app and a phone app
    // signed with the same key. Without one, a release build is left unsigned.
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

    buildTypes {
        release {
            isMinifyEnabled = false
            if (hasReleaseSigning) signingConfig = signingConfigs.getByName("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
        }
    }

    buildFeatures {
        compose = true
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.activity.compose)
    implementation(libs.wear.compose.material)
    implementation(libs.wear.compose.foundation)
    implementation(libs.play.services.wearable)
    implementation(libs.coroutines.android)

    testImplementation(libs.junit)
}

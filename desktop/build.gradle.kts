import org.jetbrains.compose.desktop.application.dsl.TargetFormat
import java.util.Properties

// Mythaia Pro for Windows and macOS: Compose for Desktop over the shared core.
plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.compose.multiplatform)
    alias(libs.plugins.kotlin.compose)
}

val localProperties = Properties().apply {
    val file = rootProject.file("local.properties")
    if (file.exists()) load(file.inputStream())
}

// jpackage needs a JDK that ships jmods; Android Studio's runtime does not.
val packagingJdk: String? = localProperties.getProperty("desktop.jdk")?.takeIf { it.isNotBlank() }
    ?: System.getenv("MYTHAIA_DESKTOP_JDK")?.takeIf { it.isNotBlank() }
    ?: listOf("C:/Program Files/Java/jdk-21").firstOrNull { file(it).isDirectory }

sourceSets {
    main { kotlin.srcDirs("src/main/kotlin") }
    test { kotlin.srcDirs("src/test/kotlin") }
}

dependencies {
    implementation(project(":core"))
    implementation(compose.desktop.currentOs)
    implementation(compose.material3)
    implementation(compose.materialIconsExtended)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.coroutines.core)
    implementation(libs.coroutines.swing)
    implementation(libs.json)
    implementation(libs.jna)
    implementation(libs.jna.platform)
    implementation(libs.zxing.core)
    implementation(libs.zxing.javase)

    testImplementation(libs.junit)
}

// The JNI library is built into desktop/native/out: by build.cmd (MSVC) on
// Windows, where fetch-wintun.cmd puts wintun.dll and its licence beside it,
// and by native/macos/build.sh on macOS. It is copied next to the app's other
// resources, in the folder the Compose plugin picks for the build machine, so
// the packaged app and `gradle :desktop:run` find it.
val hostOs: String = System.getProperty("os.name").orEmpty()
val isMacHost = hostOs.startsWith("Mac")
val hostArch = if (System.getProperty("os.arch") in listOf("aarch64", "arm64")) "arm64" else "x64"
val nativeLibraryName = if (isMacHost) "libmythaia_native.dylib" else "mythaia_native.dll"

val prepareNative by tasks.registering(Copy::class) {
    from(layout.projectDirectory.dir("native/out")) {
        include(nativeLibraryName, "wintun.dll", "wintun-LICENSE.txt")
    }
    into(layout.projectDirectory.dir(if (isMacHost) "resources/macos-$hostArch" else "resources/windows-x64"))
}

tasks.configureEach {
    if (name == "run" || name.startsWith("createDistributable") || name.startsWith("package") ||
        name.startsWith("createReleaseDistributable") || name == "prepareAppResources") {
        dependsOn(prepareNative)
    }
}

// Tests load the JNI library from the native build output when it is there.
tasks.withType<Test>().configureEach {
    val dll = layout.projectDirectory.file("native/out/$nativeLibraryName").asFile
    if (dll.isFile) systemProperty("mythaia.native.library", dll.absolutePath)
    testLogging { showStandardStreams = false }
}

compose.desktop {
    application {
        mainClass = "com.mythaia.desktop.MainKt"
        packagingJdk?.let { javaHome = it }

        // Compose scales for HiDPI itself; forcing Java2D scaling on top doubled it.
        // The appearance flag gives macOS windows a title bar that follows dark mode.
        jvmArgs("-Dfile.encoding=UTF-8", "-Dapple.awt.application.appearance=system")

        nativeDistributions {
            targetFormats(TargetFormat.Msi, TargetFormat.Exe, TargetFormat.Dmg)
            packageName = "Mythaia Pro"
            packageVersion = "1.3.0"
            description = "Mythaia Pro proxy client"
            vendor = "Mythaia"
            copyright = "Mythaia"
            // What jdeps finds plus the JSSE curves for DoH/DoT and JNA's needs.
            modules("java.instrument", "java.naming", "java.sql", "jdk.unsupported", "jdk.crypto.ec", "java.management")
            appResourcesRootDir.set(project.layout.projectDirectory.dir("resources"))

            windows {
                iconFile.set(project.file("icon/mythaia.ico"))
                menuGroup = "Mythaia"
                shortcut = true
                menu = true
                perUserInstall = true
                dirChooser = true
                upgradeUuid = "7d3f1c2e-6a0b-4b5e-9c1d-2f8a4e6b7c90"
            }

            macOS {
                bundleID = "com.mythaia.desktop"
                dockName = "Mythaia Pro"
                appCategory = "public.app-category.utilities"
                minimumSystemVersion = "12.0"
                iconFile.set(project.file("icon/mythaia.icns"))
                // The links the app opens from a browser, as on Windows and Android.
                infoPlist {
                    extraKeysRawXml = macUrlTypes
                }
            }
        }

        buildTypes.release.proguard {
            isEnabled.set(false)
        }
    }
}

/** CFBundleURLTypes for the Info.plist: mythaia:// and the proxy share-link schemes. */
val macUrlTypes: String
    get() {
        val schemes = listOf("mythaia", "vless", "vmess", "trojan", "ss", "socks5", "hysteria2", "hy2", "anytls", "tuic")
        return buildString {
            appendLine("<key>CFBundleURLTypes</key>")
            appendLine("<array>")
            appendLine("  <dict>")
            appendLine("    <key>CFBundleURLName</key>")
            appendLine("    <string>com.mythaia.desktop.links</string>")
            appendLine("    <key>CFBundleTypeRole</key>")
            appendLine("    <string>Viewer</string>")
            appendLine("    <key>CFBundleURLSchemes</key>")
            appendLine("    <array>")
            schemes.forEach { appendLine("      <string>$it</string>") }
            appendLine("    </array>")
            appendLine("  </dict>")
            appendLine("</array>")
        }
    }

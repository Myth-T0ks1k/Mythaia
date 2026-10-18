import org.jetbrains.compose.desktop.application.dsl.TargetFormat
import java.util.Properties

// Mythaia Pro for Windows: Compose for Desktop over the shared core.
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

// The JNI library is built by desktop/native/build.cmd (MSVC) into
// desktop/native/out, and desktop/native/fetch-wintun.cmd puts wintun.dll
// (plus its licence) there too; both are copied next to the app's other
// resources so the packaged app and `gradle :desktop:run` find them.
val prepareNative by tasks.registering(Copy::class) {
    from(layout.projectDirectory.dir("native/out")) {
        include("mythaia_native.dll", "wintun.dll", "wintun-LICENSE.txt")
    }
    into(layout.projectDirectory.dir("resources/windows-x64"))
}

tasks.configureEach {
    if (name == "run" || name.startsWith("createDistributable") || name.startsWith("package") ||
        name.startsWith("createReleaseDistributable") || name == "prepareAppResources") {
        dependsOn(prepareNative)
    }
}

// Tests load the JNI library from the native build output when it is there.
tasks.withType<Test>().configureEach {
    val dll = layout.projectDirectory.file("native/out/mythaia_native.dll").asFile
    if (dll.isFile) systemProperty("mythaia.native.library", dll.absolutePath)
    testLogging { showStandardStreams = false }
}

compose.desktop {
    application {
        mainClass = "com.mythaia.desktop.MainKt"
        packagingJdk?.let { javaHome = it }

        // Compose scales for HiDPI itself; forcing Java2D scaling on top doubled it.
        jvmArgs(
            "-Dfile.encoding=UTF-8",
            // A crash in native code leaves its report next to the app, where
            // the next start collects it into the log (CrashReporting); the JVM
            // falls back to the working directory and %TEMP% where it cannot write.
            "-XX:ErrorFile=\$APPDIR/hs_err_pid%p.log",
            // Skia's Direct3D errors go to %USERPROFILE%\.skiko instead of nowhere.
            "-Dskiko.win.exception.logger.enabled=true"
        )

        nativeDistributions {
            targetFormats(TargetFormat.Msi, TargetFormat.Exe)
            packageName = "Mythaia Pro"
            packageVersion = "1.3.1"
            description = "Mythaia Pro proxy client"
            vendor = "Mythaia"
            copyright = "Mythaia"
            // What jdeps finds plus the JSSE curves for DoH/DoT and JNA's needs.
            // jdk.accessibility: where Java Access Bridge is on (screen readers
            // turn it on), AWT loads it at start and, missing, refuses to start.
            modules("java.instrument", "java.naming", "java.sql", "jdk.unsupported", "jdk.crypto.ec", "java.management", "jdk.accessibility")
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
        }

        buildTypes.release.proguard {
            isEnabled.set(false)
        }
    }
}

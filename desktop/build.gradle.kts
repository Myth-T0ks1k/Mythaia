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

// The JNI library and the proxy guard are built by desktop/native/build.cmd
// (MSVC) into desktop/native/out, and desktop/native/fetch-wintun.cmd puts
// wintun.dll (plus its licence) there too; all are copied next to the app's
// other resources so the packaged app and `gradle :desktop:run` find them.
val prepareNative by tasks.registering(Copy::class) {
    from(layout.projectDirectory.dir("native/out")) {
        include("mythaia_native.dll", "mythaia-proxy-guard.exe", "wintun.dll", "wintun-LICENSE.txt")
    }
    // JNA's own native part. Left in the jar, JNA unpacks it into %TEMP% on
    // first use, where antivirus and AppLocker block DLLs and every registry,
    // Wintun and service call then fails; shipped with the app it is loaded
    // from there (jna.boot.library.path below, Main.configureJna).
    from(configurations.runtimeClasspath.map { classpath ->
        classpath.filter { it.name.startsWith("jna-") && !it.name.startsWith("jna-platform") }.map { zipTree(it) }
    }) {
        include("com/sun/jna/win32-x86-64/jnidispatch.dll")
        eachFile { path = name }
        includeEmptyDirs = false
    }
    into(layout.projectDirectory.dir("resources/windows-x64"))
}

/**
 * The Windows SDK's manifest tool: `desktop.mt` in local.properties,
 * MYTHAIA_MT, or the newest one under Windows Kits.
 */
fun findManifestTool(): File? {
    (localProperties.getProperty("desktop.mt") ?: System.getenv("MYTHAIA_MT"))
        ?.takeIf { it.isNotBlank() }?.let { return File(it).takeIf(File::isFile) }
    val bin = File("C:/Program Files (x86)/Windows Kits/10/bin")
    return bin.listFiles().orEmpty()
        .filter { it.isDirectory && it.name.startsWith("10.") }
        .sortedByDescending { dir -> dir.name.split('.').map { it.toIntOrNull() ?: 0 }.fold(0L) { acc, part -> acc * 100_000 + part } }
        .map { File(it, "x64/mt.exe") }
        .firstOrNull { it.isFile }
}

fun runTool(vararg command: String): String {
    val process = ProcessBuilder(*command).redirectErrorStream(true).start()
    val output = process.inputStream.bufferedReader().readText()
    if (process.waitFor() != 0) throw GradleException("${command.first()} failed (${process.exitValue()}): $output")
    return output
}

// The launcher gets UTF-8 as its ANSI code page (Windows 10 1903 and
// later). The JVM loads its own DLLs, skiko's, JNA's and ours through ANSI
// calls, so on a PC whose code page cannot spell the install folder (a
// Turkmen ň, ş or ý under a Russian or English system locale, often in the
// user name of a per-user install) the app used to quit before showing
// anything. The installers are made from this image, so they carry it too.
// Without the SDK tool the build fails rather than ship without it; pass
// -Pmythaia.skipLauncherManifest=true to build anyway.
val launcherManifest = layout.projectDirectory.file("launcher/utf8-codepage.manifest")
tasks.withType<org.jetbrains.compose.desktop.application.tasks.AbstractJPackageTask>()
    .matching { it.name == "createDistributable" || it.name == "createReleaseDistributable" }
    .configureEach {
        inputs.file(launcherManifest)
        val skip = providers.gradleProperty("mythaia.skipLauncherManifest").map { it.toBoolean() }.orElse(false)
        doLast {
            val exe = destinationDir.get().asFile.resolve("Mythaia Pro/Mythaia Pro.exe")
            if (!exe.isFile) throw GradleException("No launcher at $exe")
            val mt = findManifestTool()
            if (mt == null) {
                if (skip.get()) {
                    logger.warn("mt.exe not found: ${exe.name} keeps the system code page")
                    return@doLast
                }
                throw GradleException("mt.exe (Windows SDK) not found; set desktop.mt in local.properties or pass -Pmythaia.skipLauncherManifest=true")
            }
            // jpackage writes the launcher read-only.
            exe.setWritable(true)
            val manifest = launcherManifest.asFile.absolutePath
            runTool(mt.absolutePath, "-nologo", "-inputresource:${exe.absolutePath};#1", "-manifest", manifest, "-outputresource:${exe.absolutePath};#1")
            val check = File(temporaryDir, "launcher.manifest")
            runTool(mt.absolutePath, "-nologo", "-inputresource:${exe.absolutePath};#1", "-out:${check.absolutePath}")
            if (!check.readText().contains("<activeCodePage>UTF-8</activeCodePage>")) {
                throw GradleException("The launcher manifest did not take the UTF-8 code page")
            }
            logger.lifecycle("Launcher manifest: UTF-8 code page")
        }
    }

tasks.configureEach {
    if (name == "run" || name.startsWith("createDistributable") || name.startsWith("package") ||
        name.startsWith("createReleaseDistributable") || name == "prepareAppResources") {
        dependsOn(prepareNative)
    }
}

// Tests load the JNI library from the native build output when it is there.
// They never see the real data folder or the real proxy settings: APPDATA
// is a folder under build/, and SystemProxy writes to a key of its own
// (removed by the tests that use it), so a test run on a PC whose Mythaia
// is connected cannot undo or overwrite that connection's proxy.
tasks.withType<Test>().configureEach {
    val dll = layout.projectDirectory.file("native/out/mythaia_native.dll").asFile
    if (dll.isFile) systemProperty("mythaia.native.library", dll.absolutePath)
    val appData = layout.buildDirectory.dir("test-appdata").get().asFile
    doFirst { appData.mkdirs() }
    environment("APPDATA", appData.absolutePath)
    systemProperty("mythaia.test.registryRoot", "Software\\MythaiaTest\\desktop-test")
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
            "-Dskiko.win.exception.logger.enabled=true",
            // JNA's jnidispatch.dll ships in resources (prepareNative) and is
            // loaded from there, never from the system path. Main.configureJna
            // also stops the %TEMP% unpacking once it sees the file there.
            "-Djna.boot.library.path=\$APPDIR/resources",
            "-Djna.nosys=true"
        )

        nativeDistributions {
            targetFormats(TargetFormat.Msi, TargetFormat.Exe)
            packageName = "Mythaia Pro"
            packageVersion = "1.4.0"
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

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

    testImplementation(libs.junit)
}

// The JNI library is built by desktop/native/build.cmd (MSVC) into
// desktop/native/out; it is copied next to the app's other resources so the
// packaged app and `gradle :desktop:run` both find it.
val prepareNative by tasks.registering(Copy::class) {
    from(layout.projectDirectory.file("native/out/mythaia_native.dll"))
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

        jvmArgs("-Dfile.encoding=UTF-8", "-Dsun.java2d.uiScale.enabled=true")

        nativeDistributions {
            targetFormats(TargetFormat.Msi, TargetFormat.Exe)
            packageName = "Mythaia Pro"
            packageVersion = "1.9.0"
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
        }

        buildTypes.release.proguard {
            isEnabled.set(false)
        }
    }
}

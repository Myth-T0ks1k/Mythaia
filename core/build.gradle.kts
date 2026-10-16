import org.jetbrains.kotlin.gradle.dsl.JvmTarget

// The platform-free half of Mythaia: models, share links, subscriptions,
// every outbound protocol and the TLS stack. The Android app and the Windows
// desktop app both build on it; nothing here may import android.*.
plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    `maven-publish`
}

group = "com.mythaia"
version = "1.2.0"

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
    withSourcesJar()
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

// Published to GitHub Packages as com.mythaia:mythaia-core by the
// "Publish core library" workflow when a release goes out.
publishing {
    publications {
        create<MavenPublication>("core") {
            artifactId = "mythaia-core"
            from(components["java"])
            pom {
                name.set("Mythaia core")
                description.set("The platform-free protocol stack of Mythaia: share links, subscriptions, every outbound protocol and the TLS stack.")
                url.set("https://github.com/Myth-T0ks1k/Mythaia")
                licenses {
                    license {
                        name.set("GNU General Public License v3.0")
                        url.set("https://www.gnu.org/licenses/gpl-3.0.html")
                    }
                }
                scm {
                    url.set("https://github.com/Myth-T0ks1k/Mythaia")
                    connection.set("scm:git:https://github.com/Myth-T0ks1k/Mythaia.git")
                }
            }
        }
    }
    repositories {
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/Myth-T0ks1k/Mythaia")
            credentials {
                username = System.getenv("GITHUB_ACTOR")
                password = System.getenv("GITHUB_TOKEN")
            }
        }
    }
}

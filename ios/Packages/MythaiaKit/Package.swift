// swift-tools-version: 5.10

import PackageDescription

// The platform-free half of Mythaia for Apple platforms: models, share links,
// subscriptions, every outbound protocol and the local proxy engine. The iOS
// app and its packet tunnel both build on it. It is a Swift port of the
// Kotlin `core` module and uses only the system frameworks (Foundation,
// Network, CryptoKit, Security, SQLite3) plus the repository's own vendored C.
let package = Package(
    name: "MythaiaKit",
    defaultLocalization: "en",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(name: "MythaiaKit", targets: ["MythaiaKit"]),
    ],
    targets: [
        // QUIC for Hysteria2 and TUIC: the vendored ngtcp2 with its mbedTLS
        // crypto backend, and the plain-C bridge Swift drives it through
        // (include/cquic.h). The vendored sources are not committed here:
        // ios/bootstrap.sh copies them from app/src/main/jni into vendor/,
        // and has to run before the first build.
        //
        // The search paths are deliberately narrow. vendor/ngtcp2 holds both
        // the library's lib-internal ngtcp2_crypto.h and, under ngtcp2/, the
        // public helper header of the same name; adding vendor/ itself would
        // make <ngtcp2/ngtcp2_crypto.h> resolve to the internal one. The
        // Darwin config.h sits in vendor/ngtcp2, which HAVE_CONFIG_H makes
        // ngtcp2 include; mbedTLS finds its minimal config as its default
        // mbedtls/mbedtls_config.h, so no config file has to be named.
        .target(
            name: "CQuic",
            cSettings: [
                .headerSearchPath("vendor/ngtcp2"),
                .headerSearchPath("vendor/mbedtls/include"),
                .define("HAVE_CONFIG_H"),
            ]
        ),
        // The routing rules database (Rules.db) is not bundled here: the app
        // and the tunnel take the one file the Android app ships
        // (app/src/main/assets/Rules.db) as a resource, and RulesDatabase
        // opens it from their bundle.
        .target(
            name: "MythaiaKit",
            dependencies: ["CQuic"]
        ),
        .testTarget(
            name: "MythaiaKitTests",
            dependencies: ["MythaiaKit"]
        ),
    ]
)

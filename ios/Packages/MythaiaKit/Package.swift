// swift-tools-version: 5.9

import PackageDescription

// The platform-free half of Mythaia for Apple platforms: models, share links,
// subscriptions, every outbound protocol and the local proxy engine. The iOS
// app and its packet tunnel both build on it. It is a Swift port of the
// Kotlin `core` module and uses only the system frameworks (Foundation,
// Network, CryptoKit, Security, SQLite3).
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
        // The routing rules database (Rules.db) is not bundled here: the app
        // and the tunnel take the one file the Android app ships
        // (app/src/main/assets/Rules.db) as a resource, and RulesDatabase
        // opens it from their bundle.
        .target(
            name: "MythaiaKit"
        ),
        .testTarget(
            name: "MythaiaKitTests",
            dependencies: ["MythaiaKit"]
        ),
    ]
)

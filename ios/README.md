# Mythaia Pro for iOS

A native Swift app with a packet tunnel extension. The protocol stack
(`Packages/MythaiaKit`) is a Swift port of the Kotlin `core` that the Android
and desktop apps share, so links, subscriptions, Happ metadata, Auto and the
country bypass behave the same everywhere. See [ARCHITECTURE.md](ARCHITECTURE.md).

## Building

On a Mac with Xcode 16 or newer:

```sh
brew install xcodegen
cd ios
cp Config.example.xcconfig Config.xcconfig   # then set DEVELOPMENT_TEAM and the bundle id
xcodegen
open Mythaia.xcodeproj
```

The core alone builds and tests without Xcode's project:

```sh
cd ios/Packages/MythaiaKit
swift test
```

The `Apple` workflow (`.github/workflows/apple.yml`) does both on every push
to the `apple` branch and keeps an unsigned `.ipa` as a build artifact.

## Signing and installing

A VPN app on iOS needs the Network Extensions entitlement, which Apple grants
only to paid developer accounts. Without one the app builds, but iOS will not
let it start a tunnel:

| Route | Tunnel works | Needs |
|---|---|---|
| Xcode with a paid account (99 USD a year) | Yes | Team id in `Config.xcconfig`, bundle ids registered with *App Groups* and *Network Extensions* |
| TestFlight / App Store | Yes | The same account, plus App Store Connect |
| AltStore, Sideloadly with a free Apple ID | No | The free profile drops the Network Extension entitlement |
| TrollStore (devices and iOS versions it supports) | Yes | The unsigned `.ipa` from the workflow |

With a paid account: set `DEVELOPMENT_TEAM`, pick a bundle id you own for
`MYTHAIA_BUNDLE_ID` (the tunnel is `<bundle id>.Tunnel`, the App Group is
`group.<bundle id>`), enable both capabilities for both ids in the developer
portal, regenerate the project, and run on a device.

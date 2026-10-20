<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../assets/banner-dark.svg">
  <img alt="Mythaia — Reach anywhere." src="../assets/banner-light.svg" width="100%">
</picture>

<br>

[![Release](https://img.shields.io/github/v/release/Myth-T0ks1k/Mythaia?style=flat-square&color=24548F&label=release)](https://github.com/Myth-T0ks1k/Mythaia/releases/latest)
[![CI](https://img.shields.io/github/actions/workflow/status/Myth-T0ks1k/Mythaia/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Myth-T0ks1k/Mythaia/actions/workflows/ci.yml)
[![Android](https://img.shields.io/badge/Android-8.0%2B-3DDC84?style=flat-square&logo=android&logoColor=white)](#下载)
[![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D4?style=flat-square&logo=windows&logoColor=white)](#下载)
[![Kotlin](https://img.shields.io/badge/Kotlin-2.2-7F52FF?style=flat-square&logo=kotlin&logoColor=white)](https://kotlinlang.org)
[![License](https://img.shields.io/badge/license-GPL--3.0-14213A?style=flat-square)](../../LICENSE.txt)
[![Telegram](https://img.shields.io/badge/Telegram-%40mythaia-26A5E4?style=flat-square&logo=telegram&logoColor=white)](https://t.me/mythaia)
[![Chat](https://img.shields.io/badge/chat-%40mythaia__chat-26A5E4?style=flat-square&logo=telegram&logoColor=white)](https://t.me/mythaia_chat)

[English](../../README.md) · [Русский](README.ru.md) · [Türkmençe](README.tk.md) · **简体中文** · [فارسی](README.fa.md)

[网站](https://myth-t0ks1k.github.io/Mythaia/zh/) · [下载](#下载) · [功能](#功能) · [一条链接里的域前置](#一条链接里的域前置) · [构建](#从源码构建) · [更新日志](../../CHANGELOG.md)

</div>

---

Mythaia 是一款适用于 **Android** 和 **Windows** 的代理客户端，拥有完全用 Kotlin 从零编写的协议栈。
它无需封装 Xray-core 或 sing-box，即可使用 VLESS（含 Reality）、Hysteria2、TUIC、Trojan、Shadowsocks、
WireGuard 等协议，并专为严格过滤的网络而设计：域前置、ClientHello 分片、ECH、自动选择服务器和按国家绕行
都是应用本身的一部分，而不是附加组件。

<div align="center">
  <img src="../assets/screenshots/home.png" width="24%" alt="主界面，已连接">
  <img src="../assets/screenshots/proxies.png" width="24%" alt="订阅中的服务器">
  <img src="../assets/screenshots/add-fronting.png" width="24%" alt="添加带域前置的订阅">
  <img src="../assets/screenshots/settings.png" width="24%" alt="设置">
</div>

## 为什么选择 Mythaia

- **一套原生协议栈。** 协议、传输层、TLS 和路由均以 Kotlin 实现，仅用少量 C 库（lwIP、BLAKE3、libyaml、
  ngtcp2、Mbed TLS）处理最适合原生代码的部分。没有 Go 运行时，没有桥接层，APK 体积小巧。
- **两个平台，一个核心。** Android 与 Windows 应用共用同一个 `core` 模块，链接、订阅和修复在两端表现一致。
- **为受过滤的网络而生。** 订阅通过前置下载，服务器会持续测速并自动切换，本地流量留在本地，
  不安全的设置会以红色明确标出，而不是被隐藏。

## 功能

| | |
|---|---|
| **协议** | VLESS（Vision、Reality、ML-KEM 加密）、VMess、Trojan、Shadowsocks（AEAD 与 2022）、Hysteria2（Salamander、Brutal）、TUIC v5、AnyTLS、NaiveProxy（HTTP/1.1、HTTP/2）、WireGuard、SOCKS5、Sudoku |
| **传输** | TCP、支持 early data 的 WebSocket、HTTPUpgrade、gRPC、XHTTP（stream-one、stream-up、packet-up）、QUIC |
| **TLS** | 浏览器指纹（Chrome、Firefox、Safari、iOS、Edge）、Reality、ECH、ClientHello 分片、证书固定、按服务器设置并带醒目警告的 *allow insecure* |
| **路由** | 规则与全局模式、按域名/IP/GeoIP 的规则集、按国家绕行、按应用分流、广告拦截、Fake-IP DNS、DNS over HTTPS 与 TLS、IPv6 |
| **服务器** | 分享链接、二维码、Clash YAML、Xray 与 sing-box JSON、代理链、带 XUDP 的 Mux，可按 TCP（QUIC 服务器为 UDP）Ping、握手或真实 HTTP 请求测量延迟；导出为链接；删除不可用的服务器 |
| **订阅** | 面板提供的流量与到期时间、自动更新、服务商公告与兼容 Happ 的元数据（新地址、备用地址、信息块）、Remnawave HWID、**下载时的域前置**、通过可用服务器下载 |
| **自动** | 选出分组中最快的服务器，持续测速，仅在明显更快时才切换；服务器被封锁时自动重新连接 |
| **Android** | 快捷设置磁贴、桌面小部件、始终开启的 VPN、Android TV、Wear OS 配套应用、使用自有 CA 的 HTTPS 拦截、9 种语言 |
| **Windows** | 系统代理模式（同一端口支持 SOCKS5 与 HTTP）或基于 Wintun 的完整 TUN 模式、托盘图标，以及同样的服务器、订阅和自动选择 |

## 下载

最新版本见 **[Releases](https://github.com/Myth-T0ks1k/Mythaia/releases/latest)**。
新版本也会发布在 Telegram 频道 [@mythaia](https://t.me/mythaia)。

| 平台 | 文件 | 说明 |
|---|---|---|
| Android | `Mythaia-1.3.1-android-universal.apk` | 适用于所有设备：arm64、armeabi-v7a、x86、x86_64 |
| Android | `Mythaia-1.3.1-android-arm64-v8a.apk` | 体积更小，适用于现代手机 |
| Wear OS | `Mythaia-1.3.1-wear-os.apk` | 手机应用的配套应用，需要 Wear OS 3 或更高版本 |
| Windows | `Mythaia-Pro-1.3.1-windows-x64-setup.exe` | 按用户安装，无需管理员权限 |
| Windows | `Mythaia-Pro-1.3.1-windows-x64.msi` | 同上，MSI 安装包 |
| Windows | `Mythaia-Pro-1.3.1-windows-x64-portable.zip` | 解压到任意位置后运行 `Mythaia Pro.exe` |

每个版本都附有 `SHA256SUMS.txt`，列出所有文件的 SHA-256 校验值。需要 Android 8.0 或更高版本，
以及 Windows 10 或 11（x64）；在 Windows 上使用 TUN 模式时会请求管理员权限——每次都请求，或只在安装 Mythaia 服务时请求一次；
该服务从 Program Files 中自己的副本运行。

在 Windows 上也可以通过 Scoop 安装和更新：

```pwsh
scoop bucket add mythaia https://github.com/Myth-T0ks1k/scoop-bucket
scoop install mythaia/mythaia-pro
```

## 一条链接里的域前置

域名被封锁的面板，往往仍可通过未被封锁的 CDN 访问。Mythaia 下载订阅时会连接到**前置地址**（CDN 地址或
其上的其他域名），在 TLS 握手中发送一个无害的 **SNI**，而在 HTTP `Host` 头中填写面板的真实域名。

域前置设置可以直接放在链接里，收到链接的人一步即可添加订阅，无需手动输入：

```text
https://panel.example.com/sub/TOKEN#front=104.16.1.1,cdn.example.net:443&sni=www.example.org
```

```text
mythaia://import?url=https://panel.example.com/sub/TOKEN&front=104.16.1.1&sni=www.example.org
```

| 参数 | 含义 |
|---|---|
| `front` | 实际连接的地址：IP 或域名，可带 `:端口`（IPv6 写作 `[地址]:端口`）。用逗号分隔或重复该参数，按顺序尝试。 |
| `sni` | TLS 握手中发送的名称（也可写作 `front-sni`）。只填 `sni` 时，将以该名称连接面板自身的地址。 |
| `name` | 可选的分组名称。 |

- 第一种是普通 URL：`#` 之后的部分永远不会发送到面板，因此该链接在其他客户端中同样可用。
- 第二种可以直接从浏览器或聊天软件中打开 Mythaia。
- 粘贴、扫描或打开任意一种链接，添加窗口中的**域前置**字段都会自动填好，下载前即可核对。
- **订阅设置 → 复制带域前置的链接** 可以把已有的订阅转换成这样的链接，Android 和 Windows 均支持。

Happ 的写法也可以用：地址写前置域名，`host` 写面板：

```text
https://cdn.example.net/sub/TOKEN#My%20VPN?resolve-address=104.16.1.1&host=panel.example.com
```

## 订阅元数据

服务商可以像在 Happ 中那样控制订阅。每个键先从响应头读取，没有该响应头时，再从正文中的 `#key: value` 行读取——可在 base64 列表之上或其中。文本可以是明文或 `base64:`；开关在 `true` 或 `1` 时开启。

```text
#profile-title: base64:TXkgVlBO
#profile-update-interval: 6
#fallback-url: https://backup.example.com/sub/TOKEN
#sub-info-text: Maintenance tonight 02:00–03:00 UTC
#sub-info-color: blue
vless://…
```

| 键 | 作用 |
|---|---|
| `profile-title`, `subscription-userinfo` | 分组名称；流量与到期时间 |
| `announce`, `support-url`, `profile-web-page-url` | 服务商消息；“客服”和“账户页面”按钮 |
| `sub-info-text`, `sub-info-color` (`red`, `blue`, `green`), `sub-info-button-text`, `sub-info-button-link` | 带按钮的彩色提示块 |
| `sub-expire` (or `notification-subs-expire`), `sub-expire-button-link` | 到期前三天提醒，附“续费”按钮 |
| `profile-update-interval` | 后台更新间隔（小时） |
| `subscription-auto-update-open-enable` | 每次打开应用时更新 |
| `subscription-auto-update-enable: 0` | 此订阅不在后台更新 |
| `subscription-request-timeout` | 等待面板响应的秒数 |
| `new-url` | 订阅永久迁移到此地址（片段中的域前置也会读取） |
| `new-domain` | 同上，但保留路径和参数 |
| `fallback-url` | 主地址返回错误或 10 秒内无响应时，从此地址获取 |
| `fronting-target` (or `resolve-address`) | 代替面板去连接的地址，逗号分隔；`off` 关闭域前置 |
| `fronting-sni` | 要发送的 SNI |
| `host` | 与 `resolve-address` 一起使用：面板的真实主机，与 Happ 写法相同 |
| `routing` (`happ://routing/add/…`, `happ://routing/onadd/…`, `happ://routing/off`), `routing-enable` | 路由配置（直连、代理、拦截列表及 `geosite.dat` / `geoip.dat` 文件）；直接打开或粘贴 `happ://routing/…` 链接同样生效 |
| `subscription-autoconnect`, `subscription-autoconnect-type` (`lastused`, `lowestdelay`, `random`) | 启动时自动连接此订阅中的指定服务器 |
| `subscription-ping-onopen-enabled`, `ping-type` (`proxy`, `proxy-head`, `tcp`, `icmp`), `check-url-via-proxy` | 打开应用时测速；延迟测量方式与检测 URL |
| `change-user-agent` | 后续更新此订阅时发送的 `User-Agent` |
| `fragmentation-enable`, `fragmentation-packets`, `fragmentation-length`, `fragmentation-interval`, `fragmentation-maxsplit` | TLS 记录 / TCP 分片设置 |
| `exclude-routes`, `exclude-routes-set` | 排除在隧道外的额外 CIDR 网段（`off` 清空） |
| `per-app-proxy-mode` (`off`, `bypass`, `only`), `per-app-proxy-list` | Android 上按应用包名分应用代理 |
| `app-auto-start` | Android 开机启动 VPN 或 Windows 登录时启动 Mythaia |
| `subscriptions-sort-type` (`ping`, `alphabet`, `off`), `subscription-pin`, `subscriptions-collapse`, `subscriptions-expand-now` | 服务器排序方式、分组置顶与折叠状态 |
| `hide-settings` | 隐藏此订阅下服务器的配置编辑器和原始分享链接 |
| `serverDescription`（或 `description`） | 服务器链接参数或 JSON 对象中的简短说明，显示在服务器名称下方 |

`new-url`、`new-domain`、`fallback-url`、域前置相关键、路由配置以及修改应用设置的键，只在响应经由已验证的 HTTPS 到达时才生效：对于明文 HTTP 面板，路径上的任何人都可能重定向订阅或篡改设置。设置中的开关（**允许订阅更改应用设置**）可关闭远程设置修改，同时保留服务器列表和通知。当更新带来新的 `announce` 或 `sub-info-text`，或 `sub-expire` 进入三天提醒期时，应用还会为每条新消息发送一次系统通知。

更新失败时，底部会出现提示条，并提供 **通过可用服务器重试**：通过已连接的服务器或快速检测中响应最快的服务器下载订阅，即使面板被完全封锁也能更新。提示条会自动消失。

## 从源码构建

**环境要求：** JDK 21 和带有 36 版平台的 Android SDK。NDK 与 CMake 会在首次构建时由 Android Gradle
Plugin 自动安装。

```bash
git clone https://github.com/Myth-T0ks1k/Mythaia.git
cd Mythaia
./gradlew :app:assembleDebug                  # Android 调试版 APK
./gradlew :core:test :app:testDebugUnitTest   # 单元测试
```

正式版使用你自己的密钥签名。把以下内容写入 `local.properties`（该文件不会提交到仓库），
或设置为环境变量：

```properties
KEYSTORE_FILE=/path/to/release.jks
KEYSTORE_PASSWORD=...
KEY_ALIAS=...
KEY_PASSWORD=...
```

`./gradlew :app:assembleRelease` 构建 arm64 版 APK；加上 `-Pmythaia.universal=true` 则构建全部 ABI。

<details>
<summary><b>Windows 应用</b></summary>

<br>

原生库需要带有 MSVC、CMake 和 Ninja 的 Visual Studio 2022；打包需要带 `jmods` 的 JDK 21，
其路径写入 `local.properties` 的 `desktop.jdk`。

```bat
desktop\native\build.cmd
gradlew :desktop:run
gradlew :desktop:packageExe :desktop:packageMsi
```

生成安装包需要 `PATH` 中有 WiX 3.14。用户数据保存在 `%APPDATA%\Mythaia`。

</details>

## 项目结构

| 模块 | 说明 |
|---|---|
| [`core`](../../core) | 与平台无关的 Kotlin 代码：模型、分享链接、订阅、全部协议和 TLS 协议栈 |
| [`app`](../../app) | Android 应用：Jetpack Compose 界面、`VpnService` 以及基于 lwIP 的用户态 TCP/IP 协议栈 |
| [`wear`](../../wear) | Wear OS 应用：显示连接状态，一键开关 |
| [`desktop`](../../desktop) | Windows 应用：Compose for Desktop、系统代理与 Wintun TUN 引擎 |

`core` 模块也以 `com.mythaia:mythaia-core` 发布在
[GitHub Packages](https://github.com/Myth-T0ks1k?tab=packages&repo_name=Mythaia)。

## 参与贡献

欢迎提交问题报告、想法和 pull request。请先阅读 [CONTRIBUTING.md](../../CONTRIBUTING.md)；
安全问题请按 [SECURITY.md](../../SECURITY.md) 中的说明私下报告。

提问与讨论：Telegram 群组 [@mythaia_chat](https://t.me/mythaia_chat) 或 [GitHub Discussions](https://github.com/Myth-T0ks1k/Mythaia/discussions)。

## 许可证

Mythaia 是基于 [GNU General Public License v3.0](../../LICENSE.txt) 的自由软件。

本项目基于 NodePassProject 的 Anywhere（GPL-3.0），并包含
[lwIP](https://savannah.nongnu.org/projects/lwip/)、[BLAKE3](https://github.com/BLAKE3-team/BLAKE3)、
[libyaml](https://github.com/yaml/libyaml)、[ngtcp2](https://github.com/ngtcp2/ngtcp2)、[Mbed TLS](https://github.com/Mbed-TLS/mbedtls)、
[Wintun](https://www.wintun.net)、[Bouncy Castle](https://www.bouncycastle.org) 和
[Brotli](https://github.com/google/brotli)，它们各自遵循其许可证。路由规则集中的产品名称归各自所有者所有。

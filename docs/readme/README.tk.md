<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../assets/banner-dark.svg">
  <img alt="Mythaia — Reach anywhere." src="../assets/banner-light.svg" width="100%">
</picture>

<br>

[![Release](https://img.shields.io/github/v/release/Myth-T0ks1k/Mythaia?style=flat-square&color=24548F&label=release)](https://github.com/Myth-T0ks1k/Mythaia/releases/latest)
[![CI](https://img.shields.io/github/actions/workflow/status/Myth-T0ks1k/Mythaia/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Myth-T0ks1k/Mythaia/actions/workflows/ci.yml)
[![Android](https://img.shields.io/badge/Android-8.0%2B-3DDC84?style=flat-square&logo=android&logoColor=white)](#ýükläp-almak)
[![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D4?style=flat-square&logo=windows&logoColor=white)](#ýükläp-almak)
[![Kotlin](https://img.shields.io/badge/Kotlin-2.2-7F52FF?style=flat-square&logo=kotlin&logoColor=white)](https://kotlinlang.org)
[![License](https://img.shields.io/badge/license-GPL--3.0-14213A?style=flat-square)](../../LICENSE.txt)
[![Telegram](https://img.shields.io/badge/Telegram-%40mythaia-26A5E4?style=flat-square&logo=telegram&logoColor=white)](https://t.me/mythaia)
[![Chat](https://img.shields.io/badge/chat-%40mythaia__chat-26A5E4?style=flat-square&logo=telegram&logoColor=white)](https://t.me/mythaia_chat)

[English](../../README.md) · [Русский](README.ru.md) · **Türkmençe** · [简体中文](README.zh-CN.md) · [فارسی](README.fa.md)

[Ýükläp almak](#ýükläp-almak) · [Mümkinçilikler](#mümkinçilikler) · [Bir baglanyşykda fronting](#bir-baglanyşykda-fronting) · [Ýygnamak](#çeşme-kodundan-ýygnamak) · [Üýtgeşmeler](../../CHANGELOG.md)

</div>

---

Mythaia — **Android** we **Windows** üçin proksi kliýenti. Onuň öz tor steki bar we ol Kotlin dilinde
noldan ýazyldy. Xray-core ýa-da sing-box-a daýanman, Reality bilen VLESS, Hysteria2, TUIC, Trojan,
Shadowsocks, WireGuard we beýleki protokollar bilen işleýär. Programma güýçli süzgüçli torlar üçin
döredildi: domen frontingi, ClientHello bölmek, ECH, serweri awtomatik saýlamak we ýurt aýlawy
goşmaça däl-de, programmanyň öz bölegidir.

<div align="center">
  <img src="../assets/screenshots/home.png" width="24%" alt="Baş ekran, birikdirildi">
  <img src="../assets/screenshots/proxies.png" width="24%" alt="Abunanyň serwerleri">
  <img src="../assets/screenshots/add-fronting.png" width="24%" alt="Fronting bilen abuna goşmak">
  <img src="../assets/screenshots/settings.png" width="24%" alt="Sazlamalar">
</div>

## Näme üçin Mythaia

- **Bir ýerli stek.** Protokollar, transportlar, TLS we marşrutlaşdyrma Kotlin-de ýazyldy. Birnäçe
  kiçi C kitaphanasy (lwIP, BLAKE3, libyaml, ngtcp2, Mbed TLS) diňe ýerli kodda has gowy işleýän işleri edýär.
  Go gurşawy ýok, köpri ýok, APK ýeňil.
- **Iki platforma, bir ýadro.** Android we Windows programmalary umumy `core` modulyny ulanýar:
  baglanyşyk, abuna ýa-da düzediş iki ýerde-de birmeňzeş işleýär.
- **Süzgüçli torlar üçin döredildi.** Abunalar front arkaly ýüklenýär, serwerler täzeden ölçelýär we
  özbaşdak çalşylýar, ýerli trafik ýerli galýar, howply sazlamalar bolsa gizlenmän, gyzyl bilen
  bellenýär.

## Mümkinçilikler

| | |
|---|---|
| **Protokollar** | VLESS (Vision, Reality, ML-KEM şifrlemesi), VMess, Trojan, Shadowsocks (AEAD we 2022), Hysteria2 (Salamander, Brutal), TUIC v5, AnyTLS, NaiveProxy (HTTP/1.1, HTTP/2), WireGuard, SOCKS5, Sudoku |
| **Transportlar** | TCP, early data bilen WebSocket, HTTPUpgrade, gRPC, XHTTP (stream-one, stream-up, packet-up), QUIC |
| **TLS** | Brauzer barmak yzlary (Chrome, Firefox, Safari, iOS, Edge), Reality, ECH, ClientHello bölmek, sertifikat berkitmek, aýry serwer üçin duýduryşly *allow insecure* |
| **Marşrutlaşdyrma** | «Düzgün» we «Global» režimler, domen, IP we GeoIP boýunça düzgün toplumlary, ýurt aýlawy, programmalar boýunça bölünen tunnel, mahabat blokirlemek, Fake-IP DNS, HTTPS we TLS üsti bilen DNS, IPv6 |
| **Serwerler** | Baglanyşyklar, QR kodlar, Clash YAML, Xray we sing-box JSON, proksi zynjyrlary, XUDP bilen Mux, TCP ýa-da QUIC serwerleri üçin UDP boýunça ping, handshake ýa-da hakyky HTTP haýyşy bilen ölçemek; baglanyşyk görnüşinde eksport; işlemeýänleri pozmak |
| **Abunalar** | Paneldäki trafik we möhlet, awtomatik täzelenme, üpjün edijiniň bildirişleri, Remnawave HWID, **ýüklemek üçin domen frontingi** |
| **Awto** | Toparyň iň çalt serwerini saýlaýar, ölçemegi dowam edýär we diňe ep-esli utuş bolanda geçýär; serwer petiklenende özbaşdak täzeden birikýär |
| **Android** | Çalt sazlamalar plitkasy, widžet, hemişelik VPN, Android TV, Wear OS goşmaçasy, öz sertifikatyňyz bilen HTTPS aralyk tutmak, 9 dil |
| **Windows** | Ulgam proksi režimi (bir portda SOCKS5 we HTTP) ýa-da Wintun arkaly doly TUN režimi, treý nyşany, şol bir serwerler, abunalar we Awto |

## Ýükläp almak

Iň täze wersiýa **[Releases](https://github.com/Myth-T0ks1k/Mythaia/releases/latest)** sahypasynda.
Täze wersiýalar Telegram kanalynda [@mythaia](https://t.me/mythaia) hem çap edilýär.

| Platforma | Faýl | Bellik |
|---|---|---|
| Android | `Mythaia-1.1.1-android-universal.apk` | Islendik enjam üçin: arm64, armeabi-v7a, x86, x86_64 |
| Android | `Mythaia-1.1.1-android-arm64-v8a.apk` | Has ýeňil, häzirki zaman telefonlary üçin |
| Wear OS | `Mythaia-1.1.1-wear-os.apk` | Telefon programmasyna goşmaça, Wear OS 3 we täzesi |
| Windows | `Mythaia-Pro-1.1.1-windows-x64-setup.exe` | Häzirki ulanyjy üçin gurnaýjy, administrator hukuklary gerek däl |
| Windows | `Mythaia-Pro-1.1.1-windows-x64.msi` | Şol bir zat, MSI bukjasy görnüşinde |
| Windows | `Mythaia-Pro-1.1.1-windows-x64-portable.zip` | Islendik ýere açyň we `Mythaia Pro.exe` işlediň |

Her neşirde ähli faýllaryň SHA-256 jemleri bilen `SHA256SUMS.txt` bar. Android 8.0 ýa-da täzesi we
Windows 10 ýa-da 11 (x64) gerek; TUN režimi üçin Windows administrator hukuklaryny sorar.

## Bir baglanyşykda fronting

Domeni petiklenen panele köplenç petiklenmedik CDN arkaly baryp bolýar. Mythaia abunany **fronta**
(CDN salgysyna ýa-da onuň üstündäki başga domene) birigip ýükleýär: TLS handshake-de zyýansyz
**SNI**, HTTP `Host` sözbaşysynda bolsa paneliň hakyky ady iberilýär.

Fronting sazlamalaryny baglanyşygyň özünde geçirip bolýar. Baglanyşygy iberen adamyňyz abunany hiç
zat ýazmazdan bir ädimde goşar:

```text
https://panel.example.com/sub/TOKEN#front=104.16.1.1,cdn.example.net:443&sni=www.example.org
```

```text
mythaia://import?url=https://panel.example.com/sub/TOKEN&front=104.16.1.1&sni=www.example.org
```

| Parametr | Manysy |
|---|---|
| `front` | Birigilýän salgylar: IP ýa-da domen, gerek bolsa `:port` bilen (IPv6 — `[salgy]:port`). Otur bilen bölüň ýa-da açary gaýtalaň; olar tertip boýunça synanyşylýar. |
| `sni` | TLS handshake-de iberilýän at (`front-sni` hem bolýar). Diňe `sni` berlen bolsa, paneliň öz salgysyna şu at bilen birigilýär. |
| `name` | Toparyň hökmany däl ady. |

- Birinji görnüş adaty URL: `#` belgisinden soňky bölek panele hiç haçan ýetmeýär, şonuň üçin
  baglanyşyk beýleki kliýentlerde-de işleýär.
- Ikinji görnüş Mythaia-ny brauzerden ýa-da messenjerden göni açýar.
- Islendik görnüşi goýsaňyz, skanirleseňiz ýa-da açsaňyz, goşmak penjiresindäki **Fronting**
  meýdançalary özbaşdak doldurylýar we ýüklemezden öň olary barlap bolýar.
- **Abuna sazlamalary → Fronting bilen baglanyşygy göçür** bar bolan abunany şeýle baglanyşyga
  öwürýär — Android-de-de, Windows-da-da.

## Çeşme kodundan ýygnamak

**Talaplar:** JDK 21 we 36-njy platformaly Android SDK. NDK we CMake ilkinji ýygnamakda Android
Gradle Plugin tarapyndan özbaşdak gurnalýar.

```bash
git clone https://github.com/Myth-T0ks1k/Mythaia.git
cd Mythaia
./gradlew :app:assembleDebug                  # Android üçin debug APK
./gradlew :core:test :app:testDebugUnitTest   # modul synaglary
```

Release ýygnamalary siziň öz açaryňyz bilen gol çekilýär. Şu setirleri `local.properties` faýlyna
goşuň (ol hiç haçan repozitoriýa düşmeýär) ýa-da gurşaw üýtgeýänleri hökmünde beriň:

```properties
KEYSTORE_FILE=/path/to/release.jks
KEYSTORE_PASSWORD=...
KEY_ALIAS=...
KEY_PASSWORD=...
```

`./gradlew :app:assembleRelease` arm64 üçin APK ýygnaýar; `-Pmythaia.universal=true` bilen — ähli ABI üçin.

<details>
<summary><b>Windows programmasy</b></summary>

<br>

Ýerli kitaphana üçin MSVC, CMake we Ninja bilen Visual Studio 2022 gerek; gaplamak üçin bolsa
`jmods` bilen JDK 21 gerek, onuň ýoly `local.properties` faýlynda `desktop.jdk` hökmünde görkezilýär.

```bat
desktop\native\build.cmd
gradlew :desktop:run
gradlew :desktop:packageExe :desktop:packageMsi
```

Gurnaýjylar üçin `PATH`-da WiX 3.14 gerek. Ulanyjynyň maglumatlary `%APPDATA%\Mythaia` bukjasynda saklanýar.

</details>

## Taslamanyň gurluşy

| Modul | Näme |
|---|---|
| [`core`](../../core) | Platforma bagly bolmadyk Kotlin: modeller, baglanyşyklar, abunalar, ähli protokollar we TLS steki |
| [`app`](../../app) | Android programmasy: Jetpack Compose interfeýsi, `VpnService` we lwIP esasly ulanyjy TCP/IP steki |
| [`wear`](../../wear) | Wear OS programmasy: birikmäniň ýagdaýy we bir basyşda açmak |
| [`desktop`](../../desktop) | Windows programmasy: Compose for Desktop, ulgam proksi we Wintun TUN hereketlendirijileri |

`core` moduly [GitHub Packages](https://github.com/Myth-T0ks1k?tab=packages&repo_name=Mythaia)-da
`com.mythaia:mythaia-core` ady bilen hem çap edildi.

## Goşant goşmak

Ýalňyşlyklar barada habarlar, pikirler we pull request-ler hoş görülýär. Ilki
[CONTRIBUTING.md](../../CONTRIBUTING.md) okaň, howpsuzlyk meseleleri barada bolsa
[SECURITY.md](../../SECURITY.md)-de beýan edilişi ýaly gizlin habar beriň.

Soraglar we pikir alyşmak — Telegram söhbetdeşliginde [@mythaia_chat](https://t.me/mythaia_chat).

## Ygtyýarnama

Mythaia — [GNU General Public License v3.0](../../LICENSE.txt) ygtyýarnamasy boýunça erkin programma.

Taslama NodePassProject-iň Anywhere (GPL-3.0) taslamasyna esaslanýar we öz ygtyýarnamalary bilen
[lwIP](https://savannah.nongnu.org/projects/lwip/), [BLAKE3](https://github.com/BLAKE3-team/BLAKE3),
[libyaml](https://github.com/yaml/libyaml), [ngtcp2](https://github.com/ngtcp2/ngtcp2), [Mbed TLS](https://github.com/Mbed-TLS/mbedtls),
[Wintun](https://www.wintun.net), [Bouncy Castle](https://www.bouncycastle.org) we
[Brotli](https://github.com/google/brotli) kitaphanalaryny öz içine alýar. Marşrutlaşdyrma düzgünlerindäki
önüm atlary öz eýelerine degişlidir.

<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="../assets/banner-dark.svg">
  <img alt="Mythaia — Reach anywhere." src="../assets/banner-light.svg" width="100%">
</picture>

<br>

[![Release](https://img.shields.io/github/v/release/Myth-T0ks1k/Mythaia?style=flat-square&color=24548F&label=release)](https://github.com/Myth-T0ks1k/Mythaia/releases/latest)
[![CI](https://img.shields.io/github/actions/workflow/status/Myth-T0ks1k/Mythaia/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/Myth-T0ks1k/Mythaia/actions/workflows/ci.yml)
[![Android](https://img.shields.io/badge/Android-8.0%2B-3DDC84?style=flat-square&logo=android&logoColor=white)](#دانلود)
[![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D4?style=flat-square&logo=windows&logoColor=white)](#دانلود)
[![Kotlin](https://img.shields.io/badge/Kotlin-2.2-7F52FF?style=flat-square&logo=kotlin&logoColor=white)](https://kotlinlang.org)
[![License](https://img.shields.io/badge/license-GPL--3.0-14213A?style=flat-square)](../../LICENSE.txt)
[![Telegram](https://img.shields.io/badge/Telegram-%40mythaia-26A5E4?style=flat-square&logo=telegram&logoColor=white)](https://t.me/mythaia)
[![Chat](https://img.shields.io/badge/chat-%40mythaia__chat-26A5E4?style=flat-square&logo=telegram&logoColor=white)](https://t.me/mythaia_chat)

[English](../../README.md) · [Русский](README.ru.md) · [Türkmençe](README.tk.md) · [简体中文](README.zh-CN.md) · **فارسی**

[وب‌سایت](https://myth-t0ks1k.github.io/Mythaia/fa/) · [دانلود](#دانلود) · [امکانات](#امکانات) · [فرانتینگ در یک لینک](#فرانتینگ-در-یک-لینک) · [ساخت](#ساخت-از-سورس) · [تغییرات](../../CHANGELOG.md)

</div>

---

Mythaia یک کلاینت پروکسی برای **Android** و **Windows** است که پشتهٔ پروتکل خودش را دارد و از صفر با
Kotlin نوشته شده است. بدون تکیه بر Xray-core یا sing-box با VLESS همراه Reality، Hysteria2، TUIC، Trojan،
Shadowsocks، WireGuard و پروتکل‌های دیگر کار می‌کند و برای شبکه‌هایی با فیلترینگ سنگین ساخته شده است:
دامین فرانتینگ، تکه‌تکه کردن ClientHello، ECH، انتخاب خودکار سرور و عبور بر اساس کشور بخشی از خود
برنامه‌اند، نه افزونه.

<div align="center">
  <img src="../assets/screenshots/home.png" width="24%" alt="صفحهٔ اصلی، متصل">
  <img src="../assets/screenshots/proxies.png" width="24%" alt="سرورهای یک اشتراک">
  <img src="../assets/screenshots/add-fronting.png" width="24%" alt="افزودن اشتراک با فرانتینگ">
  <img src="../assets/screenshots/settings.png" width="24%" alt="تنظیمات">
</div>

## چرا Mythaia

- **یک پشتهٔ بومی.** پروتکل‌ها، لایه‌های انتقال، TLS و مسیریابی با Kotlin نوشته شده‌اند. چند کتابخانهٔ کوچک
  C (lwIP، BLAKE3، libyaml، ngtcp2، Mbed TLS) کارهایی را انجام می‌دهند که کد بومی در آن‌ها بهتر است. نه محیط اجرای Go،
  نه پل ارتباطی، و یک APK سبک.
- **دو پلتفرم، یک هسته.** برنامه‌های Android و Windows از یک ماژول مشترک `core` استفاده می‌کنند؛ یک لینک،
  یک اشتراک یا یک اصلاح در هر دو یکسان رفتار می‌کند.
- **ساخته‌شده برای شبکه‌های فیلترشده.** اشتراک‌ها از طریق فرانت دانلود می‌شوند، سرورها دوباره سنجیده و
  خودکار عوض می‌شوند، ترافیک داخلی داخلی می‌ماند و تنظیمات ناامن به‌جای پنهان شدن با رنگ قرمز مشخص می‌شوند.

## امکانات

| | |
|---|---|
| **پروتکل‌ها** | VLESS (Vision، Reality، رمزنگاری ML-KEM)، VMess، Trojan، Shadowsocks (AEAD و 2022)، Hysteria2 (Salamander، Brutal)، TUIC v5، AnyTLS، NaiveProxy (HTTP/1.1، HTTP/2)، WireGuard، SOCKS5، Sudoku |
| **انتقال** | TCP، WebSocket با early data، HTTPUpgrade، gRPC، XHTTP (stream-one، stream-up، packet-up)، QUIC |
| **TLS** | اثر انگشت مرورگرها (Chrome، Firefox، Safari، iOS، Edge)، Reality، ECH، تکه‌تکه کردن ClientHello، پین کردن گواهی، *allow insecure* برای هر سرور با هشدار آشکار |
| **مسیریابی** | حالت‌های قاعده‌ای و سراسری، مجموعه‌قواعد بر اساس دامنه، IP و GeoIP، عبور بر اساس کشور، تونل جداگانه برای هر برنامه، مسدودسازی تبلیغات، Fake-IP DNS، DNS روی HTTPS و TLS، IPv6 |
| **سرورها** | لینک‌های اشتراک‌گذاری، کد QR، Clash YAML، JSON برای Xray و sing-box، زنجیرهٔ پروکسی، Mux با XUDP، پینگ با TCP یا برای سرورهای QUIC با UDP، دست‌دهی یا درخواست واقعی HTTP؛ خروجی به‌صورت لینک؛ حذف سرورهای ناکارآمد |
| **اشتراک‌ها** | حجم مصرفی و تاریخ انقضا از پنل، به‌روزرسانی خودکار، اطلاعیه‌های ارائه‌دهنده، Remnawave HWID، **دامین فرانتینگ برای دانلود** |
| **خودکار** | سریع‌ترین سرور گروه را انتخاب می‌کند، سنجش را ادامه می‌دهد و فقط با بهبود محسوس جابه‌جا می‌شود؛ وقتی سروری مسدود شود، خودش دوباره وصل می‌شود |
| **Android** | کاشی تنظیمات سریع، ویجت صفحهٔ اصلی، VPN همیشه روشن، Android TV، برنامهٔ همراه Wear OS، رهگیری HTTPS با CA شخصی، ۹ زبان |
| **Windows** | حالت پروکسی سیستم (SOCKS5 و HTTP روی یک پورت) یا حالت کامل TUN با Wintun، آیکون در سینی سیستم، همان سرورها، اشتراک‌ها و حالت خودکار |

## دانلود

آخرین نسخه را از صفحهٔ **[Releases](https://github.com/Myth-T0ks1k/Mythaia/releases/latest)** دریافت کنید.
نسخه‌های جدید در کانال تلگرام [@mythaia](https://t.me/mythaia) هم منتشر می‌شوند.

| پلتفرم | فایل | توضیح |
|---|---|---|
| Android | `Mythaia-1.1.2-android-universal.apk` | برای همهٔ دستگاه‌ها: arm64، armeabi-v7a، x86، x86_64 |
| Android | `Mythaia-1.1.2-android-arm64-v8a.apk` | کم‌حجم‌تر، برای گوشی‌های جدید |
| Wear OS | `Mythaia-1.1.2-wear-os.apk` | همراه برنامهٔ گوشی، Wear OS 3 یا جدیدتر |
| Windows | `Mythaia-Pro-1.1.2-windows-x64-setup.exe` | نصب‌کننده برای کاربر فعلی، بدون نیاز به دسترسی مدیر |
| Windows | `Mythaia-Pro-1.1.2-windows-x64.msi` | همان، به‌صورت بستهٔ MSI |
| Windows | `Mythaia-Pro-1.1.2-windows-x64-portable.zip` | در هر جایی از حالت فشرده خارج کنید و `Mythaia Pro.exe` را اجرا کنید |

هر نسخه فایل `SHA256SUMS.txt` را با چکسام SHA-256 همهٔ فایل‌ها دارد. Android 8.0 یا جدیدتر و Windows
10 یا 11 (x64) لازم است؛ حالت TUN در Windows دسترسی مدیر می‌خواهد — هر بار، یا فقط یک بار هنگام نصب
سرویس Mythaia که از نسخهٔ خودش در Program Files اجرا می‌شود.

در Windows می‌توانید آن را با Scoop هم نصب و به‌روزرسانی کنید:

```pwsh
scoop bucket add mythaia https://github.com/Myth-T0ks1k/scoop-bucket
scoop install mythaia/mythaia-pro
```

## فرانتینگ در یک لینک

پنلی که دامنه‌اش مسدود شده، اغلب هنوز از طریق یک CDN مسدودنشده در دسترس است. Mythaia اشتراک را با اتصال
به **فرانت** (آدرس CDN یا دامنهٔ دیگری روی آن) دانلود می‌کند: در دست‌دهی TLS یک **SNI** بی‌خطر ارسال
می‌شود و نام واقعی پنل در هدر HTTP `Host` قرار می‌گیرد.

تنظیمات فرانتینگ می‌تواند داخل خود لینک باشد، تا هر کسی که لینک را برایش می‌فرستید اشتراک را در یک قدم
و بدون تایپ چیزی اضافه کند:

```text
https://panel.example.com/sub/TOKEN#front=104.16.1.1,cdn.example.net:443&sni=www.example.org
```

```text
mythaia://import?url=https://panel.example.com/sub/TOKEN&front=104.16.1.1&sni=www.example.org
```

| پارامتر | معنی |
|---|---|
| `front` | آدرس‌هایی که واقعاً به آن‌ها وصل می‌شویم: IP یا دامنه، در صورت نیاز با `:port` (IPv6 به شکل `[addr]:port`). با ویرگول جدا کنید یا کلید را تکرار کنید؛ به ترتیب امتحان می‌شوند. |
| `sni` | نامی که در دست‌دهی TLS فرستاده می‌شود (`front-sni` هم پذیرفته است). اگر فقط `sni` باشد، با همین نام به آدرس خود پنل وصل می‌شویم. |
| `name` | نام اختیاری برای گروه. |

- شکل اول یک URL معمولی است: بخش بعد از `#` هرگز به پنل نمی‌رسد، پس همین لینک در کلاینت‌های دیگر هم
  کار می‌کند.
- شکل دوم Mythaia را مستقیم از مرورگر یا پیام‌رسان باز می‌کند.
- با چسباندن، اسکن یا باز کردن هر دو شکل، فیلدهای **فرانتینگ** در پنجرهٔ افزودن خودکار پر می‌شوند و
  می‌توانید پیش از دانلود آن‌ها را بررسی کنید.
- **تنظیمات اشتراک ← کپی لینک همراه با فرانتینگ** اشتراکی را که دارید به چنین لینکی تبدیل می‌کند،
  هم در Android و هم در Windows.

## ساخت از سورس

**پیش‌نیازها:** JDK 21 و Android SDK با پلتفرم 36. NDK و CMake در اولین ساخت توسط Android Gradle Plugin
نصب می‌شوند.

```bash
git clone https://github.com/Myth-T0ks1k/Mythaia.git
cd Mythaia
./gradlew :app:assembleDebug                  # Android debug APK
./gradlew :core:test :app:testDebugUnitTest   # unit tests
```

نسخه‌های release با کلید خود شما امضا می‌شوند. این خطوط را در `local.properties` بگذارید (این فایل هرگز
در مخزن ثبت نمی‌شود) یا آن‌ها را به‌صورت متغیر محیطی تعریف کنید:

```properties
KEYSTORE_FILE=/path/to/release.jks
KEYSTORE_PASSWORD=...
KEY_ALIAS=...
KEY_PASSWORD=...
```

دستور `./gradlew :app:assembleRelease` یک APK برای arm64 می‌سازد؛ با `-Pmythaia.universal=true` برای همهٔ ABIها.

<details>
<summary><b>برنامهٔ Windows</b></summary>

<br>

کتابخانهٔ بومی به Visual Studio 2022 با MSVC، CMake و Ninja نیاز دارد؛ بسته‌بندی به JDK 21 همراه با
`jmods` نیاز دارد که مسیرش در `local.properties` با نام `desktop.jdk` قرار می‌گیرد.

```bat
desktop\native\build.cmd
gradlew :desktop:run
gradlew :desktop:packageExe :desktop:packageMsi
```

ساخت نصب‌کننده‌ها به WiX 3.14 در `PATH` نیاز دارد. داده‌های کاربر در `%APPDATA%\Mythaia` ذخیره می‌شوند.

</details>

## ساختار پروژه

| ماژول | چیست |
|---|---|
| [`core`](../../core) | Kotlin مستقل از پلتفرم: مدل‌ها، لینک‌ها، اشتراک‌ها، همهٔ پروتکل‌ها و پشتهٔ TLS |
| [`app`](../../app) | برنامهٔ Android: رابط Jetpack Compose، `VpnService` و پشتهٔ TCP/IP در فضای کاربر بر پایهٔ lwIP |
| [`wear`](../../wear) | برنامهٔ Wear OS: وضعیت اتصال و روشن و خاموش کردن با یک لمس |
| [`desktop`](../../desktop) | برنامهٔ Windows: Compose for Desktop، موتورهای پروکسی سیستم و TUN با Wintun |

ماژول `core` همچنین با نام `com.mythaia:mythaia-core` در
[GitHub Packages](https://github.com/Myth-T0ks1k?tab=packages&repo_name=Mythaia) منتشر شده است.

## مشارکت

گزارش اشکال، ایده و pull request پذیرفته می‌شود. لطفاً ابتدا [CONTRIBUTING.md](../../CONTRIBUTING.md) را
بخوانید و مشکلات امنیتی را طبق [SECURITY.md](../../SECURITY.md) به‌صورت خصوصی گزارش دهید.

پرسش و گفت‌وگو: گروه تلگرام [@mythaia_chat](https://t.me/mythaia_chat) یا [GitHub Discussions](https://github.com/Myth-T0ks1k/Mythaia/discussions).

## مجوز

Mythaia نرم‌افزاری آزاد تحت مجوز [GNU General Public License v3.0](../../LICENSE.txt) است.

این پروژه بر پایهٔ Anywhere از NodePassProject (GPL-3.0) ساخته شده و شامل
[lwIP](https://savannah.nongnu.org/projects/lwip/)، [BLAKE3](https://github.com/BLAKE3-team/BLAKE3)،
[libyaml](https://github.com/yaml/libyaml)، [ngtcp2](https://github.com/ngtcp2/ngtcp2)، [Mbed TLS](https://github.com/Mbed-TLS/mbedtls)،
[Wintun](https://www.wintun.net)، [Bouncy Castle](https://www.bouncycastle.org) و
[Brotli](https://github.com/google/brotli) تحت مجوزهای خودشان است. نام محصولات در مجموعه‌قواعد مسیریابی
متعلق به صاحبانشان است.

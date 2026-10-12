# Как проверять Mythaia руками и автоматически

Здесь три уровня проверки, от быстрой к полной:

1. **Лаборатория на ПК** — эталонные серверы Xray и sing-box на `127.0.0.1` и прогон всех протоколов ядром на JVM. Пять минут, не нужен ни телефон, ни эмулятор.
2. **Матрица на устройстве** — тот же прогон внутри Android-приложения на телефоне или эмуляторе (Android-рантайм, нативная библиотека, Conscrypt).
3. **Ручная проверка VPN** — импорт подписки, подключение, трафик через TUN, всё через `adb`.

Каждая проверка гоняет через сервер HTTP-запрос, скачивание 4 МБ со сверкой SHA-256 и UDP (эхо или DNS). Ядро для этого — `ProtocolProbe` (core): тот же код можно вызвать и в приложении.

## 1. Лаборатория на ПК

Нужны `xray` (26.x) и `sing-box` (1.12+) — подойдут бинарники из установленного Happ (`Program Files\FlyFrogLLC\Happ\core\xray.exe`, `...\tun\sing-box.exe`). В само приложение они не попадают: это только «другой конец провода», эталон, с которым сверяется наше ядро.

```bash
cd scripts/lab
mkdir -p out
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout out/lab.key -out out/lab.crt -days 3650 -subj "//CN=lab.mythaia.test" -addext "subjectAltName=DNS:lab.mythaia.test"
python gen.py
python helpers.py &
xray run -c out/xray-lab.json &
sing-box run -c out/sb-lab.json &
```

Ключи Reality, VLESS Encryption, WireGuard и пароли зашиты в `gen.py` — для тестового стенда это нормально, для настоящих серверов их не использовать.

Прогон на ПК (через нативную DLL, как в версии для Windows):

```bash
export MYTHAIA_MATRIX="scripts/lab/out/lab-links.txt;scripts/lab/out/lab-naive11.txt;scripts/lab/out/lab-wg.conf"
export MYTHAIA_MATRIX_HOST=127.0.0.1
export MYTHAIA_MATRIX_OUT=matrix-results.tsv
./gradlew :desktop:test --tests "com.mythaia.desktop.engine.LabMatrixSmoke" --rerun
```

`MYTHAIA_MATRIX_LOG=1` добавляет журнал ядра в отчёт теста (`desktop/build/test-results/test/*LabMatrix*.xml`). Сейчас проходят все 36 строк.

**Ваши подписки через провайдера.** Тот же тест принимает файлы подписок: сохраните тело подписки (base64, ссылки, JSON Xray или sing-box) в файл и передайте его в `MYTHAIA_MATRIX` без `MYTHAIA_MATRIX_HOST`. JVM ходит в сеть напрямую, мимо системного прокси (Hiddify), поэтому это честная проверка «как у телефона в Туркменистане».

## 2. Матрица на телефоне или эмуляторе

```bash
./gradlew :app:installDebug :app:installDebugAndroidTest
python scripts/android-matrix.py scripts/lab/out/lab-emu.txt scripts/lab/out/lab-naive11.txt scripts/lab/out/lab-wg.conf
python scripts/android-matrix.py my-subscription.txt
```

Отладочная сборка содержит и arm64, и x86_64, поэтому ставится и на телефон, и на эмулятор. `adb` берётся из `$ADB`, `$ANDROID_HOME` или `PATH`; если устройств несколько — задайте `ANDROID_SERIAL`.

**Эмулятор и прокси.** Если эмулятор запущен с переменной `http_proxy`, его Wi-Fi (netsim) гонит весь TCP через этот прокси: до `10.0.2.2` такие соединения не доходят, а настоящие серверы проверяются через чужой туннель. Поэтому для эмулятора есть `lab-emu.txt`: TCP-протоколы идут на `127.0.0.1` через `adb reverse`, QUIC — на `10.0.2.2` напрямую. Команду `adb reverse` для всех портов печатает `gen.py`:

```bash
for p in 20001 20002 ...; do adb reverse tcp:$p tcp:$p; done
```

UDP у SS и SOCKS5 на таком эмуляторе не проверить (UDP через `adb reverse` не ходит) — на ПК он проверяется. Лучше всего запускать эмулятор без прокси в окружении или проверять на телефоне.

## 3. Ручная проверка VPN через adb

```bash
python scripts/android-ui.py dump                 # что на экране
python scripts/android-ui.py tap "Add a Configuration"
python scripts/android-ui.py tap "Link"
python scripts/android-ui.py text "https://example.com/sub/..."
python scripts/android-ui.py tap "Continue"
adb shell am start -a android.intent.action.VIEW -d mythaia://connect com.mythaia
adb shell "printf 'GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n' | toybox nc -w 10 api.ipify.org 80"
adb shell am start -a android.intent.action.VIEW -d mythaia://disconnect com.mythaia
```

Системный запрос разрешения VPN и уведомлений появляется один раз: `python scripts/android-ui.py tap "OK"`. Трафик оболочки `adb shell` идёт через VPN, поэтому `nc` показывает адрес выхода сервера. Состояние туннеля: `adb shell ip addr show tun0`, журнал: `adb logcat -s LWIPStack MythaiaVpnService`.

## Что уже находил этот стенд

- TUIC: метка экспортёра TLS должна быть 16 байт UUID, а не текст — иначе «token mismatch» на любом сервере.
- VLESS через WebSocket, gRPC, XHTTP терял фрагментацию (`fm=`/FinalMask) по дороге к TLS-клиенту — DPI видел SNI.
- WebSocket/HTTPUpgrade у VMess и Trojan предлагали ALPN h2.
- VLESS Encryption игнорировал транспорт и TLS.
- На Windows не было RSA-PSS (каждый TLS 1.3-сервер с RSA-сертификатом) и ChaCha20 в Shadowsocks.
- Hysteria2/TUIC не передавали UDP, а клиент создавался на каждое соединение; HTTP/3 SETTINGS с H3_DATAGRAM отдавали датаграммы Hysteria слою HTTP/3 сервера.
- Naive HTTP/2 терял хвост каждого ответа.

## Особенности Xray 26 для своих серверов

- `allowInsecure` удалён: вместо него `pinnedPeerCertSha256` (в ссылках `pcs=`) и `verifyPeerCertByName` (`vcn=`). Клиент понимает оба.
- `freedom` по умолчанию не пускает на приватные и loopback-адреса; для стенда нужен `"settings": {"finalRules": [{"action": "allow"}]}` (`ipsBlocked` тоже удалён).

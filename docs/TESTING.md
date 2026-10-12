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

## 4. Звонки: UDP-поток как у Telegram

Один DNS-запрос или один STUN-пакет проверяет только то, что UDP вообще проходит. Звонок — это непрерывный поток по 50 пакетов в секунду с нескольких сокетов сразу, и ломается он иначе. В отладочной сборке есть приёмник, который запускает такой поток изнутри приложения, то есть через его собственный туннель:

```bash
adb shell am broadcast -n com.mythaia/.debug.UdpSimReceiver --es targets 1.2.3.4:9053,5.6.7.8:9053 --ei seconds 6
adb exec-out run-as com.mythaia cat files/matrix/udpsim.txt
```

На каждую цель идут два потока: по 64 байта (голос) и по 1100 байт (видео). В результате — сколько ответов вернулось, потери, медиана и 95-й перцентиль задержки. `am instrument` для этого не годится: он останавливает приложение, а вместе с ним и VPN.

На стенде любой UDP на порт 9053 Xray и sing-box отправляют на эхо из `helpers.py`, так что адреса `1.2.3.4` и `5.6.7.8` работают без интернета. На настоящих серверах берите STUN Google: `stun.l.google.com:19302,stun1.l.google.com:19302`.

То же без эмулятора, прямо через ядро на ПК:

```bash
MYTHAIA_UDPCALL=scripts/lab/out/lab-links.txt MYTHAIA_UDPCALL_ONLY="TUIC,Hysteria2" ./gradlew :desktop:test --tests "*UdpCallSmoke*" -i
```

Через ядро без туннеля потерь на стенде быть не должно, а медиана — около 1 мс. Если ядро на ПК чистое, а в эмуляторе есть потери, проблема в туннеле, а не в протоколе.

## Что уже находил этот стенд

- TUIC: метка экспортёра TLS должна быть 16 байт UUID, а не текст — иначе «token mismatch» на любом сервере.
- VLESS через WebSocket, gRPC, XHTTP терял фрагментацию (`fm=`/FinalMask) по дороге к TLS-клиенту — DPI видел SNI.
- WebSocket/HTTPUpgrade у VMess и Trojan предлагали ALPN h2.
- VLESS Encryption игнорировал транспорт и TLS.
- На Windows не было RSA-PSS (каждый TLS 1.3-сервер с RSA-сертификатом) и ChaCha20 в Shadowsocks.
- Hysteria2/TUIC не передавали UDP, а клиент создавался на каждое соединение; HTTP/3 SETTINGS с H3_DATAGRAM отдавали датаграммы Hysteria слою HTTP/3 сервера.
- Naive HTTP/2 терял хвост каждого ответа.
- VLESS и VMess теряли почти все UDP-пакеты непрерывного потока: буфер разбора длины склеивал новый кусок со старыми, уже прочитанными данными. Отсюда и неработающие звонки Telegram через VLESS (в том числе XHTTP).
- Один UDP-поток через SOCKS5 навсегда занимал единственный поток туннеля: блокирующий `receive` выполнялся прямо на нём. После этого переставало работать всё, включая TCP, хотя VPN оставался «подключённым».
- Shadowsocks держал один UDP-сокет на весь сервер, поэтому два локальных сокета к одному адресу (два QUIC-соединения к одному сайту, два потока звонка к одному реле) получали ответы друг друга.
- QUIC (Hysteria2, TUIC) выбрасывал датаграмму, если пейсер ngtcp2 ещё не был готов, и вместе с ней — уже пронумерованный пакет с ACK. Сервер считал свои пакеты потерянными и сбрасывал скорость. Второй фрагмент крупного пакета почти всегда попадал на пейсер.
- Hysteria2 и TUIC делили на фрагменты всё, что длиннее 1100 байт. Сервер Hysteria2 из подписки (Xray) фрагменты не собирает, поэтому пакеты видео в звонке терялись все. Теперь пакет делится, только если не влезает в один QUIC-пакет текущего пути, как у официальных клиентов.
- Эталон для своей сети: прямой поток к STUN Google без VPN. Если через сервер потери такие же, туннель ни при чём.

## Особенности Xray 26 для своих серверов

- `allowInsecure` удалён: вместо него `pinnedPeerCertSha256` (в ссылках `pcs=`) и `verifyPeerCertByName` (`vcn=`). Клиент понимает оба.
- `freedom` по умолчанию не пускает на приватные и loopback-адреса; для стенда нужен `"settings": {"finalRules": [{"action": "allow"}]}` (`ipsBlocked` тоже удалён).

"""Generates the local interop lab (see docs/TESTING.md).

Writes into scripts/lab/out/: xray-lab.json and sb-lab.json (reference servers,
all on 127.0.0.1), lab.crt/lab.key are expected next to them, lab-links.txt
(the emulator reaches the PC as 10.0.2.2), lab-emu.txt (TCP protocols on
127.0.0.1 for `adb reverse`, QUIC ones on 10.0.2.2), lab-naive11.txt,
lab-wg.conf and www/blob for the hashed download.

LAB_WG_EXTRA_PEER=<base64 public key> adds a second WireGuard peer (10.77.0.3),
for checking a profile made in the app's own WireGuard form.
"""
import base64, hashlib, json, os, urllib.parse

HERE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")
os.makedirs(HERE, exist_ok=True)
CRT = os.path.join(HERE, "lab.crt").replace("\\", "/")
KEY = os.path.join(HERE, "lab.key").replace("\\", "/")
UUID = "5c8a1b9e-3f7d-4e2a-9b61-0d4c7e8f2a13"
PW = "lab-pass-123"
SNI = "lab.mythaia.test"
HOST = "10.0.2.2"  # the PC as the emulator sees it
REALITY_PRIV = "WBiA8VNbGsWRgzAzsx6Y26_5rlySTn2MzalAyp8AQn0"
REALITY_PUB = "xcMXdL5OD3jkvoDjFX4_0uMvQsALrvZybRj9U4lCiG4"
VLESSENC_DEC = "mlkem768x25519plus.native.600s.0FJpWMANZE8l0vB5xQlY0ymaI-uGjdFDZtwPpZNUWlE"
VLESSENC_ENC = "mlkem768x25519plus.native.0rtt.tA1BgXBVGsfP2UfUVBXpbgXTY9aYRNt0b3EIz3gokgQ"
SS2022_128 = base64.b64encode(hashlib.sha256(b"lab128").digest()[:16]).decode()
SS2022_256 = base64.b64encode(hashlib.sha256(b"lab256").digest()).decode()
WG_SERVER_PRIV = "+Du8QkHucyNTKMZf5cv8K/STrQjMyJsv66UY35lD2mQ="
WG_SERVER_PUB = "8f8vrIkNUX7YeEmFFDOm40WjPrdFJx7FYrQxrH7kHUo="
WG_CLIENT_PRIV = "ADAS9brqmHVG11XeR2owXGOqZnYvZMvr4Zl2ZB24ImM="
WG_CLIENT_PUB = "QANhijWsyxQzzFP07g1lIY75OK57fF0HGuJJdrsPiFA="

tls = {"certificates": [{"certificateFile": CRT, "keyFile": KEY}], "alpn": ["h2", "http/1.1"]}
inbounds, links = [], []


def q(params):
    return urllib.parse.urlencode(params, quote_via=urllib.parse.quote)


def name(s):
    return urllib.parse.quote(s)


def vless(port, network, security, label, stream_extra=None, flow=None, link_extra=None, decryption="none", client_enc="none"):
    client = {"id": UUID}
    if flow: client["flow"] = flow
    stream = {"network": network, "security": security}
    if security == "tls": stream["tlsSettings"] = tls
    if security == "reality":
        stream["realitySettings"] = {"dest": "127.0.0.1:20001", "serverNames": [SNI], "privateKey": REALITY_PRIV, "shortIds": ["", "a1b2c3d4"]}
    stream.update(stream_extra or {})
    inbounds.append({"tag": f"in-{port}", "listen": "127.0.0.1", "port": port, "protocol": "vless",
                     "settings": {"clients": [client], "decryption": decryption}, "streamSettings": stream})
    params = {"type": network, "security": security, "encryption": client_enc}
    if security == "tls": params.update({"sni": SNI, "allowInsecure": "1", "fp": "chrome"})
    if security == "reality": params.update({"sni": SNI, "pbk": REALITY_PUB, "sid": "a1b2c3d4", "fp": "chrome"})
    if flow: params["flow"] = flow
    params.update(link_extra or {})
    links.append(f"vless://{UUID}@{HOST}:{port}?{q(params)}#{name(label)}")


# ---------------------------------------------------------------- xray: VLESS
vless(20001, "tcp", "tls", "VLESS TCP TLS")
vless(20015, "tcp", "tls", "VLESS TCP TLS Vision", flow="xtls-rprx-vision")
vless(20002, "tcp", "reality", "VLESS Reality Vision", flow="xtls-rprx-vision")
vless(20003, "ws", "tls", "VLESS WS TLS", {"wsSettings": {"path": "/ws"}}, link_extra={"path": "/ws", "host": SNI})
vless(20016, "ws", "none", "VLESS WS plain", {"wsSettings": {"path": "/ws"}}, link_extra={"path": "/ws"})
vless(20004, "grpc", "tls", "VLESS gRPC TLS", {"grpcSettings": {"serviceName": "lab"}}, link_extra={"serviceName": "lab", "mode": "gun"})
vless(20006, "httpupgrade", "tls", "VLESS HTTPUpgrade TLS", {"httpupgradeSettings": {"path": "/hu"}}, link_extra={"path": "/hu", "host": SNI})
vless(20005, "xhttp", "tls", "VLESS XHTTP auto TLS", {"xhttpSettings": {"path": "/xh", "mode": "auto"}}, link_extra={"path": "/xh", "mode": "auto", "host": SNI})
for mode in ("packet-up", "stream-up", "stream-one"):
    links.append(links[-1].replace("mode=auto", f"mode={mode}").replace("XHTTP%20auto", "XHTTP%20" + mode))
vless(20014, "xhttp", "reality", "VLESS XHTTP Reality", {"xhttpSettings": {"path": "/xr", "mode": "auto"}}, link_extra={"path": "/xr", "mode": "auto"})
vless(20020, "tcp", "tls", "VLESS Encryption (ML-KEM)", decryption=VLESSENC_DEC, client_enc=VLESSENC_ENC)
# Same TLS server as 20001, dialled with the subscription's FinalMask fragment.
fm = json.dumps({"tcp": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["3"], "delays": ["1"], "maxSplit": "2"}}]}, separators=(",", ":"))
links.append(f"vless://{UUID}@{HOST}:20001?{q({'type':'tcp','security':'tls','sni':SNI,'allowInsecure':'1','encryption':'none','fm':fm})}#{name('VLESS TCP TLS + FinalMask fragment')}")
links.append(f"vless://{UUID}@{HOST}:20003?{q({'type':'ws','security':'tls','sni':SNI,'allowInsecure':'1','encryption':'none','path':'/ws','host':SNI,'fragment':'3-5,1-2,tlshello'})}#{name('VLESS WS TLS + fragment=')}")

# ---------------------------------------------------------------- xray: VMess
def vmess_link(port, label, net, tls_on, path=""):
    j = {"v": "2", "ps": label, "add": HOST, "port": str(port), "id": UUID, "aid": "0", "scy": "auto", "net": net,
         "type": "none", "host": SNI if tls_on else "", "path": path, "tls": "tls" if tls_on else "", "sni": SNI if tls_on else "",
         "allowInsecure": "1" if tls_on else ""}
    links.append("vmess://" + base64.b64encode(json.dumps(j).encode()).decode())

inbounds.append({"tag": "in-20007", "listen": "127.0.0.1", "port": 20007, "protocol": "vmess", "settings": {"clients": [{"id": UUID}]}, "streamSettings": {"network": "tcp"}})
vmess_link(20007, "VMess TCP", "tcp", False)
inbounds.append({"tag": "in-20008", "listen": "127.0.0.1", "port": 20008, "protocol": "vmess", "settings": {"clients": [{"id": UUID}]},
                 "streamSettings": {"network": "ws", "security": "tls", "tlsSettings": tls, "wsSettings": {"path": "/vws"}}})
vmess_link(20008, "VMess WS TLS", "ws", True, "/vws")
inbounds.append({"tag": "in-20018", "listen": "127.0.0.1", "port": 20018, "protocol": "vmess", "settings": {"clients": [{"id": UUID}]},
                 "streamSettings": {"network": "grpc", "security": "tls", "tlsSettings": tls, "grpcSettings": {"serviceName": "vg"}}})
vmess_link(20018, "VMess gRPC TLS", "grpc", True, "vg")

# ---------------------------------------------------------------- xray: Trojan
def trojan(port, network, label, extra=None, link_extra=None):
    stream = {"network": network, "security": "tls", "tlsSettings": tls}
    stream.update(extra or {})
    inbounds.append({"tag": f"in-{port}", "listen": "127.0.0.1", "port": port, "protocol": "trojan", "settings": {"clients": [{"password": PW}]}, "streamSettings": stream})
    params = {"type": network, "security": "tls", "sni": SNI, "allowInsecure": "1"}
    params.update(link_extra or {})
    links.append(f"trojan://{PW}@{HOST}:{port}?{q(params)}#{name(label)}")

trojan(20009, "tcp", "Trojan TCP TLS")
trojan(20010, "grpc", "Trojan gRPC TLS", {"grpcSettings": {"serviceName": "tg"}}, {"serviceName": "tg"})
trojan(20019, "ws", "Trojan WS TLS", {"wsSettings": {"path": "/tws"}}, {"path": "/tws", "host": SNI})

# ---------------------------------------------------------------- xray: Shadowsocks / SOCKS
def ss(port, method, password, label, network="tcp,udp"):
    inbounds.append({"tag": f"in-{port}", "listen": "127.0.0.1", "port": port, "protocol": "shadowsocks",
                     "settings": {"method": method, "password": password, "network": network}})
    userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
    links.append(f"ss://{userinfo}@{HOST}:{port}#{name(label)}")

ss(20011, "aes-256-gcm", PW, "Shadowsocks AES-256-GCM")
ss(20017, "chacha20-ietf-poly1305", PW, "Shadowsocks ChaCha20")
ss(20012, "2022-blake3-aes-128-gcm", SS2022_128, "Shadowsocks 2022 AES-128")
inbounds.append({"tag": "in-20013", "listen": "127.0.0.1", "port": 20013, "protocol": "socks",
                 "settings": {"auth": "password", "accounts": [{"user": "lab", "pass": PW}], "udp": True, "ip": "127.0.0.1"}})
links.append(f"socks5://lab:{PW}@{HOST}:20013#{name('SOCKS5 auth')}")

# Call test (docs/TESTING.md, section 4): UDP to any address on port 9053 goes to
# the helpers' echo, so a call stream to two "public" relays needs no internet.
xray = {"log": {"loglevel": "warning", "access": "", "error": os.path.join(HERE, "xray.log").replace("\\", "/")},
        "inbounds": inbounds,
        "outbounds": [{"protocol": "freedom", "tag": "direct", "settings": {"finalRules": [{"action": "allow"}]}},
                      {"protocol": "freedom", "tag": "echo", "settings": {"redirect": "127.0.0.1:9053", "finalRules": [{"action": "allow"}]}}],
        "routing": {"rules": [{"type": "field", "port": "9053", "outboundTag": "echo"}]}}
json.dump(xray, open(os.path.join(HERE, "xray-lab.json"), "w"), indent=1)

# ---------------------------------------------------------------- sing-box
sb_tls = {"enabled": True, "server_name": SNI, "certificate_path": CRT, "key_path": KEY}
sb_in = [
    {"type": "hysteria2", "tag": "hy2", "listen": "127.0.0.1", "listen_port": 21001, "users": [{"password": PW}], "tls": {**sb_tls, "alpn": ["h3"]}},
    {"type": "hysteria2", "tag": "hy2-obfs", "listen": "127.0.0.1", "listen_port": 21002, "users": [{"password": PW}],
     "obfs": {"type": "salamander", "password": "salty"}, "tls": {**sb_tls, "alpn": ["h3"]}},
    {"type": "hysteria2", "tag": "hy2-brutal", "listen": "127.0.0.1", "listen_port": 21010, "users": [{"password": PW}], "up_mbps": 100, "down_mbps": 100,
     "ignore_client_bandwidth": False, "tls": {**sb_tls, "alpn": ["h3"]}},
    {"type": "tuic", "tag": "tuic", "listen": "127.0.0.1", "listen_port": 21003, "users": [{"uuid": UUID, "password": PW}], "congestion_control": "bbr",
     "tls": {**sb_tls, "alpn": ["h3"]}},
    {"type": "anytls", "tag": "anytls", "listen": "127.0.0.1", "listen_port": 21004, "users": [{"password": PW}], "tls": sb_tls},
    {"type": "naive", "tag": "naive", "listen": "127.0.0.1", "listen_port": 21005, "network": "tcp", "users": [{"username": "lab", "password": PW}], "tls": {**sb_tls, "alpn": ["h2", "http/1.1"]}},
    {"type": "http", "tag": "https-proxy", "listen": "127.0.0.1", "listen_port": 21006, "users": [{"username": "lab", "password": PW}], "tls": sb_tls},
    {"type": "shadowsocks", "tag": "ss2022-256", "listen": "127.0.0.1", "listen_port": 21007, "method": "2022-blake3-aes-256-gcm", "password": SS2022_256},
    {"type": "shadowsocks", "tag": "ss2022-chacha", "listen": "127.0.0.1", "listen_port": 21008, "method": "2022-blake3-chacha20-poly1305", "password": SS2022_256},
]
sb = {"log": {"level": "warn", "output": os.path.join(HERE, "sb.log").replace("\\", "/")},
      "inbounds": sb_in,
      "endpoints": [{"type": "wireguard", "tag": "wg", "system": False, "listen_port": 21009, "address": ["10.77.0.1/24"], "private_key": WG_SERVER_PRIV,
                     "peers": [{"public_key": WG_CLIENT_PUB, "allowed_ips": ["10.77.0.2/32"]}] + ([{"public_key": os.environ["LAB_WG_EXTRA_PEER"], "allowed_ips": ["10.77.0.3/32"]}] if os.environ.get("LAB_WG_EXTRA_PEER") else [])}],
      "outbounds": [{"type": "direct", "tag": "direct"}],
      "route": {"rules": [{"port": [9053], "action": "route-options", "override_address": "127.0.0.1"}]}}
json.dump(sb, open(os.path.join(HERE, "sb-lab.json"), "w"), indent=1)

links.append(f"hysteria2://{PW}@{HOST}:21001?{q({'sni': SNI, 'insecure': '1'})}#{name('Hysteria2')}")
links.append(f"hysteria2://{PW}@{HOST}:21002?{q({'sni': SNI, 'insecure': '1', 'obfs': 'salamander', 'obfs-password': 'salty'})}#{name('Hysteria2 Salamander')}")
links.append(f"hysteria2://{PW}@{HOST}:21010?{q({'sni': SNI, 'insecure': '1', 'upmbps': '50', 'downmbps': '100'})}#{name('Hysteria2 Brutal')}")
fm_salamander = json.dumps({"udp": [{"type": "salamander", "settings": {"password": "salty"}}]}, separators=(",", ":"))
links.append(f"hysteria2://{PW}@{HOST}:21002?{q({'sni': SNI, 'insecure': '1', 'fm': fm_salamander})}#{name('Hysteria2 Salamander via fm')}")
links.append(f"tuic://{UUID}:{PW}@{HOST}:21003?{q({'sni': SNI, 'allow_insecure': '1', 'alpn': 'h3', 'congestion_control': 'bbr'})}#{name('TUIC v5')}")
links.append(f"anytls://{PW}@{HOST}:21004?{q({'sni': SNI, 'insecure': '1'})}#{name('AnyTLS')}")
links.append(f"https://lab:{PW}@{HOST}:21005#{name('Naive HTTP2')}")
links.append(f"ss://{base64.urlsafe_b64encode(('2022-blake3-aes-256-gcm:' + SS2022_256).encode()).decode().rstrip('=')}@{HOST}:21007#{name('Shadowsocks 2022 AES-256')}")
links.append(f"ss://{base64.urlsafe_b64encode(('2022-blake3-chacha20-poly1305:' + SS2022_256).encode()).decode().rstrip('=')}@{HOST}:21008#{name('Shadowsocks 2022 ChaCha20')}")

# Naive over HTTP/1.1 has no link scheme of its own; the matrix file marks it.
naive11 = f"https://lab:{PW}@{HOST}:21006#{name('Naive HTTP1.1 (HTTPS proxy)')}"

wg_ini = f"""[Interface]
PrivateKey = {WG_CLIENT_PRIV}
Address = 10.77.0.2/32
DNS = 1.1.1.1
MTU = 1280

[Peer]
PublicKey = {WG_SERVER_PUB}
AllowedIPs = 0.0.0.0/0
Endpoint = {HOST}:21009
PersistentKeepalive = 25
"""
open(os.path.join(HERE, "lab-wg.conf"), "w").write(wg_ini)

blob = os.urandom(4 * 1024 * 1024)
os.makedirs(os.path.join(HERE, "www"), exist_ok=True)
open(os.path.join(HERE, "www", "blob"), "wb").write(blob)
sha = hashlib.sha256(blob).hexdigest()
header = f"#http 127.0.0.1:8099/blob {sha}\n#udp 127.0.0.1:9053 echo\n#insecure\n"
open(os.path.join(HERE, "lab-links.txt"), "w", encoding="utf-8").write(header + "\n".join(links) + "\n")
open(os.path.join(HERE, "lab-naive11.txt"), "w", encoding="utf-8").write(header + "#naive11\n" + naive11 + "\n")
print(len(links), "links;", len(inbounds), "xray inbounds;", len(sb_in), "sing-box inbounds; sha", sha[:12])

# The emulator's Wi-Fi may run through a host proxy (netsim honours http_proxy),
# which cannot reach 10.0.2.2: TCP protocols go to 127.0.0.1 via `adb reverse`.
emu = []
for line in (header + "\n".join(links)).splitlines():
    if line.startswith(("hysteria2://", "tuic://")) or line.startswith("#"):
        emu.append(line)
    elif line.startswith("vmess://"):
        j = json.loads(base64.b64decode(line[8:]))
        j["add"] = "127.0.0.1"
        emu.append("vmess://" + base64.b64encode(json.dumps(j).encode()).decode())
    else:
        emu.append(line.replace("@10.0.2.2:", "@127.0.0.1:"))
open(os.path.join(HERE, "lab-emu.txt"), "w", encoding="utf-8").write("\n".join(emu) + "\n")
tcp_ports = sorted({int(i["port"]) for i in inbounds} | {21004, 21005, 21006, 21007, 21008})
print("adb reverse for the emulator:", " ".join(f"tcp:{p}" for p in tcp_ports))

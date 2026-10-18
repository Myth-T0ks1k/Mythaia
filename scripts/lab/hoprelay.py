"""UDP port-hopping relay for the lab: what iptables DNAT does in front of a real Hysteria2 server.

    python scripts/lab/hoprelay.py 21100-21104=21001 21110-21114=21002

Every port of a range forwards to the one sing-box port after "=" (all on 127.0.0.1). Each
(client address, relay port) pair gets an upstream socket of its own, as conntrack gives each its own
entry, so after a hop the server sees the client arrive from a new address, as it does in front of a
real server. Mappings idle for 60 s are dropped. Logs every new mapping, and every QUIC long-header
packet a client sends (a handshake; a session that hops without redialling sends them only at its
start), so a run can be checked afterwards.
"""
import selectors
import socket
import sys
import time

IDLE = 60.0
START = time.time()
sel = selectors.DefaultSelector()
mappings = {}  # (client address, relay port) -> upstream socket
routes = {}  # upstream socket -> (listener socket, client address, key)
seen = {}  # key -> last packet time


def log(text):
    print(f"{time.time() - START:8.2f} {text}", flush=True)


def quiet_icmp(s):
    # Windows reports an ICMP "port unreachable" for a closed client socket
    # as an error on the next read; a relay must not stop over it.
    if hasattr(socket, "SIO_UDP_CONNRESET"):
        s.ioctl(socket.SIO_UDP_CONNRESET, False)


for arg in sys.argv[1:]:
    ports, target = arg.split("=")
    low, _, high = ports.partition("-")
    for port in range(int(low), int(high or low) + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", port))
        s.setblocking(False)
        quiet_icmp(s)
        sel.register(s, selectors.EVENT_READ, ("listen", port, int(target)))
    log(f"relay {ports} -> 127.0.0.1:{target}")

last_sweep = time.time()
while True:
    for key, _ in sel.select(timeout=1.0):
        sock = key.fileobj
        kind = key.data[0]
        try:
            data, addr = sock.recvfrom(65535)
        except (BlockingIOError, ConnectionResetError, OSError):
            continue
        now = time.time()
        if kind == "listen":
            _, port, target = key.data
            mkey = (addr, port)
            up = mappings.get(mkey)
            if up is None:
                up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                up.bind(("127.0.0.1", 0))
                up.setblocking(False)
                quiet_icmp(up)
                mappings[mkey] = up
                routes[up] = (sock, addr, mkey)
                sel.register(up, selectors.EVENT_READ, ("up",))
                log(f"map {addr[0]}:{addr[1]} via {port} -> server sees 127.0.0.1:{up.getsockname()[1]}")
            if data and data[0] & 0x80:
                log(f"long-header packet from {addr[0]}:{addr[1]} via {port} ({len(data)} bytes)")
            seen[mkey] = now
            up.sendto(data, ("127.0.0.1", target))
        else:
            listener, client, mkey = routes[sock]
            seen[mkey] = now
            try:
                listener.sendto(data, client)
            except OSError:
                pass
    if time.time() - last_sweep > 5:
        last_sweep = time.time()
        for mkey in [k for k, t in seen.items() if last_sweep - t > IDLE]:
            up = mappings.pop(mkey)
            routes.pop(up, None)
            seen.pop(mkey, None)
            sel.unregister(up)
            up.close()
            log(f"expired {mkey[0][0]}:{mkey[0][1]} via {mkey[1]}")

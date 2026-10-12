"""HTTP file server on 127.0.0.1:8099 (serves out/www, written by gen.py) and a UDP echo on 127.0.0.1:9053."""
import functools, http.server, os, socket, threading

HERE = os.path.dirname(os.path.abspath(__file__))


def udp_echo():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 9053))
    while True:
        data, addr = s.recvfrom(65535)
        s.sendto(data, addr)


class Quiet(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass


threading.Thread(target=udp_echo, daemon=True).start()
handler = functools.partial(Quiet, directory=os.path.join(HERE, "out", "www"))
http.server.ThreadingHTTPServer(("127.0.0.1", 8099), handler).serve_forever()

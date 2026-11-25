"""Share gateway: ONE address + ONE port that carries the FINAL output of the connected mode.

The same port speaks SOCKS5 and HTTP (the first byte tells them apart):
  * SOCKS5 clients are passed straight to the exit SOCKS5 port of the current mode.
  * HTTP proxy clients (plain requests and CONNECT for HTTPS) are converted to SOCKS5 and sent to that same exit port.

Because it always talks to the exit port, other devices get Psiphon's or Tor's output (not only Aether's):
Aether, Aether -> Psiphon, Aether -> Tor, Psiphon only, Tor only and the reverse modes.
(Port of ShareGateway.kt from the Android app.)
"""
import socket
import threading

_BUF = 64 * 1024


def _split_host_port(v: str, default_port: int):
    t = (v or "").strip()
    if not t:
        return None
    if t.startswith("["):
        end = t.find("]")
        if end < 0:
            return None
        host = t[1:end]
        if len(t) > end + 2 and t[end + 1] == ":":
            if not t[end + 2:].isdigit():
                return None
            return host, int(t[end + 2:])
        return host, default_port
    if ":" not in t:
        return t, default_port
    host, _, port = t.rpartition(":")
    if not port.isdigit() or not (1 <= int(port) <= 65535):
        return None
    return host, int(port)


def _read_exact(s: socket.socket, n: int) -> bytes:
    out = b""
    while len(out) < n:
        d = s.recv(n - len(out))
        if not d:
            raise OSError("eof")
        out += d
    return out


def _is_ipv4(h: str) -> bool:
    p = h.split(".")
    return len(p) == 4 and all(x.isdigit() and int(x) <= 255 for x in p)


class ShareGateway:
    def __init__(self, log=None):
        self._log = log or (lambda m: None)
        self._server = None
        self._lock = threading.RLock()
        self._socks = set()
        self._socks_lock = threading.Lock()

    # ------------------------------------------------------------ public
    def start(self, listen_host: str, listen_port: int, exit_host: str, exit_port: int):
        """Starts listening. Returns None on success or a short error text."""
        with self._lock:
            self.stop()
            ss = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                ss.bind((listen_host, listen_port))
                ss.listen(128)
            except OSError as e:
                try:
                    ss.close()
                except OSError:
                    pass
                return str(e)
            self._server = ss
            self._log(f"Share gateway on {listen_host}:{listen_port} -> exit {exit_host}:{exit_port}")
            threading.Thread(target=self._accept, args=(ss, exit_host, exit_port),
                             name="8vpn-share-accept", daemon=True).start()
            return None

    def stop(self):
        with self._lock:
            ss, self._server = self._server, None
            if ss is not None:
                for fn in (lambda: ss.shutdown(socket.SHUT_RDWR), ss.close):   # shutdown wakes a blocked accept()
                    try:
                        fn()
                    except OSError:
                        pass
            with self._socks_lock:
                allsocks = list(self._socks)
            for s in allsocks:
                self._close(s)

    # ------------------------------------------------------------ plumbing
    def _track(self, s):
        with self._socks_lock:
            self._socks.add(s)

    def _close(self, s):
        if s is None:
            return
        with self._socks_lock:
            self._socks.discard(s)
        try:
            s.close()
        except OSError:
            pass

    def _accept(self, ss, exit_host, exit_port):
        ss.settimeout(0.5)                   # so the loop also ends where close() does not wake accept()
        while self._server is ss:
            try:
                c, _ = ss.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            c.settimeout(None)
            self._track(c)
            threading.Thread(target=self._serve, args=(c, exit_host, exit_port),
                             name="8vpn-share", daemon=True).start()

    def _serve(self, c, exit_host, exit_port):
        try:
            self._handle(c, exit_host, exit_port)
        except Exception:
            pass
        finally:
            self._close(c)

    # ------------------------------------------------------------ one connection
    def _handle(self, c, exit_host, exit_port):
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        c.settimeout(20)                     # only while the first bytes are read
        first = c.recv(_BUF)
        if not first:
            return

        # SOCKS client: the exit port already speaks SOCKS5, so just join the two sockets.
        if first[0] in (4, 5):
            up = socket.socket()
            self._track(up)
            try:
                up.settimeout(8)
                up.connect((exit_host, exit_port))
                up.settimeout(None)
                c.settimeout(None)
                up.sendall(first)
                self._pipe(c, up)
            finally:
                self._close(up)
            return

        # HTTP proxy client
        buf = first
        while b"\r\n\r\n" not in buf:
            if len(buf) > 32 * 1024:
                return
            d = c.recv(_BUF)
            if not d:
                return
            buf += d
        head_b, _, rest = buf.partition(b"\r\n\r\n")
        lines = head_b.decode("iso-8859-1").split("\r\n")
        req = lines[0].split(" ")
        if len(req) < 3:
            self._reply(c, "400 Bad Request")
            return
        method, target, version = req[0], req[1], req[2]

        if method.upper() == "CONNECT":
            hp = _split_host_port(target, 443)
            if not hp:
                self._reply(c, "400 Bad Request")
                return
            try:
                up = self._socks5_connect(exit_host, exit_port, hp[0], hp[1])
            except Exception:
                self._reply(c, "502 Bad Gateway")
                return
            try:
                c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                c.settimeout(None)
                if rest:
                    up.sendall(rest)
                self._pipe(c, up)
            finally:
                self._close(up)
            return

        # Plain HTTP: absolute-form request line, rewritten to origin-form.
        headers = [h for h in lines[1:] if h]
        if target.lower().startswith("http://"):
            r = target[7:]
            slash = r.find("/")
            host_port = r[:slash] if slash >= 0 else r
            path = r[slash:] if slash >= 0 else "/"
        elif target.startswith("/"):
            hv = next((h.split(":", 1)[1].strip() for h in headers if h.lower().startswith("host:")), None)
            if not hv:
                self._reply(c, "400 Bad Request")
                return
            host_port, path = hv, target
        else:
            self._reply(c, "400 Bad Request")
            return
        host_port = host_port.rsplit("@", 1)[-1]
        hp = _split_host_port(host_port, 80)
        if not hp:
            self._reply(c, "400 Bad Request")
            return
        try:
            up = self._socks5_connect(exit_host, exit_port, hp[0], hp[1])
        except Exception:
            self._reply(c, "502 Bad Gateway")
            return
        try:
            out = [f"{method} {path} {version}"]
            has_host = False
            for h in headers:
                name = h.split(":", 1)[0].strip().lower()
                if name in ("proxy-connection", "proxy-authorization", "connection", "keep-alive"):
                    continue
                if name == "host":
                    has_host = True
                out.append(h)
            if not has_host:
                out.append(f"Host: {host_port}")
            out.append("Connection: close")
            up.sendall(("\r\n".join(out) + "\r\n\r\n").encode("iso-8859-1") + rest)
            c.settimeout(None)
            self._pipe(c, up)
        finally:
            self._close(up)

    @staticmethod
    def _reply(c, status):
        try:
            c.sendall(f"HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode())
        except OSError:
            pass

    # ------------------------------------------------------------ SOCKS5 towards the exit
    def _socks5_connect(self, exit_host, exit_port, host, port):
        """Opens host:port through the exit SOCKS5 proxy. Names are sent as names so Psiphon / Tor resolve them remotely."""
        s = socket.socket()
        self._track(s)
        try:
            s.settimeout(8)
            s.connect((exit_host, exit_port))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.settimeout(60)                 # Psiphon and Tor can take long to answer a new connection
            s.sendall(b"\x05\x01\x00")
            r = _read_exact(s, 2)
            if r != b"\x05\x00":
                raise OSError("socks auth")
            req = b"\x05\x01\x00"
            if _is_ipv4(host):
                req += b"\x01" + socket.inet_aton(host)
            elif ":" in host:
                req += b"\x04" + socket.inet_pton(socket.AF_INET6, host)
            else:
                hb = host.encode("idna") if not host.isascii() else host.encode("ascii")
                if not hb or len(hb) > 255:
                    raise OSError("bad host")
                req += b"\x03" + bytes([len(hb)]) + hb
            req += bytes([port >> 8, port & 255])
            s.sendall(req)
            h = _read_exact(s, 4)
            if h[1] != 0:
                raise OSError(f"socks refused {h[1]}")
            atyp = h[3]
            if atyp == 1:
                _read_exact(s, 4 + 2)
            elif atyp == 4:
                _read_exact(s, 16 + 2)
            else:
                ln = _read_exact(s, 1)[0]
                _read_exact(s, ln + 2)
            s.settimeout(None)
            return s
        except Exception:
            self._close(s)
            raise

    # ------------------------------------------------------------ copy both ways
    def _pipe(self, a, b):
        def cp(src, dst):
            ok = True
            try:
                while True:
                    d = src.recv(_BUF)
                    if not d:
                        break
                    dst.sendall(d)
            except OSError:
                ok = False
            if ok:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            else:
                self._close(a)
                self._close(b)

        t = threading.Thread(target=cp, args=(b, a), daemon=True)
        t.start()
        cp(a, b)
        t.join()

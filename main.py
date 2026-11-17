"""
Minimalistic HTTP/HTTPS proxy server with domain blocking.

Usage:
    python main.py [--host HOST] [--port PORT] [--blocklist FILE]

Point your devices' HTTP proxy setting to this server's address and port.
Blocked domains return HTTP 403. HTTPS connections to blocked domains are refused.
"""

import argparse
import socket
import select
import sys
import threading
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

# ─── Configuration ────────────────────────────────────────────────────────────

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8888
BUFFER_SIZE = 65536
BLOCKLIST_FILE = Path(__file__).parent / "blocklist.txt"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-5s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("proxy")

# ─── Blocklist ────────────────────────────────────────────────────────────────

_blocked: set[str] = set()


def load_blocklist(path: Path) -> None:
    """Load domains from a text file (one per line, # comments allowed)."""
    _blocked.clear()
    if not path.exists():
        log.warning("Blocklist file not found: %s — starting with empty list", path)
        return
    for raw in path.read_text().splitlines():
        domain = raw.strip().lower()
        if domain and not domain.startswith("#"):
            _blocked.add(domain)
    log.info("Loaded %d blocked domains from %s", len(_blocked), path)


def is_blocked(host: str) -> bool:
    """Check if *host* (or any parent domain) is in the blocklist."""
    host = host.lower()
    parts = host.split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in _blocked:
            return True
    return False


# ─── Proxy logic ──────────────────────────────────────────────────────────────

# ─── Active session tracking ──────────────────────────────────────────────────

@dataclass
class Session:
    tunnel_id: str
    remote_ip: str
    started: float = field(default_factory=time.monotonic)
    tx_bytes: int = 0  # client → server
    rx_bytes: int = 0  # server → client

_sessions: dict[str, Session] = {}
_sessions_lock = threading.Lock()
_session_counter = 0


def _register_session(tunnel_id: str, remote_ip: str) -> str:
    """Register a new session, return a unique session key."""
    global _session_counter
    with _sessions_lock:
        _session_counter += 1
        key = f"{tunnel_id}#{_session_counter}"
        _sessions[key] = Session(tunnel_id=tunnel_id, remote_ip=remote_ip)
    return key


def _unregister_session(key: str) -> None:
    with _sessions_lock:
        _sessions.pop(key, None)


def _update_session_bytes(key: str, tx: int = 0, rx: int = 0) -> None:
    with _sessions_lock:
        s = _sessions.get(key)
        if s:
            s.tx_bytes += tx
            s.rx_bytes += rx


def _print_active_sessions() -> None:
    with _sessions_lock:
        sessions = list(_sessions.values())
    if not sessions:
        print("\n── Active HTTPS sessions: (none) ──\n")
        return
    now = time.monotonic()
    print(f"\n── Active HTTPS sessions: {len(sessions)} ──")
    print(f"  {'HOST':<45} {'REMOTE IP':<22} {'AGE':>8} {'TX':>12} {'RX':>12}")
    print(f"  {'─'*45} {'─'*22} {'─'*8} {'─'*12} {'─'*12}")
    for s in sorted(sessions, key=lambda s: s.started):
        age = now - s.started
        if age < 60:
            age_str = f"{age:.0f}s"
        elif age < 3600:
            age_str = f"{age/60:.1f}m"
        else:
            age_str = f"{age/3600:.1f}h"
        print(f"  {s.tunnel_id:<45} {s.remote_ip:<22} {age_str:>8} {s.tx_bytes:>12,} {s.rx_bytes:>12,}")
    print()


# ─── Console input listener ──────────────────────────────────────────────────

def _console_listener() -> None:
    """Background thread: reads stdin; prints active sessions when 'i' is pressed."""
    if not sys.stdin.readable():
        return
    try:
        import msvcrt  # Windows: read single keypress without Enter
        while True:
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch.lower() == "i":
                    _print_active_sessions()
            else:
                time.sleep(0.1)
    except ImportError:
        # Unix / fallback: line-buffered, user must press Enter
        for line in sys.stdin:
            if line.strip().lower() == "i":
                _print_active_sessions()


# ──────────────────────────────────────────────────────────────────────────────

BLOCKED_RESPONSE = (
    b"HTTP/1.1 403 Forbidden\r\n"
    b"Content-Type: text/plain\r\n"
    b"Connection: close\r\n\r\n"
    b"Blocked by proxy: this domain is on the blocklist.\n"
)


def _connect_upstream(host: str, port: int, timeout: float = 10) -> socket.socket:
    """Connect to *host*:*port*, trying IPv4 first then IPv6.

    ``socket.create_connection`` takes whichever address family the OS
    resolver returns first — on many Windows machines that's IPv6, which
    may have a broken or slow path to CDN hosts (like *.googlevideo.com).
    This helper resolves all addresses, tries IPv4 first with a short
    per-address timeout, and falls back to IPv6 if needed.
    """
    # Resolve all candidate addresses
    infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    if not infos:
        raise OSError(f"getaddrinfo returned no results for {host}:{port}")

    # Sort: AF_INET (IPv4) first, then AF_INET6
    infos.sort(key=lambda i: (i[0] != socket.AF_INET, i))

    last_err: OSError | None = None
    per_addr_timeout = min(timeout, 5)  # don't spend too long on one address

    for af, socktype, proto, canonname, sa in infos:
        sock = socket.socket(af, socktype, proto)
        sock.settimeout(per_addr_timeout)
        family = "IPv4" if af == socket.AF_INET else "IPv6"
        t0 = time.monotonic()
        try:
            sock.connect(sa)
            elapsed = time.monotonic() - t0
            sock.settimeout(None)  # back to blocking
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            log.debug("[%s:%s] connected via %s to %s in %.0f ms",
                      host, port, family, sa[0], elapsed * 1000)
            return sock
        except OSError as exc:
            elapsed = time.monotonic() - t0
            log.debug("[%s:%s] %s connect to %s failed after %.0f ms: %s",
                      host, port, family, sa[0], elapsed * 1000, exc)
            last_err = exc
            sock.close()

    raise last_err  # type: ignore[misc]


def _relay(label: str, src: socket.socket, dst: socket.socket,
           session_key: str = "", direction: str = "") -> None:
    """Shovel bytes from *src* to *dst* until either side closes.

    On clean EOF: signals the *dst* side with SHUT_WR (half-close) so the
    remote peer knows this direction is done, but leaves the reverse
    direction alive.  Socket cleanup is handled by the caller after both
    relay threads finish.
    """
    total_bytes = 0
    chunks = 0
    error = False
    try:
        while True:
            data = src.recv(BUFFER_SIZE)
            if not data:
                log.debug("[%s] EOF after %d chunks, %d bytes total", label, chunks, total_bytes)
                break
            chunks += 1
            total_bytes += len(data)
            if session_key:
                if direction == "tx":
                    _update_session_bytes(session_key, tx=len(data))
                elif direction == "rx":
                    _update_session_bytes(session_key, rx=len(data))
            if chunks <= 3 or chunks % 100 == 0:
                log.debug("[%s] chunk #%d  (%d bytes, %d total)", label, chunks, len(data), total_bytes)
            dst.sendall(data)
    except OSError as exc:
        error = True
        log.warning("[%s] relay error after %d bytes: %s", label, total_bytes, exc)
    finally:
        # On clean EOF, only half-close the write side of dst so the other
        # relay direction can keep flowing.  On error, don't bother — the
        # caller will tear everything down.
        if not error:
            try:
                dst.shutdown(socket.SHUT_WR)
                log.debug("[%s] half-closed dst (SHUT_WR)", label)
            except OSError:
                pass
        log.debug("[%s] relay finished — %d bytes in %d chunks", label, total_bytes, chunks)


def handle_connect(client: socket.socket, host: str, port: int) -> None:
    """Handle an HTTPS CONNECT tunnel."""
    tunnel_id = f"{host}:{port}"

    if is_blocked(host):
        log.info("BLOCKED  (CONNECT) %s", tunnel_id)
        client.sendall(BLOCKED_RESPONSE)
        client.close()
        return

    log.debug("[%s] opening upstream connection…", tunnel_id)
    t0 = time.monotonic()
    try:
        remote = _connect_upstream(host, port)
    except OSError as exc:
        elapsed = time.monotonic() - t0
        log.warning("[%s] upstream connect failed after %.0f ms: %s", tunnel_id, elapsed * 1000, exc)
        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
        client.close()
        return

    remote_addr = remote.getpeername()
    elapsed = time.monotonic() - t0
    log.info("CONNECT  %s  (remote %s:%s, %.0f ms)", tunnel_id, remote_addr[0], remote_addr[1], elapsed * 1000)
    client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

    session_key = _register_session(tunnel_id, remote_addr[0])

    # Bi-directional relay in two threads — sockets are cleaned up after both finish
    up_label = f"{tunnel_id} client→server"
    dn_label = f"{tunnel_id} server→client"
    t = threading.Thread(target=_relay, args=(up_label, client, remote),
                         kwargs={"session_key": session_key, "direction": "tx"}, daemon=True)
    t.start()
    _relay(dn_label, remote, client, session_key=session_key, direction="rx")
    t.join(timeout=30)

    _unregister_session(session_key)
    log.debug("[%s] both relay directions finished, closing sockets", tunnel_id)
    for s in (client, remote):
        try:
            s.close()
        except OSError:
            pass


def handle_http(client: socket.socket, first_line: str, rest: bytes) -> None:
    """Forward a plain HTTP request."""
    # Parse: METHOD http://host[:port]/path HTTP/1.x
    parts = first_line.split()
    if len(parts) < 3:
        client.close()
        log.info("HTTP parts error : closing the connection")
        return

    method, url, version = parts[0], parts[1], parts[2]

    # Extract host from the URL
    if "://" in url:
        after = url.split("://", 1)[1]
        host_path = after.split("/", 1)
        host_port = host_path[0]
        path = "/" + host_path[1] if len(host_path) > 1 else "/"
    else:
        client.close()
        log.info("HTTP extract host error : closing the connection")
        return

    if ":" in host_port:
        host, port_s = host_port.rsplit(":", 1)
        port = int(port_s)
    else:
        host = host_port
        port = 80

    if is_blocked(host):
        log.info("BLOCKED  (HTTP)    %s", host)
        client.sendall(BLOCKED_RESPONSE)
        client.close()
        return

    # Rebuild the request with a relative path for the upstream server
    request = f"{method} {path} {version}\r\n".encode() + rest

    try:
        remote = _connect_upstream(host, port)
        remote.sendall(request)
    except OSError as exc:
        log.warning("Cannot reach %s:%s — %s", host, port, exc)
        client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
        client.close()
        return

    log.info("HTTP     %s %s", method, url)
    # Simple relay back
    _relay(f"HTTP {method} {host} server→client", remote, client)


def handle_client(client: socket.socket, addr: tuple) -> None:
    """Dispatch a single client connection."""
    try:
        data = client.recv(BUFFER_SIZE)
        if not data:
            log.info("No data found : closing..")
            client.close()
            return

        # Split off the first line
        first_line_end = data.find(b"\r\n")
        if first_line_end == -1:
            log.info("First line not found : closing..")
            client.close()
            return

        first_line = data[:first_line_end].decode("ascii", errors="replace")
        rest = data[first_line_end + 2:]  # everything after the first \r\n

        if first_line.upper().startswith("CONNECT"):
            # CONNECT host:port HTTP/1.x
            target = first_line.split()[1]
            if ":" in target:
                host, port_s = target.rsplit(":", 1)
                port = int(port_s)
            else:
                host, port = target, 443
            handle_connect(client, host, port)
        else:
            handle_http(client, first_line, rest)

    except Exception:
        log.exception("Error handling %s", addr)
        client.close()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    level = logging.DEBUG if "--verbose" in __import__("sys").argv else logging.INFO
    parser = argparse.ArgumentParser(description="Blocking HTTP/HTTPS proxy")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Bind address")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Bind port")
    parser.add_argument("--verbose", "-v", action="store_true", help="Debug logging")
    parser.add_argument(
        "--blocklist",
        type=Path,
        default=BLOCKLIST_FILE,
        help="Path to blocklist file",
    )
    args = parser.parse_args()

    load_blocklist(args.blocklist)
    if args.verbose:
        log.setLevel(logging.DEBUG)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(128)
    log.info("Proxy listening on %s:%d", args.host, args.port)

    # Print network interfaces so the user knows which IPs to point devices at
    log.info("── Network interfaces ──")
    try:
        import psutil  # type: ignore[import-untyped]
        for iface, snics in psutil.net_if_addrs().items():
            ips = [s.address for s in snics if s.family in (socket.AF_INET, socket.AF_INET6) and not s.address.startswith("fe80")]
            if ips:
                log.info("  %-25s %s", iface, ", ".join(ips))
    except ImportError:
        # Fallback: parse hostname + all IPs from getaddrinfo
        try:
            hostname = socket.gethostname()
            seen = []
            for info in socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
                addr = info[4][0]
                if addr not in seen and not addr.startswith("fe80"):
                    seen.append(addr)
            log.info("  %-25s %s", hostname, ", ".join(seen) if seen else "(no addresses)")
        except OSError:
            pass
    log.info("Point devices to any of the above IPs on port %d", args.port)
    log.info("Press 'i' to inspect active HTTPS sessions")

    # Start the console input listener
    threading.Thread(target=_console_listener, daemon=True).start()

    try:
        while True:
            client, addr = srv.accept()
            threading.Thread(
                target=handle_client, args=(client, addr), daemon=True
            ).start()
    except KeyboardInterrupt:
        log.info("Shutting down.")
    finally:
        srv.close()


if __name__ == "__main__":
    main()


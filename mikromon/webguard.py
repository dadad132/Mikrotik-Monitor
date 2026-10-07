"""Keeping one visitor from flooding the dashboard.

Two layers, both per client IP:

  * WebGuard -- requests per second. Every request spends a token from its
    IP's bucket; the bucket refills at a steady rate up to a burst. Logging
    in and signing up have their own, much smaller buckets on top, because
    each try costs a password hash (and a sign-up an email to a stranger).
    Over the limit is a 429 with Retry-After, sent before the page is built.

  * GuardedHTTPServer -- connections. ThreadingHTTPServer starts a thread
    for every connection with no ceiling, so a few thousand idle sockets are
    a few thousand threads. This caps them per IP and in total; past the
    cap a connection is answered 503 and closed at once.

Behind nginx every request arrives from 127.0.0.1 with the visitor's
address in X-Real-IP (deploy/install.sh sets it, overwriting anything the
visitor sent). That header is believed ONLY from a loopback peer -- from
anywhere else it would let a visitor pick a fresh address per request. A
loopback request without it is the server talking to itself (a local tool,
a test) and is not limited. nginx carries its own limits too (install.sh);
these are the floor for when it is bypassed or misconfigured.
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time
from http.server import ThreadingHTTPServer

log = logging.getLogger(__name__)

# (refill per second, burst). A person clicking around, with a page that
# polls every few seconds, never comes near the first.
GENERAL = (10.0, 120)
# POST /login and /signup/verify: a password or a code checked per try.
LOGIN = (20 / 60, 20)
# POST /signup and /signup/resend: each one can send an email.
SIGNUP = (1 / 120, 8)

_LOGIN_PATHS = frozenset({"/login", "/signup/verify"})
_SIGNUP_PATHS = frozenset({"/signup", "/signup/resend"})


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


class TokenBuckets:
    """Per-key token buckets. take() -> 0 when allowed, else the seconds
    until the next token. Idle keys are dropped as they refill, so a stream
    of one-off addresses cannot grow this without bound."""

    def __init__(self, rate: float, burst: int, clock=time.monotonic,
                 max_keys: int = 100_000):
        self.rate, self.burst, self.clock = float(rate), float(burst), clock
        self.max_keys = max_keys
        self._b: dict = {}            # key -> [tokens, last]
        self._lock = threading.Lock()
        self._pruned = clock()

    def take(self, key: str) -> float:
        now = self.clock()
        with self._lock:
            if now - self._pruned > 60 or len(self._b) > self.max_keys:
                self._prune(now)
            tokens, last = self._b.get(key) or (self.burst, now)
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens >= 1:
                self._b[key] = [tokens - 1, now]
                return 0.0
            self._b[key] = [tokens, now]
            return (1 - tokens) / self.rate

    def _prune(self, now: float) -> None:
        full = self.burst / self.rate      # time for an empty bucket to refill
        self._b = {k: v for k, v in self._b.items() if now - v[1] < full}
        if len(self._b) > self.max_keys:   # a flood of addresses: keep newest
            keep = sorted(self._b.items(), key=lambda kv: kv[1][1])
            self._b = dict(keep[-self.max_keys // 2:])
        self._pruned = now


class WebGuard:
    def __init__(self, general=GENERAL, login=LOGIN, signup=SIGNUP,
                 clock=time.monotonic):
        self.general = TokenBuckets(*general, clock=clock)
        self.login = TokenBuckets(*login, clock=clock)
        self.signup = TokenBuckets(*signup, clock=clock)
        self.clock = clock
        self._warned: dict = {}
        self._lock = threading.Lock()

    @staticmethod
    def client_ip(peer: str, headers) -> str | None:
        """The visitor's address, or None for the server's own requests."""
        if not _is_loopback(peer):
            return peer
        real = (headers.get("X-Real-IP") or "").strip() if headers else ""
        return real or None

    def check(self, peer: str, headers, method: str, path: str) -> int:
        """0 to go ahead, else the Retry-After seconds for a 429."""
        ip = self.client_ip(peer, headers)
        if ip is None:
            return 0
        wait = self.general.take(ip)
        if not wait and method == "POST":
            if path in _LOGIN_PATHS:
                wait = self.login.take(ip)
            elif path in _SIGNUP_PATHS:
                wait = self.signup.take(ip)
        if wait:
            self._warn(ip, method, path)
            return max(1, int(wait + 0.999))
        return 0

    def _warn(self, ip: str, method: str, path: str) -> None:
        """One log line per address per minute, not one per refused request
        -- a flood should not also fill the disk."""
        now = self.clock()
        with self._lock:
            if now - self._warned.get(ip, -1e9) < 60:
                return
            self._warned[ip] = now
            if len(self._warned) > 10_000:
                self._warned = {k: v for k, v in self._warned.items()
                                if now - v < 60}
        log.warning("rate limit: slowing %s down (%s %s)", ip, method, path)


class GuardedHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer with a ceiling on connections: per peer address
    (loopback exempt -- behind nginx every visitor is 127.0.0.1, and nginx
    limits them) and in total."""

    daemon_threads = True
    max_connections = 400
    max_per_ip = 40

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._conn_lock = threading.Lock()
        self._per_ip: dict = {}
        self._total = 0

    def _release(self, ip: str) -> None:
        with self._conn_lock:
            self._total -= 1
            n = self._per_ip.get(ip, 1) - 1
            if n > 0:
                self._per_ip[ip] = n
            else:
                self._per_ip.pop(ip, None)

    def process_request(self, request, client_address):
        ip = str(client_address[0])
        with self._conn_lock:
            full = (self._total >= self.max_connections
                    or (not _is_loopback(ip)
                        and self._per_ip.get(ip, 0) >= self.max_per_ip))
            if not full:
                self._total += 1
                self._per_ip[ip] = self._per_ip.get(ip, 0) + 1
        if full:
            try:
                request.settimeout(2)
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\n"
                                b"Retry-After: 10\r\nConnection: close\r\n"
                                b"Content-Length: 0\r\n\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._release(ip)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._release(str(client_address[0]))

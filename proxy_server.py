#!/usr/bin/env python3
"""
Advanced forward proxy server implemented with Python standard library only.

Features:
- HTTP forwarding and HTTPS CONNECT tunneling
- Optional Basic authentication
- Host and CIDR ACL controls
- Per-client token-bucket rate limiting
- In-memory response cache for cacheable GET requests
- Structured request logging

Example:
    python proxy_server.py --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import logging
import select
import signal
import socket
import socketserver
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from http import HTTPStatus
from http.client import HTTPConnection, HTTPResponse
from http.server import BaseHTTPRequestHandler
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit


HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


def now_monotonic() -> float:
    return time.monotonic()


def now_epoch() -> float:
    return time.time()


@dataclass
class TokenBucket:
    rate: float
    capacity: float
    tokens: float = 0.0
    updated_at: float = field(default_factory=now_monotonic)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def allow(self, cost: float = 1.0) -> bool:
        with self.lock:
            ts = now_monotonic()
            elapsed = max(0.0, ts - self.updated_at)
            self.updated_at = ts
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens >= cost:
                self.tokens -= cost
                return True
            return False


@dataclass
class CacheEntry:
    status: int
    reason: str
    headers: List[Tuple[str, str]]
    body: bytes
    expires_at: float
    stored_at: float

    def is_expired(self) -> bool:
        return now_epoch() >= self.expires_at


class ResponseCache:
    def __init__(self, max_entries: int, max_object_bytes: int, default_ttl: int) -> None:
        self.max_entries = max_entries
        self.max_object_bytes = max_object_bytes
        self.default_ttl = default_ttl
        self._store: "OrderedDict[str, CacheEntry]" = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[CacheEntry]:
        with self._lock:
            item = self._store.get(key)
            if not item:
                return None
            if item.is_expired():
                self._store.pop(key, None)
                return None
            self._store.move_to_end(key)
            return item

    def put(self, key: str, entry: CacheEntry) -> None:
        if len(entry.body) > self.max_object_bytes:
            return
        with self._lock:
            self._store[key] = entry
            self._store.move_to_end(key)
            while len(self._store) > self.max_entries:
                self._store.popitem(last=False)


@dataclass
class ProxyConfig:
    connect_timeout: float = 8.0
    io_timeout: float = 30.0
    tunnel_idle_timeout: float = 60.0
    max_request_body: int = 10 * 1024 * 1024
    auth_user: Optional[str] = None
    auth_pass: Optional[str] = None
    allowed_hosts: List[str] = field(default_factory=list)
    blocked_hosts: List[str] = field(default_factory=list)
    blocked_cidrs: List[str] = field(default_factory=list)
    requests_per_minute: int = 240
    cache_enabled: bool = True
    cache_default_ttl: int = 30
    cache_max_entries: int = 200
    cache_max_object_bytes: int = 1024 * 1024


class ACL:
    def __init__(self, allowed_hosts: Iterable[str], blocked_hosts: Iterable[str], blocked_cidrs: Iterable[str]) -> None:
        self.allowed_hosts = [v.lower().strip() for v in allowed_hosts if v.strip()]
        self.blocked_hosts = [v.lower().strip() for v in blocked_hosts if v.strip()]
        self.blocked_networks = [ipaddress.ip_network(v.strip(), strict=False) for v in blocked_cidrs if v.strip()]

    @staticmethod
    def _matches_host(host: str, rule: str) -> bool:
        host = host.lower()
        rule = rule.lower()
        if host == rule:
            return True
        return host.endswith("." + rule)

    def _ip_blocked(self, host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
            return any(ip in net for net in self.blocked_networks)
        except ValueError:
            pass

        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return False
        for info in infos:
            raw = info[4][0]
            try:
                ip = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if any(ip in net for net in self.blocked_networks):
                return True
        return False

    def is_allowed(self, host: str) -> bool:
        h = host.lower()
        if any(self._matches_host(h, r) for r in self.blocked_hosts):
            return False
        if self._ip_blocked(h):
            return False
        if not self.allowed_hosts:
            return True
        return any(self._matches_host(h, r) for r in self.allowed_hosts)


class RateLimiter:
    def __init__(self, requests_per_minute: int) -> None:
        rpm = max(1, requests_per_minute)
        self.rate = rpm / 60.0
        self.capacity = float(rpm)
        self.buckets: Dict[str, TokenBucket] = {}
        self.lock = threading.Lock()

    def allow(self, client_ip: str) -> bool:
        with self.lock:
            bucket = self.buckets.get(client_ip)
            if not bucket:
                bucket = TokenBucket(rate=self.rate, capacity=self.capacity, tokens=self.capacity)
                self.buckets[client_ip] = bucket
        return bucket.allow(1.0)


class ProxyServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address: Tuple[str, int], config: ProxyConfig):
        super().__init__(server_address, ProxyRequestHandler)
        self.config = config
        self.acl = ACL(config.allowed_hosts, config.blocked_hosts, config.blocked_cidrs)
        self.ratelimiter = RateLimiter(config.requests_per_minute)
        self.cache = (
            ResponseCache(config.cache_max_entries, config.cache_max_object_bytes, config.cache_default_ttl)
            if config.cache_enabled
            else None
        )


class ProxyRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_CONNECT(self) -> None:
        if not self._preflight():
            return

        host, port = self._parse_connect_target(self.path)
        if not host:
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid CONNECT target")
            return
        if not self.server.acl.is_allowed(host):
            self.send_error(HTTPStatus.FORBIDDEN, "Target blocked by ACL")
            return

        upstream = None
        try:
            upstream = socket.create_connection((host, port), timeout=self.server.config.connect_timeout)
            self.send_response(HTTPStatus.OK, "Connection Established")
            self.end_headers()
            self._tunnel_bidirectional(self.connection, upstream, self.server.config.tunnel_idle_timeout)
        except OSError as exc:
            self.send_error(HTTPStatus.BAD_GATEWAY, f"CONNECT failed: {exc}")
        finally:
            if upstream:
                try:
                    upstream.close()
                except OSError:
                    pass

    def do_GET(self) -> None:
        self._handle_http_request()

    def do_POST(self) -> None:
        self._handle_http_request()

    def do_PUT(self) -> None:
        self._handle_http_request()

    def do_PATCH(self) -> None:
        self._handle_http_request()

    def do_DELETE(self) -> None:
        self._handle_http_request()

    def do_HEAD(self) -> None:
        self._handle_http_request()

    def do_OPTIONS(self) -> None:
        self._handle_http_request()

    def _preflight(self) -> bool:
        client_ip = self.client_address[0]
        if not self.server.ratelimiter.allow(client_ip):
            self.send_error(HTTPStatus.TOO_MANY_REQUESTS, "Rate limit exceeded")
            return False
        if not self._auth_ok():
            self.send_response(HTTPStatus.PROXY_AUTHENTICATION_REQUIRED, "Proxy auth required")
            self.send_header("Proxy-Authenticate", 'Basic realm="proxy"')
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            return False
        return True

    def _auth_ok(self) -> bool:
        cfg = self.server.config
        if not cfg.auth_user:
            return True
        value = self.headers.get("Proxy-Authorization", "")
        if not value.startswith("Basic "):
            return False
        raw = value[6:].strip()
        try:
            decoded = base64.b64decode(raw).decode("utf-8")
        except Exception:
            return False
        return decoded == f"{cfg.auth_user}:{cfg.auth_pass or ''}"

    def _handle_http_request(self) -> None:
        if not self._preflight():
            return
        request_start = now_monotonic()

        target = self._resolve_http_target()
        if not target:
            self.send_error(HTTPStatus.BAD_REQUEST, "Target URL/Host is invalid")
            return
        scheme, host, port, path, absolute_url = target

        if scheme not in {"http", "https"}:
            self.send_error(HTTPStatus.BAD_REQUEST, "Unsupported URL scheme")
            return
        if scheme == "https":
            self.send_error(HTTPStatus.BAD_REQUEST, "Use CONNECT for HTTPS proxying")
            return
        if not self.server.acl.is_allowed(host):
            self.send_error(HTTPStatus.FORBIDDEN, "Target blocked by ACL")
            return

        req_headers = self._filter_request_headers()
        default_port = 80 if scheme == "http" else 443
        req_headers["Host"] = host if port == default_port else f"{host}:{port}"
        req_body = self._read_request_body()
        if req_body is None:
            return

        cache_key = f"{self.command} {absolute_url}"
        cached = self.server.cache.get(cache_key) if self.server.cache and self.command == "GET" else None
        if cached:
            self._send_cached_response(cached)
            self._log_request(host, port, HTTPStatus(cached.status).phrase, cached.status, request_start, cache="HIT")
            return

        conn = None
        upstream_resp: Optional[HTTPResponse] = None
        try:
            conn = HTTPConnection(host, port=port, timeout=self.server.config.io_timeout)
            conn.request(self.command, path, body=req_body, headers=req_headers)
            upstream_resp = conn.getresponse()
            status = upstream_resp.status
            reason = upstream_resp.reason or HTTPStatus(status).phrase
            resp_headers = self._filter_response_headers(upstream_resp.getheaders())

            body_chunks: List[bytes] = []
            content_length = 0
            should_cache = self._can_cache_response(upstream_resp, resp_headers)

            self.send_response(status, reason)
            for k, v in resp_headers:
                self.send_header(k, v)
            self.send_header("X-Proxy-Cache", "MISS")
            self.end_headers()

            while True:
                chunk = upstream_resp.read(64 * 1024)
                if not chunk:
                    break
                self.wfile.write(chunk)
                if should_cache:
                    content_length += len(chunk)
                    if content_length <= self.server.config.cache_max_object_bytes:
                        body_chunks.append(chunk)
                    else:
                        should_cache = False
                        body_chunks = []

            self.wfile.flush()

            if should_cache and self.server.cache:
                expires_at = self._cache_expiry(resp_headers)
                if expires_at > now_epoch():
                    self.server.cache.put(
                        cache_key,
                        CacheEntry(
                            status=status,
                            reason=reason,
                            headers=resp_headers,
                            body=b"".join(body_chunks),
                            expires_at=expires_at,
                            stored_at=now_epoch(),
                        ),
                    )

            self._log_request(host, port, reason, status, request_start, cache="MISS")
        except TimeoutError:
            self.send_error(HTTPStatus.GATEWAY_TIMEOUT, "Upstream timed out")
        except OSError as exc:
            self.send_error(HTTPStatus.BAD_GATEWAY, f"Upstream error: {exc}")
        finally:
            if upstream_resp:
                try:
                    upstream_resp.close()
                except OSError:
                    pass
            if conn:
                conn.close()

    def _resolve_http_target(self) -> Optional[Tuple[str, str, int, str, str]]:
        raw = self.path.strip()
        if raw.startswith("http://") or raw.startswith("https://"):
            parts = urlsplit(raw)
            if not parts.hostname:
                return None
            scheme = (parts.scheme or "http").lower()
            host = parts.hostname
            port = parts.port or (443 if scheme == "https" else 80)
            path = urlunsplit(("", "", parts.path or "/", parts.query or "", ""))
            absolute = raw
            return scheme, host, port, path, absolute

        host_header = self.headers.get("Host")
        if not host_header:
            return None
        host, port = self._split_host_port(host_header, default_port=80)
        if not host:
            return None
        path = raw if raw.startswith("/") else "/" + raw
        absolute = f"http://{host}:{port}{path}"
        return "http", host, port, path, absolute

    def _read_request_body(self) -> Optional[bytes]:
        content_length = self.headers.get("Content-Length")
        if not content_length:
            return b""
        try:
            total = int(content_length)
        except ValueError:
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid Content-Length")
            return None
        if total < 0 or total > self.server.config.max_request_body:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Request body too large")
            return None
        return self.rfile.read(total)

    def _send_cached_response(self, entry: CacheEntry) -> None:
        self.send_response(entry.status, entry.reason)
        for k, v in entry.headers:
            self.send_header(k, v)
        self.send_header("X-Proxy-Cache", "HIT")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(entry.body)
        self.wfile.flush()

    def _cache_expiry(self, headers: List[Tuple[str, str]]) -> float:
        ttl = self.server.config.cache_default_ttl
        now = now_epoch()
        mapping = {k.lower(): v for k, v in headers}
        cache_control = mapping.get("cache-control", "")
        if cache_control:
            directives = [d.strip().lower() for d in cache_control.split(",")]
            if "no-store" in directives or "private" in directives:
                return now - 1
            for d in directives:
                if d.startswith("max-age="):
                    try:
                        max_age = int(d.split("=", 1)[1])
                        return now + max(0, max_age)
                    except ValueError:
                        pass
        expires = mapping.get("expires")
        if expires:
            try:
                dt = parsedate_to_datetime(expires)
                return dt.timestamp()
            except Exception:
                pass
        return now + ttl

    def _can_cache_response(self, response: HTTPResponse, filtered_headers: List[Tuple[str, str]]) -> bool:
        if self.command != "GET":
            return False
        if response.status != 200:
            return False
        mapping = {k.lower(): v.lower() for k, v in filtered_headers}
        cache_control = mapping.get("cache-control", "")
        if "no-store" in cache_control or "private" in cache_control:
            return False
        return True

    def _filter_request_headers(self) -> Dict[str, str]:
        out: Dict[str, str] = {}
        for k, v in self.headers.items():
            lk = k.lower()
            if lk in HOP_BY_HOP_HEADERS:
                continue
            if lk == "proxy-connection":
                continue
            if lk == "host":
                out["Host"] = v
                continue
            out[k] = v
        out["Connection"] = "close"
        return out

    def _filter_response_headers(self, headers: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        out: List[Tuple[str, str]] = []
        has_length = False
        for k, v in headers:
            lk = k.lower()
            if lk in HOP_BY_HOP_HEADERS:
                continue
            if lk == "proxy-connection":
                continue
            if lk == "content-length":
                has_length = True
            out.append((k, v))
        if not has_length:
            out.append(("Connection", "close"))
        return out

    def _parse_connect_target(self, target: str) -> Tuple[Optional[str], int]:
        host, port = self._split_host_port(target, default_port=443)
        return host, port

    @staticmethod
    def _split_host_port(value: str, default_port: int) -> Tuple[Optional[str], int]:
        raw = value.strip()
        if not raw:
            return None, default_port
        # Bracketed IPv6 form: [::1]:443
        if raw.startswith("["):
            end = raw.find("]")
            if end == -1:
                return None, default_port
            host = raw[1:end]
            port = default_port
            if end + 1 < len(raw) and raw[end + 1] == ":":
                p = raw[end + 2 :]
                try:
                    port = int(p)
                except ValueError:
                    return None, default_port
            return host, port
        if ":" in raw and raw.count(":") == 1:
            host, p = raw.rsplit(":", 1)
            try:
                return host, int(p)
            except ValueError:
                return None, default_port
        return raw, default_port

    def _tunnel_bidirectional(self, client: socket.socket, upstream: socket.socket, idle_timeout: float) -> None:
        client.setblocking(False)
        upstream.setblocking(False)
        sockets = [client, upstream]
        last_activity = now_monotonic()
        while True:
            timeout = max(1.0, idle_timeout - (now_monotonic() - last_activity))
            if timeout <= 0:
                break
            readable, _, exceptional = select.select(sockets, [], sockets, timeout)
            if exceptional:
                break
            if not readable:
                continue
            for sock in readable:
                try:
                    data = sock.recv(64 * 1024)
                except OSError:
                    return
                if not data:
                    return
                last_activity = now_monotonic()
                dst = upstream if sock is client else client
                try:
                    dst.sendall(data)
                except OSError:
                    return

    def _log_request(self, host: str, port: int, reason: str, status: int, start: float, cache: str = "-") -> None:
        elapsed_ms = int((now_monotonic() - start) * 1000)
        payload = {
            "client": self.client_address[0],
            "method": self.command,
            "target": f"{host}:{port}",
            "path": self.path,
            "status": status,
            "reason": reason,
            "duration_ms": elapsed_ms,
            "cache": cache,
            "thread": threading.current_thread().name,
        }
        logging.info(json.dumps(payload, separators=(",", ":")))

    def log_message(self, fmt: str, *args) -> None:
        # Route default BaseHTTPRequestHandler logs through logging module.
        logging.debug("%s - %s", self.client_address[0], fmt % args)

def parse_csv_arg(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [p.strip() for p in value.split(",") if p.strip()]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Advanced Python forward proxy (stdlib only)")
    p.add_argument("--host", default="127.0.0.1", help="Bind address")
    p.add_argument("--port", type=int, default=8080, help="Bind port")
    p.add_argument("--auth-user", default=None, help="Basic auth username")
    p.add_argument("--auth-pass", default=None, help="Basic auth password")
    p.add_argument("--allow-hosts", default="", help="Comma-separated host/domain allowlist")
    p.add_argument("--block-hosts", default="", help="Comma-separated host/domain blocklist")
    p.add_argument("--block-cidrs", default="", help="Comma-separated CIDR blocklist (e.g. 10.0.0.0/8)")
    p.add_argument("--rpm", type=int, default=240, help="Per-client requests per minute")
    p.add_argument("--connect-timeout", type=float, default=8.0)
    p.add_argument("--io-timeout", type=float, default=30.0)
    p.add_argument("--tunnel-idle-timeout", type=float, default=60.0)
    p.add_argument("--max-request-body", type=int, default=10 * 1024 * 1024)
    p.add_argument("--cache", action="store_true", default=False, help="Enable response caching for GET")
    p.add_argument("--cache-ttl", type=int, default=30, help="Default cache TTL seconds")
    p.add_argument("--cache-max-entries", type=int, default=200)
    p.add_argument("--cache-max-object-bytes", type=int, default=1024 * 1024)
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args()


def build_config(args: argparse.Namespace) -> ProxyConfig:
    return ProxyConfig(
        connect_timeout=args.connect_timeout,
        io_timeout=args.io_timeout,
        tunnel_idle_timeout=args.tunnel_idle_timeout,
        max_request_body=args.max_request_body,
        auth_user=args.auth_user,
        auth_pass=args.auth_pass,
        allowed_hosts=parse_csv_arg(args.allow_hosts),
        blocked_hosts=parse_csv_arg(args.block_hosts),
        blocked_cidrs=parse_csv_arg(args.block_cidrs),
        requests_per_minute=args.rpm,
        cache_enabled=args.cache,
        cache_default_ttl=args.cache_ttl,
        cache_max_entries=args.cache_max_entries,
        cache_max_object_bytes=args.cache_max_object_bytes,
    )


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(message)s",
    )
    config = build_config(args)
    server = ProxyServer((args.host, args.port), config)
    stop_event = threading.Event()

    def shutdown_handler(signum, frame):  # type: ignore[no-untyped-def]
        if stop_event.is_set():
            return
        stop_event.set()
        logging.info("signal=%s action=shutdown", signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    logging.info(
        "proxy_start host=%s port=%s auth=%s cache=%s",
        args.host,
        args.port,
        "on" if args.auth_user else "off",
        "on" if args.cache else "off",
    )
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
        logging.info("proxy_stop")


if __name__ == "__main__":
    main()

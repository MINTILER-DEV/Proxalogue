import base64
import socket
import socketserver
import threading
import unittest
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional, Tuple

from proxy_server import ProxyConfig, ProxyServer


class CountingOriginHandler(BaseHTTPRequestHandler):
    hits = 0
    lock = threading.Lock()

    @classmethod
    def reset_hits(cls) -> None:
        with cls.lock:
            cls.hits = 0

    @classmethod
    def get_hits(cls) -> int:
        with cls.lock:
            return cls.hits

    def _write_ok(self, include_body: bool) -> None:
        with self.__class__.lock:
            self.__class__.hits += 1
            hit_number = self.__class__.hits

        body = f"origin-hit-{hit_number}".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Cache-Control", "public, max-age=120")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/redirect-abs":
            port = self.server.server_address[1]
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{port}/final-target")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._write_ok(include_body=True)

    def do_HEAD(self) -> None:
        if self.path == "/redirect-abs":
            port = self.server.server_address[1]
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{port}/final-target")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self._write_ok(include_body=False)

    def log_message(self, fmt: str, *args) -> None:
        return


class EchoTCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            data = self.request.recv(4096)
            if not data:
                return
            self.request.sendall(data)


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_in_thread(server_obj) -> threading.Thread:
    thread = threading.Thread(target=server_obj.serve_forever, daemon=True)
    thread.start()
    return thread


def stop_server(server_obj, thread: threading.Thread) -> None:
    server_obj.shutdown()
    server_obj.server_close()
    thread.join(timeout=3)


def send_proxy_http_request(
    proxy_port: int,
    url_or_path: str,
    headers: Optional[Dict[str, str]] = None,
    method: str = "GET",
) -> Tuple[int, Dict[str, str], bytes]:
    conn = HTTPConnection("127.0.0.1", proxy_port, timeout=5)
    conn.request(method, url_or_path, headers=headers or {})
    resp = conn.getresponse()
    body = resp.read()
    out_headers = {k.lower(): v for k, v in resp.getheaders()}
    status = resp.status
    conn.close()
    return status, out_headers, body


def recv_until(sock: socket.socket, marker: bytes, timeout: float = 5.0) -> bytes:
    sock.settimeout(timeout)
    data = bytearray()
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


class ProxyServerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.origin = ThreadingHTTPServer(("127.0.0.1", 0), CountingOriginHandler)
        cls.origin_thread = start_in_thread(cls.origin)
        cls.origin_port = cls.origin.server_address[1]

        cls.echo = ThreadedTCPServer(("127.0.0.1", 0), EchoTCPHandler)
        cls.echo_thread = start_in_thread(cls.echo)
        cls.echo_port = cls.echo.server_address[1]

    @classmethod
    def tearDownClass(cls) -> None:
        stop_server(cls.origin, cls.origin_thread)
        stop_server(cls.echo, cls.echo_thread)

    def start_proxy(self, config: ProxyConfig) -> Tuple[ProxyServer, threading.Thread, int]:
        proxy = ProxyServer(("127.0.0.1", 0), config)
        thread = start_in_thread(proxy)
        port = proxy.server_address[1]
        return proxy, thread, port

    def test_http_cache_hit(self) -> None:
        CountingOriginHandler.reset_hits()
        config = ProxyConfig(cache_enabled=True, cache_default_ttl=120)
        proxy, thread, port = self.start_proxy(config)
        try:
            url = f"http://127.0.0.1:{self.origin_port}/cacheable"
            headers = {"Host": f"127.0.0.1:{self.origin_port}"}

            first_status, first_headers, first_body = send_proxy_http_request(port, url, headers)
            second_status, second_headers, second_body = send_proxy_http_request(port, url, headers)

            self.assertEqual(first_status, 200)
            self.assertEqual(second_status, 200)
            self.assertEqual(first_headers.get("x-proxy-cache"), "MISS")
            self.assertEqual(second_headers.get("x-proxy-cache"), "HIT")
            self.assertEqual(first_headers.get("access-control-allow-origin"), "*")
            self.assertEqual(second_headers.get("access-control-allow-origin"), "*")
            self.assertEqual(first_body, second_body)
            self.assertEqual(CountingOriginHandler.get_hits(), 1)
        finally:
            stop_server(proxy, thread)

    def test_proxy_auth_required(self) -> None:
        CountingOriginHandler.reset_hits()
        config = ProxyConfig(auth_user="alice", auth_pass="secret", cache_enabled=False)
        proxy, thread, port = self.start_proxy(config)
        try:
            url = f"http://127.0.0.1:{self.origin_port}/auth"
            host_header = {"Host": f"127.0.0.1:{self.origin_port}"}

            status, headers, _ = send_proxy_http_request(port, url, host_header)
            self.assertEqual(status, 407)
            self.assertEqual(headers.get("access-control-allow-origin"), "*")

            token = base64.b64encode(b"alice:secret").decode("ascii")
            auth_headers = dict(host_header)
            auth_headers["Proxy-Authorization"] = f"Basic {token}"
            status2, _, _ = send_proxy_http_request(port, url, auth_headers)
            self.assertEqual(status2, 200)
        finally:
            stop_server(proxy, thread)

    def test_acl_blocked_host(self) -> None:
        config = ProxyConfig(blocked_hosts=["127.0.0.1"], cache_enabled=False)
        proxy, thread, port = self.start_proxy(config)
        try:
            url = f"http://127.0.0.1:{self.origin_port}/blocked"
            headers = {"Host": f"127.0.0.1:{self.origin_port}"}
            status, _, _ = send_proxy_http_request(port, url, headers)
            self.assertEqual(status, 403)
        finally:
            stop_server(proxy, thread)

    def test_connect_tunnel_to_echo_server(self) -> None:
        config = ProxyConfig(cache_enabled=False)
        proxy, thread, port = self.start_proxy(config)
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                connect_req = (
                    f"CONNECT 127.0.0.1:{self.echo_port} HTTP/1.1\r\n"
                    f"Host: 127.0.0.1:{self.echo_port}\r\n"
                    "Proxy-Connection: keep-alive\r\n\r\n"
                ).encode("ascii")
                sock.sendall(connect_req)
                response = recv_until(sock, b"\r\n\r\n", timeout=5)
                self.assertIn(b"200 Connection Established", response)

                payload = b"tunnel-payload"
                sock.sendall(payload)
                echoed = sock.recv(len(payload))
                self.assertEqual(echoed, payload)
        finally:
            stop_server(proxy, thread)

    def test_local_root_path_does_not_self_proxy(self) -> None:
        CountingOriginHandler.reset_hits()
        config = ProxyConfig(cache_enabled=False)
        proxy, thread, port = self.start_proxy(config)
        try:
            status, headers, body = send_proxy_http_request(
                port,
                "/",
                headers={"Host": "proxalogue-proxy.wasmer.app"},
            )
            self.assertEqual(status, 200)
            self.assertEqual(headers.get("access-control-allow-origin"), "*")
            self.assertIn(b"Forward proxy is running", body)
            self.assertEqual(CountingOriginHandler.get_hits(), 0)
        finally:
            stop_server(proxy, thread)

    def test_url_prefix_mode_http(self) -> None:
        CountingOriginHandler.reset_hits()
        config = ProxyConfig(cache_enabled=False)
        proxy, thread, port = self.start_proxy(config)
        try:
            path_mode_url = f"/http://127.0.0.1:{self.origin_port}/path-mode"
            status, headers, body = send_proxy_http_request(
                port,
                path_mode_url,
                headers={"Host": "proxalogue-proxy.wasmer.app"},
                method="HEAD",
            )
            self.assertEqual(status, 200)
            self.assertEqual(headers.get("access-control-allow-origin"), "*")
            self.assertEqual(body, b"")

            status2, _, body2 = send_proxy_http_request(
                port,
                path_mode_url,
                headers={"Host": "proxalogue-proxy.wasmer.app"},
            )
            self.assertEqual(status2, 200)
            self.assertIn(b"origin-hit-", body2)
        finally:
            stop_server(proxy, thread)

    def test_query_url_mode_http(self) -> None:
        CountingOriginHandler.reset_hits()
        config = ProxyConfig(cache_enabled=False)
        proxy, thread, port = self.start_proxy(config)
        try:
            query_mode_path = f"/proxy?url=http://127.0.0.1:{self.origin_port}/query-mode"
            status, headers, body = send_proxy_http_request(
                port,
                query_mode_path,
                headers={"Host": "proxalogue-proxy.wasmer.app"},
            )
            self.assertEqual(status, 200)
            self.assertEqual(headers.get("access-control-allow-origin"), "*")
            self.assertIn(b"origin-hit-", body)
        finally:
            stop_server(proxy, thread)

    def test_url_prefix_mode_rewrites_redirect_location(self) -> None:
        config = ProxyConfig(cache_enabled=False)
        proxy, thread, port = self.start_proxy(config)
        try:
            path_mode_url = f"/http://127.0.0.1:{self.origin_port}/redirect-abs"
            status, headers, _ = send_proxy_http_request(
                port,
                path_mode_url,
                headers={"Host": "proxalogue-proxy.wasmer.app"},
                method="HEAD",
            )
            self.assertEqual(status, 302)
            self.assertEqual(
                headers.get("location"),
                f"/http://127.0.0.1:{self.origin_port}/final-target",
            )
        finally:
            stop_server(proxy, thread)


if __name__ == "__main__":
    unittest.main(verbosity=2)

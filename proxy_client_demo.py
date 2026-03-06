#!/usr/bin/env python3
"""
Small demo client for proxy_server.py.

Modes:
- http-get: send an HTTP GET through the proxy to an absolute URL
- connect: open a CONNECT tunnel and send raw bytes through it
"""

import argparse
import base64
import socket
from http.client import HTTPConnection
from typing import Dict
from urllib.parse import urlsplit


def basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Basic {token}"


def run_http_get(args: argparse.Namespace) -> None:
    parts = urlsplit(args.url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise SystemExit("Only absolute http(s) URLs are supported")
    if parts.scheme != "http":
        raise SystemExit("For HTTPS use the 'connect' mode (this demo keeps stdlib-only and simple)")

    headers: Dict[str, str] = {
        "Host": parts.netloc,
        "Connection": "close",
    }
    if args.user:
        headers["Proxy-Authorization"] = basic_auth_header(args.user, args.password or "")

    conn = HTTPConnection(args.proxy_host, args.proxy_port, timeout=args.timeout)
    try:
        conn.request("GET", args.url, headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        print(f"Status: {resp.status} {resp.reason}")
        print(f"X-Proxy-Cache: {resp.getheader('X-Proxy-Cache', '-')}")
        print(f"Body ({len(body)} bytes):")
        print(body.decode("utf-8", errors="replace"))
    finally:
        conn.close()


def recv_until(sock: socket.socket, marker: bytes, limit: int = 1024 * 1024) -> bytes:
    data = bytearray()
    while marker not in data and len(data) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def run_connect(args: argparse.Namespace) -> None:
    with socket.create_connection((args.proxy_host, args.proxy_port), timeout=args.timeout) as sock:
        lines = [
            f"CONNECT {args.target} HTTP/1.1",
            f"Host: {args.target}",
            "Proxy-Connection: keep-alive",
        ]
        if args.user:
            lines.append(f"Proxy-Authorization: {basic_auth_header(args.user, args.password or '')}")
        request = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
        sock.sendall(request)

        response = recv_until(sock, b"\r\n\r\n")
        head = response.decode("iso-8859-1", errors="replace").splitlines()[0] if response else "<no response>"
        print(f"CONNECT response: {head}")
        if b" 200 " not in response and not response.startswith(b"HTTP/1.1 200"):
            return

        payload = args.payload.encode("utf-8")
        sock.sendall(payload)
        echoed = sock.recv(max(1, len(payload)))
        print(f"Sent:   {payload!r}")
        print(f"Echoed: {echoed!r}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Demo client for proxy_server.py")
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, default=8080)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--user", default=None, help="Proxy auth username")
    parser.add_argument("--password", default=None, help="Proxy auth password")

    sub = parser.add_subparsers(dest="mode", required=True)

    get_parser = sub.add_parser("http-get", help="GET an absolute HTTP URL through proxy")
    get_parser.add_argument("--url", required=True, help="Absolute URL, e.g. http://example.com/")

    connect_parser = sub.add_parser("connect", help="Open CONNECT tunnel and send payload")
    connect_parser.add_argument("--target", required=True, help="host:port to tunnel to")
    connect_parser.add_argument("--payload", default="hello-through-connect")

    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.mode == "http-get":
        run_http_get(args)
        return
    if args.mode == "connect":
        run_connect(args)
        return
    raise SystemExit(f"Unknown mode: {args.mode}")


if __name__ == "__main__":
    main()

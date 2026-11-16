#!/usr/bin/env python3
"""A small HTTPS listener for the title's sign-on and content-manifest requests.

It accepts one TLS 1.2 request per connection, saves the decrypted request under --capture-dir (private, for your
own debugging) and answers HTTP 200 with a fixed body (--reply-body-file). One readable line per request:

    14:02:11 sign-on   POST /signon (482 B) -> 200 OK, 1182 B

--verbose adds the TLS details, the request headers (cookies and authorization redacted) and the capture path.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path

MAX_REQUEST_BYTES = 1 << 20
GAME_HOSTS = (".signon.deadorbit.net", ".signon.gravityshavings.net")   # the hosts the certificate is made for
SENSITIVE_HEADERS = {b"authorization", b"cookie", b"proxy-authorization", b"set-cookie"}


def now() -> str:
    return datetime.now().strftime("%H:%M:%S")


def read_request(connection: ssl.SSLSocket) -> bytes:
    """The request headers and any declared body, with a size cap."""
    connection.settimeout(3)
    data, target = bytearray(), None
    while len(data) < MAX_REQUEST_BYTES:
        try:
            chunk = connection.recv(min(8192, MAX_REQUEST_BYTES - len(data)))
        except TimeoutError:
            break
        if not chunk:
            break
        data += chunk
        if target is None:
            end = data.find(b"\r\n\r\n")
            if end < 0:
                continue
            target = end + 4
            for line in bytes(data[:end]).split(b"\r\n")[1:]:
                name, sep, value = line.partition(b":")
                if sep and name.strip().lower() == b"content-length":
                    try:
                        target += int(value.strip())
                    except ValueError:
                        pass
                    break
        if target is not None and len(data) >= target:
            break
    return bytes(data)


def send_response(connection: ssl.SSLSocket, body: bytes) -> None:
    connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                       + f"Content-Length: {len(body)}\r\n".encode() + b"Connection: close\r\n\r\n" + body)


def save_capture(capture_dir: Path, request: bytes) -> Path:
    capture_dir.mkdir(parents=True, exist_ok=True)
    path = capture_dir / f"request-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')}.bin"
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as fh:
        fh.write(request)
    return path


def describe(request: bytes) -> tuple[str, list[str]]:
    """('POST /path (n B)', header lines for --verbose)."""
    end = request.find(b"\r\n\r\n")
    if end < 0:
        return f"incomplete request ({len(request)} B)", []
    lines = request[:end].split(b"\r\n")
    first = lines[0].decode("latin-1", "replace").rsplit(" HTTP/", 1)[0]
    headers = []
    for line in lines[1:]:
        name, sep, value = line.partition(b":")
        if sep:
            shown = b"<redacted>" if name.strip().lower() in SENSITIVE_HEADERS else value.strip()
            headers.append(f"    {name.decode('latin-1', 'replace')}: {shown.decode('latin-1', 'replace')}")
    return f"{first} ({len(request) - end - 4} B body)", headers


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", default="listener", help="label printed on each line (e.g. sign-on, manifest)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--cert", required=True, type=Path)
    ap.add_argument("--key", required=True, type=Path)
    ap.add_argument("--capture-dir", type=Path, default=Path("private/requests"))
    ap.add_argument("--reply-body-file", required=True, type=Path, help="body of every HTTP 200 reply")
    ap.add_argument("--dedup-captures", action="store_true", help="save each distinct request only once")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    body = args.reply_body_file.read_bytes()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:@SECLEVEL=0")
    context.load_cert_chain(certfile=args.cert, keyfile=args.key)
    sni = {"name": None}
    context.set_servername_callback(lambda _s, name, _c: sni.__setitem__("name", name))
    seen: set[str] = set()
    failed: dict[str, int] = {}
    label = f"{args.name:<9s}"

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.host, args.port))
        listener.listen()
        print(f"{now()} {label} listening on {args.host}:{args.port} "
              f"(replies with {args.reply_body_file}, {len(body)} B)", flush=True)
        try:
            while True:
                connection, peer = listener.accept()
                sni["name"] = None
                try:
                    with context.wrap_socket(connection, server_side=True) as tls:
                        request = read_request(tls)
                        if not request:
                            print(f"{now()} {label} connection from {peer[0]} closed without a request", flush=True)
                            continue
                        what, headers = describe(request)
                        digest = hashlib.sha256(request).hexdigest()
                        capture = None
                        if not (args.dedup_captures and digest in seen):
                            seen.add(digest)
                            capture = save_capture(args.capture_dir, request)
                        send_response(tls, body)
                        print(f"{now()} {label} {what} -> 200 OK, {len(body)} B", flush=True)
                        if args.verbose:
                            print(f"    TLS {tls.version()} {tls.cipher()[0]}, SNI {sni['name'] or '(none)'}, "
                                  f"from {peer[0]}:{peer[1]}", flush=True)
                            print("\n".join(headers), flush=True)
                            print(f"    capture: {capture or 'duplicate, not saved'}", flush=True)
                        try:
                            tls.unwrap().close()
                        except (ssl.SSLError, OSError, TimeoutError):
                            pass
                except (ssl.SSLError, OSError, TimeoutError) as error:
                    host = sni["name"] or "(no name)"
                    failed[host] = failed.get(host, 0) + 1
                    if failed[host] == 1 or args.verbose:
                        hint = ("" if host.endswith(GAME_HOSTS) else
                                " - not a server this stand-in provides; harmless (further ones not shown)")
                        print(f"{now()} {label} connection for {host} failed: {error}{hint}", flush=True)
        except KeyboardInterrupt:
            print(f"{now()} {label} stopped", flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Capture local HTTPS requests and optionally send controlled HTTP replies."""

from __future__ import annotations

import argparse
import hashlib
import os
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path

MAX_REQUEST_BYTES = 1 << 20
SENSITIVE_HEADERS = {"authorization", "cookie", "proxy-authorization", "set-cookie"}
PENDING_ERROR_PREFIX = bytes.fromhex("08 02 3A 09 08 05 22 05 45 72 72 6F 72 60")
PENDING_ERROR_DISCRIMINATOR_ZERO_PREFIX = bytes.fromhex(
    "08 00 3A 09 08 05 22 05 45 72 72 6F 72 60"
)
PENDING_ERROR_DISCRIMINATOR_ONE_PREFIX = bytes.fromhex(
    "08 01 3A 09 08 05 22 05 45 72 72 6F 72 60"
)
PENDING_ERROR_SUFFIX = bytes.fromhex(
    "6A 12 50 72 6F 64 52 65 74 61 69 6C 3A 50 65 6E 64 69 6E 67"
)
# Minimal length-delimited top-level field 2. This is the first controlled
# schema probe for the discriminator-1 record family; the nested message is
# intentionally empty so presence/branch selection is tested separately from
# guessed field values.
TYPE1_EMPTY_FIELD_TWO = bytes.fromhex("12 00")


def encode_varint(value: int) -> bytes:
    """Encode one non-negative protobuf-style unsigned varint."""
    if value < 0:
        raise ValueError("varint value must be non-negative")
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def pending_error_body(
    server_time: int | None = None,
    *,
    discriminator: int = 2,
    extra_fields: bytes = b"",
) -> tuple[bytes, int]:
    """Build the observed error body, optionally with a schema probe field."""
    if server_time is None:
        server_time = int(time.time())
    if discriminator == 2:
        prefix = PENDING_ERROR_PREFIX
    elif discriminator == 0:
        prefix = PENDING_ERROR_DISCRIMINATOR_ZERO_PREFIX
    elif discriminator == 1:
        prefix = PENDING_ERROR_DISCRIMINATOR_ONE_PREFIX
    else:
        raise ValueError(f"unsupported pending/error discriminator: {discriminator}")
    # The existing prefix contains field 1 followed by the field-7 Error
    # record and field-12's tag. Keep any candidate field in tag order.
    body = (
        prefix[:2]
        + extra_fields
        + prefix[2:]
        + encode_varint(server_time)
        + PENDING_ERROR_SUFFIX
    )
    expected_length = 39 + len(extra_fields)
    if len(body) != expected_length:
        raise AssertionError(f"unexpected pending/error body length: {len(body)}")
    return body, server_time


def send_http_response(connection: ssl.SSLSocket, body: bytes) -> None:
    """Send the minimal response envelope used by the controlled experiments."""
    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/octet-stream\r\n"
        + f"Content-Length: {len(body)}\r\n".encode("ascii")
        + b"Connection: close\r\n"
        b"\r\n"
        + body
    )
    connection.sendall(response)


def read_request(connection: ssl.SSLSocket) -> bytes:
    """Read the request headers and any declared body, with a strict size cap."""
    connection.settimeout(3)
    data = bytearray()
    target: int | None = None

    while len(data) < MAX_REQUEST_BYTES:
        try:
            chunk = connection.recv(min(8192, MAX_REQUEST_BYTES - len(data)))
        except TimeoutError:
            break
        if not chunk:
            break
        data.extend(chunk)

        if target is None:
            header_end = data.find(b"\r\n\r\n")
            if header_end < 0:
                continue
            target = header_end + 4
            for line in bytes(data[:header_end]).split(b"\r\n")[1:]:
                name, separator, value = line.partition(b":")
                if separator and name.strip().lower() == b"content-length":
                    try:
                        target += int(value.strip())
                    except ValueError:
                        pass
                    break
            if target > MAX_REQUEST_BYTES:
                return bytes(data)
            if len(data) >= target:
                break

        if target is not None and len(data) >= target:
            break

    return bytes(data)


def save_capture(capture_dir: Path, request: bytes) -> Path:
    capture_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    path = capture_dir / f"request-{stamp}.bin"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(request)
    return path


def log_request(request: bytes, capture: Path) -> None:
    header_end = request.find(b"\r\n\r\n")
    if header_end < 0:
        print(f"Received {len(request)} decrypted bytes without complete HTTP headers")
        return

    lines = request[:header_end].split(b"\r\n")
    print(f"HTTP request: {lines[0].decode('latin-1', errors='replace')}")
    for line in lines[1:]:
        name, separator, value = line.partition(b":")
        if not separator:
            continue
        label = name.decode("latin-1", errors="replace")
        if name.strip().lower().decode("ascii", errors="ignore") in SENSITIVE_HEADERS:
            rendered = "<redacted>"
        else:
            rendered = value.strip().decode("latin-1", errors="replace")
        print(f"  {label}: {rendered}")

    body = request[header_end + 4 :]
    print(f"Body: {len(body)} bytes; SHA-256={hashlib.sha256(body).hexdigest()}")
    print(f"Private raw capture: {capture}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--cert", required=True, type=Path)
    parser.add_argument("--key", required=True, type=Path)
    parser.add_argument("--capture-dir", type=Path, default=Path("local/tls/captures"))
    replies = parser.add_mutually_exclusive_group()
    replies.add_argument(
        "--reply-empty-200",
        action="store_true",
        help="after each capture, return HTTP 200 with a zero-byte body",
    )
    replies.add_argument(
        "--reply-live-pending-error",
        action="store_true",
        help=(
            "after each capture, return the observed 39-byte Error/"
            "ProdRetail:Pending body with the current Unix time"
        ),
    )
    replies.add_argument(
        "--reply-pending-error-discriminator-zero",
        action="store_true",
        help=(
            "after each capture, return the pending/error body with only its "
            "leading discriminator changed from 2 to 0"
        ),
    )
    replies.add_argument(
        "--reply-pending-error-discriminator-one",
        action="store_true",
        help=(
            "after each capture, return the pending/error body with only its "
            "leading discriminator changed from 2 to 1"
        ),
    )
    replies.add_argument(
        "--reply-pending-error-type1-field-two-empty",
        action="store_true",
        help=(
            "after each capture, return discriminator 1 with an empty "
            "top-level field-2 nested message (bytes 12 00)"
        ),
    )
    replies.add_argument(
        "--reply-body-hex",
        metavar="HEX",
        help=(
            "after each capture, return HTTP 200 with this exact body, given as "
            "hex bytes (whitespace allowed). Example: --reply-body-hex '08 01 1A 00'"
        ),
    )
    replies.add_argument(
        "--reply-body-file",
        type=Path,
        metavar="PATH",
        help="after each capture, return HTTP 200 with the exact bytes in PATH",
    )
    parser.add_argument(
        "--reload-reply-body-file",
        action="store_true",
        help="re-read --reply-body-file for each request (for controlled response iteration)",
    )
    parser.add_argument(
        "--dedup-captures",
        action="store_true",
        help=(
            "only write a capture the first time a given request is seen; repeated "
            "identical requests (e.g. a client retry storm) are logged but not saved"
        ),
    )
    args = parser.parse_args()

    custom_body: bytes | None = None
    if args.reply_body_hex is not None:
        cleaned = "".join(args.reply_body_hex.split())
        try:
            custom_body = bytes.fromhex(cleaned)
        except ValueError:
            parser.error(f"--reply-body-hex is not valid hex: {args.reply_body_hex!r}")
    elif args.reply_body_file is not None:
        custom_body = args.reply_body_file.read_bytes()
    if args.reload_reply_body_file and args.reply_body_file is None:
        parser.error("--reload-reply-body-file requires --reply-body-file")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_ciphers("AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:@SECLEVEL=0")
    context.load_cert_chain(certfile=args.cert, keyfile=args.key)

    current_sni: dict[str, str | None] = {"name": None}
    seen_captures: set[str] = set()

    def remember_sni(_socket: ssl.SSLSocket, server_name: str | None, _context: ssl.SSLContext) -> None:
        current_sni["name"] = server_name

    context.set_servername_callback(remember_sni)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((args.host, args.port))
        listener.listen()
        if args.reply_live_pending_error:
            mode = "live pending/error HTTP 200 replies enabled"
        elif args.reply_pending_error_discriminator_zero:
            mode = "discriminator-0 pending/error HTTP 200 replies enabled"
        elif args.reply_pending_error_discriminator_one:
            mode = "discriminator-1 pending/error HTTP 200 replies enabled"
        elif args.reply_pending_error_type1_field_two_empty:
            mode = "type-1 field-2-empty pending/error HTTP 200 replies enabled"
        elif custom_body is not None:
            if args.reload_reply_body_file:
                mode = f"live HTTP 200 replies from {args.reply_body_file}"
            else:
                mode = (
                    f"fixed HTTP 200 replies enabled ({len(custom_body)}-byte body: "
                    f"{custom_body.hex() or '(empty)'})"
                )
        elif args.reply_empty_200:
            mode = "empty HTTP 200 replies enabled"
        else:
            mode = "no HTTP response will be sent"
        print(f"TLS probe listening on {args.host}:{args.port}; {mode}", flush=True)
        try:
            while True:
                connection, peer = listener.accept()
                current_sni["name"] = None
                try:
                    with context.wrap_socket(connection, server_side=True) as secure:
                        print(
                            f"{peer}: TLS {secure.version()}, cipher={secure.cipher()[0]}, "
                            f"SNI={current_sni['name'] or '(none)'}",
                            flush=True,
                        )
                        request = read_request(secure)
                        if request:
                            digest = hashlib.sha256(request).hexdigest()
                            if args.dedup_captures and digest in seen_captures:
                                print(
                                    f"{peer}: duplicate request (sha256 {digest[:12]}...); "
                                    "capture skipped",
                                    flush=True,
                                )
                            else:
                                seen_captures.add(digest)
                                capture = save_capture(args.capture_dir, request)
                                log_request(request, capture)
                            if (
                                args.reply_live_pending_error
                                or args.reply_pending_error_discriminator_zero
                                or args.reply_pending_error_discriminator_one
                                or args.reply_pending_error_type1_field_two_empty
                            ):
                                if args.reply_pending_error_type1_field_two_empty:
                                    discriminator = 1
                                    extra_fields = TYPE1_EMPTY_FIELD_TWO
                                elif args.reply_pending_error_discriminator_zero:
                                    discriminator = 0
                                    extra_fields = b""
                                elif args.reply_pending_error_discriminator_one:
                                    discriminator = 1
                                    extra_fields = b""
                                else:
                                    discriminator = 2
                                    extra_fields = b""
                                body, server_time = pending_error_body(
                                    discriminator=discriminator,
                                    extra_fields=extra_fields,
                                )
                                send_http_response(secure, body)
                                print(
                                    "HTTP response: 200 OK; "
                                    f"{len(body)}-byte Error/ProdRetail:Pending body; "
                                    f"discriminator={discriminator}; "
                                    f"extra_fields={extra_fields.hex() or '(none)'}; "
                                    f"unix_time={server_time}",
                                    flush=True,
                                )
                                try:
                                    secure.unwrap().close()
                                except (ssl.SSLError, OSError, TimeoutError) as error:
                                    print(f"TLS shutdown after response was incomplete: {error}", flush=True)
                            elif custom_body is not None:
                                body = (
                                    args.reply_body_file.read_bytes()
                                    if args.reload_reply_body_file else custom_body
                                )
                                send_http_response(secure, body)
                                print(
                                    "HTTP response: 200 OK; "
                                    f"{len(body)}-byte body: "
                                    f"{body.hex() or '(empty)'}",
                                    flush=True,
                                )
                                try:
                                    secure.unwrap().close()
                                except (ssl.SSLError, OSError, TimeoutError) as error:
                                    print(f"TLS shutdown after response was incomplete: {error}", flush=True)
                            elif args.reply_empty_200:
                                send_http_response(secure, b"")
                                print("HTTP response: 200 OK; empty body", flush=True)
                                try:
                                    secure.unwrap().close()
                                except (ssl.SSLError, OSError, TimeoutError) as error:
                                    print(f"TLS shutdown after response was incomplete: {error}", flush=True)
                        else:
                            print(f"{peer}: TLS established; no HTTP request received", flush=True)
                except (ssl.SSLError, OSError, TimeoutError) as error:
                    print(
                        f"{peer}: TLS/request failed; SNI={current_sni['name'] or '(none)'}: {error}",
                        flush=True,
                    )
        except KeyboardInterrupt:
            print("Stopped", flush=True)


if __name__ == "__main__":
    main()

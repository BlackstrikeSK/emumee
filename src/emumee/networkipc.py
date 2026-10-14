"""Parent-side network broker for a network-disabled AppContainer worker.

The two fixed streams are opened by the parent before the worker starts. The
broker never opens a path supplied by the worker, including if it replaces or
links either stream after launch.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import socket
import ssl
import struct
import threading
import time
import os
import uuid
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from .network import MAX_TRANSFER, NetworkDenied, public_ipv4
from .networkfixtures import (MAX_FIXTURE_FILE, matching_fixture,
                              parse_network_fixtures)
from .safeio import read_regular_file


MAX_MESSAGE = 24 * 1024 * 1024
MAX_CALLS = 4_096
MAX_REQUEST_STREAM = 128 * 1024 * 1024
MAX_OPEN_SOCKETS = 128
MAX_URL = 2_048
MAX_HOST = 253
MAX_HEADER_BYTES = 16 * 1024
MAX_OPERATION = 64
BROKER_JOURNAL = "network-broker.journal"
BROKER_IPC_DIRECTORY = "broker-ipc"
MAX_BROKER_JOURNAL_BYTES = 64 * 1024 * 1024
MAX_BROKER_EVENT_BYTES = 40 * 1024
MAX_BROKER_EVENTS = 50_000


def broker_ipc_dir(run_dir: Path) -> Path:
    """Use the dedicated broker directory when the parent has staged one."""
    private = run_dir / BROKER_IPC_DIRECTORY
    try:
        details = private.lstat()
    except FileNotFoundError:
        return run_dir
    if not private.is_dir() or getattr(details, "st_file_attributes", 0) & 0x400:
        raise NetworkDenied("Broker IPC path is not a regular directory")
    return private


def _packet(message: dict) -> bytes:
    payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_MESSAGE:
        raise ValueError("Network broker message too large")
    return struct.pack("<I", len(payload)) + payload


def _read_packet(stream, limit: float) -> dict:
    until = time.monotonic() + limit
    while time.monotonic() < until:
        position = stream.tell()
        header = stream.read(4)
        if len(header) == 4:
            size = struct.unpack("<I", header)[0]
            if size > MAX_MESSAGE:
                raise ValueError("Network broker message exceeds limit")
            payload = stream.read(size)
            if len(payload) == size:
                return json.loads(payload)
        stream.seek(position)
        time.sleep(0.01)
    raise TimeoutError("Network broker did not respond")


def read_broker_journal(stream) -> tuple[list[dict], bool, str | None]:
    """Recover complete bounded records from a parent-held journal file handle."""
    stream.seek(0)
    data = stream.read(MAX_BROKER_JOURNAL_BYTES + 1)
    if len(data) > MAX_BROKER_JOURNAL_BYTES:
        raise NetworkDenied("Network broker journal exceeds limit")
    events: list[dict] = []
    for line in data.splitlines(keepends=True):
        if not line.endswith(b"\n"):
            return events, False, "Network broker journal ended mid-record"
        if len(line) > MAX_BROKER_EVENT_BYTES or len(events) >= MAX_BROKER_EVENTS:
            return events, False, "Network broker journal record limit exceeded"
        try:
            value = json.loads(line)
        except (UnicodeError, ValueError, RecursionError):
            return events, False, "Network broker journal contains malformed JSON"
        if (not isinstance(value, dict) or not isinstance(value.get("event"), str)
                or len(value["event"]) > 64):
            return events, False, "Network broker journal contains malformed event"
        events.append(value)
    complete = bool(events) and events[-1] == {"event": "broker_closed"}
    return events, complete, None if complete else "Network broker journal has no close marker"


class FileRPCClient:
    def __init__(self, run_dir: Path):
        ipc_dir = broker_ipc_dir(run_dir)
        self.requests = (ipc_dir / "network-requests.bin").open("ab", buffering=0)
        self.responses = (ipc_dir / "network-responses.bin").open("rb", buffering=0)
        self.sequence = 0

    def call(self, op: str, **kwargs):
        self.sequence += 1
        self.requests.write(_packet({"id": self.sequence, "op": op, **kwargs}))
        reply = _read_packet(self.responses, 55)
        if (not isinstance(reply, dict) or type(reply.get("id")) is not int
                or type(reply.get("ok")) is not bool):
            raise NetworkDenied("Malformed network broker reply")
        if reply.get("id") != self.sequence:
            raise OSError("Out-of-order network broker reply")
        if not reply.get("ok"):
            raise NetworkDenied(str(reply.get("error", "Network broker denied request")))
        return reply.get("value")

    def close(self) -> None:
        self.requests.close()
        self.responses.close()


class NetworkBroker:
    def __init__(self, run_dir: Path, *, network_mode: str | None = None,
                 local_hostname: str | None = None,
                 journal_path: Path | None = None):
        self.run_dir = run_dir
        self.ipc_dir = broker_ipc_dir(run_dir)
        request_raw = (read_regular_file(run_dir / "request.json", 1024 * 1024)
                       if network_mode is None or local_hostname is None else None)
        try:
            request_document = json.loads(request_raw) if request_raw is not None else {}
        except (ValueError, RecursionError):
            request_document = {}
        mode = (network_mode if network_mode is not None else
                request_document.get("network_mode", "live") if isinstance(
                    request_document, dict) else "live")
        if mode not in {"live", "live_with_exact_fixtures", "offline_replay"}:
            raise NetworkDenied("Invalid network mode")
        self.offline_replay = mode == "offline_replay"
        persona = request_document.get("persona") if isinstance(request_document, dict) else None
        hostname = (local_hostname if local_hostname is not None else
                    persona.get("hostname") if isinstance(persona, dict) else None)
        self.local_hostnames = {"localhost"}
        if isinstance(hostname, str) and 0 < len(hostname) <= MAX_HOST:
            self.local_hostnames.add(hostname.casefold().rstrip("."))
        fixture_path = run_dir / "network-fixtures.json"
        if fixture_path.exists():
            if fixture_path.is_symlink() or not fixture_path.is_file():
                raise NetworkDenied("HTTP fixture file is not a regular bounded file")
            with fixture_path.open("rb") as stream:
                fixture_data = stream.read(MAX_FIXTURE_FILE + 1)
            if len(fixture_data) > MAX_FIXTURE_FILE:
                raise NetworkDenied("HTTP fixture file exceeds 48 MiB")
            self.fixtures = parse_network_fixtures(fixture_data)
        else:
            self.fixtures = []
        self.request_path = self.ipc_dir / "network-requests.bin"
        self.response_path = self.ipc_dir / "network-responses.bin"
        self.request_path.write_bytes(b"")
        self.response_path.write_bytes(b"")
        self.requests = self.request_path.open("rb", buffering=0)
        self.responses = self.response_path.open("ab", buffering=0)
        self.journal_path = journal_path if journal_path is not None else run_dir / BROKER_JOURNAL
        self.journal = self.journal_path.open("ab", buffering=0)
        self.journal_bytes = self.journal.tell()
        if self.journal_bytes:
            self.journal.close()
            self.requests.close()
            self.responses.close()
            raise RuntimeError("Network broker journal was not empty at startup")
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, name="emumee-network-broker", daemon=True)
        self.events: list[dict] = []
        self.sockets: dict[int, socket.socket] = {}
        self.next_socket = 1
        self.thread.start()

    def _public_address(self, host: str, port: int) -> str:
        if host.casefold().rstrip(".") in getattr(self, "local_hostnames", {"localhost"}):
            raise NetworkDenied(f"Virtual or host-local destination denied: {host}")
        return public_ipv4(host, port)

    def _event(self, value: dict) -> None:
        line = json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
        if (len(line) > MAX_BROKER_EVENT_BYTES or len(self.events) >= MAX_BROKER_EVENTS or
                self.journal_bytes + len(line) > MAX_BROKER_JOURNAL_BYTES):
            raise NetworkDenied("Network broker journal quota exceeded")
        written = self.journal.write(line)
        if written != len(line):
            raise OSError("Network broker journal write was incomplete")
        self.journal_bytes += written
        self.events.append(value)

    def _serve(self) -> None:
        calls = 0
        while not self.stop.is_set():
            try:
                request = _read_packet(self.requests, 0.1)
            except TimeoutError:
                continue
            except (ValueError, UnicodeDecodeError, RecursionError) as exc:
                self._event({"event": "protocol_error", "error": str(exc)})
                break
            calls += 1
            if calls > MAX_CALLS or self.requests.tell() > MAX_REQUEST_STREAM:
                reason = "Broker request quota exceeded"
                self._event({"event": "protocol_error", "error": reason})
                if isinstance(request, dict) and type(request.get("id")) is int:
                    try:
                        self.responses.write(_packet({"id": request["id"], "ok": False,
                                                      "error": reason}))
                    except (OSError, ValueError):
                        pass
                break
            if not isinstance(request, dict):
                self._event({"event": "protocol_error", "error": "Malformed broker request"})
                break
            ident = request.get("id")
            op = request.get("op")
            if (type(ident) is not int or ident != calls or not isinstance(op, str)
                    or not op or len(op) > MAX_OPERATION):
                self._event({"event": "protocol_error", "error": "Invalid request ID or operation"})
                break
            self._event({"event": "request", "id": ident, "op": op})
            try:
                value = self._handle(request)
                response = {"id": ident, "ok": True, "value": value}
            except Exception as exc:
                self._event({"event": "error", "id": ident, "op": op, "error": str(exc)})
                response = {"id": ident, "ok": False, "error": str(exc)}
            try:
                self.responses.write(_packet(response))
            except (OSError, ValueError) as exc:
                self._event({"event": "protocol_error", "error": str(exc)})
                break

    def _handle(self, request: dict):
        op = request["op"]
        if getattr(self, "offline_replay", False) and op.startswith("socket_"):
            event = {"event": "network_replay_miss", "operation": op}
            if isinstance(request.get("host"), str):
                event["host"] = request["host"][:MAX_HOST]
            if type(request.get("port")) is int:
                event["port"] = request["port"]
            self._event(event)
            raise NetworkDenied("Offline replay denied raw socket operation")
        if op == "resolve":
            host = request["host"]
            if not isinstance(host, str) or not 0 < len(host) <= MAX_HOST:
                raise NetworkDenied("Invalid DNS hostname")
            self._event({"event": "dns_attempt", "host": host})
            if getattr(self, "offline_replay", False):
                self._event({"event": "network_replay_miss", "operation": "dns",
                             "host": host})
                raise NetworkDenied("Offline replay denied DNS request")
            address = self._public_address(host, 80)
            self._event({"event": "dns", "host": host, "address": address})
            return address
        if op == "socket_open":
            af, typ = int(request["af"]), int(request["type"])
            if af != socket.AF_INET or typ not in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                raise NetworkDenied("Only IPv4 TCP/UDP sockets are supported")
            if len(self.sockets) >= MAX_OPEN_SOCKETS:
                raise NetworkDenied("Broker socket quota exceeded")
            sock = socket.socket(af, typ)
            sock.settimeout(10)
            ident = self.next_socket
            self.next_socket += 1
            self.sockets[ident] = sock
            self._event({"event": "socket_open", "socket": ident, "type": typ})
            return ident
        if op == "socket_connect":
            ident, host, port = int(request["socket"]), request["host"], int(request["port"])
            if not isinstance(host, str) or not 0 < len(host) <= MAX_HOST:
                raise NetworkDenied("Invalid socket hostname")
            self._event({"event": "connect_attempt", "socket": ident,
                                "host": host, "port": port})
            address = self._public_address(host, port)
            self.sockets[ident].connect((address, port))
            self._event({"event": "connect", "socket": ident, "host": host,
                                "address": address, "port": port})
            return True
        if op == "socket_send":
            ident = int(request["socket"])
            encoded = request["data"]
            if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_TRANSFER + 2) // 3):
                raise NetworkDenied("Network send exceeds 16 MiB limit")
            payload = base64.b64decode(encoded, validate=True)
            if len(payload) > MAX_TRANSFER:
                raise NetworkDenied("Network send exceeds 16 MiB limit")
            self._event({"event": "send_attempt", "socket": ident,
                                "size": len(payload),
                                "sha256": hashlib.sha256(payload).hexdigest()})
            sent = self.sockets[ident].send(payload)
            self._event({"event": "send", "socket": ident, "size": sent,
                                "sha256": hashlib.sha256(payload[:sent]).hexdigest()})
            return sent
        if op == "socket_recv":
            ident, size = int(request["socket"]), int(request["size"])
            if not 0 <= size <= MAX_TRANSFER:
                raise NetworkDenied("Invalid receive length")
            flags = socket.MSG_PEEK if request.get("peek") else 0
            self._event({"event": "recv_attempt", "socket": ident,
                                "size": size, "peek": bool(flags)})
            payload = self.sockets[ident].recv(size, flags)
            self._event({"event": "recv", "socket": ident, "size": len(payload),
                                "sha256": hashlib.sha256(payload).hexdigest()})
            return base64.b64encode(payload).decode("ascii")
        if op == "socket_close":
            ident = int(request["socket"])
            self.sockets.pop(ident).close()
            self._event({"event": "close", "socket": ident})
            return True
        if op in {"http_fetch", "http_fetch_meta"}:
            encoded_body = request.get("body", "")
            if (not isinstance(encoded_body, str)
                    or len(encoded_body) > 4 * ((MAX_TRANSFER + 2) // 3)):
                raise NetworkDenied("HTTP body exceeds 16 MiB limit")
            body = base64.b64decode(encoded_body, validate=True)
            if len(body) > MAX_TRANSFER:
                raise NetworkDenied("HTTP body exceeds 16 MiB limit")
            chunked = request.get("chunked", False)
            if type(chunked) is not bool:
                raise NetworkDenied("Invalid HTTP chunked flag")
            payload, metadata = self._fetch(request["url"], request.get("method", "GET"),
                                            body if chunked else body or None,
                                            request.get("headers") or {}, chunked=chunked)
            encoded = base64.b64encode(payload).decode("ascii")
            return {"body": encoded, **metadata} if op == "http_fetch_meta" else encoded
        raise NetworkDenied(f"Unsupported network operation: {op}")

    def _fetch(self, url: str, method: str, body: bytes | None,
               headers: dict, chunked: bool = False) -> tuple[bytes, dict]:
        if not isinstance(url, str) or not 0 < len(url) <= MAX_URL:
            raise NetworkDenied("HTTP URL exceeds limit or is invalid")
        if not isinstance(method, str) or method not in {
                "GET", "POST", "HEAD", "PUT", "DELETE", "PATCH"}:
            raise NetworkDenied("HTTP method denied")
        if not isinstance(headers, dict) or len(headers) > 64:
            raise NetworkDenied("Invalid HTTP headers")
        if (any(not isinstance(k, str) or not isinstance(v, str)
                or any(c in k + v for c in "\r\n\0") for k, v in headers.items())
                or sum(len(k) + len(v) for k, v in headers.items()) > MAX_HEADER_BYTES):
            raise NetworkDenied("Invalid or oversized HTTP headers")
        transfer_values = [value for name, value in headers.items()
                           if name.lower() == "transfer-encoding"]
        if (chunked and (len(transfer_values) != 1 or
                         transfer_values[0].strip().lower() != "chunked" or
                         any(name.lower() == "content-length" for name in headers))
                or not chunked and transfer_values):
            raise NetworkDenied("Invalid HTTP transfer encoding")
        for _ in range(4):
            parts = urlsplit(url)
            if parts.scheme not in {"http", "https"} or not parts.hostname:
                raise NetworkDenied("Only HTTP(S) URLs are supported")
            port = parts.port or (443 if parts.scheme == "https" else 80)
            self._event({"event": "http_request_attempt", "url": url,
                                "method": method, "host": parts.hostname,
                                "port": port, "body_size": len(body or b""),
                                "body_sha256": hashlib.sha256(body or b"").hexdigest(),
                                "headers": headers, "chunked": chunked})
            fixture = matching_fixture(self.fixtures, method, url, chunked,
                                       headers, body or b"")
            if fixture is not None:
                response_spec = fixture["response"]
                payload = fixture["response_body"]
                status, reason, version = (response_spec["status"], response_spec["reason"],
                                           response_spec["version"])
                response_headers = response_spec["headers"]
                location = next((value for name, value in response_headers
                                 if name.casefold() == "location"), None)
                self._event({"event": "network_fixture_match", "id": fixture["id"],
                             "url": url, "method": method, "headers": headers,
                             "body_size": len(body or b""),
                             "body_sha256": hashlib.sha256(body or b"").hexdigest(),
                             "status": status, "response_headers": response_headers,
                             "response_size": len(payload),
                             "response_sha256": hashlib.sha256(payload).hexdigest()})
            else:
                if getattr(self, "offline_replay", False):
                    self._event({"event": "network_replay_miss", "operation": "http",
                                 "url": url, "method": method, "host": parts.hostname,
                                 "port": port,
                                 "body_sha256": hashlib.sha256(body or b"").hexdigest()})
                    raise NetworkDenied("Offline replay denied unmatched HTTP request")
                address = self._public_address(parts.hostname, port)
                self._event({"event": "http_request", "url": url, "method": method,
                                    "address": address, "port": port,
                                    "body_size": len(body or b""), "headers": headers,
                                    "chunked": chunked})
                if parts.scheme == "https":
                    connection = http.client.HTTPSConnection(parts.hostname, port, timeout=10,
                                                              context=ssl.create_default_context())
                else:
                    connection = http.client.HTTPConnection(parts.hostname, port, timeout=10)
                connection._create_connection = lambda _target, timeout, source_address=None: socket.create_connection(
                    (address, port), timeout=timeout, source_address=source_address)
                target = (parts.path or "/") + ("?" + parts.query if parts.query else "")
                try:
                    connection.request(method, target, body=body, headers=headers,
                                       encode_chunked=chunked)
                    response = connection.getresponse()
                    payload = response.read(MAX_TRANSFER + 1)
                    status, location = response.status, response.getheader("Location")
                    reason = response.reason or ""
                    response_headers = response.getheaders()
                    version = "HTTP/1.0" if response.version == 10 else "HTTP/1.1"
                finally:
                    connection.close()
            if len(payload) > MAX_TRANSFER:
                raise NetworkDenied("HTTP response exceeds 16 MiB limit")
            if (len(response_headers) > 64 or
                    any(not isinstance(k, str) or not isinstance(v, str)
                        or any(c in k + v for c in "\r\n\0")
                        for k, v in response_headers) or
                    sum(len(k) + len(v) for k, v in response_headers) > MAX_HEADER_BYTES or
                    len(reason) > 128 or any(c in reason for c in "\r\n\0")):
                raise NetworkDenied("Invalid or oversized HTTP response headers")
            self._event({"event": "http_response", "url": url,
                                "source": "fixture" if fixture is not None else "live",
                                "status": status,
                                "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
            if status in {301, 302, 303, 307, 308} and location:
                url = urljoin(url, location)
                if len(url) > MAX_URL:
                    raise NetworkDenied("HTTP redirect URL exceeds limit")
                if status == 303:
                    method, body = "GET", None
                    if chunked:
                        headers = {name: value for name, value in headers.items()
                                   if name.lower() != "transfer-encoding"}
                        chunked = False
                continue
            return payload, {"status": status, "reason": reason,
                             "headers": response_headers, "version": version}
        raise NetworkDenied("Too many HTTP redirects")

    def close(self) -> None:
        self.stop.set()
        self.thread.join(timeout=2)
        for sock in self.sockets.values():
            sock.close()
        self.sockets.clear()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise TimeoutError("Network broker thread did not stop before close")
        self.requests.close()
        self.responses.close()
        try:
            self._event({"event": "broker_closed"})
        finally:
            self.journal.close()
        if self.journal_path.parent == self.run_dir:
            target = self.run_dir / "network-broker.json"
            temporary = self.run_dir / f".network-broker-{uuid.uuid4().hex}.tmp"
            temporary.write_text(json.dumps(self.events, indent=2), encoding="utf-8")
            os.replace(temporary, target)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

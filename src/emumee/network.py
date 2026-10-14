"""Explicit network bridge; guest sockets cannot address host-local services."""

from __future__ import annotations

import http.client
import base64
import hashlib
import ipaddress
import ntpath
import socket
import struct
from io import BytesIO

from speakeasy.errors import SpeakeasyError

from .artifacts import ArtifactCatalog


MAX_TRANSFER = 16 * 1024 * 1024
MAX_URL_CHARS = 2_048
MAX_GUEST_PATH_CHARS = 32_767
MAX_HEADER_CHARS = 16 * 1024
MAX_HTTP_CHUNKS = 4_096
MAX_PENDING_HTTP = 128
MAX_PENDING_HTTP_BYTES = 32 * 1024 * 1024
MAX_REQUEST_BODY_ARTIFACT_BYTES = 64 * 1024 * 1024
HTTP_QUERY_FLAG_NUMBER = 0x20000000
HTTP_QUERY_ATTRIBUTE_MASK = 0x0000FFFF
HTTP_QUERY_NAMES = {1: "content-type", 5: "content-length", 33: "location"}
HEADER_NAME_CHARS = frozenset("!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


class NetworkDenied(OSError):
    pass


def public_ipv4(host: str, port: int) -> str:
    if not 0 < port < 65536:
        raise NetworkDenied("Invalid network port")
    try:
        literal = ipaddress.ip_address(host)
        addresses = [literal]
    except ValueError:
        addresses = [ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(
            host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)]
    for address in addresses:
        if address.version == 4 and address.is_global:
            return str(address)
    raise NetworkDenied(f"Private or host-local destination denied: {host}")


class NetworkBridge:
    def __init__(self, catalog: ArtifactCatalog, virtual_files=None):
        self.catalog = catalog
        self.virtual_files = virtual_files
        self.events: list[dict] = []
        self.unsupported: list[str] = []
        self.broker_sockets: dict[int, int] = {}
        self.socket_types: dict[int, int] = {}
        self.socket_owners: dict[int, int] = {}
        self.connected_tcp: dict[int, dict] = {}
        self.next_guest_tcp_port = 49152
        self.http_fetched: set[int] = set()
        self.http_ready: set[int] = set()
        self.http_metadata: dict[int, dict] = {}
        self.http_closed: set[int] = set()
        self.request_body_artifact_bytes = 0
        self.pending_winhttp: dict[int, dict] = {}
        self.pending_wininet: dict[int, dict] = {}
        self.rpc = None
        self.guest_dns = None
        run_dir = catalog.root.parent
        from .networkipc import FileRPCClient, broker_ipc_dir
        if (broker_ipc_dir(run_dir) / "network-requests.bin").is_file():
            self.rpc = FileRPCClient(run_dir)

    def install(self, emulator) -> None:
        for name, handler in {
            "socket": self._socket,
            "WSASocketA": self._socket,
            "WSASocketW": self._socket,
            "connect": self._connect,
            "WSAConnect": self._connect,
            "send": self._send,
            "recv": self._recv,
            "closesocket": self._close,
            "gethostbyname": self._gethostbyname,
            "bind": self._deny_inbound,
            "listen": self._deny_inbound,
            "accept": self._deny_inbound,
        }.items():
            emulator.add_api_hook(handler, "ws2_32", name)
        emulator.add_api_hook(self._internet_open_url, "wininet", "InternetOpenUrl*")
        emulator.add_api_hook(self._internet_connect, "wininet", "InternetConnect*")
        emulator.add_api_hook(self._http_open_request, "wininet", "HttpOpenRequest*")
        for name in ("HttpSendRequest", "HttpSendRequestA", "HttpSendRequestW"):
            emulator.add_api_hook(self._http_send, "wininet", name)
        emulator.add_api_hook(self._wininet_send_ex, "wininet", "HttpSendRequestEx*",
                              argc=5)
        emulator.add_api_hook(self._http_write, "wininet", "InternetWriteFile", argc=4)
        emulator.add_api_hook(self._wininet_end, "wininet", "HttpEndRequest*", argc=4)
        emulator.add_api_hook(self._http_send, "winhttp", "WinHttpSendRequest")
        emulator.add_api_hook(self._http_receive, "winhttp", "WinHttpReceiveResponse")
        emulator.add_api_hook(self._http_write, "winhttp", "WinHttpWriteData", argc=4)
        emulator.add_api_hook(self._http_read, "wininet", "InternetReadFile")
        emulator.add_api_hook(self._http_read, "winhttp", "WinHttpReadData")
        emulator.add_api_hook(self._http_available, "wininet", "InternetQueryDataAvailable")
        emulator.add_api_hook(self._http_available, "winhttp", "WinHttpQueryDataAvailable",
                              argc=2)
        emulator.add_api_hook(self._http_query, "wininet", "HttpQueryInfo*")
        emulator.add_api_hook(self._http_query, "winhttp", "WinHttpQueryHeaders")
        emulator.add_api_hook(self._http_close, "wininet", "InternetCloseHandle")
        emulator.add_api_hook(self._http_close, "winhttp", "WinHttpCloseHandle")
        emulator.add_api_hook(self._url_download_file, "urlmon", "URLDownloadToFile*")
        emulator.add_api_hook(self._url_download_cache, "urlmon", "URLDownloadToCacheFile*")

    @staticmethod
    def _http_manager(emu, api_name: str):
        module = api_name.partition(".")[0].lower()
        handler = emu.api.load_api_handler(module)
        if handler is None:
            raise NetworkDenied(f"HTTP API handler unavailable: {module}")
        return handler.netman

    def _http_object_closed(self, obj) -> bool:
        for _ in range(3):
            if obj is None:
                return False
            get_handle = getattr(obj, "get_handle", None)
            if callable(get_handle) and int(get_handle()) in self.http_closed:
                return True
            obj = getattr(obj, "session", None) or getattr(obj, "instance", None)
        return False

    @staticmethod
    def _read_http_headers(emu, api_name: str, pointer: int, length: int,
                           allow_chunked: bool = False) -> dict[str, str]:
        if not pointer:
            if length not in (0, -1, 0xFFFFFFFF):
                raise NetworkDenied("HTTP header pointer missing")
            return {}
        if length in (-1, 0xFFFFFFFF):
            if api_name.endswith("W") and api_name.startswith("wininet."):
                raise NetworkDenied("WinINet Unicode header length cannot be -1")
            width = 2 if api_name.endswith("W") or api_name.startswith("winhttp.") else 1
            raw = emu.read_mem_string(pointer, width, MAX_HEADER_CHARS + 1)
        else:
            if length < 0 or length > MAX_HEADER_CHARS:
                raise NetworkDenied("HTTP headers exceed limit")
            width = 2 if api_name.endswith("W") or api_name.startswith("winhttp.") else 1
            data = emu.mem_read(pointer, length * width)
            try:
                raw = data.decode("utf-16le" if width == 2 else "latin-1")
            except UnicodeError as exc:
                raise NetworkDenied("Invalid HTTP header encoding") from exc
        if len(raw) > MAX_HEADER_CHARS or "\0" in raw:
            raise NetworkDenied("HTTP headers exceed limit or contain NUL")
        headers: dict[str, str] = {}
        for line in raw.split("\r\n"):
            if not line:
                continue
            if ":" not in line or "\n" in line or "\r" in line:
                raise NetworkDenied("Malformed HTTP header line")
            name, value = line.split(":", 1)
            if (not name or any(char not in HEADER_NAME_CHARS for char in name)
                    or name.lower() == "content-length"
                    or (name.lower() == "transfer-encoding" and
                        (not allow_chunked or value.strip(" \t").lower() != "chunked"))
                    or any(existing.lower() == name.lower() for existing in headers)
                    or len(headers) >= 64):
                raise NetworkDenied("Unsupported HTTP header name")
            headers[name] = value.strip(" \t")
        return headers

    def _socket(self, emu, api_name, original, params):
        af, typ = int(params[0]), int(params[1])
        if af != socket.AF_INET or typ not in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            self.events.append({"event": "network_denied", "api": api_name, "reason": "unsupported socket type"})
            return 0xFFFFFFFF
        if self.rpc is None:
            self.events.append({"event": "network_error", "api": api_name,
                                "error": "Network broker unavailable"})
            return 0xFFFFFFFF
        try:
            handle = original(params)
            self.broker_sockets[handle] = self.rpc.call("socket_open", af=af, type=typ)
            self.socket_types[handle] = typ
            process = emu.get_current_process() if hasattr(emu, "get_current_process") else None
            if process is not None:
                self.socket_owners[handle] = id(process)
        except OSError as exc:
            self.events.append({"event": "network_error", "api": api_name, "error": str(exc)})
            return 0xFFFFFFFF
        return handle

    def _connect(self, emu, api_name, original, params):
        handle, ptr = int(params[0]), int(params[1])
        try:
            raw = emu.mem_read(ptr, 16)
            if int.from_bytes(raw[0:2], "little") != socket.AF_INET:
                raise NetworkDenied("Only IPv4 outbound sockets are supported")
            port = int.from_bytes(raw[2:4], "big")
            host = str(ipaddress.IPv4Address(raw[4:8]))
            ident = self.broker_sockets.get(handle)
            if self.rpc is None or ident is None:
                raise NetworkDenied("Network broker unavailable or guest socket unknown")
            self.rpc.call("socket_connect", socket=ident, host=host, port=port)
            self.events.append({"event": "connect", "host": host, "port": port, "api": api_name})
            result = original(params)
            if result == 0 and self.socket_types.get(handle) == socket.SOCK_STREAM:
                process = emu.get_current_process() if hasattr(emu, "get_current_process") else None
                self.connected_tcp[handle] = {
                    "local_port": self.next_guest_tcp_port,
                    "remote_ip": host,
                    "remote_port": port,
                    "pid": int(process.pid) if process is not None else 0,
                }
                self.next_guest_tcp_port += 1
                if self.next_guest_tcp_port > 65535:
                    self.next_guest_tcp_port = 49152
            return result
        except (OSError, ValueError) as exc:
            self.events.append({"event": "network_error", "api": api_name, "error": str(exc)})
            return 0xFFFFFFFF

    def _send(self, emu, api_name, original, params):
        handle, ptr, length = map(int, params[:3])
        if length < 0 or length > MAX_TRANSFER:
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "invalid send length", "socket": handle})
            return 0xFFFFFFFF
        ident = self.broker_sockets.get(handle)
        if self.rpc is None or ident is None:
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "Network broker unavailable or guest socket unknown", "socket": handle})
            return 0xFFFFFFFF
        payload = emu.mem_read(ptr, length) if ptr and length else b""
        try:
            sent = self.rpc.call("socket_send", socket=ident,
                                 data=base64.b64encode(payload).decode("ascii"))
            self.catalog.add(payload[:sent], "network_outbound", kind="network")
            self.events.append({"event": "send", "socket": handle, "size": sent, "api": api_name})
            original(params)  # Preserve Speakeasy's guest-side traffic event.
            return sent
        except OSError as exc:
            self.events.append({"event": "network_error", "api": api_name, "error": str(exc)})
            return 0xFFFFFFFF

    def _recv(self, emu, api_name, original, params):
        handle, ptr, length, flags = map(int, params[:4])
        ident = self.broker_sockets.get(handle)
        if self.rpc is None or ident is None or length < 0:
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "Network broker unavailable, guest socket unknown, or invalid receive length",
                                "socket": handle})
            return 0xFFFFFFFF
        try:
            payload = base64.b64decode(self.rpc.call("socket_recv", socket=ident,
                                                     size=min(length, MAX_TRANSFER), peek=bool(flags & 2)))
            if ptr:
                emu.mem_write(ptr, payload)
            self.catalog.add(payload, "network_inbound", kind="network")
            self.events.append({"event": "recv", "socket": handle, "size": len(payload), "api": api_name})
            return len(payload)
        except OSError as exc:
            self.events.append({"event": "network_error", "api": api_name, "error": str(exc)})
            return 0xFFFFFFFF

    def _close(self, emu, api_name, original, params):
        handle = int(params[0])
        ident = self.broker_sockets.pop(handle, None)
        self.socket_types.pop(handle, None)
        self.socket_owners.pop(handle, None)
        self.connected_tcp.pop(handle, None)
        if ident is not None and self.rpc:
            try:
                self.rpc.call("socket_close", socket=ident)
            except OSError as exc:
                self.events.append({"event": "network_error", "api": api_name, "error": str(exc)})
        return original(params)

    def cleanup_process(self, process) -> None:
        for handle, owner in tuple(self.socket_owners.items()):
            if owner != id(process):
                continue
            self.socket_owners.pop(handle, None)
            self.socket_types.pop(handle, None)
            self.connected_tcp.pop(handle, None)
            ident = self.broker_sockets.pop(handle, None)
            if ident is not None and self.rpc is not None:
                try:
                    self.rpc.call("socket_close", socket=ident)
                except OSError as exc:
                    self.events.append({"event": "network_error", "api": "process_exit",
                                        "error": str(exc)})

    def _deny_inbound(self, emu, api_name, original, params):
        self.events.append({"event": "network_denied", "api": api_name, "reason": "inbound networking disabled"})
        return 0xFFFFFFFF

    def _gethostbyname(self, emu, api_name, original, params):
        self.events.append({"event": "network_attempt", "api": api_name})
        if not int(params[0]):
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "missing hostname"})
            return 0
        hostname = emu.read_mem_string(int(params[0]), 1, 256)
        if len(hostname) > 255:
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "hostname exceeds limit"})
            return 0
        try:
            if self.guest_dns is not None:
                from .dns_records import dns_name
                normalized = dns_name(hostname)
                owned = [r for r in self.guest_dns.records if r["name"] == normalized]
                if owned:
                    addresses = [r["data"] for r in owned if r["type"] == "A"]
                    if not addresses:
                        self.events.append({"event": "guest_dns_query", "api": api_name,
                                            "host": normalized, "record_type": 1, "source": "persona",
                                            "network_used": False, "status": 9501})
                        return 0
                    address = addresses[0]
                    emu.get_network_manager().dns.names[hostname.lower()] = address
                    emu.get_network_manager().dns.names[hostname] = address
                    self.events.append({"event": "guest_dns_query", "api": api_name,
                                        "host": normalized, "record_type": 1, "source": "persona",
                                        "network_used": False, "status": 0, "answers": [address]})
                    return original(params)
            if self.rpc is None:
                raise NetworkDenied("Network broker unavailable")
            address = self.rpc.call("resolve", host=hostname)
            emu.get_network_manager().dns.names[hostname.lower()] = address
            self.events.append({"event": "dns", "host": hostname, "address": address})
            return original(params)
        except (OSError, ValueError) as exc:
            self.events.append({"event": "network_error", "api": api_name, "error": str(exc)})
            return 0

    def fetch(self, url: str, method: str = "GET", body: bytes | None = None,
              headers: dict[str, str] | None = None,
              with_metadata: bool = False, chunked: bool = False) -> bytes | tuple[bytes, dict]:
        self.events.append({"event": "http_request", "url": url, "method": method,
                            "size": len(body or b""), "headers": headers or {},
                            "chunked": chunked})
        if self.rpc is None:
            self.events.append({"event": "network_denied", "api": "http_fetch",
                                "url": url, "reason": "Network broker unavailable"})
            raise NetworkDenied("Network broker unavailable")
        if body and isinstance(body, (bytes, bytearray)) and len(body) <= MAX_TRANSFER:
            if self.request_body_artifact_bytes + len(body) <= MAX_REQUEST_BODY_ARTIFACT_BYTES:
                item = self.catalog.add(bytes(body), "network_request_body",
                                        guest_path=url, kind="network")
                if item is not None:
                    self.request_body_artifact_bytes += item["size"]
            else:
                self.events.append({"event": "http_request_body_artifact_skipped",
                                    "url": url, "size": len(body),
                                    "reason": "per-run extraction quota exceeded"})
        reply = self.rpc.call("http_fetch_meta" if with_metadata else "http_fetch",
                              url=url, method=method,
                              body=base64.b64encode(body or b"").decode("ascii"),
                              headers=headers or {}, chunked=chunked)
        metadata = None
        if with_metadata:
            if not isinstance(reply, dict):
                raise NetworkDenied("Malformed HTTP broker metadata")
            metadata = {key: reply.get(key) for key in ("status", "reason", "headers", "version")}
            encoded = reply.get("body")
            if (type(metadata["status"]) is not int or not 100 <= metadata["status"] <= 999
                    or not isinstance(metadata["reason"], str)
                    or len(metadata["reason"]) > 128
                    or any(control in metadata["reason"] for control in "\r\n\0")
                    or not isinstance(metadata["version"], str)
                    or metadata["version"] not in {"HTTP/1.0", "HTTP/1.1"}
                    or not isinstance(metadata["headers"], list)
                    or len(metadata["headers"]) > 64
                    or any(not isinstance(pair, (list, tuple)) or len(pair) != 2
                           or not all(isinstance(value, str) for value in pair)
                           or any(control in pair[0] + pair[1] for control in "\r\n\0")
                           for pair in metadata["headers"])
                    or sum(len(pair[0]) + len(pair[1]) for pair in metadata["headers"])
                    > MAX_HEADER_CHARS):
                raise NetworkDenied("Malformed HTTP broker metadata")
        else:
            encoded = reply
        if not isinstance(encoded, str) or len(encoded) > 4 * ((MAX_TRANSFER + 2) // 3):
            raise NetworkDenied("Invalid or oversized HTTP broker body")
        payload = base64.b64decode(encoded, validate=True)
        if len(payload) > MAX_TRANSFER:
            raise NetworkDenied("HTTP broker body exceeds limit")
        self.catalog.add(payload, "network_download", guest_path=url, kind="network")
        self.events.append({"event": "http_response", "url": url, "size": len(payload),
                            "status": metadata["status"] if metadata else None,
                            "via": "parent_broker"})
        return (payload, metadata) if metadata else payload

    def _url_download_file(self, emu, api_name, original, params):
        if self.virtual_files is None:
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "virtual filesystem unavailable"})
            return 0x800C0008  # INET_E_DOWNLOAD_FAILURE
        if not params[1] or not params[2]:
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "missing URL or destination"})
            return 0x800C0008
        width = 2 if api_name.endswith("W") else 1
        url = emu.read_mem_string(int(params[1]), width, MAX_URL_CHARS + 1)
        path = emu.read_mem_string(int(params[2]), width, MAX_GUEST_PATH_CHARS + 1)
        if len(url) > MAX_URL_CHARS or len(path) > MAX_GUEST_PATH_CHARS:
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "URL or guest path exceeds limit"})
            return 0x800C0008
        if any(int(params[index]) for index in (0, 3, 4)):
            self.unsupported.append(f"{api_name}: bind host, reserved flags, or callback unsupported")
            self.events.append({"event": "network_denied", "api": api_name,
                                "url": url, "reason": "unsupported bind context or callback"})
            return 0x80004001  # E_NOTIMPL
        try:
            payload = self.fetch(url)
            try:
                guest_path = self.virtual_files.save_network_download(emu, path, payload, url)
            except ValueError as exc:
                self.unsupported.append(f"{api_name}: {exc}")
                raise
            self.events.append({"event": "urlmon_download", "api": api_name,
                                "url": url, "path": guest_path, "size": len(payload)})
            return 0  # S_OK
        except (OSError, ValueError, http.client.HTTPException) as exc:
            self.events.append({"event": "network_error", "api": api_name,
                                "url": url, "error": str(exc)})
            return 0x800C0008

    def _url_download_cache(self, emu, api_name, original, params):
        if self.virtual_files is None or not params[1] or not params[2]:
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "virtual filesystem, URL, or output missing"})
            return 0x80004005  # E_FAIL
        width = 2 if api_name.endswith("W") else 1
        url = emu.read_mem_string(int(params[1]), width, MAX_URL_CHARS + 1)
        if len(url) > MAX_URL_CHARS:
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "URL exceeds limit"})
            return 0x80004005
        if any(int(params[index]) for index in (0, 4, 5)):
            self.unsupported.append(f"{api_name}: bind host, reserved flags, or callback unsupported")
            self.events.append({"event": "network_denied", "api": api_name,
                                "url": url, "reason": "unsupported bind context or callback"})
            return 0x80004001
        digest = hashlib.sha256(url.encode("utf-8", errors="replace")).hexdigest()[:24]
        user_dir = ntpath.dirname(self.virtual_files.current_dir)
        path = ntpath.join(user_dir, "AppData", "Local", "Microsoft", "Windows",
                           "INetCache", digest + ".bin")
        if int(params[3]) <= len(path):
            self.events.append({"event": "network_denied", "api": api_name,
                                "url": url, "reason": "cache path output buffer too small"})
            return 0x8007000E  # E_OUTOFMEMORY
        try:
            payload = self.fetch(url)
            try:
                guest_path = self.virtual_files.save_network_download(emu, path, payload, url)
            except ValueError as exc:
                self.unsupported.append(f"{api_name}: {exc}")
                raise
            emu.mem_write(int(params[2]), guest_path.encode("utf-16le" if width == 2 else "ascii")
                          + (b"\0\0" if width == 2 else b"\0"))
            self.events.append({"event": "urlmon_cache_download", "api": api_name,
                                "url": url, "path": guest_path, "size": len(payload)})
            return 0
        except (OSError, ValueError, UnicodeEncodeError, http.client.HTTPException) as exc:
            self.events.append({"event": "network_error", "api": api_name,
                                "url": url, "error": str(exc)})
            return 0x80004005

    def _internet_open_url(self, emu, api_name, original, params):
        self.events.append({"event": "network_attempt", "api": api_name})
        if not int(params[1]):
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "missing URL"})
            return 0
        url = emu.read_mem_string(int(params[1]),
                                  2 if api_name.endswith("W") else 1, MAX_URL_CHARS + 1)
        if len(url) > MAX_URL_CHARS:
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "URL exceeds limit"})
            return 0
        session = self._http_manager(emu, api_name).get_wininet_object(int(params[0]))
        if (session is None or not hasattr(session, "new_session")
                or self._http_object_closed(session)):
            self.events.append({"event": "network_denied", "api": api_name,
                                "url": url, "reason": "invalid session handle"})
            return 0
        if self.rpc is None:
            self.events.append({"event": "network_denied", "api": api_name,
                                "url": url, "reason": "Network broker unavailable"})
            return 0
        try:
            headers = self._read_http_headers(emu, api_name, int(params[2]), int(params[3]))
        except NetworkDenied as exc:
            self.unsupported.append(f"{api_name}: {exc}")
            self.events.append({"event": "network_denied", "api": api_name,
                                "url": url, "reason": str(exc)})
            return 0
        modeled_params = list(params)
        modeled_params[2:4] = [0, 0]
        handle = original(modeled_params)
        if not handle:
            self.events.append({"event": "network_denied", "api": api_name,
                                "url": url, "reason": "invalid session handle or URL"})
            return 0
        try:
            payload, metadata = self.fetch(url, headers=headers, with_metadata=True)
            req = self._http_manager(emu, api_name).get_wininet_object(handle)
            req.response = BytesIO(payload)
            self.http_metadata[handle] = metadata
            self.http_fetched.add(handle)
            self.http_ready.add(handle)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            self.events.append({"event": "network_error", "api": api_name, "url": url, "error": str(exc)})
            return 0
        return handle

    def _internet_connect(self, emu, api_name, original, params):
        handle, server_ptr = int(params[0]), int(params[1])
        port, service = int(params[2]), int(params[5])
        self.events.append({"event": "http_connect_attempt", "api": api_name,
                            "handle": handle})
        instance = self._http_manager(emu, api_name).get_wininet_object(handle)
        if (instance is None or not callable(getattr(instance, "new_session", None))
                or self._http_object_closed(instance)):
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "invalid Internet session handle", "handle": handle})
            return 0
        if not server_ptr or not 0 <= port <= 65535 or service != 3:
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "invalid HTTP server, port, or service", "handle": handle})
            return 0
        width = 2 if api_name.endswith("W") else 1
        try:
            server = emu.read_mem_string(server_ptr, width, 254)
            if (not server or len(server) > 253 or any(c in server for c in "\r\n\0")):
                raise ValueError("invalid or oversized server name")
            for pointer in (int(params[3]), int(params[4])):
                if pointer and len(emu.read_mem_string(pointer, width, 257)) > 256:
                    raise ValueError("HTTP credential exceeds limit")
        except (SpeakeasyError, ValueError) as exc:
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": str(exc), "handle": handle})
            return 0
        modeled_params = list(params)
        if port == 0:  # INTERNET_INVALID_PORT_NUMBER uses the HTTP service default.
            modeled_params[2] = 80
        rv = original(modeled_params)
        if rv:
            self.events.append({"event": "http_connect", "api": api_name,
                                "handle": int(rv), "server": server,
                                "port": int(modeled_params[2])})
        return rv

    def _http_open_request(self, emu, api_name, original, params):
        handle = int(params[0])
        self.events.append({"event": "http_open_request_attempt", "api": api_name,
                            "handle": handle})
        session = self._http_manager(emu, api_name).get_wininet_object(handle)
        if (session is None or not callable(getattr(session, "new_request", None))
                or self._http_object_closed(session)):
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "invalid HTTP connection handle", "handle": handle})
            return 0
        width = 2 if api_name.endswith("W") else 1
        try:
            for index, limit in ((1, 32), (2, MAX_URL_CHARS), (3, 32),
                                 (4, MAX_URL_CHARS)):
                pointer = int(params[index])
                if pointer:
                    value = emu.read_mem_string(pointer, width, limit + 1)
                    if len(value) > limit or any(c in value for c in "\r\n\0"):
                        raise ValueError("invalid or oversized HTTP request field")
        except (SpeakeasyError, ValueError) as exc:
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": str(exc), "handle": handle})
            return 0
        rv = original(params)
        if rv:
            self.events.append({"event": "http_request_opened", "api": api_name,
                                "handle": int(rv), "connection": handle})
        return rv

    def _http_send(self, emu, api_name, original, params):
        handle = int(params[0])
        self.events.append({"event": "network_attempt", "api": api_name,
                            "handle": handle})
        req = self._http_manager(emu, api_name).get_wininet_object(handle)
        if req is None or self._http_object_closed(req):
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "invalid request handle", "handle": handle})
            return 0
        if not (callable(getattr(req, "get_server", None)) and
                callable(getattr(req, "get_port", None)) and
                callable(getattr(req, "is_secure", None)) and
                hasattr(req, "objname") and hasattr(req, "verb")):
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "invalid request handle type", "handle": handle})
            return 0
        self.http_fetched.discard(handle)
        self.http_ready.discard(handle)
        self.http_metadata.pop(handle, None)
        self.pending_winhttp.pop(handle, None)
        self.pending_wininet.pop(handle, None)
        req.response = None
        server, port = req.get_server(), int(req.get_port())
        secure = bool(req.is_secure()) or port == 443
        path = req.objname.path or "/"
        if req.objname.query:
            path += "?" + req.objname.query
        url = f'{"https" if secure else "http"}://{server}:{port}{path}'
        body_ptr = int(params[3])
        body_len = int(params[4])
        if body_len < 0 or body_len > MAX_TRANSFER or (body_len and not body_ptr):
            self.events.append({"event": "network_denied", "api": api_name,
                                "url": url, "reason": "invalid or oversized optional data",
                                "size": body_len})
            return 0
        is_winhttp = api_name.startswith("winhttp.")
        total_len = int(params[5]) & 0xFFFFFFFF if is_winhttp else body_len
        chunked = is_winhttp and total_len == 0xFFFFFFFF
        if not chunked and (total_len < body_len or total_len > MAX_TRANSFER):
            self.events.append({"event": "network_denied", "api": api_name,
                                "url": url, "reason": "invalid or oversized total request data",
                                "size": total_len})
            return 0
        if self.rpc is None:
            self.events.append({"event": "network_denied", "api": api_name,
                                "url": url, "reason": "Network broker unavailable"})
            return 0
        try:
            headers = self._read_http_headers(emu, api_name, int(params[1]), int(params[2]),
                                              allow_chunked=chunked)
        except NetworkDenied as exc:
            self.unsupported.append(f"{api_name}: {exc}")
            self.events.append({"event": "network_denied", "api": api_name,
                                "url": url, "reason": str(exc)})
            return 0
        has_chunked_header = any(name.lower() == "transfer-encoding" for name in headers)
        if chunked and (body_ptr or body_len or not has_chunked_header):
            self.events.append({"event": "network_denied", "api": api_name,
                                "url": url, "reason": "invalid chunked request parameters"})
            return 0
        body = emu.mem_read(body_ptr, body_len) if body_ptr and body_len else None
        if is_winhttp and (chunked or total_len > body_len):
            if (len(self.pending_winhttp) + len(self.pending_wininet) >= MAX_PENDING_HTTP or
                    sum(len(item["body"]) for item in
                        (*self.pending_winhttp.values(), *self.pending_wininet.values()))
                    + body_len > MAX_PENDING_HTTP_BYTES):
                self.events.append({"event": "network_denied", "api": api_name,
                                    "url": url, "reason": "streamed request staging quota exceeded"})
                return 0
            self.pending_winhttp[handle] = {
                "url": url, "method": req.verb.upper(), "headers": headers,
                "body": bytearray(body or b""), "total": None if chunked else total_len,
                "chunks": 0, "chunked": chunked, "terminated": False,
            }
            self.events.append({"event": "http_request_staged", "api": api_name,
                                "handle": handle, "url": url,
                                "initial_size": body_len,
                                "total_size": None if chunked else total_len,
                                "chunked": chunked})
            return 1
        try:
            modeled_params = list(params)
            modeled_params[1:3] = [0, 0]
            rv = original(modeled_params)
            if not rv:
                self.events.append({"event": "network_denied", "api": api_name,
                                    "url": url, "reason": "request rejected by API model"})
                return 0
            payload, metadata = self.fetch(url, method=req.verb.upper(), body=body,
                                           headers=headers, with_metadata=True)
            req.response = BytesIO(payload)
            self.http_metadata[handle] = metadata
            self.http_fetched.add(handle)
            if api_name.startswith("wininet."):
                self.http_ready.add(handle)
            return rv
        except (OSError, ValueError, http.client.HTTPException) as exc:
            self.events.append({"event": "network_error", "api": api_name, "url": url, "error": str(exc)})
            return 0

    def _wininet_send_ex(self, emu, api_name, original, params):
        handle, buffers_ptr, buffers_out, flags, context = (int(value) for value in params)
        self.events.append({"event": "network_attempt", "api": api_name,
                            "handle": handle})
        req = self._http_manager(emu, api_name).get_wininet_object(handle)
        if (req is None or self._http_object_closed(req)
                or not all(callable(getattr(req, name, None)) for name in
                           ("get_server", "get_port", "is_secure"))
                or not hasattr(req, "objname") or not hasattr(req, "verb")):
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "invalid request handle", "handle": handle})
            return 0
        if buffers_out or flags or handle in self.pending_wininet:
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "reserved arguments or request already staged",
                                "handle": handle})
            return 0
        if self.rpc is None:
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "Network broker unavailable", "handle": handle})
            return 0
        pointer_size = emu.get_ptr_size()
        if pointer_size not in (4, 8):
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "invalid guest pointer size", "handle": handle})
            return 0
        try:
            headers_ptr = headers_len = body_ptr = body_len = total_len = next_ptr = 0
            if buffers_ptr:
                raw = emu.mem_read(buffers_ptr, 56 if pointer_size == 8 else 40)
                if pointer_size == 8:
                    struct_size, next_ptr, headers_ptr, headers_len, _headers_total = (
                        struct.unpack_from("<I4xQQII", raw))
                    body_ptr, body_len, total_len, offset_low, offset_high = (
                        struct.unpack_from("<QIIII", raw, 32))
                else:
                    (struct_size, next_ptr, headers_ptr, headers_len, _headers_total,
                     body_ptr, body_len, total_len, offset_low, offset_high) = (
                        struct.unpack_from("<10I", raw))
                # A harmless Win11 HttpSendRequestEx probe sent only the head node's
                # data/header even when Next named a valid second node. Keep Next inert.
                if (struct_size != len(raw) or offset_low or offset_high
                        or body_len > total_len or total_len > MAX_TRANSFER
                        or (body_len and not body_ptr)):
                    raise NetworkDenied("invalid or oversized INTERNET_BUFFERS")
            headers = self._read_http_headers(emu, api_name, headers_ptr, headers_len)
            body = emu.mem_read(body_ptr, body_len) if body_len else b""
        except (NetworkDenied, SpeakeasyError, ValueError, struct.error) as exc:
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": str(exc), "handle": handle})
            return 0
        if (len(self.pending_wininet) + len(self.pending_winhttp) >= MAX_PENDING_HTTP
                or sum(len(item["body"]) for item in
                       (*self.pending_wininet.values(), *self.pending_winhttp.values()))
                + body_len > MAX_PENDING_HTTP_BYTES):
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "streamed request staging quota exceeded",
                                "handle": handle})
            return 0
        server, port = req.get_server(), int(req.get_port())
        secure = bool(req.is_secure()) or port == 443
        path = req.objname.path or "/"
        if req.objname.query:
            path += "?" + req.objname.query
        url = f'{"https" if secure else "http"}://{server}:{port}{path}'
        if len(url) > MAX_URL_CHARS:
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "URL exceeds limit", "handle": handle})
            return 0
        self.http_fetched.discard(handle)
        self.http_ready.discard(handle)
        self.http_metadata.pop(handle, None)
        req.response = None
        self.pending_wininet[handle] = {
            "url": url, "method": req.verb.upper(), "headers": headers,
            "body": bytearray(body), "total": total_len, "chunks": 0,
            "context": context,
        }
        self.events.append({"event": "http_request_staged", "api": api_name,
                            "handle": handle, "url": url,
                            "initial_size": body_len, "total_size": total_len,
                            "linked_buffer_ignored": bool(next_ptr)})
        return 1

    def _http_write(self, emu, api_name, original, params):
        handle, buffer, size, count_ptr = (int(value) for value in params)
        self.events.append({"event": "http_write_attempt", "api": api_name,
                            "handle": handle, "size": size})
        if api_name.startswith("wininet.") and not count_ptr:
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "byte-count pointer missing", "handle": handle})
            return 0
        if count_ptr:
            try:
                emu.mem_write(count_ptr, b"\0" * 4)
            except (SpeakeasyError, ValueError):
                self.events.append({"event": "network_denied", "api": api_name,
                                    "reason": "invalid byte-count pointer", "handle": handle})
                return 0
        pending_store = (self.pending_wininet if api_name.startswith("wininet.")
                         else self.pending_winhttp)
        pending = pending_store.get(handle)
        req = self._http_manager(emu, api_name).get_wininet_object(handle)
        if (pending is None or req is None or self._http_object_closed(req)
                or size < 0 or size > MAX_TRANSFER or (size and not buffer)
                or pending["chunks"] >= MAX_HTTP_CHUNKS
                or pending.get("terminated")
                or (pending["total"] is not None and
                    len(pending["body"]) + size > pending["total"])
                or sum(len(item["body"]) for item in
                       (*self.pending_wininet.values(), *self.pending_winhttp.values()))
                + size > MAX_PENDING_HTTP_BYTES):
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "invalid or excessive streamed request data",
                                "handle": handle})
            return 0
        try:
            chunk = emu.mem_read(buffer, size) if size else b""
            if count_ptr:
                emu.mem_write(count_ptr, size.to_bytes(4, "little"))
        except (SpeakeasyError, ValueError):
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "invalid streamed request buffer", "handle": handle})
            return 0
        pending["body"].extend(chunk)
        pending["chunks"] += 1
        if pending.get("chunked") and size == 0:
            pending["terminated"] = True
        self.events.append({"event": "http_write", "api": api_name,
                            "handle": handle, "size": size,
                            "accumulated": len(pending["body"]),
                            "chunk_terminated": bool(pending.get("terminated"))})
        return 1

    def _wininet_end(self, emu, api_name, original, params):
        handle, buffers_out, flags, context = (int(value) for value in params)
        self.events.append({"event": "http_end_attempt", "api": api_name,
                            "handle": handle})
        req = self._http_manager(emu, api_name).get_wininet_object(handle)
        pending = self.pending_wininet.get(handle)
        if (buffers_out or flags or context or pending is None or req is None
                or self._http_object_closed(req)
                or len(pending["body"]) != pending["total"]):
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "streamed request body incomplete or invalid",
                                "handle": handle,
                                "size": len(pending["body"]) if pending else 0,
                                "total": pending["total"] if pending else 0})
            return 0
        try:
            payload, metadata = self.fetch(
                pending["url"], method=pending["method"],
                body=bytes(pending["body"]), headers=pending["headers"],
                with_metadata=True)
        except (OSError, ValueError, http.client.HTTPException) as exc:
            self.pending_wininet.pop(handle, None)
            self.events.append({"event": "network_error", "api": api_name,
                                "url": pending["url"], "error": str(exc)})
            return 0
        self.pending_wininet.pop(handle, None)
        req.response = BytesIO(payload)
        self.http_metadata[handle] = metadata
        self.http_fetched.add(handle)
        self.http_ready.add(handle)
        self.events.append({"event": "http_response_ready", "api": api_name,
                            "handle": handle})
        return 1

    def _http_receive(self, emu, api_name, original, params):
        handle = int(params[0])
        self.events.append({"event": "http_receive_attempt", "api": api_name,
                            "handle": handle})
        req = self._http_manager(emu, api_name).get_wininet_object(handle)
        pending = self.pending_winhttp.get(handle)
        if pending is not None:
            if (int(params[1]) != 0 or req is None or self._http_object_closed(req)
                    or (not pending.get("terminated") if pending.get("chunked")
                        else len(pending["body"]) != pending["total"])):
                self.events.append({"event": "network_denied", "api": api_name,
                                    "reason": "streamed request body incomplete or invalid",
                                    "handle": handle,
                                    "size": len(pending["body"]), "total": pending["total"]})
                return 0
            try:
                payload, metadata = self.fetch(
                    pending["url"], method=pending["method"],
                    body=bytes(pending["body"]), headers=pending["headers"],
                    with_metadata=True,
                    **({"chunked": True} if pending.get("chunked") else {}))
            except (OSError, ValueError, http.client.HTTPException) as exc:
                self.pending_winhttp.pop(handle, None)
                self.events.append({"event": "network_error", "api": api_name,
                                    "url": pending["url"], "error": str(exc)})
                return 0
            self.pending_winhttp.pop(handle, None)
            req.response = BytesIO(payload)
            self.http_metadata[handle] = metadata
            self.http_fetched.add(handle)
        if (int(params[1]) != 0 or handle not in self.http_fetched or req is None
                or self._http_object_closed(req)
                or not isinstance(getattr(req, "response", None), BytesIO)):
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "response not available or invalid request", "handle": handle})
            return 0
        rv = original(params)
        if rv:
            self.http_ready.add(handle)
            self.events.append({"event": "http_response_ready", "api": api_name,
                                "handle": handle})
        return rv

    def _http_read(self, emu, api_name, original, params):
        handle, buffer, size, count_ptr = (int(value) for value in params)
        self.events.append({"event": "http_read_attempt", "api": api_name,
                            "handle": handle, "size": size})
        if count_ptr:
            try:
                emu.mem_write(count_ptr, b"\0" * 4)
            except (SpeakeasyError, ValueError):
                self.events.append({"event": "network_denied", "api": api_name,
                                    "reason": "invalid byte-count pointer", "handle": handle})
                return 0
        if (not count_ptr or size < 0 or size > MAX_TRANSFER or
                (size and not buffer)):
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "invalid or oversized read buffer", "handle": handle})
            return 0
        req = self._http_manager(emu, api_name).get_wininet_object(handle)
        response = getattr(req, "response", None)
        if (handle not in self.http_ready or self._http_object_closed(req)
                or not isinstance(response, BytesIO)):
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "response not ready or invalid request handle",
                                "handle": handle})
            return 0
        position = response.tell()
        data = response.read(size)
        try:
            if data:
                emu.mem_write(buffer, data)
            emu.mem_write(count_ptr, len(data).to_bytes(4, "little"))
        except (SpeakeasyError, ValueError):
            response.seek(position)
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "invalid read buffer", "handle": handle})
            return 0
        self.events.append({"event": "http_read", "api": api_name,
                            "handle": handle, "size": len(data)})
        return 1

    def _http_available(self, emu, api_name, original, params):
        handle, count_ptr = int(params[0]), int(params[1])
        self.events.append({"event": "http_available_attempt", "api": api_name,
                            "handle": handle})
        if api_name.startswith("wininet.") and (int(params[2]) or int(params[3])):
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "reserved availability arguments must be zero",
                                "handle": handle})
            return 0
        if api_name.startswith("winhttp.") and not count_ptr:
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "availability output pointer missing",
                                "handle": handle})
            return 0
        req = self._http_manager(emu, api_name).get_wininet_object(handle)
        response = getattr(req, "response", None)
        if (handle not in self.http_ready or self._http_object_closed(req)
                or not isinstance(response, BytesIO)):
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "response not ready or invalid request handle",
                                "handle": handle})
            return 0
        available = len(response.getbuffer()) - response.tell()
        if count_ptr:
            try:
                emu.mem_write(count_ptr, available.to_bytes(4, "little"))
            except (SpeakeasyError, ValueError, OverflowError):
                self.events.append({"event": "network_denied", "api": api_name,
                                    "reason": "invalid availability output pointer",
                                    "handle": handle})
                return 0
        self.events.append({"event": "http_available", "api": api_name,
                            "handle": handle, "size": available})
        return 1

    def _http_query(self, emu, api_name, original, params):
        winhttp = api_name.startswith("winhttp.")
        handle, info = int(params[0]), int(params[1])
        buffer = int(params[3] if winhttp else params[2])
        length_ptr = int(params[4] if winhttp else params[3])
        index_ptr = int(params[5] if winhttp else params[4])
        attribute = info & HTTP_QUERY_ATTRIBUTE_MASK
        flags = info & ~HTTP_QUERY_ATTRIBUTE_MASK
        self.events.append({"event": "http_query_attempt", "api": api_name,
                            "handle": handle, "attribute": attribute, "flags": flags})
        metadata = self.http_metadata.get(handle)
        req = self._http_manager(emu, api_name).get_wininet_object(handle)
        if (handle not in self.http_ready or metadata is None or not length_ptr
                or req is None
                or self._http_object_closed(req)):
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "response not ready or invalid query pointer",
                                "handle": handle})
            return 0
        if flags not in (0, HTTP_QUERY_FLAG_NUMBER) or attribute not in {
                1, 5, 18, 19, 20, 22, 33, 65535}:
            self.unsupported.append(f"{api_name}: unsupported query level 0x{info:x}")
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "unsupported HTTP query level", "handle": handle})
            return 0
        width = 2 if winhttp or api_name.endswith("W") else 1
        try:
            available = int.from_bytes(emu.mem_read(length_ptr, 4), "little")
            index = int.from_bytes(emu.mem_read(index_ptr, 4), "little") if index_ptr else 0
            if index > 64:
                raise ValueError("HTTP header index exceeds limit")
            if attribute == 65535:
                name_ptr = int(params[2]) if winhttp else buffer
                if not name_ptr:
                    raise ValueError("HTTP custom header name missing")
                name = emu.read_mem_string(name_ptr, width, 257)
                if not name or len(name) > 256 or any(c not in HEADER_NAME_CHARS for c in name):
                    raise ValueError("Invalid HTTP custom header name")
                name = name.lower()
            else:
                name = HTTP_QUERY_NAMES.get(attribute)
            if attribute == 19:
                value = str(metadata["status"])
            elif attribute == 20:
                value = metadata["reason"]
            elif attribute == 18:
                value = metadata["version"]
            elif attribute == 22:
                value = (f'{metadata["version"]} {metadata["status"]} '
                         f'{metadata["reason"]}\r\n' + "".join(
                             f"{key}: {item}\r\n" for key, item in metadata["headers"]) + "\r\n")
                if len(value) > MAX_HEADER_CHARS:
                    raise ValueError("HTTP raw headers exceed limit")
            else:
                matches = [item for key, item in metadata["headers"]
                           if key.lower() == name]
                value = matches[index] if index < len(matches) else None
            if value is None:
                emu.set_last_error(12150)  # ERROR_HTTP_HEADER_NOT_FOUND
                self.events.append({"event": "http_query_missing", "api": api_name,
                                    "handle": handle, "attribute": attribute})
                return 0
            if flags == HTTP_QUERY_FLAG_NUMBER:
                if attribute not in (5, 19) or not value.isdecimal() or int(value) > 0xFFFFFFFF:
                    raise ValueError("HTTP query cannot return a DWORD")
                data, terminator = int(value).to_bytes(4, "little"), b""
            else:
                data = value.encode("utf-16le" if width == 2 else "latin-1")
                terminator = b"\0" * width
            required = len(data) + len(terminator)
            if not buffer or available < required:
                emu.mem_write(length_ptr, required.to_bytes(4, "little"))
                emu.set_last_error(122)  # ERROR_INSUFFICIENT_BUFFER
                self.events.append({"event": "http_query_buffer_small", "api": api_name,
                                    "handle": handle, "required": required})
                return 0
            emu.mem_write(buffer, data + terminator)
            emu.mem_write(length_ptr, len(data).to_bytes(4, "little"))
            if index_ptr and name:
                emu.mem_write(index_ptr, (index + 1).to_bytes(4, "little"))
            emu.set_last_error(0)
            self.events.append({"event": "http_query", "api": api_name,
                                "handle": handle, "attribute": attribute,
                                "size": len(data)})
            return 1
        except (SpeakeasyError, ValueError, UnicodeError, OverflowError) as exc:
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": str(exc), "handle": handle})
            return 0

    def _http_close(self, emu, api_name, original, params):
        handle = int(params[0])
        self.events.append({"event": "http_close_attempt", "api": api_name,
                            "handle": handle})
        manager = self._http_manager(emu, api_name)
        obj = manager.get_wininet_object(handle)
        if obj is None or self._http_object_closed(obj):
            self.events.append({"event": "network_denied", "api": api_name,
                                "reason": "invalid or closed HTTP handle", "handle": handle})
            return 0
        affected = []
        for candidate in (self.http_metadata.keys() | self.pending_winhttp.keys()
                          | self.pending_wininet.keys()):
            child = manager.get_wininet_object(candidate)
            for _ in range(3):
                if child is None:
                    break
                get_handle = getattr(child, "get_handle", None)
                if callable(get_handle) and int(get_handle()) == handle:
                    affected.append(candidate)
                    break
                child = getattr(child, "session", None) or getattr(child, "instance", None)
        rv = original(params)
        if rv:
            self.http_closed.add(handle)
            for candidate in affected:
                self.http_fetched.discard(candidate)
                self.http_ready.discard(candidate)
                self.http_metadata.pop(candidate, None)
                self.pending_winhttp.pop(candidate, None)
                self.pending_wininet.pop(candidate, None)
            self.events.append({"event": "http_closed", "api": api_name,
                                "handle": handle, "responses_invalidated": len(affected)})
        return rv

    def close(self) -> None:
        if self.rpc:
            self.rpc.close()

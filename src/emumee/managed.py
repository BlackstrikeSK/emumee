"""Bounded CIL interpreter with modeled framework calls and no host CLR execution.

The interpreter deliberately stops at unknown IL or framework methods. Guessing a
return value can send an analyzed program down a false path.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import io
import json
import ntpath
import operator
import re
import stat
import zipfile
import zlib
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import dnfile
import pefile
from Crypto.Cipher import AES
from dncil.cil.body.reader import read_method_body_from_bytes

from .artifacts import ArtifactCatalog, MAX_ARTIFACT, MAX_MEMORY_SCAN
from .console_output import ConsoleOutput
from .network import MAX_HEADER_CHARS, MAX_TRANSFER, NetworkBridge, NetworkDenied
from .pe import SampleInfo


class UnsupportedManaged(Exception):
    pass


MAX_MANAGED_EVENTS = 20_000
MAX_STDOUT_CHARS = 1024 * 1024
MAX_GUEST_FILES = 2048
MAX_GUEST_DIRECTORIES = 4096
MAX_GUEST_FILE_BYTES = 64 * 1024 * 1024
MAX_GUEST_PATH_CHARS = 4096
MAX_LOADED_ASSEMBLIES = 16
MAX_LOADED_ASSEMBLY_BYTES = 64 * 1024 * 1024
MAX_MANAGED_OBJECTS = 20_000
MAX_DIRECTORY_ENUM_RESULTS = 4096
MAX_DIRECTORY_ENUM_CHARS = 1024 * 1024
MAX_FILE_STREAMS = 4096
MAX_MEMORY_STREAMS = 4096
MAX_MANIFEST_RESOURCES = 1024
MAX_MANIFEST_RESOURCE_BYTES = 64 * 1024 * 1024
MAX_AES_OBJECTS = 4096
MAX_AES_PLAINTEXT_CAPTURE_BYTES = 64 * 1024 * 1024
MAX_AES_PLAINTEXT_ARTIFACTS = 128
MAX_CRYPTO_STREAMS = 4096
MAX_COMPRESSED_STREAMS = 4096
MAX_ZIP_ENTRIES = 1024
MAX_ZIP_OUTPUT = MAX_ARTIFACT
MAX_ZIP_CENTRAL_BYTES = 4 * 1024 * 1024
MAX_HTTP_CLIENTS = 1024
MAX_HTTP_TASKS = 1024
MAX_HTTP_TASK_BYTES = 64 * 1024 * 1024
MAX_HTTP_REQUEST_CONTENT_BYTES = 64 * 1024 * 1024
MAX_HTTP_REQUESTS = 1024
MAX_HTTP_HEADER_SETS = 2048
HTTP_METHODS = frozenset({"GET", "POST", "HEAD", "PUT", "DELETE", "PATCH"})
HTTP_RESTRICTED_REQUEST_HEADERS = frozenset({
    "host", "content-type", "content-length", "transfer-encoding", "connection",
    "proxy-authorization", "proxy-connection", "upgrade", "te", "trailer",
})
MAX_PBKDF2_OBJECTS = 4096
MAX_PBKDF2_ITERATIONS = 1_000_000
MAX_PBKDF2_DERIVED_BYTES = 4096
MAX_PBKDF2_WORK = 8_000_000
MAX_ENV_VARIABLES = 256
MAX_ENV_NAME_CHARS = 1024
MAX_ENV_VALUE_CHARS = 32_767
MAX_ENV_TOTAL_CHARS = 128 * 1024
MAX_JSON_CHARS = 4 * 1024 * 1024
ATTR_READONLY = 0x1
ATTR_HIDDEN = 0x2
ATTR_SYSTEM = 0x4
ATTR_DIRECTORY = 0x10
ATTR_ARCHIVE = 0x20
ATTR_NORMAL = 0x80
SUPPORTED_SET_ATTRIBUTES = (ATTR_READONLY | ATTR_HIDDEN | ATTR_SYSTEM |
                            ATTR_ARCHIVE | ATTR_NORMAL)
KNOWN_SPECIAL_FOLDERS = frozenset({
    0, 2, 5, 6, 7, 8, 9, 11, 13, 14, 16, 17, 19, 20, 21, 22, 23, 24,
    25, 26, 27, 28, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
    44, 45, 46, 47, 48, 53, 54, 55, 56, 57, 58, 59,
})


class ManagedThrown(Exception):
    def __init__(self, value: dict):
        self.value = value
        super().__init__(str(value.get("__type", "System.Exception")))


def _compressed_uint(data: bytes, offset: int = 0) -> tuple[int, int]:
    first = data[offset]
    if first & 0x80 == 0:
        return first, offset + 1
    if first & 0xC0 == 0x80:
        return ((first & 0x3F) << 8) | data[offset + 1], offset + 2
    if first & 0xE0 == 0xC0:
        return ((first & 0x1F) << 24) | (data[offset + 1] << 16) | (data[offset + 2] << 8) | data[offset + 3], offset + 4
    raise UnsupportedManaged("Invalid managed method signature")


def _signature(row) -> tuple[int, bool, bool]:
    sig = bytes(row.Signature.value)
    flags = sig[0]
    at = 1
    if flags & 0x10:
        _, at = _compressed_uint(sig, at)
    count, at = _compressed_uint(sig, at)
    returns_value = sig[at] != 0x01
    return count, bool(flags & 0x20), returns_value


class ManagedRunner:
    def __init__(self, data: bytes, info: SampleInfo, persona: dict, run_dir: Path,
                 max_instructions: int, companions: list[tuple[str, bytes]] | None = None,
                 guest_args: list[str] | None = None,
                 guest_env: dict[str, str] | None = None,
                 bundle_files: list[tuple[str, bytes]] | None = None,
                 bundle_guest_root: str | None = None):
        self.pe = dnfile.dnPE(data=data)
        if self.pe.net is None:
            raise ValueError("Not a managed PE")
        self.main_pe = self.pe
        self.info = info
        self.guest_args = list(guest_args or [])
        self.persona = persona
        self.current_dir = ntpath.normpath(persona["current_dir"])
        home = f'C:\\Users\\{persona["user_name"]}'
        roaming = home + r"\AppData\Roaming"
        local = home + r"\AppData\Local"
        start_menu = roaming + r"\Microsoft\Windows\Start Menu"
        common_start_menu = r"C:\ProgramData\Microsoft\Windows\Start Menu"
        self.special_folders = {
            0: home + r"\Desktop", 2: start_menu + r"\Programs",
            5: home + r"\Documents", 7: start_menu + r"\Programs\Startup",
            11: start_menu, 13: home + r"\Music", 14: home + r"\Videos",
            16: home + r"\Desktop", 17: "",
            21: roaming + r"\Microsoft\Windows\Templates",
            22: common_start_menu, 23: common_start_menu + r"\Programs",
            24: common_start_menu + r"\Programs\Startup",
            25: r"C:\Users\Public\Desktop", 26: roaming, 28: local,
            35: r"C:\ProgramData", 36: r"C:\Windows", 37: r"C:\Windows\System32",
            38: r"C:\Program Files", 39: home + r"\Pictures", 40: home,
            41: r"C:\Windows\SysWOW64", 42: r"C:\Program Files (x86)",
        }
        self.temp_dir = local + "\\Temp\\"
        self.environment = {
            "USERNAME": persona["user_name"], "COMPUTERNAME": persona["hostname"],
            "USERPROFILE": home, "HOMEDRIVE": "C:", "HOMEPATH": home[2:],
            "SYSTEMROOT": r"C:\Windows", "WINDIR": r"C:\Windows",
            "SYSTEMDRIVE": "C:", "COMSPEC": r"C:\Windows\System32\cmd.exe",
            "TEMP": self.temp_dir, "TMP": self.temp_dir,
            "APPDATA": roaming, "LOCALAPPDATA": local,
            "PROGRAMDATA": r"C:\ProgramData", "PROGRAMFILES": r"C:\Program Files",
            "PROGRAMFILES(X86)": r"C:\Program Files (x86)",
        }
        self.environment.update({key.upper(): value for key, value in (guest_env or {}).items()})
        if sum(len(key) + len(value) for key, value in self.environment.items()) > MAX_ENV_TOTAL_CHARS:
            raise UnsupportedManaged("Managed persona environment exceeds limit")
        self.catalog = ArtifactCatalog(run_dir / "artifacts", checkpoint=True)
        self.network = NetworkBridge(self.catalog)
        self.max_instructions = max_instructions
        self.instructions = 0
        self.managed_pe_buffers: list[bytearray] = []
        self.managed_pe_buffer_ids: set[int] = set()
        self.managed_pe_buffer_bytes = 0
        self.opcode_counts: dict[str, int] = {}
        self.framework_call_counts: dict[str, int] = {}
        self.untracked_framework_calls = 0
        self.events: list[dict] = []
        self.stdout: list[str] = []
        self.stdout_chars = 0
        self.console_output = ConsoleOutput()
        self.files: dict[str, bytes] = {}
        self.file_display_paths: dict[str, str] = {}
        self.directories: set[str] = set()
        self.directory_display_paths: dict[str, str] = {}
        self.created_directories: set[str] = set()
        for directory in (self.current_dir, self.temp_dir, *self.special_folders.values()):
            if len(directory) > MAX_GUEST_PATH_CHARS:
                raise UnsupportedManaged("Managed persona special folder exceeds path limit")
            if not directory:
                continue
            self._seed_directory(directory)
        for entry in persona["virtual_files"]:
            if len(entry["path"]) > MAX_GUEST_PATH_CHARS or len(self.files) >= MAX_GUEST_FILES:
                raise UnsupportedManaged("Managed persona file mapping exceeds limit")
            self._seed_directory(ntpath.dirname(self._guest_path(entry["path"])))
            key = self._file_key(entry["path"])
            self.files[key] = entry["text"].encode("utf-8")
            self.file_display_paths[key] = self._guest_path(entry["path"])
        for relative, payload in bundle_files or []:
            guest_path = ntpath.normpath(ntpath.join(
                bundle_guest_root or self.current_dir, relative.replace("/", "\\")))
            if len(guest_path) > MAX_GUEST_PATH_CHARS:
                raise UnsupportedManaged("Managed bundle path exceeds limit")
            self._seed_directory(ntpath.dirname(guest_path))
            key = self._file_key(guest_path)
            if key not in self.files and len(self.files) >= MAX_GUEST_FILES:
                raise UnsupportedManaged("Managed bundle file count exceeds limit")
            self.files[key] = payload
            self.file_display_paths[key] = guest_path
        self.protected_directories = set(self.directories)
        self.file_attributes = {key: ATTR_ARCHIVE for key in self.files}
        self.directory_attributes = {key: ATTR_DIRECTORY for key in self.directories}
        self.file_bytes = sum(map(len, self.files.values()))
        if self.file_bytes > MAX_GUEST_FILE_BYTES:
            raise UnsupportedManaged("Managed persona file storage exceeds 64 MiB")
        self.file_streams: list[dict] = []
        self.memory_streams: list[dict] = []
        self.opened_manifest_resources: set[tuple[int, str]] = set()
        self.manifest_resource_bytes = 0
        self.zip_archives: list[dict] = []
        self.http_clients: list[dict] = []
        self.http_tasks: list[dict] = []
        self.async_tasks: list[dict] = []
        self.http_responses: list[dict] = []
        self.http_contents: list[dict] = []
        self.http_requests: list[dict] = []
        self.http_header_sets: list[dict] = []
        self.http_methods: list[dict] = []
        self.http_task_bytes = 0
        self.http_request_content_bytes = 0
        self.crypto_streams: list[dict] = []
        self.compressed_streams: list[dict] = []
        self.aes_objects = 0
        self.aes_transform_sequence = 0
        self.aes_plaintext_capture_bytes = 0
        self.aes_plaintext_capture_count = 0
        self.aes_plaintext_omitted_bytes = 0
        self.aes_plaintext_omitted_count = 0
        self.pbkdf2_objects = 0
        self.pbkdf2_work = 0
        self.depth = 0
        self.loaded_assemblies: list[dnfile.dnPE] = []
        self.static_fields: dict[tuple[int, int], object] = {}
        self.initialized_types: set[tuple[int, int]] = set()
        self.initializing_types: set[tuple[int, int]] = set()
        self.failed_type_initializers: set[tuple[int, int]] = set()
        self.loaded_assembly_bytes = 0
        self.companion_assemblies: dict[str, tuple[str, bytes]] = {}
        self.named_assemblies: dict[str, dict] = {}
        supplied = companions or []
        if len(supplied) > MAX_LOADED_ASSEMBLIES:
            raise UnsupportedManaged("Managed companion assembly limit exceeded")
        total_companion_bytes = 0
        for filename, raw in supplied:
            if (not isinstance(filename, str) or Path(filename).name != filename or
                    not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_ARTIFACT):
                raise UnsupportedManaged("Invalid managed companion input")
            total_companion_bytes += len(raw)
            if total_companion_bytes > MAX_LOADED_ASSEMBLY_BYTES:
                raise UnsupportedManaged("Managed companion assembly limit exceeded")
            try:
                module = dnfile.dnPE(data=raw)
                if module.net is None or not module.net.mdtables.Assembly.rows:
                    raise ValueError("Missing managed assembly manifest")
                simple_name = str(module.net.mdtables.Assembly.rows[0].Name)
            except (pefile.PEFormatError, ValueError, IndexError, KeyError, TypeError) as exc:
                raise UnsupportedManaged(f"Invalid managed companion {filename}") from exc
            if not simple_name or len(simple_name) > 256 or simple_name.casefold() in self.companion_assemblies:
                raise UnsupportedManaged("Ambiguous or invalid managed companion name")
            self.companion_assemblies[simple_name.casefold()] = (filename, raw)
        self.objects_created = 0
        self.error: str | None = None
        self.catalog.carve_pe(data, "embedded_input", skip_offset_zero=True)

    def _row(self, token: int):
        table = token >> 24
        index = (token & 0xFFFFFF) - 1
        tables = {0x06: "MethodDef", 0x0A: "MemberRef", 0x2B: "MethodSpec"}
        if table not in tables or index < 0:
            raise UnsupportedManaged(f"Unsupported metadata token 0x{token:08x}")
        rows = getattr(self.pe.net.mdtables, tables[table]).rows
        if index >= len(rows):
            raise UnsupportedManaged(f"Invalid metadata token 0x{token:08x}")
        row = rows[index]
        if table == 0x2B:
            return self._row((row.Method.table.number << 24) | row.Method.row_index)
        return row

    def _method_name(self, token: int) -> str:
        row = self._row(token)
        table = token >> 24
        if table in {0x0A, 0x2B} and row.Class and row.Class.row:
            owner = row.Class.row
            namespace = str(getattr(owner, "TypeNamespace", ""))
            typ = str(getattr(owner, "TypeName", ""))
            return ".".join(part for part in (namespace, typ, str(row.Name)) if part)
        return str(row.Name)

    def _generic_type_index(self, token: int) -> int:
        if token >> 24 != 0x2B:
            raise UnsupportedManaged("Expected a generic method instantiation")
        specification = self.pe.net.mdtables.MethodSpec.rows[(token & 0xFFFFFF) - 1]
        signature = bytes(specification.Instantiation.value)
        if len(signature) < 4 or signature[0] != 0x0A:
            raise UnsupportedManaged("Invalid generic method instantiation")
        count, at = _compressed_uint(signature, 1)
        if count != 1 or at >= len(signature) or signature[at] != 0x12:
            raise UnsupportedManaged("Unsupported generic JSON target type")
        coded, at = _compressed_uint(signature, at + 1)
        if at != len(signature) or coded & 3:
            raise UnsupportedManaged("JSON target must be a local class")
        index = coded >> 2
        if not 1 <= index <= len(self.pe.net.mdtables.TypeDef.rows):
            raise UnsupportedManaged("Invalid generic JSON target type")
        return index

    def _json_deserialize(self, token: int, args: list):
        if (len(args) not in (1, 2) or not isinstance(args[0], str)
                or len(args) == 2 and args[1] is not None):
            raise UnsupportedManaged("Unsupported JsonSerializer.Deserialize overload")
        if len(args[0]) > MAX_JSON_CHARS:
            raise UnsupportedManaged("Managed JSON input exceeds 4 MiB")
        try:
            value = json.loads(args[0])
        except (ValueError, RecursionError) as exc:
            raise ManagedThrown({"__type": "System.Text.Json.JsonException",
                                 "args": []}) from exc
        if value is None:
            return None
        if not isinstance(value, dict) or len(value) > 1024:
            raise UnsupportedManaged("Unsupported JSON target shape")
        type_index = self._generic_type_index(token)
        row = self.pe.net.mdtables.TypeDef.rows[type_index - 1]
        if row.Flags.tdAbstract or row.Flags.tdInterface:
            raise UnsupportedManaged("JSON target type cannot be instantiated")
        constructors = [reference.row_index for reference in row.MethodList
                        if str(reference.row.Name) == ".ctor" and reference.row.Flags.mdPublic
                        and _signature(reference.row)[:2] == (0, True)]
        if len(constructors) != 1:
            raise UnsupportedManaged("JSON target public constructor unavailable")
        instance = self._instance(self._current_module_id(), type_index)
        self._execute(constructors[0], [instance])
        setters = {str(reference.row.Name)[4:]: reference.row_index
                   for reference in row.MethodList
                   if str(reference.row.Name).startswith("set_") and
                   reference.row.Flags.mdPublic and
                   _signature(reference.row)[:2] == (1, True)}
        fields = {str(reference.row.Name): reference.row_index
                  for reference in row.FieldList if reference.row.Flags.fdPublic and
                  not reference.row.Flags.fdStatic}
        for name, item in value.items():
            if not isinstance(name, str) or len(name) > 256 or not isinstance(
                    item, (str, int, float, bool, type(None))):
                raise UnsupportedManaged("Unsupported JSON property value")
            if name in setters:
                self._execute(setters[name], [instance, item])
            elif name in fields:
                instance["fields"][fields[name]] = item
        self._record_event({"event": "managed_json_deserialize", "type_index": type_index,
                            "properties": sorted(value)[:100]})
        return instance

    def _type_name(self, token: int) -> str:
        table = token >> 24
        index = (token & 0xFFFFFF) - 1
        tables = {0x01: "TypeRef", 0x02: "TypeDef"}
        if table not in tables or index < 0:
            raise UnsupportedManaged(f"Unsupported exception type token 0x{token:08x}")
        rows = getattr(self.pe.net.mdtables, tables[table]).rows
        if index >= len(rows):
            raise UnsupportedManaged(f"Invalid exception type token 0x{token:08x}")
        row = rows[index]
        return ".".join(part for part in (str(row.TypeNamespace), str(row.TypeName)) if part)

    def _matching_catch(self, body, code_base: int, offset: int,
                        thrown: ManagedThrown):
        candidates = [handler for handler in body.exception_handlers
                      if handler.is_catch() and
                      code_base + handler.try_start <= offset < code_base + handler.try_end]
        candidates.sort(key=lambda handler: handler.try_end - handler.try_start)
        actual = str(thrown.value["__type"])
        for handler in candidates:
            if handler.catch_type is None:
                raise UnsupportedManaged("Catch clause has no exception type")
            expected = self._type_name(handler.catch_type.value)
            if expected != actual and not (expected == "System.Exception" and actual.endswith("Exception")):
                continue
            return handler
        return None

    @staticmethod
    def _finalizers(body, code_base: int, source: int, destination: int | None) -> list[int]:
        handlers = [handler for handler in body.exception_handlers
                    if handler.is_finally() and
                    code_base + handler.try_start <= source < code_base + handler.try_end and
                    (destination is None or not (
                        code_base + handler.try_start <= destination < code_base + handler.try_end))]
        handlers.sort(key=lambda handler: handler.try_end - handler.try_start)
        return [code_base + handler.handler_start for handler in handlers]

    def _route_exception(self, body, code_base: int, offset: int, thrown: ManagedThrown,
                         stack: list, offsets: dict[int, int],
                         active_catches: list[tuple[int, int, ManagedThrown]]) -> tuple[int, dict | None]:
        catch = self._matching_catch(body, code_base, offset, thrown)
        target = code_base + catch.handler_start if catch is not None else None
        finalizers = self._finalizers(body, code_base, offset, target)
        stack.clear()
        if finalizers:
            if any(position not in offsets for position in finalizers):
                raise UnsupportedManaged("Invalid managed finally handler target")
            self._record_event({"event": "managed_finally", "reason": "exception",
                                "handler": finalizers[0]})
            return offsets[finalizers[0]], {"remaining": finalizers[1:],
                                            "target": target, "thrown": thrown,
                                            "catch": catch}
        if target is None:
            raise thrown
        if target not in offsets:
            raise UnsupportedManaged("Invalid managed exception handler target")
        stack.append(thrown.value)
        active_catches.append((target, code_base + catch.handler_end, thrown))
        self._record_event({"event": "managed_catch", "type": thrown.value["__type"],
                            "handler": target})
        return offsets[target], None

    def _track_managed_buffer(self, value) -> None:
        if (isinstance(value, bytearray) and len(value) >= 512 and
                id(value) not in self.managed_pe_buffer_ids and
                len(self.managed_pe_buffers) < 1024 and
                self.managed_pe_buffer_bytes + len(value) <= MAX_MEMORY_SCAN):
            self.managed_pe_buffers.append(value)
            self.managed_pe_buffer_ids.add(id(value))
            self.managed_pe_buffer_bytes += len(value)

    def _capture_before_buffer_mutation(self, value, index: int) -> None:
        """Keep a decoded PE when the guest overwrites its live byte array."""
        if (isinstance(value, bytearray) and len(value) >= 512 and
                value[:2] == b"MZ" and index < 512):
            self.catalog.carve_pe(bytes(value), "managed_array_before_overwrite")

    def _checked_array(self, array, index: int | None = None):
        if array is None:
            raise ManagedThrown({"__type": "System.NullReferenceException", "args": []})
        if not isinstance(array, (list, bytes, bytearray)):
            raise UnsupportedManaged("Unsupported managed array value")
        if index is not None and not 0 <= index < len(array):
            raise ManagedThrown({"__type": "System.IndexOutOfRangeException", "args": []})
        self._track_managed_buffer(array)
        return array

    def _call(self, token: int, stack: list, constructor: bool = False,
              virtual: bool = False):
        row = self._row(token)
        argc, has_this, returns = _signature(row)
        name = self._method_name(token)
        if len(stack) < argc + (1 if has_this and not constructor else 0):
            raise UnsupportedManaged(f"Stack underflow at {name}")
        args = [stack.pop() for _ in range(argc)][::-1]
        this = stack.pop() if has_this and not constructor else None
        for value in args:
            self._track_managed_buffer(value)
        secret = name.startswith("System.Security.Cryptography.Rfc2898DeriveBytes.")
        self._record_event({"event": "managed_call", "method": name,
                            "args": (["[redacted]" for _ in args] if secret else
                                     [self._safe_repr(a) for a in args])})
        if token >> 24 == 0x06:
            index = token & 0xFFFFFF
            if constructor:
                if name != ".ctor":
                    raise UnsupportedManaged("Managed newobj target is not a constructor")
                owner = self._method_owner(self.pe, index)
                module_id = self._current_module_id()
                self._ensure_type_initialized(owner, field_access=False)
                instance = self._instance(module_id, owner)
                self._execute(index, [instance, *args])
                self._record_event({"event": "managed_object_create", "module_id": module_id,
                                    "type_index": owner, "via": "newobj"})
                result = instance
            else:
                if not has_this and name != ".cctor":
                    self._ensure_type_initialized(self._method_owner(self.pe, index),
                                                  field_access=False)
                if has_this:
                    if this is None:
                        raise ManagedThrown({"__type": "System.NullReferenceException", "args": []})
                    module_id = self._current_module_id()
                    owner = self._method_owner(self.pe, index)
                    if (not isinstance(this, dict) or this.get("__type") != "System.Object" or
                            this.get("module_id") != module_id or
                            owner not in self._type_lineage(self.pe, this.get("type_index"))):
                        raise UnsupportedManaged("Managed instance does not match method type")
                    if virtual:
                        resolved = self._dispatch_virtual_method(
                            self.pe, index, this["type_index"], public_only=False)
                        self._record_event({"event": "managed_virtual_dispatch",
                                            "module_id": module_id, "declared_method": index,
                                            "method": resolved})
                        index = resolved
                result = self._execute(index, args if this is None else [this, *args])
        else:
            try:
                external = self._companion_member(row, args, this, constructor, virtual)
                if external is not None:
                    result = external[0]
                else:
                    coverage_name = name[:256]
                    if coverage_name in self.framework_call_counts or len(self.framework_call_counts) < 1024:
                        self.framework_call_counts[coverage_name] = self.framework_call_counts.get(coverage_name, 0) + 1
                    else:
                        self.untracked_framework_calls += 1
                    result = (self._json_deserialize(token, args)
                              if token >> 24 == 0x2B and
                              name == "System.Text.Json.JsonSerializer.Deserialize"
                              else self._framework(name, args, this, constructor))
            except ManagedThrown as thrown:
                self._record_event({"event": "managed_throw", "type": thrown.value["__type"],
                                    "method": name})
                raise
        if constructor or returns:
            self._track_managed_buffer(result)
            stack.append(result)

    def _companion_member(self, member, args: list, this, constructor: bool,
                          virtual: bool = False):
        """Resolve a direct MemberRef through an explicitly supplied guest DLL."""
        owner = getattr(member, "Class", None)
        if not owner or owner.table.name != "TypeRef" or not owner.row:
            return None
        type_ref = owner.row
        scope = getattr(type_ref, "ResolutionScope", None)
        if not scope or scope.table.name != "AssemblyRef" or not scope.row:
            return None
        assembly_name = str(scope.row.Name)
        key = assembly_name.casefold()
        if key not in self.companion_assemblies and (
                key in {"mscorlib", "netstandard"} or
                key.startswith(("system.", "microsoft."))):
            return None
        if key not in self.companion_assemblies:
            raise ManagedThrown({"__type": "System.IO.FileNotFoundException", "args": []})
        assembly = self._load_assembly([assembly_name])
        module = self._loaded_pe(assembly, "System.Reflection.Assembly")
        namespace, type_name = str(type_ref.TypeNamespace), str(type_ref.TypeName)
        type_rows = [(index, row) for index, row in enumerate(module.net.mdtables.TypeDef.rows, 1)
                     if str(row.TypeNamespace) == namespace and str(row.TypeName) == type_name]
        if len(type_rows) != 1:
            raise ManagedThrown({"__type": "System.TypeLoadException", "args": []})
        type_index, type_row = type_rows[0]
        _, has_this, _ = _signature(member)
        if constructor and (str(member.Name) != ".ctor" or not has_this):
            raise UnsupportedManaged("Invalid companion constructor reference")
        if not constructor and has_this:
            if this is None:
                raise ManagedThrown({"__type": "System.NullReferenceException", "args": []})
            if (not isinstance(this, dict) or this.get("__type") != "System.Object" or
                    this.get("module_id") != assembly["module_id"] or
                    type_index not in self._type_lineage(module, this.get("type_index"))):
                raise UnsupportedManaged("Companion instance does not match referenced type")
        elif this is not None:
            raise UnsupportedManaged("Static companion call has an instance target")
        signature = bytes(member.Signature.value)
        matches = [reference.row_index for reference in type_row.MethodList
                   if str(reference.row.Name) == str(member.Name) and
                   bytes(reference.row.Signature.value) == signature and
                   reference.row.Flags.mdPublic and
                   bool(reference.row.Flags.mdStatic) == (not has_this)]
        if len(matches) != 1:
            raise ManagedThrown({"__type": "System.MissingMethodException", "args": []})
        method_index = matches[0]
        if virtual and has_this:
            method_index = self._dispatch_virtual_method(
                module, method_index, this["type_index"], public_only=True)
        if constructor:
            if type_row.Flags.tdAbstract or type_row.Flags.tdInterface:
                raise UnsupportedManaged("Managed type cannot be instantiated")
            this = self._instance(assembly["module_id"], type_index)
        self._record_event({"event": "managed_companion_call", "assembly": assembly_name,
                            "type": ".".join(part for part in (namespace, type_name) if part),
                            "method": str(member.Name)[:256],
                            "dispatch_type_index": self._method_owner(module, method_index)})
        previous = self.pe
        self.pe = module
        try:
            if (not constructor and not has_this and str(member.Name) != ".cctor"):
                self._ensure_type_initialized(type_index, field_access=False)
            elif constructor:
                self._ensure_type_initialized(type_index, field_access=False)
            result = self._execute(method_index, [this, *args] if has_this else args)
        finally:
            self.pe = previous
        if constructor:
            self._record_event({"event": "managed_object_create", "module_id": assembly["module_id"],
                                "type_index": type_index, "via": "newobj"})
            return (this,)
        return (result,)

    @staticmethod
    def _safe_repr(value):
        if isinstance(value, (bytes, bytearray, list)):
            return f"{type(value).__name__}[{len(value)}]"
        if isinstance(value, str):
            return repr(value[:250]) + (f"...[{len(value)} chars]" if len(value) > 250 else "")
        if isinstance(value, dict):
            return f"object[{str(value.get('__type', 'field-handle'))[:120]}]"
        return repr(value)[:500]

    @staticmethod
    def _deref(value):
        if isinstance(value, dict) and "__ref" in value:
            location, index = value["__ref"], value["index"]
            return location.get(index) if isinstance(location, dict) else location[index]
        return value

    def _record_event(self, event: dict) -> None:
        if len(self.events) >= MAX_MANAGED_EVENTS:
            raise UnsupportedManaged("Managed event limit exceeded")
        self.events.append(event)

    @staticmethod
    def _to_text(value) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, (int, float, bool)):
            return str(value)
        raise UnsupportedManaged("Unsupported managed string conversion")

    @staticmethod
    def _managed_network_url(value) -> str:
        if value is None:
            raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
        if isinstance(value, dict) and value.get("__type") == "System.Uri":
            args = value.get("args")
            if not isinstance(args, list) or len(args) != 1:
                raise UnsupportedManaged("Unsupported managed HTTP Uri constructor")
            value = args[0]
        if not isinstance(value, str):
            raise UnsupportedManaged("Unsupported managed HTTP address type")
        if len(value) > 2048 or "\0" in value:
            raise UnsupportedManaged("Managed network URL exceeds limit")
        return value

    def _http_header_set(self, owner: dict) -> dict:
        if len(self.http_header_sets) >= MAX_HTTP_HEADER_SETS:
            raise UnsupportedManaged("Managed HTTP header-set count exceeded")
        headers = {"__type": "System.Net.Http.Headers.HttpRequestHeaders",
                   "owner": owner, "items": {}}
        self.http_header_sets.append(headers)
        return headers

    def _http_header_call(self, name: str, args: list, headers: dict):
        if not any(item is headers for item in self.http_header_sets):
            raise UnsupportedManaged("Unknown managed HTTP headers")
        if headers["owner"].get("closed"):
            raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
        method = name.rsplit(".", 1)[-1]
        items = headers["items"]
        if headers["owner"].get("sent") and method in {"Add", "Remove", "Clear"}:
            raise ManagedThrown({"__type": "System.InvalidOperationException", "args": []})
        if method == "Clear" and not args:
            items.clear()
            return None
        if method in {"Contains", "Remove"} and len(args) == 1:
            key = args[0]
            if not isinstance(key, str):
                raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
            folded = key.lower()
            if method == "Contains":
                return folded in items
            return items.pop(folded, None) is not None
        if method != "Add" or len(args) != 2:
            raise UnsupportedManaged(f"Unsupported HTTP header method: {name}")
        key, value = args
        if not isinstance(key, str) or not key:
            raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
        if (len(key) > 128 or not re.fullmatch(
                r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", key)):
            raise ManagedThrown({"__type": "System.FormatException", "args": []})
        folded = key.lower()
        if folded in HTTP_RESTRICTED_REQUEST_HEADERS:
            raise ManagedThrown({"__type": "System.InvalidOperationException", "args": []})
        if not isinstance(value, str) or len(value) > 4096 or any(
                ord(char) < 32 or ord(char) == 127 for char in value):
            raise ManagedThrown({"__type": "System.FormatException", "args": []})
        previous = items.get(folded)
        combined = previous[1] + ", " + value if previous else value
        new_size = sum(len(item[0]) + len(item[1]) for item in items.values())
        if previous:
            new_size -= len(previous[0]) + len(previous[1])
        if new_size + len(key) + len(combined) > MAX_HEADER_CHARS:
            raise UnsupportedManaged("Managed HTTP headers exceed 16 KiB")
        if not previous and len(items) >= 64:
            raise UnsupportedManaged("Managed HTTP header count exceeded")
        items[folded] = (previous[0] if previous else key, combined)
        return None

    def _http_method_state(self, verb: str) -> dict:
        if len(self.http_methods) >= MAX_HTTP_REQUESTS:
            raise UnsupportedManaged("Managed HTTP method count exceeded")
        if verb not in HTTP_METHODS:
            raise UnsupportedManaged(f"Unsupported managed HTTP method: {verb}")
        value = {"__type": "System.Net.Http.HttpMethod", "verb": verb}
        self.http_methods.append(value)
        return value

    def _http_request_state(self, args: list) -> dict:
        if len(self.http_requests) >= MAX_HTTP_REQUESTS:
            raise UnsupportedManaged("Managed HTTP request count exceeded")
        if len(args) == 0:
            verb, uri = "GET", None
        elif len(args) == 2:
            method = args[0]
            if not isinstance(method, dict) or not any(
                    item is method for item in self.http_methods):
                raise UnsupportedManaged("Unknown managed HTTP method")
            verb = method["verb"]
            uri = self._managed_network_url(args[1]) if args[1] is not None else None
        else:
            raise UnsupportedManaged("Unsupported HttpRequestMessage constructor overload")
        request = {"__type": "System.Net.Http.HttpRequestMessage",
                   "verb": verb, "uri": uri, "content": None,
                   "closed": False, "sent": False}
        request["headers"] = self._http_header_set(request)
        self.http_requests.append(request)
        return request

    def _http_request_call(self, name: str, args: list, request: dict):
        if not any(item is request for item in self.http_requests):
            raise UnsupportedManaged("Unknown managed HTTP request")
        method = name.rsplit(".", 1)[-1]
        if method == "Dispose" and not args:
            request["closed"] = True
            if request["content"] is not None:
                request["content"]["closed"] = True
            return None
        if request["closed"]:
            raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
        if request["sent"] and method in {"set_Content", "set_RequestUri"}:
            raise ManagedThrown({"__type": "System.InvalidOperationException", "args": []})
        if method == "get_Headers" and not args:
            return request["headers"]
        if method == "get_Content" and not args:
            return request["content"]
        if method == "set_Content" and len(args) == 1:
            content = args[0]
            if content is not None and (not isinstance(content, dict) or not any(
                    item is content for item in self.http_contents) or
                    content.get("request_kind") not in {"StringContent", "ByteArrayContent"}):
                raise UnsupportedManaged("Unsupported HTTP request content")
            request["content"] = content
            return None
        if method == "get_RequestUri" and not args:
            return request["uri"]
        if method == "set_RequestUri" and len(args) == 1:
            request["uri"] = self._managed_network_url(args[0]) if args[0] is not None else None
            return None
        raise UnsupportedManaged(f"Unsupported HttpRequestMessage method: {name}")

    @staticmethod
    def _http_headers_merge(*sources: dict) -> dict[str, str]:
        merged: dict[str, tuple[str, str]] = {}
        for source in sources:
            for key, value in source.items():
                merged[key.lower()] = (key, value)
        if len(merged) > 64 or sum(len(key) + len(value) for key, value in
                                   merged.values()) > MAX_HEADER_CHARS:
            raise UnsupportedManaged("Managed HTTP headers exceed limit")
        return dict(merged.values())

    def _http_client_call(self, name: str, args: list, client: dict):
        if not any(item is client for item in self.http_clients):
            raise UnsupportedManaged("Unknown managed HttpClient object")
        method = name.rsplit(".", 1)[-1]
        if method in {"Dispose", "Close"} and not args:
            client["closed"] = True
            return None
        if client["closed"]:
            raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
        if method == "get_DefaultRequestHeaders" and not args:
            return client["headers"]
        if method == "get_BaseAddress" and not args:
            return client["base_address"]
        if method == "set_BaseAddress" and len(args) == 1:
            address = args[0]
            if address is not None:
                if not isinstance(address, dict) or address.get("__type") != "System.Uri":
                    raise UnsupportedManaged("Unsupported HttpClient BaseAddress value")
                text = self._managed_network_url(address)
                try:
                    absolute = bool(urlsplit(text).scheme)
                except ValueError:
                    absolute = False
                if not absolute:
                    raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
            if client["started"]:
                raise ManagedThrown({"__type": "System.InvalidOperationException", "args": []})
            client["base_address"] = address
            return None
        if (method not in {"GetByteArrayAsync", "GetStringAsync", "GetAsync", "PostAsync",
                           "SendAsync"}
                or len(args) != (2 if method == "PostAsync" else 1)):
            raise UnsupportedManaged(f"Unsupported HttpClient method: {name}")
        request = None
        body = None
        verb = "POST" if method == "PostAsync" else "GET"
        if method == "SendAsync":
            request = args[0]
            if request is None:
                raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
            if not isinstance(request, dict) or not any(
                    item is request for item in self.http_requests):
                raise UnsupportedManaged("Unknown managed HTTP request")
            if request["closed"]:
                raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
            if request["sent"]:
                raise ManagedThrown({"__type": "System.InvalidOperationException", "args": []})
            verb = request["verb"]
            content = request["content"]
        else:
            content = args[1] if method == "PostAsync" else None
        if content is not None:
            if (not isinstance(content, dict) or
                    not any(item is content for item in self.http_contents) or
                    content.get("request_kind") not in {"StringContent", "ByteArrayContent"}):
                raise UnsupportedManaged("Unsupported HttpClient request content")
            if content["closed"]:
                raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
            body = self._http_content_bytes(content)
        header_sources = [dict(client["headers"]["items"].values())]
        if request is not None:
            header_sources.append(dict(request["headers"]["items"].values()))
        if content is not None:
            header_sources.append(content["headers"])
        headers = self._http_headers_merge(*header_sources)
        raw_address = (request["uri"] if request is not None else
                       self._managed_network_url(args[0]) if args[0] is not None else None)
        client["started"] = True
        if request is not None:
            request["sent"] = True
        base_address = client["base_address"]
        base_url = self._managed_network_url(base_address) if base_address is not None else None
        if raw_address is None:
            if base_url is None:
                raise ManagedThrown({"__type": "System.InvalidOperationException", "args": []})
            url = base_url
        else:
            try:
                is_absolute = bool(urlsplit(raw_address).scheme)
            except ValueError as exc:
                raise ManagedThrown({"__type": "System.UriFormatException", "args": []}) from exc
            if not is_absolute and base_url is None:
                raise ManagedThrown({"__type": "System.InvalidOperationException", "args": []})
            url = raw_address if is_absolute else urljoin(base_url, raw_address)
        if len(url) > 2048:
            raise UnsupportedManaged("Managed network URL exceeds limit")
        try:
            parts = urlsplit(url)
            hostname = parts.hostname
        except ValueError as exc:
            raise ManagedThrown({"__type": "System.UriFormatException", "args": []}) from exc
        if parts.scheme not in {"http", "https"} or not hostname:
            raise ManagedThrown({"__type": "System.InvalidOperationException", "args": []})
        if len(self.http_tasks) >= MAX_HTTP_TASKS:
            raise UnsupportedManaged("Managed HTTP task count exceeded")
        if request is not None:
            request["uri"] = url
        value = None
        error = None
        status = None
        size = 0
        try:
            payload, metadata = self.network.fetch(
                url, method=verb,
                body=body, headers=headers, with_metadata=True)
            size = len(payload)
            status = metadata["status"]
            if self.http_task_bytes + size > MAX_HTTP_TASK_BYTES:
                raise UnsupportedManaged("Managed HTTP task bytes exceed 64 MiB")
            self.http_task_bytes += size
            if method not in {"GetAsync", "PostAsync", "SendAsync"} and not 200 <= status < 300:
                error = {"__type": "System.Net.Http.HttpRequestException", "args": []}
            elif method == "GetByteArrayAsync":
                value = bytearray(payload)
            elif method == "GetStringAsync":
                value = payload.decode("utf-8", errors="replace")
            else:
                content = {"__type": "System.Net.Http.HttpContent", "data": bytes(payload),
                           "closed": False}
                value = {"__type": "System.Net.Http.HttpResponseMessage", "status": status,
                         "content": content, "closed": False}
                self.http_contents.append(content)
                self.http_responses.append(value)
        except NetworkDenied as exc:
            error = {"__type": "System.Net.Http.HttpRequestException",
                     "args": [str(exc)[:256]]}
        task = {"__type": "System.Threading.Tasks.Task`1", "value": value,
                "error": error}
        self.http_tasks.append(task)
        self._record_event({"event": "managed_http_task", "method": method,
                            "url": url, "verb": verb, "status": status, "size": size,
                            "request_size": len(body or b""),
                            "faulted": error is not None})
        return task

    def _http_content_state(self, name: str, args: list) -> dict:
        if len(self.http_contents) >= MAX_HTTP_TASKS:
            raise UnsupportedManaged("Managed HTTP content count exceeded")
        kind = name.removesuffix("..ctor").rsplit(".", 1)[-1]
        headers: dict[str, str] = {}
        if kind == "StringContent":
            if not 1 <= len(args) <= 3:
                raise UnsupportedManaged("Unsupported StringContent constructor overload")
            if args[0] is None:
                raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
            if not isinstance(args[0], str):
                raise UnsupportedManaged("Unsupported StringContent value")
            if len(args) >= 2 and args[1] is not None and not (
                    isinstance(args[1], dict) and
                    args[1].get("__type") == "System.Text.Encoding" and
                    args[1].get("encoding") == "utf-8"):
                raise UnsupportedManaged("Only UTF-8 StringContent is modeled")
            media = args[2] if len(args) == 3 and args[2] is not None else "text/plain"
            if (not isinstance(media, str) or len(media) > 128 or not re.fullmatch(
                    r"[A-Za-z0-9!#$%&'*+.^_`|~-]+/[A-Za-z0-9!#$%&'*+.^_`|~-]+", media)):
                raise ManagedThrown({"__type": "System.FormatException", "args": []})
            data = self._encode_utf8_bounded(args[0])
            if len(data) > MAX_TRANSFER:
                raise UnsupportedManaged("Managed HTTP request exceeds 16 MiB")
            if self.http_request_content_bytes + len(data) > MAX_HTTP_REQUEST_CONTENT_BYTES:
                raise UnsupportedManaged("Managed HTTP request content exceeds 64 MiB")
            self.http_request_content_bytes += len(data)
            headers = {"Content-Type": media + "; charset=utf-8"}
            offset, count = 0, len(data)
        elif kind == "ByteArrayContent":
            if len(args) not in (1, 3):
                raise UnsupportedManaged("Unsupported ByteArrayContent constructor overload")
            data = args[0]
            if data is None:
                raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
            if not isinstance(data, (bytes, bytearray)):
                raise UnsupportedManaged("Unsupported ByteArrayContent array")
            offset, count = (0, len(data)) if len(args) == 1 else (args[1], args[2])
            if (type(offset) is not int or type(count) is not int or offset < 0 or
                    count < 0 or offset > len(data) or count > len(data) - offset):
                raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
            if count > MAX_TRANSFER:
                raise UnsupportedManaged("Managed HTTP request exceeds 16 MiB")
        else:
            raise UnsupportedManaged(f"Unsupported managed HTTP content: {name}")
        content = {"__type": "System.Net.Http.HttpContent", "request_kind": kind,
                   "data": data, "offset": offset, "count": count,
                   "headers": headers, "closed": False}
        self.http_contents.append(content)
        return content

    @staticmethod
    def _http_content_bytes(content: dict) -> bytes:
        data = content["data"]
        offset = content.get("offset", 0)
        count = content.get("count", len(data))
        if count > MAX_TRANSFER:
            raise UnsupportedManaged("Managed HTTP content exceeds 16 MiB")
        return bytes(data[offset:offset + count])

    def _http_response_call(self, name: str, args: list, response: dict):
        if not any(item is response for item in self.http_responses):
            raise UnsupportedManaged("Unknown managed HTTP response")
        method = name.rsplit(".", 1)[-1]
        if method in {"Dispose", "Close"} and not args:
            response["closed"] = True
            response["content"]["closed"] = True
            return None
        if method == "get_StatusCode" and not args:
            return response["status"]
        if method == "get_IsSuccessStatusCode" and not args:
            return 200 <= response["status"] < 300
        if method == "get_Content" and not args:
            return response["content"]
        if method == "EnsureSuccessStatusCode" and not args:
            if not 200 <= response["status"] < 300:
                raise ManagedThrown({"__type": "System.Net.Http.HttpRequestException", "args": []})
            return response
        raise UnsupportedManaged(f"Unsupported managed HTTP response method: {name}")

    def _http_content_call(self, name: str, args: list, content: dict):
        if not any(item is content for item in self.http_contents):
            raise UnsupportedManaged("Unknown managed HTTP content")
        method = name.rsplit(".", 1)[-1]
        if method == "Dispose" and not args:
            content["closed"] = True
            return None
        if content["closed"]:
            raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
        if method not in {"ReadAsByteArrayAsync", "ReadAsStringAsync"} or args:
            raise UnsupportedManaged(f"Unsupported managed HTTP content method: {name}")
        if len(self.http_tasks) >= MAX_HTTP_TASKS:
            raise UnsupportedManaged("Managed HTTP task count exceeded")
        data = self._http_content_bytes(content)
        if self.http_task_bytes + len(data) > MAX_HTTP_TASK_BYTES:
            raise UnsupportedManaged("Managed HTTP task bytes exceed 64 MiB")
        self.http_task_bytes += len(data)
        value = bytearray(data) if method == "ReadAsByteArrayAsync" else data.decode(
            "utf-8", errors="replace")
        task = {"__type": "System.Threading.Tasks.Task`1", "value": value, "error": None}
        self.http_tasks.append(task)
        self._record_event({"event": "managed_http_content_task", "method": method,
                            "size": len(data)})
        return task

    def _http_task_call(self, name: str, args: list, state: dict):
        method = name.rsplit(".", 1)[-1]
        if state.get("__type") == "System.Threading.Tasks.Task`1":
            task = state
            if not any(item is task for item in self.http_tasks):
                raise UnsupportedManaged("Unknown managed HTTP task")
            if method == "GetAwaiter" and not args:
                return {"__type": "System.Runtime.CompilerServices.TaskAwaiter`1",
                        "task": task}
            if method == "get_IsCompleted" and not args:
                return True
            if method == "get_IsCompletedSuccessfully" and not args:
                return task["error"] is None
            if method == "get_IsFaulted" and not args:
                return task["error"] is not None
            if method == "get_Result" and not args:
                if task["error"] is not None:
                    raise ManagedThrown({"__type": "System.AggregateException", "args": []})
                return task["value"]
        elif state.get("__type") == "System.Runtime.CompilerServices.TaskAwaiter`1":
            task = state.get("task")
            if not any(item is task for item in self.http_tasks):
                raise UnsupportedManaged("Unknown managed HTTP task awaiter")
            if method == "get_IsCompleted" and not args:
                return True
            if method == "GetResult" and not args:
                if task["error"] is not None:
                    raise ManagedThrown(task["error"])
                return task["value"]
        raise UnsupportedManaged(f"Unsupported managed HTTP task method: {name}")

    @staticmethod
    def _encode_utf8_bounded(value: str) -> bytes:
        if len(value) > MAX_ARTIFACT:
            raise UnsupportedManaged("Managed UTF-8 value exceeds 32 MiB")
        output = bytearray()
        for offset in range(0, len(value), 64 * 1024):
            chunk = value[offset:offset + 64 * 1024].encode("utf-8", errors="replace")
            if len(output) + len(chunk) > MAX_ARTIFACT:
                raise UnsupportedManaged("Managed UTF-8 value exceeds 32 MiB")
            output.extend(chunk)
        return bytes(output)

    def _check_stream_access(self, key: str, access: int, *, exclude: dict | None = None) -> None:
        for stream in self.file_streams:
            if (stream is not exclude and not stream["closed"] and stream["key"] == key
                    and access & ~stream["share"]):
                raise ManagedThrown({"__type": "System.IO.IOException", "args": [key]})

    def _check_stream_delete(self, key: str) -> None:
        for stream in self.file_streams:
            if not stream["closed"] and stream["key"] == key:
                if not stream["share"] & 4:
                    raise ManagedThrown({"__type": "System.IO.IOException", "args": [key]})
                raise UnsupportedManaged("Deleting an open managed FileStream is unsupported")

    def _store_file(self, path: str, payload: bytes, *, stream: dict | None = None) -> None:
        self._file_path(path)
        if len(payload) > MAX_ARTIFACT:
            raise UnsupportedManaged("Managed guest file exceeds 32 MiB")
        key = self._file_key(path)
        self._check_stream_access(key, 2, exclude=stream)
        if key in self.directories:
            raise ManagedThrown({"__type": "System.UnauthorizedAccessException", "args": [path]})
        self._require_parent(key)
        if key in self.files and self.file_attributes.get(key, ATTR_ARCHIVE) & ATTR_READONLY:
            raise ManagedThrown({"__type": "System.UnauthorizedAccessException", "args": [path]})
        if key not in self.files and len(self.files) >= MAX_GUEST_FILES:
            raise UnsupportedManaged("Managed guest file count exceeded")
        total = self.file_bytes - len(self.files.get(key, b"")) + len(payload)
        if total > MAX_GUEST_FILE_BYTES:
            raise UnsupportedManaged("Managed guest file storage exceeds 64 MiB")
        self.files[key] = payload
        self.file_display_paths.setdefault(key, self._guest_path(path))
        self.file_attributes.setdefault(key, ATTR_ARCHIVE)
        self.file_bytes = total
        self.catalog.add(payload, "managed_file_write", guest_path=path)
        self._record_event({"event": "file_write", "path": path, "size": len(payload)})

    @staticmethod
    def _zip_preflight(data: bytes) -> tuple[int, int, int]:
        """Bound central-directory parsing before ZipFile allocates one ZipInfo per entry."""
        cursor = len(data)
        oversized = False
        too_many = False
        zip64 = False
        best = None
        for _ in range(64):
            end = data.rfind(b"PK\x05\x06", 0, cursor)
            if end < 0:
                break
            cursor = end
            if end + 22 > len(data):
                continue
            field = lambda offset, width: int.from_bytes(data[end + offset:end + offset + width],
                                                          "little")
            comment_length = field(20, 2)
            if end + 22 + comment_length > len(data):
                continue
            disk, directory_disk = field(4, 2), field(6, 2)
            disk_count, expected_count = field(8, 2), field(10, 2)
            size = field(12, 4)
            if disk or directory_disk or disk_count != expected_count:
                continue
            if expected_count == 0xFFFF or size == 0xFFFFFFFF:
                zip64 = True
                continue
            if size > MAX_ZIP_CENTRAL_BYTES:
                oversized = True
                continue
            start = end - size
            if start < 0:
                continue
            at = start
            actual_count = 0
            while at < end:
                if at + 46 > end or data[at:at + 4] != b"PK\x01\x02":
                    break
                name_length = int.from_bytes(data[at + 28:at + 30], "little")
                extra_length = int.from_bytes(data[at + 30:at + 32], "little")
                comment_length = int.from_bytes(data[at + 32:at + 34], "little")
                at += 46 + name_length + extra_length + comment_length
                actual_count += 1
                if actual_count > MAX_ZIP_ENTRIES:
                    too_many = True
                    break
                if at > end:
                    break
            if at == end and actual_count == expected_count and actual_count <= MAX_ZIP_ENTRIES:
                # A comment can contain a fake EOCD. Favor the candidate that
                # accounts for the most structurally valid directory entries.
                candidate = (actual_count, end + 22 + field(20, 2) == len(data),
                             -end, size, end)
                if best is None or candidate[:3] > best[:3]:
                    best = candidate
        if best is not None:
            return best[0], best[3], best[4]
        if too_many:
            raise UnsupportedManaged("Managed ZIP entry count exceeds limit")
        if oversized:
            raise UnsupportedManaged("Managed ZIP central directory exceeds limit")
        if zip64:
            raise UnsupportedManaged("ZIP64 central directory is not modeled")
        raise ManagedThrown({"__type": "System.IO.InvalidDataException", "args": []})

    def _zip_parser_bytes(self, data: bytes) -> bytes:
        if len(data) > MAX_ARTIFACT:
            raise UnsupportedManaged("Managed ZIP input exceeds 32 MiB")
        count, central_size, end_record = self._zip_preflight(data)
        self._record_event({"event": "managed_zip_preflight", "entries": count,
                            "central_size": central_size})
        # A verified end record prevents a fake signature inside the comment or
        # trailing overlay from steering Python's ZIP parser to a different record.
        if end_record + 22 == len(data) and data[end_record + 20:end_record + 22] == b"\0\0":
            return data
        return data[:end_record + 20] + b"\0\0"

    def _zip_archive_state(self, args: list) -> dict:
        if len(args) not in (1, 2, 3, 4):
            raise UnsupportedManaged("Unsupported ZipArchive constructor overload")
        source = args[0]
        if source is None:
            raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
        mode = args[1] if len(args) >= 2 else 0
        if type(mode) is not int or mode not in (0, 1, 2):
            raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
        if mode != 0:
            raise UnsupportedManaged("ZipArchive create/update mode is not modeled")
        leave_open = args[2] if len(args) >= 3 else False
        if leave_open not in (False, True, 0, 1):
            raise UnsupportedManaged("Unsupported ZipArchive leaveOpen flag")
        encoding = args[3] if len(args) == 4 else None
        if encoding is not None:
            if (not isinstance(encoding, dict) or
                    encoding.get("__type") != "System.Text.Encoding" or
                    encoding.get("encoding") != "utf-8"):
                raise UnsupportedManaged("Unsupported ZIP entry name encoding")
            encoding = "utf-8"
        if len(self.zip_archives) >= MAX_ZIP_ENTRIES:
            raise UnsupportedManaged("Managed ZipArchive count exceeded")
        if not isinstance(source, dict):
            raise UnsupportedManaged("Unsupported ZipArchive source stream")
        kind = source.get("__type")
        if kind == "System.IO.MemoryStream":
            source = self._memory_stream_state(source)
            if source["closed"]:
                raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
            data = bytes(source["buffer"][source["position"]:source["length"]])
            source["position"] = source["length"]
        elif kind == "System.IO.FileStream":
            if not any(item is source for item in self.file_streams):
                raise UnsupportedManaged("Unknown ZipArchive FileStream source")
            if source["closed"] or not source["access"] & 1:
                raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
            data = self.files[source["key"]][source["position"]:]
            source["position"] = len(self.files[source["key"]])
        else:
            raise UnsupportedManaged("Unsupported ZipArchive source stream")
        parser_bytes = self._zip_parser_bytes(data)
        try:
            archive = zipfile.ZipFile(io.BytesIO(parser_bytes), "r",
                                      metadata_encoding=encoding)
            try:
                entries = archive.infolist()
                if len(entries) > MAX_ZIP_ENTRIES:
                    raise UnsupportedManaged("Managed ZIP entry count exceeds limit")
                declared = 0
                for entry in entries:
                    if (entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
                            or entry.flag_bits & 1):
                        raise ManagedThrown({"__type": "System.IO.InvalidDataException", "args": []})
                    if len(entry.filename) > MAX_GUEST_PATH_CHARS:
                        raise UnsupportedManaged("Managed ZIP entry name exceeds limit")
                    mode_bits = entry.external_attr >> 16
                    if entry.create_system == 3 and stat.S_IFMT(mode_bits) == stat.S_IFLNK:
                        raise UnsupportedManaged("ZIP symbolic link entry is not modeled")
                    declared += entry.file_size
                    if declared > MAX_ZIP_OUTPUT:
                        raise UnsupportedManaged("Managed ZIP output exceeds 32 MiB")
            except BaseException:
                archive.close()
                raise
        except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError,
                EOFError, UnicodeError, zlib.error) as exc:
            raise ManagedThrown({"__type": "System.IO.InvalidDataException", "args": []}) from exc
        state = {"__type": "System.IO.Compression.ZipArchive", "archive": archive,
                 "entries": entries, "source": source, "leave_open": bool(leave_open),
                 "closed": False, "decoded": 0}
        self.zip_archives.append(state)
        self._record_event({"event": "managed_zip_open", "entries": len(entries)})
        return state

    def _zip_archive_call(self, name: str, args: list, state: dict):
        if not any(item is state for item in self.zip_archives):
            raise UnsupportedManaged("Unknown ZipArchive object")
        method = name.rsplit(".", 1)[-1]
        if method in ("Close", "Dispose") and not args:
            if not state["closed"]:
                state["archive"].close()
                state["closed"] = True
                if not state["leave_open"]:
                    source = state["source"]
                    source["closed"] = True
            return None
        if state["closed"]:
            raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
        if method == "get_Entries" and not args:
            return {"__type": "System.Collections.ObjectModel.ReadOnlyCollection`1",
                    "owner": state}
        if method == "GetEntry" and len(args) == 1:
            if args[0] is None:
                raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
            if not isinstance(args[0], str):
                raise UnsupportedManaged("Unsupported ZipArchive.GetEntry argument")
            for entry in state["entries"]:
                if entry.filename == args[0]:
                    return {"__type": "System.IO.Compression.ZipArchiveEntry",
                            "owner": state, "entry": entry}
            return None
        raise UnsupportedManaged(f"Unsupported ZipArchive method: {name}")

    def _zip_collection_call(self, name: str, args: list, state: dict):
        owner = state.get("owner")
        if not isinstance(owner, dict) or not any(item is owner for item in self.zip_archives):
            raise UnsupportedManaged("Unknown ZIP entry collection")
        if owner["closed"]:
            raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
        method = name.rsplit(".", 1)[-1]
        if method == "get_Count" and not args:
            return len(owner["entries"])
        if method == "get_Item" and len(args) == 1:
            index = args[0]
            if type(index) is not int or not 0 <= index < len(owner["entries"]):
                raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException",
                                     "args": []})
            return {"__type": "System.IO.Compression.ZipArchiveEntry",
                    "owner": owner, "entry": owner["entries"][index]}
        if method == "GetEnumerator" and not args:
            return {"__type": "System.Collections.Generic.IEnumerator`1",
                    "owner": owner, "index": -1}
        raise UnsupportedManaged(f"Unsupported ZIP entry collection method: {name}")

    def _zip_enumerator_call(self, name: str, args: list, state: dict):
        owner = state.get("owner")
        if not isinstance(owner, dict) or not any(item is owner for item in self.zip_archives):
            raise UnsupportedManaged("Unknown ZIP entry enumerator")
        method = name.rsplit(".", 1)[-1]
        if method in ("Dispose", "Close") and not args:
            return None
        if owner["closed"]:
            raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
        if method == "MoveNext" and not args:
            if state["index"] < len(owner["entries"]):
                state["index"] += 1
            return state["index"] < len(owner["entries"])
        if method == "get_Current" and not args:
            index = state["index"]
            if not 0 <= index < len(owner["entries"]):
                raise ManagedThrown({"__type": "System.InvalidOperationException", "args": []})
            return {"__type": "System.IO.Compression.ZipArchiveEntry",
                    "owner": owner, "entry": owner["entries"][index]}
        if method == "Reset" and not args:
            state["index"] = -1
            return None
        raise UnsupportedManaged(f"Unsupported ZIP entry enumerator method: {name}")

    def _zip_entry_call(self, name: str, args: list, state: dict):
        owner = state.get("owner")
        if not isinstance(owner, dict) or not any(item is owner for item in self.zip_archives):
            raise UnsupportedManaged("Unknown ZipArchiveEntry object")
        if owner["closed"]:
            raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
        entry = state["entry"]
        method = name.rsplit(".", 1)[-1]
        if not args and method in ("get_FullName", "get_Name", "get_Length",
                                   "get_CompressedLength"):
            return {"get_FullName": entry.filename,
                    "get_Name": ntpath.basename(entry.filename.replace("/", "\\")),
                    "get_Length": entry.file_size,
                    "get_CompressedLength": entry.compress_size}[method]
        if method != "Open" or args:
            raise UnsupportedManaged(f"Unsupported ZipArchiveEntry method: {name}")
        output = bytearray()
        try:
            with owner["archive"].open(entry) as member:
                while True:
                    chunk = member.read(65_536)
                    if not chunk:
                        break
                    if len(output) + len(chunk) > MAX_ARTIFACT or \
                            owner["decoded"] + len(output) + len(chunk) > MAX_ZIP_OUTPUT:
                        raise UnsupportedManaged("Managed ZIP output exceeds 32 MiB")
                    output.extend(chunk)
        except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError,
                EOFError, UnicodeError, zlib.error) as exc:
            raise ManagedThrown({"__type": "System.IO.InvalidDataException", "args": []}) from exc
        owner["decoded"] += len(output)
        payload = bytes(output)
        self.catalog.add(payload, "managed_zip_entry_open")
        self._record_event({"event": "managed_zip_entry_open", "name": entry.filename,
                            "size": len(payload)})
        return self._memory_stream_state({"__type": "System.IO.MemoryStream",
                                          "args": [bytearray(payload), False]})

    def _zip_extract_to_directory(self, args: list) -> None:
        if len(args) not in (2, 3, 4):
            raise UnsupportedManaged("Unsupported ZipFile.ExtractToDirectory overload")
        source, destination = args[:2]
        overwrite = False
        encoding = None
        if len(args) == 3:
            if args[2] in (False, True, 0, 1):
                overwrite = bool(args[2])
            else:
                encoding = args[2]
        elif len(args) == 4:
            encoding, overwrite = args[2:]
            if overwrite not in (False, True, 0, 1):
                raise UnsupportedManaged("Unsupported ZIP overwrite flag")
            overwrite = bool(overwrite)
        if encoding is not None:
            if (not isinstance(encoding, dict) or
                    encoding.get("__type") != "System.Text.Encoding" or
                    encoding.get("encoding") != "utf-8"):
                raise UnsupportedManaged("Unsupported ZIP entry name encoding")
            encoding = "utf-8"
        destination = self._file_path(destination)
        root = self._guest_path(destination)
        root_key = self._file_key(root)
        if root_key in self.files:
            raise ManagedThrown({"__type": "System.IO.IOException", "args": [destination]})
        if source is None:
            raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
        if isinstance(source, str):
            source = self._file_path(source)
            source_key = self._file_key(source)
            self._require_parent(source_key)
            self._check_stream_access(source_key, 1)
            if source_key not in self.files:
                raise ManagedThrown({"__type": "System.IO.FileNotFoundException", "args": [source]})
            archive_bytes = self.files[source_key]
        elif isinstance(source, dict) and source.get("__type") == "System.IO.MemoryStream":
            source = self._memory_stream_state(source)
            if source["closed"]:
                raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
            archive_bytes = bytes(source["buffer"][source["position"]:source["length"]])
            source["position"] = source["length"]
        elif isinstance(source, dict) and source.get("__type") == "System.IO.FileStream":
            if not any(item is source for item in self.file_streams):
                raise UnsupportedManaged("Unknown ZIP FileStream source")
            if source["closed"]:
                raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
            if not source["access"] & 1:
                raise ManagedThrown({"__type": "System.NotSupportedException", "args": []})
            archive_bytes = self.files[source["key"]][source["position"]:]
            source["position"] = len(self.files[source["key"]])
        else:
            raise UnsupportedManaged("Unsupported ZIP archive source")
        parser_bytes = self._zip_parser_bytes(archive_bytes)
        try:
            with zipfile.ZipFile(io.BytesIO(parser_bytes), "r",
                                 metadata_encoding=encoding) as archive:
                entries = archive.infolist()
                if len(entries) > MAX_ZIP_ENTRIES:
                    raise UnsupportedManaged("Managed ZIP entry count exceeds limit")
                planned = []
                declared = 0
                root_prefix = root_key.rstrip("\\") + "\\"
                for entry in entries:
                    raw = entry.filename.replace("\\", "/")
                    if (not raw or raw.startswith("/") or ntpath.splitdrive(raw)[0]
                            or any(ord(ch) < 32 or ch in '<>"|?*:' for ch in raw)):
                        raise ManagedThrown({"__type": "System.IO.IOException", "args": []})
                    mode = entry.external_attr >> 16
                    if entry.create_system == 3 and stat.S_IFMT(mode) == stat.S_IFLNK:
                        raise UnsupportedManaged("ZIP symbolic link entry is not modeled")
                    target = ntpath.normpath(ntpath.join(root, raw.replace("/", "\\")))
                    target_key = self._file_key(target)
                    if (len(target) > MAX_GUEST_PATH_CHARS or
                            not target_key.startswith(root_prefix)):
                        raise ManagedThrown({"__type": "System.IO.IOException", "args": []})
                    if entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) \
                            or entry.flag_bits & 1:
                        raise ManagedThrown({"__type": "System.IO.InvalidDataException", "args": []})
                    declared += entry.file_size
                    if declared > MAX_ZIP_OUTPUT:
                        raise UnsupportedManaged("Managed ZIP output exceeds 32 MiB")
                    planned.append((entry, target, entry.is_dir() or raw.endswith("/")))
                self._framework("System.IO.Directory.CreateDirectory", [root], None, False)
                extracted = 0
                total = 0
                for entry, target, is_directory in planned:
                    if is_directory:
                        self._framework("System.IO.Directory.CreateDirectory", [target],
                                        None, False)
                        continue
                    parent = ntpath.dirname(target)
                    self._framework("System.IO.Directory.CreateDirectory", [parent], None, False)
                    if self._file_key(target) in self.files and not overwrite:
                        raise ManagedThrown({"__type": "System.IO.IOException", "args": [target]})
                    output = bytearray()
                    with archive.open(entry) as member:
                        while True:
                            chunk = member.read(65_536)
                            if not chunk:
                                break
                            if len(output) + len(chunk) > MAX_ARTIFACT or total + len(output) + len(chunk) > MAX_ZIP_OUTPUT:
                                raise UnsupportedManaged("Managed ZIP output exceeds 32 MiB")
                            output.extend(chunk)
                    total += len(output)
                    self._store_file(target, bytes(output))
                    extracted += 1
                self._record_event({"event": "managed_zip_extract", "entries": len(entries),
                                    "files": extracted, "size": total, "overwrite": overwrite})
        except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError,
                EOFError, UnicodeError, zlib.error) as exc:
            raise ManagedThrown({"__type": "System.IO.InvalidDataException", "args": []}) from exc
        return None

    def _transfer_file(self, name: str, args: list) -> None:
        operation = "copy" if name.endswith(".Copy") else "move"
        if len(args) not in (2, 3) or (len(args) == 3 and args[2] not in (False, True, 0, 1)):
            raise UnsupportedManaged(f"Unsupported File.{operation} overload")
        source, target = self._file_path(args[0]), self._file_path(args[1])
        source_key, target_key = self._file_key(source), self._file_key(target)
        self._require_parent(source_key)
        self._require_parent(target_key)
        self._check_stream_access(source_key, 1)
        if operation == "move":
            self._check_stream_delete(source_key)
            self._check_stream_delete(target_key)
        else:
            self._check_stream_access(target_key, 2)
        if source_key in self.directories or target_key in self.directories:
            raise ManagedThrown({"__type": "System.UnauthorizedAccessException", "args": []})
        payload = self.files.get(source_key)
        if payload is None:
            raise ManagedThrown({"__type": "System.IO.FileNotFoundException", "args": [source]})
        overwrite = bool(args[2]) if len(args) == 3 else False
        if source_key == target_key:
            if operation == "copy":
                raise ManagedThrown({"__type": "System.IO.IOException", "args": [target]})
            self._record_event({"event": "file_move", "source": source, "target": target,
                                "overwrite": overwrite, "same_file": True, "size": len(payload)})
            return None
        previous = self.files.get(target_key)
        if previous is not None and not overwrite:
            raise ManagedThrown({"__type": "System.IO.IOException", "args": [target]})
        if previous is not None and self.file_attributes.get(target_key, ATTR_ARCHIVE) & ATTR_READONLY:
            raise ManagedThrown({"__type": "System.UnauthorizedAccessException", "args": [target]})
        if operation == "copy":
            if previous is None and len(self.files) >= MAX_GUEST_FILES:
                raise UnsupportedManaged("Managed guest file count exceeded")
            total = self.file_bytes - len(previous or b"") + len(payload)
            if total > MAX_GUEST_FILE_BYTES:
                raise UnsupportedManaged("Managed guest file storage exceeds 64 MiB")
        else:
            total = self.file_bytes - len(previous or b"")
        if len(self.events) >= MAX_MANAGED_EVENTS:
            raise UnsupportedManaged("Managed event limit exceeded")
        if operation == "move":
            self.files.pop(source_key)
            source_attributes = self.file_attributes.pop(source_key, ATTR_ARCHIVE)
            self.file_display_paths.pop(source_key, None)
        else:
            source_attributes = self.file_attributes.get(source_key, ATTR_ARCHIVE)
        self.files[target_key] = payload
        self.file_display_paths.setdefault(target_key, self._guest_path(target))
        self.file_attributes[target_key] = source_attributes
        self.file_bytes = total
        self.catalog.add(payload, f"managed_file_{operation}", guest_path=target)
        self._record_event({"event": f"file_{operation}", "source": source, "target": target,
                            "overwrite": overwrite, "size": len(payload)})
        return None

    def _file_attribute_call(self, name: str, args: list):
        if len(args) != (2 if name.endswith("SetAttributes") else 1):
            raise UnsupportedManaged(f"Unsupported {name} overload")
        path = self._file_path(args[0])
        key = self._file_key(path)
        self._require_parent(key)
        directory = key in self.directories
        if not directory and key not in self.files:
            raise ManagedThrown({"__type": "System.IO.FileNotFoundException", "args": [path]})
        attributes = (self.directory_attributes.get(key, ATTR_DIRECTORY) if directory else
                      self.file_attributes.get(key, ATTR_ARCHIVE))
        if name.endswith("GetAttributes"):
            return attributes
        requested = args[1]
        if not isinstance(requested, int) or requested < 0 or requested & ~SUPPORTED_SET_ATTRIBUTES:
            raise UnsupportedManaged("Unsupported managed file attributes")
        if requested & ATTR_NORMAL and requested != ATTR_NORMAL:
            raise UnsupportedManaged("Normal cannot be combined with other file attributes")
        if len(self.events) >= MAX_MANAGED_EVENTS:
            raise UnsupportedManaged("Managed event limit exceeded")
        normalized = requested or ATTR_NORMAL
        if directory:
            normalized = ATTR_DIRECTORY | (normalized & ~ATTR_NORMAL)
            self.directory_attributes[key] = normalized
        else:
            self.file_attributes[key] = normalized
        self._record_event({"event": "file_attributes_set", "path": path,
                            "previous": attributes, "attributes": normalized,
                            "directory": directory})
        return None

    def _open_file_stream(self, path_value, mode: int, access: int, share: int) -> dict:
        if (type(mode) is not int or mode not in range(1, 7)
                or type(access) is not int or access not in (1, 2, 3)
                or type(share) is not int or share & ~7 or share < 0):
            raise UnsupportedManaged("Unsupported FileStream mode, access, or sharing")
        if ((mode in (1, 2, 5, 6) and not access & 2) or
                (mode == 6 and access != 2)):
            raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
        path = self._file_path(path_value)
        key = self._file_key(path)
        self._require_parent(key)
        if key in self.directories:
            raise ManagedThrown({"__type": "System.UnauthorizedAccessException", "args": [path]})
        exists = key in self.files
        if mode == 1 and exists:
            raise ManagedThrown({"__type": "System.IO.IOException", "args": [path]})
        if mode in (3, 5) and not exists:
            raise ManagedThrown({"__type": "System.IO.FileNotFoundException", "args": [path]})
        if exists and access & 2 and self.file_attributes.get(key, ATTR_ARCHIVE) & ATTR_READONLY:
            raise ManagedThrown({"__type": "System.UnauthorizedAccessException", "args": [path]})
        if len(self.file_streams) >= MAX_FILE_STREAMS:
            raise UnsupportedManaged("Managed FileStream count exceeded")
        for other in self.file_streams:
            if (not other["closed"] and other["key"] == key and
                    ((access & ~other["share"]) or (other["access"] & ~share))):
                raise ManagedThrown({"__type": "System.IO.IOException", "args": [path]})
        if mode in (1, 2, 5) or (not exists and mode in (4, 6)):
            self._store_file(path, b"")
        stream = {"__type": "System.IO.FileStream", "path": path, "key": key,
                  "access": access, "share": share, "position": len(self.files[key]) if mode == 6 else 0,
                  "append_start": len(self.files[key]) if mode == 6 else 0, "closed": False}
        self.file_streams.append(stream)
        self._record_event({"event": "file_stream_open", "path": path, "mode": mode,
                            "access": access, "share": share})
        return stream

    def _file_stream_call(self, name: str, args: list, stream: dict):
        if not any(item is stream for item in self.file_streams):
            raise UnsupportedManaged("Unknown managed FileStream object")
        method = name.rsplit(".", 1)[-1]
        if method in {"Close", "Dispose"} and not args:
            if not stream["closed"]:
                stream["closed"] = True
                self._record_event({"event": "file_stream_close", "path": stream["path"]})
            return None
        if stream["closed"]:
            raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
        if method == "get_CanRead" and not args:
            return bool(stream["access"] & 1)
        if method == "get_CanWrite" and not args:
            return bool(stream["access"] & 2)
        if method == "get_CanSeek" and not args:
            return True
        if method == "get_Length" and not args:
            return len(self.files[stream["key"]])
        if method == "get_Position" and not args:
            return stream["position"]
        if method == "set_Position" and len(args) == 1:
            position = args[0]
            if type(position) is not int or not 0 <= position <= MAX_ARTIFACT:
                raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
            if position < stream["append_start"]:
                raise ManagedThrown({"__type": "System.IO.IOException", "args": []})
            stream["position"] = position
            return None
        if method == "Seek" and len(args) == 2:
            offset, origin = args
            if type(offset) is not int or type(origin) is not int or origin not in (0, 1, 2):
                raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
            base = (0 if origin == 0 else stream["position"] if origin == 1
                    else len(self.files[stream["key"]]))
            position = base + offset
            if not stream["append_start"] <= position <= MAX_ARTIFACT:
                raise ManagedThrown({"__type": "System.IO.IOException", "args": []})
            stream["position"] = position
            self._record_event({"event": "file_stream_seek", "path": stream["path"],
                                "position": position})
            return position
        if method == "Flush" and not args:
            return None
        if method in {"Read", "ReadByte"}:
            if not stream["access"] & 1:
                raise ManagedThrown({"__type": "System.NotSupportedException", "args": []})
            data = self.files[stream["key"]]
            if method == "ReadByte" and not args:
                if stream["position"] >= len(data):
                    return -1
                value = data[stream["position"]]
                stream["position"] += 1
                return value
            if (method != "Read" or len(args) != 3 or not isinstance(args[0], bytearray)
                    or any(type(value) is not int for value in args[1:])):
                raise UnsupportedManaged("Unsupported FileStream.Read overload")
            buffer, offset, count = args
            if offset < 0 or count < 0 or offset + count > len(buffer):
                raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
            chunk = data[stream["position"]:stream["position"] + count]
            buffer[offset:offset + len(chunk)] = chunk
            stream["position"] += len(chunk)
            self._record_event({"event": "file_stream_read", "path": stream["path"],
                                "size": len(chunk)})
            return len(chunk)
        if method in {"Write", "WriteByte", "SetLength"}:
            if not stream["access"] & 2:
                raise ManagedThrown({"__type": "System.NotSupportedException", "args": []})
            prior = self.files[stream["key"]]
            if method == "SetLength" and len(args) == 1:
                length = args[0]
                if type(length) is not int or not 0 <= length <= MAX_ARTIFACT:
                    raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
                if length < stream["append_start"]:
                    raise ManagedThrown({"__type": "System.IO.IOException", "args": []})
                payload = prior[:length] + b"\0" * max(0, length - len(prior))
                self._store_file(stream["path"], payload, stream=stream)
                stream["position"] = min(stream["position"], length)
                return None
            if method == "WriteByte" and len(args) == 1 and type(args[0]) is int \
                    and 0 <= args[0] <= 255:
                chunk = bytes([args[0]])
            elif (method == "Write" and len(args) == 3
                  and isinstance(args[0], (bytes, bytearray))
                  and all(type(value) is int for value in args[1:])):
                buffer, offset, count = args
                if offset < 0 or count < 0 or offset + count > len(buffer):
                    raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
                chunk = bytes(buffer[offset:offset + count])
            else:
                raise UnsupportedManaged(f"Unsupported FileStream.{method} overload")
            if not chunk:
                return None
            position = stream["position"]
            if position < stream["append_start"]:
                raise ManagedThrown({"__type": "System.IO.IOException", "args": []})
            end = position + len(chunk)
            if end > MAX_ARTIFACT:
                raise UnsupportedManaged("Managed FileStream exceeds 32 MiB")
            payload = prior[:position] + b"\0" * max(0, position - len(prior)) + chunk + prior[end:]
            self._store_file(stream["path"], payload, stream=stream)
            stream["position"] = end
            return None
        raise UnsupportedManaged(f"Unsupported FileStream method: {name}")

    def _memory_stream_state(self, stream: dict) -> dict:
        if not isinstance(stream, dict) or stream.get("__type") != "System.IO.MemoryStream":
            raise UnsupportedManaged("Unsupported MemoryStream object")
        if "length" in stream:
            if not any(item is stream for item in self.memory_streams):
                raise UnsupportedManaged("Unknown MemoryStream object")
            return stream
        if len(self.memory_streams) >= MAX_MEMORY_STREAMS:
            raise UnsupportedManaged("Managed MemoryStream count exceeded")
        args = stream.get("args", [])
        if not isinstance(args, list) or len(args) > 2:
            raise UnsupportedManaged("Unsupported MemoryStream constructor overload")
        seed = stream.get("buffer")
        expandable = True
        writable = True
        if seed is None and args:
            seed = args[0]
            if type(seed) is int:
                if len(args) != 1 or not 0 <= seed <= MAX_ARTIFACT:
                    raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
                seed = None
            elif isinstance(seed, (bytes, bytearray)):
                expandable = False
                if len(args) == 2:
                    if args[1] not in (False, True, 0, 1):
                        raise UnsupportedManaged("Unsupported MemoryStream writable flag")
                    writable = bool(args[1])
            elif seed is None:
                raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
            else:
                raise UnsupportedManaged("Unsupported MemoryStream constructor overload")
        if seed is None:
            buffer = bytearray()
        elif isinstance(seed, bytearray):
            buffer = seed
        elif isinstance(seed, bytes):
            buffer = bytearray(seed)
        else:
            raise UnsupportedManaged("Unsupported MemoryStream buffer")
        if len(buffer) > MAX_ARTIFACT:
            raise UnsupportedManaged("Managed MemoryStream exceeds 32 MiB")
        stream.update({"buffer": buffer, "length": len(buffer), "position": 0,
                       "expandable": expandable, "capacity": len(buffer) if not expandable else None,
                       "writable": writable, "closed": False})
        self.memory_streams.append(stream)
        return stream

    def _memory_stream_call(self, name: str, args: list, stream: dict):
        stream = self._memory_stream_state(stream)
        method = name.rsplit(".", 1)[-1]
        if method == "ToArray" and not args:
            return bytearray(stream["buffer"][:stream["length"]])
        if method in {"Close", "Dispose"} and not args:
            stream["closed"] = True
            return None
        if stream["closed"]:
            raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
        if method == "get_CanRead" and not args:
            return True
        if method == "get_CanWrite" and not args:
            return stream["writable"]
        if method == "get_CanSeek" and not args:
            return True
        if method == "get_Length" and not args:
            return stream["length"]
        if method == "get_Position" and not args:
            return stream["position"]
        if method == "set_Position" and len(args) == 1:
            position = args[0]
            if type(position) is not int or not 0 <= position <= MAX_ARTIFACT:
                raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
            stream["position"] = position
            return None
        if method == "Seek" and len(args) == 2:
            offset, origin = args
            if type(offset) is not int or type(origin) is not int or origin not in (0, 1, 2):
                raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
            base = (0 if origin == 0 else stream["position"] if origin == 1 else stream["length"])
            position = base + offset
            if not 0 <= position <= MAX_ARTIFACT:
                raise ManagedThrown({"__type": "System.IO.IOException", "args": []})
            stream["position"] = position
            return position
        if method == "Flush" and not args:
            return None
        if method in {"Read", "ReadByte"}:
            if method == "ReadByte" and not args:
                if stream["position"] >= stream["length"]:
                    return -1
                value = stream["buffer"][stream["position"]]
                stream["position"] += 1
                return value
            if (method != "Read" or len(args) != 3 or not isinstance(args[0], bytearray)
                    or any(type(value) is not int for value in args[1:])):
                raise UnsupportedManaged("Unsupported MemoryStream.Read overload")
            buffer, offset, count = args
            if offset < 0 or count < 0 or offset + count > len(buffer):
                raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
            start = stream["position"]
            end = min(start + count, stream["length"])
            chunk = stream["buffer"][start:end]
            buffer[offset:offset + len(chunk)] = chunk
            stream["position"] = end if start <= stream["length"] else start
            return len(chunk)
        if method in {"Write", "WriteByte", "SetLength"}:
            if not stream["writable"]:
                raise ManagedThrown({"__type": "System.NotSupportedException", "args": []})
            if method == "SetLength" and len(args) == 1:
                length = args[0]
                if type(length) is not int or not 0 <= length <= MAX_ARTIFACT:
                    raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
                if not stream["expandable"] and length > stream["capacity"]:
                    raise ManagedThrown({"__type": "System.NotSupportedException", "args": []})
                buffer = stream["buffer"]
                if stream["expandable"]:
                    if length > len(buffer):
                        buffer.extend(b"\0" * (length - len(buffer)))
                    else:
                        del buffer[length:]
                elif length > stream["length"]:
                    buffer[stream["length"]:length] = b"\0" * (length - stream["length"])
                stream["length"] = length
                stream["position"] = min(stream["position"], length)
                return None
            if method == "WriteByte" and len(args) == 1 and type(args[0]) is int \
                    and 0 <= args[0] <= 255:
                chunk = bytes([args[0]])
            elif (method == "Write" and len(args) == 3
                  and isinstance(args[0], (bytes, bytearray))
                  and all(type(value) is int for value in args[1:])):
                buffer, offset, count = args
                if offset < 0 or count < 0 or offset + count > len(buffer):
                    raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
                chunk = bytes(buffer[offset:offset + count])
            else:
                raise UnsupportedManaged(f"Unsupported MemoryStream.{method} overload")
            if not chunk:
                return None
            position = stream["position"]
            end = position + len(chunk)
            if end > MAX_ARTIFACT:
                raise UnsupportedManaged("Managed MemoryStream exceeds 32 MiB")
            if not stream["expandable"] and end > stream["capacity"]:
                raise ManagedThrown({"__type": "System.NotSupportedException", "args": []})
            buffer = stream["buffer"]
            if end > len(buffer):
                buffer.extend(b"\0" * (end - len(buffer)))
            if position > stream["length"]:
                buffer[stream["length"]:position] = b"\0" * (position - stream["length"])
            buffer[position:end] = chunk
            stream["length"] = max(stream["length"], end)
            stream["position"] = end
            return None
        raise UnsupportedManaged(f"Unsupported MemoryStream method: {name}")

    def _compressed_stream_state(self, name: str, args: list) -> dict:
        if len(args) not in (2, 3):
            raise UnsupportedManaged("Unsupported compressed stream constructor overload")
        underlying, mode = args[:2]
        leave_open = args[2] if len(args) == 3 else False
        if underlying is None:
            raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
        if not isinstance(underlying, dict) or underlying.get("__type") not in {
                "System.IO.MemoryStream", "System.IO.FileStream"}:
            raise UnsupportedManaged("Unsupported compressed stream source")
        if type(mode) is not int or mode != 0:
            raise UnsupportedManaged("Only compressed-stream decompression is modeled")
        if leave_open not in (False, True, 0, 1):
            raise UnsupportedManaged("Unsupported compressed stream leaveOpen value")
        if underlying["__type"] == "System.IO.MemoryStream":
            underlying = self._memory_stream_state(underlying)
        elif not any(item is underlying for item in self.file_streams):
            raise UnsupportedManaged("Unknown compressed FileStream source")
        if underlying["closed"]:
            raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
        if underlying["__type"] == "System.IO.FileStream" and not underlying["access"] & 1:
            raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
        if len(self.compressed_streams) >= MAX_COMPRESSED_STREAMS:
            raise UnsupportedManaged("Managed compressed stream count exceeded")
        kind = name.removesuffix("..ctor")
        formats = {"System.IO.Compression.GZipStream": ("gzip", 16 + zlib.MAX_WBITS),
                   "System.IO.Compression.DeflateStream": ("deflate", -zlib.MAX_WBITS),
                   "System.IO.Compression.ZLibStream": ("zlib", zlib.MAX_WBITS)}
        if kind not in formats:
            raise UnsupportedManaged("Unsupported compression format")
        fmt, window = formats[kind]
        stream = {"__type": kind, "format": fmt, "underlying": underlying,
                  "decoder": zlib.decompressobj(window), "leave_open": bool(leave_open),
                  "closed": False, "finished": False, "read_buffer": bytearray(),
                  "decoded": bytearray(), "input_size": 0}
        self.compressed_streams.append(stream)
        self._record_event({"event": "managed_compressed_stream_open", "format": fmt,
                            "underlying": underlying["__type"]})
        return stream

    def _compressed_stream_finish(self, stream: dict) -> None:
        if stream["finished"]:
            return
        if not stream["decoder"].eof:
            raise ManagedThrown({"__type": "System.IO.InvalidDataException", "args": []})
        stream["finished"] = True
        payload = bytes(stream["decoded"])
        self.catalog.add(payload, f"managed_{stream['format']}_decompress")
        self._record_event({"event": "managed_decompress", "format": stream["format"],
                            "size": len(payload)})

    def _compressed_stream_fill_read(self, stream: dict, desired: int) -> None:
        while len(stream["read_buffer"]) < desired and not stream["finished"]:
            decoder = stream["decoder"]
            if decoder.eof:
                self._compressed_stream_finish(stream)
                break
            if decoder.unconsumed_tail:
                chunk = decoder.unconsumed_tail
            else:
                request = min(65_536, max(64, desired - len(stream["read_buffer"])))
                chunk = self._crypto_stream_underlying_read(stream, request)
                stream["input_size"] += len(chunk)
                if stream["input_size"] > MAX_ARTIFACT:
                    raise UnsupportedManaged("Managed compressed input exceeds 32 MiB")
            if not chunk:
                self._compressed_stream_finish(stream)
                break
            limit = min(65_536, MAX_ARTIFACT - len(stream["decoded"]) + 1)
            try:
                output = decoder.decompress(chunk, limit)
            except zlib.error as exc:
                raise ManagedThrown({"__type": "System.IO.InvalidDataException", "args": []}) from exc
            if len(stream["decoded"]) + len(output) > MAX_ARTIFACT:
                raise UnsupportedManaged("Decompressed output exceeds 32 MiB")
            stream["decoded"].extend(output)
            stream["read_buffer"].extend(output)

    def _compressed_stream_call(self, name: str, args: list, stream: dict):
        if not any(item is stream for item in self.compressed_streams):
            raise UnsupportedManaged("Unknown managed compressed stream object")
        operation = name.rsplit(".", 1)[-1]
        if operation in {"Close", "Dispose"} and not args:
            if not stream["closed"]:
                stream["closed"] = True
                if not stream["leave_open"]:
                    underlying = stream["underlying"]
                    if underlying["__type"] == "System.IO.MemoryStream":
                        self._memory_stream_call("System.IO.Stream.Close", [], underlying)
                    else:
                        self._file_stream_call("System.IO.Stream.Close", [], underlying)
            return None
        if stream["closed"]:
            raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
        if operation == "get_CanRead" and not args:
            return True
        if operation in {"get_CanWrite", "get_CanSeek"} and not args:
            return False
        if operation == "ReadByte" and not args:
            buffer = bytearray(1)
            return buffer[0] if self._compressed_stream_call("System.IO.Stream.Read",
                                                              [buffer, 0, 1], stream) else -1
        if operation == "Read" and len(args) == 3 and isinstance(args[0], bytearray):
            buffer, offset, count = args
            if (type(offset) is not int or type(count) is not int or offset < 0
                    or count < 0 or offset + count > len(buffer)):
                raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
            if not count:
                return 0
            self._compressed_stream_fill_read(stream, count)
            available = min(count, len(stream["read_buffer"]))
            buffer[offset:offset + available] = stream["read_buffer"][:available]
            del stream["read_buffer"][:available]
            return available
        raise UnsupportedManaged(f"Unsupported compressed stream method: {name}")

    def _stream_copy_to(self, args: list, source: dict):
        if (len(args) not in (1, 2) or not isinstance(args[0], dict)
                or args[0].get("__type") not in {"System.IO.FileStream", "System.IO.MemoryStream"}):
            raise UnsupportedManaged("Unsupported CopyTo target")
        if len(args) == 2 and (type(args[1]) is not int or args[1] <= 0):
            raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
        target = args[0]
        if target is source:
            raise UnsupportedManaged("CopyTo on the same stream is unsupported")
        if not isinstance(source, dict):
            raise UnsupportedManaged("Unsupported CopyTo source")
        kind = source.get("__type")
        if kind in {"System.IO.Compression.GZipStream", "System.IO.Compression.DeflateStream",
                    "System.IO.Compression.ZLibStream"}:
            if not any(item is source for item in self.compressed_streams):
                raise UnsupportedManaged("Unknown compressed CopyTo source")
            buffer = bytearray(min(args[1] if len(args) == 2 else 81_920, 65_536))
            copied = 0
            while True:
                count = self._compressed_stream_call("System.IO.Stream.Read",
                                                      [buffer, 0, len(buffer)], source)
                if count == 0:
                    break
                chunk = bytes(buffer[:count])
                if target["__type"] == "System.IO.MemoryStream":
                    self._memory_stream_call("System.IO.Stream.Write", [chunk, 0, count], target)
                else:
                    self._file_stream_call("System.IO.Stream.Write", [chunk, 0, count], target)
                copied += count
            self._record_event({"event": "managed_stream_copy", "source": kind,
                                "target": target["__type"], "size": copied})
            return None
        elif kind == "System.Security.Cryptography.CryptoStream":
            if not any(item is source for item in self.crypto_streams):
                raise UnsupportedManaged("Unknown CryptoStream CopyTo source")
            if source["closed"]:
                raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
            if source["mode"] != 0:
                raise ManagedThrown({"__type": "System.NotSupportedException", "args": []})
            buffer = bytearray(min(args[1] if len(args) == 2 else 81_920, 65_536))
            copied = 0
            while True:
                count = self._crypto_stream_call("System.IO.Stream.Read",
                                                 [buffer, 0, len(buffer)], source)
                if count == 0:
                    break
                chunk = bytes(buffer[:count])
                if target["__type"] == "System.IO.MemoryStream":
                    self._memory_stream_call("System.IO.Stream.Write", [chunk, 0, count], target)
                else:
                    self._file_stream_call("System.IO.Stream.Write", [chunk, 0, count], target)
                copied += count
            self._record_event({"event": "managed_stream_copy", "source": kind,
                                "target": target["__type"], "size": copied})
            return None
        elif kind == "System.IO.MemoryStream":
            memory = self._memory_stream_state(source)
            if memory["closed"]:
                raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
            payload = bytes(memory["buffer"][memory["position"]:memory["length"]])
        elif kind == "System.IO.FileStream":
            if not any(item is source for item in self.file_streams):
                raise UnsupportedManaged("Unknown managed FileStream object")
            if source["closed"]:
                raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
            if not source["access"] & 1:
                raise ManagedThrown({"__type": "System.NotSupportedException", "args": []})
            payload = self.files[source["key"]][source["position"]:]
        else:
            raise UnsupportedManaged("Unsupported CopyTo source")
        if target["__type"] == "System.IO.MemoryStream":
            self._memory_stream_call("System.IO.Stream.Write", [payload, 0, len(payload)], target)
        else:
            self._file_stream_call("System.IO.Stream.Write", [payload, 0, len(payload)], target)
        source["position"] += len(payload)
        self._record_event({"event": "managed_stream_copy", "source": kind,
                            "target": target["__type"], "size": len(payload)})
        return None

    @staticmethod
    def _wildcard_match(name: str, pattern: str) -> bool:
        if pattern == "*.*":
            pattern = "*"
        name, pattern = name.casefold(), pattern.casefold()
        position = wildcard = restart = 0
        star = -1
        while position < len(name):
            if wildcard < len(pattern) and (pattern[wildcard] == "?" or
                                            pattern[wildcard] == name[position]):
                position += 1
                wildcard += 1
            elif wildcard < len(pattern) and pattern[wildcard] == "*":
                star = wildcard
                wildcard += 1
                restart = position
            elif star >= 0:
                wildcard = star + 1
                restart += 1
                position = restart
            else:
                return False
        return all(char == "*" for char in pattern[wildcard:])

    def _enumerate_directory(self, name: str, args: list) -> list[str]:
        if len(args) not in (1, 2, 3):
            raise UnsupportedManaged(f"Unsupported {name} overload")
        path = self._file_path(args[0])
        key = self._file_key(path)
        if key in self.files:
            raise ManagedThrown({"__type": "System.IO.IOException", "args": [path]})
        if key not in self.directories:
            raise ManagedThrown({"__type": "System.IO.DirectoryNotFoundException", "args": [path]})
        pattern = args[1] if len(args) >= 2 else "*"
        if pattern is None:
            raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
        if not isinstance(pattern, str):
            raise UnsupportedManaged("Unsupported managed search pattern type")
        if "\x00" in pattern:
            raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
        if (len(pattern) > 256 or any(char in pattern for char in "\\/:[]") or
                ".." in pattern):
            raise UnsupportedManaged("Managed search pattern path or syntax unsupported")
        option = args[2] if len(args) == 3 else 0
        if option not in (0, 1) or not isinstance(option, int):
            raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
        recursive = option == 1
        prefix = key.rstrip("\\") + "\\"
        kind = name.rsplit(".", 1)[-1]
        entries: list[tuple[str, str]] = []
        if kind in {"GetFiles", "GetFileSystemEntries"}:
            entries.extend((item, self.file_display_paths.get(item, item)) for item in self.files)
        if kind in {"GetDirectories", "GetFileSystemEntries"}:
            entries.extend((item, self.directory_display_paths.get(item, item))
                           for item in self.directories)
        base_display = self.directory_display_paths.get(key, self._guest_path(path))
        matches = []
        total_chars = 0
        for item, display in entries:
            if not item.startswith(prefix) or (not recursive and ntpath.dirname(item) != key):
                continue
            if not self._wildcard_match(ntpath.basename(display), pattern):
                continue
            relative = ntpath.relpath(display, base_display)
            result = ntpath.normpath(ntpath.join(path, relative))
            total_chars += len(result)
            if len(matches) >= MAX_DIRECTORY_ENUM_RESULTS or total_chars > MAX_DIRECTORY_ENUM_CHARS:
                raise UnsupportedManaged("Managed directory enumeration exceeds limit")
            matches.append(result)
        matches.sort(key=str.casefold)
        self._record_event({"event": "directory_enumerate", "path": path,
                            "pattern": pattern, "recursive": recursive,
                            "kind": kind, "count": len(matches)})
        return matches

    def _file_key(self, path: str) -> str:
        return ntpath.normcase(self._guest_path(path))

    def _guest_path(self, path: str) -> str:
        return ntpath.normpath(ntpath.join(self.current_dir, path))

    @staticmethod
    def _combine_path_parts(parts: list[str]) -> str:
        combined = ""
        for part in parts:
            if part is None:
                raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
            if not isinstance(part, str):
                raise UnsupportedManaged("Unsupported Path.Combine argument type")
            if "\x00" in part:
                raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
            if part.startswith(("\\", "/")) or ntpath.splitdrive(part)[0]:
                combined = part
            elif part:
                combined = ntpath.join(combined, part) if combined else part
            if len(combined) > MAX_GUEST_PATH_CHARS:
                raise UnsupportedManaged("Managed combined path exceeds limit")
        return combined

    @staticmethod
    def _path_text(value) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise UnsupportedManaged("Unsupported managed path argument type")
        if "\0" in value:
            raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
        if len(value) > MAX_GUEST_PATH_CHARS:
            raise UnsupportedManaged("Managed path argument exceeds limit")
        return value

    @staticmethod
    def _path_filename(path: str) -> str:
        return ntpath.basename(path)

    @classmethod
    def _path_extension(cls, path: str) -> str:
        filename = cls._path_filename(path)
        dot = filename.rfind(".")
        return filename[dot:] if 0 <= dot < len(filename) - 1 else ""

    @staticmethod
    def _full_guest_path(path: str, base: str) -> str:
        if path.startswith(("\\\\", "//")) or base.startswith(("\\\\", "//")):
            raise UnsupportedManaged("UNC and device full paths are not modeled")
        if any(ord(char) < 32 or char in '<>"|?*' for char in path + base):
            raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
        if any(":" in value[2 if len(value) >= 2 and value[1] == ":" else 0:]
               for value in (path, base)):
            raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
        drive, _ = ntpath.splitdrive(base)
        if (len(drive) != 2 or not "A" <= drive[0].upper() <= "Z"
                or not ntpath.isabs(base)):
            raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
        path_drive, path_tail = ntpath.splitdrive(path)
        if path_drive and (len(path_drive) != 2 or not "A" <= path_drive[0].upper() <= "Z"):
            raise UnsupportedManaged("Unsupported managed path root")
        if path_drive and not path_tail.startswith(("\\", "/")):
            if path_drive.casefold() != drive.casefold():
                raise UnsupportedManaged("Other-drive relative current directory is not modeled")
            path = path_tail
        result = ntpath.normpath(ntpath.join(base, path))
        if len(result) > MAX_GUEST_PATH_CHARS:
            raise UnsupportedManaged("Managed full path exceeds limit")
        return result

    def _directory_chain(self, path: str) -> list[str]:
        current = self._file_key(path)
        chain = []
        while current:
            chain.append(current)
            parent = ntpath.dirname(current)
            if parent == current:
                break
            current = parent
        return chain[::-1]

    def _seed_directory(self, path: str) -> None:
        current = self._guest_path(path)
        while current:
            key = ntpath.normcase(current)
            self.directories.add(key)
            self.directory_display_paths.setdefault(key, current)
            parent = ntpath.dirname(current)
            if parent == current:
                break
            current = parent
        if len(self.directories) > MAX_GUEST_DIRECTORIES:
            raise UnsupportedManaged("Managed persona directory count exceeds limit")

    def _require_parent(self, key: str) -> None:
        if ntpath.dirname(key) not in self.directories:
            raise ManagedThrown({"__type": "System.IO.DirectoryNotFoundException", "args": [key]})

    @staticmethod
    def _file_path(value) -> str:
        if value is None:
            raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
        if not isinstance(value, str):
            raise UnsupportedManaged("Unsupported managed file path type")
        if not value:
            raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
        if "\x00" in value:
            raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
        if len(value) > MAX_GUEST_PATH_CHARS:
            raise UnsupportedManaged("Managed guest path exceeds limit")
        return value

    @staticmethod
    def _decode_file_text(payload: bytes) -> str:
        for marker, encoding in ((b"\xff\xfe\x00\x00", "utf-32-le"),
                                 (b"\x00\x00\xfe\xff", "utf-32-be"),
                                 (b"\xef\xbb\xbf", "utf-8"),
                                 (b"\xff\xfe", "utf-16-le"),
                                 (b"\xfe\xff", "utf-16-be")):
            if payload.startswith(marker):
                return payload[len(marker):].decode(encoding, errors="replace")
        return payload.decode("utf-8", errors="replace")

    @staticmethod
    def _pbkdf2_hash(value) -> str:
        if isinstance(value, dict) and value.get("__type") == "System.Security.Cryptography.HashAlgorithmName":
            value = value.get("name")
        if value not in ("SHA1", "SHA256", "SHA384", "SHA512"):
            raise ManagedThrown({"__type": "System.Security.Cryptography.CryptographicException",
                                 "args": []})
        return value.lower()

    def _pbkdf2_derive(self, password: bytes, salt: bytes, iterations: int,
                       algorithm: str, length: int) -> bytearray:
        if type(length) is not int or length < 0:
            raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
        if length > MAX_PBKDF2_DERIVED_BYTES:
            raise UnsupportedManaged("Managed PBKDF2 output exceeds limit")
        blocks = (length + hashlib.new(algorithm).digest_size - 1) // hashlib.new(algorithm).digest_size
        work = iterations * blocks
        if self.pbkdf2_work + work > MAX_PBKDF2_WORK:
            raise UnsupportedManaged("Managed PBKDF2 work exceeds limit")
        self.pbkdf2_work += work
        result = bytearray(hashlib.pbkdf2_hmac(algorithm, password, salt, iterations, length)) if length else bytearray()
        self._record_event({"event": "managed_pbkdf2", "hash": algorithm.upper(),
                            "iterations": iterations, "output_size": length})
        return result

    def _pbkdf2_state(self, args: list) -> dict:
        if len(args) not in (3, 4):
            raise UnsupportedManaged("Unsupported PBKDF2 constructor overload")
        if self.pbkdf2_objects >= MAX_PBKDF2_OBJECTS:
            raise UnsupportedManaged("Managed PBKDF2 object count exceeds limit")
        password, salt, iterations = args[:3]
        if password is None or salt is None:
            raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
        if isinstance(password, str):
            password = self._encode_utf8_bounded(password)
        elif isinstance(password, (bytes, bytearray)):
            password = bytes(password)
        else:
            raise UnsupportedManaged("Unsupported PBKDF2 password type")
        if not isinstance(salt, (bytes, bytearray)):
            raise UnsupportedManaged("Unsupported PBKDF2 salt type")
        if len(salt) < 8 or type(iterations) is not int or iterations <= 0:
            raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
        if iterations > MAX_PBKDF2_ITERATIONS:
            raise UnsupportedManaged("Managed PBKDF2 iteration count exceeds limit")
        algorithm = self._pbkdf2_hash(args[3]) if len(args) == 4 else "sha1"
        self.pbkdf2_objects += 1
        return {"__type": "System.Security.Cryptography.Rfc2898DeriveBytes",
                "password": password, "salt": bytes(salt), "iterations": iterations,
                "algorithm": algorithm, "position": 0, "disposed": False}

    def _pbkdf2_call(self, name: str, args: list, this: dict):
        operation = name.rsplit(".", 1)[-1]
        if operation == "Dispose" and not args:
            this.update({"disposed": True, "password": b"", "salt": b""})
            return None
        if this["disposed"]:
            raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
        if operation == "Reset" and not args:
            this["position"] = 0
            return None
        if operation == "GetBytes" and len(args) == 1:
            count = args[0]
            if type(count) is not int or count < 0:
                raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
            end = this["position"] + count
            full = self._pbkdf2_derive(this["password"], this["salt"],
                                       this["iterations"], this["algorithm"], end)
            result = full[this["position"]:end]
            this["position"] = end
            return result
        if operation == "get_Salt" and not args:
            return bytearray(this["salt"])
        if operation == "get_IterationCount" and not args:
            return this["iterations"]
        raise UnsupportedManaged(f"Unsupported PBKDF2 method: {name}")

    def _aes_state(self) -> dict:
        if self.aes_objects >= MAX_AES_OBJECTS:
            raise UnsupportedManaged("Managed AES object count exceeds limit")
        self.aes_objects += 1
        return {"__type": "System.Security.Cryptography.Aes", "key": None,
                "iv": None, "key_size": 256, "mode": 1, "padding": 2,
                "disposed": False}

    @staticmethod
    def _aes_bytes(value, length: tuple[int, ...]) -> bytes:
        if value is None:
            raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
        if not isinstance(value, (bytes, bytearray)):
            raise UnsupportedManaged("Unsupported AES byte-array argument")
        if len(value) not in length:
            raise ManagedThrown({"__type": "System.Security.Cryptography.CryptographicException",
                                 "args": []})
        return bytes(value)

    def _aes_call(self, name: str, args: list, this: dict):
        operation = name.rsplit(".", 1)[-1]
        if operation in {"Dispose", "Clear"}:
            this.update({"disposed": True, "key": None, "iv": None})
            return None
        if this["disposed"]:
            raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
        if operation == "set_Key" and len(args) == 1:
            this["key"] = self._aes_bytes(args[0], (16, 24, 32))
            this["key_size"] = len(this["key"]) * 8
            return None
        if operation == "get_Key" and not args:
            if this["key"] is None:
                raise UnsupportedManaged("Uninitialized AES key generation is not modeled")
            return bytearray(this["key"])
        if operation == "set_IV" and len(args) == 1:
            this["iv"] = self._aes_bytes(args[0], (16,))
            return None
        if operation == "get_IV" and not args:
            if this["iv"] is None:
                raise UnsupportedManaged("Uninitialized AES IV generation is not modeled")
            return bytearray(this["iv"])
        if operation == "set_KeySize" and len(args) == 1:
            if type(args[0]) is not int or args[0] not in (128, 192, 256):
                raise ManagedThrown({"__type": "System.Security.Cryptography.CryptographicException",
                                     "args": []})
            this["key_size"] = args[0]
            this["key"] = None
            return None
        if operation == "get_KeySize" and not args:
            return this["key_size"]
        if operation == "get_BlockSize" and not args:
            return 128
        if operation in {"set_Mode", "set_Padding"} and len(args) == 1:
            value = args[0]
            if type(value) is not int or value not in (1, 2, 3, 4, 5):
                raise ManagedThrown({"__type": "System.Security.Cryptography.CryptographicException",
                                     "args": []})
            if value not in (1, 2):
                raise UnsupportedManaged(f"Unsupported AES {operation[4:]}: {value}")
            this["mode" if operation == "set_Mode" else "padding"] = value
            return None
        if operation == "get_Mode" and not args:
            return this["mode"]
        if operation == "get_Padding" and not args:
            return this["padding"]
        if operation in {"CreateDecryptor", "CreateEncryptor"} and len(args) in (0, 2):
            key = this["key"] if not args else self._aes_bytes(args[0], (16, 24, 32))
            iv = this["iv"] if not args else self._aes_bytes(args[1], (16,))
            if key is None or (this["mode"] == 1 and iv is None):
                raise UnsupportedManaged("Uninitialized AES key or IV is not modeled")
            if self.aes_objects >= MAX_AES_OBJECTS:
                raise UnsupportedManaged("Managed AES object count exceeds limit")
            self.aes_objects += 1
            return {"__type": "System.Security.Cryptography.ICryptoTransform",
                    "key": key, "iv": iv, "mode": this["mode"],
                    "padding": this["padding"],
                    "direction": "decrypt" if operation == "CreateDecryptor" else "encrypt",
                    "disposed": False, "cipher": None, "pending": b"",
                    "total_input": 0, "total_output": 0,
                    "carve_buffer": bytearray()}
        raise UnsupportedManaged(f"Unsupported AES method: {name}")

    @staticmethod
    def _aes_cipher(this: dict):
        if this["cipher"] is None:
            try:
                this["cipher"] = (AES.new(this["key"], AES.MODE_CBC, iv=this["iv"])
                                  if this["mode"] == 1 else AES.new(this["key"], AES.MODE_ECB))
            except ValueError as exc:
                raise ManagedThrown({"__type": "System.Security.Cryptography.CryptographicException",
                                     "args": []}) from exc
        return this["cipher"]

    def _aes_plaintext_capture_report(self) -> dict:
        return {"captured_artifacts": self.aes_plaintext_capture_count,
                "captured_bytes": self.aes_plaintext_capture_bytes,
                "omitted_transforms": self.aes_plaintext_omitted_count,
                "omitted_bytes": self.aes_plaintext_omitted_bytes,
                "artifact_limit": MAX_AES_PLAINTEXT_ARTIFACTS,
                "byte_limit": MAX_AES_PLAINTEXT_CAPTURE_BYTES}

    def _aes_transform_call(self, name: str, args: list, this: dict):
        operation = name.rsplit(".", 1)[-1]
        if operation == "Dispose":
            this.update({"disposed": True, "cipher": None, "pending": b"",
                         "key": None, "iv": None, "carve_buffer": bytearray()})
            return None
        if this["disposed"]:
            raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
        if operation in {"get_InputBlockSize", "get_OutputBlockSize"} and not args:
            return 16
        if operation in {"get_CanReuseTransform", "get_CanTransformMultipleBlocks"} and not args:
            return True
        if operation not in {"TransformBlock", "TransformFinalBlock"} or len(args) != (5 if operation == "TransformBlock" else 3):
            raise UnsupportedManaged(f"Unsupported AES transform method: {name}")
        source, offset, count = args[:3]
        if source is None:
            raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
        if not isinstance(source, (bytes, bytearray)) or type(offset) is not int or type(count) is not int:
            raise UnsupportedManaged("Unsupported AES transform arguments")
        if offset < 0 or count < 0 or (operation == "TransformBlock" and count == 0):
            raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
        if offset > len(source) or count > len(source) - offset:
            raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
        if operation == "TransformBlock" and count % 16:
            raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
        if this["total_input"] + count > MAX_ARTIFACT:
            raise UnsupportedManaged("Managed AES input exceeds 32 MiB")
        if operation == "TransformBlock":
            target, target_offset = args[3:]
            if target is None:
                raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
            if not isinstance(target, bytearray) or type(target_offset) is not int:
                raise UnsupportedManaged("Unsupported AES output buffer")
            # .NET requires room for inputCount even when PKCS7 decryption holds one block.
            if target_offset < 0 or target_offset > len(target) or count > len(target) - target_offset:
                raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
        payload = bytes(source[offset:offset + count])
        if operation == "TransformBlock":
            if this["direction"] == "decrypt" and this["padding"] == 2:
                transform_input = this["pending"] + payload[:-16]
                pending = payload[-16:]
            else:
                transform_input = payload
                pending = b""
            if this["total_output"] + len(transform_input) > MAX_ARTIFACT:
                raise UnsupportedManaged("Managed AES output exceeds 32 MiB")
            cipher = self._aes_cipher(this)
            result = (cipher.decrypt(transform_input) if this["direction"] == "decrypt"
                      else cipher.encrypt(transform_input)) if transform_input else b""
            target[target_offset:target_offset + len(result)] = result
            this["pending"] = pending
            this["total_input"] += count
            this["total_output"] += len(result)
            if this["direction"] == "decrypt":
                this["carve_buffer"].extend(result)
            self._record_event({"event": "managed_aes_block", "direction": this["direction"],
                                "input_size": count, "output_size": len(result),
                                "output_sha256": hashlib.sha256(result).hexdigest()})
            return len(result)
        payload = this["pending"] + payload
        if this["direction"] == "encrypt" and this["padding"] == 2:
            pad = 16 - len(payload) % 16
            if this["total_output"] + len(payload) + pad > MAX_ARTIFACT:
                raise UnsupportedManaged("Managed AES output exceeds 32 MiB")
            payload += bytes([pad]) * pad
        if len(payload) % 16:
            raise ManagedThrown({"__type": "System.Security.Cryptography.CryptographicException",
                                 "args": []})
        if this["total_output"] + len(payload) > MAX_ARTIFACT:
            raise UnsupportedManaged("Managed AES output exceeds 32 MiB")
        cipher = self._aes_cipher(this)
        result = (cipher.decrypt(payload) if this["direction"] == "decrypt"
                  else cipher.encrypt(payload)) if payload else b""
        if this["direction"] == "decrypt" and this["padding"] == 2 and result:
            pad = result[-1]
            if pad < 1 or pad > 16 or result[-pad:] != bytes([pad]) * pad:
                raise ManagedThrown({"__type": "System.Security.Cryptography.CryptographicException",
                                     "args": []})
            result = result[:-pad]
        self.aes_transform_sequence += 1
        event = {"event": "managed_aes_transform", "direction": this["direction"],
                 "mode": this["mode"], "padding": this["padding"],
                 "input_size": count, "output_size": len(result),
                 "output_sha256": hashlib.sha256(result).hexdigest(),
                 "transform_sequence": self.aes_transform_sequence}
        if this["direction"] == "decrypt":
            this["carve_buffer"].extend(result)
            plaintext = bytes(this["carve_buffer"])
            event["combined_output_size"] = len(plaintext)
            event["combined_output_sha256"] = hashlib.sha256(plaintext).hexdigest()
            context = {"transform_sequence": self.aes_transform_sequence,
                       "mode": this["mode"], "padding": this["padding"],
                       "total_input_size": this["total_input"] + count,
                       "final_input_sha256": hashlib.sha256(payload).hexdigest()}
            if not plaintext:
                event["plaintext_artifact_status"] = "empty"
            elif (self.aes_plaintext_capture_count >= MAX_AES_PLAINTEXT_ARTIFACTS or
                  len(plaintext) > MAX_AES_PLAINTEXT_CAPTURE_BYTES -
                  self.aes_plaintext_capture_bytes):
                event["plaintext_artifact_status"] = "omitted_budget"
                self.aes_plaintext_omitted_count += 1
                self.aes_plaintext_omitted_bytes += len(plaintext)
            else:
                item = self.catalog.add(plaintext, "managed_aes_plaintext",
                                        kind="memory", context=context)
                if item is None:
                    event["plaintext_artifact_status"] = "omitted_catalog"
                    self.aes_plaintext_omitted_count += 1
                    self.aes_plaintext_omitted_bytes += len(plaintext)
                else:
                    event["plaintext_artifact_status"] = "captured"
                    event["plaintext_artifact_sha256"] = item["sha256"]
                    self.aes_plaintext_capture_count += 1
                    self.aes_plaintext_capture_bytes += len(plaintext)
            self.catalog.carve_pe(plaintext, "managed_aes_decrypt", context=context)
        self._record_event(event)
        # .NET exposes reusable transforms. A final block starts a fresh operation.
        this.update({"cipher": None, "pending": b"", "total_input": 0,
                     "total_output": 0, "carve_buffer": bytearray()})
        return bytearray(result)

    def _crypto_stream_state(self, args: list) -> dict:
        if len(args) not in (3, 4):
            raise UnsupportedManaged("Unsupported CryptoStream constructor overload")
        underlying, transform, mode = args[:3]
        leave_open = args[3] if len(args) == 4 else False
        if underlying is None or transform is None:
            raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
        if (not isinstance(underlying, dict) or
                underlying.get("__type") not in {"System.IO.MemoryStream", "System.IO.FileStream"} or
                not isinstance(transform, dict) or transform.get("__type") !=
                "System.Security.Cryptography.ICryptoTransform"):
            raise UnsupportedManaged("Unsupported CryptoStream source or transform")
        if type(mode) is not int or mode not in (0, 1):
            raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
        if leave_open not in (False, True, 0, 1):
            raise UnsupportedManaged("Unsupported CryptoStream leaveOpen value")
        if transform["disposed"]:
            raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
        if underlying["__type"] == "System.IO.MemoryStream":
            underlying = self._memory_stream_state(underlying)
            can_read = True
            can_write = underlying["writable"]
        else:
            if not any(item is underlying for item in self.file_streams):
                raise UnsupportedManaged("Unknown CryptoStream FileStream source")
            can_read = bool(underlying["access"] & 1)
            can_write = bool(underlying["access"] & 2)
        if underlying["closed"]:
            raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
        if not (can_read if mode == 0 else can_write):
            raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
        if len(self.crypto_streams) >= MAX_CRYPTO_STREAMS:
            raise UnsupportedManaged("Managed CryptoStream count exceeded")
        stream = {"__type": "System.Security.Cryptography.CryptoStream",
                  "underlying": underlying, "transform": transform, "mode": mode,
                  "leave_open": bool(leave_open), "closed": False, "flushed": False,
                  "input_buffer": bytearray(), "read_buffer": bytearray(), "position": 0,
                  "read_input": 0, "read_output": 0}
        self.crypto_streams.append(stream)
        self._record_event({"event": "managed_crypto_stream_open", "mode": mode,
                            "underlying": underlying["__type"]})
        return stream

    def _crypto_stream_underlying_read(self, stream: dict, count: int) -> bytes:
        if not 0 < count <= 65_536:
            raise UnsupportedManaged("Invalid CryptoStream read chunk")
        underlying = stream["underlying"]
        if underlying["__type"] == "System.IO.MemoryStream":
            underlying = self._memory_stream_state(underlying)
            if underlying["closed"]:
                raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
            start = underlying["position"]
            end = min(start + count, underlying["length"])
            payload = bytes(underlying["buffer"][start:end])
            underlying["position"] = end if start <= underlying["length"] else start
        else:
            if underlying["closed"]:
                raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
            payload = self.files[underlying["key"]][underlying["position"]:
                                                     underlying["position"] + count]
            underlying["position"] += len(payload)
        return payload

    def _crypto_stream_underlying_write(self, stream: dict, payload: bytes) -> None:
        if not payload:
            return
        underlying = stream["underlying"]
        if underlying["__type"] == "System.IO.MemoryStream":
            self._memory_stream_call("System.IO.Stream.Write", [payload, 0, len(payload)], underlying)
        else:
            self._file_stream_call("System.IO.Stream.Write", [payload, 0, len(payload)], underlying)

    def _crypto_stream_fill_read(self, stream: dict, desired: int) -> None:
        while len(stream["read_buffer"]) < desired and not stream["flushed"]:
            missing = desired - len(stream["read_buffer"])
            request = min(65_536, max(16, ((missing + 31) // 16) * 16))
            chunk = self._crypto_stream_underlying_read(stream, request)
            if chunk:
                stream["read_input"] += len(chunk)
                if stream["read_input"] > MAX_ARTIFACT:
                    raise UnsupportedManaged("Managed CryptoStream input exceeds 32 MiB")
                stream["input_buffer"].extend(chunk)
                block_count = len(stream["input_buffer"]) // 16 * 16
                if block_count:
                    output = bytearray(block_count)
                    written = self._aes_transform_call(
                        "System.Security.Cryptography.ICryptoTransform.TransformBlock",
                        [stream["input_buffer"], 0, block_count, output, 0],
                        stream["transform"])
                    stream["read_buffer"].extend(output[:written])
                    stream["read_output"] += written
                    del stream["input_buffer"][:block_count]
                continue
            pending = stream["input_buffer"]
            final = self._aes_transform_call(
                "System.Security.Cryptography.ICryptoTransform.TransformFinalBlock",
                [pending, 0, len(pending)], stream["transform"])
            stream["read_buffer"].extend(final)
            stream["read_output"] += len(final)
            stream["input_buffer"] = bytearray()
            stream["flushed"] = True
            self._record_event({"event": "managed_crypto_stream_read_transform",
                                "input_size": stream["read_input"],
                                "output_size": stream["read_output"]})

    def _crypto_stream_flush_final(self, stream: dict) -> None:
        if stream["flushed"]:
            raise ManagedThrown({"__type": "System.NotSupportedException", "args": []})
        if stream["mode"] != 1:
            raise ManagedThrown({"__type": "System.NotSupportedException", "args": []})
        pending = stream["input_buffer"]
        output = self._aes_transform_call(
            "System.Security.Cryptography.ICryptoTransform.TransformFinalBlock",
            [pending, 0, len(pending)], stream["transform"])
        self._crypto_stream_underlying_write(stream, bytes(output))
        stream["input_buffer"] = bytearray()
        stream["flushed"] = True
        self._record_event({"event": "managed_crypto_stream_flush_final",
                            "size": len(output)})

    def _crypto_stream_call(self, name: str, args: list, stream: dict):
        if not any(item is stream for item in self.crypto_streams):
            raise UnsupportedManaged("Unknown managed CryptoStream object")
        operation = name.rsplit(".", 1)[-1]
        if operation in {"Dispose", "Close", "Clear"} and not args:
            if not stream["closed"]:
                if stream["mode"] == 1 and not stream["flushed"]:
                    self._crypto_stream_flush_final(stream)
                if not stream["leave_open"]:
                    underlying = stream["underlying"]
                    if underlying["__type"] == "System.IO.MemoryStream":
                        self._memory_stream_call("System.IO.Stream.Close", [], underlying)
                    else:
                        self._file_stream_call("System.IO.Stream.Close", [], underlying)
                stream["closed"] = True
                stream["input_buffer"] = bytearray()
                stream["read_buffer"] = bytearray()
                self._record_event({"event": "managed_crypto_stream_close"})
            return None
        if operation == "get_CanRead" and not args:
            return stream["mode"] == 0 and not stream["closed"]
        if operation == "get_CanWrite" and not args:
            return stream["mode"] == 1 and not stream["closed"]
        if operation == "get_CanSeek" and not args:
            return False
        if operation == "get_HasFlushedFinalBlock" and not args:
            return stream["flushed"]
        if stream["closed"]:
            raise ManagedThrown({"__type": "System.ObjectDisposedException", "args": []})
        if operation in {"get_Length", "get_Position", "set_Position", "Seek", "SetLength"}:
            raise ManagedThrown({"__type": "System.NotSupportedException", "args": []})
        if operation == "Flush" and not args:
            return None
        if operation == "FlushFinalBlock" and not args:
            return self._crypto_stream_flush_final(stream)
        if operation in {"Read", "ReadByte"}:
            if stream["mode"] != 0:
                raise ManagedThrown({"__type": "System.NotSupportedException", "args": []})
            if operation == "ReadByte" and not args:
                self._crypto_stream_fill_read(stream, 1)
                if not stream["read_buffer"]:
                    return -1
                value = stream["read_buffer"][0]
                del stream["read_buffer"][0]
                stream["position"] += 1
                return value
            if operation != "Read" or len(args) != 3:
                raise UnsupportedManaged("Unsupported CryptoStream.Read overload")
            target, offset, count = args
            if target is None:
                raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
            if (not isinstance(target, bytearray) or type(offset) is not int or
                    type(count) is not int):
                raise UnsupportedManaged("Unsupported CryptoStream.Read arguments")
            if offset < 0 or count < 0 or offset + count > len(target):
                raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
            if count == 0:
                return 0
            self._crypto_stream_fill_read(stream, min(count, 65_536))
            chunk = stream["read_buffer"][:count]
            target[offset:offset + len(chunk)] = chunk
            del stream["read_buffer"][:len(chunk)]
            stream["position"] += len(chunk)
            return len(chunk)
        if operation in {"Write", "WriteByte"}:
            if stream["mode"] != 1 or stream["flushed"]:
                raise ManagedThrown({"__type": "System.NotSupportedException", "args": []})
            if operation == "WriteByte" and len(args) == 1 and type(args[0]) is int \
                    and 0 <= args[0] <= 255:
                chunk = bytes([args[0]])
            elif operation == "Write" and len(args) == 3:
                source, offset, count = args
                if source is None:
                    raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
                if (not isinstance(source, (bytes, bytearray)) or type(offset) is not int or
                        type(count) is not int):
                    raise UnsupportedManaged("Unsupported CryptoStream.Write arguments")
                if offset < 0 or count < 0 or offset + count > len(source):
                    raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
                chunk = bytes(source[offset:offset + count])
            else:
                raise UnsupportedManaged("Unsupported CryptoStream.Write overload")
            if not chunk:
                return None
            buffered = stream["input_buffer"] + chunk
            if stream["transform"]["total_input"] + len(buffered) > MAX_ARTIFACT:
                raise UnsupportedManaged("Managed CryptoStream input exceeds 32 MiB")
            block_count = len(buffered) // 16 * 16
            if block_count:
                output = bytearray(block_count)
                written = self._aes_transform_call(
                    "System.Security.Cryptography.ICryptoTransform.TransformBlock",
                    [buffered, 0, block_count, output, 0], stream["transform"])
                self._crypto_stream_underlying_write(stream, bytes(output[:written]))
            stream["input_buffer"] = bytearray(buffered[block_count:])
            self._record_event({"event": "managed_crypto_stream_write", "size": len(chunk)})
            return None
        raise UnsupportedManaged(f"Unsupported CryptoStream method: {name}")

    def _loaded_pe(self, handle: dict, expected_type: str):
        if not isinstance(handle, dict) or handle.get("__type") != expected_type:
            raise UnsupportedManaged(f"Invalid managed {expected_type} handle")
        module_id = handle.get("module_id")
        if type(module_id) is not int or not 0 <= module_id <= len(self.loaded_assemblies):
            raise UnsupportedManaged("Invalid managed assembly index")
        return self.main_pe if module_id == 0 else self.loaded_assemblies[module_id - 1]

    def _manifest_resources(self, assembly: dict):
        module = self._loaded_pe(assembly, "System.Reflection.Assembly")
        table = getattr(module.net.mdtables, "ManifestResource", None)
        rows = table.rows if table is not None else []
        if len(rows) > MAX_MANIFEST_RESOURCES:
            raise UnsupportedManaged("Managed manifest resource count exceeded")
        names = [str(row.Name) for row in rows]
        if any(not name or len(name) > 512 for name in names) or len(set(names)) != len(names):
            raise UnsupportedManaged("Invalid managed manifest resource names")
        return module, rows, names

    def _manifest_resource_stream(self, assembly: dict, name: str):
        if name is None:
            raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
        if not isinstance(name, str) or not name:
            raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
        module, rows, names = self._manifest_resources(assembly)
        if name not in names:
            return None
        row = rows[names.index(name)]
        if not row.Flags.mrPublic and assembly["module_id"] != self._current_module_id():
            return None
        if row.Implementation is not None:
            raise UnsupportedManaged("External managed manifest resource is unsupported")
        base = int(module.net.struct.ResourcesRva)
        span = int(module.net.struct.ResourcesSize)
        offset = int(row.Offset)
        if (base <= 0 or not 0 <= offset <= span - 4 or span > MAX_ARTIFACT + 4):
            raise UnsupportedManaged("Invalid managed manifest resource range")
        header = module.get_data(base + offset, 4)
        if len(header) != 4:
            raise UnsupportedManaged("Truncated managed manifest resource header")
        size = int.from_bytes(header, "little")
        if size > MAX_ARTIFACT or offset + 4 + size > span:
            raise UnsupportedManaged("Managed manifest resource exceeds limit")
        resource_key = (assembly["module_id"], name)
        if (resource_key not in self.opened_manifest_resources and
                self.manifest_resource_bytes + size > MAX_MANIFEST_RESOURCE_BYTES):
            raise UnsupportedManaged("Managed manifest resource cumulative limit exceeded")
        payload = module.get_data(base + offset + 4, size)
        if len(payload) != size:
            raise UnsupportedManaged("Truncated managed manifest resource")
        if resource_key not in self.opened_manifest_resources:
            self.opened_manifest_resources.add(resource_key)
            self.manifest_resource_bytes += size
        self.catalog.add(payload, "managed_manifest_resource")
        self._record_event({"event": "managed_manifest_resource", "module_id": assembly["module_id"],
                            "name": name, "size": size,
                            "sha256": hashlib.sha256(payload).hexdigest()})
        return self._memory_stream_state({"__type": "System.IO.MemoryStream",
                                          "args": [payload, False]})

    def _current_module_id(self) -> int:
        if self.pe is self.main_pe:
            return 0
        for index, module in enumerate(self.loaded_assemblies, 1):
            if self.pe is module:
                return index
        raise UnsupportedManaged("Unknown managed module context")

    @staticmethod
    def _method_owner(module, method_index: int) -> int:
        for index, row in enumerate(module.net.mdtables.TypeDef.rows, 1):
            if any(reference.row_index == method_index for reference in row.MethodList):
                return index
        raise UnsupportedManaged("Managed method has no declaring type")

    @staticmethod
    def _field_owner(module, field_index: int) -> int:
        for index, row in enumerate(module.net.mdtables.TypeDef.rows, 1):
            if any(reference.row_index == field_index for reference in row.FieldList):
                return index
        raise UnsupportedManaged("Managed field has no declaring type")

    def _ensure_type_initialized(self, type_index: int, *, field_access: bool) -> None:
        module_id = self._current_module_id()
        key = module_id, type_index
        if key in self.initialized_types or key in self.initializing_types:
            return
        if key in self.failed_type_initializers:
            raise UnsupportedManaged("Managed type initializer previously failed")
        rows = self.pe.net.mdtables.TypeDef.rows
        if not 1 <= type_index <= len(rows):
            raise UnsupportedManaged("Invalid managed type initializer owner")
        row = rows[type_index - 1]
        if not field_access and row.Flags.tdBeforeFieldInit:
            return
        constructors = [reference.row_index for reference in row.MethodList
                        if str(reference.row.Name) == ".cctor"]
        if len(constructors) > 1:
            raise UnsupportedManaged("Ambiguous managed type initializer")
        if constructors:
            method = self.pe.net.mdtables.MethodDef.rows[constructors[0] - 1]
            if not method.Flags.mdStatic or _signature(method) != (0, False, False):
                raise UnsupportedManaged("Invalid managed type initializer signature")
            self.initializing_types.add(key)
            try:
                self._execute(constructors[0], [])
            except Exception:
                self.failed_type_initializers.add(key)
                raise
            finally:
                self.initializing_types.remove(key)
            self._record_event({"event": "managed_type_init", "module_id": module_id,
                                "type_index": type_index,
                                "type": ".".join(part for part in
                                                 (str(row.TypeNamespace), str(row.TypeName)) if part)[:256]})
        self.initialized_types.add(key)

    def _companion_field(self, token: int, *, is_static: bool):
        index = token & 0xFFFFFF
        members = self.pe.net.mdtables.MemberRef.rows
        if token >> 24 != 0x0A or not 1 <= index <= len(members):
            raise UnsupportedManaged("Invalid managed field reference token")
        member = members[index - 1]
        if not bytes(member.Signature.value).startswith(b"\x06"):
            raise UnsupportedManaged("Managed field reference has method signature")
        self._default_instance_field(member)
        owner = getattr(member, "Class", None)
        if not owner or owner.table.name != "TypeRef" or not owner.row:
            raise UnsupportedManaged("Unsupported managed field owner")
        type_ref = owner.row
        scope = getattr(type_ref, "ResolutionScope", None)
        if not scope or scope.table.name != "AssemblyRef" or not scope.row:
            raise UnsupportedManaged("Unsupported managed field scope")
        assembly_name = str(scope.row.Name)
        assembly = self._load_assembly([assembly_name])
        module = self._loaded_pe(assembly, "System.Reflection.Assembly")
        namespace, type_name = str(type_ref.TypeNamespace), str(type_ref.TypeName)
        types = [(type_index, row)
                 for type_index, row in enumerate(module.net.mdtables.TypeDef.rows, 1)
                 if str(row.TypeNamespace) == namespace and str(row.TypeName) == type_name]
        if len(types) != 1:
            raise ManagedThrown({"__type": "System.TypeLoadException", "args": []})
        type_index, type_row = types[0]
        signature = bytes(member.Signature.value)
        matches = [reference.row_index for reference in type_row.FieldList
                   if str(reference.row.Name) == str(member.Name) and
                   bytes(reference.row.Signature.value) == signature and
                   bool(reference.row.Flags.fdStatic) == is_static and
                   reference.row.Flags.fdPublic]
        if len(matches) != 1:
            raise ManagedThrown({"__type": "System.MissingFieldException", "args": []})
        field_index = matches[0]
        return assembly["module_id"], module, type_index, field_index, module.net.mdtables.Field.rows[field_index - 1]

    def _static_field(self, token: int) -> tuple[tuple[int, int], object]:
        index = token & 0xFFFFFF
        if token >> 24 == 0x0A:
            module_id, module, type_index, field_index, field = self._companion_field(
                token, is_static=True)
            previous = self.pe
            self.pe = module
            try:
                self._ensure_type_initialized(type_index, field_access=True)
            finally:
                self.pe = previous
            return (module_id, field_index), field
        fields = self.pe.net.mdtables.Field.rows
        if token >> 24 != 0x04 or not 1 <= index <= len(fields):
            raise UnsupportedManaged("Invalid managed static field token")
        field = fields[index - 1]
        if not field.Flags.fdStatic:
            raise UnsupportedManaged("Managed static access to instance field")
        self._ensure_type_initialized(self._field_owner(self.pe, index), field_access=True)
        return (self._current_module_id(), index), field

    @staticmethod
    def _type_lineage(module, type_index: int) -> list[int]:
        rows = module.net.mdtables.TypeDef.rows
        lineage = []
        while type_index:
            if (not isinstance(type_index, int) or not 1 <= type_index <= len(rows) or
                    type_index in lineage or len(lineage) >= 64):
                raise UnsupportedManaged("Invalid managed type hierarchy")
            lineage.append(type_index)
            parent = rows[type_index - 1].Extends
            if not parent or parent.table.name != "TypeDef":
                break
            type_index = parent.row_index
        return lineage

    def _dispatch_virtual_method(self, module, method_index: int, actual_type_index: int,
                                 *, public_only: bool) -> int:
        methods = module.net.mdtables.MethodDef.rows
        if not 1 <= method_index <= len(methods):
            raise UnsupportedManaged("Invalid managed virtual method")
        declared = methods[method_index - 1]
        owner_index = self._method_owner(module, method_index)
        lineage = self._type_lineage(module, actual_type_index)
        if owner_index not in lineage:
            raise UnsupportedManaged("Managed virtual receiver has unrelated type")
        if declared.Flags.mdVirtual:
            signature = bytes(declared.Signature.value)
            for derived_index in reversed(lineage[:lineage.index(owner_index)]):
                derived = module.net.mdtables.TypeDef.rows[derived_index - 1]
                candidates = [reference for reference in derived.MethodList
                              if str(reference.row.Name) == str(declared.Name) and
                              bytes(reference.row.Signature.value) == signature and
                              reference.row.Flags.mdVirtual and
                              (not public_only or reference.row.Flags.mdPublic)]
                if len(candidates) > 1:
                    raise UnsupportedManaged("Ambiguous managed virtual override")
                if candidates and candidates[0].row.Flags.mdNewSlot:
                    break
                if candidates:
                    method_index = candidates[0].row_index
        if methods[method_index - 1].Flags.mdAbstract:
            raise UnsupportedManaged("Unresolved managed abstract virtual method")
        return method_index

    def _instance(self, module_id: int, type_index: int) -> dict:
        if self.objects_created >= MAX_MANAGED_OBJECTS:
            raise UnsupportedManaged("Managed object allocation limit exceeded")
        self.objects_created += 1
        return {"__type": "System.Object", "module_id": module_id,
                "type_index": type_index, "fields": {}}

    def _create_instance(self, args: list):
        if len(args) != 1:
            raise UnsupportedManaged("Unsupported Activator.CreateInstance overload")
        typ = args[0]
        module = self._loaded_pe(typ, "System.Type")
        type_index = typ.get("type_index")
        rows = module.net.mdtables.TypeDef.rows
        if not isinstance(type_index, int) or not 1 <= type_index <= len(rows):
            raise UnsupportedManaged("Invalid managed activation type index")
        row = rows[type_index - 1]
        if row.Flags.tdAbstract or row.Flags.tdInterface:
            raise UnsupportedManaged("Managed type cannot be instantiated")
        constructors = [reference.row_index for reference in row.MethodList
                        if str(reference.row.Name) == ".ctor"
                        and reference.row.Flags.mdPublic
                        and _signature(reference.row)[:2] == (0, True)]
        if len(constructors) != 1:
            raise UnsupportedManaged("Managed public parameterless constructor unavailable")
        instance = self._instance(typ["module_id"], type_index)
        previous = self.pe
        self.pe = module
        try:
            self._execute(constructors[0], [instance])
        finally:
            self.pe = previous
        self._record_event({"event": "managed_object_create", "module_id": typ["module_id"],
                            "type_index": type_index, "via": "activator"})
        return instance

    def _instance_field(self, token: int, instance: dict) -> tuple[dict, int, object]:
        index = token & 0xFFFFFF
        if token >> 24 not in {0x04, 0x0A}:
            raise UnsupportedManaged("Invalid managed instance field token")
        if isinstance(instance, dict) and "__ref" in instance:
            location, slot = instance["__ref"], instance["index"]
            value = location.get(slot) if isinstance(location, dict) else location[slot]
            if value in (None, 0) and token >> 24 == 0x04:
                owner = self._field_owner(self.pe, index)
                value = self._instance(self._current_module_id(), owner)
                location[slot] = value
            instance = value
        if instance is None:
            raise ManagedThrown({"__type": "System.NullReferenceException", "args": []})
        if not isinstance(instance, dict) or instance.get("__type") != "System.Object":
            raise UnsupportedManaged("Invalid managed instance object")
        if token >> 24 == 0x0A:
            module_id, module, owner_index, index, field = self._companion_field(
                token, is_static=False)
        else:
            module_id, module = self._current_module_id(), self.pe
            if not 1 <= index <= len(module.net.mdtables.Field.rows):
                raise UnsupportedManaged("Invalid managed instance field token")
            owner_index = self._field_owner(module, index)
            field = module.net.mdtables.Field.rows[index - 1]
        if instance.get("module_id") != module_id:
            raise UnsupportedManaged("Managed field access crossed module boundary")
        type_index = instance.get("type_index")
        types = module.net.mdtables.TypeDef.rows
        if not isinstance(type_index, int) or not 1 <= type_index <= len(types):
            raise UnsupportedManaged("Invalid managed instance type")
        if owner_index not in self._type_lineage(module, type_index):
            raise UnsupportedManaged("Managed field does not belong to object type")
        if field.Flags.fdStatic:
            raise UnsupportedManaged("Managed instance access to static field")
        return instance["fields"], index, field

    @staticmethod
    def _default_instance_field(field):
        signature = bytes(field.Signature.value)
        if len(signature) < 2 or signature[0] != 0x06:
            raise UnsupportedManaged("Invalid managed field signature")

        def parse_type(at: int, depth: int = 0) -> tuple[str, int]:
            if at >= len(signature) or depth >= 4:
                raise UnsupportedManaged("Invalid managed field type")
            kind = signature[at]
            at += 1
            if kind in {0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                        0x0A, 0x0B, 0x18, 0x19}:
                return "integer", at
            if kind in {0x0C, 0x0D}:
                return "float", at
            if kind in {0x0E, 0x1C}:
                return "reference", at
            if kind in {0x11, 0x12}:
                token, at = _compressed_uint(signature, at)
                if token == 0:
                    raise UnsupportedManaged("Invalid managed field type reference")
                return ("value" if kind == 0x11 else "reference"), at
            if kind == 0x1D:
                _, at = parse_type(at, depth + 1)
                return "reference", at
            raise UnsupportedManaged(f"Unsupported managed field type 0x{kind:02x}")

        try:
            category, end = parse_type(1)
        except IndexError as exc:
            raise UnsupportedManaged("Invalid managed field signature") from exc
        if end != len(signature):
            raise UnsupportedManaged("Invalid managed field signature length")
        if category == "value":
            raise UnsupportedManaged("Default managed value-type field is not modeled")
        return None if category == "reference" else 0.0 if category == "float" else 0

    def _load_assembly(self, args: list):
        if len(args) != 1 or args[0] is None:
            if len(args) == 1 and args[0] is None:
                raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
            raise UnsupportedManaged("Unsupported Assembly.Load overload")
        raw = args[0]
        if isinstance(raw, str):
            if not raw:
                raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
            if len(raw) > 256 or "," in raw:
                raise UnsupportedManaged("Qualified managed assembly names are not modeled")
            key = raw.casefold()
            if key in self.named_assemblies:
                return self.named_assemblies[key]
            companion = self.companion_assemblies.get(key)
            if companion is None:
                raise ManagedThrown({"__type": "System.IO.FileNotFoundException", "args": []})
            filename, payload = companion
            handle = self._load_assembly([payload])
            self.named_assemblies[key] = handle
            self._record_event({"event": "managed_companion_load", "module_id": handle["module_id"],
                                "filename": filename, "assembly": raw})
            return handle
        if not isinstance(raw, (bytes, bytearray)):
            raise UnsupportedManaged("Assembly.Load expects guest bytes")
        if (not raw or len(raw) > MAX_ARTIFACT or
                len(self.loaded_assemblies) >= MAX_LOADED_ASSEMBLIES or
                self.loaded_assembly_bytes + len(raw) > MAX_LOADED_ASSEMBLY_BYTES):
            raise UnsupportedManaged("Managed assembly load limit exceeded")
        try:
            module = dnfile.dnPE(data=bytes(raw))
        except (pefile.PEFormatError, ValueError, IndexError, KeyError, TypeError) as exc:
            raise ManagedThrown({"__type": "System.BadImageFormatException", "args": []}) from exc
        if module.net is None:
            raise ManagedThrown({"__type": "System.BadImageFormatException", "args": []})
        self.loaded_assemblies.append(module)
        self.loaded_assembly_bytes += len(raw)
        module_id = len(self.loaded_assemblies)
        self.catalog.add(bytes(raw), "managed_assembly_load", kind="pe")
        self._record_event({"event": "managed_assembly_load", "module_id": module_id,
                            "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        return {"__type": "System.Reflection.Assembly", "module_id": module_id}

    def _reflect_entry_point(self, assembly: dict):
        module = self._loaded_pe(assembly, "System.Reflection.Assembly")
        token = int(module.net.struct.EntryPointTokenOrRva)
        if token == 0:
            return None
        index = token & 0xFFFFFF
        if token >> 24 != 0x06 or not 1 <= index <= len(module.net.mdtables.MethodDef.rows):
            raise UnsupportedManaged("Unsupported reflected assembly entry point")
        return {"__type": "System.Reflection.MethodInfo", "module_id": assembly["module_id"],
                "method_index": index}

    def _reflect_type(self, assembly: dict, name: str):
        if len(name) > 512:
            raise UnsupportedManaged("Managed reflection type name exceeds limit")
        module = self._loaded_pe(assembly, "System.Reflection.Assembly")
        for index, row in enumerate(module.net.mdtables.TypeDef.rows, 1):
            full_name = ".".join(part for part in (str(row.TypeNamespace), str(row.TypeName)) if part)
            if full_name == name:
                return {"__type": "System.Type", "module_id": assembly["module_id"],
                        "type_index": index}
        return None

    def _reflect_method(self, typ: dict, name: str):
        if len(name) > 512:
            raise UnsupportedManaged("Managed reflection method name exceeds limit")
        module = self._loaded_pe(typ, "System.Type")
        type_index = typ.get("type_index")
        rows = module.net.mdtables.TypeDef.rows
        if not isinstance(type_index, int) or not 1 <= type_index <= len(rows):
            raise UnsupportedManaged("Invalid managed reflection type index")
        matches = [reference.row_index for reference in rows[type_index - 1].MethodList
                   if str(reference.row.Name) == name and reference.row.Flags.mdPublic]
        if len(matches) > 1:
            raise UnsupportedManaged("Ambiguous managed reflected method")
        if not matches:
            return None
        return {"__type": "System.Reflection.MethodInfo", "module_id": typ["module_id"],
                "method_index": matches[0]}

    def _invoke_reflected(self, method: dict, args: list):
        module = self._loaded_pe(method, "System.Reflection.MethodInfo")
        index = method.get("method_index")
        rows = module.net.mdtables.MethodDef.rows
        if not isinstance(index, int) or not 1 <= index <= len(rows):
            raise UnsupportedManaged("Invalid managed reflected method index")
        if len(args) != 2:
            raise UnsupportedManaged("Unsupported MethodBase.Invoke overload")
        target, parameters = args
        argc, has_this, _ = _signature(rows[index - 1])
        if has_this:
            if (not isinstance(target, dict) or target.get("__type") != "System.Object"
                    or target.get("module_id") != method["module_id"]
                    or target.get("type_index") != self._method_owner(module, index)):
                raise UnsupportedManaged("Reflected target does not match instance method")
        elif target is not None:
            raise UnsupportedManaged("Reflected static method requires null target")
        actual = [] if parameters is None else parameters
        if not isinstance(actual, list) or len(actual) != argc:
            raise UnsupportedManaged("Reflected method arguments do not match signature")
        self._record_event({"event": "managed_reflect_invoke", "module_id": method["module_id"],
                            "method": str(rows[index - 1].Name)[:512]})
        previous = self.pe
        self.pe = module
        try:
            return self._execute(index, [target, *actual] if has_this else actual)
        finally:
            self.pe = previous

    def _framework(self, name: str, args: list, this, constructor: bool):
        if name == "System.Object..ctor" and not constructor:
            return None
        if name == "System.Runtime.CompilerServices.AsyncTaskMethodBuilder.Create":
            if args or len(self.async_tasks) >= MAX_HTTP_TASKS:
                raise UnsupportedManaged("Managed async task limit exceeded")
            task = {"__type": "System.Threading.Tasks.Task", "completed": False,
                    "error": None}
            self.async_tasks.append(task)
            return {"__type": "System.Runtime.CompilerServices.AsyncTaskMethodBuilder",
                    "task": task}
        if name.startswith("System.Runtime.CompilerServices.AsyncTaskMethodBuilder."):
            builder = self._deref(this)
            if (not isinstance(builder, dict) or builder.get("__type") !=
                    "System.Runtime.CompilerServices.AsyncTaskMethodBuilder"):
                raise UnsupportedManaged("Invalid managed async builder")
            operation = name.rsplit(".", 1)[-1]
            if operation == "Start" and len(args) == 1:
                state = self._deref(args[0])
                if not isinstance(state, dict) or state.get("__type") != "System.Object":
                    raise UnsupportedManaged("Invalid managed async state machine")
                type_index = state.get("type_index")
                rows = self.pe.net.mdtables.TypeDef.rows
                if type(type_index) is not int or not 1 <= type_index <= len(rows):
                    raise UnsupportedManaged("Invalid managed async state type")
                moves = [reference.row_index for reference in rows[type_index - 1].MethodList
                         if str(reference.row.Name) == "MoveNext"]
                if len(moves) != 1:
                    raise UnsupportedManaged("Managed async MoveNext unavailable")
                self._execute(moves[0], [state])
                return None
            if operation == "get_Task" and not args:
                return builder["task"]
            if operation == "SetResult" and not args:
                builder["task"]["completed"] = True
                return None
            if operation == "SetException" and len(args) == 1:
                builder["task"]["completed"] = True
                builder["task"]["error"] = args[0]
                return None
            raise UnsupportedManaged(f"Unsupported managed async builder method: {name}")
        if name == "System.IO.File.WriteAllTextAsync":
            if len(args) not in (2, 3) or len(self.async_tasks) >= MAX_HTTP_TASKS:
                raise UnsupportedManaged("Unsupported File.WriteAllTextAsync overload")
            if len(args) == 3 and args[2] not in (None, 0):
                raise UnsupportedManaged("Managed cancellation token is not modeled")
            self._framework("System.IO.File.WriteAllText", args[:2], None, False)
            task = {"__type": "System.Threading.Tasks.Task", "completed": True,
                    "error": None}
            self.async_tasks.append(task)
            return task
        if name == "System.Threading.Tasks.Task.GetAwaiter":
            task = self._deref(this)
            if args or not any(item is task for item in self.async_tasks):
                raise UnsupportedManaged("Unknown managed async task")
            return {"__type": "System.Runtime.CompilerServices.TaskAwaiter", "task": task}
        if name.startswith("System.Runtime.CompilerServices.TaskAwaiter."):
            awaiter = self._deref(this)
            if (not isinstance(awaiter, dict) or awaiter.get("__type") !=
                    "System.Runtime.CompilerServices.TaskAwaiter"):
                raise UnsupportedManaged("Invalid managed task awaiter")
            task = awaiter["task"]
            if not any(item is task for item in self.async_tasks):
                raise UnsupportedManaged("Unknown managed task awaiter")
            operation = name.rsplit(".", 1)[-1]
            if operation == "get_IsCompleted" and not args:
                return task["completed"]
            if operation == "GetResult" and not args:
                if not task["completed"]:
                    raise UnsupportedManaged("Pending managed task is unsupported")
                if task["error"] is not None:
                    raise ManagedThrown(task["error"])
                return None
            raise UnsupportedManaged(f"Unsupported managed task awaiter method: {name}")
        if name in {"System.Console.get_Out", "System.Console.get_Error"} and not args:
            return {"__type": "System.IO.TextWriter",
                    "stream": "stderr" if name.endswith("get_Error") else "stdout"}
        if (isinstance(this, dict) and this.get("__type") == "System.IO.TextWriter"
                and name in {"System.IO.TextWriter.Write", "System.IO.TextWriter.WriteLine"}):
            if len(args) > 1:
                raise UnsupportedManaged("Unsupported console TextWriter overload")
            value = "" if not args else self._to_text(args[0])
            rendered = value + ("\n" if name.endswith("WriteLine") else "")
            if self.stdout_chars + len(rendered) > MAX_STDOUT_CHARS:
                raise UnsupportedManaged("Managed console output limit exceeded")
            self.stdout_chars += len(rendered)
            stream = this.get("stream")
            if stream not in ("stdout", "stderr"):
                raise UnsupportedManaged("Unknown console writer")
            if stream == "stdout":
                self.stdout.append(value)
            self.console_output.append_text(stream, rendered)
            return None
        if constructor and name == "System.IO.FileStream..ctor":
            if len(args) not in (2, 3, 4):
                raise UnsupportedManaged("Unsupported FileStream constructor overload")
            return self._open_file_stream(args[0], args[1], args[2] if len(args) >= 3 else 3,
                                          args[3] if len(args) == 4 else 0)
        if constructor and name == "System.IO.MemoryStream..ctor":
            return self._memory_stream_state({"__type": "System.IO.MemoryStream", "args": args})
        if constructor and name == "System.IO.Compression.ZipArchive..ctor":
            return self._zip_archive_state(args)
        if constructor and name == "System.Net.Http.HttpClient..ctor":
            if args:
                raise UnsupportedManaged("Unsupported HttpClient constructor overload")
            if len(self.http_clients) >= MAX_HTTP_CLIENTS:
                raise UnsupportedManaged("Managed HttpClient count exceeded")
            client = {"__type": "System.Net.Http.HttpClient", "closed": False,
                      "base_address": None, "started": False}
            client["headers"] = self._http_header_set(client)
            self.http_clients.append(client)
            return client
        if constructor and name == "System.Net.Http.HttpMethod..ctor":
            if len(args) != 1 or not isinstance(args[0], str):
                raise UnsupportedManaged("Unsupported HttpMethod constructor")
            return self._http_method_state(args[0].upper())
        if constructor and name == "System.Net.Http.HttpRequestMessage..ctor":
            return self._http_request_state(args)
        if constructor and name in {"System.Net.Http.StringContent..ctor",
                                    "System.Net.Http.ByteArrayContent..ctor"}:
            return self._http_content_state(name, args)
        if constructor and name in {"System.IO.Compression.GZipStream..ctor",
                                    "System.IO.Compression.DeflateStream..ctor",
                                    "System.IO.Compression.ZLibStream..ctor"}:
            return self._compressed_stream_state(name, args)
        if constructor and name == "System.Security.Cryptography.CryptoStream..ctor":
            return self._crypto_stream_state(args)
        if constructor and name == "System.Security.Cryptography.Rfc2898DeriveBytes..ctor":
            return self._pbkdf2_state(args)
        if constructor and name in {"System.Security.Cryptography.AesManaged..ctor",
                                    "System.Security.Cryptography.AesCryptoServiceProvider..ctor"}:
            if args:
                raise UnsupportedManaged("Unsupported AES constructor overload")
            return self._aes_state()
        if constructor:
            return {"__type": name.removesuffix("..ctor"), "args": args}
        if name == "System.Security.Cryptography.Aes.Create":
            if args:
                raise UnsupportedManaged("Unsupported Aes.Create overload")
            return self._aes_state()
        if name == "System.Security.Cryptography.SHA256.HashData":
            if len(args) != 1 or not isinstance(args[0], (bytes, bytearray)):
                raise UnsupportedManaged("Unsupported SHA256.HashData overload")
            if len(args[0]) > MAX_ARTIFACT:
                raise UnsupportedManaged("Managed hash input exceeds 32 MiB")
            return bytearray(hashlib.sha256(args[0]).digest())
        if name in {"System.UInt64.ToString", "System.UInt32.ToString",
                    "System.Int64.ToString", "System.Int32.ToString"}:
            number = (this["__ref"][this["index"]]
                      if isinstance(this, dict) and "__ref" in this else this)
            if args or type(number) is not int:
                raise UnsupportedManaged(f"Unsupported {name} overload")
            return str(number)
        if name == "System.Array.Clear":
            if len(args) != 3 or not isinstance(args[0], (bytearray, list)):
                raise UnsupportedManaged("Unsupported Array.Clear overload")
            array, start, length = args
            if type(start) is not int or type(length) is not int or start < 0 or length < 0 \
                    or start + length > len(array):
                raise ManagedThrown({"__type": "System.IndexOutOfRangeException", "args": []})
            if length and isinstance(array, bytearray) and array[:2] == b"MZ":
                self.catalog.carve_pe(bytes(array), "managed_array_before_clear")
            array[start:start + length] = (b"\0" * length if isinstance(array, bytearray)
                                           else [None] * length)
            return None
        if name.startswith("System.Net.Http.HttpMethod.get_") and not args:
            return self._http_method_state(name.rsplit("get_", 1)[-1].upper())
        if name == "System.IO.Compression.ZipFile.OpenRead":
            if len(args) != 1:
                raise UnsupportedManaged("Unsupported ZipFile.OpenRead overload")
            source = self._open_file_stream(args[0], 3, 1, 1)
            try:
                return self._zip_archive_state([source, 0, False])
            except BaseException:
                source["closed"] = True
                raise
        if (isinstance(this, dict) and this.get("__type") ==
                "System.IO.Compression.ZipArchive"):
            return self._zip_archive_call(name, args, this)
        if (isinstance(this, dict) and this.get("__type") ==
                "System.IO.Compression.ZipArchiveEntry"):
            return self._zip_entry_call(name, args, this)
        if (isinstance(this, dict) and this.get("__type") ==
                "System.Collections.ObjectModel.ReadOnlyCollection`1"):
            return self._zip_collection_call(name, args, this)
        if (isinstance(this, dict) and this.get("__type") ==
                "System.Collections.Generic.IEnumerator`1"):
            return self._zip_enumerator_call(name, args, this)
        if isinstance(this, dict) and "__ref" in this:
            location, index = this["__ref"], this.get("index")
            if isinstance(location, dict) and type(index) is int:
                referenced = location.get(index)
                if (isinstance(referenced, dict) and referenced.get("__type") ==
                        "System.Runtime.CompilerServices.TaskAwaiter`1"):
                    return self._http_task_call(name, args, referenced)
        if isinstance(this, dict) and this.get("__type") == "System.Net.Http.HttpClient":
            return self._http_client_call(name, args, this)
        if (isinstance(this, dict) and this.get("__type") ==
                "System.Net.Http.HttpRequestMessage"):
            return self._http_request_call(name, args, this)
        if (isinstance(this, dict) and this.get("__type") ==
                "System.Net.Http.Headers.HttpRequestHeaders"):
            return self._http_header_call(name, args, this)
        if (isinstance(this, dict) and this.get("__type") ==
                "System.Net.Http.HttpResponseMessage"):
            return self._http_response_call(name, args, this)
        if isinstance(this, dict) and this.get("__type") == "System.Net.Http.HttpContent":
            return self._http_content_call(name, args, this)
        if (isinstance(this, dict) and this.get("__type") in {
                "System.Threading.Tasks.Task`1",
                "System.Runtime.CompilerServices.TaskAwaiter`1"}):
            return self._http_task_call(name, args, this)
        if name.startswith("System.Security.Cryptography.HashAlgorithmName.get_") and not args:
            algorithm = name.rsplit("get_", 1)[-1]
            if algorithm not in ("MD5", "SHA1", "SHA256", "SHA384", "SHA512"):
                raise UnsupportedManaged("Unsupported HashAlgorithmName property")
            return {"__type": "System.Security.Cryptography.HashAlgorithmName",
                    "name": algorithm}
        if name == "System.Security.Cryptography.Rfc2898DeriveBytes.Pbkdf2":
            if len(args) != 5:
                raise UnsupportedManaged("Unsupported PBKDF2 static overload")
            password, salt, iterations, algorithm, length = args
            if password is None or salt is None:
                raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
            if isinstance(password, str):
                password = self._encode_utf8_bounded(password)
            if not isinstance(password, (bytes, bytearray)) or not isinstance(salt, (bytes, bytearray)):
                raise UnsupportedManaged("Unsupported PBKDF2 static argument")
            if type(iterations) is not int or iterations <= 0:
                raise ManagedThrown({"__type": "System.ArgumentOutOfRangeException", "args": []})
            if iterations > MAX_PBKDF2_ITERATIONS:
                raise UnsupportedManaged("Managed PBKDF2 iteration count exceeds limit")
            return self._pbkdf2_derive(bytes(password), bytes(salt), iterations,
                                       self._pbkdf2_hash(algorithm), length)
        if (isinstance(this, dict) and this.get("__type") ==
                "System.Security.Cryptography.Rfc2898DeriveBytes"):
            return self._pbkdf2_call(name, args, this)
        if isinstance(this, dict) and this.get("__type") == "System.Security.Cryptography.Aes":
            return self._aes_call(name, args, this)
        if (isinstance(this, dict) and this.get("__type") ==
                "System.Security.Cryptography.ICryptoTransform"):
            return self._aes_transform_call(name, args, this)
        if name in {"System.IO.Stream.CopyTo", "System.IO.FileStream.CopyTo",
                    "System.IO.MemoryStream.CopyTo", "System.IO.Compression.GZipStream.CopyTo",
                    "System.IO.Compression.DeflateStream.CopyTo",
                    "System.IO.Compression.ZLibStream.CopyTo",
                    "System.Security.Cryptography.CryptoStream.CopyTo"}:
            return self._stream_copy_to(args, this)
        if (isinstance(this, dict) and this.get("__type") in {
                "System.IO.Compression.GZipStream", "System.IO.Compression.DeflateStream",
                "System.IO.Compression.ZLibStream"} and
                name.startswith(("System.IO.Compression.", "System.IO.Stream.",
                                 "System.IDisposable."))):
            return self._compressed_stream_call(name, args, this)
        if (isinstance(this, dict) and this.get("__type") ==
                "System.Security.Cryptography.CryptoStream" and
                name.startswith(("System.Security.Cryptography.CryptoStream.",
                                 "System.IO.Stream.", "System.IDisposable."))):
            return self._crypto_stream_call(name, args, this)
        if (isinstance(this, dict) and this.get("__type") == "System.IO.FileStream"
                and name.startswith(("System.IO.FileStream.", "System.IO.Stream.",
                                     "System.IDisposable."))):
            return self._file_stream_call(name, args, this)
        if (isinstance(this, dict) and this.get("__type") == "System.IO.MemoryStream"
                and name.startswith(("System.IO.MemoryStream.", "System.IO.Stream.",
                                     "System.IDisposable."))):
            return self._memory_stream_call(name, args, this)
        if name == "System.Activator.CreateInstance":
            return self._create_instance(args)
        if name == "System.Reflection.Assembly.Load":
            return self._load_assembly(args)
        if name == "System.Reflection.Assembly.GetExecutingAssembly" and not args:
            return {"__type": "System.Reflection.Assembly",
                    "module_id": self._current_module_id()}
        if name == "System.Reflection.Assembly.GetManifestResourceNames" and not args:
            return self._manifest_resources(this)[2]
        if name == "System.Reflection.Assembly.GetManifestResourceStream" and len(args) == 1:
            return self._manifest_resource_stream(this, args[0])
        if name == "System.Reflection.Assembly.get_EntryPoint":
            return self._reflect_entry_point(this)
        if name == "System.Reflection.Assembly.GetType":
            if len(args) != 1 or not isinstance(args[0], str):
                raise UnsupportedManaged("Unsupported Assembly.GetType overload")
            return self._reflect_type(this, args[0])
        if name == "System.Type.GetMethod":
            if len(args) != 1 or not isinstance(args[0], str):
                raise UnsupportedManaged("Unsupported Type.GetMethod overload")
            return self._reflect_method(this, args[0])
        if name in {"System.Reflection.MethodBase.Invoke", "System.Reflection.MethodInfo.Invoke"}:
            return self._invoke_reflected(this, args)
        if name == "System.Runtime.CompilerServices.RuntimeHelpers.InitializeArray":
            if (len(args) != 2 or not isinstance(args[0], bytearray)
                    or not isinstance(args[1], dict) or "__field_token" not in args[1]):
                raise UnsupportedManaged("Unsupported managed array initializer")
            token = args[1]["__field_token"]
            if not isinstance(token, int) or token >> 24 != 0x04:
                raise UnsupportedManaged("Invalid managed array field token")
            fields = self.pe.net.mdtables.Field.rows
            field_index = token & 0xFFFFFF
            if not 1 <= field_index <= len(fields):
                raise UnsupportedManaged("Invalid managed array field index")
            table = getattr(self.pe.net.mdtables, "FieldRva", None)
            rows = table.rows if table is not None else []
            field = next((row for row in rows if row.Field.row_index == field_index), None)
            if field is None:
                raise UnsupportedManaged("Managed array field has no RVA data")
            payload = self.pe.get_data(field.Rva, len(args[0]))
            if len(payload) != len(args[0]):
                raise UnsupportedManaged("Truncated managed array initializer")
            args[0][:] = payload
            self._record_event({"event": "managed_array_init", "size": len(payload)})
            return None
        if name.startswith("System.Console.Write"):
            value = "" if not args else self._to_text(args[0])
            rendered = value + ("\n" if name.startswith("System.Console.WriteLine") else "")
            if self.stdout_chars + len(rendered) > MAX_STDOUT_CHARS:
                raise UnsupportedManaged("Managed stdout limit exceeded")
            self.stdout.append(value)
            self.stdout_chars += len(rendered)
            self.console_output.append_text("stdout", rendered)
            return None
        if name == "System.String.Concat":
            values = args[0] if len(args) == 1 and isinstance(args[0], list) else args
            parts = [self._to_text(arg) for arg in values]
            if sum(map(len, parts)) > MAX_ARTIFACT:
                raise UnsupportedManaged("Managed string exceeds 32 MiB")
            return "".join(parts)
        if name in {"System.String.op_Equality", "System.String.op_Inequality"}:
            if len(args) != 2 or any(value is not None and not isinstance(value, str)
                                     for value in args):
                raise UnsupportedManaged("Unsupported managed string comparison")
            equal = args[0] == args[1]
            return equal if name == "System.String.op_Equality" else not equal
        if name == "System.String.IsNullOrEmpty":
            return not args[0]
        if name == "System.String.Replace" and isinstance(this, str):
            old, new = self._to_text(args[0]), self._to_text(args[1])
            if not old:
                raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
            result_length = len(this) + this.count(old) * (len(new) - len(old))
            if result_length > MAX_ARTIFACT:
                raise UnsupportedManaged("Managed string exceeds 32 MiB")
            return this.replace(old, new)
        if name == "System.Convert.FromBase64String":
            if args[0] is None:
                raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
            if not isinstance(args[0], str):
                raise UnsupportedManaged("Invalid Base64 argument type")
            if len(args[0]) > 2 * MAX_ARTIFACT:
                raise UnsupportedManaged("Managed Base64 input exceeds limit")
            encoded = args[0].translate(str.maketrans("", "", " \t\r\n"))
            if len(encoded) > 4 * ((MAX_ARTIFACT + 2) // 3):
                raise UnsupportedManaged("Managed Base64 input exceeds 32 MiB output limit")
            try:
                decoded = base64.b64decode(encoded, validate=True)
            except (ValueError, binascii.Error) as exc:
                raise ManagedThrown({"__type": "System.FormatException", "args": []}) from exc
            if len(decoded) > MAX_ARTIFACT:
                raise UnsupportedManaged("Managed Base64 output exceeds 32 MiB limit")
            return bytearray(decoded)
        if name == "System.Convert.ToBase64String":
            if len(args[0]) > 3 * (MAX_ARTIFACT // 4):
                raise UnsupportedManaged("Managed Base64 output exceeds 32 MiB")
            return base64.b64encode(bytes(args[0])).decode("ascii")
        if name in {"System.Text.Encoding.get_UTF8", "System.Text.Encoding.get_ASCII"}:
            return {"__type": "System.Text.Encoding",
                    "encoding": "ascii" if name.endswith("get_ASCII") else "utf-8"}
        if name == "System.Text.Encoding.GetString" and isinstance(this, dict):
            if len(args[0]) > MAX_ARTIFACT:
                raise UnsupportedManaged("Managed encoded value exceeds 32 MiB")
            return bytes(args[0]).decode(this["encoding"], errors="replace")
        if name == "System.Text.Encoding.GetBytes" and isinstance(this, dict):
            encoding = this.get("encoding")
            if encoding == "utf-8":
                return self._encode_utf8_bounded(self._to_text(args[0]))
            if encoding == "ascii":
                value = self._to_text(args[0])
                if len(value) > MAX_ARTIFACT:
                    raise UnsupportedManaged("Managed encoded value exceeds 32 MiB")
                return bytearray(value.encode("ascii", errors="replace"))
            raise UnsupportedManaged("Unsupported managed encoding")
        if name == "System.Environment.GetFolderPath":
            if len(args) not in (1, 2):
                raise UnsupportedManaged("Unsupported Environment.GetFolderPath overload")
            folder = args[0]
            option = args[1] if len(args) == 2 else 0
            if type(folder) is not int or folder not in KNOWN_SPECIAL_FOLDERS:
                raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
            if type(option) is not int or option not in (0, 16384, 32768):
                raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
            if folder not in self.special_folders:
                raise UnsupportedManaged(f"Unsupported SpecialFolder value: {folder}")
            path = self.special_folders[folder]
            if path and self._file_key(path) not in self.directories:
                if option == 32768:
                    self._seed_directory(path)
                elif option == 0:
                    path = ""
            self._record_event({"event": "special_folder", "folder": folder,
                                "option": option, "path": path})
            return path
        if name == "System.Environment.GetCommandLineArgs" and not args:
            return [self.info.name, *self.guest_args]
        if name in {"System.Environment.GetEnvironmentVariable",
                    "System.Environment.SetEnvironmentVariable"}:
            setter = name.endswith("SetEnvironmentVariable")
            if len(args) not in ((2, 3) if setter else (1, 2)):
                raise UnsupportedManaged("Unsupported environment variable overload")
            if len(args) == (3 if setter else 2):
                if type(args[-1]) is not int or args[-1] != 0:
                    raise UnsupportedManaged("Only process environment variables are modeled")
            variable = args[0]
            if variable is None:
                raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
            if (not isinstance(variable, str) or not variable or "=" in variable
                    or "\0" in variable):
                raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
            if len(variable) > MAX_ENV_NAME_CHARS:
                raise UnsupportedManaged("Managed environment variable name exceeds limit")
            key = variable.upper()
            if not setter:
                return self.environment.get(key)
            value = args[1]
            if value is not None and not isinstance(value, str):
                raise UnsupportedManaged("Unsupported environment variable value")
            if value is not None:
                value = value.split("\0", 1)[0]
                if len(value) > MAX_ENV_VALUE_CHARS:
                    raise UnsupportedManaged("Managed environment variable value exceeds limit")
                if key not in self.environment and len(self.environment) >= MAX_ENV_VARIABLES:
                    raise UnsupportedManaged("Managed environment variable count exceeds limit")
                used = sum(len(item) + len(text) for item, text in self.environment.items())
                used -= len(key) + len(self.environment[key]) if key in self.environment else 0
                if used + len(key) + len(value) > MAX_ENV_TOTAL_CHARS:
                    raise UnsupportedManaged("Managed environment storage exceeds limit")
                self.environment[key] = value
            else:
                self.environment.pop(key, None)
            self._record_event({"event": "environment_set", "name": key,
                                "deleted": value is None,
                                "size": len(value) if value is not None else 0})
            return None
        if name == "System.Environment.ExpandEnvironmentVariables":
            if len(args) != 1:
                raise UnsupportedManaged("Unsupported environment expansion overload")
            value = args[0]
            if value is None:
                raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
            if not isinstance(value, str) or len(value) > MAX_ENV_VALUE_CHARS:
                raise UnsupportedManaged("Managed environment expansion input exceeds limit")
            pieces: list[str] = []
            size = 0
            offset = 0
            for match in re.finditer(r"%([^%]+)%", value):
                for piece in (value[offset:match.start()],
                              self.environment.get(match.group(1).upper(), match.group(0))):
                    size += len(piece)
                    if size > MAX_ENV_VALUE_CHARS:
                        raise UnsupportedManaged("Managed environment expansion output exceeds limit")
                    pieces.append(piece)
                offset = match.end()
            tail = value[offset:]
            if size + len(tail) > MAX_ENV_VALUE_CHARS:
                raise UnsupportedManaged("Managed environment expansion output exceeds limit")
            pieces.append(tail)
            return "".join(pieces)
        if name == "System.IO.Path.Combine":
            parts = args[0] if len(args) == 1 and isinstance(args[0], list) else args
            if not 2 <= len(parts) <= 16:
                raise UnsupportedManaged("Unsupported Path.Combine overload")
            return self._combine_path_parts(parts)
        if name == "System.IO.Compression.ZipFile.ExtractToDirectory":
            return self._zip_extract_to_directory(args)
        if name in {"System.IO.Path.GetFileName", "System.IO.Path.GetExtension",
                    "System.IO.Path.GetFileNameWithoutExtension",
                    "System.IO.Path.HasExtension", "System.IO.Path.GetDirectoryName",
                    "System.IO.Path.IsPathRooted", "System.IO.Path.GetPathRoot"}:
            if len(args) != 1:
                raise UnsupportedManaged("Unsupported managed Path overload")
            path = self._path_text(args[0])
            if name == "System.IO.Path.IsPathRooted":
                return bool(path and (path[0] in "\\/" or
                                      (len(path) >= 2 and path[1] == ":")))
            if name == "System.IO.Path.HasExtension":
                return bool(path and self._path_extension(path))
            if path is None:
                return None
            if name == "System.IO.Path.GetFileName":
                return self._path_filename(path)
            if name == "System.IO.Path.GetExtension":
                return self._path_extension(path)
            if name == "System.IO.Path.GetFileNameWithoutExtension":
                filename = self._path_filename(path)
                dot = filename.rfind(".")
                return filename[:dot] if dot >= 0 else filename
            if name == "System.IO.Path.GetDirectoryName":
                if not path or path in ("\\", "/") or (len(path) == 2 and path[1] == ":"):
                    return None if path else ""
                parent = ntpath.dirname(path.replace("/", "\\"))
                return None if parent == path.replace("/", "\\") else parent
            if not path or path.isspace():
                return None
            if path.startswith(("\\\\", "//")):
                raise UnsupportedManaged("UNC and device path roots are not modeled")
            if len(path) >= 2 and path[1] == ":":
                return path[:2] + "\\" if len(path) > 2 and path[2] in "\\/" else path[:2]
            return "\\" if path[0] in "\\/" else ""
        if name == "System.IO.Path.ChangeExtension":
            if len(args) != 2:
                raise UnsupportedManaged("Unsupported Path.ChangeExtension overload")
            path, extension = map(self._path_text, args)
            if path is None or not path:
                return path
            if extension == "":
                raise UnsupportedManaged("Empty replacement extension is not modeled")
            filename = self._path_filename(path)
            dot = filename.rfind(".")
            stem = path[:len(path) - len(filename) + dot] if dot >= 0 else path
            result = stem if extension is None else stem + (extension if extension.startswith(".") else "." + extension)
            if len(result) > MAX_GUEST_PATH_CHARS:
                raise UnsupportedManaged("Managed changed path exceeds limit")
            return result
        if name == "System.IO.Path.GetFullPath":
            if len(args) not in (1, 2):
                raise UnsupportedManaged("Unsupported Path.GetFullPath overload")
            if any(value is None for value in args):
                raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
            path = self._path_text(args[0])
            base = self.current_dir if len(args) == 1 else self._path_text(args[1])
            if (not path and len(args) == 1) or path.isspace():
                raise ManagedThrown({"__type": "System.ArgumentException", "args": []})
            if not path:
                self._full_guest_path(".", base)
                return base
            return self._full_guest_path(path, base)
        if name == "System.IO.Path.GetTempPath":
            if args:
                raise UnsupportedManaged("Unsupported Path.GetTempPath overload")
            return self.temp_dir
        if name in {"System.IO.Directory.GetCurrentDirectory", "System.Environment.get_CurrentDirectory"}:
            if args:
                raise UnsupportedManaged("Unsupported current directory getter overload")
            return self.current_dir
        if name in {"System.IO.Directory.SetCurrentDirectory", "System.Environment.set_CurrentDirectory"}:
            if len(args) != 1:
                raise UnsupportedManaged("Unsupported current directory setter overload")
            path = self._file_path(args[0])
            key = self._file_key(path)
            if key not in self.directories:
                raise ManagedThrown({"__type": "System.IO.DirectoryNotFoundException", "args": [path]})
            self.current_dir = self._guest_path(path)
            self._record_event({"event": "current_directory", "path": self.current_dir})
            return None
        if name == "System.IO.Directory.Exists":
            if len(args) != 1:
                raise UnsupportedManaged("Unsupported Directory.Exists overload")
            path = args[0]
            return isinstance(path, str) and bool(path) and "\x00" not in path \
                and len(path) <= MAX_GUEST_PATH_CHARS \
                and self._file_key(path) in self.directories
        if name in {"System.IO.Directory.GetFiles", "System.IO.Directory.GetDirectories",
                    "System.IO.Directory.GetFileSystemEntries"}:
            return self._enumerate_directory(name, args)
        if name == "System.IO.Directory.CreateDirectory":
            if len(args) != 1:
                raise UnsupportedManaged("Unsupported Directory.CreateDirectory overload")
            path = self._file_path(args[0])
            chain = self._directory_chain(path)
            if not chain or chain[0] not in self.directories:
                raise ManagedThrown({"__type": "System.IO.DirectoryNotFoundException", "args": [path]})
            if any(item in self.files for item in chain):
                raise ManagedThrown({"__type": "System.IO.IOException", "args": [path]})
            created = [item for item in chain if item not in self.directories]
            if len(self.directories) + len(created) > MAX_GUEST_DIRECTORIES:
                raise UnsupportedManaged("Managed guest directory count exceeded")
            self.directories.update(created)
            self.created_directories.update(created)
            current = self._guest_path(path)
            while current:
                key = ntpath.normcase(current)
                if key in created:
                    self.directory_display_paths[key] = current
                parent = ntpath.dirname(current)
                if parent == current:
                    break
                current = parent
            for item in created:
                self.directory_attributes[item] = ATTR_DIRECTORY
            self._record_event({"event": "directory_create", "path": path,
                                "created": len(created)})
            return {"__type": "System.IO.DirectoryInfo", "path": self._file_key(path)}
        if name == "System.IO.Directory.Delete":
            if len(args) not in (1, 2) or (len(args) == 2 and args[1] not in (False, True, 0, 1)):
                raise UnsupportedManaged("Unsupported Directory.Delete overload")
            recursive = bool(args[1]) if len(args) == 2 else False
            path = self._file_path(args[0])
            key = self._file_key(path)
            if key not in self.directories:
                raise ManagedThrown({"__type": "System.IO.DirectoryNotFoundException", "args": [path]})
            if key in self.protected_directories:
                raise UnsupportedManaged("Cannot delete predefined managed directory")
            prefix = key.rstrip("\\") + "\\"
            if self._file_key(self.current_dir) == key or self._file_key(self.current_dir).startswith(prefix):
                raise ManagedThrown({"__type": "System.IO.IOException", "args": [path]})
            children = {item for item in self.directories if item.startswith(prefix)}
            files = {item for item in self.files if item.startswith(prefix)}
            for item in files:
                self._check_stream_delete(item)
            if any(item in self.protected_directories for item in children):
                raise UnsupportedManaged("Cannot delete predefined managed directory")
            if any(self.directory_attributes.get(item, ATTR_DIRECTORY) & ATTR_READONLY
                   for item in children | {key}) or any(
                       self.file_attributes.get(item, ATTR_ARCHIVE) & ATTR_READONLY
                       for item in files):
                raise ManagedThrown({"__type": "System.IO.IOException", "args": [path]})
            if not recursive and (children or files):
                raise ManagedThrown({"__type": "System.IO.IOException", "args": [path]})
            if len(self.events) >= MAX_MANAGED_EVENTS:
                raise UnsupportedManaged("Managed event limit exceeded")
            removed_bytes = sum(len(self.files[item]) for item in files)
            for item in files:
                del self.files[item]
                self.file_attributes.pop(item, None)
                self.file_display_paths.pop(item, None)
            self.file_bytes -= removed_bytes
            self.directories.difference_update(children | {key})
            self.created_directories.difference_update(children | {key})
            for item in children | {key}:
                self.directory_attributes.pop(item, None)
                self.directory_display_paths.pop(item, None)
            self._record_event({"event": "directory_delete", "path": path,
                                "recursive": recursive, "directories_removed": len(children) + 1,
                                "files_removed": len(files), "bytes_removed": removed_bytes})
            return None
        if name in {"System.IO.File.OpenRead", "System.IO.File.OpenWrite",
                    "System.IO.File.Create", "System.IO.File.Open"}:
            if name == "System.IO.File.OpenRead" and len(args) == 1:
                return self._open_file_stream(args[0], 3, 1, 1)
            if name == "System.IO.File.OpenWrite" and len(args) == 1:
                return self._open_file_stream(args[0], 4, 2, 0)
            if name == "System.IO.File.Create" and len(args) == 1:
                return self._open_file_stream(args[0], 2, 3, 0)
            if name == "System.IO.File.Open" and len(args) in (2, 3, 4):
                return self._open_file_stream(args[0], args[1], args[2] if len(args) >= 3 else 3,
                                              args[3] if len(args) == 4 else 0)
            raise UnsupportedManaged(f"Unsupported {name} overload")
        if name == "System.IO.File.WriteAllText":
            path = self._file_path(args[0])
            content = self._to_text(args[1])
            payload = self._encode_utf8_bounded(content)
            self._store_file(path, payload)
            return None
        if name in {"System.IO.File.GetAttributes", "System.IO.File.SetAttributes"}:
            return self._file_attribute_call(name, args)
        if name == "System.IO.File.WriteAllBytes":
            path = self._file_path(args[0])
            if len(args[1]) > MAX_ARTIFACT:
                raise UnsupportedManaged("Managed guest file exceeds 32 MiB")
            self._store_file(path, bytes(args[1]))
            return None
        if name == "System.IO.File.ReadAllBytes":
            path = self._file_path(args[0])
            self._require_parent(self._file_key(path))
            self._check_stream_access(self._file_key(path), 1)
            if self._file_key(path) not in self.files:
                raise ManagedThrown({"__type": "System.IO.FileNotFoundException", "args": [path]})
            # A managed byte[] is mutable and independent of the file's contents.
            return bytearray(self.files[self._file_key(path)])
        if name == "System.IO.File.Exists":
            if len(args) != 1:
                raise UnsupportedManaged("Unsupported File.Exists overload")
            path = args[0]
            return isinstance(path, str) and bool(path) and "\x00" not in path \
                and len(path) <= MAX_GUEST_PATH_CHARS and self._file_key(path) in self.files
        if name == "System.IO.File.ReadAllText":
            if len(args) != 1:
                raise UnsupportedManaged("Unsupported File.ReadAllText overload")
            path = self._file_path(args[0])
            self._require_parent(self._file_key(path))
            self._check_stream_access(self._file_key(path), 1)
            payload = self.files.get(self._file_key(path))
            if payload is None:
                raise ManagedThrown({"__type": "System.IO.FileNotFoundException", "args": [path]})
            return self._decode_file_text(payload)
        if name == "System.IO.File.AppendAllText":
            if len(args) != 2:
                raise UnsupportedManaged("Unsupported File.AppendAllText overload")
            path = self._file_path(args[0])
            if args[1] is not None and not isinstance(args[1], str):
                raise UnsupportedManaged("Unsupported File.AppendAllText content type")
            payload = self._encode_utf8_bounded(args[1] or "")
            prior = self.files.get(self._file_key(path), b"")
            if len(prior) + len(payload) > MAX_ARTIFACT:
                raise UnsupportedManaged("Managed guest file exceeds 32 MiB")
            self._store_file(path, prior + payload)
            return None
        if name == "System.IO.File.Delete":
            if len(args) != 1:
                raise UnsupportedManaged("Unsupported File.Delete overload")
            path = self._file_path(args[0])
            self._require_parent(self._file_key(path))
            self._check_stream_delete(self._file_key(path))
            if self._file_key(path) in self.directories:
                raise ManagedThrown({"__type": "System.UnauthorizedAccessException", "args": [path]})
            if (self._file_key(path) in self.files and
                    self.file_attributes.get(self._file_key(path), ATTR_ARCHIVE) & ATTR_READONLY):
                raise ManagedThrown({"__type": "System.UnauthorizedAccessException", "args": [path]})
            prior = self.files.pop(self._file_key(path), None)
            if prior is not None:
                self.file_bytes -= len(prior)
                self.file_attributes.pop(self._file_key(path), None)
                self.file_display_paths.pop(self._file_key(path), None)
            self._record_event({"event": "file_delete", "path": path,
                                "existed": prior is not None})
            return None
        if name in {"System.IO.File.Copy", "System.IO.File.Move"}:
            return self._transfer_file(name, args)
        if name in {"System.Net.WebClient.DownloadData", "System.Net.WebClient.DownloadString",
                    "System.Net.WebClient.DownloadFile"}:
            if len(args) != (2 if name.endswith("DownloadFile") else 1):
                raise UnsupportedManaged(f"Unsupported {name} overload")
            url = self._managed_network_url(args[0])
            path = None
            if name.endswith("DownloadFile"):
                if args[1] is None:
                    raise ManagedThrown({"__type": "System.ArgumentNullException", "args": []})
                path = self._file_path(args[1])
                key = self._file_key(path)
                self._require_parent(key)
                self._check_stream_access(key, 2)
                if key in self.directories or (key in self.files and
                        self.file_attributes.get(key, ATTR_ARCHIVE) & ATTR_READONLY):
                    raise ManagedThrown({"__type": "System.UnauthorizedAccessException",
                                         "args": [path]})
            try:
                payload = self.network.fetch(url)
            except NetworkDenied as exc:
                raise ManagedThrown({"__type": "System.Net.WebException",
                                     "args": [str(exc)[:256]]}) from exc
            if name.endswith("DownloadFile"):
                self._store_file(path, payload)
                self._record_event({"event": "managed_download_file", "url": url,
                                    "path": path, "size": len(payload)})
                return None
            if name.endswith("DownloadString"):
                return payload.decode("utf-8", errors="replace")
            return bytearray(payload)
        raise UnsupportedManaged(f"Unsupported framework method: {name}")

    def _execute(self, method_index: int, args: list):
        self.depth += 1
        try:
            if self.depth > 64:
                raise UnsupportedManaged("Managed call depth exceeded 64")
            rows = self.pe.net.mdtables.MethodDef.rows
            if not 1 <= method_index <= len(rows):
                raise UnsupportedManaged(f"Invalid method index {method_index}")
            method = rows[method_index - 1]
            if not method.Rva:
                for mapping in getattr(self.pe.net.mdtables, "ImplMap", None).rows \
                        if getattr(self.pe.net.mdtables, "ImplMap", None) else []:
                    member = getattr(mapping, "MemberForwarded", None)
                    if member is None or member.row is not method:
                        continue
                    module = str(mapping.ImportScope.row.Name).casefold()
                    entry = str(mapping.ImportName)
                    if module in {"kernel32", "kernel32.dll"} and entry in {
                            "GetTickCount64", "GetTickCount", "IsDebuggerPresent"} and not args:
                        value = (0 if entry == "IsDebuggerPresent" else
                                 int(self.persona["uptime_ms"]) + self.instructions // 1000)
                        if entry == "GetTickCount":
                            value &= 0xFFFFFFFF
                        self._record_event({"event": "managed_pinvoke", "module": module,
                                            "entry": entry, "result": value})
                        return value
                    raise UnsupportedManaged(f"Unsupported managed P/Invoke: {module}!{entry}")
                raise UnsupportedManaged(f"No IL body for {method.Name}")
            body = read_method_body_from_bytes(self.pe.get_data(method.Rva, 1024 * 1024))
            instructions = body.instructions
            if any(not (handler.is_catch() or handler.is_finally())
                   for handler in body.exception_handlers):
                raise UnsupportedManaged(f"Unsupported managed exception clause in {method.Name}")
            offsets = {ins.offset: i for i, ins in enumerate(instructions)}
            code_base = instructions[0].offset if instructions else body.header_size
            code_end = code_base + body.code_size
            for handler in body.exception_handlers:
                if (not 0 <= handler.try_start < handler.try_end <= body.code_size
                        or not 0 <= handler.handler_start < handler.handler_end <= body.code_size
                        or code_base + handler.try_start not in offsets
                        or code_base + handler.handler_start not in offsets
                        or (code_base + handler.try_end not in offsets and
                            code_base + handler.try_end != code_end)
                        or (code_base + handler.handler_end not in offsets and
                            code_base + handler.handler_end != code_end)):
                    raise UnsupportedManaged(f"Invalid managed exception region in {method.Name}")
                if handler.is_catch():
                    if handler.catch_type is None:
                        raise UnsupportedManaged("Catch clause has no exception type")
                    self._type_name(handler.catch_type.value)
            stack: list = []
            locals_: dict[int, object] = {}
            pending: dict | None = None
            active_catches: list[tuple[int, int, ManagedThrown]] = []
            pc = 0
            while pc < len(instructions):
                if self.instructions >= self.max_instructions:
                    raise UnsupportedManaged("Managed instruction budget exhausted")
                self.instructions += 1
                ins = instructions[pc]
                active_catches[:] = [entry for entry in active_catches
                                     if entry[0] <= ins.offset < entry[1]]
                op = ins.mnemonic
                self.opcode_counts[op] = self.opcode_counts.get(op, 0) + 1
                operand = ins.operand
                next_pc = pc + 1
                if op in {"nop", "break", "volatile.", "tail."}:
                    pass
                elif op == "ldstr":
                    token = int(operand.value if hasattr(operand, "value") else operand)
                    value = self.pe.net.user_strings.get(token & 0xFFFFFF)
                    stack.append(str(value))
                elif op == "ldnull":
                    stack.append(None)
                elif op.startswith("ldc.i4.") and op not in {"ldc.i4.s"}:
                    suffix = op[7:]
                    stack.append(-1 if suffix == "m1" else int(suffix))
                elif op in {"ldc.i4", "ldc.i4.s", "ldc.i8", "ldc.r4", "ldc.r8"}:
                    stack.append(operand)
                elif op.startswith("ldarg.") and op[-1].isdigit():
                    stack.append(args[int(op[-1])])
                elif op in {"ldarg", "ldarg.s"}:
                    stack.append(args[int(getattr(operand, "index", operand))])
                elif op.startswith("ldloc.") and op[-1].isdigit():
                    stack.append(locals_.get(int(op[-1]), 0))
                elif op in {"ldloc", "ldloc.s"}:
                    stack.append(locals_.get(int(getattr(operand, "index", operand)), 0))
                elif op in {"ldloca", "ldloca.s"}:
                    stack.append({"__ref": locals_, "index": int(getattr(operand, "index", operand))})
                elif op.startswith("stloc.") and op[-1].isdigit():
                    locals_[int(op[-1])] = stack.pop()
                elif op in {"stloc", "stloc.s"}:
                    locals_[int(getattr(operand, "index", operand))] = stack.pop()
                elif op in {"ldarga", "ldarga.s"}:
                    stack.append({"__ref": args, "index": int(getattr(operand, "index", operand))})
                elif op == "dup":
                    stack.append(stack[-1])
                elif op == "pop":
                    stack.pop()
                elif op == "initobj":
                    reference = stack.pop()
                    if not isinstance(reference, dict) or "__ref" not in reference:
                        raise UnsupportedManaged("Invalid managed initobj target")
                    reference["__ref"][reference["index"]] = None
                elif op in {"ldfld", "stfld"}:
                    value = stack.pop() if op == "stfld" else None
                    instance = stack.pop()
                    try:
                        fields, field_index, field = self._instance_field(int(operand.value), instance)
                    except ManagedThrown as thrown:
                        next_pc, pending = self._route_exception(body, code_base, ins.offset,
                                                                 thrown, stack, offsets, active_catches)
                    else:
                        if op == "stfld":
                            fields[field_index] = value
                        elif field_index in fields:
                            stack.append(fields[field_index])
                        else:
                            stack.append(self._default_instance_field(field))
                elif op == "ldflda":
                    instance = stack.pop()
                    fields, field_index, _ = self._instance_field(int(operand.value), instance)
                    if field_index not in fields:
                        fields[field_index] = None
                    stack.append({"__ref": fields, "index": field_index})
                elif op in {"ldsfld", "stsfld"}:
                    value = stack.pop() if op == "stsfld" else None
                    try:
                        field_key, field = self._static_field(int(operand.value))
                    except ManagedThrown as thrown:
                        next_pc, pending = self._route_exception(body, code_base, ins.offset,
                                                                 thrown, stack, offsets, active_catches)
                    else:
                        if op == "stsfld":
                            self.static_fields[field_key] = value
                        elif field_key in self.static_fields:
                            stack.append(self.static_fields[field_key])
                        else:
                            stack.append(self._default_instance_field(field))
                elif op in {"call", "callvirt", "newobj"}:
                    try:
                        self._call(int(operand.value), stack, constructor=op == "newobj",
                                   virtual=op == "callvirt")
                    except ManagedThrown as thrown:
                        next_pc, pending = self._route_exception(body, code_base, ins.offset,
                                                                 thrown, stack, offsets, active_catches)
                elif op == "throw":
                    value = stack.pop()
                    if value is None:
                        value = {"__type": "System.NullReferenceException", "args": []}
                    if not isinstance(value, dict) or not isinstance(value.get("__type"), str):
                        raise UnsupportedManaged("Invalid managed exception object")
                    self._record_event({"event": "managed_throw", "type": value["__type"]})
                    next_pc, pending = self._route_exception(body, code_base, ins.offset,
                                                             ManagedThrown(value), stack, offsets,
                                                             active_catches)
                elif op == "rethrow":
                    if stack:
                        raise UnsupportedManaged("Managed rethrow requires an empty evaluation stack")
                    regions = [handler for handler in body.exception_handlers
                               if code_base + handler.handler_start <= ins.offset <
                               code_base + handler.handler_end]
                    regions.sort(key=lambda handler: handler.handler_end - handler.handler_start)
                    if not regions or not regions[0].is_catch():
                        raise UnsupportedManaged("Managed rethrow outside a catch handler")
                    catch_start = code_base + regions[0].handler_start
                    original = next((entry[2] for entry in reversed(active_catches)
                                     if entry[0] == catch_start), None)
                    if original is None:
                        raise UnsupportedManaged("Managed rethrow has no active exception")
                    self._record_event({"event": "managed_rethrow",
                                        "type": original.value["__type"]})
                    next_pc, pending = self._route_exception(body, code_base, ins.offset,
                                                             original, stack, offsets, active_catches)
                elif op == "endfinally":
                    if pending is None:
                        raise UnsupportedManaged("Managed endfinally without a pending transfer")
                    stack.clear()
                    remaining = pending["remaining"]
                    if remaining:
                        target = remaining.pop(0)
                        self._record_event({"event": "managed_finally", "reason": "nested",
                                            "handler": target})
                        next_pc = offsets[target]
                    else:
                        target = pending["target"]
                        thrown = pending["thrown"]
                        catch = pending["catch"]
                        pending = None
                        if thrown is not None:
                            if target is None:
                                raise thrown
                            stack.append(thrown.value)
                            if catch is None:
                                raise UnsupportedManaged("Missing managed catch after finally")
                            active_catches.append((target, code_base + catch.handler_end, thrown))
                            self._record_event({"event": "managed_catch",
                                                "type": thrown.value["__type"], "handler": target})
                        next_pc = offsets[target]
                elif op == "ret":
                    if pending is not None or any(
                            code_base + handler.try_start <= ins.offset < code_base + handler.try_end
                            or code_base + handler.handler_start <= ins.offset < code_base + handler.handler_end
                            for handler in body.exception_handlers):
                        raise UnsupportedManaged("Managed ret inside an exception region")
                    return stack.pop() if stack else None
                elif op in {"add", "sub", "mul", "div", "rem", "and", "or", "xor", "shl", "shr"}:
                    right, left = stack.pop(), stack.pop()
                    fn = {"add": operator.add, "sub": operator.sub, "mul": operator.mul,
                          "div": operator.floordiv, "rem": operator.mod, "and": operator.and_,
                          "or": operator.or_, "xor": operator.xor, "shl": operator.lshift,
                          "shr": operator.rshift}[op]
                    stack.append(fn(left, right))
                elif op in {"ceq", "cgt", "clt", "cgt.un"}:
                    right, left = stack.pop(), stack.pop()
                    if op == "cgt.un":
                        if isinstance(left, (int, float)) and isinstance(right, (int, float)):
                            if isinstance(left, float) or isinstance(right, float):
                                comparison = left != left or right != right or left > right
                            else:
                                comparison = (left & ((1 << 64) - 1)) > (right & ((1 << 64) - 1))
                        elif right is None:
                            comparison = left is not None
                        elif left is None:
                            comparison = False
                        else:
                            raise UnsupportedManaged("Unsupported cgt.un object comparison")
                        stack.append(int(comparison))
                    else:
                        stack.append(int({"ceq": operator.eq, "cgt": operator.gt,
                                          "clt": operator.lt}[op](left, right)))
                elif op == "neg":
                    stack.append(-stack.pop())
                elif op == "not":
                    stack.append(~int(stack.pop()))
                elif op.startswith("conv."):
                    value = int(stack.pop())
                    width = {"conv.u1": 8, "conv.i1": 8, "conv.u2": 16, "conv.i2": 16,
                             "conv.u4": 32, "conv.i4": 32, "conv.u8": 64, "conv.i8": 64}.get(op)
                    if width:
                        value &= (1 << width) - 1
                        if op.startswith("conv.i") and value & (1 << (width - 1)):
                            value -= 1 << width
                    stack.append(value)
                elif op in {"br", "br.s", "leave", "leave.s"}:
                    target = int(operand)
                    if target not in offsets:
                        raise UnsupportedManaged("Invalid managed branch target")
                    if op.startswith("leave"):
                        if pending is not None:
                            raise UnsupportedManaged("Managed leave inside finally handler")
                        stack.clear()
                        finalizers = self._finalizers(body, code_base, ins.offset, target)
                        if finalizers:
                            if any(position not in offsets for position in finalizers):
                                raise UnsupportedManaged("Invalid managed finally handler target")
                            self._record_event({"event": "managed_finally", "reason": "leave",
                                                "handler": finalizers[0]})
                            pending = {"remaining": finalizers[1:], "target": target,
                                       "thrown": None, "catch": None}
                            next_pc = offsets[finalizers[0]]
                        else:
                            next_pc = offsets[target]
                    else:
                        next_pc = offsets[target]
                elif op == "switch":
                    index = int(stack.pop()) & 0xFFFFFFFF
                    if not isinstance(operand, list):
                        raise UnsupportedManaged("Invalid managed switch table")
                    if index < len(operand):
                        target = int(operand[index])
                        if target not in offsets:
                            raise UnsupportedManaged("Invalid managed switch target")
                        next_pc = offsets[target]
                elif op in {"brtrue", "brtrue.s", "brfalse", "brfalse.s"}:
                    condition = bool(stack.pop())
                    if condition == op.startswith("brtrue"):
                        next_pc = offsets[int(operand)]
                elif op.removesuffix(".s") in {"beq", "bne.un", "bge", "bge.un", "bgt", "bgt.un",
                                                   "ble", "ble.un", "blt", "blt.un"}:
                    right, left = stack.pop(), stack.pop()
                    branch = op.removesuffix(".s")
                    if branch.endswith(".un") and branch != "bne.un":
                        left, right = int(left) & 0xFFFFFFFFFFFFFFFF, int(right) & 0xFFFFFFFFFFFFFFFF
                    compare = {"beq": operator.eq, "bne.un": operator.ne,
                               "bge": operator.ge, "bge.un": operator.ge,
                               "bgt": operator.gt, "bgt.un": operator.gt,
                               "ble": operator.le, "ble.un": operator.le,
                               "blt": operator.lt, "blt.un": operator.lt}[branch]
                    if compare(left, right):
                        next_pc = offsets[int(operand)]
                elif op == "newarr":
                    length = int(stack.pop())
                    element = self._type_name(int(operand.value))
                    limit = MAX_ARTIFACT if element == "System.Byte" else 1024 * 1024
                    if length < 0 or length > limit:
                        raise UnsupportedManaged(f"Managed array length exceeds limit for {element}")
                    if element == "System.Byte":
                        buffer = bytearray(length)
                        self._track_managed_buffer(buffer)
                        stack.append(buffer)
                    else:
                        stack.append([0] * length)
                elif op == "ldtoken":
                    token = int(operand.value)
                    if token >> 24 != 0x04 or not 1 <= (token & 0xFFFFFF) <= len(self.pe.net.mdtables.Field.rows):
                        raise UnsupportedManaged(f"Unsupported managed ldtoken 0x{token:08x}")
                    stack.append({"__field_token": token})
                elif op == "ldlen":
                    try:
                        stack.append(len(self._checked_array(stack.pop())))
                    except ManagedThrown as thrown:
                        next_pc, pending = self._route_exception(body, code_base, ins.offset,
                                                                 thrown, stack, offsets, active_catches)
                elif op == "ldelema":
                    index, array = int(stack.pop()), stack.pop()
                    try:
                        stack.append({"__ref": self._checked_array(array, index), "index": index})
                    except ManagedThrown as thrown:
                        next_pc, pending = self._route_exception(body, code_base, ins.offset,
                                                                 thrown, stack, offsets, active_catches)
                elif op.startswith("ldind"):
                    reference = stack.pop()
                    if not isinstance(reference, dict) or "__ref" not in reference:
                        raise UnsupportedManaged(f"Invalid managed reference for {op}")
                    value = reference["__ref"][reference["index"]]
                    if op.endswith("u1"):
                        value = int(value) & 0xFF
                    elif op.endswith("i1"):
                        value = (int(value) & 0xFF)
                        if value & 0x80:
                            value -= 0x100
                    stack.append(value)
                elif op.startswith("stind"):
                    value, reference = stack.pop(), stack.pop()
                    if not isinstance(reference, dict) or "__ref" not in reference:
                        raise UnsupportedManaged(f"Invalid managed reference for {op}")
                    if op.endswith("i1"):
                        value = int(value) & 0xFF
                    elif op.endswith("i2"):
                        value = int(value) & 0xFFFF
                    self._capture_before_buffer_mutation(reference["__ref"], reference["index"])
                    reference["__ref"][reference["index"]] = value
                elif op.startswith("stelem"):
                    value, index, array = stack.pop(), int(stack.pop()), stack.pop()
                    try:
                        array = self._checked_array(array, index)
                        if isinstance(array, bytes):
                            raise UnsupportedManaged("Immutable managed array value")
                        self._capture_before_buffer_mutation(array, index)
                        array[index] = int(value) & 0xFF if isinstance(array, bytearray) else value
                    except ManagedThrown as thrown:
                        next_pc, pending = self._route_exception(body, code_base, ins.offset,
                                                                 thrown, stack, offsets, active_catches)
                elif op.startswith("ldelem"):
                    index, array = int(stack.pop()), stack.pop()
                    try:
                        array = self._checked_array(array, index)
                        value = array[index]
                        if op == "ldelem.i1" and isinstance(array, (bytes, bytearray)) and value & 0x80:
                            value -= 0x100
                        stack.append(value)
                    except ManagedThrown as thrown:
                        next_pc, pending = self._route_exception(body, code_base, ins.offset,
                                                                 thrown, stack, offsets, active_catches)
                else:
                    raise UnsupportedManaged(f"Unsupported IL {op} in {method.Name} at 0x{ins.offset:x}")
                pc = next_pc
            return None
        finally:
            self.depth -= 1

    def run(self, run_dir: Path) -> dict:
        token = int(self.pe.net.struct.EntryPointTokenOrRva)
        if token >> 24 != 0x06:
            raise UnsupportedManaged("Managed entry point is not a MethodDef")
        entry_result = None
        try:
            try:
                self._ensure_type_initialized(self._method_owner(self.pe, token & 0xFFFFFF),
                                              field_access=False)
                entry_result = self._execute(token & 0xFFFFFF, [self.guest_args])
            except ManagedThrown as exc:
                self.error = f"Unhandled managed exception: {exc}"
            except (UnsupportedManaged, IndexError, KeyError, ValueError, TypeError, OSError) as exc:
                self.error = str(exc)
        finally:
            self.network.close()
        for index, buffer in enumerate(self.managed_pe_buffers):
            if len(buffer) >= 512 and b"MZ" in buffer:
                self.catalog.carve_pe(bytes(buffer), f"managed_array:{index}")
        self.catalog.save_manifest()
        top_opcodes = sorted(self.opcode_counts.items(), key=lambda item: (-item[1], item[0]))[:100]
        top_framework = sorted(self.framework_call_counts.items(),
                               key=lambda item: (-item[1], item[0]))[:100]
        opcode_attempts = sum(self.opcode_counts.values())
        framework_calls = sum(self.framework_call_counts.values()) + self.untracked_framework_calls
        coverage = {
            "opcode_attempts": opcode_attempts,
            "tracked_opcodes": len(self.opcode_counts),
            "top_opcodes": [{"opcode": name[:128], "count": count}
                            for name, count in top_opcodes],
            "other_opcode_attempts": opcode_attempts - sum(count for _, count in top_opcodes),
            "framework_calls": framework_calls,
            "tracked_framework_methods": len(self.framework_call_counts),
            "top_framework_calls": [{"method": name, "count": count}
                                    for name, count in top_framework],
            "other_framework_calls": framework_calls - sum(count for _, count in top_framework),
            "untracked_framework_calls": self.untracked_framework_calls,
        }
        report = {"engine": "emumee-cil", "entry_point": f"0x{token:08x}",
                  "instructions": self.instructions, "events": self.events,
                  "network_events": self.network.events,
                  "stdout": self.stdout, "console_output": self.console_output.report(),
                  "error": self.error,
                  "instruction_limit_reached": self.error == "Managed instruction budget exhausted",
                  "guest_exit_code": (entry_result & 0xFFFFFFFF)
                                     if type(entry_result) is int else None,
                  "guest_entry_return": (entry_result & 0xFFFFFFFF)
                                        if type(entry_result) is int else None,
                  "artifacts": self.catalog.items,
                  "artifact_capture": self.catalog.capture_summary(),
                  "cil_coverage": coverage,
                  "aes_plaintext_capture": self._aes_plaintext_capture_report()}
        (run_dir / "engine-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        return {"engine": "emumee-cil", "engine_report": "engine-report.json",
                "artifacts": self.catalog.items, "entry_points": 1,
                "artifact_groups": self.catalog.groups(),
                "artifact_capture": self.catalog.capture_summary(),
                "cil_coverage": coverage,
                "aes_plaintext_capture": self._aes_plaintext_capture_report(),
                "console_output": self.console_output.report(),
                "instruction_count": self.instructions,
                "instruction_limit_reached": self.error == "Managed instruction budget exhausted",
                "guest_exit_code": (entry_result & 0xFFFFFFFF)
                                   if type(entry_result) is int else None,
                "guest_entry_return": (entry_result & 0xFFFFFFFF)
                                      if type(entry_result) is int else None,
                "completion_reason": ("entry_return" if self.error is None else
                                      "instruction_limit" if self.error ==
                                      "Managed instruction budget exhausted" else "error"),
                "denied_operations": sum(event.get("event") == "network_denied"
                                         for event in self.network.events),
                "errors": [self.error] if self.error else []}


def run_managed(data: bytes, info: SampleInfo, persona: dict, run_dir: Path,
                max_instructions: int, companions: list[tuple[str, bytes]] | None = None,
                guest_args: list[str] | None = None,
                guest_env: dict[str, str] | None = None,
                bundle_files: list[tuple[str, bytes]] | None = None,
                bundle_guest_root: str | None = None) -> dict:
    return ManagedRunner(data, info, persona, run_dir, max_instructions,
                         companions=companions, guest_args=guest_args,
                         guest_env=guest_env, bundle_files=bundle_files,
                         bundle_guest_root=bundle_guest_root).run(run_dir)

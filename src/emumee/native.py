"""Run native PE bytes entirely in a modeled Windows user-mode process."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import ntpath
import re
import shutil
import struct
import zlib
from pathlib import Path

import speakeasy
import pefile
from speakeasy.profiler import Run
from speakeasy.windows.loaders import PeLoader
from speakeasy.winenv.arch import CALL_CONV_STDCALL

from .artifacts import ArtifactCatalog, MAX_ARTIFACT, MAX_MEMORY_SCAN
from .clock import VirtualClock
from .console_output import ConsoleOutput
from .crt import LegacyCRTStreams
from .crt_startup import CRTStartup, process_argv
from .winenvironment import GuestEnvironmentBlocks
from .heap_checks import GuestHeapChecks
from .network_adapter import GuestNetworkAdapter
from .feature_config import GuestFeatureConfiguration
from .cpu import VirtualCPU
from .identity import GuestIdentity
from .audit import GuestAudit
from .guest_programs import hostname_exe
from .enumeration_programs import enumeration_programs
from .network import NetworkBridge
from .pe import InvalidSample, SampleInfo, inspect_pe
from .persona import make_speakeasy_config, materialize_virtual_files
from .persona_content import desktop_directories, oem_code_page
from .virtualfs import VirtualFileBridge
from .virtualprocess import (PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
                             VirtualProcessBridge)
from .virtualregistry import VirtualRegistryBridge
from .ui_language import ThreadUILanguage
from .winmessages import WinMessages
from .version_info import GuestVersionInfo
from .winstrings import GuestStrings
from .delay_imports import GuestDelayImports
from .tokens import GuestTokens
from .lsa import GuestLSA


SIGNATURE_ARGUMENT = re.compile(r"^(?![A-Z][A-Z_0-9]*: )[A-Za-z_][A-Za-z_0-9]*: \S")
MAX_GUEST_DLLS = 32
STATUS_SUCCESS = 0
STATUS_ACCESS_VIOLATION = 0xC0000005
STATUS_INVALID_PARAMETER = 0xC000000D
STATUS_NOT_SUPPORTED = 0xC00000BB
STATUS_PROCEDURE_NOT_FOUND = 0xC000007A
STATUS_DLL_NOT_FOUND = 0xC0000135
STATUS_DLL_INIT_FAILED = 0xC0000142


class _PositionedEvents(list):
    """Stamp virtual side effects at the guest instruction that produced them."""

    def __init__(self, emulator, sequence: list[int]):
        super().__init__()
        self.emulator = emulator
        self.sequence = sequence

    def append(self, event):
        if isinstance(event, dict) and "pos" not in event:
            try:
                engine = self.emulator.emu
                run = engine.get_current_run() if engine is not None else None
                if run is not None:
                    thread = engine.get_current_thread()
                    process = engine.get_current_process()
                    try:
                        pc = int(engine.get_pc())
                    except Exception:
                        pc = None
                    event["pos"] = {
                        "tick": int(run.instr_cnt),
                        "tid": int(thread.tid) if thread is not None else 0,
                        "pid": int(process.id) if process is not None else 0,
                        "pc": pc,
                    }
                    if process is not None and getattr(process, "pid", None) is not None:
                        event["guest_pid"] = int(process.pid)
                    self.sequence[0] += 1
                    event["capture_sequence"] = self.sequence[0]
            except Exception:
                pass  # Evidence capture must not change guest execution.
        super().append(event)


def _has_supported_base_relocations(parsed: pefile.PE) -> bool:
    """Accept bounded PE relocation blocks using fixups handled by pefile."""
    image_size = int(parsed.OPTIONAL_HEADER.SizeOfImage)
    directories = parsed.OPTIONAL_HEADER.DATA_DIRECTORY
    if len(directories) <= 5:
        return False
    directory = directories[5]
    rva, size = int(directory.VirtualAddress), int(directory.Size)
    if (int(parsed.FILE_HEADER.Characteristics) & 0x0001 or
            not 0 < image_size <= MAX_MEMORY_SCAN or
            not 0 < rva < image_size or
            not 8 <= size <= MAX_ARTIFACT or size > image_size - rva):
        return False
    if int(parsed.FILE_HEADER.Machine) not in (0x14C, 0x8664):
        return False
    supported_widths = {1: 2, 2: 2, 3: 4, 4: 2, 10: 8}
    try:
        data = parsed.get_data(rva, size)
    except (pefile.PEFormatError, ValueError, OverflowError):
        return False
    if len(data) != size:
        return False
    cursor = 0
    found_fixup = False
    while cursor < size:
        if size - cursor < 8:
            return False
        page_rva, block_size = struct.unpack_from("<II", data, cursor)
        if (page_rva % 0x1000 or page_rva >= image_size or
                block_size < 8 or block_size % 4 or block_size > size - cursor):
            return False
        entry_offset = cursor + 8
        while entry_offset < cursor + block_size:
            entry = struct.unpack_from("<H", data, entry_offset)[0]
            kind, offset = entry >> 12, entry & 0xFFF
            entry_offset += 2
            if kind == 0:  # IMAGE_REL_BASED_ABSOLUTE padding
                continue
            width = supported_widths.get(kind)
            if width is None or page_rva + offset + width > image_size:
                return False
            if kind == 4:  # HIGHADJ consumes the following WORD as an addend.
                if entry_offset >= cursor + block_size:
                    return False
                entry_offset += 2
            found_fixup = True
        cursor += block_size
    return found_fixup


def _resolve_loaded_export(emu, module, name: str, *, load_missing=None,
                           on_forward=None, is_visible=None) -> int:
    """Follow a bounded PE export forwarder through loaded guest modules."""
    visited: set[tuple[int, str]] = set()
    for _depth in range(8):
        key = (int(module.base), name)
        if key in visited:
            raise ValueError("Cyclic DLL export forwarder")
        visited.add(key)
        export = next((item for item in module.get_exports()
                       if item.name == name or name == f"ordinal_{item.ordinal}"), None)
        if export is None:
            raise ValueError(f"DLL export absent: {module.name}.{name}")
        address = int(export.address)
        parsed = getattr(getattr(module._image, "loader", None), "_pe_obj", None)
        if parsed is None:
            return address
        directories = parsed.OPTIONAL_HEADER.DATA_DIRECTORY
        if not directories:
            return address
        directory = directories[0]
        rva, size = int(directory.VirtualAddress), int(directory.Size)
        if (not 0 < rva < int(module.image_size) or
                not 0 < size <= int(module.image_size) - rva):
            raise ValueError("Invalid DLL export directory")
        start = int(module.base) + rva
        end = start + size
        if not start <= address < end:
            return address
        count = min(128, end - address)
        if count < 4:
            raise ValueError("Invalid DLL export forwarder")
        try:
            raw = emu.mem_read(address, count)
        except Exception as exc:
            raise ValueError("Unreadable DLL export forwarder") from exc
        terminator = raw.find(b"\0")
        if terminator < 3:
            raise ValueError("Invalid DLL export forwarder")
        try:
            forwarder = raw[:terminator].decode("ascii")
        except UnicodeDecodeError as exc:
            raise ValueError("Invalid DLL export forwarder") from exc
        if "." not in forwarder:
            raise ValueError("Invalid DLL export forwarder")
        target_name, symbol = forwarder.rsplit(".", 1)
        if (not re.fullmatch(r"[A-Za-z0-9_$.-]{1,64}", target_name) or
                not re.fullmatch(r"[A-Za-z0-9_?$@-]{1,64}|#[1-9][0-9]{0,4}", symbol)):
            raise ValueError("Invalid DLL export forwarder")
        stem = target_name.lower().removesuffix(".dll")
        target = next((item for item in emu.modules
                       if ntpath.splitext(ntpath.basename(str(item.name)))[0].lower() == stem
                       and (is_visible is None or is_visible(item))), None)
        if target is None and load_missing is not None:
            target = load_missing(module, stem)
        if target is None:
            raise ValueError(f"Forwarded DLL target not loaded: {stem}")
        if on_forward is not None:
            on_forward(module, target)
        module = target
        name = f"ordinal_{symbol[1:]}" if symbol.startswith("#") else symbol
    raise ValueError("DLL export forwarder depth exceeded")


def _api_coverage(report: dict) -> dict:
    """Summarize observed API names and signature-only fallbacks, with bounds."""
    total = 0
    observed: dict[str, int] = {}
    signature_only: dict[str, int] = {}
    for entry in report.get("entry_points") or []:
        for event in entry.get("events") or []:
            if event.get("event") != "api":
                continue
            total += 1
            name = str(event.get("api_name") or "unknown")[:256]
            observed[name] = observed.get(name, 0) + 1
            args = event.get("args") or []
            if any(isinstance(arg, str) and SIGNATURE_ARGUMENT.match(arg) for arg in args):
                signature_only[name] = signature_only.get(name, 0) + 1
    top = sorted(observed.items(), key=lambda item: (-item[1], item[0]))[:100]
    return {"api_calls": total, "observed_apis": len(observed),
            "observed_calls": [{"api": name, "count": count,
                                "signature_only_count": signature_only.get(name, 0)}
                               for name, count in top],
            "other_calls": total - sum(count for _, count in top),
            "signature_only_calls": [
        {"api": name, "count": count} for name, count in sorted(signature_only.items())
    ]}


def _primary_exit_code(entry_points: list[dict], process_events: list[dict]) -> int | None:
    primary_pid = next((entry.get("guest_pid") for entry in entry_points
                        if type(entry.get("guest_pid")) is int), None)
    exits = [event["exit_code"] for event in process_events
             if event.get("event") == "virtual_process_exit"
             and type(event.get("exit_code")) is int
             and event.get("pid") == primary_pid]
    return exits[-1] if exits else None


def _primary_entry_return(entry_points: list[dict]) -> int | None:
    primary = next((entry for entry in entry_points
                    if entry.get("ep_type") == "module_entry"), None)
    if primary is None or primary.get("error"):
        return None
    value = primary.get("ret_val")
    try:
        result = int(value, 0) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None
    return result & 0xFFFFFFFF


def _engine_error_text(error: object) -> str:
    """Keep structured engine faults in the engine report, not the summary envelope."""
    if isinstance(error, str):
        return error[:1024]
    if not isinstance(error, dict):
        return "Native emulation error with unrecognized detail"
    parts = ["Native emulation error"]
    for key, limit in (("type", 80), ("pc", 64), ("context_summary", 760)):
        value = error.get(key)
        if isinstance(value, str) and value:
            clean = "".join(char if char.isprintable() else " " for char in value[:limit])
            parts.append(clean)
    return ": ".join(parts)[:1024]


def _report_blob(store: dict, ref: str) -> bytes | None:
    item = store.get(ref)
    if not item or item.get("encoding") != "base64" or item.get("size", 0) > 32 * 1024 * 1024:
        return None
    raw = base64.b64decode(item["data"], validate=True)
    if item.get("compression") == "zlib":
        decompressor = zlib.decompressobj()
        data = decompressor.decompress(raw, 32 * 1024 * 1024 + 1)
        if not decompressor.eof:
            return None
    elif item.get("compression") in ("none", None):
        data = raw
    else:
        return None
    if len(data) != item["size"] or hashlib.sha256(data).hexdigest() != ref:
        return None
    return data


def _read_nt_counted_string(emu, address: int, *, wide: bool) -> str:
    """Read a bounded guest UNICODE_STRING or ANSI_STRING by its byte length."""
    if not address:
        raise ValueError("null counted string")
    pointer_size = emu.get_ptr_size()
    header_size = 16 if pointer_size == 8 else 8
    header = emu.mem_read(address, header_size)
    length, maximum = struct.unpack_from("<HH", header)
    pointer = struct.unpack_from("<Q" if pointer_size == 8 else "<I",
                                 header, 8 if pointer_size == 8 else 4)[0]
    if (not 0 < length <= 4096 or maximum < length or maximum > 4096 or
            not pointer or (wide and (length % 2 or maximum % 2))):
        raise ValueError("invalid counted string bounds")
    raw = emu.mem_read(pointer, length)
    value = raw.decode("utf-16le" if wide else "latin-1")
    if "\0" in value:
        raise ValueError("embedded NUL in counted string")
    return value


def _enter_companion_dllmain(emu, module, events: list[dict], load_argc: int,
                             on_failure=None) -> None:
    """Tail into guest DllMain and resume its LoadLibrary caller afterward."""
    if not module.ep:
        return
    original_return = emu.get_ret_address()
    base = int(module.base)
    is_x64 = emu.get_ptr_size() == 8
    if is_x64:
        # DllMain returns to this guest stub, which restores LoadLibrary's HMODULE.
        success = b"\x48\xb8" + struct.pack("<Q", base)
        jump_back = b"\x49\xbb" + struct.pack("<Q", original_return) + b"\x41\xff\xe3"
        failure = b"\x31\xc0" + jump_back
        code = b"\x85\xc0\x74" + bytes([len(success + jump_back)]) + success + jump_back + failure
    else:
        success = b"\xb8" + struct.pack("<I", base) + b"\x68" + struct.pack("<I", original_return) + b"\xc3"
        failure = b"\x31\xc0\x68" + struct.pack("<I", original_return) + b"\xc3"
        code = b"\x85\xc0\x74" + bytes([len(success)]) + success + failure
    trampoline = emu.mem_map(0x1000, tag="emu.dll_init_trampoline")
    emu.mem_write(trampoline, code)
    hook_ref = [None]

    def completed(active_emu, _address, _size):
        success = bool(active_emu.reg_read("eax"))
        events.append({"event": "dll_process_attach", "module": module.name,
                       "base": hex(base), "success": success})
        hook_ref[0].disable()
        if not success and on_failure is not None:
            _enter_guest_detach(active_emu, module, events, on_failure,
                                original_return=original_return,
                                frame_consumed=True, return_value=0)
        return True

    hook_ref[0] = emu.add_code_hook(completed, begin=trampoline, end=trampoline + 1)
    sp = emu.get_stack_ptr()
    if is_x64:
        emu.mem_write(sp, struct.pack("<Q", trampoline))
        emu.reg_write("rcx", base)
        emu.reg_write("rdx", 1)  # DLL_PROCESS_ATTACH
        emu.reg_write("r8", 0)
    else:
        # stdcall DllMain ret 12 leaves ESP where the loader API would.
        call_sp = sp + 4 * load_argc - 12
        emu.mem_write(call_sp, struct.pack("<IIII", trampoline, base, 1, 0))
        emu.set_stack_ptr(call_sp)
    emu.set_pc(base + int(module.ep))


def _enter_companion_with_tls(emu, module, events: list[dict], load_argc: int,
                              on_failure=None) -> None:
    """Call a companion's TLS callbacks and entry point in the guest CPU."""
    base = int(module.base)
    callbacks = [int(addr) for addr in module.get_tls_callbacks()
                 if base < int(addr) < base + int(module.image_size)][:100]
    if not callbacks:
        _enter_companion_dllmain(emu, module, events, load_argc, on_failure)
        return

    is_x64 = emu.get_ptr_size() == 8
    original_return = emu.get_ret_address()
    code = bytearray()

    def call_guest(address: int) -> None:
        if is_x64:
            code.extend(b"\x48\xb9" + struct.pack("<Q", base))  # rcx = HMODULE
            code.extend(b"\xba\x01\x00\x00\x00\x45\x31\xc0")  # edx = attach, r8d = 0
            code.extend(b"\x48\xb8" + struct.pack("<Q", address) + b"\xff\xd0")
        else:
            code.extend(b"\x6a\x00\x6a\x01\x68" + struct.pack("<I", base))
            code.extend(b"\xb8" + struct.pack("<I", address) + b"\xff\xd0")

    if is_x64:
        code.extend(b"\x48\x83\xec\x20")  # Windows x64 shadow space.
    callback_offsets = []
    for callback in callbacks:
        callback_offsets.append(len(code))
        call_guest(callback)
    if module.ep:
        call_guest(base + int(module.ep))
    check_offset = len(code)
    if is_x64:
        code.extend(b"\x48\x83\xc4\x20")
        success = (b"\x48\xb8" + struct.pack("<Q", base)
                   + b"\x49\xbb" + struct.pack("<Q", original_return) + b"\x41\xff\xe3")
        failure = b"\x31\xc0\x49\xbb" + struct.pack("<Q", original_return) + b"\x41\xff\xe3"
    else:
        success = b"\xb8" + struct.pack("<I", base) + b"\x68" + struct.pack("<I", original_return) + b"\xc3"
        failure = b"\x31\xc0\x68" + struct.pack("<I", original_return) + b"\xc3"
    if module.ep:
        code.extend(b"\x85\xc0\x74" + bytes([len(success)]))
    code.extend(success)
    if module.ep:
        code.extend(failure)

    bootstrap = emu.mem_map(0x1000, tag="emu.dll_tls_bootstrap")
    emu.mem_write(bootstrap, bytes(code))
    hooks = []

    for index, offset in enumerate(callback_offsets):
        def started(active_emu, _address, _size, index=index):
            events.append({"event": "dll_tls_callback", "module": module.name,
                           "base": hex(base), "index": index})
            return True
        hooks.append(emu.add_code_hook(started, begin=bootstrap + offset,
                                       end=bootstrap + offset + 1))

    if module.ep:
        def completed(active_emu, _address, _size):
            success = bool(active_emu.reg_read("eax"))
            events.append({"event": "dll_process_attach", "module": module.name,
                           "base": hex(base), "success": success})
            if not success and on_failure is not None:
                if is_x64:
                    active_emu.set_stack_ptr(active_emu.get_stack_ptr() + 0x20)
                _enter_guest_detach(active_emu, module, events, on_failure,
                                    original_return=original_return,
                                    frame_consumed=True, return_value=0)
            return True
        hooks.append(emu.add_code_hook(completed, begin=bootstrap + check_offset,
                                       end=bootstrap + check_offset + 1))
    # Keep hook objects alive until the emulated run finishes.
    emu._emumee_tls_hooks = getattr(emu, "_emumee_tls_hooks", []) + hooks
    emu.set_stack_ptr(emu.get_stack_ptr() + (8 if is_x64 else 4 + 4 * load_argc))
    emu.set_pc(bootstrap)


def _enter_dll_chain(emu, modules: list, result_module, events: list[dict],
                     load_argc: int, on_failure=None,
                     result_address: int | None = None) -> None:
    """Initialize mapped dependencies before the requested DLL, in guest CPU."""
    original_return = emu.get_ret_address()
    is_x64 = emu.get_ptr_size() == 8
    code = bytearray(b"\x48\x83\xec\x20" if is_x64 else b"")
    callback_offsets: list[tuple[int, object, int]] = []
    entry_offsets: list[tuple[int, object]] = []
    failure_patches: list[tuple[int, int]] = []
    detach_callback_offsets: list[tuple[int, object, int]] = []
    detach_entry_offsets: list[tuple[int, object]] = []
    cleanup_offsets: list[int] = []

    def call_guest(module, address: int, reason: int = 1) -> None:
        base = int(module.base)
        if is_x64:
            code.extend(b"\x48\xb9" + struct.pack("<Q", base))
            code.extend(b"\xba" + struct.pack("<I", reason) + b"\x45\x31\xc0")
            code.extend(b"\x48\xb8" + struct.pack("<Q", address) + b"\xff\xd0")
        else:
            code.extend(b"\x6a\0\x6a" + bytes([reason])
                        + b"\x68" + struct.pack("<I", base))
            code.extend(b"\xb8" + struct.pack("<I", address) + b"\xff\xd0")

    for module_index, module in enumerate(modules):
        base = int(module.base)
        callbacks = [int(address) for address in module.get_tls_callbacks()
                     if base < int(address) < base + int(module.image_size)][:100]
        for index, address in enumerate(callbacks):
            callback_offsets.append((len(code), module, index))
            call_guest(module, address)
        if module.ep:
            call_guest(module, base + int(module.ep))
            entry_offsets.append((len(code), module))
            code.extend(b"\x85\xc0\x0f\x84\0\0\0\0")
            failure_patches.append((len(code) - 4, module_index))

    def return_to_caller(success: bool) -> None:
        value = int(result_module.base if result_address is None else result_address)
        if is_x64:
            code.extend(b"\x48\x83\xc4\x20")
            code.extend((b"\x48\xb8" + struct.pack("<Q", value))
                        if success else b"\x31\xc0")
            code.extend(b"\x49\xbb" + struct.pack("<Q", original_return) + b"\x41\xff\xe3")
        else:
            code.extend((b"\xb8" + struct.pack("<I", value))
                        if success else b"\x31\xc0")
            code.extend(b"\x68" + struct.pack("<I", original_return) + b"\xc3")

    return_to_caller(True)
    for patch, failed_index in failure_patches:
        failure_offset = len(code)
        struct.pack_into("<i", code, patch, failure_offset - patch - 4)
        for attached in reversed(modules[:failed_index + 1]):
            attached_base = int(attached.base)
            callbacks = [int(address) for address in attached.get_tls_callbacks()
                         if attached_base < int(address) < attached_base + int(attached.image_size)][:100]
            for index, address in enumerate(callbacks):
                detach_callback_offsets.append((len(code), attached, index))
                call_guest(attached, address, 0)
            if attached.ep:
                call_guest(attached, attached_base + int(attached.ep), 0)
                detach_entry_offsets.append((len(code), attached))
        cleanup_offsets.append(len(code))
        return_to_caller(False)
    if len(code) > 0x1000:
        raise ValueError("DLL initialization chain exceeds guest bootstrap page")
    bootstrap = emu.mem_map(0x1000, tag="emu.dll_dependency_bootstrap")
    emu.mem_write(bootstrap, bytes(code))
    hooks = []
    for offset, module, index in callback_offsets:
        def started(_active_emu, _address, _size, module=module, index=index):
            events.append({"event": "dll_tls_callback", "module": module.name,
                           "base": hex(module.base), "index": index})
            return True
        hooks.append(emu.add_code_hook(started, begin=bootstrap + offset,
                                       end=bootstrap + offset + 1))
    for offset, module in entry_offsets:
        def completed(active_emu, _address, _size, module=module):
            events.append({"event": "dll_process_attach", "module": module.name,
                           "base": hex(module.base),
                           "success": bool(active_emu.reg_read("eax"))})
            return True
        hooks.append(emu.add_code_hook(completed, begin=bootstrap + offset,
                                       end=bootstrap + offset + 1))
    for offset, module, index in detach_callback_offsets:
        def started_detach(_active_emu, _address, _size, module=module, index=index):
            events.append({"event": "dll_tls_detach", "module": module.name,
                           "base": hex(module.base), "index": index})
            return True
        hooks.append(emu.add_code_hook(started_detach, begin=bootstrap + offset,
                                       end=bootstrap + offset + 1))
    for offset, module in detach_entry_offsets:
        def completed_detach(_active_emu, _address, _size, module=module):
            events.append({"event": "dll_process_detach", "module": module.name,
                           "base": hex(module.base)})
            return True
        hooks.append(emu.add_code_hook(completed_detach, begin=bootstrap + offset,
                                       end=bootstrap + offset + 1))
    if on_failure is not None:
        for offset in cleanup_offsets:
            def cleaned(active_emu, _address, _size):
                on_failure(active_emu, modules)
                return True
            hooks.append(emu.add_code_hook(cleaned, begin=bootstrap + offset,
                                           end=bootstrap + offset + 1))
    emu._emumee_tls_hooks = getattr(emu, "_emumee_tls_hooks", []) + hooks
    emu.set_stack_ptr(emu.get_stack_ptr() + (8 if is_x64 else 4 + 4 * load_argc))
    emu.set_pc(bootstrap)


def _remove_guest_module(emu, module) -> None:
    """Remove a dynamically loaded guest image from CPU and loader views."""
    process = emu.get_current_process()
    entries = process.ldr_entries
    entries[:] = [entry for entry in entries if entry.object.DllBase != module.base]
    if entries:
        width = process.sizeof(process.nt_types.LIST_ENTRY(emu.get_ptr_size()))
        first, last = entries[0], entries[-1]
        for index, entry in enumerate(entries):
            previous = entries[index - 1]
            following = entries[(index + 1) % len(entries)]
            for offset, field in ((0, "InLoadOrderLinks"),
                                  (width, "InMemoryOrderLinks"),
                                  (2 * width, "InInitializationOrderLinks")):
                link = getattr(entry.object, field)
                link.Flink = following.address + offset
                link.Blink = previous.address + offset
            if index == 0:
                entry.object.InInitializationOrderLinks.Blink = 0 if len(entries) == 1 else last.address + 2 * width
            if index == len(entries) - 1:
                entry.object.InInitializationOrderLinks.Flink = 0 if len(entries) == 1 else first.address + 2 * width
            entry.write_back()
        ldr = process.peb_ldr_data
        for offset, field in ((0, "InLoadOrderModuleList"),
                              (width, "InMemoryOrderModuleList"),
                              (2 * width, "InInitializationOrderModuleList")):
            link = getattr(ldr.object, field)
            link.Flink = first.address + offset
            link.Blink = last.address + offset
        ldr.object.InInitializationOrderModuleList.Flink = (
            entries[1].address + 2 * width if len(entries) > 1 else 0)
        ldr.write_back()
    emu.modules.remove(module)
    mapping = emu.get_address_map(module.base)
    if mapping is not None:
        emu.mem_unmap(mapping.block_base, mapping.block_size)
        emu.maps.remove(mapping)


def _enter_guest_detach(emu, module, events: list[dict], cleanup, *,
                        original_return: int | None = None,
                        frame_consumed: bool = False,
                        return_value: int = 1) -> None:
    """Run TLS and DllMain detach in guest CPU before removing the DLL."""
    base = int(module.base)
    if original_return is None:
        original_return = emu.get_ret_address()
    is_x64 = emu.get_ptr_size() == 8
    callbacks = [int(address) for address in module.get_tls_callbacks()
                 if base < int(address) < base + int(module.image_size)][:100]
    code = bytearray(b"\x48\x83\xec\x20" if is_x64 else b"")
    callbacks_at = []

    def call_guest(address: int) -> None:
        if is_x64:
            code.extend(b"\x48\xb9" + struct.pack("<Q", base))
            code.extend(b"\x31\xd2\x45\x31\xc0")
            code.extend(b"\x48\xb8" + struct.pack("<Q", address) + b"\xff\xd0")
        else:
            code.extend(b"\x6a\0\x6a\0\x68" + struct.pack("<I", base))
            code.extend(b"\xb8" + struct.pack("<I", address) + b"\xff\xd0")

    for index, address in enumerate(callbacks):
        callbacks_at.append((len(code), index))
        call_guest(address)
    if module.ep:
        call_guest(base + int(module.ep))
    cleanup_at = len(code)
    if is_x64:
        code.extend(b"\x48\x83\xc4\x20\xb8" + struct.pack("<I", return_value))
        code.extend(b"\x49\xbb" + struct.pack("<Q", original_return) + b"\x41\xff\xe3")
    else:
        code.extend(b"\xb8" + struct.pack("<I", return_value)
                    + b"\x68" + struct.pack("<I", original_return) + b"\xc3")
    trampoline = emu.mem_map(0x1000, tag="emu.dll_detach_bootstrap")
    emu.mem_write(trampoline, bytes(code))
    hooks = []
    for offset, index in callbacks_at:
        def started(_active_emu, _address, _size, index=index):
            events.append({"event": "dll_tls_detach", "module": module.name,
                           "base": hex(base), "index": index})
            return True
        hooks.append(emu.add_code_hook(started, begin=trampoline + offset,
                                       end=trampoline + offset + 1))

    def completed(active_emu, _address, _size):
        events.append({"event": "dll_process_detach", "module": module.name,
                       "base": hex(base)})
        cleanup(active_emu, module)
        return True

    hooks.append(emu.add_code_hook(completed, begin=trampoline + cleanup_at,
                                   end=trampoline + cleanup_at + 1))
    emu._emumee_tls_hooks = getattr(emu, "_emumee_tls_hooks", []) + hooks
    if not frame_consumed:
        emu.set_stack_ptr(emu.get_stack_ptr() + 8)
    emu.set_pc(trampoline)


def run_native(
    data: bytes,
    info: SampleInfo,
    persona: dict,
    run_dir: Path,
    bundled_dlls: list[Path],
    timeout: int,
    max_instructions: int,
    guest_args: list[str] | None = None,
    guest_env: dict[str, str] | None = None,
    bundle_files: list[tuple[str, Path, bytes]] | None = None,
    bundle_guest_root: str | None = None,
    companion_guest_paths: dict[str, str] | None = None,
    emulate_exports: bool = False,
    quoted_arg_indices: list[int] | None = None,
) -> dict:
    cfg = make_speakeasy_config(persona, info.name, timeout, max_instructions,
                                guest_args, guest_env, quoted_arg_indices)
    persona_sources = {}
    for guest_path, host_path in materialize_virtual_files(
            persona, run_dir / "persona-files"):
        cfg["filesystem"]["files"].insert(0, {
            "mode": "full_path", "emu_path": guest_path, "path": str(host_path)
        })
        persona_sources[str(host_path)] = host_path.read_bytes()
    program_dir = run_dir / "persona-programs"
    program_dir.mkdir(parents=True, exist_ok=True)
    generated_programs = {
        "hostname.exe": hostname_exe(info.architecture == "x64"),
    }
    generated_programs.update(enumeration_programs(
        info.architecture == "x64", persona))
    for name, payload in generated_programs.items():
        host_path = program_dir / name
        host_path.write_bytes(payload)
        cfg["filesystem"]["files"].insert(0, {
            "mode": "full_path", "emu_path": r"C:\Windows\System32" + "\\" + name,
            "path": str(host_path),
        })
        if name == "wmic.exe":
            cfg["filesystem"]["files"].insert(0, {
                "mode": "full_path", "emu_path": r"C:\Windows\System32\Wbem\wmic.exe",
                "path": str(host_path),
            })
        persona_sources[str(host_path)] = payload
    input_dir = run_dir / "inputs"
    input_dir.mkdir(parents=True, exist_ok=True)
    mapped_guest_paths: set[str] = set()
    for relative, source, payload in bundle_files or []:
        guest_path = ntpath.normpath(ntpath.join(
            bundle_guest_root or persona["current_dir"], relative.replace("/", "\\")))
        cfg["filesystem"]["files"].insert(0, {
            "mode": "full_path", "emu_path": guest_path, "path": str(source)})
        persona_sources[str(source)] = payload
        mapped_guest_paths.add(guest_path.casefold())
    cfg["modules"]["module_directory_x86"] = str(input_dir)
    cfg["modules"]["module_directory_x64"] = str(input_dir)
    cfg["modules"]["modules_always_exist"] = True
    companion_images: dict[str, tuple[int, int]] = {}
    companion_relocations: dict[str, bool] = {}
    companion_paths: dict[str, str] = {}
    # Only explicitly named companion files are visible to guest filesystem APIs.
    for dll in bundled_dlls:
        destination = input_dir / dll.name
        if dll.resolve() != destination.resolve():
            shutil.copyfile(dll, destination)
        dll = destination
        persona_sources[str(dll)] = dll.read_bytes()
        guest_path = ntpath.normpath((companion_guest_paths or {}).get(
            dll.name, persona["current_dir"] + "\\" + dll.name))
        if guest_path.casefold() not in mapped_guest_paths:
            cfg["filesystem"]["files"].insert(0, {
                "mode": "full_path", "emu_path": guest_path, "path": str(dll)})
            mapped_guest_paths.add(guest_path.casefold())
        parsed = pefile.PE(str(dll), fast_load=True)
        companion_images[dll.stem.lower()] = (
            int(parsed.OPTIONAL_HEADER.ImageBase), int(parsed.OPTIONAL_HEADER.SizeOfImage))
        companion_relocations[dll.stem.lower()] = _has_supported_base_relocations(parsed)
        companion_paths[dll.stem.lower()] = guest_path.casefold()
        parsed.close()
    catalog = ArtifactCatalog(run_dir / "artifacts", checkpoint=True)
    catalog.carve_pe(data, "embedded_input", skip_offset_zero=True)
    # Speakeasy's command-line fallback uses shlex(posix=False), which keeps
    # quotes around Windows arguments containing spaces. Supply the parsed
    # guest arguments separately while retaining the Win32 command-line text.
    se = speakeasy.Speakeasy(config=cfg, argv=list(guest_args or []))
    version_images = {ntpath.join(persona["current_dir"], info.name): data}
    for mapped in cfg["filesystem"]["files"]:
        source_bytes = persona_sources.get(str(mapped.get("path", "")))
        if source_bytes is not None and mapped.get("mode") == "full_path":
            version_images[mapped["emu_path"]] = source_bytes
    version_info = GuestVersionInfo(persona["current_dir"], version_images)
    event_sequence = [0]
    dll_init_events: list[dict] = _PositionedEvents(se, event_sequence)
    clock = VirtualClock(persona)
    cpu = VirtualCPU(persona, clock)
    guest_identity = GuestIdentity(persona)
    virtual_files = VirtualFileBridge(persona["current_dir"], catalog, persona_sources,
                                    clock.filetime_ticks(),
                                    desktop_directories(persona["user_name"]),
                                    persona["volume_guid"],
                                    persona["volume_capacity_bytes"],
                                    persona["volume_free_bytes"])
    bridge = NetworkBridge(catalog, virtual_files)
    virtual_registry = VirtualRegistryBridge(catalog, clock.filetime_ticks())
    virtual_process = VirtualProcessBridge(catalog, persona_sources)
    for observer in (bridge, virtual_files, virtual_registry, virtual_process):
        observer.events = _PositionedEvents(se, event_sequence)
    console_output = ConsoleOutput(oem_code_page(persona["locale"]))
    crt_streams = LegacyCRTStreams(persona["locale"], oem_code_page(persona["locale"]))
    crt_startup = CRTStartup()
    guest_environment = GuestEnvironmentBlocks()
    ui_language = ThreadUILanguage(persona)
    win_messages = WinMessages(persona["locale"])
    guest_strings = GuestStrings(oem_code_page(persona["locale"]))
    guest_delay_imports = GuestDelayImports()
    guest_tokens = GuestTokens(persona)
    guest_lsa = GuestLSA(persona)
    guest_audit = GuestAudit(persona)
    guest_network_adapter = GuestNetworkAdapter(persona)
    guest_network_adapter.network_bridge = bridge
    guest_feature_configuration = GuestFeatureConfiguration()
    win_messages.guest_images = version_info.images
    win_messages.current_dir = persona["current_dir"]
    version_info.read_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "read")
    version_info.write_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "write")
    guest_strings.read_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "read")
    guest_strings.write_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "write")
    guest_delay_imports.read_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "read")
    guest_delay_imports.write_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "write")
    guest_tokens.read_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "read")
    guest_tokens.write_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "write")
    guest_lsa.read_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "read")
    guest_lsa.write_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "write")
    guest_audit.read_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "read")
    guest_audit.write_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "write")
    guest_identity.write_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "write")
    guest_identity.read_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "read")
    heap_checks = GuestHeapChecks()
    crt_streams.read_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "read")
    crt_streams.write_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "write")
    crt_streams.console_write = console_output.append_text
    crt_startup.read_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "read")
    crt_startup.write_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "write")
    crt_startup.execute_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "execute")
    win_messages.read_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "read")
    win_messages.write_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "write")
    heap_checks.read_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "read")
    guest_network_adapter.read_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "read")
    guest_network_adapter.write_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "write")
    guest_feature_configuration.write_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "write")
    console_output.read_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "read")
    console_output.write_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "write")
    virtual_files.console_write_handler = console_output.observe_write_file
    virtual_files.console_open_handler = console_output.open_console_handle
    virtual_files.console_close_handler = console_output.close_console_handle
    virtual_files.read_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "read")
    virtual_files.write_guard = lambda emu, address, size: virtual_process._cpu_access(
        emu, address, size, "write")
    def cleanup_guest_process(emu, process):
        bridge.cleanup_process(process)
        guest_lsa.cleanup_process(emu, process)
        guest_audit.cleanup_process(emu, process)
        guest_identity.cleanup_process(process)
        crt_streams.cleanup_process(process)
        crt_startup.cleanup_process(process)
        return virtual_files.cleanup_process(emu, process)

    virtual_process.process_cleanup_handler = cleanup_guest_process
    virtual_process.registry_cleanup_handler = virtual_registry.cleanup_process
    virtual_files.process_close_handler = virtual_process.close_process_handle
    virtual_files.api_memory_allowance = virtual_process._allow_api_memory
    virtual_process.file_cpu_write_handler = virtual_files.record_cpu_mapped_write
    virtual_process.file_cpu_flush_handler = virtual_files.flush_pending_mapped_cpu_writes
    virtual_process.cpu_instruction_handler = cpu.observe_instruction
    virtual_process.file_api_write_handler = virtual_files.observe_mapped_api_write
    virtual_process.file_duplicate_handler = virtual_files.duplicate_guest_handle
    virtual_process.file_close_handler = lambda emu, handle, owner_process: virtual_files._close_handle(
        emu, "kernel32.CloseHandle", None, [handle], owner_override=id(owner_process))
    virtual_process.file_flag_entry_handler = virtual_files.handle_flag_entry
    virtual_process.file_inherit_handler = virtual_files.inherit_file_handles
    virtual_process.mapping_inherit_handler = virtual_files.inherit_mapping_handles
    try:
        bridge.install(se)
        virtual_files.install(se)
        console_output.install(se)
        crt_streams.install(se)
        crt_startup.install(se)
        guest_environment.install(se)
        ui_language.install(se)
        win_messages.install(se)
        version_info.install(se)
        guest_strings.install(se)
        guest_delay_imports.install(se)
        guest_tokens.install(se)
        guest_lsa.install(se)
        guest_audit.install(se)
        # Speakeasy models the x86 MSVC operator delete decoration, while
        # modern x64 binaries import this different decoration.
        se.add_api_hook(
            lambda emu, _name, _original, params: emu.mem_free(int(params[0]))
            if int(params[0]) else None,
            "msvcrt", "??3@YAXPEAX@Z", argc=1)
        heap_checks.install(se)
        guest_network_adapter.install(se)
        guest_feature_configuration.install(se)
        virtual_registry.install(se)
        virtual_process.install(se)
        se.add_api_hook(
            lambda emu, _api_name, _original, _params: int(
                emu.get_current_process().pid) if emu.get_current_process() is not None else 0,
            "kernel32", "GetCurrentProcessId")
        # COMCTL32 ordinal 17 is InitCommonControls. On the Win11 persona's
        # version 6 controls it has no observable effect, but older installers
        # still import it by ordinal.
        se.add_api_hook(lambda _emu, _api_name, _original, _params: 0,
                        "comctl32", "ordinal_17", argc=0)
        clock.install(se)
        cpu.install(se)
        guest_identity.install(se)
        loaded_guest_dlls: dict[tuple[int, str], object] = {}
        guest_dll_references: dict[int, int] = {}
        guest_dll_sizes: dict[int, int] = {}
        companion_references: dict[int, int] = {}
        system_module_references: dict[tuple[int, int], int] = {}
        module_owners: dict[int, int] = {}
        module_dependencies: dict[int, list[int]] = {}
        loaded_guest_bytes = 0
        main_image_base: int | None = None

        def app_policy_termination_method(emu, api_name, original, params):
            token, output = (int(value) for value in params)
            if not token or not output:
                return 87  # ERROR_INVALID_PARAMETER
            # GetCurrentProcessToken is the only token identity modeled here.
            if token != (1 << (emu.get_ptr_size() * 8)) - 6:
                virtual_files.unsupported.append(
                    f"{api_name}: policy for non-current token is not modeled")
                return 6  # ERROR_INVALID_HANDLE
            if not virtual_process._cpu_access(emu, output, 4, "write"):
                return 6
            try:
                emu.mem_write(output, struct.pack("<I", 0))  # ExitProcess: desktop app
            except Exception:
                return 87
            return 0  # ERROR_SUCCESS

        se.add_api_hook(app_policy_termination_method, "kernelbase",
                        "AppPolicyGetProcessTerminationMethod", argc=2)

        def current_owner(emu) -> int:
            process = emu.get_current_process()
            # Static imports are mapped before Speakeasy creates the primary
            # Process object. Keep that bootstrap owner for the primary image
            # after execution starts; child images have distinct guest bases.
            if (process is None or main_image_base is None or
                    int(process.base) == main_image_base):
                return 0
            return id(process)

        def module_visible(emu, candidate) -> bool:
            owner = module_owners.get(candidate.base)
            return owner is None or owner == current_owner(emu)

        win_messages.module_visible = module_visible

        def named_module(emu, stem: str):
            return next((candidate for candidate in emu.modules
                         if module_visible(emu, candidate) and
                         (ntpath.splitext(ntpath.basename(
                             candidate.emu_path))[0].lower() == stem or
                          str(candidate.name).lower() == stem)), None)

        def register_child_image(emu, process, image: bytes) -> None:
            child = next((candidate for candidate in emu.modules
                          if candidate.base == int(process.base)), None)
            if child is not None:
                module_owners[child.base] = id(process)
            cpu.register_child_image(process, image)

        virtual_process.process_created_handler = register_child_image

        def discard_guest_dll(active_emu, unloaded):
            nonlocal loaded_guest_bytes
            _remove_guest_module(active_emu, unloaded)
            guest_dll_references.pop(unloaded.base, None)
            module_owners.pop(unloaded.base, None)
            module_dependencies.pop(unloaded.base, None)
            loaded_guest_bytes -= guest_dll_sizes.pop(unloaded.base)
            for path, candidate in tuple(loaded_guest_dlls.items()):
                if candidate is unloaded:
                    del loaded_guest_dlls[path]

        def discard_companion_dll(active_emu, unloaded):
            _remove_guest_module(active_emu, unloaded)
            companion_references.pop(unloaded.base, None)
            module_owners.pop(unloaded.base, None)
            module_dependencies.pop(unloaded.base, None)

        def load_companion(emu, api_name, original, params, *,
                           guest_name_override: str | None = None):
            nonlocal loaded_guest_bytes
            if not params[0] and guest_name_override is None:
                emu.set_last_error(87)
                return 0
            width = 2 if api_name.endswith("W") else 1
            guest_name = (guest_name_override if guest_name_override is not None else
                          emu.read_mem_string(int(params[0]), width))
            stem = ntpath.splitext(ntpath.basename(guest_name))[0].lower()
            def retain_loaded(existing, *, by_name: bool):
                if ("LoadLibraryEx" in api_name and
                        (int(params[1]) or int(params[2])) and
                        (existing.base in guest_dll_references or
                         existing.base in companion_references)):
                    emu.set_last_error(50)
                    virtual_files.unsupported.append(
                        f"{api_name}: loaded guest DLL flags unsupported")
                    return 0
                if existing.base in guest_dll_references:
                    guest_dll_references[existing.base] += 1
                    dll_init_events.append({
                        "event": "virtual_dll_load", "api": api_name,
                        "path": existing.emu_path, "requested_name": guest_name,
                        "mapped": True, "base": hex(existing.base),
                        "references": guest_dll_references[existing.base],
                        "reused_by_name": by_name})
                elif existing.base in companion_references:
                    companion_references[existing.base] += 1
                    dll_init_events.append({
                        "event": "companion_dll_retain", "module": existing.name,
                        "base": hex(existing.base),
                        "references": companion_references[existing.base],
                        "reused_by_name": by_name})
                else:
                    key = (current_owner(emu), int(existing.base))
                    system_module_references[key] = system_module_references.get(key, 0) + 1
                return existing.base

            if not ntpath.dirname(guest_name):
                existing = named_module(emu, stem)
                if existing is not None:
                    return retain_loaded(existing, by_name=True)
            path = guest_name
            if not ntpath.splitext(ntpath.basename(path))[1]:
                path += ".dll"
            if not ntpath.isabs(path):
                path = ntpath.join(emu.get_cd(), path)
            path = ntpath.normpath(path)
            existing_path = next((candidate for candidate in emu.modules
                                  if module_visible(emu, candidate) and
                                  ntpath.normpath(candidate.emu_path).casefold() ==
                                  path.casefold()), None)
            if existing_path is not None:
                return retain_loaded(existing_path, by_name=False)
            guest_file = next((item for item in emu.get_file_manager().files
                               if item.path.casefold() == path.casefold()), None)
            image = (companion_images.get(stem) if
                     path.casefold() == companion_paths.get(stem) and
                     (guest_file is None or guest_file.config) else None)
            if image is not None:
                existing = next((candidate for candidate in emu.modules
                                 if module_visible(emu, candidate) and
                                 ntpath.normpath(candidate.emu_path).casefold() ==
                                 path.casefold()), None)
                if existing:
                    companion_references[existing.base] = (
                        companion_references.get(existing.base, 0) + 1)
                    dll_init_events.append({"event": "companion_dll_retain",
                                            "module": existing.name,
                                            "base": hex(existing.base),
                                            "references": companion_references[existing.base]})
                    return existing.base
                preferred, size = image
                base, _ = emu.get_valid_ranges(size, addr=preferred)
                if not base or (base != preferred and not companion_relocations[stem]):
                    emu.set_last_error(193)
                    virtual_files.unsupported.append(
                        f"{api_name}: companion relocation unavailable {path}")
                    return 0
                module = emu.load_module_by_name(stem, emu_path=path, base=base)
                parser = getattr(getattr(module._image, "loader", None), "_pe_obj", None)
                if parser is not None:
                    parser.close()
                companion_references[module.base] = 1
                module_owners[module.base] = current_owner(emu)
                failed_cleanup = discard_companion_dll
            else:
                if guest_file is None:
                    if ntpath.isabs(guest_name) or ntpath.dirname(guest_name):
                        emu.set_last_error(126)  # ERROR_MOD_NOT_FOUND
                        dll_init_events.append({"event": "virtual_dll_load", "api": api_name,
                                                "path": path, "mapped": False,
                                                "reason": "module path absent from guest filesystem"})
                        return 0
                    handle = int(original(params))
                    if handle:
                        loaded = next((item for item in emu.modules
                                       if int(item.base) == handle and
                                       module_visible(emu, item)), None)
                        if loaded is not None:
                            key = (current_owner(emu), handle)
                            system_module_references[key] = (
                                system_module_references.get(key, 0) + 1)
                    return handle
                event = {"event": "virtual_dll_load", "api": api_name,
                         "path": path, "mapped": False}
                dll_init_events.append(event)
                if guest_file.config:
                    emu.set_last_error(50)
                    event["reason"] = "host-backed guest mapping cannot supply a DLL"
                    virtual_files.unsupported.append(f"{api_name}: host-backed DLL mapping {path}")
                    return 0
                if "LoadLibraryEx" in api_name and (int(params[1]) or int(params[2])):
                    emu.set_last_error(50)
                    event["reason"] = "LoadLibraryEx flags or file handle unsupported for guest DLL"
                    virtual_files.unsupported.append(f"{api_name}: guest DLL load flags unsupported")
                    return 0
                raw = guest_file.data
                payload = raw.getvalue() if isinstance(raw, io.BytesIO) else raw
                if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_ARTIFACT:
                    emu.set_last_error(193)
                    event["reason"] = "empty or oversized guest DLL"
                    return 0
                try:
                    info = inspect_pe(payload, ntpath.basename(path))
                    if info.kind != "dll" or info.managed:
                        raise InvalidSample("guest image is not a native DLL")
                    if info.architecture != ("x64" if emu.get_ptr_size() == 8 else "x86"):
                        raise InvalidSample("guest DLL architecture differs from process")
                    parsed = pefile.PE(data=payload, fast_load=True)
                    preferred = int(parsed.OPTIONAL_HEADER.ImageBase)
                    size = int(parsed.OPTIONAL_HEADER.SizeOfImage)
                    has_reloc = _has_supported_base_relocations(parsed)
                    parsed.close()
                    if not 0 < size <= MAX_MEMORY_SCAN:
                        raise InvalidSample("guest DLL image exceeds memory limit")
                    existing = loaded_guest_dlls.get((current_owner(emu), path.casefold()))
                    if existing is not None:
                        guest_dll_references[existing.base] += 1
                        event["mapped"] = True
                        event["base"] = hex(existing.base)
                        event["references"] = guest_dll_references[existing.base]
                        return existing.base
                    if len(loaded_guest_dlls) >= MAX_GUEST_DLLS or loaded_guest_bytes + len(payload) > 64 * 1024 * 1024:
                        raise InvalidSample("guest DLL load budget exceeded")
                    base, _ = emu.get_valid_ranges(size, addr=preferred)
                    if not base or (base != preferred and not has_reloc):
                        raise InvalidSample("guest DLL cannot be mapped at preferred base")
                    loader = PeLoader(data=payload, base_override=base, emu_path=path)
                    loaded_image = loader.make_image()
                    loaded_image.name = stem
                    module = emu.load_image(loaded_image)
                except (InvalidSample, pefile.PEFormatError, ValueError, OSError) as exc:
                    emu.set_last_error(193)
                    event["reason"] = str(exc)
                    return 0
                except Exception as exc:
                    emu.set_last_error(193)
                    event["reason"] = f"guest DLL loader failed: {type(exc).__name__}"
                    virtual_files.unsupported.append(f"{api_name}: guest DLL loader failed {path}")
                    return 0
                loaded_guest_dlls[(current_owner(emu), path.casefold())] = module
                failed_cleanup = discard_guest_dll
                guest_dll_references[module.base] = 1
                module_owners[module.base] = current_owner(emu)
                guest_dll_sizes[module.base] = len(payload)
                loaded_guest_bytes += len(payload)
                event["mapped"] = True
                event["base"] = hex(module.base)
                event["sha256"] = info.sha256
                catalog.add(payload, "guest_dll_load", guest_path=path, kind="pe")
            process = emu.get_current_process()
            dependencies = []  # Postorder: each newly mapped child precedes its parent.
            newly_mapped = []
            acquired_edges: list[tuple[int, int]] = []
            pending_edges: dict[int, list[int]] = {}
            visiting: set[int] = set()
            new_bases: set[int] = set()

            class DependencyError(Exception):
                pass

            def reference_table(base: int):
                return (guest_dll_references if base in guest_dll_references
                        else companion_references)

            def rollback_dependencies():
                for owner_base, dependency_base in reversed(acquired_edges):
                    refs = reference_table(dependency_base)
                    refs[dependency_base] -= 1
                    edges = module_dependencies.get(owner_base, [])
                    if dependency_base in edges:
                        edges.remove(dependency_base)
                    if not edges:
                        module_dependencies.pop(owner_base, None)
                for dependency in reversed(newly_mapped):
                    (discard_guest_dll if dependency.base in guest_dll_references
                     else discard_companion_dll)(emu, dependency)

            def failed_before_attach(reason: str):
                rollback_dependencies()
                failed_cleanup(emu, module)
                dll_init_events.append({"event": "virtual_dll_load_failed",
                                        "module": module.name, "base": hex(module.base),
                                        "reason": reason})
                return 0

            def link_dependency(owner, dependency) -> None:
                if (owner.base not in guest_dll_references and
                        owner.base not in companion_references):
                    return
                if (dependency.base not in guest_dll_references and
                        dependency.base not in companion_references):
                    return
                edges = pending_edges.setdefault(owner.base, [])
                if (dependency.base in edges or
                        dependency.base in module_dependencies.get(owner.base, [])):
                    return
                edges.append(dependency.base)
                refs = reference_table(dependency.base)
                refs[dependency.base] += 1
                acquired_edges.append((owner.base, dependency.base))

            def map_dependency(owner, dependency_name: str):
                nonlocal loaded_guest_bytes
                # PE import descriptors contain names, not paths. Windows checks the
                # loaded-module list before searching for another file by that name.
                dependency = next((candidate for candidate in emu.modules
                                   if (candidate.base in guest_dll_references or
                                       candidate.base in companion_references) and
                                   module_visible(emu, candidate) and
                                   ntpath.splitext(ntpath.basename(
                                       candidate.emu_path))[0].lower() == dependency_name), None)
                if dependency is not None:
                    return dependency
                dll_name = dependency_name + ".dll"
                sibling_path = ntpath.normpath(ntpath.join(
                    ntpath.dirname(owner.emu_path), dll_name))
                guest_file = next((item for item in emu.get_file_manager().files
                                   if item.path.casefold() == sibling_path.casefold()
                                   and not item.config), None)
                companion_path = companion_paths.get(dependency_name)
                if guest_file is None and companion_path is None:
                    return None  # A modeled system DLL remains Speakeasy's responsibility.
                dependency_path = sibling_path if guest_file is not None else companion_path
                if len(new_bases) >= 32:
                    raise DependencyError("guest DLL dependency count exceeded")
                if guest_file is not None:
                    if len(loaded_guest_dlls) >= MAX_GUEST_DLLS:
                        raise DependencyError("guest DLL load budget exceeded")
                    raw = guest_file.data
                    payload = raw.getvalue() if isinstance(raw, io.BytesIO) else raw
                    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_ARTIFACT:
                        raise DependencyError("empty or oversized guest dependency")
                    try:
                        child_info = inspect_pe(payload, dll_name)
                        if (child_info.kind != "dll" or child_info.managed or
                                child_info.architecture != info.architecture):
                            raise DependencyError("guest dependency type or architecture mismatch")
                        parsed = pefile.PE(data=payload, fast_load=True)
                        preferred = int(parsed.OPTIONAL_HEADER.ImageBase)
                        size = int(parsed.OPTIONAL_HEADER.SizeOfImage)
                        has_reloc = _has_supported_base_relocations(parsed)
                        parsed.close()
                        if (not 0 < size <= MAX_MEMORY_SCAN or
                                loaded_guest_bytes + len(payload) > 64 * 1024 * 1024):
                            raise DependencyError("guest dependency memory budget exceeded")
                        child_base, _ = emu.get_valid_ranges(size, addr=preferred)
                        if not child_base or (child_base != preferred and not has_reloc):
                            raise DependencyError("guest dependency cannot be mapped at preferred base")
                        loader = PeLoader(data=payload, base_override=child_base,
                                          emu_path=dependency_path)
                        image = loader.make_image()
                        image.name = dependency_name
                        dependency = emu.load_image(image)
                    except (InvalidSample, pefile.PEFormatError, ValueError, OSError) as exc:
                        raise DependencyError(str(exc)) from exc
                    loaded_guest_dlls[(current_owner(emu), dependency_path.casefold())] = dependency
                    guest_dll_references[dependency.base] = 0
                    module_owners[dependency.base] = current_owner(emu)
                    guest_dll_sizes[dependency.base] = len(payload)
                    loaded_guest_bytes += len(payload)
                    catalog.add(payload, "guest_dll_load", guest_path=dependency_path, kind="pe")
                else:
                    preferred, size = companion_images[dependency_name]
                    child_base, _ = emu.get_valid_ranges(size, addr=preferred)
                    if not child_base or (child_base != preferred and
                                          not companion_relocations[dependency_name]):
                        raise DependencyError("dependency relocation unavailable")
                    dependency = emu.load_module_by_name(
                        dependency_name, emu_path=dependency_path, base=child_base)
                    parser = getattr(getattr(dependency._image, "loader", None), "_pe_obj", None)
                    if parser is not None:
                        parser.close()
                    companion_references[dependency.base] = 0
                    module_owners[dependency.base] = current_owner(emu)
                new_bases.add(dependency.base)
                newly_mapped.append(dependency)
                dll_init_events.append({"event": "dll_dependency_map",
                                        "module": dependency.name,
                                        "base": hex(dependency.base),
                                        "required_by": owner.name})
                if emu.get_address_map(process.peb_ldr_data.address):
                    process.add_module_to_peb(dependency)
                return dependency

            def resolve_dependencies(owner, depth: int) -> None:
                if depth > 8:
                    raise DependencyError("guest DLL dependency depth exceeded")
                visiting.add(owner.base)
                for imported in owner._image.imports:
                    dependency_name = ntpath.splitext(ntpath.basename(imported.dll_name))[0].lower()
                    dependency = map_dependency(owner, dependency_name)
                    if dependency is None:
                        continue
                    if dependency.base in visiting:
                        raise DependencyError("cyclic guest DLL dependency unsupported")
                    link_dependency(owner, dependency)
                    if dependency.base in new_bases and dependency not in dependencies:
                        resolve_dependencies(dependency, depth + 1)
                    name = imported.func_name
                    try:
                        forwarded: list[tuple[object, object]] = []
                        address = _resolve_loaded_export(
                            emu, dependency, name,
                            load_missing=lambda source, stem: map_dependency(source, stem),
                            on_forward=lambda source, target: forwarded.append((source, target)),
                            is_visible=lambda candidate: module_visible(emu, candidate))
                        for source, target in reversed(forwarded):
                            if target.base in visiting:
                                raise DependencyError("cyclic guest DLL dependency unsupported")
                            if target.base in new_bases and target not in dependencies:
                                resolve_dependencies(target, depth + 1)
                                dependencies.append(target)
                            link_dependency(source, target)
                        if dependency.base in new_bases and dependency not in dependencies:
                            dependencies.append(dependency)
                    except ValueError as exc:
                        emu.set_last_error(127)
                        if str(exc).startswith("DLL export absent:"):
                            raise DependencyError(
                                f"unresolved dependency export {dependency_name}.{name}") from exc
                        raise DependencyError(str(exc)) from exc
                    emu.mem_write(int(imported.iat_address),
                                  address.to_bytes(emu.get_ptr_size(), "little"))
                visiting.remove(owner.base)

            try:
                resolve_dependencies(module, 0)
                for owner_base, edges in pending_edges.items():
                    active = module_dependencies.setdefault(owner_base, [])
                    active.extend(edge for edge in edges if edge not in active)
            except DependencyError as exc:
                emu.set_last_error(50)
                virtual_files.unsupported.append(f"{api_name}: {exc}")
                return failed_before_attach(str(exc))
            if emu.get_address_map(process.peb_ldr_data.address):
                process.add_module_to_peb(module)
            load_argc = (4 if api_name.endswith("LdrLoadDll") else
                         3 if "LoadLibraryEx" in api_name else 1)
            def failed_load(active_emu, failed_module):
                failed_cleanup(active_emu, failed_module)
                dll_init_events.append({"event": "virtual_dll_load_failed",
                                        "module": failed_module.name,
                                        "base": hex(failed_module.base)})
                active_emu.set_last_error(1114)  # ERROR_DLL_INIT_FAILED

            if dependencies:
                def failed_chain(active_emu, mapped):
                    rollback_dependencies()
                    failed_load(active_emu, mapped[-1])

                try:
                    _enter_dll_chain(emu, [*dependencies, module], module,
                                     dll_init_events, load_argc, failed_chain)
                except ValueError as exc:
                    emu.set_last_error(50)
                    virtual_files.unsupported.append(f"{api_name}: {exc}")
                    return failed_before_attach(str(exc))
            else:
                _enter_companion_with_tls(emu, module, dll_init_events, load_argc,
                                          failed_load)
            return module.base

        for name in ("LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW"):
            for module in ("kernel32", "api-ms-win-core-libraryloader-l1-2-0"):
                se.add_api_hook(load_companion, module, name)

        def find_process_module(emu, requested: str):
            if ntpath.dirname(requested):
                path = requested if ntpath.isabs(requested) else ntpath.join(
                    emu.get_cd(), requested)
                path = ntpath.normpath(path).casefold()
                return next((item for item in emu.modules
                             if module_visible(emu, item) and
                             ntpath.normpath(item.emu_path).casefold() == path), None)
            stem = ntpath.splitext(ntpath.basename(requested))[0].lower()
            return named_module(emu, stem)

        def get_process_module_handle(emu, api_name, original, params):
            if not params[0]:
                process = emu.get_current_process()
                return int(process.base) if process is not None else 0
            width = 2 if api_name.endswith("W") else 1
            candidate = find_process_module(
                emu, emu.read_mem_string(int(params[0]), width))
            if candidate is None:
                emu.set_last_error(126)
                return 0
            return int(candidate.base)

        for name in ("GetModuleHandleA", "GetModuleHandleW"):
            se.add_api_hook(get_process_module_handle, "kernel32", name)

        def get_process_module_handle_ex(emu, api_name, original, params):
            flags, name_pointer, output = (int(value) for value in params)
            if not output or flags & ~7 or flags & 3 == 3:
                emu.set_last_error(87)
                return 0
            if flags & 1:
                emu.set_last_error(50)
                virtual_files.unsupported.append(
                    f"{api_name}: module pinning unsupported")
                return 0
            if flags & 4:
                candidate = next((item for item in emu.modules
                                  if module_visible(emu, item) and
                                  item.base <= name_pointer < item.base + item.image_size), None)
            elif name_pointer:
                width = 2 if api_name.endswith("W") else 1
                candidate = find_process_module(
                    emu, emu.read_mem_string(name_pointer, width))
            else:
                process = emu.get_current_process()
                candidate = next((item for item in emu.modules
                                  if process is not None and
                                  item.base == int(process.base) and
                                  module_visible(emu, item)), None)
            handle = int(candidate.base) if candidate is not None else 0
            emu.mem_write(output, handle.to_bytes(emu.get_ptr_size(), "little"))
            if not handle:
                emu.set_last_error(126)
                return 0
            if not flags & 2:
                if handle in guest_dll_references:
                    guest_dll_references[handle] += 1
                elif handle in companion_references:
                    companion_references[handle] += 1
                else:
                    key = (current_owner(emu), handle)
                    system_module_references[key] = system_module_references.get(key, 0) + 1
            emu.set_last_error(0)
            return 1

        for name in ("GetModuleHandleExA", "GetModuleHandleExW"):
            se.add_api_hook(get_process_module_handle_ex, "kernel32", name)

        def resolve_companion_export(emu, api_name, original, params, *,
                                     symbol_override: str | None = None):
            handle, pointer = int(params[0]), int(params[1])
            if (handle in module_owners and
                    module_owners[handle] != current_owner(emu)):
                emu.set_last_error(6)
                virtual_files.unsupported.append(
                    f"{api_name}: DLL handle belongs to different guest process")
                return 0
            for module in emu.modules:
                if module.base != handle or not module_visible(emu, module) or (
                                                module.name.lower() not in companion_images and
                                                module not in loaded_guest_dlls.values()):
                    continue
                name = (symbol_override if symbol_override is not None else
                        f"ordinal_{pointer}" if pointer < 0x10000 else
                        emu.read_mem_string(pointer, 1))
                mapped = []
                acquired_edges: list[tuple[int, int]] = []

                def rollback() -> None:
                    for owner_base, target_base in reversed(acquired_edges):
                        edges = module_dependencies.get(owner_base, [])
                        if target_base in edges:
                            edges.remove(target_base)
                        if not edges:
                            module_dependencies.pop(owner_base, None)
                        refs = (guest_dll_references if target_base in guest_dll_references
                                else companion_references)
                        refs[target_base] -= 1
                    for target in reversed(mapped):
                        (discard_guest_dll if target.base in guest_dll_references
                         else discard_companion_dll)(emu, target)

                def load_forwarder_target(owner, stem):
                    nonlocal loaded_guest_bytes
                    sibling = ntpath.normpath(ntpath.join(
                        ntpath.dirname(owner.emu_path), stem + ".dll"))
                    guest_file = next((item for item in emu.get_file_manager().files
                                       if item.path.casefold() == sibling.casefold() and
                                       not item.config), None)
                    if guest_file is None and stem not in companion_images:
                        return None
                    if len(mapped) >= 8:
                        raise ValueError("Forwarded DLL module budget exceeded")
                    collision = named_module(emu, stem)
                    if collision is not None:
                        raise ValueError(f"Forwarded DLL module basename collision: {stem}")
                    if guest_file is not None:
                        raw = guest_file.data
                        payload = raw.getvalue() if isinstance(raw, io.BytesIO) else raw
                        if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_ARTIFACT:
                            raise ValueError("Empty or oversized forwarded guest DLL")
                        dll_name = ntpath.basename(sibling)
                        info = inspect_pe(payload, dll_name)
                        if (info.kind != "dll" or info.managed or
                                info.architecture != ("x64" if emu.get_ptr_size() == 8 else "x86")):
                            raise ValueError("Forwarded guest DLL type or architecture mismatch")
                        parsed = pefile.PE(data=payload, fast_load=True)
                        try:
                            preferred = int(parsed.OPTIONAL_HEADER.ImageBase)
                            size = int(parsed.OPTIONAL_HEADER.SizeOfImage)
                            has_reloc = _has_supported_base_relocations(parsed)
                        finally:
                            parsed.close()
                        if (not 0 < size <= MAX_MEMORY_SCAN or len(loaded_guest_dlls) >= MAX_GUEST_DLLS or
                                loaded_guest_bytes + len(payload) > 64 * 1024 * 1024):
                            raise ValueError("Forwarded guest DLL memory budget exceeded")
                        base, _ = emu.get_valid_ranges(size, addr=preferred)
                        if not base or (base != preferred and not has_reloc):
                            raise ValueError(f"Forwarded guest DLL relocation unavailable: {stem}")
                        loader = PeLoader(data=payload, base_override=base, emu_path=sibling)
                        image = loader.make_image()
                        image.name = stem
                        target = emu.load_image(image)
                        loaded_guest_dlls[(current_owner(emu), sibling.casefold())] = target
                        guest_dll_references[target.base] = 0
                        module_owners[target.base] = current_owner(emu)
                        guest_dll_sizes[target.base] = len(payload)
                        loaded_guest_bytes += len(payload)
                        catalog.add(payload, "guest_dll_load", guest_path=sibling, kind="pe")
                    else:
                        if len(companion_references) >= 32:
                            raise ValueError("Forwarded DLL module budget exceeded")
                        preferred, size = companion_images[stem]
                        base, _ = emu.get_valid_ranges(size, addr=preferred)
                        if not base or (base != preferred and not companion_relocations[stem]):
                            raise ValueError(f"Forwarded DLL relocation unavailable: {stem}")
                        target = emu.load_module_by_name(
                            stem, emu_path=companion_paths[stem], base=base)
                        parser = getattr(getattr(target._image, "loader", None), "_pe_obj", None)
                        if parser is not None:
                            parser.close()
                        companion_references[target.base] = 0
                        module_owners[target.base] = current_owner(emu)
                    mapped.append(target)
                    for imported in target._image.imports:
                        imported_stem = ntpath.splitext(
                            ntpath.basename(imported.dll_name))[0].lower()
                        sibling = ntpath.normpath(ntpath.join(
                            ntpath.dirname(target.emu_path), imported_stem + ".dll"))
                        guest_dependency = any(
                            item.path.casefold() == sibling.casefold() and not item.config
                            for item in emu.get_file_manager().files)
                        if imported_stem in companion_images or guest_dependency:
                            raise ValueError("Forwarded DLL target dependencies unsupported")
                    process = emu.get_current_process()
                    if process is not None and emu.get_address_map(process.peb_ldr_data.address):
                        process.add_module_to_peb(target)
                    dll_init_events.append({"event": "dll_forwarder_map",
                                            "module": target.name, "base": hex(target.base),
                                            "required_by": owner.name})
                    return target

                def link_forwarder(owner, target):
                    if owner.base not in companion_references and owner.base not in guest_dll_references:
                        return
                    refs = (guest_dll_references if target.base in guest_dll_references
                            else companion_references)
                    if target.base not in refs:
                        return
                    edges = module_dependencies.setdefault(owner.base, [])
                    if target.base not in edges:
                        edges.append(target.base)
                        refs[target.base] += 1
                        acquired_edges.append((owner.base, target.base))

                try:
                    address = _resolve_loaded_export(
                        emu, module, name, load_missing=load_forwarder_target,
                        on_forward=link_forwarder,
                        is_visible=lambda candidate: module_visible(emu, candidate))
                except ValueError as exc:
                    rollback()
                    emu.set_last_error(127)
                    if not str(exc).startswith("DLL export absent:"):
                        virtual_files.unsupported.append(f"{api_name}: {exc}")
                    return 0
                if mapped:
                    def failed_forwarder(active_emu, _mapped):
                        rollback()
                        active_emu.set_last_error(1114)
                        dll_init_events.append({"event": "dll_forwarder_load_failed",
                                                "module": module.name})

                    try:
                        _enter_dll_chain(emu, list(reversed(mapped)), module,
                                         dll_init_events,
                                         4 if api_name.endswith("LdrGetProcedureAddress") else 2,
                                         failed_forwarder,
                                         result_address=address)
                    except ValueError as exc:
                        rollback()
                        emu.set_last_error(127)
                        virtual_files.unsupported.append(f"{api_name}: {exc}")
                        return 0
                return address
            return original(params)

        for module in ("kernel32", "api-ms-win-core-libraryloader-l1-2-0"):
            se.add_api_hook(resolve_companion_export, module, "GetProcAddress")

        def nt_loader_result(emu, api_name: str, output: int,
                             call_pc: int, call_return: int,
                             value: int, failure_status: int,
                             deferred_failure_status: int | None = None) -> int:
            """Translate the guest loader's deferred HMODULE/FARPROC to NTSTATUS."""
            pointer_size = emu.get_ptr_size()

            def finish(active_emu, loaded: int, failed: int) -> int:
                if not loaded:
                    return failed
                if output:
                    try:
                        active_emu.mem_write(output, loaded.to_bytes(pointer_size, "little"))
                    except Exception:
                        return STATUS_ACCESS_VIOLATION
                return STATUS_SUCCESS

            if emu.get_pc() == call_pc:
                return finish(emu, value, failure_status)
            owner = current_owner(emu)
            run = emu.get_current_run()
            call_tick = int(run.instr_cnt) if run is not None else None
            thread = emu.get_current_thread()
            tid = int(thread.tid) if thread is not None else None
            hook_ref = [None]

            def completed(active_emu, _address, _size):
                current_thread = active_emu.get_current_thread()
                if (current_owner(active_emu) != owner or
                        (tid is not None and (current_thread is None or
                                              int(current_thread.tid) != tid))):
                    return True
                hook_ref[0].disable()
                register = "rax" if pointer_size == 8 else "eax"
                loaded = int(active_emu.reg_read(register))
                status = finish(
                    active_emu, loaded,
                    deferred_failure_status if deferred_failure_status is not None
                    else failure_status)
                active_emu.reg_write("eax", status)
                active_run = active_emu.get_current_run()
                if active_run is not None:
                    for event in reversed(active_run.events):
                        if (getattr(event, "event", None) == "api" and
                                getattr(event, "api_name", None) == api_name and
                                getattr(getattr(event, "pos", None), "tick", None) ==
                                call_tick):
                            event.ret_val = hex(status)
                            break
                return True

            hook_ref[0] = emu.add_code_hook(
                completed, begin=call_return, end=call_return + 1)
            emu._emumee_nt_loader_hooks = getattr(
                emu, "_emumee_nt_loader_hooks", []) + hook_ref
            return STATUS_SUCCESS  # The guest return hook sets the final status.

        def ldr_load_dll(emu, api_name, original, params):
            search_path, flags_pointer, name_pointer, output = (int(p) for p in params)
            if not name_pointer:
                return STATUS_INVALID_PARAMETER
            if search_path:
                virtual_files.unsupported.append(
                    f"{api_name}: custom DLL search path unsupported")
                return STATUS_NOT_SUPPORTED
            if flags_pointer:
                try:
                    flags = struct.unpack("<I", emu.mem_read(flags_pointer, 4))[0]
                except Exception:
                    return STATUS_ACCESS_VIOLATION
                if flags:
                    virtual_files.unsupported.append(
                        f"{api_name}: nonzero DLL load flags unsupported")
                    return STATUS_NOT_SUPPORTED
            try:
                name = _read_nt_counted_string(emu, name_pointer, wide=True)
                if output:
                    emu.mem_write(output, b"\0" * emu.get_ptr_size())
            except ValueError:
                return STATUS_INVALID_PARAMETER
            except Exception:
                return STATUS_ACCESS_VIOLATION
            call_pc, call_return = emu.get_pc(), emu.get_ret_address()
            stem = ntpath.splitext(ntpath.basename(name))[0]
            loaded = load_companion(
                emu, api_name, lambda _params: emu.load_library(stem), [1],
                guest_name_override=name)
            return nt_loader_result(emu, api_name, output, call_pc, call_return,
                                    loaded,
                                    STATUS_DLL_NOT_FOUND, STATUS_DLL_INIT_FAILED)

        se.add_api_hook(ldr_load_dll, "ntdll", "LdrLoadDll")

        def ldr_get_procedure_address(emu, api_name, original, params):
            handle, name_pointer, ordinal, output = (int(p) for p in params)
            if not output or not handle or (not name_pointer and not ordinal):
                return STATUS_INVALID_PARAMETER
            try:
                if name_pointer:
                    name = _read_nt_counted_string(emu, name_pointer, wide=False)
                else:
                    name = f"ordinal_{ordinal & 0xFFFF}"
                emu.mem_write(output, b"\0" * emu.get_ptr_size())
            except ValueError:
                return STATUS_INVALID_PARAMETER
            except Exception:
                return STATUS_ACCESS_VIOLATION
            module = next((item for item in emu.modules
                           if int(item.base) == handle and module_visible(emu, item)), None)
            if module is None:
                return STATUS_DLL_NOT_FOUND
            call_pc, call_return = emu.get_pc(), emu.get_ret_address()
            address = resolve_companion_export(
                emu, api_name,
                lambda _params: emu.get_proc(module.name, name),
                [handle, ordinal & 0xFFFF if not name_pointer else 1],
                symbol_override=name)
            return nt_loader_result(emu, api_name, output, call_pc, call_return,
                                    address,
                                    STATUS_PROCEDURE_NOT_FOUND,
                                    STATUS_DLL_INIT_FAILED)

        se.add_api_hook(ldr_get_procedure_address, "ntdll",
                        "LdrGetProcedureAddress")

        def free_guest_dll(emu, api_name, original, params):
            nonlocal loaded_guest_bytes
            handle = int(params[0])
            if (handle in module_owners and
                    module_owners[handle] != current_owner(emu)):
                emu.set_last_error(6)
                virtual_files.unsupported.append(
                    f"{api_name}: DLL handle belongs to different guest process")
                return 0
            refs = guest_dll_references.get(handle)
            companion = refs is None and handle in companion_references
            if companion:
                refs = companion_references[handle]
            if refs is None:
                module = next((item for item in emu.modules if item.base == handle), None)
                if module is not None:
                    key = (current_owner(emu), handle)
                    system_refs = system_module_references.get(key, 0)
                    if system_refs:
                        if system_refs == 1:
                            del system_module_references[key]
                        else:
                            system_module_references[key] = system_refs - 1
                        dll_init_events.append({"event": "system_dll_release",
                                                "module": module.name,
                                                "base": hex(handle),
                                                "references": system_refs - 1})
                        return 1
                    virtual_files.unsupported.append(
                        f"{api_name}: unload of unreferenced system module {module.name} is not modeled")
                    emu.set_last_error(50)
                else:
                    emu.set_last_error(6)  # ERROR_INVALID_HANDLE
                return 0
            if refs > 1:
                if companion:
                    companion_references[handle] = refs - 1
                else:
                    guest_dll_references[handle] = refs - 1
                dll_init_events.append({"event": ("companion_dll_release" if companion
                                                   else "virtual_dll_release"),
                                        "base": hex(handle), "references": refs - 1})
                return 1

            module = next(item for item in emu.modules if item.base == handle)
            dependent_unloads = []
            scheduled = {handle}

            def release_dependencies(owner_base: int) -> None:
                for dependency_base in reversed(module_dependencies.get(owner_base, [])):
                    refs = (guest_dll_references if dependency_base in guest_dll_references
                            else companion_references)
                    dependency_refs = refs.get(dependency_base)
                    if dependency_refs is None or dependency_base in scheduled:
                        virtual_files.unsupported.append(
                            f"{api_name}: dependency was already unloaded: 0x{dependency_base:x}")
                        continue
                    if dependency_refs > 1:
                        refs[dependency_base] = dependency_refs - 1
                        dll_init_events.append({
                            "event": ("virtual_dll_release" if refs is guest_dll_references
                                      else "companion_dll_release"),
                            "base": hex(dependency_base),
                            "references": dependency_refs - 1})
                    else:
                        dependency = next((item for item in emu.modules
                                           if item.base == dependency_base), None)
                        if dependency is not None:
                            scheduled.add(dependency_base)
                            dependent_unloads.append(dependency)
                            release_dependencies(dependency_base)

            release_dependencies(handle)
            original_return = emu.get_ret_address()
            unloading = [module, *dependent_unloads]

            def enter_next(active_emu, *, frame_consumed: bool):
                current = unloading.pop(0)

                def cleanup(active_emu, unloaded):
                    is_companion = unloaded.base in companion_references
                    (discard_companion_dll if is_companion else discard_guest_dll)(
                        active_emu, unloaded)
                    dll_init_events.append({"event": ("companion_dll_unload" if is_companion
                                                       else "virtual_dll_unload"),
                                            "module": unloaded.name,
                                            "base": hex(unloaded.base)})
                    if unloading:
                        if active_emu.get_ptr_size() == 8:
                            active_emu.set_stack_ptr(active_emu.get_stack_ptr() + 0x20)
                        enter_next(active_emu, frame_consumed=True)

                _enter_guest_detach(active_emu, current, dll_init_events, cleanup,
                                    original_return=original_return,
                                    frame_consumed=frame_consumed)

            enter_next(emu, frame_consumed=False)
            return 1

        for module in ("kernel32", "api-ms-win-core-libraryloader-l1-2-0"):
            se.add_api_hook(free_guest_dll, module, "FreeLibrary")

        def ldr_unload_dll(emu, api_name, original, params):
            handle = int(params[0])
            if not handle:
                return STATUS_INVALID_PARAMETER
            call_pc, call_return = emu.get_pc(), emu.get_ret_address()
            released = free_guest_dll(emu, api_name, original, [handle])
            return nt_loader_result(emu, api_name, 0, call_pc, call_return,
                                    released,
                                    STATUS_DLL_NOT_FOUND)

        se.add_api_hook(ldr_unload_dll, "ntdll", "LdrUnloadDll")
        (run_dir / "worker-stage.txt").write_text("loading native module", encoding="utf-8")
        # data= avoids Speakeasy's automatic mount of the input's host directory.
        module = se.load_module(data=data, filename=info.name)
        # Speakeasy's argv[0] walks every loaded EXE module and can select its
        # synthetic ntoskrnl.exe instead of the running guest image.
        original_get_argv = se.emu.get_argv
        se.emu.get_argv = lambda: process_argv(se.emu, original_get_argv())
        # Give the hook a normal API dispatch path, which honors a guest detach
        # trampoline instead of forcing an immediate return for unknown exports.
        ntdll = se.emu.api.load_api_handler("ntdll")
        if ntdll is not None and "LdrUnloadDll" not in ntdll.funcs:
            def unsupported_ldr_unload(_handler, _emu, _argv, _ctx):
                return STATUS_NOT_SUPPORTED
            ntdll.funcs["LdrUnloadDll"] = (
                "LdrUnloadDll", unsupported_ldr_unload, 1, CALL_CONV_STDCALL, None)
        cpu.register_primary_image(module.base, data if info.kind == "exe" else b"")
        clock.attach_shared_data(se.emu)
        cpu.avx_read_guard = lambda address, size: virtual_process._cpu_access(
            se.emu, address, size, "read")
        def guarded_avx_write(address, size):
            if not virtual_process._cpu_access(se.emu, address, size, "write"):
                return False
            virtual_files.record_cpu_mapped_write(se.emu, address, size)
            return True
        cpu.avx_write_guard = guarded_avx_write
        cpu.attach(se.emu)
        crt_startup.attach(se.emu)
        main_image_base = module.base
        virtual_process.primary_image_bases.add(module.base)
        module_owners[module.base] = current_owner(se.emu)
        virtual_process.install_dispatch_memory_guard(se.emu)
        virtual_process.install_run_context_guard(se.emu)
        virtual_files.extend_enumeration(se.emu)
        static_attach_failures: list[str] = []
        if companion_images:
            static_modules: dict[str, object] = {}
            static_visiting: set[int] = set()
            static_scheduled: set[str] = set()
            static_attached: list[object] = []
            static_tls_only_last: dict[str, int] = {}
            static_forward_edges: dict[int, list[int]] = {}

            def map_static_companion(stem: str):
                companion = static_modules.get(stem)
                if companion is not None:
                    return companion
                if len(static_modules) >= 32:
                    raise ValueError("Static companion module budget exceeded")
                preferred, size = companion_images[stem]
                base, _ = se.emu.get_valid_ranges(size, addr=preferred)
                if not base or (base != preferred and not companion_relocations[stem]):
                    raise ValueError(f"Static companion relocation unavailable: {stem}")
                companion = se.emu.load_module_by_name(
                    stem, emu_path=companion_paths[stem], base=base)
                parser = getattr(getattr(companion._image, "loader", None), "_pe_obj", None)
                if parser is not None:
                    parser.close()
                static_modules[stem] = companion
                virtual_process.primary_image_bases.add(companion.base)
                companion_references[companion.base] = 1  # Process lifetime reference.
                module_owners[companion.base] = current_owner(se.emu)
                return companion

            def resolve_static_imports(owner, depth: int) -> None:
                if depth > 8:
                    raise ValueError("Static companion dependency depth exceeded")
                owner_name = owner.name.lower()
                if owner.base in static_visiting:
                    raise ValueError(f"Cyclic static companion dependency: {owner_name}")
                static_visiting.add(owner.base)
                edges: list[int] = []
                for imp in owner._image.imports:
                    stem = ntpath.splitext(ntpath.basename(imp.dll_name))[0].lower()
                    if stem not in companion_images:
                        continue
                    companion = map_static_companion(stem)
                    if companion.base in static_visiting:
                        raise ValueError(f"Cyclic static companion dependency: {stem}")
                    if owner is not module and companion.base not in edges:
                        edges.append(companion.base)
                        companion_references[companion.base] += 1
                    try:
                        forwarded: list[tuple[object, object]] = []
                        address = _resolve_loaded_export(
                            se.emu, companion, imp.func_name,
                            load_missing=lambda _owner, target_stem: (
                                map_static_companion(target_stem)
                                if target_stem in companion_images else None),
                            on_forward=lambda source, target: forwarded.append((source, target)),
                            is_visible=lambda candidate: module_visible(se.emu, candidate))
                        # The resolver may have mapped a multi-hop chain. Schedule its
                        # leaves first, before the DLL that contains this import.
                        for source, target in reversed(forwarded):
                            target_stem = ntpath.splitext(ntpath.basename(target.name))[0].lower()
                            if target_stem not in companion_images:
                                continue
                            if target.base in static_visiting:
                                raise ValueError(f"Cyclic static companion dependency: {target_stem}")
                            if target_stem not in static_scheduled:
                                resolve_static_imports(target, depth + 1)
                            if source is not module and source.base in companion_references:
                                forward_edges = static_forward_edges.setdefault(source.base, [])
                                if target.base not in forward_edges:
                                    forward_edges.append(target.base)
                        if stem not in static_scheduled:
                            resolve_static_imports(companion, depth + 1)
                    except ValueError as exc:
                        raise ValueError(f"Companion DLL export unavailable: {stem}.{imp.func_name}: {exc}") from exc
                    old = int.from_bytes(se.emu.mem_read(imp.iat_address, se.emu.get_ptr_size()), "little")
                    se.emu.import_table.pop(old, None)
                    se.emu.mem_write(imp.iat_address,
                                     address.to_bytes(se.emu.get_ptr_size(), "little"))
                if edges:
                    module_dependencies[owner.base] = edges
                static_visiting.remove(owner.base)
                if owner is not module:
                    stem = owner_name
                    valid_callbacks = [(index, callback)
                                       for index, callback in enumerate(owner.get_tls_callbacks())
                                       if owner.base < callback < owner.base + owner.image_size]
                    for index, callback in valid_callbacks:
                        run = Run()
                        run.start_addr = callback
                        run.type = f"static_dll_tls_{stem}_{index}"
                        run.args = [owner.base, 1, 0]
                        se.emu.add_run(run)
                    if owner.ep:
                        run = Run()
                        run.start_addr = owner.base + owner.ep
                        run.type = f"static_dll_entry_{stem}"
                        run.args = [owner.base, 1, 1]
                        se.emu.add_run(run)
                    elif valid_callbacks:
                        static_tls_only_last[stem] = valid_callbacks[-1][0]
                    static_scheduled.add(stem)

            resolve_static_imports(module, 0)
            for owner_base, targets in static_forward_edges.items():
                edges = module_dependencies.setdefault(owner_base, [])
                for target_base in targets:
                    if target_base not in edges:
                        edges.append(target_base)
                        companion_references[target_base] += 1
        if companion_images:
            completed_run = se.emu.on_run_complete

            def queue_static_detach(companion, *, failed_load: bool) -> None:
                reserved = 0 if failed_load else 1
                for index, callback in enumerate(companion.get_tls_callbacks()):
                    if companion.base < callback < companion.base + companion.image_size:
                        run = Run()
                        run.start_addr = callback
                        run.type = f"static_dll_tls_detach_{companion.name.lower()}_{index}"
                        run.args = [companion.base, 0, 0]
                        se.emu.add_run(run)
                if companion.ep:
                    run = Run()
                    run.start_addr = companion.base + companion.ep
                    run.type = f"static_dll_detach_{companion.name.lower()}"
                    run.args = [companion.base, 0, reserved]
                    se.emu.add_run(run)

            def check_static_attach():
                current = se.emu.curr_run
                run_type = str(current.type) if current is not None else ""
                if run_type.startswith("static_dll_entry_"):
                    stem = run_type.removeprefix("static_dll_entry_")
                    companion = static_modules[stem]
                    if se.emu.get_return_val():
                        static_attached.append(companion)
                    else:
                        static_attach_failures.append(run_type)
                        dll_init_events.append({"event": "static_dll_process_attach_failed",
                                                "module": stem})
                        # Speakeasy would otherwise continue to the EXE entry point.
                        se.emu.run_queue.clear()
                        queue_static_detach(companion, failed_load=True)
                        for attached in reversed(static_attached):
                            queue_static_detach(attached, failed_load=False)
                elif run_type.startswith("static_dll_tls_detach_"):
                    stem, _, index = run_type.removeprefix("static_dll_tls_detach_").rpartition("_")
                    dll_init_events.append({"event": "dll_tls_detach", "module": stem,
                                            "index": int(index)})
                elif run_type.startswith("static_dll_tls_"):
                    stem, _, index = run_type.removeprefix("static_dll_tls_").rpartition("_")
                    if static_tls_only_last.get(stem) == int(index):
                        static_attached.append(static_modules[stem])
                elif run_type.startswith("static_dll_detach_"):
                    dll_init_events.append({"event": "dll_process_detach",
                                            "module": run_type.removeprefix("static_dll_detach_")})
                return completed_run()

            se.emu.on_run_complete = check_static_attach
        original_get_peb_modules = se.emu.get_peb_modules

        def get_process_peb_modules():
            return [candidate for candidate in original_get_peb_modules()
                    if module_visible(se.emu, candidate)]

        # Speakeasy keeps a global module list and uses this method both for
        # WinAPI module-name queries and for populating each process's PEB.
        se.emu.get_peb_modules = get_process_peb_modules

        def modules_for_process(process):
            owner = (0 if int(process.base) == main_image_base else id(process))
            visible = [candidate for candidate in original_get_peb_modules()
                       if module_owners.get(candidate.base, owner) == owner]
            visible.sort(key=lambda candidate: candidate.base != int(process.base))
            return visible

        def psapi_process(emu, handle: int):
            process = virtual_process._process(emu, handle)
            if process is None:
                emu.set_last_error(6)
                return None
            if not virtual_process._rights_allow(
                    emu, handle, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ):
                emu.set_last_error(5)
                return None
            return process

        def enum_process_modules(emu, api_name, original, params):
            handle, output, capacity, needed = (int(value) for value in params)
            process = psapi_process(emu, handle)
            if process is None:
                return 0
            bases = [candidate.base for candidate in modules_for_process(process)]
            width = emu.get_ptr_size()
            if needed:
                emu.mem_write(needed, (len(bases) * width).to_bytes(4, "little"))
            if output:
                for index, base in enumerate(bases[:capacity // width]):
                    emu.mem_write(output + index * width,
                                  int(base).to_bytes(width, "little"))
            return 1

        for module_name, name in (("psapi", "EnumProcessModules"),
                                  ("kernel32", "K32EnumProcessModules")):
            se.add_api_hook(enum_process_modules, module_name, name)

        def psapi_module_name(emu, api_name, original, params):
            handle, module_handle, output, capacity = (int(value) for value in params)
            if not output or not capacity:
                emu.set_last_error(87)
                return 0
            process = psapi_process(emu, handle)
            if process is None:
                return 0
            if module_handle:
                candidate = next((item for item in modules_for_process(process)
                                  if item.base == module_handle), None)
                if candidate is None:
                    emu.set_last_error(6)
                    return 0
                path = str(candidate.emu_path)
            else:
                path = str(process.path or "")
            if not path:
                emu.set_last_error(126)
                return 0
            value = (ntpath.basename(path) if "BaseName" in api_name else path)
            value = value[:capacity - 1]
            width = 2 if api_name.endswith("W") else 1
            emu.mem_write(output, value.encode("utf-16le" if width == 2 else "utf-8") +
                          bytes(width))
            return len(value)

        for module_name, prefix in (("psapi", ""), ("kernel32", "K32")):
            for operation in ("GetModuleBaseName", "GetModuleFileNameEx"):
                for suffix in ("", "A", "W"):
                    se.add_api_hook(psapi_module_name, module_name,
                                    prefix + operation + suffix)

        snapshot_owners: dict[int, int] = {}

        def toolhelp_target(emu, pid: int):
            current = emu.get_current_process()
            if pid == 0 or (current is not None and int(current.pid) == pid):
                return current
            candidates = [*emu.child_processes, *emu.get_processes()]
            manager = getattr(emu, "om", None)
            if manager is not None:
                candidates.extend(manager.objects.values())
            return next((item for item in candidates
                         if hasattr(item, "pid") and getattr(item, "pid", None) is not None
                         and int(item.pid) == pid), None)

        def create_toolhelp_snapshot(emu, api_name, original, params):
            flags, pid = (int(value) for value in params)
            handler = emu.api.load_api_handler("kernel32")
            if not flags & 0x18:
                handle = int(original(params)) if original is not None else 0
            else:
                target = toolhelp_target(emu, pid)
                if target is None:
                    emu.set_last_error(87)
                    return (1 << (emu.get_ptr_size() * 8)) - 1
                handle = int(handler.get_handle())
                snapshot = {0x8: [0, modules_for_process(target), int(target.pid)]}
                if flags & 0x2:
                    snapshot[0x2] = [0, emu.get_processes()]
                if flags & 0x4:
                    snapshot[0x4] = [0, target.threads, int(target.pid)]
                handler.snapshots[handle] = snapshot
            if handle and handle != (1 << (emu.get_ptr_size() * 8)) - 1:
                snapshot_owners[handle] = current_owner(emu)
            return handle

        se.add_api_hook(create_toolhelp_snapshot, "kernel32",
                        "CreateToolhelp32Snapshot", argc=2)

        def toolhelp_module_entry(emu, api_name, original, params):
            handle = int(params[0])
            if snapshot_owners.get(handle) != current_owner(emu):
                emu.set_last_error(6)
                return 0
            if original is not None:
                return original(params)
            handler = emu.api.load_api_handler("kernel32")
            operation = (handler.Module32First if "First" in api_name
                         else handler.Module32Next)
            return operation(emu, params, {"func_name": api_name})

        for operation in ("Module32First", "Module32Next"):
            for suffix in ("", "A", "W"):
                se.add_api_hook(toolhelp_module_entry, "kernel32",
                                operation + suffix, argc=2)

        def close_toolhelp_snapshot(emu, handle: int):
            handler = emu.api.load_api_handler("kernel32")
            if handle not in handler.snapshots:
                return None
            if snapshot_owners.get(handle) != current_owner(emu):
                emu.set_last_error(6)
                return 0
            handler.snapshots.pop(handle, None)
            snapshot_owners.pop(handle, None)
            emu.set_last_error(0)
            return 1

        virtual_files.snapshot_close_handler = close_toolhelp_snapshot
        completed_with_dll_lifecycle = se.emu.on_run_complete

        def complete_after_cpu_rollback():
            virtual_process.restore_denied_writes(se.emu)
            virtual_files.flush_pending_mapped_cpu_writes(se.emu)
            if virtual_process.isolation_denied:
                se.emu.run_queue.clear()
                se.emu.child_processes.clear()
            return completed_with_dll_lifecycle()

        se.emu.on_run_complete = complete_after_cpu_rollback
        (run_dir / "worker-stage.txt").write_text("emulating native module", encoding="utf-8")
        # Speakeasy's emulate_children loop ignores CREATE_SUSPENDED, while its
        # ResumeThread handler removes resumed children from that loop. Run the
        # main image first, then enter only children with a runnable primary thread.
        se.run_module(module, all_entrypoints=emulate_exports, emulate_children=False)
        if virtual_process.isolation_denied:
            # A stopped import/CPU hook may bypass Speakeasy's normal
            # on_run_complete callback. Roll back before snapshotting or
            # considering any queued guest work.
            virtual_process.restore_denied_writes(se.emu)
            se.emu.run_queue.clear()
            se.emu.child_processes.clear()
            if se.emu.curr_run is not None and not se.emu.curr_run.memory_regions:
                se.emu._capture_memory_layout()
        if virtual_process.cpu_isolation_failed:
            se.emu.child_processes.clear()
            virtual_process.unsupported.append(
                "Guest child execution halted after CPU memory rollback failure")
        child_runs = 0
        while se.emu.child_processes:
            child = se.emu.child_processes.pop(0)
            primary = child.threads[0]
            if primary.suspend_count:
                virtual_process.events.append({
                    "event": "virtual_process_suspended", "pid": int(child.pid),
                    "path": str(child.path), "suspend_count": int(primary.suspend_count)})
                continue
            child_runs += 1
            if child_runs > 32:
                virtual_process.unsupported.append("child process run limit exceeded")
                break
            if not child.pe_data:
                virtual_process.unsupported.append(
                    f"child executable bytes unavailable: {child.path}")
                continue
            child.pe = se.emu.load_module(data=child.pe_data)
            for region in child.pe._image.regions:
                mapping = se.emu.get_address_map(region.base)
                if mapping is not None:
                    mapping.process = child
            child.base = child.pe.base
            se.emu.curr_process = child
            se.emu.alloc_peb(child)
            se.emu.prepare_module_for_emulation(child.pe, False)
            se.emu.command_line = child.cmdline
            se.emu.curr_thread = primary
            se.emu.om.objects[primary.address] = primary
            se.emu.start()
            if virtual_process.isolation_denied:
                # A stopped child CPU hook can bypass on_run_complete just as
                # the primary run can. Restore its pending write before any
                # memory snapshot or further child execution.
                virtual_process.restore_denied_writes(se.emu)
                se.emu.run_queue.clear()
                se.emu.child_processes.clear()
                if se.emu.curr_run is not None and not se.emu.curr_run.memory_regions:
                    se.emu._capture_memory_layout()
                break
        virtual_files.flush_pending_mapped_cpu_writes(se.emu)
        virtual_files.capture_live_views(se.emu)
        virtual_files.finalize_delete_on_close(se.emu)
        (run_dir / "worker-stage.txt").write_text("collecting native report", encoding="utf-8")
        report = se.get_report().model_dump(mode="json")
        # Speakeasy calls its internal process object ID `pid` in entry-point
        # traces. Preserve that field for existing consumers and expose the
        # process's guest-visible PID alongside it for API/event correlation.
        process_pids = {
            int(process.id): int(process.pid)
            for process in (list(se.emu.get_processes()) +
                            list(se.emu.om.objects.values()))
            if getattr(process, "id", None) is not None and
            getattr(process, "pid", None) is not None
        }
        for entry in report.get("entry_points") or []:
            if entry.get("pid") in process_pids:
                entry["guest_pid"] = process_pids[entry["pid"]]
        report["network_events"] = bridge.events
        report["virtual_file_events"] = virtual_files.events
        report["virtual_registry_events"] = virtual_registry.events
        report["guest_adapter_events"] = guest_network_adapter.events
        report["guest_feature_events"] = guest_feature_configuration.events
        report["virtual_process_events"] = virtual_process.events
        report["avx_fallback_counts"] = dict(cpu.avx_fallback.counts)
        report["console_output"] = console_output.report()
        report["dll_initialization_events"] = dll_init_events
        report["crt_initialization_events"] = crt_startup.events
        report["environment_block_events"] = guest_environment.events
        for outcome in dll_init_events:
            if outcome["event"] != "dll_process_attach" or outcome["success"]:
                continue
            for entry in report.get("entry_points") or []:
                match = next((event for event in entry.get("events") or []
                              if str(event.get("api_name", "")).startswith("kernel32.LoadLibrary")
                              and event.get("ret_val") == outcome["base"]), None)
                if match is not None:
                    match["ret_val"] = "0x0"
                    break
        coverage = _api_coverage(report)
        entry_points = report.get("entry_points") or []
        instruction_count = sum(int(entry.get("instr_count") or 0) for entry in entry_points)
        # Speakeasy does not emit an error when Unicorn's count limit stops a
        # run. A capped entry with no return value has not reached a modeled
        # completion path, even if the profiler has no error to report.
        limit_reached = any(
            int(entry.get("instr_count") or 0) >= max_instructions
            and entry.get("ret_val") is None and not entry.get("error")
            for entry in entry_points
        )
        guest_exit_code = _primary_exit_code(entry_points, virtual_process.events)
        guest_entry_return = (_primary_entry_return(entry_points)
                              if guest_exit_code is None else None)
        timeout_reached = (isinstance(report.get("emulation_total_runtime"), (int, float))
                           and report["emulation_total_runtime"] >= timeout
                           and any(entry.get("ret_val") is None and not entry.get("error")
                                   for entry in entry_points))
        denied_operations = sum(event.get("event") == "network_denied"
                                for event in bridge.events)
        # Speakeasy's trace retains write chunks even when its dropped-file
        # heuristic omits the final file or leaves its read cursor at EOF.
        data_store = report.get("data") or {}
        for entry in report.get("entry_points") or []:
            for event in entry.get("events") or []:
                if event.get("event") == "file_write" and event.get("data_ref"):
                    payload = _report_blob(data_store, event["data_ref"])
                    if payload:
                        observed_size = event.get("size")
                        position = event.get("pos")
                        context = {"captured_size": len(payload)}
                        if type(observed_size) is int:
                            context["observed_size"] = observed_size
                            context["partial_snapshot"] = len(payload) < observed_size
                        if isinstance(position, dict) and type(position.get("tick")) is int:
                            context["event_tick"] = position["tick"]
                        catalog.add(payload, "file_write", guest_path=event.get("path") or "",
                                    context=context)
            for segment in entry.get("dynamic_code_segments") or []:
                try:
                    base = int(segment["base"], 0)
                    observed_size = int(segment["size"], 0)
                    size = min(observed_size, 4 * 1024 * 1024)
                    if observed_size > size:
                        catalog.note_omission(f"executed_dynamic_code:0x{base:x}",
                                              observed_size - size,
                                              "dynamic_segment_capture_limit")
                    if size > 0:
                        payload = se.mem_read(base, size)
                        catalog.add(payload, f"executed_dynamic_code:0x{base:x}", kind="shellcode")
                        catalog.carve_pe(payload, f"executed_dynamic_code:0x{base:x}")
                except (ValueError, OSError):
                    pass
        for item in se.emu.get_file_manager().files:
            if item.config or not item.bytes_written:
                continue
            data = item.data
            payload = data.getvalue() if isinstance(data, io.BytesIO) else data
            if not isinstance(payload, bytes) or not payload:
                continue
            catalog.add(payload, "virtual_file_final", guest_path=item.path)
        strings = (report.get("strings") or {}).get("in_memory") or {}
        for value in (strings.get("ansi") or []) + (strings.get("unicode") or []):
            lower = value.lower()
            if len(value) >= 64 and any(marker in lower for marker in (
                    "powershell", "wscript", "function ", "<script", "frombase64string", "invoke-expression")):
                catalog.add(value.encode("utf-8", errors="replace"), "decoded_memory_string", kind="script")
        scanned = 0
        for tag, base, size, is_free, proc, blob in se.get_memory_dumps():
            # Freed maps can remain readable in Speakeasy's backing arena.
            # Their bytes are historical evidence, not live final memory.
            if is_free:
                continue
            remaining = MAX_MEMORY_SCAN - scanned
            if len(blob) > remaining:
                catalog.note_omission(f"memory:{tag}:0x{base:x}",
                                      len(blob) - max(0, remaining),
                                      "memory_scan_run_limit")
                blob = blob[:max(0, remaining)]
            if not blob:
                continue
            scanned += len(blob)
            # Speakeasy maps dozens of decoy system modules. Their PE headers
            # are emulator furniture, not extracted malware payloads.
            catalog.carve_pe(blob, f"memory:{tag}:0x{base:x}",
                             skip_offset_zero=str(tag).startswith("emu.module."))
            if 0 < len(blob) <= 4 * 1024 * 1024 and any(x in str(tag).lower() for x in ("alloc", "shellcode", "dynamic")):
                catalog.add(blob, f"memory:{tag}:0x{base:x}", kind="memory")
        remote_threads = [(index, event) for index, event in enumerate(virtual_process.events)
                          if event.get("event") == "virtual_remote_thread_create"
                          and event.get("success") and type(event.get("pid")) is int]
        for item in catalog.items:
            context = item.get("context")
            if not isinstance(context, dict) or "write_order" not in context:
                continue
            associated = [
                {"thread_id": event.get("thread_id"),
                 "start_address": event.get("start_address"), "event_order": index}
                for index, event in remote_threads
                if index > context["write_order"] and event["pid"] == context["target_pid"]
            ][:16]
            if associated:
                context["subsequent_remote_threads"] = associated
        (run_dir / "engine-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        (run_dir / "worker-stage.txt").write_text("saving native manifest", encoding="utf-8")
        report["artifact_capture"] = catalog.capture_summary()
        catalog.save_manifest()
        errors = [_engine_error_text(e) for e in (report.get("errors") or []) if e]
        errors.extend(_engine_error_text(ep["error"])
                      for ep in (report.get("entry_points") or []) if ep.get("error"))
        errors.extend(virtual_files.unsupported)
        errors.extend(bridge.unsupported)
        errors.extend(virtual_registry.unsupported)
        errors.extend(virtual_process.unsupported)
        errors.extend(crt_streams.unsupported)
        errors.extend(crt_startup.unsupported)
        errors.extend(guest_environment.unsupported)
        errors.extend(ui_language.unsupported)
        errors.extend(win_messages.unsupported)
        errors.extend(guest_strings.unsupported)
        errors.extend(guest_delay_imports.unsupported)
        errors.extend(guest_lsa.unsupported)
        errors.extend(guest_network_adapter.unsupported)
        errors.extend(guest_feature_configuration.unsupported)
        if limit_reached:
            errors.append(f"Native instruction budget exhausted at {max_instructions} instructions")
        if timeout_reached:
            errors.append(f"Native emulation exceeded the {timeout}-second wall-clock limit")
        for failed in static_attach_failures:
            errors.append(f"Static companion initialization failed; EXE entry was not run: {failed}")
        if coverage["signature_only_calls"]:
            names = ", ".join(item["api"] for item in coverage["signature_only_calls"][:20])
            suffix = " ..." if len(coverage["signature_only_calls"]) > 20 else ""
            errors.append(f"Signature-only WinAPI behavior has no modeled side effects: {names}{suffix}")
        (run_dir / "worker-stage.txt").write_text("closing native engine", encoding="utf-8")
        return {
            "engine": "speakeasy-unicorn",
            "engine_report": "engine-report.json",
            "artifacts": catalog.items,
            "artifact_groups": catalog.groups(),
            "artifact_capture": catalog.capture_summary(),
            "entry_points": len(report.get("entry_points") or []),
            "api_coverage": coverage,
            "instruction_count": instruction_count,
            "instruction_limit_reached": limit_reached,
            "timeout_reached": timeout_reached,
            "guest_exit_code": guest_exit_code,
            "guest_entry_return": guest_entry_return,
            "completion_reason": ("exit_process" if guest_exit_code is not None else
                                  "instruction_limit" if limit_reached else
                                  "timeout" if timeout_reached else
                                  "error" if errors else
                                  "entry_return" if guest_entry_return is not None else
                                  "unknown"),
            "denied_operations": denied_operations,
            "console_output": console_output.report(),
            "dll_initialization_events": dll_init_events,
            "errors": errors,
        }
    finally:
        bridge.close()
        se.shutdown()
        (run_dir / "worker-stage.txt").write_text("native engine closed", encoding="utf-8")

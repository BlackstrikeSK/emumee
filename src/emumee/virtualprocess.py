"""Bound and record guest process-memory writes in the CPU emulator."""

from __future__ import annotations

import hashlib
import io
import ntpath
import shlex
from contextlib import contextmanager

from speakeasy.winenv import arch as e_arch

from .artifacts import ArtifactCatalog, MAX_ARTIFACT, MAX_MEMORY_SCAN
from .pe import InvalidSample, inspect_pe_header

PROCESS_TERMINATE = 0x0001
PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_DUP_HANDLE = 0x0040
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_ALL_ACCESS = 0x001FFFFF
MEM_RELEASE = 0x8000
MAX_TRANSIENT_ALLOCATION = 4 * 1024 * 1024
MAX_TRANSIENT_OBSERVATIONS = 128
MAX_GUEST_STRING_CHARS = 65536
THREAD_SUSPEND_RESUME = 0x0002
THREAD_TERMINATE = 0x0001
THREAD_QUERY_INFORMATION = 0x0040
THREAD_QUERY_LIMITED_INFORMATION = 0x0800
THREAD_ALL_ACCESS = 0x001FFFFF
SYNCHRONIZE = 0x00100000
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x102
WAIT_FAILED = 0xFFFFFFFF


class _GuestApiMemoryDenied(BaseException):
    """Unwind an engine API handler before it consumes a foreign guest page."""

    def __init__(self, access: str, address: int, size: int, reason: str):
        self.access = access
        self.address = address
        self.size = size
        self.reason = reason
        super().__init__(reason)


class VirtualProcessBridge:
    def __init__(self, catalog: ArtifactCatalog,
                 staged_sources: dict[str, bytes] | None = None):
        self.catalog = catalog
        self.staged_sources = {key.casefold(): value
                               for key, value in (staged_sources or {}).items()}
        self.events: list[dict] = []
        self.unsupported: list[str] = []
        self.captured_bytes = 0
        self.transient_scanned_bytes = 0
        self.transient_observations = 0
        self.process_access: dict[int, int] = {}
        self.process_handle_owners: dict[int, int] = {}
        self.shared_process_handle_owners: dict[int, set[int]] = {}
        self.process_handle_flags: dict[tuple[int, int], int] = {}
        self.closed_process_handles: set[int] = set()
        self.thread_access: dict[int, int] = {}
        self.thread_handle_owners: dict[int, int] = {}
        self.shared_thread_handle_owners: dict[int, set[int]] = {}
        self.thread_handle_flags: dict[tuple[int, int], int] = {}
        self.closed_thread_handles: set[int] = set()
        self.terminated_threads: set[int] = set()
        self.thread_exit_codes: dict[int, int] = {}
        self.created_processes: set[int] = set()
        self.terminated_processes: set[int] = set()
        self.process_exit_codes: dict[int, int] = {}
        self.cleaned_processes: set[int] = set()
        self.process_cleanup_handler = None
        self.registry_cleanup_handler = None
        self._released_extents: dict[int, int] = {}
        self._pending_cpu_writes: list[tuple[int, bytes]] = []
        self.cpu_isolation_failed = False
        self.isolation_denied = False
        self._foreign_allocation_seen = False
        self._dispatch_guard_names: list[str] = []
        self._api_memory_allowances: list[tuple[int, int, str]] = []
        self.file_cpu_write_handler = None
        self.file_cpu_flush_handler = None
        self.cpu_instruction_handler = None
        self.file_api_write_handler = None
        self.file_duplicate_handler = None
        self.file_close_handler = None
        self._dispatch_guard_installed = False
        self._active_segment_thread = None
        self._segment_states: dict[int, bytes] = {}
        self._run_context_guard_installed = False
        self.primary_image_bases: set[int] = set()
        self._primary_process = None

    def install(self, emulator) -> None:
        emulator.add_mem_read_hook(self._cpu_read)
        emulator.add_mem_write_hook(self._cpu_write)
        emulator.add_code_hook(self._cpu_execute)
        for module in ("kernel32", "ntdll"):
            for name, argc in (("RtlMoveMemory", 3), ("RtlCopyMemory", 3),
                               ("RtlZeroMemory", 2)):
                emulator.add_api_hook(self._bulk_memory_api, module, name, argc=argc)
        for name in ("memcpy", "memmove", "memset", "memcmp"):
            emulator.add_api_hook(self._bulk_memory_api, "msvcrt", name, argc=3)
        emulator.add_api_hook(self._bulk_memory_api, "msvcrt", "_memicmp", argc=3,
                              call_conv=e_arch.CALL_CONV_CDECL)
        emulator.add_api_hook(self._bulk_memory_api,
                              "api-ms-win-crt-private-l1-1-0", "_o__memicmp",
                              argc=3, call_conv=e_arch.CALL_CONV_CDECL)
        for name, argc in (("lstrlen", 1), ("lstrcmp", 2), ("lstrcmpi", 2),
                           ("lstrcpy", 2), ("lstrcpyn", 3), ("lstrcat", 2)):
            for suffix in ("A", "W"):
                emulator.add_api_hook(self._string_memory_api, "kernel32",
                                      name + suffix, argc=argc)
        emulator.add_api_hook(self._write_process_memory, "kernel32",
                              "WriteProcessMemory", argc=5)
        emulator.add_api_hook(self._read_process_memory, "kernel32",
                              "ReadProcessMemory", argc=5)
        emulator.add_api_hook(self._create_remote_thread, "kernel32",
                              "CreateRemoteThread", argc=7)
        emulator.add_api_hook(self._virtual_alloc_ex, "kernel32",
                              "VirtualAllocEx", argc=5)
        emulator.add_api_hook(self._virtual_alloc, "kernel32", "VirtualAlloc", argc=4)
        emulator.add_api_hook(self._virtual_protect_ex, "kernel32",
                              "VirtualProtectEx", argc=5)
        emulator.add_api_hook(self._virtual_protect, "kernel32",
                              "VirtualProtect", argc=4)
        emulator.add_api_hook(self._virtual_free_ex, "kernel32",
                              "VirtualFreeEx", argc=4)
        emulator.add_api_hook(self._virtual_free, "kernel32", "VirtualFree", argc=3)
        emulator.add_api_hook(self._open_process, "kernel32", "OpenProcess", argc=3)
        emulator.add_api_hook(self._is_debugger_present, "kernel32",
                              "IsDebuggerPresent", argc=0)
        emulator.add_api_hook(self._check_remote_debugger_present, "kernel32",
                              "CheckRemoteDebuggerPresent", argc=2)
        emulator.add_api_hook(self._nt_query_information_process, "ntdll",
                              "NtQueryInformationProcess", argc=5)
        emulator.add_api_hook(self._terminate_process, "kernel32", "TerminateProcess", argc=2)
        emulator.add_api_hook(self._get_exit_code_process, "kernel32", "GetExitCodeProcess", argc=2)
        emulator.add_api_hook(self._exit_process, "kernel32", "ExitProcess", argc=1)
        emulator.add_api_hook(self._crt_exit, "api-ms-win-crt-private-l1-1-0",
                              "_o_exit", argc=1)
        emulator.add_api_hook(self._open_thread, "kernel32", "OpenThread", argc=3)
        emulator.add_api_hook(self._create_thread, "kernel32", "CreateThread", argc=6)
        emulator.add_api_hook(self._terminate_thread, "kernel32", "TerminateThread", argc=2)
        emulator.add_api_hook(self._get_exit_code_thread, "kernel32", "GetExitCodeThread", argc=2)
        emulator.add_api_hook(self._exit_thread, "kernel32", "ExitThread", argc=1)
        emulator.add_api_hook(self._wait_for_single_object, "kernel32", "WaitForSingleObject", argc=2)
        emulator.add_api_hook(self._duplicate_handle, "kernel32", "DuplicateHandle", argc=7)
        emulator.add_api_hook(self._set_handle_information, "kernel32", "SetHandleInformation", argc=3)
        emulator.add_api_hook(self._get_handle_information, "kernel32", "GetHandleInformation", argc=2)
        for name in ("CreateProcessA", "CreateProcessW"):
            emulator.add_api_hook(self._create_process, "kernel32", name, argc=10)
        emulator.add_api_hook(self._winexec, "kernel32", "WinExec", argc=2)
        for name in ("CreateProcessInternalA", "CreateProcessInternalW"):
            emulator.add_api_hook(self._create_process, "kernel32", name, argc=12)
        emulator.add_api_hook(self._resume_thread, "kernel32", "ResumeThread", argc=1)
        emulator.add_api_hook(self._suspend_thread, "kernel32", "SuspendThread", argc=1)

    def install_dispatch_memory_guard(self, emu) -> None:
        """Guard Python-side guest-memory access during every imported API call."""
        if self._dispatch_guard_installed:
            return
        self._dispatch_guard_installed = True
        original_dispatch = emu.handle_import_func
        original_read = emu.mem_read
        original_write = emu.mem_write
        original_map = getattr(emu, "mem_map", None)
        original_alloc_peb = getattr(emu, "alloc_peb", None)

        def check(access: str, address: int, size: int) -> None:
            if not self._dispatch_guard_names or size <= 0:
                return
            if not (self.created_processes or self._foreign_allocation_seen or
                    self._released_extents):
                return
            process = emu.get_current_process()
            if process is None:
                return
            if self._released_range(address, size):
                raise _GuestApiMemoryDenied(access, address, size, "released memory")
            if any(start <= address and address + size <= end and access[0] in modes
                   for start, end, modes in self._api_memory_allowances):
                return
            if self._owner_conflict(emu, address, size, process):
                raise _GuestApiMemoryDenied(access, address, size,
                                            "different guest process")

        def guarded_read(address, size):
            check("read", int(address), int(size))
            return original_read(address, size)

        def guarded_write(address, data):
            check("write", int(address), len(data))
            result = original_write(address, data)
            if self.file_api_write_handler is not None:
                self.file_api_write_handler(emu, int(address), len(data))
            return result

        def guarded_map(*args, **kwargs):
            # Some installed API handlers create private maps with no tag, so
            # Speakeasy leaves their process unset. Assign the calling guest
            # process here; preserve explicitly shared or owned mappings.
            if self._dispatch_guard_names and original_map is not None:
                size = int(args[0] if args else kwargs.get("size", 0))
                base = kwargs.get("base", args[1] if len(args) > 1 else None)
                tag = kwargs.get("tag", args[3] if len(args) > 3 else None)
                if size <= 0 or size > MAX_ARTIFACT:
                    raise _GuestApiMemoryDenied("map", int(base or 0), size,
                                                "API map size exceeds limit")
                if base == 0x1000 and tag is None:
                    raise _GuestApiMemoryDenied("map", int(base), size,
                                                "untagged API map at reserved page")
                shared = kwargs.get("shared", args[5] if len(args) > 5 else False)
                owner = kwargs.get("process", args[6] if len(args) > 6 else None)
                process = emu.get_current_process()
                if process is not None and owner is None and not shared:
                    if len(args) > 6:
                        args = (*args[:6], process, *args[7:])
                    else:
                        kwargs = {**kwargs, "process": process}
            return original_map(*args, **kwargs)

        def guarded_alloc_peb(process):
            peb = original_alloc_peb(process)
            self.bind_process_private_maps(emu, process)
            return peb

        def guarded_dispatch(dll, name):
            api_name = f"{dll}.{name}"
            self._dispatch_guard_names.append(api_name)
            try:
                return original_dispatch(dll, name)
            except _GuestApiMemoryDenied as denied:
                self.events.append({"event": "virtual_handler_memory_denied",
                                    "api": api_name, "access": denied.access,
                                    "address": denied.address, "size": denied.size,
                                    "reason": denied.reason})
                if emu.curr_run is not None:
                    emu.curr_run.error = emu.get_error_info(
                        f"{api_name}: guest API {denied.access} denied: {denied.reason}",
                        emu.get_pc())
                self._halt_guest_after_isolation_denial(emu)
                emu.stop()
                return None
            finally:
                self._dispatch_guard_names.pop()

        emu.mem_read = guarded_read
        emu.mem_write = guarded_write
        if original_map is not None:
            emu.mem_map = guarded_map
        if original_alloc_peb is not None:
            emu.alloc_peb = guarded_alloc_peb
        emu.handle_import_func = guarded_dispatch
        seen = set()
        for process in (getattr(emu, "curr_process", None),
                        *getattr(emu, "processes", [])):
            if process is not None and id(process) not in seen:
                self.bind_process_private_maps(emu, process)
                seen.add(id(process))

    @staticmethod
    def bind_process_private_maps(emu, process) -> None:
        """Correct ownership of per-process structures made under a parent API."""
        peb = getattr(process, "peb", None)
        ldr = getattr(process, "peb_ldr_data", None)
        addresses = [
            (getattr(peb, "address", 0), "emu.struct.PEB."),
            (getattr(getattr(peb, "object", None), "ProcessParameters", 0),
             ".ProcessParameters."),
            (getattr(ldr, "address", 0), "emu.struct.PEB_LDR_DATA."),
        ]
        addresses.extend((getattr(entry, "address", 0), "emu.struct.LDR_DATA_TABLE_ENTRY.")
                         for entry in getattr(process, "ldr_entries", []))
        addresses.extend((int(getattr(thread, "stack_base", 0) or 0) - 1, "emu.stack.")
                         for thread in getattr(process, "threads", [])
                         if getattr(thread, "stack_base", 0))
        for address, expected_tag in addresses:
            if not address:
                continue
            mapping = emu.get_address_map(int(address))
            if (mapping is not None and not getattr(mapping, "shared", False) and
                    expected_tag in str(getattr(mapping, "tag", ""))):
                mapping.process = process

    def install_run_context_guard(self, emu) -> None:
        """Select a private stack and saved FS/GS page before each guest run."""
        if self._run_context_guard_installed:
            return
        self._run_context_guard_installed = True
        original_start = emu.start
        original_next_run = emu._exec_next_run
        original_complete = emu.on_run_complete

        def prepare_next_run():
            queued = getattr(emu, "run_queue", [])
            if queued:
                run = queued[0]
                thread = getattr(run, "thread", None) or emu.get_current_thread()
                process = (getattr(run, "process_context", None) or
                           getattr(thread, "process", None) or emu.get_current_process())
                if process is not None and thread is not None:
                    if self._primary_process is None:
                        self._primary_process = process
                    if process is self._primary_process:
                        for base in self.primary_image_bases:
                            image_map = emu.get_address_map(base)
                            if (image_map is None or image_map.base != base or
                                    getattr(image_map, "shared", False) or
                                    getattr(image_map, "process", None) not in (None, process)):
                                self.unsupported.append("primary image map owner mismatch")
                                raise ValueError("primary image map owner mismatch")
                            image_map.process = process
                    if getattr(thread, "process", None) is None:
                        thread.process = process
                    stack_base = int(getattr(thread, "stack_base", 0) or 0)
                    if not stack_base:
                        stack_size = int(getattr(emu.config, "stack_size", 0) or
                                         getattr(getattr(process, "pe", None), "stack_size", 0) or
                                         0x100000)
                        if not 0 < stack_size <= MAX_ARTIFACT:
                            self.unsupported.append("guest thread stack size exceeds limit")
                            raise ValueError("guest thread stack size exceeds limit")
                        stack_base, _ = emu.alloc_stack(stack_size)
                        thread.stack_base = stack_base
                        thread.stack_commit = int(
                            getattr(getattr(process, "pe", None), "stack_commit", 0) or
                            stack_size)
                        stack_map = emu.get_address_map(stack_base - 1)
                        if (stack_map is None or not str(getattr(stack_map, "tag", "")).startswith(
                                "emu.stack.")):
                            self.unsupported.append("guest thread stack map unavailable")
                            raise ValueError("guest thread stack map unavailable")
                        stack_map.process = process
                        self.events.append({
                            "event": "virtual_process_stack", "pid": int(process.pid),
                            "tid": int(thread.tid), "address": int(stack_map.base),
                            "size": int(stack_map.size)})
                    else:
                        stack_map = emu.get_address_map(stack_base - 1)
                        if (stack_map is None or not str(getattr(stack_map, "tag", "")).startswith(
                                "emu.stack.") or
                                getattr(stack_map, "process", None) not in (None, process)):
                            self.unsupported.append("guest thread stack owner mismatch")
                            raise ValueError("guest thread stack owner mismatch")
                        stack_map.process = process
                    emu.stack_base = stack_base
                    self.bind_process_private_maps(emu, process)
                    if self._active_segment_thread is None:
                        self._active_segment_thread = thread
                    elif self._active_segment_thread is not thread:
                        segment_kind = "gs" if emu.get_ptr_size() == 8 else "fs"
                        segment_address = int(getattr(emu, f"{segment_kind}_addr", 0) or 0)
                        segment_map = (emu.get_address_map(segment_address)
                                       if segment_address else None)
                        if (segment_map is None or
                                not str(getattr(segment_map, "tag", "")).startswith(
                                    f"emu.segment.{segment_kind}.") or
                                not 0 < int(segment_map.size) <= emu.page_size):
                            self.unsupported.append("guest TEB segment unavailable")
                            raise ValueError("guest TEB segment unavailable")
                        self._segment_states[id(self._active_segment_thread)] = emu.mem_read(
                            segment_map.base, segment_map.size)
                        data = self._segment_states.get(id(thread), b"\0" * segment_map.size)
                        emu.mem_write(segment_map.base, data)
                        self._active_segment_thread = thread
                        self.events.append({
                            "event": "virtual_process_segment_reset", "pid": int(process.pid),
                            "tid": int(thread.tid), "address": int(segment_map.base),
                            "size": int(segment_map.size)})
        def guarded_start(*args, **kwargs):
            prepare_next_run()
            return original_start(*args, **kwargs)

        def guarded_next_run(*args, **kwargs):
            prepare_next_run()
            return original_next_run(*args, **kwargs)

        def guarded_complete(*args, **kwargs):
            run = getattr(emu, "curr_run", None)
            run_type = str(getattr(run, "type", ""))
            thread = getattr(run, "thread", None)
            if (thread is not None and not getattr(run, "error", None) and
                    (run_type == "thread" or run_type.startswith(
                        ("injected_thread_", "thread.")))):
                self._record_thread_exit(emu, thread, int(emu.get_return_val()),
                                         "thread_return")
            return original_complete(*args, **kwargs)

        emu.start = guarded_start
        emu._exec_next_run = guarded_next_run
        emu.on_run_complete = guarded_complete

    @contextmanager
    def _allow_api_memory(self, address: int, size: int, modes: str):
        allowance = (address, address + size, modes)
        self._api_memory_allowances.append(allowance)
        try:
            yield
        finally:
            self._api_memory_allowances.remove(allowance)

    def _halt_guest_after_isolation_denial(self, emu) -> None:
        self.isolation_denied = True
        getattr(emu, "child_processes", []).clear()

    @staticmethod
    def _raw_thread(emu, handle: int):
        thread = emu.get_object_from_handle(handle)
        if (thread is None or not hasattr(thread, "tid") or
                not hasattr(thread, "suspend_count") or not hasattr(thread, "process")):
            return None
        return thread

    @staticmethod
    def _owns_handle(owners: dict[int, int], shared: dict[int, set[int]],
                     handle: int, process_id: int) -> bool:
        return owners.get(handle) == process_id or process_id in shared.get(handle, ())

    @staticmethod
    def _release_handle_owner(owners: dict[int, int], shared: dict[int, set[int]],
                              handle: int, process_id: int) -> bool:
        """Release one guest table entry; return whether other owners remain."""
        others = shared.get(handle)
        if owners.get(handle) == process_id:
            if others:
                owners[handle] = others.pop()
                if not others:
                    shared.pop(handle, None)
                return True
            owners.pop(handle, None)
            return False
        if others is not None:
            others.discard(process_id)
            if not others:
                shared.pop(handle, None)
        return handle in owners

    def _handle_flag_entry(self, emu, handle: int):
        """Resolve only a real process/thread handle issued to this guest process."""
        pseudo = (1 << (emu.get_ptr_size() * 8)) - 1
        if handle & pseudo == pseudo:
            return None
        owner = id(emu.get_current_process())
        if self._process(emu, handle) is not None:
            return self.process_handle_flags, (owner, handle), "process"
        if self._thread(emu, handle) is not None:
            return self.thread_handle_flags, (owner, handle), "thread"
        file_handler = getattr(self, "file_flag_entry_handler", None)
        if file_handler is not None:
            return file_handler(emu, handle)
        return None

    def _missing_handle_flag_entry(self, emu, api_name: str, handle: int,
                                   event: dict) -> int:
        manager = emu.get_file_manager() if hasattr(emu, "get_file_manager") else None
        obj = emu.get_object_from_handle(handle)
        if (handle in getattr(manager, "file_handles", {}) or
                handle in getattr(manager, "file_maps", {})):
            emu.set_last_error(6)
            event["reason"] = "invalid or foreign file/mapping handle"
        elif (obj is not None and self._raw_process(emu, handle) is None and
              self._raw_thread(emu, handle) is None):
            emu.set_last_error(50)
            event["reason"] = "non-process/thread handle flags unsupported"
            warning = f"{api_name}: non-process/thread handle flags unsupported"
            if warning not in self.unsupported:
                self.unsupported.append(warning)
        else:
            emu.set_last_error(6)
            event["reason"] = "invalid or foreign process/thread handle"
        return 0

    def _set_handle_information(self, emu, api_name, original, params):
        handle, mask, flags = (int(value) for value in params)
        event = {"event": "virtual_handle_information_set", "api": api_name,
                 "handle": handle, "mask": mask, "flags": flags, "success": False}
        self.events.append(event)
        entry = self._handle_flag_entry(emu, handle)
        if entry is None:
            return self._missing_handle_flag_entry(emu, api_name, handle, event)
        if mask & ~3:
            emu.set_last_error(87)
            event["reason"] = "unsupported handle flag mask"
            return 0
        table, key, kind = entry
        previous = table.get(key, 0)
        table[key] = (previous & ~mask) | (flags & mask)
        event.update({"object_type": kind, "previous_flags": previous,
                      "result_flags": table[key], "success": True})
        emu.set_last_error(0)
        return 1

    def _get_handle_information(self, emu, api_name, original, params):
        handle, output = (int(value) for value in params)
        event = {"event": "virtual_handle_information_get", "api": api_name,
                 "handle": handle, "success": False}
        self.events.append(event)
        entry = self._handle_flag_entry(emu, handle)
        if entry is None:
            return self._missing_handle_flag_entry(emu, api_name, handle, event)
        if not output:
            emu.set_last_error(87)
            event["reason"] = "missing output pointer"
            return 0
        table, key, kind = entry
        flags = table.get(key, 0)
        try:
            emu.mem_write(output, flags.to_bytes(4, "little"))
        except Exception:
            emu.set_last_error(998)
            event["reason"] = "invalid guest output pointer"
            return 0
        event.update({"object_type": kind, "flags": flags, "success": True})
        emu.set_last_error(0)
        return 1

    def _thread(self, emu, handle: int):
        if (handle in self.closed_thread_handles or
                not self._owns_handle(self.thread_handle_owners,
                                      self.shared_thread_handle_owners, handle,
                                      id(emu.get_current_process()))):
            return None
        return self._raw_thread(emu, handle)

    def _thread_operation_allowed(self, emu, handle: int) -> bool:
        if handle in self.closed_thread_handles or self._thread(emu, handle) is None:
            emu.set_last_error(6)
            return False
        if id(self._thread(emu, handle)) in self.terminated_threads:
            emu.set_last_error(5)
            return False
        if not self.thread_access.get(handle, THREAD_ALL_ACCESS) & THREAD_SUSPEND_RESUME:
            emu.set_last_error(5)
            return False
        return True

    def _open_thread(self, emu, api_name, original, params):
        access, inherit, tid = (int(value) for value in params)
        event = {"event": "virtual_thread_open", "api": api_name,
                 "tid": tid, "requested_access": access,
                 "inherit": bool(inherit), "success": False}
        self.events.append(event)
        thread = emu.get_object_from_id(tid)
        if (thread is None or not hasattr(thread, "tid") or
                not hasattr(thread, "suspend_count") or id(thread) in self.terminated_threads):
            emu.set_last_error(87)
            event["reason"] = "thread id absent from guest"
            return 0
        if access & ~THREAD_ALL_ACCESS:
            emu.set_last_error(87)
            event["reason"] = "requested access outside modeled thread rights"
            return 0
        handle = int(emu.get_object_handle(thread))
        self.thread_access[handle] = access
        owner = id(emu.get_current_process())
        self.thread_handle_owners[handle] = owner
        self.closed_thread_handles.discard(handle)
        self.thread_handle_flags[(owner, handle)] = int(bool(inherit))
        event["handle"] = handle
        event["success"] = True
        emu.set_last_error(0)
        return handle

    def _create_thread(self, emu, api_name, original, params):
        flags = int(params[4])
        result = int(original(params))
        if result:
            thread = self._raw_thread(emu, result)
            if thread is not None:
                self.thread_access[result] = THREAD_ALL_ACCESS
                owner = id(emu.get_current_process())
                self.thread_handle_owners[result] = owner
                self.thread_handle_flags[(owner, result)] = 0
                if flags & 4:
                    thread.suspend_count = max(1, int(thread.suspend_count))
                self.events.append({"event": "virtual_thread_create", "api": api_name,
                                    "handle": result, "tid": int(thread.id),
                                    "suspend_count": int(thread.suspend_count),
                                    "success": True})
        return result

    def _suspend_thread(self, emu, api_name, original, params):
        handle = int(params[0])
        if not self._thread_operation_allowed(emu, handle):
            self.events.append({"event": "virtual_thread_suspend", "api": api_name,
                                "handle": handle, "success": False})
            return 0xFFFFFFFF
        thread = self._thread(emu, handle)
        previous = int(thread.suspend_count)
        result = int(original(params))
        self.events.append({"event": "virtual_thread_suspend", "api": api_name,
                            "handle": handle, "tid": int(thread.tid),
                            "previous_suspend_count": previous,
                            "suspend_count": int(thread.suspend_count),
                            "success": result != -1})
        return result

    def _resume_thread(self, emu, api_name, original, params):
        handle = int(params[0])
        if not self._thread_operation_allowed(emu, handle):
            self.events.append({"event": "virtual_thread_resume", "api": api_name,
                                "handle": handle, "success": False})
            return 0xFFFFFFFF
        thread = self._thread(emu, handle)
        children = emu.child_processes
        process = getattr(thread, "process", None)
        previous = int(thread.suspend_count)
        if process in children and getattr(process, "threads", [None])[0] is thread:
            if previous > 0:
                thread.suspend_count = previous - 1
            self.events.append({"event": "virtual_thread_resume", "api": api_name,
                                "handle": handle, "pid": int(process.pid),
                                "previous_suspend_count": previous,
                                "suspend_count": int(thread.suspend_count),
                                "success": True})
            emu.set_last_error(0)
            return previous
        if previous != 1:
            if previous > 1:
                thread.suspend_count = previous - 1
            self.events.append({"event": "virtual_thread_resume", "api": api_name,
                                "handle": handle, "pid": int(process.pid) if process else None,
                                "previous_suspend_count": previous,
                                "suspend_count": int(thread.suspend_count),
                                "success": True})
            emu.set_last_error(0)
            return previous
        result = original(params)
        self.events.append({"event": "virtual_thread_resume", "api": api_name,
                            "handle": handle, "pid": int(process.pid) if process else None,
                            "previous_suspend_count": previous,
                            "suspend_count": int(thread.suspend_count),
                            "success": result != -1})
        return result

    def _terminate_thread(self, emu, api_name, original, params):
        handle, exit_code = (int(value) for value in params)
        event = {"event": "virtual_thread_terminate", "api": api_name,
                 "handle": handle, "exit_code": exit_code & 0xFFFFFFFF,
                 "success": False}
        self.events.append(event)
        thread = self._thread(emu, handle)
        if thread is None:
            emu.set_last_error(6)
            event["reason"] = "invalid thread handle"
            return 0
        event["tid"] = int(thread.tid)
        process = thread.process
        if process is None or (process is not emu.get_current_process() and
                               id(process) not in self.created_processes):
            emu.set_last_error(50)
            event["reason"] = "persona thread termination unsupported"
            self.unsupported.append(f"{api_name}: persona thread termination")
            return 0
        if not self.thread_access.get(handle, THREAD_ALL_ACCESS) & THREAD_TERMINATE:
            emu.set_last_error(5)
            event["reason"] = "thread handle lacks terminate right"
            return 0
        if id(thread) in self.terminated_threads:
            emu.set_last_error(5)
            event["reason"] = "thread already terminated"
            return 0

        current = emu.get_current_thread()
        queued = [run for run in emu.run_queue if getattr(run, "thread", None) is thread]
        suspended = [run for run in emu.suspended_runs
                     if getattr(run, "thread", None) is thread]
        child_primary = (process in emu.child_processes and
                         bool(getattr(process, "threads", [])) and
                         process.threads[0] is thread)
        if thread is not current and not queued and not suspended and not child_primary:
            emu.set_last_error(50)
            event["reason"] = "thread has no modeled pending run"
            self.unsupported.append(f"{api_name}: unmodeled thread lifetime")
            return 0

        emu.run_queue[:] = [run for run in emu.run_queue
                            if getattr(run, "thread", None) is not thread]
        emu.suspended_runs[:] = [run for run in emu.suspended_runs
                                 if getattr(run, "thread", None) is not thread]
        self._record_thread_exit(emu, thread, exit_code, "TerminateThread")
        if child_primary and id(process) in self.terminated_processes:
            emu.child_processes[:] = [child for child in emu.child_processes
                                      if child is not process]
            emu.kill_process(process)
        if thread is current:
            emu.exit_process()  # End only this run; other queued threads remain.
        event.update({"pid": int(process.pid), "cancelled_runs": len(queued) + len(suspended),
                      "success": True})
        emu.set_last_error(0)
        return 1

    def _record_thread_exit(self, emu, thread, exit_code: int, reason: str,
                            *, record_process: bool = True) -> None:
        if id(thread) in self.terminated_threads:
            return
        process = getattr(thread, "process", None)
        code = exit_code & 0xFFFFFFFF
        self.terminated_threads.add(id(thread))
        self.thread_exit_codes[id(thread)] = code
        self.events.append({"event": "virtual_thread_exit", "reason": reason,
                            "tid": int(thread.tid),
                            "pid": int(process.pid) if process is not None else None,
                            "exit_code": code, "success": True})
        if not record_process or process is None or id(process) in self.terminated_processes:
            return
        if (emu.get_current_process() is process and
                emu.get_current_thread() is not thread):
            return
        pending = (*getattr(emu, "run_queue", ()),
                   *getattr(emu, "suspended_runs", ()))
        if any((getattr(run, "process_context", None) is process or
                getattr(getattr(run, "thread", None), "process", None) is process)
               and getattr(run, "thread", None) is not thread for run in pending):
            return
        self.terminated_processes.add(id(process))
        self.process_exit_codes[id(process)] = code
        self.events.append({"event": "virtual_process_exit", "api": reason,
                            "pid": int(process.pid), "exit_code": code,
                            "success": True})
        self._cleanup_process(emu, process)

    def _exit_thread(self, emu, api_name, original, params):
        thread = emu.get_current_thread()
        if thread is not None:
            self._record_thread_exit(emu, thread, int(params[0]), "ExitThread")
        return original(params)

    def _wait_for_single_object(self, emu, api_name, original, params):
        handle, timeout = (int(value) for value in params)
        event = {"event": "virtual_object_wait", "api": api_name,
                 "handle": handle, "timeout": timeout & 0xFFFFFFFF}
        self.events.append(event)
        thread = self._raw_thread(emu, handle)
        process = self._raw_process(emu, handle) if thread is None else None
        if thread is not None:
            if self._thread(emu, handle) is None:
                error, reason = 6, "invalid or foreign thread handle"
            elif not self.thread_access.get(handle, THREAD_ALL_ACCESS) & SYNCHRONIZE:
                error, reason = 5, "thread handle lacks synchronize right"
            else:
                error, reason = 0, ""
            signaled = (id(thread) in self.terminated_threads or
                        id(getattr(thread, "process", None)) in self.terminated_processes)
            event["object_type"] = "thread"
        elif process is not None or handle & ((1 << (emu.get_ptr_size() * 8)) - 1) == (
                (1 << (emu.get_ptr_size() * 8)) - 1):
            process = self._process(emu, handle)
            if process is None:
                error, reason = 6, "invalid or foreign process handle"
            elif not self._rights_allow(emu, handle, SYNCHRONIZE):
                error, reason = 5, "process handle lacks synchronize right"
            else:
                error, reason = 0, ""
            signaled = process is not None and id(process) in self.terminated_processes
            event["object_type"] = "process"
        else:
            error, reason = 50, "unmodeled wait object"
            signaled = False
            self.unsupported.append(f"{api_name}: unmodeled wait object")
        if error:
            emu.set_last_error(error)
            event.update({"result": WAIT_FAILED, "reason": reason})
            return WAIT_FAILED
        if signaled:
            result = WAIT_OBJECT_0
        elif timeout != 0xFFFFFFFF:
            result = WAIT_TIMEOUT
            if timeout:
                event["virtual_timeout"] = True
        else:
            emu.set_last_error(50)
            event.update({"result": WAIT_FAILED,
                          "reason": "blocking wait requires cooperative scheduling"})
            self.unsupported.append(f"{api_name}: blocking wait unsupported")
            return WAIT_FAILED
        event["result"] = result
        emu.set_last_error(0)
        return result

    def _get_exit_code_thread(self, emu, api_name, original, params):
        handle, output = (int(value) for value in params)
        event = {"event": "virtual_thread_exit_code", "api": api_name,
                 "handle": handle, "success": False}
        self.events.append(event)
        thread = self._thread(emu, handle)
        if thread is None:
            emu.set_last_error(6)
            event["reason"] = "invalid thread handle"
            return 0
        if not (self.thread_access.get(handle, THREAD_ALL_ACCESS) &
                (THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION)):
            emu.set_last_error(5)
            event["reason"] = "thread handle lacks query right"
            return 0
        if not output:
            emu.set_last_error(87)
            event["reason"] = "missing output pointer"
            return 0
        try:
            emu.mem_read(output, 4)
            value = self.thread_exit_codes.get(
                id(thread), self.process_exit_codes.get(id(thread.process), 259))
            emu.mem_write(output, value.to_bytes(4, "little"))
        except Exception:
            emu.set_last_error(998)
            event["reason"] = "inaccessible output pointer"
            return 0
        event.update({"tid": int(thread.tid), "exit_code": value, "success": True})
        emu.set_last_error(0)
        return 1

    def _winexec(self, emu, api_name, original, params):
        command_ptr, show = map(int, params)
        command = emu.read_mem_string(command_ptr, 1) if command_ptr else ""
        event = {"event": "virtual_process_create", "api": api_name,
                 "application": "", "command_line": command[:MAX_GUEST_STRING_CHARS],
                 "show": show, "success": False}
        self.events.append(event)
        if not command or len(command) > MAX_GUEST_STRING_CHARS:
            emu.set_last_error(87)
            event["reason"] = "missing or oversized command line"
            return 1
        try:
            app = shlex.split(command, posix=False)[0].strip('"')
        except (IndexError, ValueError):
            emu.set_last_error(87)
            event["reason"] = "missing executable name"
            return 1
        path, file = self._guest_executable(emu, app)
        event.update({"application": app, "path": path})
        if file is None:
            emu.set_last_error(2)
            event["reason"] = "executable absent from guest filesystem"
            self.unsupported.append(f"{api_name}: executable unavailable in guest: {path}")
            return 2
        data = self._guest_image_bytes(file)
        if data is None:
            emu.set_last_error(50)
            event["reason"] = "executable source not verified"
            self.unsupported.append(f"{api_name}: executable source not verified {path}")
            return 1
        try:
            info = inspect_pe_header(data or b"", ntpath.basename(path))
        except InvalidSample:
            emu.set_last_error(193)
            event["reason"] = "invalid guest PE"
            return 11  # ERROR_BAD_FORMAT in WinExec's return convention.
        if info.kind != "exe" or info.managed or info.architecture != (
                "x64" if emu.get_ptr_size() == 8 else "x86"):
            emu.set_last_error(50)
            event["reason"] = "child image type or architecture unsupported"
            self.unsupported.append(f"{api_name}: child image unsupported {path}")
            return 1
        if sum(item.get("event") == "virtual_process_create" and item.get("success")
               for item in self.events) >= 32:
            emu.set_last_error(8)
            event["reason"] = "guest child process limit reached"
            self.unsupported.append(f"{api_name}: guest child process limit reached")
            return 8
        process = None
        try:
            process = emu.create_process(path=path, cmdline=command, child=True)
            if not process.pe_data:
                raise RuntimeError("guest image was not loaded")
            self.created_processes.add(id(process))
            callback = getattr(self, "process_created_handler", None)
            if callback is not None:
                callback(emu, process, data)
        except Exception as exc:
            if process is not None:
                self.created_processes.discard(id(process))
                if process in emu.child_processes:
                    emu.child_processes.remove(process)
            emu.set_last_error(193)
            event["reason"] = f"child loader failed: {type(exc).__name__}"
            self.unsupported.append(f"{api_name}: child loader failed for {path}")
            return 11
        event.update({"success": True, "pid": int(process.pid)})
        emu.set_last_error(0)
        return 33  # A WinExec return above 31 denotes success.

    def _guest_executable(self, emu, application: str):
        """Resolve only files already present in the guest filesystem."""
        names = [application]
        if not ntpath.splitext(application)[1]:
            names.append(application + ".exe")
        if ntpath.isabs(application):
            directories = [""]
        elif ntpath.dirname(application):
            directories = [emu.get_cd()]
        else:
            directories = [emu.get_cd(), r"C:\Windows\System32", r"C:\Windows"]
        manager = emu.get_file_manager()
        files = {item.path.casefold(): item for item in manager.files}
        first = ""
        for directory in directories:
            for name in names:
                path = ntpath.normpath(ntpath.join(directory, name))
                if not first:
                    first = path
                file = files.get(path.casefold())
                if file is None:
                    for mapping in getattr(getattr(manager, "file_config", None),
                                           "files", ()):
                        if (mapping.mode != "full_path" or
                                mapping.emu_path.casefold() != path.casefold()):
                            continue
                        payload = self.staged_sources.get(str(mapping.path).casefold())
                        if payload is not None:
                            file = manager.add_existing_file(path, payload)
                            files[path.casefold()] = file
                        break
                if file is not None:
                    return path, file
        return first, None

    def _guest_image_bytes(self, file) -> bytes | None:
        if file.config:
            source = getattr(file.config, "path", None)
            payload = self.staged_sources.get(str(source).casefold()) if source else None
            if payload is None:
                return None
            # Speakeasy's child loader expects the BytesIO to be populated.
            # Use the verified worker payload rather than opening a path here.
            file.data = io.BytesIO(payload)
            return payload
        return file.data.getvalue() if isinstance(file.data, io.BytesIO) else file.data

    def _create_process(self, emu, api_name, original, params):
        internal = "Internal" in api_name
        shift = 1 if internal else 0
        width = 2 if api_name.endswith("W") else 1
        app = emu.read_mem_string(int(params[shift]), width) if params[shift] else ""
        cmd = emu.read_mem_string(int(params[shift + 1]), width) if params[shift + 1] else ""
        event = {"event": "virtual_process_create", "api": api_name,
                 "application": app, "command_line": cmd, "success": False}
        self.events.append(event)
        if not params[shift + 8] or not params[shift + 9]:
            emu.set_last_error(87)
            event["reason"] = "missing startup or process-information pointer"
            return 0
        try:
            path = app or shlex.split(cmd, posix=False)[0].strip('"')
        except (IndexError, ValueError):
            emu.set_last_error(87)
            event["reason"] = "missing executable name"
            return 0
        path, file = self._guest_executable(emu, path)
        event["path"] = path
        if file is None:
            emu.set_last_error(2)  # ERROR_FILE_NOT_FOUND
            event["reason"] = "executable absent from guest filesystem"
            self.unsupported.append(f"{api_name}: executable unavailable in guest: {path}")
            return 0
        data = self._guest_image_bytes(file)
        if data is None:
            emu.set_last_error(50)
            event["reason"] = "executable source not verified"
            self.unsupported.append(f"{api_name}: executable source not verified {path}")
            return 0
        try:
            info = inspect_pe_header(data or b"", ntpath.basename(path))
        except InvalidSample:
            emu.set_last_error(193)  # ERROR_BAD_EXE_FORMAT
            event["reason"] = "invalid guest PE"
            return 0
        if info.kind != "exe" or info.managed:
            emu.set_last_error(50)
            event["reason"] = "child image type unsupported"
            self.unsupported.append(f"{api_name}: child image type unsupported {path}")
            return 0
        if info.architecture != ("x64" if emu.get_ptr_size() == 8 else "x86"):
            emu.set_last_error(50)
            event["reason"] = "cross-architecture child unsupported"
            self.unsupported.append(f"{api_name}: cross-architecture child {path}")
            return 0
        if sum(item.get("event") == "virtual_process_create" and item.get("success")
               for item in self.events) >= 32:
            emu.set_last_error(8)  # ERROR_NOT_ENOUGH_MEMORY in bounded model
            event["reason"] = "guest child process limit reached"
            self.unsupported.append(f"{api_name}: guest child process limit reached")
            return 0
        try:
            caller = emu.get_current_process()
            inherit_handles = bool(params[shift + 4])
            process_handles = tuple(
                handle for (owner, handle), flags in self.process_handle_flags.items()
                if owner == id(caller) and flags & 1 and
                self._owns_handle(self.process_handle_owners,
                                  self.shared_process_handle_owners, handle, owner))
            thread_handles = tuple(
                handle for (owner, handle), flags in self.thread_handle_flags.items()
                if owner == id(caller) and flags & 1 and
                self._owns_handle(self.thread_handle_owners,
                                  self.shared_thread_handle_owners, handle, owner))
            # Speakeasy's CreateProcess handler loads only lpApplicationName.
            # Supply the resolved guest path even when the caller used a bare
            # filename or placed the executable solely in lpCommandLine.
            encoded = path.encode("utf-16-le" if width == 2 else "utf-8") + b"\0" * width
            replacement = emu.mem_map(len(encoded), tag="emumee.create_process_path",
                                      process=caller)
            try:
                emu.mem_write(replacement, encoded)
                launch_params = list(params)
                launch_params[shift] = replacement
                result = int(original(launch_params))
            finally:
                emu.mem_free(replacement)
        except Exception as exc:
            emu.set_last_error(193)
            event["reason"] = f"child loader failed: {type(exc).__name__}"
            self.unsupported.append(f"{api_name}: child loader failed for {path}")
            return 0
        event["success"] = bool(result)
        if result:
            ppi = int(params[shift + 9])
            handle = int.from_bytes(emu.mem_read(ppi, emu.get_ptr_size()), "little")
            thread_handle = int.from_bytes(emu.mem_read(ppi + emu.get_ptr_size(), emu.get_ptr_size()), "little")
            process = self._raw_process(emu, handle)
            if process is not None:
                self.process_handle_owners[handle] = id(caller)
                self.process_handle_flags[(id(caller), handle)] = 0
                self.closed_process_handles.discard(handle)
                if inherit_handles:
                    for source_handle in process_handles:
                        self.shared_process_handle_owners.setdefault(source_handle, set()).add(id(process))
                        self.process_handle_flags[(id(process), source_handle)] = self.process_handle_flags[
                            (id(caller), source_handle)]
                    for source_handle in thread_handles:
                        self.shared_thread_handle_owners.setdefault(source_handle, set()).add(id(process))
                        self.thread_handle_flags[(id(process), source_handle)] = self.thread_handle_flags[
                            (id(caller), source_handle)]
                event["inherited_process_handles"] = len(process_handles) if inherit_handles else 0
                event["inherited_thread_handles"] = len(thread_handles) if inherit_handles else 0
                file_inherit_handler = getattr(self, "file_inherit_handler", None)
                event["inherited_file_handles"] = (
                    file_inherit_handler(emu, caller, process)
                    if inherit_handles and file_inherit_handler is not None else 0)
                mapping_inherit_handler = getattr(self, "mapping_inherit_handler", None)
                event["inherited_mapping_handles"] = (
                    mapping_inherit_handler(emu, caller, process)
                    if inherit_handles and mapping_inherit_handler is not None else 0)
                self.bind_process_private_maps(emu, process)
                process_created_handler = getattr(self, "process_created_handler", None)
                if process_created_handler is not None:
                    process_created_handler(emu, process, data)
                event["pid"] = int(process.pid)
                event["handle"] = handle
                self.created_processes.add(id(process))
            if self._raw_thread(emu, thread_handle) is not None:
                self.thread_access[thread_handle] = THREAD_ALL_ACCESS
                self.thread_handle_owners[thread_handle] = id(caller)
                self.thread_handle_flags[(id(caller), thread_handle)] = 0
                self.closed_thread_handles.discard(thread_handle)
        return result

    @staticmethod
    def _raw_process(emu, handle: int):
        process = emu.get_object_from_handle(handle)
        if process is None or not hasattr(process, "pid") or not hasattr(process, "path"):
            return None
        return process

    def _process(self, emu, handle: int):
        mask = (1 << (emu.get_ptr_size() * 8)) - 1
        if handle & mask == mask:
            process = emu.get_current_process()
        else:
            if (handle in self.closed_process_handles or
                    not self._owns_handle(self.process_handle_owners,
                                          self.shared_process_handle_owners, handle,
                                          id(emu.get_current_process()))):
                return None
            process = self._raw_process(emu, handle)
        if process is None or not hasattr(process, "pid") or not hasattr(process, "path"):
            return None
        return process

    def _rights_allow(self, emu, handle: int, needed: int) -> bool:
        mask = (1 << (emu.get_ptr_size() * 8)) - 1
        if handle & mask == mask:
            return True  # GetCurrentProcess pseudo handle.
        granted = self.process_access.get(handle, PROCESS_ALL_ACCESS)
        if not self._owns_handle(self.process_handle_owners,
                                 self.shared_process_handle_owners, handle,
                                 id(emu.get_current_process())):
            return False
        return (granted & needed) == needed

    def _is_debugger_present(self, emu, api_name, original, params):
        process = emu.get_current_process()
        self.events.append({"event": "virtual_debugger_check", "api": api_name,
                            "pid": int(process.pid) if process is not None else None,
                            "debugger_present": False, "success": True})
        return 0

    def _check_remote_debugger_present(self, emu, api_name, original, params):
        handle, output = (int(value) for value in params)
        event = {"event": "virtual_debugger_check", "api": api_name,
                 "handle": handle, "success": False}
        self.events.append(event)
        process = self._process(emu, handle)
        if process is None:
            emu.set_last_error(6)
            event["reason"] = "invalid or foreign process handle"
            return 0
        event["pid"] = int(process.pid)
        if not (self._rights_allow(emu, handle, PROCESS_QUERY_INFORMATION) or
                self._rights_allow(emu, handle, PROCESS_QUERY_LIMITED_INFORMATION)):
            emu.set_last_error(5)
            event["reason"] = "process handle lacks query right"
            return 0
        if not output:
            emu.set_last_error(87)
            event["reason"] = "missing output pointer"
            return 0
        try:
            emu.mem_read(output, 4)
            emu.mem_write(output, b"\0" * 4)
        except Exception:
            emu.set_last_error(998)
            event["reason"] = "inaccessible output pointer"
            return 0
        event.update({"debugger_present": False, "success": True})
        emu.set_last_error(0)
        return 1

    def _nt_query_information_process(self, emu, api_name, original, params):
        handle, information_class, output, length, return_length = (
            int(value) for value in params)
        event = {"event": "virtual_nt_process_debug_query", "api": api_name,
                 "handle": handle, "information_class": information_class,
                 "success": False}
        self.events.append(event)

        def fail(status: int, reason: str) -> int:
            event.update({"status": status, "reason": reason})
            return status

        expected = (4 if information_class == 31 else emu.get_ptr_size()
                    if information_class in (7, 30) else None)
        if expected is None:
            self.unsupported.append(f"{api_name}: information class {information_class}")
            return fail(0xC0000002, "unmodeled process information class")
        process = self._process(emu, handle)
        if process is None:
            return fail(0xC0000008, "invalid or foreign process handle")
        event["pid"] = int(process.pid)
        if not self._rights_allow(emu, handle, PROCESS_QUERY_INFORMATION):
            return fail(0xC0000022, "process handle lacks query right")
        if length != expected:
            if return_length:
                try:
                    emu.mem_read(return_length, 4)
                    emu.mem_write(return_length, expected.to_bytes(4, "little"))
                except Exception:
                    return fail(0xC0000005, "inaccessible return-length pointer")
            return fail(0xC0000004, "process information length mismatch")
        if not output:
            return fail(0xC0000005, "missing output pointer")
        value = 1 if information_class == 31 else 0
        try:
            emu.mem_read(output, expected)
            if return_length:
                emu.mem_read(return_length, 4)
            emu.mem_write(output, value.to_bytes(expected, "little"))
            if return_length:
                emu.mem_write(return_length, expected.to_bytes(4, "little"))
        except Exception:
            return fail(0xC0000005, "inaccessible output pointer")
        status = 0xC0000353 if information_class == 30 else 0
        event.update({"status": status, "debugger_present": False,
                      "value": value, "success": status == 0})
        return status

    def _get_exit_code_process(self, emu, api_name, original, params):
        handle, output = (int(value) for value in params)
        event = {"event": "virtual_process_exit_code", "api": api_name,
                 "handle": handle, "success": False}
        self.events.append(event)
        process = self._process(emu, handle)
        if process is None:
            emu.set_last_error(6)
            event["reason"] = "invalid process handle"
            return 0
        event["pid"] = int(process.pid)
        if not (self._rights_allow(emu, handle, PROCESS_QUERY_INFORMATION) or
                self._rights_allow(emu, handle, PROCESS_QUERY_LIMITED_INFORMATION)):
            emu.set_last_error(5)
            event["reason"] = "process handle lacks query right"
            return 0
        if not output:
            emu.set_last_error(87)
            event["reason"] = "missing output pointer"
            return 0
        try:
            emu.mem_read(output, 4)
            value = self.process_exit_codes.get(id(process), 259)
            emu.mem_write(output, value.to_bytes(4, "little"))
        except Exception:
            emu.set_last_error(998)
            event["reason"] = "inaccessible output pointer"
            return 0
        event["success"] = True
        event["exit_code"] = value
        emu.set_last_error(0)
        return 1

    def _exit_process(self, emu, api_name, original, params):
        exit_code = int(params[0]) & 0xFFFFFFFF
        process = emu.get_current_process()
        if process is not None:
            thread = (emu.get_current_thread() if hasattr(emu, "get_current_thread")
                      else None)
            if thread is not None:
                self._record_thread_exit(emu, thread, exit_code, "ExitProcess",
                                         record_process=False)
            self.terminated_processes.add(id(process))
            self.process_exit_codes[id(process)] = exit_code
            self.events.append({"event": "virtual_process_exit", "api": api_name,
                                "pid": int(process.pid), "exit_code": exit_code,
                                "success": True})
            self._cleanup_process(emu, process)
        return original(params)

    def _crt_exit(self, emu, api_name, _original, params):
        return self._exit_process(emu, api_name, lambda _args: emu.exit_process(), params)

    def _terminate_process(self, emu, api_name, original, params):
        handle, exit_code = (int(value) for value in params)
        event = {"event": "virtual_process_terminate", "api": api_name,
                 "handle": handle, "exit_code": exit_code & 0xFFFFFFFF,
                 "success": False}
        self.events.append(event)
        process = self._process(emu, handle)
        if process is None:
            emu.set_last_error(6)
            event["reason"] = "invalid process handle"
            return 0
        event["pid"] = int(process.pid)
        if process is not emu.get_current_process() and id(process) not in self.created_processes:
            emu.set_last_error(50)
            event["reason"] = "persona process termination unsupported"
            self.unsupported.append(f"{api_name}: persona process termination")
            return 0
        if not self._rights_allow(emu, handle, PROCESS_TERMINATE):
            emu.set_last_error(5)
            event["reason"] = "process handle lacks terminate right"
            return 0
        if id(process) in self.terminated_processes:
            emu.set_last_error(5)
            event["reason"] = "process already terminated"
            return 0
        self.terminated_processes.add(id(process))
        self.process_exit_codes[id(process)] = exit_code & 0xFFFFFFFF
        self._cleanup_process(emu, process)
        # Speakeasy's TerminateProcess handler removes only its process-list
        # entry; pending child runs live in a different queue.
        emu.child_processes[:] = [child for child in emu.child_processes
                                   if child is not process]
        emu.kill_process(process)
        if process is emu.get_current_process():
            emu.run_queue.clear()
            emu.exit_process()
        event["success"] = True
        emu.set_last_error(0)
        return 1

    def _cleanup_process(self, emu, process) -> None:
        owner = id(process)
        if owner in self.cleaned_processes:
            return
        files = self.process_cleanup_handler(emu, process) if self.process_cleanup_handler else {}
        registry_handles = (self.registry_cleanup_handler(emu, process)
                            if self.registry_cleanup_handler else 0)
        counts = {"process_handles": 0, "thread_handles": 0}
        for handle, candidate in tuple(self.process_handle_owners.items()):
            if self._owns_handle(self.process_handle_owners,
                                 self.shared_process_handle_owners, handle, owner):
                if self.close_process_handle(emu, handle, process, force=True) != 1:
                    raise RuntimeError(f"exiting guest process handle 0x{handle:x} remained open")
                counts["process_handles"] += 1
        for handle, candidate in tuple(self.thread_handle_owners.items()):
            if self._owns_handle(self.thread_handle_owners,
                                 self.shared_thread_handle_owners, handle, owner):
                if self.close_process_handle(emu, handle, process, force=True) != 1:
                    raise RuntimeError(f"exiting guest thread handle 0x{handle:x} remained open")
                counts["thread_handles"] += 1
        self.cleaned_processes.add(owner)
        self.events.append({"event": "virtual_process_cleanup", "pid": int(process.pid),
                            **counts, "files": files,
                            "registry_handles": registry_handles, "success": True})

    def _open_process(self, emu, api_name, original, params):
        access, inherit, pid = (int(value) for value in params)
        event = {"event": "virtual_process_open", "api": api_name,
                 "pid": pid, "requested_access": access, "inherit": bool(inherit),
                 "success": False}
        self.events.append(event)
        if pid == 0:
            emu.set_last_error(87)
            event["reason"] = "invalid process id"
            return 0
        current = emu.get_current_process()
        process = next((item for item in [current, self._primary_process,
                                          *emu.child_processes, *emu.get_processes()]
                        if item is not None and int(item.pid) == pid), None)
        if process is None:
            emu.set_last_error(87)
            event["reason"] = "process id absent from guest"
            return 0
        if process is not current and id(process) not in self.created_processes:
            kind = "guest parent" if process is self._primary_process else "persona"
            event["access_model"] = f"assumed for {kind} process"
            if not any(f"{kind} process access" in item for item in self.unsupported):
                self.unsupported.append(f"{api_name}: {kind} process access control not modeled")
        if not emu.get_object_from_addr(process.address):
            emu.add_object(process)
        handle = int(emu.get_object_handle(process))
        if not handle:
            emu.set_last_error(8)
            event["reason"] = "guest handle allocation failed"
            return 0
        self.process_access[handle] = access & 0xFFFFFFFF
        self.process_handle_owners[handle] = id(current)
        self.closed_process_handles.discard(handle)
        self.process_handle_flags[(id(current), handle)] = int(bool(inherit))
        event["success"] = True
        event["handle"] = handle
        emu.set_last_error(0)
        return handle

    def close_process_handle(self, emu, handle: int,
                             owner_process=None, *, force: bool = False) -> int | None:
        owner = id(owner_process) if owner_process is not None else id(emu.get_current_process())
        if ((handle in self.thread_handle_owners and
             not self._owns_handle(self.thread_handle_owners,
                                   self.shared_thread_handle_owners, handle, owner)) or
            (handle in self.process_handle_owners and
             not self._owns_handle(self.process_handle_owners,
                                   self.shared_process_handle_owners, handle, owner))):
            emu.set_last_error(6)
            self.events.append({"event": "virtual_process_handle_close", "handle": handle,
                                "success": False, "reason": "different guest process"})
            return 0
        if (handle not in self.closed_process_handles and
                handle not in self.closed_thread_handles and
                handle not in self.process_handle_owners and
                handle not in self.thread_handle_owners and
                (self._raw_process(emu, handle) is not None or
                 self._raw_thread(emu, handle) is not None)):
            emu.set_last_error(6)
            self.events.append({"event": "virtual_process_handle_close", "handle": handle,
                                "success": False, "reason": "unissued guest handle"})
            return 0
        if handle in self.closed_thread_handles:
            emu.set_last_error(6)
            self.events.append({"event": "virtual_thread_close", "handle": handle,
                                "success": False, "reason": "already closed"})
            return 0
        thread = (self._raw_thread(emu, handle) if
                  self._owns_handle(self.thread_handle_owners,
                                    self.shared_thread_handle_owners, handle, owner) else None)
        if thread is not None and handle in getattr(thread, "handles", ()):
            if not force and self.thread_handle_flags.get((owner, handle), 0) & 2:
                emu.set_last_error(6)
                self.events.append({"event": "virtual_thread_close", "handle": handle,
                                    "success": False, "reason": "protected from close"})
                return 0
            if not self._release_handle_owner(self.thread_handle_owners,
                                              self.shared_thread_handle_owners,
                                              handle, owner):
                thread.handles.remove(handle)
                self.thread_access.pop(handle, None)
                self.closed_thread_handles.add(handle)
            self.thread_handle_flags.pop((owner, handle), None)
            emu.set_last_error(0)
            self.events.append({"event": "virtual_thread_close", "handle": handle,
                                "tid": int(thread.tid), "success": True})
            return 1
        if handle in self.closed_process_handles:
            emu.set_last_error(6)
            self.events.append({"event": "virtual_process_close", "handle": handle,
                                "success": False, "reason": "already closed"})
            return 0
        process = (self._raw_process(emu, handle) if
                   self._owns_handle(self.process_handle_owners,
                                     self.shared_process_handle_owners, handle, owner) else None)
        if process is None or handle not in getattr(process, "handles", ()):
            return None
        if not force and self.process_handle_flags.get((owner, handle), 0) & 2:
            emu.set_last_error(6)
            self.events.append({"event": "virtual_process_close", "handle": handle,
                                "success": False, "reason": "protected from close"})
            return 0
        if not self._release_handle_owner(self.process_handle_owners,
                                          self.shared_process_handle_owners,
                                          handle, owner):
            process.handles.remove(handle)
            self.process_access.pop(handle, None)
            self.closed_process_handles.add(handle)
        self.process_handle_flags.pop((owner, handle), None)
        emu.set_last_error(0)
        self.events.append({"event": "virtual_process_close", "handle": handle,
                            "pid": int(process.pid), "success": True})
        return 1

    def _duplicate_handle(self, emu, api_name, original, params):
        source_process_handle, source_handle, target_process_handle, output, access, inherit, options = (
            int(value) for value in params)
        event = {"event": "virtual_process_handle_duplicate", "api": api_name,
                 "source_handle": source_handle, "requested_access": access,
                 "options": options, "success": False}
        current = emu.get_current_process()
        source_process = self._process(emu, source_process_handle)
        target_process = self._process(emu, target_process_handle)
        if source_process is None or target_process is None:
            self.events.append(event)
            emu.set_last_error(6)
            event["reason"] = "invalid source or target process handle"
            return 0
        if ((source_process is not current and
             id(source_process) not in self.created_processes) or
            (target_process is not current and
             id(target_process) not in self.created_processes)):
            self.events.append(event)
            emu.set_last_error(50)
            event["reason"] = "persona source or target duplication unsupported"
            self.unsupported.append(f"{api_name}: persona source or target duplication")
            return 0
        event["source_pid"] = int(source_process.pid)
        event["target_pid"] = int(target_process.pid)
        if not self._rights_allow(emu, source_process_handle, PROCESS_DUP_HANDLE):
            self.events.append(event)
            emu.set_last_error(5)
            event["reason"] = "source process handle lacks duplicate right"
            return 0
        manager = emu.get_file_manager() if hasattr(emu, "get_file_manager") else None
        if not self._rights_allow(emu, target_process_handle, PROCESS_DUP_HANDLE):
            self.events.append(event)
            event["reason"] = "target process handle lacks duplicate right"
            if options & 1 and source_handle != (1 << (emu.get_ptr_size() * 8)) - 1:
                if (source_handle in getattr(manager, "file_handles", {}) or
                        source_handle in getattr(manager, "file_maps", {})):
                    if self.file_close_handler is not None:
                        event["source_closed"] = bool(self.file_close_handler(
                            emu, source_handle, source_process))
                else:
                    event["source_closed"] = bool(self.close_process_handle(
                        emu, source_handle, source_process))
            emu.set_last_error(5)
            return 0
        if (source_handle in getattr(manager, "file_handles", {}) or
                source_handle in getattr(manager, "file_maps", {})):
            if self.file_duplicate_handler is not None:
                return self.file_duplicate_handler(emu, api_name, source_handle,
                                                   output, access, inherit, options,
                                                   target_process, source_process)
        self.events.append(event)
        pseudo = (1 << (emu.get_ptr_size() * 8)) - 1
        source_owner = id(source_process)
        process = (current if source_handle & pseudo == pseudo and
                   source_process is current else
                   self._raw_process(emu, source_handle) if
                   self._owns_handle(self.process_handle_owners,
                                     self.shared_process_handle_owners,
                                     source_handle, source_owner) else None)
        thread = (self._raw_thread(emu, source_handle) if
                  self._owns_handle(self.thread_handle_owners,
                                    self.shared_thread_handle_owners,
                                    source_handle, source_owner) else None)
        if ((process is None or source_handle in self.closed_process_handles) and
                (thread is None or source_handle in self.closed_thread_handles)):
            other_object = emu.get_object_from_handle(source_handle)
            if (other_object is not None or
                    source_handle in getattr(manager, "file_handles", {}) or
                    source_handle in getattr(manager, "file_maps", {})):
                emu.set_last_error(50)
                event["reason"] = "non-process handle duplication unsupported"
                self.unsupported.append(f"{api_name}: non-process handle duplication")
                return 0
            emu.set_last_error(6)
            event["reason"] = "invalid source process handle"
            return 0
        close_after = bool(options & 1 and source_handle != pseudo)

        def deny(error: int, reason: str, unsupported: str | None = None) -> int:
            event["reason"] = reason
            if unsupported:
                self.unsupported.append(unsupported)
            if close_after:
                self.close_process_handle(emu, source_handle, source_process)
            emu.set_last_error(error)
            return 0

        if not output or options & ~3:
            return deny(87, "invalid output pointer or options")
        is_thread = thread is not None
        available = (self.thread_access.get(source_handle, THREAD_ALL_ACCESS) if is_thread
                     else self.process_access.get(source_handle, PROCESS_ALL_ACCESS))
        granted = available if options & 2 else access & 0xFFFFFFFF
        target = thread if is_thread else process
        can_recheck_dacl = ((thread.process is current or id(thread.process) in self.created_processes)
                            if is_thread else
                            process is current or id(process) in self.created_processes)
        if granted & ~(THREAD_ALL_ACCESS if is_thread else PROCESS_ALL_ACCESS):
            return deny(87, "requested access outside modeled handle rights")
        if granted & ~available and not can_recheck_dacl:
            return deny(5, "target process security descriptor unavailable",
                        f"{api_name}: target process access check unavailable")
        try:
            emu.mem_read(output, emu.get_ptr_size())
            duplicate = int(emu.get_object_handle(target))
            emu.mem_write(output, duplicate.to_bytes(emu.get_ptr_size(), "little"))
        except Exception as exc:
            return deny(87, f"guest handle duplication failed: {type(exc).__name__}")
        (self.thread_access if is_thread else self.process_access)[duplicate] = granted
        (self.thread_handle_owners if is_thread else self.process_handle_owners)[
            duplicate] = id(target_process)
        closed = self.closed_thread_handles if is_thread else self.closed_process_handles
        flags = self.thread_handle_flags if is_thread else self.process_handle_flags
        closed.discard(duplicate)
        flags[(id(target_process), duplicate)] = int(bool(inherit))
        event["success"] = True
        event["handle"] = duplicate
        event["granted_access"] = granted
        event["object_type"] = "thread" if is_thread else "process"
        if close_after:
            self.close_process_handle(emu, source_handle, source_process)
        emu.set_last_error(0)
        return 1

    @staticmethod
    def _owner_conflict(emu, address: int, size: int, expected) -> bool:
        """Reject known cross-process maps in Speakeasy's shared address arena."""
        end = address + max(size, 1)
        cursor = address
        while cursor < end:
            mapping = emu.get_address_map(cursor)
            if mapping is None:
                return False  # The engine's ordinary range check handles holes.
            owner = getattr(mapping, "process", None)
            if owner is not None and owner is not expected and not getattr(mapping, "shared", False):
                return True
            next_cursor = min(end, int(mapping.base) + int(mapping.size))
            if next_cursor <= cursor:
                return True
            cursor = next_cursor
        return False

    def _released_range(self, address: int, size: int) -> bool:
        end = address + max(size, 1)
        return any(address <= base < end or base <= address < base + extent
                   for base, extent in self._released_extents.items())

    def _cpu_access(self, facade, address: int, size: int, access: str) -> bool:
        """Stop a guest instruction that crosses a known process or free map."""
        if (not self.created_processes and not self._released_extents and
                not self._foreign_allocation_seen):
            return True
        emu = getattr(facade, "emu", facade)
        run = getattr(emu, "curr_run", None)
        if run is None or getattr(run, "error", None) is not None:
            return True
        process = emu.get_current_process()
        if process is None:
            return True
        released = self._released_range(address, size)
        owner = None
        cursor = address
        end = address + max(size, 1)
        while cursor < end:
            mapping = emu.get_address_map(cursor)
            if mapping is None:
                break  # Existing invalid-memory hooks handle unmapped pages.
            candidate = getattr(mapping, "process", None)
            if candidate is not None and candidate is not process and not getattr(mapping, "shared", False):
                owner = candidate
                break
            next_cursor = min(end, int(mapping.base) + int(mapping.size))
            if next_cursor <= cursor:
                break
            cursor = next_cursor
        if not released and owner is None:
            return True
        reason = "released memory" if released else "different guest process"
        if access == "write":
            try:
                if not 0 < size <= MAX_ARTIFACT:
                    raise ValueError("CPU write size exceeds rollback limit")
                self._pending_cpu_writes.append((address, emu.mem_read(address, size)))
            except Exception as exc:
                self.cpu_isolation_failed = True
                self.unsupported.append(f"CPU write rollback unavailable: {type(exc).__name__}")
                getattr(emu, "run_queue", []).clear()
        self.events.append({"event": "virtual_cpu_memory_denied", "access": access,
                            "address": address, "size": size, "pid": int(process.pid),
                            "owner_pid": int(owner.pid) if owner is not None else None,
                            "reason": reason})
        run.error = emu.get_error_info(f"guest {access} denied: {reason}", emu.get_pc())
        self._halt_guest_after_isolation_denial(emu)
        emu.stop()
        return False

    def restore_denied_writes(self, emu) -> None:
        """Undo a stopped instruction before the engine snapshots or queues another run."""
        while self._pending_cpu_writes:
            address, data = self._pending_cpu_writes.pop()
            try:
                emu.mem_write(address, data)
                self.events.append({"event": "virtual_cpu_memory_restored",
                                    "address": address, "size": len(data), "success": True})
            except Exception as exc:
                self.cpu_isolation_failed = True
                self.events.append({"event": "virtual_cpu_memory_restored",
                                    "address": address, "size": len(data), "success": False,
                                    "reason": type(exc).__name__})
                self.unsupported.append("CPU write rollback failed")
                getattr(emu, "run_queue", []).clear()

    def _cpu_read(self, facade, access, address, size, value):
        return self._cpu_access(facade, address, size, "read")

    def _cpu_write(self, facade, access, address, size, value):
        allowed = self._cpu_access(facade, address, size, "write")
        if allowed and self.file_cpu_write_handler is not None:
            emu = getattr(facade, "emu", facade)
            self.file_cpu_write_handler(emu, address, size)
        return allowed

    def _cpu_execute(self, facade, address, size):
        if self.file_cpu_flush_handler is not None:
            emu = getattr(facade, "emu", facade)
            self.file_cpu_flush_handler(emu)
        allowed = self._cpu_access(facade, address, size, "execute")
        if allowed and self.cpu_instruction_handler is not None:
            emu = getattr(facade, "emu", facade)
            self.cpu_instruction_handler(emu, address, size)
        return allowed

    def _bulk_memory_api(self, emu, api_name, original, params):
        """Validate guest pointer ownership before Python-backed memory helpers run."""
        name = api_name.rsplit(".", 1)[-1].lower()
        if name.startswith("_o_"):
            name = name[3:]
        values = [int(value) for value in params]
        if name == "rtlzeromemory":
            ranges = [("destination", values[0])]
            size = values[1]
        elif name == "memset":
            ranges = [("destination", values[0])]
            size = values[2]
        elif name in ("memcmp", "_memicmp"):
            ranges = [("left", values[0]), ("right", values[1])]
            size = values[2]
        else:
            ranges = [("destination", values[0]), ("source", values[1])]
            size = values[2]
        current = emu.get_current_process()
        reason = None
        if size < 0 or size > MAX_ARTIFACT:
            reason = "transfer exceeds guest memory limit"
        elif size and any(not pointer for _, pointer in ranges):
            reason = "null guest pointer"
        elif current is not None:
            for role, pointer in ranges:
                if self._released_range(pointer, size):
                    reason = f"{role} is released memory"
                    break
                if self._owner_conflict(emu, pointer, size, current):
                    reason = f"{role} belongs to different guest process"
                    break
        if reason is not None:
            self.events.append({"event": "virtual_memory_api_denied", "api": api_name,
                                "size": size, "pointers": dict(ranges), "reason": reason})
            emu.curr_run.error = emu.get_error_info(f"{api_name}: {reason}", emu.get_pc())
            self._halt_guest_after_isolation_denial(emu)
            emu.stop()
            return 0 if name in ("memcpy", "memmove", "memset", "memcmp", "_memicmp") else None
        if name == "_memicmp":
            # The legacy CRT compares exactly `size` bytes, including NULs.
            # ASCII folding covers the invariant English tokens used by the
            # modeled locale; other bytes retain their original ordering.
            for offset in range(0, size, 65536):
                count = min(65536, size - offset)
                left = emu.mem_read(values[0] + offset, count).lower()
                right = emu.mem_read(values[1] + offset, count).lower()
                if left != right:
                    for a, b in zip(left, right):
                        if a != b:
                            return a - b
            return 0
        if original is not None:
            return original(params)
        # Speakeasy has no RtlCopyMemory handler; provide bounded guest-only copy.
        if name == "rtlcopymemory":
            emu.mem_write(values[0], emu.mem_read(values[1], size))
            return None
        self.unsupported.append(f"{api_name}: bulk-memory handler unavailable")
        return 0

    def _string_memory_api(self, emu, api_name, original, params):
        """Check every byte a Python string handler can read or overwrite."""
        name = api_name.rsplit(".", 1)[-1].lower()
        operation = name[:-1]
        width = 2 if name.endswith("w") else 1
        process = emu.get_current_process()
        views: dict[str, str] = {}

        def deny(reason: str):
            self.events.append({"event": "virtual_memory_api_denied", "api": api_name,
                                "pointers": [int(value) for value in params], "reason": reason})
            emu.curr_run.error = emu.get_error_info(f"{api_name}: {reason}", emu.get_pc())
            self._halt_guest_after_isolation_denial(emu)
            emu.stop()
            return 0

        def read_string(pointer: int, role: str):
            if not pointer:
                return None, f"{role} is null guest pointer"
            data = bytearray()
            for index in range(MAX_GUEST_STRING_CHARS + 1):
                address = pointer + index * width
                if self._released_range(address, width):
                    return None, f"{role} is released memory"
                if process is not None and self._owner_conflict(emu, address, width, process):
                    return None, f"{role} belongs to different guest process"
                if emu.get_address_map(address) is None:
                    return None, f"{role} is unmapped guest memory"
                try:
                    char = emu.mem_read(address, width)
                except Exception:
                    return None, f"{role} is inaccessible guest memory"
                data.extend(char)
                if char == b"\0" * width:
                    encoding = "utf-16le" if width == 2 else "utf-8"
                    return data.decode(encoding, "ignore").replace("\0", ""), None
            return None, f"{role} exceeds guest string limit"

        if operation == "lstrlen" and not int(params[0]):
            return 0  # Windows defines a null lstrlen input as length zero.
        roles = (["source"] if operation == "lstrlen" else
                 ["left", "right"] if operation in ("lstrcmp", "lstrcmpi") else
                 ["destination", "source"] if operation == "lstrcat" else
                 ["source"])
        for role in roles:
            pointer = int(params[0] if role in ("left", "destination") else
                          params[1] if role in ("right", "source") and operation != "lstrlen"
                          else params[0])
            value, reason = read_string(pointer, role)
            if reason is not None:
                return deny(reason)
            views[role] = value

        if operation in ("lstrcpy", "lstrcpyn", "lstrcat"):
            destination = int(params[0])
            if operation == "lstrcpyn":
                limit = int(params[2])
                if not 0 < limit <= MAX_GUEST_STRING_CHARS:
                    return deny("copy length exceeds guest string limit")
                output = views["source"][:limit - 1] + "\0"
            elif operation == "lstrcat":
                output = views["destination"] + views["source"]
            else:
                output = views["source"]
            encoding = "utf-16le" if width == 2 else "utf-8"
            if operation == "lstrcat":
                byte_count = len(output.encode(encoding)) + 1  # Installed handler's write.
            else:
                byte_count = len((output if output.endswith("\0") else output + "\0").encode(encoding))
            if not destination or byte_count > MAX_ARTIFACT:
                return deny("destination is invalid or copy exceeds guest memory limit")
            if self._released_range(destination, byte_count):
                return deny("destination is released memory")
            if process is not None and self._owner_conflict(emu, destination, byte_count, process):
                return deny("destination belongs to different guest process")
        return original(params) if original is not None else 0

    def _prepare_transient_allocation(self, emu, process, mapping):
        """Read an owned guest allocation while it is still present."""
        if (getattr(mapping, "process", None) is not process or
                getattr(mapping, "free", False)):
            return None, "allocation ownership changed"
        base, size = int(mapping.base), int(mapping.size)
        if size <= 0 or size > MAX_TRANSIENT_ALLOCATION:
            return None, "allocation exceeds transient capture limit"
        if (self.transient_observations >= MAX_TRANSIENT_OBSERVATIONS or
                self.transient_scanned_bytes + size > MAX_MEMORY_SCAN or
                self.captured_bytes + size > MAX_MEMORY_SCAN):
            return None, "transient capture budget exhausted"
        self.transient_observations += 1
        self.transient_scanned_bytes += size
        try:
            with self._allow_api_memory(base, size, "r"):
                data = bytes(emu.mem_read(base, size))
        except Exception as exc:
            return None, f"guest allocation unreadable: {type(exc).__name__}"
        if len(data) != size:
            return None, "guest allocation read was incomplete"
        return data, None

    def _record_transient_allocation(self, data, reason, mapping, process,
                                     event: dict, source: str) -> None:
        size = int(mapping.size)
        if reason is not None:
            event["snapshot_skipped"] = reason
            self.catalog.note_omission(source, size, reason)
            return
        if not data or not any(data):
            return
        context = {"target_pid": int(process.pid), "target_path": str(process.path),
                   "address": int(mapping.base), "allocation_size": size,
                   "capture_point": source.removeprefix("virtual_memory_"),
                   "event_order": len(self.events) - 1}
        try:
            self.catalog.add(data, source, kind="memory", context=context)
            self.catalog.carve_pe(data, source, context=context)
        except Exception as exc:
            event["snapshot_skipped"] = f"artifact capture failed: {type(exc).__name__}"
            self.catalog.note_omission(source, size, "artifact_capture_failed")
            return
        self.captured_bytes += size
        event["snapshot_sha256"] = hashlib.sha256(data).hexdigest()

    def _virtual_free_ex(self, emu, api_name, original, params):
        handle, address, size, free_type = (int(value) for value in params)
        event = {"event": "virtual_process_free", "api": api_name,
                 "handle": handle, "address": address, "size": size,
                 "free_type": free_type, "success": False}
        self.events.append(event)
        process = self._process(emu, handle)
        if process is None:
            emu.set_last_error(6)
            event["reason"] = "invalid process handle"
            return 0
        event["pid"] = int(process.pid)
        if not self._rights_allow(emu, handle, PROCESS_VM_OPERATION):
            emu.set_last_error(5)
            event["reason"] = "process handle lacks VM operation rights"
            return 0
        if free_type != MEM_RELEASE or size != 0 or not address:
            emu.set_last_error(87)
            event["reason"] = "unsupported free type or invalid release parameters"
            if free_type != MEM_RELEASE:
                self.unsupported.append(f"{api_name}: free type 0x{free_type:x} not modeled")
            return 0
        mapping = emu.get_address_map(address)
        local = api_name.lower().endswith(".virtualfree")
        tag = str(getattr(mapping, "tag", "")) if mapping is not None else ""
        allocated = (tag == "api.VirtualAlloc" if local else
                     tag.startswith("api.VirtualAllocEx."))
        if (mapping is None or int(mapping.base) != address or
                bool(getattr(mapping, "free", False)) or not allocated):
            emu.set_last_error(487)
            event["reason"] = "address is not a live virtual allocation base"
            return 0
        owner = getattr(mapping, "process", None)
        if owner is not process:
            emu.set_last_error(487)
            event["reason"] = "allocation belongs to different guest process"
            return 0
        snapshot, snapshot_reason = self._prepare_transient_allocation(
            emu, process, mapping)
        try:
            emu.mem_free(address)
        except Exception as exc:
            emu.set_last_error(487)
            event["reason"] = f"guest release failed: {type(exc).__name__}"
            return 0
        self._released_extents[address] = int(mapping.size)
        event["success"] = True
        self._record_transient_allocation(
            snapshot, snapshot_reason, mapping, process, event,
            "virtual_memory_before_free")
        emu.set_last_error(0)
        return 1

    def _virtual_free(self, emu, api_name, original, params):
        pseudo = (1 << (emu.get_ptr_size() * 8)) - 1
        return self._virtual_free_ex(emu, api_name, original, [pseudo, *params])

    def _virtual_alloc(self, emu, api_name, original, params):
        address, size = (int(value) for value in params[:2])
        process = emu.get_current_process()
        if address and self._owner_conflict(emu, address, size, process):
            emu.set_last_error(487)
            self.events.append({"event": "virtual_process_allocate", "api": api_name,
                                "requested_address": address, "size": size,
                                "success": False,
                                "reason": "requested address belongs to different guest process"})
            return 0
        result = int(original(params))
        if result:
            mapping = emu.get_address_map(result)
            if mapping is not None and getattr(mapping, "tag", None) == "api.VirtualAlloc":
                mapping.process = process
                if result in self._released_extents:
                    mapping.free = False
            self._released_extents.pop(result, None)
        return result

    def _write_process_memory(self, emu, api_name, original, params):
        handle, address, source, size, _written = (int(value) for value in params)
        event = {"event": "virtual_process_memory_write", "api": api_name,
                 "handle": handle, "address": address, "size": size,
                 "success": False}
        self.events.append(event)

        process = self._process(emu, handle)
        if process is None:
            emu.set_last_error(6)  # ERROR_INVALID_HANDLE
            event["reason"] = "invalid process handle"
            return 0
        event["pid"] = int(process.pid)
        event["path"] = str(process.path)
        if not self._rights_allow(emu, handle, PROCESS_VM_WRITE | PROCESS_VM_OPERATION):
            emu.set_last_error(5)
            event["reason"] = "process handle lacks write rights"
            return 0
        if size > MAX_ARTIFACT:
            emu.set_last_error(223)  # ERROR_FILE_TOO_LARGE in bounded model
            event["reason"] = "transfer exceeds guest artifact limit"
            self.unsupported.append(f"{api_name}: transfer exceeds {MAX_ARTIFACT} bytes")
            return 0
        if size < 0 or not address or not source:
            emu.set_last_error(87)  # ERROR_INVALID_PARAMETER
            event["reason"] = "invalid address or size"
            return 0
        if self._released_range(address, size) or self._released_range(source, size):
            emu.set_last_error(299)
            event["reason"] = "memory was released"
            return 0
        if (self._owner_conflict(emu, address, size, process) or
                self._owner_conflict(emu, source, size, emu.get_current_process()) or
                (_written and self._owner_conflict(
                    emu, _written, emu.get_ptr_size(), emu.get_current_process()))):
            emu.set_last_error(299)
            event["reason"] = "memory belongs to different guest process"
            return 0
        try:
            data = emu.mem_read(source, size)
            # The installed engine's write helper does not validate the full
            # target range before copying. Check it before any side effect.
            with self._allow_api_memory(address, size, "rw"):
                emu.mem_read(address, size)
                if _written:
                    emu.mem_read(_written, emu.get_ptr_size())
                result = int(original(params))
        except Exception as exc:
            emu.set_last_error(299)  # ERROR_PARTIAL_COPY
            event["reason"] = f"guest memory inaccessible: {type(exc).__name__}"
            return 0
        if not result:
            event["reason"] = "engine rejected write"
            return 0
        event["success"] = True
        if data and self.captured_bytes + len(data) <= MAX_MEMORY_SCAN:
            context = {"target_pid": int(process.pid), "target_path": str(process.path),
                       "address": address, "write_order": len(self.events) - 1,
                       "written_size": len(data)}
            self.catalog.add(data, "process_memory_write", kind="memory", context=context)
            self.catalog.carve_pe(data, "process_memory_write", context=context)
            self.captured_bytes += len(data)
            event["sha256"] = hashlib.sha256(data).hexdigest()
        elif data:
            event["reason"] = "capture budget exhausted"
            if not any("capture budget" in item for item in self.unsupported):
                self.unsupported.append(f"{api_name}: capture budget exhausted")
        return result

    def _read_process_memory(self, emu, api_name, original, params):
        handle, address, buffer, size, _read = (int(value) for value in params)
        event = {"event": "virtual_process_memory_read", "api": api_name,
                 "handle": handle, "address": address, "size": size,
                 "success": False}
        self.events.append(event)
        process = self._process(emu, handle)
        if process is None:
            emu.set_last_error(6)  # ERROR_INVALID_HANDLE
            event["reason"] = "invalid process handle"
            return 0
        event["pid"] = int(process.pid)
        event["path"] = str(process.path)
        if not self._rights_allow(emu, handle, PROCESS_VM_READ):
            emu.set_last_error(5)
            event["reason"] = "process handle lacks read rights"
            return 0
        if size > MAX_ARTIFACT:
            emu.set_last_error(223)
            event["reason"] = "transfer exceeds guest artifact limit"
            self.unsupported.append(f"{api_name}: transfer exceeds {MAX_ARTIFACT} bytes")
            return 0
        if size < 0 or not address or not buffer:
            emu.set_last_error(87)
            event["reason"] = "invalid address or size"
            return 0
        if self._released_range(address, size) or self._released_range(buffer, size):
            emu.set_last_error(299)
            event["reason"] = "memory was released"
            return 0
        if (self._owner_conflict(emu, address, size, process) or
                self._owner_conflict(emu, buffer, size, emu.get_current_process()) or
                (_read and self._owner_conflict(
                    emu, _read, emu.get_ptr_size(), emu.get_current_process()))):
            emu.set_last_error(299)
            event["reason"] = "memory belongs to different guest process"
            return 0
        try:
            with self._allow_api_memory(address, size, "r"):
                data = emu.mem_read(address, size)
                emu.mem_read(buffer, size)
                if _read:
                    emu.mem_read(_read, emu.get_ptr_size())
                result = int(original(params))
        except Exception as exc:
            emu.set_last_error(299)
            event["reason"] = f"guest memory inaccessible: {type(exc).__name__}"
            return 0
        if not result:
            event["reason"] = "engine rejected read"
            return 0
        event["success"] = True
        if data and self.captured_bytes + len(data) <= MAX_MEMORY_SCAN:
            self.catalog.add(data, "process_memory_read", kind="memory")
            self.catalog.carve_pe(data, "process_memory_read")
            self.captured_bytes += len(data)
            event["sha256"] = hashlib.sha256(data).hexdigest()
        elif data:
            event["reason"] = "capture budget exhausted"
            if not any("capture budget" in item for item in self.unsupported):
                self.unsupported.append(f"{api_name}: capture budget exhausted")
        return result

    def _capture_remote_thread_stage(self, emu, process, start: int, event: dict) -> None:
        """Capture an assembled guest allocation after multiple remote writes."""
        mapping = emu.get_address_map(start)
        if (mapping is None or getattr(mapping, "process", None) is not process or
                getattr(mapping, "free", False)):
            return
        base, size = int(mapping.base), int(mapping.size)
        if not 0 < size <= MAX_ARTIFACT or self.captured_bytes + size > MAX_MEMORY_SCAN:
            event["stage_capture_skipped"] = "allocation exceeds capture budget"
            return
        try:
            with self._allow_api_memory(base, size, "r"):
                data = emu.mem_read(base, size)
        except Exception as exc:
            event["stage_capture_skipped"] = f"guest allocation unreadable: {type(exc).__name__}"
            return
        if len(data) != size:
            event["stage_capture_skipped"] = "guest allocation read was incomplete"
            return
        writes = [(index, item) for index, item in enumerate(self.events)
                  if item is not event and item.get("event") == "virtual_process_memory_write"
                  and item.get("success") and item.get("pid") == int(process.pid)
                  and type(item.get("address")) is int
                  and base <= item["address"] < base + size]
        context = {"target_pid": int(process.pid), "target_path": str(process.path),
                   "address": base, "allocation_size": size,
                   "capture_point": "remote_thread_create", "start_address": start,
                   "contributing_write_count": len(writes),
                   "contributing_writes": [
                       {"event_order": index, "address": item["address"],
                        "size": item["size"], "sha256": item.get("sha256")}
                       for index, item in writes[:32]]}
        self.catalog.add(data, "remote_thread_stage", kind="memory", context=context)
        self.catalog.carve_pe(data, "remote_thread_stage", context=context)
        self.captured_bytes += size
        event["stage_sha256"] = hashlib.sha256(data).hexdigest()

    def _create_remote_thread(self, emu, api_name, original, params):
        handle, _attributes, _stack, start, parameter, flags, _tid = (
            int(value) for value in params)
        event = {"event": "virtual_remote_thread_create", "api": api_name,
                 "handle": handle, "start_address": start, "parameter": parameter,
                 "flags": flags, "success": False}
        self.events.append(event)
        process = self._process(emu, handle)
        if process is None:
            emu.set_last_error(6)
            event["reason"] = "invalid process handle"
            return 0
        event["pid"] = int(process.pid)
        event["path"] = str(process.path)
        needed = (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                  PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)
        if not self._rights_allow(emu, handle, needed):
            emu.set_last_error(5)
            event["reason"] = "process handle lacks thread creation rights"
            return 0
        if self._owner_conflict(emu, start, 1, process):
            emu.set_last_error(487)  # ERROR_INVALID_ADDRESS
            event["reason"] = "start address belongs to different guest process"
            self.unsupported.append(f"{api_name}: cross-process start address")
            return 0
        if self._released_range(start, 1):
            emu.set_last_error(487)
            event["reason"] = "start address was released"
            return 0
        if flags & ~4:
            emu.set_last_error(87)
            event["reason"] = "unsupported thread creation flags"
            self.unsupported.append(f"{api_name}: unsupported flags 0x{flags:x}")
            return 0
        if sum(item.get("event") == "virtual_remote_thread_create" and item.get("success")
               for item in self.events) >= 64:
            emu.set_last_error(8)
            event["reason"] = "guest remote thread limit reached"
            self.unsupported.append(f"{api_name}: guest remote thread limit reached")
            return 0
        try:
            if params[6]:
                emu.mem_read(int(params[6]), 4)
            if flags & 4:
                # The installed engine ignores CREATE_SUSPENDED here. Defer the
                # run in its own suspended queue for its ResumeThread handler.
                thread_type = f"injected_thread_{ntpath.basename(str(process.path)).replace('.', '_')}_{process.id:x}"
                thread_handle, thread = emu.create_thread(
                    start, parameter, process, thread_type=thread_type, is_suspended=True)
                if thread is None:
                    event["reason"] = "engine rejected suspended thread"
                    return 0
                thread.suspend_count = 1
                if params[6]:
                    emu.mem_write(int(params[6]), int(thread.id).to_bytes(4, "little"))
                result = int(thread_handle)
            else:
                result = int(original(params))
        except Exception as exc:
            emu.set_last_error(87)
            event["reason"] = f"guest thread creation failed: {type(exc).__name__}"
            self.unsupported.append(f"{api_name}: thread creation failed")
            return 0
        event["success"] = bool(result)
        if result:
            self._capture_remote_thread_stage(emu, process, start, event)
            event["thread_handle"] = result
            thread = emu.get_object_from_handle(result)
            if thread is not None:
                event["thread_id"] = int(thread.id)
                self.thread_access[result] = THREAD_ALL_ACCESS
                owner = id(emu.get_current_process())
                self.thread_handle_owners[result] = owner
                self.thread_handle_flags[(owner, result)] = 0
            emu.set_last_error(0)
        return result

    def _virtual_alloc_ex(self, emu, api_name, original, params):
        handle, address, size, allocation_type, protection = (int(value) for value in params)
        event = {"event": "virtual_process_allocate", "api": api_name,
                 "handle": handle, "requested_address": address, "size": size,
                 "allocation_type": allocation_type, "protection": protection,
                 "success": False}
        self.events.append(event)
        process = self._process(emu, handle)
        if process is None:
            emu.set_last_error(6)
            event["reason"] = "invalid process handle"
            return 0
        event["pid"] = int(process.pid)
        if not self._rights_allow(emu, handle, PROCESS_VM_OPERATION):
            emu.set_last_error(5)
            event["reason"] = "process handle lacks VM operation rights"
            return 0
        if not 0 < size <= MAX_MEMORY_SCAN:
            emu.set_last_error(87 if size <= 0 else 223)
            event["reason"] = "invalid or excessive allocation size"
            self.unsupported.append(f"{api_name}: allocation size outside guest limit")
            return 0
        if address and self._owner_conflict(emu, address, size, process):
            emu.set_last_error(487)
            event["reason"] = "requested address belongs to different guest process"
            return 0
        try:
            result = int(original(params))
        except Exception as exc:
            emu.set_last_error(487)
            event["reason"] = f"guest allocation failed: {type(exc).__name__}"
            return 0
        event["success"] = bool(result)
        if result:
            event["address"] = result
            if process is not emu.get_current_process():
                self._foreign_allocation_seen = True
            mapping = emu.get_address_map(result)
            if mapping is not None and result in self._released_extents:
                mapping.free = False
            self._released_extents.pop(result, None)
            if mapping is not None and getattr(mapping, "process", None) is not process:
                self.unsupported.append(f"{api_name}: allocated mapping has unknown owner")
        return result

    def _virtual_protect_ex(self, emu, api_name, original, params):
        handle, address, size, protection, old_pointer = (int(value) for value in params)
        event = {"event": "virtual_process_protect", "api": api_name,
                 "handle": handle, "address": address, "size": size,
                 "protection": protection, "success": False}
        self.events.append(event)
        process = self._process(emu, handle)
        if process is None:
            emu.set_last_error(6)
            event["reason"] = "invalid process handle"
            return 0
        event["pid"] = int(process.pid)
        if not self._rights_allow(emu, handle, PROCESS_VM_OPERATION):
            emu.set_last_error(5)
            event["reason"] = "process handle lacks VM operation rights"
            return 0
        if not address or not old_pointer or not 0 < size <= MAX_MEMORY_SCAN:
            emu.set_last_error(87)
            event["reason"] = "invalid address, size, or output pointer"
            return 0
        if self._released_range(address, size) or self._released_range(old_pointer, 4):
            emu.set_last_error(487)
            event["reason"] = "memory was released"
            return 0
        if (self._owner_conflict(emu, address, size, process) or
                self._owner_conflict(emu, old_pointer, 4, emu.get_current_process())):
            emu.set_last_error(487)
            event["reason"] = "memory belongs to different guest process"
            return 0
        mapping = emu.get_address_map(address)
        tag = str(getattr(mapping, "tag", "")) if mapping is not None else ""
        local = api_name.lower().endswith(".virtualprotect")
        owned_allocation = (mapping is not None and
                            getattr(mapping, "process", None) is process and
                            not getattr(mapping, "free", False) and
                            (tag == "api.VirtualAlloc" if local else
                             tag.startswith("api.VirtualAllocEx.")))
        executable = (protection & 0xFF) in (0x10, 0x20, 0x40, 0x80)
        snapshot = snapshot_reason = None
        try:
            emu.mem_read(old_pointer, 4)
            if executable and owned_allocation:
                snapshot, snapshot_reason = self._prepare_transient_allocation(
                    emu, process, mapping)
            result = int(original(params))
        except Exception as exc:
            emu.set_last_error(487)
            event["reason"] = f"guest protection change failed: {type(exc).__name__}"
            return 0
        event["success"] = bool(result)
        if result and executable and owned_allocation:
            self._record_transient_allocation(
                snapshot, snapshot_reason, mapping, process, event,
                "virtual_memory_before_execute")
        if not result:
            event["reason"] = "engine rejected protection change"
        return result

    def _virtual_protect(self, emu, api_name, original, params):
        pseudo = (1 << (emu.get_ptr_size() * 8)) - 1
        return self._virtual_protect_ex(
            emu, api_name, lambda _params: original(params), [pseudo, *params])

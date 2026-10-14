"""Small guest-only filesystem behaviors missing from Speakeasy's API model."""

from __future__ import annotations

import ntpath
import io
import struct
from contextlib import ExitStack

from speakeasy import common
from speakeasy.windows.fileman import File as GuestFile

from .artifacts import ArtifactCatalog, MAX_ARTIFACT, MAX_MEMORY_SCAN


class SharedGuestFileView:
    """One handle's cursor over bytes owned by a guest-only FileManager entry."""

    def __init__(self, file: GuestFile, *, append_only: bool = False):
        self.file = file
        self.position = 0
        self.append_only = append_only

    @property
    def path(self):
        return self.file.path

    @property
    def config(self):
        return self.file.config

    def _bytes(self) -> bytes:
        data = self.file.data
        if isinstance(data, io.BytesIO):
            return data.getvalue()
        return data if isinstance(data, bytes) else b""

    def get_size(self):
        return len(self._bytes())

    def get_data(self, size=-1, reset_pointer=False):
        data = self._bytes()
        if reset_pointer:
            self.position = 0
        if self.position >= len(data):
            return b""
        end = len(data) if size < 0 else min(len(data), self.position + size)
        result = data[self.position:end]
        self.position = end
        return result

    def seek(self, offset, whence):
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self.position,
                io.SEEK_END: self.get_size()}.get(whence)
        if base is not None and 0 <= base + offset <= MAX_ARTIFACT:
            self.position = base + offset

    def tell(self):
        return self.position

    def add_data(self, data):
        previous = self._bytes()
        if self.append_only:
            # FILE_APPEND_DATA without FILE_WRITE_DATA ignores the file pointer.
            # Re-evaluate EOF for every write because another handle may have written.
            self.position = len(previous)
        end = self.position + len(data)
        if end > MAX_ARTIFACT:
            raise ValueError("virtual file size limit exceeded")
        updated = bytearray(previous)
        if self.position > len(updated):
            updated.extend(b"\0" * (self.position - len(updated)))
        updated[self.position:end] = data
        self.file.data = io.BytesIO(updated)
        self.file.bytes_written += len(data)
        self.position = end

    def set_size(self, size: int):
        previous = self._bytes()
        if not 0 <= size <= MAX_ARTIFACT:
            raise ValueError("virtual file size limit exceeded")
        if size <= len(previous):
            updated = previous[:size]
        else:
            # Windows leaves extended bytes undefined; this model uses zeroes.
            updated = previous + b"\0" * (size - len(previous))
        self.file.data = io.BytesIO(updated)


class VirtualFileBridge:
    def __init__(self, current_dir: str, catalog: ArtifactCatalog,
                 persona_sources: dict[str, bytes] | None = None,
                 filetime_ticks: int = 0,
                 persona_directories: list[str] | None = None):
        self.current_dir = current_dir
        self.catalog = catalog
        self.persona_sources = {key.lower(): value for key, value in (persona_sources or {}).items()}
        self.filetime_ticks = filetime_ticks
        self.events: list[dict] = []
        self.unsupported: list[str] = []
        self.directories = {self._key(part) for part in self._ancestors(current_dir)}
        for directory in persona_directories or []:
            self.directories.update(self._key(part) for part in self._ancestors(directory))
        self.directory_attributes: dict[str, int] = {}
        self.closed_file_handles: set[int] = set()
        self.file_handle_owners: dict[int, set[int]] = {}
        self.file_handle_flags: dict[tuple[int, int], int] = {}
        self.mapping_handle_owners: dict[int, set[int]] = {}
        self.mapping_handle_flags: dict[tuple[int, int], int] = {}
        self.mapping_handle_access: dict[tuple[int, int], int] = {}
        self.mapped_guest_view_owners: dict[int, int] = {}
        # Pagefile section IDs share bytes even though each view address has
        # one guest-process owner. Keep section bytes after a view unmaps.
        self.pagefile_sections: dict[int, bytearray] = {}
        self.pagefile_views: dict[int, tuple[object, int, int]] = {}
        self.pending_mapped_cpu_writes: list[tuple[int, int]] = []
        self._mirroring_mapped_write = False
        self.process_close_handler = None
        self.snapshot_close_handler = None
        self.api_memory_allowance = None
        self.read_guard = None
        self.write_guard = None
        self.console_write_handler = None
        self.captured_large_write_bytes = 0
        # Per-open sharing modes, independent of Speakeasy's cloned file data.
        # A None path denotes an unlinked file that still has a live handle.
        self.file_open_options: dict[int, tuple[str | None, int, int]] = {}
        self.file_open_raw_access: dict[int, int] = {}
        # A delete-on-close disposition belongs to the shared file, not just
        # the handle that requested it. Other handles may outlive that handle.
        self.delete_on_close_files: dict[int, GuestFile] = {}
        self.pending_disposition_files: dict[int, GuestFile] = {}
        # base -> (canonical guest file, file offset, visible length, writable)
        self.mapped_guest_views: dict[int, tuple[GuestFile, int, int, bool]] = {}
        self.mapped_guest_view_sections: dict[int, object] = {}

    def _owns_file_handle(self, emu, handle: int) -> bool:
        if not hasattr(emu, "get_current_process"):
            # Direct unit doubles bypass CreateFile and do not model processes.
            # The real Speakeasy emulator always supplies this method.
            return id(emu) in self.file_handle_owners.setdefault(handle, {id(emu)})
        return id(emu.get_current_process()) in self.file_handle_owners.get(handle, ())

    @staticmethod
    def _guest_owner(emu) -> int:
        return id(emu.get_current_process()) if hasattr(emu, "get_current_process") else id(emu)

    def handle_flag_entry(self, emu, handle: int):
        manager = emu.get_file_manager()
        owner = id(emu.get_current_process())
        if handle in manager.file_handles and self._owns_file_handle(emu, handle):
            return self.file_handle_flags, (owner, handle), "file"
        if handle in manager.file_maps and self._owns_mapping_handle(emu, handle):
            return self.mapping_handle_flags, (owner, handle), "mapping"
        return None

    def _owns_mapping_handle(self, emu, handle: int) -> bool:
        if not hasattr(emu, "get_current_process"):
            return id(emu) in self.mapping_handle_owners.setdefault(handle, {id(emu)})
        return id(emu.get_current_process()) in self.mapping_handle_owners.get(handle, ())

    def _mapping_handle_allowed(self, emu, api_name: str, handle: int) -> bool:
        if (handle not in emu.get_file_manager().file_maps or
                self._owns_mapping_handle(emu, handle)):
            return True
        emu.set_last_error(6)
        self.events.append({"event": "virtual_mapping_handle_denied", "api": api_name,
                            "handle": handle, "reason": "different guest process or unissued handle"})
        return False

    def inherit_file_handles(self, emu, caller, child) -> int:
        """Share inheritable numeric file handles with one newly modeled child."""
        manager = emu.get_file_manager()
        count = 0
        for handle, owners in self.file_handle_owners.items():
            if (handle in manager.file_handles and id(caller) in owners and
                    self.file_handle_flags.get((id(caller), handle), 0) & 1):
                owners.add(id(child))
                self.file_handle_flags[(id(child), handle)] = self.file_handle_flags[
                    (id(caller), handle)]
                count += 1
        return count

    def inherit_mapping_handles(self, emu, caller, child) -> int:
        manager = emu.get_file_manager()
        count = 0
        for handle, owners in self.mapping_handle_owners.items():
            if (handle in manager.file_maps and id(caller) in owners and
                    self.mapping_handle_flags.get((id(caller), handle), 0) & 1):
                owners.add(id(child))
                self.mapping_handle_flags[(id(child), handle)] = self.mapping_handle_flags[
                    (id(caller), handle)]
                self.mapping_handle_access[(id(child), handle)] = self.mapping_handle_access.get(
                    (id(caller), handle), self._section_rights(
                        getattr(manager.file_maps[handle], "prot", 4)))
                count += 1
        return count

    def duplicate_guest_handle(self, emu, api_name: str, source: int,
                               output: int, access: int, inherit: int,
                               options: int, target_process=None,
                               source_process=None) -> int:
        """Duplicate an owned file or section entry into a modeled process."""
        manager = emu.get_file_manager()
        owner = id(source_process) if source_process is not None else self._guest_owner(emu)
        target_owner = id(target_process) if target_process is not None else owner
        is_mapping = source in manager.file_maps
        table = manager.file_maps if is_mapping else manager.file_handles
        event = {"event": "virtual_guest_handle_duplicate", "api": api_name,
                 "source_handle": source, "object_type": "mapping" if is_mapping else "file",
                 "requested_access": access & 0xFFFFFFFF, "options": options,
                 "success": False}
        if source_process is not None:
            event["source_pid"] = getattr(source_process, "pid", None)
        if target_process is not None:
            event["target_pid"] = getattr(target_process, "pid", None)
        self.events.append(event)
        owners = self.mapping_handle_owners if is_mapping else self.file_handle_owners
        owned = owner in owners.get(source, ())
        if not hasattr(emu, "get_current_process") and source in table:
            owned = self._owns_mapping_handle(emu, source) if is_mapping else self._owns_file_handle(emu, source)
        if source not in table or not owned:
            emu.set_last_error(6)
            event["reason"] = "different guest process or unissued handle"
            return 0
        close_source = bool(options & 1)

        def deny(error: int, reason: str) -> int:
            event["reason"] = reason
            if close_source:
                self._close_handle(emu, "kernel32.CloseHandle", None, [source],
                                   owner_override=owner)
            emu.set_last_error(error)
            return 0

        if options & ~3 or not output:
            return deny(87, "invalid output pointer or options")
        try:
            emu.mem_read(output, emu.get_ptr_size())
        except Exception:
            return deny(87, "unreadable output pointer")

        same_access = bool(options & 2)
        if is_mapping:
            mapping = table[source]
            available = self.mapping_handle_access.get(
                (owner, source), self._section_rights(mapping.prot))
            granted = (available if same_access else
                       0 if access == 0 else self._mapping_access_rights(access, opening=True))
            if granted is None:
                return deny(50, "unmodeled mapping access mask")
            if granted & ~available:
                return deny(5, "requested mapping access exceeds source")
            duplicate = mapping.get_handle()
            table[duplicate] = mapping
            self._register_mapping_handle(emu, duplicate, bool(inherit), granted,
                                          owner=target_owner)
        else:
            available = self.file_open_raw_access.get(source, 0)
            requested = available if same_access else access & 0xFFFFFFFF
            available_generic = available & 0xF0000000
            if available & 0x10000000:  # GENERIC_ALL grants the other generic classes.
                available_generic |= 0xE0000000
            if (requested & 0xF0000000 & ~available_generic or
                    self._effective_file_access(requested) &
                    ~self._effective_file_access(available)):
                return deny(5, "requested file access exceeds source")
            duplicate = emu.handle_allocator.allocate_file_handle()
            table[duplicate] = table[source]  # Duplicate shares the file cursor.
            path, _, share = self.file_open_options.get(source, (None, 0, 0))
            self.file_open_options[duplicate] = (
                path, self._share_access(requested), share)
            self.file_open_raw_access[duplicate] = requested
            self.file_handle_owners[duplicate] = {target_owner}
            self.file_handle_flags[(target_owner, duplicate)] = int(bool(inherit))
            self.closed_file_handles.discard(duplicate)
        try:
            emu.mem_write(output, duplicate.to_bytes(emu.get_ptr_size(), "little"))
        except Exception:
            table.pop(duplicate, None)
            if is_mapping:
                self.mapping_handle_owners.pop(duplicate, None)
                self.mapping_handle_flags.pop((target_owner, duplicate), None)
                self.mapping_handle_access.pop((target_owner, duplicate), None)
            else:
                self.file_handle_owners.pop(duplicate, None)
                self.file_handle_flags.pop((target_owner, duplicate), None)
                self.file_open_options.pop(duplicate, None)
                self.file_open_raw_access.pop(duplicate, None)
            return deny(87, "unwritable output pointer")
        event.update({"success": True, "handle": duplicate,
                      "granted_access": granted if is_mapping else requested})
        if close_source:
            self._close_handle(emu, "kernel32.CloseHandle", None, [source],
                               owner_override=owner)
        emu.set_last_error(0)
        return 1

    def _register_mapping_handle(self, emu, handle: int, inherit: bool,
                                 access: int | None = None,
                                 owner: int | None = None) -> None:
        if handle:
            if owner is None:
                owner = id(emu.get_current_process()) if hasattr(emu, "get_current_process") else id(emu)
            self.mapping_handle_owners[handle] = {owner}
            self.mapping_handle_flags[(owner, handle)] = int(inherit)
            mapping = emu.get_file_manager().get_mapping_from_handle(handle)
            if access is not None or mapping is not None:
                self.mapping_handle_access[(owner, handle)] = (
                    access if access is not None else self._section_rights(mapping.prot))

    @staticmethod
    def _section_rights(protection: int) -> int:
        return {2: 4, 4: 6, 0x20: 0x24, 0x40: 0x26}.get(int(protection) & 0xFF, 0)

    @staticmethod
    def _mapping_access_rights(access: int, *, opening: bool = False) -> int | None:
        access &= 0xFFFFFFFF
        if access == 0xF001F:  # FILE_MAP_ALL_ACCESS does not include execute.
            return 6
        if access == 0xF003F:
            return 0x26
        if opening and access == 1:  # FILE_MAP_COPY opens as FILE_MAP_READ.
            return 4
        if access not in (2, 4, 6, 0x20, 0x22, 0x24, 0x26):
            return None
        return (4 if access & 6 else 0) | (2 if access & 2 else 0) | (0x20 if access & 0x20 else 0)

    @staticmethod
    def _mapping_name_key(name: str) -> str | None:
        if not name or len(name) > 260:
            return None
        lowered = name.casefold()
        if lowered.startswith("global\\"):
            namespace, tail = "global", name[7:]
        elif lowered.startswith("local\\"):
            namespace, tail = "local", name[6:]
        else:
            namespace, tail = "local", name
        if not tail or "\\" in tail:
            return None
        return f"{namespace}\\{tail.casefold()}"

    def _named_mapping(self, manager, key: str):
        for mapping in manager.file_maps.values():
            if self._mapping_name_key(getattr(mapping, "name", "")) == key:
                return mapping
        return None

    def _open_mapping_alias(self, emu, mapping, inherit: bool, rights: int) -> int:
        handle = mapping.get_handle()
        emu.get_file_manager().file_maps[handle] = mapping
        self._register_mapping_handle(emu, handle, inherit, rights)
        return handle

    def _file_handle_allowed(self, emu, api_name: str, handle: int) -> bool:
        manager = emu.get_file_manager()
        if handle not in manager.file_handles or self._owns_file_handle(emu, handle):
            return True
        emu.set_last_error(6)
        self.events.append({"event": "virtual_file_handle_denied", "api": api_name,
                            "handle": handle, "reason": "different guest process or unissued handle"})
        return False

    def install(self, emulator) -> None:
        for name in ("GetFullPathNameA", "GetFullPathNameW"):
            emulator.add_api_hook(self._get_full_path_name, "kernel32", name, argc=4)
        for name in ("GetLongPathNameA", "GetLongPathNameW"):
            emulator.add_api_hook(self._get_long_path_name, "kernel32", name, argc=3)
        for name in ("MoveFileExA", "MoveFileExW"):
            emulator.add_api_hook(self._move_file_ex, "kernel32", name, argc=3)
        for name in ("DeleteFileA", "DeleteFileW"):
            emulator.add_api_hook(self._delete_file, "kernel32", name, argc=1)
        for name in ("CopyFileA", "CopyFileW"):
            emulator.add_api_hook(self._copy_file, "kernel32", name, argc=3)
        for name in ("CreateDirectoryA", "CreateDirectoryW"):
            emulator.add_api_hook(self._create_directory, "kernel32", name, argc=2)
        for name in ("RemoveDirectoryA", "RemoveDirectoryW"):
            emulator.add_api_hook(self._remove_directory, "kernel32", name, argc=1)
        for name in ("GetFileAttributesA", "GetFileAttributesW"):
            emulator.add_api_hook(self._get_file_attributes, "kernel32", name, argc=1)
        for name in ("GetFileAttributesExA", "GetFileAttributesExW"):
            emulator.add_api_hook(self._get_file_attributes_ex, "kernel32", name, argc=3)
        for name in ("GetVolumeInformationA", "GetVolumeInformationW"):
            emulator.add_api_hook(self._get_volume_information, "kernel32", name, argc=8)
        for name in ("GetTempPathA", "GetTempPathW"):
            emulator.add_api_hook(self._get_temp_path, "kernel32", name, argc=2)
        for name in ("SetFileAttributesA", "SetFileAttributesW"):
            emulator.add_api_hook(self._set_file_attributes, "kernel32", name, argc=2)
        for name in ("CreateFileA", "CreateFileW"):
            emulator.add_api_hook(self._create_file, "kernel32", name, argc=7)
        emulator.add_api_hook(self._close_handle, "kernel32", "CloseHandle", argc=1)
        emulator.add_api_hook(self._set_end_of_file, "kernel32", "SetEndOfFile", argc=1)
        emulator.add_api_hook(self._set_file_information, "kernel32",
                              "SetFileInformationByHandle", argc=4)
        for name in ("CreateFileMappingA", "CreateFileMappingW"):
            emulator.add_api_hook(self._create_file_mapping, "kernel32", name, argc=6)
        for name in ("OpenFileMappingA", "OpenFileMappingW"):
            emulator.add_api_hook(self._open_file_mapping, "kernel32", name, argc=3)
        emulator.add_api_hook(self._map_view_of_file, "kernel32", "MapViewOfFile", argc=5)
        emulator.add_api_hook(self._unmap_view_of_file, "kernel32", "UnmapViewOfFile", argc=1)
        emulator.add_api_hook(self._flush_view_of_file, "kernel32", "FlushViewOfFile", argc=2)
        for name, argc in (("ReadFile", 5), ("WriteFile", 5), ("GetFileSize", 2),
                           ("GetFileSizeEx", 2), ("SetFilePointer", 4),
                           ("SetFilePointerEx", 5)):
            emulator.add_api_hook(self._closed_file_operation, "kernel32", name, argc=argc)
        for name in ("ReadFile", "WriteFile"):
            emulator.add_api_hook(self._closed_file_operation,
                                  "api-ms-win-core-file-l1-1-0", name, argc=5)

    def _get_volume_information(self, emu, api_name, original, params):
        root_ptr, label_ptr, label_size, serial_ptr, component_ptr, flags_ptr, fs_ptr, fs_size = (
            int(value) for value in params)
        width = 2 if api_name.endswith("W") else 1
        root = (emu.read_mem_string(root_ptr, width) if root_ptr else
                ntpath.splitdrive(emu.get_cd())[0] + "\\")
        if root.casefold() != "c:\\":
            emu.set_last_error(3)
            return 0
        label, fs_name = "Windows", "NTFS"
        if ((label_ptr and not len(label) < label_size <= 261) or
                (fs_ptr and not len(fs_name) < fs_size <= 261)):
            emu.set_last_error(122)
            return 0
        encode = "utf-16-le" if width == 2 else "utf-8"
        try:
            if label_ptr:
                emu.mem_write(label_ptr, (label + "\0").encode(encode))
            if serial_ptr:
                emu.mem_write(serial_ptr, (0x4C2F91A7).to_bytes(4, "little"))
            if component_ptr:
                emu.mem_write(component_ptr, (255).to_bytes(4, "little"))
            if flags_ptr:
                emu.mem_write(flags_ptr, (0x024400DF).to_bytes(4, "little"))
            if fs_ptr:
                emu.mem_write(fs_ptr, (fs_name + "\0").encode(encode))
        except Exception:
            emu.set_last_error(998)
            return 0
        emu.set_last_error(0)
        self.events.append({"event": "virtual_volume_query", "api": api_name,
                            "root": "C:\\", "serial": "4C2F-91A7", "file_system": fs_name})
        return 1

    def _get_temp_path(self, emu, api_name, original, params):
        length, buffer = (int(value) for value in params)
        env = {key.lower(): value for key, value in emu.get_env().items()}
        path = next((env[key] for key in ("tmp", "temp", "userprofile")
                     if env.get(key)), r"C:\Windows")
        if len(path) > 259 or not ntpath.isabs(path):
            emu.set_last_error(87)
            return 0
        path = path.rstrip("\\/") + "\\"
        encoding = "utf-16-le" if api_name.endswith("W") else "utf-8"
        encoded = (path + "\0").encode(encoding)
        width = 2 if api_name.endswith("W") else 1
        needed = len(encoded) // width
        if length < needed:
            return needed
        if not buffer:
            emu.set_last_error(87)
            return 0
        try:
            emu.mem_write(buffer, encoded)
        except Exception:
            emu.set_last_error(998)
            return 0
        emu.set_last_error(0)
        return needed - 1

    def _create_file(self, emu, api_name, original, params):
        disposition = int(params[4]) & 0xFFFFFFFF
        manager = emu.get_file_manager()
        inherit = False
        security = int(params[3])
        if security:
            size = 24 if emu.get_ptr_size() == 8 else 12
            offset = 16 if emu.get_ptr_size() == 8 else 8
            try:
                length = int.from_bytes(emu.mem_read(security, 4), "little")
                inherit = bool(int.from_bytes(emu.mem_read(security + offset, 4), "little"))
            except Exception:
                emu.set_last_error(87)
                return 0xFFFFFFFF
            if length < size:
                emu.set_last_error(87)
                return 0xFFFFFFFF
        width = 2 if api_name.endswith("W") else 1
        path = self._path(emu.read_mem_string(int(params[0]), width)) if params[0] else ""
        existed = bool(path and manager.does_file_exist(path))
        access, share = int(params[1]) & 0xFFFFFFFF, int(params[2]) & 0xFFFFFFFF
        creation_attributes = int(params[5]) & 0xFFFF
        initial_attributes = self._normalized_attributes(creation_attributes)
        if initial_attributes is None:
            self.unsupported.append(f"{api_name}: unsupported creation attributes "
                                    f"0x{creation_attributes:x}")
            emu.set_last_error(50)
            return 0xFFFFFFFF
        delete_on_close = bool(int(params[5]) & 0x04000000)
        # TRUNCATE_EXISTING requires GENERIC_WRITE even when the file exists.
        if disposition == 5 and not access & 0x40000000:
            emu.set_last_error(87)  # ERROR_INVALID_PARAMETER
            self.events.append({"event": "virtual_file_open_denied", "api": api_name,
                                "path": path, "reason": "truncate requires GENERIC_WRITE"})
            return 0xFFFFFFFF
        key = self._key(path) if path else ""
        canonical_before = self._file(manager, path) if path else None
        if canonical_before is not None and self._attributes_for(canonical_before) & 0x1 and (
                access & (0x40000000 | 0x10000000 | 0x2 | 0x4 | 0x10000) or
                disposition in (2, 5)):
            emu.set_last_error(5)  # ERROR_ACCESS_DENIED for a new mutating handle.
            self.events.append({"event": "virtual_file_open_denied", "api": api_name,
                                "path": path, "reason": "read-only file"})
            return 0xFFFFFFFF
        if canonical_before is not None and id(canonical_before) in self.pending_disposition_files:
            emu.set_last_error(5)  # ERROR_ACCESS_DENIED
            self.events.append({"event": "virtual_file_open_denied", "api": api_name,
                                "path": path, "reason": "pending disposition deletion"})
            return 0xFFFFFFFF
        granted = self._share_access(access)
        if delete_on_close:
            granted |= 0x4  # The open requests delete access as well.
        requested = granted
        if existed and disposition in (2, 5):
            requested |= 0x2  # Truncation is a write operation.
        for open_path, open_access, open_share in self.file_open_options.values():
            if open_path != key:
                continue
            if requested & ~open_share or open_access & ~share:
                emu.set_last_error(32)  # ERROR_SHARING_VIOLATION
                self.events.append({"event": "virtual_file_open_denied", "api": api_name,
                                    "path": path, "reason": "sharing violation"})
                return 0xFFFFFFFF
        if delete_on_close:
            if (canonical_before is not None and canonical_before.config or
                    existed and canonical_before is None):
                self.unsupported.append(f"{api_name}: delete-on-close configured mapping {path}")
                emu.set_last_error(50)  # ERROR_NOT_SUPPORTED
                return 0xFFFFFFFF
        if (canonical_before is not None and id(canonical_before) in self.delete_on_close_files
                and not share & 0x4):
            emu.set_last_error(32)  # ERROR_SHARING_VIOLATION
            self.events.append({"event": "virtual_file_open_denied", "api": api_name,
                                "path": path, "reason": "delete-on-close sharing violation"})
            return 0xFFFFFFFF
        if disposition == 5:
            # Installed Speakeasy incorrectly defines TRUNCATE_EXISTING as 4,
            # so its CreateFile handler cannot process the real Win32 value 5.
            if canonical_before is None:
                if existed:
                    self.unsupported.append(f"{api_name}: TRUNCATE_EXISTING configured mapping {path}")
                    emu.set_last_error(50)  # ERROR_NOT_SUPPORTED
                else:
                    emu.set_last_error(2)  # ERROR_FILE_NOT_FOUND
                return 0xFFFFFFFF
            if canonical_before.config:
                self.unsupported.append(f"{api_name}: TRUNCATE_EXISTING configured mapping {path}")
                emu.set_last_error(50)
                return 0xFFFFFFFF
            opened_handle = manager.file_open(path, create=False)
            handle = int(opened_handle) if opened_handle is not None else 0xFFFFFFFF
            emu.set_last_error(0 if handle != 0xFFFFFFFF else 2)
            self.events.append({"event": "virtual_file_truncate", "api": api_name,
                                "path": path, "handle": handle})
        else:
            handle = int(original(params))
        if handle not in (0, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
            opened = manager.file_handles.get(handle)
            if opened is not None:
                canonical = self._file(manager, opened.path)
                if disposition in (2, 5) and canonical_before is not None and not canonical_before.config:
                    # Keep the same file object so other open views observe truncation.
                    if canonical is not canonical_before:
                        if canonical is not None:
                            manager.files.remove(canonical)
                        manager.files.append(canonical_before)
                    canonical_before.data = io.BytesIO()
                    canonical_before.bytes_written = 0
                    canonical = canonical_before
                if canonical is not None and not canonical.config:
                    if canonical_before is None:
                        canonical.virtual_attributes = initial_attributes
                    append_only = bool(access & 0x4) and not bool(
                        access & (0x2 | 0x40000000 | 0x10000000))
                    manager.file_handles[handle] = SharedGuestFileView(
                        canonical, append_only=append_only)
                self.file_open_options[handle] = (self._key(opened.path), granted, share)
                self.file_open_raw_access[handle] = access
                owner = id(emu.get_current_process()) if hasattr(emu, "get_current_process") else id(emu)
                self.file_handle_owners[handle] = {owner}
                self.file_handle_flags[(owner, handle)] = int(inherit)
                self.closed_file_handles.discard(handle)
                if delete_on_close and canonical is not None and not canonical.config:
                    self.delete_on_close_files[id(canonical)] = canonical
                    self.events.append({"event": "virtual_file_delete_on_close_open",
                                        "api": api_name, "path": path, "handle": handle})
        if disposition == 4:
            event = {"event": "virtual_file_open_always", "api": api_name,
                     "path": path, "existed_before": existed,
                     "handle": handle,
                     "success": handle not in (0, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF)}
            self.events.append(event)
            if event["success"]:
                emu.set_last_error(183 if existed else 0)  # ERROR_ALREADY_EXISTS or SUCCESS
        return handle

    def _close_handle(self, emu, api_name, original, params, *,
                      owner_override: int | None = None,
                      force: bool = False):
        handle = int(params[0])
        manager = emu.get_file_manager()
        if handle in getattr(manager, "file_maps", {}):
            owner = (owner_override if owner_override is not None else
                     self._guest_owner(emu))
            if owner not in self.mapping_handle_owners.get(handle, ()):
                emu.set_last_error(6)
                self.events.append({"event": "virtual_mapping_handle_denied", "api": api_name,
                                    "handle": handle,
                                    "reason": "different guest process or unissued handle"})
                return 0
            if not force and self.mapping_handle_flags.get((owner, handle), 0) & 2:
                emu.set_last_error(6)
                self.events.append({"event": "virtual_mapping_close", "handle": handle,
                                    "success": False, "reason": "protected from close"})
                return 0
            owners = self.mapping_handle_owners[handle]
            owners.remove(owner)
            self.mapping_handle_flags.pop((owner, handle), None)
            self.mapping_handle_access.pop((owner, handle), None)
            if not owners:
                self.mapping_handle_owners.pop(handle, None)
                mapping = manager.file_maps.pop(handle)
                self._retire_pagefile_section(manager, mapping)
            emu.set_last_error(0)
            self.events.append({"event": "virtual_mapping_close", "handle": handle,
                                "success": True, "remaining_owners": len(owners)})
            return 1
        if handle in manager.file_handles:
            owner = (owner_override if owner_override is not None else
                     self._guest_owner(emu))
            if not hasattr(emu, "get_current_process"):
                self._owns_file_handle(emu, handle)
            if owner not in self.file_handle_owners.get(handle, ()):
                emu.set_last_error(6)
                self.events.append({"event": "virtual_file_close", "api": api_name,
                                    "handle": handle, "success": False,
                                    "reason": "different guest process or unissued handle"})
                return 0
            if not force and self.file_handle_flags.get((owner, handle), 0) & 2:
                emu.set_last_error(6)
                self.events.append({"event": "virtual_file_close", "api": api_name,
                                    "handle": handle, "success": False,
                                    "reason": "protected from close"})
                return 0
            owners = self.file_handle_owners[handle]
            owners.remove(owner)
            self.file_handle_flags.pop((owner, handle), None)
            if owners:
                emu.set_last_error(0)
                self.events.append({"event": "virtual_file_close", "api": api_name,
                                    "handle": handle, "path": manager.file_handles[handle].path,
                                    "success": True, "remaining_owners": len(owners)})
                return 1
            self.file_handle_owners.pop(handle, None)
            item = manager.file_handles.pop(handle)
            self.file_open_options.pop(handle, None)
            self.file_open_raw_access.pop(handle, None)
            self.closed_file_handles.add(handle)
            self.events.append({"event": "virtual_file_close", "api": api_name,
                                "handle": handle, "path": item.path, "success": True})
            canonical = item.file if isinstance(item, SharedGuestFileView) else item
            if (id(canonical) in self.delete_on_close_files or
                    id(canonical) in self.pending_disposition_files) and not any(
                    (opened.file if isinstance(opened, SharedGuestFileView) else opened) is canonical
                    for opened in manager.file_handles.values()):
                self._retire_delete_on_close(manager, canonical, handle=handle)
            emu.set_last_error(0)
            return 1
        if handle in self.closed_file_handles:
            self.events.append({"event": "virtual_file_close", "api": api_name,
                                "handle": handle, "success": False})
            emu.set_last_error(6)  # ERROR_INVALID_HANDLE
            return 0
        if self.snapshot_close_handler is not None:
            result = self.snapshot_close_handler(emu, handle)
            if result is not None:
                return result
        if self.process_close_handler is not None:
            result = self.process_close_handler(emu, handle)
            if result is not None:
                return result
        return original(params)

    def cleanup_process(self, emu, process) -> dict[str, int]:
        """Release one exiting guest's views and file/section table entries."""
        owner = id(process)
        views = [base for base, candidate in self.mapped_guest_view_owners.items()
                 if candidate == owner]
        closed = {"views": 0, "files": 0, "mappings": 0}
        self.flush_pending_mapped_cpu_writes(emu)
        for base in views:
            mapping = emu.get_address_map(base)
            if mapping is None or int(mapping.base) != base:
                raise RuntimeError(f"exiting guest view 0x{base:x} has no exact mapping")
            length = int(mapping.size)
            with ExitStack() as allowance:
                if self.api_memory_allowance is not None:
                    allowance.enter_context(self.api_memory_allowance(base, length, "rw"))
                if base in self.mapped_guest_views:
                    self._sync_guest_view(emu, base, "process_exit")
                if base in self.pagefile_views:
                    self._sync_pagefile_write(emu, base, self.pagefile_views[base][2])
            emu.mem_free(base)
            if not getattr(mapping, "free", False):
                raise RuntimeError(f"exiting guest view 0x{base:x} remained mapped")
            section = self.mapped_guest_view_sections.pop(base, None)
            if section is not None:
                getattr(section, "views", {}).pop(base, None)
            pagefile = self.pagefile_views.pop(base, None)
            if pagefile is not None:
                getattr(pagefile[0], "views", {}).pop(base, None)
                self._retire_pagefile_section(emu.get_file_manager(), pagefile[0])
            self.mapped_guest_views.pop(base, None)
            self.mapped_guest_view_owners.pop(base, None)
            closed["views"] += 1
            self.events.append({"event": "virtual_mapping_view_process_exit",
                                "pid": int(process.pid), "base": base, "success": True})
        for handle, owners in tuple(self.file_handle_owners.items()):
            if owner in owners and self._close_handle(
                    emu, "process_exit", None, [handle],
                    owner_override=owner, force=True):
                closed["files"] += 1
        for handle, owners in tuple(self.mapping_handle_owners.items()):
            if owner in owners and self._close_handle(
                    emu, "process_exit", None, [handle],
                    owner_override=owner, force=True):
                closed["mappings"] += 1
        self.events.append({"event": "virtual_file_process_cleanup",
                            "pid": int(process.pid), **closed, "success": True})
        return closed

    def _retire_delete_on_close(self, manager, canonical: GuestFile,
                                *, handle: int | None = None) -> None:
        self.delete_on_close_files.pop(id(canonical), None)
        disposition = self.pending_disposition_files.pop(id(canonical), None) is not None
        if not any(existing is canonical for existing in manager.files):
            return
        data = self._copy_source_data(canonical, None)
        source = "virtual_file_disposition_delete" if disposition else "virtual_file_delete_on_close"
        artifact = self.catalog.add(data, source,
                                    guest_path=canonical.path) if data else None
        manager.files.remove(canonical)
        event = {"event": source, "path": canonical.path,
                 "handle": handle, "exists_after": self._exact_exists(manager, canonical.path)}
        if artifact:
            event["artifact_sha256"] = artifact["sha256"]
        self.events.append(event)

    def finalize_delete_on_close(self, emu) -> None:
        """Process exit closes live handles, including delete-on-close handles."""
        manager = emu.get_file_manager()
        pending = {**self.delete_on_close_files, **self.pending_disposition_files}
        for canonical in tuple(pending.values()):
            self._retire_delete_on_close(manager, canonical)

    def _set_file_information(self, emu, api_name, original, params):
        handle, info_class, address, size = (int(value) for value in params)
        if not self._file_handle_allowed(emu, api_name, handle):
            return 0
        manager = emu.get_file_manager()
        item = manager.file_handles.get(handle)
        if item is None:
            emu.set_last_error(6)  # ERROR_INVALID_HANDLE
            return 0
        if info_class not in (0, 3, 4, 6):  # Basic, rename, disposition, end-of-file.
            self.unsupported.append(f"{api_name}: information class {info_class} unsupported")
            emu.set_last_error(50)  # ERROR_NOT_SUPPORTED
            return 0
        if not isinstance(item, SharedGuestFileView):
            self.unsupported.append(f"{api_name}: configured file handle {handle}")
            emu.set_last_error(50)
            return 0
        if not address:
            emu.set_last_error(87)  # ERROR_INVALID_PARAMETER
            return 0
        if info_class == 0:
            return self._set_file_basic_info(emu, api_name, handle, item,
                                             address, size)
        if info_class == 3:
            return self._rename_file_by_handle(emu, api_name, handle, item,
                                               address, size)
        if info_class == 6:
            if size < 8:
                emu.set_last_error(24)  # ERROR_BAD_LENGTH
                return 0
            if size > 64:
                self.unsupported.append(f"{api_name}: oversized end-of-file buffer {size}")
                emu.set_last_error(50)
                return 0
            access = self.file_open_raw_access.get(handle, 0)
            if not access & (0x2 | 0x40000000 | 0x10000000):
                emu.set_last_error(5)  # FILE_WRITE_DATA required.
                return 0
            try:
                raw = emu.mem_read(address, 8)
                if len(raw) != 8:
                    raise ValueError("short guest end-of-file buffer")
                length = int.from_bytes(raw, "little", signed=True)
            except Exception:
                emu.set_last_error(998)  # ERROR_NOACCESS
                return 0
            if length < 0:
                emu.set_last_error(87)  # ERROR_INVALID_PARAMETER
                return 0
            if length > MAX_ARTIFACT:
                self.unsupported.append(f"{api_name}: end-of-file exceeds virtual limit")
                emu.set_last_error(223)  # ERROR_FILE_TOO_LARGE
                return 0
            if any(file is item.file for file, _, _, _ in self.mapped_guest_views.values()):
                self.unsupported.append(f"{api_name}: resize with mapped guest view")
                emu.set_last_error(50)
                return 0
            previous = item.get_size()
            item.set_size(length)
            emu.set_last_error(0)
            self.events.append({"event": "virtual_file_resize", "api": api_name,
                                "handle": handle, "path": item.path,
                                "old_size": previous, "new_size": length})
            return 1
        if size < 1:
            emu.set_last_error(24)  # ERROR_BAD_LENGTH
            return 0
        if size > 64:
            self.unsupported.append(f"{api_name}: oversized disposition buffer {size}")
            emu.set_last_error(50)
            return 0
        if not self.file_open_options.get(handle, (None, 0, 0))[1] & 0x4:
            emu.set_last_error(5)  # ERROR_ACCESS_DENIED: DELETE right required.
            return 0
        try:
            delete = bool(emu.mem_read(address, 1)[0])
        except Exception:
            emu.set_last_error(998)  # ERROR_NOACCESS
            return 0
        canonical = item.file
        if delete:
            self.pending_disposition_files[id(canonical)] = canonical
        else:
            self.pending_disposition_files.pop(id(canonical), None)
        emu.set_last_error(0)
        self.events.append({"event": "virtual_file_disposition", "api": api_name,
                            "handle": handle, "path": canonical.path,
                            "delete": delete,
                            "pending": id(canonical) in self.pending_disposition_files or
                                       id(canonical) in self.delete_on_close_files})
        return 1

    @staticmethod
    def _normalized_attributes(value: int, *, directory: bool = False) -> int | None:
        # These flags have meaningful guest-visible state in the current model.
        supported = 0x1 | 0x2 | 0x4 | 0x20 | 0x80 | 0x100 | 0x2000
        if directory:
            supported |= 0x10
        if value & ~supported:
            return None
        value &= ~(0x80 | 0x10)  # NORMAL is ignored; DIRECTORY is derived from the path.
        if directory:
            return value | 0x10
        return value or 0x80

    @staticmethod
    def _attributes_for(source: GuestFile) -> int:
        return getattr(source, "virtual_attributes", 0x80)

    def _set_file_basic_info(self, emu, api_name: str, handle: int,
                             item: SharedGuestFileView, address: int,
                             size: int) -> int:
        if size < 40:
            emu.set_last_error(24)  # ERROR_BAD_LENGTH
            return 0
        if size > 65536:
            self.unsupported.append(f"{api_name}: oversized basic-information buffer {size}")
            emu.set_last_error(50)
            return 0
        access = self.file_open_raw_access.get(handle, 0)
        if not access & (0x100 | 0x40000000 | 0x10000000):
            emu.set_last_error(5)  # FILE_WRITE_ATTRIBUTES required.
            return 0
        try:
            raw = emu.mem_read(address, 40)
            if len(raw) != 40:
                raise ValueError("short guest basic-information buffer")
            creation, last_access, last_write, change, attributes = struct.unpack("<qqqqI4x", raw)
        except Exception:
            emu.set_last_error(998)  # ERROR_NOACCESS
            return 0
        if any(value < 0 for value in (creation, last_access, last_write, change)):
            self.unsupported.append(f"{api_name}: special or negative FILETIME values")
            emu.set_last_error(50)
            return 0
        normalized = self._normalized_attributes(attributes) if attributes else None
        if attributes and normalized is None:
            self.unsupported.append(f"{api_name}: unsupported file attributes 0x{attributes:x}")
            emu.set_last_error(50)
            return 0
        source = item.file
        previous_times = getattr(source, "virtual_times", (self.filetime_ticks,) * 4)
        source.virtual_times = tuple(value or old for value, old in
                                     zip((creation, last_access, last_write, change),
                                         previous_times))
        if attributes:
            source.virtual_attributes = normalized
        self.events.append({"event": "virtual_file_basic_info", "api": api_name,
                            "handle": handle, "path": source.path,
                            "attributes": self._attributes_for(source),
                            "times": list(source.virtual_times)})
        emu.set_last_error(0)
        return 1

    def _rename_file_by_handle(self, emu, api_name: str, handle: int,
                               item: SharedGuestFileView, address: int,
                               size: int) -> int:
        """Apply FILE_RENAME_INFO to the guest namespace, never the host FS."""
        pointer_size = emu.get_ptr_size()
        name_offset = 20 if pointer_size == 8 else 12
        event = {"event": "virtual_file_rename_by_handle", "api": api_name,
                 "handle": handle, "old_path": item.path, "success": False}
        self.events.append(event)
        if size < name_offset:
            emu.set_last_error(24)  # ERROR_BAD_LENGTH
            return 0
        if size > name_offset + 65534:
            self.unsupported.append(f"{api_name}: oversized rename buffer {size}")
            emu.set_last_error(50)
            return 0
        if not self.file_open_options.get(handle, (None, 0, 0))[1] & 0x4:
            emu.set_last_error(5)  # DELETE right required.
            return 0
        try:
            header = emu.mem_read(address, name_offset)
            if len(header) != name_offset:
                raise ValueError("short rename header")
            root_offset = 8 if pointer_size == 8 else 4
            root = int.from_bytes(header[root_offset:root_offset + pointer_size], "little")
            name_length = int.from_bytes(header[name_offset - 4:name_offset], "little")
            if root:
                # Directory handles are not modeled by this bridge.
                self.unsupported.append(f"{api_name}: RootDirectory handle {root}")
                emu.set_last_error(6)  # ERROR_INVALID_HANDLE
                return 0
            if not name_length or name_length & 1:
                emu.set_last_error(87)  # ERROR_INVALID_PARAMETER
                return 0
            if name_length > 65534 or name_offset + name_length > size:
                emu.set_last_error(24)  # ERROR_BAD_LENGTH
                return 0
            name_bytes = emu.mem_read(address + name_offset, name_length)
            if len(name_bytes) != name_length:
                raise ValueError("short rename name")
            name = name_bytes.decode("utf-16le", errors="strict").rstrip("\0")
        except UnicodeDecodeError:
            emu.set_last_error(87)
            return 0
        except Exception:
            emu.set_last_error(998)  # ERROR_NOACCESS
            return 0
        if not name or "\0" in name:
            emu.set_last_error(87)
            return 0
        if name.startswith(":"):
            self.unsupported.append(f"{api_name}: alternate stream rename")
            emu.set_last_error(50)
            return 0
        old, new = item.path, self._path(name)
        event["new_path"] = new
        manager = emu.get_file_manager()
        source = item.file
        if source not in manager.files or id(source) in self.pending_disposition_files:
            emu.set_last_error(5)
            return 0
        if source.config or self._config(manager, old) is not None:
            self.unsupported.append(f"{api_name}: configured source {old}")
            emu.set_last_error(50)
            return 0
        if ntpath.splitdrive(old)[0].lower() != ntpath.splitdrive(new)[0].lower():
            emu.set_last_error(17)  # ERROR_NOT_SAME_DEVICE
            return 0
        if self._key(ntpath.dirname(new)) not in self._known_directories(manager):
            emu.set_last_error(3)  # ERROR_PATH_NOT_FOUND
            return 0
        if self._key(old) == self._key(new):
            self._rename_open_name(old, new)
            source.path = new
            event["success"] = True
            event["old_exists_after"] = True
            event["new_exists_after"] = True
            emu.set_last_error(0)
            return 1
        if self._key(new) in self._known_directories(manager):
            emu.set_last_error(183)  # ERROR_ALREADY_EXISTS
            return 0
        target = self._file(manager, new)
        target_config = self._config(manager, new)
        replace = bool(header[0])
        event["replace"] = replace
        if target is not None or target_config is not None:
            if not replace:
                emu.set_last_error(183)  # ERROR_ALREADY_EXISTS
                return 0
            if target_config is not None or target is not None and target.config:
                self.unsupported.append(f"{api_name}: configured destination {new}")
                emu.set_last_error(50)
                return 0
            if self._handles_at(new):
                emu.set_last_error(5)  # ERROR_ACCESS_DENIED
                return 0
            if any(file is target for file, _, _, _ in self.mapped_guest_views.values()):
                self.unsupported.append(f"{api_name}: mapped destination {new}")
                emu.set_last_error(50)
                return 0
            if target is not None:
                old_bytes = SharedGuestFileView(target)._bytes()
                artifact = self.catalog.add(old_bytes, "virtual_file_rename_replaced",
                                            guest_path=new) if old_bytes else None
                if artifact:
                    event["replaced_sha256"] = artifact["sha256"]
                manager.files.remove(target)
        self._rename_open_name(old, new)
        source.path = new
        moved_bytes = item._bytes()
        artifact = self.catalog.add(moved_bytes, "virtual_file_rename_by_handle",
                                    guest_path=new) if moved_bytes else None
        if artifact:
            event["artifact_sha256"] = artifact["sha256"]
        event["success"] = True
        event["old_exists_after"] = self._exact_exists(manager, old)
        event["new_exists_after"] = self._exact_exists(manager, new)
        emu.set_last_error(0)
        return 1

    def _create_file_mapping(self, emu, api_name, original, params):
        manager = emu.get_file_manager()
        handle = int(params[0])
        inherit = False
        security = int(params[1])
        if security:
            struct_size = 24 if emu.get_ptr_size() == 8 else 12
            flag_offset = 16 if emu.get_ptr_size() == 8 else 8
            try:
                length = int.from_bytes(emu.mem_read(security, 4), "little")
                inherit = bool(int.from_bytes(emu.mem_read(security + flag_offset, 4), "little"))
            except Exception:
                emu.set_last_error(87)
                return 0
            if length < struct_size:
                emu.set_last_error(87)
                return 0
        name = ""
        if params[5]:
            try:
                name = emu.read_mem_string(int(params[5]),
                                           2 if api_name.endswith("W") else 1,
                                           max_chars=261)
            except Exception:
                emu.set_last_error(87)
                return 0
            key = self._mapping_name_key(name)
            if key is None:
                emu.set_last_error(123)  # ERROR_INVALID_NAME
                return 0
            existing = self._named_mapping(manager, key)
            if existing is not None:
                requested = self._section_rights(int(params[2]))
                available = self._section_rights(existing.prot)
                if requested == 0 or requested & ~available:
                    emu.set_last_error(5)
                    return 0
                alias = self._open_mapping_alias(emu, existing, inherit, requested)
                self.events.append({"event": "virtual_mapping_open", "api": api_name,
                                    "handle": alias, "name": name, "existing": True,
                                    "size": existing.size})
                emu.set_last_error(183)  # ERROR_ALREADY_EXISTS
                return alias
        if not self._file_handle_allowed(emu, api_name, handle):
            return 0
        size = ((int(params[3]) & 0xFFFFFFFF) << 32) | (int(params[4]) & 0xFFFFFFFF)
        protection = int(params[2]) & 0xFFFFFFFF
        invalid = (1 << (emu.get_ptr_size() * 8)) - 1
        if handle in (invalid, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
            # The engine owns the section bytes, but its allocation must stay
            # within our guest memory budget and use a modeled protection.
            if size == 0 or size > MAX_ARTIFACT:
                emu.set_last_error(87 if size == 0 else 223)
                return 0
            if protection & ~0x080000FF or protection & 0xFF not in (2, 4, 0x20, 0x40):
                self.unsupported.append(f"{api_name}: pagefile protection 0x{protection:x}")
                emu.set_last_error(50)
                return 0
            mapped = int(original(params))
            self._register_mapping_handle(emu, mapped, inherit)
            return mapped
        item = manager.file_handles.get(handle)
        if item is None:
            emu.set_last_error(6)  # ERROR_INVALID_HANDLE
            return 0
        if not isinstance(item, SharedGuestFileView):
            self.unsupported.append(f"{api_name}: non-guest file mapping")
            emu.set_last_error(50)
            return 0
        if protection not in (2, 4):  # PAGE_READONLY, PAGE_READWRITE
            self.unsupported.append(f"{api_name}: protection 0x{protection:x}")
            emu.set_last_error(50)
            return 0
        raw_access = self.file_open_raw_access.get(handle, 0)
        if not raw_access & (0x80000000 | 0x10000000):
            emu.set_last_error(5)
            return 0
        if protection == 4 and not raw_access & (0x40000000 | 0x10000000):
            emu.set_last_error(5)
            return 0
        if size == 0:
            size = item.get_size()
        if size == 0 or size > MAX_ARTIFACT:
            emu.set_last_error(1006 if size == 0 else 223)  # ERROR_FILE_INVALID
            return 0
        if size > item.get_size():
            if protection != 4:
                emu.set_last_error(5)
                return 0
            item.set_size(size)
        mapped = manager.file_create_mapping(handle, name, size, protection)
        self._register_mapping_handle(emu, mapped, inherit)
        mapping = manager.get_mapping_from_handle(mapped)
        mapping.size = size
        self.events.append({"event": "virtual_mapping_create", "handle": mapped,
                            "path": item.path, "size": size, "protection": protection})
        emu.set_last_error(0)
        return mapped

    def _open_file_mapping(self, emu, api_name, original, params):
        access = int(params[0]) & 0xFFFFFFFF
        rights = self._mapping_access_rights(access, opening=True)
        if rights is None:
            self.unsupported.append(f"{api_name}: access 0x{access:x}")
            emu.set_last_error(50)
            return 0
        if not params[2]:
            emu.set_last_error(87)
            return 0
        try:
            name = emu.read_mem_string(int(params[2]),
                                       2 if api_name.endswith("W") else 1,
                                       max_chars=261)
        except Exception:
            emu.set_last_error(87)
            return 0
        key = self._mapping_name_key(name)
        if key is None:
            emu.set_last_error(123)
            return 0
        mapping = self._named_mapping(emu.get_file_manager(), key)
        if mapping is None:
            emu.set_last_error(2)  # ERROR_FILE_NOT_FOUND
            return 0
        if rights & ~self._section_rights(mapping.prot):
            emu.set_last_error(5)
            return 0
        handle = self._open_mapping_alias(emu, mapping, bool(params[1]), rights)
        self.events.append({"event": "virtual_mapping_open", "api": api_name,
                            "handle": handle, "name": name, "existing": True,
                            "size": mapping.size})
        emu.set_last_error(0)
        return handle

    @staticmethod
    def _bind_view_to_process(emu, base: int) -> None:
        """A shared file object still has a process-private view address."""
        if not hasattr(emu, "get_current_process"):
            return  # Small API doubles used by source tests have no map model.
        process = emu.get_current_process()
        mapping = emu.get_address_map(base)
        if process is None or mapping is None or int(mapping.base) != base:
            raise RuntimeError(f"MapViewOfFile: cannot assign guest view 0x{base:x} to a process")
        mapping.process = process
        mapping.shared = False

    def _pagefile_bytes(self, mapping) -> bytearray:
        key = id(mapping)
        data = self.pagefile_sections.get(key)
        if data is None:
            size = int(mapping.size)
            if not 0 < size <= MAX_ARTIFACT:
                raise ValueError("pagefile section exceeds guest memory limit")
            data = bytearray(size)
            self.pagefile_sections[key] = data
        return data

    def _retire_pagefile_section(self, manager, mapping) -> None:
        if (not any(item is mapping for item in manager.file_maps.values()) and
                not any(item is mapping for item, _, _ in self.pagefile_views.values())):
            self.pagefile_sections.pop(id(mapping), None)

    def record_cpu_mapped_write(self, emu, address: int, size: int) -> None:
        if size <= 0:
            return
        if size > MAX_ARTIFACT:
            raise ValueError("CPU mapped write exceeds guest memory limit")
        ranges = ((base, length) for base, (_, _, length) in self.pagefile_views.items())
        ranges = (*ranges, *((base, length) for base, (_, _, length, writable)
                              in self.mapped_guest_views.items() if writable))
        for base, length in ranges:
            if address < base + length and base < address + size:
                if self.pending_mapped_cpu_writes:
                    prior_address, prior_size = self.pending_mapped_cpu_writes[-1]
                    if address <= prior_address + prior_size and prior_address <= address + size:
                        begin = min(address, prior_address)
                        stop = max(address + size, prior_address + prior_size)
                        self.pending_mapped_cpu_writes[-1] = (begin, stop - begin)
                        return
                if len(self.pending_mapped_cpu_writes) >= 4096:
                    # The hook fires before this store, so older stores have
                    # completed and can be mirrored without growing the queue.
                    self.flush_pending_mapped_cpu_writes(emu)
                self.pending_mapped_cpu_writes.append((address, size))
                return

    def flush_pending_mapped_cpu_writes(self, emu) -> None:
        pending, self.pending_mapped_cpu_writes = self.pending_mapped_cpu_writes, []
        for address, size in pending:
            self._sync_pagefile_write(emu, address, size)
            self._sync_guest_file_write(emu, address, size)

    def observe_mapped_api_write(self, emu, address: int, size: int) -> None:
        if not self._mirroring_mapped_write and size > 0:
            self._sync_pagefile_write(emu, address, size)
            self._sync_guest_file_write(emu, address, size)

    def _sync_pagefile_write(self, emu, address: int, size: int) -> None:
        """Copy one completed write into its section and overlapping views."""
        end = address + size
        for base, (mapping, offset, length) in tuple(self.pagefile_views.items()):
            start = max(address, base)
            stop = min(end, base + length)
            if start >= stop:
                continue
            source_map = emu.get_address_map(base)
            if source_map is None or getattr(source_map, "free", False):
                continue
            section_start = offset + start - base
            chunk = emu.mem_read(start, stop - start)
            backing = self._pagefile_bytes(mapping)
            backing[section_start:section_start + len(chunk)] = chunk
            for peer_base, (peer, peer_offset, peer_length) in tuple(self.pagefile_views.items()):
                if peer_base == base or peer is not mapping:
                    continue
                peer_start = max(section_start, peer_offset)
                peer_end = min(section_start + len(chunk), peer_offset + peer_length)
                if peer_start >= peer_end:
                    continue
                peer_map = emu.get_address_map(peer_base)
                if peer_map is None or getattr(peer_map, "free", False):
                    continue
                peer_address = peer_base + peer_start - peer_offset
                peer_data = chunk[peer_start - section_start:peer_end - section_start]
                self._mirroring_mapped_write = True
                try:
                    with ExitStack() as allowance:
                        if self.api_memory_allowance is not None:
                            allowance.enter_context(self.api_memory_allowance(
                                peer_address, len(peer_data), "w"))
                        emu.mem_write(peer_address, peer_data)
                finally:
                    self._mirroring_mapped_write = False
            self.events.append({"event": "virtual_pagefile_write", "base": base,
                                "offset": section_start, "size": len(chunk)})

    def _sync_guest_file_write(self, emu, address: int, size: int) -> None:
        """Commit a completed view write to guest file bytes and overlapping views."""
        end = address + size
        for base, (file, offset, length, writable) in tuple(self.mapped_guest_views.items()):
            start, stop = max(address, base), min(end, base + length)
            if not writable or start >= stop:
                continue
            source_map = emu.get_address_map(base)
            if source_map is None or getattr(source_map, "free", False):
                continue
            file_start = offset + start - base
            chunk = emu.mem_read(start, stop - start)
            current = file.data.getvalue() if isinstance(file.data, io.BytesIO) else file.data or b""
            if current[file_start:file_start + len(chunk)] != chunk:
                file.data = io.BytesIO(current[:file_start] + chunk +
                                       current[file_start + len(chunk):])
                file.bytes_written += len(chunk)
                self.events.append({"event": "virtual_mapping_writeback", "base": base,
                                    "path": file.path, "offset": file_start,
                                    "size": len(chunk), "reason": "live_write"})
            for peer_base, (peer, peer_offset, peer_length, _) in tuple(self.mapped_guest_views.items()):
                if peer_base == base or peer is not file:
                    continue
                peer_start = max(file_start, peer_offset)
                peer_end = min(file_start + len(chunk), peer_offset + peer_length)
                if peer_start >= peer_end:
                    continue
                peer_map = emu.get_address_map(peer_base)
                if peer_map is None or getattr(peer_map, "free", False):
                    continue
                peer_address = peer_base + peer_start - peer_offset
                peer_data = chunk[peer_start - file_start:peer_end - file_start]
                self._mirroring_mapped_write = True
                try:
                    with ExitStack() as allowance:
                        if self.api_memory_allowance is not None:
                            allowance.enter_context(self.api_memory_allowance(
                                peer_address, len(peer_data), "w"))
                        emu.mem_write(peer_address, peer_data)
                finally:
                    self._mirroring_mapped_write = False

    def _map_view_of_file(self, emu, api_name, original, params):
        manager = emu.get_file_manager()
        handle = int(params[0])
        if not self._mapping_handle_allowed(emu, api_name, handle):
            return 0
        mapping = manager.get_mapping_from_handle(handle)
        if mapping is None:
            emu.set_last_error(6)
            return 0
        access = int(params[1]) & 0xFFFFFFFF
        rights = self._mapping_access_rights(access)
        if rights is not None:
            granted = self.mapping_handle_access.get(
                (self._guest_owner(emu), handle), self._section_rights(mapping.prot))
            if rights & ~granted:
                emu.set_last_error(5)
                return 0
        item = mapping.backed_file
        if not isinstance(item, SharedGuestFileView):
            offset = ((int(params[2]) & 0xFFFFFFFF) << 32) | (int(params[3]) & 0xFFFFFFFF)
            length = int(params[4])
            protection = int(mapping.prot) & 0xFF
            all_access = 0xF001F
            # FILE_MAP_COPY has private write semantics which the engine does
            # not provide. Restrict accepted views to explicit shared rights.
            if access == all_access:
                readable, writable, executable = True, True, False
            elif access == all_access | 0x20:
                readable, writable, executable = True, True, True
            elif access in (2, 4, 6, 0x20, 0x22, 0x24, 0x26):
                writable = bool(access & 2)
                readable = bool(access & 4) or writable
                executable = bool(access & 0x20)
            else:
                self.unsupported.append(f"{api_name}: pagefile access 0x{access:x}")
                emu.set_last_error(50)
                return 0
            if ((writable and protection not in (4, 0x40)) or
                    (executable and protection not in (0x20, 0x40)) or
                    (readable and protection not in (2, 4, 0x20, 0x40))):
                emu.set_last_error(5)
                return 0
            size = int(mapping.size)
            if size <= 0 or size > MAX_ARTIFACT or offset % 65536 or offset >= size or length < 0 or (length and length > size - offset):
                emu.set_last_error(87)
                return 0
            if not length:
                length = size - offset
            if length > MAX_ARTIFACT:
                emu.set_last_error(223)
                return 0
            self.flush_pending_mapped_cpu_writes(emu)
            backing = self._pagefile_bytes(mapping)
            # Speakeasy does not interpret a zero length as "to end" for
            # pagefile sections; always pass the bounded effective length.
            # Speakeasy accesses existing views when mapping a second one.
            # Scope its internal operations to this validated section.
            with ExitStack() as allowances:
                if self.api_memory_allowance is not None:
                    for source_view in getattr(mapping, "views", {}).values():
                        allowances.enter_context(self.api_memory_allowance(
                            int(source_view.base), int(source_view.size), "rw"))
                base = int(original([params[0], access, params[2], params[3], length]))
                if base:
                    emu.mem_write(base, bytes(backing[offset:offset + length]))
            if base:
                self._bind_view_to_process(emu, base)
                if hasattr(emu, "get_address_map"):
                    view_map = emu.get_address_map(base)
                    perms = ((common.PERM_MEM_READ if readable else 0) |
                             (common.PERM_MEM_WRITE if writable else 0) |
                             (common.PERM_MEM_EXEC if executable else 0))
                    emu.mem_protect(base, view_map.size, perms)
                    view_map.prot = perms
                self.mapped_guest_view_owners[base] = self._guest_owner(emu)
                self.pagefile_views[base] = (mapping, offset, length)
                self.events.append({"event": "virtual_mapping_view", "base": base,
                                    "path": "<pagefile>", "offset": offset,
                                    "size": length, "writable": writable,
                                    "executable": executable})
            return base
        offset = ((int(params[2]) & 0xFFFFFFFF) << 32) | (int(params[3]) & 0xFFFFFFFF)
        length = int(params[4])
        # Model the normal read/write views; copy, executable, and all-access
        # modes need distinct consistency and protection handling.
        if access not in (2, 4) or (access == 2 and mapping.prot != 4):
            self.unsupported.append(f"{api_name}: access 0x{access:x}")
            emu.set_last_error(50)
            return 0
        if offset % 65536 or offset >= mapping.size or length < 0 or (length and length > mapping.size - offset):
            emu.set_last_error(87)
            return 0
        if not length:
            length = mapping.size - offset
        if length > MAX_ARTIFACT:
            emu.set_last_error(223)
            return 0
        self.flush_pending_mapped_cpu_writes(emu)
        cursor = item.tell()
        item.position = 0
        try:
            # Speakeasy otherwise maps from the file cursor and ignores an
            # offset when dwNumberOfBytesToMap is zero.
            with ExitStack() as allowances:
                if self.api_memory_allowance is not None:
                    for source_view in getattr(mapping, "views", {}).values():
                        allowances.enter_context(self.api_memory_allowance(
                            int(source_view.base), int(source_view.size), "r"))
                base = int(original([params[0], access, params[2], params[3], length]))
        finally:
            item.position = cursor
        if base:
            self._bind_view_to_process(emu, base)
            self.mapped_guest_views[base] = (item.file, offset, length, access == 2)
            self.mapped_guest_view_sections[base] = mapping
            self.mapped_guest_view_owners[base] = self._guest_owner(emu)
            self.events.append({"event": "virtual_mapping_view", "base": base,
                                "path": item.path, "offset": offset, "size": length,
                                "writable": access == 2})
        return base

    def _unmap_view_of_file(self, emu, api_name, original, params):
        base = int(params[0])
        mapping = emu.get_address_map(base) if hasattr(emu, "get_address_map") else None
        mapped_base = int(mapping.base) if mapping is not None else base
        owner = self.mapped_guest_view_owners.get(mapped_base)
        if owner is not None and owner != self._guest_owner(emu):
            emu.set_last_error(6)
            self.events.append({"event": "virtual_mapping_view_denied", "api": api_name,
                                "base": mapped_base, "reason": "different guest process"})
            return 0
        if owner is None:
            emu.set_last_error(87)
            self.events.append({"event": "virtual_mapping_view_denied", "api": api_name,
                                "base": mapped_base, "reason": "untracked view"})
            return 0
        view = self.mapped_guest_views.get(mapped_base)
        if view is None:
            self.flush_pending_mapped_cpu_writes(emu)
            pagefile_view = self.pagefile_views.get(mapped_base)
            if pagefile_view is not None:
                self._sync_pagefile_write(emu, mapped_base, pagefile_view[2])
            result = original([mapped_base])
            if result:
                self.mapped_guest_view_owners.pop(mapped_base, None)
                if pagefile_view is not None:
                    section = pagefile_view[0]
                    self.pagefile_views.pop(mapped_base, None)
                    getattr(section, "views", {}).pop(mapped_base, None)
                    self._retire_pagefile_section(emu.get_file_manager(), section)
            return result
        self._sync_guest_view(emu, mapped_base, "unmap")
        result = original([mapped_base])
        if result:
            self.mapped_guest_views.pop(mapped_base, None)
            self.mapped_guest_view_owners.pop(mapped_base, None)
            section = self.mapped_guest_view_sections.pop(mapped_base, None)
            if section is not None:
                getattr(section, "views", {}).pop(mapped_base, None)
        return result

    def _sync_guest_view(self, emu, base: int, reason: str) -> None:
        file, offset, length, writable = self.mapped_guest_views[base]
        if not writable:
            return
        data = emu.mem_read(base, length)
        current = file.data.getvalue() if isinstance(file.data, io.BytesIO) else file.data or b""
        if current[offset:offset + length] != data:
            file.data = io.BytesIO(current[:offset] + data + current[offset + length:])
            file.bytes_written += len(data)
            self.events.append({"event": "virtual_mapping_writeback", "base": base,
                                "path": file.path, "offset": offset, "size": length,
                                "reason": reason})

    def capture_live_views(self, emu) -> None:
        """Recover guest file bytes even when execution ends without unmapping."""
        for base in tuple(self.mapped_guest_views):
            try:
                self._sync_guest_view(emu, base, "end_of_run")
            except Exception as exc:
                # A guest can free a view without calling UnmapViewOfFile;
                # do not turn that stale address into a worker failure.
                self.unsupported.append(f"MapViewOfFile: live view 0x{base:x} unreadable: {exc}")

    def _flush_view_of_file(self, emu, api_name, original, params):
        address, count = int(params[0]), int(params[1])
        mapping = emu.get_address_map(address) if hasattr(emu, "get_address_map") else None
        mapped_base = int(mapping.base) if mapping is not None else None
        if mapped_base in self.mapped_guest_view_owners:
            owner = self.mapped_guest_view_owners[mapped_base]
            if owner != self._guest_owner(emu):
                emu.set_last_error(6)
                self.events.append({"event": "virtual_mapping_view_denied", "api": api_name,
                                    "base": mapped_base, "reason": "different guest process"})
                return 0
            if mapped_base not in self.mapped_guest_views:
                if count < 0 or count > int(mapping.base) + int(mapping.size) - address:
                    emu.set_last_error(87)
                    return 0
                emu.set_last_error(0)
                self.events.append({"event": "virtual_mapping_flush", "base": mapped_base,
                                    "backing": "pagefile", "size": count})
                return 1
        for base, (_, _, length, _) in self.mapped_guest_views.items():
            if base <= address < base + length:
                owner = self.mapped_guest_view_owners.get(base)
                if owner is None and not hasattr(emu, "get_current_process"):
                    owner = id(emu)
                    self.mapped_guest_view_owners[base] = owner
                if owner != self._guest_owner(emu):
                    emu.set_last_error(6)
                    self.events.append({"event": "virtual_mapping_view_denied", "api": api_name,
                                        "base": base, "reason": "different guest process"})
                    return 0
                if count < 0 or count > base + length - address:
                    emu.set_last_error(87)
                    return 0
                self._sync_guest_view(emu, base, "flush")
                emu.set_last_error(0)
                return 1
        if callable(original):
            return original(params)
        emu.set_last_error(87)
        return 0

    def _closed_file_operation(self, emu, api_name, original, params):
        # Speakeasy may report a core-file API-set import under its contract
        # name even when it dispatches this kernel32 hook.
        if api_name.startswith("api-ms-win-core-file-"):
            api_name = "kernel32." + api_name.rsplit(".", 1)[-1]
        handle = int(params[0])
        if not self._file_handle_allowed(emu, api_name, handle):
            if api_name in ("kernel32.ReadFile", "kernel32.WriteFile") and params[3]:
                emu.mem_write(int(params[3]), b"\0" * 4)
            return 0
        if handle not in self.closed_file_handles:
            if api_name in ("kernel32.SetFilePointer", "kernel32.SetFilePointerEx"):
                item = emu.get_file_manager().file_handles.get(handle)
                if isinstance(item, SharedGuestFileView):
                    return self._set_guest_file_pointer(emu, api_name, params, item)
            if api_name in ("kernel32.ReadFile", "kernel32.WriteFile"):
                options = self.file_open_options.get(handle)
                needed = 0x1 if api_name == "kernel32.ReadFile" else 0x2
                if options is not None and not options[1] & needed:
                    if params[3]:
                        emu.mem_write(int(params[3]), b"\0" * 4)
                    emu.set_last_error(5)  # ERROR_ACCESS_DENIED
                    self.events.append({"event": "virtual_file_access_denied", "api": api_name,
                                        "handle": handle})
                    return 0
                opened = emu.get_file_manager().file_handles.get(handle)
                if isinstance(opened, SharedGuestFileView):
                    if params[4]:
                        if params[3]:
                            emu.mem_write(int(params[3]), b"\0" * 4)
                        emu.set_last_error(50)  # ERROR_NOT_SUPPORTED
                        self.unsupported.append(
                            f"{api_name}: overlapped guest file I/O unsupported")
                        self.events.append({"event": "virtual_file_overlapped_unsupported",
                                            "api": api_name, "handle": handle})
                        return 0
                    # Committed view writes already update the guest file.
                    # Reading every view here would touch another process's
                    # private address when the file handle is inherited.
                    self.flush_pending_mapped_cpu_writes(emu)
            if api_name == "kernel32.WriteFile":
                item = emu.get_file_manager().file_handles.get(handle)
                if isinstance(item, SharedGuestFileView) and (
                    int(params[2]) > MAX_ARTIFACT or
                    (item.get_size() if item.append_only else item.tell()) +
                    int(params[2]) > MAX_ARTIFACT
                ):
                    if params[3]:
                        emu.mem_write(int(params[3]), b"\0" * 4)
                    emu.set_last_error(223)  # ERROR_FILE_TOO_LARGE
                    self.events.append({"event": "virtual_file_write_limit", "api": api_name,
                                        "handle": handle, "size": int(params[2])})
                    return 0
            console_pointer = int(params[1]) if api_name == "kernel32.WriteFile" else 0
            console_count = int(params[2]) if api_name == "kernel32.WriteFile" else 0
            console_written = int(params[3]) if api_name == "kernel32.WriteFile" else 0
            full_write = None
            opened_before = emu.get_file_manager().file_handles.get(handle)
            if (api_name == "kernel32.WriteFile" and 1024 < console_count <= MAX_ARTIFACT
                    and self.captured_large_write_bytes + console_count <= MAX_MEMORY_SCAN
                    and getattr(opened_before, "path", None)):
                try:
                    full_write = emu.mem_read(console_pointer, console_count)
                except (OSError, ValueError):
                    pass
            result = original(params)
            if api_name == "kernel32.WriteFile" and result:
                if full_write is not None:
                    actual = console_count
                    if console_written:
                        try:
                            actual = min(actual, int.from_bytes(emu.mem_read(console_written, 4),
                                                               "little"))
                        except (OSError, ValueError):
                            pass
                    if actual:
                        artifact = self.catalog.add(full_write[:actual], "file_write_full",
                                                    guest_path=str(opened_before.path))
                        if artifact is not None:
                            self.events.append({"event": "virtual_file_write_capture",
                                                "api": api_name, "path": str(opened_before.path),
                                                "size": actual, "sha256": artifact["sha256"]})
                        self.captured_large_write_bytes += actual
                if self.console_write_handler is not None:
                    self.console_write_handler(emu, handle, console_pointer,
                                               console_count, console_written)
                opened = emu.get_file_manager().file_handles.get(handle)
                if isinstance(opened, SharedGuestFileView):
                    data = opened.file.data
                    content = data.getvalue() if isinstance(data, io.BytesIO) else data or b""
                    for base, (file, offset, length, _) in tuple(self.mapped_guest_views.items()):
                        if file is opened.file:
                            view_bytes = content[offset:offset + length].ljust(length, b"\0")
                            self._mirroring_mapped_write = True
                            try:
                                with ExitStack() as allowance:
                                    if self.api_memory_allowance is not None:
                                        allowance.enter_context(self.api_memory_allowance(
                                            base, len(view_bytes), "w"))
                                    emu.mem_write(base, view_bytes)
                            finally:
                                self._mirroring_mapped_write = False
            return result
        emu.set_last_error(6)  # ERROR_INVALID_HANDLE
        self.events.append({"event": "virtual_file_closed_handle", "api": api_name,
                            "handle": handle})
        return 0xFFFFFFFF if api_name in ("kernel32.GetFileSize", "kernel32.SetFilePointer") else 0

    def _set_guest_file_pointer(self, emu, api_name, params, item: SharedGuestFileView):
        extended = api_name.endswith("Ex")
        handle = int(params[0])
        options = self.file_open_options.get(handle)
        if options is not None and not options[1] & 0x3:
            emu.set_last_error(5)  # ERROR_ACCESS_DENIED
            return 0 if extended else 0xFFFFFFFF
        if extended:
            if emu.get_ptr_size() == 4:
                low, high, output, method = (int(value) for value in params[1:5])
                distance = ((high & 0xFFFFFFFF) << 32) | (low & 0xFFFFFFFF)
            else:
                distance, output, method = (int(value) for value in params[1:4])
            distance &= 0xFFFFFFFFFFFFFFFF
            if distance & (1 << 63):
                distance -= 1 << 64
        else:
            low, high_pointer, method = (int(value) for value in params[1:4])
            low &= 0xFFFFFFFF
            if high_pointer:
                high = int.from_bytes(emu.mem_read(high_pointer, 4), "little")
                distance = (high << 32) | low
                if distance & (1 << 63):
                    distance -= 1 << 64
            else:
                distance = low if low < 1 << 31 else low - (1 << 32)
        if method not in (0, 1, 2):
            emu.set_last_error(87)  # ERROR_INVALID_PARAMETER
            return 0 if extended else 0xFFFFFFFF
        base = (0, item.tell(), item.get_size())[method]
        position = base + distance
        if position < 0:
            emu.set_last_error(131)  # ERROR_NEGATIVE_SEEK
            return 0 if extended else 0xFFFFFFFF
        if position > MAX_ARTIFACT:
            self.unsupported.append(f"{api_name}: virtual file offset exceeds limit")
            emu.set_last_error(223)  # ERROR_FILE_TOO_LARGE
            return 0 if extended else 0xFFFFFFFF
        item.position = position
        if extended:
            if output:
                emu.mem_write(output, position.to_bytes(8, "little"))
        elif high_pointer:
            emu.mem_write(high_pointer, (position >> 32).to_bytes(4, "little"))
        emu.set_last_error(0)
        self.events.append({"event": "virtual_file_seek", "api": api_name,
                            "handle": handle, "position": position})
        return 1 if extended else position & 0xFFFFFFFF

    def _set_end_of_file(self, emu, api_name, original, params):
        handle = int(params[0])
        if not self._file_handle_allowed(emu, api_name, handle):
            return 0
        item = emu.get_file_manager().file_handles.get(handle)
        if item is None:
            emu.set_last_error(6)  # ERROR_INVALID_HANDLE
            return 0
        if not isinstance(item, SharedGuestFileView):
            self.unsupported.append(f"{api_name}: non-guest file handle {handle}")
            emu.set_last_error(50)  # ERROR_NOT_SUPPORTED
            return 0
        if not self.file_open_raw_access.get(handle, 0) & 0x40000000:
            emu.set_last_error(5)  # ERROR_ACCESS_DENIED
            return 0
        previous = item.get_size()
        item.set_size(item.tell())
        emu.set_last_error(0)
        self.events.append({"event": "virtual_file_resize", "api": api_name,
                            "handle": handle, "path": item.path,
                            "old_size": previous, "new_size": item.get_size()})
        return 1

    @staticmethod
    def _effective_file_access(access: int) -> int:
        """Expand Win32 generic file rights before comparing duplicate masks."""
        rights = access & ~0xF0000000
        if access & 0x10000000:  # GENERIC_ALL -> FILE_ALL_ACCESS
            rights |= 0x1F01FF
        if access & 0x80000000:  # GENERIC_READ -> FILE_GENERIC_READ
            rights |= 0x120089
        if access & 0x40000000:  # GENERIC_WRITE -> FILE_GENERIC_WRITE
            rights |= 0x120116
        if access & 0x20000000:  # GENERIC_EXECUTE -> FILE_GENERIC_EXECUTE
            rights |= 0x1200A0
        return rights

    @staticmethod
    def _share_access(access: int) -> int:
        rights = 0
        if access & (0x80000000 | 0x10000000 | 0x1):
            rights |= 0x1  # FILE_SHARE_READ
        if access & (0x40000000 | 0x10000000 | 0x2 | 0x4):
            rights |= 0x2  # FILE_SHARE_WRITE
        if access & (0x10000000 | 0x10000):
            rights |= 0x4  # FILE_SHARE_DELETE
        return rights

    def _handles_at(self, path: str) -> list[tuple[int, int, int]]:
        key = self._key(path)
        return [(handle, access, share)
                for handle, (open_path, access, share) in self.file_open_options.items()
                if open_path == key]

    def _unlink_open_name(self, path: str) -> None:
        for handle, access, share in self._handles_at(path):
            self.file_open_options[handle] = (None, access, share)

    def _rename_open_name(self, old: str, new: str) -> None:
        for handle, access, share in self._handles_at(old):
            self.file_open_options[handle] = (self._key(new), access, share)

    def extend_enumeration(self, emulator) -> None:
        """Feed guest-created entries into Speakeasy's existing FindFirstFile walker."""
        manager = emulator.get_file_manager()
        original_walk = manager.walk_files

        def walk_files():
            yield from original_walk()
            for item in tuple(manager.files):
                yield item.path
            for directory in tuple(self.directories):
                # The walker infers a directory when it sees a descendant.
                yield directory + "\\."

        manager.walk_files = walk_files

    @staticmethod
    def _ancestors(path: str):
        path = ntpath.normpath(path)
        while path:
            yield path
            parent = ntpath.dirname(path)
            if parent == path:
                break
            path = parent

    def _known_directories(self, manager) -> set[str]:
        known = set(self.directories)
        for item in manager.files:
            known.update(self._key(parent) for parent in
                         list(self._ancestors(item.path))[1:])
        for item in getattr(getattr(manager, "file_config", None), "files", []):
            if getattr(item, "mode", None) == "full_path":
                known.update(self._key(parent) for parent in
                             list(self._ancestors(item.emu_path))[1:])
        return known

    def _directory_path(self, emu, api_name, address):
        width = 2 if api_name.endswith("W") else 1
        return self._path(emu.read_mem_string(int(address), width)) if address else ""

    def _create_directory(self, emu, api_name, original, params):
        path = self._directory_path(emu, api_name, params[0])
        event = {"event": "virtual_directory_create", "api": api_name,
                 "path": path, "success": False}
        self.events.append(event)
        if not path:
            emu.set_last_error(87)
            event["reason"] = "missing path"
            return 0
        manager = emu.get_file_manager()
        key = self._key(path)
        known = self._known_directories(manager)
        if key in known or self._exact_exists(manager, path):
            emu.set_last_error(183)  # ERROR_ALREADY_EXISTS
            event["reason"] = "path exists"
            return 0
        if self._key(ntpath.dirname(path)) not in known:
            emu.set_last_error(3)  # ERROR_PATH_NOT_FOUND
            event["reason"] = "parent absent"
            return 0
        self.directories.add(key)
        emu.set_last_error(0)
        event["success"] = True
        return 1

    def _remove_directory(self, emu, api_name, original, params):
        path = self._directory_path(emu, api_name, params[0])
        event = {"event": "virtual_directory_remove", "api": api_name,
                 "path": path, "success": False}
        self.events.append(event)
        if not path:
            emu.set_last_error(87)
            event["reason"] = "missing path"
            return 0
        manager = emu.get_file_manager()
        key = self._key(path)
        if key not in self.directories:
            if key in self._known_directories(manager):
                emu.set_last_error(50)  # ERROR_NOT_SUPPORTED
                event["reason"] = "preset directory removal unsupported"
                self.unsupported.append(f"{api_name}: preset directory removal {path}")
            else:
                emu.set_last_error(3)  # ERROR_PATH_NOT_FOUND
                event["reason"] = "directory absent"
            return 0
        if any(other.startswith(key + "\\") for other in self._known_directories(manager) if other != key):
            emu.set_last_error(145)  # ERROR_DIR_NOT_EMPTY
            event["reason"] = "directory not empty"
            return 0
        if any(self._key(item.path).startswith(key + "\\") for item in manager.files) or any(
            getattr(item, "mode", None) == "full_path" and
            self._key(item.emu_path).startswith(key + "\\")
            for item in getattr(getattr(manager, "file_config", None), "files", [])
        ):
            emu.set_last_error(145)
            event["reason"] = "directory not empty"
            return 0
        if key == self._key(self.current_dir) or key == self._key(ntpath.splitdrive(path)[0] + "\\"):
            emu.set_last_error(5)  # ERROR_ACCESS_DENIED
            event["reason"] = "current directory or volume root"
            return 0
        self.directories.remove(key)
        self.directory_attributes.pop(key, None)
        emu.set_last_error(0)
        event["success"] = True
        return 1

    def _set_file_attributes(self, emu, api_name, original, params):
        path = self._directory_path(emu, api_name, params[0])
        requested = int(params[1]) & 0xFFFFFFFF
        event = {"event": "virtual_file_set_attributes", "api": api_name,
                 "path": path, "requested": requested, "success": False}
        self.events.append(event)
        if not path:
            emu.set_last_error(87)  # ERROR_INVALID_PARAMETER
            return 0
        manager = emu.get_file_manager()
        key = self._key(path)
        if key in self._known_directories(manager):
            attributes = self._normalized_attributes(requested, directory=True)
            if attributes is None:
                self.unsupported.append(f"{api_name}: unsupported directory attributes 0x{requested:x}")
                emu.set_last_error(50)
                return 0
            self.directory_attributes[key] = attributes
        else:
            source = self._file(manager, path)
            configured = self._config(manager, path)
            if source is None and configured is None:
                if manager.does_file_exist(path):
                    self.unsupported.append(f"{api_name}: unsupported mapping {path}")
                    emu.set_last_error(50)
                else:
                    emu.set_last_error(2)  # ERROR_FILE_NOT_FOUND
                return 0
            if source is None or source.config or configured is not None:
                self.unsupported.append(f"{api_name}: configured mapping {path}")
                emu.set_last_error(50)
                return 0
            attributes = self._normalized_attributes(requested)
            if attributes is None:
                self.unsupported.append(f"{api_name}: unsupported file attributes 0x{requested:x}")
                emu.set_last_error(50)
                return 0
            source.virtual_attributes = attributes
        event.update({"success": True, "attributes": attributes})
        emu.set_last_error(0)
        return 1

    def _guest_pointer_access(self, emu, address: int, size: int, write: bool) -> bool:
        if not address or size <= 0:
            return False
        mapping = emu.get_address_map(address)
        permission = common.PERM_MEM_WRITE if write else common.PERM_MEM_READ
        guard = self.write_guard if write else self.read_guard
        return bool(mapping is not None and not mapping.free and
                    address >= int(mapping.base) and
                    address + size <= int(mapping.base) + int(mapping.size) and
                    int(mapping.prot) & permission and
                    (guard is None or guard(emu, address, size)))

    def _read_guest_path(self, emu, source: int, width: int) -> str:
        if not source:
            raise ValueError("missing path")
        raw = bytearray()
        for index in range(32767):
            pointer = source + index * width
            if not self._guest_pointer_access(emu, pointer, width, False):
                raise ValueError("unreadable path")
            unit = emu.mem_read(pointer, width)
            if unit == b"\0" * width:
                name = raw.decode("utf-16le" if width == 2 else "cp1252")
                if not name:
                    raise ValueError("empty path")
                return name
            raw.extend(unit)
        raise ValueError("unterminated path")

    @staticmethod
    def _full_guest_path(current_dir: str, name: str) -> str:
        drive, tail = ntpath.splitdrive(name)
        current_drive = ntpath.splitdrive(current_dir)[0]
        if drive and not ntpath.isabs(name) and drive.casefold() != current_drive.casefold():
            raise ValueError("current directory for another drive is unavailable")
        if not drive and tail.startswith(("\\", "/")):
            name = current_drive + tail
        elif not ntpath.isabs(name):
            name = ntpath.join(current_dir, name)
        return ntpath.normpath(name)

    def _get_full_path_name(self, emu, api_name, _original, params):
        source, capacity, output, file_part = map(int, params)
        width = 2 if api_name.endswith("W") else 1
        if capacity < 0 or capacity > 32768:
            emu.set_last_error(87)
            return 0
        try:
            name = self._read_guest_path(emu, source, width)
            current_dir = emu.get_cd() if hasattr(emu, "get_cd") else self.current_dir
            full = self._full_guest_path(current_dir, name)
            encoded = full.encode("utf-16le" if width == 2 else "cp1252")
        except (ValueError, UnicodeError, OverflowError):
            emu.set_last_error(87)
            return 0
        length = len(encoded) // width
        if length + 1 > capacity:
            return length + 1
        image = encoded + b"\0" * width
        pointer_size = emu.get_ptr_size()
        if (not self._guest_pointer_access(emu, output, len(image), True) or
                file_part and not self._guest_pointer_access(
                    emu, file_part, pointer_size, True)):
            emu.set_last_error(87)
            return 0
        final_name = ntpath.basename(full)
        part = (output + (length - len(final_name)) * width
                if file_part and final_name and not name.endswith(("\\", "/")) else 0)
        try:
            emu.mem_write(output, image)
            if file_part:
                emu.mem_write(file_part, part.to_bytes(pointer_size, "little"))
        except Exception:
            emu.set_last_error(87)
            return 0
        emu.set_last_error(0)
        return length

    def _get_long_path_name(self, emu, api_name, _original, params):
        source, output, capacity = map(int, params)
        width = 2 if api_name.endswith("W") else 1
        if capacity < 0 or capacity > 32768:
            emu.set_last_error(87)
            return 0
        try:
            name = self._read_guest_path(emu, source, width)
            current_dir = emu.get_cd() if hasattr(emu, "get_cd") else self.current_dir
            path = self._full_guest_path(current_dir, name)
            manager = emu.get_file_manager()
            if (self._key(path) not in self._known_directories(manager) and
                    not self._exact_exists(manager, path)):
                emu.set_last_error(2)
                return 0
            if "~" in name:
                self.unsupported.append(f"{api_name}: short-name expansion unavailable")
                emu.set_last_error(50)
                return 0
            encoded = name.encode("utf-16le" if width == 2 else "cp1252")
        except (ValueError, UnicodeError, OverflowError):
            emu.set_last_error(87)
            return 0
        length = len(encoded) // width
        if length + 1 > capacity:
            return length + 1
        image = encoded + b"\0" * width
        if not self._guest_pointer_access(emu, output, len(image), True):
            emu.set_last_error(87)
            return 0
        try:
            emu.mem_write(output, image)
        except Exception:
            emu.set_last_error(87)
            return 0
        emu.set_last_error(0)
        return length

    def _get_file_attributes(self, emu, api_name, original, params):
        path = self._directory_path(emu, api_name, params[0])
        manager = emu.get_file_manager()
        if path and self._key(path) in self._known_directories(manager):
            value = self.directory_attributes.get(self._key(path), 0x10)
        elif path and self._exact_exists(manager, path):
            source = self._file(manager, path)
            value = self._attributes_for(source) if source is not None else 0x80
        elif path and manager.does_file_exist(path):
            self.unsupported.append(f"{api_name}: unsupported virtual file mapping {path}")
            value = 0xFFFFFFFF
        else:
            value = 0xFFFFFFFF  # INVALID_FILE_ATTRIBUTES
        self.events.append({"event": "virtual_file_attributes", "api": api_name,
                            "path": path, "attributes": value})
        emu.set_last_error(2 if value == 0xFFFFFFFF else 0)
        return value

    def _get_file_attributes_ex(self, emu, api_name, original, params):
        path = self._directory_path(emu, api_name, params[0])
        level, output = int(params[1]), int(params[2])
        event = {"event": "virtual_file_attributes_ex", "api": api_name,
                 "path": path, "level": level, "success": False}
        self.events.append(event)
        if not path or not output or level != 0:  # GetFileExInfoStandard
            event["reason"] = "invalid path, output pointer, or info level"
            emu.set_last_error(87)  # ERROR_INVALID_PARAMETER
            return 0
        manager = emu.get_file_manager()
        if self._key(path) in self._known_directories(manager):
            attributes, size = self.directory_attributes.get(self._key(path), 0x10), 0
            timestamps = (self.filetime_ticks,) * 4
        else:
            source = self._file(manager, path)
            configured = self._config(manager, path)
            if source is None and configured is None:
                if manager.does_file_exist(path):
                    event["reason"] = "unsupported virtual file mapping"
                    self.unsupported.append(f"{api_name}: unsupported mapping {path}")
                    emu.set_last_error(50)  # ERROR_NOT_SUPPORTED
                else:
                    event["reason"] = "path absent"
                    emu.set_last_error(2)  # ERROR_FILE_NOT_FOUND
                return 0
            data = self._copy_source_data(source, configured)
            if data is None:
                event["reason"] = "file bytes unavailable in guest state"
                self.unsupported.append(f"{api_name}: file bytes unavailable {path}")
                emu.set_last_error(50)
                return 0
            attributes, size = (self._attributes_for(source) if source is not None else 0x80,
                                len(data))
            timestamps = getattr(source, "virtual_times", (self.filetime_ticks,) * 4)
        metadata = struct.pack("<IQQQII", attributes, *timestamps[:3],
                               size >> 32, size & 0xFFFFFFFF)
        emu.mem_write(output, metadata)
        event.update({"success": True, "attributes": attributes, "size": size})
        emu.set_last_error(0)
        return 1

    def _path(self, value: str) -> str:
        if not ntpath.isabs(value):
            value = ntpath.join(self.current_dir, value)
        return ntpath.normpath(value)

    @staticmethod
    def _key(path: str) -> str:
        return ntpath.normcase(ntpath.normpath(path))

    def _file(self, manager, path: str):
        return next((item for item in manager.files if self._key(item.path) == self._key(path)), None)

    def _config(self, manager, path: str):
        entries = getattr(getattr(manager, "file_config", None), "files", [])
        return next((item for item in entries if getattr(item, "mode", None) == "full_path"
                     and self._key(item.emu_path) == self._key(path)), None)

    def _exact_exists(self, manager, path: str) -> bool:
        return self._file(manager, path) is not None or self._config(manager, path) is not None

    def save_network_download(self, emu, path: str, payload: bytes, url: str) -> str:
        """Commit broker bytes to guest storage, never to a configured host file."""
        path = self._path(path)
        if not path or len(path) > 32767 or not isinstance(payload, bytes) or len(payload) > MAX_ARTIFACT:
            raise ValueError("invalid or oversized guest download")
        manager = emu.get_file_manager()
        target = self._file(manager, path)
        if self._config(manager, path) is not None or (target is not None and target.config):
            raise ValueError("download destination is a host-backed guest mapping")
        if target is not None and self._attributes_for(target) & 0x1:
            raise ValueError("download destination is read-only in guest state")
        if any(not share & 0x2 for _, _, share in self._handles_at(path)):
            raise ValueError("download destination sharing violation")
        old_size = 0
        if target is not None:
            old = target.data
            old_size = len(old.getbuffer()) if isinstance(old, io.BytesIO) else len(old or b"")
        total = sum((len(item.data.getbuffer()) if isinstance(item.data, io.BytesIO)
                     else len(item.data or b"")) for item in manager.files if not item.config)
        if total - old_size + len(payload) > 64 * 1024 * 1024:
            raise ValueError("guest download file-store budget exceeded")
        if target is None:
            manager.files.append(GuestFile(manager.emu.handle_allocator, path, data=payload))
        else:
            target.data = io.BytesIO(payload)
            target.bytes_written += len(payload)
        artifact = self.catalog.add(payload, "urlmon_download_file", guest_path=path,
                                    kind="network")
        event = {"event": "virtual_network_download", "path": path,
                 "url": url, "size": len(payload)}
        if artifact:
            event["artifact_sha256"] = artifact["sha256"]
        self.events.append(event)
        return path

    def _copy_source_data(self, source, configured) -> bytes | None:
        if source is not None and not source.config:
            data = source.data
            if isinstance(data, io.BytesIO):
                return data.getvalue() if len(data.getbuffer()) <= MAX_ARTIFACT else None
            if isinstance(data, bytes):
                return data if len(data) <= MAX_ARTIFACT else None
            return b""
        if configured is None:
            return None
        backing = getattr(configured, "path", None)
        if not isinstance(backing, str):
            return None
        preset = self.persona_sources.get(backing.lower())
        if preset is None or len(preset) > MAX_ARTIFACT:
            return None
        if source is not None and isinstance(source.data, io.BytesIO):
            return source.data.getvalue() if len(source.data.getbuffer()) <= MAX_ARTIFACT else None
        return preset

    def _copy_file(self, emu, api_name, original, params):
        width = 2 if api_name.endswith("W") else 1
        old = self._path(emu.read_mem_string(int(params[0]), width)) if params[0] else ""
        new = self._path(emu.read_mem_string(int(params[1]), width)) if params[1] else ""
        fail_if_exists = bool(int(params[2]))
        event = {"event": "virtual_file_copy", "api": api_name, "source_path": old,
                 "destination_path": new, "fail_if_exists": fail_if_exists, "success": False}
        self.events.append(event)
        if not old or not new:
            event["reason"] = "missing path"
            emu.set_last_error(87)  # ERROR_INVALID_PARAMETER
            return 0
        if len(old) > 32767 or len(new) > 32767:
            event["reason"] = "path exceeds virtual limit"
            self.unsupported.append(f"{api_name}: path exceeds virtual limit")
            emu.set_last_error(50)  # ERROR_NOT_SUPPORTED
            return 0
        if self._key(old) == self._key(new):
            event["reason"] = "source equals destination"
            emu.set_last_error(32)  # ERROR_SHARING_VIOLATION
            return 0
        manager = emu.get_file_manager()
        source = self._file(manager, old)
        source_config = self._config(manager, old)
        if source is None and source_config is None:
            if manager.does_file_exist(old):
                event["reason"] = "unsupported source mapping"
                self.unsupported.append(f"{api_name}: unsupported source mapping {old}")
                emu.set_last_error(50)
            else:
                event["reason"] = "source absent"
                emu.set_last_error(2)  # ERROR_FILE_NOT_FOUND
            return 0
        if source is not None and source.config and source_config is None:
            event["reason"] = "unsupported source mapping"
            self.unsupported.append(f"{api_name}: unsupported source mapping {old}")
            emu.set_last_error(50)
            return 0
        if any(not share & 0x1 for _, _, share in self._handles_at(old)):
            event["reason"] = "source sharing violation"
            emu.set_last_error(32)  # ERROR_SHARING_VIOLATION
            return 0
        target = self._file(manager, new)
        target_config = self._config(manager, new)
        if target is not None and self._attributes_for(target) & 0x1:
            event["reason"] = "read-only destination"
            emu.set_last_error(5)  # ERROR_ACCESS_DENIED
            return 0
        if target is not None and target.config and target_config is None:
            event["reason"] = "unsupported destination mapping"
            self.unsupported.append(f"{api_name}: unsupported destination mapping {new}")
            emu.set_last_error(50)
            return 0
        if fail_if_exists and (target is not None or target_config is not None):
            event["reason"] = "destination exists"
            emu.set_last_error(80)  # ERROR_FILE_EXISTS
            return 0
        target_handles = self._handles_at(new)
        if any(not share & 0x2 for _, _, share in target_handles):
            event["reason"] = "destination sharing violation"
            emu.set_last_error(32)  # ERROR_SHARING_VIOLATION
            return 0
        if target_handles and (target is None or target.config):
            event["reason"] = "open configured destination cannot share guest bytes"
            self.unsupported.append(f"{api_name}: open configured destination {new}")
            emu.set_last_error(50)  # ERROR_NOT_SUPPORTED
            return 0
        data = self._copy_source_data(source, source_config)
        if data is None:
            event["reason"] = "source bytes unavailable in guest persona or exceed limit"
            self.unsupported.append(f"{api_name}: source bytes unavailable {old}")
            emu.set_last_error(50)
            return 0
        if target_handles:
            # Keep the existing file object, cursor positions, and live views.
            target.data = io.BytesIO(data)
            target.bytes_written += len(data)
            target.virtual_attributes = (self._attributes_for(source)
                                         if source is not None else 0x80)
            target.virtual_times = (getattr(source, "virtual_times", (self.filetime_ticks,) * 4)
                                    if source is not None else (self.filetime_ticks,) * 4)
        else:
            if target is not None:
                manager.files.remove(target)
            allocator = source.allocator if source is not None else manager.emu.handle_allocator
            copied = GuestFile(allocator, new, data=data)
            copied.virtual_attributes = (self._attributes_for(source)
                                         if source is not None else 0x80)
            copied.virtual_times = (getattr(source, "virtual_times", (self.filetime_ticks,) * 4)
                                    if source is not None else (self.filetime_ticks,) * 4)
            manager.files.append(copied)
        if target_config is not None:
            manager.file_config.files.remove(target_config)
        artifact = self.catalog.add(data, "virtual_file_copy", guest_path=new)
        event.update({"success": True, "size": len(data),
                      "source_exists_after": self._exact_exists(manager, old),
                      "destination_exists_after": self._exact_exists(manager, new)})
        if artifact:
            event["artifact_sha256"] = artifact["sha256"]
        emu.set_last_error(0)
        return 1

    def _delete_file(self, emu, api_name, original, params):
        width = 2 if api_name.endswith("W") else 1
        path = self._path(emu.read_mem_string(int(params[0]), width)) if params[0] else ""
        event = {"event": "virtual_file_delete", "api": api_name,
                 "path": path, "success": False}
        self.events.append(event)
        if not path:
            event["reason"] = "missing path"
            emu.set_last_error(87)  # ERROR_INVALID_PARAMETER
            return 0
        manager = emu.get_file_manager()
        source = self._file(manager, path)
        configured = self._config(manager, path)
        if source is None and configured is None:
            if manager.does_file_exist(path):
                event["reason"] = "unsupported virtual file mapping"
                self.unsupported.append(f"{api_name}: unsupported mapping {path}")
                emu.set_last_error(50)  # ERROR_NOT_SUPPORTED
            else:
                event["reason"] = "file absent"
                emu.set_last_error(2)  # ERROR_FILE_NOT_FOUND
            return 0
        if source is not None and source.config and configured is None:
            event["reason"] = "unsupported virtual file mapping"
            self.unsupported.append(f"{api_name}: unsupported mapping {path}")
            emu.set_last_error(50)
            return 0
        if source is not None and self._attributes_for(source) & 0x1:
            event["reason"] = "read-only file"
            emu.set_last_error(5)  # ERROR_ACCESS_DENIED
            return 0
        open_handles = self._handles_at(path)
        if any(not share & 0x4 for _, _, share in open_handles):
            event["reason"] = "sharing violation"
            emu.set_last_error(32)  # ERROR_SHARING_VIOLATION
            return 0
        if source is not None and not source.config and source.bytes_written:
            data = self._copy_source_data(source, None)
            if data:
                artifact = self.catalog.add(data, "virtual_file_delete", guest_path=path)
                if artifact:
                    event["artifact_sha256"] = artifact["sha256"]
        if source is not None:
            manager.files.remove(source)
        if configured is not None:
            manager.file_config.files.remove(configured)
        self._unlink_open_name(path)
        event["success"] = True
        event["exists_after"] = self._exact_exists(manager, path)
        emu.set_last_error(0)
        return 1

    def _move_file_ex(self, emu, api_name, original, params):
        width = 2 if api_name.endswith("W") else 1
        old = self._path(emu.read_mem_string(int(params[0]), width)) if params[0] else ""
        new = self._path(emu.read_mem_string(int(params[1]), width)) if params[1] else ""
        flags = int(params[2])
        event = {"event": "virtual_file_move", "api": api_name,
                 "old_path": old, "new_path": new, "flags": flags, "success": False}
        self.events.append(event)
        if not old or not new:
            event["reason"] = "missing path"
            emu.set_last_error(87)  # ERROR_INVALID_PARAMETER
            return 0
        if flags & ~(0x1 | 0x8):
            event["reason"] = "unsupported MoveFileEx flags"
            self.unsupported.append(f"{api_name}: unsupported flags 0x{flags:x}")
            emu.set_last_error(50)  # ERROR_NOT_SUPPORTED
            return 0
        if ntpath.splitdrive(old)[0].lower() != ntpath.splitdrive(new)[0].lower():
            event["reason"] = "different virtual volumes"
            emu.set_last_error(17)  # ERROR_NOT_SAME_DEVICE
            return 0
        manager = emu.get_file_manager()
        source = self._file(manager, old)
        source_config = self._config(manager, old)
        if source is None and source_config is None:
            event["reason"] = "source absent"
            emu.set_last_error(2)  # ERROR_FILE_NOT_FOUND
            return 0
        if source is not None and source.config and source_config is None:
            event["reason"] = "source uses an unsupported virtual file mapping"
            self.unsupported.append(f"{api_name}: unsupported source mapping {old}")
            emu.set_last_error(50)
            return 0
        if any(not share & 0x4 for _, _, share in self._handles_at(old)):
            event["reason"] = "sharing violation"
            emu.set_last_error(32)  # ERROR_SHARING_VIOLATION
            return 0
        target = self._file(manager, new)
        target_config = self._config(manager, new)
        if self._key(old) != self._key(new) and (target is not None or target_config is not None):
            if not flags & 0x1:
                event["reason"] = "destination exists"
                emu.set_last_error(183)  # ERROR_ALREADY_EXISTS
                return 0
            if self._handles_at(new):
                event["reason"] = "destination open"
                emu.set_last_error(5)  # ERROR_ACCESS_DENIED
                return 0
            if target is not None and target is not source:
                manager.files.remove(target)
            if target_config is not None and target_config is not source_config:
                manager.file_config.files.remove(target_config)
        if self._key(old) != self._key(new):
            self._rename_open_name(old, new)
            if source_config is not None:
                if source is None or source.config:
                    replacement = source_config.model_copy(update={"emu_path": new})
                    entries = manager.file_config.files
                    entries[entries.index(source_config)] = replacement
                    if source is not None:
                        source.config = replacement
                else:
                    # A guest-created replacement takes precedence over its old preset mapping.
                    manager.file_config.files.remove(source_config)
            if source is not None:
                source.path = new
                if not source.config:
                    moved = source.get_data(reset_pointer=True)
                    artifact = self.catalog.add(moved, "virtual_file_move", guest_path=new)
                    if artifact:
                        event["artifact_sha256"] = artifact["sha256"]
        event["success"] = True
        event["old_exists_after"] = self._exact_exists(manager, old)
        event["new_exists_after"] = self._exact_exists(manager, new)
        emu.set_last_error(0)
        return 1

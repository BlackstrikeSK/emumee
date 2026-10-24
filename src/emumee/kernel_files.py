"""Bounded synchronous kernel file handles backed solely by guest bytes.

IoCreateFileEx contract: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-iocreatefileex
Device stacks, EAs, asynchronous requests and reparse points are not modeled.
"""

import io
import ntpath

from speakeasy.profiler_events import FILE_OPEN, FILE_READ, FILE_WRITE
from speakeasy.windows.fileman import File as GuestFile

from .artifacts import MAX_ARTIFACT
from .virtualfs import SharedGuestFileView


class KernelFiles:
    def __init__(self, kernel):
        self.kernel = kernel
        self.handles = {}
        self.closed = set()
        self.directories = {"c:\\", r"c:\windows", r"c:\windows\system32",
                            r"c:\windows\system32\drivers"}

    def configure(self, persona):
        from .persona_content import desktop_directories
        paths = desktop_directories(persona["user_name"]) + [persona["current_dir"]]
        paths += [ntpath.dirname(item.emu_path) for item in self.kernel.config.filesystem.files
                  if item.mode == "full_path" and not any(char in item.emu_path for char in "*?")]
        for path in paths:
            while path:
                self.directories.add(path.casefold())
                parent = ntpath.dirname(path)
                if parent == path:
                    break
                path = parent

    def unsupported(self, message):
        self.kernel.lifecycle_errors.append("Kernel file model: " + message)
        return 0xC00000BB

    def status(self, address, result, information=0):
        from .kernel_api import require_range
        width = self.kernel.get_ptr_size()
        require_range(self.kernel, address, width * 2, True)
        self.kernel.mem_write(address, result.to_bytes(width, "little") + information.to_bytes(width, "little"))
        return result

    def create(self, handler, emu, argv, ctx=None):
        from .kernel_api import require_range
        (output, access, attributes, ios, allocation, file_attributes, share,
         disposition, options, ea, ea_length, kind, internal, io_options, context) = map(int, argv)
        access, file_attributes, share, disposition, options, ea_length, kind, io_options = (
            value & 0xFFFFFFFF for value in (access, file_attributes, share, disposition,
                                            options, ea_length, kind, io_options))
        width = emu.get_ptr_size()
        require_range(emu, output, width, True)
        require_range(emu, ios, width * 2, True)
        require_range(emu, attributes, 48 if width == 8 else 24)
        oa = handler.mem_cast(handler.win.OBJECT_ATTRIBUTES(width), attributes)
        require_range(emu, oa.ObjectName, 16 if width == 8 else 8)
        us = handler.mem_cast(handler.win.UNICODE_STRING(width), oa.ObjectName)
        if us.Length % 2 or us.Length > us.MaximumLength or us.Length > 32766:
            return self.status(ios, 0xC000000D)
        require_range(emu, us.Buffer, us.Length)
        name = emu.mem_read(us.Buffer, us.Length).decode("utf-16le")
        if "\0" in name:
            return self.status(ios, 0xC0000033)
        if name.startswith("\\??\\"):
            name = name[4:]
        if name.lower().startswith("\\systemroot\\"):
            name = "C:\\Windows\\" + name[12:]
        if oa.RootDirectory:
            parent = self.handles.get(int(oa.RootDirectory))
            if parent is None or not parent[0].file.is_dir:
                return self.status(ios, 0xC0000008)
            if ntpath.isabs(name):
                return self.status(ios, 0xC000003B)
            name = ntpath.join(parent[0].path, name)
        if not ntpath.isabs(name) or not ntpath.splitdrive(name)[0]:
            return self.status(ios, 0xC000003B)
        path = ntpath.normpath(name)
        key = path.casefold()
        argv[2] = path
        if (ea or ea_length or kind or internal or context or io_options & ~8
                or options & ~0x73 or file_attributes & ~0xB7):
            return self.status(ios, self.unsupported("unsupported create flags, EAs or device context"))
        if options & 0x30 == 0x30 or options & 0x41 == 0x41 or share & ~7 or disposition > 5:
            return self.status(ios, 0xC000000D)
        directory = bool(options & 1)
        if directory and disposition not in (1, 2, 3):
            return self.status(ios, 0xC000000D)
        if not directory and not options & 0x30:
            return self.status(ios, self.unsupported("asynchronous file creation"))
        if allocation:
            require_range(emu, allocation, 8)
            if not 0 <= int.from_bytes(emu.mem_read(allocation, 8), "little", signed=True) <= MAX_ARTIFACT:
                return self.status(ios, 0xC000000D)
        manager = emu.get_file_manager()
        canonical = next((item for item in manager.files if item.path.casefold() == key), None)
        configured = manager.get_emu_file(path) if canonical is None else None
        if configured is not None and (getattr(configured, "mode", None) != "full_path"
                or configured.emu_path.casefold() != key):
            return self.status(ios, self.unsupported("non-exact configured file mapping"))
        exists = canonical is not None or configured is not None or key in self.directories
        is_directory = key in self.directories or canonical is not None and canonical.is_dir
        if exists and directory and not is_directory:
            return self.status(ios, 0xC0000103)
        if exists and not directory and options & 0x40 and is_directory:
            return self.status(ios, 0xC00000BA)
        if exists and disposition == 2:
            return self.status(ios, 0xC0000035, 4)
        if not exists and disposition in (1, 4):
            return self.status(ios, 0xC0000034, 5)
        if not exists and ntpath.dirname(path).casefold() not in self.directories:
            return self.status(ios, 0xC000003A, 5)
        granted = ((1 if access & (0x80000000 | 0x10000000 | 1) else 0)
                   | (2 if access & (0x40000000 | 0x10000000 | 6) else 0)
                   | (4 if access & (0x10000000 | 0x10000) else 0))
        for view, previous, allowed in self.handles.values():
            if view.path.casefold() == key and (granted & ~allowed or previous & ~share):
                return self.status(ios, 0xC0000043)
        if canonical is not None and getattr(canonical, "kernel_attributes", 0) & 1 and granted & 2:
            return self.status(ios, 0xC0000022)
        if canonical is not None and canonical.config and (disposition in (0, 4, 5) or granted & 2):
            return self.status(ios, self.unsupported("mutating a configured file mapping"))
        if canonical is None and configured is not None:
            # Materialize only explicitly configured input bytes, never guest
            # path names as host paths. Keep the canonical source read-only.
            if disposition in (0, 4, 5) or granted & 2:
                return self.status(ios, self.unsupported("mutating a configured file mapping"))
            canonical = GuestFile(emu.handle_allocator, path, config=configured)
            manager.files.append(canonical)
            handle = canonical.get_handle()
            canonical.get_size()  # Materialize configured bytes before sharing a view.
        else:
            if canonical is None:
                # FileManager's stock lookup treats any name containing the
                # sample basename as the primary file. Use exact guest names.
                canonical = GuestFile(emu.handle_allocator, path)
                manager.files.append(canonical)
                canonical.is_dir = directory or is_directory
                canonical.kernel_attributes = file_attributes
            if exists and disposition in (0, 4, 5):
                if is_directory:
                    return self.status(ios, 0xC00000BA)
                if not granted & (4 if disposition == 0 else 2):
                    return self.status(ios, 0xC0000022)
                canonical.data = io.BytesIO()
            handle = canonical.get_handle()
        append_only = bool(access & 4) and not bool(access & (0x40000000 | 0x10000000 | 2))
        view = SharedGuestFileView(canonical, append_only=append_only)
        manager.file_handles[handle] = view
        self.handles[handle] = view, granted, share
        if canonical.is_dir:
            self.directories.add(key)
        self.closed.discard(handle)
        emu.mem_write(output, handle.to_bytes(width, "little"))
        handler.record_file_access_event(path, FILE_OPEN)
        information = 2 if not exists else 0 if disposition == 0 else 3 if disposition in (4, 5) else 1
        return self.status(ios, 0, information)

    def transfer(self, handler, emu, argv, original, *, write):
        from .kernel_api import require_range
        handle, event, apc, apc_context, ios, buffer, length, offset, key = map(int, argv)
        if handle not in self.handles:
            if handle in self.closed:
                return self.status(ios, 0xC0000008)
            return original(handler, emu, argv)
        view, granted, _share = self.handles[handle]
        require_range(emu, ios, emu.get_ptr_size() * 2, True)
        length &= 0xFFFFFFFF
        if event or apc or apc_context or key:
            return self.status(ios, self.unsupported("asynchronous or keyed file I/O"))
        if view.file.is_dir:
            return self.status(ios, 0xC00000BA)
        if not granted & (2 if write else 1):
            return self.status(ios, 0xC0000022)
        if length > MAX_ARTIFACT:
            return self.status(ios, self.unsupported("file I/O size limit exceeded"))
        if length:
            require_range(emu, buffer, length, not write)
        if offset:
            require_range(emu, offset, 8)
            position = int.from_bytes(emu.mem_read(offset, 8), "little", signed=True)
            if position == -1 and write:
                position = view.get_size()
            elif position == -2:
                position = view.tell()
            if not 0 <= position <= MAX_ARTIFACT:
                return self.status(ios, 0xC000000D)
            view.seek(position, io.SEEK_SET)
        if write:
            if view.tell() + length > MAX_ARTIFACT:
                return self.status(ios, self.unsupported("file size limit exceeded"))
            data = emu.mem_read(buffer, length) if length else b""
            view.add_data(data)
            handler.record_file_access_event(view.path, FILE_WRITE, data=data, size=length)
        else:
            data = view.get_data(length)
            if data:
                emu.mem_write(buffer, data)
            handler.record_file_access_event(view.path, FILE_READ, buffer=buffer, size=len(data))
        return self.status(ios, 0 if write or data or not length else 0xC0000011, len(data))

    def install(self, handler):
        from speakeasy.winenv import arch
        def bind(name, function, count):
            handler.funcs[name] = name, function, count, arch.CALL_CONV_STDCALL, None
        bind("IoCreateFileEx", self.create, 15)
        for name, write in (("ZwWriteFile", True), ("ZwReadFile", False)):
            original = handler.funcs[name][1]
            def transfer(api, emu, argv, ctx=None, original=original, write=write):
                return self.transfer(api, emu, argv, original, write=write)
            bind(name, transfer, 9)
        original_close = handler.funcs["ZwClose"][1]
        def close(api, emu, argv, ctx=None):
            handle = int(argv[0])
            if handle in self.handles:
                del self.handles[handle]
                emu.get_file_manager().file_handles.pop(handle, None)
                self.closed.add(handle)
                return 0
            return 0xC0000008 if handle in self.closed else original_close(api, emu, argv)
        def flush(api, emu, argv, ctx=None):
            handle, ios = map(int, argv)
            return self.status(ios, 0 if handle in self.handles else 0xC0000008)
        bind("ZwClose", close, 1)
        bind("ZwFlushBuffersFile", flush, 2)

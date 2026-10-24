"""Loaded-module queries backed solely by the modeled kernel address space."""

import ntpath
import struct

from .kernel_api import require_range
from .kernel_provider_reads import KernelProviderReads


class KernelSystemInformation:
    def __init__(self, kernel):
        self.kernel = kernel
        self.queries = []
        self.omitted = 0
        self.native_reads = KernelProviderReads(kernel, stack_limit=1024, all_register_pointers=True,
            scope='Native reads of successfully returned module-list buffers; bounded registers, readable pointer prefixes and stack snapshots; labels identify initial buffer registration, not resolved modules')

    @staticmethod
    def header_metadata(module, width):
        # Loader bytes retain the preferred base even when guest mappings move.
        # Read only a bounded header prefix; never discover host module files.
        data = next((region.data[:4096] for region in module._image.regions
                     if region.base == module.base), b"")
        metadata = module.get_pe_metadata()
        timestamp = metadata.timestamp if metadata else 0
        checksum, preferred = 0, module.base
        if len(data) >= 64 and data[:2] == b"MZ":
            pe = int.from_bytes(data[60:64], "little")
            optional = pe + 24
            if pe >= 64 and optional + 68 <= len(data) and data[pe:pe + 4] == b"PE\0\0":
                magic = int.from_bytes(data[optional:optional + 2], "little")
                if magic == (0x20B if width == 8 else 0x10B):
                    start = optional + (24 if width == 8 else 28)
                    preferred = int.from_bytes(data[start:start + width], "little")
                    checksum = int.from_bytes(data[optional + 64:optional + 68], "little")
                    timestamp = int.from_bytes(data[pe + 8:pe + 12], "little")
        return checksum, timestamp, preferred

    def module_buffer(self, extended):
        emu = self.kernel
        width = emu.get_ptr_size()
        modules = emu.get_peb_modules()
        if len(modules) > 1024:
            raise ValueError("Kernel module query exceeds its 1024-module model limit")
        # The kernel and HAL head the modeled kernel load order. The remaining
        # entries preserve the loader's order, including the target driver.
        modules = sorted(modules, key=lambda item: {"ntoskrnl": 0, "hal": 1}.get(item.name, 2))
        base_size = 296 if width == 8 else 284
        stride = 320 if width == 8 else 300
        rows = []
        for index, module in enumerate(modules):
            path = ntpath.normpath(module.emu_path or module.name).encode("cp1252", errors="replace")
            if not path or len(path) > 255 or b"\0" in path:
                raise ValueError("Modeled kernel module path does not fit FullPathName")
            base = bytearray(base_size)
            base[2 * width:3 * width] = int(module.base).to_bytes(width, "little")
            struct.pack_into("<II4H", base, 3 * width, module.image_size, 0,
                             index, index, 1, path.rfind(b"\\") + 1)
            base[3 * width + 16:3 * width + 16 + len(path)] = path
            if extended:
                row = bytearray(stride)
                struct.pack_into("<H", row, 0, stride)
                row[width:width + base_size] = base
                checksum, timestamp, preferred = self.header_metadata(module, width)
                struct.pack_into("<II", row, width + base_size, checksum, timestamp)
                row[-width:] = preferred.to_bytes(width, "little")
                rows.append(row)
            else:
                rows.append(base)
        # Class 77 ends with a standalone zero USHORT, not a last module whose
        # NextOffset is zero. Class 11 starts with a ULONG plus native padding.
        prefix = b"" if extended else struct.pack("<I", len(rows)) + bytes(width - 4)
        return prefix + b"".join(rows) + (bytes(2) if extended else b""), len(rows)

    def query(self, handler, emu, argv, ctx=None):
        information_class, output, capacity, returned = map(int, argv)
        information_class &= 0xFFFFFFFF
        capacity &= 0xFFFFFFFF
        if information_class not in (11, 77):
            return self.original[1](handler, emu, argv, ctx)
        data, count = self.module_buffer(information_class == 77)
        if returned:
            require_range(emu, returned, 4, True)
        status = 0xC0000004
        if capacity >= len(data):
            require_range(emu, output, len(data), True)
            emu.mem_write(output, data)
            status = 0
            self.native_reads.watch_region(f'class{information_class}_query{len(self.queries)}', output, len(data))
        if returned:
            emu.mem_write(returned, struct.pack("<I", len(data)))
        event = {"class": information_class, "capacity": capacity,
                 "required_length": len(data), "modules": count, "status": hex(status)}
        if len(self.queries) < 128:
            self.queries.append(event)
        else:
            self.omitted += 1
        return status

    def install(self, handler):
        self.original = handler.funcs["ZwQuerySystemInformation"]
        for name in ("ZwQuerySystemInformation", "NtQuerySystemInformation"):
            handler.funcs[name] = (name, self.query, *self.original[2:])

    def report(self):
        return {"queries": self.queries, "omitted": self.omitted,
                "native_buffer_reads": self.native_reads.report(),
                "scope": "Classes 11 and 77 enumerate modeled loaded kernel modules; "
                         "no host kernel enumeration; other classes use existing API models"}

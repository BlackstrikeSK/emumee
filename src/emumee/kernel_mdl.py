"""Nonpaged MDL descriptors and coherent user aliases of modeled NX pool buffers."""

import ctypes
import struct
from speakeasy import common
from speakeasy.winenv import arch
from .kernel_api import require_range


class KernelMdls:
    """Nonpaged buffer descriptors; physical frame IDs belong only to the guest."""

    def __init__(self, kernel):
        self.kernel = kernel
        self.records = {}
        self.frames = {}
        self.backing = {}
        self.aliases = {}
        self.alias_sources = {}
        self.next_alias = 0x40000000
        self.readonly_alias_ranges = {}

    def require_api_write(self, address, size):
        if not size:
            return
        for start, stop in self.readonly_alias_ranges.values():
            if address < stop and address + size > start:
                raise ValueError("Kernel API write to a read-only MDL alias")

    def allocate(self, api, emu, argv, ctx=None):
        address, length, secondary, quota, irp = map(int, argv)
        length &= 0xFFFFFFFF
        if irp or quota & 0xFF:
            raise ValueError("IRP-linked/quota MDL allocation is not modeled")
        if not length or address + length > 1 << (emu.get_ptr_size() * 8):
            return 0
        width = emu.get_ptr_size()
        header = 48 if width == 8 else 28
        pages = ((address & 4095) + length + 4095) // 4096
        size = header + pages * width
        if size > 0x7FFF or len(self.records) >= 4096:
            raise ValueError("MDL descriptor exceeds the modeled size/count limit")
        pointer = emu.pool_alloc(0x200, size, "MdlN")
        if not pointer:
            return 0
        blob = bytearray(size)
        struct.pack_into("<HH", blob, width, size, 0)
        start_offset = 32 if width == 8 else 16
        blob[start_offset:start_offset + width] = (address & ~4095).to_bytes(width, "little")
        struct.pack_into("<II", blob, start_offset + width, length, address & 4095)
        emu.mem_write(pointer, bytes(blob))
        self.records[pointer] = {"buffer": address, "length": length, "pages": pages,
                                 "size": size, "built": False}
        return pointer

    def descriptor(self, emu, pointer):
        item = self.records.get(pointer)
        if item is None:
            raise ValueError("Unsupported or freed MDL descriptor")
        require_range(emu, pointer, item["size"])
        return item

    def frame(self, address):
        page = address & ~4095
        page = self.alias_sources.get(page, page)
        if page not in self.frames:
            if len(self.frames) >= 32768:
                raise ValueError("Guest physical page identity limit exceeded")
            self.frames[page] = 256 + len(self.frames)
        return self.frames[page]

    def build(self, api, emu, argv, ctx=None):
        pointer = int(argv[0])
        item = self.descriptor(emu, pointer)
        require_range(emu, item["buffer"], item["length"])
        require_range(emu, pointer, item["size"], True)
        width = emu.get_ptr_size()
        start_offset = 32 if width == 8 else 16
        shape = emu.mem_read(pointer, 48 if width == 8 else 28)
        described_start = int.from_bytes(shape[start_offset:start_offset + width], "little")
        length, offset = struct.unpack_from("<II", shape, start_offset + width)
        if (int.from_bytes(shape[width:width + 2], "little") != item["size"] or
                described_start != item["buffer"] & ~4095 or offset != item["buffer"] & 4095 or
                length != item["length"]):
            raise ValueError("Modified MDL geometry is not modeled")
        flags = int.from_bytes(emu.mem_read(pointer + width + 2, 2), "little")
        emu.mem_write(pointer + width + 2, (flags | 4).to_bytes(2, "little"))
        mapped_offset, header = (24, 48) if width == 8 else (12, 28)
        emu.mem_write(pointer + mapped_offset, item["buffer"].to_bytes(width, "little"))
        start = item["buffer"] & ~4095
        frames = [self.frame(start + index * 4096) for index in range(item["pages"])]
        emu.mem_write(pointer + header, b"".join(frame.to_bytes(width, "little") for frame in frames))
        item["built"] = True

    def free(self, api, emu, argv, ctx=None):
        pointer = int(argv[0])
        self.descriptor(emu, pointer)
        if any(mapping["mdl"] == pointer for mapping in self.aliases.values()):
            raise ValueError("Freeing an MDL with active mappings")
        emu.mem_free(pointer)
        del self.records[pointer]

    def physical_address(self, api, emu, argv, ctx=None):
        address = int(argv[0])
        require_range(emu, address, 1)
        value = self.frame(address) * 4096 + (address & 4095)
        if emu.get_ptr_size() == 4:
            emu.reg_write(arch.X86_REG_EDX, value >> 32)
            return value & 0xFFFFFFFF
        return value

    def map(self, api, emu, argv, ctx=None):
        pointer, mode, cache, requested, bugcheck, priority = map(int, argv)
        item = self.descriptor(emu, pointer)
        if not item["built"]:
            raise ValueError("Mapping an MDL whose pages have not been built/locked")
        if mode & 0xFF != 1 or cache & 0xFFFFFFFF != 1 or requested or bugcheck & 0xFF:
            raise ValueError("Only automatically placed cached user MDL mappings are modeled")
        if emu.get_current_irql() > 1:
            raise ValueError("User MDL mapping above APC_LEVEL")
        priority &= 0xFFFFFFFF
        if priority & ~0xC0000030 or priority & 0x30 == 0x30:
            raise ValueError("Unsupported MDL mapping priority")
        if len(self.aliases) >= 4096:
            raise ValueError("MDL mapping limit exceeded")
        address, length = item["buffer"], item["length"]
        allocation = next((entry for entry in emu.pool_allocs if
            entry[0] <= address and address + length <= entry[0] + entry[2] and
            (entry[1] & ~0x500) in (0x200, 0x204)), None)
        source_map = emu.get_address_map(address)
        if allocation is None or source_map is None or source_map.free:
            raise ValueError("MDL aliases currently require an active modeled NX pool allocation")
        start, size = address & ~4095, item["pages"] * 4096
        require_range(emu, start, size)
        native = emu.emu_eng.emu
        for page in range(start, start + size, 4096):
            permissions = next(permissions for lo, hi, permissions in native.mem_regions()
                               if lo <= page and page + 4095 <= hi)
            if permissions != 3:
                raise ValueError("MDL source pages must be readable/writable and NX")
            if page not in self.backing:
                # The host pointer is obtained only from this owned allocation;
                # guest pointer values are never used as host memory addresses.
                buffer = ctypes.create_string_buffer(bytes(native.mem_read(page, 4096)), 4096)
                self.backing[page] = buffer
                native.mem_unmap(page, 4096)
                native.mem_map_ptr(page, 4096, permissions, ctypes.addressof(buffer))
        readonly = bool(priority & 0x80000000)
        protection = common.PERM_MEM_READ if readonly else common.PERM_MEM_RW
        base = emu.mem_map(size, base=self.next_alias, perms=protection, tag="api.mdl.user_alias",
                           process=emu.get_current_process())
        self.next_alias = base + ((size + 65535) & ~65535)
        native.mem_unmap(base, size)
        for offset in range(0, size, 4096):
            native.mem_map_ptr(base + offset, 4096, 1 if readonly else 3,
                               ctypes.addressof(self.backing[start + offset]))
            self.alias_sources[base + offset] = start + offset
        returned = base + (address & 4095)
        self.aliases[returned] = {"base": base, "size": size, "mdl": pointer,
                                 "owner": emu.get_current_process(), "readonly": readonly}
        if readonly:
            self.readonly_alias_ranges[returned] = (base, base + size)
        return returned

    def unmap(self, api, emu, argv, ctx=None):
        address, pointer = map(int, argv)
        self.descriptor(emu, pointer)
        mapping = self.aliases.get(address)
        if mapping is None or mapping["mdl"] != pointer:
            raise ValueError("Invalid MDL mapping address or descriptor")
        if mapping["owner"] is not emu.get_current_process() or emu.get_current_irql() > 1:
            raise ValueError("User MDL unmap requires the original process at APC_LEVEL or below")
        memory_map = emu.get_address_map(mapping["base"])
        emu.mem_free(mapping["base"])
        if emu.config.keep_memory_on_free:
            # Trace retention must not leave the unmapped alias accessible.
            emu.mem_unmap(mapping["base"], mapping["size"])
        if memory_map in emu.maps:
            # The engine's final string scan reads every retained map, including
            # freed maps. Do not leave metadata for an inaccessible alias there.
            emu.maps.remove(memory_map)
        for page in range(mapping["base"], mapping["base"] + mapping["size"], 4096):
            self.alias_sources.pop(page, None)
        del self.aliases[address]
        self.readonly_alias_ranges.pop(address, None)

    def report(self):
        return {"descriptors": len(self.records), "guest_page_identities": len(self.frames),
                "user_aliases": len(self.aliases),
                "scope": "Nonpaged MDL metadata and coherent current-process user aliases of modeled NX pool buffers; synthetic guest PFNs"}

    def install(self, handler):
        for name, function, argc in (("IoAllocateMdl", self.allocate, 5),
                ("IoFreeMdl", self.free, 1), ("MmBuildMdlForNonPagedPool", self.build, 1),
                ("MmGetPhysicalAddress", self.physical_address, 1),
                ("MmMapLockedPagesSpecifyCache", self.map, 6), ("MmUnmapLockedPages", self.unmap, 2)):
            handler.funcs[name] = name, function, argc, arch.CALL_CONV_STDCALL, None

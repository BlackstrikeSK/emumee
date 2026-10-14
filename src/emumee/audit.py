"""Bounded, process-owned audit-policy read APIs backed by guest persona data."""

import struct
import uuid

import speakeasy.common as common
from .audit_policy import CATEGORIES, SETTINGS, SUBCATEGORIES


CATEGORY_GUIDS = tuple(uuid.UUID(f"{0x69979848 + i:08x}-797a-11d9-bed3-505054503030").bytes_le
                       for i in range(len(CATEGORIES)))
SUBCATEGORY_INFO = {uuid.UUID(guid).bytes_le: (category, name)
                    for category, name, guid in SUBCATEGORIES}


class GuestAudit:
    def __init__(self, persona):
        self.persona = persona
        self.buffers = {}
        self.read_guard = None
        self.write_guard = None

    def install(self, emulator):
        hooks = (("AuditQuerySystemPolicy", self._query, 3),
                 ("AuditEnumerateCategories", self._categories, 2),
                 ("AuditEnumerateSubCategories", self._subcategories, 4),
                 ("AuditLookupCategoryIdFromCategoryGuid", self._category_id, 2),
                 ("AuditLookupCategoryGuidFromCategoryId", self._category_guid, 2),
                 ("AuditFree", self._free, 1),
                 ("AuditSetSystemPolicy", self._unsupported, 2))
        for name, callback, argc in hooks:
            emulator.add_api_hook(callback, "advapi32", name, argc=argc)
        for kind in ("Category", "SubCategory"):
            for suffix in ("A", "W"):
                emulator.add_api_hook(self._name, "advapi32",
                                      f"AuditLookup{kind}Name{suffix}", argc=2)

    def _fail(self, emu, error=87):
        emu.set_last_error(error)
        return 0

    def _owner(self, emu):
        process = emu.get_current_process()
        return id(process) if process is not None else 0

    def _access(self, emu, address, size, write=False):
        if address <= 0 or size <= 0:
            return False
        mapping = emu.get_address_map(address)
        permission = common.PERM_MEM_WRITE if write else common.PERM_MEM_READ
        if (mapping is None or mapping.free or not (int(mapping.prot) & permission) or
                address + size > int(mapping.base) + int(mapping.size)):
            return False
        guard = self.write_guard if write else self.read_guard
        return guard is None or bool(guard(emu, address, size))

    def _read(self, emu, address, size):
        if not self._access(emu, address, size):
            return None
        try:
            return bytes(emu.mem_read(address, size))
        except Exception:
            return None

    def _write(self, emu, address, data):
        if not self._access(emu, address, len(data), True):
            return self._fail(emu)
        try:
            emu.mem_write(address, data)
        except Exception:
            return self._fail(emu)
        emu.set_last_error(0)
        return 1

    def _deliver(self, emu, pointer, data, count_pointer=0, count=0):
        width = emu.get_ptr_size()
        owner = self._owner(emu)
        if (not owner or not self._access(emu, pointer, width, True) or
                count_pointer and (not self._access(emu, count_pointer, 4, True) or
                    pointer < count_pointer + 4 and count_pointer < pointer + width)):
            return self._fail(emu)
        if len(self.buffers) >= 128:
            return self._fail(emu, 8)
        buffer = 0
        try:
            buffer = emu.mem_map((len(data) + 4095) & ~4095, perms=common.PERM_MEM_RW,
                                 tag="api.audit.response", process=emu.get_current_process())
            emu.mem_write(buffer, data)
            emu.mem_write(pointer, buffer.to_bytes(width, "little"))
            if count_pointer:
                emu.mem_write(count_pointer, struct.pack("<I", count))
        except Exception:
            if buffer:
                emu.mem_free(buffer)
            return self._fail(emu, 8)
        self.buffers[(owner, buffer)] = emu.get_address_map(buffer)
        emu.set_last_error(0)
        return 1

    def _query(self, emu, _name, _original, params):
        guids_pointer, count, output = map(int, params)
        count &= 0xffffffff
        if not 1 <= count <= 59:
            return self._fail(emu)
        data = self._read(emu, guids_pointer, count * 16)
        if data is None:
            return self._fail(emu)
        selected = [data[i * 16:(i + 1) * 16] for i in range(count)]
        if any(guid not in SUBCATEGORY_INFO for guid in selected):
            return self._fail(emu)
        if not (self.persona["user_is_admin"] or self.persona["audit_policy"]["read_allowed"]):
            return self._fail(emu, 5)
        settings = self.persona["audit_policy"]["subcategories"]
        rows = []
        for guid in selected:
            category, name = SUBCATEGORY_INFO[guid]
            flags = SETTINGS.index(settings.get(name, "No Auditing")) or 4
            rows.append(guid + struct.pack("<I", flags) + CATEGORY_GUIDS[CATEGORIES.index(category)])
        return self._deliver(emu, output, b"".join(rows))

    def _categories(self, emu, _name, _original, params):
        pointer, count = map(int, params)
        if not count:
            return self._fail(emu)
        return self._deliver(emu, pointer, b"".join(CATEGORY_GUIDS), count, len(CATEGORY_GUIDS))

    def _subcategories(self, emu, _name, _original, params):
        category_ptr, all_categories, output, count = map(int, params)
        if not count:
            return self._fail(emu)
        category = None
        if not (all_categories & 0xff):
            guid = self._read(emu, category_ptr, 16)
            if guid not in CATEGORY_GUIDS:
                return self._fail(emu)
            category = CATEGORIES[CATEGORY_GUIDS.index(guid)]
        selected = [guid for guid, (group, _) in SUBCATEGORY_INFO.items()
                    if category is None or group == category]
        return self._deliver(emu, output, b"".join(selected), count, len(selected))

    def _name(self, emu, api_name, _original, params):
        guid_pointer, output = map(int, params)
        guid = self._read(emu, guid_pointer, 16)
        if "SubCategory" in api_name:
            info = SUBCATEGORY_INFO.get(guid)
            if info is None:
                return self._fail(emu)
            name = info[1]
        else:
            if guid not in CATEGORY_GUIDS:
                return self._fail(emu)
            name = CATEGORIES[CATEGORY_GUIDS.index(guid)]
        data = (name + "\0").encode("utf-16le" if api_name.endswith("W") else "ascii")
        return self._deliver(emu, output, data)

    def _category_id(self, emu, _name, _original, params):
        source, output = map(int, params)
        guid = self._read(emu, source, 16)
        if guid not in CATEGORY_GUIDS:
            return self._fail(emu)
        return self._write(emu, output, struct.pack("<I", CATEGORY_GUIDS.index(guid)))

    def _category_guid(self, emu, _name, _original, params):
        category, output = map(int, params)
        category &= 0xffffffff
        if category >= len(CATEGORY_GUIDS):
            return self._fail(emu)
        return self._write(emu, output, CATEGORY_GUIDS[category])

    def _free(self, emu, _name, _original, params):
        pointer = int(params[0])
        mapping = self.buffers.pop((self._owner(emu), pointer), None)
        # A guest may have freed or remapped this address with a different API.
        # Only release the original, still-live mapping owned by this process.
        if mapping is not None and emu.get_address_map(pointer) is mapping and not mapping.free:
            emu.mem_free(pointer)
        return None

    def _unsupported(self, emu, _name, _original, _params):
        return self._fail(emu, 50)

    def cleanup_process(self, emu, process):
        owner = id(process)
        for entry in tuple(self.buffers):
            if entry[0] == owner:
                mapping = self.buffers.pop(entry)
                if emu.get_address_map(entry[1]) is mapping and not mapping.free:
                    emu.mem_free(entry[1])

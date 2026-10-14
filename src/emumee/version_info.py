"""Read-only, guest-backed Win32 file version resource APIs."""

from __future__ import annotations

import ntpath
import struct

import pefile
import speakeasy.common as common


MAX_PATH_CHARS = 32767
MAX_VERSION_BYTES = 65536
ERROR_FILE_NOT_FOUND = 2
ERROR_INVALID_PARAMETER = 87
ERROR_RESOURCE_DATA_NOT_FOUND = 1812


def _align4(value: int) -> int:
    return (value + 3) & ~3


def _version_node(raw: bytes, start: int, limit: int):
    """Parse one bounded VS_VERSIONINFO child without following PE pointers."""
    if start < 0 or start + 6 > limit:
        return None
    length, value_length, value_type = struct.unpack_from('<HHH', raw, start)
    end = start + length
    if length < 8 or end > limit:
        return None
    pos = start + 6
    units = bytearray()
    while pos + 2 <= end and len(units) <= 512:
        unit = raw[pos:pos + 2]
        pos += 2
        if unit == b'\0\0':
            break
        units.extend(unit)
    else:
        return None
    try:
        key = units.decode('utf-16le')
    except UnicodeError:
        return None
    value_at = _align4(pos)
    value_bytes = value_length * (2 if value_type == 1 else 1)
    if value_at + value_bytes > end:
        return None
    child_at = _align4(value_at + value_bytes)
    return key, value_at, value_length, value_bytes, child_at, end


def query_version_resource(raw: bytes, subblock: str) -> tuple[int, int] | None:
    """Return (offset, reported length) for root, translation, or a string."""
    if not raw or len(raw) > MAX_VERSION_BYTES:
        return None
    root = _version_node(raw, 0, len(raw))
    if root is None or root[0].casefold() != 'vs_version_info':
        return None
    if subblock == '\\':
        return root[1], root[2]
    parts = [part.casefold() for part in subblock.split('\\') if part]
    if not parts or len(parts) > 3:
        return None
    node = root
    for part in parts:
        cursor = node[4]
        found = None
        for _ in range(256):
            if cursor + 6 > node[5]:
                break
            child = _version_node(raw, cursor, node[5])
            if child is None:
                return None
            if child[0].casefold() == part:
                found = child
                break
            cursor = _align4(child[5])
        if found is None:
            return None
        node = found
    if not node[2]:
        return None
    return node[1], node[2]


def version_resource(image: bytes) -> bytes | None:
    """Return a bounded RT_VERSION leaf from supplied PE bytes."""
    try:
        pe = pefile.PE(data=image, fast_load=True)
        try:
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
            root = getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', None)
            if root is None:
                return None
            for entry in root.entries:
                if entry.id != 16 or not hasattr(entry, 'directory'):
                    continue
                for name in entry.directory.entries:
                    if not hasattr(name, 'directory'):
                        continue
                    for language in name.directory.entries:
                        if not hasattr(language, 'data'):
                            continue
                        leaf = language.data.struct
                        size = int(leaf.Size)
                        if not 6 <= size <= MAX_VERSION_BYTES:
                            continue
                        raw = pe.get_data(int(leaf.OffsetToData), size)
                        if len(raw) == size and query_version_resource(raw, '\\'):
                            return raw
        finally:
            pe.close()
    except (ValueError, OSError, pefile.PEFormatError, AttributeError,
            IndexError, struct.error):
        return None
    return None


class GuestVersionInfo:
    def __init__(self, current_dir: str, images: dict[str, bytes]):
        self.current_dir = current_dir
        self.images = {ntpath.normcase(ntpath.normpath(path)): data
                       for path, data in images.items()}
        self.read_guard = None
        self.write_guard = None
        self.buffers: dict[int, bytes] = {}

    def install(self, emulator) -> None:
        for suffix in ('A', 'W'):
            emulator.add_api_hook(self._size, 'version',
                                  'GetFileVersionInfoSize' + suffix, argc=2)
            emulator.add_api_hook(self._size_ex, 'version',
                                  'GetFileVersionInfoSizeEx' + suffix, argc=3)
            emulator.add_api_hook(self._info, 'version',
                                  'GetFileVersionInfo' + suffix, argc=4)
            emulator.add_api_hook(self._info_ex, 'version',
                                  'GetFileVersionInfoEx' + suffix, argc=5)
            emulator.add_api_hook(self._query, 'version',
                                  'VerQueryValue' + suffix, argc=4)

    def _access(self, emu, address: int, size: int, mode: str) -> bool:
        if not address or size <= 0:
            return False
        mapping = emu.get_address_map(address)
        if (mapping is None or mapping.free or
                address + size > int(mapping.base) + int(mapping.size) or
                not (int(mapping.prot) &
                     (common.PERM_MEM_READ if mode == 'read' else
                      common.PERM_MEM_WRITE))):
            return False
        guard = self.read_guard if mode == 'read' else self.write_guard
        return guard is None or bool(guard(emu, address, size))

    def _name(self, emu, api_name: str, address: int) -> str | None:
        width = 2 if api_name.endswith('W') else 1
        pieces = bytearray()
        for index in range(MAX_PATH_CHARS + 1):
            ptr = address + index * width
            if not self._access(emu, ptr, width, 'read'):
                return None
            try:
                unit = emu.mem_read(ptr, width)
            except Exception:
                return None
            if unit == b'\0' * width:
                try:
                    return pieces.decode('utf-16le' if width == 2 else 'cp1252')
                except UnicodeError:
                    return None
            pieces.extend(unit)
        return None

    def _resource(self, emu, api_name: str, name_ptr: int) -> bytes | None:
        name = self._name(emu, api_name, name_ptr)
        if not name:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return None
        path = ntpath.normcase(ntpath.normpath(
            name if ntpath.isabs(name) else ntpath.join(self.current_dir, name)))
        image = self.images.get(path)
        if image is None:
            emu.set_last_error(ERROR_FILE_NOT_FOUND)
            return None
        resource = version_resource(image)
        if resource is None:
            emu.set_last_error(ERROR_RESOURCE_DATA_NOT_FOUND)
        return resource

    def _size(self, emu, api_name, _original, params) -> int:
        name, handle = map(int, params)
        return self._get_size(emu, api_name, name, handle)

    def _size_ex(self, emu, api_name, _original, params) -> int:
        _flags, name, handle = map(int, params)
        return self._get_size(emu, api_name, name, handle)

    def _get_size(self, emu, api_name: str, name: int, handle: int) -> int:
        if handle:
            if not self._access(emu, handle, 4, 'write'):
                emu.set_last_error(ERROR_INVALID_PARAMETER)
                return 0
            try:
                emu.mem_write(handle, b'\0' * 4)
            except Exception:
                emu.set_last_error(ERROR_INVALID_PARAMETER)
                return 0
        resource = self._resource(emu, api_name, name)
        if resource is None:
            return 0
        emu.set_last_error(0)
        return len(resource)

    def _info(self, emu, api_name, _original, params) -> int:
        name, _handle, length, output = map(int, params)
        return self._get_info(emu, api_name, name, length, output)

    def _info_ex(self, emu, api_name, _original, params) -> int:
        _flags, name, _handle, length, output = map(int, params)
        return self._get_info(emu, api_name, name, length, output)

    def _get_info(self, emu, api_name: str, name: int, length: int,
                  output: int) -> int:
        resource = self._resource(emu, api_name, name)
        if resource is None:
            return 0
        copied = resource[:length]
        if not copied or not self._access(emu, output, len(copied), 'write'):
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        try:
            emu.mem_write(output, copied)
        except Exception:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        self.buffers[output] = copied
        if len(self.buffers) > 256:
            self.buffers.pop(next(iter(self.buffers)))
        emu.set_last_error(0)
        return 1

    def _query(self, emu, api_name, _original, params) -> int:
        block, subblock_ptr, pointer_out, length_out = map(int, params)
        raw = self.buffers.get(block)
        subblock = self._name(emu, api_name, subblock_ptr)
        ptr_width = emu.get_ptr_size()
        if (raw is None or subblock is None or
                not self._access(emu, block, len(raw), 'read') or
                not self._access(emu, pointer_out, ptr_width, 'write') or
                not self._access(emu, length_out, 4, 'write')):
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        try:
            if emu.mem_read(block, len(raw)) != raw:
                return 0
            value = query_version_resource(raw, subblock)
            if value is None:
                return 0
            offset, length = value
            # The binary root and translation values have identical A/W bytes.
            # String values are UTF-16 in the version resource. VerQueryValueA
            # would need a converted guest buffer, so leave it unavailable.
            if api_name.endswith('A') and subblock.lower().startswith('\\stringfileinfo\\'):
                return 0
            emu.mem_write(pointer_out, (block + offset).to_bytes(ptr_width, 'little'))
            emu.mem_write(length_out, length.to_bytes(4, 'little'))
        except Exception:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        emu.set_last_error(0)
        return 1

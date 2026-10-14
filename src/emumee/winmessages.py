"""Bounded guest-only FormatMessageW behavior for common Win32 messages."""

from __future__ import annotations

import re
import struct
import ntpath

import pefile

import speakeasy.common as common


FORMAT_MESSAGE_ALLOCATE_BUFFER = 0x00000100
FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200
FORMAT_MESSAGE_FROM_STRING = 0x00000400
FORMAT_MESSAGE_FROM_HMODULE = 0x00000800
FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
FORMAT_MESSAGE_ARGUMENT_ARRAY = 0x00002000
MAX_MESSAGE_CHARS = 32767

ERROR_INVALID_PARAMETER = 87
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_MR_MID_NOT_FOUND = 317

# These en-US strings are persona data, not messages fetched from the host OS.
_SYSTEM_MESSAGES = {
    0: "The operation completed successfully.\r\n",
    1: "Incorrect function.\r\n",
    2: "The system cannot find the file specified.\r\n",
    3: "The system cannot find the path specified.\r\n",
    5: "Access is denied.\r\n",
    6: "The handle is invalid.\r\n",
    8: "Not enough memory resources are available to process this command.\r\n",
    14: "Not enough memory resources are available to complete this operation.\r\n",
    18: "There are no more files.\r\n",
    32: "The process cannot access the file because it is being used by another process.\r\n",
    50: "The request is not supported.\r\n",
    80: "The file exists.\r\n",
    87: "The parameter is incorrect.\r\n",
    109: "The pipe has been ended.\r\n",
    112: "There is not enough space on the disk.\r\n",
    122: "The data area passed to a system call is too small.\r\n",
    126: "The specified module could not be found.\r\n",
    127: "The specified procedure could not be found.\r\n",
    183: "Cannot create a file when that file already exists.\r\n",
    234: "More data is available.\r\n",
    259: "No more data is available.\r\n",
    267: "The directory name is invalid.\r\n",
    995: "The I/O operation has been aborted because of either a thread exit or an application request.\r\n",
    10013: "An attempt was made to access a socket in a way forbidden by its access permissions.\r\n",
}


def mui_string(image: bytes, string_id: int) -> str | None:
    """Read a bounded RT_STRING entry from an explicitly staged MUI PE."""
    if string_id < 0 or len(image) > 32 * 1024 * 1024:
        return None
    try:
        pe = pefile.PE(data=image, fast_load=True)
        try:
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
            root = getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', None)
            if root is None:
                return None
            block_id = (string_id >> 4) + 1
            item_id = string_id & 15
            for resource in root.entries:
                if resource.id != 6 or not hasattr(resource, 'directory'):
                    continue
                for block in resource.directory.entries:
                    if block.id != block_id or not hasattr(block, 'directory'):
                        continue
                    for language in block.directory.entries:
                        if not hasattr(language, 'data'):
                            continue
                        leaf = language.data.struct
                        size = int(leaf.Size)
                        if size < 32 or size > 65536:
                            continue
                        raw = pe.get_data(int(leaf.OffsetToData), size)
                        if len(raw) != size:
                            continue
                        pos = 0
                        for index in range(16):
                            if pos + 2 > size:
                                break
                            length = struct.unpack_from('<H', raw, pos)[0]
                            pos += 2
                            end = pos + length * 2
                            if end > size:
                                break
                            if index == item_id:
                                return raw[pos:end].decode('utf-16le') if length else None
                            pos = end
        finally:
            pe.close()
    except (ValueError, OSError, pefile.PEFormatError, AttributeError,
            IndexError, struct.error, UnicodeError):
        return None
    return None


def mui_message(image: bytes, message_id: int, language: int = 0) -> str | None:
    """Read one bounded RT_MESSAGETABLE entry from a supplied guest MUI."""
    if message_id < 0 or len(image) > 32 * 1024 * 1024:
        return None
    try:
        pe = pefile.PE(data=image, fast_load=True)
        try:
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
            root = getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', None)
            if root is None:
                return None
            for resource in root.entries:
                if resource.id != 11 or not hasattr(resource, 'directory'):
                    continue
                for block in resource.directory.entries:
                    if not hasattr(block, 'directory'):
                        continue
                    for item in block.directory.entries:
                        if not hasattr(item, 'data') or (language and item.id != language):
                            continue
                        leaf = item.data.struct
                        size = int(leaf.Size)
                        if size < 16 or size > 1024 * 1024:
                            continue
                        raw = pe.get_data(int(leaf.OffsetToData), size)
                        if len(raw) != size:
                            continue
                        count = struct.unpack_from('<I', raw, 0)[0]
                        if count > 4096 or 4 + count * 12 > size:
                            continue
                        for index in range(count):
                            low, high, offset = struct.unpack_from('<III', raw, 4 + index * 12)
                            if not low <= message_id <= high or high - low > 65535:
                                continue
                            position = offset
                            for _ in range(message_id - low + 1):
                                if position + 4 > size:
                                    return None
                                length, flags = struct.unpack_from('<HH', raw, position)
                                if length < 4 or position + length > size or flags & ~1:
                                    return None
                                if _ == message_id - low:
                                    data = raw[position + 4:position + length]
                                    encoding = 'utf-16le' if flags & 1 else 'cp1252'
                                    if flags & 1 and len(data) % 2:
                                        return None
                                    return data.decode(encoding).rstrip('\0')
                                position += length
        finally:
            pe.close()
    except (ValueError, OSError, pefile.PEFormatError, AttributeError,
            IndexError, struct.error, UnicodeError):
        return None
    return None


class WinMessages:
    def __init__(self, locale: str = "en-US"):
        self.locale = locale.casefold().replace("_", "-")
        self.unsupported: list[str] = []
        self._missing_mui: set[tuple[int, int]] = set()
        self.read_guard = None
        self.write_guard = None
        self.module_visible = None
        self.guest_images: dict[str, bytes] = {}
        self.current_dir = ''
        self._mui_cache: dict[tuple[str, int], str | None] = {}

    def _mui_image(self, module) -> tuple[str, bytes] | None:
        name = ntpath.basename(str(module.name))
        candidates = [path for path in self.guest_images
                      if ntpath.splitext(ntpath.basename(path))[0].casefold()
                      == ntpath.splitext(name)[0].casefold()]
        module_path = ntpath.normcase(ntpath.normpath(str(getattr(module, 'path', ''))))
        preferred = ntpath.normcase(ntpath.normpath(ntpath.join(
            self.current_dir, name if ntpath.splitext(name)[1] else name + '.exe')))
        if module_path in candidates:
            stem_path = module_path
        elif preferred in candidates:
            stem_path = preferred
        elif len(candidates) == 1:
            stem_path = candidates[0]
        else:
            return None
        mui_path = ntpath.normcase(ntpath.normpath(ntpath.join(
            ntpath.dirname(stem_path), self.locale,
            ntpath.basename(stem_path) + '.mui')))
        image = self.guest_images.get(mui_path)
        return (mui_path, image) if image is not None else None

    def _mui_message(self, module, string_id: int) -> str | None:
        found = self._mui_image(module)
        if found is None:
            return None
        mui_path, image = found
        key = (mui_path, string_id)
        if key not in self._mui_cache:
            self._mui_cache[key] = mui_string(image, string_id)
        return self._mui_cache[key]

    def _mui_message_table(self, module, message_id: int, language: int) -> str | None:
        found = self._mui_image(module)
        return mui_message(found[1], message_id, language) if found else None

    def install(self, emulator) -> None:
        emulator.add_api_hook(self._format_w, "kernel32", "FormatMessageW", argc=7)
        emulator.add_api_hook(self._format_w, "kernelbase", "FormatMessageW", argc=7)
        emulator.add_api_hook(self._format_w,
                              "api-ms-win-core-localization-l1-2-0",
                              "FormatMessageW", argc=7)
        emulator.add_api_hook(self._load_string_w, "user32", "LoadStringW", argc=4)
        emulator.add_api_hook(self._load_string_w,
                              "api-ms-win-core-libraryloader-l1-2-0",
                              "LoadStringW", argc=4)

    def _access(self, emu, address: int, size: int, mode: str) -> bool:
        guard = self.read_guard if mode == "read" else self.write_guard
        if not address or size <= 0:
            return False
        mapped = emu.get_address_map(address)
        required = (common.PERM_MEM_READ if mode == "read" else
                    common.PERM_MEM_WRITE)
        if (mapped is None or mapped.free or
                address + size > int(mapped.base) + int(mapped.size) or
                not (int(mapped.prot) & required)):
            return False
        return bool(guard is None or guard(emu, address, size))

    def _read_wide(self, emu, address: int) -> str | None:
        chars = []
        for index in range(MAX_MESSAGE_CHARS + 1):
            ptr = address + index * 2
            if not self._access(emu, ptr, 2, "read"):
                return None
            try:
                unit = emu.mem_read(ptr, 2)
            except Exception:
                return None
            if unit == b"\0\0":
                return b"".join(chars).decode("utf-16le", errors="replace")
            chars.append(unit)
        return None

    @staticmethod
    def _format_escapes(message: str, ignore_inserts: bool) -> str | None:
        if not ignore_inserts and re.search(r"%[1-9][0-9]?(?:![^!]*!)?", message):
            return None
        # Control escapes are part of message-table syntax even when insert
        # expansion is disabled. %0 terminates the message text.
        message = message.split("%0", 1)[0]
        return re.sub(r"%%|%[nrt]", lambda match: {
            "%%": "%", "%n": "\r\n", "%r": "\r", "%t": "\t",
        }[match.group()], message)

    def _format_inserts(self, emu, message: str, arguments: int,
                        argument_array: bool) -> str | None:
        found = list(re.finditer(r"%([1-9][0-9]?)(?:!([^!]*)!)?", message))
        if not found:
            return message
        width = emu.get_ptr_size()
        if not arguments:
            return None
        base = arguments
        if not argument_array:
            if not self._access(emu, arguments, width, "read"):
                return None
            base = int.from_bytes(emu.mem_read(arguments, width), "little")
        values = {}
        for match in found:
            number = int(match.group(1))
            specifier = match.group(2)
            if specifier not in (None, "s", "ls", "ws"):
                return None
            slot = base + (number - 1) * width
            if not self._access(emu, slot, width, "read"):
                return None
            pointer = int.from_bytes(emu.mem_read(slot, width), "little")
            value = self._read_wide(emu, pointer)
            if value is None:
                return None
            values[match.start()] = value
        return re.sub(r"%([1-9][0-9]?)(?:!([^!]*)!)?",
                      lambda match: values[match.start()], message)

    def _format_w(self, emu, api_name, _original, params) -> int:
        flags, source, message_id, language, output, capacity, arguments = map(int, params)
        flags &= 0xffffffff
        message_id &= 0xffffffff
        language &= 0xffffffff
        capacity &= 0xffffffff
        allocate = bool(flags & FORMAT_MESSAGE_ALLOCATE_BUFFER)
        from_string = bool(flags & FORMAT_MESSAGE_FROM_STRING)
        from_system = bool(flags & FORMAT_MESSAGE_FROM_SYSTEM)
        from_module = bool(flags & FORMAT_MESSAGE_FROM_HMODULE)
        if (not output or (from_string and (from_system or from_module)) or
                (not from_string and not (from_system or from_module)) or
                (flags & ~(0xFF | FORMAT_MESSAGE_ALLOCATE_BUFFER |
                           FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_STRING |
                           FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_FROM_SYSTEM |
                           FORMAT_MESSAGE_ARGUMENT_ARRAY))):
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        if flags & 0xFF:
            self.unsupported.append(f"{api_name}: message width not modeled")
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        if from_string:
            message = self._read_wide(emu, source)
            if message is None:
                emu.set_last_error(ERROR_INVALID_PARAMETER)
                return 0
        else:
            message = None
            if from_module:
                process = emu.get_current_process()
                module = (emu.get_mod_from_addr(int(process.base)) if source == 0 and
                          process is not None else emu.get_mod_from_addr(source))
                if module is not None and (source == 0 or int(module.base) == source) and (
                        self.module_visible is None or self.module_visible(emu, module)):
                    message = self._mui_message_table(module, message_id, language)
            if message is None and from_system:
                message = _SYSTEM_MESSAGES.get(message_id)
            if message is None:
                self.unsupported.append(f"{api_name}: message {message_id:#x} not modeled")
                emu.set_last_error(ERROR_MR_MID_NOT_FOUND)
                return 0
            if from_system and not from_module and language == 0 and self.locale not in ("en-us", "en-gb"):
                self.unsupported.append(f"{api_name}: persona message locale {self.locale} not modeled")
                emu.set_last_error(ERROR_MR_MID_NOT_FOUND)
                return 0
            if from_system and not from_module and language not in (0, 0x0409, 0x0809):
                self.unsupported.append(f"{api_name}: system message language {language:#x} not modeled")
                emu.set_last_error(ERROR_MR_MID_NOT_FOUND)
                return 0
        ignore_inserts = bool(flags & FORMAT_MESSAGE_IGNORE_INSERTS)
        message = self._format_escapes(message, True)
        if message is not None and not ignore_inserts:
            try:
                message = self._format_inserts(emu, message, arguments,
                                               bool(flags & FORMAT_MESSAGE_ARGUMENT_ARRAY))
            except Exception:
                message = None
        if message is None:
            self.unsupported.append(f"{api_name}: message inserts not modeled")
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        if len(message) > MAX_MESSAGE_CHARS:
            emu.set_last_error(ERROR_INSUFFICIENT_BUFFER)
            return 0
        payload = (message + "\0").encode("utf-16le")
        if allocate:
            if capacity > MAX_MESSAGE_CHARS + 1:
                emu.set_last_error(ERROR_INSUFFICIENT_BUFFER)
                return 0
            if not self._access(emu, output, emu.get_ptr_size(), "write"):
                emu.set_last_error(ERROR_INVALID_PARAMETER)
                return 0
            size = max(len(payload), min(capacity, MAX_MESSAGE_CHARS + 1) * 2)
            try:
                allocated = emu.mem_map(size, tag="api.heap.FormatMessage",
                                        perms=common.PERM_MEM_RW,
                                        process=emu.get_current_process())
            except Exception:
                emu.set_last_error(8)
                return 0
            try:
                emu.mem_write(allocated, payload)
                emu.mem_write(output, struct.pack("<Q" if emu.get_ptr_size() == 8 else "<I", allocated))
            except Exception:
                emu.mem_free(allocated)
                emu.set_last_error(ERROR_INVALID_PARAMETER)
                return 0
        else:
            if capacity <= 0 or capacity > MAX_MESSAGE_CHARS + 1:
                emu.set_last_error(ERROR_INSUFFICIENT_BUFFER)
                return 0
            if not self._access(emu, output, capacity * 2, "write"):
                emu.set_last_error(ERROR_INVALID_PARAMETER)
                return 0
            if len(message) + 1 > capacity:
                try:
                    emu.mem_write(output, (message[:capacity - 1] + "\0").encode("utf-16le"))
                except Exception:
                    emu.set_last_error(ERROR_INVALID_PARAMETER)
                    return 0
                emu.set_last_error(ERROR_INSUFFICIENT_BUFFER)
                return 0
            try:
                emu.mem_write(output, payload)
            except Exception:
                emu.set_last_error(ERROR_INVALID_PARAMETER)
                return 0
        return len(message)

    def _load_string_w(self, emu, api_name, _original, params) -> int:
        instance, string_id, output, capacity = map(int, params)
        if capacity < 0 or capacity > MAX_MESSAGE_CHARS + 1:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        process = emu.get_current_process()
        if instance == 0:
            module = (emu.get_mod_from_addr(int(process.base)) if process is not None
                      else (emu.modules[0] if emu.modules else None))
        else:
            module = emu.get_mod_from_addr(instance)
            if module is not None and int(module.base) != instance:
                module = None
        if module is None or (self.module_visible is not None and
                              not self.module_visible(emu, module)):
            return 0
        metadata = module.get_pe_metadata()
        if metadata is None:
            return 0
        message = metadata.string_table.get(string_id)
        if message is None:
            message = self._mui_message(module, string_id)
        if message is None:
            if any(str(resource.type_id).casefold() == "mui"
                   for resource in metadata.resources):
                key = (int(module.base), string_id)
                if key not in self._missing_mui:
                    self._missing_mui.add(key)
                    self.unsupported.append(
                        f"{api_name}: external MUI string {string_id:#x} unavailable "
                        f"for {module.name}")
            return 0
        if capacity == 0:
            self.unsupported.append(f"{api_name}: resource pointer return not modeled")
            return 0
        if not output:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        encoded = message.encode("utf-16le")
        copied = encoded[:max(0, capacity - 1) * 2]
        payload = copied + b"\0\0"
        if not self._access(emu, output, len(payload), "write"):
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        try:
            emu.mem_write(output, payload)
        except Exception:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        return len(copied) // 2

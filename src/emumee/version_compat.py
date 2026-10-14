"""Bounded reading of an EXE's embedded Windows compatibility manifest."""

from __future__ import annotations

import struct
from xml.etree import ElementTree


WIN10_GUID = "8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a"
WIN81_GUID = "1f676c76-80e1-4239-95bb-83d0f6d0da78"


def manifest_compatibility(image: bytes) -> str:
    """Return win10, win81, or none using only bounded PE resource reads."""
    try:
        if len(image) < 0x40 or image[:2] != b"MZ":
            return "none"
        pe_offset = struct.unpack_from("<I", image, 0x3C)[0]
        if pe_offset > len(image) - 24 or image[pe_offset:pe_offset + 4] != b"PE\0\0":
            return "none"
        sections = struct.unpack_from("<H", image, pe_offset + 6)[0]
        optional_size = struct.unpack_from("<H", image, pe_offset + 20)[0]
        if not 1 <= sections <= 96:
            return "none"
        optional = pe_offset + 24
        section_table = optional + optional_size
        if section_table > len(image) - sections * 40:
            return "none"
        magic = struct.unpack_from("<H", image, optional)[0]
        if magic not in (0x10B, 0x20B):
            return "none"
        rva_count = struct.unpack_from("<I", image,
                                       optional + (92 if magic == 0x10B else 108))[0]
        if rva_count < 3:
            return "none"
        data_directory = optional + (96 if magic == 0x10B else 112)
        if data_directory + 24 > section_table:
            return "none"
        resource_rva, resource_size = struct.unpack_from("<II", image,
                                                          data_directory + 16)
        if not resource_rva or not 16 <= resource_size <= 1_048_576:
            return "none"
        raw_sections = []
        for index in range(sections):
            entry = section_table + index * 40
            virtual_address = struct.unpack_from("<I", image, entry + 12)[0]
            raw_size = struct.unpack_from("<I", image, entry + 16)[0]
            raw_pointer = struct.unpack_from("<I", image, entry + 20)[0]
            if raw_size and raw_pointer <= len(image) and raw_size <= len(image) - raw_pointer:
                raw_sections.append((virtual_address, raw_size, raw_pointer))

        def read_rva(rva: int, size: int) -> bytes:
            if size < 0 or size > 65_536:
                raise ValueError("resource read outside limit")
            for start, raw_size, raw_pointer in raw_sections:
                if start <= rva and rva - start <= raw_size - size:
                    offset = raw_pointer + rva - start
                    return image[offset:offset + size]
            raise ValueError("resource RVA not backed by file data")

        def read_relative(offset: int, size: int) -> bytes:
            if offset > resource_size or size > resource_size - offset:
                raise ValueError("resource offset outside directory")
            return read_rva(resource_rva + offset, size)

        def entries(offset: int):
            header = read_relative(offset, 16)
            named, numbered = struct.unpack_from("<HH", header, 12)
            count = named + numbered
            if count > 128:
                raise ValueError("resource directory entry limit")
            raw = read_relative(offset + 16, count * 8)
            return [struct.unpack_from("<II", raw, index * 8)
                    for index in range(count)]

        for kind, kind_ref in entries(0):
            if kind != 24 or not kind_ref & 0x80000000:
                continue
            for name, name_ref in entries(kind_ref & 0x7FFFFFFF):
                if name != 1 or not name_ref & 0x80000000:
                    continue
                for _language, data_ref in entries(name_ref & 0x7FFFFFFF):
                    if data_ref & 0x80000000:
                        continue
                    rva, size = struct.unpack_from("<II", read_relative(data_ref, 16))
                    if not 0 < size <= 65_536:
                        continue
                    raw = read_rva(rva, size)
                    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
                        continue
                    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
                        xml = raw.decode("utf-16")
                    elif raw.startswith(b"<\0"):
                        xml = raw.decode("utf-16le")
                    else:
                        xml = raw.decode("utf-8-sig")
                    if "<!DOCTYPE" in xml.upper() or "<!ENTITY" in xml.upper():
                        continue
                    root = ElementTree.fromstring(xml.rstrip("\0"))
                    supported = set()
                    for element in root.iter():
                        if element.tag.rsplit("}", 1)[-1].casefold() != "supportedos":
                            continue
                        for key, value in element.attrib.items():
                            if key.rsplit("}", 1)[-1].casefold() == "id":
                                supported.add(value.strip("{} ").casefold())
                    if WIN10_GUID in supported:
                        return "win10"
                    if WIN81_GUID in supported:
                        return "win81"
    except (IndexError, OverflowError, RecursionError, ValueError, struct.error,
            UnicodeError, ElementTree.ParseError):
        return "none"
    return "none"

"""Bounded relocation of driver images into the modeled kernel address range."""

import struct

from .pe import InvalidSample


def place_driver_image(image):
    parser = getattr(image.loader, "_pe_obj", None)
    if parser is None:
        return None
    preferred = image.image_base
    width = 8 if int(parser.FILE_HEADER.Machine) == 0x8664 else 4
    directories = parser.OPTIONAL_HEADER.DATA_DIRECTORY
    directory = directories[5] if len(directories) > 5 else None
    # Fixed images retain their declared address; inventing relocation entries
    # would silently corrupt code. Report that placement explicitly.
    if directory is None or not directory.Size:
        return {"preferred_base": hex(preferred), "mapped_base": hex(preferred),
                "relocations_applied": 0, "placement": "fixed_preferred_address"}
    if int(parser.FILE_HEADER.Characteristics) & 1:
        raise InvalidSample("Driver relocation directory conflicts with RELOCS_STRIPPED")
    if len(image.regions) != 1:
        raise InvalidSample("Driver relocation requires one bounded mapped image")
    original = image.regions[0].data
    rva, size = int(directory.VirtualAddress), int(directory.Size)
    if not 0 < rva < len(original) or not 8 <= size <= 32 * 1024 * 1024 or rva + size > len(original):
        raise InvalidSample("Invalid driver relocation directory bounds")
    base = 0xFFFFF80100000000 if width == 8 else 0x90000000
    if preferred >= (0xFFFF800000000000 if width == 8 else 0x80000000):
        base = preferred
    difference = base - preferred
    relocated = bytearray(original)
    cursor, count = rva, 0
    while cursor < rva + size:
        if cursor + 8 > rva + size:
            raise InvalidSample("Truncated driver relocation block")
        page, block_size = struct.unpack_from("<II", original, cursor)
        if page % 4096 or page >= len(original) or block_size < 8 or block_size % 4 or cursor + block_size > rva + size:
            raise InvalidSample("Invalid driver relocation block")
        for offset in range(cursor + 8, cursor + block_size, 2):
            entry = struct.unpack_from("<H", original, offset)[0]
            kind, target = entry >> 12, page + (entry & 4095)
            if kind == 0:
                continue
            if kind != (10 if width == 8 else 3) or target + width > len(original):
                raise InvalidSample("Unsupported or out-of-image driver relocation")
            value = int.from_bytes(relocated[target:target + width], "little")
            relocated[target:target + width] = ((value + difference) & ((1 << (width * 8)) - 1)).to_bytes(width, "little")
            count += 1
        cursor += block_size
    # Windows retains the preferred ImageBase in the mapped PE header. Only
    # runtime placement metadata and relocation targets use the actual base.
    image.image_base = image.regions[0].base = base
    image.regions[0].data = bytes(relocated)
    for entry in image.imports:
        entry.iat_address += difference
    for entry in image.exports:
        entry.address += difference
    image.entry_points = [address + difference for address in image.entry_points]
    image.tls_callbacks = [address + difference for address in image.tls_callbacks]
    if image.tls_directory_va is not None:
        image.tls_directory_va += difference
    parser.base = base
    parser.mapped_image = image.regions[0].data
    parser.imports = {address + difference: value for address, value in parser.imports.items()}
    for descriptor in getattr(parser, "DIRECTORY_ENTRY_IMPORT", ()):
        for entry in descriptor.imports:
            entry.address += difference
    return {"preferred_base": hex(preferred), "mapped_base": hex(base),
            "relocations_applied": count, "placement": "kernel_address_range"}

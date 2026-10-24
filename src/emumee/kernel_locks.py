"""Guest backing storage for the WDK's per-processor queued spin locks.

This supplies the idle single-processor data layout, not a scheduler or support
for lock acquisition APIs that the kernel engine does not implement.
"""

import struct

import pefile
from speakeasy.common import PERM_MEM_RW
from speakeasy.windows.loaders import SectionEntry, ApiModuleLoader


def add_kernel_lock_storage(image):
    if image.name != "ntoskrnl" or not isinstance(image.loader, ApiModuleLoader):
        return None
    parsed = pefile.PE(data=image.regions[0].data, fast_load=True)
    section_rva = (max(image.image_size, len(image.regions[0].data)) + 4095) & ~4095
    offset = parsed.sections[-1].get_file_offset() + 40
    if offset + 40 > min(section.VirtualAddress for section in parsed.sections):
        raise ValueError("Modeled kernel headers have no room for lock storage section")
    data = bytearray(image.regions[0].data)
    data.extend(bytes(section_rva + 4096 - len(data)))
    struct.pack_into("<8sIIIIIIHHI", data, offset, b".emulock", 4096, section_rva,
                     4096, section_rva, 0, 0, 0, 0, 0xC0000040)
    struct.pack_into("<H", data, parsed.FILE_HEADER.get_field_absolute_offset("NumberOfSections"),
                     parsed.FILE_HEADER.NumberOfSections + 1)
    struct.pack_into("<I", data, parsed.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfImage"), section_rva + 4096)
    alignment = parsed.OPTIONAL_HEADER.FileAlignment
    headers = max(parsed.OPTIONAL_HEADER.SizeOfHeaders, (offset + 40 + alignment - 1) // alignment * alignment)
    struct.pack_into("<I", data, parsed.OPTIONAL_HEADER.get_field_absolute_offset("SizeOfHeaders"), headers)
    image.image_size = section_rva + 4096
    image.regions[0].data = bytes(data)
    image.sections.append(SectionEntry(".emulock", section_rva, 4096, PERM_MEM_RW))
    return image.image_base + section_rva

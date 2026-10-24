"""Optional static NTOS code inspection data; reference instructions never run.

The ordinary generated API stubs and exports remain the execution interface.
File-backed executable sections are readable/NX at their original RVAs.
Private data is inaccessible apart from explicitly modeled guest fields:
a file is not initialized kernel state.
"""
from __future__ import annotations

import hashlib
import struct
import pefile
from speakeasy.common import PERM_MEM_NONE, PERM_MEM_READ
from speakeasy.windows.loaders import ApiModuleLoader, SectionEntry
from speakeasy.winenv import arch
from .pe import InvalidSample

MAX_REFERENCE_BYTES = 32 * 1024 * 1024
MAX_REFERENCE_IMAGE = 18 * 1024 * 1024
REFERENCE_PROVIDER_SPACING = 32 * 1024 * 1024
KNOWN_REFERENCE_SHA256 = '4b954aae4b18a231b2254c0989b1b6bcc55741a8ef90a350f036d09cd480cc99'
# Public symbol metadata from the matching Microsoft PDB. This labels a
# refused call; it supplies neither a private ABI nor an implementation.
# PDB SHA256:5eea0257091c91a86da4a1633248723eb07f08f6d2718447ed4c0a95706790f5
KNOWN_PRIVATE_SYMBOLS = {0x85e330: 'MmAllocateIndependentPages',
    0xc13098: 'MmUnloadedDrivers', 0xc13090: 'MmLastUnloadedDriver'}
KNOWN_GUEST_DATA_LAYOUTS = {KNOWN_REFERENCE_SHA256: (
    {'name': 'MmUnloadedDrivers', 'rva': 0xc13098, 'size': 8, 'value': 0},
    {'name': 'MmLastUnloadedDriver', 'rva': 0xc13090, 'size': 4, 'value': 0})}


def reference_identity(data):
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_REFERENCE_BYTES:
        raise InvalidSample('Kernel code reference exceeds the 32 MiB input limit')
    digest = hashlib.sha256(data).hexdigest()
    known = digest == KNOWN_REFERENCE_SHA256
    return {'sha256': digest, 'size': len(data),
        'purpose': 'non_executable_kernel_code_inspection',
        'provenance': 'pinned_authenticated_Microsoft_reference' if known else 'unverified_user_supplied_PE_data',
        'file_version': '10.0.22621.2506' if known else None}


class KernelCodeReference:
    def __init__(self, kernel, data):
        self.kernel = kernel
        self.identity = reference_identity(data)
        try:
            self.pe = pefile.PE(data=data, fast_load=True)
            self.pe.parse_data_directories(directories=[5])
        except pefile.PEFormatError as exc:
            raise InvalidSample('Invalid kernel code reference PE') from exc
        p = self.pe
        if (p.FILE_HEADER.Machine != 0x8664 or p.OPTIONAL_HEADER.Magic != 0x20b or
                p.OPTIONAL_HEADER.SectionAlignment != 4096 or
                not 0 < p.OPTIONAL_HEADER.SizeOfImage <= MAX_REFERENCE_IMAGE or
                getattr(kernel, 'persona_config', {}).get('windows_build') != 22631):
            raise InvalidSample('Kernel code references require the supported x64 build22631 profile and bounded image')
        self.source_size = (p.OPTIONAL_HEADER.SizeOfImage + 4095) & ~4095
        self.source_base = p.OPTIONAL_HEADER.ImageBase
        self.code = []
        for section in p.sections:
            if not section.Characteristics & 0x20000000 or not section.SizeOfRawData:
                continue
            start = section.VirtualAddress
            size = section.Misc_VirtualSize
            if (start & 4095 or not 0 < size <= section.SizeOfRawData or
                    start + size > self.source_size or
                    section.PointerToRawData + section.SizeOfRawData > len(data)):
                raise InvalidSample('Invalid file-backed kernel reference code section')
            if any(start < other['rva'] + other['size'] and other['rva'] < start + size for other in self.code):
                raise InvalidSample('Overlapping kernel reference code sections')
            self.code.append({'name': section.Name.rstrip(b'\0').decode('ascii', 'strict'),
                'rva': start, 'size': size, 'data': p.get_data(start, size)})
        if not 0 < len(self.code) <= 24:
            raise InvalidSample('Kernel reference has no bounded file-backed executable sections')
        self.code_exports = {}
        directory = p.OPTIONAL_HEADER.DATA_DIRECTORY[0]
        if directory.VirtualAddress and directory.Size:
            header = p.get_data(directory.VirtualAddress, 40)
            if len(header) != 40 or max(struct.unpack_from('<II', header, 20)) > 16384:
                raise InvalidSample('Kernel reference export directory exceeds its bound')
            try:
                p.parse_data_directories(directories=[0])
            except pefile.PEFormatError as exc:
                raise InvalidSample('Invalid kernel reference export directory') from exc
            for symbol in getattr(getattr(p, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', ()):
                if not symbol.name or symbol.forwarder or not any(
                        s['rva'] <= symbol.address < s['rva']+s['size'] for s in self.code):
                    continue
                try:
                    name = symbol.name.decode('ascii', 'strict')
                except UnicodeError as exc:
                    raise InvalidSample('Invalid kernel reference export name') from exc
                if not 0 < len(name) <= 512 or (name in self.code_exports and self.code_exports[name] != symbol.address):
                    raise InvalidSample('Ambiguous or oversized kernel reference export name')
                self.code_exports[name] = symbol.address
        self.export_names_by_rva = {}
        for name, rva in self.code_exports.items():
            self.export_names_by_rva.setdefault(rva, []).append(name)
        # This emulator starts a new guest kernel with no recorded module
        # unloads. It implements neither ZwUnloadDriver nor MmUnloadSystemImage.
        # Calling DriverUnload alone is not an image-unload operation. The
        # matching reference's MiRememberUnloadedDriver lazily allocates its
        # history buffer; its empty pointer/index are therefore model state,
        # never bytes copied from the reference or the host's boot history.
        self.guest_data = [dict(field) for field in KNOWN_GUEST_DATA_LAYOUTS.get(self.identity['sha256'], ())]
        self.guest_data_reads = 0
        self.guest_data_tail = []
        self.base = self.start = self.end = None
        self.relocations = 0
        self.denials = []
        self.omitted = 0

    def prepare(self, image):
        if image.name != 'ntoskrnl' or not isinstance(image.loader, ApiModuleLoader):
            return False
        if self.base is not None or image.arch != arch.ARCH_AMD64:
            raise InvalidSample('Kernel reference already mapped or architecture mismatch')
        data = bytearray(image.regions[0].data)
        pe = pefile.PE(data=bytes(data), fast_load=True)
        legacy_end = (max(image.image_size, len(data)) + 4095) & ~4095
        if (legacy_end >= self.source_size or any(s['rva'] < legacy_end for s in self.code) or
                len({s['name'] for s in self.code}) != len(self.code)):
            raise InvalidSample('Kernel reference code overlaps generated API storage')
        header = pe.sections[-1].get_file_offset() + 40
        header_end = header + len(self.code) * 40
        if header_end > min(s.VirtualAddress for s in pe.sections):
            raise InvalidSample('Kernel reference section metadata exceeds header space')
        # Keep API execution stubs distinct from the authentic inspection view.
        for old in pe.sections:
            if old.Name.rstrip(b'\0') == b'.text':
                data[old.get_file_offset():old.get_file_offset()+8] = b'.emuapi\0'
        for old in image.sections:
            if old.name == '.text':
                old.name = '.emuapi'
        data.extend(bytes(self.source_size - len(data)))
        for index, section in enumerate(self.code):
            start, size = section['rva'], section['size']
            data[start:start+size] = section['data']
            struct.pack_into('<8sIIIIIIHHI', data, header + index*40,
                section['name'].encode('ascii'), size, start, size, start, 0, 0, 0, 0, 0x40000020)
            image.sections.append(SectionEntry(section['name'], start, size, PERM_MEM_READ))
        for field in self.guest_data:
            if (not 0 <= field['rva'] < field['rva']+field['size'] <= self.source_size or
                    any(s['rva'] <= field['rva'] < s['rva']+s['size'] for s in self.code)):
                raise InvalidSample('Guest unload metadata overlaps reference code')
            data[field['rva']:field['rva']+field['size']] = field['value'].to_bytes(field['size'], 'little')
        delta = (image.image_base - self.source_base) & 0xffffffffffffffff
        for block in getattr(self.pe, 'DIRECTORY_ENTRY_BASERELOC', ()):
            for entry in block.entries:
                if not entry.type:
                    continue
                target = next((s for s in self.code if s['rva'] <= entry.rva < s['rva']+s['size']), None)
                if target is not None:
                    if entry.type != 10 or entry.rva+8 > target['rva']+target['size']:
                        raise InvalidSample('Unsupported kernel reference code relocation')
                    value = struct.unpack_from('<Q', data, entry.rva)[0]
                    struct.pack_into('<Q', data, entry.rva, (value+delta) & 0xffffffffffffffff)
                    self.relocations += 1
        struct.pack_into('<H', data, pe.FILE_HEADER.get_field_absolute_offset('NumberOfSections'), len(image.sections))
        struct.pack_into('<I', data, pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfImage'), self.source_size)
        struct.pack_into('<I', data, pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfCode'),
            pe.OPTIONAL_HEADER.SizeOfCode + sum(s['size'] for s in self.code))
        alignment = pe.OPTIONAL_HEADER.FileAlignment
        struct.pack_into('<I', data, pe.OPTIONAL_HEADER.get_field_absolute_offset('SizeOfHeaders'),
            max(pe.OPTIONAL_HEADER.SizeOfHeaders, (header_end+alignment-1)//alignment*alignment))
        image.image_size = self.source_size
        image.regions[0].data = bytes(data)
        for section in self.code:
            section.pop('data')
        self.pe.close()
        self.pe = None
        self.base = image.image_base
        self.start, self.end = self.base+legacy_end, self.base+self.source_size
        return True

    def protect(self):
        self.kernel.mem_protect(self.start, self.end-self.start, PERM_MEM_NONE)
        for section in self.code:
            self.kernel.mem_protect(self.base+section['rva'], (section['size']+4095)&~4095, PERM_MEM_READ)
        # Native permissions are page-granular. A read hook rejects every byte
        # outside the explicitly modeled fields on each otherwise private page.
        for page in sorted({field['rva'] & ~4095 for field in self.guest_data}):
            self.kernel.mem_protect(self.base+page, 4096, PERM_MEM_READ)
            self.kernel.add_mem_read_hook(self.guard_guest_data_read,
                begin=self.base+page, end=self.base+page+4095)

    def guest_field(self, address, size):
        if self.base is None or size <= 0:
            return None
        return next((field for field in self.guest_data
            if self.base+field['rva'] <= address and address+size <= self.base+field['rva']+field['size']), None)

    def guard_guest_data_read(self, _facade, _access, address, size, _value):
        field = self.guest_field(address, size)
        if field is None:
            return self.kernel._stop_memory_fault('unmodeled_kernel_reference_read', address, 'read')
        self.guest_data_reads += 1
        if len(self.guest_data_tail) < 64:
            self.guest_data_tail.append({'name': field['name'], 'address': hex(address), 'size': size,
                'pc': hex(self.kernel.get_pc())})
        return True

    def describe(self, address, size=1):
        if self.start is None or size <= 0 or address >= self.end or address+size <= self.start:
            return None
        rva = max(address, self.start)-self.base
        code = next((s for s in self.code if s['rva'] <= rva < s['rva']+s['size']), None)
        name = (KNOWN_PRIVATE_SYMBOLS.get(rva) if self.identity['sha256'] == KNOWN_REFERENCE_SHA256 else None)
        exported = self.export_names_by_rva.get(rva)
        if exported:
            name = sorted(exported)[0]
        field = self.guest_field(address, 1)
        if field:
            name = field['name']
        return {'name': name or ('reference_code' if code else 'unmodeled_reference_data'),
            'kind': 'code' if code else 'data', 'rva': rva, 'exported': bool(exported),
            'offset': address-(self.base+(field['rva'] if field else rva if name else code['rva'] if code else self.start-self.base))}

    def record(self, item, access, address, size):
        row = {**item, 'access': access, 'address': hex(address), 'size': size}
        if len(self.denials) < 64:
            self.denials.append(row)
        else:
            self.omitted += 1

    def require_api_access(self, address, size, access):
        item = self.describe(address, size)
        if item is None:
            return
        if access == 'read' and any(self.base+s['rva'] <= address and address+size <= self.base+s['rva']+s['size'] for s in self.code):
            return
        if access == 'read' and self.guest_field(address, size):
            return
        self.record(item, access, address, size)
        raise ValueError(f"Unmodeled kernel reference {access}: {item['name']} at RVA {item['rva']:#x}")

    def report(self):
        return {**self.identity, 'enabled': self.base is not None, 'base': hex(self.base) if self.base else None,
            'source_image_size': self.source_size, 'relocations': self.relocations,
            'file_backed_named_code_exports': len(self.code_exports),
            'sections': [{k:v for k,v in s.items() if k != 'data'} for s in self.code],
            'permissions': 'r--',
            'other_reference_data': '--- except byte-guarded modeled guest unload globals' if self.guest_data else '---',
            'execution_allowed': False,
            'guest_unload_history': {'enabled': bool(self.guest_data), 'recorded_image_unloads': 0,
                'fields': self.guest_data, 'native_reads': self.guest_data_reads,
                'read_observations': self.guest_data_tail,
                'omitted_read_observations': max(0, self.guest_data_reads-len(self.guest_data_tail)),
                'scope': 'Fresh guest with no modeled image-unload operations: lazy history pointer NULL and index0. DriverUnload callback alone does not unload an image. No host history, invented unload records, other private fields or private function implementation.'},
            'denials': self.denials, 'omitted': self.omitted,
            'scope': 'Reference code inspection with ordinary APIs in generated stubs; no reference instructions execute. Only explicit guest unload-history fields may expose modeled empty-session state; all other private reference bytes remain inaccessible.'}

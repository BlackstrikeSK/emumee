"""Conservative PE classification before any guest execution."""

from __future__ import annotations

import hashlib
import struct
from dataclasses import asdict, dataclass
from pathlib import Path

import pefile


class InvalidSample(ValueError):
    pass


MSI_SIGNATURE = bytes.fromhex("d0cf11e0a1b11ae1")


@dataclass(frozen=True)
class SampleInfo:
    name: str
    sha256: str
    size: int
    architecture: str
    kind: str
    managed: bool
    subsystem: int
    imports: tuple[str, ...]

    def to_dict(self) -> dict:
        return asdict(self)


def inspect_pe_header(data: bytes, name: str = "sample.exe") -> SampleInfo:
    """Bounded parent-side check; detailed parsing happens in AppContainer."""
    if Path(name).suffix.lower() in {".msi", ".msp", ".mst"}:
        if len(data) < 512 or data[:8] != MSI_SIGNATURE:
            raise InvalidSample("Input is not a Windows Installer MSI database")
        return SampleInfo(name=Path(name).name, sha256=hashlib.sha256(data).hexdigest(),
                          size=len(data), architecture="container", kind="msi",
                          managed=False, subsystem=0, imports=())
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise InvalidSample("Input is not a PE file")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset > min(len(data) - 24, 1024 * 1024) or data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise InvalidSample("Invalid PE signature or header offset")
    machine, sections, _, _, _, optional_size, characteristics = struct.unpack_from(
        "<HHIIIHH", data, pe_offset + 4)
    if machine == 0x14C:
        architecture, magic, directory_offset = "x86", 0x10B, 96
    elif machine == 0x8664:
        architecture, magic, directory_offset = "x64", 0x20B, 112
    else:
        raise InvalidSample(f"Unsupported PE machine 0x{machine:04x}")
    optional_offset = pe_offset + 24
    if (sections == 0 or optional_size < directory_offset or
            optional_offset + optional_size > len(data) or
            struct.unpack_from("<H", data, optional_offset)[0] != magic):
        raise InvalidSample("Invalid or truncated PE optional header")
    subsystem = struct.unpack_from("<H", data, optional_offset + 68)[0]
    if subsystem == 1 or Path(name).suffix.lower() == ".sys":
        raise InvalidSample("Kernel drivers are outside the user-mode scope")
    clr_offset = optional_offset + directory_offset + 14 * 8
    managed = False
    if clr_offset + 8 <= optional_offset + optional_size:
        clr_rva, clr_size = struct.unpack_from("<II", data, clr_offset)
        managed = bool(clr_rva and clr_size)
    return SampleInfo(name=Path(name).name, sha256=hashlib.sha256(data).hexdigest(),
                      size=len(data), architecture=architecture,
                      kind="dll" if characteristics & 0x2000 else "exe",
                      managed=managed, subsystem=subsystem, imports=())


def inspect_pe(data: bytes, name: str = "sample.exe") -> SampleInfo:
    if len(data) < 128 or data[:2] != b"MZ":
        raise InvalidSample("Input is not a PE file")
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as exc:
        raise InvalidSample(f"Invalid PE file: {exc}") from exc
    machine = pe.FILE_HEADER.Machine
    if machine == 0x14C:
        architecture = "x86"
    elif machine == 0x8664:
        architecture = "x64"
    else:
        raise InvalidSample(f"Unsupported PE machine 0x{machine:04x}")
    characteristics = pe.FILE_HEADER.Characteristics
    kind = "dll" if characteristics & 0x2000 else "exe"
    subsystem = int(pe.OPTIONAL_HEADER.Subsystem)
    if subsystem == 1 or Path(name).suffix.lower() == ".sys":
        raise InvalidSample("Kernel drivers are outside the user-mode scope")
    directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    clr_dir = directories[14] if len(directories) > 14 else None
    managed = bool(clr_dir and clr_dir.VirtualAddress and clr_dir.Size)
    if not managed:
        image_size = int(pe.OPTIONAL_HEADER.SizeOfImage)
        entry_rva = int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        if image_size <= 0 or entry_rva >= image_size:
            raise InvalidSample("Native entry point lies outside the PE image")
        if len(directories) > 1:
            import_dir = directories[1]
            import_rva, import_size = int(import_dir.VirtualAddress), int(import_dir.Size)
            if ((not import_rva and import_size) or
                    (import_rva and (import_rva >= image_size or
                                     import_size > image_size - import_rva))):
                raise InvalidSample("Native import directory lies outside the PE image")
    imports: list[str] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        imports.append(entry.dll.decode("ascii", errors="replace"))
    return SampleInfo(
        name=Path(name).name,
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        architecture=architecture,
        kind=kind,
        managed=managed,
        subsystem=subsystem,
        imports=tuple(imports),
    )

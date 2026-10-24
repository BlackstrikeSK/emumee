"""Build four harmless submitted PEs for the pinned READ/NX reference view.

This only reads PE metadata and writes generated fixtures; it executes no input.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

import pefile

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from tests.fixtures.build_driver import build_driver

REFERENCE_SHA256 = "4b954aae4b18a231b2254c0989b1b6bcc55741a8ef90a350f036d09cd480cc99"
NT_BASE = 0xFFFFF80000400000
SUCCESS = 0x52534631
EXPORT = "ObFindHandleForObject"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    raw = args.reference.read_bytes()
    if hashlib.sha256(raw).hexdigest() != REFERENCE_SHA256:
        raise ValueError("Reference differs from the exact pinned kernel")
    pe = pefile.PE(data=raw)
    code = [s for s in pe.sections if s.Characteristics & 0x20000000 and s.SizeOfRawData]
    spans = [{"name": s.Name.rstrip(b"\0").decode("ascii"), "rva": s.VirtualAddress,
              "bytes": s.Misc_VirtualSize, "mapped_bytes": (s.Misc_VirtualSize + 4095) & ~4095}
             for s in code]
    exports = {s.name.decode("ascii"): s for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name}
    export = exports[EXPORT]
    if export.forwarder or not any(s.VirtualAddress <= export.address < s.VirtualAddress + s.Misc_VirtualSize for s in code):
        raise ValueError("Probe export is not file-backed code")
    delta = NT_BASE - pe.OPTIONAL_HEADER.ImageBase
    relocations = [e.rva for block in pe.DIRECTORY_ENTRY_BASERELOC for e in block.entries
                   if e.type == 10 and any(s.VirtualAddress <= e.rva and e.rva + 8 <= s.VirtualAddress + s.Misc_VirtualSize for s in code)]
    if not relocations:
        raise ValueError("Pinned reference has no file-backed code relocation")
    relocation = relocations[0]
    original_word = struct.unpack("<Q", pe.get_data(relocation, 8))[0]
    relocated_word = (original_word + delta) & ((1 << 64) - 1)
    private = next(s for s in pe.sections if s.Name.rstrip(b"\0") == b".data")
    if private.Characteristics & 0x20000000:
        raise ValueError("Private probe must be outside every code section")
    expected_byte = pe.get_data(export.address, 1)[0]
    if any(r <= export.address < r + 8 for r in relocations):
        raise ValueError("Probe byte unexpectedly requires relocation")
    args.destination.mkdir()
    cases = []
    for name, error in [("read", None), ("write", "WRITE_PROT"), ("fetch", "FETCH_PROT"), ("private-read", "READ_PROT")]:
        image = bytearray(build_driver(0x8664))
        image[0x200:0x400] = bytes(0x200)
        image[0x400:] = bytes(0x200)
        struct.pack_into("<IIIII", image, 0x400, 0x2080, 0, 0, 0x2060, 0x20A0)
        image[0x460:0x46D] = b"ntoskrnl.exe\0"
        for index, (rva, symbol) in enumerate([(0x20D0, EXPORT), (0x2100, "KeGetCurrentIrql")]):
            for table in [0x480, 0x4A0]:
                struct.pack_into("<Q", image, table + index * 8, rva)
            encoded = b"\0\0" + symbol.encode("ascii") + b"\0"
            start = rva - 0x2000 + 0x400
            image[start:start + len(encoded)] = encoded
        instructions = bytearray(b"\x48\x83\xec\x28")
        failures = []

        def emit(data: bytes) -> None:
            instructions.extend(data)

        def equal() -> None:
            emit(b"\x0f\x85")
            failures.append(len(instructions))
            emit(bytes(4))

        def load_iat(index: int) -> None:
            emit(b"\x48\x8b\x05" + struct.pack("<i", 0x20A0 + index * 8 - (0x1000 + len(instructions) + 7)))

        # The IAT is rebound from the actual generated ntoskrnl EAT. No test
        # oracle replaces guest API behavior or supplies a forged resolver.
        load_iat(0)
        emit(b"\x48\xba" + struct.pack("<Q", NT_BASE + export.address))
        emit(b"\x48\x39\xd0")
        equal()
        emit(b"\x48\x89\x44\x24\x20")
        # Also consume the actual guest EAT: walk bounded function-RVA slots
        # from the PE header and require the IAT target's authenticated RVA.
        emit(b"\x49\xbb" + struct.pack("<Q", NT_BASE))
        emit(b"\x41\x8b\x43\x3c\x4c\x01\xd8\x8b\x80\x88\x00\x00\x00\x4c\x01\xd8\x8b\x48\x14")
        emit(b"\x81\xf9\x00\x10\x00\x00\x0f\x87")
        failures.append(len(instructions))
        emit(bytes(4))
        emit(b"\x85\xc9\x0f\x84")
        failures.append(len(instructions))
        emit(bytes(4))
        emit(b"\x8b\x40\x1c\x4c\x01\xd8\x49\x89\xc2\xba" + struct.pack("<I", export.address))
        loop = len(instructions)
        emit(b"\x41\x39\x12\x0f\x84")
        found = len(instructions)
        emit(bytes(4))
        emit(b"\x49\x83\xc2\x04\xff\xc9\x0f\x85")
        emit(struct.pack("<i", loop - len(instructions) - 4))
        emit(b"\xe9")
        failures.append(len(instructions))
        emit(bytes(4))
        struct.pack_into("<i", instructions, found, len(instructions) - found - 4)
        emit(b"\x48\x8b\x44\x24\x20\x0f\xb6\x10\x81\xfa" + struct.pack("<I", expected_byte))
        equal()
        emit(b"\x48\xb8" + struct.pack("<Q", NT_BASE + relocation) + b"\x48\x8b\x00")
        emit(b"\x48\xba" + struct.pack("<Q", relocated_word) + b"\x48\x39\xd0")
        equal()
        # A modeled gate still runs and reports the initialized PASSIVE_LEVEL.
        emit(b"\xff\x15" + struct.pack("<i", 0x20A8 - (0x1000 + len(instructions) + 6)))
        emit(b"\x85\xc0")
        equal()
        emit(b"\x48\x8b\x44\x24\x20")
        fault_rva = None
        fault_address = None
        if name == "write":
            fault_rva = 0x1000 + len(instructions)
            fault_address = NT_BASE + export.address
            emit(b"\xc6\x00\x00")
        elif name == "fetch":
            fault_rva = 0x1000 + len(instructions)
            fault_address = NT_BASE + export.address
            emit(b"\xff\xd0")
        elif name == "private-read":
            emit(b"\x48\xb8" + struct.pack("<Q", NT_BASE + private.VirtualAddress))
            fault_rva = 0x1000 + len(instructions)
            fault_address = NT_BASE + private.VirtualAddress
            emit(b"\x0f\xb6\x00")
        emit(b"\xb8" + struct.pack("<I", SUCCESS) + b"\x48\x83\xc4\x28\xc3")
        failed = len(instructions)
        emit(b"\xb8\x0d\x00\x00\xc0\x48\x83\xc4\x28\xc3")
        for offset in failures:
            struct.pack_into("<i", instructions, offset, failed - offset - 4)
        if len(instructions) > 0x200:
            raise ValueError("Generated control exceeds its text section")
        image[0x200:0x200 + len(instructions)] = instructions
        filename = f"reference-{name}.sys"
        (args.destination / filename).write_bytes(image)
        cases.append({"name": name, "filename": filename, "sha256": hashlib.sha256(image).hexdigest(),
                      "error": error, "fault_rva": fault_rva, "fault_address": fault_address})
    document = {"schema": 1, "scope": "Harmless generated PE controls; no supplied driver execution or unpacking claim",
                "reference_sha256": REFERENCE_SHA256, "target_base": NT_BASE,
                "reference_image_size": pe.OPTIONAL_HEADER.SizeOfImage,
                "export": EXPORT, "export_rva": export.address, "expected_byte": expected_byte,
                "relocation_rva": relocation, "relocated_word": relocated_word,
                "private_rva": private.VirtualAddress, "success": SUCCESS,
                "reference_sections": spans, "cases": cases}
    (args.destination / "generated-controls.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

"""Generate harmless PEs that test the pinned fresh-session unload fields."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from tests.fixtures.build_driver import build_driver

REFERENCE_SHA256 = "4b954aae4b18a231b2254c0989b1b6bcc55741a8ef90a350f036d09cd480cc99"
PDB_SHA256 = "5eea0257091c91a86da4a1633248723eb07f08f6d2718447ed4c0a95706790f5"
BASE = 0xFFFFF80000400000
LAST = 0xC13090
POINTER = 0xC13098
BUFFER = 0x2180
SUCCESS = 0x554C4431


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    if hashlib.sha256(args.reference.read_bytes()).hexdigest() != REFERENCE_SHA256:
        raise ValueError("Only the exact pinned kernel reference is allowed")
    args.destination.mkdir()
    cases = []
    for name, access, address, size, error in [
        ("read", None, None, None, None),
        ("before", "native_read", BASE + LAST - 1, 1, "outside modeled unload-history fields"),
        ("padding", "native_read", BASE + LAST + 4, 1, "outside modeled unload-history fields"),
        ("cross", "native_read", BASE + LAST + 2, 8, "outside modeled unload-history fields"),
        ("api-read", "api_read", BASE + LAST + 4, 1, "Guest unload-history field policy refuses api_read"),
        ("write", "write", BASE + POINTER, 1, "WRITE_PROT"),
        ("fetch", "execute", BASE + POINTER, 1, "FETCH_PROT"),
    ]:
        image = bytearray(build_driver(0x8664))
        image[0x200:0x400] = bytes(0x200)
        image[0x400:] = bytes(0x200)
        struct.pack_into("<IIIII", image, 0x400, 0x2080, 0, 0, 0x2060, 0x20A0)
        image[0x460:0x46D] = b"ntoskrnl.exe\0"
        for index, (rva, symbol) in enumerate([(0x20D0, "KeGetCurrentIrql"), (0x2100, "RtlCopyMemory")]):
            for table in [0x480, 0x4A0]:
                struct.pack_into("<Q", image, table + index * 8, rva)
            encoded = b"\0\0" + symbol.encode("ascii") + b"\0"
            start = rva - 0x2000 + 0x400
            image[start:start + len(encoded)] = encoded
        image[0x580:0x58C] = bytes([0x55]) * 12
        code = bytearray(b"\x48\x83\xec\x28")
        failures = []

        def emit(data: bytes) -> None:
            code.extend(data)

        def require_zero(wide: bool = False) -> None:
            emit((b"\x48" if wide else b"") + b"\x85\xc0\x0f\x85")
            failures.append(len(code))
            emit(bytes(4))

        def call(index: int) -> None:
            emit(b"\xff\x15" + struct.pack("<i", 0x20A0 + index * 8 - (0x1000 + len(code) + 6)))

        def copy(source: int, destination_rva: int, count: int) -> int:
            emit(b"\x48\x8d\x0d" + struct.pack("<i", destination_rva - (0x1000 + len(code) + 7)))
            emit(b"\x48\xba" + struct.pack("<Q", source))
            emit(b"\x41\xb8" + struct.pack("<I", count))
            fault_rva = 0x1000 + len(code)
            call(1)
            return fault_rva

        # Every case first proves both permitted native loads and ordinary
        # modeled API execution; refusal cannot pass by blanket page denial.
        emit(b"\x48\xb8" + struct.pack("<Q", BASE + POINTER) + b"\x48\x8b\x00")
        require_zero(True)
        emit(b"\x48\xb8" + struct.pack("<Q", BASE + LAST) + b"\x8b\x00")
        require_zero()
        call(0)
        require_zero()
        fault_rva = None
        if name == "read":
            copy(BASE + POINTER, BUFFER, 8)
            copy(BASE + LAST, BUFFER + 8, 4)
            emit(b"\x48\x8b\x05" + struct.pack("<i", BUFFER - (0x1000 + len(code) + 7)))
            require_zero(True)
            emit(b"\x8b\x05" + struct.pack("<i", BUFFER + 8 - (0x1000 + len(code) + 6)))
            require_zero()
        elif name == "api-read":
            fault_rva = copy(address, BUFFER, size)
        else:
            emit(b"\x48\xb8" + struct.pack("<Q", address))
            fault_rva = 0x1000 + len(code)
            if name == "write":
                emit(b"\xc6\x00\x00")
            elif name == "fetch":
                emit(b"\xff\xd0")
            else:
                emit(b"\x48\x8b\x00" if size == 8 else b"\x0f\xb6\x00")
        emit(b"\xb8" + struct.pack("<I", SUCCESS) + b"\x48\x83\xc4\x28\xc3")
        failed = len(code)
        emit(b"\xb8\x0d\x00\x00\xc0\x48\x83\xc4\x28\xc3")
        for offset in failures:
            struct.pack_into("<i", code, offset, failed - offset - 4)
        if len(code) > 0x200:
            raise ValueError("Generated unload probe exceeds its text page")
        image[0x200:0x200 + len(code)] = code
        filename = f"unload-{name}.sys"
        (args.destination / filename).write_bytes(image)
        cases.append({"name": name, "filename": filename, "sha256": hashlib.sha256(image).hexdigest(),
                      "access": access, "address": address, "size": size, "error": error,
                      "fault_rva": fault_rva, "api_calls": 3 if name == "read" else 2 if name == "api-read" else 1})
    document = {"schema": 1, "reference_sha256": REFERENCE_SHA256, "pdb_sha256": PDB_SHA256,
                "target_base": BASE, "success": SUCCESS, "buffer_rva": BUFFER, "buffer_bytes": 12,
                "fields": [{"name": "MmUnloadedDrivers", "rva": POINTER, "address": BASE + POINTER, "width": 8, "value": 0},
                           {"name": "MmLastUnloadedDriver", "rva": LAST, "address": BASE + LAST, "width": 4, "value": 0}],
                "scope": "Harmless generated fresh-session field controls; no host unload state or supplied-driver execution",
                "cases": cases}
    (args.destination / "generated-controls.json").write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

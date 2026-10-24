"""Generate harmless kernel PEs; never install or load these on Windows."""

import struct
from pathlib import Path

from tests.fixtures.build_native import build


def build_driver(machine, mode="success"):
    x64 = machine == 0x8664
    base = 0x140000000 if x64 else 0x400000
    buf = bytearray(build(machine))
    struct.pack_into("<H", buf, 0x98 + 68, 1)  # IMAGE_SUBSYSTEM_NATIVE
    sh = 0x98 + (0xF0 if x64 else 0xE0)
    struct.pack_into("<I", buf, sh + 8, 0x200)
    struct.pack_into("<I", buf, sh + 48, 0x200)
    buf[0x400:] = bytes(0x200)
    struct.pack_into("<IIIII", buf, 0x400, 0x2080, 0, 0, 0x2060, 0x20A0)
    buf[0x460:0x46D] = b"ntoskrnl.exe\0"
    names = [(0x20D0, b"IoCreateDevice"), (0x20F0, b"IoDeleteDevice"),
             (0x2110, b"ExAllocatePoolWithTag"), (0x2140, b"MissingEmumeeKernelApi")]
    fmt, width = ("<Q", 8) if x64 else ("<I", 4)
    for index, (rva, name) in enumerate(names):
        struct.pack_into(fmt, buf, 0x480 + width * index, rva)
        struct.pack_into(fmt, buf, 0x4A0 + width * index, rva)
        start = 0x400 + rva - 0x2000
        buf[start:start + len(name) + 3] = b"\0\0" + name + b"\0"
    # Three imported routines in normal cases; unknown API only when requested.
    if mode != "unknown":
        struct.pack_into(fmt, buf, 0x480 + width * 3, 0)
        struct.pack_into(fmt, buf, 0x4A0 + width * 3, 0)
    code = bytearray()
    failures = []

    def require_nonzero(test):
        code.extend(test + b"\x0f\x84")
        failures.append(len(code))
        code.extend(bytes(4))

    def call(index):
        if x64:
            code.extend(b"\xff\x15" + struct.pack("<i", 0x20A0 + width * index - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + 0x20A0 + width * index))

    if mode == "loop":
        code.extend(b"\xeb\xfe")
    elif mode == "fault":
        code.extend(b"\x0f\x0b")
    elif mode == "unknown":
        call(3)
        code.extend(b"\xc3" if x64 else b"\xc2\x08\x00")
    elif x64:
        code.extend(b"\x53\x48\x83\xec\x40\x48\x89\xcb")  # preserve driver
        require_nonzero(b"\x48\x85\xc9")
        require_nonzero(b"\x48\x85\xd2")
        require_nonzero(b"\x66\x83\x3a\x00")  # registry path has a length
        # DriverUnload at image RVA 0x1180; a dispatch routine is recorded too.
        code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x1180))
        code.extend(b"\x48\x89\x43\x68\x48\x89\x43\x70")
        if mode == "failure":
            code.extend(b"\xb8\x01\x00\x00\xc0")
        else:
            code.extend(b"\xba\x10\x00\x00\x00\x45\x31\xc0\x41\xb9\x22\x00\x00\x00")
            code.extend(b"\x48\xc7\x44\x24\x20\x00\x00\x00\x00")
            code.extend(b"\x48\xc7\x44\x24\x28\x00\x00\x00\x00")
            code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x21C0) + b"\x48\x89\x44\x24\x30")
            call(0)
            code.extend(b"\x31\xc9\xba\x10\x00\x00\x00\x41\xb8TEST")
            call(2)
            code.extend(b"\xc7\x00EMU!\x31\xc0")
        code.extend(b"\x48\x83\xc4\x40\x5b\xc3")
        failed_at = len(code)
        code.extend(b"\xb8\x0d\x00\x00\xc0\x48\x83\xc4\x40\x5b\xc3")
    else:
        code.extend(b"\x53\x8b\x5c\x24\x08")
        require_nonzero(b"\x85\xdb")
        code.extend(b"\x8b\x44\x24\x0c")
        require_nonzero(b"\x85\xc0")
        require_nonzero(b"\x66\x83\x38\x00")
        code.extend(b"\xb8" + struct.pack("<I", base + 0x1180))
        code.extend(b"\x89\x43\x34\x89\x43\x38")
        if mode == "failure":
            code.extend(b"\xb8\x01\x00\x00\xc0")
        else:
            code.extend(b"\x68" + struct.pack("<I", base + 0x21C0))
            code.extend(b"\x6a\x00\x6a\x00\x6a\x22\x6a\x00\x6a\x10\x53")
            call(0)
            code.extend(b"\x68TEST\x6a\x10\x6a\x00")
            call(2)
            code.extend(b"\xc7\x00EMU!\x31\xc0")
        code.extend(b"\x5b\xc2\x08\x00")
        failed_at = len(code)
        code.extend(b"\xb8\x0d\x00\x00\xc0\x5b\xc2\x08\x00")
    for location in failures:
        struct.pack_into("<i", code, location, failed_at - (location + 4))
    buf[0x200:0x200 + len(code)] = code
    # Separate unload body, checks a shared instruction budget and faults too.
    if mode == "unload_loop":
        unload = b"\xeb\xfe"
    elif mode == "unload_fault":
        unload = b"\x0f\x0b"
    elif x64:
        unload = (b"\x48\x83\xec\x28\x48\x8b\x0d" +
                  struct.pack("<i", 0x21C0 - (0x1180 + 11)) +
                  b"\xff\x15" + struct.pack("<i", 0x20A8 - (0x1180 + 17)) +
                  b"\x48\x83\xc4\x28\xc3")
    else:
        unload = (b"\xff\x35" + struct.pack("<I", base + 0x21C0) +
                  b"\xff\x15" + struct.pack("<I", base + 0x20A4) + b"\xc2\x04\x00")
    buf[0x380:0x380 + len(unload)] = unload
    return bytes(buf)


def build_driver_file_probe(machine, guest_path):
    """Ask the modeled ZwCreateFile to create an otherwise absent host path."""
    x64 = machine == 0x8664
    base = 0x140000000 if x64 else 0x400000
    buf = bytearray(build_driver(machine))
    buf.extend(bytes(0xE00))
    sh = 0x98 + (0xF0 if x64 else 0xE0) + 40
    struct.pack_into("<I", buf, sh + 8, 0x1000)
    struct.pack_into("<I", buf, sh + 16, 0x1000)
    buf[0x480:0x4C0] = bytes(0x40)
    for offset in (0x480, 0x4A0):
        struct.pack_into("<Q" if x64 else "<I", buf, offset, 0x20D0)
    buf[0x4D0:0x4D0 + 15] = b"\0\0ZwCreateFile\0"
    name = ("\\??\\" + guest_path).encode("utf-16le")
    if len(name) > 2000:
        raise ValueError("Probe path is too long")
    buf[0x800:0x800 + len(name) + 2] = name + b"\0\0"
    if x64:
        struct.pack_into("<HHIQ", buf, 0x640, len(name), len(name) + 2, 0, base + 0x2400)
        struct.pack_into("<QQQIIQQ", buf, 0x660, 48, 0, base + 0x2240, 0x40, 0, 0, 0)
        code = bytearray(b"\x48\x83\xec\x68")
        for offset, value in ((0x20, 0), (0x28, 0x80), (0x30, 7), (0x38, 5),
                              (0x40, 0x20), (0x48, 0), (0x50, 0)):
            code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
        for opcode, rva in ((b"\x48\xb9", 0x2200), (b"\x49\xb8", 0x2260), (b"\x49\xb9", 0x2210)):
            code.extend(opcode + struct.pack("<Q", base + rva))
        code.extend(b"\xba\x00\x00\x00\x40")
        code.extend(b"\xff\x15" + struct.pack("<i", 0x20A0 - (0x1000 + len(code) + 6)))
        code.extend(b"\x48\x83\xc4\x68\xc3")
    else:
        struct.pack_into("<HHI", buf, 0x640, len(name), len(name) + 2, base + 0x2400)
        struct.pack_into("<IIIIII", buf, 0x660, 24, 0, base + 0x2240, 0x40, 0, 0)
        code = bytearray()
        for value in (0, 0, 0x20, 5, 7, 0x80, 0, base + 0x2210, base + 0x2260,
                      0x40000000, base + 0x2200):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\xff\x15" + struct.pack("<I", base + 0x20A0) + b"\xc2\x08\x00")
    buf[0x200:0x400] = bytes(0x200)
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def main():
    root = Path(__file__).parent
    for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
        for mode in ("success", "failure", "loop", "fault", "unknown", "unload_loop", "unload_fault"):
            (root / f"driver_{mode}_{arch}.sys").write_bytes(build_driver(machine, mode))


if __name__ == "__main__":
    main()

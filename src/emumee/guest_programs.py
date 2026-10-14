"""Small, deterministic Windows PE utilities that execute only in the guest."""

from __future__ import annotations

import struct


def hostname_exe(is_x64: bool) -> bytes:
    """Build a PE that calls GetComputerNameA and writes it to guest stdout."""
    return _identity_exe(is_x64, "hostname", "")


def whoami_exe(is_x64: bool, hostname: str) -> bytes:
    """Build a PE that prints the local computer and guest USERNAME."""
    return _identity_exe(is_x64, "whoami", hostname)


def _identity_exe(is_x64: bool, kind: str, hostname: str) -> bytes:
    if kind not in ("hostname", "whoami"):
        raise ValueError("unknown guest utility")
    prefix = ((hostname + "\\").encode("cp437", errors="replace")
              if kind == "whoami" else b"")
    if len(prefix) > 80:
        raise ValueError("guest identity prefix exceeds buffer")
    machine = 0x8664 if is_x64 else 0x14C
    base = 0x190000000 if is_x64 else 0x600000
    optional_size = 0xF0 if is_x64 else 0xE0
    buf = bytearray(0x800)
    buf[:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", buf, 0x84, machine, 2, 0, 0, 0,
                     optional_size, 0x0022 if is_x64 else 0x0102)
    opt = 0x98
    struct.pack_into("<HBBIII", buf, opt, 0x20B if is_x64 else 0x10B,
                     14, 0, 0x200, 0x400, 0)
    struct.pack_into("<II", buf, opt + 16, 0x1000, 0x1000)
    if is_x64:
        struct.pack_into("<Q", buf, opt + 24, base)
    else:
        struct.pack_into("<II", buf, opt + 24, 0x2000, base)
    struct.pack_into("<II", buf, opt + 32, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", buf, opt + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<III", buf, opt + 56, 0x3000, 0x200, 0)
    struct.pack_into("<H", buf, opt + 68, 3)
    if is_x64:
        struct.pack_into("<QQQQII", buf, opt + 72,
                         0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
        dd = opt + 112
    else:
        struct.pack_into("<IIIIII", buf, opt + 72,
                         0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
        dd = opt + 96
    struct.pack_into("<II", buf, dd + 8, 0x2000, 0x80)
    sh = opt + optional_size
    buf[sh:sh + 8] = b".text\0\0\0"
    struct.pack_into("<IIIIIIHHI", buf, sh + 8,
                     0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    sh += 40
    buf[sh:sh + 8] = b".idata\0\0"
    struct.pack_into("<IIIIIIHHI", buf, sh + 8,
                     0x400, 0x2000, 0x400, 0x400, 0, 0, 0, 0, 0xC0000040)

    # Exact guest imports; whoami uses Advapi32's token-backed user name.
    struct.pack_into("<IIIII", buf, 0x400, 0x2040, 0, 0, 0x20C0, 0x2080)
    buf[0x4C0:0x4CD] = b"KERNEL32.dll\0"
    step = 8 if is_x64 else 4
    name_at = 0x500
    if kind == "hostname":
        imports = ((b"GetComputerNameA", 0x2040, 0x2080),
                   (b"GetStdHandle", 0x2040 + step, 0x2080 + step),
                   (b"WriteFile", 0x2040 + 2 * step, 0x2080 + 2 * step),
                   (b"ExitProcess", 0x2040 + 3 * step, 0x2080 + 3 * step))
        iat_rvas = [0x2080 + index * step for index in range(4)]
    else:
        struct.pack_into("<IIIII", buf, 0x414, 0x2060, 0, 0, 0x20D0, 0x20A0)
        buf[0x4D0:0x4DD] = b"ADVAPI32.dll\0"
        imports = ((b"GetStdHandle", 0x2040, 0x2080),
                   (b"WriteFile", 0x2040 + step, 0x2080 + step),
                   (b"ExitProcess", 0x2040 + 2 * step, 0x2080 + 2 * step),
                   (b"GetUserNameA", 0x2060, 0x20A0))
        iat_rvas = [0x20A0, 0x2080, 0x2080 + step, 0x2080 + 2 * step]
    for name, int_rva, iat_rva in imports:
        rva = 0x2000 + name_at - 0x400
        struct.pack_into("<Q" if is_x64 else "<I", buf, 0x400 + int_rva - 0x2000, rva)
        struct.pack_into("<Q" if is_x64 else "<I", buf, 0x400 + iat_rva - 0x2000, rva)
        entry = b"\0\0" + name + b"\0"
        buf[name_at:name_at + len(entry)] = entry
        name_at += (len(entry) + 1) & ~1
    struct.pack_into("<I", buf, 0x700, 128 - len(prefix))
    if kind == "whoami":
        buf[0x600:0x600 + len(prefix)] = prefix

    code = bytearray()
    def call(index: int) -> None:
        iat = iat_rvas[index]
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", iat - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + iat))

    if is_x64:
        code.extend(b"\x48\x83\xec\x38")
        if kind == "hostname":
            code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2200))
            code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x2300))
        else:
            code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2200 + len(prefix)))
            code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x2300))
        call(0)
        code.extend(b"\x85\xc0\x0f\x84\0\0\0\0")
        fail_jump = len(code) - 4
        if kind == "whoami":
            code.extend(b"\x49\xba" + struct.pack("<Q", base + 0x2300) +
                        b"\x41\x8b\x02")
            code.extend(b"\x83\xc0" + bytes([len(prefix) - 1]))
            code.extend(b"\x41\x89\x02")
        code.extend(b"\xb9\xf5\xff\xff\xff")
        call(1)
        code.extend(b"\x48\x89\xc1")
        code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x2200))
        code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x2300) + b"\x45\x8b\x00")
        code.extend(b"\x49\xb9" + struct.pack("<Q", base + 0x2304))
        code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
        call(2)
        code.extend(b"\x31\xc9")
        call(3)
        fail_at = len(code)
        code.extend(b"\xb9\x01\0\0\0")
        call(3)
    else:
        if kind == "hostname":
            code.extend(b"\x68" + struct.pack("<I", base + 0x2300))
            code.extend(b"\x68" + struct.pack("<I", base + 0x2200))
        else:
            code.extend(b"\x68" + struct.pack("<I", base + 0x2300))
            code.extend(b"\x68" + struct.pack("<I", base + 0x2200 + len(prefix)))
        call(0)
        code.extend(b"\x85\xc0\x0f\x84\0\0\0\0")
        fail_jump = len(code) - 4
        if kind == "whoami":
            code.extend(b"\xa1" + struct.pack("<I", base + 0x2300))
            code.extend(b"\x83\xc0" + bytes([len(prefix) - 1]))
            code.extend(b"\xa3" + struct.pack("<I", base + 0x2300))
        code.extend(b"\x68\xf5\xff\xff\xff")
        call(1)
        code.extend(b"\x89\xc3\x6a\0")
        code.extend(b"\x68" + struct.pack("<I", base + 0x2304))
        code.extend(b"\xff\x35" + struct.pack("<I", base + 0x2300))
        code.extend(b"\x68" + struct.pack("<I", base + 0x2200) + b"\x53")
        call(2)
        code.extend(b"\x6a\0")
        call(3)
        fail_at = len(code)
        code.extend(b"\x6a\x01")
        call(3)
    code.extend(b"\xc3")
    struct.pack_into("<i", code, fail_jump, fail_at - (fail_jump + 4))
    if len(code) > 0x200:
        raise ValueError("guest utility entry exceeds PE text section")
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)

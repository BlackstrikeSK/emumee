"""Create harmless x86/x64 PE fixtures that call ExitProcess(0)."""

from __future__ import annotations

import struct
from pathlib import Path

API_PRIVATE_MAP_ADDRESS = 0x30000000


def build(machine: int, dll: bool = False) -> bytes:
    is_x64 = machine == 0x8664
    optional_size = 0xF0 if is_x64 else 0xE0
    image_base = (0x180000000 if dll else 0x140000000) if is_x64 else (0x50000000 if dll else 0x400000)
    buf = bytearray(0x600)
    buf[:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\0\0"
    characteristics = 0x0022 if is_x64 else 0x0102
    if dll:
        characteristics |= 0x2000
    struct.pack_into("<HHIIIHH", buf, 0x84, machine, 2, 0, 0, 0, optional_size,
                     characteristics)
    opt = 0x98
    struct.pack_into("<HBBIII", buf, opt, 0x20B if is_x64 else 0x10B, 14, 0, 0x200, 0x200, 0)
    struct.pack_into("<I", buf, opt + 16, 0x1000)
    struct.pack_into("<I", buf, opt + 20, 0x1000)
    if is_x64:
        struct.pack_into("<Q", buf, opt + 24, image_base)
    else:
        struct.pack_into("<I", buf, opt + 24, 0x2000)
        struct.pack_into("<I", buf, opt + 28, image_base)
    struct.pack_into("<II", buf, opt + 32, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", buf, opt + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<III", buf, opt + 56, 0x3000, 0x200, 0)
    struct.pack_into("<H", buf, opt + 68, 3)
    if is_x64:
        struct.pack_into("<QQQQII", buf, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
        dd = opt + 112
    else:
        struct.pack_into("<IIIIII", buf, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
        dd = opt + 96
    struct.pack_into("<II", buf, dd + 8, 0x2000, 0x28)
    sh = opt + optional_size
    buf[sh:sh + 8] = b".text\0\0\0"
    struct.pack_into("<IIIIIIHHI", buf, sh + 8, 0x100, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)
    sh += 40
    buf[sh:sh + 8] = b".idata\0\0"
    struct.pack_into("<IIIIIIHHI", buf, sh + 8, 0x100, 0x2000, 0x200, 0x400, 0, 0, 0, 0, 0xC0000040)
    if dll:
        marker_rva = 0x21E0
        if is_x64:
            disp_init = marker_rva - (0x1000 + 7)
            disp_export = marker_rva - (0x1010 + 7)
            init_code = (b"\xc6\x05" + struct.pack("<i", disp_init) + b"\x01"
                         + b"\xb8\x01\x00\x00\x00\xc3")
            export_code = (b"\x80\x3d" + struct.pack("<i", disp_export) + b"\x01"
                           + b"\x75\x06\xb8\x2a\x00\x00\x00\xc3\x31\xc0\xc3")
        else:
            marker = image_base + marker_rva
            init_code = (b"\xc6\x05" + struct.pack("<I", marker) + b"\x01"
                         + b"\xb8\x01\x00\x00\x00\xc2\x0c\x00")
            export_code = (b"\x80\x3d" + struct.pack("<I", marker) + b"\x01"
                           + b"\x75\x06\xb8\x2a\x00\x00\x00\xc3\x31\xc0\xc3")
        buf[0x200:0x200 + len(init_code)] = init_code
        buf[0x210:0x210 + len(export_code)] = export_code
        struct.pack_into("<II", buf, dd, 0x2100, 0x80)
        struct.pack_into("<IIHHIIIIIII", buf, 0x500, 0, 0, 0, 0,
                         0x2150, 1, 1, 1, 0x2130, 0x2134, 0x2138)
        struct.pack_into("<IIIH", buf, 0x530, 0x1010, 0x2170, 0, 0)
        dll_name = b"companion_x64.dll\0" if is_x64 else b"companion_x86.dll\0"
        buf[0x550:0x550 + len(dll_name)] = dll_name
        buf[0x570:0x57B] = b"ProbeValue\0"
    elif is_x64:
        disp = 0x2040 - (0x1000 + 9)
        buf[0x200:0x20A] = b"\x48\x31\xc9\xff\x15" + struct.pack("<i", disp) + b"\xc3"
    else:
        buf[0x200:0x209] = b"\x6a\x00\xff\x15" + struct.pack("<I", image_base + 0x2040) + b"\xc3"
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x2060, 0x2040)
    fmt = "<Q" if is_x64 else "<I"
    struct.pack_into(fmt, buf, 0x430, 0x2070)
    struct.pack_into(fmt, buf, 0x440, 0x2070)
    buf[0x460:0x46D] = b"KERNEL32.dll\0"
    buf[0x470:0x47E] = b"\0\0ExitProcess\0"
    return bytes(buf)


def build_crt_initializer(machine: int) -> bytes:
    """Call msvcrt._initterm; its guest callback marks memory before return."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf[0x460:0x46D] = b"msvcrt.dll\0\0\0"
    buf[0x470:0x47E] = b"\0\0_initterm\0\0\0"
    callback = base + 0x1100
    array = base + 0x2180
    end = array + (8 if is_x64 else 4)
    struct.pack_into("<Q" if is_x64 else "<I", buf, 0x580, callback)
    if is_x64:
        code = bytearray(b"\x48\x83\xec\x28\x48\xb9" + struct.pack("<Q", array) +
                         b"\x48\xba" + struct.pack("<Q", end))
        code.extend(b"\xff\x15" + struct.pack("<i", 0x2040 - (0x1000 + len(code) + 6)))
        code.extend(b"\x80\x3d" + struct.pack("<i", 0x21E0 - (0x1000 + len(code) + 7)) +
                    b"\x01\x0f\x94\xc0\x0f\xb6\xc0\x48\x83\xc4\x28\xc3")
        callback_code = (b"\xc6\x05" + struct.pack("<i", 0x21E0 - (0x1100 + 7)) +
                         b"\x01\xc3")
    else:
        code = bytearray(b"\x68" + struct.pack("<I", end) +
                         b"\x68" + struct.pack("<I", array) +
                         b"\xff\x15" + struct.pack("<I", base + 0x2040) +
                         b"\x83\xc4\x08\x80\x3d" +
                         struct.pack("<I", base + 0x21E0) +
                         b"\x01\x0f\x94\xc0\x0f\xb6\xc0\xc3")
        callback_code = b"\xc6\x05" + struct.pack("<I", base + 0x21E0) + b"\x01\xc3"
    buf[0x200:0x200 + len(code)] = code
    buf[0x300:0x300 + len(callback_code)] = callback_code
    return bytes(buf)


def build_crt_args(machine: int, *, wide: bool) -> bytes:
    """Call a CRT mainargs export and verify guest argc and x86 stack cleanup."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf[0x460:0x46D] = b"msvcrt.dll\0\0\0"
    export = b"__wgetmainargs" if wide else b"__getmainargs"
    buf[0x470:0x490] = (b"\0\0" + export + b"\0").ljust(0x20, b"\0")
    argc, argv, env, startup = (base + rva for rva in (0x21A0, 0x21A8, 0x21B0, 0x21B8))
    code = bytearray()
    if is_x64:
        code.extend(b"\x48\x83\xec\x38\x48\xb9" + struct.pack("<Q", argc) +
                    b"\x48\xba" + struct.pack("<Q", argv) +
                    b"\x49\xb8" + struct.pack("<Q", env) +
                    b"\x45\x31\xc9\x48\xb8" + struct.pack("<Q", startup) +
                    b"\x48\x89\x44\x24\x20")
        code.extend(b"\xff\x15" + struct.pack("<i", 0x2040 - (0x1000 + len(code) + 6)))
        code.extend(b"\x83\x3d" + struct.pack("<i", 0x21A0 - (0x1000 + len(code) + 7)) +
                    b"\x01\x0f\x94\xc0\x0f\xb6\xc0\x48\x83\xc4\x38\xc3")
    else:
        code.extend(b"\x68" + struct.pack("<I", startup) + b"\x6a\0" +
                    b"\x68" + struct.pack("<I", env) +
                    b"\x68" + struct.pack("<I", argv) +
                    b"\x68" + struct.pack("<I", argc) +
                    b"\xff\x15" + struct.pack("<I", base + 0x2040) +
                    b"\x83\xc4\x14\x83\x3d" + struct.pack("<I", argc) +
                    b"\x01\x0f\x94\xc0\x0f\xb6\xc0\xc3")
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_crt_wide_args(machine: int) -> bytes:
    return build_crt_args(machine, wide=True)


def build_environment_block_probe(machine: int, *, wide: bool) -> bytes:
    """Call the environment block API from guest CPU and check its pointer."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    export = b"GetEnvironmentStringsW" if wide else b"GetEnvironmentStringsA"
    buf[0x470:0x490] = (b"\0\0" + export + b"\0").ljust(0x20, b"\0")
    if is_x64:
        code = (b"\x48\x83\xec\x28\xff\x15" +
                struct.pack("<i", 0x2040 - (0x1000 + 10)) +
                b"\x48\x85\xc0\x0f\x95\xc0\x0f\xb6\xc0\x48\x83\xc4\x28\xc3")
    else:
        code = (b"\xff\x15" + struct.pack("<I", base + 0x2040) +
                b"\x85\xc0\x0f\x95\xc0\x0f\xb6\xc0\xc3")
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_acrt_stream_probe(machine: int) -> bytes:
    """Dereference the guest FILE pointer returned by ucrtbase."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf[0x460:0x46D] = b"ucrtbase.dll\0"
    buf[0x470:0x490] = (b"\0\0__acrt_iob_func\0").ljust(0x20, b"\0")
    if is_x64:
        code = (b"\x48\x83\xec\x28\xb9\x01\0\0\0\xff\x15" +
                struct.pack("<i", 0x2040 - (0x1000 + 15)) +
                b"\x0f\xb6\x00\xff\xc0\x48\x83\xc4\x28\xc3")
    else:
        code = (b"\x6a\x01\xff\x15" + struct.pack("<I", base + 0x2040) +
                b"\x83\xc4\x04\x0f\xb6\x00\xff\xc0\xc3")
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_crt_error_initializer(machine: int) -> bytes:
    """_initterm_e must stop at a nonzero initializer result."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    width = 8 if is_x64 else 4
    buf = bytearray(build(machine))
    buf[0x460:0x46D] = b"msvcrt.dll\0\0\0"
    buf[0x470:0x490] = (b"\0\0_initterm_e\0").ljust(0x20, b"\0")
    array = base + 0x2180
    for index, rva in enumerate((0x1100, 0x1110)):
        struct.pack_into("<Q" if is_x64 else "<I", buf,
                         0x580 + index * width, base + rva)
    end = array + 2 * width
    code = bytearray()
    if is_x64:
        code.extend(b"\x48\x83\xec\x28\x48\xb9" + struct.pack("<Q", array) +
                    b"\x48\xba" + struct.pack("<Q", end))
        code.extend(b"\xff\x15" + struct.pack("<i", 0x2040 - (0x1000 + len(code) + 6)))
        code.extend(b"\x80\x3d" + struct.pack("<i", 0x21E0 - (0x1000 + len(code) + 7)) +
                    b"\x00\x75\x05\x48\x83\xc4\x28\xc3\x31\xc0\x48\x83\xc4\x28\xc3")
        callback2 = (b"\xc6\x05" + struct.pack("<i", 0x21E0 - (0x1110 + 7)) +
                     b"\x01\x31\xc0\xc3")
    else:
        code.extend(b"\x68" + struct.pack("<I", end) +
                    b"\x68" + struct.pack("<I", array) +
                    b"\xff\x15" + struct.pack("<I", base + 0x2040) +
                    b"\x83\xc4\x08\x80\x3d" + struct.pack("<I", base + 0x21E0) +
                    b"\x00\x75\x01\xc3\x31\xc0\xc3")
        callback2 = (b"\xc6\x05" + struct.pack("<I", base + 0x21E0) +
                     b"\x01\x31\xc0\xc3")
    buf[0x200:0x200 + len(code)] = code
    buf[0x300:0x306] = b"\xb8\x07\0\0\0\xc3"
    buf[0x310:0x310 + len(callback2)] = callback2
    return bytes(buf)


def build_process_exit_status(machine: int) -> bytes:
    """Query the current live process and exit one only for STILL_ACTIVE."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    struct.pack_into("<IIIII", buf, 0x400, 0x2090, 0, 0, 0x2060, 0x2040)
    buf[0x430:0x450] = b"\0" * 0x20
    for index, hint in enumerate((0x2070, 0x20B0)):
        struct.pack_into(fmt, buf, 0x440 + index * step, hint)
        struct.pack_into(fmt, buf, 0x490 + index * step, hint)
    buf[0x470:0x490] = b"\0" * 0x20
    buf[0x470:0x470 + len(b"\0\0GetExitCodeProcess\0")] = b"\0\0GetExitCodeProcess\0"
    buf[0x4B0:0x4C0] = b"\0" * 0x10
    buf[0x4B0:0x4B0 + len(b"\0\0ExitProcess\0")] = b"\0\0ExitProcess\0"
    code = bytearray()

    def call(index: int) -> None:
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack(
                "<i", 0x2040 + index * step - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + 0x2040 + index * step))

    if is_x64:
        code.extend(b"\x48\x83\xec\x28\x48\xc7\xc1\xff\xff\xff\xff" +
                    b"\x48\xba" + struct.pack("<Q", base + 0x20D0))
    else:
        code.extend(b"\x68" + struct.pack("<I", base + 0x20D0) + b"\x6a\xff")
    call(0)
    code.extend(b"\x85\xc0\x0f\x84\0\0\0\0")
    failed_call = len(code) - 4
    if is_x64:
        code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x20D0) +
                    b"\x81\x38\x03\x01\0\0")
    else:
        code.extend(b"\x81\x3d" + struct.pack("<I", base + 0x20D0) +
                    b"\x03\x01\0\0")
    code.extend(b"\x0f\x85\0\0\0\0")
    wrong_status = len(code) - 4
    code.extend(b"\xb9\x01\0\0\0" if is_x64 else b"\x6a\x01")
    call(1)
    failed = len(code)
    code.extend(b"\x31\xc9" if is_x64 else b"\x6a\x00")
    call(1)
    code.extend(b"\xc3")
    for offset in (failed_call, wrong_status):
        struct.pack_into("<i", code, offset, failed - offset - 4)
    assert len(code) < 0x200
    buf[0x200:0x400] = code.ljust(0x200, b"\0")
    return bytes(buf)


def build_console_output(machine: int) -> bytes:
    """Write harmless stdout/stderr bytes and Unicode console text."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    buf = bytearray(build(machine))
    buf.extend(b"\0" * (0x800 - len(buf)))
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<II", buf, section + 8, 0x400, 0x2000)
    struct.pack_into("<I", buf, section + 16, 0x400)
    struct.pack_into("<IIIII", buf, 0x400, 0x2100, 0, 0, 0x2200, 0x2070)
    for index, name in enumerate((b"GetStdHandle", b"WriteFile",
                                  b"WriteConsoleW", b"ExitProcess")):
        hint = 0x2130 + index * 0x20
        struct.pack_into(fmt, buf, 0x470 + index * step, hint)
        struct.pack_into(fmt, buf, 0x500 + index * step, hint)
        offset = 0x530 + index * 0x20
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x600:0x60D] = b"KERNEL32.dll\0"
    stdout = b"native stdout\n"
    stderr = b"native stderr\n"
    wide = "wide console ✓\n".encode("utf-16le")
    buf[0x640:0x640 + len(stdout)] = stdout
    buf[0x680:0x680 + len(stderr)] = stderr
    buf[0x6C0:0x6C0 + len(wide)] = wide
    code = bytearray()

    def call(index: int) -> None:
        rva = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    if is_x64:
        code.extend(b"\x48\x83\xec\x38\xb9\xf5\xff\xff\xff")
        call(0)
        code.extend(b"\x48\x89\xc3")

        def write_file(handle_reg: bytes, address: int, size: int) -> None:
            code.extend(handle_reg + b"\x48\xba" + struct.pack("<Q", address) +
                        b"\x41\xb8" + struct.pack("<I", size) +
                        b"\x49\xb9" + struct.pack("<Q", base + 0x2340) +
                        b"\x48\xc7\x44\x24\x20\0\0\0\0")
            call(1)

        write_file(b"\x48\x89\xd9", base + 0x2240, len(stdout))
        code.extend(b"\xb9\xf4\xff\xff\xff")
        call(0)
        write_file(b"\x48\x89\xc1", base + 0x2280, len(stderr))
        code.extend(b"\x48\x89\xd9\x48\xba" + struct.pack("<Q", base + 0x22C0) +
                    b"\x41\xb8" + struct.pack("<I", len(wide) // 2) +
                    b"\x49\xb9" + struct.pack("<Q", base + 0x2340) +
                    b"\x48\xc7\x44\x24\x20\0\0\0\0")
        call(2)
        code.extend(b"\x31\xc9")
        call(3)
    else:
        code.extend(b"\x68\xf5\xff\xff\xff")
        call(0)
        code.extend(b"\x89\xc3")

        def write_file(handle: bytes, address: int, size: int) -> None:
            code.extend(b"\x6a\0\x68" + struct.pack("<I", base + 0x2340) +
                        b"\x68" + struct.pack("<I", size) +
                        b"\x68" + struct.pack("<I", address) + handle)
            call(1)

        write_file(b"\x53", base + 0x2240, len(stdout))
        code.extend(b"\x68\xf4\xff\xff\xff")
        call(0)
        write_file(b"\x50", base + 0x2280, len(stderr))
        code.extend(b"\x6a\0\x68" + struct.pack("<I", base + 0x2340) +
                    b"\x68" + struct.pack("<I", len(wide) // 2) +
                    b"\x68" + struct.pack("<I", base + 0x22C0) + b"\x53")
        call(2)
        code.extend(b"\x6a\0")
        call(3)
    code.extend(b"\xc3")
    assert len(code) < 0x200
    buf[0x200:0x400] = code.ljust(0x200, b"\0")
    return bytes(buf)


def build_remote_debug_check(machine: int) -> bytes:
    """Require a valid false debugger result and reject an invalid handle."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build_process_exit_status(machine))
    buf[0x470:0x490] = b"\0" * 0x20
    name = b"\0\0CheckRemoteDebuggerPresent\0"
    buf[0x470:0x470 + len(name)] = name
    struct.pack_into("<I", buf, 0x4D4, 0x7F)
    step = 8 if is_x64 else 4
    code = bytearray(b"\x48\x83\xec\x28" if is_x64 else b"")
    jumps = []

    def call(index: int) -> None:
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack(
                "<i", 0x2040 + index * step - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + 0x2040 + index * step))

    def branch(opcode: bytes) -> None:
        code.extend(opcode + b"\0\0\0\0")
        jumps.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\xc7\xc1\xff\xff\xff\xff" +
                    b"\x48\xba" + struct.pack("<Q", base + 0x20D0))
    else:
        code.extend(b"\x68" + struct.pack("<I", base + 0x20D0) + b"\x6a\xff")
    call(0)
    code.extend(b"\x85\xc0")
    branch(b"\x0f\x84")  # Valid pseudo-handle must succeed.
    if is_x64:
        code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x20D0) +
                    b"\x83\x38\x00")
    else:
        code.extend(b"\x83\x3d" + struct.pack("<I", base + 0x20D0) + b"\x00")
    branch(b"\x0f\x85")
    if is_x64:
        code.extend(b"\x48\xc7\xc1\x34\x12\0\0" +
                    b"\x48\xba" + struct.pack("<Q", base + 0x20D4))
    else:
        code.extend(b"\x68" + struct.pack("<I", base + 0x20D4) +
                    b"\x68\x34\x12\0\0")
    call(0)
    code.extend(b"\x85\xc0")
    branch(b"\x0f\x85")  # Invalid handle must fail.
    if is_x64:
        code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x20D4) +
                    b"\x83\x38\x7f")
    else:
        code.extend(b"\x83\x3d" + struct.pack("<I", base + 0x20D4) + b"\x7f")
    branch(b"\x0f\x85")  # Failed call must not change output.
    code.extend(b"\xb9\x01\0\0\0" if is_x64 else b"\x6a\x01")
    call(1)
    failed = len(code)
    code.extend(b"\x31\xc9" if is_x64 else b"\x6a\x00")
    call(1)
    code.extend(b"\xc3")
    for offset in jumps:
        struct.pack_into("<i", code, offset, failed - offset - 4)
    assert len(code) < 0x200
    buf[0x200:0x400] = code.ljust(0x200, b"\0")
    return bytes(buf)


def build_is_debugger_present(machine: int) -> bytes:
    """Exit one only when the Win32 current-process debugger check is false."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build_process_exit_status(machine))
    buf[0x470:0x490] = b"\0" * 0x20
    name = b"\0\0IsDebuggerPresent\0"
    buf[0x470:0x470 + len(name)] = name
    step = 8 if is_x64 else 4
    code = bytearray(b"\x48\x83\xec\x28" if is_x64 else b"")

    def call(index: int) -> None:
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack(
                "<i", 0x2040 + index * step - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + 0x2040 + index * step))

    call(0)
    code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
    failed_jump = len(code) - 4
    code.extend(b"\xb9\x01\0\0\0" if is_x64 else b"\x6a\x01")
    call(1)
    failed = len(code)
    code.extend(b"\x31\xc9" if is_x64 else b"\x6a\x00")
    call(1)
    code.extend(b"\xc3")
    struct.pack_into("<i", code, failed_jump, failed - failed_jump - 4)
    buf[0x200:0x400] = code.ljust(0x200, b"\0")
    return bytes(buf)


def build_nt_debug_query(machine: int, information_class: int = 7) -> bytes:
    """Return one only for the modeled no-debugger NT query result."""
    assert information_class in (7, 30, 31)
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf[0x460:0x46D] = b"ntdll.dll\0".ljust(13, b"\0")
    buf[0x470:0x490] = b"\0" * 0x20
    name = b"\0\0NtQueryInformationProcess\0"
    buf[0x470:0x470 + len(name)] = name
    width = 4 if information_class == 31 else 8 if is_x64 else 4
    struct.pack_into("<Q" if is_x64 else "<I", buf, 0x4D0,
                     0xFFFFFFFFFFFFFFFF if is_x64 else 0xFFFFFFFF)
    code = bytearray()
    if is_x64:
        code.extend(b"\x48\x83\xec\x38" +
                    b"\x48\xc7\x44\x24\x20\0\0\0\0" +
                    b"\x48\xc7\xc1\xff\xff\xff\xff" +
                    b"\xba" + struct.pack("<I", information_class) +
                    b"\x49\xb8" + struct.pack("<Q", base + 0x20D0) +
                    b"\x41\xb9" + struct.pack("<I", width))
        code.extend(b"\xff\x15" + struct.pack("<i", 0x2040 - (0x1000 + len(code) + 6)))
    else:
        code.extend(b"\x6a\0\x6a" + bytes([width]) +
                    b"\x68" + struct.pack("<I", base + 0x20D0) +
                    b"\x6a" + bytes([information_class]) + b"\x6a\xff" +
                    b"\xff\x15" + struct.pack("<I", base + 0x2040))
    expected_status = 0xC0000353 if information_class == 30 else 0
    code.extend(b"\x3d" + struct.pack("<I", expected_status) +
                b"\x0f\x85\0\0\0\0")
    bad_status = len(code) - 4
    if is_x64:
        code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x20D0))
        if width == 8:
            code.extend(b"\x48")
        code.extend(b"\x83\x38" + bytes([int(information_class == 31)]))
    else:
        code.extend(b"\x83\x3d" + struct.pack("<I", base + 0x20D0) +
                    bytes([int(information_class == 31)]))
    code.extend(b"\x0f\x85\0\0\0\0")
    bad_value = len(code) - 4
    code.extend(b"\xb8\x01\0\0\0")
    if is_x64:
        code.extend(b"\x48\x83\xc4\x38")
    code.extend(b"\xc3")
    failed = len(code)
    code.extend(b"\x31\xc0")
    if is_x64:
        code.extend(b"\x48\x83\xc4\x38")
    code.extend(b"\xc3")
    for offset in (bad_status, bad_value):
        struct.pack_into("<i", code, offset, failed - offset - 4)
    assert len(code) < 0x200
    buf[0x200:0x400] = code.ljust(0x200, b"\0")
    return bytes(buf)


def build_peb_debug_check(machine: int) -> bytes:
    """Read the guest PEB BeingDebugged byte via FS/GS and exit one if clear."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    code = bytearray()
    if is_x64:
        code.extend(b"\x48\x83\xec\x28" +
                    b"\x65\x48\x8b\x04\x25\x60\0\0\0")
    else:
        code.extend(b"\x64\xa1\x30\0\0\0")
    code.extend(b"\x80\x78\x02\0" + b"\x0f\x85\0\0\0\0")
    failed_jump = len(code) - 4

    def exit_call(value: int) -> None:
        code.extend((b"\xb9" if is_x64 else b"\x6a") +
                    (struct.pack("<I", value) if is_x64 else bytes([value])))
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack(
                "<i", 0x2040 - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + 0x2040))

    exit_call(1)
    failed = len(code)
    exit_call(0)
    code.extend(b"\xc3")
    struct.pack_into("<i", code, failed_jump, failed - failed_jump - 4)
    assert len(code) < 0x200
    buf[0x200:0x400] = code.ljust(0x200, b"\0")
    return bytes(buf)


def build_qpc_progress(machine: int) -> bytes:
    """Exit one only when two consecutive guest QPC calls advance."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    struct.pack_into("<IIIII", buf, 0x400, 0x2090, 0, 0, 0x2060, 0x2040)
    buf[0x430:0x450] = b"\0" * 0x20
    for index, hint in enumerate((0x2070, 0x20B0)):
        struct.pack_into(fmt, buf, 0x440 + index * step, hint)
        struct.pack_into(fmt, buf, 0x490 + index * step, hint)
    buf[0x470:0x490] = b"\0" * 0x20
    buf[0x470:0x470 + len(b"\0\0QueryPerformanceCounter\0")] = b"\0\0QueryPerformanceCounter\0"
    buf[0x4B0:0x4C0] = b"\0" * 0x10
    buf[0x4B0:0x4B0 + len(b"\0\0ExitProcess\0")] = b"\0\0ExitProcess\0"
    code = bytearray(b"\x48\x83\xec\x28" if is_x64 else b"")

    def call(index: int) -> None:
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack(
                "<i", 0x2040 + index * step - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + 0x2040 + index * step))

    for address in (base + 0x20D0, base + 0x20D8):
        if is_x64:
            code.extend(b"\x48\xb9" + struct.pack("<Q", address))
        else:
            code.extend(b"\x68" + struct.pack("<I", address))
        call(0)
    if is_x64:
        code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x20D0) +
                    b"\x48\x8b\x18\x48\x39\x58\x08")
    else:
        code.extend(b"\xa1" + struct.pack("<I", base + 0x20D0) +
                    b"\x39\x05" + struct.pack("<I", base + 0x20D8))
    code.extend(b"\x0f\x8e\0\0\0\0")  # JLE failure
    failure_jump = len(code) - 4
    code.extend(b"\xb9\x01\0\0\0" if is_x64 else b"\x6a\x01")
    call(1)
    failure = len(code)
    code.extend(b"\x31\xc9" if is_x64 else b"\x6a\x00")
    call(1)
    code.extend(b"\xc3")
    struct.pack_into("<i", code, failure_jump, failure - failure_jump - 4)
    assert len(code) < 0x200
    buf[0x200:0x400] = code.ljust(0x200, b"\0")
    return bytes(buf)


def build_shared_time_check(machine: int) -> bytes:
    """Compare time APIs with direct KUSER_SHARED_DATA CPU reads."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    struct.pack_into("<IIIII", buf, 0x400, 0x2080, 0, 0, 0x21B0, 0x2040)
    for index, name in enumerate((b"GetSystemTimeAsFileTime", b"GetTickCount",
                                  b"Sleep", b"ExitProcess")):
        hint = 0x20C0 + index * 0x30
        struct.pack_into(fmt, buf, 0x440 + index * step, hint)
        struct.pack_into(fmt, buf, 0x480 + index * step, hint)
        raw = 0x4C0 + index * 0x30
        buf[raw:raw + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5B0:0x5BD] = b"KERNEL32.dll\0"
    code = bytearray(b"\x48\x83\xec\x28" if is_x64 else b"")
    failures = []

    def call(index: int) -> None:
        iat = 0x2040 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack(
                "<i", iat - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + iat))

    def fail_if_not_equal() -> None:
        code.extend(b"\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2180))
    else:
        code.extend(b"\x68" + struct.pack("<I", base + 0x2180))
    call(0)
    if is_x64:
        code.extend(b"\x48\xa1" + struct.pack("<Q", base + 0x2180))
        code.extend(b"\x48\xbb" + struct.pack("<Q", 0x7FFE0014))
        code.extend(b"\x48\x3b\x03")
    else:
        code.extend(b"\xa1" + struct.pack("<I", base + 0x2180))
        code.extend(b"\x3b\x05" + struct.pack("<I", 0x7FFE0014))
    fail_if_not_equal()
    if is_x64:
        code.extend(b"\x48\xbb" + struct.pack("<Q", 0xFFFFF78000000014))
        code.extend(b"\x48\x3b\x03")
        fail_if_not_equal()
    else:
        code.extend(b"\x3b\x05" + struct.pack("<I", 0xFFDF0014))
        fail_if_not_equal()
    if not is_x64:
        code.extend(b"\xa1" + struct.pack("<I", base + 0x2184))
        code.extend(b"\x3b\x05" + struct.pack("<I", 0x7FFE0018))
        fail_if_not_equal()
        code.extend(b"\x3b\x05" + struct.pack("<I", 0xFFDF0018))
        fail_if_not_equal()

    def check_shared_dword(address: int, expected: int) -> None:
        if is_x64:
            code.extend(b"\x48\xbb" + struct.pack("<Q", address))
            code.extend(b"\x81\x3b" + struct.pack("<I", expected))
        else:
            code.extend(b"\x81\x3d" + struct.pack("<II", address, expected))
        fail_if_not_equal()

    for address, expected in ((0x7FFE002C, 0x86648664),  # x64 image range
                              (0x7FFE0030, 0x003A0043),  # C:\\ root
                              (0x7FFE0260, 22631),  # NtBuildNumber
                              (0x7FFE026C, 10),     # NtMajorVersion
                              (0x7FFE0270, 0),      # NtMinorVersion
                              (0x7FFE02E8, 16_384 * 256),  # physical pages
                              (0x7FFE0300, 10_000_000),  # QpcFrequency
                              (0x7FFE0304, 0),
                              (0x7FFE03B8, 0),      # QpcBias
                              (0x7FFE03C0, 12),     # ActiveProcessorCount
                              (0x7FFE03C4, 1)):     # ActiveGroupCount
        check_shared_dword(address, expected)
    call(1)
    if is_x64:
        code.extend(b"\x48\xbb" + struct.pack("<Q", 0x7FFE0320))
        code.extend(b"\x3b\x03")
    else:
        code.extend(b"\x3b\x05" + struct.pack("<I", 0x7FFE0320))
    fail_if_not_equal()
    code.extend(b"\x89\xc6")  # esi = old tick
    if is_x64:
        code.extend(b"\xb9\xd0\x07\0\0")
    else:
        code.extend(b"\x68\xd0\x07\0\0")
    call(2)
    if is_x64:
        code.extend(b"\x8b\x03")
    else:
        code.extend(b"\xa1" + struct.pack("<I", 0x7FFE0320))
    code.extend(b"\x29\xf0\x3d\xd0\x07\0\0")
    fail_if_not_equal()
    code.extend(b"\xb9\x01\0\0\0" if is_x64 else b"\x6a\x01")
    call(3)
    failed = len(code)
    code.extend(b"\x31\xc9" if is_x64 else b"\x6a\x00")
    call(3)
    code.extend(b"\xc3")
    for location in failures:
        struct.pack_into("<i", code, location, failed - location - 4)
    assert len(code) < 0x200
    buf[0x200:0x400] = code.ljust(0x200, b"\0")
    return bytes(buf)


def build_cpuid_identity_check(machine: int) -> bytes:
    """Exit one for a consistent Intel vendor and no hypervisor CPUID bit."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    code = bytearray(b"\x48\x83\xec\x28" if is_x64 else b"")
    failures = []

    def fail_if_not_equal() -> None:
        code.extend(b"\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)

    code.extend(b"\x31\xc0\x31\xc9\x0f\xa2")
    for opcode, expected in ((b"\x81\xfb", 0x756E6547),
                             (b"\x81\xfa", 0x49656E69),
                             (b"\x81\xf9", 0x6C65746E)):
        code.extend(opcode + struct.pack("<I", expected))
        fail_if_not_equal()
    code.extend(b"\xb8\x01\0\0\0\x31\xc9\x0f\xa2")
    code.extend(b"\xf7\xc1\0\0\0\x80")  # test ecx, 1 << 31
    code.extend(b"\x0f\x85\0\0\0\0")
    failures.append(len(code) - 4)
    code.extend(b"\xf7\xc1\x20\0\0\0")  # VMX on the Intel persona
    code.extend(b"\x0f\x84\0\0\0\0")
    failures.append(len(code) - 4)
    code.extend(b"\xf7\xc1\0\0\0\x10")  # AVX in leaf 1
    code.extend(b"\x0f\x84\0\0\0\0")
    failures.append(len(code) - 4)
    code.extend(b"\x31\xc9\x0f\x01\xd0")  # XGETBV(0)
    code.extend(b"\x83\xe0\x07\x83\xf8\x07")
    fail_if_not_equal()
    code.extend(b"\x85\xd2")
    code.extend(b"\x0f\x85\0\0\0\0")
    failures.append(len(code) - 4)
    code.extend(b"\xb8\x07\0\0\0\x31\xc9\x0f\xa2")
    code.extend(b"\xf7\xc3\x20\0\0\0")  # AVX2 in leaf 7
    code.extend(b"\x0f\x84\0\0\0\0")
    failures.append(len(code) - 4)
    code.extend(b"\xb8\x02\0\0\x80\x31\xc9\x0f\xa2")
    code.extend(b"\x3d" + struct.pack("<I", 0x65746E49))  # "Inte"
    fail_if_not_equal()
    code.extend(b"\xb8\0\0\0\x40\x31\xc9\x0f\xa2")
    code.extend(b"\x09\xd8\x09\xc8\x09\xd0")  # no hypervisor leaves
    code.extend(b"\x0f\x85\0\0\0\0")
    failures.append(len(code) - 4)

    def exit_call(value: int) -> None:
        code.extend((b"\xb9" + struct.pack("<I", value)) if is_x64
                    else (b"\x68" + struct.pack("<I", value)))
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack(
                "<i", 0x2040 - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + 0x2040))

    exit_call(1)
    failed = len(code)
    exit_call(0)
    code.extend(b"\xc3")
    for location in failures:
        struct.pack_into("<i", code, location, failed - location - 4)
    assert len(code) < 0x200
    buf[0x200:0x400] = code.ljust(0x200, b"\0")
    return bytes(buf)


def build_processor_feature_check(machine: int) -> bytes:
    """Compare WinAPI and KUSER processor features, including VT-x/EPT."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    struct.pack_into("<IIIII", buf, 0x400, 0x2090, 0, 0, 0x2100, 0x2040)
    for index, name in enumerate((b"IsProcessorFeaturePresent", b"ExitProcess")):
        hint = 0x2070 + index * 0x40
        struct.pack_into(fmt, buf, 0x440 + index * step, hint)
        struct.pack_into(fmt, buf, 0x490 + index * step, hint)
        raw = 0x470 + index * 0x40
        buf[raw:raw + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x500:0x50D] = b"KERNEL32.dll\0"
    code = bytearray(b"\x48\x83\xec\x28" if is_x64 else b"")
    failures = []

    def call(index: int) -> None:
        iat = 0x2040 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack(
                "<i", iat - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + iat))

    def require(expected: int) -> None:
        code.extend(b"\x83\xf8" + bytes([expected]) + b"\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)

    for index, expected in ((20, 1), (21, 1), (39, 1), (40, 1), (42, 1),
                            (41, 0), (0, 0), (63, 0)):
        code.extend((b"\xb9" + struct.pack("<I", index)) if is_x64
                    else (b"\x6a" + bytes([index])))
        call(0)
        require(expected)
        address = 0x7FFE0274 + index
        if is_x64:
            code.extend(b"\x48\xb8" + struct.pack("<Q", address) + b"\x0f\xb6\x00")
        else:
            code.extend(b"\x0f\xb6\x05" + struct.pack("<I", address))
        require(expected)
    code.extend(b"\xb9\x01\0\0\0" if is_x64 else b"\x6a\x01")
    call(1)
    failed = len(code)
    code.extend(b"\x31\xc9" if is_x64 else b"\x6a\x00")
    call(1)
    code.extend(b"\xc3")
    for location in failures:
        struct.pack_into("<i", code, location, failed - location - 4)
    assert len(code) < 0x200, len(code)
    buf[0x200:0x400] = code.ljust(0x200, b"\0")
    return bytes(buf)


def build_nt_version_consistency_check(machine: int, expected_build: int = 22631) -> bytes:
    """Compare two NTDLL version queries with direct shared-page build data."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * 0x200)
    sh = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", buf, sh + 8, 0x400)   # .idata VirtualSize
    struct.pack_into("<I", buf, sh + 16, 0x400)  # .idata SizeOfRawData
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    buf[0x400:0x600] = b"\0" * 0x200
    struct.pack_into("<IIIII", buf, 0x400, 0x2040, 0, 0, 0x21A0, 0x2080)
    struct.pack_into("<IIIII", buf, 0x414, 0x2060, 0, 0, 0x21C0, 0x20A0)
    for index, hint in enumerate((0x20C0, 0x20E0)):
        struct.pack_into(fmt, buf, 0x440 + index * step, hint)
        struct.pack_into(fmt, buf, 0x480 + index * step, hint)
    struct.pack_into(fmt, buf, 0x460, 0x2120)
    struct.pack_into(fmt, buf, 0x4A0, 0x2120)
    for raw, name in ((0x4C0, b"RtlGetVersion"),
                      (0x4E0, b"RtlGetNtVersionNumbers"),
                      (0x520, b"ExitProcess")):
        buf[raw:raw + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5A0:0x5AA] = b"NTDLL.dll\0"
    buf[0x5C0:0x5CD] = b"KERNEL32.dll\0"
    struct.pack_into("<I", buf, 0x600, 276)
    code = bytearray(b"\x48\x83\xec\x28" if is_x64 else b"")
    failures = []

    def call(rva: int) -> None:
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack(
                "<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    def require_equal() -> None:
        code.extend(b"\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)

    def compare_dword(address: int, expected: int) -> None:
        if is_x64:
            code.extend(b"\x48\xb8" + struct.pack("<Q", address))
            code.extend(b"\x81\x38" + struct.pack("<I", expected))
        else:
            code.extend(b"\x81\x3d" + struct.pack("<II", address, expected))
        require_equal()

    if is_x64:
        code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2200))
    else:
        code.extend(b"\x68" + struct.pack("<I", base + 0x2200))
    call(0x2080)  # RtlGetVersion
    code.extend(b"\x85\xc0")
    require_equal()  # STATUS_SUCCESS
    for offset, expected in ((4, 10), (8, 0), (12, expected_build), (16, 2)):
        compare_dword(base + 0x2200 + offset, expected)
    if is_x64:
        code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2320))
        code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x2324))
        code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x2328))
    else:
        for address in (base + 0x2328, base + 0x2324, base + 0x2320):
            code.extend(b"\x68" + struct.pack("<I", address))
    call(0x2080 + step)  # RtlGetNtVersionNumbers
    for address, expected in ((base + 0x2320, 10),
                              (base + 0x2324, 0),
                              (base + 0x2328, 0xF0000000 | expected_build),
                              (0x7FFE0260, expected_build)):
        compare_dword(address, expected)
    code.extend(b"\xb9\x01\0\0\0" if is_x64 else b"\x6a\x01")
    call(0x20A0)  # ExitProcess
    failed = len(code)
    code.extend(b"\x31\xc9" if is_x64 else b"\x6a\x00")
    call(0x20A0)
    code.extend(b"\xc3")
    for location in failures:
        struct.pack_into("<i", code, location, failed - location - 4)
    assert len(code) < 0x200, len(code)
    buf[0x200:0x400] = code.ljust(0x200, b"\0")
    return bytes(buf)


def build_version_compat_check(machine: int, compatibility: str) -> bytes:
    """Probe manifest-conditioned Win32 version APIs against the true build."""
    versions = {"none": (6, 2, 9200), "win81": (6, 3, 9600),
                "win10": (10, 0, 22631)}
    guids = {"win81": "1f676c76-80e1-4239-95bb-83d0f6d0da78",
             "win10": "8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a"}
    major, minor, build_number = versions[compatibility]
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * 0x600)
    opt = 0x98
    optional_size = 0xF0 if is_x64 else 0xE0
    sh = opt + optional_size
    struct.pack_into("<I", buf, opt + 56, 0x4000)  # SizeOfImage
    struct.pack_into("<I", buf, sh + 40 + 8, 0x400)   # .idata VirtualSize
    struct.pack_into("<I", buf, sh + 40 + 16, 0x400)  # .idata SizeOfRawData
    resource_sh = sh + 80
    buf[resource_sh:resource_sh + 8] = b".rsrc\0\0\0"
    struct.pack_into("<IIIIIIHHI", buf, resource_sh + 8,
                     0x400, 0x3000, 0x400, 0x800, 0, 0, 0, 0, 0x40000040)
    struct.pack_into("<H", buf, 0x86, 3)  # NumberOfSections
    buf[0x400:0x800] = b"\0" * 0x400
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    struct.pack_into("<IIIII", buf, 0x400, 0x2090, 0, 0, 0x2180, 0x2040)
    for index, name in enumerate((b"GetVersion", b"GetVersionExW", b"ExitProcess")):
        hint = 0x20D0 + index * 0x30
        struct.pack_into(fmt, buf, 0x440 + index * step, hint)
        struct.pack_into(fmt, buf, 0x490 + index * step, hint)
        raw = 0x4D0 + index * 0x30
        buf[raw:raw + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x580:0x58D] = b"KERNEL32.dll\0"
    struct.pack_into("<I", buf, 0x600, 276)
    if compatibility != "none":
        guid = guids[compatibility]
        manifest = (
            '<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">'
            '<compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">'
            f'<application><supportedOS Id="{{{guid}}}"/></application>'
            '</compatibility></assembly>').encode("utf-8")
        assert len(manifest) <= 0x3A8
        dd = opt + (112 if is_x64 else 96)
        struct.pack_into("<II", buf, dd + 16, 0x3000, 0x400)
        struct.pack_into("<H", buf, 0x800 + 14, 1)
        struct.pack_into("<II", buf, 0x810, 24, 0x80000018)
        struct.pack_into("<H", buf, 0x818 + 14, 1)
        struct.pack_into("<II", buf, 0x828, 1, 0x80000030)
        struct.pack_into("<H", buf, 0x830 + 14, 1)
        struct.pack_into("<II", buf, 0x840, 0x409, 0x48)
        struct.pack_into("<IIII", buf, 0x848, 0x3058, len(manifest), 0, 0)
        buf[0x858:0x858 + len(manifest)] = manifest
    code = bytearray(b"\x48\x83\xec\x28" if is_x64 else b"")
    failures = []

    def call(index: int) -> None:
        iat = 0x2040 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack(
                "<i", iat - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + iat))

    def require_equal() -> None:
        code.extend(b"\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)

    def compare_dword(address: int, expected: int) -> None:
        if is_x64:
            code.extend(b"\x48\xb8" + struct.pack("<Q", address))
            code.extend(b"\x81\x38" + struct.pack("<I", expected))
        else:
            code.extend(b"\x81\x3d" + struct.pack("<II", address, expected))
        require_equal()

    call(0)  # GetVersion
    code.extend(b"\x3d" + struct.pack("<I", (build_number << 16) |
                                       (minor << 8) | major))
    require_equal()
    if is_x64:
        code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2200))
    else:
        code.extend(b"\x68" + struct.pack("<I", base + 0x2200))
    call(1)  # GetVersionExW
    code.extend(b"\x83\xf8\x01")
    require_equal()
    for offset, expected in ((4, major), (8, minor), (12, build_number),
                             (16, 2)):
        compare_dword(base + 0x2200 + offset, expected)
    compare_dword(0x7FFE0260, 22631)  # true kernel build
    code.extend(b"\xb9\x01\0\0\0" if is_x64 else b"\x6a\x01")
    call(2)
    failed = len(code)
    code.extend(b"\x31\xc9" if is_x64 else b"\x6a\x00")
    call(2)
    code.extend(b"\xc3")
    for location in failures:
        struct.pack_into("<i", code, location, failed - location - 4)
    assert len(code) < 0x200, len(code)
    buf[0x200:0x400] = code.ljust(0x200, b"\0")
    return bytes(buf)


def build_version_verify_check(machine: int, compatibility: str) -> bytes:
    """Branch on manifest-aware Win32 and true NTDLL version comparisons."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build_version_compat_check(machine, compatibility))
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    for index, name in enumerate((b"VerSetConditionMask", b"VerifyVersionInfoW",
                                  b"GetLastError", b"ExitProcess")):
        hint = 0x20D0 + index * 0x30
        struct.pack_into(fmt, buf, 0x440 + index * step, hint)
        struct.pack_into(fmt, buf, 0x490 + index * step, hint)
        offset = 0x4D0 + index * 0x30
        buf[offset:offset + 0x30] = b"\0" * 0x30
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x580:0x58D] = b"KERNEL32.dll\0"
    # One separate NTDLL import. All tables and request bytes stay in .idata.
    struct.pack_into("<IIIII", buf, 0x414, 0x21A0, 0, 0, 0x2220, 0x21B0)
    buf[0x428:0x43C] = b"\0" * 20
    struct.pack_into(fmt, buf, 0x5A0, 0x21D0)
    struct.pack_into(fmt, buf, 0x5B0, 0x21D0)
    rtl_name = b"\0\0RtlVerifyVersionInfo\0"
    buf[0x5D0:0x5D0 + len(rtl_name)] = rtl_name
    buf[0x620:0x62A] = b"ntdll.dll\0"
    request = bytearray(284)
    struct.pack_into("<IIIII", request, 0, 284, 10, 0, 22631, 2)
    request[282] = 1
    buf[0x650:0x650 + len(request)] = request
    condition_mask = 0x800000000000001B  # major/minor >= via VerSetConditionMask
    code = bytearray(b"\x48\x83\xec\x28" if is_x64 else b"")
    failures = []

    def call(rva: int) -> None:
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack(
                "<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    def require_eax(value: int) -> None:
        code.extend(b"\x3d" + struct.pack("<I", value))
        code.extend(b"\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)

    def version_args() -> None:
        if is_x64:
            code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2250))
            code.extend(b"\xba\x03\0\0\0")
            code.extend(b"\x49\xb8" + struct.pack("<Q", condition_mask))
        else:
            for value in (condition_mask >> 32, condition_mask & 0xFFFFFFFF,
                          3, base + 0x2250):
                code.extend(b"\x68" + struct.pack("<I", value))

    if is_x64:
        code.extend(b"\x48\x31\xc9\xba\x02\0\0\0")
        code.extend(b"\x41\xb8\x03\0\0\0")
    else:
        for value in (3, 2, 0, 0):
            code.extend(b"\x68" + struct.pack("<I", value))
    call(0x2040)  # VerSetConditionMask, major >=
    if is_x64:
        code.extend(b"\x48\xbb" + struct.pack("<Q", 0x8000000000000018))
        code.extend(b"\x48\x39\xd8\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)
    else:
        require_eax(0x18)
        code.extend(b"\x81\xfa\0\0\0\x80\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)
    version_args()
    call(0x2040 + step)  # VerifyVersionInfoW
    require_eax(1 if compatibility == "win10" else 0)
    if compatibility != "win10":
        call(0x2040 + step * 2)  # GetLastError
        require_eax(1150)
    version_args()
    call(0x21B0)  # RtlVerifyVersionInfo: true persona version
    require_eax(0)
    if is_x64:
        code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x2254))
        code.extend(b"\xc7\x00\x0b\0\0\0")
    else:
        code.extend(b"\xc7\x05" + struct.pack("<I", base + 0x2254) +
                    b"\x0b\0\0\0")
    version_args()
    call(0x2040 + step)
    require_eax(0)
    call(0x2040 + step * 2)
    require_eax(1150)
    version_args()
    call(0x21B0)
    require_eax(0xC0000059)
    code.extend(b"\xb9\x01\0\0\0" if is_x64 else b"\x6a\x01")
    call(0x2040 + step * 3)
    failed = len(code)
    code.extend(b"\x31\xc9" if is_x64 else b"\x6a\x00")
    call(0x2040 + step * 3)
    code.extend(b"\xc3")
    for location in failures:
        struct.pack_into("<i", code, location, failed - location - 4)
    assert len(code) < 0x200, len(code)
    buf[0x200:0x400] = code.ljust(0x200, b"\0")
    return bytes(buf)


def build_avx_fallback_check(machine: int) -> bytes:
    """Fill guest memory through AVX and branch on every resulting byte."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", buf, section + 8, 0x200)  # .idata VirtualSize
    buf[0x500:0x540] = b"\0" * 64
    buf[0x540:0x580] = b"Z" * 64
    code = bytearray(b"\x48\x83\xec\x28" if is_x64 else b"")

    def exit_call() -> None:
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack(
                "<i", 0x2040 - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + 0x2040))

    if is_x64:
        code.extend(b"\xf3\x0f\x6f\x05" + struct.pack(
            "<i", 0x2140 - (0x1000 + len(code) + 8)))
    else:
        code.extend(b"\xf3\x0f\x6f\x05" + struct.pack("<I", base + 0x2140))
    code.extend(b"\xc4\xe3\x7d\x18\xc0\x01")  # VINSERTF128
    code.extend((b"\x48\xb9" + struct.pack("<Q", base + 0x2100)) if is_x64
                else (b"\xb9" + struct.pack("<I", base + 0x2100)))
    code.extend(b"\xc5\xfd\x7f\x01")  # VMOVDQA [rcx],ymm0
    code.extend(b"\xc5\xfe\x7f\x41\x20")  # VMOVDQU [rcx+32],ymm0
    code.extend(b"\xc5\xf8\x77")  # VZEROUPPER
    if is_x64:
        code.extend(b"\x48\xbe" + struct.pack("<Q", base + 0x2100))
        code.extend(b"\x48\xbf" + struct.pack("<Q", base + 0x2140))
    else:
        code.extend(b"\xbe" + struct.pack("<I", base + 0x2100))
        code.extend(b"\xbf" + struct.pack("<I", base + 0x2140))
    code.extend(b"\xb9\x40\0\0\0\xf3\xa6\x0f\x85\0\0\0\0")
    failed_jump = len(code) - 4
    code.extend(b"\xb9\x01\0\0\0" if is_x64 else b"\x6a\x01")
    exit_call()
    failed = len(code)
    code.extend(b"\x31\xc9" if is_x64 else b"\x6a\x00")
    exit_call()
    code.extend(b"\xc3")
    struct.pack_into("<i", code, failed_jump, failed - failed_jump - 4)
    assert len(code) < 0x200
    buf[0x200:0x400] = code.ljust(0x200, b"\0")
    return bytes(buf)


def build_tsc_sleep_check(machine: int) -> bytes:
    """Check direct RDTSC/RDTSCP progress across a virtual one-second sleep."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    struct.pack_into("<IIIII", buf, 0x400, 0x2090, 0, 0, 0x2060, 0x2040)
    for index, name in enumerate((b"Sleep", b"ExitProcess")):
        hint = 0x2070 + index * 0x30
        struct.pack_into(fmt, buf, 0x440 + index * step, hint)
        struct.pack_into(fmt, buf, 0x490 + index * step, hint)
        raw = 0x470 + index * 0x30
        buf[raw:raw + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x500:0x50D] = b"KERNEL32.dll\0"
    code = bytearray(b"\x48\x83\xec\x28" if is_x64 else b"")
    failures = []

    def call(index: int) -> None:
        iat = 0x2040 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack(
                "<i", iat - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + iat))

    def fail(jump: bytes) -> None:
        code.extend(jump + b"\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\xbb" + struct.pack("<Q", base + 0x20D0))
    code.extend(b"\x0f\x31")  # RDTSC
    if is_x64:
        code.extend(b"\x89\x03\xb9\xe8\x03\0\0")
    else:
        code.extend(b"\xa3" + struct.pack("<I", base + 0x20D0))
        code.extend(b"\x68\xe8\x03\0\0")
    call(0)
    code.extend(b"\x0f\x01\xf9")  # RDTSCP
    code.extend(b"\x85\xc9")
    fail(b"\x0f\x85")
    if is_x64:
        code.extend(b"\x2b\x03")
    else:
        code.extend(b"\x2b\x05" + struct.pack("<I", base + 0x20D0))
    code.extend(b"\x3d" + struct.pack("<I", 2_900_000_000))
    fail(b"\x0f\x82")  # JB: virtual sleep did not advance TSC enough
    code.extend(b"\x3d" + struct.pack("<I", 2_900_010_000))
    fail(b"\x0f\x87")  # JA: TSC jumped too far
    code.extend(b"\xb9\x01\0\0\0" if is_x64 else b"\x6a\x01")
    call(1)
    failed = len(code)
    code.extend(b"\x31\xc9" if is_x64 else b"\x6a\x00")
    call(1)
    code.extend(b"\xc3")
    for location in failures:
        struct.pack_into("<i", code, location, failed - location - 4)
    assert len(code) < 0x200
    buf[0x200:0x400] = code.ljust(0x200, b"\0")
    return bytes(buf)


def build_memory_persona_check(machine: int) -> bytes:
    """Compare GlobalMemoryStatusEx with shared physical-page count."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    struct.pack_into("<IIIII", buf, 0x400, 0x2090, 0, 0, 0x21C0, 0x2040)
    for index, name in enumerate((b"GlobalMemoryStatusEx", b"ExitProcess")):
        hint = 0x2070 + index * 0x40
        struct.pack_into(fmt, buf, 0x440 + index * step, hint)
        struct.pack_into(fmt, buf, 0x490 + index * step, hint)
        raw = 0x470 + index * 0x40
        buf[raw:raw + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5C0:0x5CD] = b"KERNEL32.dll\0"
    struct.pack_into("<I", buf, 0x500, 64)
    code = bytearray(b"\x48\x83\xec\x28" if is_x64 else b"")
    failures = []

    def call(index: int) -> None:
        iat = 0x2040 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack(
                "<i", iat - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + iat))

    def fail_if(jump: bytes) -> None:
        code.extend(jump + b"\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2100))
    else:
        code.extend(b"\x68" + struct.pack("<I", base + 0x2100))
    call(0)
    code.extend(b"\x85\xc0")
    fail_if(b"\x0f\x84")
    code.extend((b"\x48\xbb" + struct.pack("<Q", base + 0x2100)) if is_x64
                else (b"\xbb" + struct.pack("<I", base + 0x2100)))
    for offset, value in ((0, 64), (4, 56), (8, 0), (12, 4),
                          (16, 0xC0000000), (20, 1)):
        code.extend(b"\x81\x7b" + bytes([offset]) + struct.pack("<I", value))
        fail_if(b"\x0f\x85")
    code.extend((b"\x48\xbb" + struct.pack("<Q", 0x7FFE02E8)) if is_x64
                else (b"\xbb" + struct.pack("<I", 0x7FFE02E8)))
    code.extend(b"\x81\x3b" + struct.pack("<I", 16_384 * 256))
    fail_if(b"\x0f\x85")
    code.extend(b"\xb9\x01\0\0\0" if is_x64 else b"\x6a\x01")
    call(1)
    failed = len(code)
    code.extend(b"\x31\xc9" if is_x64 else b"\x6a\x00")
    call(1)
    code.extend(b"\xc3")
    for location in failures:
        struct.pack_into("<i", code, location, failed - location - 4)
    assert len(code) < 0x200
    buf[0x200:0x400] = code.ljust(0x200, b"\0")
    return bytes(buf)


def build_relocatable_companion(machine: int, preferred: int) -> bytes:
    """Build a DLL whose entry and export both use genuine base relocations."""
    is_x64 = machine == 0x8664
    buf = bytearray(build(machine, dll=True))
    opt = 0x98
    dd = opt + (112 if is_x64 else 96)
    struct.pack_into("<Q" if is_x64 else "<I", buf,
                     opt + (24 if is_x64 else 28), preferred)
    marker = preferred + 0x21E0
    magic = preferred + 0x21F0
    if is_x64:
        init = (b"\x48\xb8" + struct.pack("<Q", marker) +
                b"\xc6\x00\x01\xb8\x01\0\0\0\xc3")
        export = (b"\x48\xb8" + struct.pack("<Q", magic) +
                  b"\x80\x38\x42\x75\x06\xb8\x2a\0\0\0\xc3\x31\xc0\xc3")
    else:
        init = (b"\xc6\x05" + struct.pack("<I", marker) +
                b"\x01\xb8\x01\0\0\0\xc2\x0c\0")
        export = (b"\x80\x3d" + struct.pack("<I", magic) +
                  b"\x42\x75\x06\xb8\x2a\0\0\0\xc3\x31\xc0\xc3")
    buf[0x200:0x260] = b"\0" * 0x60
    buf[0x200:0x200 + len(init)] = init
    buf[0x230:0x230 + len(export)] = export
    buf[0x5F0] = 0x42  # Not present in the colliding EXE or middle DLL.
    struct.pack_into("<I", buf, 0x530, 0x1030)
    section = opt + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", buf, section + 8, 0x200)  # .idata virtual size
    reloc_type = 10 if is_x64 else 3
    struct.pack_into("<IIHH", buf, 0x5B0, 0x1000, 12,
                     (reloc_type << 12) | 0x002, (reloc_type << 12) | 0x032)
    struct.pack_into("<II", buf, dd + 5 * 8, 0x21B0, 12)
    return bytes(buf)


def build_host_process_probe(machine: int, marker_path: str) -> bytes:
    """Ask guest CreateProcessW to run harmless cmd.exe and write a host marker."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * (0x1400 - len(buf)))
    opt = 0x98
    section = opt + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", buf, opt + 8, 0x1000)
    struct.pack_into("<I", buf, section + 8, 0x1000)
    struct.pack_into("<I", buf, section + 16, 0x1000)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    for index, target in enumerate((0x2070, 0x2090, 0)):
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x440 + index * step, target)
    buf[0x470:0x481] = b"\0\0CreateProcessW\0"
    buf[0x490:0x49E] = b"\0\0ExitProcess\0"
    application = "C:\\Windows\\System32\\cmd.exe".encode("utf-16le") + b"\0\0"
    command = (f'cmd.exe /c echo emumee-host-probe > "{marker_path}"').encode("utf-16le") + b"\0\0"
    if len(application) > 0x200 or len(command) > 0x200:
        raise ValueError("Host probe path is too long")
    buf[0x500:0x500 + len(application)] = application
    buf[0x700:0x700 + len(command)] = command
    struct.pack_into("<I", buf, 0x900, 104 if is_x64 else 68)
    code = bytearray()
    if is_x64:
        code.extend(b"\x48\x81\xec\x88\0\0\0")
        code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2100))
        code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x2300))
        code.extend(b"\x45\x31\xc0\x45\x31\xc9\x31\xc0")
        for offset in (0x20, 0x28, 0x30, 0x38):
            code.extend(b"\x48\x89\x44\x24" + bytes([offset]))
        for offset, value in ((0x40, base + 0x2500), (0x48, base + 0x2600)):
            code.extend(b"\x48\xb8" + struct.pack("<Q", value))
            code.extend(b"\x48\x89\x44\x24" + bytes([offset]))
        displacement = 0x2040 - (0x1000 + len(code) + 6)
        code.extend(b"\xff\x15" + struct.pack("<i", displacement))
        code.extend(b"\x89\xc1")
        displacement = 0x2048 - (0x1000 + len(code) + 6)
        code.extend(b"\xff\x15" + struct.pack("<i", displacement))
        code.extend(b"\x48\x81\xc4\x88\0\0\0\xc3")
    else:
        for value in (base + 0x2600, base + 0x2500, 0, 0, 0, 0, 0, 0,
                      base + 0x2300, base + 0x2100):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\xff\x15" + struct.pack("<I", base + 0x2040))
        code.extend(b"\x50\xff\x15" + struct.pack("<I", base + 0x2044))
        code.extend(b"\xc3")
    if len(code) > 0x200:
        raise ValueError("Host probe entry point is too large")
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_host_winexec_probe(machine: int, marker_path: str) -> bytes:
    """Ask guest WinExec to run a harmless host-marker command."""
    base = 0x140000000 if machine == 0x8664 else 0x400000
    buf = bytearray(build_host_process_probe(machine, marker_path))
    buf[0x470:0x481] = b"\0" * 0x11
    buf[0x470:0x470 + len(b"\0\0WinExec\0")] = b"\0\0WinExec\0"
    command = f'cmd.exe /c echo emumee-host-probe > "{marker_path}"'.encode("cp1252") + b"\0"
    if len(command) > 0x200:
        raise ValueError("Host probe path is too long")
    buf[0x700:0x900] = b"\0" * 0x200
    buf[0x700:0x700 + len(command)] = command
    code = bytearray()
    if machine == 0x8664:
        code.extend(b"\x48\x83\xec\x28")
        code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2300))
        code.extend(b"\x31\xd2")
        code.extend(b"\xff\x15" + struct.pack("<i", 0x2040 - (0x1000 + len(code) + 6)))
        code.extend(b"\x31\xc9")
        code.extend(b"\xff\x15" + struct.pack("<i", 0x2048 - (0x1000 + len(code) + 6)))
    else:
        code.extend(b"\x6a\x00\x68" + struct.pack("<I", base + 0x2300))
        code.extend(b"\xff\x15" + struct.pack("<I", base + 0x2040))
        code.extend(b"\x6a\x00\xff\x15" + struct.pack("<I", base + 0x2044))
    code.extend(b"\xc3")
    buf[0x200:0x400] = b"\0" * 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_drop_x86() -> bytes:
    """PE32 fixture that writes a virtual file with WinAPI, then exits."""
    buf = bytearray(build(0x14C))
    image_base = 0x400000
    # One import descriptor and four imported functions.
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x2070, 0x2050)
    for index, rva in enumerate((0x2080, 0x2090, 0x20A0, 0x20B0)):
        struct.pack_into("<I", buf, 0x430 + index * 4, rva)
        struct.pack_into("<I", buf, 0x450 + index * 4, rva)
    buf[0x470:0x47D] = b"KERNEL32.dll\0"
    for off, name in ((0x480, b"CreateFileA"), (0x490, b"WriteFile"),
                      (0x4A0, b"CloseHandle"), (0x4B0, b"ExitProcess")):
        buf[off:off + 2 + len(name) + 1] = b"\0\0" + name + b"\0"
    guest_path = b"C:\\Users\\Alex\\Downloads\\native-output.bin\0"
    buf[0x4C0:0x4C0 + len(guest_path)] = guest_path
    payload = b"native payload marker"
    buf[0x500:0x500 + len(payload)] = payload
    code = bytearray()

    def push32(value: int) -> None:
        code.extend(b"\x68" + struct.pack("<I", value))

    def call_iat(index: int) -> None:
        code.extend(b"\xff\x15" + struct.pack("<I", image_base + 0x2050 + index * 4))

    for value in (0, 0, 2, 0, 0, 0x40000000, image_base + 0x20C0):
        push32(value)
    call_iat(0)
    code.extend(b"\x89\xc3")  # mov ebx, eax
    for value in (0, image_base + 0x2110, len(payload), image_base + 0x2100):
        push32(value)
    code.extend(b"\x53")  # push ebx
    call_iat(1)
    code.extend(b"\x53")
    call_iat(2)
    push32(0)
    call_iat(3)
    code.extend(b"\xc3")
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_signature_stub_x86() -> bytes:
    """Call a signature-known API with no modeled side effect, then exit."""
    buf = bytearray(build(0x14C))
    image_base = 0x400000
    for offset in (0x430, 0x440):
        struct.pack_into("<III", buf, offset, 0x2070, 0x2090, 0)
    buf[0x470:0x488] = b"\0\0MoveFileWithProgressW\0"
    buf[0x490:0x49E] = b"\0\0ExitProcess\0"
    old_path = "C:\\Users\\Alex\\Downloads\\old.txt".encode("utf-16le") + b"\0\0"
    new_path = "C:\\Users\\Alex\\Downloads\\new.txt".encode("utf-16le") + b"\0\0"
    buf[0x4C0:0x4C0 + len(old_path)] = old_path
    buf[0x520:0x520 + len(new_path)] = new_path
    code = bytearray()
    for value in (0, 0, 0, image_base + 0x2120, image_base + 0x20C0):
        code += b"\x68" + struct.pack("<I", value)
    code += b"\xff\x15" + struct.pack("<I", image_base + 0x2040)
    code += b"\x6a\x00\xff\x15" + struct.pack("<I", image_base + 0x2044)
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_local_network_x86() -> bytes:
    """Try connecting to 127.0.0.1; the broker must deny host access."""
    buf = bytearray(build(0x14C))
    struct.pack_into("<II", buf, 0x98 + 96 + 8, 0x2000, 0x3C)
    buf[0x400:0x43C] = b"\0" * 0x3C
    struct.pack_into("<IIIII", buf, 0x400, 0x2050, 0, 0, 0x20B0, 0x2070)
    struct.pack_into("<IIIII", buf, 0x414, 0x2060, 0, 0, 0x20C0, 0x2090)
    for i, rva in enumerate((0x20D0, 0x20E0, 0x20F0)):
        struct.pack_into("<I", buf, 0x450 + i * 4, rva)
        struct.pack_into("<I", buf, 0x470 + i * 4, rva)
    struct.pack_into("<I", buf, 0x460, 0x2110)
    struct.pack_into("<I", buf, 0x490, 0x2110)
    buf[0x4B0:0x4BB] = b"ws2_32.dll\0"
    buf[0x4C0:0x4CD] = b"KERNEL32.dll\0"
    for off, name in ((0x4D0, b"socket"), (0x4E0, b"connect"),
                      (0x4F0, b"closesocket"), (0x510, b"ExitProcess")):
        buf[off:off + 2 + len(name) + 1] = b"\0\0" + name + b"\0"
    buf[0x530:0x540] = b"\x02\x00\x00\x50\x7f\x00\x00\x01" + b"\0" * 8
    code = bytearray()

    def push(value: int) -> None:
        code.extend(b"\x68" + struct.pack("<I", value))

    def call(addr: int) -> None:
        code.extend(b"\xff\x15" + struct.pack("<I", 0x400000 + addr))

    for value in (0, 1, 2):
        push(value)
    call(0x2070)
    code.extend(b"\x89\xc3")
    for value in (16, 0x400000 + 0x2130):
        push(value)
    code.extend(b"\x53")
    call(0x2074)
    code.extend(b"\x53")
    call(0x2078)
    push(0)
    call(0x2090)
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_urlmon_download(machine: int, *, cache: bool = False, wide: bool = True,
                          url: str = "http://127.0.0.1/payload.bin") -> bytes:
    """Download a harmless URL into guest storage, then exit with API success."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * 0x200)
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<II", buf, section + 8, 0x400, 0x2000)
    struct.pack_into("<I", buf, section + 16, 0x400)
    dd = 0x98 + (112 if is_x64 else 96)
    struct.pack_into("<II", buf, dd + 8, 0x2000, 0x3C)
    buf[0x400:0x600] = b"\0" * 0x200
    struct.pack_into("<IIIII", buf, 0x400, 0x2040, 0, 0, 0x20E0, 0x2060)
    struct.pack_into("<IIIII", buf, 0x414, 0x2050, 0, 0, 0x20F0, 0x2070)
    fmt = "<Q" if is_x64 else "<I"
    for offset, target in ((0x440, 0x20A0), (0x450, 0x20C0),
                           (0x460, 0x20A0), (0x470, 0x20C0)):
        struct.pack_into(fmt, buf, offset, target)
    api = (b"URLDownloadToCacheFile" if cache else b"URLDownloadToFile") + (b"W" if wide else b"A")
    buf[0x4A0:0x4A0 + len(api) + 3] = b"\0\0" + api + b"\0"
    buf[0x4C0:0x4CE] = b"\0\0ExitProcess\0"
    buf[0x4E0:0x4EB] = b"URLMON.dll\0"
    buf[0x4F0:0x4FD] = b"KERNEL32.dll\0"
    encoding = "utf-16le" if wide else "ascii"
    raw_url = url.encode(encoding) + (b"\0\0" if wide else b"\0")
    assert len(raw_url) < 0x100
    buf[0x520:0x520 + len(raw_url)] = raw_url
    if not cache:
        path = r"C:\Users\Alex\Downloads\urlmon-output.bin".encode(encoding) + (b"\0\0" if wide else b"\0")
        buf[0x620:0x620 + len(path)] = path
    code = bytearray()

    def call(rva: int):
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    if is_x64:
        code.extend(b"\x48\x83\xec\x38\x48\x31\xc9")
        code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x2120))
        code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x2220))
        code.extend((b"\x41\xb9" + struct.pack("<I", 128)) if cache else b"\x45\x31\xc9")
        code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
        if cache:
            code.extend(b"\x48\xc7\x44\x24\x28\0\0\0\0")
        call(0x2060)
        if cache:
            displacement = 0x2220 - (0x1000 + len(code) + 7)
            code.extend(b"\x80\x3d" + struct.pack("<i", displacement) + b"\x43")
            code.extend(b"\x74\x05\xb8\x01\0\0\0")
        code.extend(b"\x85\xc0\x0f\x94\xc0\x0f\xb6\xc8")
        call(0x2070)
        code.extend(b"\x48\x83\xc4\x38\xc3")
    else:
        values = ([0, 0, 128, base + 0x2220, base + 0x2120, 0] if cache
                  else [0, 0, base + 0x2220, base + 0x2120, 0])
        for value in values:
            code.extend(b"\x68" + struct.pack("<I", value))
        call(0x2060)
        if cache:
            code.extend(b"\x80\x3d" + struct.pack("<I", base + 0x2220) + b"\x43")
            code.extend(b"\x74\x05\xb8\x01\0\0\0")
        code.extend(b"\x85\xc0\x0f\x94\xc0\x0f\xb6\xc0\x50")
        call(0x2070)
        code.extend(b"\xc3")
    assert len(code) < 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_invalid_network_request(machine: int, api: str) -> bytes:
    """Call a network API with harmless invalid inputs and exit with its result."""
    assert api in ("InternetOpenUrlA", "HttpSendRequestA", "WinHttpSendRequest",
                   "gethostbyname")
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build_urlmon_download(machine, wide=False))
    buf[0x4A0:0x4C0] = b"\0" * 0x20
    name = api.encode("ascii")
    buf[0x4A0:0x4A0 + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x4E0:0x4F0] = b"\0" * 0x10
    dll_name = (b"WS2_32.dll\0" if api == "gethostbyname" else
                b"WINHTTP.dll\0" if api.startswith("WinHttp") else b"WININET.dll\0")
    buf[0x4E0:0x4E0 + len(dll_name)] = dll_name
    code = bytearray()

    def call(rva: int) -> None:
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    if is_x64:
        code.extend(b"\x48\x83\xec\x48\x48\x31\xc9\x48\x31\xd2\x45\x31\xc0\x45\x31\xc9")
        if api == "InternetOpenUrlA":
            code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x2120))
        for offset in (0x20, 0x28, 0x30):
            code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + b"\0\0\0\0")
        call(0x2060)
        code.extend(b"\x48\x89\xc1")
        call(0x2070)
        code.extend(b"\x48\x83\xc4\x48\xc3")
    else:
        count = (1 if api == "gethostbyname" else
                 6 if api == "InternetOpenUrlA" else
                 7 if api == "WinHttpSendRequest" else 5)
        for index in range(count):
            value = base + 0x2120 if api == "InternetOpenUrlA" and index == 4 else 0
            code.extend(b"\x68" + struct.pack("<I", value))
        call(0x2060)
        code.extend(b"\x50")
        call(0x2070)
        code.extend(b"\xc3")
    buf[0x200:0x400] = b"\0" * 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_wininet_session_probe(machine: int,
                               url: str = "http://127.0.0.1/marker",
                               headers: str = "", read_response: bool = False,
                               query_status: bool = False,
                               query_available: bool = False) -> bytes:
    """Open a modeled WinINet session, then request a supplied URL."""
    is_x64 = machine == 0x8664
    assert not query_status or read_response
    assert not query_available or read_response
    assert not (query_status and query_available)
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build_urlmon_download(machine, wide=False))
    buf[0x400:0x800] = b"\0" * 0x400
    struct.pack_into("<IIIII", buf, 0x400, 0x2040, 0, 0, 0x2110, 0x2060)
    struct.pack_into("<IIIII", buf, 0x414, 0x2080, 0, 0, 0x2120, 0x2090)
    fmt, step = ("<Q", 8) if is_x64 else ("<I", 4)
    for raw in (0x440, 0x460):
        struct.pack_into(fmt, buf, raw, 0x20B0)
        struct.pack_into(fmt, buf, raw + step, 0x20D0)
        if read_response:
            struct.pack_into(fmt, buf, raw + 2 * step, 0x2200)
        if query_status or query_available:
            struct.pack_into(fmt, buf, raw + 3 * step, 0x2220)
    for raw in (0x480, 0x490):
        struct.pack_into(fmt, buf, raw, 0x20F0)
    for raw, name in ((0x4B0, b"InternetOpenA"),
                      (0x4D0, b"InternetOpenUrlA"),
                      (0x4F0, b"ExitProcess")):
        buf[raw:raw + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x510:0x51C] = b"WININET.dll\0"
    buf[0x520:0x52D] = b"KERNEL32.dll\0"
    raw_url = url.encode("ascii") + b"\0"
    assert len(raw_url) < 0x200
    buf[0x540:0x540 + len(raw_url)] = raw_url
    raw_headers = headers.encode("latin-1") + b"\0"
    assert len(raw_url) < 0x40 and len(raw_headers) < 0x80
    buf[0x580:0x580 + len(raw_headers)] = raw_headers
    if read_response:
        buf[0x600:0x613] = b"\0\0InternetReadFile\0"
    if query_status:
        buf[0x620:0x631] = b"\0\0HttpQueryInfoA\0"
        struct.pack_into("<I", buf, 0x7C0, 4)
    if query_available:
        buf[0x620:0x63D] = b"\0\0InternetQueryDataAvailable\0"
    code = bytearray()

    def call(rva: int) -> None:
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    if is_x64:
        code.extend(b"\x48\x83\xec\x48\x48\x31\xc9\x48\x31\xd2\x45\x31\xc0\x45\x31\xc9")
        code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
        call(0x2060)
        code.extend(b"\x48\x89\xc1\x48\xba" + struct.pack("<Q", base + 0x2140))
        if headers:
            code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x2180))
            code.extend(b"\x41\xb9" + struct.pack("<I", len(headers)))
        else:
            code.extend(b"\x45\x31\xc0\x45\x31\xc9")
        for offset in (0x20, 0x28):
            code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + b"\0\0\0\0")
        call(0x2068)
        if read_response:
            if query_status or query_available:
                code.extend(b"\x48\x89\xc3")
            if query_status:
                code.extend(b"\x48\x89\xc3\x48\x89\xd9\xba\x13\0\0\x20")
                code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x2380))
                code.extend(b"\x49\xb9" + struct.pack("<Q", base + 0x23C0))
                code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
                call(0x2078)
                code.extend(b"\x48\x89\xd9")
            else:
                code.extend(b"\x48\x89\xd9" if query_available else b"\x48\x89\xc1")
            code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x2300))
            code.extend(b"\x41\xb8\x04\0\0\0\x49\xb9" +
                        struct.pack("<Q", base + 0x2340))
            call(0x2070)
            code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x2300))
            code.extend(b"\x8b\x08\x33\x48\x40")
            if query_status:
                code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x2380))
                code.extend(b"\x33\x08")
            if query_available:
                code.extend(b"\x89\xce\x48\x89\xd9\x48\xba" +
                            struct.pack("<Q", base + 0x2380))
                code.extend(b"\x45\x31\xc0\x45\x31\xc9")
                call(0x2078)
                code.extend(b"\x89\xf1\x48\xb8" + struct.pack("<Q", base + 0x2380))
                code.extend(b"\x33\x08")
        else:
            code.extend(b"\x48\x89\xc1")
        call(0x2090)
        code.extend(b"\x48\x83\xc4\x48\xc3")
    else:
        code.extend(b"\x6a\0" * 5)
        call(0x2060)
        code.extend(b"\x89\xc3")
        for value in (0, 0, len(headers), base + 0x2180 if headers else 0):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\x68" + struct.pack("<I", base + 0x2140) + b"\x53")
        call(0x2064)
        if read_response:
            if query_status or query_available:
                code.extend(b"\x89\xc3")
            if query_status:
                for value in (0, base + 0x23C0, base + 0x2380, 0x20000013):
                    code.extend(b"\x68" + struct.pack("<I", value))
                code.extend(b"\x53")
                call(0x206C)
            for value in (base + 0x2340, 4, base + 0x2300):
                code.extend(b"\x68" + struct.pack("<I", value))
            code.extend(b"\x53" if query_status or query_available else b"\x50")
            call(0x2068)
            code.extend(b"\xa1" + struct.pack("<I", base + 0x2300))
            code.extend(b"\x33\x05" + struct.pack("<I", base + 0x2340))
            if query_status:
                code.extend(b"\x33\x05" + struct.pack("<I", base + 0x2380))
            if query_available:
                code.extend(b"\x89\xc6\x6a\0\x6a\0\x68" +
                            struct.pack("<I", base + 0x2380) + b"\x53")
                call(0x206C)
                code.extend(b"\x89\xf0\x33\x05" + struct.pack("<I", base + 0x2380))
        code.extend(b"\x50")
        call(0x2090)
        code.extend(b"\xc3")
    buf[0x200:0x400] = b"\0" * 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_wininet_post_probe(machine: int, *, host: str = "127.0.0.1",
                             port: int = 80,
                             invalid_stage: str | None = None) -> bytes:
    """Send a harmless WinINet POST and verify response APIs in guest code."""
    is_x64 = machine == 0x8664
    assert invalid_stage in (None, "connect", "request")
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * (0xC00 - len(buf)))
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<II", buf, section + 8, 0x800, 0x2000)
    struct.pack_into("<I", buf, section + 16, 0x800)
    dd = 0x98 + (112 if is_x64 else 96)
    struct.pack_into("<II", buf, dd + 8, 0x2000, 0x3C)
    buf[0x400:0xC00] = b"\0" * 0x800
    struct.pack_into("<IIIII", buf, 0x400, 0x2040, 0, 0, 0x21E0, 0x2080)
    struct.pack_into("<IIIII", buf, 0x414, 0x20C0, 0, 0, 0x21F0, 0x20D0)
    fmt, step = ("<Q", 8) if is_x64 else ("<I", 4)
    for raw in (0x440, 0x480):
        for index, target in enumerate((0x2100, 0x2130, 0x2160, 0x2190,
                                        0x2400, 0x2430, 0x2460)):
            struct.pack_into(fmt, buf, raw + index * step, target)
    for raw in (0x4C0, 0x4D0):
        struct.pack_into(fmt, buf, raw, 0x21C0)
    for raw, name in ((0x500, b"InternetOpenA"), (0x530, b"InternetConnectA"),
                      (0x560, b"HttpOpenRequestA"), (0x590, b"HttpSendRequestA"),
                      (0x800, b"InternetReadFile"), (0x830, b"HttpQueryInfoA"),
                      (0x860, b"InternetQueryDataAvailable"),
                      (0x5C0, b"ExitProcess")):
        buf[raw:raw + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5E0:0x5EC] = b"WININET.dll\0"
    buf[0x5F0:0x5FD] = b"KERNEL32.dll\0"
    body = b"harmless WinINet body"
    headers = b"X-Test: emumee\r\n"
    for raw, value in ((0x600, b"Emumee"), (0x640, host.encode("ascii")),
                       (0x680, b"POST"), (0x6C0, b"/marker"),
                       (0x700, headers), (0x780, body)):
        assert len(value) < 0x40
        buf[raw:raw + len(value) + 1] = value + b"\0"
    struct.pack_into("<I", buf, 0x9C0, 4)
    code = bytearray()

    def call(rva: int) -> None:
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    if is_x64:
        code.extend(b"\x48\x83\xec\x58\x48\xb9" + struct.pack("<Q", base + 0x2200))
        code.extend(b"\x31\xd2\x45\x31\xc0\x45\x31\xc9")
        code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
        call(0x2080)
        code.extend(b"\x48\x89\xc3")
        code.extend(b"\x31\xc9" if invalid_stage == "connect" else b"\x48\x89\xd9")
        code.extend(b"\x48\xba" +
                    struct.pack("<Q", base + 0x2240))
        code.extend(b"\x41\xb8" + struct.pack("<I", port) + b"\x45\x31\xc9")
        for offset, value in ((0x20, 0), (0x28, 3), (0x30, 0), (0x38, 0)):
            code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
        call(0x2088)
        code.extend(b"\x48\x89\xc6")
        code.extend(b"\x31\xc9" if invalid_stage == "request" else b"\x48\x89\xf1")
        code.extend(b"\x48\xba" +
                    struct.pack("<Q", base + 0x2280))
        code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x22C0) + b"\x45\x31\xc9")
        for offset in (0x20, 0x28, 0x30, 0x38):
            code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + b"\0\0\0\0")
        call(0x2090)
        code.extend(b"\x48\x89\xc7\x48\x89\xf9\x48\xba" +
                    struct.pack("<Q", base + 0x2300))
        code.extend(b"\x41\xb8" + struct.pack("<I", len(headers)))
        code.extend(b"\x49\xb9" + struct.pack("<Q", base + 0x2380))
        code.extend(b"\x48\xc7\x44\x24\x20" + struct.pack("<I", len(body)))
        call(0x2098)
        code.extend(b"\x41\x89\xc4\x48\x89\xf9\xba\x13\0\0\x20")
        code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x2580))
        code.extend(b"\x49\xb9" + struct.pack("<Q", base + 0x25C0))
        code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
        call(0x20A8)
        code.extend(b"\x48\x89\xf9\x48\xba" + struct.pack("<Q", base + 0x2500))
        code.extend(b"\x41\xb8\x04\0\0\0\x49\xb9" +
                    struct.pack("<Q", base + 0x2540))
        call(0x20A0)
        code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x2500))
        code.extend(b"\x8b\x08\x33\x48\x40")
        code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x2580) + b"\x33\x08")
        code.extend(b"\x89\xce\x48\x89\xf9\x48\xba" +
                    struct.pack("<Q", base + 0x2640))
        code.extend(b"\x45\x31\xc0\x45\x31\xc9")
        call(0x20B0)
        code.extend(b"\x89\xf1\x48\xb8" + struct.pack("<Q", base + 0x2640))
        code.extend(b"\x33\x08\x44\x31\xe1")
        call(0x20D0)
        code.extend(b"\x48\x83\xc4\x58\xc3")
    else:
        for value in (0, 0, 0, 0, base + 0x2200):
            code.extend(b"\x68" + struct.pack("<I", value))
        call(0x2080)
        code.extend(b"\x89\xc3")
        for value in (0, 0, 3, 0, 0, port, base + 0x2240):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\x6a\0" if invalid_stage == "connect" else b"\x53")
        call(0x2084)
        code.extend(b"\x89\xc6")
        for value in (0, 0, 0, 0, 0, base + 0x22C0, base + 0x2280):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\x6a\0" if invalid_stage == "request" else b"\x56")
        call(0x2088)
        code.extend(b"\x89\xc7")
        for value in (len(body), base + 0x2380, len(headers), base + 0x2300):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\x57")
        call(0x208C)
        code.extend(b"\x89\xc5")
        for value in (0, base + 0x25C0, base + 0x2580, 0x20000013):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\x57")
        call(0x2094)
        for value in (base + 0x2540, 4, base + 0x2500):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\x57")
        call(0x2090)
        code.extend(b"\xa1" + struct.pack("<I", base + 0x2500))
        code.extend(b"\x33\x05" + struct.pack("<I", base + 0x2540))
        code.extend(b"\x33\x05" + struct.pack("<I", base + 0x2580))
        code.extend(b"\x89\xc6\x6a\0\x6a\0\x68" +
                    struct.pack("<I", base + 0x2640) + b"\x57")
        call(0x2098)
        code.extend(b"\x89\xf0\x33\x05" + struct.pack("<I", base + 0x2640))
        code.extend(b"\x31\xe8\x50")
        call(0x20D0)
        code.extend(b"\xc3")
    assert len(code) < 0x200
    buf[0x200:0x400] = b"\0" * 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_wininet_stream_probe(machine: int, *, host: str = "127.0.0.1",
                               port: int = 80, linked: bool = False) -> bytes:
    """Send a fixed-length POST using WinINet's streaming API sequence."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build_wininet_post_probe(machine, host=host, port=port))
    for raw, name in ((0x590, b"HttpSendRequestExA"),
                      (0x800, b"InternetWriteFile"),
                      (0x830, b"HttpEndRequestA"),
                      (0x860, b"InternetReadFile")):
        buf[raw:raw + 0x30] = b"\0" * 0x30
        buf[raw:raw + len(name) + 3] = b"\0\0" + name + b"\0"
    body = b"harmless WinINet body"
    initial = b"harmless "
    remaining = body[len(initial):]
    buf[0x7A0:0x7A0 + len(remaining)] = remaining
    headers = b"X-Test: emumee\r\n"
    next_ptr = base + 0x26C0 if linked else 0
    if is_x64:
        struct.pack_into("<I4xQQIIQIIII", buf, 0xA80, 56, next_ptr,
                         base + 0x2300, len(headers), 0,
                         base + 0x2380, len(initial), len(body), 0, 0)
    else:
        struct.pack_into("<10I", buf, 0xA80, 40, next_ptr,
                         base + 0x2300, len(headers), 0,
                         base + 0x2380, len(initial), len(body), 0, 0)
    if linked:
        ignored_body = b"linked-ignored"
        ignored_header = b"X-Tail: ignored\r\n"
        buf[0xB20:0xB20 + len(ignored_body)] = ignored_body
        buf[0xB40:0xB40 + len(ignored_header)] = ignored_header
        if is_x64:
            struct.pack_into("<I4xQQIIQIIII", buf, 0xAC0, 56, 0,
                             base + 0x2740, len(ignored_header), 0,
                             base + 0x2720, len(ignored_body), len(body), 0, 0)
        else:
            struct.pack_into("<10I", buf, 0xAC0, 40, 0,
                             base + 0x2740, len(ignored_header), 0,
                             base + 0x2720, len(ignored_body), len(body), 0, 0)
    code = bytearray()

    def call(rva: int) -> None:
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    if is_x64:
        code.extend(b"\x48\x83\xec\x58\x48\xb9" + struct.pack("<Q", base + 0x2200))
        code.extend(b"\x31\xd2\x45\x31\xc0\x45\x31\xc9")
        code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
        call(0x2080)
        code.extend(b"\x48\x89\xc3\x48\x89\xd9\x48\xba" +
                    struct.pack("<Q", base + 0x2240))
        code.extend(b"\x41\xb8" + struct.pack("<I", port) + b"\x45\x31\xc9")
        for offset, value in ((0x20, 0), (0x28, 3), (0x30, 0), (0x38, 0)):
            code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
        call(0x2088)
        code.extend(b"\x48\x89\xc6\x48\x89\xf1\x48\xba" +
                    struct.pack("<Q", base + 0x2280))
        code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x22C0) + b"\x45\x31\xc9")
        for offset in (0x20, 0x28, 0x30, 0x38):
            code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + b"\0\0\0\0")
        call(0x2090)
        code.extend(b"\x48\x89\xc7\x48\x89\xf9\x48\xba" +
                    struct.pack("<Q", base + 0x2680))
        code.extend(b"\x45\x31\xc0\x45\x31\xc9")
        code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
        call(0x2098)
        code.extend(b"\x41\x89\xc4\x48\x89\xf9\x48\xba" +
                    struct.pack("<Q", base + 0x23A0))
        code.extend(b"\x41\xb8" + struct.pack("<I", len(remaining)))
        code.extend(b"\x49\xb9" + struct.pack("<Q", base + 0x2600))
        call(0x20A0)
        code.extend(b"\x48\x89\xf9\x31\xd2\x45\x31\xc0\x45\x31\xc9")
        call(0x20A8)
        code.extend(b"\x41\x89\xc5\x48\x89\xf9\x48\xba" +
                    struct.pack("<Q", base + 0x2500))
        code.extend(b"\x41\xb8\x04\0\0\0\x49\xb9" +
                    struct.pack("<Q", base + 0x2540))
        call(0x20B0)
        code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x2500))
        code.extend(b"\x8b\x08\x33\x48\x40")
        code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x2600))
        code.extend(b"\x33\x08\x44\x31\xe1\x44\x31\xe9")
        call(0x20D0)
        code.extend(b"\x48\x83\xc4\x58\xc3")
    else:
        for value in (0, 0, 0, 0, base + 0x2200):
            code.extend(b"\x68" + struct.pack("<I", value))
        call(0x2080)
        code.extend(b"\x89\xc3")
        for value in (0, 0, 3, 0, 0, port, base + 0x2240):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\x53")
        call(0x2084)
        code.extend(b"\x89\xc6")
        for value in (0, 0, 0, 0, 0, base + 0x22C0, base + 0x2280):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\x56")
        call(0x2088)
        code.extend(b"\x89\xc7")
        for value in (0, 0, 0, base + 0x2680):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\x57")
        call(0x208C)
        code.extend(b"\x89\xc5")
        for value in (base + 0x2600, len(remaining), base + 0x23A0):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\x57")
        call(0x2090)
        code.extend(b"\x6a\0\x6a\0\x6a\0\x57")
        call(0x2094)
        code.extend(b"\x89\xc3")
        for value in (base + 0x2540, 4, base + 0x2500):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\x57")
        call(0x2098)
        code.extend(b"\xa1" + struct.pack("<I", base + 0x2500))
        code.extend(b"\x33\x05" + struct.pack("<I", base + 0x2540))
        code.extend(b"\x33\x05" + struct.pack("<I", base + 0x2600))
        code.extend(b"\x31\xe8\x31\xd8\x50")
        call(0x20D0)
        code.extend(b"\xc3")
    assert len(code) < 0x200
    buf[0x200:0x400] = b"\0" * 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_winhttp_post_probe(machine: int, *, host: str = "127.0.0.1",
                             port: int = 80, read_response: bool = False,
                             query_status: bool = False,
                             streamed: bool = False,
                             query_available: bool = False,
                             chunked: bool = False) -> bytes:
    """Send a harmless native WinHTTP POST with one custom header."""
    is_x64 = machine == 0x8664
    assert not query_status or read_response
    assert not streamed or read_response
    assert not chunked or streamed
    assert not query_available or read_response
    assert not (query_available and streamed)
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * (0xC00 - len(buf)))
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<II", buf, section + 8, 0x800, 0x2000)
    struct.pack_into("<I", buf, section + 16, 0x800)
    dd = 0x98 + (112 if is_x64 else 96)
    struct.pack_into("<II", buf, dd + 8, 0x2000, 0x3C)
    buf[0x400:0xC00] = b"\0" * 0x800
    struct.pack_into("<IIIII", buf, 0x400, 0x2040, 0, 0, 0x21E0, 0x2080)
    struct.pack_into("<IIIII", buf, 0x414, 0x20C0, 0, 0, 0x21F0, 0x20D0)
    fmt, step = ("<Q", 8) if is_x64 else ("<I", 4)
    for raw in (0x440, 0x480):
        for index, target in enumerate((0x2100, 0x2130, 0x2160, 0x2190)):
            struct.pack_into(fmt, buf, raw + index * step, target)
        if read_response:
            for index, target in enumerate((0x2400, 0x2430), start=4):
                struct.pack_into(fmt, buf, raw + index * step, target)
        if query_status:
            struct.pack_into(fmt, buf, raw + 6 * step, 0x2460)
        if streamed:
            struct.pack_into(fmt, buf, raw + 7 * step, 0x2490)
        if query_available:
            struct.pack_into(fmt, buf, raw + 7 * step, 0x2490)
    for raw in (0x4C0, 0x4D0):
        struct.pack_into(fmt, buf, raw, 0x21C0)
    for raw, name in ((0x500, b"WinHttpOpen"), (0x530, b"WinHttpConnect"),
                      (0x560, b"WinHttpOpenRequest"),
                      (0x590, b"WinHttpSendRequest"), (0x5C0, b"ExitProcess")):
        buf[raw:raw + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5E0:0x5EC] = b"WINHTTP.dll\0"
    buf[0x5F0:0x5FD] = b"KERNEL32.dll\0"
    header_text = (("Transfer-Encoding: chunked\r\n" if chunked else "") +
                   "X-Test: emumee\r\n")
    for raw, value in ((0x600, "Emumee"), (0x640, host),
                       (0x680, "POST"), (0x6C0, "/marker"),
                       (0x700, header_text)):
        encoded = value.encode("utf-16le") + b"\0\0"
        assert len(encoded) < (0x80 if raw == 0x700 else 0x40)
        buf[raw:raw + len(encoded)] = encoded
    body = b"harmless WinHTTP body"
    buf[0x780:0x780 + len(body)] = body
    initial_body = b"" if chunked else b"harmless " if streamed else body
    remaining_body = body[len(initial_body):]
    if streamed:
        buf[0x7A0:0x7A0 + len(remaining_body)] = remaining_body
        buf[0x890:0x8A3] = b"\0\0WinHttpWriteData\0"
    if query_available:
        buf[0x890:0x8AC] = b"\0\0WinHttpQueryDataAvailable\0"
    if read_response:
        for raw, name in ((0x800, b"WinHttpReceiveResponse"),
                          (0x830, b"WinHttpReadData")):
            buf[raw:raw + len(name) + 3] = b"\0\0" + name + b"\0"
    if query_status:
        buf[0x860:0x876] = b"\0\0WinHttpQueryHeaders\0"
        struct.pack_into("<I", buf, 0x9C0, 4)
    headers_chars = len(header_text)
    code = bytearray()

    def call(rva: int) -> None:
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    if is_x64:
        code.extend(b"\x48\x83\xec\x48\x48\xb9" + struct.pack("<Q", base + 0x2200))
        code.extend(b"\x31\xd2\x45\x31\xc0\x45\x31\xc9")
        code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
        call(0x2080)
        code.extend(b"\x48\x89\xc3\x48\x89\xd9\x48\xba" +
                    struct.pack("<Q", base + 0x2240))
        code.extend(b"\x41\xb8" + struct.pack("<I", port) + b"\x45\x31\xc9")
        call(0x2088)
        code.extend(b"\x48\x89\xc6\x48\x89\xf1\x48\xba" +
                    struct.pack("<Q", base + 0x2280))
        code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x22C0) + b"\x45\x31\xc9")
        for offset in (0x20, 0x28, 0x30):
            code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + b"\0\0\0\0")
        call(0x2090)
        code.extend(b"\x48\x89\xc7\x48\x89\xf9\x48\xba" +
                    struct.pack("<Q", base + 0x2300))
        code.extend(b"\x41\xb8" + struct.pack("<I", headers_chars))
        code.extend(b"\x49\xb9" + struct.pack("<Q", 0 if chunked else base + 0x2380))
        for offset, value in ((0x20, len(initial_body)),
                              (0x28, 0xFFFFFFFF if chunked else len(body)), (0x30, 0)):
            code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
        call(0x2098)
        if read_response:
            if streamed:
                code.extend(b"\x48\x89\xf9\x48\xba" + struct.pack("<Q", base + 0x23A0))
                code.extend(b"\x41\xb8" + struct.pack("<I", len(remaining_body)))
                code.extend(b"\x49\xb9" + struct.pack("<Q", base + 0x2600))
                call(0x20B8)
                if chunked:
                    code.extend(b"\x48\x89\xf9\x31\xd2\x45\x31\xc0\x49\xb9" +
                                struct.pack("<Q", base + 0x2608))
                    call(0x20B8)
            code.extend(b"\x48\x89\xf9\x31\xd2")
            call(0x20A0)
            if query_status:
                code.extend(b"\x48\x89\xf9\xba\x13\0\0\x20\x45\x31\xc0")
                code.extend(b"\x49\xb9" + struct.pack("<Q", base + 0x2580))
                code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x25C0))
                code.extend(b"\x48\x89\x44\x24\x20")
                code.extend(b"\x48\xc7\x44\x24\x28\0\0\0\0")
                call(0x20B0)
            code.extend(b"\x48\x89\xf9\x48\xba" + struct.pack("<Q", base + 0x2500))
            code.extend(b"\x41\xb8\x04\0\0\0\x49\xb9" +
                        struct.pack("<Q", base + 0x2540))
            call(0x20A8)
            code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x2500))
            code.extend(b"\x8b\x08\x33\x48\x40")
            if query_status:
                code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x2580))
                code.extend(b"\x33\x08")
            if streamed:
                code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x2600))
                code.extend(b"\x33\x08")
            if query_available:
                code.extend(b"\x89\xce\x48\x89\xf9\x48\xba" +
                            struct.pack("<Q", base + 0x2640))
                call(0x20B8)
                code.extend(b"\x89\xf1\x48\xb8" + struct.pack("<Q", base + 0x2640))
                code.extend(b"\x33\x08")
        else:
            code.extend(b"\x48\x89\xc1")
        call(0x20D0)
        code.extend(b"\x48\x83\xc4\x48\xc3")
    else:
        for value in (0, 0, 0, 0, base + 0x2200):
            code.extend(b"\x68" + struct.pack("<I", value))
        call(0x2080)
        code.extend(b"\x89\xc3")
        for value in (0, port, base + 0x2240):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\x53")
        call(0x2084)
        code.extend(b"\x89\xc6")
        for value in (0, 0, 0, 0, base + 0x22C0, base + 0x2280):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\x56")
        call(0x2088)
        code.extend(b"\x89\xc7")
        for value in (0, 0xFFFFFFFF if chunked else len(body), len(initial_body),
                      0 if chunked else base + 0x2380,
                      headers_chars, base + 0x2300):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\x57")
        call(0x208C)
        if read_response:
            if streamed:
                for value in (base + 0x2600, len(remaining_body), base + 0x23A0):
                    code.extend(b"\x68" + struct.pack("<I", value))
                code.extend(b"\x57")
                call(0x209C)
                if chunked:
                    for value in (base + 0x2608, 0, 0):
                        code.extend(b"\x68" + struct.pack("<I", value))
                    code.extend(b"\x57")
                    call(0x209C)
            code.extend(b"\x6a\0\x57")
            call(0x2090)
            if query_status:
                for value in (0, base + 0x25C0, base + 0x2580, 0,
                              0x20000013):
                    code.extend(b"\x68" + struct.pack("<I", value))
                code.extend(b"\x57")
                call(0x2098)
            for value in (base + 0x2540, 4, base + 0x2500):
                code.extend(b"\x68" + struct.pack("<I", value))
            code.extend(b"\x57")
            call(0x2094)
            code.extend(b"\xa1" + struct.pack("<I", base + 0x2500))
            code.extend(b"\x33\x05" + struct.pack("<I", base + 0x2540))
            if query_status:
                code.extend(b"\x33\x05" + struct.pack("<I", base + 0x2580))
            if streamed:
                code.extend(b"\x33\x05" + struct.pack("<I", base + 0x2600))
            if query_available:
                code.extend(b"\x89\xc6\x68" + struct.pack("<I", base + 0x2640) + b"\x57")
                call(0x209C)
                code.extend(b"\x89\xf0\x33\x05" + struct.pack("<I", base + 0x2640))
        code.extend(b"\x50")
        call(0x20D0)
        code.extend(b"\xc3")
    assert len(code) < 0x200
    buf[0x200:0x400] = b"\0" * 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_load_library(machine: int) -> bytes:
    """Load an explicitly supplied companion DLL before exiting."""
    is_x64 = machine == 0x8664
    buf = bytearray(build(machine))
    image_base = 0x140000000 if is_x64 else 0x400000
    fmt = "<Q" if is_x64 else "<I"
    step = 8 if is_x64 else 4
    for offset in (0x430, 0x440):
        struct.pack_into(fmt, buf, offset, 0x2070)
        struct.pack_into(fmt, buf, offset + step, 0x2080)
        struct.pack_into(fmt, buf, offset + 2 * step, 0)
    buf[0x470:0x47D] = b"\0\0LoadLibraryA\0"
    buf[0x480:0x48E] = b"\0\0ExitProcess\0"
    name = b"companion_x64.dll\0" if is_x64 else b"companion_x86.dll\0"
    buf[0x4A0:0x4A0 + len(name)] = name
    if is_x64:
        code = bytearray(b"\x48\xb9" + struct.pack("<Q", image_base + 0x20A0))
        code += b"\xff\x15" + struct.pack("<i", 0x2040 - (0x1000 + len(code) + 6))
        code += b"\x31\xc9"
        code += b"\xff\x15" + struct.pack("<i", 0x2048 - (0x1000 + len(code) + 6))
    else:
        code = bytearray(b"\x68" + struct.pack("<I", image_base + 0x20A0))
        code += b"\xff\x15" + struct.pack("<I", image_base + 0x2040)
        code += b"\x6a\x00\xff\x15" + struct.pack("<I", image_base + 0x2044)
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_load_library_ex(machine: int) -> bytes:
    """Call LoadLibraryExA with its three arguments and exit with the HMODULE."""
    is_x64 = machine == 0x8664
    buf = bytearray(build_load_library(machine))
    image_base = 0x140000000 if is_x64 else 0x400000
    fmt = "<Q" if is_x64 else "<I"
    for offset in (0x430, 0x440):
        struct.pack_into(fmt, buf, offset, 0x20D0)
    buf[0x4D0:0x4E1] = b"\0\0LoadLibraryExA\0"
    if is_x64:
        code = bytearray(b"\x48\xb9" + struct.pack("<Q", image_base + 0x20A0))
        code += b"\x31\xd2\x45\x31\xc0"
        code += b"\xff\x15" + struct.pack("<i", 0x2040 - (0x1000 + len(code) + 6))
        code += b"\x48\x89\xc1"
        code += b"\xff\x15" + struct.pack("<i", 0x2048 - (0x1000 + len(code) + 6))
    else:
        code = bytearray(b"\x6a\x00\x6a\x00\x68" + struct.pack("<I", image_base + 0x20A0))
        code += b"\xff\x15" + struct.pack("<I", image_base + 0x2040)
        code += b"\x50\xff\x15" + struct.pack("<I", image_base + 0x2044)
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_call_export(machine: int) -> bytes:
    """Load a DLL, resolve an export, execute its CPU code, then exit with 42."""
    is_x64 = machine == 0x8664
    buf = bytearray(build(machine))
    image_base = 0x140000000 if is_x64 else 0x400000
    fmt = "<Q" if is_x64 else "<I"
    step = 8 if is_x64 else 4
    if is_x64:
        struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x2080, 0x2050)
        for offset in (0x430, 0x450):
            for index, rva in enumerate((0x20A0, 0x20C0, 0x20E0, 0)):
                struct.pack_into("<Q", buf, offset + index * 8, rva)
        buf[0x480:0x48D] = b"KERNEL32.dll\0"
        for offset, name in ((0x4A0, b"LoadLibraryA"), (0x4C0, b"GetProcAddress"),
                             (0x4E0, b"ExitProcess")):
            buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
        buf[0x520:0x532] = b"companion_x64.dll\0"
        buf[0x540:0x54B] = b"ProbeValue\0"
        code = bytearray(b"\x48\xb9" + struct.pack("<Q", image_base + 0x2120))
        def call_iat(rva):
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        call_iat(0x2050)
        code += b"\x48\x89\xc1"
        code += b"\x48\xba" + struct.pack("<Q", image_base + 0x2140)
        call_iat(0x2058)
        code += b"\xff\xd0\x89\xc1"
        call_iat(0x2060)
    else:
        for offset in (0x430, 0x440):
            for index, rva in enumerate((0x2070, 0x2080, 0x2090, 0)):
                struct.pack_into("<I", buf, offset + index * 4, rva)
        for offset, name in ((0x470, b"LoadLibraryA"), (0x480, b"GetProcAddress"),
                             (0x490, b"ExitProcess")):
            buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
        buf[0x4A0:0x4B2] = b"companion_x86.dll\0"
        buf[0x4C0:0x4CB] = b"ProbeValue\0"
        code = bytearray(b"\x68" + struct.pack("<I", image_base + 0x20A0))
        code += b"\xff\x15" + struct.pack("<I", image_base + 0x2040)
        code += b"\x89\xc3"
        code += b"\x68" + struct.pack("<I", image_base + 0x20C0)
        code += b"\x53\xff\x15" + struct.pack("<I", image_base + 0x2044)
        code += b"\xff\xd0\x50\xff\x15" + struct.pack("<I", image_base + 0x2048)
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_ldr_companion(machine: int) -> bytes:
    """Use counted NT strings to load a guest DLL and call its export."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * (0x800 - len(buf)))
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<II", buf, section + 8, 0x400, 0x2000)
    struct.pack_into("<I", buf, section + 16, 0x400)
    buf[0x400:0x800] = b"\0" * 0x400
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x21E0, 0x2070)
    fmt, step = ("<Q", 8) if is_x64 else ("<I", 4)
    for index, name in enumerate((b"LdrLoadDll", b"LdrGetProcedureAddress",
                                  b"LdrUnloadDll")):
        name_offset = 0x4C0 + index * 0x40
        for thunk in (0x430, 0x470):
            struct.pack_into(fmt, buf, thunk + index * step, 0x2000 + name_offset - 0x400)
        buf[name_offset:name_offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5E0:0x5EA] = b"ntdll.dll\0"
    path = f"companion_{'x64' if is_x64 else 'x86'}.dll".encode("utf-16le")
    buf[0x600:0x600 + len(path) + 2] = path + b"\0\0"
    buf[0x670:0x67B] = b"ProbeValue\0"
    if is_x64:
        struct.pack_into("<HH4xQ", buf, 0x650, len(path), len(path) + 2,
                         base + 0x2200)
        struct.pack_into("<HH4xQ", buf, 0x690, 10, 11, base + 0x2270)
    else:
        struct.pack_into("<HHI", buf, 0x650, len(path), len(path) + 2,
                         base + 0x2200)
        struct.pack_into("<HHI", buf, 0x690, 10, 11, base + 0x2270)
    code = bytearray()

    def call(index: int) -> None:
        target = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack(
                "<i", target - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + target))

    failures = []

    def fail_if_status() -> None:
        code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x83\xec\x28\x31\xc9\x31\xd2")
        code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x2250))
        code.extend(b"\x49\xb9" + struct.pack("<Q", base + 0x22B0))
        call(0); fail_if_status()
        code.extend(b"\x48\x8b\x0d" + struct.pack(
            "<i", 0x22B0 - (0x1000 + len(code) + 7)))
        code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x2290))
        code.extend(b"\x45\x31\xc0\x49\xb9" + struct.pack("<Q", base + 0x22C0))
        call(1); fail_if_status()
        code.extend(b"\x48\x8b\x05" + struct.pack(
            "<i", 0x22C0 - (0x1000 + len(code) + 7)))
        code.extend(b"\xff\xd0\x89\x05" + struct.pack(
            "<i", 0x22D0 - (0x1000 + len(code) + 8)))
        code.extend(b"\x48\x8b\x0d" + struct.pack(
            "<i", 0x22B0 - (0x1000 + len(code) + 7)))
        call(2); fail_if_status()
        code.extend(b"\x8b\x05" + struct.pack(
            "<i", 0x22D0 - (0x1000 + len(code) + 6)))
        code.extend(b"\x48\x83\xc4\x28\xc3")
        failure = len(code)
        code.extend(b"\xb8\x01\0\0\0\x48\x83\xc4\x28\xc3")
    else:
        for value in (base + 0x22B0, base + 0x2250, 0, 0):
            code.extend(b"\x68" + struct.pack("<I", value))
        call(0); fail_if_status()
        code.extend(b"\x68" + struct.pack("<I", base + 0x22C0))
        code.extend(b"\x6a\0\x68" + struct.pack("<I", base + 0x2290))
        code.extend(b"\xff\x35" + struct.pack("<I", base + 0x22B0))
        call(1); fail_if_status()
        code.extend(b"\xa1" + struct.pack("<I", base + 0x22C0) + b"\xff\xd0")
        code.extend(b"\xa3" + struct.pack("<I", base + 0x22D0))
        code.extend(b"\xff\x35" + struct.pack("<I", base + 0x22B0))
        call(2); fail_if_status()
        code.extend(b"\xa1" + struct.pack("<I", base + 0x22D0) + b"\xc3")
        failure = len(code)
        code.extend(b"\xb8\x01\0\0\0\xc3")
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x100, len(code)
    buf[0x200:0x300] = b"\0" * 0x100
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_host_winexec_via_ldr_probe(machine: int, marker_path: str) -> bytes:
    """Resolve guest WinExec through Ldr* and request a harmless host marker."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build_ldr_companion(machine))
    dll_name = "kernel32.dll".encode("utf-16le")
    command = (f'cmd.exe /c echo emumee-ldr-probe > "{marker_path}"'
               ).encode("cp1252") + b"\0"
    if len(command) > 0x100:
        raise ValueError("Host marker command is too long")
    buf[0x600:0x650] = b"\0" * 0x50
    buf[0x600:0x600 + len(dll_name) + 2] = dll_name + b"\0\0"
    struct.pack_into("<HH", buf, 0x650, len(dll_name), len(dll_name) + 2)
    buf[0x670:0x680] = b"\0" * 0x10
    buf[0x670:0x678] = b"WinExec\0"
    struct.pack_into("<HH", buf, 0x690, 7, 8)
    buf[0x700:0x800] = b"\0" * 0x100
    buf[0x700:0x700 + len(command)] = command
    step = 8 if is_x64 else 4
    code = bytearray()

    def call(index: int) -> None:
        target = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack(
                "<i", target - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + target))

    failures = []

    def fail_if_status() -> None:
        code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x83\xec\x28\x31\xc9\x31\xd2")
        code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x2250))
        code.extend(b"\x49\xb9" + struct.pack("<Q", base + 0x22B0))
        call(0); fail_if_status()
        code.extend(b"\x48\x8b\x0d" + struct.pack(
            "<i", 0x22B0 - (0x1000 + len(code) + 7)))
        code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x2290))
        code.extend(b"\x45\x31\xc0\x49\xb9" + struct.pack("<Q", base + 0x22C0))
        call(1); fail_if_status()
        code.extend(b"\x48\x8b\x05" + struct.pack(
            "<i", 0x22C0 - (0x1000 + len(code) + 7)))
        code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2300))
        code.extend(b"\x31\xd2\xff\xd0\xb8\x01\0\0\0")
        code.extend(b"\x48\x83\xc4\x28\xc3")
        failure = len(code)
        code.extend(b"\x31\xc0\x48\x83\xc4\x28\xc3")
    else:
        for value in (base + 0x22B0, base + 0x2250, 0, 0):
            code.extend(b"\x68" + struct.pack("<I", value))
        call(0); fail_if_status()
        code.extend(b"\x68" + struct.pack("<I", base + 0x22C0))
        code.extend(b"\x6a\0\x68" + struct.pack("<I", base + 0x2290))
        code.extend(b"\xff\x35" + struct.pack("<I", base + 0x22B0))
        call(1); fail_if_status()
        code.extend(b"\xa1" + struct.pack("<I", base + 0x22C0))
        code.extend(b"\x6a\0\x68" + struct.pack("<I", base + 0x2300))
        code.extend(b"\xff\xd0\xb8\x01\0\0\0\xc3")
        failure = len(code)
        code.extend(b"\x31\xc0\xc3")
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x100, len(code)
    buf[0x200:0x300] = b"\0" * 0x100
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_local_virtualprotect_probe(machine: int) -> bytes:
    """Change protection of a page owned by the current guest process."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf[0x470:0x490] = b"\0" * 0x20
    buf[0x470:0x481] = b"\0\0VirtualProtect\0"
    code = bytearray()
    if is_x64:
        code.extend(b"\x48\x83\xec\x28")
        code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2100))
        code.extend(b"\xba\x10\0\0\0\x41\xb8\x40\0\0\0")
        code.extend(b"\x49\xb9" + struct.pack("<Q", base + 0x2150))
        code.extend(b"\xff\x15" + struct.pack(
            "<i", 0x2040 - (0x1000 + len(code) + 6)))
        code.extend(b"\x48\x83\xc4\x28\xc3")
    else:
        for value in (base + 0x2150, 0x40, 0x10, base + 0x2100):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\xff\x15" + struct.pack("<I", base + 0x2040) + b"\xc3")
    buf[0x200:0x300] = b"\0" * 0x100
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_checked_call_export(machine: int) -> bytes:
    """Call a DLL export only when GetProcAddress returns a guest address."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build_call_export(machine))
    code = bytearray()
    if is_x64:
        def call_iat(rva):
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2120))
        call_iat(0x2050)
        code.extend(b"\x48\x89\xc1\x48\xba" + struct.pack("<Q", base + 0x2140))
        call_iat(0x2058)
        code.extend(b"\x48\x85\xc0\x74\0")
        jump = len(code) - 1
        code.extend(b"\xff\xd0\x89\xc1")
        call_iat(0x2060)
        failure = len(code)
        code.extend(b"\x31\xc9")
        call_iat(0x2060)
    else:
        code.extend(b"\x68" + struct.pack("<I", base + 0x20A0))
        code.extend(b"\xff\x15" + struct.pack("<I", base + 0x2040))
        code.extend(b"\x89\xc3\x68" + struct.pack("<I", base + 0x20C0))
        code.extend(b"\x53\xff\x15" + struct.pack("<I", base + 0x2044))
        code.extend(b"\x85\xc0\x74\0")
        jump = len(code) - 1
        code.extend(b"\xff\xd0\x50\xff\x15" + struct.pack("<I", base + 0x2048))
        failure = len(code)
        code.extend(b"\x6a\0\xff\x15" + struct.pack("<I", base + 0x2048))
    assert 0 <= failure - jump - 1 < 128
    code[jump] = failure - jump - 1
    code.extend(b"\xc3")
    buf[0x200:0x300] = b"\0" * 0x100
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_companion_lifecycle(machine: int) -> bytes:
    """Reference-count and unload an explicitly supplied DLL in guest CPU."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * (0x800 - len(buf)))
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", buf, section + 8, 0x400)
    struct.pack_into("<I", buf, section + 16, 0x400)
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x21E0, 0x2070)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    for index, name in enumerate((b"LoadLibraryW", b"GetProcAddress",
                                  b"FreeLibrary", b"ExitProcess")):
        rva = 0x20C0 + index * 0x28
        struct.pack_into(fmt, buf, 0x430 + index * step, rva)
        struct.pack_into(fmt, buf, 0x470 + index * step, rva)
        offset = 0x4C0 + index * 0x28
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5E0:0x5ED] = b"KERNEL32.dll\0"
    path = f"companion_{'x64' if is_x64 else 'x86'}.dll".encode("utf-16le") + b"\0\0"
    buf[0x600:0x600 + len(path)] = path
    buf[0x680:0x68B] = b"ProbeValue\0"
    code, failures = bytearray(), []

    def call(index: int) -> None:
        rva = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    def fail_zero() -> None:
        code.extend(b"\x85\xc0\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)

    def fail_nonzero() -> None:
        code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x83\xec\x28")
        def load() -> None:
            code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2200))
            call(0)
        def resolve() -> None:
            code.extend(b"\x48\x89\xd9\x48\xba" + struct.pack("<Q", base + 0x2280))
            call(1)
        def free() -> None:
            code.extend(b"\x48\x89\xd9")
            call(2)
        load(); fail_zero()
        code.extend(b"\x48\x89\xc3")
        resolve(); fail_zero()
        code.extend(b"\xff\xd0\x83\xf8\x2a\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)
        load()
        code.extend(b"\x48\x39\xd8\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)
        free(); fail_zero()
        resolve(); fail_zero()
        free(); fail_zero()
        resolve(); fail_nonzero()
        free(); fail_nonzero()
        load(); fail_zero()
        code.extend(b"\x48\x89\xc3")
        resolve(); fail_zero()
        code.extend(b"\xff\xd0\x89\xc1")
        call(3)
        failure = len(code)
        code.extend(b"\xb9\x01\0\0\0")
        call(3)
    else:
        def push(value: int) -> None:
            code.extend(b"\x68" + struct.pack("<I", value))
        def load() -> None:
            push(base + 0x2200)
            call(0)
        def resolve() -> None:
            push(base + 0x2280)
            code.extend(b"\x53")
            call(1)
        def free() -> None:
            code.extend(b"\x53")
            call(2)
        load(); fail_zero()
        code.extend(b"\x89\xc3")
        resolve(); fail_zero()
        code.extend(b"\xff\xd0\x83\xf8\x2a\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)
        load()
        code.extend(b"\x39\xd8\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)
        free(); fail_zero()
        resolve(); fail_zero()
        free(); fail_zero()
        resolve(); fail_nonzero()
        free(); fail_nonzero()
        load(); fail_zero()
        code.extend(b"\x89\xc3")
        resolve(); fail_zero()
        code.extend(b"\xff\xd0\x50")
        call(3)
        failure = len(code)
        code.extend(b"\x6a\x01")
        call(3)
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x200, len(code)
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_load_result(machine: int) -> bytes:
    """Exit with the HMODULE returned by LoadLibrary (zero on init failure)."""
    buf = bytearray(build_load_library(machine))
    if machine == 0x8664:
        buf[0x210:0x212] = b"\x89\xc1"  # mov ecx, eax
    else:
        buf[0x20B:0x20D] = b"\x50\x90"  # push eax; nop
    return bytes(buf)


def build_load_wrong_companion_path(machine: int) -> bytes:
    """Request a missing full path with the same basename as a supplied DLL."""
    is_x64 = machine == 0x8664
    buf = bytearray(build_load_result(machine))
    path = (rf"C:\Users\Alex\Documents\companion_{'x64' if is_x64 else 'x86'}.dll"
            .encode("ascii") + b"\0")
    buf[0x4A0:0x500] = b"\0" * 0x60
    buf[0x4A0:0x4A0 + len(path)] = path
    return bytes(buf)


def build_static_companion(machine: int) -> bytes:
    """Import ProbeValue from a companion DLL before the EXE entry point."""
    is_x64 = machine == 0x8664
    buf = bytearray(build(machine))
    image_base = 0x140000000 if is_x64 else 0x400000
    dd = 0x98 + (112 if is_x64 else 96)
    struct.pack_into("<II", buf, dd + 8, 0x2000, 0x3C)
    buf[0x400:0x43C] = b"\0" * 0x3C
    struct.pack_into("<IIIII", buf, 0x400, 0x2050, 0, 0, 0x20B0, 0x2070)
    struct.pack_into("<IIIII", buf, 0x414, 0x2060, 0, 0, 0x20C0, 0x2090)
    fmt = "<Q" if is_x64 else "<I"
    for off, target in ((0x450, 0x20D0), (0x470, 0x20D0),
                        (0x460, 0x20F0), (0x490, 0x20F0)):
        struct.pack_into(fmt, buf, off, target)
    companion = b"companion_x64.dll\0" if is_x64 else b"companion_x86.dll\0"
    buf[0x4B0:0x4B0 + len(companion)] = companion
    buf[0x4C0:0x4CD] = b"KERNEL32.dll\0"
    buf[0x4D0:0x4DD] = b"\0\0ProbeValue\0"
    buf[0x4F0:0x4FE] = b"\0\0ExitProcess\0"
    if is_x64:
        code = bytearray(b"\xff\x15" + struct.pack("<i", 0x2070 - (0x1000 + 6)))
        code += b"\x89\xc1"
        code += b"\xff\x15" + struct.pack("<i", 0x2090 - (0x1000 + len(code) + 6))
    else:
        code = bytearray(b"\xff\x15" + struct.pack("<I", image_base + 0x2070))
        code += b"\x50\xff\x15" + struct.pack("<I", image_base + 0x2090)
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_static_companion_lifecycle(machine: int) -> bytes:
    """Combine a static companion import with dynamic loads and releases."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * (0xA00 - len(buf)))
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", buf, section + 8, 0x600)
    struct.pack_into("<I", buf, section + 16, 0x600)
    dd = 0x98 + (112 if is_x64 else 96)
    struct.pack_into("<II", buf, dd + 8, 0x2000, 0x3C)
    buf[0x400:0x800] = b"\0" * 0x400
    struct.pack_into("<IIIII", buf, 0x400, 0x2050, 0, 0, 0x2180, 0x2090)
    struct.pack_into("<IIIII", buf, 0x414, 0x2060, 0, 0, 0x21A0, 0x20A0)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    for offset in (0x450, 0x490):
        struct.pack_into(fmt, buf, offset, 0x2200)
    for index, name in enumerate((b"LoadLibraryW", b"FreeLibrary",
                                  b"GetProcAddress", b"ExitProcess")):
        rva = 0x2220 + 0x20 * index
        struct.pack_into(fmt, buf, 0x460 + index * step, rva)
        struct.pack_into(fmt, buf, 0x4A0 + index * step, rva)
        offset = 0x620 + index * 0x20
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x580:0x592] = f"companion_{'x64' if is_x64 else 'x86'}.dll".encode() + b"\0"
    buf[0x5A0:0x5AD] = b"KERNEL32.dll\0"
    buf[0x600:0x60D] = b"\0\0ProbeValue\0"
    path = f"companion_{'x64' if is_x64 else 'x86'}.dll".encode("utf-16le") + b"\0\0"
    buf[0x700:0x700 + len(path)] = path
    buf[0x780:0x78B] = b"ProbeValue\0"
    code, failures = bytearray(), []

    def call(rva: int) -> None:
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    def check(expected: int) -> None:
        if expected == 42:
            code.extend(b"\x83\xf8\x2a\x0f\x85\0\0\0\0")
        else:
            code.extend(b"\x85\xc0\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x83\xec\x28")
        call(0x2090); check(42)
        code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2300))
        call(0x20A0); check(1)
        code.extend(b"\x48\x89\xc3\x48\x89\xd9")
        call(0x20A8); check(1)
        call(0x2090); check(42)
        code.extend(b"\x48\x89\xd9")
        call(0x20A8); check(1)
        code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2300))
        call(0x20A0); check(1)
        code.extend(b"\x48\x89\xc1\x48\xba" + struct.pack("<Q", base + 0x2380))
        call(0x20B0); check(1)
        code.extend(b"\xff\xd0\x89\xc1")
        call(0x20B8)
        failure = len(code)
        code.extend(b"\xb9\x01\0\0\0")
        call(0x20B8)
    else:
        def push(value: int) -> None:
            code.extend(b"\x68" + struct.pack("<I", value))
        call(0x2090); check(42)
        push(base + 0x2300)
        call(0x20A0); check(1)
        code.extend(b"\x89\xc3\x53")
        call(0x20A4); check(1)
        call(0x2090); check(42)
        code.extend(b"\x53")
        call(0x20A4); check(1)
        push(base + 0x2300)
        call(0x20A0); check(1)
        push(base + 0x2380)
        code.extend(b"\x50")
        call(0x20A8); check(1)
        code.extend(b"\xff\xd0\x50")
        call(0x20AC)
        failure = len(code)
        code.extend(b"\x6a\x01")
        call(0x20AC)
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x200, len(code)
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_tls_companion(machine: int) -> bytes:
    """DLL whose DllMain succeeds only if its TLS callback ran first."""
    is_x64 = machine == 0x8664
    image_base = 0x180000000 if is_x64 else 0x50000000
    buf = bytearray(build(machine, dll=True))
    marker_rva = 0x21E0
    if is_x64:
        cmp_disp = marker_rva - (0x1000 + 7)
        set_disp = marker_rva - (0x1009 + 7)
        export_disp = marker_rva - (0x1030 + 7)
        tls_disp = marker_rva - (0x1060 + 7)
        init_code = (b"\x80\x3d" + struct.pack("<i", cmp_disp) + b"\x01"
                     + b"\x75\x0d\xc6\x05" + struct.pack("<i", set_disp) + b"\x02"
                     + b"\xb8\x01\x00\x00\x00\xc3\x31\xc0\xc3")
        export_code = (b"\x80\x3d" + struct.pack("<i", export_disp) + b"\x02"
                       + b"\x75\x06\xb8\x2a\x00\x00\x00\xc3\x31\xc0\xc3")
        callback_code = b"\xc6\x05" + struct.pack("<i", tls_disp) + b"\x01\xc3"
        struct.pack_into("<QQQQII", buf, 0x580, image_base + 0x21D0,
                         image_base + 0x21D4, image_base + 0x21C0,
                         image_base + 0x21B0, 0, 0)
        struct.pack_into("<QQ", buf, 0x5B0, image_base + 0x1060, 0)
        tls_size = 40
    else:
        marker = image_base + marker_rva
        init_code = (b"\x80\x3d" + struct.pack("<I", marker) + b"\x01"
                     + b"\x75\x0f\xc6\x05" + struct.pack("<I", marker) + b"\x02"
                     + b"\xb8\x01\x00\x00\x00\xc2\x0c\x00\x31\xc0\xc2\x0c\x00")
        export_code = (b"\x80\x3d" + struct.pack("<I", marker) + b"\x02"
                       + b"\x75\x06\xb8\x2a\x00\x00\x00\xc3\x31\xc0\xc3")
        callback_code = b"\xc6\x05" + struct.pack("<I", marker) + b"\x01\xc2\x0c\x00"
        struct.pack_into("<IIIIII", buf, 0x580, image_base + 0x21D0,
                         image_base + 0x21D4, image_base + 0x21C0,
                         image_base + 0x21B0, 0, 0)
        struct.pack_into("<II", buf, 0x5B0, image_base + 0x1060, 0)
        tls_size = 24
    buf[0x200:0x200 + len(init_code)] = init_code
    buf[0x230:0x230 + len(export_code)] = export_code
    buf[0x260:0x260 + len(callback_code)] = callback_code
    struct.pack_into("<I", buf, 0x530, 0x1030)
    dd = 0x98 + (112 if is_x64 else 96)
    struct.pack_into("<II", buf, dd + 9 * 8, 0x2180, tls_size)
    return bytes(buf)


def build_tls_only_companion(machine: int) -> bytes:
    """No DllMain; TLS traps if attach/detach reason or reserved is wrong."""
    is_x64 = machine == 0x8664
    buf = bytearray(build_tls_companion(machine))
    struct.pack_into("<I", buf, 0x98 + 16, 0)
    code = bytearray(b"\x83\xfa\x01" if is_x64 else b"\x83\x7c\x24\x08\x01")
    code.extend(b"\x74\0")
    attach_jump = len(code) - 1
    code.extend(b"\x85\xd2" if is_x64 else b"\x83\x7c\x24\x08\0")
    code.extend(b"\x75\0")
    bad_jumps = [len(code) - 1]
    code.extend(b"\x4d\x85\xc0" if is_x64 else b"\x83\x7c\x24\x0c\0")
    code.extend(b"\x75\0")
    bad_jumps.append(len(code) - 1)
    code.extend(b"\xc3" if is_x64 else b"\xc2\x0c\0")
    attach_offset = len(code)
    code.extend(b"\x4d\x85\xc0" if is_x64 else b"\x83\x7c\x24\x0c\0")
    code.extend(b"\x75\0")
    bad_jumps.append(len(code) - 1)
    if is_x64:
        disp = 0x21E0 - (0x1060 + len(code) + 7)
        code.extend(b"\xc6\x05" + struct.pack("<i", disp) + b"\x02")
    else:
        code.extend(b"\xc6\x05" + struct.pack("<I", 0x50000000 + 0x21E0) + b"\x02")
    code.extend(b"\xc3" if is_x64 else b"\xc2\x0c\0")
    bad_offset = len(code)
    code.extend(b"\x0f\x0b")  # UD2 makes a wrong callback observable.
    assert len(code) < 0x60
    for jump, target in [(attach_jump, attach_offset),
                         *((offset, bad_offset) for offset in bad_jumps)]:
        displacement = target - (jump + 1)
        assert 0 <= displacement < 128
        code[jump] = displacement
    buf[0x260:0x2C0] = b"\0" * 0x60
    buf[0x260:0x260 + len(code)] = code
    return bytes(buf)


def build_importing_companion(machine: int, *, dependency: bool = False,
                              fail_attach: bool = False) -> bytes:
    """DLL whose DllMain calls an imported guest WinAPI before its export works."""
    is_x64 = machine == 0x8664
    base = ((0x1A0000000 if is_x64 else 0x52000000) if dependency else
            (0x180000000 if is_x64 else 0x50000000))
    buf = bytearray(build(machine, dll=True))
    if dependency:
        struct.pack_into("<Q" if is_x64 else "<I", buf,
                         0x98 + (24 if is_x64 else 28), base)
    buf[0x470:0x490] = b"\0" * 0x20
    name = b"\0\0ProbeValue\0" if dependency else b"\0\0GetCurrentProcessId\0"
    buf[0x470:0x470 + len(name)] = name
    if dependency:
        struct.pack_into("<I", buf, 0x40C, 0x2180)
        dep_name = f"companion_{'x64' if is_x64 else 'x86'}.dll".encode() + b"\0"
        buf[0x580:0x580 + len(dep_name)] = dep_name
    marker_rva = 0x21E0
    if is_x64:
        code = bytearray(b"\x48\x83\xec\x28")
        code.extend(b"\xff\x15" + struct.pack("<i", 0x2040 - (0x1000 + len(code) + 6)))
        code.extend(b"\x48\x83\xc4\x28")
        code.extend(b"\x83\xf8\x2a\x75\x0d" if dependency else b"\x85\xc0\x74\x0d")
        code.extend(b"\xc6\x05" + struct.pack("<i", marker_rva - (0x1000 + len(code) + 7)) + b"\x01")
        code.extend(b"\xb8\x01\0\0\0\xc3\x31\xc0\xc3")
        export_code = (b"\x80\x3d" + struct.pack("<i", marker_rva - (0x1030 + 7)) +
                       b"\x01\x75\x06\xb8\x2a\0\0\0\xc3\x31\xc0\xc3")
    else:
        code = bytearray(b"\xff\x15" + struct.pack("<I", base + 0x2040))
        code.extend(b"\x83\xf8\x2a\x75\x0f" if dependency else b"\x85\xc0\x74\x0f")
        code.extend(b"\xc6\x05" + struct.pack("<I", base + marker_rva) + b"\x01")
        code.extend(b"\xb8\x01\0\0\0\xc2\x0c\0\x31\xc0\xc2\x0c\0")
        export_code = (b"\x80\x3d" + struct.pack("<I", base + marker_rva) +
                       b"\x01\x75\x06\xb8\x2a\0\0\0\xc3\x31\xc0\xc3")
    if fail_attach:
        assert b"\xb8\x01\0\0\0" in code
        code = code.replace(b"\xb8\x01\0\0\0", b"\xb8\0\0\0\0", 1)
    assert len(code) <= 0x30
    buf[0x200:0x230] = b"\0" * 0x30
    buf[0x200:0x200 + len(code)] = code
    buf[0x230:0x230 + len(export_code)] = export_code
    struct.pack_into("<I", buf, 0x530, 0x1030)
    return bytes(buf)


def _forward_export(machine: int, source: bytes, target: str,
                    *, raw_offset: int = 0x5A0) -> bytes:
    """Replace ProbeValue's export address with a PE forwarder string."""
    is_x64 = machine == 0x8664
    buf = bytearray(source)
    export_directory = 0x98 + (112 if is_x64 else 96)
    assert raw_offset in (0x5A0, 0x5C0)
    struct.pack_into("<II", buf, export_directory, 0x2100,
                     0xE0 if raw_offset == 0x5C0 else 0xC0)
    forwarder = target.encode() + b"\0"
    assert len(forwarder) <= 0x20
    buf[raw_offset:raw_offset + 0x20] = b"\0" * 0x20
    buf[raw_offset:raw_offset + len(forwarder)] = forwarder
    struct.pack_into("<I", buf, 0x530, 0x21C0 if raw_offset == 0x5C0 else 0x21A0)
    return bytes(buf)


def build_forwarding_companion(machine: int, target: str | None = None) -> bytes:
    """Forward ProbeValue from a DLL that also imports an initialized leaf."""
    is_x64 = machine == 0x8664
    buf = bytearray(build_importing_companion(machine, dependency=True))
    name = f"leaf_{'x64' if is_x64 else 'x86'}.dll".encode() + b"\0"
    buf[0x580:0x5A0] = b"\0" * 0x20
    buf[0x580:0x580 + len(name)] = name
    return _forward_export(machine, bytes(buf), target or
                           f"leaf_{'x64' if is_x64 else 'x86'}.ProbeValue")


def build_static_detach_probe(machine: int, source: bytes, *, fail_attach: bool,
                              detach_reserved: int) -> bytes:
    """Return 77 on detach only when reason and reserved arguments match."""
    is_x64 = machine == 0x8664
    buf = bytearray(source)
    struct.pack_into("<I", buf, 0x98 + 16, 0x1080)
    code = bytearray(b"\x85\xd2" if is_x64 else b"\x83\x7c\x24\x08\0")
    code.extend(b"\x75\0")
    attach_jump = len(code) - 1
    code.extend((b"\x49\x83\xf8" if is_x64 else b"\x83\x7c\x24\x0c") +
                bytes([detach_reserved]))
    code.extend(b"\x75\0")
    wrong_jump = len(code) - 1
    code.extend(b"\xb8\x4d\0\0\0" + (b"\xc3" if is_x64 else b"\xc2\x0c\0"))
    wrong_offset = len(code)
    code.extend(b"\x31\xc0" + (b"\xc3" if is_x64 else b"\xc2\x0c\0"))
    attach_offset = len(code)
    if fail_attach:
        code.extend(b"\x31\xc0")
    else:
        marker_rva = 0x21E0
        if is_x64:
            disp = marker_rva - (0x1080 + len(code) + 7)
            code.extend(b"\xc6\x05" + struct.pack("<i", disp) + b"\x01")
        else:
            image_base = struct.unpack_from("<I", buf, 0x98 + 28)[0]
            code.extend(b"\xc6\x05" + struct.pack("<I", image_base + marker_rva) + b"\x01")
        code.extend(b"\xb8\x01\0\0\0")
    code.extend(b"\xc3" if is_x64 else b"\xc2\x0c\0")
    assert len(code) < 0x80
    for jump, target in ((attach_jump, attach_offset), (wrong_jump, wrong_offset)):
        displacement = target - (jump + 1)
        assert 0 <= displacement < 128
        code[jump] = displacement
    buf[0x280:0x280 + len(code)] = code
    return bytes(buf)


def build_move_file(machine: int, *, wide: bool = True, delete: bool = False,
                    copy: bool = False, while_open: bool = False,
                    share_delete: bool = False, open_share: int | None = None,
                    target_open: bool = False) -> bytes:
    """Create a guest file, move, copy, or delete it, and exit with the API result."""
    is_x64 = machine == 0x8664
    image_base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * 0x400)
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", buf, section + 8, 0x600)
    struct.pack_into("<I", buf, section + 16, 0x600)
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x21C0, 0x2070)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    for index in range(5):
        target = 0x20C0 + index * 0x20
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x470 + index * step, target)
    move_name = ((b"DeleteFileW" if wide else b"DeleteFileA") if delete else
                 (b"CopyFileW" if wide else b"CopyFileA") if copy else
                 (b"MoveFileExW" if wide else b"MoveFileExA"))
    for index, name in enumerate((b"CreateFileA", b"WriteFile", b"CloseHandle",
                                  move_name, b"ExitProcess")):
        off = 0x4C0 + index * 0x20
        buf[off:off + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5C0:0x5CD] = b"KERNEL32.dll\0"
    old = r"C:\Users\Alex\Downloads\old.bin"
    new = r"C:\Users\Alex\Downloads\new.bin"
    for off, raw in ((0x600, old.encode() + b"\0"),
                     (0x680, old.encode("utf-16le") + b"\0\0"),
                     (0x700, new.encode("utf-16le") + b"\0\0"),
                     (0x800, new.encode() + b"\0")):
        buf[off:off + len(raw)] = raw
    payload = b"copied payload marker" if copy else b"moved payload marker"
    buf[0x780:0x780 + len(payload)] = payload
    code = bytearray()

    def call_iat(index: int) -> None:
        iat = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", iat - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", image_base + iat))

    if is_x64:
        code.extend(b"\x48\x83\xec\x38")
        code.extend(b"\x48\xb9" + struct.pack("<Q", image_base + 0x2200))
        code.extend(b"\xba\x00\x00\x00\x40")
        code.extend((b"\x41\xb8" + struct.pack("<I", open_share if open_share is not None
                                                else (7 if share_delete else 3)))
                    if while_open else b"\x45\x31\xc0")
        code.extend(b"\x45\x31\xc9")
        for offset, value in ((0x20, 2), (0x28, 0), (0x30, 0)):
            code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
        call_iat(0)
        code.extend(b"\x48\x89\xc3\x48\x89\xd9")
        code.extend(b"\x48\xba" + struct.pack("<Q", image_base + 0x2380))
        code.extend(b"\x41\xb8" + struct.pack("<I", len(payload)))
        code.extend(b"\x49\xb9" + struct.pack("<Q", image_base + 0x23C0))
        code.extend(b"\x48\xc7\x44\x24\x20\x00\x00\x00\x00")
        call_iat(1)
        if not while_open:
            code.extend(b"\x48\x89\xd9")
            call_iat(2)
        if target_open:
            code.extend(b"\x48\xb9" + struct.pack("<Q", image_base + 0x2400))
            code.extend(b"\xba\x00\x00\x00\xc0\x41\xb8" +
                        struct.pack("<I", open_share if open_share is not None else 0))
            code.extend(b"\x45\x31\xc9")
            for offset, value in ((0x20, 2), (0x28, 0x80), (0x30, 0)):
                code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
            call_iat(0)
            code.extend(b"\x48\x89\xc3")
        code.extend(b"\x48\xb9" + struct.pack("<Q", image_base + (0x2280 if wide else 0x2200)))
        if not delete:
            code.extend(b"\x48\xba" + struct.pack("<Q", image_base + (0x2300 if wide else 0x2400)))
            code.extend(b"\x45\x31\xc0")
        call_iat(3)
        if while_open or target_open:
            code.extend(b"\x89\xc6\x48\x89\xd9")
            call_iat(2)
            code.extend(b"\x89\xf1")
        else:
            code.extend(b"\x89\xc1")
        call_iat(4)
        code.extend(b"\x48\x83\xc4\x38\xc3")
    else:
        def push(value: int) -> None:
            code.extend(b"\x68" + struct.pack("<I", value))
        for value in (0, 0, 2, 0,
                      (open_share if open_share is not None else (7 if share_delete else 3))
                      if while_open else 0,
                      0x40000000, image_base + 0x2200):
            push(value)
        call_iat(0)
        code.extend(b"\x89\xc3")
        for value in (0, image_base + 0x23C0, len(payload), image_base + 0x2380):
            push(value)
        code.extend(b"\x53")
        call_iat(1)
        if not while_open:
            code.extend(b"\x53")
            call_iat(2)
        if target_open:
            for value in (0, 0x80, 2, 0, open_share if open_share is not None else 0,
                          0xC0000000, image_base + 0x2400):
                push(value)
            call_iat(0)
            code.extend(b"\x89\xc3")
        args = ([image_base + (0x2280 if wide else 0x2200)] if delete else
                [0, image_base + (0x2300 if wide else 0x2400),
                 image_base + (0x2280 if wide else 0x2200)])
        for value in args:
            push(value)
        call_iat(3)
        if while_open or target_open:
            code.extend(b"\x89\xc6\x53")
            call_iat(2)
            code.extend(b"\x56")
        else:
            code.extend(b"\x50")
        call_iat(4)
        code.extend(b"\xc3")
    assert len(code) < 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_attributes_ex(machine: int, *, wide: bool = True) -> bytes:
    """Read a preset guest file's metadata without opening a host file."""
    is_x64 = machine == 0x8664
    image_base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * 0x400)
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", buf, section + 8, 0x600)
    struct.pack_into("<I", buf, section + 16, 0x600)
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x2140, 0x2070)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    for index, name in enumerate((b"GetFileAttributesEx" + (b"W" if wide else b"A"),
                                  b"ExitProcess")):
        target = 0x20C0 + index * 0x30
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x470 + index * step, target)
        offset = 0x4C0 + index * 0x30
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x540:0x54D] = b"KERNEL32.dll\0"
    path = r"C:\Users\Alex\Documents\readme.txt"
    raw = path.encode("utf-16le") + b"\0\0" if wide else path.encode() + b"\0"
    buf[0x580:0x580 + len(raw)] = raw
    code = bytearray()
    failures = []

    def call_iat(index: int):
        iat = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", iat - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", image_base + iat))

    def fail_if(condition: bytes):
        code.extend(condition + b"\x00")
        failures.append(len(code) - 1)

    if is_x64:
        code.extend(b"\x48\x83\xec\x28")
        code.extend(b"\x48\xb9" + struct.pack("<Q", image_base + 0x2180))
        code.extend(b"\x31\xd2")
        code.extend(b"\x49\xb8" + struct.pack("<Q", image_base + 0x2300))
        call_iat(0)
        code.extend(b"\x85\xc0")
        fail_if(b"\x74")
        code.extend(b"\x48\xb8" + struct.pack("<Q", image_base + 0x2300))
        code.extend(b"\x81\x38\x80\x00\x00\x00")
        fail_if(b"\x75")
        code.extend(b"\x83\x78\x20\x0f")
        fail_if(b"\x75")
        code.extend(b"\xb9\x01\x00\x00\x00")
        call_iat(1)
        failure = len(code)
        code.extend(b"\x31\xc9")
        call_iat(1)
    else:
        code.extend(b"\x68" + struct.pack("<I", image_base + 0x2300))
        code.extend(b"\x6a\x00")
        code.extend(b"\x68" + struct.pack("<I", image_base + 0x2180))
        call_iat(0)
        code.extend(b"\x85\xc0")
        fail_if(b"\x74")
        code.extend(b"\xb8" + struct.pack("<I", image_base + 0x2300))
        code.extend(b"\x81\x38\x80\x00\x00\x00")
        fail_if(b"\x75")
        code.extend(b"\x83\x78\x20\x0f")
        fail_if(b"\x75")
        code.extend(b"\x6a\x01")
        call_iat(1)
        failure = len(code)
        code.extend(b"\x6a\x00")
        call_iat(1)
    for offset in failures:
        displacement = failure - offset - 1
        assert -128 <= displacement <= 127
        code[offset] = displacement & 0xff
    assert len(code) < 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


REGISTRY_PAYLOAD = b"BLUE_TEAM_REGISTRY_MARKER"


def build_registry_roundtrip(machine: int, *, wide: bool = True) -> bytes:
    """Set and query a harmless binary value under the emulated HKCU root."""
    is_x64 = machine == 0x8664
    image_base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * 0x400)
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", buf, section + 8, 0x600)
    struct.pack_into("<I", buf, section + 16, 0x600)
    buf[0x400:0x600] = b"\0" * 0x200
    struct.pack_into("<IIIII", buf, 0x400, 0x2060, 0, 0, 0x2170, 0x2080)
    struct.pack_into("<IIIII", buf, 0x414, 0x20A0, 0, 0, 0x2190, 0x20B0)
    dd = 0x98 + (112 if is_x64 else 96)
    struct.pack_into("<II", buf, dd + 8, 0x2000, 0x3C)
    fmt, step = ("<Q", 8) if is_x64 else ("<I", 4)
    for index, target in enumerate((0x20E0, 0x2110)):
        struct.pack_into(fmt, buf, 0x460 + index * step, target)
        struct.pack_into(fmt, buf, 0x480 + index * step, target)
    struct.pack_into(fmt, buf, 0x4A0, 0x2140)
    struct.pack_into(fmt, buf, 0x4B0, 0x2140)
    names = (b"RegSetValueEx" + (b"W" if wide else b"A"),
             b"RegQueryValueEx" + (b"W" if wide else b"A"), b"ExitProcess")
    for offset, name in zip((0x4E0, 0x510, 0x540), names):
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x570:0x57D] = b"ADVAPI32.dll\0"
    buf[0x590:0x59D] = b"KERNEL32.dll\0"
    raw_name = "EmumeeProbe".encode("utf-16le") + b"\0\0" if wide else b"EmumeeProbe\0"
    buf[0x5C0:0x5C0 + len(raw_name)] = raw_name
    buf[0x640:0x640 + len(REGISTRY_PAYLOAD)] = REGISTRY_PAYLOAD
    struct.pack_into("<I", buf, 0x7C0, len(REGISTRY_PAYLOAD))
    code = bytearray()
    failures = []

    def call_iat(rva: int):
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", image_base + rva))

    def fail_if_nonzero():
        code.extend(b"\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)

    def assert_value(ptr: int, expected: int):
        if is_x64:
            code.extend(b"\x48\xb8" + struct.pack("<Q", image_base + ptr))
        else:
            code.extend(b"\xb8" + struct.pack("<I", image_base + ptr))
        code.extend(b"\x81\x38" + struct.pack("<I", expected))
        fail_if_nonzero()

    if is_x64:
        code.extend(b"\x48\x83\xec\x38")
        code.extend(b"\xb9\x01\x00\x00\x80")
        code.extend(b"\x48\xba" + struct.pack("<Q", image_base + 0x21C0))
        code.extend(b"\x45\x31\xc0\x41\xb9\x03\x00\x00\x00")
        code.extend(b"\x48\xb8" + struct.pack("<Q", image_base + 0x2240))
        code.extend(b"\x48\x89\x44\x24\x20")
        code.extend(b"\x48\xc7\x44\x24\x28" + struct.pack("<I", len(REGISTRY_PAYLOAD)))
        call_iat(0x2080)
        code.extend(b"\x85\xc0")
        fail_if_nonzero()
        code.extend(b"\xb9\x01\x00\x00\x80")
        code.extend(b"\x48\xba" + struct.pack("<Q", image_base + 0x21C0))
        code.extend(b"\x45\x31\xc0")
        code.extend(b"\x49\xb9" + struct.pack("<Q", image_base + 0x23C8))
        code.extend(b"\x48\xb8" + struct.pack("<Q", image_base + 0x2300))
        code.extend(b"\x48\x89\x44\x24\x20")
        code.extend(b"\x48\xb8" + struct.pack("<Q", image_base + 0x23C0))
        code.extend(b"\x48\x89\x44\x24\x28")
        call_iat(0x2088)
        code.extend(b"\x85\xc0")
        fail_if_nonzero()
        for ptr, expected in ((0x23C8, 3), (0x23C0, len(REGISTRY_PAYLOAD)),
                              (0x2300, 0x45554C42)):
            assert_value(ptr, expected)
        code.extend(b"\xb9\x01\x00\x00\x00")
        call_iat(0x20B0)
        failure = len(code)
        code.extend(b"\x31\xc9")
        call_iat(0x20B0)
    else:
        def push(value: int):
            code.extend(b"\x68" + struct.pack("<I", value))

        for value in (len(REGISTRY_PAYLOAD), image_base + 0x2240, 3, 0,
                      image_base + 0x21C0, 0x80000001):
            push(value)
        call_iat(0x2080)
        code.extend(b"\x85\xc0")
        fail_if_nonzero()
        for value in (image_base + 0x23C0, image_base + 0x2300,
                      image_base + 0x23C8, 0, image_base + 0x21C0, 0x80000001):
            push(value)
        call_iat(0x2084)
        code.extend(b"\x85\xc0")
        fail_if_nonzero()
        for ptr, expected in ((0x23C8, 3), (0x23C0, len(REGISTRY_PAYLOAD)),
                              (0x2300, 0x45554C42)):
            assert_value(ptr, expected)
        code.extend(b"\x6a\x01")
        call_iat(0x20B0)
        failure = len(code)
        code.extend(b"\x6a\x00")
        call_iat(0x20B0)
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_registry_key_lifecycle(machine: int, *, wide: bool = True,
                                 leave_open: bool = False,
                                 create_ex: bool = False) -> bytes:
    """Create, open, close, delete, and fail to reopen a guest HKCU key."""
    is_x64 = machine == 0x8664
    image_base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * 0x400)
    text_section = 0x98 + (0xF0 if is_x64 else 0xE0)
    struct.pack_into("<I", buf, text_section + 8, 0x200)
    idata_section = text_section + 40
    struct.pack_into("<I", buf, idata_section + 8, 0x600)
    struct.pack_into("<I", buf, idata_section + 16, 0x600)
    buf[0x400:0xA00] = b"\0" * 0x600
    struct.pack_into("<IIIII", buf, 0x400, 0x2060, 0, 0, 0x2210, 0x20A0)
    struct.pack_into("<IIIII", buf, 0x414, 0x20E0, 0, 0, 0x2230, 0x20F0)
    dd = 0x98 + (112 if is_x64 else 96)
    struct.pack_into("<II", buf, dd + 8, 0x2000, 0x3C)
    fmt, step = ("<Q", 8) if is_x64 else ("<I", 4)
    targets = (0x2120, 0x2150, 0x2180, 0x21B0)
    for index, target in enumerate(targets):
        struct.pack_into(fmt, buf, 0x460 + index * step, target)
        struct.pack_into(fmt, buf, 0x4A0 + index * step, target)
    struct.pack_into(fmt, buf, 0x4E0, 0x21E0)
    struct.pack_into(fmt, buf, 0x4F0, 0x21E0)
    names = (b"RegCreateKeyEx" if create_ex else b"RegCreateKey",
             b"RegOpenKeyEx", b"RegCloseKey", b"RegDeleteKey")
    for offset, name in zip((0x520, 0x550, 0x580, 0x5B0), names):
        if name != b"RegCloseKey":
            name += b"W" if wide else b"A"
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5E0:0x5EE] = b"\0\0ExitProcess\0"
    buf[0x610:0x61D] = b"ADVAPI32.dll\0"
    buf[0x630:0x63D] = b"KERNEL32.dll\0"
    subkey = r"Software\EmumeeLifecycle"
    raw = subkey.encode("utf-16le") + b"\0\0" if wide else subkey.encode() + b"\0"
    buf[0x660:0x660 + len(raw)] = raw
    code = bytearray()
    failures = []

    def call_iat(rva):
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", image_base + rva))

    def fail_if_nonzero():
        code.extend(b"\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x83\xec" + (b"\x48" if create_ex else b"\x28"))

        def hkey_and_path():
            code.extend(b"\xb9\x01\x00\x00\x80")
            code.extend(b"\x48\xba" + struct.pack("<Q", image_base + 0x2260))

        def open_key(out_rva):
            hkey_and_path()
            code.extend(b"\x45\x31\xc0\x41\xb9\x19\x00\x02\x00")
            code.extend(b"\x48\xb8" + struct.pack("<Q", image_base + out_rva))
            code.extend(b"\x48\x89\x44\x24\x20")
            call_iat(0x20A8)

        hkey_and_path()
        if create_ex:
            for displacement, value in ((0x20, 0), (0x28, 0xF003F), (0x30, 0)):
                code.extend(b"\x48\xc7\x44\x24" + bytes((displacement,)) +
                            struct.pack("<I", value))
            for displacement, rva in ((0x38, 0x2380), (0x40, 0x2398)):
                code.extend(b"\x48\xb8" + struct.pack("<Q", image_base + rva))
                code.extend(b"\x48\x89\x44\x24" + bytes((displacement,)))
            code.extend(b"\x45\x31\xc0\x45\x31\xc9")
        else:
            code.extend(b"\x49\xb8" + struct.pack("<Q", image_base + 0x2380))
        call_iat(0x20A0)
        code.extend(b"\x85\xc0")
        fail_if_nonzero()
        open_key(0x2388)
        code.extend(b"\x85\xc0")
        fail_if_nonzero()
        code.extend(b"\x48\xb8" + struct.pack("<Q", image_base + 0x2388))
        code.extend(b"\x48\x8b\x08")
        call_iat(0x20B0)
        code.extend(b"\x85\xc0")
        fail_if_nonzero()
        hkey_and_path()
        call_iat(0x20B8)
        code.extend(b"\x85\xc0")
        fail_if_nonzero()
        open_key(0x2390)
        code.extend(b"\x83\xf8\x02")
        fail_if_nonzero()
        if not leave_open:
            code.extend(b"\x48\xb8" + struct.pack("<Q", image_base + 0x2380))
            code.extend(b"\x48\x8b\x08")
            call_iat(0x20B0)
            code.extend(b"\x85\xc0")
            fail_if_nonzero()
        code.extend(b"\xb9\x01\x00\x00\x00")
        call_iat(0x20F0)
        failure = len(code)
        code.extend(b"\x31\xc9")
        call_iat(0x20F0)
    else:
        def push(value):
            code.extend(b"\x68" + struct.pack("<I", value))

        def open_key(out_rva):
            for value in (image_base + out_rva, 0x20019, 0, image_base + 0x2260, 0x80000001):
                push(value)
            call_iat(0x20A4)

        creation_args = ((image_base + 0x2398, image_base + 0x2380, 0, 0xF003F,
                          0, 0, 0, image_base + 0x2260, 0x80000001)
                         if create_ex else
                         (image_base + 0x2380, image_base + 0x2260, 0x80000001))
        for value in creation_args:
            push(value)
        call_iat(0x20A0)
        code.extend(b"\x85\xc0")
        fail_if_nonzero()
        open_key(0x2388)
        code.extend(b"\x85\xc0")
        fail_if_nonzero()
        code.extend(b"\xa1" + struct.pack("<I", image_base + 0x2388))
        code.extend(b"\x50")
        call_iat(0x20A8)
        code.extend(b"\x85\xc0")
        fail_if_nonzero()
        for value in (image_base + 0x2260, 0x80000001):
            push(value)
        call_iat(0x20AC)
        code.extend(b"\x85\xc0")
        fail_if_nonzero()
        open_key(0x2390)
        code.extend(b"\x83\xf8\x02")
        fail_if_nonzero()
        if not leave_open:
            code.extend(b"\xa1" + struct.pack("<I", image_base + 0x2380))
            code.extend(b"\x50")
            call_iat(0x20A8)
            code.extend(b"\x85\xc0")
            fail_if_nonzero()
        code.extend(b"\x6a\x01")
        call_iat(0x20F0)
        failure = len(code)
        code.extend(b"\x6a\x00")
        call_iat(0x20F0)
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_directory_lifecycle(machine: int, *, wide: bool = True) -> bytes:
    """Create, inspect, enumerate, and remove a guest directory."""
    is_x64 = machine == 0x8664
    image_base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * 0x400)
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", buf, section + 8, 0x600)
    struct.pack_into("<I", buf, section + 16, 0x600)
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x21C0, 0x2070)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    names = (b"CreateDirectory", b"GetFileAttributes", b"RemoveDirectory",
             b"FindFirstFile", b"ExitProcess")
    for index, name in enumerate(names):
        target = 0x20C0 + index * 0x30
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x470 + index * step, target)
        if index != 4:
            name += b"W" if wide else b"A"
        buf[0x4C0 + index * 0x30:0x4C0 + index * 0x30 + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5C0:0x5CD] = b"KERNEL32.dll\0"
    path = r"C:\Users\Alex\Downloads\created-dir"
    raw = path.encode("utf-16le") + b"\0\0" if wide else path.encode() + b"\0"
    buf[0x600:0x600 + len(raw)] = raw
    pattern = r"C:\Users\Alex\Downloads\created-*"
    pattern_raw = pattern.encode("utf-16le") + b"\0\0" if wide else pattern.encode() + b"\0"
    buf[0x680:0x680 + len(pattern_raw)] = pattern_raw
    code = bytearray()
    failures = []

    def call_iat(index: int):
        iat = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", iat - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", image_base + iat))

    def path_arg():
        if is_x64:
            code.extend(b"\x48\xb9" + struct.pack("<Q", image_base + 0x2200))
        else:
            code.extend(b"\x68" + struct.pack("<I", image_base + 0x2200))

    def fail_if(condition: bytes):
        code.extend(condition + b"\x00")
        failures.append(len(code) - 1)

    if is_x64:
        code.extend(b"\x48\x83\xec\x28")
        path_arg()
        code.extend(b"\x31\xd2")
        call_iat(0)
        code.extend(b"\x89\xc3")
        path_arg()
        call_iat(1)
        code.extend(b"\x83\xf8\x10")
        fail_if(b"\x75")
        code.extend(b"\x48\xb9" + struct.pack("<Q", image_base + 0x2280))
        code.extend(b"\x48\xba" + struct.pack("<Q", image_base + 0x2300))
        call_iat(3)
        code.extend(b"\x83\xf8\xff")
        fail_if(b"\x74")
        path_arg()
        call_iat(2)
        code.extend(b"\x85\xc0")
        fail_if(b"\x74")
        path_arg()
        call_iat(1)
        code.extend(b"\x83\xf8\xff")
        fail_if(b"\x75")
        code.extend(b"\x89\xd9")
        call_iat(4)
        failure = len(code)
        code.extend(b"\x31\xc9")
        call_iat(4)
    else:
        code.extend(b"\x6a\x00")
        path_arg()
        call_iat(0)
        code.extend(b"\x89\xc3")
        path_arg()
        call_iat(1)
        code.extend(b"\x83\xf8\x10")
        fail_if(b"\x75")
        code.extend(b"\x68" + struct.pack("<I", image_base + 0x2300))
        code.extend(b"\x68" + struct.pack("<I", image_base + 0x2280))
        call_iat(3)
        code.extend(b"\x83\xf8\xff")
        fail_if(b"\x74")
        path_arg()
        call_iat(2)
        code.extend(b"\x85\xc0")
        fail_if(b"\x74")
        path_arg()
        call_iat(1)
        code.extend(b"\x83\xf8\xff")
        fail_if(b"\x75")
        code.extend(b"\x53")
        call_iat(4)
        failure = len(code)
        code.extend(b"\x6a\x00")
        call_iat(4)
    for offset in failures:
        displacement = failure - offset - 1
        assert -128 <= displacement <= 127
        code[offset] = displacement & 0xff
    assert len(code) < 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_open_always_lifecycle(machine: int, *, wide: bool = True) -> bytes:
    """Open a guest file twice and verify last-error and close semantics."""
    is_x64 = machine == 0x8664
    image_base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * 0x400)
    text_section = 0x98 + (0xF0 if is_x64 else 0xE0)
    struct.pack_into("<I", buf, text_section + 8, 0x200)
    idata_section = text_section + 40
    struct.pack_into("<I", buf, idata_section + 8, 0x600)
    struct.pack_into("<I", buf, idata_section + 16, 0x600)
    buf[0x400:0xA00] = b"\0" * 0x600
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x21C0, 0x2070)
    fmt, step = ("<Q", 8) if is_x64 else ("<I", 4)
    names = (b"CreateFile" + (b"W" if wide else b"A"), b"GetLastError",
             b"CloseHandle", b"ExitProcess")
    for index, name in enumerate(names):
        target = 0x20C0 + index * 0x30
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x470 + index * step, target)
        offset = 0x4C0 + index * 0x30
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5C0:0x5CD] = b"KERNEL32.dll\0"
    path = r"C:\Users\Alex\Downloads\open-always.bin"
    raw = path.encode("utf-16le") + b"\0\0" if wide else path.encode() + b"\0"
    buf[0x600:0x600 + len(raw)] = raw
    code = bytearray()
    failures = []

    def call_iat(index):
        rva = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", image_base + rva))

    def fail_if_nonzero():
        code.extend(b"\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x83\xec\x48")

        def create_file():
            code.extend(b"\x48\xb9" + struct.pack("<Q", image_base + 0x2200))
            code.extend(b"\xba\x00\x00\x00\xc0\x45\x31\xc0\x45\x31\xc9")
            for offset, value in ((0x20, 4), (0x28, 0x80), (0x30, 0)):
                code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
            call_iat(0)
            code.extend(b"\x48\x89\xc3\x83\xf8\xff")
            code.extend(b"\x0f\x84\0\0\0\0")
            failures.append(len(code) - 4)

        def close_file():
            code.extend(b"\x48\x89\xd9")
            call_iat(2)

        create_file()
        call_iat(1)
        code.extend(b"\x85\xc0")
        fail_if_nonzero()
        close_file()
        code.extend(b"\x83\xf8\x01")
        fail_if_nonzero()
        create_file()
        call_iat(1)
        code.extend(b"\x3d\xb7\x00\x00\x00")
        fail_if_nonzero()
        close_file()
        code.extend(b"\x83\xf8\x01")
        fail_if_nonzero()
        close_file()
        code.extend(b"\x85\xc0")
        fail_if_nonzero()
        call_iat(1)
        code.extend(b"\x83\xf8\x06")
        fail_if_nonzero()
        code.extend(b"\xb9\x01\x00\x00\x00")
        call_iat(3)
        failure = len(code)
        code.extend(b"\x31\xc9")
        call_iat(3)
    else:
        def push(value):
            code.extend(b"\x68" + struct.pack("<I", value))

        def create_file():
            for value in (0, 0x80, 4, 0, 0, 0xC0000000, image_base + 0x2200):
                push(value)
            call_iat(0)
            code.extend(b"\x89\xc3\x83\xf8\xff")
            code.extend(b"\x0f\x84\0\0\0\0")
            failures.append(len(code) - 4)

        def close_file():
            code.extend(b"\x53")
            call_iat(2)

        create_file()
        call_iat(1)
        code.extend(b"\x85\xc0")
        fail_if_nonzero()
        close_file()
        code.extend(b"\x83\xf8\x01")
        fail_if_nonzero()
        create_file()
        call_iat(1)
        code.extend(b"\x3d\xb7\x00\x00\x00")
        fail_if_nonzero()
        close_file()
        code.extend(b"\x83\xf8\x01")
        fail_if_nonzero()
        close_file()
        code.extend(b"\x85\xc0")
        fail_if_nonzero()
        call_iat(1)
        code.extend(b"\x83\xf8\x06")
        fail_if_nonzero()
        code.extend(b"\x6a\x01")
        call_iat(3)
        failure = len(code)
        code.extend(b"\x6a\x00")
        call_iat(3)
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_reopen_overwrite(machine: int, *, wide: bool = True,
                           truncate: bool = False, append: bool = False,
                           delete_on_close: bool = False,
                           leave_delete_handle_open: bool = False,
                           delete_on_create: bool = False,
                           file_disposition: bool = False,
                           file_disposition_cancel: bool = False,
                           file_disposition_leave_open: bool = False) -> bytes:
    """Write, close, reopen, optionally truncate, and read a guest file."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * 0x400)
    section = 0x98 + (0xF0 if is_x64 else 0xE0)
    struct.pack_into("<I", buf, section + 8, 0x200)
    struct.pack_into("<I", buf, section + 40 + 8, 0x600)
    struct.pack_into("<I", buf, section + 40 + 16, 0x600)
    buf[0x400:0xA00] = b"\0" * 0x600
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x21E0, 0x2070)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    names = (b"CreateFile" + (b"W" if wide else b"A"),
             b"WriteFile", b"ReadFile", b"CloseHandle", b"ExitProcess",
             b"SetFileInformationByHandle" if file_disposition else
             b"GetLastError" if delete_on_close or delete_on_create else b"GetFileSize")
    for index, name in enumerate(names):
        target = 0x20C0 + index * 0x30
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x470 + index * step, target)
        offset = 0x4C0 + index * 0x30
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5E0:0x5ED] = b"KERNEL32.dll\0"
    path = r"C:\Users\Alex\Downloads\reopened.bin"
    raw = path.encode("utf-16le") + b"\0\0" if wide else path.encode() + b"\0"
    buf[0x600:0x600 + len(raw)] = raw
    buf[0x700:0x704] = b"OLD!"
    buf[0x708:0x70C] = b"NEW!"
    buf[0x740] = 1  # FILE_DISPOSITION_INFO.DeleteFile for the disposition fixture.
    code = bytearray()
    failures = []

    def call(index):
        rva = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    def fail_unless_one():
        code.extend(b"\x83\xf8\x01\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x83\xec\x48")

        def open_file(disposition, access=0xC0000000, flags=0x80,
                      expect_failure=False):
            code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2200))
            code.extend(b"\xba" + struct.pack("<I", access) +
                        b"\x45\x31\xc0\x45\x31\xc9")
            for offset, value in ((0x20, disposition), (0x28, flags), (0x30, 0)):
                code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
            call(0)
            code.extend(b"\x48\x89\xc3\x83\xf8\xff\x0f" +
                        (b"\x85" if expect_failure else b"\x84") + b"\0\0\0\0")
            failures.append(len(code) - 4)

        def io_file(index, address, count=4):
            code.extend(b"\x48\x89\xd9\x48\xba" + struct.pack("<Q", base + address))
            code.extend(b"\x41\xb8" + struct.pack("<I", count) + b"\x49\xb9" +
                        struct.pack("<Q", base + 0x2338))
            code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
            call(index)
            fail_unless_one()

        def close_file():
            code.extend(b"\x48\x89\xd9")
            call(3)
            fail_unless_one()

        open_file(2, access=0x40010000 if file_disposition else 0xC0000000,
                  flags=0x04000000 if delete_on_create else 0x80)
        io_file(1, 0x2300)
        if file_disposition:
            code.extend(b"\x48\x89\xd9\xba\x04\0\0\0\x49\xb8" +
                        struct.pack("<Q", base + 0x2340) +
                        b"\x41\xb9\x01\0\0\0")
            call(5)
            fail_unless_one()
            if file_disposition_cancel:
                code.extend(b"\x48\x89\xd9\xba\x04\0\0\0\x49\xb8" +
                            struct.pack("<Q", base + 0x2341) +
                            b"\x41\xb9\x01\0\0\0")
                call(5)
                fail_unless_one()
        if not file_disposition_leave_open:
            close_file()
        if file_disposition and not file_disposition_leave_open:
            open_file(3, expect_failure=not file_disposition_cancel)
            if file_disposition_cancel:
                close_file()
        elif delete_on_create:
            open_file(3, expect_failure=True)
            call(5)
            code.extend(b"\x83\xf8\x02\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
        elif not file_disposition:
            open_file(5 if truncate else 3, 0x4 if append else 0xC0000000,
                      0x04000000 if delete_on_close else 0x80)
        if delete_on_close and not delete_on_create and not file_disposition:
            if not leave_delete_handle_open:
                close_file()
                open_file(3, expect_failure=True)
                call(5)
                code.extend(b"\x83\xf8\x02\x0f\x85\0\0\0\0")
                failures.append(len(code) - 4)
        elif not delete_on_create and not file_disposition:
            if truncate:
                code.extend(b"\x48\x89\xd9\x31\xd2")
                call(5)
                code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
                failures.append(len(code) - 4)
            io_file(1, 0x2308)
            close_file()
            open_file(3)
            io_file(2, 0x2330, 8 if append else 4)
            close_file()
            code.extend(b"\x48\xa1" + struct.pack("<Q", base + 0x2330))
    else:
        def push(value):
            code.extend(b"\x68" + struct.pack("<I", value))

        def open_file(disposition, access=0xC0000000, flags=0x80,
                      expect_failure=False):
            for value in (0, flags, disposition, 0, 0, access, base + 0x2200):
                push(value)
            call(0)
            code.extend(b"\x89\xc3\x83\xf8\xff\x0f" +
                        (b"\x85" if expect_failure else b"\x84") + b"\0\0\0\0")
            failures.append(len(code) - 4)

        def io_file(index, address, count=4):
            for value in (0, base + 0x2338, count, base + address):
                push(value)
            code.extend(b"\x53")
            call(index)
            fail_unless_one()

        def close_file():
            code.extend(b"\x53")
            call(3)
            fail_unless_one()

        open_file(2, access=0x40010000 if file_disposition else 0xC0000000,
                  flags=0x04000000 if delete_on_create else 0x80)
        io_file(1, 0x2300)
        if file_disposition:
            for value in (1, base + 0x2340, 4):
                push(value)
            code.extend(b"\x53")
            call(5)
            fail_unless_one()
            if file_disposition_cancel:
                for value in (1, base + 0x2341, 4):
                    push(value)
                code.extend(b"\x53")
                call(5)
                fail_unless_one()
        if not file_disposition_leave_open:
            close_file()
        if file_disposition and not file_disposition_leave_open:
            open_file(3, expect_failure=not file_disposition_cancel)
            if file_disposition_cancel:
                close_file()
        elif delete_on_create:
            open_file(3, expect_failure=True)
            call(5)
            code.extend(b"\x83\xf8\x02\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
        elif not file_disposition:
            open_file(5 if truncate else 3, 0x4 if append else 0xC0000000,
                      0x04000000 if delete_on_close else 0x80)
        if delete_on_close and not delete_on_create and not file_disposition:
            if not leave_delete_handle_open:
                close_file()
                open_file(3, expect_failure=True)
                call(5)
                code.extend(b"\x83\xf8\x02\x0f\x85\0\0\0\0")
                failures.append(len(code) - 4)
        elif not delete_on_create and not file_disposition:
            if truncate:
                code.extend(b"\x6a\x00\x53")
                call(5)
                code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
                failures.append(len(code) - 4)
            io_file(1, 0x2308)
            close_file()
            open_file(3)
            io_file(2, 0x2330, 8 if append else 4)
            close_file()
            code.extend(b"\xa1" + struct.pack("<I", base + 0x2330))
    if not delete_on_close and not delete_on_create and not file_disposition:
        code.extend(b"\x3d" + (b"OLD!" if append else b"NEW!"))
        code.extend(b"\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)
        if append:
            if is_x64:
                code.extend(b"\x48\xa1" + struct.pack("<Q", base + 0x2334))
            else:
                code.extend(b"\xa1" + struct.pack("<I", base + 0x2334))
            code.extend(b"\x3dNEW!\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
    if is_x64:
        code.extend(b"\xb9\x01\x00\x00\x00")
    else:
        code.extend(b"\x6a\x01")
    call(4)
    failure = len(code)
    if is_x64:
        code.extend(b"\x31\xc9")
    else:
        code.extend(b"\x6a\x00")
    call(4)
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_sharing_probe(machine: int, *, wide: bool = True) -> bytes:
    """An exclusive guest open rejects a second open until CloseHandle."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * 0x400)
    section = 0x98 + (0xF0 if is_x64 else 0xE0)
    struct.pack_into("<I", buf, section + 8, 0x200)
    struct.pack_into("<I", buf, section + 40 + 8, 0x600)
    struct.pack_into("<I", buf, section + 40 + 16, 0x600)
    buf[0x400:0xA00] = b"\0" * 0x600
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x21C0, 0x2070)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    names = (b"CreateFile" + (b"W" if wide else b"A"),
             b"GetLastError", b"CloseHandle", b"ExitProcess")
    for index, name in enumerate(names):
        target = 0x20C0 + index * 0x30
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x470 + index * step, target)
        offset = 0x4C0 + index * 0x30
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5C0:0x5CD] = b"KERNEL32.dll\0"
    path = r"C:\Users\Alex\Downloads\exclusive.bin"
    raw = path.encode("utf-16le") + b"\0\0" if wide else path.encode() + b"\0"
    buf[0x600:0x600 + len(raw)] = raw
    code, failures = bytearray(), []

    def call(index):
        rva = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    def fail_if_not_equal(value):
        code.extend(b"\x3d" + struct.pack("<I", value) + b"\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)

    def open_file(disposition, access):
        if is_x64:
            code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2200))
            code.extend(b"\xba" + struct.pack("<I", access) +
                        b"\x45\x31\xc0\x45\x31\xc9")
            for offset, value in ((0x20, disposition), (0x28, 0x80), (0x30, 0)):
                code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
        else:
            for value in (0, 0x80, disposition, 0, 0, access, base + 0x2200):
                code.extend(b"\x68" + struct.pack("<I", value))
        call(0)

    def close_first():
        if is_x64:
            code.extend(b"\x48\x89\xd9")
        else:
            code.extend(b"\x53")
        call(2)
        fail_if_not_equal(1)

    if is_x64:
        code.extend(b"\x48\x83\xec\x48")
    open_file(2, 0xC0000000)
    code.extend(b"\x89\xc3")
    code.extend(b"\x83\xf8\xff\x0f\x84\0\0\0\0")
    failures.append(len(code) - 4)
    open_file(3, 0x80000000)
    fail_if_not_equal(0xFFFFFFFF)
    call(1)
    fail_if_not_equal(32)
    close_first()
    open_file(3, 0x80000000)
    code.extend(b"\x83\xf8\xff\x0f\x84\0\0\0\0")
    failures.append(len(code) - 4)
    if is_x64:
        code.extend(b"\x48\x89\xc1")
    else:
        code.extend(b"\x50")
    call(2)
    fail_if_not_equal(1)
    if is_x64:
        code.extend(b"\xb9\x01\x00\x00\x00")
    else:
        code.extend(b"\x6a\x01")
    call(3)
    failure = len(code)
    if is_x64:
        code.extend(b"\x31\xc9")
    else:
        code.extend(b"\x6a\x00")
    call(3)
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_set_end_of_file(machine: int, *, wide: bool = True,
                          by_handle_info: bool = False,
                          by_handle_rename: bool = False) -> bytes:
    """Write eight guest bytes and exercise a handle-based file operation."""
    assert not (by_handle_info and by_handle_rename)
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * 0x400)
    section = 0x98 + (0xF0 if is_x64 else 0xE0)
    struct.pack_into("<I", buf, section + 8, 0x200)
    struct.pack_into("<I", buf, section + 40 + 8, 0x600)
    struct.pack_into("<I", buf, section + 40 + 16, 0x600)
    buf[0x400:0xA00] = b"\0" * 0x600
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x21E0, 0x2070)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    names = (b"CreateFile" + (b"W" if wide else b"A"), b"WriteFile",
             b"SetFilePointer", (b"SetFileInformationByHandle"
                                 if by_handle_info or by_handle_rename else b"SetEndOfFile"),
             b"GetFileSize", b"ExitProcess")
    for index, name in enumerate(names):
        target = 0x20C0 + index * 0x30
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x470 + index * step, target)
        offset = 0x4C0 + index * 0x30
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5E0:0x5ED] = b"KERNEL32.dll\0"
    path = r"C:\Users\Alex\Downloads\resized.bin"
    raw = path.encode("utf-16le") + b"\0\0" if wide else path.encode() + b"\0"
    buf[0x600:0x600 + len(raw)] = raw
    buf[0x700:0x708] = b"ABCDEFGH"
    rename_size = 0
    if by_handle_info:
        struct.pack_into("<q", buf, 0x740, 3)
    if by_handle_rename:
        target = r"C:\Users\Alex\Downloads\renamed.bin".encode("utf-16le")
        name_offset = 20 if is_x64 else 12
        struct.pack_into("<I", buf, 0x740, 0)
        struct.pack_into("<I", buf, 0x740 + name_offset - 4, len(target))
        buf[0x740 + name_offset:0x740 + name_offset + len(target)] = target
        rename_size = name_offset + len(target)
    code, failures = bytearray(), []

    def call(index):
        rva = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    def fail_unless(value):
        code.extend(b"\x3d" + struct.pack("<I", value) + b"\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x83\xec\x48")
        code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2200))
        code.extend(b"\xba" + struct.pack("<I", 0xC0010000 if by_handle_rename
                                           else 0xC0000000) + b"\x45\x31\xc0\x45\x31\xc9")
        for offset, value in ((0x20, 2), (0x28, 0x80), (0x30, 0)):
            code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
        call(0)
        code.extend(b"\x48\x89\xc3\x83\xf8\xff\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)
        code.extend(b"\x48\x89\xd9\x48\xba" + struct.pack("<Q", base + 0x2300))
        code.extend(b"\x41\xb8\x08\x00\x00\x00\x49\xb9" +
                    struct.pack("<Q", base + 0x2320))
        code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
        call(1)
        fail_unless(1)
        code.extend(b"\x48\x89\xd9\xba\x03\0\0\0\x45\x31\xc0\x45\x31\xc9")
        call(2)
        fail_unless(3)
        code.extend(b"\x48\x89\xd9")
        if by_handle_info or by_handle_rename:
            code.extend(b"\xba" + struct.pack("<I", 3 if by_handle_rename else 6) +
                        b"\x49\xb8" + struct.pack("<Q", base + 0x2340) +
                        b"\x41\xb9" + struct.pack("<I", rename_size if by_handle_rename else 8))
        call(3)
        fail_unless(1)
        code.extend(b"\x48\x89\xd9\x31\xd2")
        call(4)
        fail_unless(8 if by_handle_rename else 3)
        code.extend(b"\xb9\x01\0\0\0")
    else:
        def push(value):
            code.extend(b"\x68" + struct.pack("<I", value))
        for value in (0, 0x80, 2, 0, 0,
                      0xC0010000 if by_handle_rename else 0xC0000000,
                      base + 0x2200):
            push(value)
        call(0)
        code.extend(b"\x89\xc3\x83\xf8\xff\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)
        for value in (0, base + 0x2320, 8, base + 0x2300):
            push(value)
        code.extend(b"\x53")
        call(1)
        fail_unless(1)
        for value in (0, 0, 3):
            push(value)
        code.extend(b"\x53")
        call(2)
        fail_unless(3)
        if by_handle_info or by_handle_rename:
            for value in (rename_size if by_handle_rename else 8,
                          base + 0x2340, 3 if by_handle_rename else 6):
                push(value)
        code.extend(b"\x53")
        call(3)
        fail_unless(1)
        code.extend(b"\x6a\x00\x53")
        call(4)
        fail_unless(8 if by_handle_rename else 3)
        code.extend(b"\x6a\x01")
    call(5)
    failure = len(code)
    code.extend(b"\x31\xc9" if is_x64 else b"\x6a\x00")
    call(5)
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_file_attributes(machine: int, *, wide: bool = True,
                          by_handle: bool = False) -> bytes:
    """Write a guest file, set attributes, and query both metadata APIs."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * 0x400)
    section = 0x98 + (0xF0 if is_x64 else 0xE0)
    struct.pack_into("<I", buf, section + 8, 0x200)
    struct.pack_into("<I", buf, section + 40 + 8, 0x600)
    struct.pack_into("<I", buf, section + 40 + 16, 0x600)
    buf[0x400:0xA00] = b"\0" * 0x600
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x21E0, 0x2070)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    names = (b"CreateFile" + (b"W" if wide else b"A"), b"WriteFile",
             b"SetFileInformationByHandle" if by_handle else
             b"SetFileAttributes" + (b"W" if wide else b"A"),
             b"GetFileAttributes" + (b"W" if wide else b"A"),
             b"GetFileAttributesEx" + (b"W" if wide else b"A"), b"ExitProcess")
    for index, name in enumerate(names):
        target = 0x20C0 + index * 0x30
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x470 + index * step, target)
        offset = 0x4C0 + index * 0x30
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5E0:0x5ED] = b"KERNEL32.dll\0"
    path = r"C:\Users\Alex\Downloads\metadata.bin"
    raw = path.encode("utf-16le") + b"\0\0" if wide else path.encode() + b"\0"
    buf[0x600:0x600 + len(raw)] = raw
    buf[0x700:0x708] = b"ABCDEFGH"
    struct.pack_into("<qqqqI4x", buf, 0x740, 0x12345678, 0, 0, 0, 3)
    code, failures = bytearray(), []

    def call(index):
        rva = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    def fail_unless(value):
        code.extend(b"\x3d" + struct.pack("<I", value) + b"\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x83\xec\x48\x48\xb9" + struct.pack("<Q", base + 0x2200))
        code.extend(b"\xba\x00\x00\x01\xc0\x41\xb8\x07\0\0\0\x45\x31\xc9")
        for offset, value in ((0x20, 2), (0x28, 0x80), (0x30, 0)):
            code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
        call(0)
        code.extend(b"\x48\x89\xc3\x83\xf8\xff\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)
        code.extend(b"\x48\x89\xd9\x48\xba" + struct.pack("<Q", base + 0x2300))
        code.extend(b"\x41\xb8\x08\0\0\0\x49\xb9" + struct.pack("<Q", base + 0x2320))
        code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
        call(1)
        fail_unless(1)
        if by_handle:
            code.extend(b"\x48\x89\xd9\x31\xd2\x49\xb8" +
                        struct.pack("<Q", base + 0x2340) + b"\x41\xb9\x28\0\0\0")
        else:
            code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2200) +
                        b"\xba\x03\0\0\0")
        call(2)
        fail_unless(1)
        code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2200))
        call(3)
        fail_unless(3)
        code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2200) +
                    b"\x31\xd2\x49\xb8" + struct.pack("<Q", base + 0x2400))
        call(4)
        fail_unless(1)
        for offset, expected in ((0, 3), (0x20, 8)) + (((4, 0x12345678),)
                                                          if by_handle else ()):
            code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x2400 + offset) + b"\x8b\x00")
            fail_unless(expected)
        code.extend(b"\xb9\x01\0\0\0")
    else:
        def push(value):
            code.extend(b"\x68" + struct.pack("<I", value))
        for value in (0, 0x80, 2, 0, 7, 0xC0010000, base + 0x2200):
            push(value)
        call(0)
        code.extend(b"\x89\xc3\x83\xf8\xff\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)
        for value in (0, base + 0x2320, 8, base + 0x2300):
            push(value)
        code.extend(b"\x53")
        call(1)
        fail_unless(1)
        if by_handle:
            for value in (40, base + 0x2340, 0):
                push(value)
            code.extend(b"\x53")
        else:
            for value in (3, base + 0x2200):
                push(value)
        call(2)
        fail_unless(1)
        push(base + 0x2200)
        call(3)
        fail_unless(3)
        for value in (base + 0x2400, 0, base + 0x2200):
            push(value)
        call(4)
        fail_unless(1)
        for offset, expected in ((0, 3), (0x20, 8)) + (((4, 0x12345678),)
                                                          if by_handle else ()):
            code.extend(b"\xa1" + struct.pack("<I", base + 0x2400 + offset))
            fail_unless(expected)
        code.extend(b"\x6a\x01")
    call(5)
    failure = len(code)
    code.extend(b"\x31\xc9" if is_x64 else b"\x6a\x00")
    call(5)
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_mapped_file(machine: int, *, unmap: bool = True,
                      coherent: bool = False, file_io: bool = False) -> bytes:
    """Write a guest file through a writable mapped view."""
    assert not (unmap and coherent)
    assert not file_io or coherent
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * 0x400)
    section = 0x98 + (0xF0 if is_x64 else 0xE0)
    struct.pack_into("<I", buf, section + 8, 0x200)
    struct.pack_into("<I", buf, section + 40 + 8, 0x600)
    struct.pack_into("<I", buf, section + 40 + 16, 0x600)
    buf[0x400:0xA00] = b"\0" * 0x600
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x21E0, 0x2070)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    names = (b"CreateFileW", b"WriteFile", b"CreateFileMappingW",
             b"MapViewOfFile", b"SetFilePointer" if file_io else b"UnmapViewOfFile",
             b"ExitProcess")
    for index, name in enumerate(names):
        target = 0x20C0 + index * 0x30
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x470 + index * step, target)
        offset = 0x4C0 + index * 0x30
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5E0:0x5ED] = b"KERNEL32.dll\0"
    path = r"C:\Users\Alex\Downloads\mapped.bin"
    raw = path.encode("utf-16le") + b"\0\0"
    buf[0x600:0x600 + len(raw)] = raw
    buf[0x700:0x708] = b"ABCDEFGH"
    if file_io:
        buf[0x708:0x70C] = b"QRST"
    code, failures = bytearray(), []

    def call(index):
        rva = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    def fail_zero():
        code.extend(b"\x85\xc0\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x83\xec\x48")
        code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2200))
        code.extend(b"\xba\x00\x00\x00\xc0\x45\x31\xc0\x45\x31\xc9")
        for offset, value in ((0x20, 2), (0x28, 0x80), (0x30, 0)):
            code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
        call(0)
        code.extend(b"\x48\x89\xc3\x83\xf8\xff\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)
        if file_io:
            code.extend(b"\x48\x89\xc7")  # Keep the file handle in RDI.
        code.extend(b"\x48\x89\xd9\x48\xba" + struct.pack("<Q", base + 0x2300))
        code.extend(b"\x41\xb8\x08\0\0\0\x49\xb9" + struct.pack("<Q", base + 0x2320))
        code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
        call(1)
        fail_zero()
        code.extend(b"\x48\x89\xd9\x31\xd2\x41\xb8\x04\0\0\0\x45\x31\xc9")
        code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
        code.extend(b"\x48\xc7\x44\x24\x28\0\0\0\0")
        call(2)
        fail_zero()
        code.extend(b"\x48\x89\xc3\x48\x89\xd9\xba\x02\0\0\0\x45\x31\xc0\x45\x31\xc9")
        code.extend(b"\x48\xc7\x44\x24\x20\x08\0\0\0")
        call(3)
        fail_zero()
        if coherent:
            code.extend(b"\x48\x89\xc6")  # Keep the first view in RSI.
            code.extend(b"\x48\x89\xd9\xba\x02\0\0\0\x45\x31\xc0\x45\x31\xc9")
            code.extend(b"\x48\xc7\x44\x24\x20\x08\0\0\0")
            call(3)
            fail_zero()
            code.extend(b"\xc7\x06XYZ!\x81\x38XYZ!\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
            if file_io:
                code.extend(b"\x49\x89\xc4")  # Keep the second view in R12.
                code.extend(b"\x48\x89\xf9\x31\xd2\x45\x31\xc0\x45\x31\xc9")
                call(4)  # SetFilePointer(file, 0, NULL, FILE_BEGIN).
                code.extend(b"\x48\x89\xf9\x48\xba" + struct.pack("<Q", base + 0x2308))
                code.extend(b"\x41\xb8\x04\0\0\0\x49\xb9" +
                            struct.pack("<Q", base + 0x2320))
                code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
                call(1)
                fail_zero()
                code.extend(b"\x81\x3eQRST\x0f\x85\0\0\0\0")
                failures.append(len(code) - 4)
                code.extend(b"\x41\x81\x3c\x24QRST\x0f\x85\0\0\0\0")
                failures.append(len(code) - 4)
        else:
            code.extend(b"\xc7\x00\x58\x59\x5a\x21")  # XYZ!
        if unmap:
            code.extend(b"\x48\x89\xc1")
            call(4)
            fail_zero()
        code.extend(b"\xb9\x01\0\0\0")
    else:
        def push(value):
            code.extend(b"\x68" + struct.pack("<I", value))
        for value in (0, 0x80, 2, 0, 0, 0xC0000000, base + 0x2200):
            push(value)
        call(0)
        code.extend(b"\x89\xc3\x83\xf8\xff\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)
        if file_io:
            code.extend(b"\x89\xc7")  # Keep the file handle in EDI.
        for value in (0, base + 0x2320, 8, base + 0x2300):
            push(value)
        code.extend(b"\x53")
        call(1)
        fail_zero()
        for value in (0, 0, 0, 4, 0):
            push(value)
        code.extend(b"\x53")
        call(2)
        fail_zero()
        code.extend(b"\x89\xc3")  # mapping handle
        for value in (8, 0, 0, 2):
            push(value)
        code.extend(b"\x53")
        call(3)
        fail_zero()
        if coherent:
            code.extend(b"\x89\xc6")  # Keep the first view in ESI.
            for value in (8, 0, 0, 2):
                push(value)
            code.extend(b"\x53")
            call(3)
            fail_zero()
            code.extend(b"\xc7\x06XYZ!\x81\x38XYZ!\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
            if file_io:
                code.extend(b"\x89\xc5")  # Keep the second view in EBP.
                for value in (0, 0, 0):
                    push(value)
                code.extend(b"\x57")
                call(4)  # SetFilePointer(file, 0, NULL, FILE_BEGIN).
                for value in (0, base + 0x2320, 4, base + 0x2308):
                    push(value)
                code.extend(b"\x57")
                call(1)
                fail_zero()
                code.extend(b"\x81\x3eQRST\x0f\x85\0\0\0\0")
                failures.append(len(code) - 4)
                code.extend(b"\x81\x7d\x00QRST\x0f\x85\0\0\0\0")
                failures.append(len(code) - 4)
        else:
            code.extend(b"\xc7\x00\x58\x59\x5a\x21")
        if unmap:
            code.extend(b"\x50")
            call(4)
            fail_zero()
        code.extend(b"\x6a\x01")
    call(5)
    failure = len(code)
    code.extend(b"\x31\xc9" if is_x64 else b"\x6a\x00")
    call(5)
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_duplicate_guest_file(machine: int) -> bytes:
    """Duplicate an owned guest file handle and continue at its shared cursor."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * 0x400)
    section = 0x98 + (0xF0 if is_x64 else 0xE0)
    struct.pack_into("<I", buf, section + 8, 0x200)
    struct.pack_into("<I", buf, section + 40 + 8, 0x600)
    struct.pack_into("<I", buf, section + 40 + 16, 0x600)
    buf[0x400:0xA00] = b"\0" * 0x600
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x21E0, 0x2070)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    names = (b"CreateFileW", b"WriteFile", b"DuplicateHandle",
             b"CloseHandle", b"ExitProcess")
    for index, name in enumerate(names):
        target = 0x20C0 + index * 0x30
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x470 + index * step, target)
        offset = 0x4C0 + index * 0x30
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5E0:0x5ED] = b"KERNEL32.dll\0"
    path = r"C:\Users\Alex\Downloads\duplicate-file.bin"
    raw = path.encode("utf-16le") + b"\0\0"
    buf[0x600:0x600 + len(raw)] = raw
    buf[0x700:0x70C] = b"ABCDEFGHQRST"
    code, failures = bytearray(), []

    def call(index):
        rva = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    def fail_zero():
        code.extend(b"\x85\xc0\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x83\xec\x48\x48\xb9" + struct.pack("<Q", base + 0x2200))
        code.extend(b"\xba\0\0\0\xc0\x45\x31\xc0\x45\x31\xc9")
        for offset, value in ((0x20, 2), (0x28, 0x80), (0x30, 0)):
            code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
        call(0)
        code.extend(b"\x48\x89\xc3\x83\xf8\xff\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)
        for address, count in ((base + 0x2300, 8), (base + 0x2308, 4)):
            if count == 4:
                code.extend(b"\x48\x89\xd9")
                call(3)
                fail_zero()
                code.extend(b"\x48\xa1" + struct.pack("<Q", base + 0x2340))
                code.extend(b"\x48\x89\xc3")
            code.extend(b"\x48\x89\xd9\x48\xba" + struct.pack("<Q", address))
            code.extend(b"\x41\xb8" + struct.pack("<I", count) +
                        b"\x49\xb9" + struct.pack("<Q", base + 0x2320))
            code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
            call(1)
            fail_zero()
            if count == 8:
                code.extend(b"\x48\xc7\xc1\xff\xff\xff\xff\x48\x89\xda")
                code.extend(b"\x49\xc7\xc0\xff\xff\xff\xff")
                code.extend(b"\x49\xb9" + struct.pack("<Q", base + 0x2340))
                for offset, value in ((0x20, 0), (0x28, 0), (0x30, 2)):
                    code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
                call(2)
                fail_zero()
        code.extend(b"\xb9\x01\0\0\0")
        call(4)
        failure = len(code)
        code.extend(b"\x31\xc9")
        call(4)
    else:
        def push(value):
            code.extend(b"\x68" + struct.pack("<I", value))
        for value in (0, 0x80, 2, 0, 0, 0xC0000000, base + 0x2200):
            push(value)
        call(0)
        code.extend(b"\x89\xc3\x83\xf8\xff\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)
        for value in (0, base + 0x2320, 8, base + 0x2300):
            push(value)
        code.extend(b"\x53")
        call(1)
        fail_zero()
        for value in (2, 0, 0, base + 0x2340, 0xFFFFFFFF):
            push(value)
        code.extend(b"\x53\x6a\xff")
        call(2)
        fail_zero()
        code.extend(b"\x53")
        call(3)
        fail_zero()
        code.extend(b"\xa1" + struct.pack("<I", base + 0x2340) + b"\x89\xc3")
        for value in (0, base + 0x2320, 4, base + 0x2308):
            push(value)
        code.extend(b"\x53")
        call(1)
        fail_zero()
        code.extend(b"\x6a\x01")
        call(4)
        failure = len(code)
        code.extend(b"\x6a\0")
        call(4)
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_named_pagefile_mapping(machine: int, *, coherent: bool = False,
                                 remap: bool = False, duplicate: bool = False) -> bytes:
    """Open one guest-only named pagefile section twice and read its bytes."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * 0x400)
    section = 0x98 + (0xF0 if is_x64 else 0xE0)
    struct.pack_into("<I", buf, section + 8, 0x200)
    struct.pack_into("<I", buf, section + 40 + 8, 0x600)
    struct.pack_into("<I", buf, section + 40 + 16, 0x600)
    buf[0x400:0xA00] = b"\0" * 0x600
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x21E0, 0x2070)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    assert sum((coherent, remap, duplicate)) <= 1
    names = (b"CreateFileMappingW", b"MapViewOfFile",
             b"DuplicateHandle" if duplicate else b"OpenFileMappingW",
             b"UnmapViewOfFile" if remap else b"CloseHandle", b"ExitProcess")
    for index, name in enumerate(names):
        target = 0x20C0 + index * 0x30
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x470 + index * step, target)
        offset = 0x4C0 + index * 0x30
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5E0:0x5ED] = b"KERNEL32.dll\0"
    named = "Local\\EmumeeNamedPagefile".encode("utf-16le") + b"\0\0"
    buf[0x600:0x600 + len(named)] = named
    code = bytearray()
    failures = []

    def call(index):
        rva = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    def fail_zero():
        code.extend(b"\x85\xc0\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x83\xec\x48")
        code.extend(b"\x48\xc7\xc1\xff\xff\xff\xff\x31\xd2")
        code.extend(b"\x41\xb8\x04\0\0\0\x45\x31\xc9")
        code.extend(b"\x48\xc7\x44\x24\x20\0\x10\0\0")
        code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x2200))
        code.extend(b"\x48\x89\x44\x24\x28")
        call(0)
        fail_zero()
        code.extend(b"\x48\x89\xc3\x48\x89\xd9\xba\x02\0\0\0")
        code.extend(b"\x45\x31\xc0\x45\x31\xc9")
        code.extend(b"\x48\xc7\x44\x24\x20\x04\0\0\0")
        call(1)
        fail_zero()
        if coherent:
            code.extend(b"\x48\x89\xc6")  # Keep the first view in RSI.
        code.extend(b"\xc7\x00Pers")
        if remap:
            code.extend(b"\x48\x89\xc1")
            call(3)
            fail_zero()
        if duplicate:
            code.extend(b"\x48\xc7\xc1\xff\xff\xff\xff\x48\x89\xda")
            code.extend(b"\x49\xc7\xc0\xff\xff\xff\xff")
            code.extend(b"\x49\xb9" + struct.pack("<Q", base + 0x2300))
            for offset, value in ((0x20, 0), (0x28, 0), (0x30, 2)):
                code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
            call(2)
            fail_zero()
            code.extend(b"\x48\xa1" + struct.pack("<Q", base + 0x2300))
        else:
            code.extend(b"\xb9\x04\0\0\0\x31\xd2")
            code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x2200))
            call(2)
            fail_zero()
        code.extend(b"\x48\x89\xc3\x48\x89\xd9\xba\x04\0\0\0")
        code.extend(b"\x45\x31\xc0\x45\x31\xc9")
        code.extend(b"\x48\xc7\x44\x24\x20\x04\0\0\0")
        call(1)
        fail_zero()
        if coherent:
            code.extend(b"\xc7\x06Cohr")
        code.extend(b"\x81\x38" + (b"Cohr" if coherent else b"Pers") +
                    b"\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)
        code.extend(b"\xb9\x01\0\0\0")
        call(4)
        failure = len(code)
        code.extend(b"\x31\xc9")
        call(4)
    else:
        for value in (base + 0x2200, 0x1000, 0, 4, 0, 0xFFFFFFFF):
            code.extend(b"\x68" + struct.pack("<I", value))
        call(0)
        fail_zero()
        code.extend(b"\x89\xc3")
        for value in (4, 0, 0, 2):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\x53")
        call(1)
        fail_zero()
        if coherent:
            code.extend(b"\x89\xc6")  # Keep the first view in ESI.
        code.extend(b"\xc7\x00Pers")
        if remap:
            code.extend(b"\x50")
            call(3)
            fail_zero()
        if duplicate:
            for value in (2, 0, 0, base + 0x2300, 0xFFFFFFFF):
                code.extend(b"\x68" + struct.pack("<I", value))
            code.extend(b"\x53\x6a\xff")
            call(2)
            fail_zero()
            code.extend(b"\xa1" + struct.pack("<I", base + 0x2300))
        else:
            for value in (base + 0x2200, 0, 4):
                code.extend(b"\x68" + struct.pack("<I", value))
            call(2)
            fail_zero()
        code.extend(b"\x89\xc3")
        for value in (4, 0, 0, 4):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\x53")
        call(1)
        fail_zero()
        if coherent:
            code.extend(b"\xc7\x06Cohr")
        code.extend(b"\x81\x38" + (b"Cohr" if coherent else b"Pers") +
                    b"\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)
        code.extend(b"\x6a\x01")
        call(4)
        failure = len(code)
        code.extend(b"\x6a\x00")
        call(4)
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_open_host_named_mapping_probe(machine: int, name: str) -> bytes:
    """Try a host-only canary name through guest OpenFileMappingW."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", buf, section + 8, 0x200)
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x2080, 0x2050)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    for index, target in enumerate((0x20A0, 0x20C0)):
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x450 + index * step, target)
    buf[0x480:0x48D] = b"KERNEL32.dll\0"
    buf[0x4A0:0x4A0 + len(b"\0\0OpenFileMappingW\0")] = b"\0\0OpenFileMappingW\0"
    buf[0x4C0:0x4CE] = b"\0\0ExitProcess\0"
    raw = name.encode("utf-16le") + b"\0\0"
    assert len(raw) <= 0x100
    buf[0x500:0x500 + len(raw)] = raw
    code = bytearray()
    if is_x64:
        code.extend(b"\x48\x83\xec\x28\xb9\x04\0\0\0\x31\xd2")
        code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x2100))
        code.extend(b"\xff\x15" + struct.pack("<i", 0x2050 - (0x1000 + len(code) + 6)))
        code.extend(b"\x48\x85\xc0\x0f\x94\xc1\x0f\xb6\xc9")
        code.extend(b"\xff\x15" + struct.pack("<i", 0x2058 - (0x1000 + len(code) + 6)))
    else:
        code.extend(b"\x68" + struct.pack("<I", base + 0x2100) +
                    b"\x6a\0\x6a\x04\xff\x15" + struct.pack("<I", base + 0x2050))
        code.extend(b"\x85\xc0\x0f\x94\xc0\x0f\xb6\xc0\x50")
        code.extend(b"\xff\x15" + struct.pack("<I", base + 0x2054))
    code.extend(b"\xc3")
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_process_memory_write(machine: int) -> bytes:
    """Copy a harmless nested PE through the guest WriteProcessMemory API."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * (0x1000 - len(buf)))
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", buf, section + 8, 0xC00)
    struct.pack_into("<I", buf, section + 16, 0xC00)
    buf[0x400:0xA00] = b"\0" * 0x600
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x2150, 0x2070)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    names = (b"VirtualAllocEx", b"WriteProcessMemory", b"ExitProcess")
    for index, name in enumerate(names):
        target = 0x20C0 + index * 0x30
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x470 + index * step, target)
        offset = 0x4C0 + index * 0x30
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x550:0x55D] = b"KERNEL32.dll\0"
    payload = build(machine)
    assert len(payload) == 0x600
    buf[0xA00:0x1000] = payload
    code, failures = bytearray(), []

    def call(index):
        rva = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    def branch(opcode):
        code.extend(opcode + b"\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x83\xec\x48")
        code.extend(b"\x48\xc7\xc1\xff\xff\xff\xff\x31\xd2")
        code.extend(b"\x41\xb8\x00\x10\x00\x00\x41\xb9\x00\x30\x00\x00")
        code.extend(b"\x48\xc7\x44\x24\x20\x04\0\0\0")
        call(0)
        code.extend(b"\x48\x89\xc3\x48\x85\xc0")
        branch(b"\x0f\x84")
        for invalid in (True, False):
            code.extend(b"\x48\xc7\xc1" + struct.pack("<I", 0xBAD if invalid else 0xFFFFFFFF))
            code.extend(b"\x48\x89\xda\x49\xb8" + struct.pack("<Q", base + 0x2600))
            code.extend(b"\x41\xb9\x00\x06\x00\x00")
            code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
            call(1)
            code.extend(b"\x85\xc0")
            branch(b"\x0f\x85" if invalid else b"\x0f\x84")
        code.extend(b"\x66\x81\x3b\x4d\x5a")
        branch(b"\x0f\x85")
        code.extend(b"\xb9\x01\0\0\0")
    else:
        def push(value):
            code.extend(b"\x68" + struct.pack("<I", value))
        for value in (4, 0x3000, 0x1000, 0, 0xFFFFFFFF):
            push(value)
        call(0)
        code.extend(b"\x89\xc3\x85\xc0")
        branch(b"\x0f\x84")
        for invalid in (True, False):
            for value in (0, len(payload), base + 0x2600):
                push(value)
            code.extend(b"\x53")
            push(0xBAD if invalid else 0xFFFFFFFF)
            call(1)
            code.extend(b"\x85\xc0")
            branch(b"\x0f\x85" if invalid else b"\x0f\x84")
        code.extend(b"\x66\x81\x3b\x4d\x5a")
        branch(b"\x0f\x85")
        code.extend(b"\x6a\x01")
    call(2)
    failure = len(code)
    code.extend(b"\x31\xc9" if is_x64 else b"\x6a\x00")
    call(2)
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_virtual_free_ex(machine: int, *, direct_read_after_release: bool = False,
                          copy_pe_before_release: bool = False) -> bytes:
    """Release an emulated allocation and reject malformed or repeated releases."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x2150, 0x2070)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    for index, name in enumerate((b"VirtualAllocEx", b"VirtualFreeEx", b"ExitProcess")):
        target = 0x20C0 + index * 0x30
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x470 + index * step, target)
        offset = 0x4C0 + index * 0x30
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x550:0x55D] = b"KERNEL32.dll\0"
    code, failures = bytearray(), []

    def call(index):
        rva = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    def check(success):
        code.extend(b"\x85\xc0\x0f" + (b"\x84" if success else b"\x85") + b"\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x83\xec\x48")
        code.extend(b"\x48\xc7\xc1\xff\xff\xff\xff\x31\xd2")
        code.extend(b"\x41\xb8\x00\x10\0\0\x41\xb9\x00\x30\0\0")
        code.extend(b"\x48\xc7\x44\x24\x20\x04\0\0\0")
        call(0)
        check(True)
        code.extend(b"\x48\x89\xc3")

        if copy_pe_before_release:
            for source_rva, destination_offset in ((0, 0), (0x1000, 0x200),
                                                   (0x2000, 0x400)):
                code.extend(b"\x48\x8d\xbb" + struct.pack("<I", destination_offset))
                code.extend(b"\x48\xbe" + struct.pack("<Q", base + source_rva))
                code.extend(b"\xb9\x00\x02\x00\x00\xf3\xa4")

        def free(size, success):
            code.extend(b"\x48\xc7\xc1\xff\xff\xff\xff\x48\x89\xda")
            code.extend(b"\x41\xb8" + struct.pack("<I", size))
            code.extend(b"\x41\xb9\x00\x80\0\0")
            call(1)
            check(success)
    else:
        def push(value):
            code.extend(b"\x68" + struct.pack("<I", value))

        for value in (4, 0x3000, 0x1000, 0, 0xFFFFFFFF):
            push(value)
        call(0)
        check(True)
        code.extend(b"\x89\xc3")

        if copy_pe_before_release:
            for source_rva, destination_offset in ((0, 0), (0x1000, 0x200),
                                                   (0x2000, 0x400)):
                code.extend(b"\x8d\xbb" + struct.pack("<I", destination_offset))
                code.extend(b"\xbe" + struct.pack("<I", base + source_rva))
                code.extend(b"\xb9\x00\x02\x00\x00\xf3\xa4")

        def free(size, success):
            for value in (0x8000, size):
                push(value)
            code.extend(b"\x53")
            push(0xFFFFFFFF)
            call(1)
            check(success)

    free(1, False)
    free(0, True)
    if direct_read_after_release:
        code.extend(b"\x8b\x03")  # CPU read of retained, but logically free, guest page.
    free(0, False)
    code.extend(b"\xb9\x01\0\0\0" if is_x64 else b"\x6a\x01")
    call(2)
    failure = len(code)
    code.extend(b"\x31\xc9" if is_x64 else b"\x6a\0")
    call(2)
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_child_process(machine: int, *, suspended: bool = False,
                        resume: bool = False, read_back: bool = False,
                        inject_thread: bool = False,
                        remote_suspended: bool = False,
                        remote_resume: bool = False,
                        wrong_owner_write: bool = False,
                        wrong_owner_allocation: bool = False,
                        protect_probe: bool = False,
                        cpu_cross_owner_access: str | None = None,
                        parent_image_access: str | None = None,
                        parent_dynamic_dll: bool = False,
                        parent_guest_dll: bool = False,
                        inherit_handles: bool = False,
                        close_parent_numeric: bool = False,
                        api_cross_owner_copy: bool = False,
                        api_cross_owner_string: bool = False,
                        api_local_string_copy: bool = False,
                        api_cross_owner_env: bool = False,
                        api_local_env: bool = False,
                        api_private_map: str | None = None,
                        child_peb_read: str | None = None,
                        child_stack_read: str | None = None,
                        child_teb_read: bool = False,
                        remote_teb_mode: str | None = None,
                        duplicate_to_child: bool = False) -> bytes:
    """Drop and launch a harmless child PE entirely in guest state."""
    assert not resume or suspended
    assert sum((resume, read_back, inject_thread)) <= 1
    assert not remote_suspended or inject_thread
    assert not remote_resume or remote_suspended
    assert cpu_cross_owner_access in (None, "read", "write", "write_rep", "execute")
    assert parent_image_access in (None, "read", "write", "execute")
    assert not (parent_dynamic_dll and parent_guest_dll)
    assert not close_parent_numeric or not (parent_dynamic_dll or parent_guest_dll)
    assert not (api_cross_owner_string and api_local_string_copy)
    assert not (api_cross_owner_env and api_local_env)
    assert api_private_map in (None, "child_read", "local_read", "foreign_write")
    assert child_peb_read in (None, "own", "own_parameters", "own_ldr",
                              "parent", "parent_ldr")
    assert child_stack_read in (None, "own", "parent")
    assert remote_teb_mode in (None, "read", "write")
    assert remote_teb_mode is None or (inject_thread and child_teb_read)
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * (0x1000 - len(buf)))
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", buf, section + 8, 0x1200 if parent_guest_dll else 0xC00)
    struct.pack_into("<I", buf, section + 16, 0x1200 if parent_guest_dll else 0xC00)
    if parent_guest_dll:
        struct.pack_into("<I", buf, 0x98 + 56, 0x4000)
    buf[0x400:0xA00] = b"\0" * 0x600
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x21E0, 0x2070)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    names = (b"CreateFileW", b"WriteFile",
             b"RtlMoveMemory" if api_cross_owner_copy else
             b"lstrcpyA" if api_cross_owner_string or api_local_string_copy else
             b"GetEnvironmentVariableA" if api_cross_owner_env or api_local_env else
             b"LoadLibraryW" if parent_dynamic_dll or parent_guest_dll else
             b"VirtualProtectEx" if protect_probe else
             b"ResumeThread" if resume else b"ReadProcessMemory" if read_back else
             b"CreateRemoteThread" if inject_thread else
             b"DuplicateHandle" if duplicate_to_child else b"CloseHandle",
             b"CreateProcessW", b"VirtualAllocEx", b"WriteProcessMemory",
             b"ResumeThread" if remote_resume else b"ExitProcess")
    for index, name in enumerate(names):
        target = 0x20C0 + index * 0x28
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x470 + index * step, target)
        offset = 0x4C0 + index * 0x28
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5E0:0x5ED] = b"KERNEL32.dll\0"
    if api_private_map:
        # Move the import descriptor table to unused .idata space so a second
        # descriptor can import the real ole32.CoCreateGuid handler.
        import_dir = 0x98 + (112 if is_x64 else 96) + 8
        struct.pack_into("<II", buf, import_dir, 0x2400, 0x3C)
        buf[0x800:0x814] = buf[0x400:0x414]
        struct.pack_into("<IIIII", buf, 0x814, 0x2460, 0, 0, 0x24A0, 0x2450)
        struct.pack_into(fmt, buf, 0x850, 0x2480)
        struct.pack_into(fmt, buf, 0x860, 0x2480)
        buf[0x880:0x880 + len(b"\0\0CoCreateGuid\0")] = b"\0\0CoCreateGuid\0"
        buf[0x8A0:0x8AA] = b"OLE32.dll\0"
    path = r"C:\Users\Alex\Downloads\child-stage.exe"
    raw = path.encode("utf-16le") + b"\0\0"
    buf[0x600:0x600 + len(raw)] = raw
    if parent_dynamic_dll or parent_guest_dll:
        dll_path = rf"C:\Users\Alex\Downloads\companion_{'x64' if is_x64 else 'x86'}.dll"
        raw_dll_path = dll_path.encode("utf-16le") + b"\0\0"
        buf[0x780:0x780 + len(raw_dll_path)] = raw_dll_path
    child = bytearray(build(machine))
    if is_x64:
        struct.pack_into("<Q", child, 0x98 + 24, 0x180000000)
    else:
        struct.pack_into("<I", child, 0x98 + 28, 0x500000)
    import_dir = 0x98 + (112 if is_x64 else 96) + 8
    struct.pack_into("<II", child, import_dir, 0, 0)
    if parent_image_access:
        address = base + (0x2400 if parent_image_access != "execute" else 0x1000)
        prefix = (b"\x48\xb8" + struct.pack("<Q", address) if is_x64 else
                  b"\xb8" + struct.pack("<I", address))
        operation = (b"\x8b\x00" if parent_image_access == "read" else
                     b"\xc7\x00\x01\0\0\0" if parent_image_access == "write" else
                     b"\xff\xd0")
        child_code = prefix + operation + b"\xc3"
        child[0x200:0x200 + len(child_code)] = child_code
    elif child_teb_read:
        child_code = (b"\x65\x8b\x04\x25\0\x02\0\0\xc3" if is_x64
                      else b"\x64\xa1\0\x02\0\0\xc3")
        child[0x200:0x210] = child_code.ljust(16, b"\0")
    elif child_stack_read == "own":
        child[0x200:0x210] = b"\x8b\x04\x24\xc3" + b"\0" * 12
    elif child_stack_read == "parent":
        address = 0x12FFF00
        child_code = (b"\x48\xb8" + struct.pack("<Q", address) + b"\x8b\x00\xc3"
                      if is_x64 else b"\xa1" + struct.pack("<I", address) + b"\xc3")
        child[0x200:0x210] = child_code.ljust(16, b"\0")
    elif child_peb_read in ("own", "own_parameters", "own_ldr"):
        child_code = (b"\x65\x48\x8b\x04\x25\x60\0\0\0" if is_x64
                      else b"\x64\xa1\x30\0\0\0")
        if child_peb_read != "own":
            offset = (0x20 if child_peb_read == "own_parameters" else 0x18) if is_x64 else (
                0x10 if child_peb_read == "own_parameters" else 0x0C)
            child_code += (b"\x48\x8b\x40" if is_x64 else b"\x8b\x40") + bytes([offset])
        child_code += b"\x8b\x00\xc3"
        child[0x200:0x210] = child_code.ljust(16, b"\0")
    elif child_peb_read in ("parent", "parent_ldr"):
        address = (0x49F0 if is_x64 else 0x4650) if child_peb_read == "parent_ldr" else 0x4040
        child_code = (b"\x48\xb8" + struct.pack("<Q", address) + b"\x8b\x00\xc3"
                      if is_x64 else b"\xa1" + struct.pack("<I", address) + b"\xc3")
        child[0x200:0x210] = child_code.ljust(16, b"\0")
    elif api_private_map == "child_read":
        address = API_PRIVATE_MAP_ADDRESS
        child_code = (b"\x48\xb8" + struct.pack("<Q", address) + b"\x8b\x00\xc3"
                      if is_x64 else b"\xa1" + struct.pack("<I", address) + b"\xc3")
        child[0x200:0x210] = child_code.ljust(16, b"\0")
    else:
        child[0x200:0x210] = b"\x31\xc0\xc3" + b"\0" * 13  # position-independent return
    buf[0xA00:0x1000] = child
    if parent_guest_dll:
        buf.extend(build_relocatable_companion(machine, 0x180000000 if is_x64 else 0x50000000))
    if api_local_env:
        buf[0x900:0x909] = b"USERNAME\0"
    remote_code = b"\x31\xc0\xc3"  # harmless remote thread returns zero
    if remote_teb_mode == "read":
        remote_code = (b"\x65\x8b\x04\x25\0\x02\0\0\xc3" if is_x64
                       else b"\x64\xa1\0\x02\0\0\xc3")
    elif remote_teb_mode == "write":
        remote_code = (b"\x65\xc7\x04\x25\0\x02\0\0\x44\x33\x22\x11\x31\xc0\xc3"
                       if is_x64 else
                       b"\x64\xc7\x05\0\x02\0\0\x44\x33\x22\x11\x31\xc0\xc3")
    if inject_thread:
        buf[0x900:0x900 + len(remote_code)] = remote_code
    code, failures = bytearray(), []

    def call_rva(rva):
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    def call(index):
        call_rva(0x2070 + index * step)

    def fail_zero():
        code.extend(b"\x85\xc0\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x81\xec\x88\0\0\0")
        code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2200))
        code.extend(b"\xba\0\0\0\x40\x45\x31\xc0\x45\x31\xc9")
        for offset, value in ((0x20, 2), (0x28, 0x80), (0x30, 0)):
            code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
        call(0)
        code.extend(b"\x48\x89\xc3\x83\xf8\xff\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)
        code.extend(b"\x48\x89\xd9\x48\xba" + struct.pack("<Q", base + 0x2600))
        code.extend(b"\x41\xb8\0\x06\0\0\x49\xb9" + struct.pack("<Q", base + 0x2310))
        code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
        call(1)
        fail_zero()
        if parent_guest_dll:
            code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2380))
            code.extend(b"\xba\0\0\0\x40\x45\x31\xc0\x45\x31\xc9")
            for offset, value in ((0x20, 2), (0x28, 0x80), (0x30, 0)):
                code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
            call(0)
            code.extend(b"\x48\x89\xc3\x83\xf8\xff\x0f\x84\0\0\0\0")
            failures.append(len(code) - 4)
            code.extend(b"\x48\x89\xd9\x48\xba" + struct.pack("<Q", base + 0x2C00))
            code.extend(b"\x41\xb8\0\x06\0\0\x49\xb9" + struct.pack("<Q", base + 0x2310))
            code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
            call(1)
            fail_zero()
        if parent_dynamic_dll or parent_guest_dll:
            code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2380))
            call(2)
            fail_zero()
        elif not (resume or read_back or inject_thread or protect_probe or
                api_cross_owner_copy or api_cross_owner_string or api_local_string_copy or
                api_cross_owner_env or api_local_env or duplicate_to_child):
            code.extend(b"\x48\x89\xd9")
            call(2)
            fail_zero()
        code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2200))
        code.extend(b"\x31\xd2\x45\x31\xc0\x45\x31\xc9")
        for offset, value in ((0x20, int(inherit_handles)), (0x28, 4 if suspended else 0),
                              (0x30, 0), (0x38, 0)):
            code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
        for offset, value in ((0x40, base + 0x2320), (0x48, base + 0x23C0)):
            code.extend(b"\x48\xb8" + struct.pack("<Q", value))
            code.extend(b"\x48\x89\x44\x24" + bytes([offset]))
        call(3)
        fail_zero()
        if duplicate_to_child:
            code.extend(b"\x48\xc7\xc1\xff\xff\xff\xff")
            code.extend(b"\x48\xa1" + struct.pack("<Q", base + 0x2B80) + b"\x48\x89\xc2")
            code.extend(b"\x4c\x8b\x05" + struct.pack(
                "<i", 0x23C0 - (0x1000 + len(code) + 7)))
            code.extend(b"\x49\xb9" + struct.pack("<Q", base + 0x2B90))
            for offset, value in ((0x20, 0), (0x28, 0), (0x30, 2)):
                code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
            call(2)
            fail_zero()
        if close_parent_numeric:
            code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x2B80) +
                        b"\x48\x8b\x08")
            call(2)
            fail_zero()
        displacement = 0x23C0 - (0x1000 + len(code) + 7)
        code.extend(b"\x48\x8b\x1d" + struct.pack("<i", displacement))
        if wrong_owner_allocation:
            code.extend(b"\x48\x89\xd9")
            code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x2400))
            code.extend(b"\x41\xb8\0\x10\0\0\x41\xb9\0\x30\0\0")
            code.extend(b"\x48\xc7\x44\x24\x20\x04\0\0\0")
            call(4)
            code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
        code.extend(b"\x48\x89\xd9\x31\xd2")
        code.extend(b"\x41\xb8\0\x10\0\0\x41\xb9\0\x30\0\0")
        code.extend(b"\x48\xc7\x44\x24\x20" + struct.pack(
            "<I", 0x40 if inject_thread or cpu_cross_owner_access == "execute" else 4))
        call(4)
        fail_zero()
        code.extend(b"\x48\x89\xc6")
        if cpu_cross_owner_access == "read":
            code.extend(b"\x8b\x06")  # Parent CPU directly reads a child-owned page.
        elif cpu_cross_owner_access == "write":
            code.extend(b"\xc7\x06\x01\0\0\0")
        elif cpu_cross_owner_access == "write_rep":
            code.extend(b"\x48\x89\xf7\xb9\x10\0\0\0\xb0\x5a\xf3\xaa")
        elif cpu_cross_owner_access == "execute":
            code.extend(b"\xff\xd6")
        if protect_probe:
            for target, should_succeed in ((base + 0x2400, False), (None, True)):
                code.extend(b"\x48\x89\xd9")
                if target is None:
                    code.extend(b"\x48\x89\xf2")
                else:
                    code.extend(b"\x48\xba" + struct.pack("<Q", target))
                code.extend(b"\x41\xb8\0\x10\0\0\x41\xb9\x40\0\0\0")
                code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x2310))
                code.extend(b"\x48\x89\x44\x24\x20")
                call(2)
                code.extend(b"\x85\xc0\x0f" + (b"\x84" if should_succeed else b"\x85") + b"\0\0\0\0")
                failures.append(len(code) - 4)
        if wrong_owner_write:
            code.extend(b"\x48\x89\xd9")
            code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x2400))
            code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x2600))
            code.extend(b"\x41\xb9\x10\0\0\0")
            code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
            call(5)
            code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
        code.extend(b"\x48\x89\xd9\x48\x89\xf2")
        code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x2600))
        code.extend(b"\x41\xb9\0\x06\0\0")
        code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
        call(5)
        fail_zero()
        if api_cross_owner_copy:
            code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2400))
            code.extend(b"\x48\x89\xf2\x41\xb8\x10\0\0\0")
            call(2)
        if api_cross_owner_string or api_local_string_copy:
            code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2400))
            if api_local_string_copy:
                code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x2600))
            else:
                code.extend(b"\x48\x89\xf2")
            call(2)
        if api_cross_owner_env or api_local_env:
            if api_local_env:
                code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2500))
            else:
                code.extend(b"\x48\x89\xf1")
            code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x2400))
            code.extend(b"\x41\xb8\x10\0\0\0")
            call(2)
        if inject_thread:
            code.extend(b"\x48\x89\xd9\x48\x8d\x96\0\x08\0\0")
            code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x2500))
            code.extend(b"\x41\xb9" + struct.pack("<I", len(remote_code)))
            code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
            call(5)
            fail_zero()
            code.extend(b"\x48\x89\xd9\x31\xd2\x45\x31\xc0")
            code.extend(b"\x4c\x8d\x8e\0\x08\0\0")
            for offset in (0x20, 0x28, 0x30):
                code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) +
                            struct.pack("<I", 4 if offset == 0x28 and remote_suspended else 0))
            call(2)
            fail_zero()
            if remote_resume:
                code.extend(b"\x48\x89\xc1")
                call(6)
                code.extend(b"\x83\xf8\x01\x0f\x85\0\0\0\0")
                failures.append(len(code) - 4)
        if read_back:
            code.extend(b"\x48\xc7\xc1\xad\x0b\x00\x00\x48\x89\xf2")
            code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x2400))
            code.extend(b"\x41\xb9\x10\0\0\0")
            code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x2310))
            code.extend(b"\x48\x89\x44\x24\x20")
            call(2)
            code.extend(b"\x85\xc0")
            # The intentionally invalid handle must fail before the valid read.
            code.extend(b"\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
            code.extend(b"\x48\x89\xd9\x48\x89\xf2")
            code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x2400))
            code.extend(b"\x41\xb9\x10\0\0\0")
            code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x2310))
            code.extend(b"\x48\x89\x44\x24\x20")
            call(2)
            fail_zero()
            displacement = 0x2400 - (0x1000 + len(code) + 9)
            code.extend(b"\x66\x81\x3d" + struct.pack("<i", displacement) + b"\x4d\x5a")
            code.extend(b"\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
        if resume:
            displacement = 0x23C8 - (0x1000 + len(code) + 7)
            code.extend(b"\x48\x8b\x0d" + struct.pack("<i", displacement))
            call(2)
        if api_private_map:
            if api_private_map == "foreign_write":
                code.extend(b"\x48\x89\xf1")  # rcx = child-owned allocation
            else:
                pointer = (API_PRIVATE_MAP_ADDRESS if api_private_map == "child_read"
                           else base + 0x2400)
                code.extend(b"\x48\xb9" + struct.pack("<Q", pointer))
            call_rva(0x2450)
            if api_private_map == "local_read":
                code.extend(b"\x48\xb8" + struct.pack("<Q", pointer) + b"\x8b\x00")
        if child_teb_read:
            code.extend(b"\x65\xc7\x04\x25\0\x02\0\0\xdd\xcc\xbb\xaa")
        code.extend(b"\xb9\x01\0\0\0")
    else:
        def push(value):
            code.extend(b"\x68" + struct.pack("<I", value))
        for value in (0, 0x80, 2, 0, 0, 0x40000000, base + 0x2200):
            push(value)
        call(0)
        code.extend(b"\x89\xc3\x83\xf8\xff\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)
        for value in (0, base + 0x2310, len(child), base + 0x2600):
            push(value)
        code.extend(b"\x53")
        call(1)
        fail_zero()
        if parent_guest_dll:
            for value in (0, 0x80, 2, 0, 0, 0x40000000, base + 0x2380):
                push(value)
            call(0)
            code.extend(b"\x89\xc3\x83\xf8\xff\x0f\x84\0\0\0\0")
            failures.append(len(code) - 4)
            for value in (0, base + 0x2310, 0x600, base + 0x2C00):
                push(value)
            code.extend(b"\x53")
            call(1)
            fail_zero()
        if parent_dynamic_dll or parent_guest_dll:
            push(base + 0x2380)
            call(2)
            fail_zero()
        elif not (resume or read_back or inject_thread or protect_probe or
                api_cross_owner_copy or api_cross_owner_string or api_local_string_copy or
                api_cross_owner_env or api_local_env or duplicate_to_child):
            code.extend(b"\x53")
            call(2)
            fail_zero()
        for value in (base + 0x23C0, base + 0x2320, 0, 0, 4 if suspended else 0,
                      int(inherit_handles), 0, 0, 0,
                      base + 0x2200):
            push(value)
        call(3)
        fail_zero()
        if duplicate_to_child:
            for value in (2, 0, 0, base + 0x2B90):
                push(value)
            code.extend(b"\xff\x35" + struct.pack("<I", base + 0x23C0))
            code.extend(b"\xff\x35" + struct.pack("<I", base + 0x2B80))
            code.extend(b"\x6a\xff")
            call(2)
            fail_zero()
        if close_parent_numeric:
            code.extend(b"\xff\x35" + struct.pack("<I", base + 0x2B80))
            call(2)
            fail_zero()
        code.extend(b"\x8b\x1d" + struct.pack("<I", base + 0x23C0))
        if wrong_owner_allocation:
            for value in (4, 0x3000, 0x1000, base + 0x2400):
                push(value)
            code.extend(b"\x53")
            call(4)
            code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
        for value in (0x40 if inject_thread or cpu_cross_owner_access == "execute" else 4,
                      0x3000, 0x1000, 0):
            push(value)
        code.extend(b"\x53")
        call(4)
        fail_zero()
        code.extend(b"\x89\xc6")
        if cpu_cross_owner_access == "read":
            code.extend(b"\x8b\x06")
        elif cpu_cross_owner_access == "write":
            code.extend(b"\xc7\x06\x01\0\0\0")
        elif cpu_cross_owner_access == "write_rep":
            code.extend(b"\x89\xf7\xb9\x10\0\0\0\xb0\x5a\xf3\xaa")
        elif cpu_cross_owner_access == "execute":
            code.extend(b"\xff\xd6")
        if protect_probe:
            for target, should_succeed in ((base + 0x2400, False), (None, True)):
                for value in (base + 0x2310, 0x40, 0x1000):
                    push(value)
                if target is None:
                    code.extend(b"\x56")
                else:
                    push(target)
                code.extend(b"\x53")
                call(2)
                code.extend(b"\x85\xc0\x0f" + (b"\x84" if should_succeed else b"\x85") + b"\0\0\0\0")
                failures.append(len(code) - 4)
        if wrong_owner_write:
            for value in (0, 16, base + 0x2600, base + 0x2400):
                push(value)
            code.extend(b"\x53")
            call(5)
            code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
        for value in (0, len(child), base + 0x2600):
            push(value)
        code.extend(b"\x56\x53")
        call(5)
        fail_zero()
        if api_cross_owner_copy:
            push(16)
            code.extend(b"\x56")
            push(base + 0x2400)
            call(2)
        if api_cross_owner_string or api_local_string_copy:
            if api_local_string_copy:
                push(base + 0x2600)
            else:
                code.extend(b"\x56")
            push(base + 0x2400)
            call(2)
        if api_cross_owner_env or api_local_env:
            push(16)
            push(base + 0x2400)
            if api_local_env:
                push(base + 0x2500)
            else:
                code.extend(b"\x56")
            call(2)
        if inject_thread:
            for value in (0, len(remote_code), base + 0x2500):
                push(value)
            code.extend(b"\x8d\x86\0\x08\0\0\x50\x53")
            call(5)
            fail_zero()
            for value in (0, 4 if remote_suspended else 0, 0):
                push(value)
            code.extend(b"\x8d\x86\0\x08\0\0\x50")
            code.extend(b"\x6a\0\x6a\0\x53")
            call(2)
            fail_zero()
            if remote_resume:
                code.extend(b"\x50")
                call(6)
                code.extend(b"\x83\xf8\x01\x0f\x85\0\0\0\0")
                failures.append(len(code) - 4)
        if read_back:
            for value in (base + 0x2310, 16, base + 0x2400):
                push(value)
            code.extend(b"\x56")
            push(0xBAD)
            call(2)
            code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
            for value in (base + 0x2310, 16, base + 0x2400):
                push(value)
            code.extend(b"\x56\x53")
            call(2)
            fail_zero()
            code.extend(b"\x66\x81\x3d" + struct.pack("<I", base + 0x2400) + b"\x4d\x5a")
            code.extend(b"\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
        if resume:
            code.extend(b"\xff\x35" + struct.pack("<I", base + 0x23C4))
            call(2)
        if api_private_map:
            if api_private_map == "foreign_write":
                code.extend(b"\x56")  # push esi, child-owned allocation
            else:
                pointer = (API_PRIVATE_MAP_ADDRESS if api_private_map == "child_read"
                           else base + 0x2400)
                push(pointer)
            call_rva(0x2450)
            if api_private_map == "local_read":
                code.extend(b"\xa1" + struct.pack("<I", pointer))
        if child_teb_read:
            code.extend(b"\x64\xc7\x05\0\x02\0\0\xdd\xcc\xbb\xaa")
        if not remote_resume:
            code.extend(b"\x6a\x01")
    if remote_resume:
        code.extend(b"\x31\xc0")
        if is_x64:
            code.extend(b"\x48\x81\xc4\x88\0\0\0")
        code.extend(b"\xc3")
        failure = len(code)
        code.extend(b"\xb8\xad\x0b\0\0")
        if is_x64:
            code.extend(b"\x48\x81\xc4\x88\0\0\0")
        code.extend(b"\xc3")
    else:
        call(6)
        failure = len(code)
        code.extend(b"\x31\xc9" if is_x64 else b"\x6a\x00")
        call(6)
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_child_parent_module_lookup(machine: int, *, query_only: bool = False,
                                     ex_query: bool = False,
                                     foreign_free: bool = False,
                                     foreign_proc: bool = False,
                                     foreign_filename: bool = False,
                                     peb_scan: bool = False,
                                     psapi_name: bool = False,
                                     psapi_path: bool = False,
                                     psapi_self: bool = False,
                                     psapi_enum: bool = False,
                                     direct_parent_cpu: str | None = None,
                                     dynamic_parent_dll: bool = False,
                                     guest_parent_dll: bool = False,
                                     api_parent_copy: bool = False,
                                     api_parent_write: bool = False,
                                     inherit_handles: bool = False,
                                     close_parent_numeric: bool = False,
                                     duplicate_to_child: bool = False) -> bytes:
    """Statically load a parent DLL; have a guest child query it by name."""
    is_x64 = machine == 0x8664
    assert sum((query_only, ex_query, foreign_free, foreign_proc,
                foreign_filename, peb_scan, psapi_name, psapi_path,
                psapi_self, psapi_enum)) <= 1
    assert direct_parent_cpu in (None, "read", "write", "execute")
    assert not (direct_parent_cpu and (api_parent_copy or api_parent_write))
    assert not (api_parent_copy and api_parent_write)
    assert not (dynamic_parent_dll and guest_parent_dll)
    arch = "x64" if is_x64 else "x86"
    parent_base = 0x180000000 if is_x64 else 0x50000000
    child_base = 0x1A0000000 if is_x64 else 0x500000
    buf = bytearray(build_child_process(machine, parent_dynamic_dll=dynamic_parent_dll,
                                        parent_guest_dll=guest_parent_dll,
                                        inherit_handles=inherit_handles,
                                        close_parent_numeric=close_parent_numeric,
                                        duplicate_to_child=duplicate_to_child))
    directory = 0x98 + (112 if is_x64 else 96) + 8
    if not (dynamic_parent_dll or guest_parent_dll):
        struct.pack_into("<II", buf, directory, 0x2400, 0x3C)
        buf[0x800:0x814] = buf[0x400:0x414]
        struct.pack_into("<IIIII", buf, 0x814, 0x2460, 0, 0, 0x24A0, 0x2470)
        fmt = "<Q" if is_x64 else "<I"
        struct.pack_into(fmt, buf, 0x860, 0x2480)
        struct.pack_into(fmt, buf, 0x870, 0x2480)
        buf[0x880:0x880 + len(b"\0\0ProbeValue\0")] = b"\0\0ProbeValue\0"
        name = f"companion_{arch}.dll".encode("ascii") + b"\0"
        buf[0x8A0:0x8A0 + len(name)] = name
    else:
        name = f"companion_{arch}.dll".encode("ascii") + b"\0"

    child = bytearray(buf[0xA00:0x1000])
    struct.pack_into("<Q" if is_x64 else "<I", child,
                     0x98 + (24 if is_x64 else 28), child_base)
    struct.pack_into("<II", child, directory, 0x2000, 0x28)
    imported = (b"RtlMoveMemory" if api_parent_copy or api_parent_write else
                b"EnumProcessModules" if psapi_enum else
                b"GetModuleBaseNameW" if psapi_name or psapi_self else
                b"GetModuleFileNameExW" if psapi_path else
                b"GetModuleFileNameW" if foreign_filename else
                b"FreeLibrary" if foreign_free else
                b"GetProcAddress" if foreign_proc else
                b"GetModuleHandleExW" if ex_query else
                b"GetModuleHandleW" if query_only else b"LoadLibraryW")
    child[0x470:0x490] = b"\0" * 0x20
    child[0x470:0x470 + len(imported) + 3] = b"\0\0" + imported + b"\0"
    if psapi_name or psapi_path or psapi_self or psapi_enum:
        child[0x460:0x470] = b"\0" * 0x10
        child[0x460:0x460 + len(b"PSAPI.dll\0")] = b"PSAPI.dll\0"
    guest_name = name.decode("ascii").rstrip("\0").encode("utf-16le") + b"\0\0"
    child[0x500:0x500 + len(guest_name)] = guest_name
    child[0x540:0x54B] = b"ProbeValue\0"
    if psapi_enum:
        idata_section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
        struct.pack_into("<I", child, idata_section + 8, 0x1000)
        enum_buffer = child_base + 0x2200
        enum_needed = child_base + 0x21F0
        code = bytearray()
        if is_x64:
            code.extend(b"\x48\x83\xec\x28\x48\xb9" +
                        struct.pack("<Q", 0xFFFFFFFFFFFFFFFF) +
                        b"\x48\xba" + struct.pack("<Q", enum_buffer) +
                        b"\x41\xb8\x00\x02\x00\x00" +
                        b"\x49\xb9" + struct.pack("<Q", enum_needed))
            code.extend(b"\xff\x15" + struct.pack(
                "<i", 0x2040 - (0x1000 + len(code) + 6)))
            code.extend(b"\x48\x83\xc4\x28")
        else:
            code.extend(b"\x68" + struct.pack("<I", enum_needed) +
                        b"\x68\x00\x02\x00\x00" +
                        b"\x68" + struct.pack("<I", enum_buffer) +
                        b"\x6a\xff\xff\x15" +
                        struct.pack("<I", child_base + 0x2040))
        code.extend(b"\x85\xc0\x74\x00")
        fail_jump = len(code) - 1
        code.extend((b"\x48\xbe" + struct.pack("<Q", enum_buffer))
                    if is_x64 else (b"\xbe" + struct.pack("<I", enum_buffer)))
        code.extend((b"\x48\xb8" + struct.pack("<Q", child_base))
                    if is_x64 else (b"\xb8" + struct.pack("<I", child_base)))
        code.extend(b"\x48\x39\x06" if is_x64 else b"\x39\x06")
        code.extend(b"\x75\x00")
        wrong_first_jump = len(code) - 1
        code.extend(b"\x8b\x0d" + struct.pack("<i", 0x21F0 - (0x1000 + len(code) + 6))
                    if is_x64 else b"\x8b\x0d" + struct.pack("<I", enum_needed))
        code.extend(b"\xc1\xe9\x03" if is_x64 else b"\xc1\xe9\x02")
        code.extend(b"\x83\xf9\x40\x77\x00")
        overflow_jump = len(code) - 1
        code.extend(b"\x85\xc9\x74\x00")
        empty_jump = len(code) - 1
        loop_start = len(code)
        if is_x64:
            code.extend(b"\x48\xb8" + struct.pack("<Q", parent_base) +
                        b"\x48\x39\x06")
        else:
            code.extend(b"\x81\x3e" + struct.pack("<I", parent_base))
        code.extend(b"\x74\x00")
        found_jump = len(code) - 1
        code.extend(b"\x48\x83\xc6\x08" if is_x64 else b"\x83\xc6\x04")
        code.extend(b"\xe2\x00")
        loop_jump = len(code) - 1
        code.extend(b"\x31\xc0\xc3")
        found_target = len(code)
        code.extend(b"\xb8\x01\x00\x00\x00\xc3")
        fail_target = len(code)
        code.extend(b"\xb8\xff\x00\x00\x00\xc3")
        wrong_first_target = len(code)
        code.extend(b"\xb8\xfd\x00\x00\x00\xc3")
        overflow_target = len(code)
        code.extend(b"\xb8\xfc\x00\x00\x00\xc3")
        empty_target = len(code)
        code.extend(b"\xb8\xfe\x00\x00\x00\xc3")
        for offset, target in ((fail_jump, fail_target),
                               (wrong_first_jump, wrong_first_target),
                               (overflow_jump, overflow_target),
                               (empty_jump, empty_target),
                               (found_jump, found_target),
                               (loop_jump, loop_start)):
            delta = target - offset - 1
            assert -128 <= delta <= 127, (offset, target)
            code[offset] = delta & 0xFF
    elif (psapi_name or psapi_path or psapi_self) and is_x64:
        requested = 0 if psapi_self else parent_base
        prefix = (b"\x48\x83\xec\x28\x48\xb9" + struct.pack("<Q", 0xFFFFFFFFFFFFFFFF) +
                  b"\x48\xba" + struct.pack("<Q", requested) +
                  b"\x49\xb8" + struct.pack("<Q", child_base + 0x2180) +
                  b"\x41\xb9\x40\x00\x00\x00")
        code = (prefix + b"\xff\x15" +
                struct.pack("<i", 0x2040 - (0x1000 + len(prefix) + 6)) +
                b"\x48\x83\xc4\x28\xc3")
    elif psapi_name or psapi_path or psapi_self:
        requested = 0 if psapi_self else parent_base
        code = (b"\x6a\x40" +
                b"\x68" + struct.pack("<I", child_base + 0x2180) +
                b"\x68" + struct.pack("<I", requested) +
                b"\x6a\xff" +
                b"\xff\x15" + struct.pack("<I", child_base + 0x2040) + b"\xc3")
    elif peb_scan:
        code = bytearray(
            b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00\x48\x8b\x40\x18"
            b"\x48\x8b\x40\x10\x48\x89\xc2\xb9\x10\x00\x00\x00"
            if is_x64 else
            b"\x64\xa1\x30\x00\x00\x00\x8b\x40\x0c\x8b\x40\x0c"
            b"\x89\xc2\xb9\x10\x00\x00\x00")
        loop_start = len(code)
        if is_x64:
            code.extend(b"\x4c\x8b\x40\x30\x49\xb9" +
                        struct.pack("<Q", parent_base) + b"\x4d\x39\xc8")
        else:
            code.extend(b"\x81\x78\x18" + struct.pack("<I", parent_base))
        code.extend(b"\x74\x00")
        found_jump = len(code) - 1
        code.extend(b"\x48\x8b\x00\x48\x39\xd0" if is_x64
                    else b"\x8b\x00\x39\xd0")
        code.extend(b"\x74\x00")
        done_jump = len(code) - 1
        code.extend(b"\xe2\x00")
        loop_jump = len(code) - 1
        done_target = len(code)
        code.extend(b"\x31\xc0\xc3")
        found_target = len(code)
        code.extend(b"\xb8\x01\x00\x00\x00\xc3")
        for offset, target in ((found_jump, found_target),
                               (done_jump, done_target),
                               (loop_jump, loop_start)):
            code[offset] = (target - offset - 1) & 0xFF
    elif foreign_filename and is_x64:
        prefix = (b"\x48\x83\xec\x28\x48\xb9" + struct.pack("<Q", parent_base) +
                  b"\x48\xba" + struct.pack("<Q", child_base + 0x2180) +
                  b"\x41\xb8\x80\x00\x00\x00")
        code = (prefix + b"\xff\x15" +
                struct.pack("<i", 0x2040 - (0x1000 + len(prefix) + 6)) +
                b"\x48\x83\xc4\x28\xc3")
    elif foreign_filename:
        code = (b"\x68\x80\x00\x00\x00" +
                b"\x68" + struct.pack("<I", child_base + 0x2180) +
                b"\x68" + struct.pack("<I", parent_base) +
                b"\xff\x15" + struct.pack("<I", child_base + 0x2040) + b"\xc3")
    elif foreign_free and is_x64:
        prefix = b"\x48\x83\xec\x28\x48\xb9" + struct.pack("<Q", parent_base)
        code = (prefix + b"\xff\x15" +
                struct.pack("<i", 0x2040 - (0x1000 + len(prefix) + 6)) +
                b"\x48\x83\xc4\x28\xc3")
    elif foreign_free:
        code = (b"\x68" + struct.pack("<I", parent_base) +
                b"\xff\x15" + struct.pack("<I", child_base + 0x2040) + b"\xc3")
    elif foreign_proc and is_x64:
        prefix = (b"\x48\x83\xec\x28\x48\xb9" + struct.pack("<Q", parent_base) +
                  b"\x48\xba" + struct.pack("<Q", child_base + 0x2140))
        code = (prefix + b"\xff\x15" +
                struct.pack("<i", 0x2040 - (0x1000 + len(prefix) + 6)) +
                b"\x48\x83\xc4\x28\xc3")
    elif foreign_proc:
        code = (b"\x68" + struct.pack("<I", child_base + 0x2140) +
                b"\x68" + struct.pack("<I", parent_base) +
                b"\xff\x15" + struct.pack("<I", child_base + 0x2040) + b"\xc3")
    elif ex_query and is_x64:
        prefix = (b"\x48\x83\xec\x28\x31\xc9\x48\xba" +
                  struct.pack("<Q", child_base + 0x2100) +
                  b"\x49\xb8" + struct.pack("<Q", child_base + 0x2180))
        code = (prefix + b"\xff\x15" +
                struct.pack("<i", 0x2040 - (0x1000 + len(prefix) + 6)) +
                b"\x48\xa1" + struct.pack("<Q", child_base + 0x2180) +
                b"\x48\x83\xc4\x28\xc3")
    elif ex_query:
        code = (b"\x68" + struct.pack("<I", child_base + 0x2180) +
                b"\x68" + struct.pack("<I", child_base + 0x2100) +
                b"\x6a\0\xff\x15" + struct.pack("<I", child_base + 0x2040) +
                b"\xa1" + struct.pack("<I", child_base + 0x2180) + b"\xc3")
    elif is_x64:
        code = (b"\x48\x83\xec\x28\x48\xb9" + struct.pack("<Q", child_base + 0x2100) +
                b"\xff\x15" + struct.pack("<i", 0x2040 - (0x1000 + 14 + 6)) +
                b"\x48\x83\xc4\x28\xc3")
    else:
        code = (b"\x68" + struct.pack("<I", child_base + 0x2100) +
                b"\xff\x15" + struct.pack("<I", child_base + 0x2040) + b"\xc3")
    if api_parent_copy or api_parent_write:
        idata_section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
        struct.pack_into("<I", child, idata_section + 8, 0x1000)
        destination = (parent_base + 0x2100 if api_parent_write else child_base + 0x2200)
        source = (child_base + 0x2200 if api_parent_write else parent_base + 0x2100)
        if is_x64:
            code = bytearray(b"\x48\x83\xec\x28\x48\xb9" +
                             struct.pack("<Q", destination) +
                             b"\x48\xba" + struct.pack("<Q", source) +
                             b"\x41\xb8\x04\0\0\0")
            code.extend(b"\xff\x15" + struct.pack(
                "<i", 0x2040 - (0x1000 + len(code) + 6)))
            code.extend(b"\x48\x83\xc4\x28\xc3")
        else:
            code = (b"\x6a\x04\x68" + struct.pack("<I", source) +
                    b"\x68" + struct.pack("<I", destination) +
                    b"\xff\x15" + struct.pack("<I", child_base + 0x2040) + b"\xc3")
    elif direct_parent_cpu:
        address = parent_base + (0x2100 if direct_parent_cpu != "execute" else 0x1000)
        prefix = (b"\x48\xb8" + struct.pack("<Q", address) if is_x64 else
                  b"\xb8" + struct.pack("<I", address))
        operation = (b"\x8b\x00" if direct_parent_cpu == "read" else
                     b"\xc7\x00\x01\0\0\0" if direct_parent_cpu == "write" else
                     b"\xff\xd0")
        code = prefix + operation + b"\xc3"
    child[0x200:0x200 + len(code)] = code
    buf[0xA00:0x1000] = child
    return bytes(buf)


def build_child_parent_psapi_valid_handle(machine: int, *, path: bool = False) -> bytes:
    """A guest child opens itself and queries its parent's DLL via PSAPI."""
    is_x64 = machine == 0x8664
    arch = "x64" if is_x64 else "x86"
    parent_base = 0x180000000 if is_x64 else 0x50000000
    child_base = 0x1A0000000 if is_x64 else 0x500000
    buf = bytearray(build_child_parent_module_lookup(machine, psapi_name=True))
    child = bytearray(buf[0xA00:0x1000])
    directory = 0x98 + (112 if is_x64 else 96) + 8
    struct.pack_into("<II", child, directory, 0x2000, 0x3C)
    child[0x400:0x560] = b"\0" * 0x160
    struct.pack_into("<IIIII", child, 0x400, 0x2050, 0, 0, 0x2130, 0x2070)
    struct.pack_into("<IIIII", child, 0x414, 0x2090, 0, 0, 0x2140, 0x20A0)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    for index, target in enumerate((0x20C0, 0x20E0)):
        struct.pack_into(fmt, child, 0x450 + index * step, target)
        struct.pack_into(fmt, child, 0x470 + index * step, target)
    struct.pack_into(fmt, child, 0x490, 0x2100)
    struct.pack_into(fmt, child, 0x4A0, 0x2100)
    child[0x4C0:0x4C0 + len(b"\0\0GetCurrentProcessId\0")] = b"\0\0GetCurrentProcessId\0"
    child[0x4E0:0x4E0 + len(b"\0\0OpenProcess\0")] = b"\0\0OpenProcess\0"
    imported = b"GetModuleFileNameExW" if path else b"GetModuleBaseNameW"
    child[0x500:0x500 + len(imported) + 3] = b"\0\0" + imported + b"\0"
    child[0x530:0x53D] = b"KERNEL32.dll\0"
    child[0x540:0x54A] = b"PSAPI.dll\0"
    code = bytearray()
    if is_x64:
        code.extend(b"\x48\x83\xec\x28")

        def call(rva):
            code.extend(b"\xff\x15" + struct.pack(
                "<i", rva - (0x1000 + len(code) + 6)))

        call(0x2070)
        code.extend(b"\x41\x89\xc0\xb9\x10\x04\x00\x00\x31\xd2")
        call(0x2078)
        code.extend(b"\x48\x89\xc1\x48\xba" + struct.pack("<Q", parent_base) +
                    b"\x49\xb8" + struct.pack("<Q", child_base + 0x2180) +
                    b"\x41\xb9\x40\x00\x00\x00")
        call(0x20A0)
        code.extend(b"\x48\x83\xc4\x28\xc3")
    else:
        code.extend(b"\xff\x15" + struct.pack("<I", child_base + 0x2070) +
                    b"\x50\x6a\x00\x68\x10\x04\x00\x00" +
                    b"\xff\x15" + struct.pack("<I", child_base + 0x2074) +
                    b"\x6a\x40\x68" + struct.pack("<I", child_base + 0x2180) +
                    b"\x68" + struct.pack("<I", parent_base) + b"\x50" +
                    b"\xff\x15" + struct.pack("<I", child_base + 0x20A0) + b"\xc3")
    assert len(code) < 0x100
    child[0x200:0x300] = code.ljust(0x100, b"\0")
    buf[0xA00:0x1000] = child
    return bytes(buf)


def build_child_parent_toolhelp(machine: int, *, parent: bool = False,
                                next_entry: bool = False) -> bytes:
    """A guest child snapshots its own or its parent's modeled modules."""
    is_x64 = machine == 0x8664
    child_base = 0x1A0000000 if is_x64 else 0x500000
    target_pid = 0x420 if parent else 0
    buffer = child_base + 0x2200
    buf = bytearray(build_child_parent_module_lookup(machine, query_only=True))
    child = bytearray(buf[0xA00:0x1000])
    directory = 0x98 + (112 if is_x64 else 96) + 8
    struct.pack_into("<II", child, directory, 0x2000, 0x28)
    idata_section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", child, idata_section + 8, 0x1000)
    child[0x400:0x550] = b"\0" * 0x150
    struct.pack_into("<IIIII", child, 0x400, 0x2050, 0, 0, 0x2130, 0x2070)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    for index, target in enumerate((0x20A0, 0x20C0, 0x20E0)):
        struct.pack_into(fmt, child, 0x450 + index * step, target)
        struct.pack_into(fmt, child, 0x470 + index * step, target)
    for offset, name in ((0x4A0, b"CreateToolhelp32Snapshot"),
                         (0x4C0, b"Module32FirstW"),
                         (0x4E0, b"Module32NextW" if next_entry else b"CloseHandle")):
        child[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    child[0x530:0x53D] = b"KERNEL32.dll\0"
    code = bytearray()
    if is_x64:
        code.extend(b"\x48\x83\xec\x28\x48\xb8" + struct.pack("<Q", buffer) +
                    b"\xc7\x00" + struct.pack("<I", 1072) +
                    b"\xb9\x08\x00\x00\x00\xba" + struct.pack("<I", target_pid))

        def call(rva):
            code.extend(b"\xff\x15" + struct.pack(
                "<i", rva - (0x1000 + len(code) + 6)))

        call(0x2070)
        code.extend(b"\x48\x89\xc3\x48\x89\xc1\x48\xba" + struct.pack("<Q", buffer))
        call(0x2078)
        code.extend(b"\x85\xc0\x74\x00")
        first_fail = len(code) - 1
        code.extend(b"\x48\xb8" + struct.pack("<Q", buffer) +
                    b"\x48\x8b\x70\x18\x48\x89\xd9")
        if next_entry:
            code.extend(b"\x48\xba" + struct.pack("<Q", buffer))
        call(0x2080)
        code.extend(b"\x85\xc0\x74\x00")
        close_fail = len(code) - 1
        if next_entry:
            code.extend(b"\x48\xb8" + struct.pack("<Q", buffer) +
                        b"\x48\x8b\x70\x18")
        code.extend(b"\x48\x89\xf0\x48\x83\xc4\x28\xc3")
        fail = len(code)
        code.extend(b"\x31\xc0\x48\x83\xc4\x28\xc3")
    else:
        code.extend(b"\xc7\x05" + struct.pack("<I", buffer) +
                    struct.pack("<I", 1064) +
                    b"\x68" + struct.pack("<I", target_pid) + b"\x6a\x08" +
                    b"\xff\x15" + struct.pack("<I", child_base + 0x2070) +
                    b"\x89\xc3\x68" + struct.pack("<I", buffer) + b"\x53" +
                    b"\xff\x15" + struct.pack("<I", child_base + 0x2074) +
                    b"\x85\xc0\x74\x00")
        first_fail = len(code) - 1
        code.extend(b"\x8b\x35" + struct.pack("<I", buffer + 0x14) +
                    (b"\x68" + struct.pack("<I", buffer) if next_entry else b"") +
                    b"\x53\xff\x15" + struct.pack("<I", child_base + 0x2078) +
                    b"\x85\xc0\x74\x00")
        close_fail = len(code) - 1
        if next_entry:
            code.extend(b"\x8b\x35" + struct.pack("<I", buffer + 0x14))
        code.extend(b"\x89\xf0\xc3")
        fail = len(code)
        code.extend(b"\x31\xc0\xc3")
    for offset in (first_fail, close_fail):
        delta = fail - offset - 1
        assert 0 <= delta <= 127
        code[offset] = delta
    assert len(code) < 0x100
    child[0x200:0x300] = code.ljust(0x100, b"\0")
    buf[0xA00:0x1000] = child
    return bytes(buf)


def build_child_foreign_snapshot_handle(machine: int, *, inherit_handles: bool = False,
                                        close_parent_numeric: bool = False,
                                        duplicate_to_child: bool = False) -> bytes:
    """Parent passes an un-inherited snapshot number in guest child bytes."""
    is_x64 = machine == 0x8664
    parent_base = 0x140000000 if is_x64 else 0x400000
    child_base = 0x1A0000000 if is_x64 else 0x500000
    buf = bytearray(build_child_parent_module_lookup(
        machine, query_only=True, inherit_handles=inherit_handles,
        close_parent_numeric=close_parent_numeric,
        duplicate_to_child=duplicate_to_child))
    child = bytearray(buf[0xA00:0x1000])
    directory = 0x98 + (112 if is_x64 else 96) + 8
    struct.pack_into("<II", child, directory, 0x2000, 0x28)
    child_section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", child, child_section + 8, 0x1000)
    child[0x400:0x550] = b"\0" * 0x150
    struct.pack_into("<IIIII", child, 0x400, 0x2050, 0, 0, 0x2130, 0x2070)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    for index, target in enumerate((0x20A0, 0x20C0)):
        struct.pack_into(fmt, child, 0x450 + index * step, target)
        struct.pack_into(fmt, child, 0x470 + index * step, target)
    child[0x4A0:0x4A0 + len(b"\0\0Module32FirstW\0")] = b"\0\0Module32FirstW\0"
    child[0x4C0:0x4C0 + len(b"\0\0CloseHandle\0")] = b"\0\0CloseHandle\0"
    child[0x530:0x53D] = b"KERNEL32.dll\0"
    child_code = bytearray()
    if is_x64:
        child_code.extend(b"\x48\x83\xec\x28\x48\xb8" +
                          struct.pack("<Q", child_base + 0x2180) +
                          b"\x48\x8b\x18\x48\x89\xd9\x48\xba" +
                          struct.pack("<Q", child_base + 0x2200))

        def call_child(rva):
            child_code.extend(b"\xff\x15" + struct.pack(
                "<i", rva - (0x1000 + len(child_code) + 6)))

        call_child(0x2070)
        child_code.extend(b"\x89\xc6\x48\x89\xd9")
        call_child(0x2078)
        child_code.extend(b"\x09\xf0\x48\x83\xc4\x28\xc3")
    else:
        child_code.extend(b"\x8b\x1d" + struct.pack("<I", child_base + 0x2180) +
                          b"\x68" + struct.pack("<I", child_base + 0x2200) +
                          b"\x53\xff\x15" + struct.pack("<I", child_base + 0x2070) +
                          b"\x89\xc6\x53\xff\x15" +
                          struct.pack("<I", child_base + 0x2074) +
                          b"\x09\xf0\xc3")
    child[0x200:0x300] = child_code.ljust(0x100, b"\0")
    buf[0xA00:0x1000] = child

    # The existing parent has two import descriptors. Add a third descriptor
    # and an entry stub without changing the original child-writing code.
    struct.pack_into("<II", buf, directory, 0x2400, 0x50)
    struct.pack_into("<IIIII", buf, 0x828, 0x2520, 0, 0, 0x2540, 0x2530)
    struct.pack_into(fmt, buf, 0x920, 0x2560)
    struct.pack_into(fmt, buf, 0x930, 0x2560)
    buf[0x940:0x94D] = b"KERNEL32.dll\0"
    name = b"\0\0CreateToolhelp32Snapshot\0"
    buf[0x960:0x960 + len(name)] = name
    idata_section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", buf, idata_section + 36, 0xE0000060)
    struct.pack_into("<I", buf, 0x98 + 16, 0x2580)
    patch_target = parent_base + 0x2B80
    stub = bytearray()
    if is_x64:
        stub.extend(b"\x48\x83\xec\x28\xb9\x08\x00\x00\x00\x31\xd2")
        stub.extend(b"\xff\x15" + struct.pack(
            "<i", 0x2530 - (0x2580 + len(stub) + 6)))
        stub.extend(b"\x48\xba" + struct.pack("<Q", patch_target) +
                    b"\x48\x89\x02\x48\x83\xc4\x28")
    else:
        stub.extend(b"\x6a\x00\x6a\x08\xff\x15" +
                    struct.pack("<I", parent_base + 0x2530) +
                    b"\xa3" + struct.pack("<I", patch_target))
    stub.extend(b"\xe9" + struct.pack("<i", 0x1000 - (0x2580 + len(stub) + 5)))
    assert len(stub) < 0x80
    buf[0x980:0x980 + len(stub)] = stub
    return bytes(buf)


def build_child_foreign_process_handle(machine: int, *, child_reopens: bool = False,
                                       after_close_read: bool = False,
                                       open_inheritable: bool = False,
                                       create_inherit: bool = False,
                                       close_parent: bool = False,
                                       handle_flag_change: bool | None = None,
                                       duplicate_to_child: bool = False) -> bytes:
    """Compare a guessed parent handle with one the child opens itself."""
    is_x64 = machine == 0x8664
    parent_base = 0x140000000 if is_x64 else 0x400000
    child_base = 0x1A0000000 if is_x64 else 0x500000
    companion_base = 0x180000000 if is_x64 else 0x50000000
    assert not after_close_read or child_reopens
    buf = bytearray(build_child_foreign_snapshot_handle(
        machine, inherit_handles=create_inherit,
        close_parent_numeric=close_parent,
        duplicate_to_child=duplicate_to_child))
    child = bytearray(buf[0xA00:0x1000])
    child[0x4A0:0x4A0 + 0x20] = b"\0" * 0x20
    child[0x4A0:0x4A0 + len(b"\0\0ReadProcessMemory\0")] = b"\0\0ReadProcessMemory\0"
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    if child_reopens:
        struct.pack_into(fmt, child, 0x450 + 2 * step, 0x2100)
        struct.pack_into(fmt, child, 0x470 + 2 * step, 0x2100)
        child[0x500:0x520] = b"\0" * 0x20
        child[0x500:0x500 + len(b"\0\0OpenProcess\0")] = b"\0\0OpenProcess\0"
    code = bytearray()
    if is_x64:
        code.extend(b"\x48\x83\xec\x28")
        if child_reopens:
            code.extend(b"\xb9\x10\0\0\0\x31\xd2\x41\xb8\x20\x04\0\0")
            code.extend(b"\xff\x15" + struct.pack(
                "<i", 0x2070 + 2 * step - (0x1000 + len(code) + 6)))
            code.extend(b"\x48\x89\xc3\x48\x89\xd9")
        else:
            code.extend(b"\x48\xb8" + struct.pack("<Q", child_base + 0x2180) +
                        b"\x48\x8b\x08")
        code.extend(b"\x48\xba" + struct.pack("<Q", companion_base + 0x2100) +
                    b"\x49\xb8" + struct.pack("<Q", child_base + 0x2200) +
                    b"\x41\xb9\x04\0\0\0\x48\xc7\x44\x24\x20\0\0\0\0")
        code.extend(b"\xff\x15" + struct.pack("<i", 0x2070 - (0x1000 + len(code) + 6)))
        code.extend(b"\x89\xc6")
        if child_reopens:
            code.extend(b"\x48\x89\xd9")
        else:
            code.extend(b"\x48\xb8" + struct.pack("<Q", child_base + 0x2180) +
                        b"\x48\x8b\x08")
        code.extend(b"\xff\x15" + struct.pack("<i", 0x2078 - (0x1000 + len(code) + 6)))
        if after_close_read:
            code.extend(b"\x48\x89\xd9\x48\xba" + struct.pack("<Q", companion_base + 0x2100) +
                        b"\x49\xb8" + struct.pack("<Q", child_base + 0x2200) +
                        b"\x41\xb9\x04\0\0\0\x48\xc7\x44\x24\x20\0\0\0\0")
            code.extend(b"\xff\x15" + struct.pack("<i", 0x2070 - (0x1000 + len(code) + 6)))
            code.extend(b"\x48\x83\xc4\x28\xc3")
        else:
            code.extend(b"\x09\xf0\x48\x83\xc4\x28\xc3")
    else:
        if child_reopens:
            code.extend(b"\x68\x20\x04\0\0\x6a\0\x6a\x10\xff\x15" +
                        struct.pack("<I", child_base + 0x2070 + 2 * step) +
                        b"\x89\xc3")
        code.extend(b"\x6a\0\x6a\x04\x68" + struct.pack("<I", child_base + 0x2200) +
                    b"\x68" + struct.pack("<I", companion_base + 0x2100))
        code.extend((b"\x53" if child_reopens else
                     b"\xff\x35" + struct.pack("<I", child_base + 0x2180)) +
                    b"\xff\x15" + struct.pack("<I", child_base + 0x2070) +
                    b"\x89\xc6")
        code.extend((b"\x53" if child_reopens else
                     b"\xff\x35" + struct.pack("<I", child_base + 0x2180)) +
                    b"\xff\x15" + struct.pack("<I", child_base + 0x2074))
        if after_close_read:
            code.extend(b"\x6a\0\x6a\x04\x68" + struct.pack("<I", child_base + 0x2200) +
                        b"\x68" + struct.pack("<I", companion_base + 0x2100) + b"\x53" +
                        b"\xff\x15" + struct.pack("<I", child_base + 0x2070) + b"\xc3")
        else:
            code.extend(b"\x09\xf0\xc3")
    child[0x200:0x300] = code.ljust(0x100, b"\0")
    buf[0xA00:0x1000] = child

    buf[0x960:0x980] = b"\0" * 0x20
    buf[0x960:0x960 + len(b"\0\0OpenProcess\0")] = b"\0\0OpenProcess\0"
    if handle_flag_change is not None:
        # Move this descriptor's lookup table to unused .idata space and add
        # SetHandleInformation without changing the embedded child image.
        struct.pack_into("<I", buf, 0x828, 0x2500)
        struct.pack_into("<I", buf, 0x834, 0x2550)
        buf[0x900:0x940] = b"\0" * 0x40
        for offset in (0x900, 0x930):
            struct.pack_into(fmt, buf, offset, 0x2560)
            struct.pack_into(fmt, buf, offset + step, 0x25D0)
        buf[0x940:0x960] = b"\0" * 0x20
        buf[0x950:0x95D] = b"KERNEL32.dll\0"
    patch_target = parent_base + 0x2B80
    stub = bytearray()
    if is_x64:
        stub.extend(b"\x48\x83\xec\x28\xb9\x10\x00\x00\x00" +
                    (b"\xba\x01\x00\x00\x00" if open_inheritable else b"\x31\xd2") +
                    b"\x41\xb8\x20\x04\x00\x00")
        stub.extend(b"\xff\x15" + struct.pack("<i", 0x2530 - (0x2580 + len(stub) + 6)))
        stub.extend(b"\x48\xba" + struct.pack("<Q", patch_target) +
                    b"\x48\x89\x02")
        if handle_flag_change is not None:
            stub.extend(b"\x48\x89\xc1\xba\x01\x00\x00\x00\x41\xb8" +
                        struct.pack("<I", int(handle_flag_change)))
            stub.extend(b"\xff\x15" + struct.pack(
                "<i", 0x2530 + step - (0x2580 + len(stub) + 6)))
        stub.extend(b"\x48\x83\xc4\x28")
    else:
        stub.extend(b"\x68\x20\x04\x00\x00\x6a" +
                    bytes([int(open_inheritable)]) + b"\x6a\x10\xff\x15" +
                    struct.pack("<I", parent_base + 0x2530) +
                    b"\xa3" + struct.pack("<I", patch_target))
        if handle_flag_change is not None:
            stub.extend(b"\x6a" + bytes([int(handle_flag_change)]) +
                        b"\x6a\x01\xff\x35" + struct.pack("<I", patch_target) +
                        b"\xff\x15" + struct.pack("<I", parent_base + 0x2530 + step))
    stub.extend(b"\xe9" + struct.pack("<i", 0x1000 - (0x2580 + len(stub) + 5)))
    assert len(stub) < 0x80
    buf[0x980:0xA00] = stub.ljust(0x80, b"\0")
    if handle_flag_change is not None:
        name = b"\0\0SetHandleInformation\0"
        assert len(stub) <= 0x50
        buf[0x9D0:0x9D0 + len(name)] = name
    return bytes(buf)


def build_child_foreign_terminate_process(machine: int) -> bytes:
    """Have a child try TerminateProcess using a parent's handle number."""
    is_x64 = machine == 0x8664
    child_base = 0x1A0000000 if is_x64 else 0x500000
    buf = bytearray(build_child_foreign_process_handle(machine))
    child = bytearray(buf[0xA00:0x1000])
    child[0x4A0:0x4C0] = b"\0" * 0x20
    child[0x4A0:0x4A0 + len(b"\0\0TerminateProcess\0")] = b"\0\0TerminateProcess\0"
    if is_x64:
        code = bytearray(b"\x48\x83\xec\x28\x48\xb8" +
                         struct.pack("<Q", child_base + 0x2180) +
                         b"\x48\x8b\x08\xba\x01\0\0\0")
        code.extend(b"\xff\x15" + struct.pack("<i", 0x2070 - (0x1000 + len(code) + 6)))
        code.extend(b"\x48\x83\xc4\x28\xc3")
    else:
        code = bytearray(b"\x6a\x01\xff\x35" + struct.pack("<I", child_base + 0x2180) +
                         b"\xff\x15" + struct.pack("<I", child_base + 0x2070) + b"\xc3")
    child[0x200:0x300] = code.ljust(0x100, b"\0")
    buf[0xA00:0x1000] = child
    return bytes(buf)


def build_child_foreign_terminate_thread(machine: int) -> bytes:
    """Have a guest child try to kill a parent's uninherited thread handle."""
    is_x64 = machine == 0x8664
    parent_base = 0x140000000 if is_x64 else 0x400000
    child_base = 0x1A0000000 if is_x64 else 0x500000
    buf = bytearray(build_child_foreign_snapshot_handle(machine))
    child = bytearray(buf[0xA00:0x1000])
    child[0x4A0:0x4C0] = b"\0" * 0x20
    child[0x4A0:0x4A0 + len(b"\0\0TerminateThread\0")] = b"\0\0TerminateThread\0"
    if is_x64:
        code = bytearray(b"\x48\x83\xec\x28\x48\xb8" +
                         struct.pack("<Q", child_base + 0x2180) +
                         b"\x48\x8b\x08\xba\x07\0\0\0")
        code.extend(b"\xff\x15" + struct.pack("<i", 0x2070 - (0x1000 + len(code) + 6)))
        code.extend(b"\x48\x83\xc4\x28\xc3")
    else:
        code = bytearray(b"\x6a\x07\xff\x35" + struct.pack("<I", child_base + 0x2180) +
                         b"\xff\x15" + struct.pack("<I", child_base + 0x2070) + b"\xc3")
    child[0x200:0x300] = code.ljust(0x100, b"\0")
    buf[0xA00:0x1000] = child

    buf[0x960:0x980] = b"\0" * 0x20
    buf[0x960:0x960 + len(b"\0\0CreateThread\0")] = b"\0\0CreateThread\0"
    buf[0x3E0:0x3E3] = b"\x31\xc0\xc3"
    patch_target = parent_base + 0x2B80
    stub = bytearray()
    if is_x64:
        stub.extend(b"\x48\x83\xec\x38\x31\xc9\x31\xd2")
        stub.extend(b"\x49\xb8" + struct.pack("<Q", parent_base + 0x11E0))
        stub.extend(b"\x45\x31\xc9")
        stub.extend(b"\x48\xc7\x44\x24\x20\x04\0\0\0")
        stub.extend(b"\x48\xc7\x44\x24\x28\0\0\0\0")
        stub.extend(b"\xff\x15" + struct.pack(
            "<i", 0x2530 - (0x2580 + len(stub) + 6)))
        stub.extend(b"\x48\xba" + struct.pack("<Q", patch_target) +
                    b"\x48\x89\x02\x48\x83\xc4\x38")
    else:
        for value in (0, 4, 0, parent_base + 0x11E0, 0, 0):
            stub.extend(b"\x68" + struct.pack("<I", value))
        stub.extend(b"\xff\x15" + struct.pack("<I", parent_base + 0x2530) +
                    b"\xa3" + struct.pack("<I", patch_target))
    stub.extend(b"\xe9" + struct.pack("<i", 0x1000 - (0x2580 + len(stub) + 5)))
    assert len(stub) < 0x80
    buf[0x980:0xA00] = stub.ljust(0x80, b"\0")
    return bytes(buf)


def build_child_foreign_file_handle(machine: int, *, open_inheritable: bool = False,
                                    create_inherit: bool = False,
                                    close_parent: bool = False,
                                    duplicate_to_child: bool = False) -> bytes:
    """Pass a parent's persona-file handle number to an unrelated guest child."""
    is_x64 = machine == 0x8664
    parent_base = 0x140000000 if is_x64 else 0x400000
    child_base = 0x1A0000000 if is_x64 else 0x500000
    step = 8 if is_x64 else 4
    buf = bytearray(build_child_foreign_process_handle(
        machine, create_inherit=create_inherit, close_parent=close_parent,
        duplicate_to_child=duplicate_to_child))
    child = bytearray(buf[0xA00:0x1000])
    child[0x4A0:0x4C0] = b"\0" * 0x20
    child[0x4A0:0x4A0 + len(b"\0\0ReadFile\0")] = b"\0\0ReadFile\0"
    code = bytearray()
    if duplicate_to_child:
        # The child image is loaded after the parent returns. Discover the
        # newly owned handle through its bounded guest handle table instead
        # of trying to patch an image that is not mapped yet.
        if is_x64:
            code.extend(b"\x48\x83\xec\x28\xbb\x80\0\0\0")
        else:
            code.extend(b"\xbb\x80\0\0\0")
        loop = len(code)
        if is_x64:
            code.extend(b"\x48\x89\xd9\x48\xba" + struct.pack("<Q", child_base + 0x2200) +
                        b"\x41\xb8\x04\0\0\0\x49\xb9" +
                        struct.pack("<Q", child_base + 0x2220) +
                        b"\x48\xc7\x44\x24\x20\0\0\0\0")
            code.extend(b"\xff\x15" + struct.pack("<i", 0x2070 - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\x6a\0\x68" + struct.pack("<I", child_base + 0x2220) +
                        b"\x6a\x04\x68" + struct.pack("<I", child_base + 0x2200) +
                        b"\x53\xff\x15" + struct.pack("<I", child_base + 0x2070))
        code.extend(b"\x85\xc0\x0f\x84\0\0\0\0")
        no_read = len(code) - 4
        if is_x64:
            code.extend(b"\x48\xb8" + struct.pack("<Q", child_base + 0x2200) +
                        b"\x81\x38Pers")
        else:
            code.extend(b"\x81\x3d" + struct.pack("<I", child_base + 0x2200) + b"Pers")
        code.extend(b"\x0f\x85\0\0\0\0")
        no_match = len(code) - 4
        if is_x64:
            code.extend(b"\x48\x89\xd9")
            code.extend(b"\xff\x15" + struct.pack(
                "<i", 0x2070 + step - (0x1000 + len(code) + 6)))
            code.extend(b"\xb8\x01\0\0\0\x48\x83\xc4\x28\xc3")
        else:
            code.extend(b"\x53\xff\x15" + struct.pack("<I", child_base + 0x2070 + step) +
                        b"\xb8\x01\0\0\0\xc3")
        next_handle = len(code)
        code.extend(b"\x83\xc3\x04\x81\xfb\x00\x01\0\0\x0f\x82\0\0\0\0")
        back = len(code) - 4
        if is_x64:
            code.extend(b"\x31\xc0\x48\x83\xc4\x28\xc3")
        else:
            code.extend(b"\x31\xc0\xc3")
        for offset in (no_read, no_match):
            struct.pack_into("<i", code, offset, next_handle - offset - 4)
        struct.pack_into("<i", code, back, loop - back - 4)
    elif is_x64:
        code.extend(b"\x48\x83\xec\x28\x48\xb8" + struct.pack("<Q", child_base + 0x2180) +
                    b"\x48\x8b\x08\x48\xba" + struct.pack("<Q", child_base + 0x2200) +
                    b"\x41\xb8\x04\0\0\0\x49\xb9" +
                    struct.pack("<Q", child_base + 0x2220) +
                    b"\x48\xc7\x44\x24\x20\0\0\0\0")
        code.extend(b"\xff\x15" + struct.pack("<i", 0x2070 - (0x1000 + len(code) + 6)))
        code.extend(b"\x48\xb8" + struct.pack("<Q", child_base + 0x2200) +
                    b"\x81\x38\x50\x65\x72\x73\x0f\x94\xc0\x0f\xb6\xf0")
        code.extend(b"\x48\xb8" + struct.pack("<Q", child_base + 0x2180) + b"\x48\x8b\x08")
        code.extend(b"\xff\x15" + struct.pack("<i", 0x2070 + step - (0x1000 + len(code) + 6)))
        code.extend(b"\x89\xf0\x48\x83\xc4\x28\xc3")
    else:
        code.extend(b"\x6a\0\x68" + struct.pack("<I", child_base + 0x2220) +
                    b"\x6a\x04\x68" + struct.pack("<I", child_base + 0x2200) +
                    b"\xff\x35" + struct.pack("<I", child_base + 0x2180) +
                    b"\xff\x15" + struct.pack("<I", child_base + 0x2070))
        code.extend(b"\x81\x3d" + struct.pack("<I", child_base + 0x2200) +
                    b"\x50\x65\x72\x73\x0f\x94\xc0\x0f\xb6\xf0")
        code.extend(b"\xff\x35" + struct.pack("<I", child_base + 0x2180) +
                    b"\xff\x15" + struct.pack("<I", child_base + 0x2070 + step) +
                    b"\x89\xf0\xc3")
    assert len(code) < 0x100
    child[0x200:0x300] = code.ljust(0x100, b"\0")
    buf[0xA00:0x1000] = child

    buf[0x960:0x980] = b"\0" * 0x20
    buf[0x960:0x960 + len(b"\0\0CreateFileW\0")] = b"\0\0CreateFileW\0"
    path = r"C:\Users\Alex\Documents\readme.txt".encode("utf-16le") + b"\0\0"
    buf[0x780:0x780 + len(path)] = path
    stub = bytearray()
    if is_x64:
        stub.extend(b"\x48\x83\xec\x48\x48\xb9" + struct.pack("<Q", parent_base + 0x2380) +
                    b"\xba\0\0\0\x80\x41\xb8\x01\0\0\0")
        stub.extend((b"\x49\xb9" + struct.pack("<Q", parent_base + 0x2B00)) if open_inheritable
                    else b"\x45\x31\xc9")
        for offset, value in ((0x20, 3), (0x28, 0), (0x30, 0)):
            stub.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
        stub.extend(b"\xff\x15" + struct.pack("<i", 0x2530 - (0x2580 + len(stub) + 6)))
        stub.extend(b"\x48\xba" + struct.pack("<Q", parent_base + 0x2B80) +
                    b"\x48\x89\x02\x48\x83\xc4\x48")
    else:
        for value in (0, 0, 3, parent_base + 0x2B00 if open_inheritable else 0,
                      1, 0x80000000, parent_base + 0x2380):
            stub.extend(b"\x68" + struct.pack("<I", value))
        stub.extend(b"\xff\x15" + struct.pack("<I", parent_base + 0x2530) +
                    b"\xa3" + struct.pack("<I", parent_base + 0x2B80))
    stub.extend(b"\xe9" + struct.pack("<i", 0x1000 - (0x2580 + len(stub) + 5)))
    assert len(stub) < 0x80
    buf[0x980:0xA00] = stub.ljust(0x80, b"\0")
    if open_inheritable:
        if is_x64:
            struct.pack_into("<I", buf, 0xF00, 24)
            struct.pack_into("<Q", buf, 0xF08, 0)
            struct.pack_into("<I", buf, 0xF10, 1)
        else:
            struct.pack_into("<III", buf, 0xF00, 12, 0, 1)
    return bytes(buf)


def build_child_foreign_mapping_handle(machine: int, *, map_inheritable: bool = False,
                                       create_inherit: bool = False,
                                       close_parent: bool = False) -> bytes:
    """Pass a parent's guest file-mapping number to a separate guest child."""
    is_x64 = machine == 0x8664
    parent_base = 0x140000000 if is_x64 else 0x400000
    child_base = 0x1A0000000 if is_x64 else 0x500000
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    buf = bytearray(build_child_foreign_file_handle(
        machine, create_inherit=create_inherit, close_parent=close_parent))
    child = bytearray(buf[0xA00:0x1000])
    child[0x4A0:0x4C0] = b"\0" * 0x20
    child[0x4A0:0x4A0 + len(b"\0\0MapViewOfFile\0")] = b"\0\0MapViewOfFile\0"
    code = bytearray()
    if is_x64:
        code.extend(b"\x48\x83\xec\x28\x48\xb8" + struct.pack("<Q", child_base + 0x2180) +
                    b"\x48\x8b\x08\xba\x04\0\0\0\x45\x31\xc0\x45\x31\xc9" +
                    b"\x48\xc7\x44\x24\x20\x04\0\0\0")
        code.extend(b"\xff\x15" + struct.pack("<i", 0x2070 - (0x1000 + len(code) + 6)))
        code.extend(b"\x31\xf6\x48\x85\xc0\x74\x00")
        skip = len(code) - 1
        code.extend(b"\x81\x38\x50\x65\x72\x73\x0f\x94\xc0\x0f\xb6\xf0")
        code[skip] = len(code) - skip - 1
        code.extend(b"\x48\xb8" + struct.pack("<Q", child_base + 0x2180) + b"\x48\x8b\x08")
        code.extend(b"\xff\x15" + struct.pack("<i", 0x2070 + step - (0x1000 + len(code) + 6)))
        code.extend(b"\x89\xf0\x48\x83\xc4\x28\xc3")
    else:
        for value in (4, 0, 0, 4):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\xff\x35" + struct.pack("<I", child_base + 0x2180) +
                    b"\xff\x15" + struct.pack("<I", child_base + 0x2070) +
                    b"\x31\xf6\x85\xc0\x74\x00")
        skip = len(code) - 1
        code.extend(b"\x81\x38\x50\x65\x72\x73\x0f\x94\xc0\x0f\xb6\xf0")
        code[skip] = len(code) - skip - 1
        code.extend(b"\xff\x35" + struct.pack("<I", child_base + 0x2180) +
                    b"\xff\x15" + struct.pack("<I", child_base + 0x2070 + step) +
                    b"\x89\xf0\xc3")
    assert len(code) < 0x100
    child[0x200:0x300] = code.ljust(0x100, b"\0")
    buf[0xA00:0x1000] = child

    # Extend the parent's .idata into unused image space. The parent creates a
    # guest-only four-byte file before its original child-writing entry runs.
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", buf, section + 8, 0x1000)
    struct.pack_into("<I", buf, section + 16, 0x1000)
    struct.pack_into("<I", buf, 0x98 + 16, 0x2C00)
    buf.extend(b"\0" * 0x400)
    struct.pack_into("<I", buf, 0x828, 0x2500)
    struct.pack_into("<I", buf, 0x834, 0x2550)
    buf[0x900:0x950] = b"\0" * 0x50
    for offset in (0x900, 0x930):
        struct.pack_into(fmt, buf, offset, 0x2560)
        struct.pack_into(fmt, buf, offset + step, 0x24C0)
        struct.pack_into(fmt, buf, offset + 2 * step, 0x24E0)
    buf[0x950:0x95D] = b"KERNEL32.dll\0"
    buf[0x8C0:0x8C0 + len(b"\0\0WriteFile\0")] = b"\0\0WriteFile\0"
    buf[0x8E0:0x8E0 + len(b"\0\0CreateFileMappingW\0")] = b"\0\0CreateFileMappingW\0"
    path = r"C:\Users\Alex\Downloads\map-data.bin".encode("utf-16le") + b"\0\0"
    buf[0x780:0x780 + len(path)] = path
    buf[0x1300:0x1304] = b"Pers"
    stub = bytearray()
    if is_x64:
        stub.extend(b"\x48\x83\xec\x48\x48\xb9" + struct.pack("<Q", parent_base + 0x2380) +
                    b"\xba\0\0\0\xc0\x41\xb8\x01\0\0\0\x45\x31\xc9")
        for offset, value in ((0x20, 2), (0x28, 0), (0x30, 0)):
            stub.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
        stub.extend(b"\xff\x15" + struct.pack("<i", 0x2530 - (0x2C00 + len(stub) + 6)))
        stub.extend(b"\x48\x89\xc3\x48\x89\xd9\x48\xba" +
                    struct.pack("<Q", parent_base + 0x2F00) +
                    b"\x41\xb8\x04\0\0\0\x49\xb9" +
                    struct.pack("<Q", parent_base + 0x2F20) +
                    b"\x48\xc7\x44\x24\x20\0\0\0\0")
        stub.extend(b"\xff\x15" + struct.pack("<i", 0x2530 + step - (0x2C00 + len(stub) + 6)))
        stub.extend(b"\x48\x89\xd9")
        stub.extend((b"\x48\xba" + struct.pack("<Q", parent_base + 0x2F40)) if map_inheritable
                    else b"\x31\xd2")
        stub.extend(b"\x41\xb8\x02\0\0\0\x45\x31\xc9" +
                    b"\x48\xc7\x44\x24\x20\0\0\0\0")
        stub.extend(b"\xff\x15" + struct.pack("<i", 0x2530 + 2 * step - (0x2C00 + len(stub) + 6)))
        stub.extend(b"\x48\xba" + struct.pack("<Q", parent_base + 0x2B80) +
                    b"\x48\x89\x02\x48\x83\xc4\x48")
    else:
        for value in (0, 0, 2, 0, 1, 0xC0000000, parent_base + 0x2380):
            stub.extend(b"\x68" + struct.pack("<I", value))
        stub.extend(b"\xff\x15" + struct.pack("<I", parent_base + 0x2530))
        stub.extend(b"\x89\xc3")
        for value in (0, parent_base + 0x2F20, 4, parent_base + 0x2F00):
            stub.extend(b"\x68" + struct.pack("<I", value))
        stub.extend(b"\x53\xff\x15" + struct.pack("<I", parent_base + 0x2530 + step))
        for value in (0, 0, 0, 2, parent_base + 0x2F40 if map_inheritable else 0):
            stub.extend(b"\x68" + struct.pack("<I", value))
        stub.extend(b"\x53\xff\x15" + struct.pack("<I", parent_base + 0x2530 + 2 * step) +
                    b"\xa3" + struct.pack("<I", parent_base + 0x2B80))
    stub.extend(b"\xe9" + struct.pack("<i", 0x1000 - (0x2C00 + len(stub) + 5)))
    assert len(stub) < 0x300
    buf[0x1000:0x1000 + len(stub)] = stub
    if map_inheritable:
        if is_x64:
            struct.pack_into("<I", buf, 0x1340, 24)
            struct.pack_into("<Q", buf, 0x1348, 0)
            struct.pack_into("<I", buf, 0x1350, 1)
        else:
            struct.pack_into("<III", buf, 0x1340, 12, 0, 1)
    return bytes(buf)


def build_child_parent_mapping_view_access(machine: int, *, access: str = "read",
                                           pagefile: bool = False,
                                           named: bool = False) -> bytes:
    """Have a guest child directly touch its parent's known mapped-view address."""
    assert access in ("read", "write", "execute", "api_read", "api_write",
                      "flush", "unmap", "unmap_interior")
    assert not pagefile or access in ("read", "execute", "api_read", "api_write",
                                      "flush", "unmap", "unmap_interior")
    assert pagefile or access in ("read", "write")
    assert not named or pagefile
    is_x64 = machine == 0x8664
    parent_base = 0x140000000 if is_x64 else 0x400000
    child_base = 0x1A0000000 if is_x64 else 0x500000
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    buf = bytearray(build_child_foreign_mapping_handle(machine))
    child = bytearray(buf[0xA00:0x1000])
    if access in ("flush", "unmap", "unmap_interior"):
        name = b"FlushViewOfFile" if access == "flush" else b"UnmapViewOfFile"
        child[0x4A0:0x4C0] = b"\0" * 0x20
        child[0x4A0:0x4A0 + len(name) + 3] = b"\0\0" + name + b"\0"
        if is_x64:
            code = (b"\x48\x83\xec\x28\x48\xb8" + struct.pack("<Q", child_base + 0x2180) +
                    b"\x48\x8b\x08")
            if access == "unmap_interior":
                code += b"\x48\x83\xc1\x01"
            if access == "flush":
                code += b"\xba\x04\0\0\0"
            code += (b"\xff\x15" + struct.pack("<i", 0x2070 - (0x1000 + len(code) + 6)) +
                     b"\x48\x83\xc4\x28\xc3")
        else:
            code = b"\x6a\x04" if access == "flush" else b""
            code += ((b"\xa1" + struct.pack("<I", child_base + 0x2180) +
                      b"\x40\x50") if access == "unmap_interior" else
                     (b"\xff\x35" + struct.pack("<I", child_base + 0x2180)))
            code += b"\xff\x15" + struct.pack("<I", child_base + 0x2070) + b"\xc3"
    elif access in ("api_read", "api_write"):
        child[0x4A0:0x4C0] = b"\0" * 0x20
        child[0x4A0:0x4A0 + len(b"\0\0RtlMoveMemory\0")] = b"\0\0RtlMoveMemory\0"
        child[0x400:0x404] = b"NOPE"
        if is_x64:
            code = b"\x48\x83\xec\x28"
            if access == "api_read":
                code += (b"\x48\xb9" + struct.pack("<Q", child_base + 0x2200) +
                         b"\x48\xb8" + struct.pack("<Q", child_base + 0x2180) +
                         b"\x48\x8b\x10")
            else:
                code += (b"\x48\xb8" + struct.pack("<Q", child_base + 0x2180) +
                         b"\x48\x8b\x08\x48\xba" + struct.pack("<Q", child_base + 0x2200))
            code += b"\x41\xb8\x04\0\0\0"
            code += (b"\xff\x15" + struct.pack("<i", 0x2070 - (0x1000 + len(code) + 6)) +
                     b"\x31\xc0\x48\x83\xc4\x28\xc3")
        else:
            code = (b"\x6a\x04" +
                    (b"\xff\x35" + struct.pack("<I", child_base + 0x2180) +
                     b"\x68" + struct.pack("<I", child_base + 0x2200)
                     if access == "api_read" else
                     b"\x68" + struct.pack("<I", child_base + 0x2200) +
                     b"\xff\x35" + struct.pack("<I", child_base + 0x2180)) +
                    b"\xff\x15" + struct.pack("<I", child_base + 0x2070) +
                    b"\x31\xc0\xc3")
    elif is_x64:
        code = (b"\x48\xb8" + struct.pack("<Q", child_base + 0x2180) +
                b"\x48\x8b\x00" +
                (b"\x81\x38Pers\x0f\x94\xc0\x0f\xb6\xc0\xc3" if access == "read"
                 else b"\xc7\x00NOPE\x31\xc0\xc3" if access == "write"
                 else b"\xff\xd0\xc3"))
    else:
        code = (b"\xa1" + struct.pack("<I", child_base + 0x2180) +
                (b"\x81\x38Pers\x0f\x94\xc0\x0f\xb6\xc0\xc3" if access == "read"
                 else b"\xc7\x00NOPE\x31\xc0\xc3" if access == "write"
                 else b"\xff\xd0\xc3"))
    child[0x200:0x300] = code.ljust(0x100, b"\0")
    buf[0xA00:0x1000] = child

    # Relocate the parent's third import lookup/IAT tables into its extended
    # section so a fourth import does not overlap the KERNEL32.dll name.
    struct.pack_into("<I", buf, 0x828, 0x2F80)
    struct.pack_into("<I", buf, 0x838, 0x2FB0)
    buf[0x1380:0x13E0] = b"\0" * 0x60
    for offset in (0x1380, 0x13B0):
        for index, target in enumerate((0x2560, 0x24C0, 0x24E0, 0x2F60)):
            struct.pack_into(fmt, buf, offset + index * step, target)
    name = b"\0\0MapViewOfFile\0"
    buf[0x1360:0x1360 + len(name)] = name

    stub = bytearray()
    iat = 0x2FB0
    if is_x64:
        stub.extend(b"\x48\x83\xec\x48\x48\xb9" + struct.pack("<Q", parent_base + 0x2380) +
                    b"\xba\0\0\0\xc0\x41\xb8\x01\0\0\0\x45\x31\xc9")
        for offset, value in ((0x20, 2), (0x28, 0), (0x30, 0)):
            stub.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
        stub.extend(b"\xff\x15" + struct.pack("<i", iat - (0x2C00 + len(stub) + 6)))
        stub.extend(b"\x48\x89\xc3\x48\x89\xd9\x48\xba" +
                    struct.pack("<Q", parent_base + 0x2F00) +
                    b"\x41\xb8\x04\0\0\0\x49\xb9" +
                    struct.pack("<Q", parent_base + 0x2F20) +
                    b"\x48\xc7\x44\x24\x20\0\0\0\0")
        stub.extend(b"\xff\x15" + struct.pack("<i", iat + step - (0x2C00 + len(stub) + 6)))
        stub.extend((b"\x48\xc7\xc1\xff\xff\xff\xff" if pagefile else b"\x48\x89\xd9") +
                    b"\x31\xd2\x41\xb8" + struct.pack(
                    "<I", 0x40 if pagefile and access == "execute" else 4 if access == "write" or pagefile else 2) + b"\x45\x31\xc9" +
                    b"\x48\xc7\x44\x24\x20" + struct.pack("<I", 4 if pagefile else 0))
        if named:
            stub.extend(b"\x48\xb8" + struct.pack("<Q", parent_base + 0x2F40) +
                        b"\x48\x89\x44\x24\x28")
        stub.extend(b"\xff\x15" + struct.pack("<i", iat + 2 * step - (0x2C00 + len(stub) + 6)))
        stub.extend(b"\x48\x89\xc1\xba" + struct.pack(
                    "<I", 0x22 if pagefile and access == "execute" else 2 if access == "write" or pagefile else 4) + b"\x45\x31\xc0\x45\x31\xc9" +
                    b"\x48\xc7\x44\x24\x20\x04\0\0\0")
        stub.extend(b"\xff\x15" + struct.pack("<i", iat + 3 * step - (0x2C00 + len(stub) + 6)))
        if pagefile:
            stub.extend(b"\xc7\x00" + (b"\xc3\x90\x90\x90" if access == "execute" else b"Pers"))
        stub.extend(b"\x48\xba" + struct.pack("<Q", parent_base + 0x2B80) +
                    b"\x48\x89\x02\x48\x83\xc4\x48")
    else:
        for value in (0, 0, 2, 0, 1, 0xC0000000, parent_base + 0x2380):
            stub.extend(b"\x68" + struct.pack("<I", value))
        stub.extend(b"\xff\x15" + struct.pack("<I", parent_base + iat) + b"\x89\xc3")
        for value in (0, parent_base + 0x2F20, 4, parent_base + 0x2F00):
            stub.extend(b"\x68" + struct.pack("<I", value))
        stub.extend(b"\x53\xff\x15" + struct.pack("<I", parent_base + iat + step))
        for value in (parent_base + 0x2F40 if named else 0, 4 if pagefile else 0, 0,
                      0x40 if pagefile and access == "execute" else 4 if access == "write" or pagefile else 2, 0):
            stub.extend(b"\x68" + struct.pack("<I", value))
        stub.extend((b"\x6a\xff" if pagefile else b"\x53") +
                    b"\xff\x15" + struct.pack("<I", parent_base + iat + 2 * step))
        for value in (4, 0, 0, 0x22 if pagefile and access == "execute" else 2 if access == "write" or pagefile else 4):
            stub.extend(b"\x68" + struct.pack("<I", value))
        stub.extend(b"\x50\xff\x15" + struct.pack("<I", parent_base + iat + 3 * step))
        if pagefile:
            stub.extend(b"\xc7\x00" + (b"\xc3\x90\x90\x90" if access == "execute" else b"Pers"))
        stub.extend(b"\xa3" + struct.pack("<I", parent_base + 0x2B80))
    stub.extend(b"\xe9" + struct.pack("<i", 0x1000 - (0x2C00 + len(stub) + 5)))
    assert len(stub) < 0x300
    buf[0x1000:0x1300] = stub.ljust(0x300, b"\0")
    if named:
        buf[0x1340:0x1350] = "Local\\N".encode("utf-16le") + b"\0\0"
    return bytes(buf)


def build_child_parent_named_mapping(machine: int, *, foreign_probe: bool = False) -> bytes:
    """A child opens the parent's named pagefile section by its guest name."""
    is_x64 = machine == 0x8664
    child_base = 0x1A0000000 if is_x64 else 0x500000
    step = 8 if is_x64 else 4
    buf = bytearray(build_child_parent_mapping_view_access(
        machine, access="read", pagefile=True, named=True))
    child = bytearray(buf[0xA00:0x1000])
    child[0x4A0:0x4E0] = b"\0" * 0x40
    for offset, name in ((0x4A0, b"OpenFileMappingW"), (0x4C0, b"MapViewOfFile")):
        child[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    child[0x550:0x560] = "Local\\N".encode("utf-16le") + b"\0\0"
    code = bytearray()
    failures = []

    def call(index):
        rva = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", child_base + rva))

    def fail_zero():
        code.extend(b"\x85\xc0\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x83\xec\x28\xb9\x04\0\0\0\x31\xd2")
        code.extend(b"\x49\xb8" + struct.pack("<Q", child_base + 0x2150))
        call(0)
        fail_zero()
        code.extend(b"\x48\x89\xc1\xba\x04\0\0\0\x45\x31\xc0\x45\x31\xc9")
        code.extend(b"\x48\xc7\x44\x24\x20\x04\0\0\0")
        call(1)
        fail_zero()
        if foreign_probe:
            code.extend(b"\x81\x38Pers\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
            code.extend(b"\x48\xb8" + struct.pack("<Q", child_base + 0x2180) +
                        b"\x48\x8b\x00\x81\x38Pers\xb8\x01\0\0\0")
        else:
            code.extend(b"\x81\x38Pers\x0f\x94\xc0\x0f\xb6\xc0")
        code.extend(b"\x48\x83\xc4\x28\xc3")
        failure = len(code)
        code.extend(b"\x31\xc0\x48\x83\xc4\x28\xc3")
    else:
        for value in (child_base + 0x2150, 0, 4):
            code.extend(b"\x68" + struct.pack("<I", value))
        call(0)
        fail_zero()
        for value in (4, 0, 0, 4):
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\x50")
        call(1)
        fail_zero()
        if foreign_probe:
            code.extend(b"\x81\x38Pers\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
            code.extend(b"\xa1" + struct.pack("<I", child_base + 0x2180) +
                        b"\x81\x38Pers\xb8\x01\0\0\0\xc3")
        else:
            code.extend(b"\x81\x38Pers\x0f\x94\xc0\x0f\xb6\xc0\xc3")
        failure = len(code)
        code.extend(b"\x31\xc0\xc3")
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x100
    child[0x200:0x300] = code.ljust(0x100, b"\0")
    buf[0xA00:0x1000] = child
    return bytes(buf)


def build_move_configured_file(machine: int, *, delete: bool = False,
                               copy: bool = False) -> bytes:
    """Move, copy, or delete the persona's mapped readme without changing host bytes."""
    is_x64 = machine == 0x8664
    image_base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", buf, section + 8, 0x200)
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x2080, 0x2050)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    for index, target in enumerate((0x20A0, 0x20C0)):
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x450 + index * step, target)
    buf[0x480:0x48D] = b"KERNEL32.dll\0"
    operation = b"DeleteFileW" if delete else b"CopyFileW" if copy else b"MoveFileExW"
    buf[0x4A0:0x4A0 + len(operation) + 3] = b"\0\0" + operation + b"\0"
    buf[0x4C0:0x4CE] = b"\0\0ExitProcess\0"
    old = r"C:\Users\Alex\Documents\readme.txt".encode("utf-16le") + b"\0\0"
    new = r"C:\Users\Alex\Documents\moved.txt".encode("utf-16le") + b"\0\0"
    buf[0x500:0x500 + len(old)] = old
    buf[0x580:0x580 + len(new)] = new
    code = bytearray()
    if is_x64:
        code.extend(b"\x48\xb9" + struct.pack("<Q", image_base + 0x2100))
        if not delete:
            code.extend(b"\x48\xba" + struct.pack("<Q", image_base + 0x2180))
            code.extend(b"\x45\x31\xc0")
        code.extend(b"\xff\x15" + struct.pack("<i", 0x2050 - (0x1000 + len(code) + 6)))
        code.extend(b"\x89\xc1")
        code.extend(b"\xff\x15" + struct.pack("<i", 0x2058 - (0x1000 + len(code) + 6)))
    else:
        args = ([image_base + 0x2100] if delete else
                [0, image_base + 0x2180, image_base + 0x2100])
        for value in args:
            code.extend(b"\x68" + struct.pack("<I", value))
        code.extend(b"\xff\x15" + struct.pack("<I", image_base + 0x2050))
        code.extend(b"\x50\xff\x15" + struct.pack("<I", image_base + 0x2054))
    code.extend(b"\xc3")
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_dropped_dll(machine: int, *, invalid: bool = False, tls: bool = False,
                      collision: bool = False, imported: bool = False,
                      dependency: bool = False, lifecycle: bool = False,
                      fail_attach: bool = False,
                      preload_dependency: bool = False,
                      guest_dependency: bool = False,
                      release_dependency: bool = False,
                      nested_companion: bool = False,
                      nested_cycle: bool = False,
                      reloc_mode: str | None = None,
                      dependency_reloc_mode: str | None = None,
                      forwarded_guest_mode: str | None = None,
                      guest_import_forwarder: bool = False,
                      supplied_import_guest_forwarder_mode: str | None = None) -> bytes:
    """Write a harmless native DLL to guest storage, then load its export."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    assert not (guest_dependency and (tls or invalid or preload_dependency or collision))
    assert not release_dependency or guest_dependency
    assert not nested_companion or guest_dependency
    assert not nested_cycle or guest_dependency
    assert not (nested_companion and nested_cycle)
    assert reloc_mode in (None, "valid", "missing", "bad_block")
    assert dependency_reloc_mode in (None, "valid", "missing", "bad_block")
    assert forwarded_guest_mode in (None, "valid", "missing_reloc", "failed_attach")
    assert forwarded_guest_mode is None or (guest_dependency and
        dependency_reloc_mode is None and reloc_mode is None and
        not any((release_dependency, nested_companion, nested_cycle, fail_attach)))
    assert not guest_import_forwarder or (guest_dependency and forwarded_guest_mode is None
        and dependency_reloc_mode is None and not any((
            nested_companion, nested_cycle, fail_attach)))
    assert supplied_import_guest_forwarder_mode in (
        None, "valid", "missing_reloc", "failed_attach")
    assert supplied_import_guest_forwarder_mode is None or (
        guest_dependency and forwarded_guest_mode is None and not guest_import_forwarder
        and dependency_reloc_mode is None and not any((
            nested_companion, nested_cycle, fail_attach)))
    assert dependency_reloc_mode is None or (guest_dependency and not any((
        release_dependency, nested_companion, nested_cycle)))
    assert reloc_mode is None or not any((invalid, tls, collision, imported,
                                          dependency, lifecycle, fail_attach,
                                          preload_dependency, guest_dependency,
                                          release_dependency, nested_companion,
                                          nested_cycle))
    dll = (build_tls_companion(machine) if tls else
           build_importing_companion(machine, dependency=dependency or guest_dependency,
                                     fail_attach=fail_attach)
           if imported or dependency or guest_dependency else build(machine, dll=True))
    if reloc_mode is not None:
        reloc_dll = bytearray(build_relocatable_companion(machine, base))
        if reloc_mode == "missing":
            directory = 0x98 + (112 if is_x64 else 96) + 5 * 8
            reloc_dll[directory:directory + 8] = b"\0" * 8
        elif reloc_mode == "bad_block":
            struct.pack_into("<I", reloc_dll, 0x5B4, 0)
        dll = bytes(reloc_dll)
    leaf = (build_importing_companion(machine, dependency=True)
            if nested_companion or nested_cycle else build(machine, dll=True) if guest_dependency else b"")
    if dependency_reloc_mode is not None:
        leaf_image = bytearray(build_relocatable_companion(
            machine, 0x1A0000000 if is_x64 else 0x52000000))
        if dependency_reloc_mode == "missing":
            directory = 0x98 + (112 if is_x64 else 96) + 5 * 8
            leaf_image[directory:directory + 8] = b"\0" * 8
        elif dependency_reloc_mode == "bad_block":
            struct.pack_into("<I", leaf_image, 0x5B4, 0)
        leaf = bytes(leaf_image)
    if guest_import_forwarder:
        leaf = _forward_export(machine, leaf,
                               f"terminal_{'x64' if is_x64 else 'x86'}.ProbeValue")
    if supplied_import_guest_forwarder_mode is not None:
        preferred = 0x180000000 if is_x64 else 0x50000000
        guest_leaf = bytearray(build_relocatable_companion(machine, preferred))
        if supplied_import_guest_forwarder_mode == "missing_reloc":
            directory = 0x98 + (112 if is_x64 else 96) + 5 * 8
            guest_leaf[directory:directory + 8] = b"\0" * 8
        elif supplied_import_guest_forwarder_mode == "failed_attach":
            guest_leaf[0x20E if is_x64 else 0x208] = 0
        leaf = bytes(guest_leaf)
    if forwarded_guest_mode is not None:
        preferred = 0x180000000 if is_x64 else 0x50000000
        dll = _forward_export(machine, build(machine, dll=True),
                              "guest-leaf.ProbeValue")
        guest_leaf = bytearray(build_relocatable_companion(machine, preferred))
        if forwarded_guest_mode == "missing_reloc":
            directory = 0x98 + (112 if is_x64 else 96) + 5 * 8
            guest_leaf[directory:directory + 8] = b"\0" * 8
        elif forwarded_guest_mode == "failed_attach":
            guest_leaf[0x20E if is_x64 else 0x208] = 0
        leaf = bytes(guest_leaf)
    if nested_companion or nested_cycle:
        leaf = bytearray(leaf)
        old_base = 0x1A0000000 if is_x64 else 0x52000000
        new_base = 0x1C0000000 if is_x64 else 0x54000000
        struct.pack_into("<Q" if is_x64 else "<I", leaf,
                         0x98 + (24 if is_x64 else 28), new_base)
        if not is_x64:
            for offset, rva in ((0x202, 0x2040), (0x20D, 0x21E0), (0x232, 0x21E0)):
                assert struct.unpack_from("<I", leaf, offset)[0] == old_base + rva
                struct.pack_into("<I", leaf, offset, new_base + rva)
        if nested_cycle:
            leaf[0x580:0x5A0] = b"\0" * 0x20
            leaf[0x580:0x590] = b"guest-stage.dll\0"
        leaf = bytes(leaf)
    if (guest_dependency and forwarded_guest_mode is None and
            supplied_import_guest_forwarder_mode is None):
        dll = bytearray(dll)
        dll[0x580:0x5A0] = b"\0" * 0x20
        dll[0x580:0x58F] = b"guest-leaf.dll\0"
        dll = bytes(dll)
    if invalid:
        dll = b"not a DLL" + b"\0" * (len(dll) - 9)
    if fail_attach and tls:
        dll = dll[:0x266] + b"\0" + dll[0x267:]  # TLS leaves DllMain's guard unset.
    elif fail_attach and not (imported or dependency):
        dll = dll[:0x208] + b"\0" + dll[0x209:]  # DllMain returns FALSE.
    buf = bytearray(build(machine))
    buf.extend(b"\0" * ((0x1800 if guest_dependency else 0x1000) - len(buf)))
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", buf, section + 8, 0x1400 if guest_dependency else 0xC00)
    struct.pack_into("<I", buf, section + 16, 0x1400 if guest_dependency else 0xC00)
    if guest_dependency:
        struct.pack_into("<I", buf, 0x98 + 56, 0x4000)
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x21E0, 0x2070)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    names = (b"CreateFileW", b"WriteFile", b"CloseHandle", b"LoadLibraryW",
             b"GetProcAddress", b"ExitProcess", b"FreeLibrary") if lifecycle or release_dependency else (
             b"CreateFileW", b"WriteFile", b"CloseHandle", b"LoadLibraryW",
             b"GetProcAddress", b"ExitProcess")
    for index, name in enumerate(names):
        target = 0x20C0 + index * 0x28
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x470 + index * step, target)
        offset = 0x4C0 + index * 0x28
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5E0:0x5ED] = b"KERNEL32.dll\0"
    guest_path = (rf"C:\Users\Alex\Documents\companion_{'x64' if is_x64 else 'x86'}.dll"
                  if collision else r"C:\Users\Alex\Downloads\guest-stage.dll")
    path = guest_path.encode("utf-16le") + b"\0\0"
    assert len(path) < 0x80
    buf[0x600:0x600 + len(path)] = path
    buf[0x680:0x68B] = b"ProbeValue\0"
    if preload_dependency:
        assert dependency and lifecycle
        companion_path = f"companion_{'x64' if is_x64 else 'x86'}.dll".encode("utf-16le") + b"\0\0"
        buf[0x700:0x700 + len(companion_path)] = companion_path
    if guest_dependency:
        leaf_path = r"C:\Users\Alex\Downloads\guest-leaf.dll".encode("utf-16le") + b"\0\0"
        buf[0x700:0x700 + len(leaf_path)] = leaf_path
        buf[0x1000:0x1000 + len(leaf)] = leaf
    buf[0xA00:0x1000] = dll
    code, failures = bytearray(), []

    def call(index):
        rva = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    def fail_zero():
        code.extend(b"\x85\xc0\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x83\xec\x58")
        if preload_dependency:
            code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2300))
            call(3)
            fail_zero()
            code.extend(b"\x49\x89\xc4")  # r12 = companion HMODULE
        code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2200))
        code.extend(b"\xba\0\0\0\x40\x45\x31\xc0\x45\x31\xc9")
        for offset, value in ((0x20, 2), (0x28, 0x80), (0x30, 0)):
            code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
        call(0)
        code.extend(b"\x83\xf8\xff\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)
        code.extend(b"\x48\x89\xc3\x48\x89\xd9")
        code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x2600))
        code.extend(b"\x41\xb8" + struct.pack("<I", len(dll)))
        code.extend(b"\x49\xb9" + struct.pack("<Q", base + 0x2390))
        code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
        call(1)
        fail_zero()
        code.extend(b"\x48\x89\xd9")
        call(2)
        fail_zero()
        if guest_dependency:
            code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2300))
            code.extend(b"\xba\0\0\0\x40\x45\x31\xc0\x45\x31\xc9")
            for offset, value in ((0x20, 2), (0x28, 0x80), (0x30, 0)):
                code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
            call(0)
            code.extend(b"\x83\xf8\xff\x0f\x84\0\0\0\0")
            failures.append(len(code) - 4)
            code.extend(b"\x48\x89\xc3\x48\x89\xd9")
            code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x2C00))
            code.extend(b"\x41\xb8" + struct.pack("<I", len(leaf)))
            code.extend(b"\x49\xb9" + struct.pack("<Q", base + 0x2390))
            code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
            call(1)
            fail_zero()
            code.extend(b"\x48\x89\xd9")
            call(2)
            fail_zero()
        code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2200))
        call(3)
        if invalid:
            code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
            code.extend(b"\xb9\x01\0\0\0")
            call(5)
        elif fail_attach:
            code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
            code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2200))
            call(3)
            code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
            code.extend(b"\xb9\x2a\0\0\0")
            call(5)
        else:
            fail_zero()
            code.extend(b"\x48\x89\xc3" if lifecycle or release_dependency else b"\x48\x89\xc1")
            if lifecycle or release_dependency:
                code.extend(b"\x48\x89\xd9")
            code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x2280))
            call(4)
            fail_zero()
            code.extend(b"\xff\xd0")
            if lifecycle:
                code.extend(b"\x83\xf8\x2a\x0f\x85\0\0\0\0")
                failures.append(len(code) - 4)
                code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2200))
                call(3)
                code.extend(b"\x48\x39\xd8\x0f\x85\0\0\0\0")
                failures.append(len(code) - 4)
                for _ in range(2):
                    code.extend(b"\x48\x89\xd9")
                    call(6)
                    fail_zero()
                    code.extend(b"\x48\x89\xd9\x48\xba" + struct.pack("<Q", base + 0x2280))
                    call(4)
                    if _ == 0:
                        fail_zero()
                    else:
                        code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
                        failures.append(len(code) - 4)
                code.extend(b"\x48\x89\xd9")
                call(6)
                code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
                failures.append(len(code) - 4)
                code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x2200))
                call(3)
                fail_zero()
                code.extend(b"\x48\x89\xc3\x48\x89\xc1\x48\xba" + struct.pack("<Q", base + 0x2280))
                call(4)
                fail_zero()
                code.extend(b"\xff\xd0")
                if preload_dependency:
                    code.extend(b"\x83\xf8\x2a\x0f\x85\0\0\0\0")
                    failures.append(len(code) - 4)
                    code.extend(b"\x4c\x89\xe1")
                    call(6)
                    fail_zero()
                    code.extend(b"\x48\x89\xd9")
                    call(6)
                    fail_zero()
                    code.extend(b"\xb9\x2a\0\0\0")
                else:
                    code.extend(b"\x89\xc1")
            elif release_dependency:
                code.extend(b"\x41\x89\xc4\x48\x89\xd9")
                call(6)
                fail_zero()
                code.extend(b"\x44\x89\xe1")
            else:
                code.extend(b"\x89\xc1")
            call(5)
        failure = len(code)
        code.extend(b"\x31\xc9")
        call(5)
    else:
        def push(value):
            code.extend(b"\x68" + struct.pack("<I", value))
        if preload_dependency:
            push(base + 0x2300)
            call(3)
            fail_zero()
            code.extend(b"\x89\xc6")  # esi = companion HMODULE
        for value in (0, 0x80, 2, 0, 0, 0x40000000, base + 0x2200):
            push(value)
        call(0)
        code.extend(b"\x83\xf8\xff\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)
        code.extend(b"\x89\xc3")
        for value in (0, base + 0x2390, len(dll), base + 0x2600):
            push(value)
        code.extend(b"\x53")
        call(1)
        fail_zero()
        code.extend(b"\x53")
        call(2)
        fail_zero()
        if guest_dependency:
            for value in (0, 0x80, 2, 0, 0, 0x40000000, base + 0x2300):
                push(value)
            call(0)
            code.extend(b"\x83\xf8\xff\x0f\x84\0\0\0\0")
            failures.append(len(code) - 4)
            code.extend(b"\x89\xc3")
            for value in (0, base + 0x2390, len(leaf), base + 0x2C00):
                push(value)
            code.extend(b"\x53")
            call(1)
            fail_zero()
            code.extend(b"\x53")
            call(2)
            fail_zero()
        push(base + 0x2200)
        call(3)
        if invalid:
            code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
            code.extend(b"\x6a\x01")
            call(5)
        elif fail_attach:
            code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
            push(base + 0x2200)
            call(3)
            code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
            code.extend(b"\x6a\x2a")
            call(5)
        else:
            fail_zero()
            if lifecycle or release_dependency:
                code.extend(b"\x89\xc3")
            push(base + 0x2280)
            code.extend(b"\x50")
            call(4)
            fail_zero()
            code.extend(b"\xff\xd0")
            if lifecycle:
                code.extend(b"\x83\xf8\x2a\x0f\x85\0\0\0\0")
                failures.append(len(code) - 4)
                push(base + 0x2200)
                call(3)
                code.extend(b"\x39\xd8\x0f\x85\0\0\0\0")
                failures.append(len(code) - 4)
                for index in range(2):
                    code.extend(b"\x53")
                    call(6)
                    fail_zero()
                    push(base + 0x2280)
                    code.extend(b"\x53")
                    call(4)
                    if index == 0:
                        fail_zero()
                    else:
                        code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
                        failures.append(len(code) - 4)
                code.extend(b"\x53")
                call(6)
                code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
                failures.append(len(code) - 4)
                push(base + 0x2200)
                call(3)
                fail_zero()
                code.extend(b"\x89\xc3")
                push(base + 0x2280)
                code.extend(b"\x50")
                call(4)
                fail_zero()
                code.extend(b"\xff\xd0")
                if preload_dependency:
                    code.extend(b"\x83\xf8\x2a\x0f\x85\0\0\0\0")
                    failures.append(len(code) - 4)
                    code.extend(b"\x56")
                    call(6)
                    fail_zero()
                    code.extend(b"\x53")
                    call(6)
                    fail_zero()
                    code.extend(b"\x6a\x2a")
                else:
                    code.extend(b"\x50")
            elif release_dependency:
                code.extend(b"\x89\xc6\x53")
                call(6)
                fail_zero()
                code.extend(b"\x56")
            else:
                code.extend(b"\x50")
            call(5)
        failure = len(code)
        code.extend(b"\x6a\0")
        call(5)
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x200, len(code)
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_guest_module_budget(machine: int, *, same_basename: bool = False) -> bytes:
    """Copy one harmless DLL to 32 guest names; require the 33rd load to fail."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    dll = build_relocatable_companion(machine, base)
    buf = bytearray(build_dropped_dll(machine, reloc_mode="valid"))
    assert buf[0xA00:0x1000] == dll
    buf.extend(b"\0" * (0x2400 - len(buf)))
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", buf, section + 8, 0x2000)
    struct.pack_into("<I", buf, section + 16, 0x2000)
    struct.pack_into("<I", buf, 0x98 + 56, 0x4000)
    buf[0x560:0x588] = b"\0" * 0x28
    buf[0x560:0x56C] = b"\0\0CopyFileW\0"
    fmt, step = ("<Q", 8) if is_x64 else ("<I", 4)
    cursor = 0x1100
    for index in range(32):
        guest_path = (r"C:\Users\Alex\Documents\guest-stage.dll"
                      if same_basename and index == 0 else
                      rf"C:\Users\Alex\Downloads\budget-{index:02d}.dll")
        path = guest_path.encode("utf-16le") + b"\0\0"
        assert cursor + len(path) <= 0x2400
        struct.pack_into(fmt, buf, 0x1000 + index * step, base + 0x2000 + cursor - 0x400)
        buf[cursor:cursor + len(path)] = path
        cursor += len(path)
    if same_basename:
        basename = "guest-stage.dll".encode("utf-16le") + b"\0\0"
        buf[0x2100:0x2100 + len(basename)] = basename

    code = bytearray()
    labels: dict[str, int] = {}
    patches: list[tuple[int, str]] = []

    def mark(name: str) -> None:
        labels[name] = len(code)

    def branch(opcode: bytes, label: str) -> None:
        code.extend(opcode)
        patches.append((len(code), label))
        code.extend(b"\0" * 4)

    def call(index: int) -> None:
        rva = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    source = base + 0x2200
    if is_x64:
        code.extend(b"\x48\x83\xec\x58")  # Shadow space and seven CreateFileW arguments.
        code.extend(b"\x48\xb9" + struct.pack("<Q", source))
        code.extend(b"\xba\0\0\0\x40\x45\x31\xc0\x45\x31\xc9")
        for offset, value in ((0x20, 2), (0x28, 0x80), (0x30, 0)):
            code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
        call(0)
        code.extend(b"\x83\xf8\xff")
        branch(b"\x0f\x84", "fail")
        code.extend(b"\x48\x89\xc3\x48\x89\xd9")
        code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x2600))
        code.extend(b"\x41\xb8" + struct.pack("<I", len(dll)))
        code.extend(b"\x49\xb9" + struct.pack("<Q", base + 0x2390))
        code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
        call(1)
        code.extend(b"\x85\xc0")
        branch(b"\x0f\x84", "fail")
        code.extend(b"\x48\x89\xd9")
        call(2)
        code.extend(b"\x85\xc0")
        branch(b"\x0f\x84", "fail")
        code.extend(b"\x48\xb9" + struct.pack("<Q", source))
        call(3)
        code.extend(b"\x48\x85\xc0")
        branch(b"\x0f\x84", "fail")
        if same_basename:
            code.extend(b"\x49\x89\xc6")  # r14 = first loaded HMODULE.
        code.extend(b"\x49\xbc" + struct.pack("<Q", base + 0x2C00))
        code.extend(b"\x41\xbd\x20\0\0\0")
        mark("loop")
        code.extend(b"\x49\x8b\x14\x24")  # mov rdx, [r12]
        code.extend(b"\x48\xb9" + struct.pack("<Q", source))
        code.extend(b"\x45\x31\xc0")
        call(4)
        code.extend(b"\x85\xc0")
        branch(b"\x0f\x84", "fail")
        code.extend(b"\x49\x8b\x0c\x24")  # mov rcx, [r12]
        call(3)
        if same_basename:
            code.extend(b"\x41\x83\xfd\x20")  # first iteration only
            branch(b"\x0f\x85", "skip_basename")
            code.extend(b"\x4c\x39\xf0")  # full-path module differs.
            branch(b"\x0f\x84", "fail")
            code.extend(b"\x48\xb9" + struct.pack("<Q", base + 0x3D00))
            call(3)
            code.extend(b"\x4c\x39\xf0")  # bare name reuses first module.
            branch(b"\x0f\x85", "fail")
            mark("skip_basename")
        code.extend(b"\x41\xff\xcd")  # dec r13d
        branch(b"\x0f\x84", "last")
        code.extend(b"\x48\x85\xc0")
        branch(b"\x0f\x84", "fail")
        code.extend(b"\x49\x83\xc4\x08")
        branch(b"\xe9", "loop")
        mark("last")
        code.extend(b"\x48\x85\xc0")
        branch(b"\x0f\x85", "fail")
        code.extend(b"\xb9\x2a\0\0\0")
        call(5)
        mark("fail")
        code.extend(b"\x31\xc9")
        call(5)
    else:
        def push(value: int) -> None:
            code.extend(b"\x68" + struct.pack("<I", value))

        for value in (0, 0x80, 2, 0, 0, 0x40000000, source):
            push(value)
        call(0)
        code.extend(b"\x83\xf8\xff")
        branch(b"\x0f\x84", "fail")
        code.extend(b"\x89\xc3")
        for value in (0, base + 0x2390, len(dll), base + 0x2600):
            push(value)
        code.extend(b"\x53")
        call(1)
        code.extend(b"\x85\xc0")
        branch(b"\x0f\x84", "fail")
        code.extend(b"\x53")
        call(2)
        code.extend(b"\x85\xc0")
        branch(b"\x0f\x84", "fail")
        push(source)
        call(3)
        code.extend(b"\x85\xc0")
        branch(b"\x0f\x84", "fail")
        if same_basename:
            code.extend(b"\x89\xc5")  # ebp = first loaded HMODULE.
        code.extend(b"\xbe" + struct.pack("<I", base + 0x2C00))
        code.extend(b"\xbf\x20\0\0\0")
        mark("loop")
        code.extend(b"\x6a\0\xff\x36")  # push FALSE; push dword [esi]
        push(source)
        call(4)
        code.extend(b"\x85\xc0")
        branch(b"\x0f\x84", "fail")
        code.extend(b"\xff\x36")
        call(3)
        if same_basename:
            code.extend(b"\x83\xff\x20")  # first iteration only
            branch(b"\x0f\x85", "skip_basename")
            code.extend(b"\x39\xe8")  # full-path module differs.
            branch(b"\x0f\x84", "fail")
            push(base + 0x3D00)
            call(3)
            code.extend(b"\x39\xe8")  # bare name reuses first module.
            branch(b"\x0f\x85", "fail")
            mark("skip_basename")
        code.extend(b"\x4f")  # dec edi
        branch(b"\x0f\x84", "last")
        code.extend(b"\x85\xc0")
        branch(b"\x0f\x84", "fail")
        code.extend(b"\x83\xc6\x04")
        branch(b"\xe9", "loop")
        mark("last")
        code.extend(b"\x85\xc0")
        branch(b"\x0f\x85", "fail")
        push(42)
        call(5)
        mark("fail")
        code.extend(b"\x6a\0")
        call(5)
    for offset, label in patches:
        struct.pack_into("<i", code, offset, labels[label] - offset - 4)
    assert len(code) <= 0x200, len(code)
    buf[0x200:0x400] = b"\0" * 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_guest_same_basename(machine: int) -> bytes:
    """Load distinct full paths named guest-stage.dll in one process."""
    return build_guest_module_budget(machine, same_basename=True)


def build_thread_handles(machine: int) -> bytes:
    """Exercise guest thread rights, duplicate access, and independent closes."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * (0x800 - len(buf)))
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", buf, section + 8, 0x400)
    struct.pack_into("<I", buf, section + 16, 0x400)
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x21E0, 0x2070)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    names = (b"CreateThread", b"OpenThread", b"ResumeThread",
             b"DuplicateHandle", b"CloseHandle", b"ExitProcess")
    for index, name in enumerate(names):
        target = 0x20C0 + index * 0x28
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x470 + index * step, target)
        offset = 0x4C0 + index * 0x28
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5E0:0x5ED] = b"KERNEL32.dll\0"
    code, failures = bytearray(), []

    def call(index):
        rva = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    def check(nonzero: bool):
        code.extend(b"\x85\xc0\x0f" + (b"\x84" if nonzero else b"\x85") + b"\0\0\0\0")
        failures.append(len(code) - 4)

    def expect_failure():
        code.extend(b"\x83\xf8\xff\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x83\xec\x68")
        code.extend(b"\x31\xc9\x31\xd2")
        code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x11E0))
        code.extend(b"\x45\x31\xc9")
        code.extend(b"\x48\xc7\x44\x24\x20\x04\0\0\0")
        code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x2300))
        code.extend(b"\x48\x89\x44\x24\x28")
        call(0)
        check(True)
        code.extend(b"\x48\x89\xc3")
        code.extend(b"\xb9\x40\0\0\0\x31\xd2")
        code.extend(b"\x44\x8b\x05" + struct.pack("<i", 0x2300 - (0x1000 + len(code) + 7)))
        call(1)
        check(True)
        code.extend(b"\x48\x89\xc6\x48\x89\xd9")
        call(4)
        check(True)
        for reg in (b"\x48\x89\xd9", b"\x48\x89\xf1"):
            code.extend(reg)
            call(2)
            expect_failure()
        code.extend(b"\x48\xc7\xc1\xff\xff\xff\xff\x48\x89\xf2")
        code.extend(b"\x49\xc7\xc0\xff\xff\xff\xff")
        code.extend(b"\x49\xb9" + struct.pack("<Q", base + 0x2308))
        code.extend(b"\x48\xc7\x44\x24\x20\x02\0\0\0")
        code.extend(b"\x48\xc7\x44\x24\x28\0\0\0\0")
        code.extend(b"\x48\xc7\x44\x24\x30\0\0\0\0")
        call(3)
        check(True)
        code.extend(b"\x48\x89\xf1")
        call(4)
        check(True)
        code.extend(b"\x48\x89\xf1")
        call(2)
        expect_failure()
        code.extend(b"\x48\x8b\x0d" + struct.pack("<i", 0x2308 - (0x1000 + len(code) + 7)))
        code.extend(b"\x48\x89\xcf")
        call(2)
        code.extend(b"\x83\xf8\x01\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)
        code.extend(b"\x48\x89\xf9")
        call(4)
        check(True)
        code.extend(b"\xb9\x01\0\0\0")
        call(5)
        failure = len(code)
        code.extend(b"\x31\xc9")
        call(5)
    else:
        def push(value):
            code.extend(b"\x68" + struct.pack("<I", value))
        for value in (base + 0x2300, 4, 0, base + 0x11E0, 0, 0):
            push(value)
        call(0)
        check(True)
        code.extend(b"\x89\xc3")
        code.extend(b"\xff\x35" + struct.pack("<I", base + 0x2300))
        code.extend(b"\x6a\0\x6a\x40")
        call(1)
        check(True)
        code.extend(b"\x89\xc6\x53")
        call(4)
        check(True)
        for reg in (b"\x53", b"\x56"):
            code.extend(reg)
            call(2)
            expect_failure()
        for value in (0, 0, 2, base + 0x2308, 0xFFFFFFFF):
            push(value)
        code.extend(b"\x56")
        push(0xFFFFFFFF)
        call(3)
        check(True)
        code.extend(b"\x56")
        call(4)
        check(True)
        code.extend(b"\x56")
        call(2)
        expect_failure()
        code.extend(b"\x8b\x3d" + struct.pack("<I", base + 0x2308))
        code.extend(b"\x57")
        call(2)
        code.extend(b"\x83\xf8\x01\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)
        code.extend(b"\x57")
        call(4)
        check(True)
        code.extend(b"\x6a\x01")
        call(5)
        failure = len(code)
        code.extend(b"\x6a\0")
        call(5)
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x1E0, len(code)
    buf[0x200:0x200 + len(code)] = code
    buf[0x3E0:0x3E3] = b"\x31\xc0\xc3"
    return bytes(buf)


def build_thread_termination(machine: int) -> bytes:
    """Terminate a suspended thread before it can write a guest marker."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    names = (b"CreateThread", b"TerminateThread", b"GetExitCodeThread",
             b"ExitProcess")
    struct.pack_into("<IIIII", buf, 0x400, 0x2060, 0, 0, 0x21E0, 0x2040)
    for index, name in enumerate(names):
        target = 0x20C0 + index * 0x28
        struct.pack_into(fmt, buf, 0x440 + index * step, target)
        struct.pack_into(fmt, buf, 0x460 + index * step, target)
        offset = 0x4C0 + index * 0x28
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5E0:0x5ED] = b"KERNEL32.dll\0"
    code = bytearray()
    failures = []

    def call(index):
        rva = 0x2040 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    def check_equal(value):
        code.extend(b"\x83\xf8" + bytes([value]) + b"\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x83\xec\x38\x31\xc9\x31\xd2")
        code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x11E0))
        code.extend(b"\x45\x31\xc9")
        code.extend(b"\x48\xc7\x44\x24\x20\x04\0\0\0")
        code.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x2188) +
                    b"\x48\x89\x44\x24\x28")
        call(0)
        code.extend(b"\x48\x89\xc3\x48\x89\xd9\xba\x07\0\0\0")
        call(1)
        check_equal(1)
        code.extend(b"\x48\x89\xd9\x48\xba" + struct.pack("<Q", base + 0x218C))
        call(2)
        check_equal(1)
        code.extend(b"\x83\x3d" + struct.pack(
            "<i", 0x218C - (0x1000 + len(code) + 7)) + b"\x07")
        code.extend(b"\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)
        code.extend(b"\x83\x3d" + struct.pack(
            "<i", 0x2180 - (0x1000 + len(code) + 7)) + b"\x00")
        code.extend(b"\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)
        code.extend(b"\xb9\x01\0\0\0")
        call(3)
        failure = len(code)
        code.extend(b"\x31\xc9")
        call(3)
        thread_code = b"\xc7\x05" + struct.pack(
            "<i", 0x2180 - (0x11E0 + 10)) + b"\x01\0\0\0\xc3"
    else:
        for value in (base + 0x2188, 4, 0, base + 0x11E0, 0, 0):
            code.extend(b"\x68" + struct.pack("<I", value))
        call(0)
        code.extend(b"\x89\xc3\x6a\x07\x53")
        call(1)
        check_equal(1)
        code.extend(b"\x68" + struct.pack("<I", base + 0x218C) + b"\x53")
        call(2)
        check_equal(1)
        for address, value in ((base + 0x218C, 7), (base + 0x2180, 0)):
            code.extend(b"\x83\x3d" + struct.pack("<I", address) + bytes([value]))
            code.extend(b"\x0f\x85\0\0\0\0")
            failures.append(len(code) - 4)
        code.extend(b"\x6a\x01")
        call(3)
        failure = len(code)
        code.extend(b"\x6a\x00")
        call(3)
        thread_code = b"\xc7\x05" + struct.pack("<I", base + 0x2180) + b"\x01\0\0\0\xc2\x04\0"
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x1E0, len(code)
    buf[0x200:0x200 + len(code)] = code
    buf[0x3E0:0x3E0 + len(thread_code)] = thread_code
    return bytes(buf)


def build_thread_return_wait(machine: int) -> bytes:
    """Run a worker to completion, then query and zero-wait from another thread."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf[0x400:0x5E0] = b"\0" * 0x1E0
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    names = (b"CreateThread", b"ExitThread", b"GetExitCodeThread",
             b"WaitForSingleObject", b"ExitProcess")
    struct.pack_into("<IIIII", buf, 0x400, 0x2080, 0, 0, 0x21E0, 0x2040)
    for index, name in enumerate(names):
        target = 0x20C0 + index * 0x28
        struct.pack_into(fmt, buf, 0x440 + index * step, target)
        struct.pack_into(fmt, buf, 0x480 + index * step, target)
        offset = 0x4C0 + index * 0x28
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5E0:0x5ED] = b"KERNEL32.dll\0"

    def call(code: bytearray, index: int, start: int) -> None:
        rva = 0x2040 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack(
                "<i", rva - (start + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    entry = bytearray()
    if is_x64:
        entry.extend(b"\x48\x83\xec\x38")
        for target in (0x1180, 0x1190):
            entry.extend(b"\x31\xc9\x31\xd2\x49\xb8" +
                         struct.pack("<Q", base + target) + b"\x45\x31\xc9")
            entry.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0" +
                         b"\x48\xc7\x44\x24\x28\0\0\0\0")
            call(entry, 0, 0x1000)
            if target == 0x1180:
                entry.extend(b"\x48\xbb" + struct.pack("<Q", base + 0x21A0) +
                             b"\x48\x89\x03")
        entry.extend(b"\x31\xc9")
        call(entry, 1, 0x1000)
        worker = b"\xb8\x2a\0\0\0\xc3"
    else:
        for target in (0x1180, 0x1190):
            for value in (0, 0, 0, base + target, 0, 0):
                entry.extend(b"\x68" + struct.pack("<I", value))
            call(entry, 0, 0x1000)
            if target == 0x1180:
                entry.extend(b"\xa3" + struct.pack("<I", base + 0x21A0))
        entry.extend(b"\x6a\0")
        call(entry, 1, 0x1000)
        worker = b"\xb8\x2a\0\0\0\xc2\x04\0"
    assert len(entry) < 0x180, len(entry)
    buf[0x200:0x200 + len(entry)] = entry
    buf[0x380:0x380 + len(worker)] = worker

    observer = bytearray()
    failures = []
    if is_x64:
        observer.extend(b"\x48\x83\xec\x28")
        observer.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x21A0) +
                        b"\x48\x8b\x08\x31\xd2")
        call(observer, 3, 0x1190)
        observer.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
        failures.append(len(observer) - 4)
        observer.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x21A0) +
                        b"\x48\x8b\x08\x48\xba" + struct.pack("<Q", base + 0x21A8))
        call(observer, 2, 0x1190)
        observer.extend(b"\x85\xc0\x0f\x84\0\0\0\0")
        failures.append(len(observer) - 4)
        observer.extend(b"\x48\xb8" + struct.pack("<Q", base + 0x21A8) +
                        b"\x83\x38\x2a\x0f\x85\0\0\0\0")
        failures.append(len(observer) - 4)
        observer.extend(b"\xb9\x01\0\0\0")
        call(observer, 4, 0x1190)
        failed = len(observer)
        observer.extend(b"\x31\xc9")
        call(observer, 4, 0x1190)
    else:
        observer.extend(b"\x6a\0\xff\x35" + struct.pack("<I", base + 0x21A0))
        call(observer, 3, 0x1190)
        observer.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
        failures.append(len(observer) - 4)
        observer.extend(b"\x68" + struct.pack("<I", base + 0x21A8) +
                        b"\xff\x35" + struct.pack("<I", base + 0x21A0))
        call(observer, 2, 0x1190)
        observer.extend(b"\x85\xc0\x0f\x84\0\0\0\0")
        failures.append(len(observer) - 4)
        observer.extend(b"\x83\x3d" + struct.pack("<I", base + 0x21A8) +
                        b"\x2a\x0f\x85\0\0\0\0")
        failures.append(len(observer) - 4)
        observer.extend(b"\x6a\x01")
        call(observer, 4, 0x1190)
        failed = len(observer)
        observer.extend(b"\x6a\0")
        call(observer, 4, 0x1190)
    for offset in failures:
        struct.pack_into("<i", observer, offset, failed - offset - 4)
    assert len(observer) < 0x70, len(observer)
    buf[0x390:0x390 + len(observer)] = observer
    return bytes(buf)


def build_process_access(machine: int) -> bytes:
    """Exercise distinct guest OpenProcess rights and independent handle closure."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x21E0, 0x2070)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    names = (b"GetCurrentProcessId", b"OpenProcess", b"VirtualAllocEx",
             b"WriteProcessMemory", b"ReadProcessMemory", b"CloseHandle", b"ExitProcess")
    for index, name in enumerate(names):
        target = 0x20C0 + index * 0x28
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x470 + index * step, target)
        offset = 0x4C0 + index * 0x28
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5E0:0x5ED] = b"KERNEL32.dll\0"
    code, failures = bytearray(), []

    def call(index):
        rva = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    def branch_if(condition):
        code.extend(b"\x85\xc0\x0f" + (b"\x85" if condition else b"\x84") + b"\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x83\xec\x58")
        call(0)
        code.extend(b"\x89\xc3")
        for access, reg in ((0x10, b"\x48\x89\xc6"), (0x08, b"\x48\x89\xc7")):
            code.extend(b"\xb9" + struct.pack("<I", access))
            code.extend(b"\x31\xd2\x41\x89\xd8")
            call(1)
            branch_if(False)
            code.extend(reg)
        code.extend(b"\x48\x39\xfe\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)
        code.extend(b"\x48\x89\xf1")
        code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x1000))
        code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x1000))
        code.extend(b"\x41\xb9\x04\0\0\0\x48\xc7\x44\x24\x20\0\0\0\0")
        call(3)
        branch_if(True)

        def alloc(reg: bytes, should_succeed: bool):
            code.extend(reg)
            code.extend(b"\x31\xd2\x41\xb8\0\x10\0\0\x41\xb9\0\x30\0\0")
            code.extend(b"\x48\xc7\x44\x24\x20\x04\0\0\0")
            call(2)
            branch_if(not should_succeed)

        alloc(b"\x48\x89\xf1", False)
        code.extend(b"\x48\x89\xf9")
        code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x1000))
        code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x1000))
        code.extend(b"\x41\xb9\x04\0\0\0\x48\xc7\x44\x24\x20\0\0\0\0")
        call(4)
        branch_if(True)
        code.extend(b"\x48\x89\xf1")
        call(5)
        branch_if(False)
        alloc(b"\x48\x89\xf1", False)
        alloc(b"\x48\x89\xf9", True)
        code.extend(b"\x48\x89\xf9")
        call(5)
        branch_if(False)
        code.extend(b"\xb9\x01\0\0\0")
    else:
        def push(value):
            code.extend(b"\x68" + struct.pack("<I", value))

        call(0)
        code.extend(b"\x89\xc3")
        for access, reg in ((0x10, b"\x89\xc6"), (0x08, b"\x89\xc7")):
            code.extend(b"\x53\x6a\0")
            push(access)
            call(1)
            branch_if(False)
            code.extend(reg)
        code.extend(b"\x39\xfe\x0f\x84\0\0\0\0")
        failures.append(len(code) - 4)
        for value in (0, 4, base + 0x1000, base + 0x1000):
            push(value)
        code.extend(b"\x56")
        call(3)
        branch_if(True)

        def alloc(reg: bytes, should_succeed: bool):
            for value in (4, 0x3000, 0x1000, 0):
                push(value)
            code.extend(reg)
            call(2)
            branch_if(not should_succeed)

        alloc(b"\x56", False)
        for value in (0, 4, base + 0x1000, base + 0x1000):
            push(value)
        code.extend(b"\x57")
        call(4)
        branch_if(True)
        code.extend(b"\x56")
        call(5)
        branch_if(False)
        alloc(b"\x56", False)
        alloc(b"\x57", True)
        code.extend(b"\x57")
        call(5)
        branch_if(False)
        code.extend(b"\x6a\x01")
    call(6)
    failure = len(code)
    code.extend(b"\x31\xc9" if is_x64 else b"\x6a\0")
    call(6)
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


def build_process_duplicate(machine: int, *, rights_probe: bool = False) -> bytes:
    """Duplicate a read-only guest handle, then read after closing its source."""
    is_x64 = machine == 0x8664
    base = 0x140000000 if is_x64 else 0x400000
    buf = bytearray(build(machine))
    buf.extend(b"\0" * (0x800 - len(buf)))
    section = 0x98 + (0xF0 if is_x64 else 0xE0) + 40
    struct.pack_into("<I", buf, section + 8, 0x400)
    struct.pack_into("<I", buf, section + 16, 0x400)
    struct.pack_into("<IIIII", buf, 0x400, 0x2030, 0, 0, 0x21E0, 0x2070)
    step, fmt = (8, "<Q") if is_x64 else (4, "<I")
    names = (b"GetCurrentProcessId", b"OpenProcess", b"DuplicateHandle",
             b"ReadProcessMemory", b"CloseHandle", b"ExitProcess",
             b"WriteProcessMemory")
    for index, name in enumerate(names):
        target = 0x20C0 + index * 0x28
        struct.pack_into(fmt, buf, 0x430 + index * step, target)
        struct.pack_into(fmt, buf, 0x470 + index * step, target)
        offset = 0x4C0 + index * 0x28
        buf[offset:offset + len(name) + 3] = b"\0\0" + name + b"\0"
    buf[0x5E0:0x5ED] = b"KERNEL32.dll\0"
    code, failures = bytearray(), []

    def call(index):
        rva = 0x2070 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", rva - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + rva))

    def check(nonzero: bool):
        code.extend(b"\x85\xc0\x0f" + (b"\x84" if nonzero else b"\x85") + b"\0\0\0\0")
        failures.append(len(code) - 4)

    if is_x64:
        code.extend(b"\x48\x83\xec\x58")
        call(0)
        code.extend(b"\x41\x89\xc0\xb9\x10\0\0\0\x31\xd2")
        call(1)
        check(True)
        code.extend(b"\x48\x89\xc3")
        if rights_probe:
            for source_is_real in (True, False):
                code.extend(b"\x48\x89\xd9" if source_is_real else
                            b"\x48\xc7\xc1\xff\xff\xff\xff")
                code.extend(b"\x48\x89\xda")
                code.extend(b"\x49\xc7\xc0\xff\xff\xff\xff" if source_is_real else
                            b"\x49\x89\xd8")
                code.extend(b"\x49\xb9" + struct.pack("<Q", base + 0x2300))
                for offset, value in ((0x20, 0), (0x28, 0), (0x30, 2)):
                    code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
                call(2)
                check(False)
        for requested, options in ((0x38, 0), (0, 2)):
            code.extend(b"\x48\xc7\xc1\xff\xff\xff\xff\x48\x89\xda")
            code.extend(b"\x49\xc7\xc0\xff\xff\xff\xff")
            code.extend(b"\x49\xb9" + struct.pack("<Q", base + 0x2300))
            for offset, value in ((0x20, requested), (0x28, 0), (0x30, options)):
                code.extend(b"\x48\xc7\x44\x24" + bytes([offset]) + struct.pack("<I", value))
            call(2)
            check(True)
            displacement = 0x2300 - (0x1000 + len(code) + 7)
            code.extend((b"\x48\x8b\x3d" if options == 0 else b"\x48\x8b\x35") +
                        struct.pack("<i", displacement))
        code.extend(b"\x48\x89\xd9")
        call(4)
        check(True)
        code.extend(b"\x48\x89\xf9")
        code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x2320))
        code.extend(b"\x49\xb8" + struct.pack("<Q", base))
        code.extend(b"\x41\xb9\x02\0\0\0\x48\xc7\x44\x24\x20\0\0\0\0")
        call(6)
        check(True)
        code.extend(b"\x48\x89\xf1")
        code.extend(b"\x48\xba" + struct.pack("<Q", base + 0x2320))
        code.extend(b"\x49\xb8" + struct.pack("<Q", base + 0x2310))
        code.extend(b"\x41\xb9\x02\0\0\0\x48\xc7\x44\x24\x20\0\0\0\0")
        call(3)
        check(True)
        displacement = 0x2310 - (0x1000 + len(code) + 9)
        code.extend(b"\x66\x81\x3d" + struct.pack("<i", displacement) + b"\x4d\x5a")
        code.extend(b"\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)
        code.extend(b"\x48\x89\xf9")
        call(4)
        check(True)
        code.extend(b"\x48\x89\xf1")
        call(4)
        check(True)
        code.extend(b"\xb9\x01\0\0\0")
    else:
        def push(value):
            code.extend(b"\x68" + struct.pack("<I", value))
        call(0)
        code.extend(b"\x50\x6a\0")
        push(0x10)
        call(1)
        check(True)
        code.extend(b"\x89\xc3")
        if rights_probe:
            for source_is_real in (True, False):
                for value in (2, 0, 0, base + 0x2300):
                    push(value)
                code.extend(b"\x68\xff\xff\xff\xff" if source_is_real else b"\x53")
                code.extend(b"\x53")
                code.extend(b"\x53" if source_is_real else b"\x68\xff\xff\xff\xff")
                call(2)
                check(False)
        for requested, options in ((0x38, 0), (0, 2)):
            for value in (options, 0, requested, base + 0x2300, 0xFFFFFFFF):
                push(value)
            code.extend(b"\x53")
            push(0xFFFFFFFF)
            call(2)
            check(True)
            code.extend((b"\x8b\x3d" if options == 0 else b"\x8b\x35") +
                        struct.pack("<I", base + 0x2300))
        code.extend(b"\x53")
        call(4)
        check(True)
        for value in (0, 2, base, base + 0x2320):
            push(value)
        code.extend(b"\x57")
        call(6)
        check(True)
        for value in (0, 2, base + 0x2310, base + 0x2320):
            push(value)
        code.extend(b"\x56")
        call(3)
        check(True)
        code.extend(b"\x66\x81\x3d" + struct.pack("<I", base + 0x2310) + b"\x4d\x5a")
        code.extend(b"\x0f\x85\0\0\0\0")
        failures.append(len(code) - 4)
        code.extend(b"\x57")
        call(4)
        check(True)
        code.extend(b"\x56")
        call(4)
        check(True)
        code.extend(b"\x6a\x01")
    call(5)
    failure = len(code)
    code.extend(b"\x31\xc9" if is_x64 else b"\x6a\0")
    call(5)
    for offset in failures:
        struct.pack_into("<i", code, offset, failure - offset - 4)
    assert len(code) < 0x200
    buf[0x200:0x200 + len(code)] = code
    return bytes(buf)


if __name__ == "__main__":
    out = Path(__file__).parent
    (out / "native_x86.exe").write_bytes(build(0x14C))
    (out / "native_x64.exe").write_bytes(build(0x8664))
    (out / "crt_initializer_x86.exe").write_bytes(build_crt_initializer(0x14C))
    (out / "crt_initializer_x64.exe").write_bytes(build_crt_initializer(0x8664))
    (out / "crt_wide_args_x86.exe").write_bytes(build_crt_wide_args(0x14C))
    (out / "crt_wide_args_x64.exe").write_bytes(build_crt_wide_args(0x8664))
    (out / "crt_narrow_args_x86.exe").write_bytes(build_crt_args(0x14C, wide=False))
    (out / "crt_narrow_args_x64.exe").write_bytes(build_crt_args(0x8664, wide=False))
    for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
        for wide, suffix in ((False, "a"), (True, "w")):
            (out / f"environment_block_{suffix}_{arch}.exe").write_bytes(
                build_environment_block_probe(machine, wide=wide))
        (out / f"acrt_stream_{arch}.exe").write_bytes(build_acrt_stream_probe(machine))
    (out / "crt_error_initializer_x86.exe").write_bytes(build_crt_error_initializer(0x14C))
    (out / "crt_error_initializer_x64.exe").write_bytes(build_crt_error_initializer(0x8664))
    (out / "companion_x86.dll").write_bytes(build(0x14C, dll=True))
    (out / "companion_x64.dll").write_bytes(build(0x8664, dll=True))
    (out / "ldr_companion_x86.exe").write_bytes(build_ldr_companion(0x14C))
    (out / "ldr_companion_x64.exe").write_bytes(build_ldr_companion(0x8664))
    (out / "local_virtualprotect_x86.exe").write_bytes(
        build_local_virtualprotect_probe(0x14C))
    (out / "local_virtualprotect_x64.exe").write_bytes(
        build_local_virtualprotect_probe(0x8664))
    for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
        preferred = 0x140000000 if arch == "x64" else 0x400000
        relocatable = build_relocatable_companion(machine, preferred)
        folder = out / "reloc_dynamic"
        folder.mkdir(exist_ok=True)
        (folder / f"companion_{arch}.dll").write_bytes(relocatable)
        stripped = bytearray(relocatable)
        directory = 0x98 + (112 if arch == "x64" else 96) + 5 * 8
        stripped[directory:directory + 8] = b"\0" * 8
        folder = out / "no_reloc_dynamic"
        folder.mkdir(exist_ok=True)
        (folder / f"companion_{arch}.dll").write_bytes(stripped)
        malformed = bytearray(relocatable)
        struct.pack_into("<I", malformed, 0x5B4, 0)  # Invalid block size.
        folder = out / "bad_reloc_dynamic"
        folder.mkdir(exist_ok=True)
        (folder / f"companion_{arch}.dll").write_bytes(malformed)
    (out / "drop_x86.exe").write_bytes(build_drop_x86())
    (out / "signature_stub_x86.exe").write_bytes(build_signature_stub_x86())
    (out / "move_file_x86.exe").write_bytes(build_move_file(0x14C))
    (out / "move_file_x64.exe").write_bytes(build_move_file(0x8664))
    (out / "move_file_a_x86.exe").write_bytes(build_move_file(0x14C, wide=False))
    (out / "move_file_a_x64.exe").write_bytes(build_move_file(0x8664, wide=False))
    (out / "copy_file_x86.exe").write_bytes(build_move_file(0x14C, copy=True))
    (out / "copy_file_x64.exe").write_bytes(build_move_file(0x8664, copy=True))
    (out / "copy_file_a_x86.exe").write_bytes(build_move_file(0x14C, wide=False, copy=True))
    (out / "copy_file_a_x64.exe").write_bytes(build_move_file(0x8664, wide=False, copy=True))
    (out / "delete_file_x86.exe").write_bytes(build_move_file(0x14C, delete=True))
    (out / "delete_file_x64.exe").write_bytes(build_move_file(0x8664, delete=True))
    (out / "delete_file_a_x86.exe").write_bytes(build_move_file(0x14C, wide=False, delete=True))
    (out / "delete_file_a_x64.exe").write_bytes(build_move_file(0x8664, wide=False, delete=True))
    for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
        for suffix, wide in (("", True), ("_a", False)):
            for operation, deleting in (("move", False), ("delete", True)):
                for sharing, share_delete in (("locked", False), ("shared", True)):
                    (out / f"{operation}_open_{sharing}{suffix}_{arch}.exe").write_bytes(
                        build_move_file(machine, wide=wide, delete=deleting,
                                        while_open=True, share_delete=share_delete))
            for sharing, source_share, target_share in (("locked", 0, 1), ("shared", 1, 2)):
                (out / f"copy_source_open_{sharing}{suffix}_{arch}.exe").write_bytes(
                    build_move_file(machine, wide=wide, copy=True, while_open=True,
                                    open_share=source_share))
                (out / f"copy_target_open_{sharing}{suffix}_{arch}.exe").write_bytes(
                    build_move_file(machine, wide=wide, copy=True, target_open=True,
                                    open_share=target_share))
    for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
        for suffix, wide in (("", True), ("_a", False)):
            (out / f"directory{suffix}_{arch}.exe").write_bytes(
                build_directory_lifecycle(machine, wide=wide))
            (out / f"open_always{suffix}_{arch}.exe").write_bytes(
                build_open_always_lifecycle(machine, wide=wide))
            (out / f"reopen_overwrite{suffix}_{arch}.exe").write_bytes(
                build_reopen_overwrite(machine, wide=wide))
            (out / f"append_only{suffix}_{arch}.exe").write_bytes(
                build_reopen_overwrite(machine, wide=wide, append=True))
            (out / f"delete_on_close{suffix}_{arch}.exe").write_bytes(
                build_reopen_overwrite(machine, wide=wide, delete_on_close=True))
            if wide:
                (out / f"delete_on_exit_{arch}.exe").write_bytes(
                    build_reopen_overwrite(machine, delete_on_close=True,
                                           leave_delete_handle_open=True))
                (out / f"delete_on_create_{arch}.exe").write_bytes(
                    build_reopen_overwrite(machine, delete_on_create=True))
                (out / f"file_disposition_{arch}.exe").write_bytes(
                    build_reopen_overwrite(machine, file_disposition=True))
                (out / f"file_disposition_cancel_{arch}.exe").write_bytes(
                    build_reopen_overwrite(machine, file_disposition=True,
                                           file_disposition_cancel=True))
                (out / f"file_disposition_exit_{arch}.exe").write_bytes(
                    build_reopen_overwrite(machine, file_disposition=True,
                                           file_disposition_leave_open=True))
            (out / f"truncate_existing{suffix}_{arch}.exe").write_bytes(
                build_reopen_overwrite(machine, wide=wide, truncate=True))
            (out / f"sharing{suffix}_{arch}.exe").write_bytes(
                build_sharing_probe(machine, wide=wide))
            (out / f"set_end_of_file{suffix}_{arch}.exe").write_bytes(
                build_set_end_of_file(machine, wide=wide))
            (out / f"file_end_info{suffix}_{arch}.exe").write_bytes(
                build_set_end_of_file(machine, wide=wide, by_handle_info=True))
            (out / f"file_rename_info{suffix}_{arch}.exe").write_bytes(
                build_set_end_of_file(machine, wide=wide, by_handle_rename=True))
            (out / f"file_attributes{suffix}_{arch}.exe").write_bytes(
                build_file_attributes(machine, wide=wide))
            (out / f"file_basic_info{suffix}_{arch}.exe").write_bytes(
                build_file_attributes(machine, wide=wide, by_handle=True))
            (out / f"attributes_ex{suffix}_{arch}.exe").write_bytes(
                build_attributes_ex(machine, wide=wide))
            (out / f"registry{suffix}_{arch}.exe").write_bytes(
                build_registry_roundtrip(machine, wide=wide))
            (out / f"registry_key{suffix}_{arch}.exe").write_bytes(
                build_registry_key_lifecycle(machine, wide=wide))
            if wide:
                (out / f"registry_key_ex_{arch}.exe").write_bytes(
                    build_registry_key_lifecycle(machine, create_ex=True))
            if wide:
                (out / f"registry_key_exit_{arch}.exe").write_bytes(
                    build_registry_key_lifecycle(machine, leave_open=True))
        (out / f"mapped_file_{arch}.exe").write_bytes(build_mapped_file(machine))
        (out / f"mapped_file_live_{arch}.exe").write_bytes(
            build_mapped_file(machine, unmap=False))
        (out / f"mapped_file_coherent_{arch}.exe").write_bytes(
            build_mapped_file(machine, unmap=False, coherent=True))
        (out / f"mapped_file_io_coherent_{arch}.exe").write_bytes(
            build_mapped_file(machine, unmap=False, coherent=True, file_io=True))
        (out / f"duplicate_guest_file_{arch}.exe").write_bytes(
            build_duplicate_guest_file(machine))
        (out / f"named_pagefile_mapping_{arch}.exe").write_bytes(
            build_named_pagefile_mapping(machine))
        (out / f"named_pagefile_coherent_{arch}.exe").write_bytes(
            build_named_pagefile_mapping(machine, coherent=True))
        (out / f"named_pagefile_remap_{arch}.exe").write_bytes(
            build_named_pagefile_mapping(machine, remap=True))
        (out / f"named_pagefile_duplicate_{arch}.exe").write_bytes(
            build_named_pagefile_mapping(machine, duplicate=True))
        (out / f"process_memory_write_{arch}.exe").write_bytes(
            build_process_memory_write(machine))
        (out / f"virtual_free_ex_{arch}.exe").write_bytes(build_virtual_free_ex(machine))
        (out / f"virtual_free_ex_direct_read_{arch}.exe").write_bytes(
            build_virtual_free_ex(machine, direct_read_after_release=True))
        (out / f"transient_free_stage_{arch}.exe").write_bytes(
            build_virtual_free_ex(machine, copy_pe_before_release=True))
        (out / f"child_process_{arch}.exe").write_bytes(build_child_process(machine))
        (out / f"child_suspended_{arch}.exe").write_bytes(
            build_child_process(machine, suspended=True))
        (out / f"child_resumed_{arch}.exe").write_bytes(
            build_child_process(machine, suspended=True, resume=True))
        (out / f"child_memory_read_{arch}.exe").write_bytes(
            build_child_process(machine, read_back=True))
        (out / f"child_remote_thread_{arch}.exe").write_bytes(
            build_child_process(machine, inject_thread=True))
        (out / f"child_remote_thread_suspended_{arch}.exe").write_bytes(
            build_child_process(machine, inject_thread=True, remote_suspended=True))
        (out / f"child_remote_thread_resumed_{arch}.exe").write_bytes(
            build_child_process(machine, inject_thread=True, remote_suspended=True,
                                remote_resume=True))
        (out / f"child_cross_owner_write_{arch}.exe").write_bytes(
            build_child_process(machine, wrong_owner_write=True))
        (out / f"child_cross_owner_alloc_{arch}.exe").write_bytes(
            build_child_process(machine, wrong_owner_allocation=True))
        (out / f"child_cross_owner_protect_{arch}.exe").write_bytes(
            build_child_process(machine, protect_probe=True))
        for access in ("read", "write", "write_rep", "execute"):
            (out / f"child_direct_{access}_{arch}.exe").write_bytes(
                build_child_process(machine, cpu_cross_owner_access=access))
        for access in ("read", "write", "execute"):
            (out / f"child_parent_image_{access}_{arch}.exe").write_bytes(
                build_child_process(machine, parent_image_access=access))
        (out / f"child_api_copy_{arch}.exe").write_bytes(
            build_child_process(machine, api_cross_owner_copy=True))
        (out / f"child_api_string_{arch}.exe").write_bytes(
            build_child_process(machine, api_cross_owner_string=True))
        (out / f"local_api_string_{arch}.exe").write_bytes(
            build_child_process(machine, api_local_string_copy=True))
        (out / f"child_api_env_{arch}.exe").write_bytes(
            build_child_process(machine, api_cross_owner_env=True))
        (out / f"local_api_env_{arch}.exe").write_bytes(
            build_child_process(machine, api_local_env=True))
        (out / f"private_api_map_child_read_{arch}.exe").write_bytes(
            build_child_process(machine, api_private_map="child_read"))
        (out / f"private_api_map_local_read_{arch}.exe").write_bytes(
            build_child_process(machine, api_private_map="local_read"))
        (out / f"private_api_map_foreign_write_{arch}.exe").write_bytes(
            build_child_process(machine, api_private_map="foreign_write"))
        (out / f"child_peb_read_{arch}.exe").write_bytes(
            build_child_process(machine, child_peb_read="own"))
        (out / f"child_parameters_read_{arch}.exe").write_bytes(
            build_child_process(machine, child_peb_read="own_parameters"))
        (out / f"child_ldr_read_{arch}.exe").write_bytes(
            build_child_process(machine, child_peb_read="own_ldr"))
        (out / f"child_parent_peb_read_{arch}.exe").write_bytes(
            build_child_process(machine, child_peb_read="parent"))
        (out / f"child_parent_ldr_read_{arch}.exe").write_bytes(
            build_child_process(machine, child_peb_read="parent_ldr"))
        (out / f"child_stack_read_{arch}.exe").write_bytes(
            build_child_process(machine, child_stack_read="own"))
        (out / f"child_parent_stack_read_{arch}.exe").write_bytes(
            build_child_process(machine, child_stack_read="parent"))
        (out / f"child_teb_leak_{arch}.exe").write_bytes(
            build_child_process(machine, child_teb_read=True))
        (out / f"child_parent_module_lookup_{arch}.exe").write_bytes(
            build_child_parent_module_lookup(machine))
        for access in ("read", "write", "execute"):
            (out / f"child_parent_dll_cpu_{access}_{arch}.exe").write_bytes(
                build_child_parent_module_lookup(machine, direct_parent_cpu=access))
            (out / f"child_parent_dynamic_dll_cpu_{access}_{arch}.exe").write_bytes(
                build_child_parent_module_lookup(
                    machine, direct_parent_cpu=access, dynamic_parent_dll=True))
            (out / f"child_parent_guest_dll_cpu_{access}_{arch}.exe").write_bytes(
                build_child_parent_module_lookup(
                    machine, direct_parent_cpu=access, guest_parent_dll=True))
        (out / f"child_parent_guest_dll_api_copy_{arch}.exe").write_bytes(
            build_child_parent_module_lookup(machine, guest_parent_dll=True,
                                             api_parent_copy=True))
        (out / f"child_parent_guest_dll_api_write_{arch}.exe").write_bytes(
            build_child_parent_module_lookup(machine, guest_parent_dll=True,
                                             api_parent_write=True))
        (out / f"child_parent_module_handle_{arch}.exe").write_bytes(
            build_child_parent_module_lookup(machine, query_only=True))
        (out / f"child_parent_module_handle_ex_{arch}.exe").write_bytes(
            build_child_parent_module_lookup(machine, ex_query=True))
        (out / f"child_parent_module_free_{arch}.exe").write_bytes(
            build_child_parent_module_lookup(machine, foreign_free=True))
        (out / f"child_parent_module_proc_{arch}.exe").write_bytes(
            build_child_parent_module_lookup(machine, foreign_proc=True))
        (out / f"child_parent_module_filename_{arch}.exe").write_bytes(
            build_child_parent_module_lookup(machine, foreign_filename=True))
        (out / f"child_parent_module_peb_{arch}.exe").write_bytes(
            build_child_parent_module_lookup(machine, peb_scan=True))
        for kind in ("name", "path", "self"):
            (out / f"child_parent_module_psapi_{kind}_{arch}.exe").write_bytes(
                build_child_parent_module_lookup(
                    machine, **{f"psapi_{kind}": True}))
        (out / f"child_parent_module_psapi_enum_{arch}.exe").write_bytes(
            build_child_parent_module_lookup(machine, psapi_enum=True))
        for kind, path in (("name_valid", False), ("path_valid", True)):
            (out / f"child_parent_module_psapi_{kind}_{arch}.exe").write_bytes(
                build_child_parent_psapi_valid_handle(machine, path=path))
        for target in ("self", "parent"):
            (out / f"child_parent_module_toolhelp_{target}_{arch}.exe").write_bytes(
                build_child_parent_toolhelp(machine, parent=target == "parent"))
        (out / f"child_parent_module_toolhelp_next_{arch}.exe").write_bytes(
            build_child_parent_toolhelp(machine, next_entry=True))
        (out / f"child_parent_module_toolhelp_foreign_{arch}.exe").write_bytes(
            build_child_foreign_snapshot_handle(machine))
        (out / f"child_parent_process_handle_foreign_{arch}.exe").write_bytes(
            build_child_foreign_process_handle(machine))
        (out / f"process_exit_status_{arch}.exe").write_bytes(
            build_process_exit_status(machine))
        (out / f"remote_debug_check_{arch}.exe").write_bytes(
            build_remote_debug_check(machine))
        (out / f"is_debugger_present_{arch}.exe").write_bytes(
            build_is_debugger_present(machine))
        for information_class, label in ((7, "port"), (30, "object"), (31, "flags")):
            (out / f"nt_debug_{label}_{arch}.exe").write_bytes(
                build_nt_debug_query(machine, information_class))
        (out / f"peb_debug_check_{arch}.exe").write_bytes(
            build_peb_debug_check(machine))
        (out / f"qpc_progress_{arch}.exe").write_bytes(
            build_qpc_progress(machine))
        (out / f"shared_time_check_{arch}.exe").write_bytes(
            build_shared_time_check(machine))
        (out / f"cpuid_identity_check_{arch}.exe").write_bytes(
            build_cpuid_identity_check(machine))
        (out / f"processor_feature_check_{arch}.exe").write_bytes(
            build_processor_feature_check(machine))
        (out / f"nt_version_consistency_check_{arch}.exe").write_bytes(
            build_nt_version_consistency_check(machine))
        for compatibility in ("none", "win81", "win10"):
            (out / f"version_compat_{compatibility}_{arch}.exe").write_bytes(
                build_version_compat_check(machine, compatibility))
            (out / f"version_verify_{compatibility}_{arch}.exe").write_bytes(
                build_version_verify_check(machine, compatibility))
        (out / f"avx_fallback_check_{arch}.exe").write_bytes(
            build_avx_fallback_check(machine))
        (out / f"console_output_{arch}.exe").write_bytes(
            build_console_output(machine))
        (out / f"tsc_sleep_check_{arch}.exe").write_bytes(
            build_tsc_sleep_check(machine))
        (out / f"memory_persona_check_{arch}.exe").write_bytes(
            build_memory_persona_check(machine))
        (out / f"child_parent_process_terminate_foreign_{arch}.exe").write_bytes(
            build_child_foreign_terminate_process(machine))
        (out / f"child_parent_thread_terminate_foreign_{arch}.exe").write_bytes(
            build_child_foreign_terminate_thread(machine))
        for opened in (False, True):
            for created in (False, True):
                (out / f"child_parent_file_handle_inherit_{int(opened)}{int(created)}_{arch}.exe").write_bytes(
                    build_child_foreign_file_handle(
                        machine, open_inheritable=opened, create_inherit=created))
        (out / f"child_parent_file_handle_inherit_closed_{arch}.exe").write_bytes(
            build_child_foreign_file_handle(
                machine, open_inheritable=True, create_inherit=True,
                close_parent=True))
        (out / f"child_parent_file_handle_duplicate_{arch}.exe").write_bytes(
            build_child_foreign_file_handle(machine, duplicate_to_child=True))
        for mapped in (False, True):
            for created in (False, True):
                (out / f"child_parent_mapping_handle_inherit_{int(mapped)}{int(created)}_{arch}.exe").write_bytes(
                    build_child_foreign_mapping_handle(
                        machine, map_inheritable=mapped, create_inherit=created))
        (out / f"child_parent_mapping_handle_inherit_closed_{arch}.exe").write_bytes(
            build_child_foreign_mapping_handle(
                machine, map_inheritable=True, create_inherit=True,
                close_parent=True))
        for access in ("read", "write"):
            (out / f"child_parent_mapping_view_{access}_{arch}.exe").write_bytes(
                build_child_parent_mapping_view_access(machine, access=access))
        for access in ("read", "execute", "api_read", "api_write", "flush", "unmap",
                       "unmap_interior"):
            (out / f"child_parent_pagefile_view_{access}_{arch}.exe").write_bytes(
                build_child_parent_mapping_view_access(machine, access=access,
                                                       pagefile=True))
        (out / f"child_parent_named_mapping_{arch}.exe").write_bytes(
            build_child_parent_named_mapping(machine))
        (out / f"child_parent_named_mapping_foreign_read_{arch}.exe").write_bytes(
            build_child_parent_named_mapping(machine, foreign_probe=True))
        (out / f"child_parent_process_handle_open_{arch}.exe").write_bytes(
            build_child_foreign_process_handle(machine, child_reopens=True))
        (out / f"child_parent_process_handle_closed_{arch}.exe").write_bytes(
            build_child_foreign_process_handle(machine, child_reopens=True,
                                               after_close_read=True))
        for opened in (False, True):
            for created in (False, True):
                (out / f"child_parent_process_handle_inherit_{int(opened)}{int(created)}_{arch}.exe").write_bytes(
                    build_child_foreign_process_handle(
                        machine, open_inheritable=opened, create_inherit=created))
        (out / f"child_parent_process_handle_inherit_closed_{arch}.exe").write_bytes(
            build_child_foreign_process_handle(
                machine, open_inheritable=True, create_inherit=True,
                close_parent=True))
        for opened, changed in ((False, True), (True, False)):
            (out / f"child_parent_process_handle_set_inherit_{int(changed)}_{arch}.exe").write_bytes(
                build_child_foreign_process_handle(
                    machine, open_inheritable=opened, create_inherit=True,
                    handle_flag_change=changed))
        owner_dir = out / f"child_parent_module_{arch}"
        owner_dir.mkdir(exist_ok=True)
        (owner_dir / f"companion_{arch}.dll").write_bytes(
            build_relocatable_companion(machine,
                                        0x180000000 if arch == "x64" else 0x50000000))
        for mode in ("read", "write"):
            (out / f"child_remote_teb_{mode}_{arch}.exe").write_bytes(
                build_child_process(machine, inject_thread=True,
                                    child_teb_read=True, remote_teb_mode=mode))
        (out / f"process_access_{arch}.exe").write_bytes(build_process_access(machine))
        (out / f"process_duplicate_{arch}.exe").write_bytes(build_process_duplicate(machine))
        (out / f"process_duplicate_rights_{arch}.exe").write_bytes(
            build_process_duplicate(machine, rights_probe=True))
        (out / f"thread_handles_{arch}.exe").write_bytes(build_thread_handles(machine))
        (out / f"thread_termination_{arch}.exe").write_bytes(build_thread_termination(machine))
        (out / f"thread_return_wait_{arch}.exe").write_bytes(build_thread_return_wait(machine))
        (out / f"dropped_dll_{arch}.exe").write_bytes(build_dropped_dll(machine))
        (out / f"guest_module_budget_{arch}.exe").write_bytes(
            build_guest_module_budget(machine))
        (out / f"guest_same_basename_{arch}.exe").write_bytes(
            build_guest_same_basename(machine))
        for mode in ("valid", "missing", "bad_block"):
            (out / f"dropped_reloc_{mode}_{arch}.exe").write_bytes(
                build_dropped_dll(machine, reloc_mode=mode))
        (out / f"dropped_invalid_dll_{arch}.exe").write_bytes(
            build_dropped_dll(machine, invalid=True))
        (out / f"dropped_tls_dll_{arch}.exe").write_bytes(
            build_dropped_dll(machine, tls=True))
        (out / f"dropped_import_dll_{arch}.exe").write_bytes(
            build_dropped_dll(machine, imported=True))
        (out / f"dropped_dependency_dll_{arch}.exe").write_bytes(
            build_dropped_dll(machine, dependency=True))
        (out / f"dropped_guest_dependency_dll_{arch}.exe").write_bytes(
            build_dropped_dll(machine, guest_dependency=True))
        (out / f"dropped_guest_import_forwarder_{arch}.exe").write_bytes(
            build_dropped_dll(machine, guest_dependency=True,
                              guest_import_forwarder=True))
        (out / f"dropped_guest_import_forwarder_release_{arch}.exe").write_bytes(
            build_dropped_dll(machine, guest_dependency=True,
                              guest_import_forwarder=True, release_dependency=True))
        for mode in ("valid", "missing_reloc", "failed_attach"):
            (out / f"dropped_import_guest_forwarder_{mode}_{arch}.exe").write_bytes(
                build_dropped_dll(machine, guest_dependency=True,
                                  supplied_import_guest_forwarder_mode=mode))
        (out / f"dropped_import_guest_forwarder_release_{arch}.exe").write_bytes(
            build_dropped_dll(machine, guest_dependency=True,
                              supplied_import_guest_forwarder_mode="valid",
                              release_dependency=True))
        for mode in ("valid", "missing_reloc", "failed_attach"):
            (out / f"dropped_guest_forwarder_{mode}_{arch}.exe").write_bytes(
                build_dropped_dll(machine, guest_dependency=True,
                                  forwarded_guest_mode=mode))
        for mode in ("valid", "missing", "bad_block"):
            (out / f"dropped_guest_dependency_reloc_{mode}_{arch}.exe").write_bytes(
                build_dropped_dll(machine, guest_dependency=True,
                                  dependency_reloc_mode=mode))
        (out / f"dropped_guest_dependency_release_dll_{arch}.exe").write_bytes(
            build_dropped_dll(machine, guest_dependency=True, release_dependency=True))
        (out / f"dropped_guest_nested_dll_{arch}.exe").write_bytes(
            build_dropped_dll(machine, guest_dependency=True,
                              nested_companion=True, release_dependency=True))
        (out / f"dropped_guest_cycle_dll_{arch}.exe").write_bytes(
            build_dropped_dll(machine, guest_dependency=True,
                              nested_cycle=True, fail_attach=True))
        (out / f"dropped_lifecycle_dll_{arch}.exe").write_bytes(
            build_dropped_dll(machine, lifecycle=True))
        (out / f"dropped_tls_lifecycle_dll_{arch}.exe").write_bytes(
            build_dropped_dll(machine, tls=True, lifecycle=True))
        (out / f"dropped_dependency_lifecycle_dll_{arch}.exe").write_bytes(
            build_dropped_dll(machine, dependency=True, lifecycle=True))
        (out / f"dropped_dependency_preload_dll_{arch}.exe").write_bytes(
            build_dropped_dll(machine, dependency=True, lifecycle=True,
                              preload_dependency=True))
        (out / f"dropped_failed_attach_dll_{arch}.exe").write_bytes(
            build_dropped_dll(machine, fail_attach=True))
        (out / f"dropped_tls_failed_attach_dll_{arch}.exe").write_bytes(
            build_dropped_dll(machine, tls=True, fail_attach=True))
        (out / f"dropped_dependency_failed_attach_dll_{arch}.exe").write_bytes(
            build_dropped_dll(machine, dependency=True, fail_attach=True))
        (out / f"dropped_shadow_dll_{arch}.exe").write_bytes(
            build_dropped_dll(machine, collision=True))
        (out / f"missing_companion_path_{arch}.exe").write_bytes(
            build_load_wrong_companion_path(machine))
    (out / "move_config_x86.exe").write_bytes(build_move_configured_file(0x14C))
    (out / "move_config_x64.exe").write_bytes(build_move_configured_file(0x8664))
    (out / "copy_config_x86.exe").write_bytes(build_move_configured_file(0x14C, copy=True))
    (out / "copy_config_x64.exe").write_bytes(build_move_configured_file(0x8664, copy=True))
    (out / "delete_config_x86.exe").write_bytes(build_move_configured_file(0x14C, delete=True))
    (out / "delete_config_x64.exe").write_bytes(build_move_configured_file(0x8664, delete=True))
    (out / "local_network_x86.exe").write_bytes(build_local_network_x86())
    for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
        (out / f"wininet_session_{arch}.exe").write_bytes(
            build_wininet_session_probe(machine))
        (out / f"wininet_read_{arch}.exe").write_bytes(
            build_wininet_session_probe(machine, read_response=True))
        (out / f"wininet_query_{arch}.exe").write_bytes(
            build_wininet_session_probe(machine, read_response=True, query_status=True))
        (out / f"wininet_available_{arch}.exe").write_bytes(
            build_wininet_session_probe(machine, read_response=True, query_available=True))
        (out / f"wininet_post_{arch}.exe").write_bytes(
            build_wininet_post_probe(machine))
        (out / f"wininet_stream_{arch}.exe").write_bytes(
            build_wininet_stream_probe(machine))
        (out / f"wininet_linked_{arch}.exe").write_bytes(
            build_wininet_stream_probe(machine, linked=True))
        for invalid_stage in ("connect", "request"):
            (out / f"wininet_bad_{invalid_stage}_{arch}.exe").write_bytes(
                build_wininet_post_probe(machine, invalid_stage=invalid_stage))
        (out / f"winhttp_post_{arch}.exe").write_bytes(
            build_winhttp_post_probe(machine))
        (out / f"winhttp_read_{arch}.exe").write_bytes(
            build_winhttp_post_probe(machine, read_response=True))
        (out / f"winhttp_query_{arch}.exe").write_bytes(
            build_winhttp_post_probe(machine, read_response=True, query_status=True))
        (out / f"winhttp_available_{arch}.exe").write_bytes(
            build_winhttp_post_probe(machine, read_response=True, query_status=True,
                                     query_available=True))
        (out / f"winhttp_stream_{arch}.exe").write_bytes(
            build_winhttp_post_probe(machine, read_response=True,
                                     query_status=True, streamed=True))
        (out / f"winhttp_chunked_{arch}.exe").write_bytes(
            build_winhttp_post_probe(machine, read_response=True,
                                     query_status=True, streamed=True, chunked=True))
        for api in ("InternetOpenUrlA", "HttpSendRequestA", "WinHttpSendRequest",
                    "gethostbyname"):
            (out / f"invalid_{api.lower()}_{arch}.exe").write_bytes(
                build_invalid_network_request(machine, api))
    for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
        for cache in (False, True):
            for wide in (False, True):
                name = f"urlmon_{'cache_' if cache else ''}{'w' if wide else 'a'}_{arch}.exe"
                (out / name).write_bytes(build_urlmon_download(machine, cache=cache, wide=wide))
    (out / "load_library_x86.exe").write_bytes(build_load_library(0x14C))
    (out / "load_library_x64.exe").write_bytes(build_load_library(0x8664))
    (out / "call_export_x86.exe").write_bytes(build_call_export(0x14C))
    (out / "call_export_x64.exe").write_bytes(build_call_export(0x8664))
    (out / "checked_call_export_x86.exe").write_bytes(build_checked_call_export(0x14C))
    (out / "checked_call_export_x64.exe").write_bytes(build_checked_call_export(0x8664))
    (out / "companion_lifecycle_x86.exe").write_bytes(build_companion_lifecycle(0x14C))
    (out / "companion_lifecycle_x64.exe").write_bytes(build_companion_lifecycle(0x8664))
    (out / "load_result_x86.exe").write_bytes(build_load_result(0x14C))
    (out / "load_result_x64.exe").write_bytes(build_load_result(0x8664))
    (out / "load_library_ex_x86.exe").write_bytes(build_load_library_ex(0x14C))
    (out / "load_library_ex_x64.exe").write_bytes(build_load_library_ex(0x8664))
    (out / "static_companion_x86.exe").write_bytes(build_static_companion(0x14C))
    (out / "static_companion_x64.exe").write_bytes(build_static_companion(0x8664))
    for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
        guest_forwarder_folder = out / "forwarded_dependency_guest"
        guest_forwarder_folder.mkdir(parents=True, exist_ok=True)
        (guest_forwarder_folder / f"companion_{arch}.dll").write_bytes(
            _forward_export(machine, build(machine, dll=True),
                            "guest-leaf.ProbeValue"))
        for implicit_mode in ("valid", "missing_reloc", "failed_attach", "chain"):
            lazy_folder = out / f"forwarded_implicit_{implicit_mode}"
            lazy_folder.mkdir(parents=True, exist_ok=True)
            (lazy_folder / f"companion_{arch}.dll").write_bytes(
                _forward_export(machine, build(machine, dll=True),
                                f"leaf_{arch}.ProbeValue"))
            preferred = 0x180000000 if arch == "x64" else 0x50000000
            leaf = bytearray(build_relocatable_companion(machine, preferred))
            if implicit_mode == "missing_reloc":
                directory = 0x98 + (112 if arch == "x64" else 96) + 5 * 8
                leaf[directory:directory + 8] = b"\0" * 8
            elif implicit_mode == "failed_attach":
                leaf[0x20E if arch == "x64" else 0x208] = 0
            elif implicit_mode == "chain":
                leaf = bytearray(_forward_export(machine, bytes(leaf),
                                                 f"terminal_{arch}.ProbeValue",
                                                 raw_offset=0x5C0))
                (lazy_folder / f"terminal_{arch}.dll").write_bytes(
                    build_relocatable_companion(machine, preferred))
            (lazy_folder / f"leaf_{arch}.dll").write_bytes(leaf)
        for mode in ("name", "ordinal", "missing", "cycle"):
            target = (f"leaf_{arch}.#1" if mode == "ordinal" else
                      "ghost.ProbeValue" if mode == "missing" else
                      f"leaf_{arch}.ProbeValue")
            middle = build_forwarding_companion(machine, target)
            leaf = (_forward_export(machine, build(machine, dll=True),
                                    f"companion_{arch}.ProbeValue")
                    if mode == "cycle" else build(machine, dll=True))
            for folder in (out / "static_chain" / f"forwarded_{mode}",
                           out / f"forwarded_dynamic_{mode}"):
                folder.mkdir(parents=True, exist_ok=True)
                (folder / f"companion_{arch}.dll").write_bytes(middle)
                (folder / f"leaf_{arch}.dll").write_bytes(leaf)
        middle = bytearray(build_importing_companion(machine, dependency=True))
        leaf_name = f"leaf_{arch}.dll".encode() + b"\0"
        middle[0x580:0x5A0] = b"\0" * 0x20
        middle[0x580:0x580 + len(leaf_name)] = leaf_name
        leaf = bytearray(build(machine, dll=True))
        assert leaf[0x208] == 1
        for variant in ("", "tls_leaf", "failing_leaf", "failing_middle",
                        "failing_tls_leaf", "failing_middle_tls_leaf",
                        "no_entry_tls_leaf", "failing_middle_no_entry_tls_leaf"):
            folder = out / "static_chain" / variant
            folder.mkdir(parents=True, exist_ok=True)
            staged_middle = bytearray(middle)
            staged_leaf = (bytearray(build_tls_only_companion(machine))
                           if "no_entry_tls_leaf" in variant else
                           bytearray(build_tls_companion(machine))
                           if "tls_leaf" in variant else bytearray(leaf))
            if variant == "failing_leaf":
                staged_leaf = bytearray(build_static_detach_probe(
                    machine, bytes(staged_leaf), fail_attach=True, detach_reserved=0))
            if variant == "failing_middle":
                staged_leaf = bytearray(build_static_detach_probe(
                    machine, bytes(staged_leaf), fail_attach=False, detach_reserved=1))
                staged_middle = bytearray(build_static_detach_probe(
                    machine, bytes(staged_middle), fail_attach=True, detach_reserved=0))
            if variant == "failing_tls_leaf":
                needle = b"\xb8\x01\0\0\0"
                pos = staged_leaf.find(needle, 0x200, 0x230)
                assert pos >= 0
                staged_leaf[pos + 1] = 0
            if variant in ("failing_middle_tls_leaf", "failing_middle_no_entry_tls_leaf"):
                needle = b"\xb8\x01\0\0\0"
                pos = staged_middle.find(needle, 0x200, 0x230)
                assert pos >= 0
                staged_middle[pos + 1] = 0
            (folder / f"companion_{arch}.dll").write_bytes(staged_middle)
            (folder / f"leaf_{arch}.dll").write_bytes(staged_leaf)
        reloc_folder = out / "static_chain" / "reloc_leaf"
        reloc_folder.mkdir(parents=True, exist_ok=True)
        preferred = 0x1A0000000 if arch == "x64" else 0x52000000
        (reloc_folder / f"companion_{arch}.dll").write_bytes(middle)
        (reloc_folder / f"leaf_{arch}.dll").write_bytes(
            build_relocatable_companion(machine, preferred))
        no_reloc_folder = out / "static_chain" / "no_reloc_collision"
        no_reloc_folder.mkdir(parents=True, exist_ok=True)
        (no_reloc_folder / f"companion_{arch}.dll").write_bytes(middle)
        no_reloc_leaf = bytearray(build_relocatable_companion(machine, preferred))
        directory = 0x98 + (112 if arch == "x64" else 96) + 5 * 8
        no_reloc_leaf[directory:directory + 8] = b"\0" * 8
        (no_reloc_folder / f"leaf_{arch}.dll").write_bytes(no_reloc_leaf)
        bad_reloc_folder = out / "static_chain" / "bad_reloc_block"
        bad_reloc_folder.mkdir(parents=True, exist_ok=True)
        (bad_reloc_folder / f"companion_{arch}.dll").write_bytes(middle)
        malformed_leaf = bytearray(build_relocatable_companion(machine, preferred))
        struct.pack_into("<I", malformed_leaf, 0x5B4, 0)  # Invalid block size.
        (bad_reloc_folder / f"leaf_{arch}.dll").write_bytes(malformed_leaf)
    (out / "static_companion_lifecycle_x86.exe").write_bytes(
        build_static_companion_lifecycle(0x14C))
    (out / "static_companion_lifecycle_x64.exe").write_bytes(
        build_static_companion_lifecycle(0x8664))
    tls_dir = out / "tls"
    tls_dir.mkdir(exist_ok=True)
    (tls_dir / "companion_x86.dll").write_bytes(build_tls_companion(0x14C))
    (tls_dir / "companion_x64.dll").write_bytes(build_tls_companion(0x8664))
    failing_dir = out / "failing"
    failing_dir.mkdir(exist_ok=True)
    for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
        dll = bytearray(build(machine, dll=True))
        dll[0x208] = 0  # DllMain returns FALSE after setting its guest marker.
        (failing_dir / f"companion_{arch}.dll").write_bytes(dll)

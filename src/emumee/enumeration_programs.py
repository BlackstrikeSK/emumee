"""Persona-owned console PEs for common Windows enumeration commands.

These images contain only guest instructions, imports, and text derived from
the selected persona. No host executable or host identity is copied into them.
"""

from __future__ import annotations

import ipaddress
import struct

from .persona_content import PROCESS_PATHS, oem_code_page


_MAX_TEXT = 32 * 1024


def _align(value: int, boundary: int) -> int:
    return (value + boundary - 1) // boundary * boundary


def enumeration_text(name: str, persona: dict) -> str:
    """Render the initial, no-switch command view from one persona snapshot."""
    if name == "ipconfig.exe":
        adapter = persona["network_adapter"]
        mask = ipaddress.IPv4Network(
            (adapter["ipv4"], adapter["prefix_length"]), strict=False).netmask
        suffix = "" if persona["domain"] == "WORKGROUP" else persona["domain"]
        return ("\r\nWindows IP Configuration\r\n\r\n"
                f"Ethernet adapter {adapter['name']}:\r\n\r\n"
                f"   Connection-specific DNS Suffix  . : {suffix}\r\n"
                f"   IPv4 Address. . . . . . . . . . . : {adapter['ipv4']}\r\n"
                f"   Subnet Mask . . . . . . . . . . . : {mask}\r\n"
                f"   Default Gateway . . . . . . . . : {adapter['gateway']}\r\n")
    if name == "systeminfo.exe":
        cpu = persona["cpu"]
        return (f"Host Name:                 {persona['hostname']}\r\n"
                "OS Name:                   Microsoft Windows 11 Pro\r\n"
                f"OS Version:                10.0.{persona['windows_build']}\r\n"
                f"Registered Owner:          {persona['user_name']}\r\n"
                f"System Locale:             {persona['locale']}\r\n"
                f"Time Zone:                 {persona['timezone']}\r\n"
                f"Total Physical Memory:     {persona['physical_memory_mb']:,} MB\r\n"
                f"Available Physical Memory: {persona['available_memory_mb']:,} MB\r\n"
                f"Processor(s):              {cpu['cores'] * cpu['threads_per_core']} logical processors\r\n"
                f"                           {cpu['brand']}\r\n")
    if name == "tasklist.exe":
        lines = ["Image Name                     PID Session Name        Session#    Mem Usage",
                 "========================= ======== ================ =========== ============"]
        for index, process in enumerate(persona["processes"]):
            pid = 4 if process.casefold() == "system" else 420 + index * 168
            session_id = PROCESS_PATHS.get(process.casefold(), ("", 1))[1]
            session = "Services" if session_id == 0 else "Console"
            lines.append(f"{process:25} {pid:8} {session:16} {session_id:11}        N/A")
        return "\r\n".join(lines) + "\r\n"
    raise ValueError(f"unknown guest enumeration program: {name}")


def console_text_exe(is_x64: bool, output: str, *, code_page: int = 437) -> bytes:
    """Build a minimal PE that writes fixed guest text through WriteFile."""
    data = output.encode(f"cp{code_page}", errors="replace")
    if not data or len(data) > _MAX_TEXT:
        raise ValueError("guest utility output exceeds limit")
    machine = 0x8664 if is_x64 else 0x14C
    base = 0x190000000 if is_x64 else 0x600000
    optional_size = 0xF0 if is_x64 else 0xE0
    data_size = _align(len(data) + 8, 0x200)
    image = bytearray(0x600 + data_size)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, 0x84, machine, 3, 0, 0, 0,
                     optional_size, 0x0022 if is_x64 else 0x0102)
    opt = 0x98
    struct.pack_into("<HBBIII", image, opt, 0x20B if is_x64 else 0x10B,
                     14, 0, 0x200, 0x200 + data_size, 0)
    struct.pack_into("<II", image, opt + 16, 0x1000, 0x1000)
    if is_x64:
        struct.pack_into("<Q", image, opt + 24, base)
    else:
        struct.pack_into("<II", image, opt + 24, 0x3000, base)
    struct.pack_into("<II", image, opt + 32, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", image, opt + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<III", image, opt + 56, 0x3000 + _align(data_size, 0x1000),
                     0x200, 0)
    struct.pack_into("<H", image, opt + 68, 3)
    if is_x64:
        struct.pack_into("<QQQQII", image, opt + 72,
                         0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
        dd = opt + 112
    else:
        struct.pack_into("<IIIIII", image, opt + 72,
                         0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
        dd = opt + 96
    struct.pack_into("<II", image, dd + 8, 0x2000, 0x80)
    sh = opt + optional_size
    for section_name, virtual_size, rva, raw_size, raw_offset, flags in (
            (b".text\0\0\0", 0x200, 0x1000, 0x200, 0x200, 0x60000020),
            (b".idata\0\0", 0x200, 0x2000, 0x200, 0x400, 0xC0000040),
            (b".data\0\0\0", len(data) + 8, 0x3000, data_size, 0x600, 0xC0000040)):
        image[sh:sh + 8] = section_name
        struct.pack_into("<IIIIIIHHI", image, sh + 8,
                         virtual_size, rva, raw_size, raw_offset, 0, 0, 0, 0, flags)
        sh += 40
    image[0x600:0x600 + len(data)] = data
    count_rva = 0x3000 + len(data)

    step = 8 if is_x64 else 4
    struct.pack_into("<IIIII", image, 0x400, 0x2040, 0, 0, 0x20C0, 0x2080)
    image[0x4C0:0x4CD] = b"KERNEL32.dll\0"
    names = (b"GetStdHandle", b"WriteFile", b"ExitProcess", b"GetCommandLineA")
    cursor = 0x4E0
    for index, name in enumerate(names):
        rva = 0x2000 + cursor - 0x400
        for table in (0x2040, 0x2080):
            struct.pack_into("<Q" if is_x64 else "<I", image,
                             0x400 + table - 0x2000 + index * step, rva)
        entry = b"\0\0" + name + b"\0"
        image[cursor:cursor + len(entry)] = entry
        cursor += _align(len(entry), 2)

    code = bytearray()
    labels: dict[str, int] = {}
    branches: list[tuple[int, str]] = []

    def label(name: str) -> None:
        labels[name] = len(code)

    def branch(opcode: bytes, target: str) -> None:
        code.extend(opcode + b"\0\0\0\0")
        branches.append((len(code) - 4, target))

    def call(index: int) -> None:
        iat = 0x2080 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", iat - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + iat))

    if is_x64:
        code.extend(b"\x48\x83\xec\x38")
    call(3)  # GetCommandLineA; reject switches until modeled explicitly.
    code.extend(b"\x48\x89\xc6" if is_x64 else b"\x89\xc6")
    code.extend(b"\x80\x3e\x22")
    branch(b"\x0f\x85", "unquoted")
    code.extend(b"\x48\xff\xc6" if is_x64 else b"\x46")
    label("quoted")
    code.extend(b"\x80\x3e\x00")
    branch(b"\x0f\x84", "no_args")
    code.extend(b"\x80\x3e\x22")
    branch(b"\x0f\x84", "after_token")
    code.extend(b"\x48\xff\xc6" if is_x64 else b"\x46")
    branch(b"\xe9", "quoted")
    label("unquoted")
    code.extend(b"\x80\x3e\x00")
    branch(b"\x0f\x84", "no_args")
    code.extend(b"\x80\x3e\x20")
    branch(b"\x0f\x84", "after_token")
    code.extend(b"\x80\x3e\x09")
    branch(b"\x0f\x84", "after_token")
    code.extend(b"\x48\xff\xc6" if is_x64 else b"\x46")
    branch(b"\xe9", "unquoted")
    label("after_token")
    code.extend(b"\x80\x3e\x00")
    branch(b"\x0f\x84", "no_args")
    code.extend(b"\x80\x3e\x20")
    branch(b"\x0f\x84", "skip_space")
    code.extend(b"\x80\x3e\x09")
    branch(b"\x0f\x84", "skip_space")
    branch(b"\xe9", "unsupported_args")
    label("skip_space")
    code.extend(b"\x48\xff\xc6" if is_x64 else b"\x46")
    branch(b"\xe9", "after_token")
    label("no_args")
    if is_x64:
        code.extend(b"\xb9\xf5\xff\xff\xff")
        call(0)
        code.extend(b"\x48\x89\xc1\x48\xba" + struct.pack("<Q", base + 0x3000))
        code.extend(b"\x41\xb8" + struct.pack("<I", len(data)))
        code.extend(b"\x49\xb9" + struct.pack("<Q", base + count_rva))
        code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
        call(1)
        code.extend(b"\x85\xc0")
        branch(b"\x0f\x84", "write_failed")
        code.extend(b"\x31\xc9")
        call(2)
        label("write_failed")
        code.extend(b"\xb9\x01\0\0\0")
        call(2)
    else:
        code.extend(b"\x68\xf5\xff\xff\xff")
        call(0)
        code.extend(b"\x89\xc3\x6a\0")
        code.extend(b"\x68" + struct.pack("<I", base + count_rva))
        code.extend(b"\x68" + struct.pack("<I", len(data)))
        code.extend(b"\x68" + struct.pack("<I", base + 0x3000) + b"\x53")
        call(1)
        code.extend(b"\x85\xc0")
        branch(b"\x0f\x84", "write_failed")
        code.extend(b"\x6a\0")
        call(2)
        label("write_failed")
        code.extend(b"\x6a\x01")
        call(2)
    label("unsupported_args")
    code.extend(b"\xb9\x57\0\0\0" if is_x64 else b"\x6a\x57")
    call(2)
    code.extend(b"\xc3")
    for offset, target in branches:
        struct.pack_into("<i", code, offset, labels[target] - offset - 4)
    if len(code) > 0x200:
        raise ValueError("guest utility entry exceeds PE text section")
    image[0x200:0x200 + len(code)] = code
    return bytes(image)


def enumeration_programs(is_x64: bool, persona: dict) -> dict[str, bytes]:
    """Return generated guest executables for the current persona snapshot."""
    code_page = oem_code_page(persona["locale"])
    return {name: console_text_exe(is_x64, enumeration_text(name, persona),
                                   code_page=code_page)
            for name in ("ipconfig.exe", "systeminfo.exe", "tasklist.exe")}

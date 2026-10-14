"""Persona-owned console PEs for common Windows enumeration commands.

These images contain only guest instructions, imports, and text derived from
the selected persona. No host executable or host identity is copied into them.
"""

from __future__ import annotations

import ipaddress
import struct

from .persona_content import PROCESS_PATHS, oem_code_page
from .tokens import GuestTokens


_MAX_TEXT = 32 * 1024


def _align(value: int, boundary: int) -> int:
    return (value + boundary - 1) // boundary * boundary


def enumeration_text(name: str, persona: dict, arguments: str = "") -> str:
    """Render one supported command view from the persona snapshot."""
    if name == "whoami.exe":
        identity = f"{persona['hostname']}\\{persona['user_name']}"
        if not arguments:
            return identity
        if arguments.casefold() == "/user":
            return ("\r\nUSER INFORMATION\r\n"
                    "----------------\r\n"
                    "User Name                 SID\r\n"
                    "========================= =============================================\r\n"
                    f"{identity:25} {persona['user_sid']}\r\n")
        if arguments.casefold() == "/groups":
            tokens = GuestTokens(persona)
            rows = []
            for sid, encoded in zip(tokens.group_sids, tokens.groups, strict=True):
                name, domain, _ = tokens.sid_names[encoded]
                group = f"{domain}\\{name}" if domain else name
                rows.append(f"{group:32} {sid}\r\n")
            return ("\r\nGROUP INFORMATION\r\n"
                    "-----------------\r\n"
                    "Group Name                       SID\r\n"
                    "================================ =============================================\r\n"
                    + "".join(rows))
        raise ValueError("unsupported whoami arguments")
    if name == "ipconfig.exe":
        adapter = persona["network_adapter"]
        mask = ipaddress.IPv4Network(
            (adapter["ipv4"], adapter["prefix_length"]), strict=False).netmask
        suffix = "" if persona["domain"] == "WORKGROUP" else persona["domain"]
        basic = ("\r\nWindows IP Configuration\r\n\r\n"
                f"Ethernet adapter {adapter['name']}:\r\n\r\n"
                f"   Connection-specific DNS Suffix  . : {suffix}\r\n"
                f"   IPv4 Address. . . . . . . . . . . : {adapter['ipv4']}\r\n"
                f"   Subnet Mask . . . . . . . . . . . : {mask}\r\n"
                f"   Default Gateway . . . . . . . . : {adapter['gateway']}\r\n")
        if not arguments:
            return basic
        if arguments.casefold() == "/all":
            dns = "\r\n".join(
                f"   DNS Servers . . . . . . . . . . : {server}" if index == 0
                else f"                                       {server}"
                for index, server in enumerate(adapter["dns_servers"]))
            return ("\r\nWindows IP Configuration\r\n\r\n"
                    f"   Host Name . . . . . . . . . . . : {persona['hostname']}\r\n"
                    f"   Primary Dns Suffix  . . . . . . : {suffix}\r\n\r\n"
                    f"Ethernet adapter {adapter['name']}:\r\n\r\n"
                    f"   Description . . . . . . . . . . : {adapter['description']}\r\n"
                    f"   Physical Address. . . . . . . . : {adapter['mac']}\r\n"
                    f"   DHCP Enabled. . . . . . . . . . : {'Yes' if adapter['dhcp_enabled'] else 'No'}\r\n"
                    f"   Connection-specific DNS Suffix  . : {suffix}\r\n"
                    f"   IPv4 Address. . . . . . . . . . . : {adapter['ipv4']}\r\n"
                    f"   Subnet Mask . . . . . . . . . . . : {mask}\r\n"
                    f"   Default Gateway . . . . . . . . : {adapter['gateway']}\r\n"
                    f"{dns}\r\n")
        raise ValueError("unsupported ipconfig arguments")
    if name == "getmac.exe" and not arguments:
        adapter = persona["network_adapter"]
        return ("\r\nPhysical Address    Transport Name\r\n"
                "=================== ==========================================================\r\n"
                f"{adapter['mac']:19} \\Device\\Tcpip_{adapter['guid']}\r\n")
    if name == "arp.exe":
        if not arguments:
            return "Displays and modifies the IP-to-physical address translation tables.\r\nUsage: arp -a\r\n"
        if arguments.casefold() != "-a":
            raise ValueError("unsupported arp arguments")
        adapter = persona["network_adapter"]
        if adapter["prefix_length"] >= 31:
            return "No ARP Entries Found.\r\n"
        subnet = ipaddress.IPv4Network(
            (adapter["ipv4"], adapter["prefix_length"]), strict=False)
        return (f"\r\nInterface: {adapter['ipv4']} --- 0x{adapter['if_index']:x}\r\n"
                "  Internet Address      Physical Address      Type\r\n"
                f"  {str(subnet.broadcast_address):<21} ff-ff-ff-ff-ff-ff     static\r\n")
    if name == "route.exe":
        if not arguments:
            return "Manipulates network routing tables.\r\nUsage: route print\r\n"
        if arguments.casefold() not in {"print", "print -4"}:
            raise ValueError("unsupported route arguments")
        adapter = persona["network_adapter"]
        subnet = ipaddress.IPv4Network(
            (adapter["ipv4"], adapter["prefix_length"]), strict=False)
        mac = adapter["mac"].replace("-", " ").lower()
        rows = (
            ("0.0.0.0", "0.0.0.0", adapter["gateway"], adapter["ipv4"]),
            (str(subnet.network_address), str(subnet.netmask), "On-link", adapter["ipv4"]),
            (adapter["ipv4"], "255.255.255.255", "On-link", adapter["ipv4"]),
        )
        table = "".join(f"{dest:>20} {mask:>20} {gateway:>20} {interface:>20}     25\r\n"
                        for dest, mask, gateway, interface in rows)
        return ("===========================================================================\r\n"
                "Interface List\r\n"
                f" {adapter['if_index']:2}...{mac} ......{adapter['description']}\r\n"
                "===========================================================================\r\n"
                "IPv4 Route Table\r\n"
                "===========================================================================\r\n"
                "Active Routes:\r\n"
                "Network Destination        Netmask          Gateway       Interface  Metric\r\n"
                f"{table}"
                "===========================================================================\r\n")
    if name == "netsh.exe":
        if not arguments:
            return "Network Shell\r\nUsage: netsh interface ipv4 show config\r\n"
        adapter = persona["network_adapter"]
        if arguments.casefold() == "interface ipv4 show config":
            mask = ipaddress.IPv4Network(
                (adapter["ipv4"], adapter["prefix_length"]), strict=False).netmask
            dns = "".join(f"    {server}\r\n" for server in adapter["dns_servers"])
            return (f"Configuration for interface \"{adapter['name']}\"\r\n"
                    f"    DHCP enabled:                         {'Yes' if adapter['dhcp_enabled'] else 'No'}\r\n"
                    f"    IP Address:                           {adapter['ipv4']}\r\n"
                    f"    Subnet Prefix:                        {adapter['ipv4']}/{adapter['prefix_length']} (mask {mask})\r\n"
                    f"    Default Gateway:                      {adapter['gateway']}\r\n"
                    f"    DNS servers configured:               \r\n{dns}")
        if arguments.casefold() == "interface ipv4 show dnsservers":
            dns = "".join(f"    {server}\r\n" for server in adapter["dns_servers"])
            return (f"Configuration for interface \"{adapter['name']}\"\r\n"
                    f"    DNS servers configured:               \r\n{dns}")
        raise ValueError("unsupported netsh arguments")
    if name == "tzutil.exe":
        if not arguments:
            return "Displays or configures the system time zone.\r\nUsage: tzutil /g\r\n"
        if arguments.casefold() == "/g":
            return persona["timezone"] + "_dstoff\r\n"
        raise ValueError("unsupported tzutil arguments")
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


def console_text_exe(is_x64: bool, output: str, *, code_page: int = 437,
                     variants: dict[str, str] | None = None) -> bytes:
    """Build a PE that selects bounded guest text by exact command argument."""
    variants = variants or {}
    if len(variants) > 2 or any(not key or not key.isascii() or "\0" in key
                               for key in variants):
        raise ValueError("guest utility argument variants are invalid")
    outputs = [("", output), *variants.items()]
    data = bytearray()
    output_records = []
    for argument, text in outputs:
        encoded = text.encode(f"cp{code_page}", errors="replace")
        output_records.append((argument, 0x3000 + len(data), len(encoded)))
        data.extend(encoded)
    argument_rvas = {}
    for argument in variants:
        argument_rvas[argument] = 0x3000 + len(data)
        data.extend(argument.encode("ascii") + b"\0")
    if not output or len(data) > _MAX_TEXT:
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
    names = (b"GetStdHandle", b"WriteFile", b"ExitProcess", b"GetCommandLineA",
             b"lstrcmpiA")
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
    call(3)  # GetCommandLineA; inspect only the arguments after the image name.
    code.extend(b"\x48\x89\xc6" if is_x64 else b"\x89\xc6")
    code.extend(b"\x80\x3e\x22")
    branch(b"\x0f\x85", "unquoted")
    code.extend(b"\x48\xff\xc6" if is_x64 else b"\x46")
    label("quoted")
    code.extend(b"\x80\x3e\x00")
    branch(b"\x0f\x84", "no_args")
    code.extend(b"\x80\x3e\x22")
    branch(b"\x0f\x84", "after_quote")
    code.extend(b"\x48\xff\xc6" if is_x64 else b"\x46")
    branch(b"\xe9", "quoted")
    label("after_quote")
    code.extend(b"\x48\xff\xc6" if is_x64 else b"\x46")
    branch(b"\xe9", "after_token")
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
    branch(b"\xe9", "check_variants")
    label("skip_space")
    code.extend(b"\x48\xff\xc6" if is_x64 else b"\x46")
    branch(b"\xe9", "after_token")
    label("check_variants")
    for index, argument in enumerate(variants, 1):
        if is_x64:
            code.extend(b"\x48\x89\xf1\x48\xba" +
                        struct.pack("<Q", base + argument_rvas[argument]))
        else:
            code.extend(b"\x68" + struct.pack("<I", base + argument_rvas[argument]) +
                        b"\x56")
        call(4)  # lstrcmpiA
        code.extend(b"\x85\xc0")
        branch(b"\x0f\x84", f"variant_{index}")
    branch(b"\xe9", "unsupported_args")

    def select_output(rva: int, length: int) -> None:
        if is_x64:
            code.extend(b"\x48\xbf" + struct.pack("<Q", base + rva) +
                        b"\xbb" + struct.pack("<I", length))
        else:
            code.extend(b"\xbf" + struct.pack("<I", base + rva) +
                        b"\xbd" + struct.pack("<I", length))
        branch(b"\xe9", "write_output")

    label("no_args")
    select_output(output_records[0][1], output_records[0][2])
    for index, (_, rva, length) in enumerate(output_records[1:], 1):
        label(f"variant_{index}")
        select_output(rva, length)
    label("write_output")
    if is_x64:
        code.extend(b"\xb9\xf5\xff\xff\xff")
        call(0)
        code.extend(b"\x48\x89\xc1\x48\x89\xfa\x41\x89\xd8")
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
        code.extend(b"\x55\x57\x53")
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
    result = {}
    for name in ("whoami.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe", "getmac.exe",
                 "arp.exe", "route.exe", "netsh.exe", "tzutil.exe"):
        commands = ({"whoami.exe": ("/user", "/groups"),
                     "ipconfig.exe": ("/all",),
                     "arp.exe": ("-a",),
                     "route.exe": ("print", "print -4"),
                     "netsh.exe": ("interface ipv4 show config",
                                   "interface ipv4 show dnsservers"),
                     "tzutil.exe": ("/g",)}.get(name, ()))
        variants = {argument: enumeration_text(name, persona, argument)
                    for argument in commands}
        result[name] = console_text_exe(
            is_x64, enumeration_text(name, persona), code_page=code_page,
            variants=variants)
    return result

"""Build a guarded x64 PE for task, HTTP, and virtual-registry audit checks."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tests.fixtures.build_native import build


REGISTRY_KEY = r"Software\EmumeeTest\AuditProbe"
REGISTRY_CANARY = b"EMUMEE_REGISTRY_CANARY"
TELEGRAM_URL = "https://api.telegram.org/bot000000:EMUMEE_TEST_PLACEHOLDER/getMe"
TASK_COMMAND = (r'schtasks.exe /Create /SC DAILY /TN EmumeeTestProbe '
                r'/TR "C:\Windows\System32\hostname.exe" /ST 23:59')


def build_probe() -> bytes:
    base, text_rva, data_rva, data_raw = 0x140000000, 0x1000, 0x2000, 0x1200
    image = bytearray(0x3200)
    image[:0x200] = build(0x8664)[:0x200]
    struct.pack_into("<II", image, 0x98 + 4, 0x1000, 0x2000)
    struct.pack_into("<I", image, 0x98 + 56, 0x4000)
    sections = 0x98 + 0xF0
    struct.pack_into("<IIII", image, sections + 8, 0x1000, 0x1000, 0x1000, 0x200)
    struct.pack_into("<IIII", image, sections + 48, 0x2000, data_rva, 0x2000, data_raw)
    imports = {
        "KERNEL32.dll": ["GetEnvironmentVariableW", "WinExec", "ExitProcess"],
        "ADVAPI32.dll": ["RegCreateKeyW", "RegSetValueExW", "RegCloseKey"],
        "WININET.dll": ["InternetOpenW", "InternetOpenUrlW", "InternetCloseHandle"],
    }
    cursor = (len(imports) + 1) * 20

    def allocate(raw: bytes, alignment: int = 8) -> int:
        nonlocal cursor
        cursor = (cursor + alignment - 1) & ~(alignment - 1)
        rva = data_rva + cursor
        image[data_raw + cursor:data_raw + cursor + len(raw)] = raw
        cursor += len(raw)
        return base + rva

    iat = {}
    for descriptor, (dll, names) in enumerate(imports.items()):
        lookup = allocate(b"\0" * (8 * (len(names) + 1))) - base
        slots = allocate(b"\0" * (8 * (len(names) + 1))) - base
        dll_name = allocate(dll.encode("ascii") + b"\0") - base
        for index, name in enumerate(names):
            hint_name = allocate(b"\0\0" + name.encode("ascii") + b"\0", 2) - base
            for table in (lookup, slots):
                struct.pack_into("<Q", image, data_raw + table - data_rva + index * 8, hint_name)
            iat[name] = slots + index * 8
        struct.pack_into("<IIIII", image, data_raw + descriptor * 20,
                         lookup, 0, 0, dll_name, slots)
    struct.pack_into("<II", image, 0x98 + 112 + 8, data_rva, (len(imports) + 1) * 20)

    def wide(text):
        return allocate(text.encode("utf-16le") + b"\0\0", 2)

    env_name, env_buffer = wide("EMUMEE_TEST"), allocate(b"\0" * 32)
    key_name, value_name, binary_name = wide(REGISTRY_KEY), wide("ProbeState"), wide("Canary")
    state = "emulated-only".encode("utf-16le") + b"\0\0"
    state_ptr, canary_ptr = allocate(state), allocate(REGISTRY_CANARY)
    key_handle, session_handle = allocate(b"\0" * 8), allocate(b"\0" * 8)
    command = allocate(TASK_COMMAND.encode("ascii") + b"\0")
    agent, url = wide("Emumee audit fixture"), wide(TELEGRAM_URL)
    code = bytearray(b"\x48\x83\xec\x68")
    registers = (b"\x48\xb9", b"\x48\xba", b"\x49\xb8", b"\x49\xb9")
    loads = (b"\x48\x8b\x08", b"\x48\x8b\x10", b"\x4c\x8b\x00", b"\x4c\x8b\x08")

    def call(name, args):
        for index, value in enumerate(args):
            if index < 4:
                if isinstance(value, tuple):
                    code.extend(b"\x48\xb8" + struct.pack("<Q", value[0]) + loads[index])
                else:
                    code.extend(registers[index] + struct.pack("<Q", value))
            else:
                code.extend(b"\x48\xb8" + struct.pack("<Q", value))
                code.extend(b"\x48\x89\x44\x24" + bytes([0x20 + (index - 4) * 8]))
        code.extend(b"\xff\x15" + struct.pack("<i", iat[name] - (text_rva + len(code) + 6)))

    def jne():
        code.extend(b"\x0f\x85\0\0\0\0")
        return len(code) - 4

    def patch_jump(offset, target):
        struct.pack_into("<i", code, offset, target - offset - 4)

    call("GetEnvironmentVariableW", [env_name, env_buffer, 16])
    code.extend(b"\x83\xf8\x07")
    guard_jumps = [jne()]
    for offset, expected in ((0, "virt"), (8, "ual\0")):
        code.extend(b"\x48\xb8" + struct.pack("<Q", env_buffer + offset))
        code.extend(b"\x48\xba" + expected.encode("utf-16le"))
        code.extend(b"\x48\x39\x10")
        guard_jumps.append(jne())

    call("RegCreateKeyW", [0xFFFFFFFF80000001, key_name, key_handle])
    code.extend(b"\x85\xc0")
    registry_failed = jne()
    call("RegSetValueExW", [(key_handle,), value_name, 0, 1, state_ptr, len(state)])
    call("RegSetValueExW", [(key_handle,), binary_name, 0, 3, canary_ptr, len(REGISTRY_CANARY)])
    call("RegCloseKey", [(key_handle,)])
    patch_jump(registry_failed, len(code))

    call("WinExec", [command, 0])
    call("InternetOpenW", [agent, 1, 0, 0, 0])
    code.extend(b"\x48\xa3" + struct.pack("<Q", session_handle))
    call("InternetOpenUrlW", [(session_handle,), url, 0, 0, 0, 0])
    call("InternetCloseHandle", [(session_handle,)])
    call("ExitProcess", [0])
    guard_exit = len(code)
    call("ExitProcess", [2])
    for offset in guard_jumps:
        patch_jump(offset, guard_exit)
    if len(code) > 0x1000 or cursor > 0x2000:
        raise ValueError("Fixture exceeded its sections")
    image[0x200:0x200 + len(code)] = code
    return bytes(image)


if __name__ == "__main__":
    target = Path(__file__).with_name("audit_probe_x64.exe")
    target.write_bytes(build_probe())
    print(target)

"""Compile synthetic Windows-string controls for the contained PE runner."""
import struct

from native_pe_winstrings_reference import BASE, SIZE


HELPERS = (
    'VirtualAlloc', 'WriteProcessMemory', 'VirtualProtect', 'SetLastError',
    'GetLastError', 'CreateFileA', 'WriteFile', 'CloseHandle',
)
MEMORY_PATH = r'C:\Users\Alex\Downloads\winstrings-memory.bin'


def packed(value, width):
    return (value & ((1 << (8 * width)) - 1)).to_bytes(width, 'little')


class Probe:
    def __init__(self, case, template, *, helpers=HELPERS):
        self.width = case['width']
        self.wide = self.width == 8
        self.base = 0x140000000 if self.wide else 0x400000
        # The generated template supplies only the PE and section headers.
        self.data = bytearray(0x6200)
        self.data[:512] = template[:512]
        self.code = bytearray.fromhex('4883ec78') if self.wide else bytearray()
        groups = [('kernel32.dll', list(helpers))]
        if case['module'] == 'kernel32':
            groups[0][1].append(case['export'])
        else:
            groups.append((case['module'] + '.dll', [case['export']]))
        self.slots = []
        slot = 0
        for group, (module, names) in enumerate(groups):
            module_rva = 0x2900 + group * 0x80
            descriptor = struct.pack(
                '<IIIII', 0x2180 + slot * self.width, 0, 0, module_rva,
                0x2080 + slot * self.width,
            )
            self.write(0x2000 + 20 * group, descriptor)
            self.write(module_rva, module.encode('ascii') + b'\0')
            for name in names:
                name_rva = 0x2300 + 48 * slot
                assert len(name) + 3 <= 48
                for thunk in (0x2080, 0x2180):
                    self.write(thunk + slot * self.width, packed(name_rva, self.width))
                self.write(name_rva, b'\0\0' + name.encode('ascii') + b'\0')
                self.slots.append(slot)
                slot += 1
            slot += 1  # Null thunk ends the module's import table.
        self.strings = 0x2a00

    def write(self, rva, data):
        raw = rva - 0xe00
        assert raw >= 0x1200 and raw + len(data) <= len(self.data)
        self.data[raw:raw + len(data)] = data

    def blob(self, data):
        assert len(data) <= 128 and self.strings + 128 <= 0x3400
        address = self.base + self.strings
        self.write(self.strings, data)
        self.strings += 128
        return address

    def call(self, index, arguments, *, cdecl=False):
        thunk = 0x2080 + self.slots[index] * self.width
        if self.wide:
            registers = ('4889c1', '4889c2', '4989c0', '4989c1')
            for position, argument in enumerate(arguments):
                indirect = isinstance(argument, tuple)
                value = argument[0] if indirect else argument
                self.code += bytes.fromhex('48a1' if indirect else '48b8') + packed(value, 8)
                if position < len(registers):
                    self.code += bytes.fromhex(registers[position])
                else:
                    self.code += bytes.fromhex('48894424') + bytes([32 + 8 * (position - 4)])
            displacement = thunk - (0x1000 + len(self.code) + 6)
            self.code += b'\xff\x15' + struct.pack('<i', displacement)
        else:
            for argument in reversed(arguments):
                if isinstance(argument, tuple):
                    self.code += b'\xff\x35' + packed(argument[0], 4)
                else:
                    self.code += b'\x68' + packed(argument, 4)
            self.code += b'\xff\x15' + packed(self.base + thunk, 4)
            if cdecl:
                self.code += b'\x83\xc4' + bytes([len(arguments) * 4])

    def expect(self, value, *, pointer=False):
        # A mismatch hits int3 and prevents a successful entry return.
        if pointer and self.wide:
            self.code += b'\x48\xba' + packed(value, 8) + bytes.fromhex('4839d07401cc')
        else:
            self.code += b'\x3d' + packed(value, 4) + bytes.fromhex('7401cc')

    def save(self, address):
        self.code += (b'\x48' if self.wide else b'') + b'\xa3' + packed(address, self.width)

    def finish(self):
        self.code += b'\xb8\x01\0\0\0'
        if self.wide:
            self.code += bytes.fromhex('4883c478')
        self.code += b'\xc3'
        assert len(self.code) <= 4096
        self.data[0x200:0x200 + len(self.code)] = self.code
        return bytes(self.data)


def program(case, template):
    assert case['protection'] in (0, 1, 3), 'Windows cannot represent write-only pages'
    probe = Probe(case, template)
    old, handle, count = (probe.base + rva for rva in (0x3400, 0x3410, 0x3420))
    probe.call(0, [BASE, SIZE, 0x3000, 4])
    probe.expect(BASE, pointer=True)
    for patch in case['patches']:
        raw = bytes.fromhex(patch['hex'])
        source = probe.blob(raw)
        # The pseudo handle writes fixture bytes into this guest's own arena.
        probe.call(1, [-1, patch['address'], source, len(raw), 0])
        probe.expect(1)
    if case['protection'] != 3:
        probe.call(2, [BASE, SIZE, 1 if case['protection'] == 0 else 2, old])
        probe.expect(1)
    probe.call(3, [0x12345678])
    probe.call(len(HELPERS), case['arguments'], cdecl=case['export'] == '_wcslwr')
    probe.expect(case['result'], pointer=case['export'] in ('CharUpperW', '_wcslwr'))
    probe.call(4, [])
    probe.expect(case['last_error'])
    if case['protection'] != 3:
        probe.call(2, [BASE, SIZE, 4, old])
        probe.expect(1)
    path = probe.blob(MEMORY_PATH.encode('ascii') + b'\0')
    probe.call(5, [path, 0x40000000, 0, 0, 2, 0x80, 0])
    probe.save(handle)
    probe.call(6, [(handle,), BASE, SIZE, count, 0])
    probe.expect(1)
    probe.code += b'\xa1' + packed(count, probe.width)
    probe.expect(SIZE)
    probe.call(7, [(handle,)])
    probe.expect(1)
    return probe.finish()

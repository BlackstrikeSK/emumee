"""Guest path expansion and output-buffer contracts."""

import tempfile
import unittest
import struct
from pathlib import Path
from types import SimpleNamespace

from speakeasy import common

from emumee.artifacts import ArtifactCatalog
from emumee.virtualfs import VirtualFileBridge


class _Guest:
    def __init__(self):
        self.memory = bytearray(0x10000)
        self.error = None
        self.current_dir = r"C:\Users\Alex\Downloads"

    def get_address_map(self, address):
        return (SimpleNamespace(base=0, size=len(self.memory), free=False,
                                prot=common.PERM_MEM_READ | common.PERM_MEM_WRITE)
                if 0 < address < len(self.memory) else None)

    def mem_read(self, address, size):
        return bytes(self.memory[address:address + size])

    def mem_write(self, address, data):
        self.memory[address:address + len(data)] = data

    def read_mem_string(self, address, width):
        chars = bytearray()
        while True:
            unit = self.mem_read(address + len(chars), width)
            if unit == b'\0' * width:
                return chars.decode('utf-16le' if width == 2 else 'cp1252')
            chars.extend(unit)

    def get_ptr_size(self):
        return 8

    def get_cd(self):
        return self.current_dir

    def get_file_manager(self):
        return SimpleNamespace(files=[], file_config=SimpleNamespace(files=[]))

    def set_last_error(self, error):
        self.error = error


class FullPathTests(unittest.TestCase):
    def test_create_file_failure_uses_pointer_width_invalid_handle(self):
        for pointer_size, expected in ((4, 0xffffffff), (8, 0xffffffffffffffff)):
            with self.subTest(pointer_size=pointer_size):
                emu = _Guest()
                emu.get_ptr_size = lambda: pointer_size
                manager = SimpleNamespace(files=[], file_handles={},
                                          does_file_exist=lambda _path: False)
                emu.get_file_manager = lambda: manager
                emu.mem_write(0x100, r'C:\Users\Alex\Documents\missing.txt'.encode('utf-16le') + b'\0\0')
                bridge = VirtualFileBridge(emu.current_dir, None)
                self.assertEqual(bridge._create_file(
                    emu, 'kernel32.CreateFileW', lambda _params: 0xffffffff,
                    [0x100, 0x80000000, 3, 0, 3, 0x80, 0]), expected)
                self.assertEqual(bridge._create_file(
                    emu, 'kernel32.CreateFileW', lambda _params: self.fail('invalid request reached engine'),
                    [0x100, 0x80000000, 3, 0, 5, 0x80, 0]), expected)
                emu.mem_write(0x200, 'CONOUT$\0'.encode('utf-16le'))
                bridge.console_open_handler = lambda *_args: 0xffffffff
                self.assertEqual(bridge._create_file(
                    emu, 'kernel32.CreateFileW', None,
                    [0x200, 0x80000000, 3, 0, 3, 0x80, 0]), expected)

    def test_configured_file_mapping_is_read_only_and_process_owned(self):
        path = r'C:\Users\Alex\Documents\shopping-list.txt'
        entry = SimpleNamespace(mode='full_path', emu_path=path,
                                path='persona-shopping')
        item = SimpleNamespace(path=path, config=entry, data=None)
        maps = {}
        def create_mapping(_handle, _name, size, protection):
            maps[0x280] = SimpleNamespace(size=size, prot=protection,
                                          backed_file=item)
            return 0x280
        manager = SimpleNamespace(
            file_handles={0x80: item}, file_maps=maps,
            file_config=SimpleNamespace(files=[entry]),
            file_create_mapping=create_mapping,
            get_mapping_from_handle=lambda handle: maps.get(handle))
        process = object()
        errors = []
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              get_current_process=lambda: process,
                              get_ptr_size=lambda: 8,
                              set_last_error=errors.append)
        bridge = VirtualFileBridge(r'C:\Users\Alex\Downloads', None,
                                   {'persona-shopping': b'Milk\nCoffee\nBread\n'})
        bridge.file_handle_owners[0x80] = {id(process)}
        bridge.file_open_raw_access[0x80] = 0x80000000
        call = lambda prot: bridge._create_file_mapping(
            emu, 'api-ms-win-core-memory-l1-1-0.CreateFileMappingW',
            lambda _params: self.fail('configured mapping reached default engine'),
            [0x80, 0, prot, 0, 0, 0])
        self.assertEqual(call(4), 0)
        self.assertEqual(errors[-1], 5)
        self.assertFalse(maps)
        self.assertEqual(call(2), 0x280)
        self.assertEqual(maps[0x280].size, 18)
        self.assertEqual(item.data.getvalue(), b'Milk\nCoffee\nBread\n')
        self.assertEqual(bridge.mapping_handle_owners[0x280], {id(process)})

    def test_find_data_uses_guest_file_size_for_first_and_next(self):
        path = r'C:\Users\Alex\Documents\shopping-list.txt'
        next_path = r'C:\Users\Alex\Documents\notes.txt'
        entries = [SimpleNamespace(mode='full_path', emu_path=path,
                                   path='guest-shopping'),
                   SimpleNamespace(mode='full_path', emu_path=next_path,
                                   path='guest-notes')]
        bridge = VirtualFileBridge(r'C:\Users\Alex\Downloads', None,
                                   {'guest-shopping': b'Milk\nCoffee\nBread\n',
                                    'guest-notes': b'Notes\n'},
                                   filetime_ticks=123)
        emu = _Guest()
        emu.get_file_manager = lambda: SimpleNamespace(
            files=[], file_config=SimpleNamespace(files=entries))
        emu.mem_write(0x100, (r'C:\Users\Alex\Documents\*.txt' + '\0').encode('utf-16le'))
        def write_find_name(name):
            emu.mem_write(0x400, b'\0' * 592)
            emu.mem_write(0x400 + 44, (name + '\0').encode('utf-16le'))
        def first(_params):
            write_find_name('shopping-list.txt')
            return 0x1808
        self.assertEqual(bridge._find_first_file(
            emu, 'kernel32.FindFirstFileW', first, [0x100, 0x400]), 0x1808)
        self.assertEqual(struct.unpack('<IQQQII', emu.mem_read(0x400, 36)),
                         (0x80, 123, 123, 123, 0, 18))
        def next_file(_params):
            write_find_name('notes.txt')
            return 1
        self.assertEqual(bridge._find_next_file(
            emu, 'kernel32.FindNextFileW', next_file, [0x1808, 0x400]), 1)
        self.assertEqual(struct.unpack_from('<I', emu.mem_read(0x400, 36), 32)[0], 6)
        self.assertEqual(bridge._find_close(
            emu, 'kernel32.FindClose', lambda _params: 1, [0x1808]), 1)
        self.assertFalse(bridge.find_search_dirs)

    def test_api_set_full_path_import_uses_guest_directory(self):
        with tempfile.TemporaryDirectory() as folder:
            bridge = VirtualFileBridge(r"C:\Users\Alex\Downloads",
                                       ArtifactCatalog(Path(folder)))
            callbacks = {}
            class Registrar:
                def add_api_hook(self, callback, module, name, **_kwargs):
                    callbacks[(module, name)] = callback
            bridge.install(Registrar())
            callback = callbacks[("api-ms-win-core-file-l1-1-0",
                                  "GetFullPathNameW")]
            emu = _Guest()
            emu.mem_write(0x100, '*.*\0'.encode('utf-16le'))
            expected = r'C:\Users\Alex\Downloads\*.*'
            self.assertEqual(callback(emu, 'api-ms-win-core-file-l1-1-0.GetFullPathNameW',
                                      None, [0x100, 100, 0x400, 0]), len(expected))
            self.assertEqual(emu.mem_read(0x400, (len(expected) + 1) * 2),
                             (expected + '\0').encode('utf-16le'))

    def test_full_path_size_query_wide_output_and_file_part(self):
        with tempfile.TemporaryDirectory() as folder:
            bridge = VirtualFileBridge(r"C:\Users\Alex\Downloads",
                                       ArtifactCatalog(Path(folder)))
            emu = _Guest()
            emu.mem_write(0x100, r"..\Desktop\note.txt".encode("utf-16le") + b"\0\0")
            call = lambda size: bridge._get_full_path_name(
                emu, "kernel32.GetFullPathNameW", None, [0x100, size, 0x400, 0x800])
            expected = r"C:\Users\Alex\Desktop\note.txt"
            self.assertEqual(call(0), len(expected) + 1)
            self.assertEqual(call(3), len(expected) + 1)
            self.assertEqual(emu.mem_read(0x400, 2), b"\0\0")
            self.assertEqual(call(len(expected) + 1), len(expected))
            self.assertEqual(emu.mem_read(0x400, 2 * (len(expected) + 1)),
                             expected.encode("utf-16le") + b"\0\0")
            part = int.from_bytes(emu.mem_read(0x800, 8), "little")
            self.assertEqual(part, 0x400 + 2 * expected.index("note.txt"))

    def test_relative_dot_ansi_and_denied_write(self):
        with tempfile.TemporaryDirectory() as folder:
            bridge = VirtualFileBridge(r"C:\Users\Alex\Downloads",
                                       ArtifactCatalog(Path(folder)))
            emu = _Guest()
            emu.mem_write(0x100, b".\0")
            full = emu.current_dir
            call = lambda: bridge._get_full_path_name(
                emu, "kernel32.GetFullPathNameA", None, [0x100, 100, 0x400, 0])
            self.assertEqual(call(), len(full))
            self.assertEqual(emu.mem_read(0x400, len(full) + 1), full.encode() + b"\0")
            bridge.write_guard = lambda _emu, _address, _size: False
            self.assertEqual(call(), 0)
            self.assertEqual(emu.error, 87)

    def test_long_path_size_query_existing_directory_and_missing_path(self):
        with tempfile.TemporaryDirectory() as folder:
            bridge = VirtualFileBridge(r"C:\Users\Alex\Downloads",
                                       ArtifactCatalog(Path(folder)))
            emu = _Guest()
            name = r"C:\Users\Alex\Downloads"
            emu.mem_write(0x100, name.encode("utf-16le") + b"\0\0")
            call = lambda size: bridge._get_long_path_name(
                emu, "kernel32.GetLongPathNameW", None, [0x100, 0x400, size])
            self.assertEqual(call(0), len(name) + 1)
            self.assertEqual(emu.mem_read(0x400, 2), b"\0\0")
            self.assertEqual(call(len(name) + 1), len(name))
            self.assertEqual(emu.mem_read(0x400, 2 * (len(name) + 1)),
                             name.encode("utf-16le") + b"\0\0")
            emu.mem_write(0x100, r"C:\missing".encode("utf-16le") + b"\0\0")
            self.assertEqual(call(100), 0)
            self.assertEqual(emu.error, 2)

    def test_root_relative_path_uses_guest_drive(self):
        with tempfile.TemporaryDirectory() as folder:
            bridge = VirtualFileBridge(r"C:\Users\Alex\Downloads",
                                       ArtifactCatalog(Path(folder)))
            emu = _Guest()
            emu.mem_write(0x100, '\\Windows\0'.encode('utf-16le'))
            result = bridge._get_full_path_name(
                emu, 'kernel32.GetFullPathNameW', None, [0x100, 100, 0x400, 0])
            self.assertEqual(result, len(r'C:\Windows'))
            self.assertEqual(emu.mem_read(0x400, 22),
                             'C:\\Windows\0'.encode('utf-16le'))


if __name__ == "__main__":
    unittest.main()

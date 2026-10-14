"""Guest path expansion and output-buffer contracts."""

import tempfile
import unittest
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

    def get_ptr_size(self):
        return 8

    def get_cd(self):
        return self.current_dir

    def get_file_manager(self):
        return SimpleNamespace(files=[], file_config=SimpleNamespace(files=[]))

    def set_last_error(self, error):
        self.error = error


class FullPathTests(unittest.TestCase):
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

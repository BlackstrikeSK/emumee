"""Reversible Windows probe for FileEndOfFileInfo on temporary bytes."""

from __future__ import annotations

import ctypes
import tempfile
from pathlib import Path


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
create = kernel32.CreateFileW
create.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                   ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                   ctypes.c_void_p)
create.restype = ctypes.c_void_p
close = kernel32.CloseHandle
close.argtypes = (ctypes.c_void_p,)
close.restype = ctypes.c_int
set_info = kernel32.SetFileInformationByHandle
set_info.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
set_info.restype = ctypes.c_int
set_pointer = kernel32.SetFilePointerEx
set_pointer.argtypes = (ctypes.c_void_p, ctypes.c_int64,
                        ctypes.POINTER(ctypes.c_int64), ctypes.c_uint32)
set_pointer.restype = ctypes.c_int

INVALID = ctypes.c_void_p(-1).value
GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_WRITE_DATA = 2
FILE_APPEND_DATA = 4


def open_file(path: Path, access: int) -> int:
    ctypes.set_last_error(0)
    handle = create(str(path), access, 7, None, 3, 0x80, None)
    assert handle != INVALID, ctypes.get_last_error()
    return handle


def resize(handle: int, length: int, size: int = 8) -> tuple[bool, int]:
    data = (ctypes.c_ubyte * max(size, 8))()
    ctypes.memmove(data, ctypes.byref(ctypes.c_int64(length)), 8)
    ctypes.set_last_error(0)
    success = bool(set_info(handle, 6, data, size))
    return success, ctypes.get_last_error()


def position(handle: int, offset: int, method: int) -> tuple[int, int]:
    result = ctypes.c_int64()
    ctypes.set_last_error(0)
    success = bool(set_pointer(handle, offset, ctypes.byref(result), method))
    assert success, ctypes.get_last_error()
    return result.value, ctypes.get_last_error()


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="emumee-file-eof-") as folder:
        root = Path(folder)
        for name, access in (("generic-write", GENERIC_WRITE),
                             ("write-data", FILE_WRITE_DATA),
                             ("append-only", FILE_APPEND_DATA),
                             ("read-only", GENERIC_READ)):
            path = root / f"{name}.bin"
            path.write_bytes(b"ABCDEFGH")
            handle = open_file(path, access)
            if name == "generic-write":
                print(name, "seek-before", position(handle, 5, 0))
                print(name, "shrink", resize(handle, 3))
                print(name, "seek-after", position(handle, 0, 1))
                print(name, "bytes-after", path.read_bytes())
                print(name, "zero-length", resize(handle, 4, 0))
                print(name, "short-length", resize(handle, 4, 7))
                print(name, "long-length", resize(handle, 4, 16))
                print(name, "negative", resize(handle, -1))
            else:
                print(name, "shrink", resize(handle, 3))
            assert close(handle)


if __name__ == "__main__":
    main()

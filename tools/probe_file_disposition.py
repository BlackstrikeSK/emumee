"""Reversible Windows 11 probe for FileDispositionInfo on temporary files."""

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

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
DELETE = 0x10000
SHARE_ALL = 7
OPEN_EXISTING = 3
FLAG_DELETE_ON_CLOSE = 0x04000000
INVALID = ctypes.c_void_p(-1).value


def open_file(path: Path, access: int, share: int = SHARE_ALL,
              flags: int = 0) -> tuple[int, int]:
    ctypes.set_last_error(0)
    handle = create(str(path), access, share, None, OPEN_EXISTING, flags, None)
    return handle, ctypes.get_last_error()


def disposition(handle: int, delete: bool, size: int = 1) -> tuple[bool, int]:
    value = (ctypes.c_ubyte * max(1, size))()
    value[0] = 1 if delete else 0
    ctypes.set_last_error(0)
    success = bool(set_info(handle, 4, ctypes.byref(value), size))
    return success, ctypes.get_last_error()


def close_file(handle: int) -> None:
    if handle != INVALID:
        assert close(handle)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="emumee-file-disposition-") as folder:
        root = Path(folder)
        for label, access, flags, cancel in (
                ("mark", GENERIC_READ | GENERIC_WRITE | DELETE, 0, False),
                ("cancel", GENERIC_READ | GENERIC_WRITE | DELETE, 0, True),
                ("no-delete-right", GENERIC_WRITE, 0, False),
                ("flag-cannot-cancel", GENERIC_WRITE, FLAG_DELETE_ON_CLOSE, True)):
            path = root / f"{label}.bin"
            path.write_bytes(b"harmless marker")
            first, error = open_file(path, access, flags=flags)
            assert first != INVALID, (label, error)
            second = INVALID
            if label == "mark":
                second, error = open_file(path, GENERIC_READ)
                assert second != INVALID, error
            print(label, "mark", disposition(first, True))
            reopened, reopen_error = open_file(path, GENERIC_READ)
            print(label, "reopen-after-mark", reopened != INVALID, reopen_error)
            close_file(reopened)
            if cancel:
                print(label, "cancel", disposition(first, False))
            close_file(first)
            print(label, "exists-after-first-close", path.exists())
            close_file(second)
            print(label, "exists-after-last-close", path.exists())
        path = root / "bad-size.bin"
        path.write_bytes(b"harmless marker")
        handle, error = open_file(path, DELETE)
        assert handle != INVALID, error
        print("bad-size", disposition(handle, True, 0))
        print("large-size", disposition(handle, True, 2))
        close_file(handle)
        path = root / "nonsharing.bin"
        path.write_bytes(b"harmless marker")
        first, error = open_file(path, DELETE)
        assert first != INVALID, error
        second, error = open_file(path, GENERIC_READ, share=3)
        print("nonsharing", "second-open", second != INVALID, "error", error)
        close_file(first)
        close_file(second)


if __name__ == "__main__":
    main()

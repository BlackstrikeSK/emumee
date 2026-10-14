"""Reversible Windows probe for CreateFile(FILE_FLAG_DELETE_ON_CLOSE)."""

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

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
DELETE = 0x10000
SHARE_ALL = 7
OPEN_EXISTING = 3
FLAG_DELETE_ON_CLOSE = 0x04000000
INVALID = ctypes.c_void_p(-1).value


def open_file(path: Path, access: int, share: int, flags: int = 0) -> tuple[int, int]:
    handle = create(str(path), access, share, None, OPEN_EXISTING, flags, None)
    return handle, ctypes.get_last_error()


def close_file(handle: int) -> None:
    if handle != INVALID:
        assert close(handle)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="emumee-delete-on-close-") as directory:
        root = Path(directory)
        for label, access in (("generic-write", GENERIC_WRITE),
                              ("delete-right", DELETE | GENERIC_WRITE)):
            path = root / f"{label}.bin"
            path.write_bytes(b"harmless marker")
            first, error = open_file(path, access, SHARE_ALL, FLAG_DELETE_ON_CLOSE)
            print(label, "open", first != INVALID, "error", error)
            if first == INVALID:
                continue
            denied, denied_error = open_file(path, GENERIC_READ, 3)
            print(label, "second-without-share-delete", denied != INVALID,
                  "error", denied_error)
            close_file(denied)
            second, second_error = open_file(path, GENERIC_READ, SHARE_ALL)
            print(label, "second-open", second != INVALID, "error", second_error)
            close_file(first)
            print(label, "after-first-close-exists", path.exists())
            close_file(second)
            print(label, "after-last-close-exists", path.exists())
        path = root / "sharing.bin"
        path.write_bytes(b"harmless marker")
        first, error = open_file(path, GENERIC_READ, 3)
        assert first != INVALID, error
        second, second_error = open_file(path, DELETE | GENERIC_WRITE, SHARE_ALL,
                                         FLAG_DELETE_ON_CLOSE)
        print("sharing", "second-open", second != INVALID, "error", second_error)
        close_file(second)
        close_file(first)


if __name__ == "__main__":
    main()

"""Reversible Windows 11 probe for SetFileInformationByHandle(FileRenameInfo)."""

from __future__ import annotations

import ctypes
import struct
import tempfile
from pathlib import Path


kernel = ctypes.WinDLL("kernel32", use_last_error=True)
kernel.CreateFileW.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
                               ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                               ctypes.c_void_p)
kernel.CreateFileW.restype = ctypes.c_void_p
kernel.SetFileInformationByHandle.argtypes = (ctypes.c_void_p, ctypes.c_int,
                                               ctypes.c_void_p, ctypes.c_uint32)
kernel.SetFileInformationByHandle.restype = ctypes.c_int
kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
kernel.CloseHandle.restype = ctypes.c_int


def rename_buffer(path: str, *, replace: bool = False, root: int = 0) -> bytes:
    name = path.encode("utf-16le")
    # The 64-bit FILE_RENAME_INFO layout has RootDirectory at offset 8,
    # FileNameLength at offset 16, and FileName at offset 20.
    return struct.pack("<I4xQI", int(replace), root, len(name)) + name


def attempt(folder: Path, label: str, *, access: int = 0x10000,
            share: int = 0, target_exists: bool = False,
            replace: bool = False, length_delta: int = 0,
            root: int = 0, target_open_share: int | None = None) -> None:
    source = folder / f"{label}-old.bin"
    target = folder / f"{label}-new.bin"
    source.write_bytes(b"OLD!")
    if target_exists:
        target.write_bytes(b"NEW!")
    target_handle = None
    if target_open_share is not None:
        target_handle = kernel.CreateFileW(str(target), 0x80000000,
                                            target_open_share, None, 3, 0x80, None)
        if target_handle in (None, ctypes.c_void_p(-1).value):
            print(label, "target open", ctypes.get_last_error())
            return
    handle = kernel.CreateFileW(str(source), access, share, None, 3, 0x80, None)
    if handle in (None, ctypes.c_void_p(-1).value):
        print(label, "open", ctypes.get_last_error())
        return
    try:
        raw = rename_buffer(str(target), replace=replace, root=root)
        data = ctypes.create_string_buffer(raw)
        ctypes.set_last_error(0)
        ok = bool(kernel.SetFileInformationByHandle(handle, 3, data,
                                                     len(raw) + length_delta))
        error = ctypes.get_last_error()
    finally:
        kernel.CloseHandle(handle)
        if target_handle is not None:
            kernel.CloseHandle(target_handle)
    print(label, ok, error, "old", source.exists(), "new",
          target.read_bytes() if target.exists() else None)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="emumee-rename-info-") as temporary:
        folder = Path(temporary)
        attempt(folder, "delete-right-exclusive")
        attempt(folder, "generic-write", access=0x40000000, share=7)
        attempt(folder, "collision", share=7, target_exists=True)
        attempt(folder, "replace", share=7, target_exists=True, replace=True)
        attempt(folder, "replace-open-share-delete", share=7, target_exists=True,
                replace=True, target_open_share=7)
        attempt(folder, "replace-open-no-share-delete", share=7, target_exists=True,
                replace=True, target_open_share=3)
        attempt(folder, "short-buffer", length_delta=-2)
        attempt(folder, "long-buffer", length_delta=2)
        attempt(folder, "bad-root", root=0x1234)


if __name__ == "__main__":
    main()

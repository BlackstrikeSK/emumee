"""Reversible local Windows file-attribute and FileBasicInfo probe."""

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
kernel.SetFileAttributesW.argtypes = (ctypes.c_wchar_p, ctypes.c_uint32)
kernel.SetFileAttributesW.restype = ctypes.c_int
kernel.GetFileAttributesW.argtypes = (ctypes.c_wchar_p,)
kernel.GetFileAttributesW.restype = ctypes.c_uint32
kernel.SetFileInformationByHandle.argtypes = (ctypes.c_void_p, ctypes.c_int,
                                               ctypes.c_void_p, ctypes.c_uint32)
kernel.SetFileInformationByHandle.restype = ctypes.c_int
kernel.WriteFile.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32,
                             ctypes.c_void_p, ctypes.c_void_p)
kernel.WriteFile.restype = ctypes.c_int
kernel.CloseHandle.argtypes = (ctypes.c_void_p,)
kernel.CloseHandle.restype = ctypes.c_int
kernel.DeleteFileW.argtypes = (ctypes.c_wchar_p,)
kernel.DeleteFileW.restype = ctypes.c_int


def result(call):
    ctypes.set_last_error(0)
    value = call()
    return bool(value), ctypes.get_last_error()


def open_file(path: Path, access: int) -> int:
    handle = kernel.CreateFileW(str(path), access, 7, None, 3, 0x80, None)
    if handle in (None, ctypes.c_void_p(-1).value):
        raise OSError(ctypes.get_last_error(), "CreateFileW failed")
    return handle


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="emumee-basic-info-") as temporary:
        directory = Path(temporary) / "guest-dir"
        directory.mkdir()
        print("directory-set-hidden-readonly",
              result(lambda: kernel.SetFileAttributesW(str(directory), 3)),
              hex(kernel.GetFileAttributesW(str(directory))))
        print("directory-preserve-directory-bit",
              result(lambda: kernel.SetFileAttributesW(str(directory), 0x12)),
              hex(kernel.GetFileAttributesW(str(directory))))
        kernel.SetFileAttributesW(str(directory), 0x10)
        path = Path(temporary) / "attributes.bin"
        path.write_bytes(b"ABC")
        writer = open_file(path, 0x40000000 | 0x100)  # GENERIC_WRITE | FILE_WRITE_ATTRIBUTES
        try:
            print("initial", hex(kernel.GetFileAttributesW(str(path))))
            print("set-hidden-readonly", result(lambda: kernel.SetFileAttributesW(str(path), 3)),
                  hex(kernel.GetFileAttributesW(str(path))))
            data = ctypes.create_string_buffer(b"Z")
            count = ctypes.c_uint32()
            print("existing-writer-after-readonly",
                  result(lambda: kernel.WriteFile(writer, data, 1, ctypes.byref(count), None)),
                  count.value)
            print("new-write-open-after-readonly", end=" ")
            handle = kernel.CreateFileW(str(path), 0x40000000, 7, None, 3, 0x80, None)
            print(handle not in (None, ctypes.c_void_p(-1).value), ctypes.get_last_error())
            if handle not in (None, ctypes.c_void_p(-1).value):
                kernel.CloseHandle(handle)
            print("delete-readonly", result(lambda: kernel.DeleteFileW(str(path))))
            print("set-zero", result(lambda: kernel.SetFileAttributesW(str(path), 0)),
                  hex(kernel.GetFileAttributesW(str(path))))
            print("set-normal", result(lambda: kernel.SetFileAttributesW(str(path), 0x80)),
                  hex(kernel.GetFileAttributesW(str(path))))
        finally:
            kernel.CloseHandle(writer)
            kernel.SetFileAttributesW(str(path), 0x80)
        for access, label in ((0x100, "write-attributes"),
                              (0x2, "write-data-only"),
                              (0x4, "append-only"),
                              (0x80000000, "read-only"),
                              (0x40000000, "generic-write")):
            handle = open_file(path, access)
            try:
                raw = struct.pack("<qqqqI4x", 0, 0, 0, 0, 2)
                data = ctypes.create_string_buffer(raw)
                for size in (35, 36, 40):
                    print(label, "basic-size", size,
                          result(lambda: kernel.SetFileInformationByHandle(handle, 0, data, size)),
                          hex(kernel.GetFileAttributesW(str(path))))
            finally:
                kernel.CloseHandle(handle)
                kernel.SetFileAttributesW(str(path), 0x80)


if __name__ == "__main__":
    main()

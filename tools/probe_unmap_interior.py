"""Harmless host probe for pagefile-view flush and interior unmap behavior."""

from __future__ import annotations

import ctypes
import json
from ctypes import wintypes


def main() -> None:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileMappingW.argtypes = [wintypes.HANDLE, wintypes.LPVOID,
                                          wintypes.DWORD, wintypes.DWORD,
                                          wintypes.DWORD, wintypes.LPCWSTR]
    kernel.CreateFileMappingW.restype = wintypes.HANDLE
    kernel.MapViewOfFile.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                     wintypes.DWORD, wintypes.DWORD,
                                     ctypes.c_size_t]
    kernel.MapViewOfFile.restype = ctypes.c_void_p
    kernel.FlushViewOfFile.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    kernel.FlushViewOfFile.restype = wintypes.BOOL
    kernel.UnmapViewOfFile.argtypes = [ctypes.c_void_p]
    kernel.UnmapViewOfFile.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL

    handle = kernel.CreateFileMappingW(wintypes.HANDLE(-1), None, 4, 0, 4096, None)
    if not handle:
        raise OSError(ctypes.get_last_error(), "CreateFileMappingW failed")
    view = None
    unmapped = False
    try:
        view = kernel.MapViewOfFile(handle, 2, 0, 0, 4096)
        if not view:
            raise OSError(ctypes.get_last_error(), "MapViewOfFile failed")
        ctypes.memmove(view, b"Pers", 4)
        ctypes.set_last_error(0)
        flushed = bool(kernel.FlushViewOfFile(view, 4))
        flush_error = ctypes.get_last_error()
        ctypes.set_last_error(0)
        unmapped = bool(kernel.UnmapViewOfFile(view + 1))
        unmap_error = ctypes.get_last_error()
        retained = None if unmapped else ctypes.string_at(view, 4).decode("ascii")
        print(json.dumps({"pagefile_flush_success": flushed,
                          "flush_last_error": flush_error,
                          "interior_unmap_success": unmapped,
                          "interior_unmap_last_error": unmap_error,
                          "bytes_if_still_mapped": retained}, sort_keys=True))
    finally:
        if view and not unmapped:
            kernel.UnmapViewOfFile(view)
        kernel.CloseHandle(handle)


if __name__ == "__main__":
    main()

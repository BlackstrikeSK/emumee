"""Harmless Win32 probe for DuplicateHandle process rights and close-source."""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes


def main() -> None:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateEventW.argtypes = [ctypes.c_void_p, wintypes.BOOL,
                                    wintypes.BOOL, wintypes.LPCWSTR]
    kernel.CreateEventW.restype = wintypes.HANDLE
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.DuplicateHandle.argtypes = [wintypes.HANDLE, wintypes.HANDLE,
                                       wintypes.HANDLE, ctypes.POINTER(wintypes.HANDLE),
                                       wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.DuplicateHandle.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL

    query = kernel.OpenProcess(0x1000, False, os.getpid())
    event = kernel.CreateEventW(None, False, False, None)
    if not query or not event:
        raise OSError(ctypes.get_last_error(), "test handle creation failed")
    try:
        for source_is_read_only in (True, False):
            output = wintypes.HANDLE()
            source = query if source_is_read_only else kernel.GetCurrentProcess()
            target = kernel.GetCurrentProcess() if source_is_read_only else query
            result = kernel.DuplicateHandle(source, event, target,
                                            ctypes.byref(output), 0, False, 3)
            error = ctypes.get_last_error()
            still_open = bool(kernel.CloseHandle(event))
            event = None
            if output.value:
                kernel.CloseHandle(output)
            side = "source" if source_is_read_only else "target"
            print(f"read-only {side} process: result={int(result)}, error={error}, "
                  f"source_still_open={still_open}")
            event = kernel.CreateEventW(None, False, False, None)
            if not event:
                raise OSError(ctypes.get_last_error(), "replacement test event failed")
    finally:
        if event:
            kernel.CloseHandle(event)
        kernel.CloseHandle(query)


if __name__ == "__main__":
    main()

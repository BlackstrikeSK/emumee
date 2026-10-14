"""Reversible Windows handle-flag probe using one unnamed host event."""

from __future__ import annotations

import ctypes
from ctypes import wintypes


def main() -> None:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateEventW.argtypes = (ctypes.c_void_p, wintypes.BOOL,
                                    wintypes.BOOL, wintypes.LPCWSTR)
    kernel.CreateEventW.restype = wintypes.HANDLE
    kernel.SetHandleInformation.argtypes = (wintypes.HANDLE, wintypes.DWORD,
                                             wintypes.DWORD)
    kernel.SetHandleInformation.restype = wintypes.BOOL
    kernel.GetHandleInformation.argtypes = (wintypes.HANDLE,
                                             ctypes.POINTER(wintypes.DWORD))
    kernel.GetHandleInformation.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.CreateEventW(None, False, False, None)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    closed = False
    try:
        flags = wintypes.DWORD(0)
        assert kernel.GetHandleInformation(handle, ctypes.byref(flags))
        assert flags.value == 0, flags.value
        assert kernel.SetHandleInformation(handle, 3, 3)
        assert kernel.GetHandleInformation(handle, ctypes.byref(flags))
        assert flags.value == 3, flags.value
        ctypes.set_last_error(0)
        assert not kernel.CloseHandle(handle)
        error = ctypes.get_last_error()
        assert kernel.GetHandleInformation(handle, ctypes.byref(flags))
        assert flags.value == 3, flags.value
        assert kernel.SetHandleInformation(handle, 3, 0)
        assert kernel.GetHandleInformation(handle, ctypes.byref(flags))
        assert flags.value == 0, flags.value
        assert kernel.CloseHandle(handle)
        closed = True
        print(f"protected_close_error={error} flags=0->3->0 restored_and_closed={closed}")
    finally:
        if not closed:
            kernel.SetHandleInformation(handle, 2, 0)
            kernel.CloseHandle(handle)


if __name__ == "__main__":
    main()

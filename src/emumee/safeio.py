"""Bounded reads of worker-owned files without following Windows file links."""

from __future__ import annotations

import ctypes
import ntpath
import os
from ctypes import wintypes
from pathlib import Path


_GENERIC_READ = 0x80000000
_FILE_SHARE_ALL = 0x00000001 | 0x00000002 | 0x00000004
_OPEN_EXISTING = 3
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _FileInformation(ctypes.Structure):
    _fields_ = [
        ("attributes", wintypes.DWORD),
        ("created", wintypes.FILETIME),
        ("accessed", wintypes.FILETIME),
        ("modified", wintypes.FILETIME),
        ("volume_serial", wintypes.DWORD),
        ("size_high", wintypes.DWORD),
        ("size_low", wintypes.DWORD),
        ("links", wintypes.DWORD),
        ("index_high", wintypes.DWORD),
        ("index_low", wintypes.DWORD),
    ]


def _normal_windows_path(value: str) -> str:
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return ntpath.normcase(ntpath.normpath(value))


def _contained_handle_matches(path: Path, root: Path, info: _FileInformation) -> bool:
    """Fallback for AppContainer, where final-name queries can be denied."""
    try:
        relative = path.absolute().relative_to(root.absolute())
        if not relative.parts:
            return False
        current = root.absolute()
        for part in relative.parts[:-1]:
            details = current.lstat()
            if not current.is_dir() or details.st_file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
                return False
            current = current / part
        details = current.lstat()
        if not current.is_dir() or details.st_file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            return False
        final = path.lstat()
        return (not final.st_file_attributes & _FILE_ATTRIBUTE_REPARSE_POINT and
                final.st_nlink == 1 and
                final.st_ino == (info.index_high << 32 | info.index_low) and
                final.st_size == (info.size_high << 32 | info.size_low))
    except (OSError, ValueError):
        return False


def read_regular_file(path: Path, limit: int, diagnostics: list[str] | None = None,
                      containment_root: Path | None = None) -> bytes | None:
    """Read one regular, single-linked file from its verified Windows handle."""
    def reject(reason: str) -> None:
        if diagnostics is not None:
            diagnostics.append(reason)
        return None

    if os.name != "nt" or limit < 0:
        return reject("unsupported platform or limit")
    target = _normal_windows_path(str(path.absolute()))
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                   ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                   wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE,
                                                  ctypes.POINTER(_FileInformation)]
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR,
                                                 wintypes.DWORD, wintypes.DWORD]
    kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    kernel.ReadFile.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.CreateFileW(str(path), _GENERIC_READ, _FILE_SHARE_ALL, None,
                                _OPEN_EXISTING, _FILE_FLAG_OPEN_REPARSE_POINT, None)
    if handle in (None, _INVALID_HANDLE_VALUE):
        return reject(f"open failed: Win32 {ctypes.get_last_error()}")
    try:
        info = _FileInformation()
        if not kernel.GetFileInformationByHandle(handle, ctypes.byref(info)):
            return reject(f"file information failed: Win32 {ctypes.get_last_error()}")
        if (info.attributes & (_FILE_ATTRIBUTE_DIRECTORY | _FILE_ATTRIBUTE_REPARSE_POINT)
                or info.links != 1 or (info.size_high << 32 | info.size_low) > limit):
            return reject("file type, link count, or size rejected")
        path_buffer = ctypes.create_unicode_buffer(32768)
        length = kernel.GetFinalPathNameByHandleW(handle, path_buffer, len(path_buffer), 0)
        if not length:
            error = ctypes.get_last_error()
            if (error != 5 or containment_root is None or
                    not _contained_handle_matches(path, containment_root, info)):
                return reject(f"final path unavailable: Win32 {error}")
        elif length >= len(path_buffer) or _normal_windows_path(path_buffer.value) != target:
            return reject("final path differs")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            count = min(65536, remaining)
            buffer = ctypes.create_string_buffer(count)
            read = wintypes.DWORD()
            if not kernel.ReadFile(handle, buffer, count, ctypes.byref(read), None):
                return reject(f"read failed: Win32 {ctypes.get_last_error()}")
            if not read.value:
                break
            chunks.append(buffer.raw[:read.value])
            remaining -= read.value
        data = b"".join(chunks)
        return data if len(data) <= limit else reject("file grew past limit")
    finally:
        kernel.CloseHandle(handle)

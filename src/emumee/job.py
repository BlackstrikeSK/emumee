"""Windows job limits for the emulator worker process."""

from __future__ import annotations

import ctypes
import os
import threading
from ctypes import wintypes
from pathlib import Path

MAX_OUTPUT_FILES = 10_000

if os.name == "nt":
    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [("StreamSize", ctypes.c_int64),
                    ("cStreamName", wintypes.WCHAR * (260 + 36))]


    _stream_kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    _stream_kernel.FindFirstStreamW.argtypes = [wintypes.LPCWSTR, ctypes.c_int,
                                                ctypes.c_void_p, wintypes.DWORD]
    _stream_kernel.FindFirstStreamW.restype = wintypes.HANDLE
    _stream_kernel.FindNextStreamW.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    _stream_kernel.FindNextStreamW.restype = wintypes.BOOL
    _stream_kernel.FindClose.argtypes = [wintypes.HANDLE]
    _stream_kernel.FindClose.restype = wintypes.BOOL

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]


    class BASIC_LIMITS(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]


    class EXTENDED_LIMITS(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BASIC_LIMITS),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]


def _named_stream_usage(path: Path) -> tuple[int, int]:
    """Count named NTFS/ReFS data streams hidden from ordinary file sizes."""
    if os.name != "nt":
        return 0, 0
    full = os.path.abspath(os.fspath(path))
    if not full.startswith("\\\\?\\"):
        full = ("\\\\?\\UNC\\" + full[2:] if full.startswith("\\\\")
                else "\\\\?\\" + full)
    data = WIN32_FIND_STREAM_DATA()
    handle = _stream_kernel.FindFirstStreamW(full, 0, ctypes.byref(data), 0)
    if handle == ctypes.c_void_p(-1).value:
        error = ctypes.get_last_error()
        if error in (2, 3, 38, 87):  # Gone, no streams, or unsupported filesystem.
            return 0, 0
        raise ctypes.WinError(error)
    total = count = 0
    try:
        while True:
            if data.cStreamName.casefold() != "::$data":
                if data.StreamSize < 0:
                    raise OSError("negative named stream size")
                total += int(data.StreamSize)
                count += 1
            if not _stream_kernel.FindNextStreamW(handle, ctypes.byref(data)):
                error = ctypes.get_last_error()
                if error != 38:  # ERROR_HANDLE_EOF
                    raise ctypes.WinError(error)
                return total, count
    finally:
        _stream_kernel.FindClose(handle)


class WorkerJob:
    def __init__(self, memory_mb: int = 1024):
        if os.name != "nt":
            raise RuntimeError("Windows job isolation requires Windows")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                         ctypes.c_void_p, wintypes.DWORD]
        self.kernel.SetInformationJobObject.restype = wintypes.BOOL
        self.kernel.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                           ctypes.c_void_p, wintypes.DWORD,
                                                           ctypes.c_void_p]
        self.kernel.QueryInformationJobObject.restype = wintypes.BOOL
        self.kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel.AssignProcessToJobObject.restype = wintypes.BOOL
        self.kernel.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.kernel.TerminateJobObject.restype = wintypes.BOOL
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = EXTENDED_LIMITS()
        limits.BasicLimitInformation.LimitFlags = 0x8 | 0x100 | 0x2000
        # The packaged worker is one process; guest child PEs stay in emulation.
        limits.BasicLimitInformation.ActiveProcessLimit = 1
        limits.ProcessMemoryLimit = memory_mb * 1024 * 1024
        if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            self.close()
            raise ctypes.WinError(ctypes.get_last_error())

    def assign(self, process) -> None:
        self.assign_handle(process._handle)

    def assign_handle(self, handle) -> None:
        if not self.kernel.AssignProcessToJobObject(self.handle, handle):
            raise ctypes.WinError(ctypes.get_last_error())

    def terminate(self) -> None:
        self.kernel.TerminateJobObject(self.handle, 1)

    def peak_process_memory_bytes(self) -> int | None:
        limits = EXTENDED_LIMITS()
        if not self.handle or not self.kernel.QueryInformationJobObject(
                self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits), None):
            return None
        return int(limits.PeakProcessMemoryUsed)

    def close(self) -> None:
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


class OutputWatchdog:
    """Stop isolated jobs that create excessive run data or broker journal data."""

    def __init__(self, root: Path, job: WorkerJob, max_mb: int = 512,
                 extra_files: tuple[Path, ...] = (),
                 extra_jobs: tuple[WorkerJob, ...] = ()):
        self.root = root
        self.job = job
        self.extra_files = extra_files
        self.extra_jobs = extra_jobs
        self.max_bytes = max_mb * 1024 * 1024
        self.stop = threading.Event()
        self.violation: str | None = None
        self.thread = threading.Thread(target=self._watch, name="emumee-output-watchdog", daemon=True)

    def _watch(self) -> None:
        def terminate(reason: str) -> None:
            self.violation = reason
            self.job.terminate()
            for extra_job in self.extra_jobs:
                extra_job.terminate()

        while not self.stop.wait(0.25):
            total = 0
            files = 0
            pending = [self.root]
            try:
                stream_bytes, stream_count = _named_stream_usage(self.root)
                total += stream_bytes
                files += stream_count
                if total > self.max_bytes or files > MAX_OUTPUT_FILES:
                    terminate("Worker exceeded output size or file-count limit")
                    return
                while pending:
                    directory = pending.pop()
                    with os.scandir(directory) as entries:
                        for entry in entries:
                            if entry.is_dir(follow_symlinks=False):
                                pending.append(Path(entry.path))
                                stream_bytes, stream_count = _named_stream_usage(Path(entry.path))
                                total += stream_bytes
                                files += stream_count
                            elif entry.is_file(follow_symlinks=False):
                                files += 1
                                total += entry.stat(follow_symlinks=False).st_size
                                stream_bytes, stream_count = _named_stream_usage(Path(entry.path))
                                total += stream_bytes
                                files += stream_count
                            if total > self.max_bytes or files > MAX_OUTPUT_FILES:
                                terminate("Worker exceeded output size or file-count limit")
                                return
                for path in self.extra_files:
                    if path.is_file() and not path.is_symlink():
                        total += path.stat().st_size
                        files += 1
                        stream_bytes, stream_count = _named_stream_usage(path)
                        total += stream_bytes
                        files += stream_count
                    if total > self.max_bytes or files > MAX_OUTPUT_FILES:
                        terminate("Worker and broker exceeded output size or file-count limit")
                        return
            except FileNotFoundError:
                continue
            except OSError as exc:
                terminate(f"Output watchdog could not inspect run data: {type(exc).__name__}")
                return

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.stop.set()
        self.thread.join(timeout=2)

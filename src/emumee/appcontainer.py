"""Windows AppContainer launcher for the analysis worker.

AppContainer restricts filesystem/process access even if a guest sample finds
an emulator vulnerability. Only an explicit run directory receives write access.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import subprocess
from ctypes import wintypes
from pathlib import Path


MONIKER = "Emumee.AnalysisWorker"
ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY = 0x0002000F
PROCESS_CHILD_PROCESS_POLICY = 13
EXTENDED_STARTUPINFO_PRESENT = 0x00080000
CREATE_NO_WINDOW = 0x08000000
CREATE_UNICODE_ENVIRONMENT = 0x00000400
CREATE_SUSPENDED = 0x00000004
WAIT_TIMEOUT = 0x00000102
ERROR_ALREADY_EXISTS_HRESULT = 0x800700B7
TOKEN_QUERY = 0x0008
TOKEN_IS_APP_CONTAINER = 29
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
MAX_GRANT_TREE_ENTRIES = 100_000


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]


class SECURITY_CAPABILITIES(ctypes.Structure):
    _fields_ = [("AppContainerSid", ctypes.c_void_p),
                ("Capabilities", ctypes.POINTER(SID_AND_ATTRIBUTES)),
                ("CapabilityCount", wintypes.DWORD), ("Reserved", wintypes.DWORD)]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]


class STARTUPINFOEXW(ctypes.Structure):
    _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]


def _windows_error() -> OSError:
    return ctypes.WinError(ctypes.get_last_error())


def _check_acl_tree(root: Path) -> None:
    """Refuse links before a recursive ACL command can reach outside the tree."""
    pending = [root]
    seen = 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                seen += 1
                if seen > MAX_GRANT_TREE_ENTRIES:
                    raise OSError("AppContainer ACL tree exceeds entry limit")
                details = os.stat(entry.path, follow_symlinks=False)
                if (entry.is_symlink() or
                        getattr(details, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT):
                    raise OSError(f"AppContainer ACL tree contains a reparse point: {entry.path}")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                elif not entry.is_file(follow_symlinks=False) or details.st_nlink != 1:
                    raise OSError(f"AppContainer ACL tree contains a linked or unsafe file: {entry.path}")


def restrict_current_process_children() -> None:
    """Deny host child processes before private modes handle sample data."""
    if os.name != "nt":
        raise RuntimeError("Child-process mitigation requires Windows")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.SetProcessMitigationPolicy.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                                  ctypes.c_size_t]
    kernel.SetProcessMitigationPolicy.restype = wintypes.BOOL
    kernel.GetProcessMitigationPolicy.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                  ctypes.c_void_p, ctypes.c_size_t]
    kernel.GetProcessMitigationPolicy.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    flags = wintypes.DWORD(1)
    if not kernel.SetProcessMitigationPolicy(PROCESS_CHILD_PROCESS_POLICY,
                                             ctypes.byref(flags), ctypes.sizeof(flags)):
        raise _windows_error()
    observed = wintypes.DWORD()
    if (not kernel.GetProcessMitigationPolicy(kernel.GetCurrentProcess(),
            PROCESS_CHILD_PROCESS_POLICY, ctypes.byref(observed),
            ctypes.sizeof(observed)) or not observed.value & 1):
        raise RuntimeError("Child-process mitigation did not activate")


def verify_worker_containment(*, require_job: bool = True) -> dict[str, bool]:
    """Fail before private modes read inputs if started outside containment."""
    if os.name != "nt":
        raise RuntimeError("Analysis worker requires Windows AppContainer containment")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    kernel.IsProcessInJob.argtypes = [wintypes.HANDLE, wintypes.HANDLE,
                                     ctypes.POINTER(wintypes.BOOL)]
    kernel.IsProcessInJob.restype = wintypes.BOOL
    kernel.GetProcessMitigationPolicy.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                  ctypes.c_void_p, ctypes.c_size_t]
    kernel.GetProcessMitigationPolicy.restype = wintypes.BOOL
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                        ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                           ctypes.c_void_p, wintypes.DWORD,
                                           ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    process = kernel.GetCurrentProcess()
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(process, TOKEN_QUERY, ctypes.byref(token)):
        raise _windows_error()
    try:
        is_app_container = wintypes.DWORD()
        length = wintypes.DWORD()
        if not advapi.GetTokenInformation(token, TOKEN_IS_APP_CONTAINER,
                                           ctypes.byref(is_app_container),
                                           ctypes.sizeof(is_app_container),
                                           ctypes.byref(length)):
            raise _windows_error()
    finally:
        kernel.CloseHandle(token)
    in_job = wintypes.BOOL()
    if not kernel.IsProcessInJob(process, None, ctypes.byref(in_job)):
        raise _windows_error()
    child_policy = wintypes.DWORD()
    if not kernel.GetProcessMitigationPolicy(process, PROCESS_CHILD_PROCESS_POLICY,
                                             ctypes.byref(child_policy),
                                             ctypes.sizeof(child_policy)):
        raise _windows_error()
    observed = {"app_container": bool(is_app_container.value),
                "job_object": bool(in_job.value),
                "child_process_blocked": bool(child_policy.value & 1)}
    required = ("app_container", "child_process_blocked", "job_object") if require_job else (
        "app_container", "child_process_blocked")
    if not all(observed[name] for name in required):
        missing = ", ".join(name for name in required if not observed[name])
        raise RuntimeError(f"Analysis worker containment missing: {missing}")
    return observed


class AppContainer:
    def __init__(self, moniker: str = MONIKER, network: bool = True,
                 delete_on_close: bool = False, lpac: bool = False):
        if os.name != "nt":
            raise RuntimeError("AppContainer requires Windows")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.userenv = ctypes.WinDLL("userenv", use_last_error=True)
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self.kernelbase = ctypes.WinDLL("kernelbase", use_last_error=True)
        self.sid = ctypes.c_void_p()
        self.capability_sid = ctypes.c_void_p()
        self.moniker = moniker
        self.delete_on_close = delete_on_close
        self.lpac = lpac
        self.granted_roots: dict[str, tuple[Path, bool]] = {}
        self._configure_functions()
        hr = self.userenv.CreateAppContainerProfile(moniker, "Emumee analysis worker",
                                                     "Isolated Windows PE emulation worker",
                                                     None, 0, ctypes.byref(self.sid)) & 0xFFFFFFFF
        if hr == ERROR_ALREADY_EXISTS_HRESULT:
            hr = self.userenv.DeriveAppContainerSidFromAppContainerName(
                moniker, ctypes.byref(self.sid)) & 0xFFFFFFFF
        if hr:
            raise OSError(f"Create AppContainer profile failed: HRESULT 0x{hr:08x}")
        sid_string = wintypes.LPWSTR()
        if not self.advapi.ConvertSidToStringSidW(self.sid, ctypes.byref(sid_string)):
            raise _windows_error()
        self.sid_string = sid_string.value
        self.kernel.LocalFree(sid_string)
        if network:
            self.capability_sid = self._internet_capability_sid()

    def _configure_functions(self) -> None:
        self.userenv.CreateAppContainerProfile.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR,
            wintypes.LPCWSTR, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
        self.userenv.CreateAppContainerProfile.restype = ctypes.c_long
        self.userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [
            wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)]
        self.userenv.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long
        self.userenv.DeleteAppContainerProfile.argtypes = [wintypes.LPCWSTR]
        self.userenv.DeleteAppContainerProfile.restype = ctypes.c_long
        self.advapi.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
        self.advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
        self.kernel.LocalFree.argtypes = [ctypes.c_void_p]
        self.kernel.LocalFree.restype = ctypes.c_void_p
        self.kernelbase.DeriveCapabilitySidsFromName.argtypes = [wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)), ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(ctypes.POINTER(ctypes.c_void_p)), ctypes.POINTER(wintypes.DWORD)]
        self.kernelbase.DeriveCapabilitySidsFromName.restype = wintypes.BOOL
        self.kernel.InitializeProcThreadAttributeList.argtypes = [ctypes.c_void_p,
            wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t)]
        self.kernel.InitializeProcThreadAttributeList.restype = wintypes.BOOL
        self.kernel.UpdateProcThreadAttribute.argtypes = [ctypes.c_void_p, wintypes.DWORD,
            ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p]
        self.kernel.UpdateProcThreadAttribute.restype = wintypes.BOOL
        self.kernel.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
        self.kernel.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR,
            ctypes.c_void_p, ctypes.c_void_p, wintypes.BOOL, wintypes.DWORD,
            ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFOEXW),
            ctypes.POINTER(PROCESS_INFORMATION)]
        self.kernel.CreateProcessW.restype = wintypes.BOOL
        self.kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.kernel.WaitForSingleObject.restype = wintypes.DWORD
        self.kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        self.kernel.GetExitCodeProcess.restype = wintypes.BOOL
        self.kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.kernel.TerminateProcess.restype = wintypes.BOOL
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.kernel.ResumeThread.argtypes = [wintypes.HANDLE]
        self.kernel.ResumeThread.restype = wintypes.DWORD

    def _internet_capability_sid(self) -> ctypes.c_void_p:
        groups = ctypes.POINTER(ctypes.c_void_p)()
        group_count = wintypes.DWORD()
        capabilities = ctypes.POINTER(ctypes.c_void_p)()
        capability_count = wintypes.DWORD()
        if not self.kernelbase.DeriveCapabilitySidsFromName(
                "internetClient", ctypes.byref(groups), ctypes.byref(group_count),
                ctypes.byref(capabilities), ctypes.byref(capability_count)):
            raise _windows_error()
        if capability_count.value != 1:
            raise RuntimeError("Expected one internetClient capability SID")
        sid = ctypes.c_void_p(capabilities[0])
        for i in range(group_count.value):
            self.kernel.LocalFree(groups[i])
        self.kernel.LocalFree(groups)
        self.kernel.LocalFree(capabilities)
        return sid

    def grant(self, path: Path, permission: str = "RX", *, recursive: bool = True) -> None:
        target = path.resolve(strict=True)
        if os.path.normcase(str(target)) != os.path.normcase(os.path.abspath(path)):
            raise OSError(f"AppContainer grant root redirects outside its named path: {path}")
        directory = target.is_dir()
        if not directory and (not target.is_file() or target.stat().st_nlink != 1):
            raise OSError(f"AppContainer file grant requires a single-linked regular file: {path}")
        if directory and recursive:
            _check_acl_tree(target)
        self.granted_roots[str(path.absolute()).casefold()] = (target, directory and recursive)
        ace = f"*{self.sid_string}:{'(OI)(CI)' if directory and recursive else ''}{permission}"
        command = ["icacls", str(target), "/grant", ace]
        if directory and recursive:
            command.append("/T")
        command.append("/L")
        result = subprocess.run(command,
                                capture_output=True, text=True)
        if result.returncode:
            raise OSError(f"Cannot grant AppContainer access to {path}: {result.stderr or result.stdout}")

    def revoke(self, path: Path) -> None:
        key = str(path.absolute()).casefold()
        if key not in self.granted_roots:
            return
        target = path.resolve(strict=True)
        granted_target, recursive = self.granted_roots[key]
        if target != granted_target:
            raise OSError(f"AppContainer grant root changed before cleanup: {path}")
        if recursive:
            _check_acl_tree(target)
        command = ["icacls", str(target), "/remove:g", f"*{self.sid_string}"]
        if recursive:
            command.append("/T")
        command.append("/L")
        result = subprocess.run(command,
                                capture_output=True, text=True)
        if result.returncode:
            raise OSError(f"Cannot revoke AppContainer access to {path}: {result.stderr or result.stdout}")
        self.granted_roots.pop(key, None)

    def launch(self, argv: list[str], cwd: Path, timeout: int, env: dict[str, str] | None = None,
               job=None) -> int:
        size = ctypes.c_size_t()
        attribute_count = 2 if self.lpac else 1
        self.kernel.InitializeProcThreadAttributeList(None, attribute_count, 0, ctypes.byref(size))
        attribute_buffer = ctypes.create_string_buffer(size.value)
        if not self.kernel.InitializeProcThreadAttributeList(attribute_buffer, attribute_count, 0, ctypes.byref(size)):
            raise _windows_error()
        capabilities = (SID_AND_ATTRIBUTES * 1)()
        count = 0
        if self.capability_sid:
            capabilities[0].Sid = self.capability_sid.value
            capabilities[0].Attributes = 0x00000004
            count = 1
        security = SECURITY_CAPABILITIES(self.sid, capabilities if count else None, count, 0)
        try:
            if not self.kernel.UpdateProcThreadAttribute(attribute_buffer, 0,
                    ATTRIBUTE_SECURITY_CAPABILITIES, ctypes.byref(security), ctypes.sizeof(security), None, None):
                raise _windows_error()
            if self.lpac:
                policy = wintypes.DWORD(1)  # PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT
                if not self.kernel.UpdateProcThreadAttribute(attribute_buffer, 0,
                        ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, ctypes.byref(policy),
                        ctypes.sizeof(policy), None, None):
                    raise _windows_error()
            startup = STARTUPINFOEXW()
            startup.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
            startup.lpAttributeList = ctypes.cast(attribute_buffer, ctypes.c_void_p)
            info = PROCESS_INFORMATION()
            command = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
            public_keys = ("SystemRoot", "WINDIR", "PATH", "USERPROFILE", "APPDATA",
                           "LOCALAPPDATA", "TEMP", "TMP", "COMSPEC", "SystemDrive",
                           "PATHEXT", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS",
                           "USERNAME", "USERDOMAIN", "ProgramData", "ProgramFiles")
            environment = env if env is not None else {
                key: os.environ[key] for key in public_keys if key in os.environ
            }
            environment["PYTHONDONTWRITEBYTECODE"] = "1"
            env_block = ctypes.create_unicode_buffer("\0".join(f"{k}={v}" for k, v in environment.items()) + "\0\0")
            flags = (EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW |
                     CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED)
            if not self.kernel.CreateProcessW(argv[0], command, None, None, False, flags,
                    env_block, str(cwd), ctypes.byref(startup), ctypes.byref(info)):
                raise _windows_error()
            exited = False
            try:
                if job is not None:
                    job.assign_handle(info.hProcess)
                if self.kernel.ResumeThread(info.hThread) == 0xFFFFFFFF:
                    raise _windows_error()
                wait = self.kernel.WaitForSingleObject(info.hProcess, timeout * 1000)
                if wait == WAIT_TIMEOUT:
                    raise TimeoutError("AppContainer worker exceeded wall-clock limit")
                if wait != 0:
                    raise _windows_error()
                exited = True
                code = wintypes.DWORD()
                if not self.kernel.GetExitCodeProcess(info.hProcess, ctypes.byref(code)):
                    raise _windows_error()
                return code.value
            finally:
                if not exited:
                    self.kernel.TerminateProcess(info.hProcess, 1)
                    self.kernel.WaitForSingleObject(info.hProcess, 5000)
                self.kernel.CloseHandle(info.hThread)
                self.kernel.CloseHandle(info.hProcess)
        finally:
            self.kernel.DeleteProcThreadAttributeList(attribute_buffer)

    def close(self) -> None:
        if self.capability_sid:
            self.kernel.LocalFree(self.capability_sid)
            self.capability_sid = ctypes.c_void_p()
        if self.sid:
            self.kernel.LocalFree(self.sid)
            self.sid = ctypes.c_void_p()
        if self.delete_on_close:
            hr = self.userenv.DeleteAppContainerProfile(self.moniker) & 0xFFFFFFFF
            if hr:
                raise OSError(f"Delete AppContainer profile failed: HRESULT 0x{hr:08x}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


class BundleRunLock:
    """Serialize ACL changes and launches that share a packaged worker bundle."""

    def __init__(self, bundle: Path):
        if os.name != "nt":
            raise RuntimeError("Bundle lock requires Windows")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        self.kernel.CreateMutexW.restype = wintypes.HANDLE
        self.kernel.ReleaseMutex.argtypes = [wintypes.HANDLE]
        self.kernel.ReleaseMutex.restype = wintypes.BOOL
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.CloseHandle.restype = wintypes.BOOL
        self.kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.kernel.WaitForSingleObject.restype = wintypes.DWORD
        digest = hashlib.sha256(str(bundle.resolve()).lower().encode("utf-8")).hexdigest()[:24]
        self.handle = self.kernel.CreateMutexW(None, False, f"Local\\Emumee.Bundle.{digest}")
        if not self.handle:
            raise _windows_error()
        self.held = False

    def __enter__(self):
        status = self.kernel.WaitForSingleObject(self.handle, 180_000)
        if status not in (0, 0x80):  # WAIT_OBJECT_0 or WAIT_ABANDONED
            self.kernel.CloseHandle(self.handle)
            self.handle = None
            raise RuntimeError("Timed out waiting for another Emumee run to release the bundle")
        self.held = True
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.held:
            self.kernel.ReleaseMutex(self.handle)
            self.held = False
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None

"""Reversible checks run inside AppContainer by the test harness only."""

from __future__ import annotations

import ctypes
import json
import os
import socket
import subprocess
import sys
import winreg
from pathlib import Path


def main(run_dir: Path, outside_file: Path, outside_marker: Path, parent_pid: int,
         registry_key: str, bundle_marker: Path, loopback_port: int) -> None:
    from .appcontainer import verify_worker_containment
    verify_worker_containment(require_job=False)
    results: dict[str, object] = {}
    try:
        outside_file.read_bytes()
        results["outside_read"] = "allowed"
    except OSError as exc:
        results["outside_read"] = f"denied: {exc.winerror if hasattr(exc, 'winerror') else exc.errno}"
    try:
        outside_marker.write_text("probe", encoding="utf-8")
        results["outside_write"] = "allowed"
    except OSError as exc:
        results["outside_write"] = f"denied: {exc.winerror if hasattr(exc, 'winerror') else exc.errno}"
    try:
        bundle_marker.write_text("probe", encoding="utf-8")
        results["bundle_write"] = "allowed"
    except OSError as exc:
        results["bundle_write"] = f"denied: {exc.winerror if hasattr(exc, 'winerror') else exc.errno}"
    link = run_dir / "outside-link.txt"
    try:
        link.symlink_to(outside_file)
        try:
            link.read_bytes()
            results["symlink_read"] = "allowed"
        except OSError as exc:
            results["symlink_read"] = f"denied: {exc.winerror if hasattr(exc, 'winerror') else exc.errno}"
    except OSError as exc:
        results["symlink_read"] = f"link denied: {exc.winerror if hasattr(exc, 'winerror') else exc.errno}"
    finally:
        link.unlink(missing_ok=True)
    hardlink = run_dir / "outside-hardlink.txt"
    try:
        os.link(outside_file, hardlink)
        hardlink.read_bytes()
        results["hardlink_read"] = "allowed"
    except OSError as exc:
        results["hardlink_read"] = f"denied: {exc.winerror if hasattr(exc, 'winerror') else exc.errno}"
    finally:
        hardlink.unlink(missing_ok=True)
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, registry_key, 0, winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, "probe", 0, winreg.REG_SZ, "sandbox")
        results["registry_write"] = "allowed"
    except OSError as exc:
        results["registry_write"] = f"denied: {exc.winerror if hasattr(exc, 'winerror') else exc.errno}"
    try:
        child = subprocess.run(["C:/Windows/System32/cmd.exe", "/c", "exit", "0"], timeout=3)
        results["host_child"] = f"created: {child.returncode}"
    except (OSError, subprocess.TimeoutExpired) as exc:
        results["host_child"] = f"denied: {exc}"
    try:
        sock = socket.create_connection(("1.1.1.1", 443), timeout=2)
        sock.close()
        results["direct_internet"] = "connected"
    except OSError as exc:
        results["direct_internet"] = f"denied: {exc}"
    try:
        sock = socket.create_connection(("127.0.0.1", loopback_port), timeout=2)
        sock.close()
        results["host_loopback"] = "connected"
    except OSError as exc:
        results["host_loopback"] = f"denied: {exc}"
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = ctypes.c_void_p
    kernel.GetProcessMitigationPolicy.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                                  ctypes.c_void_p, ctypes.c_size_t]
    kernel.GetProcessMitigationPolicy.restype = ctypes.c_int
    child_policy = ctypes.c_uint32()
    if kernel.GetProcessMitigationPolicy(kernel.GetCurrentProcess(), 13,
                                        ctypes.byref(child_policy),
                                        ctypes.sizeof(child_policy)):
        results["child_process_restricted"] = bool(child_policy.value & 1)
    else:
        results["child_process_restricted"] = f"query failed: {ctypes.get_last_error()}"
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    handle = kernel.OpenProcess(0x0010, 0, parent_pid)  # PROCESS_VM_READ
    results["parent_process_read"] = "allowed" if handle else f"denied: {ctypes.get_last_error()}"
    if handle:
        kernel.CloseHandle(ctypes.c_void_p(handle))
    (run_dir / "sandbox-probe.json").write_text(json.dumps(results, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), int(sys.argv[4]),
         sys.argv[5], Path(sys.argv[6]), int(sys.argv[7]))

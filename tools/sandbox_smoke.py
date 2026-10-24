"""Harmless AppContainer boundary smoke check for a built bundle."""

import json
import argparse
import hashlib
import os
import shutil
import socket
import tempfile
import uuid
import winreg
from contextlib import nullcontext
from pathlib import Path

from emumee.appcontainer import AppContainer, BundleRunLock
from emumee.job import WorkerJob
from emumee.persona import DEFAULT_PERSONA


root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--bundle", type=Path, default=root / "dist" / "Emumee")
bundle = parser.parse_args().bundle.resolve()
exe = bundle / "Emumee.exe"
with tempfile.TemporaryDirectory(dir=root / "output") as folder:
    run_dir = Path(folder)
    (run_dir / "inputs").mkdir()
    shutil.copyfile(root / "tests" / "fixtures" / "native_x86.exe", run_dir / "input.pe")
    request_raw = json.dumps({
        "sample_name": "native_x86.exe", "persona": DEFAULT_PERSONA, "dlls": [],
        "timeout": 10, "max_instructions": 100000,
        "input_sha256": hashlib.sha256((run_dir / "input.pe").read_bytes()).hexdigest(),
        "companions_sha256": {},
        "companion_guest_paths": {},
        "bundle_guest_root": DEFAULT_PERSONA["current_dir"],
        "bundle_files_sha256": {},
    }).encode("utf-8")
    (run_dir / "request.json").write_bytes(request_raw)
    with BundleRunLock(exe), WorkerJob(256) as worker_job, AppContainer(
            moniker=f"Emumee.Probe.{uuid.uuid4().hex}", network=False,
            delete_on_close=True) as box:
        box.grant(bundle, "RX")
        box.grant(run_dir, "M")
        try:
            code = box.launch([str(exe), "_worker", str(run_dir),
                               hashlib.sha256(request_raw).hexdigest()], run_dir, 20,
                              job=worker_job)
            summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
            if code != 0 or summary["status"] != "completed":
                raise AssertionError(f"AppContainer worker failed: {code}, {summary['status']}")
            print("native worker in AppContainer: completed")
            cmd = Path("C:/Windows/System32/cmd.exe")
            outside = root / "README.md"
            stolen = run_dir / "outside-copy.txt"
            box.launch([str(cmd), "/c", "copy", str(outside), str(stolen)], run_dir, 10)
            if stolen.exists():
                raise AssertionError("AppContainer unexpectedly read a file outside the run directory")
            print("outside workspace file read: denied")
        finally:
            box.revoke(run_dir)
            box.revoke(bundle)
    marker = root / f"sandbox-probe-{uuid.uuid4().hex}.txt"
    bundle_marker = bundle / f"sandbox-probe-{uuid.uuid4().hex}.txt"
    registry_key = f"Software\\EmumeeSandboxProbe\\{uuid.uuid4().hex}"
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    loopback_port = listener.getsockname()[1]
    try:
        for network, with_job in ((True, True), (False, True), (False, False)):
            with BundleRunLock(exe), AppContainer(moniker=f"Emumee.Probe.{uuid.uuid4().hex}", network=network,
                              delete_on_close=True) as box, (WorkerJob(256) if with_job else nullcontext(None)) as job:
                box.grant(bundle, "RX")
                box.grant(run_dir, "M")
                try:
                    code = box.launch([str(exe), "_sandbox_probe", str(run_dir),
                                       str(root / "README.md"), str(marker), str(os.getpid()),
                                       registry_key, str(bundle_marker), str(loopback_port)],
                                      run_dir, 15, job=job)
                    if code:
                        raise AssertionError(f"Sandbox probe exited {code}")
                    result = json.loads((run_dir / "sandbox-probe.json").read_text(encoding="utf-8"))
                    print(f"network capability {network}, job {with_job}: "
                          f"{json.dumps(result, sort_keys=True)}")
                    if result["child_process_restricted"] is not True:
                        raise AssertionError("AppContainer child-process policy is not active")
                    for key in ("outside_read", "outside_write", "bundle_write", "symlink_read",
                                "hardlink_read", "parent_process_read"):
                        if result[key] == "allowed":
                            raise AssertionError(f"Sandbox allowed {key}")
                    if result["host_child"].startswith("created"):
                        raise AssertionError("AppContainer allowed a host child process")
                    if not network and result["direct_internet"] == "connected":
                        raise AssertionError("Network-disabled AppContainer connected to the internet")
                    if result["host_loopback"] == "connected":
                        raise AssertionError("AppContainer connected to a host loopback service")
                    try:
                        host_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_key)
                    except FileNotFoundError:
                        pass
                    else:
                        host_key.Close()
                        raise AssertionError("AppContainer changed the host registry")
                finally:
                    box.revoke(run_dir)
                    box.revoke(bundle)
    finally:
        listener.close()
        marker.unlink(missing_ok=True)
        bundle_marker.unlink(missing_ok=True)
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, registry_key)
        except FileNotFoundError:
            pass
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\EmumeeSandboxProbe")
        except (FileNotFoundError, PermissionError):
            pass

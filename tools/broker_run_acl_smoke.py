"""Harmless packaged check that the broker cannot read or edit run evidence."""

from __future__ import annotations

import json
import os
import tempfile
import uuid
import winreg
from pathlib import Path

from emumee.appcontainer import AppContainer, BundleRunLock


ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "dist" / "Emumee" / "Emumee.exe"


def main() -> None:
    with tempfile.TemporaryDirectory(dir=ROOT / "output") as folder:
        run_dir = Path(folder)
        ipc_dir = run_dir / "broker-ipc"
        ipc_dir.mkdir()
        input_file = run_dir / "input.pe"
        summary_file = run_dir / "summary.json"
        input_file.write_bytes(b"harmless staged input")
        summary_file.write_bytes(b"harmless summary marker")
        bundle_marker = EXE.parent / f"broker-acl-{uuid.uuid4().hex}.txt"
        registry_key = f"Software\\EmumeeBrokerAclProbe\\{uuid.uuid4().hex}"
        try:
            with BundleRunLock(EXE), AppContainer(
                    moniker=f"Emumee.BrokerAclProbe.{uuid.uuid4().hex}",
                    network=True, delete_on_close=True) as box:
                box.grant(EXE.parent, "RX")
                box.grant(run_dir, "RX", recursive=False)
                box.grant(ipc_dir, "M")
                try:
                    code = box.launch(
                        [str(EXE), "_sandbox_probe", str(ipc_dir), str(input_file),
                         str(summary_file), str(os.getpid()), registry_key,
                         str(bundle_marker), "1"], run_dir, 15)
                    if code:
                        raise AssertionError(f"Broker ACL probe exited {code}")
                    result = json.loads((ipc_dir / "sandbox-probe.json").read_text(
                        encoding="utf-8"))
                    for key in ("outside_read", "outside_write", "bundle_write",
                                "hardlink_read", "registry_write", "parent_process_read"):
                        if result[key] == "allowed":
                            raise AssertionError(f"Broker ACL allowed {key}: {result}")
                    if result["host_child"].startswith("created"):
                        raise AssertionError("Broker ACL allowed a host child")
                    if summary_file.read_bytes() != b"harmless summary marker":
                        raise AssertionError("Broker changed the summary marker")
                    if input_file.read_bytes() != b"harmless staged input":
                        raise AssertionError("Broker changed the staged input")
                    print(json.dumps({"broker_run_acl": "passed", "observed": result},
                                     indent=2))
                finally:
                    box.revoke(ipc_dir)
                    box.revoke(run_dir)
                    box.revoke(EXE.parent)
        finally:
            bundle_marker.unlink(missing_ok=True)
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, registry_key)
            except FileNotFoundError:
                pass
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER,
                                 r"Software\EmumeeBrokerAclProbe")
            except (FileNotFoundError, PermissionError):
                pass


if __name__ == "__main__":
    main()

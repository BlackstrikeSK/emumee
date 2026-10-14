"""Check that only the broker AppContainer can open its private journal file."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import uuid
import winreg
from pathlib import Path

from emumee.appcontainer import AppContainer, BundleRunLock


ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "dist" / "Emumee" / "Emumee.exe"


def probe(box: AppContainer, run_dir: Path, journal: Path) -> dict:
    registry_key = f"Software\\EmumeeJournalProbe\\{uuid.uuid4().hex}"
    bundle_marker = EXE.parent / f"journal-probe-marker-{uuid.uuid4().hex}.txt"
    try:
        result = box.launch([str(EXE), "_sandbox_probe", str(run_dir), str(journal),
                             str(journal), str(os.getpid()), registry_key,
                             str(bundle_marker), "1"], run_dir, 15)
        if result:
            raise AssertionError(f"Sandbox probe exited with {result}")
        return json.loads((run_dir / "sandbox-probe.json").read_text(encoding="utf-8"))
    finally:
        bundle_marker.unlink(missing_ok=True)
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, registry_key)
        except FileNotFoundError:
            pass
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\EmumeeJournalProbe")
        except (FileNotFoundError, PermissionError):
            pass


def main() -> None:
    with tempfile.TemporaryDirectory(dir=ROOT / "output") as folder:
        run_dir = Path(folder)
        journal = ROOT / "output" / f".broker-journal-acl-{uuid.uuid4().hex}.journal"
        journal.write_bytes(b"probe")
        try:
            with BundleRunLock(EXE):
                for broker in (False, True):
                    with AppContainer(moniker=f"Emumee.JournalProbe.{uuid.uuid4().hex}",
                                      network=False, delete_on_close=True) as box:
                        box.grant(EXE.parent, "RX")
                        box.grant(run_dir, "M")
                        if broker:
                            box.grant(journal, "M")
                            acl = subprocess.run(["icacls", str(journal)], capture_output=True,
                                                 text=True, check=True)
                            print(acl.stdout.strip())
                        try:
                            observed = probe(box, run_dir, journal)
                            print("broker" if broker else "worker", observed["outside_read"],
                                  observed["outside_write"])
                            if any((observed[key] == "allowed") != broker
                                   for key in ("outside_read", "outside_write")):
                                raise AssertionError(
                                    f"Broker-only journal access mismatch: {observed}")
                            if not broker and any(observed[key] == "allowed"
                                                  for key in ("symlink_read", "hardlink_read")):
                                raise AssertionError(
                                    f"Worker followed a link to the private journal: {observed}")
                        finally:
                            if broker:
                                box.revoke(journal)
                            box.revoke(run_dir)
                            box.revoke(EXE.parent)
        finally:
            journal.unlink(missing_ok=True)


if __name__ == "__main__":
    main()

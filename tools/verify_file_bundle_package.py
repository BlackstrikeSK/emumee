"""Packaged checks for directory launch, bundled data, and discovered DLLs."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from emumee.persona import DEFAULT_PERSONA


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = (ROOT / "output").resolve()
FIXTURES = ROOT / "tests" / "fixtures"
RUNNER = ROOT / "dist" / "Emumee" / "Emumee.exe"


def run(*args: str) -> dict:
    process = subprocess.run([str(RUNNER), "run", *args, "--offline-replay"],
                             cwd=ROOT, capture_output=True, text=True, timeout=70)
    if not process.stdout:
        raise AssertionError(process.stderr)
    envelope = json.loads(process.stdout)
    summary = json.loads(Path(envelope["report"]).read_text(encoding="utf-8"))
    if envelope["status"] != "completed" or summary["status"] != "completed":
        raise AssertionError({"envelope": envelope, "stderr": process.stderr})
    return summary


with tempfile.TemporaryDirectory(dir=OUTPUT, prefix="bundle-package-") as folder:
    work = Path(folder).resolve()
    if not work.is_relative_to(OUTPUT):
        raise RuntimeError("Temporary bundle test escaped the output directory")
    native = work / "native"
    (native / "app" / "data").mkdir(parents=True)
    (native / "app" / "data" / "extra.bin").write_bytes(b"harmless nested extra")
    for arch in ("x86", "x64"):
        shutil.copyfile(FIXTURES / f"static_companion_{arch}.exe",
                        native / "app" / f"main_{arch}.exe")
        shutil.copyfile(FIXTURES / f"companion_{arch}.dll",
                        native / "app" / f"companion_{arch}.dll")
        summary = run(str(native), "--launch", f"app/main_{arch}.exe",
                      "--output", str(work / f"native-{arch}-runs"))
        assert summary["guest_exit_code"] == 42, summary
        assert any(item["name"] == f"companion_{arch}.dll"
                   for item in summary["run_manifest"]["companions"]), summary
        assert any(item["path"] == "app/data/extra.bin"
                   for item in summary["run_manifest"]["bundle_files"]), summary

    subprocess.run(["dotnet", "build", str(FIXTURES / "ManagedBundle" / "ManagedBundle.csproj"),
                    "-c", "Release"], cwd=ROOT, check=True,
                   capture_output=True, text=True, timeout=120)
    managed = work / "managed"
    (managed / "app" / "data").mkdir(parents=True)
    shutil.copyfile(FIXTURES / "ManagedBundle" / "bin" / "Release" / "net8.0" /
                    "ManagedBundle.dll", managed / "app" / "ManagedBundle.dll")
    (managed / "app" / "data" / "message.txt").write_bytes(b"managed bundle marker")
    summary = run(str(managed), "--launch", "app/ManagedBundle.dll",
                  "--output", str(work / "managed-runs"))
    assert any((Path(work / "managed-runs" / summary["id"] / "artifacts" / item["file"])
                .read_bytes() == b"managed bundle marker")
               for item in summary["artifacts"]), summary
    shutil.copyfile(FIXTURES / "ManagedBundle" / "bin" / "Release" / "net8.0" /
                    "ManagedBundle.exe", managed / "app" / "ManagedBundle.exe")
    summary = run(str(managed), "--launch", "app/ManagedBundle.exe",
                  "--output", str(work / "managed-apphost-runs"))
    assert summary["run_manifest"]["execution_target"]["via_managed_apphost"] is True
    assert any((work / "managed-apphost-runs" / summary["id"] / "artifacts" / item["file"])
               .read_bytes() == b"managed bundle marker"
               for item in summary["artifacts"]), summary

    supplement = work / "supplement"
    supplement.mkdir()
    (supplement / "readme.txt").write_bytes(b"supplemented readme marker")
    persona = json.loads(json.dumps(DEFAULT_PERSONA))
    persona["current_dir"] = r"C:\Users\Alex\Documents"
    persona_path = work / "persona.json"
    persona_path.write_text(json.dumps(persona), encoding="utf-8")
    summary = run(str(FIXTURES / "copy_config_x86.exe"),
                  "--files-dir", str(supplement), "--persona", str(persona_path),
                  "--output", str(work / "supplement-runs"))
    assert any((work / "supplement-runs" / summary["id"] / "artifacts" / item["file"])
               .read_bytes() == b"supplemented readme marker"
               for item in summary["artifacts"]), summary
    summary = run(str(FIXTURES / "copy_config_x86.exe"),
                  "--file", str(supplement / "readme.txt"),
                  "--persona", str(persona_path),
                  "--output", str(work / "single-file-runs"))
    assert any((work / "single-file-runs" / summary["id"] / "artifacts" / item["file"])
               .read_bytes() == b"supplemented readme marker"
               for item in summary["artifacts"]), summary

    host_marker = work / "host-marker.txt"
    host_marker.write_bytes(b"host marker unchanged")
    unsafe = work / "unsafe"
    unsafe.mkdir()
    shutil.copyfile(FIXTURES / "native_x86.exe", unsafe / "main.exe")
    (unsafe / "linked.txt").hardlink_to(host_marker)
    denied = subprocess.run([str(RUNNER), "run", str(unsafe), "--launch", "main.exe",
                             "--output", str(work / "unsafe-runs")],
                            cwd=ROOT, capture_output=True, text=True, timeout=20)
    assert denied.returncode == 2 and "link" in denied.stderr.lower(), denied
    assert host_marker.read_bytes() == b"host marker unchanged"
    print("packaged file bundle: native x86/x64 DLLs, managed DLL/apphost, nested data, directory/single extras, link denial passed")

"""Exercise an oversized embedded-resource length in the packaged worker."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

import dnfile

from emumee.reports import verify_artifact_manifest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "tests" / "fixtures" / "ManagedEmbeddedResource" / "bin" /
          "Release" / "net8.0" / "ManagedEmbeddedResource.dll")
BUNDLE = ROOT / "dist" / "Emumee" / "Emumee.exe"
OUTPUT = ROOT / "output" / "malformed-managed-resource-package"


def main() -> None:
    assert SOURCE.is_file() and BUNDLE.is_file()
    raw = bytearray(SOURCE.read_bytes())
    pe = dnfile.dnPE(data=raw)
    resource = pe.net.mdtables.ManifestResource.rows[0]
    header_offset = pe.get_offset_from_rva(pe.net.struct.ResourcesRva + resource.Offset)
    raw[header_offset:header_offset + 4] = (0x7FFFFFFF).to_bytes(4, "little")
    with tempfile.TemporaryDirectory(prefix="malformed-resource-", dir=ROOT) as folder:
        sample = Path(folder) / "malformed-resource.dll"
        sample.write_bytes(raw)
        proc = subprocess.run([str(BUNDLE), "run", str(sample), "--output", str(OUTPUT)],
                              cwd=ROOT, capture_output=True, text=True, timeout=90)
    assert proc.returncode == 1, (proc.returncode, proc.stdout, proc.stderr)
    result = json.loads(proc.stdout)
    summary_path = Path(result["report"])
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    run = summary_path.parent
    broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
    assert summary["status"] == "partial"
    assert summary["errors"] == ["Managed manifest resource exceeds limit"]
    assert summary["network_broker_complete"] is True
    assert verify_artifact_manifest(run, summary["artifacts"])
    assert not any(item["source"] == "managed_file_write" for item in summary["artifacts"])
    assert broker[-1] == {"event": "broker_closed"}
    print(f"packaged malformed managed resource: bounded partial result in {run}")


if __name__ == "__main__":
    main()

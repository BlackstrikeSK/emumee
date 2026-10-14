"""Bounded packaged parser smoke using mutations of harmless PE fixtures."""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import uuid
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
EXE = PROJECT / "dist" / "Emumee" / "Emumee.exe"
FIXTURES = (
    ("x86", PROJECT / "tests" / "fixtures" / "native_x86.exe"),
    ("x64", PROJECT / "tests" / "fixtures" / "native_x64.exe"),
    ("managed", PROJECT / "tests" / "fixtures" / "ManagedGzip" / "bin" /
     "Release" / "net8.0" / "ManagedGzip.dll"),
)


def mutations(data: bytes) -> list[tuple[str, bytes]]:
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe_offset + 24
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    magic = struct.unpack_from("<H", data, optional)[0]
    directory_offset = 112 if magic == 0x20B else 96
    cases = []
    for name, offset, value in (
        ("optional-magic", optional, b"\xff\xff"),
        ("import-range", optional + directory_offset + 8, b"\xff" * 8),
        ("entry-rva", optional + 16, b"\xff" * 4),
    ):
        changed = bytearray(data)
        changed[offset:offset + len(value)] = value
        cases.append((name, bytes(changed)))
    cut = min(len(data) - 1, optional + optional_size + 40)
    cases.append(("truncated-sections", data[:cut]))
    changed = bytearray(data)
    start = min(len(data) - 64, optional + optional_size + 128)
    for index in range(16):
        changed[start + index * 3] ^= (0x5A + index) & 0xFF
    cases.append(("section-bytes", bytes(changed)))
    return cases


def main() -> None:
    root = PROJECT / "output" / "malformed-pe-package" / uuid.uuid4().hex
    root.mkdir(parents=True)
    outcomes = []
    for architecture, fixture in FIXTURES:
        original = fixture.read_bytes()
        for variant, data in mutations(original):
            label = f"{architecture}-{variant}"
            sample = root / f"{label}{fixture.suffix}"
            sample.write_bytes(data)
            output = root / label
            result = subprocess.run(
                [str(EXE), "run", str(sample), "--output", str(output),
                 "--timeout", "6", "--max-instructions", "50000"],
                # Leave room for recursive bundle ACL cleanup on a busy host; the
                # guest itself still has the six-second execution limit above.
                cwd=PROJECT, capture_output=True, text=True, timeout=60,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            assert result.returncode in (0, 1, 2), (label, result.returncode,
                                                    result.stderr[-500:])
            summaries = list(output.glob("*/summary.json")) if output.exists() else []
            if result.returncode == 2:
                assert not summaries, f"{label}: rejected input wrote a run summary"
                assert "error:" in result.stderr.lower(), (label, result.stderr[-500:])
                status = "rejected"
            else:
                assert len(summaries) == 1, f"{label}: expected one summary"
                run_dir = summaries[0].parent
                summary = json.loads(summaries[0].read_text(encoding="utf-8"))
                status = summary["status"]
                assert status in {"completed", "partial", "failed", "timeout"}, (label, status)
                assert result.returncode == (0 if status == "completed" else 1), (label, status)
                assert summary["network_broker_complete"] is True, label
                if architecture != "managed" and variant in {"import-range", "entry-rva"}:
                    expected = ("import directory lies outside" if variant == "import-range"
                                else "entry point lies outside")
                    assert status == "failed" and any(
                        expected in error for error in summary.get("errors", [])), label
                if architecture != "managed" and variant in {"truncated-sections", "section-bytes"}:
                    assert status == "partial" and any(
                        "Native emulation error: invalid_read" in error
                        for error in summary.get("errors", [])), label
                for item in summary.get("artifacts", []):
                    payload = (run_dir / "artifacts" / item["file"]).read_bytes()
                    assert len(payload) == item["size"], label
                    assert hashlib.sha256(payload).hexdigest() == item["sha256"], label
            outcomes.append({"case": label, "status": status, "cli_exit": result.returncode})
            print(f"{label}: {status}", flush=True)
    (root / "outcomes.json").write_text(json.dumps(outcomes, indent=2), encoding="utf-8")
    print(f"packaged malformed PE corpus: {len(outcomes)} bounded cases in {root}")


if __name__ == "__main__":
    main()

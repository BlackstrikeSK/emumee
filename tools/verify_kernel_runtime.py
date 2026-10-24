"""Verify kernel formatting, Unicode and time outputs in the packaged worker."""

import datetime as dt
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.test_kernel_runtime import runtime_driver, legacy_format_probe
from emumee.persona import load_persona
from emumee.reports import valid_summary, verify_artifact_manifest


def verify(root, worker):
    root.mkdir(parents=True, exist_ok=False)
    persona = load_persona(None)
    persona["utc_offset_minutes"] = 120
    persona_path = root / "persona.json"
    persona_path.write_text(json.dumps(persona))
    moment = dt.datetime(2024, 2, 29, 23, 59, 58, 123456)
    delta = moment - dt.datetime(1601, 1, 1)
    ticks = (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10 + 7
    findings = []
    for machine, architecture in ((0x14C, "x86"), (0x8664, "x64")):
        base = 0x140000000 if machine == 0x8664 else 0x400000
        pointer_size = 8 if machine == 0x8664 else 4
        text = "-464 4294967338 emu"
        arguments = [base + 0x2400, 64, base + 0x2300, 0xFFFFFE30]
        arguments += [0x10000002A] if pointer_size == 8 else [42, 1]
        arguments += [base + 0x2380]
        formatted = runtime_driver(machine, ["swprintf_s"], [(0, arguments, True)],
            [(0x2300, "%d %I64u %s\0".encode("utf-16le")), (0x2380, "emu\0".encode("utf-16le"))])
        source = struct.pack("<HH", 6, 8) + (bytes(4) if pointer_size == 8 else b"") + (base + 0x2400).to_bytes(pointer_size, "little")
        duplicated = runtime_driver(machine, ["RtlDuplicateUnicodeString"], [(0, [3, base + 0x2300, base + 0x2320], False)],
            [(0x2300, source), (0x2400, "emu\0".encode("utf-16le"))])
        converted = runtime_driver(machine, ["ExSystemTimeToLocalTime", "RtlTimeToTimeFields"],
            [(0, [base + 0x2300, base + 0x2320], False), (1, [base + 0x2320, base + 0x2340], False)],
            [(0x2300, struct.pack("<q", ticks))], zero_return=True)
        for mode, payload, expected in (("format", formatted, len(text)), ("unicode", duplicated, 0), ("time", converted, 0),
                ("vaformat", legacy_format_probe(machine, 64), len(text)),
                ("vaexact", legacy_format_probe(machine, len(text)), len(text)),
                ("vatruncate", legacy_format_probe(machine, 3), 0xFFFFFFFF)):
            name = f"{architecture}-{mode}"
            sample = root / f"{name}.sys"
            sample.write_bytes(payload)
            process = subprocess.run([str(worker), "run", str(sample), "--output", str(root / name),
                "--persona", str(persona_path), "--offline-replay", "--timeout", "5", "--max-instructions", "2000"],
                text=True, capture_output=True, timeout=45)
            result = json.loads(process.stdout)
            run = Path(result["report"]).parent
            summary = json.loads((run / "summary.json").read_text())
            assert process.returncode == 0 and summary["status"] == "completed", (name, result)
            assert summary["guest_entry_return"] == expected, (name, result)
            assert valid_summary(summary) and verify_artifact_manifest(run, summary["artifacts"], summary["artifact_groups"]), name
            assert (run / "input.pe").read_bytes() == payload and summary["sample"]["sha256"] == hashlib.sha256(payload).hexdigest(), name
            assert not summary["api_coverage"]["signature_only_calls"], name
            assert summary["worker_containment"] and summary["network_broker_complete"], name
            assert json.loads((run / "network-broker.json").read_text()) == [{"event": "broker_closed"}], name
            assert hashlib.sha256((run / "engine-report.json").read_bytes()).hexdigest() == summary["engine_report_sha256"], name
            item = next(item for item in summary["artifacts"] if item["source"] == "modified_driver_image:0x2000")
            data = (run / "artifacts" / item["file"]).read_bytes()
            if mode == "format":
                assert data[0x400:0x400 + (len(text) + 1) * 2] == (text + "\0").encode("utf-16le"), name
            elif mode.startswith("va"):
                wanted = ((text + "\0").encode("utf-16le") if mode == "vaformat" else
                          (text[:3] if mode == "vatruncate" else text).encode("utf-16le"))
                assert data[0x400:0x480] == wanted + b"\xcd" * (128 - len(wanted)), name
            elif mode == "unicode":
                assert struct.unpack_from("<HH", data, 0x320) == (6, 8), name
                pool = next(item for item in summary["artifacts"] if "api.pool.PagedPool.Ustr" in item["source"])
                assert (run / "artifacts" / pool["file"]).read_bytes()[:8] == "emu\0".encode("utf-16le"), name
            else:
                assert struct.unpack_from("<q", data, 0x320)[0] == ticks + 7200 * 10_000_000, name
                assert struct.unpack_from("<8h", data, 0x340) == (2024, 3, 1, 1, 59, 58, 123, 5), name
            findings.append({"case": name, "verified": True, "report": str(run / "summary.json")})
            print(f"{name}: exact guest bytes, API contract, artifacts and isolation verified", flush=True)
    (root / "verification.json").write_text(json.dumps(findings, indent=2))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--worker", type=Path, default=ROOT / "dist/Emumee/Emumee.exe")
    args = parser.parse_args()
    verify(args.destination.resolve(), args.worker.resolve())

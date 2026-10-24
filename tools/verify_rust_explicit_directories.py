"""Exercise directory-only persona seeds through harmless native file callers."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from verify_rust_kernel_loader import load, sha, check, build_driver

SUCCESS = 0x44495231
NAME = r"\??\C:\Explicit\Logs\control.bin"


def fixture(present):
    base = 0x140000000
    image = bytearray(build_driver(0x8664))
    image[0x200:0x400] = bytes(512)
    image[0x400:] = bytes(512)
    struct.pack_into("<IIIII", image, 0x400, 0x2080, 0, 0, 0x2060, 0x20A0)
    image[0x460:0x46D] = b"ntoskrnl.exe\0"
    for index, (rva, name) in enumerate([(0x20D0, "IoCreateFileEx"), (0x2100, "ZwClose")]):
        for table in (0x480, 0x4A0):
            struct.pack_into("<Q", image, table + index * 8, rva)
        text = b"\0\0" + name.encode() + b"\0"
        start = rva - 0x2000 + 0x400
        image[start:start + len(text)] = text
    struct.pack_into("<I", image, 0x540, 48)
    struct.pack_into("<Q", image, 0x550, base + 0x2180)
    struct.pack_into("<I", image, 0x558, 0x240)
    name = NAME.encode("utf-16-le")
    struct.pack_into("<HH", image, 0x580, len(name), len(name) + 2)
    struct.pack_into("<Q", image, 0x588, base + 0x21A0)
    image[0x5A0:0x5A0 + len(name)] = name
    code = bytearray.fromhex("53 4881ec80000000")
    failures = []

    def lea(prefix, rva):
        code.extend(prefix + struct.pack("<i", rva - (0x1000 + len(code) + len(prefix) + 4)))

    def call(index):
        code.extend(b"\xff\x15" + struct.pack("<i", 0x20A0 + 8 * index - (0x1000 + len(code) + 6)))

    def require_equal():
        code.extend(bytes.fromhex("0f85")); failures.append(len(code)); code.extend(bytes(4))

    for index, value in enumerate([0, 0x80, 3, 3, 0x20, 0, 0, 0, 0, 0, 0]):
        code.extend(bytes.fromhex("48c74424") + bytes([0x20 + index * 8]) + struct.pack("<I", value))
    lea(bytes.fromhex("488d0d"), 0x21F8)
    code.extend(bytes.fromhex("ba000000c0"))
    lea(bytes.fromhex("4c8d05"), 0x2140)
    lea(bytes.fromhex("4c8d0d"), 0x21E8)
    call(0)
    code.extend(b"\x3d" + struct.pack("<I", 0 if present else 0xC000003A)); require_equal()
    code.extend(bytes.fromhex("813d") + struct.pack("<i", 0x21E8 - (0x1000 + len(code) + 10)) + struct.pack("<I", 0 if present else 0xC000003A)); require_equal()
    if present:
        lea(bytes.fromhex("488b0d"), 0x21F8)
        call(1)
        code.extend(bytes.fromhex("85c0")); require_equal()
    code.extend(b"\xb8" + struct.pack("<I", SUCCESS) + bytes.fromhex("4881c480000000 5b c3"))
    failed = len(code)
    code.extend(bytes.fromhex("b80d0000c0 4881c480000000 5b c3"))
    for offset in failures:
        struct.pack_into("<i", code, offset, failed - offset - 4)
    check(len(code) <= 512, "Generated file caller exceeds text section")
    image[0x200:0x200 + len(code)] = code
    return image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    bundle, root = args.bundle.resolve(), args.root.resolve()
    check(not root.exists() or args.resume, "Preserve controls; fresh root or --resume required")
    receipt = load(bundle / "rust-worker-build.json")
    for name, key in [("emumee-rs.exe", "controller_sha256"), ("emumee-worker.exe", "worker_sha256"), ("unicorn.dll", "unicorn_sha256")]:
        check(sha(bundle / name) == receipt[key], "Frozen binary differs from receipt")
    root.mkdir(exist_ok=args.resume)
    records = []
    for present in (False, True):
        name = "present" if present else "absent"
        source, persona, run = root / f"{name}.sys", root / f"{name}.persona.json", root / name
        model = {"clock_utc": "2026-10-19T16:03:01Z", "registry_keys": [], "virtual_files": []}
        if present:
            model["virtual_directories"] = [r"C:\Explicit\Logs"]
        generated = fixture(present)
        if source.exists():
            check(source.read_bytes() == generated and load(persona) == model, "Saved generated input/persona changed")
        else:
            source.write_bytes(generated); persona.write_text(json.dumps(model, indent=2) + "\n")
        if run.exists():
            check(args.resume, "Existing run requires --resume")
        else:
            with (root / f"{name}.console.log").open("wb") as out:
                process = subprocess.run([str(bundle / "emumee-rs.exe"), "submitted-driver", str(source), str(run), "--service", "DirControl", "--max-instructions", "1000", "--timeout-us", "30000000", "--persona", str(persona)], stdout=out, stderr=subprocess.STDOUT)
            check(process.returncode == 0, "Generated directory control did not process")
        m, request, result, report = [load(run / n) for n in ("controller-manifest.json", "request.json", "worker-result.json", "engine-report.json")]
        check(m["status"] == "verified" and m["guest_status"] == result["status"] == "processed" and m["cleanup"] == "restored" and not m["unpacking_confirmed"], "Controller result differs")
        for key in ("source_tree_sha256", "controller_sha256", "worker_sha256", "unicorn_sha256"):
            check(m[key] == receipt[key], "Control used another frozen build")
        check(m["worker_result_sha256"] == sha(run / "worker-result.json") and result["engine_report_sha256"] == sha(run / "engine-report.json"), "Report/result binding differs")
        check(m["persona_source_sha256"] == sha(persona) and m["persona_sha256"] == sha(run / "persona.json") == request["persona_sha256"], "Persona source/resolution binding differs")
        for row in (m, result["binding"], report["binding"]):
            check(row["request_sha256"] == sha(run / "request.json") and row["input_sha256"] == sha(source) == sha(run / "input.sys") and row["source_tree_sha256"] == receipt["source_tree_sha256"], "Generated source/request/input differs")
        witness, job, exit_record = [load(run / n) for n in ("worker-containment.json", "driver-job-profile.json", "worker-exit.json")]
        check(witness["app_container"] and witness["job_object"] and witness["child_process_blocked"] and witness["network_capabilities"] == 0 and job["active_process_limit"] == 1 and job["process_memory_bytes"] == 2147483648 and job["cleanup"] == exit_record["cleanup"] == load(run / "worker-stop.json")["cleanup"] == "restored" and exit_record["exit_code"] == 0, "Offline containment/cleanup differs")
        e = report["execution"]
        check(e["completion_reason"] == "entry_return" and e["guest_entry_return"] == SUCCESS and e["error"] is None and e["network"]["calls"] == 0 and e["configuration"]["seeded_files"] == 0, "Native directory/file assertions failed or dummy file seed appeared")
        events = e["kernel_files"]["events"]
        check(events[0]["operation"] == "create" and events[0]["status"] == (0 if present else 0xC000003A) and e["api_calls"] == (2 if present else 1) and not e["kernel_files"]["native_effect_failure"] and not e["kernel_files"]["handles"]["live"], "Real VFS result or handle lifetime differs")
        files = e["kernel_files"]
        check(files["completed_create_requests"] == 1 and files["create_request_receipt_limit"] == 64 and files["create_request_receipts_omitted"] == 0 and len(files["create_request_receipts"]) == 1, "Completed VFS create count/bound differs")
        created = files["create_request_receipts"][0]
        check(created["name"] == NAME and not created["name_truncated"] and created["name_utf16_units"] == len(NAME.encode("utf-16-le")) // 2 and created["name_utf16_sha256"] == hashlib.sha256(NAME.encode("utf-16-le")).hexdigest(), "Parsed VFS request name/hash differs")
        check(created["root_handle"] == 0 and created["desired_access"] == 0xC0000000 and created["share_access"] == 3 and created["create_disposition"] == 3 and created["create_options"] == 0x20 and created["status"] == events[0]["status"] and created["information"] == events[0]["information"] and created["instruction_count"] == e["api_events"][0]["instruction_ordinal"], "Completed VFS request arguments/status/position differ")
        records.append({"case": name, "verified": True, "source_tree_sha256": receipt["source_tree_sha256"], "run": str(run), "seeded_files": 0, "create_status": events[0]["status"], "cleanup": "restored", "unpacking_confirmed": False})
        (root / "verification.json").write_text(json.dumps(records, indent=2) + "\n")
    print("Verified 2 harmless directory-only native file controls; no dummy input files or host I/O.")


if __name__ == "__main__":
    main()

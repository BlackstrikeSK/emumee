"""Exercise owned loader metadata with harmless generated submitted drivers."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.fixtures.build_driver import build_driver

REFERENCE = "4b954aae4b18a231b2254c0989b1b6bcc55741a8ef90a350f036d09cd480cc99"
PDB = "5eea0257091c91a86da4a1633248723eb07f08f6d2718447ed4c0a95706790f5"
HEAD = 0xFFFFA10000200000
SUCCESS = 0x4C445231


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(value, message):
    if not value:
        raise ValueError(message)


def fixture(kind):
    image = bytearray(build_driver(0x8664))
    image[0x200:0x400] = bytes(0x200)
    image[0x400:] = bytes(0x200)
    struct.pack_into("<IIIII", image, 0x400, 0x2080, 0, 0, 0x2060, 0x20A0)
    image[0x460:0x46D] = b"ntoskrnl.exe\0"
    for table in (0x480, 0x4A0):
        struct.pack_into("<Q", image, table, 0x20D0)
    symbol = b"\0\0RtlCopyMemory\0"
    image[0x4D0:0x4D0 + len(symbol)] = symbol
    code, failures = bytearray(b"\x53\x48\x83\xec\x30\x48\x89\xcb"), []

    def emit(data):
        code.extend(data)

    def require(op=b"\x85", condition=b"\xc0", jump=b"\x84"):
        emit(op + condition + b"\x0f" + jump)
        failures.append(len(code))
        emit(bytes(4))

    # RBX is the actual DriverObject; RAX is its declared DriverSection.
    emit(b"\x48\x8b\x43\x28")
    if kind == "unpinned":
        require(b"\x48\x85", jump=b"\x85")
    else:
        require(b"\x48\x85")
        emit(b"\x48\x8b\x50\x30\x48\x3b\x53\x18")
        require(b"", b"", b"\x85")
        emit(b"\x48\x8b\x50\x38\x48\x3b\x53\x58")
        require(b"", b"", b"\x85")
        emit(b"\x8b\x50\x40\x3b\x53\x20")
        require(b"", b"", b"\x85")
        if kind == "read":
            # Native forward/backward list consistency, bounded at 256 links.
            emit(b"\x49\xb8" + struct.pack("<Q", HEAD) + b"\x4d\x8b\x08\x41\xba\x00\x01\x00\x00")
            loop = len(code)
            emit(b"\x4d\x8b\x19\x4d\x39\x4b\x08")
            require(b"", b"", b"\x85")
            emit(b"\x4d\x89\xd9\x4d\x39\xc1\x0f\x84")
            end_jump = len(code)
            emit(bytes(4) + b"\x41\xff\xca")
            require(b"", b"", b"\x84")
            emit(b"\xe9" + struct.pack("<i", loop - len(code) - 5))
            struct.pack_into("<i", code, end_jump, len(code) - end_jump - 4)
            # API copy of the contiguous base/entry/size view is permitted.
            emit(b"\x48\x8d\x50\x30")
            emit(b"\x48\x8d\x0d" + struct.pack("<i", 0x2180 - (0x1000 + len(code) + 7)))
            emit(b"\x41\xb8\x14\x00\x00\x00")
            emit(b"\xff\x15" + struct.pack("<i", 0x20A0 - (0x1000 + len(code) + 6)))
            emit(b"\x48\x8b\x05" + struct.pack("<i", 0x2180 - (0x1000 + len(code) + 7)))
            emit(b"\x48\x3b\x43\x18")
            require(b"", b"", b"\x85")
        elif kind == "private":
            emit(b"\x48\x8b\x40\x10")
        elif kind == "cross":
            emit(b"\x48\x8b\x40\x40")  # size plus unsupported alignment padding
        elif kind == "api-private":
            emit(b"\x48\x8d\x50\x10\x48\x8d\x0d" + struct.pack("<i", 0x2180 - (0x1000 + len(code) + 11)))
            emit(b"\x41\xb8\x08\x00\x00\x00")
            emit(b"\xff\x15" + struct.pack("<i", 0x20A0 - (0x1000 + len(code) + 6)))
        elif kind == "write":
            emit(b"\xc6\x40\x30\x00")
        elif kind == "fetch":
            emit(b"\xff\xd0")
    emit(b"\xb8" + struct.pack("<I", SUCCESS) + b"\x48\x83\xc4\x30\x5b\xc3")
    failed = len(code)
    emit(b"\xb8\x0d\x00\x00\xc0\x48\x83\xc4\x30\x5b\xc3")
    for offset in failures:
        struct.pack_into("<i", code, offset, failed - offset - 4)
    check(len(code) <= 0x200, "Generated loader test exceeds its code page")
    image[0x200:0x200 + len(code)] = code
    return image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--resume", action="store_true", help="Reverify completed receipts without rerunning workers")
    args = parser.parse_args()
    bundle, root, reference = args.bundle.resolve(), args.root.resolve(), args.reference.resolve()
    check(not root.exists() or args.resume, "Preserve completed controls; use a fresh root or --resume")
    check(sha(reference) == REFERENCE, "Only exact pinned reference is admitted")
    receipt = load(bundle / "rust-worker-build.json")
    for name, key in [("emumee-rs.exe", "controller_sha256"), ("emumee-worker.exe", "worker_sha256"), ("unicorn.dll", "unicorn_sha256")]:
        check(sha(bundle / name) == receipt[key], "Frozen binary differs from receipt")
    root.mkdir(exist_ok=args.resume)
    records = []
    for kind in ("read", "private", "cross", "api-private", "write", "fetch", "unpinned"):
        source, run = root / f"{kind}.sys", root / f"submitted-{kind}"
        generated = fixture(kind)
        if source.exists():
            check(source.read_bytes() == generated, "Saved generated input changed")
        else:
            source.write_bytes(generated)
        command = [str(bundle / "emumee-rs.exe"), "submitted-driver", str(source), str(run), "--service", "LoaderControl", "--max-instructions", "10000", "--timeout-us", "30000000"]
        if kind != "unpinned":
            command += ["--kernel-code-reference", str(reference)]
        if not run.exists():
            with (root / f"{kind}.console.log").open("wb") as out:
                process = subprocess.run(command, stdout=out, stderr=subprocess.STDOUT)
            check(process.returncode == 0, "Packaged generated loader control was not processed")
        else:
            check(args.resume, "Existing run requires explicit --resume")
        manifest, request = load(run / "controller-manifest.json"), load(run / "request.json")
        result, report = load(run / "worker-result.json"), load(run / "engine-report.json")
        witness, job = load(run / "worker-containment.json"), load(run / "driver-job-profile.json")
        stop, exit_record = load(run / "worker-stop.json"), load(run / "worker-exit.json")
        check(manifest["status"] == "verified" and manifest["guest_status"] == result["status"] == "processed" and not manifest["unpacking_confirmed"], "Controller status differs")
        for key in ("source_tree_sha256", "controller_sha256", "worker_sha256", "unicorn_sha256"):
            check(manifest[key] == receipt[key], "Control belongs to another frozen build")
        check(manifest["worker_result_sha256"] == sha(run / "worker-result.json") and result["engine_report_sha256"] == sha(run / "engine-report.json"), "Report/result binding differs")
        for row in (manifest, result["binding"], report["binding"]):
            check(row["request_sha256"] == sha(run / "request.json") and row["input_sha256"] == sha(source) and row["source_tree_sha256"] == receipt["source_tree_sha256"], "Input/request/source binding differs")
        check(sha(run / "input.sys") == sha(source) and request["max_instructions"] == 10000, "Staged generated input or budget differs")
        expected_reference = None if kind == "unpinned" else REFERENCE
        for row in (manifest, request, result["binding"]):
            check(row.get("kernel_code_reference_sha256") == expected_reference, "Request/reference authority binding differs")
        if expected_reference:
            check(sha(run / "kernel-code-reference.pe") == REFERENCE, "Staged reference changed")
        check(witness["app_container"] and witness["job_object"] and witness["child_process_blocked"] and witness["network_capabilities"] == 0 and job["active_process_limit"] == 1 and job["profile"] == "driver_capture_2048_v1" and job["process_memory_bytes"] == 2147483648 and 0 < job["peak_process_memory_bytes"] <= 2147483648, "Offline containment differs")
        check(all(row["cleanup"] == "restored" for row in (manifest, job, stop, exit_record)) and exit_record["exit_code"] == 0, "Worker cleanup differs")
        e, loader = report["execution"], report["execution"]["kernel_loader"]
        check(e["network"]["calls"] == 0, "Unexpected network activity")
        if kind in ("read", "unpinned"):
            check(e["completion_reason"] == "entry_return" and e["guest_entry_return"] == SUCCESS and e["error"] is None, "Generated native assertions failed")
        else:
            errors = {"private": "Private kernel loader metadata", "cross": "Private kernel loader metadata", "api-private": "Owned kernel loader metadata", "write": "write refused", "fetch": "FETCH_PROT"}
            check(e["completion_reason"] == "error" and e["guest_entry_return"] is None and errors[kind] in e["error"], "Unsupported metadata access escaped its boundary")
        if kind == "unpinned":
            check(loader is None, "Unpinned submitted input invented private ABI authority")
        else:
            check(loader["profile"] == "pinned-reference-x64-kldr-v1" and loader["reference_sha256"] == REFERENCE and loader["pdb_sha256"] == PDB and not loader["generated_fixture"], "Loader profile authority differs")
            check(loader["native_read_guard_installed"] and loader["native_write_guard_installed"] and loader["native_reads"] >= 3 and loader["list_head"] == HEAD, "Native permitted dereferences or guards absent")
            check({(n["name"], n["image_base"], n["image_size"]) for n in loader["nodes"]} == {(n["name"], n["base"], n["size"]) for n in e["loaded_modules"]}, "Loader list differs from actual mapped module catalog")
            primary = next(n for n in loader["nodes"] if n["address"] == loader["driver_section"])
            check(primary["image_base"] == e["image_load"]["base"] and primary["entry_point"] == e["image_load"]["entry"] and primary["image_size"] == e["image_load"]["size"] and primary["accepted_image_sha256"] == sha(source), "DriverSection is not the primary image record")
            check(all(n["entry_point"] == 0 for n in loader["nodes"] if n["origin"] == "synthetic_provider"), "Synthetic provider invented a callable entry")
            if kind == "read":
                check(not loader["denials"] and e["api_calls"] == 1, "Permitted native/API metadata use failed")
        records.append({"case": kind, "verified": True, "source_tree_sha256": receipt["source_tree_sha256"], "run": str(run), "input_sha256": sha(source), "completion": e["completion_reason"], "error": e["error"], "cleanup": "restored", "unpacking_confirmed": False})
        (root / "verification.json").write_text(json.dumps(records, indent=2) + "\n")
    print("Verified 7 harmless submitted loader metadata controls; no unpacking claimed.")


if __name__ == "__main__":
    main()

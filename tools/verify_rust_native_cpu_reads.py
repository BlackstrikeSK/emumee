"""Verify passive native CPU read evidence using harmless generated programs."""
import argparse
import json
from pathlib import Path
import struct
import subprocess

from verify_rust_kernel_loader import load, sha, check, build_driver

SUCCESS = 0x43505531


def fixture(kind):
    image = bytearray(build_driver(0x8664))
    image[0x200:0x400] = bytes(0x200)
    if kind == "read":
        # Native values are checked by the guest before returning. CR3 is read
        # to R8 through REX.B; MSR defaults refer only to the pinned backend.
        code = bytearray.fromhex("0f20d0 4885c0 0f85") + bytes(4)
        failures = [len(code) - 4]
        code += bytes.fromhex("490f20d8 4d85c0 0f85") + bytes(4)
        failures.append(len(code) - 4)
        code += bytes.fromhex("b9800000c0 0f32 a900080000 0f84") + bytes(4)
        failures.append(len(code) - 4)
        code += bytes.fromhex("b9efbeadde 0f32 09d0 0f85") + bytes(4)
        failures.append(len(code) - 4)
        code += b"\xb8" + struct.pack("<I", SUCCESS) + b"\xc3"
        failed = len(code)
        code += bytes.fromhex("b80d0000c0 c3")
        for offset in failures:
            struct.pack_into("<i", code, offset, failed - offset - 4)
    elif kind == "cap":
        code = bytearray.fromhex("b904010000 0f20d8 ffc9 75f9")
        code += b"\xb8" + struct.pack("<I", SUCCESS) + b"\xc3"
    elif kind == "budget":
        code = bytearray.fromhex("0f20d8") + b"\xb8" + struct.pack("<I", SUCCESS) + b"\xc3"
    elif kind == "fault":
        code = bytearray.fromhex("0f20c8") + b"\xb8" + struct.pack("<I", SUCCESS) + b"\xc3"
    else:
        raise ValueError(kind)
    check(len(code) <= 512, "Generated CPU probe exceeds code section")
    image[0x200:0x200 + len(code)] = code
    return image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    bundle, root = args.bundle.resolve(), args.root.resolve()
    check(not root.exists() or args.resume, "Preserve controls; use a fresh root or --resume")
    receipt = load(bundle / "rust-worker-build.json")
    for name, key in [("emumee-rs.exe", "controller_sha256"), ("emumee-worker.exe", "worker_sha256"), ("unicorn.dll", "unicorn_sha256")]:
        check(sha(bundle / name) == receipt[key], "Frozen binary differs from receipt")
    root.mkdir(exist_ok=args.resume)
    records = []
    cases = [("x86-kernel-cpu", "x86", None), ("x64-kernel-cpu", "x64", None)]
    cases += [(kind, "x64", kind) for kind in ("read", "cap", "budget", "fault")]
    for name, arch, kind in cases:
        run = root / name
        if kind:
            source = root / f"{name}.sys"
            generated = fixture(kind)
            if source.exists():
                check(source.read_bytes() == generated, "Saved generated input changed")
            else:
                source.write_bytes(generated)
            command = [str(bundle / "emumee-rs.exe"), "submitted-driver", str(source), str(run), "--service", "CpuControl", "--max-instructions", "1" if kind == "budget" else "10000", "--timeout-us", "30000000"]
        else:
            command = [str(bundle / "emumee-rs.exe"), "fixture", "--arch", arch, "--kind", "kernel-cpu", "--max-instructions", "10000", "--isolated-output", str(run)]
        if run.exists():
            check(args.resume, "Existing control requires --resume")
        else:
            with (root / f"{name}.console.log").open("wb") as out:
                process = subprocess.run(command, stdout=out, stderr=subprocess.STDOUT)
            check(process.returncode == 0, "Generated CPU control did not process")
        if kind:
            manifest, request = load(run / "controller-manifest.json"), load(run / "request.json")
            result, report = load(run / "worker-result.json"), load(run / "engine-report.json")
            e = report["execution"]
            check(manifest["status"] == "verified" and manifest["guest_status"] == result["status"] == "processed" and not manifest["unpacking_confirmed"], "Submitted controller status differs")
            check(manifest["worker_result_sha256"] == sha(run / "worker-result.json") and result["engine_report_sha256"] == sha(run / "engine-report.json"), "Submitted report binding differs")
            for row in (manifest, result["binding"], report["binding"]):
                check(row["request_sha256"] == sha(run / "request.json") and row["input_sha256"] == sha(source) and row["source_tree_sha256"] == receipt["source_tree_sha256"], "Submitted input/request/source differs")
            check(sha(run / "input.sys") == sha(source) and request["max_instructions"] == (1 if kind == "budget" else 10000), "Staged generated input or budget changed")
            witness, job = load(run / "worker-containment.json"), load(run / "driver-job-profile.json")
            check(witness["app_container"] and witness["job_object"] and witness["child_process_blocked"] and witness["network_capabilities"] == 0 and job["active_process_limit"] == 1, "Submitted offline containment differs")
            check(all(load(run / file)["cleanup"] == "restored" for file in ("controller-manifest.json", "driver-job-profile.json", "worker-stop.json", "worker-exit.json")) and load(run / "worker-exit.json")["exit_code"] == 0, "Submitted cleanup differs")
        else:
            manifest, result = load(run / "manifest.json"), load(run / "fixture-result.json")
            e = result["execution"]
            check(manifest["request_sha256"] == sha(run / "request.json") and manifest["result_sha256"] == sha(run / "fixture-result.json") and result["request_sha256"] == manifest["request_sha256"] and manifest["result"] == result, "Closed fixture binding differs")
            witness = result["containment"]
            check(witness["app_container"] and witness["job_object"] and witness["child_process_blocked"] and witness["network_capabilities"] == 0 and manifest["cleanup"] == load(run / "worker-exit.json")["cleanup"] == "restored" and load(run / "worker-exit.json")["exit_code"] == 0, "Closed fixture containment/cleanup differs")
        for key in ("source_tree_sha256", "controller_sha256", "worker_sha256", "unicorn_sha256"):
            check(manifest[key] == receipt[key], "Control used another frozen bundle")
        check(e["architecture"] == arch and e["network"]["calls"] == 0, "Architecture or network differs")
        if kind == "fault":
            check(e["completion_reason"] == "error" and e["guest_entry_return"] is None and e["error"], "Invalid native CR read invented completion")
        elif kind == "budget":
            check(e["completion_reason"] == "instruction_budget" and e["instruction_count"] == 1 and e["guest_entry_return"] is None, "Budget prefix invented entry return")
        else:
            check(e["completion_reason"] == "entry_return" and e["guest_entry_return"] == (SUCCESS if kind else 1) and e["error"] is None, "Native guest value assertions failed")
        observation = e.get("native_cpu_reads")
        if kind == "fault":
            # This reserved CR operand is rejected during translation, before
            # the ordinary instruction hook can honestly report an attempt.
            check(observation is None, "Translation rejection invented an admitted native read")
            rows = []
        else:
            check(observation is not None and observation["limit"] == 256 and observation["observation_failures"] == 0, "Native observation bound or sampling differs")
            rows = observation["attempts"]
            check(observation["omitted_attempts"] == (4 if kind == "cap" else 0), "Omitted attempt count differs")
            check(len(rows) == (256 if kind == "cap" else 1 if kind == "budget" else 4 if kind == "read" else 3), "Native attempt count differs")
            for row in rows:
                check(row["architecture"] == arch and 1 <= row["size"] <= 15 and row["pc"] > 0 and 0 < row["instruction_count"] <= e["instruction_count"] and row["thread_id"] == 1 and row["current_thread"] == e["kernel_cpu"]["current_thread"] and row["processor"] == 0 and row["execution_domain"] == "ordinary_thread", "Native attempt execution context differs")
                if kind == "budget":
                    check(row["completion"] == "run_stopped_before_next_instruction" and row["observed_value"] is None and row["observation_error"] == "instruction_budget", "Budget prefix invented a native result")
                else:
                    check(row["completion"] == "observed_next_instruction" and isinstance(row["observed_value"], int) and row["observation_error"] is None, "Completed native result is incomplete or invented")
            controls = [row for row in rows if row["kind"] == "control_register"]
            msrs = [row for row in rows if row["kind"] == "msr"]
            if kind in ("cap", "budget"):
                check(all(row["control_register"] == 3 and row["msr_index"] is None for row in controls) and len(controls) == len(rows), "CR3 attempt identity differs")
            elif kind == "read":
                check([(r["control_register"], r["destination"], r["observed_value"]) for r in controls] == [(2, "rax", 0), (3, "r8", 0)], "Native CR2 or prefixed CR3 result differs from guest assertions")
                check([r["msr_index"] for r in msrs] == [0xC0000080, 0xDEADBEEF] and msrs[0]["observed_value"] & 0x800 and msrs[1]["observed_value"] == 0 and msrs[1]["backend"] == "native_backend_unmodeled_index_default_unverified", "Seeded/default backend MSR evidence differs")
            else:
                initial = e["kernel_cpu"]["initial"]
                check([(r["control_register"], r["observed_value"]) for r in controls] == [(0, initial["cr0"]), (4, initial["cr4"])], "Closed fixture native CR0/4 results differ")
                check(len(msrs) == 1 and msrs[0]["msr_index"] == 0xC0000080 and msrs[0]["observed_value"] == initial["efer"], "Closed fixture native EFER result differs")
        records.append({"case": name, "verified": True, "run": str(run), "source_tree_sha256": receipt["source_tree_sha256"], "completion": e["completion_reason"], "cleanup": "restored", "unpacking_confirmed": False})
        (root / "verification.json").write_text(json.dumps(records, indent=2) + "\n")
    print("Verified 6 harmless native CPU read controls; no real driver or unpacking claimed.")


if __name__ == "__main__":
    main()

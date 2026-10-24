"""Verify passive final-page stack-writer receipts with harmless offline fixtures.

Generated PE files are inert inputs to the packaged AppContainer worker. This
checks observed native prewrite attempts, never byte values or store retirement.
The production submitted-driver command is x64-only; closed kernel-entry
fixtures check observer installation on both widths, while Rust source tests
cover precise x86 store behavior.
"""
import argparse
import json
from pathlib import Path
import struct
import subprocess

from verify_rust_kernel_loader import build_driver, check, load, sha

SUCCESS = 0x53545731
STACK = {"x86": 0xB0000000, "x64": 0xFFFFA00000000000}
STACK_SIZE = 0x100000
PAGE = 4096


def fixture(kind):
    image = bytearray(build_driver(0x8664))
    if kind == "identical":
        store = bytes.fromhex("48c744242078563412")  # MOV QWORD [RSP+20h],12345678h
        code = store + store
    elif kind in ("cross", "fault"):
        page = STACK["x64"] + STACK_SIZE - PAGE
        address = (page if kind == "cross" else page + PAGE) - 4
        code = b"\x48\xb8" + struct.pack("<Q", address)
        code += bytes.fromhex("48c70078563412")  # MOV QWORD [RAX],12345678h
    elif kind == "budget":
        code = bytes.fromhex("48c744242078563412")
        code += bytes.fromhex("48c744242878563412")
    else:
        raise ValueError(kind)
    code += b"\xb8" + struct.pack("<I", SUCCESS) + b"\xc3"
    check(len(code) <= 512, "Generated stack probe exceeds text section")
    image[0x200:0x400] = code + bytes(512 - len(code))
    return bytes(image)


def receipt_scope(e, arch):
    report = e["kernel_stack_writes"]
    stack = STACK[arch]
    page = stack + STACK_SIZE - PAGE
    check(report is not None and report["stack_base"] == stack
          and report["stack_size"] == STACK_SIZE and report["watched_page"] == page
          and report["native_hook_start"] == stack
          and report["native_hook_end_inclusive"] == stack + STACK_SIZE - 1,
          "Owned stack observer geometry differs")
    ranges = report["last_observed_ranges"]
    check(0 <= report["observed_bytes"] <= PAGE
          and sum(row["size"] for row in ranges) == report["observed_bytes"]
          and report["model_overlapping_writes"] >= 1
          and report["native_overlapping_attempts"] >= 0,
          "Observed byte/range bound or entry setup write differs")
    previous = page
    for row in ranges:
        writer = row["writer"]
        check(page <= row["address"] < page + PAGE
              and 0 < row["size"] <= page + PAGE - row["address"]
              and row["address"] >= previous
              and writer["sequence"] > 0
              and writer["raw_instruction_count"] <= e["instruction_count"]
              and writer["source"] in ("native_prewrite_attempt", "model_mem_write_succeeded",
                                       "model_mem_write_failed_partial_effects_unknown")
              and writer["write_size"] > 0
              and writer["write_address"] <= row["address"]
              and row["address"] + row["size"] <= writer["write_address"] + writer["write_size"],
              "Last-observed range lacks a bounded overlapping writer")
        previous = row["address"] + row["size"]
        if writer["source"] == "native_prewrite_attempt":
            check(writer["pc"] is not None and writer["raw_instruction_count"] > 0,
                  "Native prewrite lost admitted instruction position")
    check("pre-write attempts" in report["scope"]
          and "not completed stores or retirement" in report["scope"],
          "Report overstates native write evidence")
    return report


def verify_bound_run(bundle, build, run, source, kind, budget):
    manifest, request = load(run / "controller-manifest.json"), load(run / "request.json")
    result, report = load(run / "worker-result.json"), load(run / "engine-report.json")
    witness, job = load(run / "worker-containment.json"), load(run / "driver-job-profile.json")
    stop, exit_record = load(run / "worker-stop.json"), load(run / "worker-exit.json")
    check(manifest["status"] == "verified" and manifest["guest_status"] == result["status"] == "processed"
          and not manifest["unpacking_confirmed"], "Generated submitted status differs")
    for key in ("source_tree_sha256", "controller_sha256", "worker_sha256", "unicorn_sha256"):
        check(manifest[key] == build[key], "Control belongs to another frozen build")
    for row in (manifest, result["binding"], report["binding"]):
        check(row["request_sha256"] == sha(run / "request.json")
              and row["input_sha256"] == sha(source) == sha(run / "input.sys")
              and row["source_tree_sha256"] == build["source_tree_sha256"]
              and row["containment_sha256"] == sha(run / "worker-containment.json"),
              "Generated input/request/containment binding differs")
    check(manifest["worker_result_sha256"] == sha(run / "worker-result.json")
          and result["engine_report_sha256"] == sha(run / "engine-report.json")
          and request["max_instructions"] == budget,
          "Submitted result/report/budget binding differs")
    check(witness["app_container"] and witness["job_object"] and witness["child_process_blocked"]
          and witness["network_capabilities"] == 0 and job["active_process_limit"] == 1
          and job["process_memory_bytes"] == 2147483648
          and 0 < job["peak_process_memory_bytes"] <= job["process_memory_bytes"],
          "Packaged worker containment differs")
    check(all(row["cleanup"] == "restored" for row in (manifest, job, stop, exit_record))
          and exit_record["exit_code"] == 0 and stop["worker"]["reason"] == "exited"
          and stop["worker"]["exit_code"] == 0,
          "Packaged worker exit or cleanup differs")
    e = report["execution"]
    check(e["architecture"] == "x64" and e["network"]["calls"] == 0
          and e["kernel_entry"] is not None,
          "Generated program escaped x64 offline kernel scope")
    return e


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--resume", action="store_true", help="Reverify saved runs without relaunching")
    args = parser.parse_args()
    bundle, root = args.bundle.resolve(), args.root.resolve()
    check(root.is_dir() if args.resume else not root.exists(),
          "Use a fresh root, or explicitly --resume prior evidence")
    build = load(bundle / "rust-worker-build.json")
    for file, key in (("emumee-rs.exe", "controller_sha256"),
                      ("emumee-worker.exe", "worker_sha256"), ("unicorn.dll", "unicorn_sha256")):
        check(sha(bundle / file) == build[key], "Frozen binary differs from build receipt")
    if not args.resume:
        root.mkdir()
    records = []
    for arch in ("x86", "x64"):
        run = root / f"closed-{arch}-kernel-entry"
        if args.resume:
            check(run.is_dir(), "Missing saved closed fixture; refuse partial rerun")
        else:
            command = [str(bundle / "emumee-rs.exe"), "fixture", "--arch", arch,
                       "--kind", "kernel-entry", "--max-instructions", "10000",
                       "--isolated-output", str(run)]
            with (root / f"closed-{arch}.console.log").open("wb") as out:
                process = subprocess.run(command, stdout=out, stderr=subprocess.STDOUT)
            check(process.returncode == 0, "Closed kernel-entry control failed")
        manifest, result = load(run / "manifest.json"), load(run / "fixture-result.json")
        check(manifest["request_sha256"] == result["request_sha256"] == sha(run / "request.json")
              and manifest["result_sha256"] == sha(run / "fixture-result.json")
              and manifest["result"] == result,
              "Closed fixture request/result differs")
        for key in ("source_tree_sha256", "controller_sha256", "worker_sha256", "unicorn_sha256"):
            check(manifest[key] == build[key], "Closed fixture belongs to another build")
        witness, e = result["containment"], result["execution"]
        exit_record = load(run / "worker-exit.json")
        check(witness["app_container"] and witness["job_object"] and witness["child_process_blocked"]
              and witness["network_capabilities"] == 0 and e["network"]["calls"] == 0
              and manifest["cleanup"] == exit_record["cleanup"] == "restored"
              and exit_record["exit_code"] == 0,
              "Closed fixture containment/cleanup differs")
        check(e["architecture"] == arch and e["completion_reason"] == "entry_return"
              and e["guest_entry_return"] == 1 and e["error"] is None,
              "Closed kernel-entry completion differs")
        stack = receipt_scope(e, arch)
        check(not stack["frozen_before_first_callback"] and stack["freeze_instruction_count"] is None,
              "Closed kernel-entry invented a callback freeze")
        records.append({"case": f"closed-{arch}", "run": str(run), "source_tree_sha256": build["source_tree_sha256"],
                        "native_attempts": stack["native_overlapping_attempts"], "verified": True,
                        "unpacking_confirmed": False})
        (root / "verification.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    for kind in ("identical", "cross", "fault", "budget"):
        source, run = root / f"{kind}.sys", root / f"submitted-{kind}"
        generated = fixture(kind)
        if args.resume:
            check(source.is_file() and source.read_bytes() == generated and run.is_dir(),
                  "Saved generated program differs; refuse partial rerun")
        else:
            source.write_bytes(generated)
            command = [str(bundle / "emumee-rs.exe"), "submitted-driver", str(source), str(run),
                       "--service", "StackControl", "--max-instructions", "1" if kind == "budget" else "10000",
                       "--timeout-us", "30000000"]
            with (root / f"{kind}.console.log").open("wb") as out:
                process = subprocess.run(command, stdout=out, stderr=subprocess.STDOUT)
            check(process.returncode == 0, "Generated stack control did not process")
        e = verify_bound_run(bundle, build, run, source, kind, 1 if kind == "budget" else 10000)
        stack = receipt_scope(e, "x64")
        check(not stack["frozen_before_first_callback"] and stack["freeze_instruction_count"] is None,
              "No-callback generated program invented a freeze")
        if kind == "fault":
            check(e["completion_reason"] == "error" and e["guest_entry_return"] is None
                  and e["error"] is not None and "WRITE_UNMAPPED" in e["error"],
                  "Cross-stack fault invented successful completion")
            # Unicorn may report a prewrite for the first mapped fragment.
            # Presence is not a claim that the full native store retired.
            check(stack["native_overlapping_attempts"] <= 1,
                  "Faulting single instruction produced unexpected attempts")
        elif kind == "budget":
            check(e["completion_reason"] == "instruction_budget" and e["instruction_count"] == 1
                  and e["guest_entry_return"] is None and e["error"] is None
                  and stack["native_overlapping_attempts"] == 1,
                  "Budget prefix reported later store or entry return")
        else:
            check(e["completion_reason"] == "entry_return" and e["guest_entry_return"] == SUCCESS
                  and e["error"] is None, "Generated stack stores did not reach return")
            check(stack["native_overlapping_attempts"] == (2 if kind == "identical" else 1),
                  "Native identical/cross-page attempt count differs")
            if kind == "identical":
                expected = stack["watched_page"] + 0xF18  # Entry RSP is page+0xEF8.
                rows = [r for r in stack["last_observed_ranges"] if r["address"] <= expected
                        and expected + 8 <= r["address"] + r["size"]]
                check(len(rows) == 1 and rows[0]["writer"]["source"] == "native_prewrite_attempt"
                      and rows[0]["writer"]["write_address"] == expected
                      and rows[0]["writer"]["write_size"] == 8
                      and rows[0]["size"] >= 8,
                      "Latest identical native store did not replace prior observation")
            else:
                page = stack["watched_page"]
                rows = [r for r in stack["last_observed_ranges"] if r["address"] == page]
                check(len(rows) == 1 and rows[0]["size"] == 4
                      and rows[0]["writer"]["source"] == "native_prewrite_attempt"
                      and (rows[0]["writer"]["write_address"], rows[0]["writer"]["write_size"])
                      in ((page - 4, 8), (page, 4)),
                      "Native incoming cross-page store was missed")
        records.append({"case": kind, "run": str(run), "input_sha256": sha(source),
                        "source_tree_sha256": build["source_tree_sha256"], "completion": e["completion_reason"],
                        "native_attempts": stack["native_overlapping_attempts"], "verified": True,
                        "unpacking_confirmed": False})
        (root / "verification.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    check(len(records) == 6, "Stack control count differs")
    print("Verified 6 harmless offline stack-writer controls; no real driver or unpacking claimed.")


if __name__ == "__main__":
    main()

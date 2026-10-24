"""Exercise fresh-kernel callback ownership using harmless submitted fixtures.

The Python fixture builder only emits PE bytes. All CPU execution uses the
frozen packaged offline AppContainer worker, without fixture namespace opt-in.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "src"))
from tests.test_kernel_named_callbacks import named_callback_probe


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(condition, message):
    if not condition:
        raise ValueError(message)


def check_continuation(execution):
    """Verify passive rows against the actual admitted API result and boundary."""
    window = execution.get("kernel_callback_continuation")
    events = execution["api_events"]
    first = next(i for i, row in enumerate(events) if row["api"] == "ntoskrnl.ExCreateCallback")
    call = events[first]
    check(window is not None and call["error"] is None and not call["pending"],
          "Completed callback lacks its diagnostic window")
    order = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eflags"]
    check(window["architecture"] == "x64" and window["register_order"] == order
          and window["first_callback_ordinal"] == call["instruction_ordinal"]
          and window["api_gate_pc"] == call["api_gate_pc"]
          and window["result"] == call["result"] and window["limit"] == 65536
          and not window["active"], "Callback diagnostic origin, registers or bound differs")
    rows = window["instructions"]
    check(bool(rows) and len(rows) < window["limit"]
          and rows[0]["registers"][0] == call["result"],
          "First native callback row lost the actual return register")
    for index, row in enumerate(rows):
        check(row["instruction_ordinal"] == call["instruction_ordinal"] + 1 + index
              and len(row["registers"]) == len(order) and row["size"] > 0
              and all(row[key] == call[key] for key in
                      ("thread_id", "current_thread", "processor", "execution_domain")),
              "Native callback rows lost ordinal/register/context metadata")
    stop = window["stop"]
    if first + 1 < len(events):
        following = events[first + 1]
        check(not window["truncated"] and stop["reason"] == "next_api_gate"
              and stop["instruction_ordinal"] == following["instruction_ordinal"]
              and stop["pc"] == following["api_gate_pc"]
              and len(rows) == following["instruction_ordinal"] - call["instruction_ordinal"] - 1
              and stop["error"] is None and stop["run_completion"] is None,
              "Callback window did not end before the actual next API")
    else:
        check(window["truncated"] and stop["reason"] == "run_stopped"
              and stop["run_completion"] == execution["completion_reason"]
              and stop["error"] is None, "Callback run-stop prefix was misreported as complete")
    return {"rows": len(rows), "stop": stop["reason"], "truncated": window["truncated"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--resume", action="store_true", help="Reuse completed bound controls without rerunning workers")
    parser.add_argument("--continuation", action="store_true", help="Also verify the first callback native continuation diagnostic")
    args = parser.parse_args()
    bundle, root = args.bundle.resolve(), args.root.resolve()
    check(root.is_dir() if args.resume else not root.exists(), "Choose a fresh root, or explicitly resume existing evidence")
    receipt = load(bundle / "rust-worker-build.json")
    for filename, key in [("emumee-rs.exe", "controller_sha256"),
                          ("emumee-worker.exe", "worker_sha256"),
                          ("unicorn.dll", "unicorn_sha256")]:
        check(sha(bundle / filename) == receipt[key], "Frozen binary differs from receipt")
    if not args.resume:
        root.mkdir()
    records = load(root / "verification.json") if args.resume else []
    check(all(r["verified"] and r["source_tree_sha256"] == receipt["source_tree_sha256"]
              for r in records), "Resumed verification belongs to another source")
    check(not args.continuation or all("continuation" in r for r in records),
          "Existing receipts lack requested continuation validation; choose a fresh root")
    completed = {(r["arch"], r["mode"]) for r in records}
    check(len(completed) == len(records), "Duplicate resumed controls")
    modes = ("create", "missing", "system-power", "system-time", "system-processor",
             "reopen", "case-sensitive", "case-insensitive", "unregister",
             "notify-empty", "notify-active", "body-read", "api-read")
    errors = {"notify-active": "dispatch of registered guest routines is not modeled",
              "body-read": "READ_PROT", "api-read": "unmodeled private callback object/registration API access"}
    # The production submitted-driver role deliberately accepts x64 only.
    # Source tests and the separate closed callback fixture matrix cover x86.
    for arch, machine, width in [("x64", 0x8664, 8)]:
        for mode in modes:
            if (arch, mode) in completed:
                continue
            source = root / f"{arch}-{mode}.sys"
            generated = named_callback_probe(machine, mode)
            if source.exists():
                check(args.resume and source.read_bytes() == generated, "Existing generated input differs")
            else:
                source.write_bytes(generated)
            run = root / f"submitted-{arch}-{mode}"
            if run.exists():
                check(args.resume and (run / "controller-manifest.json").is_file(),
                      "An incomplete control must be preserved; choose a fresh root")
            else:
                with (root / f"{arch}-{mode}.console.log").open("wb") as console:
                    process = subprocess.run([str(bundle / "emumee-rs.exe"), "submitted-driver",
                                              str(source), str(run), "--service", "CallbackControl",
                                              "--max-instructions", "5000", "--timeout-us", "30000000"],
                                             stdout=console, stderr=subprocess.STDOUT, cwd=REPO)
                check(process.returncode == 0, f"Unverified worker outcome: {arch}/{mode}")
            manifest = load(run / "controller-manifest.json")
            result = load(run / "worker-result.json")
            ready = load(run / "worker-ready.json")
            request = load(run / "request.json")
            report = load(run / "engine-report.json")
            witness = load(run / "worker-containment.json")
            job = load(run / "driver-job-profile.json")
            stop = load(run / "worker-stop.json")
            exit_record = load(run / "worker-exit.json")
            check(manifest["status"] == "verified" and manifest["guest_status"] == "processed"
                  and result["status"] == "processed" and not manifest["unpacking_confirmed"]
                  and not result["unpacking_confirmed"], "Outcome is unverified or invents unpacking")
            bindings = {"input_sha256": sha(source), "request_sha256": sha(run / "request.json"),
                        "source_tree_sha256": receipt["source_tree_sha256"],
                        "service_name": "CallbackControl", "run_id": request["run_id"]}
            for row in (manifest, ready, result["binding"]):
                check(all(row[k] == v for k, v in bindings.items()), "Typed input/request/source binding differs")
            check(sha(run / "input.sys") == sha(source) and request["max_instructions"] == 5000
                  and request["timeout_us"] == 30000000, "Submitted bytes or budget changed")
            check(all(manifest[k] == receipt[k] for k in
                      ("controller_sha256", "worker_sha256", "unicorn_sha256")), "Frozen binary binding differs")
            check(manifest["worker_result_sha256"] == sha(run / "worker-result.json")
                  and result["engine_report_sha256"] == sha(run / "engine-report.json")
                  and report["mode"] == "submitted_driver_capture"
                  and report["binding"]["request_sha256"] == bindings["request_sha256"]
                  and report["binding"]["source_tree_sha256"] == receipt["source_tree_sha256"], "Report binding differs")
            check(witness["app_container"] and witness["job_object"] and witness["child_process_blocked"]
                  and witness["network_capabilities"] == 0 and job["profile"] == "driver_capture_2048_v1"
                  and job["process_memory_bytes"] == 2147483648 and job["active_process_limit"] == 1
                  and 0 < job["peak_process_memory_bytes"] <= job["process_memory_bytes"], "Offline containment differs")
            check(all(row["cleanup"] == "restored" for row in (manifest, job, stop, exit_record))
                  and stop["worker"]["reason"] == "exited" and stop["worker"]["exit_code"] == 0
                  and exit_record["exit_code"] == 0, "Worker exit or cleanup differs")
            e = report["execution"]
            cb, named = e["kernel_callbacks"], e["kernel_callbacks"]["named"]
            check(e["architecture"] == arch and e["kernel_cpu"] is not None and e["kernel_entry"] is not None
                  and cb["namespace_authority"] == "OwnedFreshKernelDirectory"
                  and not cb["native_effect_failure"] and not cb["lifecycle_errors"]
                  and named["callbacks_executed"] == 0 and named["pending_invocations"] == 0
                  and e["network"]["calls"] == 0, "Fresh authority or passive callback accounting differs")
            snapshots = [a for a in result["artifacts"] if any(
                o["kind"] == "memory_snapshot" and o["source"] == "settled_root_image"
                for o in a["observations"])]
            check(len(snapshots) == 1, "Settled guest snapshot missing")
            artifact = snapshots[0]
            snapshot_path = run / "artifacts" / artifact["filename"]
            check(sha(snapshot_path) == artifact["sha256"], "Snapshot binding differs")
            data = snapshot_path.read_bytes()[0x2300:0x2400]
            value = lambda offset: int.from_bytes(data[offset:offset + width], "little")
            if mode in errors:
                check(e["completion_reason"] == "error" and e["guest_entry_return"] is None
                      and errors[mode].casefold() in e["error"].casefold()
                      and data[0xF8:0xFC] == b"COLD", "Negative case falsely completed")
            else:
                check(e["completion_reason"] == "entry_return" and e["guest_entry_return"] == 0
                      and e["error"] is None and data[0xF8:0xFC] == b"DONE", "Guest continuation failed")
            if mode == "missing":
                check(not named["objects"] and value(0) == 0 and value(0x10) == 0xC0000034,
                      "Missing open invented an object or success")
            else:
                check(len(named["objects"]) == 1 and value(0) == named["objects"][0]["address"]
                      and value(0x10) == 0, "Callback object identity/status differs")
                obj = named["objects"][0]
                check(obj["permissions"] == "---" and obj["live"], "Callback body or lifetime differs")
                if mode.startswith("system-"):
                    check(obj["system"] and obj["permanent"] and obj["references"] == 2,
                          "Predefined callback open lifetime differs")
                if mode in ("reopen", "case-insensitive"):
                    check(value(0x20) == value(0) and value(0x28) == 0 and obj["references"] == 2,
                          "Repeated open lost object identity/reference")
                if mode == "case-sensitive":
                    check(value(0x20) == 0 and value(0x28) == 0xC0000034,
                          "Case-sensitive open silently folded the name")
                if mode == "unregister":
                    check(len(named["registrations"]) == 1 and not named["registrations"][0]["active"]
                          and obj["references"] == 1, "Registration lifetime differs")
            if mode == "notify-active":
                check(len(cb["blocked_notifications"]) == 1
                      and cb["blocked_notifications"][0]["dispatched"] == 0,
                      "Unsupported active notification invented callback execution")
            if mode in ("body-read", "api-read"):
                check(any(row["kind"] == "CALLBACK_OBJECT" for row in named["api_denials"]),
                      "Opaque access lacks denial evidence")
            requests = named["create_requests"]
            check(len(requests) == (2 if mode in ("reopen", "case-sensitive", "case-insensitive") else 1)
                  and named["create_requests_omitted"] == 0 and requests[0]["name"]
                  and requests[0]["error"] is None and not requests[0]["name_truncated"],
                  "Decoded callback request evidence differs")
            check(requests[0]["result"] == (0xC0000034 if mode == "missing" else 0),
                  "Callback request receipt does not match actual status")
            with (root / f"{arch}-{mode}.inspection.log").open("wb") as console:
                inspected = subprocess.run([str(bundle / "emumee-rs.exe"), "inspect-driver-capture", str(run)],
                                           stdout=console, stderr=subprocess.STDOUT, cwd=REPO)
            check(inspected.returncode == 0, "Typed report inspection failed")
            record = {"arch": arch, "mode": mode, "verified": True, "run": str(run),
                            "source_tree_sha256": receipt["source_tree_sha256"],
                            "input_sha256": sha(source), "completion": e["completion_reason"],
                            "instruction_count": e["instruction_count"], "cleanup": "restored",
                            "unpacking_confirmed": False}
            if args.continuation:
                record["continuation"] = check_continuation(e)
            records.append(record)
            (root / "verification.json").write_text(json.dumps(records, indent=2) + "\n")
    check(len(records) == 13, "Control count differs")
    print("Verified 13 harmless x64 submitted fresh-kernel callback controls; no callback execution or unpacking claimed.")


if __name__ == "__main__":
    main()

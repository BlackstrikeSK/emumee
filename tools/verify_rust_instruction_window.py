"""Packaged offline controls for opt-in submitted-driver instruction windows.

All inputs are harmless generated x64 PEs. This verifier never uses external driver images.
Use a fresh root for execution; --resume only rechecks saved runs.
"""
import argparse
import json
from pathlib import Path
import struct
import subprocess

from verify_rust_kernel_loader import build_driver, check, load, sha

SERVICE = "WindowControl"
STRAIGHT = bytes.fromhex("b87856341283c00189c1c3")
RETURN = 0x12345679
COPY_VALUE = 0x1122334455667788
COPY_BYTES = struct.pack("<Q", COPY_VALUE)
SUCCESS = 0x57494E31
REGISTERS = ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
             "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eflags")


def fixture(kind):
    image = bytearray(build_driver(0x8664))
    if kind == "straight":
        code = STRAIGHT
    elif kind == "checkpoint":
        code = b"\x48\xb8" + COPY_BYTES + bytes.fromhex("4889442420")
        code += b"\x48\xb8" + struct.pack("<Q", 0x8877665544332211)
        code += bytes.fromhex("4889442420") + b"\xb8" + struct.pack("<I", SUCCESS) + b"\xc3"
    elif kind == "cap":
        # 21,850 iterations * 3 instructions exceed the 65,536-row cap.
        code = b"\xb9" + struct.pack("<I", 21850) + bytes.fromhex("90ffc975fb")
        code += b"\xb8" + struct.pack("<I", SUCCESS) + b"\xc3"
    elif kind == "api":
        # One modeled RtlCopyMemory import, two owned stack slots and a native
        # compare of the copied value. This tests the actual guest value too.
        image[0x480:0x4C0] = bytes(0x40)
        for table in (0x480, 0x4A0):
            struct.pack_into("<Q", image, table, 0x20D0)
        image[0x4D0:0x4D0 + 16] = b"\0\0RtlCopyMemory\0"
        code = bytearray(bytes.fromhex("4883ec48"))  # SUB RSP,48h
        code += b"\x48\xb8" + COPY_BYTES
        code += bytes.fromhex("4889442420")  # MOV [RSP+20h],RAX
        code += bytes.fromhex("488d4c2428")  # LEA RCX,[RSP+28h]
        code += bytes.fromhex("488d542420")  # LEA RDX,[RSP+20h]
        code += bytes.fromhex("41b808000000")  # MOV R8D,8
        call_offset = len(code)
        code += b"\xff\x15" + struct.pack("<i", 0x20A0 - (0x1000 + call_offset + 6))
        code += bytes.fromhex("488b442428")  # MOV RAX,[RSP+28h]
        code += b"\x49\xb9" + COPY_BYTES
        code += bytes.fromhex("4c39c8")  # CMP RAX,R9
        failure_jump = len(code)
        code += b"\x75\x00"
        code += b"\xb8" + struct.pack("<I", SUCCESS) + bytes.fromhex("4883c448c3")
        failure = len(code)
        code += bytes.fromhex("b80d0000c04883c448c3")
        code[failure_jump + 1] = failure - failure_jump - 2
        code = bytes(code)
    else:
        raise ValueError(kind)
    check(len(code) <= 512, "Generated instruction caller exceeds text section")
    image[0x200:0x400] = code + bytes(512 - len(code))
    return bytes(image)


def verify_run(bundle, build, run, source, budget, window):
    manifest, request = load(run / "controller-manifest.json"), load(run / "request.json")
    result, report = load(run / "worker-result.json"), load(run / "engine-report.json")
    witness, job = load(run / "worker-containment.json"), load(run / "driver-job-profile.json")
    stop, exit_record = load(run / "worker-stop.json"), load(run / "worker-exit.json")
    check(manifest["status"] == "verified" and manifest["guest_status"] == result["status"] == "processed"
          and not manifest["unpacking_confirmed"] and not result["unpacking_confirmed"],
          "Generated submitted result or unpacking label differs")
    for key in ("source_tree_sha256", "controller_sha256", "worker_sha256", "unicorn_sha256"):
        check(manifest[key] == build[key], "Run belongs to another frozen build")
    check(request["max_instructions"] == budget and request.get("instruction_window") == window,
          "Submitted request changed observation/budget input")
    check(manifest["worker_result_sha256"] == sha(run / "worker-result.json")
          and result["engine_report_sha256"] == sha(run / "engine-report.json"),
          "Worker report/result hash differs")
    for row in (manifest, result["binding"], report["binding"]):
        check(row["request_sha256"] == sha(run / "request.json")
              and row["input_sha256"] == sha(source) == sha(run / "input.sys")
              and row["source_tree_sha256"] == build["source_tree_sha256"]
              and row["containment_sha256"] == sha(run / "worker-containment.json"),
              "Request/input/source/containment binding differs")
    check(witness["app_container"] and witness["job_object"] and witness["child_process_blocked"]
          and witness["network_capabilities"] == 0 and job["active_process_limit"] == 1
          and job["network_capabilities"] == 0 and job["process_memory_bytes"] == 2147483648
          and 0 < job["peak_process_memory_bytes"] <= job["process_memory_bytes"],
          "Generated worker was not confined by the frozen offline profile")
    check(all(row["cleanup"] == "restored" for row in (manifest, job, stop, exit_record))
          and exit_record["exit_code"] == 0 and report["execution"]["network"]["calls"] == 0,
          "Offline cleanup, worker exit or network-denial evidence differs")
    for item in result["artifacts"]:
        artifact = run / "artifacts" / item["filename"]
        check(artifact.is_file() and sha(artifact) == item["sha256"]
              and artifact.stat().st_size == item["size"], "Saved generated artifact differs")
    return report["execution"], result


def rows_and_registers(receipt, start, count):
    check(receipt["architecture"] == "x64" and receipt["start_instruction"] == start
          and receipt["end_instruction_exclusive"] == start + count
          and receipt["max_records"] == count and len(receipt["register_order"]) == 17,
          "Instruction window geometry/register order differs")
    check([name.lower() for name in receipt["register_order"]] == list(REGISTERS),
          "Fixed 17-register order differs")
    contexts = receipt["contexts"]
    check(receipt["context_limit"] == 256 and 0 <= len(contexts) <= 256
          and (not receipt["instructions"] or contexts),
          "Window context table outside bounded profile")
    rows, prior, restored = receipt["instructions"], None, []
    for row in rows:
        check(row["sequence"] > (rows[0]["sequence"] - 1 if not restored else rows[len(restored)-1]["sequence"])
              and start <= row["instruction_ordinal"] < start + count
              and 1 <= row["size"] <= 15
              and len(row["instruction_bytes"]) == row["size"]
              and row["phase"] in ("native_pre_instruction", "api_post_dispatch_pre_RET")
              and isinstance(row["context_id"], int)
              and 0 <= row["context_id"] < len(contexts),
              "Instruction row context, byte count, sequence or phase differs")
        context = contexts[row["context_id"]]
        check(context["processor"] == 0 and context["thread_id"] == 1
              and context["execution_domain"] == "ordinary_thread"
              and context["current_thread"] > 0,
              "Generated instruction switched context unexpectedly")
        full, delta = row.get("full_registers"), row["register_deltas"]
        if prior is None:
            check(isinstance(full, list) and len(full) == 17 and not delta,
                  "First instruction lacks full 17-register snapshot")
            prior = full.copy()
        else:
            check(full is None and all(isinstance(pair, list) and len(pair) == 2 for pair in delta),
                  "Later instruction did not use indexed deltas")
            indexes = [pair[0] for pair in delta]
            check(indexes == sorted(set(indexes)) and all(0 <= index < 17 for index in indexes),
                  "Register delta index is duplicated, unordered or invalid")
            for index, value in delta:
                check(value != prior[index], "Register delta repeats unchanged value")
                prior[index] = value
        restored.append(prior.copy())
    return rows, restored


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    bundle, root = args.bundle.resolve(), args.root.resolve()
    check(not root.exists() or args.resume, "Use a fresh root or --resume for saved verification")
    build = load(bundle / "rust-worker-build.json")
    for name, key in (("emumee-rs.exe", "controller_sha256"),
                      ("emumee-worker.exe", "worker_sha256"), ("unicorn.dll", "unicorn_sha256")):
        check(sha(bundle / name) == build[key], "Frozen executable differs")
    root.mkdir(exist_ok=args.resume)
    records, runs = [], {}
    cases = (("absent", "straight", 100, None), ("small", "straight", 100, (0, 4)),
             ("budget", "straight", 2, (0, 4)), ("not-reached", "straight", 100, (80, 4)),
             ("cap", "cap", 100_000, (0, 65_536)), ("api", "api", 100, (6, 5)),
             ("checkpoint", "checkpoint", 100, (2, 4)))
    for name, kind, budget, selected in cases:
        source, run = root / f"{name}.sys", root / f"submitted-{name}"
        data = fixture(kind)
        if source.exists():
            check(args.resume and source.read_bytes() == data, "Saved generated source differs")
        else:
            check(not args.resume, "Resume requires the saved generated source")
            source.write_bytes(data)
        if not run.exists():
            check(not args.resume, "Resume requires a completed run")
            command = [str(bundle / "emumee-rs.exe"), "submitted-driver", str(source), str(run),
                       "--service", SERVICE, "--max-instructions", str(budget), "--timeout-us", "30000000"]
            if selected is not None:
                command += ["--instruction-window", f"{selected[0]}:{selected[1]}"]
            with (root / f"{name}.console.log").open("wb") as out:
                process = subprocess.run(command, stdout=out, stderr=subprocess.STDOUT)
            check(process.returncode == 0, f"Generated {name} control did not process")
        else:
            check(args.resume, "Existing run requires explicit --resume")
        expected = None if selected is None else dict(start_instruction=selected[0], max_records=selected[1])
        execution, result = verify_run(bundle, build, run, source, budget, expected)
        receipt = execution.get("instruction_window")
        if selected is None:
            check(receipt is None, "Absent window invented observation")
        else:
            check(receipt is not None and receipt["run_completion"] == execution["completion_reason"]
                  and receipt["model_write_record_limit"] == 4096
                  and receipt["model_write_prefix_limit"] == 256,
                  "Window receipt is missing or misbound")
            rows, states = rows_and_registers(receipt, *selected)
            checkpoint = receipt.get("initial_stack_writes")
            if not rows:
                check(checkpoint is None, "Unreached window invented a stack checkpoint")
                check(receipt.get("first_row_pointer_samples") is None,
                      "Unreached window invented first-row memory bytes")
            else:
                samples = receipt.get("first_row_pointer_samples")
                check(isinstance(samples, list) and len(samples) <= len(REGISTERS) - 1
                      and all(sample["register"] in REGISTERS[:-1]
                              and len(sample["bytes"]) == 64
                              and all(0 <= byte <= 255 for byte in sample["bytes"])
                              for sample in samples),
                      "First-row pointer samples exceed the bounded read-only profile")
                final = execution["kernel_stack_writes"]
                check(checkpoint is not None and checkpoint["observation_raw_instruction_count"] == rows[0]["instruction_ordinal"]
                      and checkpoint["observation_phase"] == rows[0]["phase"]
                      and all(checkpoint[key] == final[key] for key in ("stack_base","stack_size","watched_page","native_hook_start","native_hook_end_inclusive"))
                      and sum(span["size"] for span in checkpoint["last_observed_ranges"]) == checkpoint["observed_bytes"] <= 4096
                      and checkpoint["native_overlapping_attempts"] <= final["native_overlapping_attempts"]
                      and checkpoint["model_overlapping_writes"] <= final["model_overlapping_writes"]
                      and all(span["writer"]["raw_instruction_count"] <= rows[0]["instruction_ordinal"] for span in checkpoint["last_observed_ranges"]),
                      "First-row bounded stack checkpoint differs from its timing/geometry")
            runs[name] = (execution, result, rows, states, receipt)
        records.append({"case": name, "run": str(run), "input_sha256": sha(source),
                        "source_tree_sha256": build["source_tree_sha256"],
                        "instruction_count": execution["instruction_count"],
                        "window_rows": 0 if receipt is None else len(receipt["instructions"]),
                        "cleanup": "restored", "unpacking_confirmed": False})
        (root / "verification.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")

    # Same generated image with/without diagnostics has identical guest effects.
    baseline = load(root / "submitted-absent" / "engine-report.json")["execution"]
    observed, _, rows, states, small = runs["small"]
    for field in ("instruction_count", "api_calls", "api_events", "completion_reason", "error",
                  "final_pc", "guest_entry_return", "capture_runtime", "capture_summary"):
        check(baseline[field] == observed[field], f"Observation changed guest field {field}")
    check(sha(root / "absent.sys") == sha(root / "small.sys")
          and load(root / "submitted-absent" / "worker-result.json")["artifacts"]
          == load(root / "submitted-small" / "worker-result.json")["artifacts"],
          "Observation changed generated input or artifact hashes")
    check(observed["completion_reason"] == "entry_return" and observed["guest_entry_return"] == RETURN
          and len(rows) == 4 and small["status"] == "record_limit" and not small["truncated"]
          and small["stop"]["reason"] == "record_limit"
          and [row["instruction_ordinal"] for row in rows] == list(range(4))
          and [bytes(row["instruction_bytes"]) for row in rows]
          == [STRAIGHT[:5], STRAIGHT[5:8], STRAIGHT[8:10], STRAIGHT[10:]],
          "Small generated instruction sequence/bytes differs")
    order = [name.lower() for name in small["register_order"]]
    check(states[1][order.index("rax")] == 0x12345678
          and states[2][order.index("rax")] == RETURN
          and states[3][order.index("rcx")] == RETURN,
          "Indexed deltas did not reconstruct actual guest GPR changes")
    budget, _, b_rows, _, b = runs["budget"]
    check(budget["completion_reason"] == "instruction_budget" and budget["instruction_count"] == 2
          and budget["guest_entry_return"] is None and len(b_rows) == 2
          and b["status"] == "prefix" and b["stop"]["reason"] == "run_stopped",
          "Budget prefix invented later rows or an entry return")
    early, _, n_rows, _, n = runs["not-reached"]
    check(early["completion_reason"] == "entry_return" and early["guest_entry_return"] == RETURN
          and not n_rows and n["status"] == n["stop"]["reason"] == "not_reached",
          "Early return invented a reached high-counter window")
    cap, _, c_rows, _, c = runs["cap"]
    check(cap["completion_reason"] == "entry_return" and cap["guest_entry_return"] == SUCCESS
          and len(c_rows) == 65_536 and c["status"] == c["stop"]["reason"] == "record_limit"
          and c_rows[0]["instruction_ordinal"] == 0
          and c_rows[-1]["instruction_ordinal"] == 65_535
          and cap["instruction_count"] > 65_536,
          "65,536-row cap did not retain exactly the admitted prefix")
    api, _, a_rows, _, a = runs["api"]
    posts = [row for row in a_rows if row["phase"] == "api_post_dispatch_pre_RET"]
    writes = [row for row in a["model_writes"] if row["requested_prefix"] == list(COPY_BYTES)
              and row["requested_bytes"] == 8 and row["succeeded"]]
    check(api["completion_reason"] == "entry_return" and api["guest_entry_return"] == SUCCESS
          and api["api_calls"] == 1 and len(posts) == 1 and len(writes) == 1
          and posts[0]["instruction_bytes"] == [0xC3]
          and writes[0]["sequence"] < posts[0]["sequence"]
          and writes[0]["raw_instruction_count"] == posts[0]["instruction_ordinal"]
          and writes[0]["effect"] == "backend_mem_write_succeeded_cache_invalidation_pending"
          and a["model_write_calls"] >= 1 and a["model_write_records_omitted"] == 0,
          "Modeled API copy lacks ordered requested-byte and post-dispatch evidence")
    execution, _, checkpoint_rows, _, selected = runs["checkpoint"]
    initial = selected["initial_stack_writes"]
    stack_samples = [sample for sample in selected["first_row_pointer_samples"]
                     if sample["register"] == "rsp"]
    check(len(stack_samples) == 1
          and bytes(stack_samples[0]["bytes"][0x20:0x28]) == COPY_BYTES,
          "First-row guest stack sample does not contain the generated written value")
    final = execution["kernel_stack_writes"]
    address = final["watched_page"] + 0xf18
    def writer_at(table):
        spans = [span for span in table["last_observed_ranges"] if span["address"] <= address < span["address"] + span["size"]]
        check(len(spans) == 1, "Selected generated stack byte lacks one writer range")
        return spans[0]["writer"]
    before, after = writer_at(initial), writer_at(final)
    check(execution["guest_entry_return"] == SUCCESS and execution["instruction_count"] == 6
          and initial["observation_raw_instruction_count"] == 2
          and initial["native_overlapping_attempts"] == 1 and final["native_overlapping_attempts"] == 2
          and before["source"] == after["source"] == "native_prewrite_attempt"
          and before["raw_instruction_count"] == 2 and after["raw_instruction_count"] == 4
          and before["pc"] == execution["image_load"]["entry"] + 10
          and after["pc"] == execution["image_load"]["entry"] + 25
          and before["sequence"] < after["sequence"],
          "First-row checkpoint lost the earlier writer or froze the final observer")
    print("Verified 7 generated offline instruction-window controls; no real driver or unpacking claimed.")


if __name__ == "__main__":
    main()

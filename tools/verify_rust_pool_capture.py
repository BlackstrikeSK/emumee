"""Verify passive pool snapshots with a harmless generated x64 driver.

Runs the same generated image in two frozen packaged offline workers. The
baseline and candidate must have identical guest effects; only capture may
add a live pool artifact. This script never reads or executes external driver images.
"""

import argparse
import json
from pathlib import Path
import struct
import subprocess

from verify_rust_instruction_window import check, load, sha, verify_run
from verify_rust_kernel_loader import build_driver


RETURN = 0x139
MARKER = bytes.fromhex("44332211")


def fixture():
    image = bytearray(build_driver(0x8664))
    image[0x200:0x400] = bytes(0x200)
    image[0x400:] = bytes(0x200)
    struct.pack_into("<IIIII", image, 0x400, 0x2080, 0, 0, 0x2060, 0x20A0)
    image[0x460:0x46D] = b"ntoskrnl.exe\0"
    for table in (0x480, 0x4A0):
        struct.pack_into("<Q", image, table, 0x20D0)
    name = b"\0\0ExAllocatePool2\0"
    image[0x4D0:0x4D0 + len(name)] = name
    code = bytearray(bytes.fromhex("4883ec28"))
    code += bytes.fromhex("b980000000")  # POOL_FLAG_NON_PAGED_EXECUTE
    code += bytes.fromhex("ba7c000000")  # 124 requested bytes
    code += bytes.fromhex("41b854534554")  # TEST pool tag
    call = len(code)
    code += b"\xff\x15" + struct.pack("<i", 0x20A0 - (0x1000 + call + 6))
    code += bytes.fromhex("4885c0")
    jump = len(code)
    code += bytes.fromhex("7400")
    code += bytes.fromhex("c700") + MARKER  # guest write to pool
    code += b"\xb8" + struct.pack("<I", RETURN) + bytes.fromhex("4883c428c3")
    failure = len(code)
    code += bytes.fromhex("b80d0000c04883c428c3")
    check(failure - jump - 2 < 128, "Generated failure jump is out of range")
    code[jump + 1] = failure - jump - 2
    check(len(code) <= 0x200, "Generated pool driver exceeds code section")
    image[0x200:0x200 + len(code)] = code
    return bytes(image)


def run(bundle, root, source, budget, resume):
    build = load(bundle / "rust-worker-build.json")
    for name, key in (("emumee-rs.exe", "controller_sha256"),
                      ("emumee-worker.exe", "worker_sha256"),
                      ("unicorn.dll", "unicorn_sha256")):
        check(sha(bundle / name) == build[key], "Frozen bundle changed")
    if not root.exists():
        check(not resume, "Resume requires both saved runs")
        command = [str(bundle / "emumee-rs.exe"), "submitted-driver", str(source), str(root),
                   "--service", "PoolCaptureControl", "--max-instructions", str(budget),
                   "--timeout-us", "30000000"]
        with (root.parent / f"{root.name}.console.log").open("wb") as stream:
            completed = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT)
        check(completed.returncode == 0, "Generated packaged run failed")
    else:
        check(resume, "Existing run requires --resume")
    execution, result = verify_run(bundle, build, root, source, budget, None)
    check(execution["completion_reason"] == "entry_return"
          and execution["guest_entry_return"] == RETURN and execution["api_calls"] == 1
          and len(execution["kernel_pool"]["allocations"]) == 1,
          "Generated driver did not allocate and return as expected")
    return execution, result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    baseline, bundle, root = args.baseline.resolve(), args.bundle.resolve(), args.root.resolve()
    check(not root.exists() or args.resume, "Use a fresh root or --resume")
    root.mkdir(exist_ok=args.resume)
    source = root / "generated-pool.sys"
    data = fixture()
    if source.exists():
        check(args.resume and source.read_bytes() == data, "Generated source changed")
    else:
        check(not args.resume, "Resume has no generated input")
        source.write_bytes(data)
    budget = 100
    old, old_result = run(baseline, root / "baseline", source, budget, args.resume)
    new, new_result = run(bundle, root / "candidate", source, budget, args.resume)
    for field in ("instruction_count", "api_calls", "api_events", "completion_reason", "error",
                  "final_pc", "guest_entry_return", "kernel_pool", "kernel_state", "image_load"):
        check(old[field] == new[field], f"Pool capture changed guest field {field}")
    old_pool = [row for row in old_result["artifacts"] if any(
        observation["source"].startswith("kernel_pool_allocation")
        for observation in row["observations"])]
    new_pool = [row for row in new_result["artifacts"] if any(
        observation["source"].startswith("kernel_pool_allocation")
        for observation in row["observations"])]
    check(not old_pool and len(new_pool) == 1, "Expected exactly one new pool snapshot")
    allocation = next(iter(new["kernel_pool"]["allocations"].values()))
    item = new_pool[0]
    payload = (root / "candidate" / "artifacts" / item["filename"]).read_bytes()
    check(allocation["executable"] and allocation["requested"] == 124
          and allocation["mapped"] == len(payload) == 4096
          and payload[:4] == MARKER and payload[124:] == bytes(4096 - 124),
          "Pool artifact lacks guest write or mapped slack")
    context = next(observation["context"] for observation in item["observations"]
                   if observation["source"].startswith("kernel_pool_allocation"))
    check(context["guest_base"] == allocation["base"]
          and context["mapped_bytes"] == 4096
          and context["requested_bytes"] == 124
          and context["executable"] is True
          and context["capture_boundary"] == "settled",
          "Pool snapshot lost address, flags or stop boundary")
    receipt = {"schema": "emumee.generated_pool_capture_verification.v1",
               "baseline_bundle": str(baseline), "candidate_bundle": str(bundle),
               "input_sha256": sha(source), "baseline_instructions": old["instruction_count"],
               "candidate_instructions": new["instruction_count"],
               "pool_artifact_sha256": item["sha256"], "pool_artifact_bytes": len(payload),
               "guest_effects_equal": True, "offline_containment_verified": True,
               "unpacking_confirmed": False}
    destination = root / "verification.json"
    if destination.exists():
        check(args.resume and load(destination) == receipt, "Saved receipt changed")
    else:
        destination.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print("Verified generated packaged pool capture and unchanged guest effects")


if __name__ == "__main__":
    main()

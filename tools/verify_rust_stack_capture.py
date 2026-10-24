"""Verify passive submitted-driver stack captures with a generated driver only."""

import argparse
import json
from pathlib import Path
import subprocess

from verify_rust_instruction_window import check, load, sha, verify_run
from verify_rust_pool_capture import fixture, RETURN


def run(bundle, root, source, resume):
    build = load(bundle / "rust-worker-build.json")
    for name, key in (("emumee-rs.exe", "controller_sha256"),
                      ("emumee-worker.exe", "worker_sha256"),
                      ("unicorn.dll", "unicorn_sha256")):
        check(sha(bundle / name) == build[key], "Frozen bundle changed")
    if not root.exists():
        check(not resume, "Resume requires saved runs")
        with (root.parent / f"{root.name}.console.log").open("wb") as output:
            process = subprocess.run(
                [str(bundle / "emumee-rs.exe"), "submitted-driver", str(source), str(root),
                 "--service", "StackControl", "--max-instructions", "100",
                 "--timeout-us", "30000000"], stdout=output, stderr=subprocess.STDOUT)
        check(process.returncode == 0, "Generated packaged run failed")
    else:
        check(resume, "Existing run requires --resume")
    return verify_run(bundle, build, root, source, 100, None)


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
    source = root / "generated-stack.sys"
    data = fixture()
    if source.exists():
        check(args.resume and source.read_bytes() == data, "Generated source changed")
    else:
        check(not args.resume, "Resume lacks source")
        source.write_bytes(data)
    old, old_result = run(baseline, root / "baseline", source, args.resume)
    new, new_result = run(bundle, root / "candidate", source, args.resume)
    for field in ("instruction_count", "api_calls", "api_events", "completion_reason",
                  "error", "final_pc", "guest_entry_return", "kernel_pool", "image_load",
                  "modeled_guest_regions"):
        check(old[field] == new[field], f"Stack capture changed guest field {field}")
    check(new["guest_entry_return"] == RETURN, "Generated driver result changed")
    old_artifacts = {(a["sha256"], a["size"]) for a in old_result["artifacts"]}
    new_artifacts = {(a["sha256"], a["size"]) for a in new_result["artifacts"]}
    check(old_artifacts <= new_artifacts, "Existing artifacts changed")
    stacks = [a for a in new["artifacts"] if any(
        o["source"].startswith("kernel_stack_mapping") for o in a["observations"])]
    check(stacks, "Candidate lacks retained stack bytes")
    check(not any(any(o["source"].startswith("kernel_stack_mapping")
                      for o in a["observations"]) for a in old["artifacts"]),
          "Baseline already contains stack captures")
    receipt = {"schema": "emumee.generated_stack_capture_verification.v1",
               "baseline_bundle": str(baseline), "candidate_bundle": str(bundle),
               "input_sha256": sha(source), "guest_instructions": new["instruction_count"],
               "stack_artifacts": len(stacks), "guest_effects_equal": True,
               "existing_artifacts_preserved": True, "offline_containment_verified": True,
               "unpacking_confirmed": False}
    destination = root / "verification.json"
    if destination.exists():
        check(args.resume and load(destination) == receipt, "Saved receipt changed")
    else:
        destination.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print("Verified generated packaged stack capture and unchanged guest effects")


if __name__ == "__main__":
    main()

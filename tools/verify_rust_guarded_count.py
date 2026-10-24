"""Offline packaged controls for generated Windows26200 mutex contention only."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import sys

from verify_rust_instruction_window import check, load, sha, verify_run

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tests.test_kernel_runtime import runtime_driver

BASE = 0x140000000
NAMES = ["KeInitializeGuardedMutex", "PsCreateSystemThread", "KeAcquireGuardedMutex",
         "KeReleaseGuardedMutex", "PsTerminateSystemThread", "ZwClose"]
MUTEX, READY, RELEASE, HANDLE = 0x2b00, 0x2b80, 0x2b90, 0x2c00


def fixture(zero=False):
    image = bytearray(runtime_driver(0x8664, NAMES, []))

    def call(code, origin, index, arguments):
        for position, value in enumerate(arguments):
            if isinstance(value, tuple):
                check(position == 0, "Generated indirect argument position")
                code += b"\x48\x8b\x0d" + struct.pack("<i", value[1] - (origin + len(code) + 7))
            elif position < 4:
                code += (b"\x48\xb9", b"\x48\xba", b"\x49\xb8", b"\x49\xb9")[position]
                code += struct.pack("<Q", value)
            else:
                code += b"\x48\xb8" + struct.pack("<Q", value)
                code += bytes.fromhex("48894424") + bytes([0x20 + 8 * (position - 4)])
        code += b"\xff\x15" + struct.pack("<i", 0x2900 + index * 8 - (origin + len(code) + 6))

    def store(code, origin, target):
        code += b"\xc7\x05" + struct.pack("<i", target - (origin + len(code) + 10)) + struct.pack("<I", 1)

    def wait(code, origin, target):
        start = len(code)
        code += b"\x8b\x05" + struct.pack("<i", target - (origin + len(code) + 6))
        code += bytes.fromhex("85c074") + bytes([(start - len(code) - 4) & 0xff])

    root = bytearray(bytes.fromhex("4883ec48"))
    if not zero:
        call(root, 0x1000, 0, [BASE + MUTEX])
        call(root, 0x1000, 1, [BASE + HANDLE, 0x1fffff, 0, 0, 0, BASE + 0x1100, BASE + MUTEX])
        wait(root, 0x1000, READY)
        store(root, 0x1000, RELEASE)
    call(root, 0x1000, 2, [BASE + MUTEX])
    if not zero:
        call(root, 0x1000, 3, [BASE + MUTEX])
        call(root, 0x1000, 5, [("memory", HANDLE)])
    root += bytes.fromhex("b8110000004883c448c3")
    check(len(root) <= 0x100, "Generated root exceeds owned text slot")
    child = bytearray(bytes.fromhex("4883ec48"))
    call(child, 0x1100, 2, [BASE + MUTEX])
    store(child, 0x1100, READY)
    wait(child, 0x1100, RELEASE)
    call(child, 0x1100, 3, [BASE + MUTEX])
    call(child, 0x1100, 4, [0])
    child += bytes.fromhex("0f0b")
    check(len(child) <= 0x100, "Generated child exceeds owned text slot")
    image[0x200:0x400] = root + bytes([0xcc]) * (0x100 - len(root)) + child + bytes([0xcc]) * (0x100 - len(child))
    return bytes(image)


def run(bundle, run_root, source, persona, resume):
    build = load(bundle / "rust-worker-build.json")
    for filename, key in (("emumee-rs.exe", "controller_sha256"),
                          ("emumee-worker.exe", "worker_sha256"), ("unicorn.dll", "unicorn_sha256")):
        check(sha(bundle / filename) == build[key], "Frozen bundle changed")
    if not run_root.exists():
        check(not resume, "Resume requires saved run")
        with run_root.with_suffix(".console.log").open("wb") as output:
            process = subprocess.run([str(bundle / "emumee-rs.exe"), "submitted-driver", str(source), str(run_root),
                "--service", "GuardedCountControl", "--max-instructions", "10000", "--timeout-us", "30000000",
                "--persona", str(persona)], stdout=output, stderr=subprocess.STDOUT)
        check(process.returncode == 0, "Generated packaged controller failed")
    else:
        check(resume, "Existing run requires explicit resume")
    return verify_run(bundle, build, run_root, source, 10000, None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    baseline, bundle, root = args.baseline.resolve(), args.bundle.resolve(), args.root.resolve()
    check(not root.exists() or args.resume, "Preserve existing evidence; use a fresh root")
    root.mkdir(exist_ok=args.resume)
    persona = root / "persona.json"
    persona_bytes = (json.dumps({"windows_build": 26200, "clock_utc": "2026-10-22T12:00:00Z"}, sort_keys=True) + "\n").encode()
    if persona.exists():
        check(args.resume and persona.read_bytes() == persona_bytes, "Persona changed")
    else:
        persona.write_bytes(persona_bytes)
    records = []
    for zero in (False, True):
        name = "zero-owner" if zero else "handoff"
        source = root / (name + ".sys")
        data = fixture(zero)
        if source.exists():
            check(args.resume and source.read_bytes() == data, "Generated fixture changed")
        else:
            source.write_bytes(data)
        old, old_result = run(baseline, root / (name + "-baseline"), source, persona, args.resume)
        new, new_result = run(bundle, root / (name + "-candidate"), source, persona, args.resume)
        for field in ("instruction_count", "api_calls", "api_events", "completion_reason", "error",
                      "final_pc", "guest_entry_return", "kernel_pool", "kernel_threads"):
            check(old[field] == new[field], f"Mutex protocol unexpectedly changed {field}")
        check(new["kernel_state"]["guarded_mutex_count_protocol"] == "windows26200-x64-fast-mutex-stable-v1",
              "Wrong protocol selected")
        if zero:
            check(new["completion_reason"] == "error" and new["guest_entry_return"] is None
                  and "guarded mutex" in new["error"], "Zero-owner refusal changed")
            trace = new["kernel_state"]["guarded_mutex_trace"]
            check(any(row["operation"] == "acquire_attempt" and row["guest_count"] == 0
                      and row["guest_owner"] == 0 for row in trace)
                  and not any(row["operation"] == "acquired" for row in trace),
                  "Zero ownerless mutex was granted")
            check(old_result["artifacts"] == new_result["artifacts"], "Zero refusal changed captured bytes")
        else:
            check(new["guest_entry_return"] == 17 and new["completion_reason"] == "entry_return",
                  "Real generated mutex handoff did not finish")
            for execution, count in ((old, -1), (new, 4)):
                check(any(row["operation"] == "blocked" and row["guest_count"] == count
                          for row in execution["kernel_state"]["guarded_mutex_trace"]), "Wrong stable waiter count")
                check(execution["kernel_threads"]["resumed_waits"] == 1, "No actual resumed waiter")
            payloads = []
            for execution, run_name in ((old, name + "-baseline"), (new, name + "-candidate")):
                digest = execution["capture_runtime"]["post_image_sha256"]
                artifact = next(a for a in execution["artifacts"] if a["sha256"] == digest)
                payloads.append((root / run_name / "artifacts" / artifact["filename"]).read_bytes())
            old_bytes, new_bytes = payloads
            check(len(old_bytes) == len(new_bytes) and [i for i, (a,b) in enumerate(zip(old_bytes,new_bytes)) if a != b] == [0x2b10]
                  and old_bytes[0x2b10] == 0 and new_bytes[0x2b10] == 1,
                  "Expected only contention-counter change in generated mapped image")
        records.append({"case": name, "input_sha256": sha(source), "guest_instructions": new["instruction_count"],
                        "completion": new["completion_reason"], "verified": True})
    receipt = {"schema": "emumee.generated_guarded_count_verification.v1", "baseline_bundle": str(baseline),
               "candidate_bundle": str(bundle), "persona_sha256": sha(persona), "cases": records,
               "offline_containment_verified": True, "unpacking_confirmed": False}
    destination = root / "verification.json"
    if destination.exists():
        check(args.resume and load(destination) == receipt, "Saved receipt changed")
    else:
        destination.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print("Verified packaged Windows26200 waiter counts, real handoff and ownerless refusal")


if __name__ == "__main__":
    main()

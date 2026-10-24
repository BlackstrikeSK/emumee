"""Verify passive image-write coverage with harmless generated native/model stores."""
import argparse
import json
from pathlib import Path
import struct
import subprocess

from verify_rust_instruction_window import check, load, sha, verify_run, fixture as window_fixture

VALUE = 0x11223344


def fixture():
    image = bytearray(window_fixture("api"))
    code = bytearray(bytes.fromhex("4883ec28"))
    code += b"\xc7\x05" + struct.pack("<i", 0x21f1 - (0x1000 + len(code) + 10))
    code += struct.pack("<I", VALUE)
    for opcode, target in ((bytes.fromhex("488d15"), 0x21f1),
                           (bytes.fromhex("488d0d"), 0x21e1)):
        code += opcode + struct.pack("<i", target - (0x1000 + len(code) + 7))
    code += bytes.fromhex("41b804000000")
    code += b"\xff\x15" + struct.pack("<i", 0x20a0 - (0x1000 + len(code) + 6))
    code += b"\x8b\x05" + struct.pack("<i", 0x21e1 - (0x1000 + len(code) + 6))
    code += bytes.fromhex("4883c428c3")
    image[0x200:0x400] = code + bytes(512 - len(code))
    return bytes(image)


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
                 "--service", "ImageWriteControl", "--max-instructions", "100",
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
    source = root / "generated-image-writes.sys"
    data = fixture()
    if source.exists():
        check(args.resume and source.read_bytes() == data, "Generated source changed")
    else:
        check(not args.resume, "Resume lacks source")
        source.write_bytes(data)
    old, old_result = run(baseline, root / "baseline", source, args.resume)
    new, new_result = run(bundle, root / "candidate", source, args.resume)
    for field in ("instruction_count", "api_calls", "api_events", "completion_reason", "error",
                  "final_pc", "guest_entry_return", "kernel_pool", "kernel_state", "image_load",
                  "modeled_guest_regions", "capture_runtime", "capture_summary"):
        check(old[field] == new[field], f"Image observer changed guest field {field}")
    check(old_result["artifacts"] == new_result["artifacts"], "Captured bytes changed")
    check(new["guest_entry_return"] == VALUE, "Generated native/model copy failed")
    check("image_writes" not in old, "Baseline already has observer")
    report = new["image_writes"]
    check(report["installed_instruction_count"] == 0 and not report["omitted_regions"]
          and report["observations_omitted"] == 0, "Observer coverage is incomplete")
    check(report["native_overlapping_attempts"] == 1
          and report["model_overlapping_writes"] == 1, "Native/model stores not observed")
    region = next(r for r in report["watched_regions"] if r["base"] == new["image_load"]["base"] + 0x2000)
    bitmap = region["touched_byte_bitmap"]
    touched = {index * 8 + bit for index, value in enumerate(bitmap)
               for bit in range(8) if value & (1 << bit)}
    check(touched == set(range(0x1e1, 0x1e5)) | set(range(0x1f1, 0x1f5)),
          "Byte coverage includes missing or extra bytes")
    receipt = {"schema": "emumee.generated_image_write_verification.v1",
               "baseline_bundle": str(baseline), "candidate_bundle": str(bundle),
               "input_sha256": sha(source), "guest_effects_equal": True,
               "artifacts_equal": True, "native_and_model_coverage_verified": True,
               "offline_containment_verified": True, "unpacking_confirmed": False}
    destination = root / "verification.json"
    if destination.exists():
        check(args.resume and load(destination) == receipt, "Saved receipt changed")
    else:
        destination.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print("Verified generated native/model image-write coverage and unchanged guest effects")


if __name__ == "__main__":
    main()

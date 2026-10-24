"""Verify explicit guest service ImagePath authority on generated drivers only."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from verify_rust_kernel_loader import load, sha, check, build_driver, REFERENCE

SERVICE = "PathControl"
SUCCESS = 0x50415431
EXPLICIT = r"C:\Program Files\Emumee Fixtures\PathControl.sys"
FALLBACK = r"C:\Windows\System32\drivers\PathControl.sys"
KEY = rf"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\{SERVICE}"


def fixture(path):
    image = bytearray(build_driver(0x8664))
    image[0x200:0x400] = bytes(512)
    text = path.encode("utf-16-le")
    check(len(text) <= 126, "Generated expected path exceeds its data buffer")
    image[0x580:0x580 + len(text)] = text
    code = bytearray.fromhex("56 57 488b4128 4885c0 0f84") + bytes(4)
    failures = [len(code) - 4]
    code += bytes.fromhex("0fb74848 81f9") + struct.pack("<I", len(text)) + bytes.fromhex("0f85") + bytes(4)
    failures.append(len(code) - 4)
    code += bytes.fromhex("488b7050 488d3d")
    code += struct.pack("<i", 0x2180 - (0x1000 + len(code) + 4))
    code += bytes.fromhex("d1e9 fc f366a7 0f85") + bytes(4)
    failures.append(len(code) - 4)
    code += b"\xb8" + struct.pack("<I", SUCCESS) + bytes.fromhex("5f 5e c3")
    failed = len(code)
    code += bytes.fromhex("b80d0000c0 5f 5e c3")
    for offset in failures:
        struct.pack_into("<i", code, offset, failed - offset - 4)
    image[0x200:0x200 + len(code)] = code
    return image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--persona", type=Path, required=True)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    bundle, root, reference = args.bundle.resolve(), args.root.resolve(), args.reference.resolve()
    check(not root.exists() or args.resume, "Preserve controls; use fresh root or --resume")
    check(sha(reference) == REFERENCE, "Only exact pinned reference admitted")
    receipt = load(bundle / "rust-worker-build.json")
    for file, key in [("emumee-rs.exe", "controller_sha256"), ("emumee-worker.exe", "worker_sha256"), ("unicorn.dll", "unicorn_sha256")]:
        check(sha(bundle / file) == receipt[key], "Frozen binary differs from receipt")
    baseline = load(args.persona)
    root.mkdir(exist_ok=args.resume)
    cases = [
        ("dos", KEY, "REG_SZ", EXPLICIT, EXPLICIT),
        ("nt-dos", KEY, "REG_EXPAND_SZ", "\\??\\" + EXPLICIT, EXPLICIT),
        ("absent", None, None, None, FALLBACK),
        ("other-service", KEY + "Other", "REG_SZ", EXPLICIT, FALLBACK),
        ("wrong-type", KEY, "REG_DWORD", 1, None),
        ("wrong-basename", KEY, "REG_SZ", r"C:\Fixtures\Other.sys", None),
        ("command", KEY, "REG_SZ", '"' + EXPLICIT + '" --boot', None),
        ("unexpanded", KEY, "REG_EXPAND_SZ", r"%SystemRoot%\System32\drivers\PathControl.sys", None),
    ]
    records = []
    for name, key, value_type, declaration, expected in cases:
        source, persona, run = root / f"{name}.sys", root / f"{name}.persona.json", root / name
        model = copy.deepcopy(baseline)
        check(not any(k["path"].lower().rstrip("\\").replace("hklm\\", "hkey_local_machine\\") == KEY.lower() for k in model["registry_keys"]), "Baseline already declares test service")
        if key:
            model["registry_keys"].append({"path": key, "values": [{"name": "ImagePath", "type": value_type, "data": declaration}]})
        generated = fixture(expected or FALLBACK)
        if source.exists():
            check(source.read_bytes() == generated and load(persona) == model, "Saved generated input/persona changed")
        else:
            source.write_bytes(generated)
            persona.write_text(json.dumps(model, indent=2) + "\n")
        if run.exists():
            check(args.resume, "Existing run requires --resume")
        else:
            command = [str(bundle / "emumee-rs.exe"), "submitted-driver", str(source), str(run), "--service", SERVICE, "--max-instructions", "1000", "--timeout-us", "30000000", "--kernel-code-reference", str(reference), "--persona", str(persona)]
            with (root / f"{name}.console.log").open("wb") as out:
                process = subprocess.run(command, stdout=out, stderr=subprocess.STDOUT)
            check(process.returncode == (0 if expected else 1), "Submitted path control processing status differs")
        manifest = load(run / "controller-manifest.json")
        request = load(run / "request.json")
        check(request["input_sha256"] == sha(source) == sha(run / "input.sys") and request["kernel_code_reference_sha256"] == REFERENCE == sha(run / "kernel-code-reference.pe") and request["persona_sha256"] == sha(run / "persona.json") and request["service_name"] == SERVICE and request["max_instructions"] == 1000, "Staged input/reference/persona/service request differs")
        check(manifest["request_sha256"] == sha(run / "request.json") and manifest["input_sha256"] == sha(source) and manifest["persona_sha256"] == sha(run / "persona.json") and manifest["persona_source_sha256"] == sha(persona) and manifest["source_tree_sha256"] == receipt["source_tree_sha256"], "Positive or failed run belongs to another request/input/persona/source")
        exit_record, job, stop = [load(run / n) for n in ("worker-exit.json", "driver-job-profile.json", "worker-stop.json")]
        witness = load(run / "worker-containment.json")
        check(witness["app_container"] and witness["job_object"] and witness["child_process_blocked"] and witness["network_capabilities"] == 0 and job["active_process_limit"] == 1 and job["profile"] == "driver_capture_2048_v1" and job["process_memory_bytes"] == 2147483648 and 0 < job["peak_process_memory_bytes"] <= 2147483648, "Offline worker containment differs")
        check(exit_record["cleanup"] == job["cleanup"] == stop["cleanup"] == "restored", "Worker cleanup differs")
        if expected:
            result, report, request = load(run / "worker-result.json"), load(run / "engine-report.json"), load(run / "request.json")
            check(manifest["status"] == "verified" and manifest["guest_status"] == result["status"] == "processed" and manifest["cleanup"] == "restored" and exit_record["exit_code"] == 0, "Positive worker result differs")
            for field in ("source_tree_sha256", "controller_sha256", "worker_sha256", "unicorn_sha256"):
                check(manifest[field] == receipt[field], "Control used another frozen bundle")
            check(manifest["worker_result_sha256"] == sha(run / "worker-result.json") and result["engine_report_sha256"] == sha(run / "engine-report.json"), "Report/result binding differs")
            for row in (manifest, result["binding"], report["binding"]):
                check(row["request_sha256"] == sha(run / "request.json") and row["input_sha256"] == sha(source) and row["source_tree_sha256"] == receipt["source_tree_sha256"], "Input/request/source binding differs")
            check(manifest["persona_source_sha256"] == sha(persona) and manifest["persona_sha256"] == sha(run / "persona.json") and request["persona_sha256"] == manifest["persona_sha256"] and request["kernel_code_reference_sha256"] == REFERENCE, "Persona/reference binding differs")
            e = report["execution"]
            check(e["completion_reason"] == "entry_return" and e["guest_entry_return"] == SUCCESS and e["error"] is None and e["network"]["calls"] == 0, "Native full path comparison failed")
            check(e["configuration"]["guest_image_path"] == expected, "Configuration path differs")
            primary = next(n for n in e["kernel_loader"]["nodes"] if n["address"] == e["kernel_loader"]["driver_section"])
            check(primary["guest_path"] == expected and primary["accepted_image_sha256"] == sha(source) and not e["kernel_loader"]["denials"] and e["kernel_loader"]["native_reads"] >= 3, "Loader path/provenance or native consumption differs")
            authority = e["configuration"]["submitted_service_image_path"]
            check(authority["service"] == SERVICE and authority["registry_key"] == KEY and authority["value_name"] == "ImagePath" and authority["normalized_path"] == expected, "Submitted service path authority differs")
            explicit = name in ("dos", "nt-dos")
            if explicit:
                check(authority["source"] == "validated_guest_registry_image_path" and authority["declared_path"] == declaration and authority["value_type"] == (1 if name == "dos" else 2) and authority["registry_value_sha256"] == hashlib.sha256((declaration + "\0").encode("utf-16-le")).hexdigest() and authority["normalization"] == ("absolute_dos_preserved" if name == "dos" else "nt_dos_prefix_removed"), "Declared service seed provenance differs")
            else:
                check(authority["source"] == "documented_absent_service_image_path_fallback" and authority["declared_path"] is None and authority["value_type"] is None and authority["registry_value_sha256"] is None and authority["normalization"] == "documented_default", "Absent exact service path did not retain documented fallback")
            completion = e["completion_reason"]
        else:
            result = load(run / "worker-result.json")
            check(manifest["status"] == "verified_refusal" and manifest["guest_status"] == result["status"] == "unreported_failure" and manifest["cleanup"] == "restored" and exit_record["exit_code"] == 0 and not (run / "engine-report.json").exists() and result["artifacts"] == [] and not manifest["unpacking_confirmed"], "Malformed path was admitted or invented a complete engine report")
            check(manifest["worker_result_sha256"] == sha(run / "worker-result.json"), "Typed refusal result binding differs")
            for field in ("source_tree_sha256", "controller_sha256", "worker_sha256", "unicorn_sha256"):
                check(manifest[field] == receipt[field], "Typed refusal used another frozen bundle")
            binding = result["binding"]
            check(binding["request_sha256"] == sha(run / "request.json") and binding["input_sha256"] == sha(source) and binding["source_tree_sha256"] == receipt["source_tree_sha256"] and binding["persona_sha256"] == sha(run / "persona.json") and binding["kernel_code_reference_sha256"] == REFERENCE and binding["service_name"] == SERVICE, "Typed refusal source/input/persona/reference/service binding differs")
            errors = {"wrong-type": "Submitted service ImagePath requires REG_SZ or REG_EXPAND_SZ", "wrong-basename": "Submitted service ImagePath basename differs from bound service identity", "command": "Submitted service ImagePath requires an absolute DOS path", "unexpanded": "Submitted service ImagePath requires an absolute DOS path"}
            check(errors[name] in result["error"], "Failure does not identify the expected service-path validation")
            completion = "verified_path_validation_refusal_no_complete_engine_report"
        records.append({"case": name, "verified": True, "run": str(run), "source_tree_sha256": receipt["source_tree_sha256"], "completion": completion, "cleanup": "restored", "unpacking_confirmed": False})
        (root / "verification.json").write_text(json.dumps(records, indent=2) + "\n")
    print("Verified 8 harmless submitted service path controls; no host service or real driver execution.")


if __name__ == "__main__":
    main()

"""Verify passive context receipts using only frozen generated CPU fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def load(path):
    return json.loads(path.read_text(encoding="utf-8-sig"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    bundle, root = args.bundle.resolve(), args.root.resolve()
    check(not root.exists(), "Preserve existing context controls; choose a fresh root")
    receipt = load(bundle / "rust-worker-build.json")
    for name, key in [("emumee-rs.exe", "controller_sha256"),
                      ("emumee-worker.exe", "worker_sha256"), ("unicorn.dll", "unicorn_sha256")]:
        check(sha(bundle / name) == receipt[key], "Frozen binary differs from receipt")
    root.mkdir()
    records = []
    for arch in ("x86", "x64"):
        for kind in ("kernel-entry", "kernel-cpu", "shared-time", "shared-time-write", "cpu-tsc-msr-user"):
            run = root / f"{arch}-{kind}"
            console = root / f"{arch}-{kind}.console.log"
            with console.open("wb") as out:
                process = subprocess.run([str(bundle / "emumee-rs.exe"), "fixture", "--arch", arch,
                                          "--kind", kind, "--max-instructions", "10000",
                                          "--isolated-output", str(run)], stdout=out, stderr=subprocess.STDOUT)
            manifest = load(run / "manifest.json")
            check(load(console) == manifest, "Controller stdout differs from saved manifest")
            request = load(run / "request.json")
            result = load(run / "fixture-result.json")
            exit_record = load(run / "worker-exit.json")
            for key in ("source_tree_sha256", "controller_sha256", "worker_sha256", "unicorn_sha256"):
                check(manifest[key] == receipt[key], "Control belongs to another build")
            check(manifest["request_sha256"] == sha(run / "request.json")
                  and manifest["result_sha256"] == sha(run / "fixture-result.json")
                  and result["request_sha256"] == manifest["request_sha256"]
                  and manifest["result"] == result, "Request/result binding differs")
            check(request["architecture"] == arch and request["kind"] == kind
                  and request["max_instructions"] == 10000, "Generated fixture request changed")
            containment = result["containment"]
            check(containment["app_container"] and containment["job_object"]
                  and containment["child_process_blocked"] and containment["network_capabilities"] == 0
                  and manifest["cleanup"] == exit_record["cleanup"] == "restored"
                  and exit_record["exit_code"] == 0, "Offline containment or cleanup differs")
            e = result["execution"]
            negative = kind in ("shared-time-write", "cpu-tsc-msr-user")
            check(e["architecture"] == arch and e["backend"] == "rust/unicorn-x86"
                  and e["network"]["calls"] == 0, "Native fixture execution changed")
            if negative:
                expected = "WRITE_PROT" if kind == "shared-time-write" else "CPL0 driver context"
                check(process.returncode == 1 and e["completion_reason"] == "error"
                      and e["guest_entry_return"] is None and expected in e["error"],
                      "Negative native fixture invented completion")
            else:
                check(process.returncode == 0 and e["completion_reason"] == "entry_return"
                      and e["guest_entry_return"] == 1 and e["error"] is None,
                      "Generated native assertion or entry return changed")
            context = e["kernel_context_reads"]
            regions = set()
            if kind == "cpu-tsc-msr-user":
                check(context is None and e["kernel_entry"] is None,
                      "User target invented kernel context observation")
            else:
                check(context["hook_installed"] and context["unique_limit"] == 256
                      and context["sample_failures"] == context["pc_failures"] == 0
                      and context["omitted_unstored_attempts"] == context["cross_boundary_attempts"] == 0
                      and len(context["receipts"]) <= context["unique_limit"],
                      "Context bounds, sampling or hook receipt differs")
                rows = context["receipts"]
                check(context["watched_read_attempts"] == sum(1 + row["repeats"] for row in rows),
                      "Native attempt/repeat accounting differs")
                for row in rows:
                    regions.add(row["region"])
                    check(row["region"] in context["watched_pages"]
                          and row["pc"] > 0 and row["size"] > 0
                          and 0 < row["raw_memory_hook_instruction_count"]
                          <= row["last_raw_memory_hook_instruction_count"] <= e["instruction_count"]
                          and row["sample_error"] is None and not row["crosses_region_boundary"]
                          and row["sampled_address"] == row["address"]
                          and row["offset"] == row["address"] - row["region_base"]
                          and len(row["sampled_prefix"]) == min(row["size"], 16)
                          and row["offset"] + len(row["sampled_prefix"]) <= 4096
                          and row["execution_domain"] == "ordinary_thread",
                          "Observed pre-read prefix or native context metadata differs")
                if kind == "kernel-entry":
                    check({"driver_object_page", "registry_path_page"} <= regions,
                          "DriverEntry fixture lost its actual header/path reads")
                    header = next(row for row in rows if row["region"] == "driver_object_page"
                                  and row["offset"] == 0)
                    check(header["sampled_prefix"][:2] == [4, 0], "Driver header Type bytes changed")
                if kind == "kernel-cpu":
                    check("kpcr_prcb_page" in regions, "Native segment-relative PCR reads were missed")
                if kind == "shared-time":
                    check("kuser_shared_data_user" in regions and any(
                        name in regions for name in ("kuser_shared_data_kernel", "kuser_shared_data_compat")),
                        "Shared-data alias reads were missed")
            records.append({"arch": arch, "kind": kind, "run": str(run), "verified": True,
                            "source_tree_sha256": receipt["source_tree_sha256"],
                            "completion": e["completion_reason"], "cleanup": "restored",
                            "context_regions": sorted(regions), "unpacking_confirmed": False})
            (root / "verification.json").write_text(json.dumps(records, indent=2) + "\n")
    check(len(records) == 10, "Context-control count differs")
    print("Verified 10 harmless x86/x64 context controls; no real driver execution or unpacking claimed.")


if __name__ == "__main__":
    main()

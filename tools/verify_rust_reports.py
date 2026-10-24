"""Inspect generated legacy report trees; never launch a worker or sample."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("utf-8")


def base():
    return {"id": "20261018T120000Z-deadbeef", "sample": {"name": "generated-report-fixture"}, "status": "partial", "artifacts": [], "errors": []}


def bound():
    summary = base()
    summary.update(status="completed", completion_reason="entry_return", run_manifest={"engine_report_integrity": "sha256-v1", "network_broker_report_integrity": "sha256-v1"})
    files = {"engine-report.json": b'{"owned_fixture_trace":[]}', "network-broker.json": b'{"owned_fixture_attempts":[]}'}
    for prefix, name in [("engine_report", "engine-report.json"), ("network_broker_report", "network-broker.json")]:
        summary.update({prefix: name, prefix + "_sha256": digest(files[name]), prefix + "_size": len(files[name])})
    return summary, files


def artifact_fixture(payload=b"\x00\xff\x10RUST\x00", observations=2, groups=True):
    summary = base()
    sha = digest(payload)
    filename = sha[:20] + ".bin"
    items = [{"sha256": sha, "file": filename, "size": len(payload), "kind": "memory", "source": "memory_fixture" if i == 0 else "virtual_file_final", "guest_path": "../../guest-only", "context": {"fixture_index": i}} for i in range(observations)]
    summary["artifacts"] = items
    if groups:
        snippet = payload[:256]
        printable = all(byte in (9, 10, 13) or 32 <= byte < 127 for byte in snippet)
        summary["artifact_groups"] = [{"sha256": sha, "file": filename, "size": len(payload), "kind": "binary", "preview": snippet.decode("ascii") if printable else payload[:32].hex(), "preview_encoding": "text" if printable else "hex", "observations": [{"source": item["source"], "guest_path": item["guest_path"], "kind": item["kind"], "stage": "memory" if i == 0 else "final", "context": item["context"]} for i, item in enumerate(items)]}]
    return summary, {"artifacts/manifest.json": encoded(items), "artifacts/" + filename: payload}


def build_cases():
    cases = []

    def add(name, summary=None, files=None, *, verify=False, accepted=True, error=None, checks=None, summary_raw=None, hardlink=None):
        cases.append({"name": name, "summary": deepcopy(base() if summary is None else summary), "files": deepcopy(files or {}), "verify": verify, "accepted": accepted, "error": error, "checks": checks or {}, "summary_raw": summary_raw, "hardlink": hardlink})

    add("minimal-partial", checks={"status": "partial", "reports.engine.integrity": "not_declared", "artifacts.integrity": "not_checked"})
    summary, files = bound()
    add("both-reports-bound", summary, files, checks={"reports.engine.integrity": "verified_sha256_v1", "reports.network_broker.integrity": "verified_sha256_v1", "reports.engine.bytes": len(files["engine-report.json"]), "status": "completed"})
    legacy = base(); legacy.update(engine_report="engine-report.json", network_broker_report="network-broker.json")
    add("legacy-unbound-labeled", legacy, files, checks={"reports.engine.integrity": "legacy_unbound", "reports.network_broker.integrity": "legacy_unbound"})
    for name in ["engine-report.json", "network-broker.json"]:
        broken = dict(files); broken[name] = b"X" + files[name][1:]
        add(name + "-same-size-corrupt", summary, broken, accepted=False, error="hash or length binding")
        broken = dict(files); broken[name] = files[name][:-1]
        add(name + "-truncated", summary, broken, accepted=False, error="hash or length binding")
        broken = dict(files); del broken[name]
        add(name + "-absent-declared", summary, broken, accepted=False, error="could not be safely read")
    for prefix in ["engine_report", "network_broker_report"]:
        bad = deepcopy(summary); bad[prefix + "_size"] += 1
        add(prefix + "-size-mismatch", bad, files, accepted=False, error="hash or length binding")
        bad = base(); bad[prefix] = "../outside.json"
        add(prefix + "-traversal-name", bad, {"outside.json": b"harmless canary"}, accepted=False, error="Invalid fixed")
    bad = deepcopy(summary); bad["engine_report_sha256"] = bad["engine_report_sha256"].upper()
    add("binding-uppercase-digest", bad, files, accepted=False, error="Summary envelope validation failed")
    for name, fields in [
        ("completed-unknown-reason", {"status": "completed", "completion_reason": "unknown"}),
        ("boolean-instruction-count", {"instruction_count": True}),
        ("completed-failed-integrity", {"status": "completed", "artifact_integrity": "failed"}),
        ("invalid-status-enum-array", {"status": []}),
    ]:
        add(name, {**base(), **fields}, accepted=False, error="Summary envelope validation failed")
    add("malformed-summary-json", summary_raw=b'{"broken":', accepted=False, error="Summary envelope validation failed")
    add("summary-exceeds-byte-bound", summary_raw=b" " * (5 * 1024 * 1024 + 1), accepted=False, error="Summary could not be safely read")
    memory = base(); memory["memory_strings"] = {"enabled": True, "truncated": False, "scanned_bytes": 0, "regex": [], "limits": [], "matches": [{"format": "url", "encoding": "managed", "value": "https://fixture.invalid/<script>fixture</script>", "source": "fixture", "offset": 0, "address": None}]}
    add("memory-metadata-not-rendered", memory, checks={"status": "partial"})

    artifacts, payload_files = artifact_fixture()
    add("binary-artifacts-and-derived-groups", artifacts, payload_files, verify=True, checks={"artifacts.integrity": "verified", "artifacts.observations": 2, "artifacts.groups": "reconstructed_and_verified", "artifacts.payload_reads": 2, "artifacts.inspected_bytes": 16})
    add("empty-manifest", files={"artifacts/manifest.json": b"[]"}, verify=True, checks={"artifacts.integrity": "verified", "artifacts.payload_reads": 0})
    no_items = base(); del no_items["artifacts"]
    add("missing-artifacts-defaults-empty", no_items, {"artifacts/manifest.json": b"[]"}, verify=True, checks={"artifacts.observations": 0})
    payload_name = next(key for key in payload_files if key != "artifacts/manifest.json")
    for name, raw in [("payload-same-size-corrupt", b"X" + payload_files[payload_name][1:]), ("payload-truncated", payload_files[payload_name][:-1])]:
        bad_files = dict(payload_files); bad_files[payload_name] = raw
        add(name, artifacts, bad_files, verify=True, accepted=False, error="failed verification")
    bad_manifest = deepcopy(artifacts["artifacts"]); bad_manifest[0]["source"] = "fabricated source"
    bad_files = dict(payload_files); bad_files["artifacts/manifest.json"] = encoded(bad_manifest)
    add("manifest-provenance-tamper", artifacts, bad_files, verify=True, accepted=False, error="failed verification")
    bad_files = dict(payload_files); bad_files["artifacts/manifest.json"] = encoded(list(reversed(artifacts["artifacts"])))
    add("manifest-order-tamper", artifacts, bad_files, verify=True, accepted=False, error="failed verification")
    for name, field, value in [("group-preview-tamper", "preview", "fabricated preview"), ("group-observation-tamper", "observations", [{}, {}])]:
        bad = deepcopy(artifacts); bad["artifact_groups"][0][field] = value
        add(name, bad, payload_files, verify=True, accepted=False, error="failed verification")
    for name, filename in [("artifact-traversal", "../outside.bin"), ("artifact-named-stream", artifacts["artifacts"][0]["file"] + ":stream"), ("artifact-prefix-mismatch", "b" * 20 + ".bin")]:
        bad = deepcopy(artifacts); bad.pop("artifact_groups"); bad["artifacts"][0]["file"] = filename
        bad_files = dict(payload_files); bad_files["artifacts/manifest.json"] = encoded(bad["artifacts"])
        add(name, bad, bad_files, verify=True, accepted=False, error="failed verification")
    missing = dict(payload_files); del missing[payload_name]
    add("artifact-missing", artifacts, missing, verify=True, accepted=False, error="could not be safely read")
    add("artifacts-optional-not-checked", artifacts, missing, checks={"artifacts.integrity": "not_checked", "artifacts.observations": 2})
    no_groups = deepcopy(artifacts); del no_groups["artifact_groups"]
    add("artifacts-without-declared-groups", no_groups, payload_files, verify=True, checks={"artifacts.integrity": "verified", "artifacts.groups": "not_declared"})
    for name, manifest in [("manifest-malformed", b"["), ("manifest-wrong-root", b"{}")]:
        bad_files = dict(payload_files); bad_files["artifacts/manifest.json"] = manifest
        add(name, artifacts, bad_files, verify=True, accepted=False, error="failed verification")
    bad = deepcopy(no_groups); bad["artifacts"][0]["size"] = 0
    bad_files = dict(payload_files); bad_files["artifacts/manifest.json"] = encoded(bad["artifacts"])
    add("artifact-zero-size-invalid", bad, bad_files, verify=True, accepted=False, error="failed verification")
    add("summary-hardlink-rejected", hardlink="summary.json", accepted=False, error="Summary could not be safely read")
    add("artifact-hardlink-rejected", artifacts, payload_files, verify=True, hardlink=payload_name, accepted=False, error="could not be safely read")

    # One owned16MiB payload is referenced repeatedly:8reads exactly reach128MiB;
    # the ninth is rejected before reading. No huge or sparse host input needed.
    payload = b"RUST-REPORT-BUDGET" * ((16 * 1024 * 1024 // 18) + 1)
    payload = payload[:16 * 1024 * 1024]
    assert len(payload) == 16 * 1024 * 1024
    for count, accepted in [(8, True), (9, False)]:
        budget_summary, budget_files = artifact_fixture(payload, observations=count, groups=False)
        add(f"artifact-budget-{count}-reads", budget_summary, budget_files, verify=True, accepted=accepted, error=None if accepted else "128 MiB cumulative read budget", checks={"artifacts.inspected_bytes": 128 * 1024 * 1024, "artifacts.payload_reads": 8} if accepted else None)
    return cases


def snapshot(root):
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_file():
            sha = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    sha.update(chunk)
            result[str(path.relative_to(root))] = {"bytes": path.stat().st_size, "sha256": sha.hexdigest()}
    return result


def get_path(value, path):
    for component in path.split("."):
        value = value[component]
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--output-root", required=True)
    args = parser.parse_args()
    exe = Path(args.bundle).resolve() / "emumee-rs.exe"
    if not exe.is_file():
        raise ValueError("Packaged controller executable missing")
    root = Path(args.output_root).resolve()
    root.mkdir(exist_ok=False)
    rows = []
    creationflags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    for case in build_cases():
        case_root = root / case["name"]
        run = case_root / "run"
        run.mkdir(parents=True)
        (run / "summary.json").write_bytes(case["summary_raw"] if case["summary_raw"] is not None else encoded(case["summary"]))
        for relative, raw in case["files"].items():
            path = run / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        if case["hardlink"]:
            target = run / case["hardlink"]
            # The extra name is wholly inside this fresh generated fixture.
            (case_root / "owned-hardlink-copy").hardlink_to(target)
        before = snapshot(case_root)
        command = [str(exe), "inspect-report", str(run)]
        if case["verify"]:
            command.append("--verify-artifacts")
        actual_exit = None
        try:
            process = subprocess.run(command, capture_output=True, check=False, timeout=90, creationflags=creationflags)
            actual_exit = process.returncode
            (case_root / "stdout.txt").write_bytes(process.stdout)
            (case_root / "stderr.txt").write_bytes(process.stderr)
            # Output capture lives outside the inspected tree; compare that tree
            # plus the hardlink name, excluding only our own saved console files.
            after = snapshot(case_root)
            after.pop("stdout.txt", None); after.pop("stderr.txt", None)
            if before != after:
                raise AssertionError("Inspection modified generated input files")
            expected_exit = 0 if case["accepted"] else 2
            if process.returncode != expected_exit:
                raise AssertionError(f"Expected exit{expected_exit}, got{process.returncode}: {process.stderr.decode('utf-8', errors='replace')}")
            if case["error"] and case["error"] not in process.stderr.decode("utf-8", errors="replace"):
                raise AssertionError("Expected rejection reason absent: " + case["error"])
            if case["accepted"]:
                result = json.loads(process.stdout)
                for path, expected in case["checks"].items():
                    if get_path(result, path) != expected:
                        raise AssertionError(f"Metadata mismatch at{path}: {get_path(result, path)!r} != {expected!r}")
                if "owned_fixture_trace" in process.stdout.decode("utf-8") or "<script>" in process.stdout.decode("utf-8"):
                    raise AssertionError("Reader printed raw trace or memory indicator content")
            rows.append({"case": case["name"], "accepted": case["accepted"], "exit": process.returncode, "verify_artifacts": case["verify"], "source_unchanged": True, "verified": True})
        except Exception as error:
            rows.append({"case": case["name"], "accepted": case["accepted"], "exit": actual_exit, "verified": False, "error": str(error)})
            (root / "verification.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
            raise
        (root / "verification.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    print(f"Verified {len(rows)} generated read-only report binding/artifact/provenance/file-boundary controls; no worker or sample executed.")


if __name__ == "__main__":
    main()

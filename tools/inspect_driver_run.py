"""Verify a finished offline driver run and print its observed stopping point.

This reads reports and artifacts only; it does not execute the driver. A verified
trace may still describe partial emulation, a failed DriverEntry, or no unpacking.
"""

import argparse
import hashlib
import json
from pathlib import Path

from emumee.reports import (
    MAX_SUMMARY_BYTES,
    read_verified_engine_report,
    read_verified_network_report,
    valid_summary,
    verify_artifact_manifest,
)
from emumee.safeio import read_regular_file


def require(condition, message):
    if not condition:
        raise ValueError(message)


def inspect(run, sample=None):
    raw = read_regular_file(run / "summary.json", MAX_SUMMARY_BYTES)
    require(raw is not None, "Missing or unsafe summary")
    summary = json.loads(raw)
    require(valid_summary(summary), "Invalid summary envelope")
    require(summary.get("execution_mode") == "kernel", "Run is not a driver run")
    require(summary.get("status") in {"completed", "partial"}, "Run has not finished with a trace")
    require(summary.get("guest_trace_complete") is True, "Trace capture did not complete")
    containment = summary.get("worker_containment") or {}
    require(all(containment.get(key) is True for key in (
        "app_container", "job_object", "child_process_blocked")), "Missing worker containment evidence")
    manifest = summary.get("run_manifest") or {}
    require(manifest.get("network_mode") == "offline_replay", "Expected an offline replay run")
    require(manifest.get("engine_report_integrity") == "sha256-v1" and
            manifest.get("network_broker_report_integrity") == "sha256-v1", "Missing report digest bindings")
    engine_raw = read_verified_engine_report(run, summary)
    require(engine_raw is not None, "Engine report digest or size mismatch")
    network_raw = read_verified_network_report(run, summary)
    require(network_raw is not None, "Broker report digest or size mismatch")
    network_events = json.loads(network_raw)
    require(summary.get("network_broker_complete") is True and isinstance(network_events, list) and
            bool(network_events) and network_events[-1] == {"event": "broker_closed"},
            "Offline broker did not close cleanly")
    require(verify_artifact_manifest(run, summary["artifacts"], summary["artifact_groups"]),
            "Artifact bytes, hashes or groups do not match")
    digest = hashlib.sha256()
    with (run / "input.pe").open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    expected = summary["sample"]["sha256"]
    require(digest.hexdigest() == expected, "Captured input hash mismatch")
    require(manifest.get("sample", {}).get("sha256") == expected and
            manifest.get("execution_target", {}).get("sha256") == expected, "Manifest input hash mismatch")
    if sample is not None:
        digest = hashlib.sha256()
        with sample.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        require(digest.hexdigest() == expected, "Requested sample differs from the captured input")
    engine = json.loads(engine_raw)
    reference = engine.get('kernel_code_reference')
    if reference is not None:
        from emumee.kernel_code_reference import MAX_REFERENCE_BYTES, reference_identity
        declared = manifest.get('kernel_code_reference')
        require(isinstance(declared, dict), 'Kernel reference is missing its parent manifest binding')
        raw_reference = read_regular_file(run/'kernel-code-reference.pe', MAX_REFERENCE_BYTES, containment_root=run)
        require(raw_reference is not None, 'Kernel reference bytes are missing or unsafe')
        identity = reference_identity(raw_reference)
        require(identity == declared and all(reference.get(k) == v for k,v in identity.items()),
                'Kernel reference bytes or identity differ from the parent manifest')
        require(reference.get('execution_allowed') is False and reference.get('permissions') == 'r--',
                'Kernel reference execution/protection policy is not explicit')
    entries = engine.get("entry_points") or []
    require(sum(int(entry.get("instr_count") or 0) for entry in entries) == summary["instruction_count"],
            "Instruction count differs between trace and summary")
    require(engine.get("driver") == summary.get("driver") and
            engine.get("driver_image_changes") == summary.get("driver_image_changes"),
            "Driver state differs between trace and summary")
    stopping_entry = next((entry for entry in entries if entry.get("error")), entries[-1] if entries else {})
    calls = [event for event in stopping_entry.get("events") or [] if event.get("event") == "api"]
    errors = ([entry["error"] for entry in entries if entry.get("error")] +
              (engine.get("errors") or []))
    return {
        "report_integrity_verified": True,
        "run": str(run),
        "sample_sha256": expected,
        "worker_sha256": manifest.get("worker_bundle_sha256"),
        "status": summary["status"],
        "completion_reason": summary.get("completion_reason"),
        "instruction_count": summary["instruction_count"],
        "driver": summary.get("driver"),
        "kernel_scheduling": engine.get("kernel_scheduling"),
        "kernel_ipi": engine.get("kernel_ipi"),
        "kernel_cpu": engine.get("kernel_cpu"),
        "kernel_initial_system_process": engine.get("kernel_initial_system_process"),
        "kernel_address_boundaries": engine.get("kernel_address_boundaries"),
        "kernel_opaque_data": engine.get("kernel_opaque_data"),
        "driver_tracing": engine.get("driver_tracing"),
        "kernel_system_information": engine.get("kernel_system_information"),
        "kernel_memory_capture": engine.get("kernel_memory_capture"),
        "kernel_object_references": engine.get("kernel_object_references"),
        "kernel_named_callbacks": engine.get("kernel_named_callbacks"),
        "kernel_export_catalog": engine.get("kernel_export_catalog"),
        "kernel_debugger_state": engine.get("kernel_debugger_state"),
        "kernel_provider_reads": engine.get("kernel_provider_reads"),
        "kernel_formatting": engine.get("kernel_formatting"),
        "kernel_code_reference": engine.get("kernel_code_reference"),
        "kernel_provider_metadata": engine.get("kernel_provider_metadata"),
        "memory_layouts_captured": sum(entry.get("memory") is not None for entry in entries),
        "reported_dynamic_code": [{"entry_type": entry.get("ep_type"), "thread_id": entry.get("tid"),
                                   "segments": entry.get("dynamic_code_segments") or []}
                                  for entry in entries if entry.get("dynamic_code_segments")],
        "memory_evidence_note": "An absent memory layout/dynamic-code record does not establish that no allocated code executed",
        "image_changes": summary.get("driver_image_changes"),
        "artifact_observations": len(summary["artifacts"]),
        "unique_artifacts": len(summary["artifact_groups"]),
        "network_attempts": summary.get("network_attempts"),
        "api_coverage": summary.get("api_coverage"),
        "last_api_calls": calls[-8:],
        "api_tail_scope": {"entry_type": stopping_entry.get("ep_type"),
                           "thread_id": stopping_entry.get("tid"),
                           "selection": "first_run_with_error" if stopping_entry.get("error") else "last_recorded_run",
                           "note": "Tail of the selected run; per-run ticks do not establish global thread chronology"},
        "run_api_tails": [{"entry_type": entry.get("ep_type"), "thread_id": entry.get("tid"),
                           "instruction_count": entry.get("instr_count"),
                           "calls": [event for event in entry.get("events") or [] if event.get("event") == "api"][-4:]}
                          for entry in entries],
        "stopping_errors": errors,
        "summary_errors": summary["errors"],
        "stopped_registers": engine.get("stopped_registers"),
        "unpacking_assessment": "Inspect recovered bytes and execution evidence; trace integrity alone does not establish unpacking",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--sample", type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.run.resolve(), args.sample), indent=2))

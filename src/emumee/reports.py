"""Validate the small report envelope crossing from the worker to the host UI."""

from __future__ import annotations

import re
import hashlib
import json
from pathlib import Path

from .safeio import read_regular_file
from .console_output import MAX_CONSOLE_CHARS
from .artifacts import groups_from_payloads


MAX_SUMMARY_BYTES = 5 * 1024 * 1024
MAX_ENGINE_BYTES = 50 * 1024 * 1024
MAX_NETWORK_REPORT_BYTES = 64 * 1024 * 1024
RUN_ID = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")
ARTIFACT_NAME = re.compile(r"^[0-9a-f]{20}\.(?:pe|txt|bin)$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MAX_ARTIFACT_BYTES = 32 * 1024 * 1024
ENGINE_INTEGRITY = "sha256-v1"


def valid_summary(value) -> bool:
    if not isinstance(value, dict):
        return False
    if not isinstance(value.get("id"), str) or not RUN_ID.fullmatch(value["id"]):
        return False
    if not isinstance(value.get("sample"), dict):
        return False
    if value.get("status") not in {"running", "completed", "partial", "failed", "timeout"}:
        return False
    artifacts = value.get("artifacts", [])
    errors = value.get("errors", [])
    if not isinstance(artifacts, list) or len(artifacts) > 10_000 or not all(
            isinstance(item, dict) for item in artifacts):
        return False
    if not isinstance(errors, list) or not all(isinstance(item, str) for item in errors):
        return False
    integrity = value.get("artifact_integrity")
    if integrity is not None and integrity not in {"failed", "unverified"}:
        return False
    if integrity is not None and value["status"] in {"completed", "partial"}:
        return False
    if "unverified_artifact_count" in value and (
            type(value["unverified_artifact_count"]) is not int or
            not 0 <= value["unverified_artifact_count"] <= 10_000):
        return False
    for field in ("instruction_count", "denied_operations"):
        if field in value and (type(value[field]) is not int or
                               not 0 <= value[field] <= 100_000_000):
            return False
    if "instruction_limit_reached" in value and type(value["instruction_limit_reached"]) is not bool:
        return False
    if "timeout_reached" in value and type(value["timeout_reached"]) is not bool:
        return False
    for field in ("guest_trace_complete", "artifact_checkpoint_recovered"):
        if field in value and type(value[field]) is not bool:
            return False
    if "guest_exit_code" in value and (value["guest_exit_code"] is not None and
                                       (type(value["guest_exit_code"]) is not int or
                                        not 0 <= value["guest_exit_code"] <= 0xFFFFFFFF)):
        return False
    if "guest_entry_return" in value and (value["guest_entry_return"] is not None and
                                          (type(value["guest_entry_return"]) is not int or
                                           not 0 <= value["guest_entry_return"] <= 0xFFFFFFFF)):
        return False
    if "completion_reason" in value and value["completion_reason"] not in {
            "exit_process", "entry_return", "instruction_limit", "timeout", "error",
            "worker_failure", "unknown", "static_inspection"}:
        return False
    if (value["status"] == "completed" and
            value.get("completion_reason") not in (None, "exit_process", "entry_return")):
        return False
    if (value["status"] == "completed" and
            (errors or value.get("timeout_reached") or
             value.get("instruction_limit_reached"))):
        return False
    if "network_attempts" in value and (not isinstance(value["network_attempts"], list)
                                        or len(value["network_attempts"]) > 1000
                                        or not all(isinstance(item, dict)
                                                   for item in value["network_attempts"])):
        return False
    if "network_attempts_omitted" in value and (
            type(value["network_attempts_omitted"]) is not int or
            not 0 <= value["network_attempts_omitted"] <= 50_000):
        return False
    capture = value.get("artifact_capture")
    if capture is not None:
        if (not isinstance(capture, dict) or
                type(capture.get("omitted_observations")) is not int or
                not 0 <= capture["omitted_observations"] <= 1_000_000 or
                type(capture.get("omitted_bytes")) is not int or
                not 0 <= capture["omitted_bytes"] <= 1 << 50):
            return False
        reasons, examples = capture.get("reasons"), capture.get("examples")
        if (not isinstance(reasons, dict) or len(reasons) > 32 or
                any(not isinstance(name, str) or len(name) > 64 or
                    type(count) is not int or not 0 <= count <= 1_000_000
                    for name, count in reasons.items()) or
                not isinstance(examples, list) or len(examples) > 20 or
                any(not isinstance(item, dict) or
                    not isinstance(item.get("source"), str) or
                    len(item["source"]) > 256 or
                    not isinstance(item.get("reason"), str) or
                    len(item["reason"]) > 64 or
                    type(item.get("bytes")) is not int or
                    not 0 <= item["bytes"] <= 1 << 50
                    for item in examples)):
            return False
    manifest = value.get("run_manifest")
    if manifest is not None and not isinstance(manifest, dict):
        return False
    engine_hash = value.get("engine_report_sha256")
    engine_size = value.get("engine_report_size")
    if engine_hash is not None or engine_size is not None:
        if (value.get("engine_report") != "engine-report.json" or
                not isinstance(engine_hash, str) or not SHA256.fullmatch(engine_hash) or
                type(engine_size) is not int or not 0 < engine_size <= MAX_ENGINE_BYTES):
            return False
    if (isinstance(manifest, dict) and
            manifest.get("engine_report_integrity") == ENGINE_INTEGRITY and
            value["status"] in {"completed", "partial"} and engine_hash is None):
        return False
    broker_hash = value.get("network_broker_report_sha256")
    broker_size = value.get("network_broker_report_size")
    if broker_hash is not None or broker_size is not None:
        if (value.get("network_broker_report") != "network-broker.json" or
                not isinstance(broker_hash, str) or not SHA256.fullmatch(broker_hash) or
                type(broker_size) is not int or not 0 < broker_size <= MAX_NETWORK_REPORT_BYTES):
            return False
    if (isinstance(manifest, dict) and
            manifest.get("network_broker_report_integrity") == ENGINE_INTEGRITY and
            value["status"] in {"completed", "partial"} and broker_hash is None):
        return False
    groups = value.get("artifact_groups")
    if groups is not None:
        if not isinstance(groups, list) or len(groups) > len(artifacts):
            return False
        first_by_hash = {}
        counts_by_hash = {}
        for item in artifacts:
            digest = item.get("sha256")
            if not isinstance(digest, str) or not SHA256.fullmatch(digest):
                return False
            first_by_hash.setdefault(digest, item)
            counts_by_hash[digest] = counts_by_hash.get(digest, 0) + 1
        if len(groups) != len(first_by_hash):
            return False
        group_hashes = [group.get("sha256") for group in groups
                        if isinstance(group, dict)]
        if (len(group_hashes) != len(groups) or
                not all(isinstance(digest, str) for digest in group_hashes) or
                set(group_hashes) != set(first_by_hash)):
            return False
        if any(not isinstance(group, dict) or
               group.get("file") != first_by_hash[group["sha256"]].get("file") or
               group.get("size") != first_by_hash[group["sha256"]].get("size") or
               not isinstance(group.get("kind"), str) or
               group.get("preview_encoding") not in {"text", "hex"} or
               not isinstance(group.get("observations"), list) or
               len(group["observations"]) != counts_by_hash[group["sha256"]] or
               not isinstance(group.get("preview"), str) or len(group["preview"]) > 256
               for group in groups):
            return False
    persona = value.get("persona")
    if persona is not None and not isinstance(persona, dict):
        return False
    console = value.get("console_output")
    if console is not None:
        if not isinstance(console, dict) or not all(
                isinstance(console.get(stream), str) and
                len(console[stream]) <= MAX_CONSOLE_CHARS and
                type(console.get(stream + "_truncated")) is bool
                for stream in ("stdout", "stderr")):
            return False
    coverage = value.get("api_coverage")
    if coverage is not None:
        if not isinstance(coverage, dict) or type(coverage.get("api_calls")) is not int \
                or not 0 <= coverage["api_calls"] <= 10_000_000:
            return False
        calls = coverage.get("signature_only_calls")
        if not isinstance(calls, list) or len(calls) > 10_000 or not all(
                isinstance(item, dict) and isinstance(item.get("api"), str)
                and len(item["api"]) <= 256 and type(item.get("count")) is int
                and 0 < item["count"] <= coverage["api_calls"] for item in calls):
            return False
        if sum(item["count"] for item in calls) > coverage["api_calls"]:
            return False
        if any(key in coverage for key in ("observed_apis", "observed_calls", "other_calls")):
            observed, other, distinct = (coverage.get("observed_calls"),
                                         coverage.get("other_calls"),
                                         coverage.get("observed_apis"))
            if not isinstance(observed, list) or len(observed) > 100 \
                    or type(other) is not int or type(distinct) is not int \
                    or not 0 <= other <= coverage["api_calls"] \
                    or not len(observed) <= distinct <= coverage["api_calls"]:
                return False
            if not all(isinstance(item, dict) and isinstance(item.get("api"), str)
                       and 0 < len(item["api"]) <= 256
                       and type(item.get("count")) is int
                       and type(item.get("signature_only_count")) is int
                       and 0 <= item["signature_only_count"] <= item["count"]
                       and 0 < item["count"] <= coverage["api_calls"]
                       for item in observed):
                return False
            if len({item["api"] for item in observed}) != len(observed) or \
                    sum(item["count"] for item in observed) + other != coverage["api_calls"]:
                return False
    cil = value.get("cil_coverage")
    if cil is not None:
        if not isinstance(cil, dict):
            return False
        for total_key, distinct_key, top_key, other_key, label_key, limit in (
                ("opcode_attempts", "tracked_opcodes", "top_opcodes",
                 "other_opcode_attempts", "opcode", 128),
                ("framework_calls", "tracked_framework_methods", "top_framework_calls",
                 "other_framework_calls", "method", 256)):
            total, distinct, top, other = (cil.get(total_key), cil.get(distinct_key),
                                           cil.get(top_key), cil.get(other_key))
            if any(type(number) is not int for number in (total, distinct, other)) \
                    or not 0 <= total <= 10_000_000 or not 0 <= distinct <= 10_000 \
                    or not 0 <= other <= total or not isinstance(top, list) \
                    or len(top) > 100 or len(top) > distinct:
                return False
            if not all(isinstance(item, dict) and isinstance(item.get(label_key), str)
                       and 0 < len(item[label_key]) <= limit
                       and type(item.get("count")) is int and 0 < item["count"] <= total
                       for item in top):
                return False
            if len({item[label_key] for item in top}) != len(top) or \
                    sum(item["count"] for item in top) + other != total:
                return False
        untracked = cil.get("untracked_framework_calls")
        if type(untracked) is not int or not 0 <= untracked <= cil["other_framework_calls"]:
            return False
    return True


def read_verified_engine_report(root: Path, summary: dict) -> bytes | None:
    """Read a bounded engine trace and verify its post-run summary binding."""
    if summary.get("engine_report") not in (None, "engine-report.json"):
        return None
    raw = read_regular_file(root / "engine-report.json", MAX_ENGINE_BYTES)
    if raw is None:
        return None
    manifest = summary.get("run_manifest")
    required = (isinstance(manifest, dict) and
                manifest.get("engine_report_integrity") == ENGINE_INTEGRITY and
                summary.get("status") in {"completed", "partial"})
    digest, size = summary.get("engine_report_sha256"), summary.get("engine_report_size")
    if required or digest is not None or size is not None:
        if (summary.get("engine_report") != "engine-report.json" or
                not isinstance(digest, str) or not SHA256.fullmatch(digest) or
                type(size) is not int or len(raw) != size or
                hashlib.sha256(raw).hexdigest() != digest):
            return None
    return raw


def read_verified_network_report(root: Path, summary: dict) -> bytes | None:
    """Read a bounded broker report and verify its post-run summary binding."""
    if summary.get("network_broker_report") not in (None, "network-broker.json"):
        return None
    raw = read_regular_file(root / "network-broker.json", MAX_NETWORK_REPORT_BYTES)
    if raw is None:
        return None
    manifest = summary.get("run_manifest")
    required = (isinstance(manifest, dict) and
                manifest.get("network_broker_report_integrity") == ENGINE_INTEGRITY and
                summary.get("status") in {"completed", "partial"})
    digest = summary.get("network_broker_report_sha256")
    size = summary.get("network_broker_report_size")
    if required or digest is not None or size is not None:
        if (summary.get("network_broker_report") != "network-broker.json" or
                not isinstance(digest, str) or not SHA256.fullmatch(digest) or
                type(size) is not int or len(raw) != size or
                hashlib.sha256(raw).hexdigest() != digest):
            return None
    return raw


def read_verified_artifact(root: Path, item: dict) -> bytes | None:
    """Read and verify an artifact from one file handle before exposing its bytes."""
    if not isinstance(item, dict):
        return None
    name, digest, size = item.get("file"), item.get("sha256"), item.get("size")
    if not isinstance(name, str) or not ARTIFACT_NAME.fullmatch(name):
        return None
    if not isinstance(digest, str) or not SHA256.fullmatch(digest) or name[:20] != digest[:20]:
        return None
    if type(size) is not int or not 0 < size <= MAX_ARTIFACT_BYTES:
        return None
    if any(not isinstance(item.get(key), str) or len(item[key]) > 4096
           for key in ("kind", "source", "guest_path")):
        return None
    if "context" in item and not isinstance(item["context"], dict):
        return None
    artifact_dir = root / "artifacts"
    path = artifact_dir / name
    try:
        if artifact_dir.is_symlink() or artifact_dir.resolve() != root.resolve() / "artifacts":
            return None
        payload = read_regular_file(path, size)
        if payload is None or len(payload) != size:
            return None
        return payload if hashlib.sha256(payload).hexdigest() == digest else None
    except (OSError, RuntimeError):
        return None


def verify_artifact(root: Path, item: dict) -> bool:
    """Verify a worker-produced artifact before trusting its bytes."""
    return read_verified_artifact(root, item) is not None


def verify_artifact_manifest(root: Path, artifacts: list[dict],
                             groups: list[dict] | None = None) -> bool:
    path = root / "artifacts" / "manifest.json"
    try:
        artifact_dir = root / "artifacts"
        if artifact_dir.is_symlink() or artifact_dir.resolve() != root.resolve() / "artifacts":
            return False
        data = read_regular_file(path, MAX_SUMMARY_BYTES)
        if data is None:
            return False
        manifest = json.loads(data)
    except (OSError, ValueError, RecursionError):
        return False
    if manifest != artifacts:
        return False
    if groups is None:
        return all(verify_artifact(root, item) for item in artifacts)

    def verified_payloads():
        for item in artifacts:
            payload = read_verified_artifact(root, item)
            if payload is None:
                raise ValueError("Artifact verification failed")
            yield item, payload

    try:
        return groups == groups_from_payloads(verified_payloads())
    except (AttributeError, KeyError, TypeError, ValueError):
        return False


def recover_artifact_checkpoint(root: Path) -> tuple[list[dict], list[dict]] | None:
    """Recover only complete, hash-verified artifact observations after a worker stop."""
    raw = read_regular_file(root / "artifacts" / "manifest.json", MAX_SUMMARY_BYTES)
    if raw is None:
        return None
    try:
        items = json.loads(raw)
        if (not isinstance(items, list) or len(items) > 10_000 or
                not all(isinstance(item, dict) for item in items) or
                not verify_artifact_manifest(root, items)):
            return None
        payloads = []
        for item in items:
            payload = read_verified_artifact(root, item)
            if payload is None:
                return None
            payloads.append((item, payload))
        return items, groups_from_payloads(payloads)
    except (AttributeError, KeyError, TypeError, ValueError, RecursionError):
        return None

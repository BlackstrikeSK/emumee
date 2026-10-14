"""Read-only loopback dashboard for completed analysis runs."""

from __future__ import annotations

import json
import hashlib
from collections import Counter
from io import BytesIO
from pathlib import Path
from urllib.parse import urlencode

from flask import Flask, abort, jsonify, render_template_string, request, send_file
from werkzeug.exceptions import NotFound

from .reports import (ARTIFACT_NAME, MAX_ENGINE_BYTES, MAX_SUMMARY_BYTES, RUN_ID,
                      ENGINE_INTEGRITY, read_verified_artifact,
                      read_verified_engine_report, read_verified_network_report,
                      valid_summary,
                      verify_artifact_manifest)
from .safeio import read_regular_file
from .networkfixtures import MAX_FIXTURE_FILE, parse_network_fixtures


from .dashboard_ui import STYLE, INDEX, COMPARE, DETAIL, ERROR, ui_number, ui_datetime


def _run_dir(root: Path, run_id: str) -> Path:
    if not RUN_ID.fullmatch(run_id):
        abort(404)
    path = root / run_id
    if path.is_symlink() or not path.is_dir() or path.resolve().parent != root:
        abort(404)
    return path


def _verified_artifact_view(path: Path, run: dict) -> dict | None:
    """Return display data that cannot present unverified artifact claims."""
    artifacts = run.get("artifacts") or []
    groups = run.get("artifact_groups") or []
    if run.get("artifact_integrity") in {"failed", "unverified"}:
        return {**run, "artifacts": [], "artifact_groups": []}
    if not artifacts and not groups:
        return run
    if verify_artifact_manifest(path, artifacts, run.get("artifact_groups")):
        return run
    if run.get("status") in {"completed", "partial"}:
        return None
    return {**run, "artifacts": [], "artifact_groups": [],
            "artifact_integrity": "unverified",
            "unverified_artifact_count": len(artifacts)}


def _read_json(path: Path) -> object:
    try:
        limit = (MAX_SUMMARY_BYTES if path.name in {"summary.json", "manifest.json"} else
                 64 * 1024 * 1024 if path.name == "network-broker.json" else MAX_ENGINE_BYTES)
        data = read_regular_file(path, limit)
        if data is None:
            abort(404)
        return json.loads(data)
    except (OSError, ValueError, RecursionError):
        abort(404)


def _engine_json(path: Path, run: dict) -> object:
    manifest = run.get("run_manifest")
    required = (isinstance(manifest, dict) and
                manifest.get("engine_report_integrity") == ENGINE_INTEGRITY and
                run.get("status") in {"completed", "partial"})
    if (not required and run.get("engine_report_sha256") is None and
            not (path / "engine-report.json").exists()):
        return {}
    data = read_verified_engine_report(path, run)
    if data is None:
        abort(404)
    try:
        return json.loads(data)
    except (ValueError, RecursionError):
        abort(404)


def _broker_json(path: Path, run: dict) -> object:
    manifest = run.get("run_manifest")
    required = (isinstance(manifest, dict) and
                manifest.get("network_broker_report_integrity") == ENGINE_INTEGRITY and
                run.get("status") in {"completed", "partial"})
    if (not required and run.get("network_broker_report_sha256") is None and
            run.get("network_broker_report") != "network-broker.json"):
        return []
    data = read_verified_network_report(path, run)
    if data is None:
        abort(404)
    try:
        return json.loads(data)
    except (ValueError, RecursionError):
        abort(404)


def _dict_events(value) -> list[dict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _command_events(engine: dict) -> list[dict]:
    commands = [event for event in _dict_events(engine.get("command_events"))
                if isinstance(event.get("command"), str) and event["command"]]
    for event in _dict_events(engine.get("virtual_process_events")):
        if event.get("event") != "virtual_process_create":
            continue
        commands.append({"command": event.get("path") or event.get("application") or "Guest process",
                         "command_line": event.get("command_line", ""),
                         "capture": "guest_process_api", "api": event.get("api"),
                         "phase": "created" if event.get("success") else "rejected",
                         "reason": event.get("reason")})
    return commands


def _timeline_events(engine: dict) -> list[dict]:
    """Merge native trace streams by execution tick, retaining provenance."""
    streams = [("events", _dict_events(engine.get("events"))),
               ("network_events", _dict_events(engine.get("network_events"))),
               ("virtual_file_events", _dict_events(engine.get("virtual_file_events"))),
               ("virtual_registry_events", _dict_events(engine.get("virtual_registry_events"))),
               ("virtual_process_events", _dict_events(engine.get("virtual_process_events"))),
               ("command_events", _dict_events(engine.get("command_events"))),
               ("dll_initialization_events", _dict_events(engine.get("dll_initialization_events")))]
    for number, entry in enumerate(engine.get("entry_points") or []):
        if isinstance(entry, dict):
            streams.append((f"entry_points[{number}].events", _dict_events(entry.get("events"))))
    api_ticks: dict[str, list[int]] = {}
    for source, events in streams:
        if not source.startswith("entry_points["):
            continue
        for event in events:
            position = event.get("pos")
            tick = position.get("tick") if isinstance(position, dict) else None
            if event.get("event") == "api" and isinstance(event.get("api_name"), str) \
                    and type(tick) is int:
                api_ticks.setdefault(event["api_name"], []).append(tick)
    timeline = []
    last_tick = 0
    for source, events in streams:
        source_tick = 0
        for sequence, event in enumerate(events):
            position = event.get("pos")
            tick = position.get("tick") if isinstance(position, dict) else None
            inferred = False
            if type(tick) is not int:
                candidates = api_ticks.get(event.get("api"), [])
                tick = next((candidate for candidate in candidates if candidate >= source_tick), None)
                inferred = tick is not None
            if type(tick) is int:
                source_tick = max(source_tick, tick)
                last_tick = max(last_tick, tick)
            shown = dict(event)
            shown["timeline_source"] = source
            shown["timeline_tick"] = tick
            if inferred:
                shown["timeline_tick_inferred"] = True
            capture_sequence = event.get("capture_sequence")
            timeline.append((tick, 0 if source.startswith("entry_points[") else 1,
                             capture_sequence if type(capture_sequence) is int else None,
                             len(timeline), shown))
    timeline.sort(key=lambda item: (item[0] if type(item[0]) is int else last_tick + 1,
                                    item[1], item[2] if item[2] is not None else 1_000_000_000 + item[3],
                                    item[3]))
    return [item[4] for item in timeline]


def _flatten(value, prefix: str = "") -> dict[str, object]:
    if isinstance(value, dict):
        result = {}
        for key, child in value.items():
            if isinstance(key, str) and len(result) < 1000:
                result.update(_flatten(child, f"{prefix}.{key}" if prefix else key))
        return result
    return {prefix: value}


def _api_results(engine: dict) -> dict[str, dict[str, int]]:
    results: dict[str, dict[str, int]] = {}
    for entry in engine.get("entry_points", []) if isinstance(engine.get("entry_points"), list) else []:
        if not isinstance(entry, dict):
            continue
        for event in entry.get("events", []) if isinstance(entry.get("events"), list) else []:
            if (not isinstance(event, dict) or event.get("event") != "api" or
                    not isinstance(event.get("api_name"), str)):
                continue
            name = event["api_name"][:256]
            value = str(event.get("ret_val"))[:256]
            if name not in results and len(results) >= 1024:
                continue
            counts = results.setdefault(name, {})
            if value in counts or len(counts) < 64:
                counts[value] = counts.get(value, 0) + 1
    return results


def _behavior_signals(run: dict, engine: dict) -> tuple[Counter[str], list[str], int]:
    fields = ("event", "api", "path", "old_path", "new_path", "key", "value",
              "name", "url", "method", "host", "port", "sha256", "body_sha256",
              "reason", "pid", "address", "target_pid", "size", "success")
    signals: Counter[str] = Counter()
    sequence: list[str] = []
    omitted = 0

    def record(value: dict) -> None:
        encoded = json.dumps(value, sort_keys=True)
        signals[encoded] += 1
        sequence.append(encoded)

    for item in run.get("network_attempts") or []:
        if isinstance(item, dict):
            record({"source": "network_attempt", **{
                key: str(value)[:512] for key, value in item.items()
                if key in fields or key in {"outcome", "operation"}}})
    for item in run.get("artifacts") or []:
        if isinstance(item, dict):
            record({"source": "artifact", **{
                key: str(item[key])[:512] for key in ("sha256", "source", "guest_path", "kind")
                if key in item}})
    for source in ("events", "network_events", "virtual_file_events",
                   "virtual_registry_events", "virtual_process_events"):
        entries = _dict_events(engine.get(source))
        omitted += max(0, len(entries) - 5000)
        for event in entries[:5000]:
            name = event.get("event", "")
            if not isinstance(name, str) or name in {"api", "managed_call"}:
                continue
            if not (name.startswith(("network_", "http_", "virtual_", "file_", "registry_"))
                    or name in {"connect_attempt", "process_create", "process_exit"}):
                continue
            record({"source": source, **{
                key: str(event[key])[:512] for key in fields if key in event}})
    return signals, sequence, omitted


def _compare_runs(left: dict, right: dict, left_engine: dict | None = None,
                  right_engine: dict | None = None) -> dict:
    left_persona, right_persona = (_flatten(left.get("persona") or {}),
                                   _flatten(right.get("persona") or {}))
    persona_changes = {key: {"left": left_persona.get(key), "right": right_persona.get(key)}
                       for key in sorted(left_persona.keys() | right_persona.keys())
                       if left_persona.get(key) != right_persona.get(key)}
    def api_counts(run: dict) -> dict[str, int]:
        coverage = run.get("api_coverage") or {}
        return {item["api"]: item["count"] for item in coverage.get("observed_calls", [])
                if isinstance(item, dict) and isinstance(item.get("api"), str)
                and type(item.get("count")) is int}
    left_api, right_api = api_counts(left), api_counts(right)
    left_results, right_results = (_api_results(left_engine or {}),
                                   _api_results(right_engine or {}))
    left_hashes = {item.get("sha256") for item in left.get("artifacts", [])
                   if isinstance(item, dict) and isinstance(item.get("sha256"), str)}
    right_hashes = {item.get("sha256") for item in right.get("artifacts", [])
                    if isinstance(item, dict) and isinstance(item.get("sha256"), str)}
    fields = ("status", "guest_exit_code", "instruction_count",
              "guest_entry_return", "completion_reason", "instruction_limit_reached",
              "timeout_reached", "denied_operations")
    left_manifest, right_manifest = (left.get("run_manifest") or {},
                                     right.get("run_manifest") or {})
    left_limits, right_limits = (left_manifest.get("limits"), right_manifest.get("limits"))
    input_fields = ("execution_target", "companions", "guest_args", "guest_env",
                    "network_mode", "network_fixtures", "worker_bundle_sha256",
                    "bundle_tree_sha256")
    input_changes = {key: {"left": left_manifest.get(key), "right": right_manifest.get(key)}
                     for key in input_fields if left_manifest.get(key) != right_manifest.get(key)}
    left_behavior, left_sequence, left_omitted = _behavior_signals(left, left_engine or {})
    right_behavior, right_sequence, right_omitted = _behavior_signals(right, right_engine or {})
    left_only, right_only = left_behavior - right_behavior, right_behavior - left_behavior
    left_display, right_display = (sorted(left_only.items())[:1000],
                                   sorted(right_only.items())[:1000])
    return {"left": {"id": left["id"], "sample": left["sample"]},
            "right": {"id": right["id"], "sample": right["sample"]},
            "artifact_evidence": {
                "left": "unverified" if left.get("artifact_integrity") in
                        {"failed", "unverified"} else "verified",
                "right": "unverified" if right.get("artifact_integrity") in
                         {"failed", "unverified"} else "verified"},
            "comparable_context": {
                "same_sample": left["sample"].get("sha256") == right["sample"].get("sha256"),
                "same_persona": left.get("persona") == right.get("persona"),
                "same_limits": left_limits == right_limits,
                "same_invocation": not input_changes if left_manifest and right_manifest else None,
                "input_changes": input_changes,
                "live_network_variable": any(
                    str(manifest.get("network_mode") or "").startswith("live")
                    for manifest in (left_manifest, right_manifest))},
            "outcomes": {key: {"left": left.get(key), "right": right.get(key)}
                         for key in fields if left.get(key) != right.get(key)} |
                        ({"limits": {"left": left_limits, "right": right_limits}}
                         if left_limits != right_limits else {}),
            "persona_changes": persona_changes,
            "api_changes": {key: {"left": left_api.get(key, 0), "right": right_api.get(key, 0)}
                            for key in sorted(left_api.keys() | right_api.keys())
                            if left_api.get(key, 0) != right_api.get(key, 0)},
            "api_result_changes": {key: {"left": left_results.get(key, {}),
                                         "right": right_results.get(key, {})}
                                   for key in sorted(left_results.keys() | right_results.keys())
                                   if left_results.get(key) != right_results.get(key)},
            "artifact_changes": {"only_left": sorted(left_hashes - right_hashes),
                                 "only_right": sorted(right_hashes - left_hashes),
                                 "shared": sorted(left_hashes & right_hashes)},
            "behavior_changes": {"only_left": [{**json.loads(value), "count": count}
                                               for value, count in left_display],
                                 "only_right": [{**json.loads(value), "count": count}
                                                for value, count in right_display],
                                 "shared_count": sum((left_behavior & right_behavior).values()),
                                 "left_observations": sum(left_behavior.values()),
                                 "right_observations": sum(right_behavior.values()),
                                 "left_omitted": left_omitted,
                                 "right_omitted": right_omitted,
                                 "left_difference_rows_omitted": len(left_only) - len(left_display),
                                 "right_difference_rows_omitted": len(right_only) - len(right_display),
                                 "source_order_changed": left_sequence != right_sequence},
            "console_output": ({"left": left.get("console_output"),
                                "right": right.get("console_output")}
                               if left.get("console_output") != right.get("console_output") else {})}


def create_app(root: Path) -> Flask:
    root = root.resolve()
    app = Flask(__name__)
    app.jinja_env.filters["ui_number"] = ui_number
    app.jinja_env.filters["ui_datetime"] = ui_datetime
    app.config["MAX_CONTENT_LENGTH"] = 1024
    app.config["TRUSTED_HOSTS"] = ["localhost", "127.0.0.1"]

    @app.errorhandler(400)
    @app.errorhandler(404)
    def report_error(error):
        code = error.code
        title = "Check your request" if code == 400 else "This report is unavailable"
        message = ("A filter or page number is invalid. Return to the run library and try again."
                   if code == 400 else
                   "The run, page, or verified artifact could not be found. Return to the run library to choose an available report.")
        return render_template_string(ERROR, title=title, message=message,
                                      code=code, style=STYLE), code

    @app.after_request
    def headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/")
    def index():
        runs = []
        sha_filter = request.args.get("sha", "").lower()
        status_filter = request.args.get("status", "")
        kind_filter = request.args.get("kind", "").lower()
        behavior_filter = request.args.get("behavior", "").casefold()
        sort_order = request.args.get("sort", "newest")
        page_text = request.args.get("page", "1")
        if sha_filter and (not 8 <= len(sha_filter) <= 64 or
                           any(char not in "0123456789abcdef" for char in sha_filter)):
            abort(400)
        if (status_filter not in {"", "completed", "partial", "failed", "timeout", "running"}
                or len(kind_filter) > 32 or len(behavior_filter) > 128
                or sort_order not in {"newest", "oldest", "artifacts"}
                or not page_text.isdecimal() or not 1 <= int(page_text) <= 1000):
            abort(400)
        page = int(page_text)
        for path in sorted(root.glob("*/summary.json"), reverse=True):
            try:
                if (RUN_ID.fullmatch(path.parent.name) and not path.parent.is_symlink()
                        and path.parent.resolve().parent == root):
                    value = _read_json(path)
                    if not valid_summary(value) or value["id"] != path.parent.name:
                        continue
                    value = _verified_artifact_view(path.parent, value)
                    if value is None:
                        continue
                    hashes = (value["sample"].get("sha256"),
                              (value.get("run_manifest") or {}).get("sample", {}).get("sha256"))
                    if sha_filter and not any(isinstance(digest, str) and
                                              digest.startswith(sha_filter) for digest in hashes):
                        continue
                    if status_filter and value["status"] != status_filter:
                        continue
                    artifacts = value.get("artifact_groups") or value.get("artifacts") or []
                    if kind_filter and not any(str(item.get("kind", "")).casefold() == kind_filter
                                               for item in artifacts if isinstance(item, dict)):
                        continue
                    if behavior_filter:
                        searchable = [str(item.get("api", "")) for item in
                                      (value.get("api_coverage") or {}).get("observed_calls", [])
                                      if isinstance(item, dict)]
                        searchable.extend(str(item.get("guest_path", "")) for item in
                                          value.get("artifacts", []) if isinstance(item, dict))
                        searchable.extend(str(item.get(key, "")) for item in
                                          value.get("network_attempts", []) if isinstance(item, dict)
                                          for key in ("url", "host", "reason"))
                        if not any(behavior_filter in text.casefold() for text in searchable):
                            continue
                    runs.append(value)
            except (OSError, ValueError, RecursionError, RuntimeError, NotFound):
                pass
        if sort_order == "oldest":
            runs.reverse()
        elif sort_order == "artifacts":
            runs.sort(key=lambda run: (-len(run.get("artifact_groups") or
                                                  run.get("artifacts") or []), run["id"]))
        total = len(runs)
        page_runs = runs[(page - 1) * 50:page * 50]
        filters = {"sha": sha_filter, "status": status_filter, "kind": kind_filter,
                   "behavior": behavior_filter, "sort": sort_order}
        previous_page = "/?" + urlencode(filters | {"page": page - 1}) if page > 1 else None
        next_page = "/?" + urlencode(filters | {"page": page + 1}) if page * 50 < total else None
        return render_template_string(INDEX, runs=page_runs, total=total, page=page,
                                      previous_page=previous_page, next_page=next_page,
                                      sha_filter=sha_filter, status_filter=status_filter,
                                      kind_filter=kind_filter, behavior_filter=behavior_filter,
                                      sort_order=sort_order, style=STYLE,
                                      status_counts=Counter(run["status"] for run in runs),
                                      review_count=sum(run["status"] in {"partial", "failed", "timeout"}
                                                       for run in runs),
                                      artifact_total=sum(len(run.get("artifact_groups") or
                                                             run.get("artifacts") or []) for run in runs))

    @app.get("/compare")
    def compare():
        left_id, right_id = request.args.get("left", ""), request.args.get("right", "")
        left_path, right_path = _run_dir(root, left_id), _run_dir(root, right_id)
        left, right = (_read_json(left_path / "summary.json"),
                       _read_json(right_path / "summary.json"))
        if (not valid_summary(left) or not valid_summary(right) or
                left["id"] != left_id or right["id"] != right_id):
            abort(404)
        left = _verified_artifact_view(left_path, left)
        right = _verified_artifact_view(right_path, right)
        if left is None or right is None:
            abort(404)
        left_engine = _engine_json(left_path, left)
        right_engine = _engine_json(right_path, right)
        _broker_json(left_path, left)
        _broker_json(right_path, right)
        comparison = _compare_runs(left, right,
                                   left_engine if isinstance(left_engine, dict) else {},
                                   right_engine if isinstance(right_engine, dict) else {})
        if request.args.get("format") == "json":
            return jsonify(comparison)
        return render_template_string(COMPARE, comparison=comparison, style=STYLE)

    @app.get("/runs/<run_id>")
    def detail(run_id: str):
        path = _run_dir(root, run_id)
        run = _read_json(path / "summary.json")
        if not valid_summary(run) or run["id"] != run_id:
            abort(404)
        run = _verified_artifact_view(path, run)
        if run is None:
            abort(404)
        engine = _engine_json(path, run)
        if not isinstance(engine, dict):
            engine = {}
        broker_events = _dict_events(_broker_json(path, run))
        events = _timeline_events(engine)
        commands = _command_events(engine)
        command_capture = engine.get("command_capture")
        if not isinstance(command_capture, dict):
            command_capture = {}
        commands_per_page = 100
        command_pages = max(1, (len(commands) + commands_per_page - 1) // commands_per_page)
        page_size = 2000
        event_pages = max(1, (len(events) + page_size - 1) // page_size)
        broker_pages = max(1, (len(broker_events) + page_size - 1) // page_size)
        def requested_page(name: str, available: int) -> int:
            raw = request.args.get(name, "1")
            if not raw.isascii() or not raw.isdecimal() or len(raw) > 8:
                abort(400)
            value = int(raw)
            if not 1 <= value <= available:
                abort(404)
            return value
        events_page = requested_page("events_page", event_pages)
        broker_page = requested_page("broker_page", broker_pages)
        commands_page = requested_page("commands_page", command_pages)
        command_start = (commands_page - 1) * commands_per_page
        event_start = (events_page - 1) * page_size
        broker_start = (broker_page - 1) * page_size
        fixture_rules = None
        if isinstance(run.get("run_manifest"), dict) and run["run_manifest"].get("network_fixtures"):
            fixture_raw = read_regular_file(path / "network-fixtures.json", MAX_FIXTURE_FILE)
            if fixture_raw is not None and hashlib.sha256(fixture_raw).hexdigest() == run["run_manifest"]["network_fixtures"].get("sha256"):
                try:
                    fixture_rules = []
                    for rule in parse_network_fixtures(fixture_raw):
                        fixture_rules.append({"id": rule["id"], "request": rule["request"],
                                              "response": rule["response"],
                                              "request_body_size": len(rule["request_body"]),
                                              "request_body_sha256": hashlib.sha256(rule["request_body"]).hexdigest(),
                                              "response_body_size": len(rule["response_body"]),
                                              "response_body_sha256": hashlib.sha256(rule["response_body"]).hexdigest()})
                except ValueError:
                    fixture_rules = None
        trace_integrity = ("SHA-256 verified" if run.get("engine_report_sha256") else
                           "Legacy unbound" if (path / "engine-report.json").exists() else
                           "Unavailable")
        broker_integrity = ("SHA-256 verified" if run.get("network_broker_report_sha256") else
                            "Legacy unbound" if run.get("network_broker_report") else
                            "Unavailable")
        return render_template_string(DETAIL, run=run,
                                      commands=commands[command_start:command_start + commands_per_page],
                                      command_count=len(commands), command_pages=command_pages,
                                      commands_page=commands_page, command_capture=command_capture,
                                      events=events[event_start:event_start + page_size],
                                      event_count=len(events), event_pages=event_pages,
                                      events_page=events_page,
                                      event_first=event_start + 1 if events else 0,
                                      event_last=min(event_start + page_size, len(events)),
                                      broker_events=broker_events[broker_start:broker_start + page_size],
                                      broker_event_count=len(broker_events),
                                      broker_pages=broker_pages, broker_page=broker_page,
                                      broker_first=broker_start + 1 if broker_events else 0,
                                      broker_last=min(broker_start + page_size,
                                                      len(broker_events)),
                                      fixture_rules=fixture_rules,
                                      trace_integrity=trace_integrity,
                                      broker_integrity=broker_integrity, style=STYLE)

    @app.get("/runs/<run_id>/network-fixtures")
    def network_fixtures(run_id: str):
        path = _run_dir(root, run_id)
        run = _read_json(path / "summary.json")
        if not valid_summary(run) or run["id"] != run_id:
            abort(404)
        manifest = run.get("run_manifest")
        fixture_info = manifest.get("network_fixtures") if isinstance(manifest, dict) else None
        if not isinstance(fixture_info, dict):
            abort(404)
        raw = read_regular_file(path / "network-fixtures.json", MAX_FIXTURE_FILE)
        if raw is None or hashlib.sha256(raw).hexdigest() != fixture_info.get("sha256"):
            abort(404)
        return send_file(BytesIO(raw), as_attachment=True,
                         download_name="network-fixtures.json", mimetype="application/json")

    @app.get("/runs/<run_id>/artifacts/<filename>")
    def artifact(run_id: str, filename: str):
        if not ARTIFACT_NAME.fullmatch(filename):
            abort(404)
        path = _run_dir(root, run_id)
        run = _read_json(path / "summary.json")
        if not valid_summary(run) or run["id"] != run_id:
            abort(404)
        if run.get("artifact_integrity") in {"failed", "unverified"}:
            abort(404)
        artifacts = run.get("artifacts", [])
        if not verify_artifact_manifest(path, artifacts, run.get("artifact_groups")):
            abort(404)
        item = next((a for a in artifacts if a.get("file") == filename), None)
        payload = read_verified_artifact(path, item) if item is not None else None
        if payload is None:
            abort(404)
        return send_file(BytesIO(payload), as_attachment=True, download_name=filename,
                         mimetype="application/octet-stream")

    return app

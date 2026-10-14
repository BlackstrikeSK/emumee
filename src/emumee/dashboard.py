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


STYLE = """
*{box-sizing:border-box}body{background:#0b111b;color:#e6edf6;font:15px/1.5 system-ui,Segoe UI,sans-serif;margin:0}
.wrap{max-width:1200px;margin:auto;padding:28px 24px 70px}header{border-bottom:1px solid #263548;background:#101a28}
header .wrap{padding-top:19px;padding-bottom:19px;display:flex;align-items:center;justify-content:space-between}
a{color:#8dc6ff;text-decoration:none}a:hover{text-decoration:underline}.brand{font-size:23px;font-weight:800;letter-spacing:.02em;color:#e6edf6}
.muted{color:#96a8bb}.eyebrow{text-transform:uppercase;letter-spacing:.13em;color:#65d8c4;font-size:12px;font-weight:700}
h1{font-size:31px;line-height:1.2;margin:9px 0 20px}h2{font-size:19px;margin:32px 0 12px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.card,.panel{background:#132032;border:1px solid #2a3b50;border-radius:12px;padding:18px}
.metric{font-size:24px;font-weight:750;overflow-wrap:anywhere}.label{font-size:12px;color:#9caec1;text-transform:uppercase;letter-spacing:.07em}
table{border-collapse:collapse;width:100%;background:#132032;border:1px solid #2a3b50;border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:12px 13px;border-bottom:1px solid #263548;vertical-align:top;overflow-wrap:anywhere}
th{color:#9badbf;font-size:12px;text-transform:uppercase;letter-spacing:.06em}tr:last-child td{border-bottom:0}
code,pre{font-family:Consolas,monospace;color:#b5d9ff}pre{white-space:pre-wrap;overflow-wrap:anywhere;margin:0}
.pill{display:inline-block;padding:2px 9px;border-radius:99px;background:#254039;color:#8becd1;font-size:12px;font-weight:700}
.pill.partial,.pill.failed,.pill.timeout{background:#503a26;color:#ffd08c}.error{border-color:#9b5949;background:#332229}
.empty{padding:28px;border:1px dashed #3b5066;border-radius:12px;color:#9badbf}
input{background:#0c1625;border:1px solid #3a5168;color:#e6edf6;padding:9px;border-radius:7px}
select,button{background:#0c1625;border:1px solid #3a5168;color:#e6edf6;padding:9px;border-radius:7px}
.console-text{max-height:360px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere}
"""

INDEX = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Emumee · Runs</title><style>{{ style }}</style></head>
<body><header><div class="wrap"><a class="brand" href="/">◈ Emumee</a><span class="muted">Local analysis dashboard</span></div></header>
<main class="wrap"><div class="eyebrow">Analysis workspace</div><h1>Runs</h1>
<form action="/" method="get" class="panel" style="margin-bottom:18px">
<label>Sample SHA-256 prefix <input name="sha" value="{{ sha_filter }}" maxlength="64" placeholder="8–64 hex characters"></label>
<label>Status <select name="status"><option value="">All</option>{% for name in ('completed','partial','failed','timeout','running') %}<option value="{{ name }}"{% if status_filter == name %} selected{% endif %}>{{ name }}</option>{% endfor %}</select></label>
<label>Artifact kind <input name="kind" value="{{ kind_filter }}" maxlength="32" placeholder="pe, script, binary..."></label>
<label>Behavior contains <input name="behavior" value="{{ behavior_filter }}" maxlength="128" placeholder="API, URL, guest path"></label>
<label>Sort <select name="sort"><option value="newest"{% if sort_order == 'newest' %} selected{% endif %}>Newest</option><option value="oldest"{% if sort_order == 'oldest' %} selected{% endif %}>Oldest</option><option value="artifacts"{% if sort_order == 'artifacts' %} selected{% endif %}>Most artifacts</option></select></label>
<button type="submit">Filter</button></form>
{% if runs|length > 1 %}<form action="/compare" method="get" class="panel" style="margin-bottom:18px"><label>Compare runs: <select name="left">{% for run in runs %}<option value="{{ run.id }}">{{ run.id }} · {{ run.sample.name }}</option>{% endfor %}</select></label> <label>with <select name="right">{% for run in runs %}<option value="{{ run.id }}"{% if loop.index == 2 %} selected{% endif %}>{{ run.id }} · {{ run.sample.name }}</option>{% endfor %}</select></label> <button type="submit">Compare</button></form>{% endif %}
{% if runs %}<p class="muted">{{ total }} matching runs · page {{ page }}</p><table><thead><tr><th>Run</th><th>Sample</th><th>Architecture</th><th>Engine</th><th>Status</th><th>Guest result</th><th>API calls</th><th>CIL opcode attempts</th><th>Signature-only names</th><th>Artifacts</th></tr></thead><tbody>
{% for run in runs %}<tr><td><a href="/runs/{{ run.id }}">{{ run.id }}</a></td><td>{{ run.sample.name if run.sample else 'unknown' }}</td><td>{{ run.sample.architecture if run.sample else '—' }}</td><td>{{ run.engine or '—' }}</td><td><span class="pill {{ run.status }}">{{ run.status }}</span></td><td>{% if run.guest_exit_code is defined and run.guest_exit_code is not none %}Exit {{ run.guest_exit_code }}{% elif run.guest_entry_return is defined and run.guest_entry_return is not none %}Return {{ run.guest_entry_return }}{% else %}—{% endif %}</td><td>{{ run.api_coverage.api_calls if run.api_coverage else '—' }}</td><td>{{ run.cil_coverage.opcode_attempts if run.cil_coverage else '—' }}</td><td>{{ run.api_coverage.signature_only_calls|length if run.api_coverage else '—' }}</td><td>{{ run.artifact_groups|length if run.artifact_groups is defined else run.artifacts|length }}</td></tr>{% endfor %}
</tbody></table><p>{% if previous_page %}<a href="{{ previous_page }}">← Previous</a>{% endif %} {% if next_page %}<a href="{{ next_page }}">Next →</a>{% endif %}</p>{% else %}<div class="empty">No matching runs. Use <code>emumee run sample.exe</code> from a terminal.</div>{% endif %}
</main></body></html>
"""

COMPARE = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Emumee · Compare runs</title><style>{{ style }}</style></head>
<body><header><div class="wrap"><a class="brand" href="/">◈ Emumee</a><a href="/">← All runs</a></div></header><main class="wrap">
<h1>Compare runs</h1><p><a href="/runs/{{ comparison.left.id }}">{{ comparison.left.id }}</a> → <a href="/runs/{{ comparison.right.id }}">{{ comparison.right.id }}</a> · <a href="/compare?left={{ comparison.left.id }}&right={{ comparison.right.id }}&format=json">JSON diff</a></p>
<h2>Comparison context</h2><div class="panel"><pre>{{ comparison.comparable_context|tojson(indent=2) }}</pre></div>
{% if comparison.artifact_evidence.left != 'verified' or comparison.artifact_evidence.right != 'verified' %}<div class="panel error">Artifact comparison excludes unverified evidence. <pre>{{ comparison.artifact_evidence|tojson(indent=2) }}</pre></div>{% endif %}
<h2>Outcomes and limits</h2><div class="panel"><pre>{{ comparison.outcomes|tojson(indent=2) }}</pre></div>
<h2>Changed persona fields</h2><div class="panel"><pre>{{ comparison.persona_changes|tojson(indent=2) }}</pre></div>
<h2>Changed API counts</h2><div class="panel"><pre>{{ comparison.api_changes|tojson(indent=2) }}</pre></div>
<h2>Changed API return values</h2><div class="panel"><pre>{{ comparison.api_result_changes|tojson(indent=2) }}</pre></div>
<h2>Artifacts</h2><div class="panel"><pre>{{ comparison.artifact_changes|tojson(indent=2) }}</pre></div>
<h2>Behavior changes</h2><div class="panel"><pre>{{ comparison.behavior_changes|tojson(indent=2) }}</pre></div>
<h2>Console output</h2><div class="panel"><pre>{{ comparison.console_output|tojson(indent=2) }}</pre></div>
</main></body></html>
"""

DETAIL = """
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Emumee · {{ run.id }}</title><style>{{ style }}</style></head>
<body><header><div class="wrap"><a class="brand" href="/">◈ Emumee</a><a href="/">← All runs</a></div></header><main class="wrap">
<div class="eyebrow">{{ run.id }}</div><h1>{{ run.sample.name if run.sample else 'Analysis run' }}</h1>
<div class="cards"><div class="card"><div class="label">Status</div><div class="metric"><span class="pill {{ run.status }}">{{ run.status }}</span></div></div>
<div class="card"><div class="label">Architecture</div><div class="metric">{{ run.sample.architecture if run.sample else '—' }}</div></div>
<div class="card"><div class="label">Runtime</div><div class="metric">{{ run.engine or '—' }}</div></div>
<div class="card"><div class="label">Engine trace</div><div class="metric">{{ trace_integrity }}</div></div>
<div class="card"><div class="label">Network report</div><div class="metric">{{ broker_integrity }}</div></div>
<div class="card"><div class="label">Unique artifacts</div><div class="metric">{{ run.artifact_groups|length if run.artifact_groups is defined else run.artifacts|length }}</div></div>
<div class="card"><div class="label">Guest exit code</div><div class="metric">{{ run.guest_exit_code if run.guest_exit_code is defined and run.guest_exit_code is not none else 'Unknown' }}</div></div>
<div class="card"><div class="label">Entry return</div><div class="metric">{{ run.guest_entry_return if run.guest_entry_return is defined and run.guest_entry_return is not none else '—' }}</div></div>
<div class="card"><div class="label">Completion reason</div><div class="metric">{{ run.completion_reason or '—' }}</div></div>
<div class="card"><div class="label">Instructions</div><div class="metric">{{ run.instruction_count if run.instruction_count is defined else '—' }}</div></div>
<div class="card"><div class="label">Instruction limit</div><div class="metric">{{ 'Reached' if run.instruction_limit_reached else 'Not reached' }}</div></div>
<div class="card"><div class="label">Wall-clock limit</div><div class="metric">{{ 'Reached' if run.timeout_reached else 'Not reached' }}</div></div>
<div class="card"><div class="label">Denied operations</div><div class="metric">{{ run.denied_operations or 0 }}</div></div>
{% if run.cil_coverage %}
<div class="card"><div class="label">CIL opcode attempts</div><div class="metric">{{ run.cil_coverage.opcode_attempts }}</div></div>
<div class="card"><div class="label">Tracked opcode names</div><div class="metric">{{ run.cil_coverage.tracked_opcodes }}</div></div>
<div class="card"><div class="label">Framework call attempts</div><div class="metric">{{ run.cil_coverage.framework_calls }}</div></div>
{% else %}
<div class="card"><div class="label">Observed API calls</div><div class="metric">{{ run.api_coverage.api_calls if run.api_coverage else '—' }}</div></div>
<div class="card"><div class="label">Distinct API names</div><div class="metric">{{ run.api_coverage.observed_apis if run.api_coverage and run.api_coverage.observed_apis is defined else '—' }}</div></div>
<div class="card"><div class="label">Signature-only API names</div><div class="metric">{{ run.api_coverage.signature_only_calls|length if run.api_coverage else '—' }}</div></div>{% endif %}</div>
<h2>Sample</h2><div class="panel"><div>SHA-256: <code>{{ run.sample.sha256 if run.sample else '—' }}</code></div>
<div>Type: {{ 'Managed' if run.sample and run.sample.managed else 'Native' }} {{ run.sample.kind if run.sample else '' }}</div>
<div>Started: {{ run.started_at or '—' }}</div><div>Persona: {{ run.persona.hostname if run.persona else '—' }} / {{ run.persona.user_name if run.persona else '—' }}</div></div>
<div class="panel"><div>Guest finished: {{ run.finished_at or '—' }}</div><div>Command finished: {{ run.command_finished_at or '—' }}</div><div>Total command time: {{ run.command_elapsed_seconds if run.command_elapsed_seconds is defined else '—' }} seconds</div><div>Worker exit code: {{ run.worker_exit_code if run.worker_exit_code is defined and run.worker_exit_code is not none else '—' }}</div></div>
{% if run.run_manifest %}<h2>Run manifest</h2><div class="panel"><pre>{{ run.run_manifest|tojson(indent=2) }}</pre></div>{% endif %}
{% if fixture_rules is not none %}<h2>Exact HTTP fixtures</h2><p class="muted">Requests match method, URL, chunked flag, every header name and value, and the complete body. Header names ignore case; values and body bytes are exact. <a href="/runs/{{ run.id }}/network-fixtures">Download full request and response definitions</a>.</p>
{% if fixture_rules %}<table><thead><tr><th>ID</th><th>Request</th><th>Response</th></tr></thead><tbody>{% for rule in fixture_rules %}<tr><td>{{ rule.id }}</td><td><code>{{ rule.request.method }} {{ rule.request.url }}</code><pre>{{ rule.request.headers|tojson(indent=2) }}</pre>Body: {{ rule.request_body_size }} bytes · <code>{{ rule.request_body_sha256 }}</code></td><td>{{ rule.response.status }} {{ rule.response.reason }}<pre>{{ rule.response.headers|tojson(indent=2) }}</pre>Body: {{ rule.response_body_size }} bytes · <code>{{ rule.response_body_sha256 }}</code></td></tr>{% endfor %}</tbody></table>{% endif %}{% endif %}
{% if run.errors %}<h2>Coverage limits and errors</h2><div class="panel error"><pre>{{ run.errors|tojson(indent=2) }}</pre></div>{% endif %}
{% if run.guest_trace_complete is sameas false %}<div class="panel error">The worker did not finish its guest trace report. Guest API, file, process, memory, and console observations may be incomplete.</div>{% endif %}
{% if run.artifact_checkpoint_recovered %}<div class="panel error">Artifacts below were recovered from a verified worker checkpoint. Later payloads and observations may be missing.</div>{% endif %}
{% if run.artifact_integrity in ('failed', 'unverified') %}<div class="panel error">Artifact claims could not be verified and are excluded from counts, search, comparison, and downloads.{% if run.unverified_artifact_count %} {{ run.unverified_artifact_count }} worker artifact rows were quarantined.{% endif %}</div>{% endif %}
{% if run.aes_plaintext_capture and (run.aes_plaintext_capture.captured_artifacts or run.aes_plaintext_capture.omitted_transforms) %}
<h2>Decrypted memory</h2><div class="panel{% if run.aes_plaintext_capture.omitted_transforms %} error{% endif %}">
{{ run.aes_plaintext_capture.captured_artifacts }} plaintext artifacts ({{ run.aes_plaintext_capture.captured_bytes }} bytes) captured.
{% if run.aes_plaintext_capture.omitted_transforms %}{{ run.aes_plaintext_capture.omitted_transforms }} transforms ({{ run.aes_plaintext_capture.omitted_bytes }} bytes) omitted by the capture budget; inspect the transform events for hashes and reasons.{% endif %}
</div>{% endif %}
{% if run.artifact_capture and run.artifact_capture.omitted_observations %}
<h2>Artifact capture limits</h2><div class="panel error">{{ run.artifact_capture.omitted_observations }} observations ({{ run.artifact_capture.omitted_bytes }} bytes) were not retained.
<pre>{{ run.artifact_capture.reasons|tojson(indent=2) }}</pre>
{% if run.artifact_capture.examples %}<pre>{{ run.artifact_capture.examples|tojson(indent=2) }}</pre>{% endif %}</div>{% endif %}
{% if run.network_broker_complete is sameas false %}<div class="panel error">Network broker log was recovered after an interrupted shutdown and may be incomplete.</div>{% endif %}
<h2>Console output</h2>
{% if run.console_output %}
<div class="panel"><div class="label">Standard output{% if run.console_output.stdout_truncated %} · truncated{% endif %}</div>
{% if run.console_output.stdout %}<pre class="console-text">{{ run.console_output.stdout }}</pre>{% else %}<div class="muted">No stdout captured.</div>{% endif %}</div>
<div class="panel"><div class="label">Standard error{% if run.console_output.stderr_truncated %} · truncated{% endif %}</div>
{% if run.console_output.stderr %}<pre class="console-text">{{ run.console_output.stderr }}</pre>{% else %}<div class="muted">No stderr captured.</div>{% endif %}</div>
{% else %}<div class="empty">No console capture in this report.</div>{% endif %}
{% if run.cil_coverage %}
<h2>Observed CIL opcodes</h2><p class="muted">Counts show interpreter dispatch attempts during this run. They do not prove that .NET behavior is fully modeled. An unsupported operation appears in Coverage limits and errors above.</p>
{% if run.cil_coverage.top_opcodes %}<table><thead><tr><th>Opcode</th><th>Attempts</th></tr></thead><tbody>
{% for item in run.cil_coverage.top_opcodes %}<tr><td><code>{{ item.opcode }}</code></td><td>{{ item.count }}</td></tr>{% endfor %}
</tbody></table>{% else %}<div class="empty">No CIL opcodes were dispatched.</div>{% endif %}
{% if run.cil_coverage.other_opcode_attempts %}<p class="muted">{{ run.cil_coverage.other_opcode_attempts }} attempts are outside the top 100 opcode names.</p>{% endif %}
<h2>Observed framework calls</h2><p class="muted">These method counts include attempted calls that may have failed. Names are limited to 256 characters; at most 1,024 names are tracked.</p>
{% if run.cil_coverage.top_framework_calls %}<table><thead><tr><th>Method</th><th>Attempts</th></tr></thead><tbody>
{% for item in run.cil_coverage.top_framework_calls %}<tr><td><code>{{ item.method }}</code></td><td>{{ item.count }}</td></tr>{% endfor %}
</tbody></table>{% else %}<div class="empty">No external framework calls were reached.</div>{% endif %}
{% if run.cil_coverage.other_framework_calls %}<p class="muted">{{ run.cil_coverage.other_framework_calls }} calls are outside the displayed names{% if run.cil_coverage.untracked_framework_calls %}; {{ run.cil_coverage.untracked_framework_calls }} exceeded the name tracking limit{% endif %}.</p>{% endif %}
{% else %}
<h2>Observed WinAPI calls</h2><p class="muted">This trace shows APIs reached during the run. A traced call does not prove that its modeled side effects match Windows. Signature-only calls have no modeled side effects.</p>
{% if run.api_coverage and run.api_coverage.observed_calls is defined %}
{% if run.api_coverage.observed_calls %}<table><thead><tr><th>API</th><th>Calls</th><th>Signature-only calls</th></tr></thead><tbody>
{% for item in run.api_coverage.observed_calls %}<tr><td><code>{{ item.api }}</code></td><td>{{ item.count }}</td><td>{{ item.signature_only_count }}</td></tr>{% endfor %}
</tbody></table>{% else %}<div class="empty">No native WinAPI calls were traced.</div>{% endif %}
{% if run.api_coverage.other_calls %}<p class="muted">{{ run.api_coverage.other_calls }} additional calls are outside the top 100 API names; see the engine report for the full trace.</p>{% endif %}
{% else %}<div class="empty">Per-API call counts were not recorded for this run.</div>{% endif %}
{% if run.api_coverage and run.api_coverage.signature_only_calls %}<h2>Signature-only API calls</h2><div class="panel"><pre>{{ run.api_coverage.signature_only_calls|tojson(indent=2) }}</pre></div>{% endif %}
{% endif %}
<h2>Network broker events <span class="muted">({{ broker_event_count }})</span></h2>
<p class="muted">Showing {{ broker_first }}–{{ broker_last }} of {{ broker_event_count }} · page {{ broker_page }} of {{ broker_pages }}.
{% if broker_page > 1 %}<a href="{{ url_for('detail', run_id=run.id, events_page=events_page, broker_page=broker_page - 1) }}">Previous broker page</a>{% endif %}
{% if broker_page < broker_pages %}<a href="{{ url_for('detail', run_id=run.id, events_page=events_page, broker_page=broker_page + 1) }}">Next broker page</a>{% endif %}</p>
{% if run.network_attempts %}<h2>Network attempts <span class="muted">({{ run.network_attempts|length }} shown{% if run.network_attempts_omitted %}; {{ run.network_attempts_omitted }} omitted by the summary cap{% endif %})</span></h2><div class="panel"><pre>{{ run.network_attempts|tojson(indent=2) }}</pre></div>{% endif %}
{% if broker_events %}<table><thead><tr><th>Type</th><th>Details</th></tr></thead><tbody>
{% for event in broker_events %}<tr><td><span class="pill">{{ event.event or 'event' }}</span></td><td><pre>{{ event|tojson(indent=2) }}</pre></td></tr>{% endfor %}
</tbody></table>{% else %}<div class="empty">No broker events in this report.</div>{% endif %}
<h2>Extracted artifacts</h2>{% if run.artifact_groups is defined and run.artifact_groups %}<table><thead><tr><th>Type and preview</th><th>Observations</th><th>Size</th><th>SHA-256</th><th>Download</th></tr></thead><tbody>
{% for a in run.artifact_groups %}<tr><td>{{ a.kind }} <span class="muted">({{ a.preview_encoding }})</span>{% if a.pe_metadata %}<pre>{{ a.pe_metadata|tojson(indent=2) }}</pre>{% endif %}<pre>{{ a.preview }}</pre></td><td>{% for observation in a.observations %}<div>{{ observation.stage or 'observation' }} · {{ observation.source }}{% if observation.guest_path %} · {{ observation.guest_path }}{% endif %}{% if observation.context %}<pre>{{ observation.context|tojson(indent=2) }}</pre>{% endif %}</div>{% endfor %}</td><td>{{ a.size }}</td><td><code>{{ a.sha256 }}</code></td><td><a href="/runs/{{ run.id }}/artifacts/{{ a.file }}">Download</a></td></tr>{% endfor %}
</tbody></table>{% elif run.artifacts %}<table><thead><tr><th>Type</th><th>Source</th><th>Guest path</th><th>Size</th><th>SHA-256</th><th>Download</th></tr></thead><tbody>{% for a in run.artifacts %}<tr><td>{{ a.kind }}</td><td>{{ a.source }}</td><td>{{ a.guest_path or '—' }}</td><td>{{ a.size }}</td><td><code>{{ a.sha256 }}</code></td><td><a href="/runs/{{ run.id }}/artifacts/{{ a.file }}">Download</a></td></tr>{% endfor %}</tbody></table>{% else %}<div class="empty">No artifacts recovered.</div>{% endif %}
<h2>Events <span class="muted">({{ event_count }})</span></h2><p class="muted">Events with execution ticks are ordered by tick. Virtual event ticks inferred from matching API calls are marked. Events without a tick follow the timed sequence. Showing {{ event_first }}–{{ event_last }} of {{ event_count }} · page {{ events_page }} of {{ event_pages }}.
{% if events_page > 1 %}<a href="{{ url_for('detail', run_id=run.id, events_page=events_page - 1, broker_page=broker_page) }}">Previous event page</a>{% endif %}
{% if events_page < event_pages %}<a href="{{ url_for('detail', run_id=run.id, events_page=events_page + 1, broker_page=broker_page) }}">Next event page</a>{% endif %}</p>
{% if events %}<table><thead><tr><th>Type</th><th>Details</th></tr></thead><tbody>
{% for event in events %}<tr><td><span class="pill">{{ event.event or 'event' }}</span></td><td><pre>{{ event|tojson(indent=2) }}</pre></td></tr>{% endfor %}
</tbody></table>{% else %}<div class="empty">No events in the engine report.</div>{% endif %}
</main></body></html>
"""


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


def _timeline_events(engine: dict) -> list[dict]:
    """Merge native trace streams by execution tick, retaining provenance."""
    streams = [("events", _dict_events(engine.get("events"))),
               ("network_events", _dict_events(engine.get("network_events"))),
               ("virtual_file_events", _dict_events(engine.get("virtual_file_events"))),
               ("virtual_registry_events", _dict_events(engine.get("virtual_registry_events"))),
               ("virtual_process_events", _dict_events(engine.get("virtual_process_events"))),
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
    app.config["MAX_CONTENT_LENGTH"] = 1024
    app.config["TRUSTED_HOSTS"] = ["localhost", "127.0.0.1"]

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
                                      sort_order=sort_order, style=STYLE)

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

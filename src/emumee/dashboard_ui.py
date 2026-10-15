"""Presentation templates for the local analysis dashboard."""

from datetime import datetime, timezone
import json


def ui_json(value, indent=2):
    """Render readable JSON as plain text for Jinja's HTML autoescaping."""
    return json.dumps(value, ensure_ascii=False, indent=indent)


def ui_number(value):
    """Format report counts without changing their stored values."""
    return f"{value:,}" if type(value) is int else str(value) if value is not None else "—"


def ui_datetime(value):
    """Keep report times explicit and compact, including older run IDs."""
    if not isinstance(value, str) or not value:
        return "Not recorded"
    try:
        moment = (datetime.strptime(value, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
                  if len(value) == 16 and value.endswith("Z") else
                  datetime.fromisoformat(value.replace("Z", "+00:00")))
        if moment.tzinfo is not None:
            moment = moment.astimezone(timezone.utc)
        return moment.strftime("%d %b %Y · %H:%M") + (" UTC" if moment.tzinfo else "")
    except ValueError:
        return value

STYLE = """
:root {
  color-scheme:light;
  --bg:#f3f4ef;
  --panel:#fff;
  --panel-2:#f7f8f4;
  --panel-3:#edf0e9;
  --hover:#f5f7f1;
  --border:#dce1d7;
  --border-soft:#e9ece5;
  --border-strong:#bdc8bc;
  --text:#202b24;
  --muted:#657066;
  --faint:#727d72;
  --accent:#285e45;
  --accent-soft:#e8f0e9;
  --link:#285e45;
  --ok:#286346;
  --ok-bg:#eaf3ec;
  --warn:#8a5b15;
  --warn-bg:#fbf1dd;
  --danger:#a54438;
  --danger-bg:#fbebe7;
  --info:#3e617c;
  --info-bg:#eaf1f6;
  --radius:8px;
  --mono:"Cascadia Code",Consolas,ui-monospace,monospace;
  --sans:"Segoe UI",system-ui,-apple-system,BlinkMacSystemFont,sans-serif
}
* {
  box-sizing:border-box
}
html {
  scroll-behavior:auto;
  scroll-padding-top:86px
}
body {
  margin:0;
  background:var(--bg);
  color:var(--text);
  font:14px/1.55 var(--sans);
  -webkit-font-smoothing:antialiased
}
::selection {
  background:#cce0ce
}
a {
  color:var(--link);
  text-decoration:none
}
a:hover {
  text-decoration:underline
}
a,button,input,select,summary {
  touch-action:manipulation
}
a:focus-visible,button:focus-visible,summary:focus-visible {
  outline:3px solid #75a981;
  outline-offset:3px
}
h1,h2,h3,p {
  margin-top:0
}
h1 {
  font-size:32px;
  line-height:1.2;
  font-weight:650;
  letter-spacing:-.9px;
  margin-bottom:10px;
  overflow-wrap:anywhere
}
h2 {
  font-size:20px;
  line-height:1.3;
  font-weight:650;
  letter-spacing:-.35px;
  margin:0 0 16px
}
h3 {
  font-size:15px;
  font-weight:650;
  margin:0 0 12px
}
.muted,.lede,.meta-line {
  color:var(--muted)
}
.faint {
  color:var(--faint)
}
.lede {
  font-size:15px;
  max-width:760px;
  margin-bottom:0
}
.eyebrow {
  font:12px/1.4 var(--mono);
  color:var(--muted);
  margin-bottom:12px;
  overflow-wrap:anywhere
}
.page-heading {
  margin:0 0 28px
}
.page-heading .hero-tags {
  margin-top:16px
}
.skip-link {
  position:fixed;
  top:-60px;
  left:230px;
  z-index:100;
  background:var(--panel);
  padding:10px 16px
}
.skip-link:focus {
  top:8px
}
.sidebar {
  position:fixed;
  inset:0 auto 0 0;
  width:208px;
  background:#202c25;
  color:#dae3d9;
  padding:30px 20px 22px;
  display:flex;
  flex-direction:column;
  z-index:30
}
.brand {
  display:flex;
  align-items:center;
  gap:11px;
  color:#f6f8f1;
  font-weight:650;
  font-size:22px;
  letter-spacing:-.6px
}
.brand:hover {
  text-decoration:none
}
.brand-mark {
  display:grid;
  place-items:center;
  width:32px;
  height:34px;
  border:1px solid #607d66;
  border-radius:6px;
  color:#c7d8b2;
  font:650 20px var(--sans)
}
.brand-caption {
  color:#9aab9d;
  font-size:11px;
  margin:9px 0 34px 43px
}
.nav-label {
  font-size:10px;
  letter-spacing:1.4px;
  font-weight:650;
  text-transform:uppercase;
  color:#9aab9d;
  margin:24px 12px 10px
}
.side-nav {
  display:flex;
  flex-direction:column;
  gap:4px
}
.side-nav a {
  color:#bfccc0;
  padding:9px 12px;
  border-radius:5px;
  font-size:13px;
  display:flex;
  justify-content:space-between;
  gap:8px
}
.side-nav a:hover {
  background:#2e3d31;
  color:#fff;
  text-decoration:none
}
.side-nav a.active {
  background:#364a38;
  color:#eef4df;
  box-shadow:inset 3px 0 #b2c699
}
.side-nav .nav-index {
  color:#8fa393;
  font:11px var(--mono)
}
.sidebar-footer {
  margin-top:auto;
  border-top:1px solid #3b4c3e;
  padding:18px 12px 0;
  color:#9aab9d;
  font-size:11px;
  line-height:1.8
}
.local-dot {
  display:inline-block;
  width:6px;
  height:6px;
  background:#a7bf91;
  border-radius:50%;
  margin-right:6px
}
.workspace {
  margin-left:208px;
  min-width:0
}
.topbar {
  position:sticky;
  top:0;
  z-index:20;
  height:62px;
  border-bottom:1px solid var(--border);
  background:var(--bg);
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:16px;
  padding:0 36px;
  font-size:12px;
  color:var(--muted)
}
.topbar .crumb {
  display:flex;
  align-items:center;
  gap:12px
}
.topbar .crumb-separator {
  color:#adb5a9
}
.topbar .current {
  color:var(--text)
}
.local-label {
  font-size:11px;
  white-space:nowrap
}
.wrap {
  max-width:1420px;
  padding:34px 36px 64px;
  margin:0 auto;
  min-width:0
}
.section {
  margin-top:32px;
  scroll-margin-top:0
}
.section>h2:not(:first-child) {
  margin-top:28px
}
.section-head {
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:16px;
  margin-bottom:15px
}
.section-head h2 {
  margin:0
}
.section-head p {
  margin:0
}
.count-tag {
  font-size:12px;
  color:var(--muted);
  font-weight:400;
  letter-spacing:0;
  margin-left:4px
}
.hero-tags {
  display:flex;
  gap:8px;
  align-items:center;
  flex-wrap:wrap
}
.chip {
  font-size:12px;
  color:var(--muted);
  border:1px solid var(--border);
  border-radius:4px;
  background:var(--panel);
  padding:3px 8px
}
.pill {
  display:inline-flex;
  align-items:center;
  gap:6px;
  max-width:100%;
  padding:3px 8px;
  border-radius:4px;
  font-size:12px;
  font-weight:600;
  color:var(--muted);
  background:var(--panel-3);
  overflow-wrap:anywhere
}
.pill.completed {
  color:var(--ok);
  background:var(--ok-bg)
}
.pill.partial,.pill.timeout {
  color:var(--warn);
  background:var(--warn-bg)
}
.pill.failed {
  color:var(--danger);
  background:var(--danger-bg)
}
.pill.running {
  color:var(--info);
  background:var(--info-bg)
}
.pill.completed::before,.pill.partial::before,.pill.failed::before,.pill.timeout::before,.pill.running::before {
  content:"";
  width:5px;
  height:5px;
  border-radius:50%;
  background:currentColor;
  flex-shrink:0
}
.cards {
  display:grid;
  grid-template-columns:repeat(4,minmax(0,1fr));
  background:var(--panel);
  border:1px solid var(--border);
  border-radius:var(--radius);
  overflow:hidden;
  margin-bottom:24px
}
.card {
  padding:20px 22px;
  min-width:0;
  border-right:1px solid var(--border)
}
.card:last-child {
  border-right:0
}
.label {
  font-size:12px;
  color:var(--muted);
  font-weight:500;
  margin-bottom:8px
}
.metric {
  font-size:29px;
  line-height:1.2;
  font-weight:600;
  letter-spacing:-.8px;
  font-variant-numeric:tabular-nums;
  overflow-wrap:anywhere
}
.metric.text {
  font-size:19px;
  letter-spacing:-.3px
}
.metric-note {
  font-size:11px;
  color:var(--muted);
  margin-top:7px
}
.panel {
  background:var(--panel);
  border:1px solid var(--border);
  border-radius:var(--radius);
  padding:20px;
  min-width:0
}
.panel+.panel {
  margin-top:12px
}
.kv {
  display:grid;
  grid-template-columns:repeat(2,minmax(0,1fr));
  column-gap:32px
}
.kv>div {
  display:flex;
  flex-direction:column;
  align-items:flex-start;
  gap:4px;
  padding:11px 0;
  border-bottom:1px solid var(--border-soft);
  min-width:0;
  overflow-wrap:anywhere
}
.kv>div:last-child {
  border-bottom:0
}
.kv .k {
  font-size:12px;
  color:var(--muted)
}
.kv .wide {
  grid-column:1/-1
}
.facts {
  display:grid;
  grid-template-columns:repeat(3,minmax(0,1fr));
  gap:20px
}
.facts .fact-value {
  font-size:13px;
  font-weight:500;
  overflow-wrap:anywhere
}
.filters {
  background:var(--panel);
  border:1px solid var(--border);
  border-radius:var(--radius);
  padding:20px;
  margin-bottom:20px
}
.form-grid {
  display:grid;
  grid-template-columns:repeat(3,minmax(0,1fr));
  gap:16px;
  align-items:end
}
.field {
  display:flex;
  flex-direction:column;
  gap:7px;
  min-width:0
}
.field>span {
  font-size:12px;
  font-weight:550;
  color:var(--text)
}
input,select {
  min-width:0;
  width:100%;
  height:39px;
  border:1px solid var(--border-strong);
  border-radius:5px;
  background:var(--panel);
  color:var(--text);
  padding:8px 10px;
  font:13px var(--sans)
}
input::placeholder {
  color:#828d80
}
input:focus,select:focus {
  outline:2px solid #92b59a;
  outline-offset:1px;
  border-color:var(--accent)
}
select {
  cursor:pointer
}
.form-actions {
  display:flex;
  flex-direction:row;
  gap:12px;
  align-items:center;
  min-height:39px
}
.button,button {
  display:inline-flex;
  justify-content:center;
  align-items:center;
  gap:8px;
  border:1px solid var(--accent);
  border-radius:5px;
  background:var(--accent);
  color:#fff;
  font:600 13px var(--sans);
  padding:10px 16px;
  cursor:pointer;
  text-decoration:none;
  white-space:nowrap;
  min-height:39px
}
.button:hover,button:hover {
  background:#1d4933;
  text-decoration:none
}
.button.secondary {
  background:var(--panel);
  border-color:var(--border-strong);
  color:var(--text)
}
.button.secondary:hover {
  background:var(--hover)
}
.text-link {
  font-size:12px
}
.compare {
  margin-top:24px;
  background:var(--panel);
  border:1px solid var(--border);
  border-radius:var(--radius);
  padding:0 20px
}
.compare>summary {
  padding:17px 0;
  cursor:pointer;
  font-size:13px;
  font-weight:600
}
.compare form {
  padding:0 0 20px
}
.compare .form-grid {
  grid-template-columns:1fr 1fr auto
}
.table-wrap {
  border:1px solid var(--border);
  border-radius:var(--radius);
  overflow:auto;
  background:var(--panel);
  max-width:100%
}
table {
  border-collapse:collapse;
  width:100%;
  font-size:13px
}
thead th {
  text-align:left;
  color:var(--muted);
  background:var(--panel-2);
  padding:11px 16px;
  border-bottom:1px solid var(--border);
  font-size:11px;
  font-weight:550;
  white-space:nowrap
}
tbody td {
  padding:15px 16px;
  border-bottom:1px solid var(--border-soft);
  vertical-align:top;
  overflow-wrap:anywhere
}
tbody tr:last-child td {
  border-bottom:0
}
tbody tr:hover td {
  background:var(--hover)
}
.run-table {
  min-width:750px
}
.run-table td {
  vertical-align:middle
}
.run-table td:nth-child(3) {
  min-width:100px
}
.run-table .pill {
  white-space:nowrap;
  overflow-wrap:normal
}
.run-table .subline {
  white-space:normal
}
.run-table .sample-cell {
  width:32%;
  min-width:220px
}
.sample-name {
  display:block;
  font-size:14px;
  font-weight:600;
  color:var(--text);
  margin-bottom:4px;
  overflow-wrap:anywhere
}
.sample-meta {
  display:flex;
  gap:7px;
  align-items:center;
  flex-wrap:wrap;
  color:var(--muted);
  font-size:11px
}
.subline {
  display:block;
  color:var(--muted);
  font-size:11px;
  margin-top:4px;
  overflow-wrap:anywhere
}
.run-id {
  font:10px var(--mono);
  color:var(--muted)
}
.num {
  font-variant-numeric:tabular-nums;
  white-space:nowrap
}
.table-action {
  font-size:12px;
  white-space:nowrap
}
.table-caption {
  display:flex;
  align-items:center;
  justify-content:space-between;
  gap:16px;
  margin:25px 0 12px;
  font-size:12px;
  color:var(--muted)
}
.table-caption strong {
  color:var(--text);
  font-weight:600
}
.pager {
  display:flex;
  gap:10px;
  align-items:center;
  justify-content:flex-end;
  margin-top:16px;
  flex-wrap:wrap
}
.pager a,.meta-line a {
  font-size:12px;
  padding:7px 12px;
  background:var(--panel);
  border:1px solid var(--border);
  border-radius:5px;
  color:var(--text);
  display:inline-block
}
.pager a:hover,.meta-line a:hover {
  background:var(--hover);
  text-decoration:none
}
.meta-line {
  font-size:12px;
  line-height:1.7
}
.meta-line a {
  margin:5px 0 5px 8px
}
code {
  font:12px/1.5 var(--mono);
  color:#385941;
  overflow-wrap:anywhere
}
pre {
  margin:0;
  background:var(--panel-2);
  color:#3d493e;
  font:12px/1.6 var(--mono);
  padding:14px;
  border:1px solid var(--border-soft);
  border-radius:5px;
  white-space:pre-wrap;
  overflow-wrap:anywhere;
  max-width:100%
}
.console {
  background:#222c25;
  color:#dde6d7;
  border:0;
  max-height:400px;
  overflow:auto
}
.console-grid,.comparison-pair {
  display:grid;
  grid-template-columns:repeat(2,minmax(0,1fr));
  gap:16px
}
.console-grid .panel+.panel {
  margin:0
}
.console-grid .panel {
  padding:16px
}
.alert {
  background:var(--panel);
  border:1px solid var(--border);
  border-left:3px solid var(--accent);
  border-radius:5px;
  padding:14px 16px;
  margin:12px 0;
  font-size:13px
}
.alert.warn {
  background:var(--warn-bg);
  border-color:#ecd6ad;
  color:#775015
}
.alert.danger {
  background:var(--danger-bg);
  border-color:#e8bdb3;
  color:#943d32
}
.alert pre {
  margin-top:10px;
  background:rgba(255,255,255,.5);
  color:inherit
}
.empty {
  padding:32px 24px;
  border:1px solid var(--border);
  border-radius:var(--radius);
  color:var(--muted);
  background:var(--panel);
  text-align:center;
  font-size:13px
}
.empty strong {
  display:block;
  color:var(--text);
  font-size:16px;
  margin-bottom:6px
}
.empty code {
  display:block;
  margin-top:16px
}
details.block {
  background:var(--panel);
  border:1px solid var(--border);
  border-radius:var(--radius);
  margin:12px 0;
  overflow:hidden
}
details.block>summary {
  cursor:pointer;
  display:flex;
  align-items:center;
  gap:10px;
  padding:14px 16px;
  font-size:13px;
  font-weight:600;
  list-style:none
}
details.block>summary::-webkit-details-marker {
  display:none
}
details.block>summary::before {
  content:"+";
  font:16px var(--mono);
  color:var(--muted);
  width:12px
}
details.block[open]>summary::before {
  content:"−"
}
details.block[open]>summary {
  border-bottom:1px solid var(--border-soft)
}
details.block>summary:hover {
  background:var(--hover)
}
details.block .body {
  padding:16px;
  min-width:0
}
details.block .body>.table-wrap {
  border:0;
  border-radius:0;
  margin:-16px;
  width:calc(100% + 32px);
  max-width:calc(100% + 32px)
}
details.raw {
  margin-top:10px
}
details.raw>summary {
  font-size:11px;
  cursor:pointer;
  color:var(--link)
}
details.raw pre {
  margin-top:8px;
  max-height:420px;
  overflow:auto
}
.evidence-list {
  display:flex;
  flex-direction:column;
  gap:12px
}
.evidence-card {
  border:1px solid var(--border);
  background:var(--panel);
  border-radius:var(--radius);
  padding:20px;
  min-width:0
}
.evidence-head {
  display:flex;
  justify-content:space-between;
  gap:20px;
  align-items:flex-start;
  margin-bottom:16px
}
.evidence-title {
  display:flex;
  align-items:center;
  gap:10px;
  flex-wrap:wrap;
  font-size:14px;
  font-weight:600
}
.evidence-head .button {
  font-size:12px;
  min-height:34px;
  padding:7px 12px
}
.evidence-hash {
  display:block;
  font-size:11px;
  color:var(--muted);
  margin:8px 0 0
}
.evidence-path {
  font:12px/1.6 var(--mono);
  overflow-wrap:anywhere;
  color:var(--text)
}
.observation {
  border-top:1px solid var(--border-soft);
  padding:12px 0 0;
  margin-top:12px;
  font-size:12px
}
.observation .label {
  font-size:11px;
  margin-bottom:5px
}
.evidence-preview {
  max-height:180px;
  overflow:auto
}
.event-table {
  table-layout:fixed
}
.event-table th:first-child {
  width:27%
}
.event-name {
  font:12px var(--mono);
  font-weight:600;
  color:var(--text);
  overflow-wrap:anywhere
}
.event-field {
  margin-bottom:5px;
  font-size:12px;
  overflow-wrap:anywhere
}
.event-field strong {
  color:var(--muted);
  font-weight:500;
  margin-right:8px
}
.comparison-pair .panel {
  padding:18px
}
.comparison-pair .panel+.panel {
  margin-top:0
}
.comparison-name {
  font-size:17px;
  font-weight:600;
  overflow-wrap:anywhere;
  margin-bottom:5px
}
.context-list {
  display:flex;
  flex-wrap:wrap;
  gap:8px;
  margin:20px 0
}
.context-item {
  border:1px solid var(--border);
  border-radius:5px;
  padding:6px 10px;
  background:var(--panel);
  font-size:12px
}
.context-item strong {
  font-weight:600
}
.change-table {
  table-layout:fixed
}
.change-table th:first-child {
  width:34%
}
.change-table pre {
  font-size:11px
}
.footer {
  font-size:11px;
  color:var(--muted);
  border-top:1px solid var(--border);
  padding-top:20px;
  margin-top:40px
}
.coverage-note {
  font-size:12px;
  color:var(--muted);
  max-width:850px
}
.section>p.muted {
  font-size:12px;
  max-width:850px
}
.fact-value code {
  color:inherit
}
@media(min-width:1600px) {
  .wrap {
    padding-left:48px;
    padding-right:48px
  }
}
@media(max-width:1100px) {
  .sidebar {
    width:180px;
    padding-left:14px;
    padding-right:14px
  }
  .workspace {
    margin-left:180px
  }
  .wrap {
    padding:28px 24px 48px
  }
  .topbar {
    padding:0 24px
  }
  .facts {
    grid-template-columns:repeat(2,minmax(0,1fr))
  }
  .skip-link {
    left:190px
  }
}
@media(max-width:900px) {
  .cards {
    grid-template-columns:repeat(2,minmax(0,1fr))
  }
  .card:nth-child(2) {
    border-right:0
  }
  .card:nth-child(-n+2) {
    border-bottom:1px solid var(--border)
  }
}
@media(max-width:760px) {
  html {
    scroll-padding-top:74px
  }
  .sidebar {
    position:static;
    width:auto;
    padding:14px 18px;
    display:block
  }
  .brand {
    font-size:19px
  }
  .brand-mark {
    width:25px;
    height:27px;
    font-size:17px
  }
  .brand-caption,.nav-label,.sidebar-footer {
    display:none
  }
  .side-nav {
    flex-direction:row;
    overflow:auto;
    margin-top:12px;
    gap:3px
  }
  .side-nav a {
    padding:7px 10px;
    white-space:nowrap;
    font-size:12px
  }
  .side-nav .nav-index {
    display:none
  }
  .workspace {
    margin-left:0
  }
  .topbar {
    height:48px;
    padding:0 18px
  }
  .wrap {
    padding:25px 18px 40px
  }
  h1 {
    font-size:27px
  }
  .form-grid {
    grid-template-columns:repeat(2,minmax(0,1fr))
  }
  .compare .form-grid {
    grid-template-columns:1fr
  }
  .kv {
    grid-template-columns:1fr
  }
  .facts {
    grid-template-columns:repeat(2,minmax(0,1fr))
  }
  .console-grid,.comparison-pair {
    grid-template-columns:1fr
  }
  .evidence-head {
    gap:12px
  }
  .evidence-card {
    padding:16px
  }
  .change-table th:first-child {
    width:28%
  }
  .change-table td {
    padding:12px 9px
  }
  .event-table th:first-child {
    width:32%
  }
  .section-head {
    align-items:flex-start
  }
  .skip-link {
    left:10px
  }
}
@media(max-width:420px) {
  .form-grid {
    grid-template-columns:1fr
  }
  .card {
    padding:16px
  }
  .metric {
    font-size:25px
  }
  .local-label {
    display:none
  }
  .evidence-head {
    flex-direction:column
  }
  .table-caption {
    align-items:flex-start
  }
  .facts {
    grid-template-columns:1fr
  }
}
@media(prefers-reduced-motion:reduce) {
  html {
    scroll-behavior:auto
  }
}
@media print {
  .sidebar,.topbar,.filters,.compare,.pager,.button,.skip-link {
    display:none
  }
  .workspace {
    margin:0
  }
  .wrap {
    padding:0
  }
  .table-wrap {
    overflow:visible
  }
  body {
    background:#fff
  }
  .cards,.panel,.evidence-card {
    break-inside:avoid
  }
}
"""

COMMON = """
{% macro start(title, view) -%}
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>Emumee · {{ title }}</title><style>{{ style | safe }}</style></head><body>
<a class="skip-link" href="#main">Skip to content</a>
<aside class="sidebar" aria-label="Workspace navigation">
<a class="brand" href="/"><span class="brand-mark" aria-hidden="true">E</span>Emumee</a><div class="brand-caption">Windows emulation</div>
<div class="nav-label">Workspace</div><nav class="side-nav"><a href="/"{% if view == 'runs' %} class="active" aria-current="page"{% endif %}>Analysis runs</a></nav>
{% if view == 'detail' %}<div class="nav-label">This run</div><nav class="side-nav" aria-label="Run sections"><a href="#overview">Overview</a><a href="#artifacts">Artifacts</a><a href="#console">Console</a><a href="#commands">Commands</a><a href="#coverage">API coverage</a><a href="#network">Network</a><a href="#events">Event timeline</a></nav>{% elif view == 'compare' %}<div class="nav-label">This comparison</div><nav class="side-nav" aria-label="Comparison sections"><a href="#outcomes">Outcomes</a><a href="#changes">API &amp; persona</a><a href="#artifacts">Artifacts</a><a href="#behavior">Behavior</a></nav>{% endif %}
<div class="sidebar-footer"><span class="local-dot"></span>Local workspace<br>Completed analysis reports</div></aside>
<div class="workspace"><header class="topbar"><div class="crumb"><a href="/">Workspace</a><span class="crumb-separator">/</span><span class="current">{{ title }}</span></div><span class="local-label">Read-only reports</span></header><main class="wrap" id="main">
{%- endmacro %}
{% macro end() -%}<footer class="footer">Emumee · Local analysis workspace</footer></main></div></body></html>{%- endmacro %}
{% macro changes(rows, empty, humanize=false) -%}
{% if rows %}<div class="table-wrap"><table class="change-table"><thead><tr><th>Field</th><th>Run A</th><th>Run B</th></tr></thead><tbody>{% for field, values in rows.items() %}<tr><td>{% if humanize %}{{ field|replace("_", " ")|capitalize }}{% else %}<code>{{ field }}</code>{% endif %}</td><td>{% if values.left is mapping or (values.left is sequence and values.left is not string) %}<pre>{{ values.left|ui_json(indent=2) }}</pre>{% else %}{{ values.left if values.left is not none else '—' }}{% endif %}</td><td>{% if values.right is mapping or (values.right is sequence and values.right is not string) %}<pre>{{ values.right|ui_json(indent=2) }}</pre>{% else %}{{ values.right if values.right is not none else '—' }}{% endif %}</td></tr>{% endfor %}</tbody></table></div>{% else %}<div class="empty">{{ empty }}</div>{% endif %}
{%- endmacro %}
{% macro event_rows(rows) -%}
<div class="table-wrap"><table class="event-table"><thead><tr><th>Event</th><th>Observation</th></tr></thead><tbody>{% for event in rows %}<tr><td><span class="event-name">{{ event.event or 'event' }}</span>{% if event.timeline_tick is defined and event.timeline_tick is not none %}<span class="subline">Tick {{ event.timeline_tick|ui_number }}{% if event.timeline_tick_inferred %} · inferred{% endif %}</span>{% endif %}</td><td>{% for key in ('api_name','api','method','url','host','guest_path','path','reason','status','result','ret_val','size','timeline_source') %}{% if event[key] is defined %}<div class="event-field"><strong>{{ key|replace('_',' ') }}</strong>{{ event[key] }}</div>{% endif %}{% endfor %}<details class="raw"><summary>View full event</summary><pre>{{ event|ui_json(indent=2) }}</pre></details></td></tr>{% endfor %}</tbody></table></div>
{%- endmacro %}
"""

INDEX = COMMON + """
{{ start('Analysis runs', 'runs') }}
<div class="page-heading"><div class="eyebrow">ANALYSIS / LIBRARY</div><h1>Analysis runs</h1><p class="lede">Review execution results, inspect recovered evidence, and compare runs.</p></div>
<div class="cards"><div class="card"><div class="label">Matching runs</div><div class="metric">{{ total|ui_number }}</div><div class="metric-note">In this view</div></div><div class="card"><div class="label">Completed</div><div class="metric">{{ status_counts.get('completed', 0)|ui_number }}</div><div class="metric-note">Analysis completed</div></div><div class="card"><div class="label">Needs review</div><div class="metric">{{ review_count|ui_number }}</div><div class="metric-note">Partial, failed, or timed out</div></div><div class="card"><div class="label">Recovered artifacts</div><div class="metric">{{ artifact_total|ui_number }}</div><div class="metric-note">Unique files within each run</div></div></div>
<form action="/" method="get" class="filters" aria-label="Filter analysis runs"><div class="form-grid">
<label class="field"><span>Sample hash</span><input name="sha" value="{{ sha_filter }}" maxlength="64" minlength="8" pattern="[a-fA-F0-9]{8,64}" spellcheck="false" placeholder="SHA-256 prefix · at least 8 characters"></label>
<label class="field"><span>Run status</span><select name="status"><option value="">All statuses</option>{% for name in ('completed','partial','failed','timeout','running') %}<option value="{{ name }}"{% if status_filter == name %} selected{% endif %}>{{ name|capitalize }}</option>{% endfor %}</select></label>
<label class="field"><span>Sort by</span><select name="sort"><option value="newest"{% if sort_order == 'newest' %} selected{% endif %}>Newest first</option><option value="oldest"{% if sort_order == 'oldest' %} selected{% endif %}>Oldest first</option><option value="artifacts"{% if sort_order == 'artifacts' %} selected{% endif %}>Most artifacts</option></select></label>
<label class="field"><span>Behavior</span><input name="behavior" value="{{ behavior_filter }}" maxlength="128" placeholder="API name, URL, or guest path"></label>
<label class="field"><span>Artifact type</span><input name="kind" value="{{ kind_filter }}" maxlength="32" placeholder="e.g. pe, script, binary"></label>
<div class="form-actions"><button type="submit">Apply filters</button>{% if sha_filter or status_filter or kind_filter or behavior_filter or sort_order != 'newest' %}<a class="text-link" href="/">Clear filters</a>{% endif %}</div></div></form>
{% if runs|length > 1 %}<details class="compare"><summary>Compare two runs</summary><form action="/compare" method="get"><div class="form-grid"><label class="field"><span>Run A</span><select name="left">{% for run in runs %}<option value="{{ run.id }}">{{ run.sample.name }} · {{ run.id }}</option>{% endfor %}</select></label><label class="field"><span>Run B</span><select name="right">{% for run in runs %}<option value="{{ run.id }}"{% if loop.index == 2 %} selected{% endif %}>{{ run.sample.name }} · {{ run.id }}</option>{% endfor %}</select></label><button type="submit">Compare runs →</button></div></form></details>{% endif %}
{% if runs %}<div class="table-caption"><span><strong>{{ total|ui_number }} {{ 'run' if total == 1 else 'runs' }}</strong>{% if total > 50 %} · Showing {{ (page - 1) * 50 + 1 }}–{{ [page * 50, total]|min }}{% endif %}</span><span>Page {{ page }}</span></div>
<div class="table-wrap"><table class="run-table"><thead><tr><th>Sample</th><th>Started</th><th>Status</th><th>Guest result</th><th>Calls</th><th>Artifacts</th></tr></thead><tbody>
{% for run in runs %}<tr><td class="sample-cell"><a class="sample-name" href="/runs/{{ run.id }}">{{ run.sample.name if run.sample else 'Unknown sample' }}</a><div class="sample-meta"><span>{{ run.sample.architecture if run.sample and run.sample.architecture else 'Unknown architecture' }}</span><span>·</span><span>{{ run.engine or 'Unknown engine' }}</span></div>{% if run.sample and run.sample.sha256 %}<span class="subline"><code title="{{ run.sample.sha256 }}">{{ run.sample.sha256[:16] }}…</code></span>{% endif %}</td><td><span class="num">{{ (run.started_at or run.id[:16])|ui_datetime }}</span><span class="subline run-id">{{ run.id }}</span></td><td><span class="pill {{ run.status }}">{{ run.status|capitalize }}</span></td><td>{% if run.guest_exit_code is defined and run.guest_exit_code is not none %}Exit {{ run.guest_exit_code }}{% elif run.guest_entry_return is defined and run.guest_entry_return is not none %}Return {{ run.guest_entry_return }}{% else %}<span class="muted">Not recorded</span>{% endif %}</td><td class="num">{% if run.cil_coverage %}{{ run.cil_coverage.framework_calls|ui_number }}<span class="subline">Framework</span>{% elif run.api_coverage %}{{ run.api_coverage.api_calls|ui_number }}<span class="subline">WinAPI{% if run.api_coverage.signature_only_calls %} · {{ run.api_coverage.signature_only_calls|length }} signature-only{% endif %}</span>{% else %}—{% endif %}</td><td class="num">{{ (run.artifact_groups|length if run.artifact_groups is defined else run.artifacts|length)|ui_number }}</td></tr>{% endfor %}
</tbody></table></div><nav class="pager" aria-label="Run pages">{% if previous_page %}<a href="{{ previous_page }}">← Previous</a>{% endif %}{% if next_page %}<a href="{{ next_page }}">Next →</a>{% endif %}</nav>

{% elif sha_filter or status_filter or kind_filter or behavior_filter %}<div class="empty"><strong>No runs match these filters.</strong>Try a shorter search or a different status.<br><a class="button secondary" href="/" style="margin-top:16px">Clear filters</a></div>{% else %}<div class="empty"><strong>Your analysis library is empty.</strong>Run a sample from the terminal to create your first report.<code>emumee run sample.exe</code></div>{% endif %}
{{ end() }}
"""

ERROR = COMMON + """
{{ start('Report unavailable', 'error') }}
<div class="page-heading"><div class="eyebrow">{{ code }}</div><h1>{{ title }}</h1><p class="lede">{{ message }}</p></div><a class="button" href="/">Back to analysis runs →</a>
{{ end() }}
"""

COMPARE = COMMON + """
{{ start('Compare runs', 'compare') }}
<div class="page-heading"><div class="eyebrow">ANALYSIS / COMPARISON</div><h1>Compare runs</h1><p class="lede">Inspect changes in execution, behavior, and recovered evidence.</p></div>
<div class="comparison-pair">{% for side, label in ((comparison.left, 'Run A'), (comparison.right, 'Run B')) %}<div class="panel"><div class="label">{{ label }}</div><div class="comparison-name">{{ side.sample.name }}</div><a class="run-id" href="/runs/{{ side.id }}">{{ side.id }} →</a></div>{% endfor %}</div>
<div class="context-list">{% for key, label in (('same_sample','Sample'),('same_persona','Persona'),('same_limits','Limits'),('same_invocation','Invocation')) %}<span class="context-item">{{ label }}: <strong>{{ 'Unknown' if comparison.comparable_context[key] is none else 'Same' if comparison.comparable_context[key] else 'Different' }}</strong></span>{% endfor %}<a class="context-item" href="/compare?left={{ comparison.left.id }}&right={{ comparison.right.id }}&format=json">Download JSON diff ↓</a></div>
{% if comparison.comparable_context.live_network_variable %}<div class="alert warn">A run used live networking. Response differences may affect the comparison.</div>{% endif %}
{% if comparison.artifact_evidence.left != 'verified' or comparison.artifact_evidence.right != 'verified' %}<div class="alert danger">Artifact comparison excludes unverified evidence.<pre>{{ comparison.artifact_evidence|ui_json(indent=2) }}</pre></div>{% endif %}
<section class="section" id="outcomes"><h2>Outcomes and limits</h2>{{ changes(comparison.outcomes, 'Both runs have the same recorded outcomes and limits.', true) }}{% if comparison.comparable_context.input_changes %}<details class="block"><summary>Invocation changes</summary><div class="body">{{ changes(comparison.comparable_context.input_changes, '', true) }}</div></details>{% endif %}<details class="block"><summary>Comparison context</summary><div class="body"><pre>{{ comparison.comparable_context|ui_json(indent=2) }}</pre></div></details></section>
<section class="section" id="changes"><h2>Changed API counts</h2>{{ changes(comparison.api_changes, 'No changes in recorded WinAPI call counts.') }}<details class="block"><summary>Changed API return values <span class="count-tag">{{ comparison.api_result_changes|length }}</span></summary><div class="body">{{ changes(comparison.api_result_changes, 'No changes in recorded API return values.') }}</div></details><details class="block"><summary>Changed persona fields <span class="count-tag">{{ comparison.persona_changes|length }}</span></summary><div class="body">{{ changes(comparison.persona_changes, 'The recorded personas are identical.') }}</div></details></section>
<section class="section" id="artifacts"><h2>Artifacts</h2><div class="comparison-pair">{% for key, label in (('only_left','Only in run A'),('only_right','Only in run B')) %}<div class="panel"><div class="label">{{ label }} · {{ comparison.artifact_changes[key]|length }}</div>{% for digest in comparison.artifact_changes[key] %}<p><code>{{ digest }}</code></p>{% else %}<span class="muted">No unique artifacts.</span>{% endfor %}</div>{% endfor %}</div><details class="block"><summary>Shared artifacts <span class="count-tag">{{ comparison.artifact_changes.shared|length }}</span></summary><div class="body">{% for digest in comparison.artifact_changes.shared %}<p><code>{{ digest }}</code></p>{% else %}<span class="muted">No shared artifacts.</span>{% endfor %}</div></details></section>
<section class="section" id="behavior"><h2>Behavior changes</h2><p class="coverage-note">{{ comparison.behavior_changes.shared_count|ui_number }} shared observations. {{ 'The recorded event order differs.' if comparison.behavior_changes.source_order_changed else 'The recorded event order is unchanged.' }}</p><div class="comparison-pair">{% for key, label in (('only_left','Only in run A'),('only_right','Only in run B')) %}<div class="panel"><h3>{{ label }}</h3>{% if comparison.behavior_changes[key] %}{% for signal in comparison.behavior_changes[key] %}<div class="observation"><div class="label">{{ signal.event or signal.source or 'Observation' }} · {{ signal.count }} occurrences</div>{% for field in ('api','guest_path','path','url','host','reason','kind') %}{% if signal[field] is defined %}<div class="event-field"><strong>{{ field|replace('_',' ') }}</strong>{{ signal[field] }}</div>{% endif %}{% endfor %}<details class="raw"><summary>Full observation</summary><pre>{{ signal|ui_json(indent=2) }}</pre></details></div>{% endfor %}{% else %}<p class="muted">No unique behavior observations.</p>{% endif %}</div>{% endfor %}</div><details class="block"><summary>Behavior changes · full details</summary><div class="body"><pre>{{ comparison.behavior_changes|ui_json(indent=2) }}</pre></div></details><details class="block"><summary>Console output</summary><div class="body">{% if comparison.console_output %}<div class="comparison-pair">{% for key, label in (('left','Run A'),('right','Run B')) %}<div><div class="label">{{ label }}</div><pre>{{ comparison.console_output[key]|ui_json(indent=2) }}</pre></div>{% endfor %}</div>{% else %}<span class="muted">No changes in captured console output.</span>{% endif %}</div></details></section>
{{ end() }}
"""


DETAIL = COMMON + """
{{ start('Run report', 'detail') }}
<section id="overview"><div class="page-heading"><div class="eyebrow">{{ run.id }}</div><h1>{{ run.sample.name if run.sample else 'Analysis run' }}</h1><p class="lede">Execution results and evidence from this analysis run.</p><div class="hero-tags"><span class="pill {{ run.status }}">{{ run.status|capitalize }}</span>{% if run.engine %}<span class="chip">{{ run.engine }}</span>{% endif %}{% if run.sample and run.sample.architecture %}<span class="chip">{{ run.sample.architecture }}</span>{% endif %}{% if run.sample %}<span class="chip">{{ 'PowerShell' if run.sample.kind in ('powershell', 'powershell-probe') else 'Managed' if run.sample.managed else 'Native' }}</span>{% endif %}</div></div>
<div class="cards"><div class="card"><div class="label">Instructions</div><div class="metric">{{ run.instruction_count|ui_number if run.instruction_count is defined else '—' }}</div><div class="metric-note">Executed guest instructions</div></div><div class="card"><div class="label">Unique artifacts</div><div class="metric">{{ (run.artifact_groups|length if run.artifact_groups is defined else run.artifacts|length)|ui_number }}</div><div class="metric-note">Recovered evidence</div></div><div class="card"><div class="label">Denied operations</div><div class="metric">{{ (run.denied_operations or 0)|ui_number }}</div><div class="metric-note">Recorded network denials</div></div><div class="card"><div class="label">Guest result</div><div class="metric text">{% if run.guest_exit_code is defined and run.guest_exit_code is not none %}Exit {{ run.guest_exit_code }}{% elif run.guest_entry_return is defined and run.guest_entry_return is not none %}Return {{ run.guest_entry_return }}{% else %}Not recorded{% endif %}</div><div class="metric-note">{{ (run.completion_reason or 'No completion reason')|replace('_', ' ') }}</div></div></div>
<div class="panel" style="margin-bottom:24px"><div class="facts">
{% for label, value in (('Engine trace', trace_integrity), ('Network report', broker_integrity), ('Instruction limit', 'Reached' if run.instruction_limit_reached else 'Not reached'), ('Wall-clock limit', 'Reached' if run.timeout_reached else 'Not reached'), ('Guest exit code', run.guest_exit_code if run.guest_exit_code is defined and run.guest_exit_code is not none else 'Unknown'), ('Entry return', run.guest_entry_return if run.guest_entry_return is defined and run.guest_entry_return is not none else '—')) %}<div><div class="label">{{ label }}</div><div class="fact-value">{{ value }}</div></div>{% endfor %}
{% if run.cil_coverage %}<div><div class="label">CIL opcode attempts</div><div class="fact-value">{{ run.cil_coverage.opcode_attempts|ui_number }} · {{ run.cil_coverage.tracked_opcodes|ui_number }} tracked names</div></div><div><div class="label">Framework call attempts</div><div class="fact-value">{{ run.cil_coverage.framework_calls|ui_number }}</div></div>{% else %}<div><div class="label">Observed API calls</div><div class="fact-value">{{ run.api_coverage.api_calls|ui_number if run.api_coverage else '—' }}</div></div><div><div class="label">Distinct API names</div><div class="fact-value">{{ run.api_coverage.observed_apis|ui_number if run.api_coverage and run.api_coverage.observed_apis is defined else '—' }}</div></div><div><div class="label">Signature-only API names</div><div class="fact-value">{{ run.api_coverage.signature_only_calls|length if run.api_coverage else '—' }}</div></div>{% endif %}
</div></div>
{% if run.errors %}<h3>Coverage limits and errors</h3><div class="alert danger"><pre>{{ run.errors|ui_json(indent=2) }}</pre></div>{% endif %}
{% if run.guest_trace_complete is sameas false %}<div class="alert danger">The worker did not finish its guest trace report. Guest API, file, process, memory, and console observations may be incomplete.</div>{% endif %}
{% if run.artifact_checkpoint_recovered %}<div class="alert warn">Artifacts below were recovered from a verified worker checkpoint. Later payloads and observations may be missing.</div>{% endif %}
{% if run.artifact_integrity in ('failed', 'unverified') %}<div class="alert danger">Artifact claims could not be verified and are excluded from counts, search, comparison, and downloads.{% if run.unverified_artifact_count %} {{ run.unverified_artifact_count }} worker artifact rows were quarantined.{% endif %}</div>{% endif %}
{% if run.aes_plaintext_capture and (run.aes_plaintext_capture.captured_artifacts or run.aes_plaintext_capture.omitted_transforms) %}
<h3>Decrypted memory</h3><div class="alert{% if run.aes_plaintext_capture.omitted_transforms %} warn{% endif %}">
{{ run.aes_plaintext_capture.captured_artifacts }} plaintext artifacts ({{ run.aes_plaintext_capture.captured_bytes }} bytes) captured.
{% if run.aes_plaintext_capture.omitted_transforms %}{{ run.aes_plaintext_capture.omitted_transforms }} transforms ({{ run.aes_plaintext_capture.omitted_bytes }} bytes) omitted by the capture budget; inspect the transform events for hashes and reasons.{% endif %}
</div>{% endif %}
{% if run.artifact_capture and run.artifact_capture.omitted_observations %}
<h3>Artifact capture limits</h3><div class="alert warn">{{ run.artifact_capture.omitted_observations }} observations ({{ run.artifact_capture.omitted_bytes }} bytes) were not retained.
<pre>{{ run.artifact_capture.reasons|ui_json(indent=2) }}</pre>
{% if run.artifact_capture.examples %}<pre>{{ run.artifact_capture.examples|ui_json(indent=2) }}</pre>{% endif %}</div>{% endif %}
{% if run.network_broker_complete is sameas false %}<div class="alert warn">Network broker log was recovered after an interrupted shutdown and may be incomplete.</div>{% endif %}
<h3>Sample &amp; execution</h3>
<div class="panel"><div class="kv">
<div class="wide"><span class="k">SHA-256</span><code>{{ run.sample.sha256 if run.sample else '—' }}</code></div>
<div><span class="k">Type</span>{{ 'PowerShell' if run.sample and run.sample.kind in ('powershell', 'powershell-probe') else 'Managed' if run.sample and run.sample.managed else 'Native' }} {{ run.sample.kind if run.sample else '' }}</div>
<div><span class="k">Started</span>{{ run.started_at|ui_datetime }}</div>
<div><span class="k">Persona</span>{{ run.persona.hostname if run.persona else '—' }} / {{ run.persona.user_name if run.persona else '—' }}</div>
<div><span class="k">Guest finished</span>{{ run.finished_at|ui_datetime }}</div>
<div><span class="k">Command finished</span>{{ run.command_finished_at|ui_datetime }}</div>
<div><span class="k">Total command time</span>{{ run.command_elapsed_seconds if run.command_elapsed_seconds is defined else '—' }} seconds</div>
<div><span class="k">Worker exit code</span>{{ run.worker_exit_code if run.worker_exit_code is defined and run.worker_exit_code is not none else '—' }}</div>
</div></div>
{% if run.run_manifest %}<details class="block"><summary>Run manifest · full configuration</summary><div class="body"><pre>{{ run.run_manifest|ui_json(indent=2) }}</pre></div></details>{% endif %}
</section>
<section class="section" id="artifacts"><div class="section-head"><h2>Extracted artifacts</h2><span class="count-tag">{{ run.artifact_groups|length if run.artifact_groups is defined else run.artifacts|length }} unique artifacts</span></div>
{% if run.artifact_groups is defined and run.artifact_groups %}<div class="evidence-list">{% for a in run.artifact_groups %}<article class="evidence-card"><div class="evidence-head"><div><div class="evidence-title"><span class="chip">{{ a.kind|upper }}</span><span>{{ a.size|ui_number }} bytes</span><span class="count-tag">{{ a.observations|length }} {{ 'observation' if a.observations|length == 1 else 'observations' }}</span></div><code class="evidence-hash">SHA-256 {{ a.sha256 }}</code>{% if a.observations and a.observations[0].guest_path %}<div class="evidence-path" style="margin-top:8px">{{ a.observations[0].guest_path }}</div>{% endif %}</div><a class="button secondary" href="/runs/{{ run.id }}/artifacts/{{ a.file }}">Download ↓</a></div><div class="label">Preview · {{ a.preview_encoding }}</div><pre class="evidence-preview">{{ a.preview }}</pre>{% if a.pe_metadata %}<details class="raw"><summary>PE metadata</summary><pre>{{ a.pe_metadata|ui_json(indent=2) }}</pre></details>{% endif %}<details class="raw"><summary>Capture observations</summary>{% for observation in a.observations %}<div class="observation"><div class="label">{{ observation.stage or 'Observation' }} · {{ observation.source }}</div>{% if observation.guest_path %}<div class="evidence-path">{{ observation.guest_path }}</div>{% endif %}{% if observation.context %}<pre>{{ observation.context|ui_json(indent=2) }}</pre>{% endif %}</div>{% endfor %}</details></article>{% endfor %}</div>
{% elif run.artifacts %}<div class="table-wrap"><table><thead><tr><th>Type</th><th>Source &amp; guest path</th><th>Size</th><th>SHA-256</th><th>Download</th></tr></thead><tbody>{% for a in run.artifacts %}<tr><td>{{ a.kind }}</td><td>{{ a.source }}<span class="subline">{{ a.guest_path or '—' }}</span></td><td class="num">{{ a.size|ui_number }} bytes</td><td><code>{{ a.sha256 }}</code></td><td><a href="/runs/{{ run.id }}/artifacts/{{ a.file }}">Download</a></td></tr>{% endfor %}</tbody></table></div>{% else %}<div class="empty">No artifacts recovered.</div>{% endif %}</section>
<section class="section" id="console"><h2>Console output</h2>
{% if run.console_output %}<div class="console-grid">
<div class="panel"><div class="label">Standard output{% if run.console_output.stdout_truncated %} · truncated{% endif %}</div>
{% if run.console_output.stdout %}<pre class="console">{{ run.console_output.stdout }}</pre>{% else %}<div class="muted">No stdout captured.</div>{% endif %}</div>
<div class="panel"><div class="label">Standard error{% if run.console_output.stderr_truncated %} · truncated{% endif %}</div>
{% if run.console_output.stderr %}<pre class="console">{{ run.console_output.stderr }}</pre>{% else %}<div class="muted">No stderr captured.</div>{% endif %}</div>
</div>{% else %}<div class="empty">No console capture in this report.</div>{% endif %}
</section>
<section class="section" id="commands"><h2>Command invocations <span class="count-tag">({{ command_count }})</span></h2>
<p class="muted">Recorded command names, evaluated parameters, and native arguments where available. An invocation record does not establish successful completion.</p>
{% if command_capture.complete is defined and not command_capture.complete %}<p class="coverage-note">Command capture is incomplete.{% for limitation in command_capture.limitations or [] %} {{ limitation }}{% endfor %}</p>{% endif %}
{% if command_capture.source == 'engine_instrumentation_and_external_native' %}<div class="coverage-note"><strong>Engine-reported values.</strong> Evaluated PowerShell parameters come from instrumentation inside the guest process. Guest code can forge or bypass these records. Native exec records are observed separately by the external process observer.</div>{% endif %}
{% if run.run_manifest and run.run_manifest.guest_tools_build %}<div class="coverage-note"><strong>Windows utility emulation.</strong> Bundled Windows utilities run through CPU emulation inside the guest using the configured persona. Each invocation starts from a fresh snapshot. Utility result records and persona hash comparisons are guest-reported diagnostics; they are not independent attestation.</div>{% endif %}
{% if command_capture.observer_state == 'interrupted' %}<div class="coverage-note"><strong>Command observer interrupted.</strong> Its breakpoint was disabled, removed, or missing at the end of execution. Subsequent invocations may be absent from this report.</div>{% endif %}
{% if command_capture.observer_state == 'terminated' %}<div class="coverage-note"><strong>Command trace ended early.</strong> The external observer did not finish its lifecycle. The report retains authenticated records received before termination; later invocations may be absent.</div>{% endif %}
{% if script_source is string %}<details class="block"><summary>Submitted PowerShell source</summary><div class="body"><p class="muted">Original script text for reference. Invocation records below show observed runtime calls.</p><pre>{{ script_source }}</pre></div></details>{% endif %}
{% if command_capture.integrity_events %}<details class="block"><summary>Command observer changes <span class="count-tag">({{ command_capture.integrity_events|length }})</span></summary><div class="body"><div class="table-wrap"><table><thead><tr><th>Observed time</th><th>Scope</th><th>Change</th><th>Breakpoint</th></tr></thead><tbody>{% for event in command_capture.integrity_events %}<tr><td>{{ event.timestamp_utc|ui_datetime }}</td><td>{{ event.scope }}</td><td>{{ event.update }}</td><td>{{ event.breakpoint_id }}</td></tr>{% endfor %}</tbody></table></div><details class="raw"><summary>Full observer records</summary><pre>{{ command_capture.integrity_events|ui_json(indent=2) }}</pre></details></div></details>{% endif %}
{% if commands %}<p class="meta-line">Page {{ commands_page }} of {{ command_pages }}.
{% if commands_page > 1 %}<a href="{{ url_for('detail', run_id=run.id, events_page=events_page, broker_page=broker_page, commands_page=commands_page - 1) }}#commands">Previous commands</a>{% endif %}
{% if commands_page < command_pages %}<a href="{{ url_for('detail', run_id=run.id, events_page=events_page, broker_page=broker_page, commands_page=commands_page + 1) }}#commands">Next commands</a>{% endif %}</p>
<div class="evidence-list">{% for command in commands %}<article class="panel"{% if command.sequence %} id="command-{{ command.sequence }}"{% endif %}><h3><code>{{ command.path or command.command }}</code></h3>
<p class="meta-line">{{ command.capture or 'Recorded command' }} · {{ command.phase or 'Invocation' }}{% if command.sequence %} · sequence {{ command.sequence }}{% endif %}</p>
{% if command.capture == 'guest_windows_emulation' %}<p class="meta-line">Reported Windows exit {{ command.reported_guest_exit_code }} · Persona {{ 'matches configured baseline' if command.persona_matches_baseline else 'differs from configured baseline' }}</p>{% endif %}
{% if command.command_line %}<div class="label">Guest command line</div><pre>{{ command.command_line }}</pre>{% endif %}
{% if command.command_type == 'DotNetProperty' %}<div class="label">Resolved .NET property</div><pre>{{ command.declaring_type }}::{{ command.property_name }}</pre>
  <p class="meta-line">{{ 'Read' if command.operation == 'get' else 'Write' }} · {{ command.access_status }} · {{ 'Static' if command.is_static else 'Instance' }} · {{ command.property_type }}{% if command.target_type %} · receiver {{ command.target_type }}{% endif %} · access {{ command.access_id }} · {{ command.dispatch_route }}</p>
  <div class="label">Property accessor</div><pre>{{ command.accessor_signature }}</pre>
  {% if command.value_available %}<div class="label">{{ 'Returned property value' if command.operation == 'get' else 'Passed property value' }}</div><pre>{{ command.property_value|ui_json }}</pre>{% elif command.access_status == 'failed' %}<p class="coverage-note">Property read failed; no returned value was captured.</p>{% else %}<p class="muted">Property read started; no returned value yet.</p>{% endif %}
  {% if command.value_stage == 'supplied_before_clr_conversion' %}<p class="coverage-note">Write value supplied before CLR reflection conversion.</p>{% endif %}
  {% if command.operation == 'set' %}<p class="meta-line">The passed value is the setter input. It does not establish the stored value.</p>{% endif %}
  {% if command.index_arguments %}<div class="label">Property index arguments</div><pre>{{ command.index_arguments|ui_json }}</pre>{% endif %}
  {% if command.error_type %}<div class="label">Property access error</div><pre>{{ command.error_type }}</pre>{% endif %}
  {% endif %}
{% if command.command_type == 'DotNetMethod' %}<div class="label">Resolved .NET method</div><pre>{{ command.method_signature }}</pre>
{% if not command.metadata_captured %}<p class="coverage-note">Method metadata was not captured for this metadata object type.</p>{% endif %}
<p class="meta-line">{{ 'Constructor' if command.is_constructor else 'Static' if command.is_static else 'Instance' }}{% if command.target_type %} · receiver {{ command.target_type }}{% endif %} · {{ command.dispatch_route }}</p>
{% if command.phase == 'reflection_arguments_supplied' %}<p class="coverage-note">Reflection target and supplied values before CLR reflection conversion. This record does not establish successful invocation.</p>{% else %}<p class="meta-line">Arguments captured before invocation; no successful return is implied.</p>{% endif %}
{% if command.generic_arguments %}<div class="label">Generic type arguments</div><pre>{{ command.generic_arguments|ui_json }}</pre>{% endif %}
{% if command.delegate_targets %}<div class="label">Registered delegate targets</div><pre>{{ command.delegate_targets|ui_json }}</pre>{% endif %}
{% if command.arguments_truncated %}<p class="coverage-note">Method arguments truncated after 32 positions.</p>{% endif %}
{% if command.method_arguments %}<div class="label">Passed method arguments</div><div class="table-wrap"><table><thead><tr><th>Position</th><th>Parameter</th><th>Type</th><th>Passed value</th></tr></thead><tbody>{% for argument in command.method_arguments %}<tr><td>{{ argument.position }}</td><td>{{ argument.name }}{% if argument.by_ref %} ({{ 'out' if argument.is_out else 'ref' }}){% endif %}</td><td><code>{{ argument.parameter_type or 'unknown' }}</code></td><td><pre>{{ argument.value|ui_json }}</pre></td></tr>{% endfor %}</tbody></table></div>{% else %}<p class="muted">No method arguments.</p>{% endif %}{% endif %}
{% if command.bound_parameters %}<div class="label">Evaluated parameters</div><pre>{{ command.bound_parameters|ui_json(indent=2) }}</pre>{% endif %}
{% if command.native_arguments is defined and command.native_arguments is not none %}<div class="label">Native argument array</div><pre>{{ command.native_arguments|ui_json(indent=2) }}</pre>{% endif %}
{% if command.unbound_arguments %}<div class="label">Unbound arguments</div><pre>{{ command.unbound_arguments|ui_json(indent=2) }}</pre>{% endif %}
{% if command.reason %}<p>{{ command.reason }}</p>{% endif %}
{% if command.source_line %}<details class="raw"><summary>Source expression{% if command.source_line_truncated %} · preview{% endif %}</summary>{% if command.source_line_truncated %}<p class="muted">Source preview truncated from {{ command.source_line_length|ui_number }} UTF-16 units. Evaluated parameters are recorded separately.</p>{% endif %}<pre>{{ command.source_line }}</pre></details>{% endif %}
<details class="raw"><summary>Full invocation record</summary><pre>{{ command|ui_json(indent=2) }}</pre></details></article>{% endfor %}</div>
{% else %}<div class="empty">No command invocation records in this report.</div>{% endif %}</section>
<section class="section" id="coverage">{% if run.sample and run.sample.kind in ('powershell', 'powershell-probe') %}
<h2>PowerShell capture scope</h2><p class="muted">Command invocation observations are shown above. This report does not establish Windows API compatibility or complete PowerShell coverage.</p>
{% elif run.cil_coverage %}
<h2>Observed CIL opcodes</h2><p class="muted">Counts show interpreter dispatch attempts during this run. They do not prove that .NET behavior is fully modeled. An unsupported operation appears in Coverage limits and errors above.</p>
{% if run.cil_coverage.top_opcodes %}<div class="table-wrap"><table><thead><tr><th>Opcode</th><th>Attempts</th></tr></thead><tbody>
{% for item in run.cil_coverage.top_opcodes %}<tr><td><code>{{ item.opcode }}</code></td><td>{{ item.count }}</td></tr>{% endfor %}
</tbody></table></div>{% else %}<div class="empty">No CIL opcodes were dispatched.</div>{% endif %}
{% if run.cil_coverage.other_opcode_attempts %}<p class="muted">{{ run.cil_coverage.other_opcode_attempts }} attempts are outside the top 100 opcode names.</p>{% endif %}
<h2>Observed framework calls</h2><p class="muted">These method counts include attempted calls that may have failed. Names are limited to 256 characters; at most 1,024 names are tracked.</p>
{% if run.cil_coverage.top_framework_calls %}<div class="table-wrap"><table><thead><tr><th>Method</th><th>Attempts</th></tr></thead><tbody>
{% for item in run.cil_coverage.top_framework_calls %}<tr><td><code>{{ item.method }}</code></td><td>{{ item.count }}</td></tr>{% endfor %}
</tbody></table></div>{% else %}<div class="empty">No external framework calls were reached.</div>{% endif %}
{% if run.cil_coverage.other_framework_calls %}<p class="muted">{{ run.cil_coverage.other_framework_calls }} calls are outside the displayed names{% if run.cil_coverage.untracked_framework_calls %}; {{ run.cil_coverage.untracked_framework_calls }} exceeded the name tracking limit{% endif %}.</p>{% endif %}
{% else %}
<h2>Observed WinAPI calls</h2><p class="muted">This trace shows APIs reached during the run. A traced call does not prove that its modeled side effects match Windows. Signature-only calls have no modeled side effects.</p>
{% if run.api_coverage and run.api_coverage.observed_calls is defined %}
{% if run.api_coverage.observed_calls %}<div class="table-wrap"><table><thead><tr><th>API</th><th>Calls</th><th>Signature-only calls</th></tr></thead><tbody>
{% for item in run.api_coverage.observed_calls %}<tr><td><code>{{ item.api }}</code></td><td>{{ item.count }}</td><td>{{ item.signature_only_count }}</td></tr>{% endfor %}
</tbody></table></div>{% else %}<div class="empty">No native WinAPI calls were traced.</div>{% endif %}
{% if run.api_coverage.other_calls %}<p class="muted">{{ run.api_coverage.other_calls }} additional calls are outside the top 100 API names; see the engine report for the full trace.</p>{% endif %}
{% else %}<div class="empty">Per-API call counts were not recorded for this run.</div>{% endif %}
{% if run.api_coverage and run.api_coverage.signature_only_calls %}<h2>Signature-only API calls</h2><details class="block"><summary>Signature-only API calls <span class="count-tag">({{ run.api_coverage.signature_only_calls|length }})</span></summary><div class="body"><pre>{{ run.api_coverage.signature_only_calls|ui_json(indent=2) }}</pre></div></details>{% endif %}
{% endif %}
</section>
<section class="section" id="network"><h2>Network broker events <span class="count-tag">({{ broker_event_count }})</span></h2>
<p class="meta-line">Showing {{ broker_first }}–{{ broker_last }} of {{ broker_event_count }} · page {{ broker_page }} of {{ broker_pages }}.
{% if broker_page > 1 %}<a href="{{ url_for('detail', run_id=run.id, events_page=events_page, broker_page=broker_page - 1) }}">Previous broker page</a>{% endif %}
{% if broker_page < broker_pages %}<a href="{{ url_for('detail', run_id=run.id, events_page=events_page, broker_page=broker_page + 1) }}">Next broker page</a>{% endif %}</p>
{% if run.network_attempts %}<h2>Network attempts <span class="count-tag">({{ run.network_attempts|length }} shown{% if run.network_attempts_omitted %}; {{ run.network_attempts_omitted }} omitted by the summary cap{% endif %})</span></h2><details class="block"><summary>Network attempts JSON</summary><div class="body"><pre>{{ run.network_attempts|ui_json(indent=2) }}</pre></div></details>{% endif %}
{% if broker_events %}<details class="block"><summary>Broker events on this page <span class="count-tag">({{ broker_events|length }})</span></summary><div class="body">{{ event_rows(broker_events) }}</div></details>{% else %}<div class="empty">No broker events in this report.</div>{% endif %}
{% if fixture_rules is not none %}<h2>Exact HTTP fixtures</h2><p class="muted">Requests match method, URL, chunked flag, every header name and value, and the complete body. Header names ignore case; values and body bytes are exact. <a href="/runs/{{ run.id }}/network-fixtures">Download full request and response definitions</a>.</p>
{% if fixture_rules %}<details class="block"><summary>HTTP fixtures <span class="count-tag">({{ fixture_rules|length }})</span></summary><div class="body"><div class="table-wrap"><table><thead><tr><th>ID</th><th>Request</th><th>Response</th></tr></thead><tbody>{% for rule in fixture_rules %}<tr><td>{{ rule.id }}</td><td><code>{{ rule.request.method }} {{ rule.request.url }}</code><pre>{{ rule.request.headers|ui_json(indent=2) }}</pre>Body: {{ rule.request_body_size }} bytes · <code>{{ rule.request_body_sha256 }}</code></td><td>{{ rule.response.status }} {{ rule.response.reason }}<pre>{{ rule.response.headers|ui_json(indent=2) }}</pre>Body: {{ rule.response_body_size }} bytes · <code>{{ rule.response_body_sha256 }}</code></td></tr>{% endfor %}</tbody></table></div></div></details>{% endif %}{% endif %}
</section>
<section class="section" id="events"><h2>Events <span class="count-tag">({{ event_count }})</span></h2><p class="meta-line">Events with execution ticks are ordered by tick. Virtual event ticks inferred from matching API calls are marked. Events without a tick follow the timed sequence. Showing {{ event_first }}–{{ event_last }} of {{ event_count }} · page {{ events_page }} of {{ event_pages }}.
{% if events_page > 1 %}<a href="{{ url_for('detail', run_id=run.id, events_page=events_page - 1, broker_page=broker_page) }}">Previous event page</a>{% endif %}
{% if events_page < event_pages %}<a href="{{ url_for('detail', run_id=run.id, events_page=events_page + 1, broker_page=broker_page) }}">Next event page</a>{% endif %}</p>
{% if events %}<details class="block"><summary>Events on this page <span class="count-tag">({{ events|length }})</span></summary><div class="body">{{ event_rows(events) }}</div></details>{% else %}<div class="empty">No events in the engine report.</div>{% endif %}
</section>
{{ end() }}
"""

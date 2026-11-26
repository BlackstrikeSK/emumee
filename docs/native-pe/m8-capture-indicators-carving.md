# M8 submitted-sample capture: memory-string indicators and executable-region carving

Started 2026-11-23 from committed M7 (`e5d4508`). M8 closes the capture
obligations the earlier milestones deferred: the N14 memory-string indicator
scan over a submitted sample (including caller-configured custom patterns,
its live private mappings and accepted companion images) and the N15 classification and retention of a payload
a sample stages, activates, releases, drops to disk or injects into another
process. It also closes the N16/N17 report-field audit and the remaining N08
public output-limit equivalence.

Before this milestone the capture model was reachable only from a closed
indicator fixture and the submitted request carried no capture configuration at
all. A submitted sample now carries an explicit, bounded, opt-in capture
configuration end to end — public CLI, contained worker, engine — and the
resulting evidence is bound into the report like every other receipt.

This milestone certifies no API partition row on its own, and the global
qualification gates remain open until M9–M11.

## Obligations this milestone closes

| Feature | Obligation | Status |
| --- | --- | --- |
| N14 | Memory IP/URL/custom-regex capture, scan ordering, limits, regex admission and omissions; submitted request carries capture configuration | closed for the settled image, accepted companions and live private mappings |
| N15 | Payload classification and retention with writer/provenance attribution | closed for the protection transition, the release, the VFS drop and the remote write |
| N16 | Capture reports normalized into the engine report and never silently dropped | closed; the replay enforces an exact report-field set |
| N17 | Report extraction audited independently | closed as a seal-time audit of every serialized report field |
| N08 | Remaining public limit equivalence (the parent output cap was fixed) | closed; the request may tighten the output caps |

## N14 — memory-string indicators

### The bounded matcher

Custom indicator patterns are compiled by `memory_strings::pattern`, a
restricted matcher that is **linear-time by construction**, not by timeout: the
pattern is compiled to a Thompson NFA and run as a set simulation that never
backtracks. A catastrophic-backtracking pattern such as `(a+)+b` over thousands
of `a`s is therefore ordinary work, not a denial of service.

Supported subset: literals, `.` (any scalar except `\n`/`\r`), character classes
`[...]` with ranges, negation and the `\d \w \s` shorthands, the escapes
`\d \D \w \W \s \S \. \\ \[ \] \( \) \{ \} \| \+ \* \? \t \n \r \xHH \uHHHH`,
greedy quantifiers `* + ?` and bounded `{m} {m,} {m,n}`, non-capturing groups
`(...)` and alternation `|`. `\d`, `\w` and `\s` are the ASCII classes, so the
subset is deterministic and host-locale independent.

Everything else is **refused at admission** rather than accepted and run
slowly: `^`/`$` anchors, every `(?...)` extension (lookaround, named groups,
recursion), lazy quantifiers, backreferences, unknown escapes, a repeat upper
bound over `MAX_REPEAT` (1024), and any pattern whose compiled program would
exceed `MAX_STATES` (4096). Matching is leftmost-longest and non-overlapping,
and an empty match can never stall a scan.

### Admission and configuration

Three independent admission points all compile the configured patterns, so an
unsupported pattern cannot reach execution by any route:

- `memory_strings::Options::decode` validates the legacy option shape and
  compiles every pattern.
- `analysis_plan` admits `capture.memory_strings = indicators { patterns }`
  through `MemoryStrings::options()`; an empty, unsupported or over-bounded set
  is rejected as `unsupported_option`. The driver128 capture profile stays
  `disabled`-only — it is outside this milestone's native scope.
- `user_input::Request.capture` carries the submitted-sample configuration
  (`memory_strings { enabled, patterns, scan_bytes }` and
  `carve_executable_regions`). It is opt-in: a request without it behaves
  exactly as before, which is why every earlier milestone's controls and seals
  are unchanged. Schema 1 cannot carry it, and the scan budget is capped at
  128 MiB.

The public CLI reads it from the `--inputs` specification, so a contained
replay drives exactly the configuration the source test drove.

### Execution and the report profile

At the settled boundary the engine's `user_strings` role scans, in order and
under the configured read and scan budgets:

1. the submitted sample's own image; then
2. other accepted real guest images, in address order, each tagged
   `guest_module_at_stop:<name>:<base>`; then
3. every committed private reservation the sample still holds, in address
   order, each tagged `guest_private_at_stop:<base>`.

Synthetic provider images are excluded by catalog provenance. Unloaded images
are absent from the live catalog. Module read/scan budget omissions, unreadable
images and backend read failures are explicit receipt reasons; `module_runs` and
`module_bytes` account for successful additional image scans.

Built-in IPv4, IPv6 and URL indicators run first, in that order, followed by
each custom pattern; a custom match is reported as `custom_<i>` against its
1-based entry in the report's `regex` array, which is the envelope the saved
report validator already required. Only owned, readable guest memory is read;
a run the budget cannot reach records a `private_scan_budget` omission rather
than being silently skipped.

The result is the additive profile `emumee.user-memory-indicators.v1`:
`execution.user_memory_strings` (the capture) and
`execution.user_memory_capture` (its receipt). The receipt binds the capture by
digest and cross-checks the configured patterns, the enablement, the scan and
read budgets, the selected bytes, the private run count and bytes, the image
base and size against the recorded image load, and the boundary instruction
count and program counter. `report_bundle` validates it on every build and
copies both fields into the summary, where they are re-checked — a capture
cannot be dropped, swapped or edited between the execution and the summary.

The closed indicator slice (`memory_strings` / `memory_string_sources`) and its
validator are untouched. A run carries one profile or the other, never both,
which is why this addition cannot alter any earlier receipt.

Image, companion and private reads share one allowance. `read_reserved_bytes` charges every
attempted read before accessing guest memory, including reads that fail;
`read_bytes` totals successful reads before scanner admission. Both include the
root image, accepted companions and private reservations. A private run is read only up to the smaller of
the remaining read and scan allowances, with `private_read_budget` and/or
`private_scan_budget` recording truncation. Receipt validation requires
`selected_bytes <= read_bytes <= read_reserved_bytes <= read_limit`.

## N15 — payload classification and attribution

A payload is retained at each of the four moments it becomes observable, and
every observation carries its writer/provenance attribution in context
(`transition`, `guest_base`, `region_bytes`, and the target process for an
injection):

| Transition | When | Classification |
| --- | --- | --- |
| `virtual_protect_executable` | memory becomes executable — the defining act of activating a staged payload | PE → `CarvedImage`; otherwise `ExecutableRegion` |
| `released_before_free` | an executable reservation is released, the last moment those bytes exist | PE → `CarvedImage`; otherwise `ExecutableRegion` |
| `guest_file_dropped` | a dropped guest file contains a PE, carved at the settled boundary in addition to the retained file | `CarvedImage` with `capture_origin: guest_file` |
| `remote_write` | the sample writes into **another** process's address space | PE → `CarvedImage`; otherwise `MemorySnapshot` |

`ExecutableRegion` is a new artifact kind for a payload that is executable but
is not a structural image — the shellcode-carving target. Such bytes previously
fell into the generic memory bucket with no executable distinction at all. The
artifact schema requires `executable: true` and a non-empty `transition` for
that kind, in both the core validator and the public CLI's kind parser. If a
PE-looking header cannot be carved, the bytes are still retained as an
executable region rather than lost.

A remote write is deliberately **not** classified as an executable region: a
write into another process does not make the bytes executable, and this must not
claim it did, so a non-PE injection is retained as a memory snapshot carrying
the `remote_write` attribution. The target is resolved to a process id, so a
sample writing into its own address space through a real handle is never
reported as an injection.

Every carve is bounded and strictly opt-in: only when the submitted request (or
resolved plan) asked for carving, only for user-mode runs, only up to the
single-artifact cap, and never for an all-zero region.

## N16/N17 — the report audit

`tools/native_pe_m8.py` holds the reviewed set of every serialized execution
report field an M8 control produces, and enforces two properties on each replay:

- no field outside that reviewed set appears, so a newly added observation
  cannot reach a receipt unreviewed; and
- the contained replay reproduces **exactly** the field set of the
  source-tested run, so a report field the packaged worker drops fails the seal.

This is the "never silently drop fields" obligation as an enforced gate rather
than a convention.

## N08 — public output-limit equivalence

The parent output cap was previously a fixed constant in the controller. A
submitted request may now carry `output { max_bytes, max_entries,
max_directories, max_depth }`. Every value is validated against the compiled
ceiling, so a request may **tighten** the parent's output containment but can
never loosen it; absent, the compiled ceilings apply exactly as before. Schema 1
cannot carry it.

## Controls

Thirty-four contained controls: the following seventeen cases, each emitted for x86 and x64:

| Control | What it drives |
| --- | --- |
| `strings-Builtin` | An image carrying an IPv4 and a URL; the built-in scan recovers both with no custom pattern configured, and reports no custom match. |
| `strings-Custom` | The same image plus a lowercase-hex digest; a configured `[a-f0-9]{32}` pattern recovers it as `custom_1`. |
| `strings-Private` | The guest copies an indicator into a committed reservation and leaves it live. The indicator is recovered twice under two sources, and the `guest_private_at_stop:<base>` match is what proves the live private-run scan ran. |
| `strings-PrivatePrefix` | Only eight bytes of the live private reservation fit after the image; the receipt charges exactly those reads and records both exhausted allowances. |
| `strings-PrivateExhausted` | The image consumes the entire read/scan allowance; private memory is omitted with explicit budget reasons and no additional reads. |
| `strings-Module` | A real accepted companion contains the only copy of a URL. Only its module-attributed match can prove companion scanning; synthetic system providers must remain excluded. |
| `strings-ModulePrefix` | Eight companion bytes fit after the root image; both allowances are charged and module truncation is explicit. |
| `strings-ModuleExhausted` | The root image consumes both allowances; no companion read occurs and both module budget omissions are recorded. |
| `carve-Shellcode` | The guest reserves read/write memory, writes a non-PE payload into it, then transitions it to `PAGE_EXECUTE_READ`. The payload is retained as an `ExecutableRegion` with its attribution. |
| `carve-Released` | The reservation is executable from the outset, so no protection transition fires; only the release carve can account for the artifact, which isolates that provenance class. |
| `carve-DroppedPe` | The guest drops a staged PE to a new guest path with `CopyFileA`. The dropped file is retained **and** its structural image evidence is carved, attributed to the dropped path. |
| `carve-RemoteWrite` | A parent writes harmless data into a suspended emulated child's read/write reservation. The child checks the bytes after resuming; capture must retain a `MemorySnapshot` with the child's process ID, address and byte count. |
| `carve-RemotePe` | The same flow writes a synthetic PE as data, without executing it. Capture must retain `CarvedImage` evidence with the remote-write attribution. |
| `carve-RemoteDisabled` | The write and child check succeed with carving disabled; no remote-write artifact is retained. |
| `carve-SelfWrite` | A real handle opened against the current process writes its own reservation; this must not be attributed as a remote write. |
| `carve-RemoteFailed` | A write to an unallocated child address fails with zero bytes transferred; the child's reserved page remains zero and no artifact is retained. |
| `carve-RemoteZero` | A successful all-zero write remains excluded from capture. |

Unlike the API-family controls, an M8 control decides nothing beyond returning
1 from its entry: the capture configuration, not the guest, drives the feature
under test, which is precisely the surface this milestone adds. Every control is
emitted as a contained fixture — image, staged inputs, the capture
configuration, arguments and limits — so the packaged worker replays the same
bytes and the same configuration through the public CLI.

## Qualification

### Companion and semantic continuation (2026-11-24)

The frozen native runner's settled dump scan includes real mapped modules as
well as private allocations. The Rust role now scans accepted companion images
under the same shared budgets, while excluding synthetic providers by explicit
catalog provenance. The module/prefix/exhaustion controls prove this route and
its omissions. The current integrated qualification root is
`output/rust-pe-semantic-closure-20261124/`; this also carries the independent
lstrlen semantic controls and the repaired M11 audit described in
`m11-closure-audit.md`. Earlier roots below remain exact-source historical proof.

### Shared read-budget follow-up (2026-11-24)

Private reads previously consumed the scan allowance but were absent from the
receipt's read counters. With a separately configured smaller read allowance,
they could also exceed that allowance. The image and private scanner now share
the read counters and limit. Engine controls exercise distinct read and scan
limits in both architectures; the public request uses equal limits, exercised
by the prefix and exhausted controls above. A receipt claiming more scanned
bytes than successful reads is rejected independently in the core validator.

The current expanded qualification is rechecked with:

```powershell
C:\Python313\python.exe tools/native_pe_m8.py --root output/rust-pe-m8-read-budget-20261124 --source-index output/rust-pe-m8-read-budget-20261124/source-validation-final/index.json --check
```

Earlier M8 receipts below belong to their exact source revisions. Recheck them
with those revisions' tools; the current replay requires all thirty-four
controls and the corrected shared read accounting. Periodic scanning and API
semantic parity remain open.

### Remote-write follow-up (2026-11-24)

The guest control reproduced a missing integration: `WriteProcessMemory` against
an isolated child succeeded and the resumed child verified its bytes, but no
artifact was retained. The old capture hook was reachable only through the
local fallback; real remote transfers go through `user_processes::remote`.
The remote dispatcher now invokes the bounded capture helper after the write
succeeds and after it restores the caller's address space and capture catalog.
Failed transfers return before capture, and the existing opt-in, size and
all-zero filters still apply. The controls also prove that a real handle naming
the current process does not create remote-write evidence.

The expanded qualification uses a fresh root so the earlier twelve-control
receipt remains historical:

```powershell
C:\Python313\python.exe tools/native_pe_m8.py --root output/rust-pe-m8-remote-20261124 --source-index output/rust-pe-m8-remote-20261124/source-validation-final/index.json --check
```

This follow-up qualifies the M8 capture path only. It does not refresh the
historical M10 release matrix or M11 denominator audit, or close API parity rows.

### Original twelve-control qualification

| Gate | Result |
| --- | --- |
| Full source validation suite | passed; index under this qualification root |
| Strict workspace Clippy, all targets, warnings denied | passes |
| Native-PE accounting suite (`tests/test_native_pe_*.py`) | 182 tests, 0 failed |
| Workspace Rust tests | passes, including 538 `emumee-core` and 636 `emumee-engine` library tests |
| Contained replay | 12 controls, independently checked against the packaged worker |

`tools/native_pe_m8.py` replays every control through the packaged worker and
the public CLI, reuses the M4 verifier for the request, result, input and
cleanup accounting, compares `user_memory_strings`, `user_memory_capture` and
`artifacts` between the source-tested execution and its contained replay, and
applies the N16/N17 report-field audit above. `tests/test_native_pe_m8.py`
guards the control set itself.

To recheck the sealed milestone from the repository root:

```powershell
C:\Python313\python.exe tools/native_pe_m8.py --root output/rust-pe-m8-complete-20261123-02 --source-index output/rust-pe-m8-complete-20261123-02/source-validation-final/index.json --check
```

Only a passing, independently checked current-source index establishes source
validation; missing or failed output is not proof. Existing M3 through M7
bundles and seals remain historical, matching their own source.

## Limits

What this milestone does **not** establish:

1. The scan is a **settled-boundary** scan, matching the observed frozen native
   runner. Periodic checkpoints are an unimplemented enhancement. An indicator
   freed before this boundary is not recovered by this string scan; executable
   bytes may instead survive through release carving.
2. Remote-write controls cover whole successful writes, a refused destination,
   capture disabled, a real self-process handle and all-zero bytes. They do not
   establish partial-transfer behavior, remote thread execution or native Windows
   process injection. All children and writes are confined to emulated state.
3. The private scan covers committed **private reservations**, including guest
   heap blocks backed by those reservations. The image scan covers the primary
   image and accepted companions still loaded in the current process. It does
   not scan synthetic providers or already-unloaded image backing.
4. A custom pattern is an indicator extractor, not a semantic classifier. The
   matcher deliberately implements a subset; a legacy pattern using lookaround,
   backreferences or lazy quantifiers is refused, not approximated, and the
   frozen Python model's exact `re` semantics are not claimed.
5. `\d`, `\w` and `\s` are ASCII. A pattern that relies on Unicode class
   membership will not match the same text the frozen model would.
6. The capture is opt-in and carries no default. Nothing in this milestone makes
   an ordinary submitted run scan memory or carve payloads, so none of this
   evidence is produced unless a request asks for it.
7. The N08 closure is the **output** cap. It lets a request tighten what the
   parent will accept; it does not re-derive the legacy reporting shape, and the
   other public limits keep their M4 qualification.
8. The N17 audit proves the report field **set** is reviewed and preserved. It
   does not prove any individual family's field contents are semantically
   correct — that is per-row parity, which stays open.
9. Per-row semantic API parity, the package/release matrix and the global M10
   gates remain open.

# M8 submitted-sample capture: memory-string indicators and executable-region carving

Started 2026-11-23 from committed M7 (`e5d4508`). M8 closes the capture
obligations the earlier milestones deferred: the N14 memory-string indicator
scan over a submitted sample (including caller-configured custom patterns) and
the N15 classification and retention of an executable payload a sample stages
and activates in its own address space.

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
| N14 | Memory IP/URL/custom-regex capture, scan ordering, limits, regex admission and omissions; submitted request carries capture configuration | closed for the submitted-sample image |
| N15 | Executable payload classification and retention with writer/provenance attribution | closed for the executable-protection transition |
| N16 | Capture reports normalized into the engine report and never silently dropped | closed for the capture fields |

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

At the settled boundary the engine's `user_strings` role reads the submitted
sample's own image — bounded by the configured read and scan budgets — and
scans it with the configured matcher. Built-in IPv4, IPv6 and URL indicators
run first, in that order, followed by each custom pattern; a custom match is
reported as `custom_<i>` against its 1-based entry in the report's `regex`
array, which is the envelope the saved-report validator already required.

The result is the additive profile `emumee.user-memory-indicators.v1`:
`execution.user_memory_strings` (the capture) and
`execution.user_memory_capture` (its receipt). The receipt binds the capture by
digest and cross-checks the configured patterns, the enablement, the scan and
read budgets, the selected bytes, the image base and size against the recorded
image load, and the boundary instruction count and program counter.
`report_bundle` validates it on every build and copies both fields into the
summary, where they are re-checked — a capture cannot be dropped, swapped or
edited between the execution and the summary.

The closed indicator slice (`memory_strings` / `memory_string_sources`) and its
validator are untouched. A run carries one profile or the other, never both,
which is why this addition cannot alter any earlier receipt.

## N15 — executable-region and dropped-PE carving

A sample that stages a payload into its own memory and then makes it executable
is doing the defining act of shellcode activation, and that transition is the
last moment the bytes are guaranteed to be present. `allocation::protect` now
carves at exactly that point:

- A structurally parseable PE at offset 0 is retained as a `CarvedImage`
  through the ordinary structural carve — a dropped image being activated.
- Any other executable payload is retained as a new, distinct artifact kind,
  `ExecutableRegion` — the shellcode-carving target. These bytes previously
  fell into the generic memory bucket with no executable distinction at all.
- If a PE-looking header cannot be carved, the bytes are still retained as an
  executable region rather than lost.

Every such observation carries its writer/provenance attribution in context:
`executable`, the `transition` that produced it, `guest_base`, `region_bytes`
and `new_protection`. The artifact schema requires `executable: true` and a
non-empty `transition` for this kind, in both the core validator and the
public CLI's kind parser.

The carve is bounded and strictly opt-in. It runs only when the submitted
request (or resolved plan) asked for carving, only for user-mode runs, only up
to the single-artifact cap, and never for an all-zero region. A request that
does not ask for it is byte-for-byte unaffected.

## Controls

Six contained controls, each emitted for x86 and x64:

| Control | What it drives |
| --- | --- |
| `strings-Builtin` | An image carrying an IPv4 and a URL; the built-in scan recovers both with no custom pattern configured, and reports no custom match. |
| `strings-Custom` | The same image plus a lowercase-hex digest; a configured `[a-f0-9]{32}` pattern recovers it as `custom_1`. |
| `carve-Shellcode` | The guest reserves read/write memory, writes a non-PE payload into it through `WriteProcessMemory`, then transitions it to `PAGE_EXECUTE_READ`. The carve retains the payload as an `ExecutableRegion` with its attribution, and the staged bytes are present in the retained region. |

Unlike the API-family controls, an M8 control decides nothing beyond returning
1 from its entry: the capture configuration, not the guest, drives the feature
under test, which is precisely the surface this milestone adds. Every control is
emitted as a contained fixture — image, inputs (including the capture
configuration), arguments and limits — so the packaged worker replays the same
bytes and the same configuration through the public CLI.

## Qualification

| Gate | Result |
| --- | --- |
| Full source validation suite | passed; index under this qualification root |
| Strict workspace Clippy, all targets, warnings denied | passes |
| Native-PE accounting suite (`tests/test_native_pe_*.py`) | 182 tests, 0 failed |
| Workspace Rust tests | passes, including 535 `emumee-core` and 632 `emumee-engine` library tests |
| Contained replay | 6 controls, independently checked against the packaged worker |

`tools/native_pe_m8.py` replays every control through the packaged worker and
the public CLI, reuses the M4 verifier for the request, result, input and
cleanup accounting, and additionally compares `user_memory_strings`,
`user_memory_capture` and `artifacts` between the source-tested execution and
its contained replay, so a capture that differs under the packaged worker fails
the seal. `tests/test_native_pe_m8.py` guards the control set itself.

To recheck the sealed milestone from the repository root:

```powershell
C:\Python313\python.exe tools/native_pe_m8.py --root output/rust-pe-m8-complete-20261123 --source-index output/rust-pe-m8-complete-20261123/source-validation-final/index.json --check
```

Only a passing, independently checked current-source index establishes source
validation; missing or failed output is not proof. Existing M3 through M7
bundles and seals remain historical, matching their own source.

## Limits

What this milestone does **not** establish:

1. The memory-string scan covers the submitted sample's **image** at the
   settled boundary. It does not yet enumerate every live private mapping, so
   an indicator that exists only in a heap or a transient allocation at stop is
   not claimed. Periodic checkpoints remain unported.
2. N15 carving is closed for the **executable-protection transition** only.
   Capturing a payload released through `VirtualFree` before it is lost, the
   overwrite/delete/exit-byte provenance classes, and remote-write attribution
   across a child's address space all remain open.
3. The dropped-PE route is covered by source tests, not by a guest control: the
   control harness's string slots cannot hold a whole PE, so a guest that drops
   and activates a full image needs a staged-input control that does not exist
   yet.
4. A custom pattern is an indicator extractor, not a semantic classifier. The
   matcher deliberately implements a subset; a legacy pattern using lookaround,
   backreferences or lazy quantifiers is refused, not approximated, and the
   frozen Python model's exact `re` semantics are not claimed.
5. `\d`, `\w` and `\s` are ASCII. A pattern that relies on Unicode class
   membership will not match the same text the frozen model would.
6. The capture is opt-in and carries no default. Nothing in this milestone makes
   an ordinary submitted run scan memory or carve payloads, so none of this
   evidence is produced unless a request asks for it.
7. Per-row semantic API parity, the package/release matrix and the global M10
   gates remain open, as do the N17 shared-state report audit and the remaining
   N08 public output-limit equivalence.

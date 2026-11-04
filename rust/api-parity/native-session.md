# Native PE session checkpoint

## Current continuation checkpoint

2026-11-04 M2 PE layout batch: the parser/mapping implementation and six core/
four engine controls are complete. The first full run caught an exact raw-length
managed-EH compatibility contract; that behavior was preserved, its existing test
was not changed, and the next full workspace run passed 1,034 Rust tests.
New source-generated x86/x64 submitted guests exercise tails, independent raw
aliases, RW writes and RX/header/NX/gap faults; malformed layout admission and
runtime-address collisions refuse. `docs/native-pe/m2-pe-layout.md` records the
invariants, regression diagnosis and clone-safe reproduction.

Current release/qualification root: `output/rust-pe-m2-layout/`. Fresh offline
release (227.077s), freeze (1.072s), 32-guest/10-refusal `-Layout` smoke (5.708s)
and independent 344-file seal pass. Build-source hash is
`706327dc0e92a6be0d86c3c35a0eb0f4ff85cf7f5280b9eef99b5b79eb76e405`.
The exact binary hashes are in the audit document. Final current-source receipt:
`final-validation/index.json`; dependency report `dependencies/report.json`;
registration `registration-final/review.json`; ledger/status `final-ledger.json`
and `final-status.json`. Missing ignored output after a clone requires recapture.
M0's old bundle remains historical. Preserve all old outputs and match the
recorded environment when checking receipts: dependency audit with
`CARGO_NET_OFFLINE` unset, source validation with it set to `true`.

Only the first M2 checkbox is being completed; all staging/import/ABI obligations
and M2's overall exit remain open, with zero API semantic closures. Next action:
admission-negative controls and submitted companion/env reproducer, then bounded
versioned staging and parent/worker binding. M3 bootstrap and M4 scheduling
remain dependent, not parallel work. Preserve historical security boundaries.

The operator requested source-only commit/push to the existing main branch.
Check Git history/remote for the resulting integration; do not add local plans,
generated evidence, binaries, samples, captures or build trees. Global API
accounting remains 2,590 open contracts and 151 batches; only the refreshed source
registration gate is verified. The bounded M2 smoke does not promote M10.

### Historical M0 completion checkpoint

2026-11-04 fresh trusted-source M0 package continuation: M0 and M1 are complete;
M2 request/staging is next. Six package fingerprint/refusal controls and all
42 dependency controls pass. Packaging uses PowerShell 5-compatible primitives,
retains the independent canonical Rust/Python digest and existing no-overwrite/
stale-build guards, and exposes source-only fingerprint mode. The capability probe
now exercises the actual portable primitives. No tool installation was needed.

Fresh offline release build (207.048s), frozen bundle (1.046s), generated harmless
fixtures/two engine controls (2.766s) and 16 guest/four refusal smoke controls
(3.379s) pass. Exact scope, package hashes, failed-attempt diagnosis and reproduction
are maintained in `docs/native-pe/m0-package-smoke.md`. First smoke was not a pass:
PowerShell 5 threw on expected negative stderr; corrected narrow handling now
requires status 2 and exact reasons, with no invalid CLI publication. Existing
failure classification is updated, not erased. No Rust model or API semantics
changed. All 2,590 semantic contracts and seven global qualification gates remain
open; only source registration review is verified. M0 smoke does not close M10.

The operator requested continuation after reporting a D:\Projects exclusion.
Only new trusted repository builds and harmless contained fixtures were used;
no exclusion/protection setting was changed or independently verified, no old
quarantined artifact was restored, and no supplied sample ran on the host.
That authorization is not retroactive clearance of the historical incident.

Current root: `output/rust-pe-m0-smoke/`. Bundle `bundle/`; current guest/refusal
records in `qualification-verified/`; 172-file seal `qualified-smoke.json`;
fresh dispatcher `dispatch-verified.log`; dependency and registration reports in
`dependencies/report.json` and `registration/review.json`; preserved-history ledger/
status `final-ledger.json` and `final-status.json`; full serial safe-source index
`final-validation/index.json`. Check each report/index before relying on local
captures. Missing raw output after a clone is missing proof. Prior roots below
are historical and no longer the current-source baseline.

Next executable action: M2 admission negative controls plus a harmless submitted
companion/env reproducer. Inspect `rust/emumee-core/src/user_input.rs`,
`rust/emumee-cli/src/user_controller.rs`, `rust/emumee-worker/src/user_worker.rs`
and `rust/emumee-engine/src/user.rs` against N01/N02/N03/N04/N05/N07/N09 before
extending the versioned request. Preserve parent/worker binding and containment;
finish a coherent end-to-end checkbox, not bulk API name bindings. M3 bootstrap
follows M2. Preserve inherited dirty files; no commits or branches were created.

### Historical packaging-blocker checkpoint

2026-11-04 M0 packaging-prerequisite/failure-classification continuation:
`tools/native_pe_baseline.py` now probes actual PowerShell/.NET capabilities,
not executable presence. Six new controls cover positive, missing-capability,
missing/failed/timed-out process and malformed-result cases. Available Windows
PowerShell 5 lacks every required packaging capability; `pwsh` is absent.
Source dependency integrity passes. Read `docs/native-pe/baseline-failures.md`
for the complete owner/action classification rather than reopening old logs.

M0 is explicitly **blocked** on P01 (approved compatible packaging runtime) and
P02 (operator/security review of the recorded quarantine incident). Existing
release controller/worker/DLL paths are present but were not executed, packaged
or authenticated. No release build, guest smoke, legacy pipeline, download,
installation, quarantine restoration or protection change occurred. Do not
rebuild or run existing artifacts as a workaround. M2 is not dependency-ready.

Current evidence root: `output/rust-pe-m0-packaging/`. Dependency report:
`dependencies/report.json`; refreshed registration review: `registration/review.json`;
preserved-history ledger/status: `final-ledger.json` and `final-status.json`;
full serial safe-source receipt: `final-validation/index.json`. Repeat each
tool's check subcommand before relying on local artifacts. Missing output is
missing proof. Detailed counts/fingerprints/timings are in the index/local plan.

Rust runtime and registration authorities are unchanged. The refreshed registration
review retains all 2,590 contract dispositions and 514 hooks per architecture;
only that narrow source-review gate is verified. All semantic contracts and seven
other gates remain open; the package gate now explicitly records its blocker.

Next executable action requires the operator/security decision for P02 and
approved provision of P01. After both, re-audit dependencies, build/package once
from final reviewed source into fresh paths, then execute existing harmless
contained x86/x64 controls. Close M0 only after its mandatory smoke exit test.
M2 request/staging follows; M3 bootstrap follows M2. Preserve inherited dirty
inventory/accounting files. No commits or branches are created.

### Historical dependency audit checkpoint

2026-11-04 continuation: the selected M0 toolchain/legacy-hash/dependency audit is
implemented in `tools/native_pe_baseline.py`, with 36 new corruption, missing-input,
marker/extras, path-escape, archive, report and toolchain controls. All 89 accounting
controls pass. The initial local audit verified 82 frozen source hashes, 35 Python
distributions and 83 Cargo registry archives/unpacked source trees. It found no
integrity issues; modern PowerShell is missing for packaging. RECORD self-consistency
does not establish independent authenticity or restore security clearance. No legacy
imports, package installs, downloads or submitted/native sample execution occurred.
The first test run exposed unavailable Windows file-symlink privileges; portable
synthetic file-resolution guards and a real unprivileged directory junction now
cover escaping paths without changing host privileges. The later CLI negative
test needed to inspect argparse's captured message, not an empty mock exception.
Neither failure was a runtime model regression; both are resolved.

Current dependency report: `output/rust-pe-m0-dependencies/final/report.json`.
Run `python tools/native_pe_baseline.py check --report` with that path to repeat
the static audit. Current full-source receipt:
`output/rust-pe-m0-dependencies/final-validation/index.json`; run
`python tools/native_pe_validation.py check --index` with that path. Missing or
stale local proof requires recapture, not inferred success. Ledger/status inputs
are in `output/rust-pe-m0-dependencies/current-ledger.json` and `current-status.json`.
Exact fingerprints, measured times and command logs live in the report/index;
do not duplicate self-referential hashes in maintained source files.

Next executable action: finish M0 effective registration review for N18/N20:
trace `src/emumee/native.py` constructor guards, original-handler delegation and
last-registration overrides by architecture into a deterministic source-bound
review artifact with synthetic positive/negative controls. Do not import the
legacy pipeline. Following M0 work is same-build harmless package qualification
and explicit failure ownership; modern PowerShell and the recorded security
boundary must be resolved safely before any package claim. M2 request/staging
remains dependent on M0. All M1 source tooling is complete; all 2,590 behavioral
contracts and eight qualification gates remain open. Preserve inherited dirty
files, including inventory and accounting edits. No runtime model changed.

### Historical M1 index checkpoint

Continuation: all M1 source-tooling deliverables are implemented, including
artifact/source indexing in
`tools/native_pe_validation.py` with maintained `docs/native-pe/validation-policy.json`.
The 53 accounting/index/partition controls and four inventory controls pass,
including real harmless subprocess timeout/reaping and synthetic tree-cleanup,
tamper, deletion/addition, environment/reference drift and interruption negatives.
The initial real indexed full run passed all 1,024 Rust tests, 50 then-current
accounting controls, four inventory controls, syntax, strict lint and whitespace.
It is retained under `output/rust-pe-m1-index-initial/`; subsequent hardening and
handoff changes supersede its source fingerprint. Initial measured wall times:
Rust tests 57.170228s, strict lint 0.742245s, accounting 6.752263s. No performance
threshold is inferred. No runtime source changed or API semantics were closed.

Final-source baseline: `output/rust-pe-m1-index/final/index.json`. The tool's `check`
command verifies current source/environment and all hashed logs; `plan` uses a
verified full baseline to select affected suites. Detailed timestamps, argv,
source hashes, toolchain/build environment and measured timings live in the
index, not duplicated into this document's own source fingerprint. A missing
index after a clone requires a new full run. Existing output is never overwritten.
Use `check` to establish the actual final-source result; missing/failed/stale
receipts are never proof of success. Only a complete successful receipt is a
full baseline. Incremental receipts do not claim unchanged suites were rerun.
Reference-only ledger/status inputs are in `output/rust-pe-m1-index-inputs/`.
An intervening indexed run at `output/rust-pe-m1-index/index.json` correctly
failed on a partition test that hardcoded M1 as unfinished. Its failed receipt
and logs are retained, not overwritten or treated as baseline proof. The test
now builds an explicit pending graph fixture and verifies closing M1 leaves M0
as the only ready foundation; no runtime regression was suppressed.
Current status command:
`python tools/native_pe_status.py --ledger output/rust-pe-m1-index-inputs/current-ledger.json`.

M1 worklist state is closed as a source-tooling milestone, not a qualification
gate. M0 is the next ready batch: effective conditional/override registration
review, dependency configuration and safely available same-build package smoke.
All 2,590 behavioral contracts and eight completion gates remain open. Preserve
package/security blockers; do not jump to broad API bindings or run legacy samples.
Keep all inherited dirty files; no commits, branches or unrelated changes made.

The earlier partition-only session below is historical; its accounting hash is
superseded by the new tools/tests. Runtime source and debug binary are unchanged.

### Previous partition checkpoint

2026-11-03: exact partition implemented and production CLI checks passed. All
2,590 contracts occur exactly once in 151 canonical, dependency-ordered batches.
The 33 accounting/partition tests and four inventory tests pass. Full serial
Rust validation-profile regression passes all 1,024 tests (58.128s helper wall
time); strict workspace/all-target Clippy passes (0.829s). Python syntax and
diff whitespace checks pass. Commands, exit codes and timings are recorded in
`output/rust-pe-m1-partition/validation-commands.json`; individual command logs
are in the same directory. Accounting controls took 2.717s; inventory 0.172s.
Current accounting scope fingerprint:
`9df6fe4e753c005257dbaf8cffa8a1d474c2a3e2cb04fcabe686fc16b21a2a10`.
Status uses `output/rust-pe-m1-partition/current-ledger.json`; old M0 ledgers
predate partition fingerprints and must be regenerated with preserved history.
No runtime code changed, no semantic API closure, no release qualification.
The selected M1 accounting-regression and exact-partition checkboxes are fully
complete. The separate artifact/test-impact indexing item was not started.
Preserve the inherited dirty checkout. Detailed M0 history follows.

Partition inventory fingerprint:
`0fd485da3a4bfca7693647f582105a5973c7b708f81a19156bda282d079fb9bf`.
`partition-check.log` proves canonical coverage/graph; `ledger.log` and
`current-ledger.json` preserve the M0 history with zero added/removed contracts;
`status.log` reports zero source/evidence/partition drift and 151 API batches.
All 2,590 semantics and eight required gates remain open (1,829 missing bindings,
761 unverified bindings). Only M0/M1 foundations are dependency-ready.
The manifest records planned oracles and guest/negative controls, not completed
API observations. CLI regressions include corrupted-partition refusal before
ledger overwrite and actionable refusal of old partition-less ledgers.

Next M1 action: implement the artifact/source index and affected-test selection
with timing baselines as one complete checkbox; no partial selector is present.
Next M0 action: effective conditional/override registration review, preserving
package/security blockers. M2 follows those foundations, not bulk API bindings.
Use the generator/status summaries instead of reading the entire large manifest.

## Historical M0 baseline (superseded accounting fingerprint)

Date: 2026-11-03, Europe/Bratislava. Start/end Git HEAD:
`92f258d48d8222b0e88c8bcb5bbd4198cc4095ba`. Initial worktree clean; preserve
all current edits. No runtime, admission schema or guest-model implementation
changed in this batch. Full port completion is **not** claimed.

Final debug build source fingerprint (467 files):
`fd293e30d57f291e41071cead742431b7f93050f530bf8bfef3c94bba11bc6ce`.
Final accounting scope fingerprint:
`7c4a22fc2fd137721938997281ab38f5508b18cf844fe96a5f333551e61414be`.
These are different domains, not interchangeable build/package receipts.

## Implemented

- M0: traced 20 feature groups in `native-feature-matrix.md`; static audit
  captures 15 inputs, 24 install sites, 27 hook sites and 18 summary fields.
  Effective conditional/override activation remains unreviewed.
- M1: source-bound ledger schema 2; preserved closures/history, conservative
  shared-source invalidation, explicit inventory-drift review, archived retired
  contracts, separate semantics/routes, required computed gates, maintained
  sparse evidence import, atomic publication and cheap source-aware status.
- Added maintained routing worklist and empty evidence store in `docs/native-pe/`.
  No semantic row was closed. Exact per-family partition remains unfinished.
- Inventory now refuses absent/empty installed baseline handlers instead of
  silently shrinking the denominator.

## Verified evidence

Raw local index: `output/rust-pe-m0/final-validation-commands.json`,
`final-source-tests.log`, `final-lint.log`, `final-debug-build.log`,
`final-rust-dispatch.json`, `current-ledger.json`, `current-status.json`,
`dependency-integrity.json`, `accounting-tests.log` and `inventory-tests.log`
in that directory. Missing local files do not become proof. The earlier
`output/rust-pe-m0-source-tests.log` is superseded by final-source validation.

- Frozen inventory matches all 82 source hashes: 806 baseline declarations,
  514 extension declarations, zero unresolved static sites.
- Fresh debug dispatcher: 2,590 architecture contracts, 1,829 missing bindings,
  761 unverified bindings. All behavioral contracts remain open.
- Serial validation-profile workspace source baseline: 1,024 passing tests;
  core library 483, engine 465, CLI 43, platform 13, worker 4, integration 16.
  Final helper wall time 66.012s; engine execution 58.51s. No release
  qualification follows from source tests.
- Final strict workspace/all-target Clippy passed (0.742s helper wall time).
- Fresh debug CLI build passed (initial 48.495s; final cached rebuild 4.317s).
- Static installed RECORD check: 35 distributions, 3,788 hashed files, no missing
  or mismatched records. This is self-reported installed-integrity evidence,
  not independent package authenticity or authorization to run legacy probes.
- Accounting/source-audit controls: 20 tests; inventory controls: 4 tests.
  Controls cover regeneration, stale gates, clone-restored sparse evidence,
  architecture/data separation, orphan/duplicate/cycle rejection, source drift,
  false completion and interrupted atomic publication.
- Python syntax compilation and `git diff --check` passed. Final status found
  no changed source/evidence fingerprints; all 2,590 contracts remain unreviewed,
  and all eight required completion gates remain open. No closed contract ID.

## Failures and limitations

- PowerShell 5 native stderr redirection raised NativeCommandError on ordinary
  Cargo progress. Reproducer: redirect the build helper with `*>` in this shell.
  Run the helper in a Python subprocess and let subprocess capture both streams.
- Python CreateProcess rejected the relative forward-slash executable path;
  the resolved absolute path worked. Fresh dispatcher collection then passed.
- No unsafe full Python regression/reference pipeline was imported or run.
  Do not restore quarantined artifacts or weaken protection. Earlier security
  incidents in `docs/release-readiness.md` are not cleared by RECORD matching.
- Fresh release/package smoke was not run. Current package helper uses modern
  PowerShell/.NET features; this session discovered only Windows PowerShell 5
  on PATH. Find an existing approved modern shell before attempting packaging.
- M0 effective registration/dependency configuration and package qualification
  remain open. M1 artifact/source indexing, affected-test selection and timing
  baselines remain open. No M2 behavioral scope reduction is authorized.

## Next executable action

Run `python tools/native_pe_status.py --ledger output/rust-pe-m1-index-inputs/current-ledger.json`.
If local evidence is absent, regenerate from the frozen inventory using a fresh
build's `inspect-api-surface` output and the maintained evidence store.

1. M0-effective-baseline: statically trace bridge constructor guards, conditional
   installs, original-handler delegation and final overrides by architecture;
   record exact activation disposition for N18/N20. Exit: no unreviewed effective
   registration path; preserve explicit package/security blockers separately.
2. M1 source accounting is implemented. Verify retained receipts using
   `python tools/native_pe_validation.py check --index output/rust-pe-m1-index/final/index.json`;
   missing artifacts require a new full run. Use `plan --baseline` to avoid
   repeating unaffected tests; invalid receipts are refused, not trusted.
3. M2-request-staging follows those prerequisites: start with a harmless
   companion/environment submitted-route reproducer and negative admission
   tests, not another bulk API binding expansion.

# M2 versioned submitted-input staging

Current completion: `docs/native-pe/m2-binding-exit.md` records the subsequently
qualified fifth checkbox and overall M2 exit. This document preserves the earlier
fourth-checkbox evidence and its historical boundaries.

## Scope and authority

2026-11-05 continuation: fourth M2 checkbox. Implements explicit bounded,
hashed companion/VFS staging and environment/quoting/export options through the
public `run --inputs` route. This is not closure of the fifth M2 rollback and
runtime-bound audit, M3 lifecycle, later API semantics or M10 qualification.
The full input format and limits are in `rust/USER_PE.md`.

Confirmed frozen reference: `src/emumee/native.py:655` admits companion DLLs,
bundle files, guest environment, zero-based forced quote indices and the optional
first-ten export schedule. `src/emumee/persona.py` uses subprocess.list2cmdline
and wraps requested otherwise-unquoted arguments. The installed frozen
Speakeasy `windows/win32.py` schedules four writable argument buffers, skips
DllMain and supplies IPRIP argc/argv to ServiceMain. These are local static
reference observations, not newly executed legacy pipeline or Windows probes.
Frozen `windows/common.py::_get_pe_exports` and pefile's name-table/ordinal loops
establish entry ordering: aliases are separate named entries, followed by unnamed
nonzero EAT slots. Selection is before skipping the exact name DllMain. Forwarded
entries preserve their original RVA rather than silently resolving a target.

## Implementation

- `user_input.rs`: backward-compatible schema 1, strict extended schema 2,
  catalog and invocation validation, deterministic slots, actual hash/PE kind/
  architecture checks, staged-byte and summed mapped-image quotas.
- `user_controller/staging.rs`: strict bounded JSON, explicit source capture
  using locked identity-pinned regular handles; relative sources resolve beside
  the specification. No directory enumeration or host DLL search.
- `user.rs` and `configured.rs`: side-effect-free parent preflight; worker
  verification again precedes publication. The existing process invocation and
  sole VFS authorities receive exact environment, quoting and file bytes.
- `filesystem_seed.rs`: unpublished candidate preserves original state on
  admission failure, creates guest parents, retains empty files, overrides
  persona seed bytes, and enforces combined persona/submitted VFS capacity.
- Native engine: explicit same-architecture companions retain their real guest
  paths and submitted provenance. Existing import/TLS/DllMain mechanisms run.
- `native_loader/export_calls.rs`: bounded opt-in export entries share the
  original instruction/time horizon, record observations and retain primary
  return identity. Guest allocator addresses are deliberately not hardcoded
  legacy addresses; buffer contents/argument structure are the contract.

The source snapshot closes after each handle capture. No promise is made that a
producer cannot replace its original source later; no later reopen authorizes
different bytes. Active writers and read-time identity changes are refused.
Duplicate destination/module names are refused rather than selecting the last
JSON entry. Separate explicit file/companion entries cannot alias one guest path.

## Verification

Current working captures: `output/rust-pe-m2-staging/`. Development failures are
preserved, not counted as passes. Initial compilation identified Request
constructors requiring explicit empty extensions and a seed-receipt field owner
mismatch. Initial positive probes found a zero-based guest-argument index being
validated as an argv index; validation now checks the same index translation as
the existing process model. No production persona quoting behavior was changed.
The next probe distinguished VFS directory creation from current-directory
selection: the candidate now uses the actual create_directory authority, not
directory_plan/commit_directory (which only select an existing cwd).
The full suite then identified a basename/path authority mixup in companion
loading. Companion identity remains a module basename; a separate submitted-only
path vector supplies the guest catalog path. Generic loader validation is not
weakened. A final frozen-reference audit corrected grouped-EAT selection to named
entry order with distinct aliases and unnamed ordinals, and retained forwarder
RVA execution. Both have direct guest/package controls rather than a parity waiver.
The first public staging qualification stopped on a harness diagnostic mismatch:
opening a host directory with the locked regular-file capture is rejected by
Windows with access denied before the file-type check. The control still requires
status 2, that exact OS error and no output publication; the failed capture is
preserved under staging-failed-01 rather than counted as a pass.

All 1,053 Rust tests pass (497 core, 480 engine, 76 other), including core
admission/VFS regressions, locked-source controls and actual x86/x64 staged-file,
environment, command-line, companion/import-forwarder and opt-in export probes.
Strict all-target Clippy passes. Six independent static pefile vectors qualify
first-ten selection, alias/name/ordinal ordering and export forwarder RVAs.
All 152 Python accounting controls, four inventory controls and exact partition
validation pass. Serial compile/test: 274.261s; strict lint: 59.843s.

Fresh release: 425.435s; freeze: 1.655s. The same bundle passes all 120 maintained
layout/import/ABI contained runs and 28 parent/direct-worker refusals (28.538s),
plus 52 new contained staging runs and 30 strict parent refusals (11.015s).
Those 52 runs include required instruction-budget and exported-NX/forwarder
failure outcomes, not 52 successful entry returns. All required outcomes pass.
The public refusal controls cover path types, case/file-directory/module/env
collisions, quoting, schema/unknown/duplicate fields, actual DLL architecture/
kind, size/count/aggregate quotas, missing/directory/hardlink/junction sources,
an active writer and oversized specification. Invalid admission publishes no run.

The independent maintained sealer verifies exact canonical build sources, both
build-info identities, release/bundle binary equality, every request/result/input/
staged-byte/spec binding, artifacts, AppContainer/job/child/network restrictions,
cleanup and all required control outcomes. It seals 2,019 files and supports a
repeat independent rehash. Its three integrity regressions reject substitution,
containment and cleanup forgery; they are included in the 152 accounting tests.

| Item | SHA-256 |
| --- | --- |
| Build sources | `a73d281bf249e307dc5c262e0b0c2439025408b934f3f244f9bdc45e8bb9d08f` |
| Controller | `de849541511bde0b28dc3295324a1c996d29d07889a8a96be003d89f24328769` |
| Worker | `e55f9d68d346794ce4a5fbb37cda70e06b4bb144e865e1fbecd2718c8cbe55b6` |
| Unicorn | `f19546ed0d1b7ea0761768e9937334d4f6ba3a20eaed7c411655000b9154386e` |
| Independent seal | `047e126c67557160be2179024abd022965a513b584dcf0ffcbdb80ef961fcf76` |

Current receipt anchors under output/rust-pe-m2-staging/: bundle/,
fixtures-final/, qualification/, staging/, qualified-smoke.json,
export-reference.json, dependencies-closed/report.json,
registration-qualified/review.json, dispatch.log, final-ledger.json,
final-status.json and final-validation/index.json. The full safe-source index is
captured after maintained evidence/docs stabilize and must pass the independent
validation check before relying on it. Missing ignored captures require fresh
capture; maintained controls are reproducible, not a substitute for raw proof.

## Outcome and next boundary

The fourth M2 checkbox has no deferred implementation, regression or package
item. No API semantic row is closed: all 2,590 contracts and 151 batches retain
their existing denominator, with 1,819 missing and 771 unverified bindings. Only
the source-registration global gate is verified; bounded package controls do
not close M10. Next is the separate fifth M2 exact-binding, total runtime bounds
and rollback audit, then M2's overall exit. M3 lifecycle/Windows compatibility
is not inferred from this batch. No commits, pushes, branches, host DLL search,
supplied-sample execution, quarantine restoration or security changes occurred.

### Reproduction

```powershell
$env:CARGO_NET_OFFLINE='true'
$env:RUST_TEST_THREADS='1'
$env:EMUMEE_USER_TEST_FIXTURES="$PWD\output\native-staging-next\fixtures-final"
.\tools\build_rust.ps1 -Validation -Test -Jobs 1
$env:EMUMEE_USER_TEST_FIXTURES=$null
.\tools\build_rust.ps1 -Lint -Jobs 1
.\tools\build_rust.ps1 -Release -Jobs 1
.\tools\package_rust.ps1 -Destination output/native-staging-next/bundle
.\tools\verify_rust_user_pe.ps1 -Bundle output/native-staging-next/bundle -Fixtures output/native-staging-next/fixtures-final -OutputRoot output/native-staging-next/qualification -Layout -Imports -Abi
python tools/native_pe_staging.py --bundle output/native-staging-next/bundle --fixtures output/native-staging-next/fixtures-final --output output/native-staging-next/staging
python tools/native_pe_staging_seal.py --root output/native-staging-next
python tools/native_pe_staging_seal.py --root output/native-staging-next --check
python tools/native_pe_validation.py run --full --output output/native-staging-next/validation --timeout 1800
python tools/native_pe_validation.py check --index output/native-staging-next/validation/index.json
```

Full validation now compiles serially (`Jobs 1`) to avoid repeating the recorded
LLVM parallel-build OOM from the preceding batch. No assertion or suite is removed.
Both recorded test environment and explicit Cargo command use one build job;
a regression prevents the metadata drifting back to two. Dependency audit/check
unsets CARGO_NET_OFFLINE and RUST_TEST_THREADS; source validation uses
offline=true/threads=1. Final source fingerprint and suite timings live in the
checked index, avoiding a self-referential fingerprint in maintained source text.

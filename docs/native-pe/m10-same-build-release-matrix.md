# M10 same-build release matrix

Started 2026-11-24 from committed M9 (`651a512`). M10 is the package gate of the
`M8-M11-qualification` batch: its exit test is the **same-build release matrix**.

Every milestone from the bounded smoke through M9 already proves its own
controls against a packaged worker, but each was sealed against its own build at
its own time. Nothing bound them together: no single receipt stated that *one*
current release reproduces the source-tested outcome of every contained control,
across every milestone, with the per-milestone seals chained exactly as each
requires. M10 is that receipt.

It introduces no new guest control and no Rust change. It is pure qualification
machinery: `tools/native_pe_m10.py` reproduces the whole chain against one
shared qualification root — one release build, one package, one full
source-validation index, one emitted fixture corpus of 836 contained controls —
and seals a matrix that records every milestone seal's fingerprint together with
the single bundle and source index they were all produced from.

This certifies no API partition row, and the global gates with an independent
audit of the full denominator remain M11.

## What this milestone closes

| Feature | Obligation | Status |
| --- | --- | --- |
| N19 | One current build reproduces every milestone's contained outcomes, chained | closed as the matrix below |

## The chain, reproduced against one build

The per-milestone seals are not independent: each tool chains to the one before
it, exactly as it did when the milestone was first qualified. M10 runs that chain
in order against the shared root, so a break anywhere — a drifted fixture, a
changed report field, a worker that no longer reproduces an outcome — fails the
stage that owns it rather than being hidden in an aggregate.

| Order | Stage | Seal file | Chains to | What it replays |
| --- | --- | --- | --- | --- |
| 1 | smoke | `qualified-smoke.json` | the package receipt | 120 regression guests + 28 refusals (`verify_rust_user_pe.ps1`) and 82 staging controls (`native_pe_staging.py`) |
| 2 | M2 | `qualified-m2.json` | the smoke seal | binding/rollback/import-exit controls |
| 3 | bootstrap | `qualified-bootstrap.json` | M2 | owned-root bootstrap controls |
| 4 | M3 | `qualified-m3.json` | the bootstrap seal | loader lifecycle and static TLS |
| 5 | M4 | `qualified-m4.json` | M3 | scheduling, waits, exceptions |
| 6 | M5 | `qualified-m5.json` | the shared source index | CRT, allocation and string families |
| 7 | M6 | `qualified-m6.json` | the shared source index | VFS, registry and persona families |
| 8 | M7 | `qualified-m7.json` | the shared source index | network, COM, crypto, security, resources |
| 9 | M8 | `qualified-m8.json` | the shared source index | submitted-sample capture |
| 10 | M9 | `qualified-m9.json` | the shared source index | cross-family operational chains |

The matrix seal `qualified-m10.json` binds the ten fingerprints above to the
single `source_tree_sha256` of the build, the hashed bundle files, and the
source-validation index. Because every stage was produced from that one bundle
and that one index, the matrix is the single receipt that a current release
reproduces the whole contained corpus.

A long reproduction is resumable: `native_pe_m10.py run` skips a stage whose seal
is already present under the root and re-checks it instead, so a failure late in
the chain does not discard the stages already proven. The smoke stage's bounded
regression is produced by `verify_rust_user_pe.ps1`, the one PowerShell step; its
pass depends on PowerShell observing the deliberately uncontained worker's native
refusal exit code, which a PowerShell launched as a child of the driver does not
always see. The driver therefore reuses a `qualification/` already produced from
a shell, and a clean room runs that one script first:

```powershell
tools/verify_rust_user_pe.ps1 -Bundle <root>/bundle -Fixtures <root>/fixtures-final -OutputRoot <root>/qualification -Layout -Imports -Abi
```

The smoke seal re-verifies its full content regardless of who produced it.

## Qualification

| Gate | Result |
| --- | --- |
| Full source validation suite | passed; index under this qualification root |
| Strict workspace Clippy, all targets, warnings denied | passes (no Rust change in this milestone) |
| Native-PE accounting suite (`tests/test_native_pe_*.py`) | 189 tests, 0 failed |
| Workspace Rust tests | passes, unchanged from M9 (538 `emumee-core`, 639 `emumee-engine`) |
| Same-build release matrix | 10 milestone seals reproduced against one build and bound, independently re-checked |

`tools/native_pe_m10.py` runs each milestone's own replay-and-seal tool against
the shared root, then binds the fingerprints; `tests/test_native_pe_m10.py`
guards the matrix set and its tamper-evidence. Each stage's own tool remains the
authority on its controls — M10 adds only the cross-milestone, single-build
binding.

To recheck the sealed matrix from the repository root:

```powershell
C:\Python313\python.exe tools/native_pe_m10.py --root output/rust-pe-m10-complete-20261124 --source-index output/rust-pe-m10-complete-20261124/source-validation-final/index.json --check
```

The `--check` re-runs every milestone seal's own check against the shared root
and then verifies the matrix byte-for-byte. Only a passing, independently checked
current-source index establishes source validation; missing or failed output is
not proof.

## Limits

What this milestone does **not** establish:

1. **No partition row gains semantic closure.** The matrix proves reproduction
   of each control's *recorded* outcome, not that any API contract is
   semantically complete. Per-contract parity for every row remains exactly as
   open as after M9.
2. **The matrix is the union of the milestone seals, not more than them.** It
   binds what each tool already checks; it does not add new controls, new
   coverage or a new denominator. A behavior no milestone control exercises is
   not covered merely because the matrix is comprehensive over the milestones.
3. **Same build, not every build.** The matrix is a receipt for one release
   build. It is requalified by rebuilding and re-running the chain; an older
   matrix remains historical, matching its own build.
4. **M11 remains open:** the global gates — all required gates green and zero
   open or stale required contracts, with an independent audit of the full
   denominator — are not established here, nor are the M8 capture carry-overs
   and the cross-family chains M9 left unrun.

# Native PE baseline failure classification

## Scope and current disposition

The initial 2026-11-04 M0 review separated safe source validation from unavailable
package qualification. The subsequent operator-authorized fresh trusted-source
build and bounded contained smoke now satisfy M0's package exit test. M0 is closed;
M2 is active; its first PE layout/mapping audit is recorded in `m2-pe-layout.md`.
This does not waive semantic contracts or close the M10
package gate. Exact limits and evidence are in `m0-package-smoke.md`.

The maintained tool is `tools/native_pe_baseline.py`. Its packaging check now
probes actual PowerShell/.NET capabilities instead of treating a `pwsh` executable
on PATH as proof. It only invokes a read-only development-shell probe; it does not
invoke the package helper, controller, worker, legacy runtime or submitted bytes.
Malformed, missing, failed and timed-out probes refuse qualification. Six new
synthetic controls cover complete and incomplete capability sets and these failure
paths; the pre-existing dependency controls remain intact.

## Owners, evidence and release actions

| ID | Confirmed evidence or historical boundary | Classification / owner | Required action and exit condition |
| --- | --- | --- | --- |
| P01 | The original modern-only helper failed on Windows PowerShell 5.1. Equivalent portable hashing/encoding now preserves the independent Rust/Python source fingerprint; all actual capability probes pass. | Resolved for the current helper; build/toolchain maintainer | Keep the six fingerprint/refusal controls and capability probe green. No runtime installation or download was needed. |
| P02 | The operator reported an exclusion and requested continuation after the fresh trusted-source package approval question. The scope was restricted to new repository builds and harmless contained tests; no protection setting was changed or exclusion independently verified. | Fresh M0 build/test authorized; historical incident not retroactively cleared; operator/security reviewer | Preserve historical quarantine evidence and do not restore old artifacts or treat an exclusion as security clearance. Comprehensive stable-release/security review remains separate. |
| P03 | A new release build, new frozen bundle, independent hash/build-info checks, 16 guest cases and four refusal controls pass for the exact bundle in `m0-package-smoke.md`. | Resolved only for this bounded M0 bundle; release maintainer | Requalify after relevant source changes. Old bundles remain historical and general parity/M10 qualification remains open. |
| P04 | Prior legacy regression was interrupted by quarantine of an installed Speakeasy x86 decoy. Current static dependency hashes pass; no legacy suite was rerun. | Historical legacy-oracle/security boundary; operator and reference-test maintainer | Independently approve the reference environment and select only safe synthetic or source-level controls. Static RECORD/hash consistency is not clearance to import or execute the legacy pipeline. This is not a reproduced Rust test failure. |
| P05 | Driver/PFN and Linux-host package claims have separate historical limitations. No driver, Linux-host or broad CLR qualification was attempted. | Out-of-scope release qualifications; respective subsystem maintainers | Retain explicit support limits in release documentation. Do not expand native M0 into driver research or count unrun unrelated suites as native failures or passes. |
| P06 | The first M2 full workspace run rejected an existing managed-EH fixture's exact short raw length after an overly strict alignment check. | Resolved in M2; parser maintainer | Preserve exact raw lengths, never treat virtual fill as file backing. The original managed test is unchanged; new raw-length controls and the subsequent 1,034-test workspace run pass. |

The earlier unavailable smoke was not called a pass. The first new attempt failed
at PowerShell 5's expected-stderr handling after its guest cases; it remains
retained. The corrected, strengthened harness passes in a fresh output directory.
Unrelated driver qualification is not a prerequisite for completing the native
source model and has not been promoted by this bounded result.

## Safe reproduction and evidence

Use a fresh path every time:

```powershell
python tools/native_pe_baseline.py audit --output output/native-baseline-next/dependencies.json
python tools/native_pe_baseline.py check --report output/native-baseline-next/dependencies.json
python -m unittest discover -s tests -p test_native_pe_baseline.py -v
```

`payload.toolchain.packaging_shell` retains the exact probe argv, process result,
raw output and parsed capability flags. Probe success means the probe ran, not
that packaging is supported: inspect `supported` and `missing_dependencies`.
`packaging_prerequisites_present` covers tool availability only, never P02 security
approval or an authenticated package. A failed API check is kept separate from
dependency-integrity failures.

Current captures are under `output/rust-pe-m0-smoke/`: `dependencies/report.json`,
`registration/review.json`, `final-ledger.json`, `final-status.json` and
`final-validation/index.json`. The full validation index binds exact commands,
source/environment fingerprints, timings and all supplied artifact hashes. Check
it using the validation tool before relying on it. Missing local files after a
clone are missing proof; the maintained classification and controls remain usable.

## Next executable release action

M0's required source and bounded package controls are satisfied; start M2
request/staging with admission negative controls and a harmless companion/env
reproducer. Preserve the exact bundle/evidence and requalify changes that affect
its trust boundary. The later comprehensive package qualification remains M10.

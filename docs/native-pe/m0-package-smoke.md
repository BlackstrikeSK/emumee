# M0 bounded native package smoke

## Scope and result

On 2026-11-04 a fresh offline release build and newly frozen controller/worker/
Unicorn bundle passed the existing bounded native PE smoke: 16 contained guest
cases (eight per architecture), direct-worker refusal and three invalid CLI
refusals. This satisfies M0's baseline package exit test, not M10's comprehensive
qualification, general Windows parity, CLR/driver/Linux qualification or clearance
of a historical security incident. All 2,590 semantic contracts remain open.

The operator reported a D:\Projects exclusion and requested continuation after
the fresh-package approval question. Work was limited to trusted repository
builds and generated harmless fixtures. No exclusion was queried, created or
modified; no protection settings changed, no quarantined artifact was restored
and no supplied sample was executed on the host. The reported exclusion is not
itself proof of artifact authenticity or security clearance.

## Compatibility changes and independent controls

`tools/package_rust.ps1` now uses SHA256.Create/ComputeHash, BitConverter and an
explicit BOM-free UTF8Encoding, available in the installed Windows PowerShell 5.
Its relative names retain forward-slash normalization and ordinal sorting. The
canonical digest remains path + NUL + lowercase file SHA-256 + newline, exactly
as in the Rust controller/worker build scripts. Existing destination and stale
controller/worker checks remain mandatory. Rooted destinations are normalized
without incorrectly joining them to the repository path.

`-SourceFingerprintOnly` reports canonical source hashes without touching release
executables or creating a bundle. Six independent controls in
`tests/test_native_pe_package.py` cover the live repository and synthetic digest,
selected/ignored mutation, no binary execution, existing destination preservation,
missing source and mutually exclusive modes. The dependency audit probes the
portable primitives actually used; every capability now passes on PowerShell 5.

PowerShell 5 initially raised NativeCommandError when the deliberately uncontained
worker wrote its expected refusal to stderr. The 16 guest cases had completed,
but that attempt was not a complete smoke pass. The harness now allows native
stderr only around the expected-negative invocations, restores strict error
handling immediately, and requires exit status 2, the exact refusal diagnostic
and no CLI run publication. It emits four explicit refusal records alongside the
16 guest records. A missing executable or unrelated failure cannot satisfy these
negative controls. The failed attempt remains retained, not overwritten.

## Current exact bundle and evidence

Local root: `output/rust-pe-m0-smoke/`; bundle: `bundle/`.

- Canonical build-source SHA-256: `3f097074775dcabe45e7be377c02cb110103bae0bf56a9441eaa56525dc63d3e`.
- Controller SHA-256: `e7631c7913cdbbd897c43ddde987925b1c340300e57ab6a5f81f14e15f7675a9`.
- Worker SHA-256: `5562cd253afe7c24949b0a90e0d4a7cfea952b413b6a7c905b95c40bb931addf`.
- Unicorn SHA-256: `f19546ed0d1b7ea0761768e9937334d4f6ba3a20eaed7c411655000b9154386e`.

`qualified-smoke.json` binds both packaged build-info results, all package hashes,
the independent source digest, 16 manifest containment/cleanup/input bindings,
four refusal records and 172 raw files. It also checks that packaged binaries/DLL
match the fresh release outputs. This is reproducibility evidence, not an external
authenticity attestation. The final source-validation index additionally hashes
the raw files and command logs/receipts, not merely this summary.

Current guest/refusal records: `qualification-verified/verification.json` and
`qualification-verified/refusal-verification.json`. The old `qualification-attempt1`
is failed evidence; `qualification-final` predates strengthened refusal-reason
checks. Only `qualification-verified` is the current smoke result. A failed local
dispatcher capture used a relative executable path unsupported by CreateProcess;
`dispatch-verified.log` is the successful absolute-path capture from this bundle.

Other current captures: `release-build.json`, `package.json`, `fixtures.json`,
`smoke-verified.json`, `dependencies/report.json`, `registration/review.json`,
`final-ledger.json`, `final-status.json` and `final-validation/index.json`.
Build took 207.048s, packaging 1.046s, fixture generation/two engine controls
2.766s and final smoke 3.379s. Source/environment fingerprints and exact argv
are retained with raw logs. Smoke-only harness changes do not change the Rust
build-source digest; they are separately covered by runtime snapshots and the
full source index. Missing local captures after a clone require regeneration.

## Reproduction

Choose fresh bundle, fixture and qualification paths; never overwrite evidence.
Run the package fingerprint controls, inspect the maintained smoke script, build
with `tools/build_rust.ps1 -Release -Jobs 2` and package with
`tools/package_rust.ps1 -Destination FRESH_BUNDLE`. Set `CARGO_NET_OFFLINE=true` to
prevent downloads. Generate fixtures as documented in `rust/USER_PE.md`, using
the validation engine tests and `EMUMEE_USER_TEST_FIXTURES`, then run
`tools/verify_rust_user_pe.ps1 -Bundle FRESH_BUNDLE -Fixtures FRESH_FIXTURES
-OutputRoot FRESH_QUALIFICATION`. Generated PE bytes are guest inputs only.
Require both verification files, all 16 guest cases and all four refusal cases.
After any source change recapture the applicable package/source evidence;
historical smoke does not qualify a new runtime. M2 request/staging follows M0.

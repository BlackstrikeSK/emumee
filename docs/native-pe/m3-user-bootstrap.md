# M3 owned user bootstrap

## Objective and scope

Close only the first M3 checkbox: required root PEB/TEB fields, user FS/GS,
process parameters, environment, command line/current directory, process/thread
IDs and shared LastError. Loader lists, static TLS and attach/detach/reentrant
loader lifecycle are subsequent M3 checkboxes. This does not qualify the entire
M3 milestone, API semantic parity, M4 scheduling or the global M10 package gate.

The preceding clean source-only M2 checkpoint is
`503d0d77a04ecb50b46ccc52de8d4a4702501777`, pushed to `origin/main` and independently
matched with `git ls-remote`. No generated captures or private plans were included.

## Confirmed architecture and reference

`api/user_bootstrap.rs` installs an owned arena only for submitted native user
execution. Generated closed profiles and kernel profiles retain their existing
initialization. Existing persona, VFS, CRT standard handles, process 1024 and
scheduler root thread 1 remain authoritative; there is no second process model.

Trusted frozen Speakeasy definitions are inspected as data, not used to execute
guests. `tools/native_pe_m3.py` serializes the ctypes layouts and hashes the exact
definition source in `bootstrap-reference.json`. Required byte offsets are:

| Field | x86 | x64 |
| --- | ---: | ---: |
| TEB ClientId | 0x20 | 0x40 |
| TEB ProcessEnvironmentBlock | 0x30 | 0x60 |
| TEB LastErrorValue | 0x34 | 0x68 |
| PEB ImageBaseAddress | 0x08 | 0x10 |
| PEB ProcessParameters | 0x10 | 0x20 |
| PEB NumberOfProcessors | 0x64 | 0xb8 |
| PEB OSMajorVersion / OSBuildNumber | 0xa4 / 0xac | 0x118 / 0x120 |
| Parameters StandardInput | 0x18 | 0x20 |
| Parameters CurrentDirectory | 0x24 | 0x38 |
| Parameters ImagePathName | 0x38 | 0x60 |
| Parameters CommandLine / Environment | 0x40 / 0x48 | 0x70 / 0x80 |
| Parameters DesktopInfo | 0x78 | 0xc0 |

The frozen process-parameter header sizes are 0x90/0xf0. Length matches that
header; MaximumLength covers its owned 0x1000-byte backing page. Normalized
string pointers may target separately owned stable storage.

The frozen x64 CLIENT_ID definition contains two uint32 members with later
padding; this implementation intentionally uses native pointer-width ID cells
at TEB+0x40/+0x48. Tests compare both IDs with the existing process/thread APIs.
Reference layout agreement is not a claim that this legacy discrepancy has been
copied or that all Windows structures/versions have been implemented.

## Implementation and bounds

- TEB occupies two pages; PEB is at arena+0x2000, parameters +0x3000 and the
  x86 GDT +0x4000. Image/cwd buffers each reserve 64 KiB, and the environment
  reserves the existing 1 MiB persona limit. Total arena size is 0x125000 bytes,
  charged to the existing VirtualMemory/AddressSpace live mapping quota.
- NT_TIB exposes exception sentinel, stack base/limit and self pointer. x64
  GS_BASE points to the TEB; x86 uses bounded GDT descriptors and FS. The GDT
  page is read-only; allocation free/protect routes refuse arena overlaps.
- Process parameters reuse the stable read-only GetCommandLineW backing rather
  than allocating an unrelated copy. Counted UTF-16 descriptors exclude the
  terminator from Length and do not wrap their uint16 fields.
- DesktopInfo reuses GetStartupInfoW's existing stable WinSta0\Default storage;
  the direct-memory probes check the descriptor and exact shared pointer. This
  field was caught during the final frozen-initializer pass; its initial omission
  is resolved rather than deferred to a different milestone. The earlier bundle
  and source captures are preserved under before-desktop names.
- Successful environment/current-directory setters refresh process-parameter
  backing from existing committed persona/VFS state. Image, standard handles,
  processor count and OS version/build project those existing authorities.
- A guest TEB write hook marks overlapping LastError stores, including partial
  and cross-boundary stores. Before the next instruction, the canonical API
  state is reconciled. Successful model writes reconcile through `cpu::write`,
  covering WriteProcessMemory as well as ordinary API stores. Changed API
  LastError is published before the guest can read it; final execution capture
  also synchronizes pending state. No unconditional native memory read is added
  to every instruction.
- `Execution.user_bootstrap` records addresses, mapping size, root identity,
  stack bounds and LastError with an explicit bounded scope.

## Controls and resolved development findings

`user_bootstrap_tests.rs` emits 32 controls: x86/x64, EXE/DLL,
default/configured persona and Basic/Mutation/Protect/Free. Direct FS/GS reads
compare TIB/PEB/parameters with APIs, exact environment bytes, Unicode counts,
command-line pointer identity, OS/processor/stdio state, full/partial/overlapping
LastError writes and model-mediated WriteProcessMemory. Mutation updates cwd
and environment. Sixteen free/protect controls require the specific ownership
refusal, not a generic fault or synthetic return. Two additional EXE controls
exercise the exact admitted command-line maximum on both architectures.

The initial boundary test incorrectly used 32767 text units; the existing
admission correctly refuses that value. The test now proves that refusal and
then executes the accepted 32766-unit command line. Admission was not weakened.
Windows cannot transport that guest maximum through a host CLI with additional
executable/options/path text. A closed `user-bootstrap-boundary-fixture` recipe
therefore checks exact generated harmless probe bytes/basename and constructs
only that deterministic argument internally, then calls the ordinary controller
staging/containment/worker/verifier route. It never executes guest code in the
controller, changes public admission or supplies an alternative runtime model.

Strict Clippy caught use of an integer convenience method stabilized after the
workspace's Rust 1.85 minimum. The parity check now uses compatible arithmetic;
the declared toolchain floor and warning policy are unchanged.

Python evidence tests reject forged addresses, identity, mapping sizes, horizons,
completion/refusal reports and static reference hash/offsets. Static definition
inspection is not independent model review. The earlier delegated audit failed
without findings; no independent-agent review is claimed.

## Verification

Evidence is captured under `output/rust-pe-m3-bootstrap/`; unsuccessful early
builds/probes and their emitted fixtures are preserved. One-job offline workspace
tests, strict all-target Clippy and a fresh release/package precede qualification.
The package must repeat the 294 M2 outcomes before the 34 new bootstrap controls.
Seals recursively bind prior matrix, exact binaries/build receipt, inputs,
persona/arguments, requests/results, containment, cleanup and captured artifacts.

Reproduction, using fresh destinations rather than overwriting sealed captures:

```powershell
$env:CARGO_NET_OFFLINE='true'; $env:RUST_TEST_THREADS='1'
$env:EMUMEE_USER_TEST_FIXTURES="$PWD\output\rust-pe-m3-bootstrap\fixtures-final"
.\tools\build_rust.ps1 -Test -Jobs 1
.\tools\build_rust.ps1 -Lint -Jobs 1
.\tools\build_rust.ps1 -Release -Jobs 1
.\tools\package_rust.ps1 -Destination output\rust-pe-m3-bootstrap\bundle
.\tools\verify_rust_user_pe.ps1 -Bundle output\rust-pe-m3-bootstrap\bundle -Fixtures output\rust-pe-m3-bootstrap\fixtures-final -OutputRoot output\rust-pe-m3-bootstrap\qualification -Layout -Imports -Abi
python tools/native_pe_staging.py --bundle output/rust-pe-m3-bootstrap/bundle --fixtures output/rust-pe-m3-bootstrap/fixtures-final --output output/rust-pe-m3-bootstrap/staging
python tools/native_pe_m2.py --root output/rust-pe-m3-bootstrap
python tools/native_pe_staging_seal.py --root output/rust-pe-m3-bootstrap
python tools/native_pe_m2.py --root output/rust-pe-m3-bootstrap --seal
python tools/native_pe_m3.py --root output/rust-pe-m3-bootstrap
python tools/native_pe_m3.py --root output/rust-pe-m3-bootstrap --seal
python tools/native_pe_m3.py --root output/rust-pe-m3-bootstrap --check
```

Fresh dependency/registration audit and repeat checks, packaged dispatcher ledger
refresh preserving semantic history, and full source validation are also required
before closure. Use offline=true/threads=1 for source validation, but unset both
variables for dependency integrity audit/check. The final source validation index
records source fingerprint and measured suite times; this document is itself
hashed there, so its index fingerprint is not embedded back into the document.

After all maintained source, documentation and accounting updates stabilize:

```powershell
$env:CARGO_NET_OFFLINE='true'; $env:RUST_TEST_THREADS='1'
python tools/native_pe_validation.py run --full --output output/rust-pe-m3-bootstrap/final-validation --timeout 1800 --artifact output/rust-pe-m3-bootstrap/qualified-bootstrap.json
python tools/native_pe_validation.py check --index output/rust-pe-m3-bootstrap/final-validation/index.json
```

Do not edit maintained files after that final run without refreshing its index.
Dependency/registration commands and their actual timings are captured in
`audits-complete.json`; the source-only integrity environment intentionally
differs from the offline serial source-test environment.

## Final outcome

2026-11-07: the first M3 bootstrap checkbox is qualified. No implementation or
negative-control obligation from that checkbox is deferred. M3 itself remains
in progress: module catalog/LDR lists and loader lifecycle are next, followed by
static TLS, startup/termination and nested callback/horizon qualification.

All 1,060 Rust controls pass serially, including the complete updated bootstrap
matrix and the unsubmitted/kernel noninstallation controls. Strict all-target
Clippy passes. Fresh source emission took 454.017s, strict lint 59.570s, the
one-job release 882.220s and freeze 3.108s. The final full source index records
the subsequent stable-source accounting/inventory/partition/syntax/Rust/lint/
whitespace results and measured timings, and requires its independent check.

The same-build package passes 328 required outcomes: all 294 M2 outcomes plus
34 bootstrap controls, with 18 completed guest returns and 16 required specific
owned-memory refusals. Regression, staging, M2 binding and bootstrap controls
took 52.742s, 21.911s, 19.149s and 12.639s respectively. The prior matrix seal
binds 2,201 files, the M2 extension 789, and the bootstrap extension 358. All
three chained seals pass independent repeat checks. Bootstrap seal fingerprint:
`565d8fda7d3cee2894c2038f28d8dd7b442207c020c857205c9fd6807221050f`.
Canonical build-source SHA-256:
`63d3a247da60362ddeccdcdbae49cb97590a5c73228bafb89ea3becfdd32e2bd`.
Exact controller/worker/Unicorn identities are in `bundle/rust-worker-build.json`.

Fresh dependency integrity audit/check confirms 82 frozen legacy sources,
35 Python distributions and 83 Cargo packages with no issues. Effective
registration audit/check is refreshed without promoting API semantics. The
preserved-history packaged dispatch ledger retains all 2,590 open contracts,
1,819 missing and 771 unverified bindings, with no semantic closures or inventory
loss. Only the source-registration global gate is verified; the M3 bootstrap
package child does not promote comprehensive M10. No supplied sample, host DLL
search, quarantine/security change, new branch or M3 commit/push was performed.

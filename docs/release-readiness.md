# Release readiness

The current tree is a development source checkpoint, not a stable packaged
release. Keep release claims narrower than the evidence.

## Supported scope

- The active Windows launcher and build use Rust, not the legacy Python runtime.
- Native PE execution is restricted to the documented bounded x86/x64 EXE/DLL
  profile in [USER_PE.md](../rust/USER_PE.md).
- Linux ELF profiles retain their explicit host-containment and architecture
  checks. Windows source checks do not qualify a Linux packaged worker.
- Driver paging, parked-thread and PFN metadata profiles are explicit opt-ins.
  PFN metadata is a synthetic model, not recovered host RAM or proof of successful
  driver initialization. Unsupported effects stop rather than being guessed.

## Integrated source validation

After integrating the upstream Rust launcher and Linux profiles with the native
PE and kernel-model changes, Windows source checks passed499 core,465 engine,
43 CLI and4 worker tests (1,011 total), plus strict workspace/all-target Clippy.
Python source, test and tool files also pass syntax compilation. These results
are source-level evidence only: no fresh release package or Linux-host runtime
qualification is inferred from them.

The retained legacy Python regression run was stopped after a new host-security
action quarantined Speakeasy's installed x86 decoy executable during testing.
No complete legacy regression pass is claimed. Review dependency integrity
before rerunning; do not restore quarantined files or change protection settings
automatically.

## Outstanding stable-release gates

The subsequent M2 PE layout audit adds six core and four engine controls;
the full workspace passes 1,034 Rust tests. The source audit and reproduction
are recorded in [M2 layout evidence](native-pe/m2-pe-layout.md). Its fresh
same-build layout/regression smoke passes 32 contained guest cases and ten refusal
controls and is separate from the historical M0 bundle.
Neither this audit nor source-only integration closes M2's remaining staging,
import and ABI work or establishes a stable release.

The 2026-11-04 native PE M0 baseline now has a fresh trusted-source release build
and bounded same-build package smoke: 16 contained guest cases and four refusal
controls. [M0 package evidence](native-pe/m0-package-smoke.md) records exact hashes,
commands, failures and limits. Packaging now works on Windows PowerShell 5 using
equivalent hashing/encoding primitives; no runtime installation was needed.
The operator authorized fresh build/testing after reporting an exclusion; no
protection setting was changed and no quarantined artifact was restored. This
does not retroactively clear the recorded incident or qualify a stable release.
M0 is closed, while full native semantic parity and M10 qualification remain open.

The new PFN model's earlier source qualification passed998 tests, strict lint
and a release build. Only22 of82 required contained package controls completed;
all14 parent admission-refusal controls passed. Host security then quarantined
one generated capture and both frozen package executables. Missing artifacts
must not be reconstructed, silently replaced or accepted by weakening checks.

Resolve that incident through the operator's approved security-review process,
authenticate any approved recovery, and complete fresh same-build package
qualification before declaring a stable binary release. Do not disable host
protection or automatically restore quarantined files. Old qualification does
not apply to the newly integrated source tree.

The latest research execution did not establish DriverEntry return. Full driver
compatibility, general managed user admission and legacy application parity
remain outside the qualified claim. No stable version tag or release binary is
published by this source checkpoint.

## Repository hygiene

Commit maintained source, tests, fixture generators, documentation and the Cargo
lockfile. Do not commit live samples, generated PE images, executable bundles,
captures, local plans, run logs, build trees, credentials or analysis outputs.
The ignored local evidence remains available to the operator; it is not needed
to clone or review the source tree.

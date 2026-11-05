# M2 import and relocation resolution

This batch owns the second checkbox in the Rust PE completion plan. It closes
bounded loader mechanisms, not every API's semantics or public companion staging.
The remaining M2 ABI, versioned staging and parent/worker dependency-binding
checkboxes still own those independent obligations.

## Baseline and implementation

- Both architectures retain HIGHLOW and DIR64, ABSOLUTE padding and wrapping
  positive/negative relocation deltas. The source audit also found baseline
  HIGH/LOW/HIGHADJ support; all five forms are implemented, including the exact
  pinned pefile HIGH/HIGHADJ arithmetic. In that baseline HIGH shifts the sum of
  the old WORD and delta, and HIGHADJ uses the following parsed entry RVA rather
  than Windows signed-addend/rounding arithmetic. These are explicit preserved
  compatibility quirks, not claims of Windows-correct behavior. Twenty trusted
  synthetic byte differentials cover both architectures, five forms and both
  delta signs without executing guest code. Relocation blocks require aligned
  page RVAs, DWORD-aligned sizes and complete paired entries. Fixups cannot target unmapped gaps or
  exceed image ranges. Adjacent real ranges remain valid; unsupported relocation
  kinds are explicit errors rather than silently ignored fixups.
- Normal import descriptors and thunk tables are bounded and terminated. Lookup
  falls back to the IAT only when OriginalFirstThunk is zero. Module names, name
  hints, empty names, reserved ordinal bits and full pointer-width IAT spans are
  checked. Duplicate or partially overlapping IAT slots refuse during parsing;
  the overlap check is ordered and bounded, not a quadratic attacker-controlled
  scan. Export names remain case-sensitive; module names are case-insensitive.
- Name and ordinal imports address actual guest exports. Forwarders retain their
  terminal module/symbol and traversal chain, including when they end in a modeled
  external gate rather than a companion export. Static and dynamic loaders retain
  the traversed dependency edges instead of rebinding the original export name.
- Data import pointers refer to guest storage, not generated return stubs. CPU
  controls import one writable datum by both name and ordinal, compare the actual
  pointers, modify through one alias and read the changed value through the other.
  This establishes loader identity, not completion of the separate M5 CRT-global
  and accessor contracts.
- Explicit libraryloader API-set aliases include GetModuleHandleA/W and
  GetProcAddress alongside existing LoadLibrary/FreeLibrary support. Known
  module-specific APIs retain their existing exact API-set registrations. There
  is no catch-all API-set-to-kernel32 rewrite, ambient DLL search or host loading;
  unknown APIs retain the API worklist's explicit unsupported disposition.
- ResolveDelayLoadedAPI is now a real six-argument, pointer-returning model.
  It reads a live guest RVA descriptor lazily, validates the actual owning image,
  readable names/hints/table slots and writable complete IAT cell, resolves only
  guest/model targets and writes the same address it returns. Unused delay imports
  are not eagerly loaded or rejected. Repeated resolution reuses the actual target.
- The frozen src/emumee/delay_imports.py contract supports named RVA descriptors
  only, flags zero and at most 128 indexed thunks; ordinal/VA descriptors and
  unavailable targets return zero. Failure callback pointers are not invoked by
  that baseline. These baseline refusals are preserved, not described as full
  Windows delay-loader functionality. Failures do not alter IAT bytes, catalog,
  gate count or last error. Up to 512 delay observations retain descriptor, thunk,
  resolved target or precise refusal reason, with an explicit omitted counter.
- Frozen native.py refuses cyclic static DLL dependencies. The existing
  architecture-paired loader controls require refusal before entry, no initializer
  events and no half-published lifecycle state. Forwarder cycles and depth limits
  also refuse; malformed exports never fall back to synthetic guest success.

## Source and submitted controls

The full regression suite caught an important scope boundary: widening generic
user PE relocation support also widened the read-only pinned kernel reference
projection. That projection now supplies its own DIR64-only relocation policy;
its original refusal remains intact and additionally checks every newly supported
non-native-width form. The generic loader keeps the frozen user-mode behavior.
The failed `fixtures-complete` capture is preserved, not counted as a pass.
An earlier malformed-hint control also exposed a fixture-offset mistake: the
actual lookup table is raw 0x4d0 (RVA 0x20d0), not raw 0x500. All mutations now
address the real table, and the named/ordinal execution tests assert the parsed
import identities and count before running. Earlier failed captures remain
available rather than being relabeled as successful validation.

New controls are in pe/tests.rs, pe_import_tests.rs and api/delay_imports.rs.
They cover nine malformed import families per architecture, valid adjacent spans,
OFT fallback, all five positive/negative relocation forms, seven malformed
relocation cases, malformed block alignment and missing HIGHADJ addends,
real native EXE/companion named/ordinal/data/forwarder execution, an uppercase
API-set DLL, lazy success/unused imports and fifteen explicit delay refusals.
Failure snapshots and 513 repeat calls verify atomicity and bounded reporting.
Existing export parsing, module catalog, static/dynamic loader, protection and
managed regression suites remain mandatory and unchanged in their expectations.

The -Imports switch on tools/verify_rust_user_pe.ps1 adds 36 actual submitted
worker executions and 18 parent-admission refusals. With -Layout the total is
68 contained guest cases and 28 refusals. The verifier checks source hashes,
submitted persona identity, actual result values and delay observations,
AppContainer/job/child-process/network restrictions and cleanup; malformed imports
must refuse before publishing a run directory.

## Reproduction

Use only source-generated harmless inputs and fresh output directories:

~~~powershell
$env:CARGO_NET_OFFLINE='true'
$env:RUST_TEST_THREADS='1'
$env:EMUMEE_USER_TEST_FIXTURES="$PWD\output\native-imports-next\fixtures"
.\tools\build_rust.ps1 -Validation -Test -Jobs 2
$env:EMUMEE_USER_TEST_FIXTURES=$null
.\tools\build_rust.ps1 -Lint -Jobs 2
.\tools\build_rust.ps1 -Release -Jobs 2
.\tools\package_rust.ps1 -Destination output/native-imports-next/bundle
.\tools\verify_rust_user_pe.ps1 -Bundle output/native-imports-next/bundle -Fixtures output/native-imports-next/fixtures -OutputRoot output/native-imports-next/qualification -Layout -Imports
python tools/native_pe_validation.py run --full --output output/native-imports-next/validation --timeout 1800
~~~

## Verified outcome

Current evidence root: `output/rust-pe-m2-imports/`. The second M2 checkbox is
complete; its loader mechanisms have no deferred implementation item. M2 ABI,
versioned public staging and parent/worker dependency binding remain distinct
subsequent checkboxes, not waived requirements or claims made by this batch.

- Complete serial workspace: **1,041 Rust tests**, including 492 core and 473
  engine controls, pass in 70.889s; strict all-target Clippy passes in 17.793s.
- All **20 static frozen relocation differentials** pass. The pinned pefile source
  SHA-256 is `0d0eb68f0f169182613dc64b3ab50b20855508c1c1d2faafe8fccf23edb6a345`.
  Its target-byte capture is `legacy-relocations.json`; the frozen delay mock
  also passes for both pointer widths in `legacy-delay-mock-final.log`.
- Fresh offline release passes in 237.694s; freeze in 1.117s; expanded contained
  smoke in 16.803s. All **68 guest cases and 28 refusals** pass. The independent
  seal rechecks both build-info results, canonical build inputs, binary hashes,
  request/result/input bindings, containment and cleanup, indexing **800 files**.
  Its repeat rehash also passes; seal fingerprint:
  `0293ea41ccdf3356592863e881dd45130ceca5e6d285e5a3cb50585fe0b8edc8`.
- Current source registration and dependency integrity are recaptured and checked.
  The exact 2,590-contract/151-batch denominator and previous evidence history are
  preserved. Dispatcher availability is 1,825 missing/765 unverified bindings;
  all 2,590 semantic contracts remain open. No API semantic gate or global M10
  package gate is promoted by this mechanism-level checkbox.

| Item | SHA-256 |
| --- | --- |
| Build sources | `6214df764202651b402d68e60473c52b9d42dc03508715d3b8477857f200f7ed` |
| Controller | `0b092497850abc742baa43753cccad239a554f28f9e1aa4b2660e9e0b7e10613` |
| Worker | `22ccdb16b69ed4d67d37601fbb4167c1830d541e7c83c1299aaa9ea8389c2611` |
| Unicorn | `f19546ed0d1b7ea0761768e9937334d4f6ba3a20eaed7c411655000b9154386e` |

The broad source snapshot changed during release compilation only because this
maintained audit text was updated. Packaging and the independent seal match
both binaries against every current canonical build input. The final safe-source
receipt is captured after maintained documentation stops changing; check it
before relying on the checkpoint. Historical failed/compile captures and the
superseded first release are retained, not counted as current qualification.

Current fixtures: `fixtures-closed/`; source controls: `fixtures-closed.json`
and `strict-lint-final.json`; bundle: `bundle/`; contained records:
`qualification/`; independent index: `qualified-smoke.json`. Current source
index: `final-validation/index.json`; dependency: `dependencies/report.json`;
registration: `registration-final/review.json`; dispatcher: `dispatch.log`;
preserved-history ledger/status: `final-ledger.json` and `final-status.json`.
Missing ignored captures after a clone require fresh evidence, not an assumed
pass. Dependency check uses CARGO_NET_OFFLINE unset; source validation uses true.

Next executable action: the M2 ABI checkbox, covering x86 calling conventions,
variadic/floating-point behavior and x64 argument/stack/return/nonvolatile rules,
with separate callback controls. Then finish public staging and binding. This
batch changes no host protection settings, restores no quarantined files, runs
no supplied samples, commits/pushes nothing and claims no full Windows/API parity.

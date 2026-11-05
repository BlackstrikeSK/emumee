# M2 ABI qualification

## Scope and frozen authority

This review closes only the third M2 checkbox in
`.codex/plans/rust-pe-completion.md`. It qualifies import/callback ABI
mechanisms for the frozen native-user baseline, not every API's semantics,
public companion staging, M3 continuation/lifecycle closure or full M10 release
qualification. No implementation item within this checkbox is deferred.

The frozen effective registration map selects the baseline-only msvcrt pow,
floor and sin handlers on both architectures, with no overriding hooks. They
are the only three frozen float declarations. No frozen user-mode declaration
uses fastcall, so its mechanism is CPU-qualified without inventing a production
API. The maintained registration policy, source and exact checked-in reference
hashes are authoritative; no external ABI documentation was required to guess
this compatibility behavior.

The pinned binemu get_func_argv reads float arguments from XMM0-XMM3 on BOTH
architectures. do_call_return writes XMM0 on both and pops argc*4 on x86 despite
register inputs. This is an explicit frozen-emulator contract, not a claim that
ordinary Windows x86 C doubles use XMM registers instead of stack/x87. Rust
preserves the required contract and does not silently substitute a different ABI.

## Implementation

- Core CallingConvention::Float, ReturnType::F64 and XMM argument registers
  preserve full 64-bit payloads on x86 and x64, with bounded argument decoding.
  Existing integer stdcall/cdecl/fastcall and x64 home/stack offsets remain intact.
- Engine floating reads/writes use Unicorn long-register APIs and full 16-byte
  backing storage, never a scalar-u64 buffer for a 128-bit XMM register. Returns
  publish the complete low 64-bit payload through XMM0.
- Only frozen msvcrt pow/floor/sin are registered. Domain, nonfinite conversion,
  complex-result and overflow cases retain explicit failure rather than invented
  NaN-success. Floor converts negative zero to positive zero as the frozen
  integer round-trip does; sin retains negative zero.
- Loader callbacks now check MXCSR control preservation on x86 as well as x64,
  matching the existing CRT callback guard. Status bits remain excluded by the
  control mask. Existing return-frame, nonvolatile GPR/vector, FPCW and protected
  flags checks are preserved; no baseline refusal was weakened.

## Independent controls

The AST-only tools/native_pe_abi_reference.py extracts just five pure math
methods and three decoder/return/cleanup methods from pinned source. It does
not import the legacy module, instantiate its runtime or load/execute PE inputs.
The checked-in rust/api-parity/abi-float-reference.json binds both source hashes,
143 exact math/domain vectors and 56 architecture/convention/cleanup vectors.
NaN arithmetic compares classification, while argument transport separately
checks raw NaN payloads and all 64 bits. Four Python controls guard regeneration,
dimensions, true builtin pow resolution, signed zero and required failures.

- 48 actual CPU import gates cover both architectures, stdcall/cdecl/fastcall and
  counts 0,1,2,3,4,5,6,32. x64 callers have aligned stacks and writable 32-byte
  shadow space poisoned independently of fifth-and-later arguments. Distinct
  register/stack values, exact cleanup, all nonvolatile GPRs, XMM6-XMM15 and
  nondefault FPCW/MXCSR controls are checked.
- Ten actual dispatch/return-gate controls cover void, u32, pointer, u64 and f64
  for both architectures, including native-width pointer values, x64 zero
  extension of sign-bit-set 32-bit payloads and x86 EDX:EAX halves.
- 52 submitted ABI controls comprise 22 floating, four variadic, 13 CRT callback
  and 13 loader callback executions. Eighteen must return; 34 must refuse with
  the exact required failure family. CRT callbacks independently check aligned
  CDECL/Win64 frames, all home slots and a nested modeled import. Loader fixtures
  check actual STDCALL3/Win64 arguments, alignment, shadow space and lifecycle
  returns. Callback stack/GPR/vector/direction/MXCSR/FPCW violations are distinct
  from import tests. Existing dependency DllMain/TLS/nested-import regressions
  remain required and pass in the full workspace suite.

## Verification and preserved failures

All 1,047 Rust tests pass (494 core, 477 engine, 76 other), and strict all-target
Clippy passes. Source-generated harmless fixtures are the only executed inputs.
The first development compile caught a test Box/slice mismatch. The next run
caught a reference harness shadowing builtin pow and a fixture retaining driver
headers. Each root cause is corrected and the failed captures are retained.
The first full compile exhausted LLVM memory with two concurrent compiler jobs;
one-job compilation passes without removing tests, changing security settings,
killing user applications or altering build semantics.

Current evidence root: output/rust-pe-m2-abi/. Commands and unique receipts are
recorded there. fixtures-closed-serial/ contains current generated inputs; bundle/
is a fresh release freeze; qualification/ contains 120 real contained runs plus
28 parent/direct-worker refusals. The 52 new ABI runs are included in those 120,
not counted again as extra successful guests. Independent seal_smoke.py checks
canonical build inputs, both build-info identities, exact binary hashes, every
request/result/input binding, floating API result observations, required ABI
failures, AppContainer/job/child/network restrictions and cleanup before sealing
all 1,320 files. qualified-smoke.json is rehashed with --check.
Release: 468.792s; freeze: 1.155s; contained smoke: 21.799s.

| Item | SHA-256 |
| --- | --- |
| Build sources | `a85e653ccb26a4c3324f44cd81535bc52cee5b015860f6f20387cc70d7d3b56b` |
| Controller | `c93fe2a93c1fddde7d44cca5d683224b34b4240d0df87d8a38f217680dd0ec79` |
| Worker | `ed3ae0cb560bb15a2d5c82c32833963b635caf3eafb13d9cd8bf4d38c5bb57be` |
| Unicorn | `f19546ed0d1b7ea0761768e9937334d4f6ba3a20eaed7c411655000b9154386e` |
| Independent seal | `3b80c4bdbdf9261ca17cf2100ec62241f19760481e9f3d1d5c674907e91b5cb3` |

Final full safe-source validation runs only after maintained evidence, review,
ledger and session text stabilize. Its final-validation/index.json must pass
native_pe_validation.py check. Dependency and source-registration audits/checks,
fresh packaged dispatch, preserved-history final-ledger.json/final-status.json,
seal recheck and whitespace are also mandatory closure gates. Missing ignored
captures after a clone require fresh capture; maintained source and controls
remain independently reproducible.

## Reproduction

~~~powershell
$env:CARGO_NET_OFFLINE='true'
$env:RUST_TEST_THREADS='1'
python tools/native_pe_abi_reference.py --check
$env:EMUMEE_USER_TEST_FIXTURES="$PWD\output\native-abi-next\fixtures"
.\tools\build_rust.ps1 -Validation -Test -Jobs 1
$env:EMUMEE_USER_TEST_FIXTURES=$null
.\tools\build_rust.ps1 -Lint -Jobs 1
.\tools\build_rust.ps1 -Release -Jobs 1
.\tools\package_rust.ps1 -Destination output/native-abi-next/bundle
.\tools\verify_rust_user_pe.ps1 -Bundle output/native-abi-next/bundle -Fixtures output/native-abi-next/fixtures -OutputRoot output/native-abi-next/qualification -Layout -Imports -Abi
python tools/native_pe_validation.py run --full --output output/native-abi-next/validation --timeout 1800
python tools/native_pe_validation.py check --index output/native-abi-next/validation/index.json
~~~

Dependency audit/check uses an ambient environment with CARGO_NET_OFFLINE and
RUST_TEST_THREADS both unset; source validation uses offline=true/threads=1.
The 2,590-contract/151-batch denominator is unchanged. All semantic contracts
remain open; six architecture binding rows becoming available is not semantic
closure. Only the effective source-registration gate is verified. The seven
other global gates stay open. Next is bounded versioned hashed companion/VFS/
environment/option staging, followed by exact parent/worker binding and rollback.
No commit, push, branch, security change or supplied-sample execution occurs.

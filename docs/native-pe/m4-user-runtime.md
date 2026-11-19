# M4 user runtime

M4's bounded runtime implementation and source/package regression qualification
are complete as of 2026-11-19. This milestone does not close the semantic API
ledger, general Windows/CRT compatibility, or the global M10 package gate.
Source remains uncommitted; starting commit is `24056c1`.

## Runtime and ownership

The user scheduler owns saved Unicorn CPU contexts, stacks, TEB/static TLS,
dynamic TLS/FLS and LastError for every guest thread. Stable thread-ID rotation
and slices of at most 4,096 instructions give deterministic cooperative/quantum
scheduling. Kernel scheduling retains its separate authority. Thread DLL/TLS
notifications retain a serialized loader owner while other existing guest threads
can run.
Static startup and terminal process detach retain serialized execution.

Virtual children own independent page/CPU/Trace snapshots on one stopped native
CPU. The process-wide Windows `NATIVE_INSTANCE` guard remains intact; no second
live engine or host thread/process implements guest behavior. Child images come
from actual VFS bytes or exact worker-verified submitted bytes. Persona backing
placeholders cannot become child executables. Child IDs/TEBs, loader state,
TLS/error state, contexts and memory/protection remain process-owned.

Process/thread/dispatcher handles retain owner, rights, flags and retired
identity. Query and wait lifetime survives backing release. Process/thread
duplication and inheritance preserve authority; dispatcher duplication preserves
object identity and rights. File allocation skips all live and retired
process/thread/registry/native/console/search namespaces, including adjacent
reserved ranges. Child creation preflights both result handles before any child
publication or output mutation, including lifetime namespace exhaustion.

Events, recursive mutexes, semaphores and critical sections implement actual
guest ownership. WaitAny/WaitAll validate the complete wait set; WaitAll consumes
nothing until the whole set can be acquired. Duplicated object identities cannot
appear twice. Thread handles signal after normal cleanup, or forced termination.
Without runnable work, the shared virtual clock advances to the next deadline;
without a future deadline, execution reports a terminal deadlock. No host sleep
implements guest waiting. GetTickCount retains its modeled 16 ms quantization.

FLS/APC, exception and thread DLL/TLS callbacks use owned continuation frames,
so waits and nested handlers do not retain recursive host execution frames.
Normal retirement runs bounded FLS destruction before DLL/TLS detach; forced
termination cancels frames and skips guest cleanup callbacks. Process detach
retains the exiting worker's owned CPU/TEB/stack until its terminal callbacks
finish. Entry return remains distinct from process exit, including later DLL
export invocations. Self-memory APIs remain usable during serialized startup.

## Exceptions and bounds

User exceptions include x86 registration chains, VEH/VCH, checked legacy CONTEXT
transport, software exceptions with pointer-width arguments, fault continuation,
nested handlers, and AMD64 static/runtime-function-table search/unwind. The x86
EH4 common handler executes checked fastcall cookie checks, CDECL filters,
finally/global/local unwind and owned non-returning handler transfer.
Guest exceptions and engine failures retain distinct child classifications.

The run shares instruction/wall horizons, virtual time, API history, artifact
retention and a 4,096 callback-call limit. Limits include 32 lifetime children,
256 aggregate threads, aggregate mapped-memory admission before image
materialization, bounded handles/queues, 16 exception frames, 128 vectored
registrations, 128 x86 chain entries and 256 handler events. AMD64 tables are
bounded to 64 registrations, 4,096 rows/table and 65,536 aggregate rows.

This is the documented bounded guest model. General C++ object destruction,
XSTATE/CET, EH4 nonlocal transfer across an already active EH4 callback, native
fastfail behavior and full native CRT/Windows parity are not qualified. The
invalid-cookie synthetic checker raises UD2 and verifies nested-fault refusal.

## Verification and retained evidence

The evidence root is `output/rust-pe-m4-complete-20261119-02/`. Generated controls
execute in Unicorn only; no supplied sample or host-native guest code was run.
No security configuration or legacy environment was modified.

- `source-validation-final/index.json`: full stable-source workspace tests,
  strict all-target Clippy, 170 accounting tests, four inventory controls,
  exact partition, syntax and whitespace checks. Includes all M3/kernel controls.
  The workspace passes 1,123 tests, including 539 engine tests and 43 M4 tests.
- `fixtures-final/`: exact source-tested bytes, limits, arguments, staged inputs
  and deterministic outcome snapshots. The 172 M4 guest controls comprise
  111 scheduling/callback/exception cases, 21 x86 EH4 cases and 40 process cases.
- `bundle/rust-worker-build.json`: a fresh release CLI/worker/Unicorn freeze,
  bound to the canonical build-source fingerprint and exact binary hashes.
- `commands.json`, `build-commands.json`: measured commands, exits and timings.
  The contained matrix repeats 398 M2/M3 outcomes and adds all 172 M4 outcomes.
- `qualified-smoke.json`, `qualified-m2.json`, `qualified-bootstrap.json`,
  `qualified-m3.json`, `qualified-m4-final.json`: independently rechecked seals
  binding request/result/staged bytes, build receipts, AppContainer/Job limits,
  network denial, worker exit and restored cleanup. The M4 seal also binds the
  final full source index, fixture snapshots and prior qualification chain.
- `audits-02/`: current dependency/registration audit and independent check
  receipts. `final-ledger.json` preserves prior semantic history and leaves
  all unreviewed API contracts open.

The full run exposed a platform cleanup regression: unconditionally applying
legacy SetFileSecurity cleared AUTO_INHERITED. Normal and recovery cleanup now
share restoration that preserves protection/automatic-inheritance flags. Actual
Windows tests cover protected/unprotected and legacy/automatic descriptors.

The contained replay also caught self-TerminateThread/ExitThread events left
pending after successful completion. Terminal events now complete without an
invented return, and every successful M4 source/package outcome rejects pending
API events.

Older development logs, the allocator boundary-test failure, the platform
cleanup failure and the terminal-event failure remain retained diagnostics. They do not support completion.
Replaying source tests preserves existing fixture bytes and refuses differing
outcomes. M4 replay refuses missing controls, stale source indexes, changed
artifacts, input substitutions and changed deterministic guest effects.

To recheck the current M4 seal from the repository root:

```powershell
C:\Python313\python.exe tools/native_pe_m4.py --root output/rust-pe-m4-complete-20261119-02 --source-index output/rust-pe-m4-complete-20261119-02/source-validation-final/index.json --receipt output/rust-pe-m4-complete-20261119-02/qualified-m4-final.json --check
```

## Frozen-source audit and remaining migration

The audit used inventory-bound installed kernel32/msvcrt handlers,
`src/emumee/virtualprocess.py`, the child runner in `src/emumee/native.py`, and
installed MSVC `crt/src/i386/chandler4.c`; no full legacy guest pipeline ran.
Baseline WaitForMultipleObjects and CreateSemaphoreW are placeholders; baseline
APC creates another thread and FLS ignores destructors. Atomic waits, actual
dispatcher state, target-thread APC delivery and real FLS destruction are tested
model improvements, not evidence of exact baseline or Windows parity.

All six M4 obligations are covered by connected guest execution and the retained
qualification. M5 CRT/allocation/string foundations is the next implementation
batch. API semantic closure, later migration milestones and M10 remain open.

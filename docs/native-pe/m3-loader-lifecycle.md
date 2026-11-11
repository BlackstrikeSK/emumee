# Submitted-user M3 loader and lifecycle

Status: bounded M3 qualified on 2026-11-11 by fresh same-source contained controls,
full source validation, integrity/accounting refresh and chained independent seals.

## Catalog and guest exports

`ModuleCatalog` remains the module identity, export, dependency and reference
authority. Submitted-user engines publish finite generated DLL images from the
existing dispatcher definitions and input bindings. Their PE export entries and
static IATs resolve to the same guest stubs. Unsupported imported routines retain
explicit stop gates. Supplied companion names retain authority over their images.
Synthetic export ordinals do not establish Windows ordinal compatibility.

Provider paths derive from the configured guest system directory. Address
placement uses the bounded guest address-space planner. No host DLL lookup or
host library execution is involved. Guest PEB lists use the frozen baseline's
primary-image, ntdll, kernel32, kernelbase, then remaining-load-order projection.

Missing guest dependency graphs are prepared against prospective catalog and
memory state before native publication. Initialization, reference edges,
relocations and cascade unload remain catalog operations. Lazy GetProcAddress
forwarders enter the same loader continuation as LoadLibrary, complete real
target initialization, retain followed ownership edges and release temporary API
references. Missing-module/export controls require ordinary guest failures with
no leaked loader transaction or temporary image.

## TLS and threads

Submitted images use validated TLS templates, zero fill, alignment, index cells
and per-thread vectors. The loader owns vector/block allocations and protects
their allocation lifetimes. Static TLS storage is separate from TlsAlloc/FLS.
Kernel and closed fixture profiles retain their earlier callback-only behavior.

User threads execute as bounded guest continuations with owned stacks and TEBs.
They switch actual x86 FS/x64 GS state, share the process PEB, and have independent
LastError and dynamic slot identity. The parent native context and actual API
frame survive child execution. Normal return/ExitThread runs thread detach;
forced termination skips guest detach. Suspended creation can resume before its
first execution. Handles and exit codes remain guest process state.

This batch uses run-to-completion continuations, at most 64 thread records and
bounded stacks. General quantum scheduling, live-thread suspension, blocking
waits and FLS destructors belong to M4. Creating a thread while executing loader
callbacks refuses with error 50 rather than pretending to model loader-lock
scheduling. All entered guest continuations share the original instruction and
wall horizon and the common depth bound.

## Process and callback termination

Normal ExitProcess executes real reverse-initialization-order DLL/TLS detach
callbacks. TerminateProcess skips guest callbacks. Cleanup does not get another
instruction budget or deadline. Interrupted cleanup is reported as incomplete;
looping detach cannot publish successful process cleanup. Root entry return is a
distinct observation and does not imply a process-exit call.

Nested CRT initializer walks use distinct real guest tables and caller frames.
Return stacks, nonvolatile registers/vectors and protected control state remain
checked. Submitted-user callback failures archive interrupted caller diagnostics
and remove active continuations while retaining the terminal error/limit result.

Terminal process module memory remains available for report capture until the
owning emulator engine is dropped. Reports distinguish retained diagnostic
memory from live thread backing and completed cleanup.

## Development evidence and remaining gates

Logs under `output/rust-pe-m3-complete/` preserve failed and successful runs:

- `user-providers-03.log`: guest LDR/export traversal, IAT equality and actual
  resolved calls on x86/x64, plus storage/dependency foundation probes.
- `forwarder-02.log`: lazy forwarding, missing-module/export cleanup and cascade
  unload controls on both architectures.
- `process-exit-01.log`: normal/forced process exit and exact detach budget
  exhaustion, with direct static TLS reads from callbacks.
- `thread-lifecycle-01.log`: normal return, ExitThread, forced termination,
  suspended startup, faults and exact shared-budget exhaustion; direct thread
  IDs/static TLS/dynamic slots and parent LastError/frame restoration.

M3 completion (2026-11-11): all remaining checkboxes and the bounded M3 exit
are qualified. Unified catalog/LDR/export views, recursive VFS graphs and lazy
forwarders, static TLS for root/companions/new threads, normal/forced lifecycle,
nested callbacks/ABI/fault unwind and shared instruction/wall/resource admission
pass x86/x64 controls. The same-source frozen bundle passes 398 required outcomes
(328 prior controls plus 70 M3 lifecycle controls); all chained seals pass.
Source controls pass 1073 Rust tests, 163 accounting tests, four inventory tests,
partition/syntax, strict all-target Clippy and whitespace. Fresh dependency and
effective registration audits/checks pass. Final source index is
output/rust-pe-m3-complete/final-validation-04/index.json; independent package
seal: output/rust-pe-m3-complete/qualification-20261111/qualified-m3.json.
Build-source SHA-256: 084f1a7e7ed1f83e0fb915bc512a263a0a187a3deca5f2a0a7d2472a3470d99d.
All 2,590 API contracts remain unreviewed (1,809 missing/781 unverified); zero
semantic closures. M4 scheduling/waits/FLS and global M10 remain separate.
Review: docs/native-pe/m3-loader-lifecycle.md. No commit/push, supplied-sample
execution, host DLL search or security-setting change occurred.

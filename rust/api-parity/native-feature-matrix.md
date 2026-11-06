# Native PE migration surface

Source audit: 2026-11-03, starting revision
`92f258d48d8222b0e88c8bcb5bbd4198cc4095ba`. This is a finite scope/reachability
matrix, not semantic qualification. Every row applies independently to x86 and
x64 unless an architecture-specific proof is recorded. Nothing here closes an
API contract. `native-surface.json` freezes lexical inputs, installs, hooks and
report keys with source hashes; it does not prove effective registration.
Public input reachability refreshed on 2026-11-06 after the complete M2 exit;
the original audit revision above is historical, not the current checkout HEAD.

## Inputs and execution

| ID | Legacy contract / source | Rust implementation / public reachability | Owner and next control |
| --- | --- | --- | --- |
| N01 | Native EXE/DLL and guest arguments: `native.py::run_native`, `cli.py` | `user_input.rs::Request`, `user.rs::run`; admitted in bounded profile; source controls exist | M2: preserve both architectures through contained smoke |
| N02 | Explicit `--dll`, companion guest paths, static/dynamic imports and forwarders | Schema-2 hashed explicit DLLs through `run --inputs`; same-architecture native admission and submitted guest module paths | M2 qualified: docs/native-pe/m2-binding-exit.md; M3 owns full loader lifecycle |
| N03 | `--file`, `--files-dir`, launch bundle root and virtual file content | Explicit bounded byte snapshots through `--inputs`; guest parents, empty files and persona replacements use owned VFS; no recursive host import | M2 staging/M6: exact guest byte controls; no ambient host reads |
| N04 | `--guest-env`, `--guest-quote-arg` | Versioned overrides and zero-based forced quoting reach existing ProcessConfig | M2 staging: real guest environment/command-line controls; docs/native-pe/m2-input-staging.md |
| N05 | `--all-exports`, DLL attach and up to ten export calls | Opt-in frozen first-ten entry order, aliases, DllMain skip and ServiceMain arguments after normal startup; shared execution horizon | M2 staging/M3: contained selection/fault/budget controls; comprehensive attach/detach lifecycle remains M3 |
| N06 | Persona and generated enumeration programs/files | Persona hash validated; configured process initialized; generated legacy program/file equivalence unreviewed | M3/M6: contrasting personas and direct guest-memory observations |
| N07 | `--network-fixtures`, `--offline-replay`, NetworkBridge | Offline internal network models exist; submitted request has no fixture document binding | M7: explicit network-fixture semantics; M2 containment grants no host network |
| N08 | Instruction, wall-time, memory, output limits | Submitted instruction/time validated; parent output cap fixed; public memory/output options differ | M4/M8: run-wide accounting and bounded worker/controller failures |
| N09 | EXE/DLL load/relocation, imports/ordinals/data, delay load, module enumeration | Submitted companion/forwarder routes and prior import/data/delay/ABI controls are contained-package qualified; full lifecycle equivalence remains unreviewed | M2 binding/bounds/rollback and staged EXE/DLL import exit qualified; M3: direct-memory loader controls |
| N10 | CRT bootstrap, TLS callbacks, module attach/detach and termination | Root synthetic startup controls exist; full static TLS/PEB/TEB lifecycle equivalence unreviewed | M3/M5: compiler-style startup and thread/process isolation |
| N11 | Virtual children, threads, waits/APCs/FLS/callback continuation | Internal kernel scheduler is not evidence of full user scheduling | M4: two-thread TLS/error/wait/callback programs with shared budgets |
| N12 | SEH/VEH, x86 chains and x64 unwind | Core/engine unwind tests exist; full baseline user exception routes unreviewed | M4: nested guest faults and continuation, separate engine errors |

## Non-API hooks and observations

| ID | Legacy contract / source | Rust implementation / public reachability | Owner and next control |
| --- | --- | --- | --- |
| N13 | CPU identity/time/instruction observation and mapped-file write hooks | CPU and filesystem models exist; exact legacy hook closure unreviewed | M6: instruction/cache/protection and persona observations |
| N14 | Memory IP/URL/custom-regex capture, `--no-memory-strings` | Native string models/corpus are not memory scanning; request has no capture configuration | M6/M8: scan ordering, limits, regex admission and omissions |
| N15 | File/drop/memory/PE-carving artifacts, group/context attribution | Worker saves artifact bytes; controller verifies artifacts; legacy carving/group/context semantics unreviewed | M6/M8: overwrite/delete/exit bytes and remote-write attribution |
| N16 | `engine-report.json`, API coverage/signature-only refusal, entry points and terminal reason | Versioned result/manifest and execution events exist; exact legacy schema/event/error mapping unreviewed | M8: normalized cross-generation observations; never silently drop fields |
| N17 | Console and CRT streams, registry/network/process/environment/adapter/feature events | Individual models exist; report extraction must be audited independently | M5-M8: shared-state and serialized report controls |
| N18 | Native-facing CLR/MSI declarations and conditional/ordinal overrides | Source review identifies literal-zero CorExitProcess and MsiDatabaseMergeA/name+ordinal placeholders on both arches; six contracts retained | M7: qualify placeholders without claiming general CLR/MSI or process-exit semantics |
| N19 | Public CLI -> contained worker -> parent verification/cleanup | Fresh same-build M2 staging package passes 172 contained executions and 58 admission/direct-worker refusals, with independent exact-byte sealing | M2 fifth-checkbox/M9/M10: comprehensive binding, tamper/interruption and operational qualification remain separate |
| N20 | Effective install order and overridden/conditional registrations | Source-reviewed: 24 installers, 514 hooks per arch, exact/wildcard chains, constructor/original references, shadowed declarations, conditional post-load LdrUnloadDll tuple | M0 source review complete: docs/native-pe/effective-registration-review.md; guest behavior still requires qualification |

## Frozen lexical install sequence

`bridge`, `virtual_files`, `console_output`, `crt_streams`, `crt_startup`,
`guest_environment`, `ui_language`, `win_messages`, `version_info`,
`guest_strings`, `guest_delay_imports`, `guest_tokens`, `guest_lsa`, `guest_audit`,
then x64 operator-delete override, `heap_checks`, `guest_network_adapter`,
`guest_dns`, `guest_icmp`, `guest_feature_configuration`, `virtual_registry`,
`virtual_process`, PID and comctl32 ordinal overrides, `clock`, `cpu`,
`guest_identity`. Later loader/module/toolhelp overrides are separate hook sites.
Constructors, guards, aliases and original-handler delegation are recorded in the
source-only N20 review. Both arches queue 493 hooks before loading and add 21
afterward; supported functions run all matched hooks, not only the last one.

## Evidence boundaries

- The frozen legacy AST inventory currently matches 82 source hashes: 806
  Speakeasy declarations plus 514 extension declarations; zero unresolved static
  sites does not close N20.
- Public reachability above is source-derived from `user_input.rs`, `user.rs`,
  `user_controller.rs`, `user_worker.rs` and CLI option parsing, not inferred from
  an internal engine fixture.
- No legacy pipeline import, submitted sample execution, host Windows export
  invocation, quarantine restoration, or security-policy weakening is needed
  for this matrix. Static dependency self-consistency now has a separate verifier,
  `tools/native_pe_baseline.py`; consult its current source-bound report. Matching
  hashes do not establish independent authenticity or remove package/security blockers.

# Native user PE execution

Build and package the Rust workspace:

```powershell
.\tools\build_rust.ps1 -Release
.\tools\package_rust.ps1 -Destination output\rust-user-bundle
.\output\rust-user-bundle\emumee-rs.exe run sample.exe --output output\sample-run -- arg1 "two words"
```

`run INPUT --output FRESH_DIRECTORY` admits submitted native x86/x64 EXE and
DLL images. Options are `--persona JSON`, `--max-instructions N` (default
100,000,000), and `--timeout-us N` (default 120,000,000). Arguments after `--`
become guest arguments. The output directory must be new and outside the frozen
bundle. Ordinary build-tree binaries cannot launch this role.

The controller stages bounded PE bytes and a strict hashed request. A dedicated
offline AppContainer worker with a one-process 1024 MiB job and blocked child
process creation verifies containment before reading inputs. Input/request files
are read-only to that worker; only `worker/` receives a write grant. The parent
verifies result bindings, containment and content-addressed captured artifacts
after restoring grants. Guest code runs in Unicorn, never through a host loader.

Native execution uses the Rust PE loader, Windows API models, guest filesystem,
registry, heaps, clock, CPU identity, process arguments and environment state.
TLS callback and DLL process-attach startup use the existing bounded loader.
Default persona time is explicitly seeded in the request; an explicit persona
clock takes precedence. JSON reports preserve configuration coverage limits.

Reports are `manifest.json` and `worker/result.json`, with captured data in
`worker/artifacts/`. Exit status zero means modeled entry/startup completed;
unsupported behavior and budget stops return nonzero while retaining the report.
A guest return value is an observation, not the controller exit status.
`ExitProcess` and `RtlExitUserProcess` stop the modeled process, retain the full
32-bit `process_exit_code`, and report `process_exit` with no invented entry return.
This bounded termination does not run Windows DLL detach callbacks.
The return/UINT exit-code distinction follows Microsoft's
[ExitProcess contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess);
the documented detach and full process lifecycle are not claimed by this profile.

This entrypoint does not establish full Python/Speakeasy compatibility. Managed
assemblies, drivers, export-as-entry execution, general static companion staging,
storage TLS, arbitrary Windows APIs and a general Windows process runtime remain
outside this submitted native profile. Drivers retain `submitted-driver`; managed
IL retains its separate bounded fixture/interpreter path. Unsupported imports
stop explicitly. Python is not invoked by this path.

Generate harmless qualification fixtures through the engine tests and verify a
fresh same-build bundle:

```powershell
$env:EMUMEE_USER_TEST_FIXTURES = "$PWD\output\rust-user-pe-fixtures"
.\tools\build_rust.ps1 -Validation -Test -Package emumee-engine -TestFilter submitted_user
.\tools\verify_rust_user_pe.ps1 -Bundle output\rust-user-bundle -Fixtures output\rust-user-pe-fixtures -OutputRoot output\rust-user-qualification
```

Local qualification on 2026-10-29 passed 473 core tests, 422 serial engine tests,
strict workspace/all-target Clippy, a release build and 16 contained native PE
cases, plus direct-worker and invalid CLI refusal controls. The frozen bundle is
`output/rust-user-pe-bundle-20261029a`; evidence is in
`output/rust-user-pe-qualification-20261029b/verification.json`. A parallel full
engine test attempt aborted on a large allocation; the complete serial suite
passed with unchanged source. This evidence covers the harmless controls, not
representative malware compatibility.

## CRT startup parity

The next API family adds `__getmainargs`, `__wgetmainargs`, `__p___argc`,
`__p___argv`, `__p___wargv`, `_get_initial_narrow_environment`,
`_get_initial_wide_environment`, `_initialize_narrow_environment`,
`_initialize_wide_environment`, `_configure_narrow_argv`, `_configure_wide_argv`,
`_initterm`, and `_initterm_e`, including bounded UCRT/API-set aliases.
Arguments and environment arrays contain guest pointers with explicit NULL
sentinels, CP1252 or UTF16 strings, and retained RW/NX backing. Virtual memory
operations cannot free, recommit or change protection on CRT-owned backing.
The initial environment snapshot is captured before guest entry and is distinct
from mutable Win32 environment state and its double-NUL string blocks.
MSVCRT and UCRT retain separate argument/environment backing; mixing the two
does not create shared mutable CRT globals. UCRT API-set aliases refer to the
same modeled UCRT state.

Initializer callbacks execute actual guest instructions and share the run's
instruction/wall horizon. NULL entries are skipped, `_initterm_e` stops at the
first nonzero return, and table changes made by earlier callbacks are observed.
Pending API/callback evidence remains pending on budget stops or faults.
Callback return frames and nonvolatile state are checked. No host CRT or callback
address is invoked. The contracts follow the installed Windows SDK CRT headers
and Microsoft's [main-argument](https://learn.microsoft.com/en-us/cpp/c-runtime-library/getmainargs-wgetmainargs)
and [initializer](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/initterm-initterm-e) references.

This remains a bounded startup profile: wildcard expansion, argv modes other
than unexpanded arguments, nondefault startup new-mode, initializer reentrancy,
and general CRT teardown are explicit unsupported boundaries.
Global accessors bind to UCRT on both architectures and MSVCRT on x86, matching
the installed CRT export profiles. Legacy data-import globals remain separate
loader parity work.

To regenerate and qualify the CRT controls against a fresh same-source bundle:

```powershell
$env:RUST_TEST_THREADS = '1'
$env:EMUMEE_CRT_STARTUP_FIXTURES = "$PWD\output\rust-crt-startup-fixtures"
.\tools\build_rust.ps1 -Validation -Test -Package emumee-engine -TestFilter crt_startup -Jobs 1
.\tools\verify_rust_crt_startup.ps1 -Bundle output\rust-crt-startup-bundle -Fixtures output\rust-crt-startup-fixtures -OutputRoot output\rust-crt-startup-qualification
```

The 2026-10-29 CRT bundle is `output/rust-crt-startup-bundle-20261029a`.
Qualification passed 475 core tests, all five CRT engine suites, strict Clippy,
the release build, 41 contained CRT controls and 16 contained native regressions.
Evidence is in `output/rust-crt-startup-qualification-20261029a/qualification-summary.json`.
The full engine suite reports 433 passed and one failing owned-paging kernel IPI
test (`generated_thread_and_ipi_handoffs_retain_the_owned_paging_domain`), which
also fails in isolation. That kernel gate is still open; the native CRT controls
do not establish kernel paging or full API parity.

## Full API parity work

The frozen declaration baseline and its limitations are documented in
[`api-parity/README.md`](api-parity/README.md). Full API parity is incomplete.
Current source adds owned current-process handles and rights checks, guest
process-memory and virtual-memory operations, TLS/FLS slots, recursive critical
sections, startup/system/version/memory/processor information and module paths.
Other processes, blocking synchronization and general user scheduling remain
open; FLS callbacks retain the legacy placeholder limitation.

The Windows string profile now includes bounded ASCII comparison and search,
in-place case mapping and trimming, CP437/CP850/CP1252/UTF8 conversions,
OEM/Unicode detection and API-set queries. Unsupported cases remain visible in
`string_api_unsupported`. Tests compare 428 trusted legacy string observations
across both pointer widths, plus four actual native PE controls. Fourteen native
runtime controls inspect guest outputs and failure/ownership behavior.
These are source-test results; the older packaged CRT bundle does not contain
these new APIs.

The previously failing paging/IPI regression paired a twelve-processor guest
program with a six-processor configured persona. Matching the test persona to
the program resolves its early INT3 while retaining all paging and IPI checks.
This fixture correction changes no production exception or paging behavior.

Current source verification passes 478 core tests, all 438 engine tests, three
static-inventory tests and workspace Clippy. Engine Clippy also passes after the
last TLS/FLS GetValue2 correction. Zero-valued and invalid GetValue2 results
preserve last error, following the
[TLS GetValue2 contract](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-tlsgetvalue2).
The current ledger records 1,829 missing bindings and 761 bindings awaiting
semantic qualification across both architectures. Binding presence alone does
not close a parity contract; fresh packaged qualification remains outstanding.

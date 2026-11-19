# M5 CRT and allocation foundations

Started 2026-11-19 from committed M4 (`2f2dc98`). The four M5 obligations and the
milestone exit criterion are complete and qualified as described below. This
certifies no API partition row: all 566 contracts in these families stay open in
the ledger, and global qualification gates remain open.

## Partition coverage

All 566 contracts in the `crt`, `crt-format`, `crt-math`, `crt-stdio`,
`allocation` and `strings` families are dispatched: 559 modeled and 7 reviewed
explicit refusals, with none left unmodeled. Before this milestone 149 of those
exports had no binding at all. Dispatcher coverage is not per-row semantic
evidence: every one of the 566 contracts stays open in the ledger, and
`inspect-api-surface` reports the classification, not parity.

The seven refusals are `msvcrt!_CxxThrowException`, `msvcrt!_EH_prolog` and
`msvcrt!_ftol` on both architectures, and `msvcrt!_except_handler4_common` on
x64. Their reasons are in the runtime-services section below.

## Existing implementation audit

The existing `crt_startup`, `crt`, `crt_format`, `crt_math`, `crt_stdio`,
`heap` and `allocation` models are retained. They already cover bounded startup
arrays and nested guest initializers, subsets of strings/formatting/math/stdio,
and Win32 heap/virtual-memory planners. The frozen string reference corpus is
unchanged. Those bindings and their prior controls do not establish full M5
semantic coverage.

The frozen installed `msvcrt.py` implements `malloc`, `calloc`, `free`,
`??2@YAPAXI@Z` and delete aliases. These were missing from the Rust dispatcher.
The exact existing batch is
`api:allocation:msvcrt:function:642bd05e5ebd0418`; its membership and evidence
requirements remain unchanged. No frozen source or inventory was refreshed.

## Initial CRT allocation batch

`api/crt_alloc.rs` delegates to the existing guest heap planner/application path.
MSVCRT and UCRT have distinct lazily created heap ownership within each process's
API state. UCRT and `api-ms-win-crt-heap-l1-1-0`, including `_o_` aliases for
these functions, share the UCRT family. Calls use CDECL on x86 and the Windows
x64 ABI. The baseline C++ new/delete spellings share MSVCRT ownership.

Allocations use guest RW/NX reservations, page alignment, deterministic zeroed
backing and existing per-block/count/mapped-memory limits. `calloc` checks its
product against the guest pointer width before planning memory. Resource failure
returns null; it does not modify Win32 last-error. `free(NULL)` is a no-op. Zero
size allocations retain the existing non-null bounded heap convention; zero size
baseline operator new requests one guest pointer width.

Only exact live pointers from the matching runtime family may be freed. Interior,
already freed, foreign and emulator-owned pointers stop explicitly. Guessed CRT
heap handles cannot bypass ownership through Win32 heap APIs; VirtualFree retains
its existing heap-owned reservation refusal. These strict invalid-pointer and
family boundaries are model policies, not a claim of exact legacy allocator or
Windows heap equivalence. General new-handler/exception behavior remains open.

## CRT data globals and the imported command line

`api/crt_startup/command_line.rs` publishes one process-owned, page-aligned RW/NX
`msvcrt._acmdln` cell. The imported data slot, the PE export walk,
`GetProcAddress` and `__p__acmdln` all resolve to that single address, so guest
mutations through any of them are observed by the others, by new threads and by
later lookups. The cell holds a guest pointer to its own trailing bytes, matching
the frozen `_acmdln` layout; its contents are the frozen join of the CRT argument
view, not the Win32 quoted command line, preserving the existing baseline
difference between `_acmdln` and `GetCommandLineA`.

Emulator-owned startup storage cannot be retired by the guest: `VirtualFree`,
`VirtualProtect` and CRT `free` on the cell stop explicitly, and the cell stays
non-executable, so calling through it raises an execute fault at its own address.
Child processes publish their own cell in their own address space; the same
virtual pointer in parent and child refers to distinct storage, and a child
mutation never replaces the parent's bytes.

### CRT argument view for processes created with a raw command line

`Persona::crt_argv` was added because a process created through `CreateProcess`
carries a supplied command line and no configured argument list. Its CRT
arguments were previously the image path alone, so `_acmdln`, `argc` and `argv`
in a child disagreed with its own command line. The frozen reference resolves
this by preferring an explicit argument list and otherwise splitting the command
line (`shlex.split(text, posix=False)`), and `crt_argv` now follows it.

`persona::split_command_line` implements that splitter exactly: whitespace
separates tokens, a quote only opens a quoted run at the start of a token, the
closing quote ends that token and both quote characters remain inside it. It is
not the Microsoft CRT parser that `persona::command_line` inverts, and the two
are deliberately not round trips. Generated reference vectors are asserted in
`persona.rs`. Bounded refusals: an unterminated quote and more than
`MAX_ARGUMENTS` tokens are rejected with Win32 87, which fails child creation
rather than closing the quote silently; real Windows would accept such a command
line, and the frozen reference raises. A command line holding no token at all
keeps the bounded image-rooted view instead of the reference's empty vector.

Image identity still comes from `Persona::argv`, so a command line whose first
token is not the image path cannot redirect the module, the process record or the
PEB. Win32 `GetCommandLineA/W` continue to serve the stored command line.

## Verification and limits

Every obligation above is decided by guest instructions or by a compiler-produced
program, never by inspecting model state alone. The eight control families emit
110 contained outcomes, 55 per architecture:

| Family | Controls per architecture | What the guest decides |
| --- | --- | --- |
| `crt-data` | 12 | Imported data, accessor and lookup agreement, mutation, thread sharing, child isolation, free/protect/execute refusals, budget stops |
| `win-alloc` | 8 | Global/Local blocks, sizes, flags, handles, locks, reallocation, heap validation, address probes, region queries, foreign/interior/owned refusals |
| `crt-runtime` | 10 | Stable global cells and their setters, exit-function order and execution, exit codes, lock balance, reentrancy and unmodeled-mode refusals |
| `crt-text` | 6 | Concatenation, spans, searches, case mapping, conversions, tokenizer continuation, clock text, locale state, refusals |
| `win-text` | 6 | lstr copies and comparisons, character types, case mapping, address text, message formatting with inserts and allocation, refusals |
| `crt-service` | 6 | Narrow formatting and scanning, generator sequence, signals, command refusal, clock readings, control word, filter literals, refusals |
| `crt-file` | 5 | Stream open, read, position, write, close over the virtual file system, console output, access and mode refusals |
| `compiled` | 2 | A compiler-produced CRT program end to end, and a compiler-produced negative control |

`tools/native_pe_m5.py` replays and independently checks all 110 contained
controls against the packaged worker, with `tests/test_native_pe_m5.py` guarding
the control set. Guest instruction assertions determine success: a wrong value
raises a breakpoint inside the guest, and the compiled program reports a distinct
exit code for each contract it checks.

`crt_alloc_probe` builds harmless owned x86/x64 PE callers. Three focused Rust
tests exercise 30 guest outcomes across both CRT families and UCRT API-set aliases:
actual buffer zeroing/alignment, CDECL caller cleanup, C++ zero-size new/delete,
allocation overflow/failure, preservation of a live block on failure, interior
and double frees, cross-family frees, guessed Win32 heap frees and VirtualFree.
Guest instruction assertions determine success; tests also inspect live-block
counts and API-event completion. These three remain source-only controls: they
run in the engine test suite and are not part of the contained replay set, whose
allocation coverage comes from the `win-alloc` family and the compiled programs.

Earlier receipts under `output/rust-pe-m5-alloc-20261119` and
`output/rust-pe-m5-data-20261119` are retained development evidence for the first
two batches; they predate the later batches and no longer match the current
source. The current receipts are
`output/rust-pe-m5-complete-20261119/source-validation-final/index.json` and the contained replay seal
`output/rust-pe-m5-complete-20261119/qualified-m5.json`. Only a passing, independently checked
current-source index establishes source validation; missing or failed output is
not proof. Existing M4 bundle and seals remain historical, matching their own
source. This replay covers the M5 obligations and their exit criterion; it is not
per-row semantic API parity, package matrix qualification or M10.

To recheck the sealed milestone from the repository root:

```powershell
C:\Python313\python.exe tools/native_pe_m5.py --root output/rust-pe-m5-complete-20261119 --source-index output/rust-pe-m5-complete-20261119/source-validation-final/index.json --check
```

## Win32 allocation families

`api/win_alloc.rs` completes the Win32 allocation partition on the existing
process heap and private reservation models. `GlobalAlloc`/`LocalAlloc` and their
size, flags, handle, lock, unlock, free and reallocation spellings are process
heap blocks, so a block allocated by one family is accepted by the others
exactly as modern Windows accepts it. Handles and pointers coincide because
nothing relocates: `GMEM_MOVEABLE` is accepted and ignored along with the other
legacy no-op bits, while discardable and modify requests stop explicitly rather
than pretending to keep discard state. `LocalReAlloc` without `LMEM_MOVEABLE`
cannot relocate, so a grow that does not fit reports failure and leaves the
original block intact.

`HeapValidate` proves membership and liveness of a block in a known heap and
leaves the last error untouched; without Windows heap headers it is not an arena
consistency claim. `RtlSizeHeap` accepts a null heap, and returns the pointer
width's all-ones value for an unknown heap, a retired block or an interior
pointer. `HeapSetInformation` accepts the documented information classes and
changes nothing, because the synthetic heaps carry no compatibility,
corruption-termination or resource-optimization state.

`VirtualQuery` reports MEMORY_BASIC_INFORMATION in the exact Windows layout,
including both x64 alignment holes, so compiler-produced callers see the 28 and
48 byte sizes they expect. Region runs stop at reservation boundaries and
wherever commitment or protection changes; backing this model did not reserve is
one committed region, reported as MEM_IMAGE when its mapping is an image, and
free space extends to the next mapped or reserved address.
`VirtualAllocExNuma` accepts only the current-process pseudo handle at the
guest's own width and a preferred node of zero or NUMA_NO_PREFERRED_NODE.
`IsBadReadPtr`/`IsBadWritePtr` check the whole requested range rather than the
reference's first and last byte, and keep the reference's answer that a zero
byte count is bad. `IsBadStringPtrA/W` stop at the terminator as Windows does,
bounded to one million characters.

Global, Local and CRT free paths all refuse emulator-owned backing: a free of
CRT startup storage, of an interior pointer or of a block belonging to another
heap stops explicitly instead of retiring memory the emulator owns.

## CRT startup, teardown and exit-time state

`api/crt_startup.rs` now owns the process-wide CRT globals as single mutable
cells. `__p__commode`, `__p__fmode` and `__p___initenv` hand back the same
address on every call, so a guest store is observed by every later read, and
`_set_fmode` writes the cell the accessor publishes instead of a private copy.
`__p___initenv` holds the same narrow array the initial environment accessors
publish. The legacy `__p___argc`, `__p___argv` and `__p___wargv` globals are
served on both architectures, and the configure/initialize environment and argv
entry points are no longer restricted to the modern runtime.

Exit-function registration is real. `_initialize_onexit_table`,
`_register_onexit_function`, `_crt_atexit`, `_onexit` and `__dllonexit` record
their targets in process state, and `exit` runs them in reverse registration
order as actual guest calls through the existing checked-callback path, from
emulator-owned NX storage the guest cannot retire, before the process exits with
the requested code. `_cexit` runs them and then terminates, and `_exit`,
`_c_exit` and `terminate` terminate without running them; the reference
terminates for all five, and the documented abort code is what `terminate`
leaves behind. Exit reentrancy stops explicitly, including from inside a
teardown callback. `_register_thread_local_exe_atexit_callback` is recorded and
never invoked, which the teardown order controls prove.

`_lock`/`_unlock` track CRT lock depth so an unbalanced release stops instead of
passing silently, while nesting stays legal because the real locks are recursive.
`_configthreadlocale` reports the process-wide default and refuses to enable
per-thread locales. `_set_new_mode`, `_set_invalid_parameter_handler`,
`_setusermatherr`, `__setusermatherr`, `__set_app_type`, `_set_app_type` and
`_adjust_fdiv` record or validate their arguments, and the new-handler
allocation mode stops explicitly because a failed allocation would otherwise
have to call a handler this profile does not model.

## Strings, conversions, locale and formatting

`api/crt_strings.rs` completes the legacy CRT text partition: concatenation and
its counted and secure spellings, spans, substring search, the legacy
two-argument `wcstok` with per-thread continuation and in-place delimiter
overwrite, case-insensitive comparison and in-place case mapping, character
classification, `atoi`, the radix formatters, narrow/wide conversion including
the secure and single-character forms, the CRT date and time strings and
`setlocale`/`_wsetlocale`. Scans and writes are bounded to 8,192 characters and
65,536 output bytes, matching the frozen CRT extension. The comparison helpers
return the real sign rather than the reference's equal-or-one answer, `tolower`
and `toupper` leave characters without case alone instead of setting bit five,
and the radix formatters produce digits where the reference wrote nothing.
Locale categories are process state; only `C` and the persona locale exist, and
any other request stops explicitly. The date and time strings derive from the one
persona clock through the existing kernel time conversion, with no host date,
timezone or daylight rule.

`api/winstrings.rs` gains the Win32 side: `lstrcat`, `lstrcpy`, `lstrcpyn`,
`lstrcmp` and `lstrcmpi` in both widths, `GetStringTypeA`, `GetStringTypeWA` and
`GetStringTypeWW` CT_CTYPE1 classification, `LCMapStringA`, `LCMapStringW` and
`LCMapStringEx` invariant case mapping with the documented zero-capacity length
query, and `RtlIpv4AddressToStringExW`. Sort keys, normalization, width folding
and any other information type stop explicitly rather than inventing an
ordering. The frozen string reference corpus is unchanged and still passes.

`api/win_messages.rs` adds `FormatMessageW` over persona message text: the
module's system message table, caller templates, message-table control escapes,
`%N` and `%N!spec!` inserts from guest string pointers, the insufficient-buffer
and unknown-identifier results, and allocation from the same process heap
`LocalFree` releases. Message resources read from a module image are refused
explicitly.

`api/crt_format.rs` completes narrow formatting: `printf`, `fprintf`, `sprintf`,
`_snprintf`,
`_vsnprintf`, `_snwprintf` and `__stdio_common_vsprintf`, plus the legacy
module's `__stdio_common_vfprintf`, all through the existing bounded grammar and
a narrow write planner that mirrors the wide one. The common entry points accept
the all-ones count the unbounded spellings pass. `sscanf` is a real bounded
scanner over whitespace, literals, suppression, field widths, length modifiers
and the integer, character and string conversions; every destination is checked
before anything is written, and an unmodeled conversion is refused rather than
skipped. The reference leaves `sscanf` as a no-op with an undefined result.
`printf` and `fprintf` reach the modeled console for a standard stream and the
guest's own virtual file for an opened one. They were previously refused as a
family, so one existing negative control was deliberately rebaselined: a null
FILE pointer is now refused for being a nonstandard stream rather than for the
family being unmodeled. The control still refuses, and no failure was removed to
make a suite pass. The frozen string reference corpus is untouched.

## CRT runtime services and file streams

`api/crt_misc.rs` models the remaining runtime services. `rand`/`srand` use the
documented Microsoft generator rather than the reference's counter, so a seeded
guest sees the real sequence. `signal` records handlers and reports SIG_IGN for
the known signals and SIG_ERR otherwise; no CRT signal is ever delivered.
`system` records the requested command and refuses it, because no command
processor exists. `time` derives legacy 32-bit epoch seconds from the one
persona clock and `clock` reports milliseconds since the first reading. `abs`,
`_controlfp` and `_controlfp_s` are modeled, with the default control word for
each architecture; a request that would actually change rounding, precision or
exception masks stops explicitly. The exception filters and handlers whose frozen
behaviour is a documented literal (`_XcptFilter`, `__CxxFrameHandler`,
`_except_handler3`, `_seh_filter_dll`, `_seh_filter_exe`,
`__current_exception`, `__current_exception_context`) return those literals.

Four rows are reviewed explicit refusals instead of models, because the frozen
behaviour cannot be reproduced without a model this profile does not have:
`_CxxThrowException` (returning from a throw would let the guest continue past
code that never continues on Windows), `_EH_prolog` (an x86 C++ frame is
pointless and dangerous without that dispatcher), `_except_handler4_common` on
x64 (scope-table dispatch is an x86 mechanism), and `_ftol` (the real helper
converts an x87 stack value, and the reference's integer argument is not that
contract).

`api/crt_stdio.rs` adds opened file streams. `fopen` and `_wfopen` parse the
documented mode strings, resolve the path through the existing virtual file
system and bind one page-owned FILE structure, in the legacy `_iobuf` layout,
to that handle; `fread`, `fseek`, `ftell`, `fputc`, `fflush`, `_fileno` and
`fclose` operate on it, and `puts` and console `fputc` reach the existing
console model. Reads report whole items as the C contract requires, a stream
opened for writing refuses reads, and an unknown FILE pointer stops explicitly.
Unmodeled mode suffixes are refused rather than guessed. The FILE page stays
mapped after `fclose` so a pointer the guest still holds cannot alias new
storage.

## Compiler-produced exit criterion

`tools/build_guest_crt_programs.ps1` builds `src/emumee/guest_native/crt_program.c`
and `crt_refusal.c` for x86 and x64 with the installed MSVC toolchain. The import
library is generated from a module definition listing only exports this profile
models, so the programs bind legacy `msvcrt.dll` instead of the host toolchain's
own runtime. `crt_program` reads its argument count, vector and command line
through the CRT accessors, allocates and releases heap memory, concatenates and
compares strings, formats with `sprintf` through the modern `__stdio_common_vsprintf`
inline the compiler emits, opens a staged guest file and reads and positions it,
writes to the console, registers an exit function and exits with a known code.
Every failure path returns its own code, so a wrong model shows up as that exit
code rather than as a crash. `crt_refusal` asks for the new-handler allocation
mode and must stop explicitly.

Both programs run on both architectures: `crt_program` exits with code 7 after
its registered teardown function has run and produced console output, and
`crt_refusal` stops with its documented reason. These are real compiler output,
including compiler-chosen intrinsics, prologues and x64 unwind data, not
instruction fixtures.

## Remaining work in order

The four M5 obligations are covered by the batches above: the imported CRT data
export and its aliases, the heap, local, global and virtual allocation families,
the startup, teardown, atexit, reentrancy and state-separation contracts, and the
string, conversion, locale, formatting, numeric and file/stdio contracts. The exit
criterion is met by compiler-produced programs and negative controls on both
architectures. The frozen string reference corpus is preserved unchanged.

These remain open and are not part of M5:

1. CRT `realloc`, aligned allocation and the broader C++ allocation contracts,
   which no partition row in this milestone covers.
2. C++ and x86 scope-table exception dispatch, behind the four reviewed refusals
   above. Message-table resources read from a module image belong with the
   resource family.
3. Per-thread CRT locales, non-invariant locale data, sort keys, normalization
   and width folding.
4. Per-contract semantic closure for all 566 partition rows in these families.
   Dispatcher coverage and guest controls are not the same thing as the
   independent per-row evidence the ledger requires; every row stays open.

No commit, push, submitted sample, host-native guest execution or legacy guest
fallback is part of this checkpoint.

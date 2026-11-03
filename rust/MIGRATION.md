# Rust replacement

Submitted native user PE execution is now implemented through `run INPUT
--output FRESH_DIRECTORY`, using the contained offline worker, request-bound
persona/process state, existing native TLS/DllMain loader and Rust API models.
`ExitProcess`/`RtlExitUserProcess` publish an explicit full-width process exit code.
See [USER_PE.md](USER_PE.md) for invocation, qualification and remaining limits.
This is bounded native execution, not a claim of complete legacy model parity;
managed user admission and general companion staging remain separate work.

The next native API batch models CRT startup:MSVCRT mainargs, UCRT argument
globals and initial environment/configuration, MSVCRT x86 global accessors, and
real `_initterm`/`_initterm_e` guest callback walks. Runtime-owned arrays are
separate across MSVCRT/UCRT, callbacks share the outer execution horizon, and
pending/fault evidence is retained. See USER_PE.md for exact scope and controls.

This is an active application migration, not a feature-complete replacement or
a Python launcher. Submitted-driver profiles require separate, same-build
containment qualification. Source checks and bounded fixture results do not
establish complete driver initialization or broad compatibility. See
[release readiness](../docs/release-readiness.md) for the current release gate.

The Cargo workspace separates bounded parsing/deterministic guest state
(`emumee-core`), CPU execution and Windows models (`emumee-engine`), and the
CLI (`emumee-cli`), host boundary (`emumee-platform`) and dedicated restricted
process (`emumee-worker`). Unicorn2.1.5 is built from its pinned Cargo source with only
x86 enabled. The executable and its native Unicorn DLL use no Python runtime.
The DLL configuration avoids an upstream unused legacy-archive symlink step
which requires privileges on Windows. Third-party licenses remain applicable.

Implemented and checked so far:

- Checked x86/x64 PE classification, sections, imports, image materialization,
  and HIGHLOW/DIR64 relocation handling. Malformed-layout and every-truncation
  fixture tests pass; broader input parity is still pending.
- Direct Rust instruction hooks with a fixed128-entry trace ring, exact
  instruction budgets, section page permissions and generated DriverEntry
  fixtures. Both architectures return the expected values and stop on
  execute/write protection violations.
- Guest CPU-cycle/virtual-clock state, QPC/TSC accounting and shared-time-page
  encoding. Guest time advancement does not wait for host time.
- Packaged offline AppContainer fixture execution with a one-process,
  kill-on-close memory-limited job; child mitigation verified before input
  reads; zero network capabilities; bounded request/result reads and restored
  DACLs. x86/x64 fixtures return expected values, a32-instruction budget stops
  exactly, altered worker/DLL files are rejected before launch, and the worker
  refuses direct uncontained execution. Bundle7 audit:4 directories,16 files,
  no residual grants, journals or worker processes. The startup sequence must
  match the existing launcher: setting child mitigation at CreateProcess time
  caused pre-main DLL initialization failures on this host; job limits apply
  during startup and worker mitigation activates before input processing.
- Controller and worker embed the same build-time source fingerprint. Packaging
  rejects stale binaries before creating a new bundle. Earlier diagnostic
  bundles1–3 predate this source-binding gate and remain unqualified evidence.
- Native Windows API dispatch with integer/pointer calling conventions,
  thread error state, bounded memory/string operations and no-input DbgPrompt.
  Unsupported calls stop explicitly. Argument faults retain error observations.
- Guest private reserve/commit/decommit/release and page protection, allocation
  boundaries, zeroed recommitted pages and preserved bytes on ordinary recommit.
  A harmless native Windows reference verified that recommit reapplies protection.
  Large page changes use a batch rather than a call per page.
- Bounded PE named/ordinal exports and forwarders, guest module catalogs and
  real companion export execution in both architectures. Missing exports and
  cycles stop. DLL initialization, arbitrary companions, relocatable module
  placement, dynamic lookup and Windows provider PE exports remain pending.
- In-memory guest files with independent cursors, shared bytes, sparse writes,
  append rights, sharing checks and process ownership. Initial synchronous
  CreateFileA/W, ReadFile, WriteFile, SetFilePointer, GetFileSizeEx and CloseHandle
  models pass CPU fixtures, including x64 arguments beyond the four registers.
  Guest filenames are metadata and never become host filesystem destinations.
- Content-addressed captured file artifacts, duplicate-content observations,
  explicit capture limits/omissions, worker writes and parent hash/size checking.
  Parent negative tests reject path escapes, oversized files and altered bytes.
  Memory snapshots are a separate evidence kind and do not imply unpacking.

Initial kernel IRQL, guarded mutex ownership and critical-region APIs are now
ported, including blocking waits on mutexes owned by modeled live threads.
The scheduler state model covers FIFO/priority readiness, mutex handoff,
manual/auto-reset events, atomic wait-all consumption, virtual deadlines and
explicit deadlocks. The execution adapter saves independent Unicorn contexts
and stacks for PsCreateSystemThread, applies a global instruction/time budget,
and handles thread return/termination. Initial system-thread critical regions
follow the documented Windows contract. Contexts are initialized through the
detached Context API; restoring the live CPU inside its API hook re-executed
the call gate, which the thread-count fixture caught and the final version fixes.
Runtime mutex continuations now suspend the caller and resume it only after
the actual guest owner releases the lock. The API is dispatched once and its
RET is counted when it resumes. A two-thread/two-lock cycle reports deadlock
with both API waits unresolved. Unknown or inconsistent ownership still stops.
Native starts now run at most4096 instructions and share an outer wall deadline;
multi-thread quanta still stop at256 instructions. This removes Unicorn's
per-start host-watchdog thread creation/join for single-thread continuations too.
A CPU that halts before its slice ends stops explicitly, and source tests cover
wall deadlines, exact budgets and completion across multiple native slices.
General dispatcher timer/DPC waits and full kernel object layouts
remain pending; generated synchronization fixtures do not establish vgk
compatibility or a real-driver scheduling result.

Deterministic guest CPUID identity/topology/cache/frequency leaves and direct
RDTSC/RDTSCP/XGETBV now execute through Rust models. Unknown CPUID leaves return
zero and unsupported XGETBV indices stop explicitly. Full-width writes clear
the upper halves of x64 results. A bounded256-page instruction classifier avoids
reading instruction bytes through FFI on each instruction. Guest stores to RWX
pages, model writes and allocation/protection changes invalidate affected pages,
including instructions crossing page boundaries. RX pages need no store callback;
protection changes invalidate them before they can become writable. Generated
probes check exact budgets and rewriting CPUID into RDTSC during execution.

Kernel fixture entries now initialize CPL0 code/data descriptors, FS/GS KPCR
access, PRCB/current-thread pointers, queued-lock backing, virtual-TLB paging,
CR0/CR4/EFER and x64 STAR/FMASK. API IRQL changes and context switches update
the processor's thread/IRQL fields. Guest probes read those fields and CPU
registers directly. Clearing CR0.WP does not grant writes to RX guest regions.
Typed native descriptor/MSR buffers use the pinned C ABI; scalar register
buffers and the binding's incorrectly sized GDTR/IDTR read helper are avoided.
Validated x64 CPL0 SYSCALL transitions can enter guest-provided executable LSTAR
code with modeled selectors and RCX/R11/flag updates. Unsupported entry/return
forms and invalid targets stop with a bounded attempt trail. Guest probes verify
the transferred control and registers, and every intermediate instruction budget.
This is initial processor context, not full ETHREAD/process layouts, hardware
page-table walks, TSS/IDT exception delivery or a Windows syscall dispatcher.

Win32 QPC/frequency/FILETIME and initial kernel counter/system/interrupt time
APIs now share the CPU clock. Read-only user/kernel KUSER_SHARED_DATA aliases
share one owned, aligned backing page. Updates occur on modeled clock advances,
including CPU-cycle flushes, without a global memory-read callback. The pinned
backend closes its native engine before dropping that backing. Generated probes
check virtual Sleep deltas, CPU-only progress, aliases, x86 64-bit returns,
invalid output buffers, denied shared-page writes and void return semantics.

Initial kernel event APIs now support manual/auto-reset state, real suspended
CPU waits, another guest thread signaling the object, and relative/absolute
virtual deadlines in100ns units. A day-long virtual wait completes without host
sleep. Deadlocks, altered guest event state, invalid IRQL, alertable/user-mode
waits and unsupported priority/Wait=TRUE semantics stop explicitly. Runtime
multi-object waits and guest KWAIT_BLOCK lists remain pending. The contracts
follow Microsoft's [KeWaitForSingleObject](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kewaitforsingleobject)
and [KeSetEvent](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kesetevent) documentation.

Tracked architectural MSR writes now remain processor state across saved thread
contexts. A generated root changed LSTAR after creating a child; the child
previously read zero because Unicorn's context memcpy restored its old MSRs.
The preserved regression log records that failure. Versioned context repair now
shares observed writes to EFER, syscall/sysenter and FS/GS/TSC_AUX registers.
Writes are observed after native execution, including at instruction-budget
boundaries; unchanged versions avoid native register work. RDTSCP reads the
guest's TSC_AUX. Other MSR families remain outside this tracked set.
Five alternating benchmark runs found the added tracking within about3% on the
arithmetic/API/event-handoff fixtures, with matching results/counts/guest time.

TSC MSR reads/writes now use the same virtual counter as RDTSC/RDTSCP. Counter
offset and IA32_TSC_ADJUST are processor state outside saved native contexts.
Guest probes cover read agreement, writes,64-bit wraparound, adjustment linkage
and reset, cross-thread visibility and privileged-access refusal. CPUID now
advertises the implemented TSC_ADJUST facility. The semantics follow
[Intel SDM Vol.3B, section18.17.3](https://cdrdv2-public.intel.com/812388/253669-sdm-vol-3b.pdf).
Five alternating samples per architecture/workload found about5-7% added cost
on arithmetic and3-5% on the API loop; cross-thread MSR timings stayed similar.

Validation audit: bundles25/26 passed their runtime controls, but a chained
PowerShell command hid a failed Clippy gate. The audit is preserved in
output/rust-lint-audit-27.json. Bundle27 corrects the warning and passes strict
Clippy; checks are now sequenced with their exit status inspected before build.

Driver API gates now occupy synthetic system-space ranges: x64 canonical
0xFFFFF80200000000 and x86 0x82000000. User API gates stay at0x68000000.
Generated code reads the full-width IAT pointer, checks its address domain and
calls the routine in both architectures. Gate regions are reported separately
from guest PE modules; Windows provider PE metadata/code remains pending.
Alternating arithmetic/API/handoff samples stayed within about6% of bundle27.

Kernel entry/child stacks, opaque thread identities, descriptor/TSS/lock storage
and return markers now use bounded synthetic system-space ranges. Root thread
storage is separate from the registry argument. Initial DriverEntry data includes
DRIVER_OBJECT type/size/name/start/image-size/init fields and a registry
UNICODE_STRING, following the public
[DRIVER_OBJECT](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_driver_object) layout.
Guest code verifies pointer domains, fields, strings and ABI arguments in both
architectures; full-width native descriptor reads verify the high GDT/IDT bases.
Object headers, process/ETHREAD internals, extensions, devices, loader lists and
callback defaults remain pending. Alternating loop/API/handoff samples stayed
within about3% of bundle28.

Driver images can now be loaded at checked kernel bases using HIGHLOW/DIR64
relocations. Guest code calls through relocated pointers and checks DriverStart;
module/entry evidence records both preferred and loaded bases. Missing, empty or
stripped relocation tables refuse rebasing. The input bytes remain unchanged.

Synthetic PE provider images now expose sorted export tables and register-
preserving guest jump bodies. Initial MmGetSystemRoutineAddress, GetModuleHandleA/W
and GetProcAddress models resolve and execute modeled exports, with identical
static/dynamic function pointers. Complete guest modules support names, ordinals
and forwarders. Synthetic profiles are explicitly partial: unknown export
availability stops rather than manufacturing absence on Windows. The models
check bounded UNICODE_STRING fields and the kernel lookup PASSIVE_LEVEL rule.
See [MmGetSystemRoutineAddress](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmgetsystemroutineaddress)
and [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress).
Provider byte-for-byte references, full export inventories and loader lifecycle
remain pending.

Initial kernel pool models now implement ExAllocatePool2, ExAllocatePoolWithTag,
ExAllocatePool and tagged/untagged free. Bounds, system addresses, zeroing,
page alignment, tags, IRQL, executable/NX protection and x86 ULONG64 flags ABI
are checked. Legacy/uninitialized bytes use deterministic guest poison; physical
paging, pool headers, quota, NUMA and verifier layout parity remain pending.
See [pool flags](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/pool_flags)
and [ExAllocatePool2](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatepool2).

An initial concurrent source suite crashed in the native backend. The pinned
Windows backend uses process-wide, per-instance VEH code-cache trampolines.
A private RAII factory now prevents overlapping native instance lifetimes in
one Windows process and closes Unicorn before releasing the guard. Independent
restricted worker processes remain parallel. Twenty complete concurrent-caller
suites passed afterward (800 test methods, including 2,560 queued fixture
requests). The exact original crash cause remains unconfirmed; the mitigation
and preserved failure/diagnostic evidence are in
output/rust-native-lifetime-audit-32.json.

The x64 build22631 synthetic kernel provider now carries the existing
reference-classified inventory of3,180 code and77 data export names. Classification
metadata is digest-bound in Rust. Implemented models keep guest stubs; each
unimplemented symbol has a distinct no-access page. Dynamic lookup therefore
retains symbol identity while attempts to execute, inspect code bytes or read
unknown data stop with bounded name/kind/access evidence. Generated ordinals and
modeled compatibility extensions are identified separately. No reference function
bytes or private data values are copied. HAL/x86/user provider inventories and
optional genuine read-only code-reference views remain pending.

The managed metadata foundation reads bounded CLI headers, BSJB stream
directories, string/blob/GUID/user-string heaps, all standard table row layouts
and their simple/coded/heap index widths. Initial tiny/fat IL body reading checks
method bounds, stack limits and local signature tokens. Bounded method/local
signatures cover primitive/reference/generic/array/pointer forms; parsing a type
does not imply runtime support. Unoptimized/pointer-table variants, EH sections
and broader IL/framework execution remain separate gates. UTF16 user strings
retain code units. No host CLR is loaded.
The formats follow [ECMA-335](https://ecma-international.org/publications-and-standards/standards/ecma-335/),
with bounded handling rather than host execution.
`inspect-managed` is read-only; `managed-fixture --write-input` emits only its
own harmless generated image and refuses to overwrite an existing file.
Sixteen packaged CLI controls verify x86/x64 generation/inspection and malformed
stream/signature/row/entry-token bounds.

An initial native Rust CIL interpreter executes generated int32/int64 arithmetic
and control flow, including signed/unsigned comparisons, shifts, switches and
short/long branches. It checks instruction boundaries, declared stack depth and
return types. Global instruction budgets and a wall deadline stop execution
without inventing returns. The controller and offline worker share a typed
native/managed dispatcher; managed requests never fall through to a native loop.
No host CLR, target JIT or P/Invoke fallback is used. Typed numeric/string locals
and arguments, void returns and ordered static MethodDef calls now execute in an
explicit frame stack. Initialization flags control zero versus uninitialized
locals; invalid types and reads stop. Global budgets span all methods. Limits
of 64 frames and 16 MiB frame storage stop recursion without host stack growth.
Instance/generic and other external calls, EH dispatch, broader objects and
framework/PowerShell behavior remain migration work. The isolated IL controls
verify results and partial/error paths. A five-sample
offline benchmark per architecture ran4,000,004 generated IL instructions in
median55.7544ms(x86) and50.916ms(x64), excluding startup/metadata parsing.
This is not a Python or vgk performance comparison.

Guest string references are stable owned identities. `ldstr` interns by exact
UTF16 code units, including duplicate metadata tokens, embedded zeros and
unpaired surrogates. String values survive typed locals, arguments and returns;
initialized string locals contain null. The heap permits 65,536 strings and
8,388,608 code units. Reports retain at most 64 object previews of 64 code units
with explicit truncation flags. Invalid tokens/type operations stop; no host CLR
object or pointer is used. Other object/array/framework behavior remains pending.
Literal identity follows [the documented ldstr contract](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes.ldstr).

Checked MemberRef reading resolves bounded owner/type/assembly identities and
method signatures without loading assemblies. Initial explicit framework models
cover String.Concat(string,string), Length, Chars, ordinal equality/inequality,
IsNullOrEmpty, Environment.NewLine and selected Console.Write/WriteLine overloads.
Unknown assembly/type/signature combinations stop. Virtual calls require an
instance method and non-null receiver. Null/index failures stop with their guest
exception names until managed exception dispatch is implemented.
Nonempty concatenation allocates a distinct object; empty/null shortcuts preserve
the documented string behavior. Length/indexing operate on UTF16 code units.
Models follow [String.Concat](https://learn.microsoft.com/en-us/dotnet/api/system.string.concat),
[String.Length](https://learn.microsoft.com/en-us/dotnet/api/system.string.length) and
[Environment.NewLine](https://learn.microsoft.com/en-us/dotnet/api/system.environment.newline).
Guest WriteLine uses Windows CRLF. Console capture retains at most 65,536 raw
UTF16 units and provides a separately labeled lossy display string. Integer
formatting currently uses the initial ASCII profile; broader cultures and report
compatibility remain pending. Framework dispatch caches at most 4,096 tokens;
call events retain 128 entries with exact omitted/attempt/completion counts.

Typed byte, int32 and string vectors now support zero initialization, exact
element access, byte-store truncation, null/index/type errors and aliasing through
typed locals/static calls. String and array identities occupy separate logical
namespaces. `ldlen` preserves a native-integer stack tag; supported conversions
are explicit. Broader native-int arithmetic/assignability remains pending.
Array limits are 4,096 objects, 1,048,576 elements per vector and 32 MiB of host
element storage. Reports retain at most 64 vectors and 32 preview values each.
TypeRef resolution uses explicit guest profiles; unsupported types stop.
Models follow [newarr](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes.newarr)
and [ldlen](https://learn.microsoft.com/en-us/dotnet/api/system.reflection.emit.opcodes.ldlen).
General objects, multidimensional arrays, boxing, element addresses and EH
dispatch remain pending.

Initial File.WriteAllBytes, ReadAllBytes and Exists models now use the shared
in-memory guest filesystem. This initial file profile is explicitly limited to
mscorlib4.0 and ASCII local paths; other runtime/path profiles stop rather than
infer host availability. Reads return independent mutable byte arrays, including
empty arrays under the selected Framework4 profile. Writes create/truncate the
guest file and close the modeled handle. Null/path/missing-parent/file failures
remain explicit; managed exception dispatch is still pending. Behavior follows
[the Framework reference source](https://github.com/microsoft/referencesource/blob/main/mscorlib/system/io/file.cs).
Each successful nonempty write and the final guest-file state feed the shared
content-addressed artifact catalog. Overwritten versions remain available;
identical content retains separate source/path observations. Parent validation
checks exported bytes/hashes. Guest paths stay metadata and never select host
destinations. Empty files appear in the bounded guest-file summary. File
summaries retain 64 path previews of 256 characters. Captures from a partial or
failed run remain evidence of that run's writes, not successful initialization
or unpacking. Source/worker tests cover overwrite, dedup, independent read
buffers, traversal-like guest names, failures and every roundtrip budget prefix.

RVA initializers now use checked FieldDef/FieldRVA/ClassLayout metadata and
opaque field handles. RuntimeHelpers.InitializeArray supports byte and int32
vectors in the initial mscorlib 4 profile. It validates the full declared
file-backed field storage before copying a requested prefix; reference layouts,
invalid flags/packing, missing metadata and undersized storage stop explicitly.
Repeated calls copy again. A generated fixture initializes encoded RVA bytes,
decodes them through IL, and exports verified guest-file content. This exercises
the managed pipeline; it is not a real-driver unpacking result.

Earlier bundle45 qualification: 136 source test methods, fourteen guest
broker/download cases, nine two-process
broker sessions, 20 journal controls, 16 metadata controls and four native
loop/budget smoke cases. The full 350-case IL and 204-case native API matrices
were repeated for44 because the worker launcher changed. Native204 was repeated
again in45; four fresh managed artifact/budget controls retain the unchanged
full350 managed baseline44. Nine fixed worker
fault probes also passed,
including a fast writer rejected after exit code zero, hidden file/directory
streams, linked output, timeout and abrupt exit. The source-difference audit
records the unchanged engine code. Worker/DLL tamper
controls pass. Cleanup found no residual grants, journals or worker processes.
The initial 35-to36 frame benchmark measured 22–27% extra cost on a four-million-
instruction tight IL loop. A simpler transition hot path was tested in36b;
follow-up results are inconclusive under a 96% host CPU-load snapshot. Matching
counts/returns are verified; no optimization speedup is claimed. Both benchmark
receipts remain in output. No real-driver execution occurred during these gates.
Five alternating benchmark runs per architecture/workload found time-page
modeling within about2% of bundle19 on the counted-loop and API fixtures.
The later23-to24 slice benchmark preserves results, instruction counts, API
counts and guest time. Arithmetic fixtures improve about5-6%, API loops1.3-1.5x,
and event handoff/day-timeout engine times49-149x by removing host timer churn.
These are bounded generated-fixture results, not vgk measurements.
The CPU-model benchmark records matched guest results/counts versus bundle15.
The added modeling costs about9-11% on a9-million-instruction arithmetic fixture
and4-8% on100,001 API calls on this host; it is not a real-driver speed result.
The Rust parser also read the original vgk.sys headers/imports/exports without
executing it. This is a parsing result, not driver compatibility or unpacking.

The bounded API dispatcher benchmark (100,001 generated calls, three runs per
architecture/build) measured median engine times of39.325ms to16.327ms on x64
and42.705ms to34.316ms on x86 between bundles9 and10. Results and captured-event
counts matched. These short fixture measurements are not real-driver speedups.

Remaining work, in dependency order:

1. Broader worker parity, output watchdog, crash cleanup recovery and the broker
   boundary. Initial AppContainer/job/handle-read/fixture manifests work.
2. Full native loader/provider/delay-import parity; heap/shared/remote memory,
   general handles and virtual processes/registry; remaining file/directory,
   remaining CPU/OS APIs and networking models.
3. Driver address space, objects, callbacks, locks, dispatcher, MDLs, threads,
   IPI scheduling, kernel providers and read-only reference inspection.
4. Managed metadata/IL interpreter and modeled framework/PowerShell behavior;
   MSI/container handling and staged child images.
5. Artifact/report compatibility, dashboard, packaging and the complete
   existing fixture matrix. Only then replace the existing default entry point.

The qualified worker output watchdog counts ordinary files, directories and
named NTFS data streams, including directory streams and optional private
broker files. It bounds bytes, entries, directory count and depth; reparse and
multiply linked entries or failed inspection stop explicitly. Parent directory
handles prevent rename replacement during a scan. The parent polls at 250 ms
and also scans after exit; this is a watchdog, not a hard filesystem quota.
Wall-clock and output stops terminate the job and wait for confirmed process
exit. A typed `worker-stop.json` records the cause and observed usage, and a
failed run cannot receive a qualified manifest. Fixed `boundary-probe` cases
generate harmless output or sleep/exit in the offline worker to qualify this
path. Bundle42 passed these runtime controls and the repeated regression suites.
The stream API follows the documented
[FindFirstStreamW contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirststreamw).
Broader broker and controller crash recovery remain to be ported.

Bundle43 adds a qualified read-only broker journal snapshot reader and
`inspect-broker-journal PATH`. It preserves complete JSON-line observations,
including attempted operations, with source and valid-prefix SHA-256 hashes.
A partial/malformed tail stays incomplete even after an earlier close marker;
only an exact final `broker_closed` object closes an otherwise valid snapshot.
Bounds are 64 MiB input, 40 KiB per line, 50,000 events, 64 Unicode characters
per event name, 8,192 JSON nodes per record and 250,000 nodes in total. The JSON
parser also retains its recursion bound. Integers outside i64/u64 are not
recovered by rounding them into floating point. The node
and integer limits are explicit Rust limits beyond the legacy journal reader.
CLI inspection leaves the
source untouched and rejects linked/oversized files on Windows. It starts no
network or broker process. Twenty CLI controls pass, including every recovered
source/prefix hash, malformed tails, range/resource refusals and unchanged
source bytes. Actual journal
staging, IPC and automatic crash recovery integration remain unfinished.

Bundle44 adds two qualified offline AppContainer roles with independent
one-process jobs. The parent pins fixed request/reply files before either role
starts. The worker has append access to requests and read access to replies;
it cannot create IPC entries or read the private broker journal. The broker
records and flushes complete attempt records before producing offline results.
The parent stops both roles before restoring grants, and uses its retained
journal handle to recover complete records even after process failure. The
initial transport bounds packets at64 KiB, streams at128 MiB and requests at
4096. Initial operations are ping, explicit offline DNS denial, an exact GET
fixture of at most4096 body bytes, and close. Full legacy fixture matching,
live networking and guest API integration remain separate migration work.
Nine process controls pass: exact GET, offline misses/DNS denial, crash after a
durable attempt, partial journal write, hanging broker, bad frame/sequence and
worker crash. All worker journal/IPC permission probes pass. The original
private journal is retained as evidence after all AppContainer grants have
been restored; the parent hashes and recovers that exact pinned file.
Controller-crash ACL recovery
also remains unfinished. Journal flush handles follow the documented
[FlushFileBuffers access contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers);
the private trusted broker handle has write access, while guest RPC writers
receive only append access.

Bundle45 connects qualified x86/x64 guest URLDownloadToFileA/W fixture calls to
that broker through an explicit client interface. A successful initial HTTP200
response is written only into the guest VFS and captured with URLMon and final
file observations. Denied offline requests return the download-failure HRESULT;
unsupported binding contexts/callbacks, null inputs, other status profiles and
missing broker transport stop explicitly. The initial profile supports ASCII
URLs/paths and at most4096 response bytes. Destination creation cancellation
records the error without inventing a file: the API can return S_OK even when
creation fails, as documented in the
[URLDownloadToFile contract](https://learn.microsoft.com/en-us/previous-versions/windows/internet-explorer/ie-developer/platform-apis/ms775123(v=vs.85)).
An entry return or S_OK is never a claim of initialization or unpacking.
Source tests cover both ABIs, A/W strings, every instruction-budget prefix,
denied transfers, cancellation and explicit unsupported cases. Fourteen
contained guest/broker runs pass, including partial/error runs with no qualified
manifest. Each exported payload and its source observations were verified.

Bundle46 qualifies controller hard-exit recovery with a private, flushed
write-ahead cleanup plan under `%USERPROFILE%\.emumee-rust-recovery`. The next
launch acquires the abandoned bundle lock, stops recorded owned jobs, restores
the original grant descriptors after checking file identities, and deletes
recorded AppContainer profiles. Torn final intents never authorize an action;
failed writes cannot receive a completion marker. Both contained roles are
denied access to the plan. Job membership is assigned during process creation
using `PROC_THREAD_ATTRIBUTE_JOB_LIST`, closing the suspended-process assignment
gap described by [Microsoft](https://devblogs.microsoft.com/oldnewthing/20230209-00/?p=107812/).
Restoration first propagates removal of transient ACEs, then restores the root
descriptor's original control flags with the non-propagating
[SetFileSecurityW API](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-setfilesecurityw).
Two deliberate controller exits, including a torn plan, pass recovery and
idempotence checks without altering broker evidence or qualifying a crashed
analysis. All142 source tests, native204, managed350 and the existing contained
boundary/broker/download/report checks pass; the final audit finds no residual
AppContainer grants or owned worker processes.

Bundle47 qualifies the larger HTTP fixture profile. Its parser preserves literal URLs,
normalizes request header names, retains duplicate ordered response headers,
and checks methods, chunked flags and exact binary bodies. Bounds match the
legacy fixture profile:48 MiB document,32 rules,16 MiB body,32 MiB bodies total,
64 headers and16 KiB header characters. URL validation deliberately rejects
control characters, backslashes and missing explicit authority more strictly
than the legacy URL splitter; it never resolves or connects to a host. Header
folding currently uses the pinned Unicode9 table; parity for later Unicode
case mappings remains outstanding. Binary RPC uses canonical standard Base64
and a24 MiB packet bound, retaining the128 MiB stream and4096 request bounds.
Twenty-eight generated schema controls match the legacy parser, and five
contained binary/exact-request controls verify64 KiB responses, metadata,
header order and body/chunked misses. The native204, managed350 and existing
boundary/regression suites pass. This remains an offline fixture profile.

Bundle48 connects full binary responses to generated x86/x64 guest URLMon
calls. Ten contained cases cover A/W calls,64 KiB byte-exact captures, empty
destination creation, denied requests and partial instruction budgets.
The controller pins fixture documents in broker-only private storage and
binds them by SHA-256; worker read denial is verified. Guest paths designate
virtual files, and exported captures retain URLMon/final-file provenance.
All147 source tests, strict lint, native204, managed350 and prior process/
report/artifact controls pass, with no residual grants or owned processes.

Bundle49 qualifies initial synchronous WinHTTP integration. The core model tracks session,
connection and request handles, parent-close invalidation, response readiness,
read cursors and fixed-length resend rules. Native adapters support Open,
Connect, OpenRequest, SendRequest, ReceiveResponse, QueryDataAvailable,
ReadData and CloseHandle. Generated x86/x64 programs pass returned handles
and read actual broker bytes into guest memory. Fourteen contained cases and
all154 source tests pass, including every instruction-budget prefix and
protected-output/state/parent-close controls. The existing native204,
managed350 and boundary suites pass with no residual grants or owned processes.
Response bytes are captured as memory evidence with broker provenance.
Proxy,
asynchronous, streamed/chunked upload, callbacks and broader option/query
profiles remain explicit migration work. The implementation follows the
[documented handle hierarchy](https://learn.microsoft.com/en-us/windows/win32/winhttp/hinternet-handles-in-winhttp),
[receive/read ordering](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpreaddata)
and [secure-transaction flag contract](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/nf-winhttp-winhttpconnect).
Bundle50 qualifies response-header queries, duplicate-header enumeration,
buffer-size contracts and empty-response EOF. Generated programs check actual
UTF-16/raw and numeric values, returned lengths, required sizes and indexes.
Poisoned output counts verify initialization on read failures and EOF; poisoned
data buffers verify that EOF writes no response bytes. All157 source tests
pass; only rustfmt formatting changed afterwards, recorded with the original
source in `output/rust-format-audit-50.json`. Final strict lint and24 contained
WinHTTP cases pass, along with native204, managed350 and the existing suites;
cleanup finds no residual grants or owned processes.
Bundle51 qualifies fixed-length upload staging and WriteData integration.
Only complete bodies reach the offline broker at receive; incomplete and
closed requests leave no HTTP attempt or body capture. Failed/excess writes
preserve staged bytes. Request and response captures match the journal hashes.
All161 source tests, strict lint and36 contained WinHTTP controls passed.

Bundle52 adds incremental caller-supplied chunk framing with bounded size
lines, chunk counts, wire bytes and decoded bytes. Every byte boundary and
binary payload is exercised; incomplete streams do not publish, and malformed
or unsupported framing stops explicitly. The broker sees the complete decoded
body and its chunked flag. An owned loopback-only Windows WinHTTP reference
(DLL10.0.26100.8521) verified literal wire write counts and zero-byte WriteData
error87 preserving the output count. This is an observed profile, not a claim
about every Windows release. Bundle52 passed167 source tests, strict lint,
46 contained WinHTTP cases and the existing native204, managed350, broker,
boundary, recovery and artifact/tamper controls. Cleanup found no residual
AppContainer grants, private journals or owned processes.

Bundle53 qualifies bounded guest user heaps through GetProcessHeap, HeapCreate,
HeapAlloc, HeapReAlloc, HeapSize, HeapFree and HeapDestroy. Reservations stay
entirely inside guest memory; no host allocator pointers or Windows heap headers
are exposed.172 source methods and26 contained heap controls check actual guest
bytes, ownership, zero growth, failure preservation and executable/NX backing.
The full baseline native204/managed350 and prior suites passed, followed by a
zero-residual cleanup audit. Fixed arenas and exception dispatch remain explicit
unsupported profiles.

Bundle55 qualifies synchronous WinINet InternetOpen/OpenUrl A/W, ReadFile,
QueryDataAvailable and CloseHandle with a separate guest handle namespace and
the private offline broker.22 contained cases check64KiB/split reads, empty EOF,
bad buffers, parent close, misses and unsupported flags/async. Bundle54 passed
174 source methods, but its first contained case exposed a missing controller
fixture-selection condition. That failed bundle/run is preserved. Only that
controller condition changed in55; strict lint, CLI test1, recovery2, contained22
and zero-residual cleanup passed afterwards. Baseline53 evidence retains its
original bundle identity and is not represented as a repeated55 suite.

Bundle56 qualifies WinINet connection/request/direct POST/header APIs with176
exact source methods and48 contained cases. An owned Windows loopback query
reference records A/W byte sizes, duplicate indexes and missing-header behavior.
Bundle57 adds fixed-length SendRequestEx/WriteFile/EndRequest, including delayed
publication for full and empty initial bodies.179 exact source methods,70
contained WinINet cases,46 repeated WinHTTP cases, recovery2 and zero-residual
cleanup pass. Zero writes fail87 preserving the count, and linked nodes remain
inert with head-only data, matching the owned loopback stream reference on
WinINet11.00.26100.8875. The native reference uses the host's56-byte layout;
generated callers separately verify both56-byte x64 and40-byte x86 layouts.
Incomplete EndRequest, unknown-length/chunked WinINet uploads and extended
header totals stop explicitly rather than guessing Windows results. No sample
or external destination was used for the references. Contracts:
[InternetReadFile](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile),
[HttpQueryInfoW](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpqueryinfow),
[HttpSendRequestW](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-httpsendrequestw).
Bundle58 qualifies bounded CRT byte/code-unit memory, comparison, length and
search models, with Cdecl stack cleanup and full pointer-return checks in
generated x86/x64 callers. An owned rewrite fixture exposed stale Unicorn
translated blocks after a modeled memory write. The shared write helper now
invalidates both instruction classification and the native translated range.
Both architectures execute the changed code correctly, including every budget
prefix.181 workspace methods pass in the assertion-enabled validation profile;
this is not a release-profile source-test claim. The frozen production release
passes28 CRT,204 native,26 heap,46 WinHTTP,70 WinINet,9 boundary,2 recovery and2
tamper controls, with no residual grants, private journals or owned processes.
Unchanged managed/broker/report baseline evidence retains its earlier bundle
identity. Bundle59 adds strcpy/strncpy/wcscpy/wcsncpy with exact truncation,
zero padding and caller-owned termination behavior.181 validation-profile
methods, strict release lint,36 contained CRT cases, recovery2 and cleanup pass.

The user authorized parallel agents for the remaining migration. The active60
source batch integrates guest registry state and A/W API adapters, bounded
kernel MDLs with genuinely shared owned alias backing, and pure legacy report
validation plus `inspect-report RUN_DIR [--verify-artifacts]`.212 workspace
methods pass in the assertion-enabled validation profile, including a pinned
543-case generated differential report corpus. Strict release lint passes.
Frozen release60 subsequently passed60 registry,26 MDL and43 read-only report
controls; native204/CRT36/heap26/WinHTTP46/WinINet70 and recovery/boundary/tamper
controls also pass. Cleanup found no residual grants, private journals or owned
processes. The canonical receipts are in output/rust-active-state.json.
Registry roots are independent guest
namespaces, and preset/persona loading, WOW64/security and binary registry
artifact capture remain separate work. MDL aliases cover only active modeled
NX pool buffers in the initial system process; probe/lock, kernel mappings and
process attach remain unsupported. Reports are safely read and verified, but
general report generation, dashboard/UI and batch integration remain pending.
The next agent lanes stage persona/process environments, callback bookkeeping
and bounded static MSI/Compound File parsing outside the frozen source tree.
General loader, native API, managed framework, kernel, container, reporting and
default-entry migration work remains outstanding.

Frozen61 qualifies the second parallel batch with247 assertion-enabled source
methods and750 contained or read-only controls. New coverage includes process
environment/identity/command-line ownership, callback registration/lifetime and
static MSI compound-file parsing. Named callback notifications stop when actual
routine dispatch is required. MSI inspection retains static stream metadata;
worker stream capture is a separate migration lane. No real driver ran.

Frozen62 qualifies PE evidence carving, typed registry/container provenance,
stricter parent artifact metadata verification, CRT standard streams and opaque
cache-aware rundown references.278 assertion-enabled workspace methods and1296
packaged or read-only controls pass, including the earlier managed350 and full
broker/recovery matrix. Cleanup found no residual grants, journals or worker
processes. A reconstructed PE is structural evidence, never confirmation of
successful unpacking. Contended rundown waits stop pending real scheduling.
Frozen63 qualifies bounded formatting/varargs, configured processor APIs and
READ/NX public globals, plus a contained static MSI role restricted to generated
fixtures.294 assertion-enabled workspace methods and1389 packaged/read-only
controls pass. Frozen64 subsequently qualifies console aliases/redirection and
shared output capture, System/Driver object identity/references, and managed
Base64 conversion.315 source methods and1087 new/affected packaged controls pass;
unchanged63 parser/HTTP/registry/persona baselines retain their original bundle
identity. Both cleanup audits found no residual grants, journals or owned worker
processes. Source65 integrates VFS metadata/enumeration/current-directory state
and managed MemoryStream/newobj; actual thread-object lifetimes are being staged.
Frozen65 now qualifies those VFS metadata/enumeration/current-directory,
MemoryStream/newobj and actual thread-object lifetimes with342 assertion-enabled
workspace methods and1331 new/affected packaged controls. Unchanged64/63
baselines retain their original identities. Cleanup found no residual grants,
journals or worker processes. Source66 integrates file unlink/copy/move/rename,
real kernel delay/multi-object waits, owned environment snapshots and a closed
report-producing controller/worker role. Its independent feature controls pass,
but the report role caught a one-ULP JSON float parsing drift and66 was not
qualified overall. Frozen67 enables exact float round trips and adds a focused
byte/hash regression:369 assertion-enabled methods, strict lint,48 closed
report/controller checks and two recovery checks pass. The1196 retained66
feature controls keep their original receipts, including92 file mutation,
72 environment snapshot and76 real delay/multiwait checks. Earlier65/64/63
evidence also retains its original identity. Cleanup found no residual grants,
journals or worker processes. Three agents continue full persona derivation,
per-CPU IPI execution and a separately bounded large-driver capture profile.
Source68 integrates strict external analysis planning and verified input binding;
this is planning data only, with worker execution still gated.
Its read-only `inspect-analysis-plan PLAN_JSON STAGED_ROOT` adapter reads bounded
inputs from fixed `inputs/0000.bin` slots in declared order, verifies actual
bytes and emits `executable:false`. It creates no worker or staging files.
The integrated68m source gate passes422 assertion-enabled methods, including
actual native perCPU IPI, CR8, mixed provider and configured persona coverage.
Normal synchronization, read-only NT registry and ordinary Driver128 capture
are now integrated for the next source gate. Packaged qualification remains
pending;68 is not qualified. New JSON source assets participate in fingerprints.

A saved-metadata target audit is in
`output/rust-vgk-readiness-before-provider-fix-68.txt`. Of129 imported names,
50 have modeled bindings and79 remain unmodeled in that saved baseline. A
provider publication correction exposes12 previously hidden implemented gates;
its source tests pass and packaged controls remain pending. These counts
describe static model existence, not runtime coverage or unpacking progress.
An exact legacy audit separates37 real bounded missing models from37 already
metadata-only names,4 placeholders and1 incomplete process-attach model.
Subsequent source additions are unqualified and do not change that baseline.
The saved final mutex page has Count0/Owner0, verified against its artifact hash
in output/rust-vgk-last-mutex-evidence-68.json. This is neither an initialized
free mutex nor evidence of a valid owning thread. Real guarded-mutex handoff
support therefore does not prove resolution of this historical zero-state
mutex. No new real-driver execution was used for either audit.

The saved vgk inspection describes an108994560-byte image, larger than the
current32MiB single-artifact profile. Before eventual recovery, a separately
bounded large-driver capture/report/job/output profile or verified chunk
reconstruction is required. Existing fixture defaults remain bounded. The full
Rust-port-before-vgk gate remains in force; no real driver has run in Rust.

General sample execution remains explicitly unavailable in the development
CLI until the Rust worker boundary and its models are qualified. `fixture`
only generates and emulates its own harmless bytes. The core CPU fixture is
not a real-driver compatibility or unpacking result.

Build/test on this workstation:

```powershell
.\tools\build_rust.ps1 -Release -Test
.\tools\build_rust.ps1 -Validation -Test
.\tools\build_rust.ps1 -Release -Lint
.\tools\build_rust.ps1 -Release
.\target\release\emumee-rs.exe fixture --arch x64 --iterations 1000000
.\target\release\emumee-rs.exe inspect path\to\sample.exe
```

MSVC, CMake, Ninja and libclang are build dependencies. The build helper finds
the workspace-local libclang/Ninja tools and the installed MSVC/SDK includes.
Runtime artifacts are the Rust controller/worker executables and `unicorn.dll`.

Primary backend documentation:
[Unicorn Rust API](https://docs.rs/unicorn-engine/2.1.5/unicorn_engine/struct.Unicorn.html),
[Microsoft AppContainer launch contract](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer).

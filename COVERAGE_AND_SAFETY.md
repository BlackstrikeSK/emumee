> Historical Python and bounded fixture evidence follows. The active Rust
> entrypoints have separate scope and same-build qualification requirements;
> these observations are not a stable Rust release certification.

# Coverage, containment, and test plan

## Experimental driver targets (2026-10-15)

Native-subsystem x86/x64 PEs are classified as `driver` and run in a separate
Speakeasy kernel emulator inside the existing no-network AppContainer worker.
`run sample.sys` runs DriverEntry; `--driver-unload` optionally calls a registered
DriverUnload only after a successful entry NTSTATUS. `batch --include-driver`
includes SYS inputs. Header classification stays bounded in the parent; detailed
parsing and guest CPU execution stay in the worker. There is no host service
installation or kernel loading. Non-native SYS files, managed native-subsystem
PEs, missing entry points, process-only options, and companion code loading are
rejected.

Reports distinguish the entry NTSTATUS and `initialization_succeeded` from an
emulated process exit. An observed failure NTSTATUS can be a `completed` analysis
with failed initialization. Created devices, dispatch routine addresses, registry
path, and optional unload completion are recorded in the summary, trace, and
dashboard. A return is accepted only when the CPU reaches a return sentinel
without a recorded fault. Entry and unload share an instruction and wall-clock
budget. Unsupported APIs, faults, skipped queued threads/callbacks, and budget
stops stay visibly partial or timeout results. Pool-memory artifacts, guest file
writes, and embedded PEs use bounded extraction and verified manifests.

The harmless generated fixtures cover x86/x64 entry arguments, device creation,
tagged pool allocation with exact marker bytes, dispatch registration without
execution, success/failure NTSTATUS, explicit unload, unknown imports, faults,
and loops in entry and unload. Source tests also cover importless drivers,
wall-clock stops, worker routing/options, dashboard rendering, and comparison.
`tools/verify_driver_cases.py` repeats sixteen lifecycle cases using the packaged
AppContainer path, checking exact submitted bytes and hashes, artifacts, report
integrity, lack of network attempts, and broker closure.

On 2026-10-15 all sixteen packaged lifecycle cases passed in
`output/driver-package-check/verification.json`. Two additional x86/x64
`ZwCreateFile` probes passed in `output/driver-boundary-check/verification.json`:
the guest file-open event named an absolute path outside its run directory,
while that host path remained absent. The package also passed
`tools/sandbox_smoke.py`, including the production worker's no-network
AppContainer restrictions. These probes exercise the tested paths only.
The ten focused driver test methods pass, and the same build bounded all fifteen
existing malformed-PE package cases (rejected, failed, partial, or completed
according to each fixture's expected behavior).
After the packaged checks, an ACL/journal/process scan of the bundle and those
new output trees found zero explicit AppContainer SID grants, zero private
broker journals, and zero packaged Emumee processes across 263 directories and
2,126 files.
The full source suite passed 757 tests with 13 skips in 1,358.5 seconds. The
separately verified final ten driver-focused methods also passed (including the
additional guest-only file-creation case). The worker build receipt matches the
final implementation source.

This is initialization and unload coverage only. IRPs/IOCTLs, dispatch execution,
hardware, interrupts, PnP/WDF/filter lifecycles, kernel scheduling, and general
Windows driver compatibility are unverified or unsupported. Native user-mode
applications with the same PE subsystem are not distinguished automatically.
Kernel API persona fidelity is narrower than the user-mode models. No real
driver corpus or compatibility percentage is claimed.

## Driver loader and kernel context upgrades (2026-10-16)

The driver path batches adjacent image-page protection requests with identical
rights, preserving request order and overlap semantics. The supplied 105-MiB
driver required 26,618 protection requests, reduced to 22 native calls. Import
sentinels use one mapped-image copy; PE classification parses only needed import
metadata, and artifact carving checks bounded PE signatures before copying large
candidates. These changes address loader/extraction costs without skipping guest
instructions or loosening image page permissions.

Relocatable x86/x64 drivers use modeled kernel addresses with bounded HIGHLOW or
DIR64 fixups. Fixed images retain their preferred addresses, explicitly reported
in `image_placement`. The x64 kernel uses Unicorn's virtual TLB mode so canonical
addresses are not truncated to physical addresses. Kernel code uses the Windows
code/data selectors and a current System thread. The x64 PCR self-pointer and
modeled system modules live in the kernel address range. PCR/PRCB offsets and the
17-entry idle queued-spin-lock layout follow the installed 26100 WDK; this does
not implement multiprocessor scheduling or otherwise unsupported lock APIs.
`RtlPcToFileHeader` searches strict image bounds and validates guest output
permissions before returning/writing a module base or NULL.

Driver traces include a bounded instruction tail, control transfers, selected
CPU-context observations, and an x64 unwind-table diagnostic on errors. Branch
register snapshots are sampled at new edges and every 4,096 transfers; every
transfer still appears in the bounded tail. That
diagnostic does not dispatch language handlers or restore a full CONTEXT. It
leaves the original error visible. Image-write evidence hashes pages before the
first CPU or modeled-API write and compares final bytes. Changed pages are retained in chunks
with module RVAs and original-page hash evidence; executed-after-write counts
require an actual final byte change. Such chunks alone do not establish a
complete unpacked PE or recovered original entry point.

The focused source checks include real CPU checks for canonical
shared-data reads, kernel selectors/PCR pointers, queued-lock module discovery,
relocated absolute pointers and imports, output permissions, x64 unwind metadata,
and modified code execution/artifact bytes. Kernel pool addresses are in the
kernel range. Tested `NonPagedPoolNx` allocations have writable, non-executable
dedicated pages; execute attempts fault. Executable-pool controls still run their
written bytes. An instruction-page cache is invalidated on CPU and modeled-API
writes, and the shared traced budget controls entry and unload. Live runs write
bounded `driver-progress.json` checkpoints. An analyst can write
`{"stop":true}` to the adjacent `driver-control.json` to stop at a checkpoint,
retain artifacts, and complete normal worker cleanup. This is reported as a
cancelled, partial trace, without a fabricated DriverEntry return value.
The package verifier now includes
twelve context/API/pool cases in addition to its sixteen lifecycle and two host-file
boundary probes. Run it against a freshly built worker to establish package
coverage for the current source; historical test counts above describe their
specific earlier builds.

Relocation updates runtime addresses and relocation targets while preserving the
preferred ImageBase in the mapped PE header. A harmless DLL forced away from its
preferred base under the native Windows loader verified this behavior; generated
driver fixtures verify the same header bytes and relocated pointer values under
emulation. A bounded header-read log records what guest instructions observed.

The kernel now models counted `RtlDuplicateUnicodeString` allocation and flags,
persona-offset `ExSystemTimeToLocalTime`, `RtlTimeToTimeFields`, and secure wide
`swprintf_s` formatting. Guest ranges are checked against native read/write
permissions. Native ntdll probes provide reference results for Unicode flags and
empty strings. The shared wide formatter consumes both x86 argument slots for
64-bit integer conversions. Source report validation accepts unsigned 64-bit
instruction counts, correcting rejection of valid traces over 100 million
instructions.

The broad source run passed 780 tests with 13 skips in 1,758 seconds before the
final pool-permission and API-write evidence refinements. The final implementation
passed all 50 focused methods and all 30 packaged driver cases in
`output/driver-upgrade-14-package`. The matching-source package also passed the
AppContainer smoke and fifteen malformed-PE cases in
`output/malformed-pe-package/453fe7d2d797481fb83a7d0a84b74be9`.
The completed validation trees had zero explicit AppContainer grants or private
broker journals across 348 directories and 2,999 files. The audit's process check
remains pending while the real stress run is active.

The subsequent source revision passed 109 focused/regression methods, including
the shared CRT and report validation checks. Its rebuilt worker passed six
runtime cases in `output/driver-upgrade-17-runtime-package` and the analyst-stop
case in `output/driver-upgrade-17-control`. The full source suite for this
revision passed 789 tests with 13 skips in 1,343.5 seconds, recorded in
`output/driver-upgrade-17-full-suite.log`. All 31 packaged lifecycle, file-boundary,
context/pool and analyst-control cases also passed in
`output/driver-upgrade-17-all-package-final`.

The supplied driver's matching-source run reached 304,460,875 instructions. It
completed Unicode duplication and both secure formatting calls, then stopped on
the missing `IoCreateFileEx` model while creating a guest Logs directory. Its
authenticated summary is partial, with ten artifact observations, six changed
image pages and zero changed pages executed. This is not evidence of a recovered
standalone unpacked driver. Report, artifact hashes and broker closure were
verified in `output/vgk-upgrade-17-retry/20261016T005442Z-b12a03e3`. A scan of the
new validation and stress-run trees found zero residual grants, private journals
or workers across 295 directories and 2,788 files.

The next revision adds bounded synchronous `IoCreateFileEx` guest files and
directories, shared bytes with independent handle positions, status blocks,
sharing checks, and read/write/flush/close behavior. Unsupported EAs, device
contexts, asynchronous I/O and non-exact input mappings remain visible. Guest
names never become host paths. Twenty x86/x64 CPU subcases cover exact bytes,
configured input reads, closed-handle failure, directory collisions/type checks,
sharing, missing parents, cursor/EOF/explicit offsets and read-only output pages.
The initial 33-method regression and fourteen loader/report checks passed, and
all seven final file-model methods passed. Harmless native ntdll file probes
provide reference return statuses and successful I/O byte counts in
`output/kernel-file-native-oracle/reference.json`.
The rebuilt worker passed all six kernel-file
probes in `output/driver-upgrade-18-files-package`, including explicit absence of
each requested host path, and all six runtime probes in
`output/driver-upgrade-18-runtime-package`, and all 31 lifecycle/context/boundary
and control cases in `output/driver-upgrade-18-all-package`. The full source suite
passed 796 tests with 13 skips in 1,367.8 seconds, recorded in
`output/driver-upgrade-18-full-suite.log`. The real driver reached 307,952,316
instructions, created its guest log directory and log file, wrote and flushed
40 exact bytes, then stopped at `KeRegisterBugCheckReasonCallback`. The verified
partial run is `output/vgk-upgrade-18/20261016T014715Z-31d6e075`; its thirteen
artifact observations include twelve distinct payloads, with seven changed image
pages and none executed after modification. A cleanup scan found zero residual
grants, private journals or workers across 385 directories and 3,457 files.

Bug-check reason callback registration now maintains guest records, duplicate
rejection, registration lists and deregistration. Its report explicitly records
that callbacks have not executed. Crash callback dispatch and Windows' internal
record checksums remain unsupported. The callback revision passed 41 focused
methods, seventeen loader/report checks, and all 47 packaged cases across
`output/driver-upgrade-19-all-package`, `output/driver-upgrade-19-runtime-package`
and `output/driver-upgrade-19-files-package`. Unsupported-API summary errors now
retain the API name as well as its address.

The subsequent revision adds current-thread, uncontended guarded mutexes,
exclusive push locks, rundown references and critical-region state. Blocked
acquisitions and rundown waits stop visibly; these synchronization models are
not yet integrated with the cooperative scheduler described below. Guarded mutexes follow the installed WDK's Windows 8+ FAST_MUTEX
layout. x86 fastcall arguments are tested. IRQL API changes update the CPU/PCR
view, and explicit x64 MOV CR8 handling corrects an observed Unicorn mismatch
between its register API and executed control-register moves.

Kernel system-time and performance-counter calls share the guest clock, including
HAL imports and x86 EDX:EAX returns. Processor queries and the imported
KeNumberProcessors variable use the persona. Recognized data imports are bound
after kernel setup: the engine originally mapped the primary image before these
handlers existed, leaving data reads pointed at zero-filled placeholders.
Unresolved import-storage reads now stop with a named error. The added queued
lock data page receives native RW/NX protection. Fifty-one focused regression
methods and the dedicated queued-lock NX probe passed. All 63 packaged cases
passed on the rebuilt revision in `output/driver-upgrade-20-all-package`,
`output/driver-upgrade-20-runtime-package` and
`output/driver-upgrade-20-files-package`. The aggregate evidence is
`output/driver-upgrade-20-verification.json`. The full source suite passed 811
tests with 13 skips in `output/driver-upgrade-20-full-suite.log`. The real-driver
run reached 308,380,782 instructions, registered its VGKT bugcheck callback and
queried the active processor count before requesting pool type 0x600. The model
incorrectly rejected that NX/zero-initialized allocation, sending the guest into
an error logging path that then stopped on missing `_vsnwprintf`. Eight image
pages changed and none were executed after a write. Report and artifact integrity
checks passed; cleanup scanned 525 directories and 4,833 files with zero residual
grants, private broker journals or packaged workers.
`tools/inspect_driver_run.py` verifies finished offline
driver reports and summarizes the actual stopping point and image-change evidence.
An import-resolution audit against this revision found handlers for 72 of the
sample's 129 imports and 57 unresolved imports, recorded in
`output/vgk-driver-import-resolution-20.json`. Handler presence does not establish
semantic fidelity, and an unresolved import is not necessarily reached. CNG,
several object-type globals, and additional scheduling APIs remain among the
unresolved imports.

The next revision recognizes the WDK POOL_ZERO_ALLOCATION (0x400) and advisory
POOL_COLD_ALLOCATION (0x100) modifiers, preserving native NX protection and zero
bytes in fresh mappings. It also binds kernel `_vsnwprintf` to the guarded CRT
formatter. A native CRT oracle confirmed the corrected exact-fit return value
without a terminator; secure formatting still rejects a full buffer. Seventy
focused source tests and all 73 packaged cases passed for build 21, recorded in
`output/driver-upgrade-21-verification.json`. The extra packaged cases cover
zero-filled/NX pools and legacy wide formatting, including exact-fit and
truncated outputs. A separate identical bundle copy allowed package probes to
run alongside the real driver without changing its active worker. The full
source suite passed 813 tests with 13 skips in 1,850.777 seconds. The real driver
successfully made four 0x600 allocations and reached event initialization before
stopping at missing KeInitializeTimerEx after 308,369,500 instructions. Its 18
artifact observations represent 17 unique payloads. Eight image pages changed;
none were executed after being written. The integrity-verified evidence is in
`output/driver-upgrade-21-inspection.json`.

Build 22 adds cache-aware rundown references, event/timer state, finite waits on
the guest clock, and nonpaged MDL descriptors. Current-process user mappings of
modeled NX pool buffers share native backing bytes, so CPU and API writes remain
coherent in both directions. Aliases remain NX; MdlMappingNoWrite mappings reject
CPU writes; unmapping removes both native access and stale scan metadata. Guest
PFNs are synthetic identities, never host physical addresses. Imported timer
initialization now has the behavior needed by the next observed stopping point.
Queued kernel threads and due timer DPCs still require scheduling and stop
explicitly; pending DPCs cannot turn a returned DriverEntry into complete
emulation. Seventy-nine focused regression methods and the expanded eleven-method
object suite passed. WDK header compilation verified x86/x64 MDL, event, timer
and DPC layouts. All 105 packaged cases passed; the full source suite passed
824 tests with 13 skips in 2,045.378 seconds. The unchanged real driver reached
314,099,273 instructions, initialized the timer and cache-aware rundown state,
built an MDL for its roughly 4-MB buffer, and created a System thread. DriverEntry
then blocked on the thread's startup event because build 22 did not execute queued
threads. Its 46 artifact observations represent 44 unique payloads. Nine image
pages changed and none executed after modification. Report integrity checks
passed. Cleanup scanned 1,006 directories and 9,008 files with zero residual
AppContainer grants or private broker journals; no packaged workers remained.
The evidence is in `output/driver-upgrade-22-verification.json` and
`output/driver-upgrade-22-inspection.json`.

Build 23 runs guest-created System threads cooperatively on CPU 0. It preserves
native CPU context, distinct RW/NX stacks, PCR thread identity, IRQL and critical
region state; guest waits suspend execution until a modeled event or timer
satisfies them. Both architectures cover single/multiple-object waits, finite
timeouts, delays, explicit thread termination, handle-close lifetime, and shared
instruction budgets. Recorded base priorities do not determine dispatch order.
The requested lifecycle may finish when its naturally created threads become
quiescent; this is not general Windows, SMP, APC, or DPC scheduling. The same
revision blocks modeled API writes through read-only MDL aliases, closing a
gap exposed by RtlMoveMemory despite CPU writes already being denied. Eighty-five
focused source tests passed, followed by three supplemental methods covering
two-worker dependency chains, dynamic priority lookup and unload coordination
on both architectures. All 145 packaged cases passed. The 828-test full-source
run had thirteen skips and one failure: the unrelated 255-hop pathping case hit
its 30-second wall-clock limit. That case passed unchanged on a separate rerun
in 19.465 seconds; the full run's failure is retained in
`output/driver-upgrade-23-verification.json`. Cleanup of the completed package
roots scanned 1,095 directories and 10,443 files with zero residual grants,
private journals or processes from that package bundle. The separate real-driver
run executed the logger thread for 59 instructions at recorded priority 15,
signaled its startup event, and resumed DriverEntry. It reached 317,596,692
instructions before stopping at missing KeIpiGenericCall. The 48 artifact
observations represent 45 unique payloads; nine image pages changed and none
executed after modification. Input, report and artifact integrity checks passed.
The subsequent real-run cleanup scanned 78 directories and 514 files with zero
residual grants, private journals or processes from that bundle. This trace used
worker SHA-256
`b7ec2ab51d82c32fd4bd191598eeba053be2c7dc67352eb46ad056b772bb74fe`.

Build 24 guards RtlMoveMemory, RtlCopyMemory, RtlFillMemory, RtlZeroMemory,
memcpy, memmove and memset with native guest-page permissions and a 128-MiB
operation bound. A harmless probe showed that the stock Python copy helper
could modify RX image bytes and then report that page as executed after a
write. The guarded helper stops before mutation. Both architectures cover
overlapping moves, invalid reads, cross-page write denials, zero-length
operations, nonzero initial buffers for zeroing, and x86 C calling conventions.
REP MOVSB byte iterations no longer fill the branch tail with self-edges;
native execution, memory tracing, per-iteration budget charges and virtual
cycles remain active. The long-copy prototype retained identical instruction
counts, bytes and cycles. Its exported memory fields were null, so no
memory-access-statistics comparison is claimed. All 84 focused source
tests passed in 156.335 seconds, including the new memory/REP probes. All 227
packaged cases passed on worker SHA-256
`d120f170fa316b72380c66f8291974451c631c47c1fcdbb4e55e2f2ca0aaedeb`.
One initial context-matrix case timed out during broker startup before a guest
worker started. The unchanged worker passed the fresh context matrix and all
remaining cases. The failed report remains at
`output/driver-upgrade-24-all-package/context/x86-zero-nx-pool/20261016T071320Z-59da744b`.
Cleanup scanned 1,772 directories and 17,013 files with zero residual grants,
private journals or processes from that bundle.

Build 25 adds guest-requested [KeIpiGenericCall](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keipigenericcall)
broadcasts. Native callbacks run cooperatively on separate processor/PCR/stack
contexts at IPI_LEVEL, with consistent CPUID, RDTSCP, TSC_AUX and processor-number
views. A shared barrier requires progress from every callback; the caller resumes
after all returns and receives its own processor's actual result. Remote CPUs use
parked modeled System contexts. Bounds are one group (32 processors on x86 or 64
on x64) and 64 broadcasts. Nested broadcasts, invalid callback addresses,
termination from a callback, changed return IRQL, faults and exhausted budgets
remain partial. This does not implement general interrupt delivery, APC/DPC
dispatch, hardware devices, or complete Windows processor state. In particular,
the measured default CR0/CR4 values and opaque ETHREAD/EPROCESS data still have
known fidelity gaps; no CR0 reads appeared before build 23's stopping point.
All 94 focused source tests passed in 111.922 seconds. The 839-test full source
run had thirteen skips and one failure: the existing max-255-hop pathping probe
exceeded its 30-second wall budget under concurrent load. With its test budget
raised to 60 seconds, it passed in 41.237 seconds; its two-million-instruction
cap and behavioral assertions are unchanged. All 254 packaged cases passed on
worker SHA-256
`c3365070ed63c13134798f26728bc88f7a9d4a6f087f81ad5f88084464102b49`.
The file group required a retry after Windows failed the bundle ACL grant before
any guest execution. The same unchanged worker passed all six retry cases.
The IPI harness also now uses a CLI-valid 64-processor persona for the x86
oversized-group rejection; x64 cannot request more than 64 through this CLI.
Cleanup of the package-test roots and original bundle scanned 1,957 directories
and 18,846 files with zero explicit AppContainer grants, private journals, or
processes in that bundle. The real-driver run uses a separate immutable bundle;
this cleanup count does not cover it. Evidence is recorded
in `output/driver-upgrade-25-verification.json`.

The real build-25 replay reached 317,869,285 instructions. All twelve requested
IPI callbacks executed 19,541 instructions each, returned zero, and completed
the broadcast. Execution then stopped on a write to `0x1000004e` at driver RVA
`0x102c`. The trace shows a preceding `SYSCALL` at RVA `0x10a0` falling through
unchanged. Harmless probes independently reproduced that engine behavior with
EFER.SCE clear, and reproduced stale upper x64 register bits after the CPUID
hook. The driver also now reads the default CR0 value `0x11`, which lacks paging
and write protection. These are measured CPU fidelity gaps, not evidence of a
successfully unpacked driver. All 48 artifact observations (45 unique byte
sequences), report/input digests and offline broker closure verified; nine
image pages changed and none executed after a write. The separate real-run
cleanup scanned 78 directories and 514 files with no explicit AppContainer
grants, private journals or worker processes left.

The next address-contract change moves modeled objects and the entry stack into
kernel ranges and binds code imports/dynamic lookups to their provider exports.
Native reads of provider code are allowed; stack/object pages remain NX. Kernel
unmapped accesses and unknown fetches stop without user SEH or fake recovery
pages. Fault reports retain their original address, access type and missing
import name after Unicorn's secondary exception. Unwind diagnostics recognize
entry, System-thread and IPI stacks. Build 26 was rejected when stricter source
checks exposed lost unresolved-import names; its 37 packaged cases are only
limited evidence, and its full suite was cancelled. Build 27 contains the
reporting correction; all 81 focused driver/kernel source tests passed in
168.882 seconds, the 842-test full source suite passed in 3,061.101 seconds with
thirteen skips, and all 268 packaged cases passed on worker SHA-256
`c1ed2833384163215f9b67079f7b3ea9e9e23e740cd69d0d8b165b809e1d44cc`,
bound to source digest
`651c5ca7e99159f60a637df44fe0d40bb84ba94edf1532ea0b10aae2e50fb3a3`.
Cleanup scanned 2,030 directories and 19,298 files in the package roots, original
bundle and unused real-driver copy, with no explicit AppContainer grants,
private journals or worker processes left. Build 27 was not replayed on the
supplied driver because build 25 had exposed the CPU gaps described above.
These pointer contracts do not supply real private ETHREAD/EPROCESS layouts or
complete kernel exception dispatch.

Build 28 corrects CPUID's x64 register clearing and initializes CR0 to
`0x80050033`, CR4.PAE and EFER.NXE. The native virtual TLB permits these values
without pretending to supply physical page tables. Guest MOV CR0 and SMSW stay
consistent, including changes made by guest code. Guest-map permission checks
remain enforced independently of CR0.WP changes. The x64 kernel CPU also sets
EFER.SCE and STAR/FMASK, and supports SYSCALL transfer to a guest-provided LSTAR
entry with saved return PC/flags and unchanged RSP. Prefixed forms and IRET
frames are covered by native probes. The placeholder Windows service dispatcher,
SYSRET/SYSENTER/SYSEXIT, invalid entry state and architectural exceptions remain
explicit partial stops; they do not fall through as no-ops. Bounded system-entry
state is included in the engine report. Its first sixteen CPU/IPI tests passed
in 12.933 seconds and all 92 focused source tests passed in 296.099 seconds on worker
`6676b390aa92fd9f234b2ce20145d90b35442c9936c59b5686d83648b04b7614`,
source digest `476f393d9c9838e376bc2bac2ef72fe9cf3f0437e8e100a10812161124655edc`.
All 37 CPU/address packaged cases passed. This intermediate build was then
superseded before real replay: a new native probe confirmed that fresh normal
kernel entry started with IF clear on both architectures. Its full suite was
cancelled and remaining package groups intentionally stopped before IPI cases.
The 405-directory/3,360-file audit found no residual grants, journals or workers.

Build 29 starts fresh normal lifecycle/System-thread contexts with IF enabled
and IPI entries with IF disabled; resumption restores native saved guest flags.
Guest probes verify fresh child and resumed caller flags as well as every IPI
callback's flag state. All seventeen first CPU/IPI/thread checks passed in
37.609 seconds. Broader source and packaged validation completed on worker
`030285a3e0e575f8fdd399cf063505f7ec366d3181289f7f40ff1265a7abaafb`,
source digest `705822ba8d134f2248b4d6d1598bbd7ee983cb2d2f7dd441f05b6707222154ea`.
The 93 focused driver/kernel/CPU tests passed in 320.981 seconds, the 849-test
full source suite passed in 3,471.240 seconds with thirteen skips, and all 293
packaged cases passed. Cleanup of the original test bundle and package roots
scanned 2,135 directories and 20,622 files with zero explicit AppContainer
grants, private broker journals or processes from that bundle. The separate
real replay finished after 566,739,869 instructions. It completed the long image
scan and all twelve IPI callbacks, passed the previous CPU-related failure
without attempting SYSCALL, then stopped at unsupported
`ZwQuerySystemInformation` class `0x4D` (extended kernel-module information).
DriverEntry did not return. Nine changed image pages and zero changed image
pages executed after writing were observed; no unpacked executable is confirmed.
The verified run is recorded in `output/driver-upgrade-29-inspection.json`.
Its separate cleanup scanned 78 directories and 514 files with zero residual
grants, journals or processes.
Completed validation is recorded in `output/driver-upgrade-29-verification.json`.
The identical verified worker now occupies `dist/Emumee`; the prior default is
preserved in `output/driver-default-before-29`. All 25 CPU and two containment
boundary cases passed from the new default path. Its separate audit scanned
333 directories and 2,669 files across the new/prior defaults and those test
roots, with no residual grants, journals or processes. That default-path audit
excludes the separately audited real-driver copy.

A reporting audit found that the upstream kernel path collects memory access
counters but does not populate the exported memory-layout snapshot. Thus an
empty dynamic-code list is not proof that no allocated code executed. A
harmless x86/x64 fixture writes and executes a two-instruction pool function;
the frozen build-29 report omits that execution, while a metadata-only prototype
exposes both writes and both executed instructions with identical instruction
count, return, virtual TSC and artifact hashes. The prototype has not been
integrated into the frozen worker. The inspector now makes this limitation
explicit; see `output/driver-memory-reporting-comparison.json`.

The next source candidate models kernel module-information classes 11 and 77
from actual modeled mappings, including architecture-specific layouts, the
extended list's terminating zero USHORT, preferred base, timestamp and checksum.
It validates writable outputs, reports required lengths and preserves other
existing information-class models. Its bounded final-layout reporting also
exports native access counters and allocated-code execution, with explicit
omission counts and one module inventory per report. API implementation memory
operations are excluded from these native counters. This is metadata, not a
memory dump or proof of unpacking. Native fixtures cover both architectures,
relocation, output faults, allocated execution and NX faults. Build 30 has worker
digest `7f385b25b85f94238bdf2abf223f29d4ff6c807dc0f31f41544d04d43d5bdbb7`
and source digest `04e2879678059098f6320be36b63db4dd3056decd0b2e47ca35d7dcda200a5af`.
All 98 focused source tests passed in 213.547 seconds, plus the separately run
existing unwind test in 1.094 seconds. All 325 packaged cases passed. The full
855-test run completed in 2,942.136 seconds with thirteen skips and one failure:
the existing 255-hop traceroute probe exceeded its 30-second wall-clock budget
under concurrent load. That unchanged test passed separately in 17.403 seconds.
The initial full run is not recorded as a clean pass, and the default remains
build 29. The scoped package cleanup scanned 2,391 directories and 22,849 files,
finding no explicit AppContainer grants, private journals or bundle processes.
The separate real-driver replay completed 569,518,855 instructions. Three
extended module enumerations succeeded before it reached cleanup and stopped
on an unresolved `PsThreadType` data import. Its next native instructions call
`ObReferenceObjectByPointer`, signal the logger and wait for thread termination.
The new reports contain fourteen execution contexts, 120 memory records and
nine loaded modules without truncation; no allocated-code execution was
observed, and no changed image page executed after writing. No unpacked driver
is confirmed. Its separate 78-directory/514-file audit also found zero residual
grants, journals or processes. See `output/driver-upgrade-30-verification.json`
and `output/driver-upgrade-30-inspection.json` for these qualified results.

The next source candidate supplies opaque Thread/Process type identities,
KernelMode object pointer/handle references and real reference-count changes.
Guest-created System-thread dispatcher headers become signaled only at actual
termination or return; joins use the existing native thread scheduler, and the
signal persists for later waits while the object is retained. Freed references,
unmodeled UserMode security checks and opaque type internals stop explicitly.
Native probes also exposed missing protected-read diagnostics and an inherited
fake-page fallback before invalid writes; both paths now retain the actual
fault address and preserve the original guest mappings. Candidate validation
is in progress. The maximum 255-hop traceroute test now gets a 60-second wall
budget, as the earlier maximum-hop pathping test does; its two-million-native-
instruction budget and all output/765-echo assertions are unchanged.

Build 31 has worker digest
`0bcb64f09e8e336aafb6d773038da6a8ce0421d801017754799d9d3c4542986e`
and source digest `e941d0c0384fb188fde349e3dd39c671de82c68b96758597ef01da4e5bbbcd0d`.
The preflight's three reference methods plus the maximum-TTL test passed in
22.546 seconds. All 102 focused source tests passed in 238.161 seconds, and all
30 new packaged reference/join cases passed. The full source suite ran 858 tests
in 3055.612 seconds with 13 skips and no failures. All 325 remaining packaged
cases also passed, bringing the total to 355. The scoped audit of the original
bundle and eleven packaged test roots found zero explicit AppContainer grants,
private broker journals or worker processes across 2632 directories and 24920
files. Build 31 was promoted to the default bundle, retaining the previous
default at `output/driver-default-before-31`. All 32 default-path reference/join
and host-file boundary sanity cases passed, followed by a clean scoped audit
of the default, previous archive and sanity roots. The dedicated isolated
real-driver replay completed after 569,719,293 instructions with a genuine
DriverEntry return of `0xC000007A`. Its logger thread terminated with status
zero, the reference/join cleanup completed, and the report contains no emulator
errors. Initialization still failed: no devices or dispatch routines were
registered. The 140-region memory report has no omissions or allocated-code
execution; eight pages remained changed and none executed after writing.
The separate replay audit scanned 77 directories and 480 files with zero
residual grants, private journals or worker processes. No unpacked driver is
confirmed. See `output/driver-upgrade-31-inspection.json` and
`output/driver-upgrade-31-verification.json`.

The next diagnostic candidate records native reads of modeled kernel provider
images: the first read at up to 256 distinct provider/PC pairs and the latest
256 reads, with registers and bounded readable pointer/stack prefixes. Total
read counts, omitted records and snapshot errors are explicit. These are passive
observations, not claims that an API resolved. Harmless x86/x64 single-read and
600-read controls preserve instruction counts, native memory counters, virtual
time, return values and artifact hashes with diagnostics enabled or disabled.
The real build31 trace read the modeled kernel image 3,541 times, but its API
trace cannot identify which native lookup led to the returned status. Additional
lookup evidence is needed before changing provider behavior. Diagnostic build32
passed 104 focused source tests in 131.180 seconds and all four new packaged
controls. Its scoped 104-directory/679-file audit found no residual grants,
journals or worker processes. Worker digest
`8c5f9dbad58fdfc40db4649262f0dd0f87be8f6094dd20b8f04d69e3e8f6ee69`
is bound to source digest
`0a2105561190057e242d001b88070be278792ae84f347720f1604ead0a8d5595`.
The isolated diagnostic replay completed with the same instruction count and
genuine failure status as build31. It captured 3,547 provider-image reads at
82 distinct PCs, with 3,219 omitted read records and zero capture errors.
All export/header reads occurred before 4.2 million instructions; only four
lock-storage reads occurred later during cleanup. The three successful module
list queries near the failure were not followed by provider-header reads.
The 77-directory/480-file replay cleanup audit was clean. The next diagnostic
candidate observes native reads of the successfully returned module-list buffers
to identify the missing lookup context. It adds up to 1,024 bytes of readable
stack and bounded prefixes at all register pointers, preserves native results,
and explicitly reports overlapping or excess watch regions. Build33 passed all
105 focused source tests in 147.173 seconds and eight packaged diagnostic
controls. Its scoped 136-directory/959-file audit was clean. Its worker digest
is `0dcfffadc7aba659edc4ce4913b79a8486a65e7bb950795e7e751cc346a06a5d`,
bound to source digest
`6b2d1df66131291e2873525bf02a946b3e741a1a7364b30f9945ee1676ba2d8e`.
The module-buffer diagnostic replay completed with the same genuine failure
and instruction count. It captured all 76 native query-buffer reads without
omissions, capture errors or watch errors. Register snapshots show a search for
`ci.dll` followed by `cng.sys`; both names are absent from the returned modeled
inventory. See `output/vgk-33-missing-providers.json` and
`output/driver-upgrade-33-inspection.json`.

The next candidate supplies synthetic read-only/NX images for those two modules,
with a fixed named-export metadata catalog inspected statically during
development. It includes no Microsoft function bytes and performs no host
module discovery at runtime. CI named ordinals start at four; its three unnamed
ordinals remain unmodeled. Every catalog function is non-executable: native
calls and writes stop at protection boundaries, and no code-integrity verdict
or cryptographic result is supplied. Native x86/x64 probes cover module-list
discovery, PE export traversal, readable metadata, blocked calls, and blocked
writes without executing a following marker. Frozen build34 passed 108 focused
tests in 230.300 seconds and all 52 related packaged controls (12 metadata,
eight read-diagnostic and 32 module-query/reporting cases). Its scoped audit
of 490 directories and 4027 files found zero residual grants, journals or
worker processes. Its worker digest is
`9959c115b5083700e94f3206a2c885374f6d1ffc28761babfaa70284bd8dd8f0`,
bound to source digest
`f59b6fb9748fab48003f24443dee371ec2eb204daf70ce97207e9de96831f4dd`.
That replay stopped after 568,218,567 instructions at a native read of the
unmodeled `ntoskrnl.MmHighestUserAddress` data export. DriverEntry did not
return, and no CI/CNG function executed. All 100 module-query-buffer reads
were captured without omissions or diagnostic errors. Nine image pages
changed, with no observed execution after writing. The completed replay's
77-directory/514-file containment audit was clean. No unpacked driver is
confirmed. See `output/driver-upgrade-34-inspection.json`.

The next candidate models the pointer-sized highest-user-address global in
read-only/NX kernel storage. Its value describes the guest's address-space
profile and is never read from the host. Imported and dynamically resolved
data addresses agree. Native fixtures check x86/x64 reads, data-write faults,
and execution faults without executing a following marker. Frozen build35
passed all 112 focused/related source checks (84 kernel checks in 134.536
seconds and 28 driver/image/CPU/unwind checks in 21.426 seconds), and all
60 targeted packaged cases (eight address-limit, 12 metadata, eight diagnostic,
32 module-query/reporting). The scoped 556-directory/4588-file audit found
zero residual grants, journals or worker processes. Worker digest
`c54158f4401ddba223a0ff7e9575cf903050e9b5ce4e5c8af5c9ba673742fbc1`
is bound to source digest
`c092977efffadf9c1cd2f2aefe698318b033a6fbd20ef32b5b366a8d77817ceb`.
The isolated real replay stopped at 568,218,640 instructions. Native code
passed the modeled address-limit read (R9 holds `0x00007ffffffeffff`) and then
called unmodeled `ntoskrnl.strcmp`. DriverEntry did not return. Nine image
pages changed, with zero observed execution after writing. The completed
77-directory/514-file replay audit was clean. This does not implement CI/CNG
routines or establish unpacking. See `output/driver-upgrade-35-inspection.json`.

The next candidate adds unsigned-byte `strcmp` with cdecl handling on x86
and the native x64 calling convention. It checks the readability of each
consumed byte and stops at the first difference or matching NUL; equal
pointers still require valid readable strings. Inputs needing more than
65,536 bytes of comparison stop explicitly without reporting equality.
Native fixtures cover ordering, high-bit bytes, case, prefixes, embedded NULs,
NUL at a mapping boundary, invalid pointers and the comparison cap. Frozen
build36 passed 116 focused/related source checks (88 kernel checks in 119.279
seconds and 28 driver/image/CPU/unwind checks in 12.275 seconds) and 68 targeted
packaged cases (eight string, eight address-limit, 12 provider metadata,
eight read-diagnostic, 32 module-query/reporting). The scoped audit of 621
directories and 5141 files found no residual grants, journals or worker
processes. Worker digest
`392d79bc8e88d92193e4e6f59a8777c3ebc77ada9a4a4196113612824a4bd8ea`
is bound to source digest
`46d7daea63fc25573e4d2cfd076b09e13aaee9aaba8a58c2a10af1f7cba5a043`.
That replay completed after 570,050,733 instructions, with eight actual
`strcmp` calls and no emulator error. DriverEntry genuinely returned
`0xc000007a`. All eight captured lookup snapshots name
`KdDebuggerNotPresent`, which is absent from the modeled export catalog.
Nine image pages changed; no execution after writing was observed. The
completed 77-directory/514-file replay audit was clean. See
`output/vgk-36-missing-debugger-data.json` and
`output/driver-upgrade-36-inspection.json`. Unpacking remains unconfirmed.
The ordinary return relation follows Microsoft's
[strcmp documentation](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strcmp-wcscmp-mbscmp).

The next candidate supplies `KdDebuggerEnabled` and `KdDebuggerNotPresent`
as BOOLEAN data in a read-only/NX kernel-provider section. The guest has no
modeled kernel debugger transport or attachment, so the values are zero and
one, respectively; they are not discovered from the host. The PE export-name
index is sorted together with its ordinal indexes, preserving function RVAs
and name/ordinal associations. Imports, dynamic lookup and native PE binary
lookup refer to the same data addresses. Native x86/x64 fixtures cover both
data values, missing-name search, and write/execute protection faults. Frozen
build37 passed 120 focused/related source checks (92 kernel checks in 160.202
seconds and 28 driver/image/CPU/unwind checks in 14.575 seconds) and 76 targeted
packaged cases (eight debugger-data, eight string, eight address-limit,
12 provider metadata, eight diagnostic and 32 module-query/reporting). The
scoped 686-directory/5694-file audit found no residual grants, journals or
worker processes. Worker digest
`f08b6d010ea8a78ed78d81cf0906b33078679106c349855754ebdad79a10e40b`
is bound to source digest
`551950c70c5da8c9509f6e9f79c4d4ccbf7d131e445e4560521a8486d0d53efe`.
That replay completed after 570,056,638 instructions with a genuine
`DriverEntry` return of `0xC000007A`. Both debugger-field lookups now resolve;
seven native lookup snapshots identify the next missing export as
`KdEnteredDebugger`. Ten image pages were written, nine changed, and none
executed after writing. Initialization and unpacking remain unconfirmed.
See `output/driver-upgrade-37-verification.json` and
`output/vgk-37-missing-entered-debugger.json`.
Debugger attachment, refresh and mutation are not
implemented. Variable semantics follow Microsoft's
[KD_DEBUGGER_NOT_PRESENT documentation](https://learn.microsoft.com/en-us/previous-versions/ff548125(v=vs.85)).
The name-index and parallel ordinal-index layout follows Microsoft's
[PE export format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#export-name-pointer-table).

Candidate build38 adds the missing `KdEnteredDebugger` BOOLEAN with value zero
for the guest's inactive debugger. Native x86/x64 fixtures compare imports,
dynamic lookup and binary export search. It also caches instruction metadata,
defers branch-tail formatting until reporting, and removes repeated work from
ordinary instruction accounting while preserving the special CPU paths.
Three alternating generated scalar-scan pairs retained identical instruction
counts, virtual time, memory counters, control/context tails and artifact hashes.
The median fell from 7.814 to 5.178 seconds for 1,286,009 instructions (1.51x).
This measures a harmless fixture; real-driver speedup must be measured separately
in the packaged isolated worker. Source validation passed 93 kernel and 33
driver/image/CPU/unwind/cache tests. Its 79 packaged controls passed, including
a native scan with observations identical to the source model. The scoped
713-directory/5960-file audit found no residual grants, journals or worker
processes. Its real replay finished after 570,059,491 instructions, resolving
all three debugger globals before a native search demanded the absent
`PsInitialSystemProcess` data export. `DriverEntry` returned `0xC000007A`.
Nine image pages changed and none executed after writing; no unpacked driver
was confirmed. The roughly 57-minute run overlapped build/test/profiling jobs
and does not establish a real-driver speedup. See
`output/driver-upgrade-38-inspection.json` and
`output/vgk-38-missing-initial-system-process.json`.
Evidence: `output/driver-hooks-ab-38/verification.json`.

Build39 adds an equivalent common execution-accounting path, retaining the
upstream cold paths. It passed 126 source checks and 236 packaged driver CPU,
thread, IPI, lifecycle, memory, debugger and scan controls. Its scoped
1818-directory/17112-file audit was clean. No real replay was started with this
candidate while build38 remained active. See
`output/driver-upgrade-39-verification.json`.

Build40 includes an experimental compiled direct instruction callback. It
buffers bounded trace tails, keeps the native instruction budget, and flushes
pending virtual CPU cycles before timer/clock observers. Special CPU,
scheduled and cold paths retain Python handling. Source and binary digests
are checked separately, including an embedded source digest; stale compiled
code fails during kernel emulator construction. Native buffers do not replace
guest instructions or alter driver branch results. Source validation passed
131 checks (93 kernel and 38 driver/image/CPU/unwind/cache/receipt checks).
The isolated scan matches the Python model's 1,286,009 instructions, clock,
memory counters, context/control tails and artifact hashes. Binary tampering,
source tampering and a valid portable manifest with stale compiled source
were rejected before guest image execution. All 239 packaged controls passed;
the scoped 2042-directory/18403-file audit was clean. Exact build40 source is
preserved under `output/frozen-source-40`. The verified default is still build31.

Three alternating scan pairs measured build40's compiled backend at 8.422
seconds median versus 14.913 seconds for receipt-bound build37 tracing
components, a 1.77x throughput gain under the same benchmark workload. This
measures a generated fixture and does not establish a real-driver speedup or
successful unpacking. See `output/driver-hooks-ab-40/verification.json` and
`output/driver-upgrade-40-binding-package/verification.json`.

Candidate41 supplies the documented `PEPROCESS PsInitialSystemProcess` global
as a read-only/NX pointer in the generated kernel image. It points to the
existing modeled System process; it does not allocate a replacement process.
Native x86/x64 import, dynamic and binary export lookups agree, the body pointer
agrees with `IoGetCurrentProcess` in DriverEntry, and object references balance.
The shared data-export builder retains sorted name/ordinal pairs and debugger
data behavior. Private EPROCESS layout and global-pointer replacement remain
outside this supported view. See Microsoft's
[kernel global variables documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/mm64bitphysicaladdress).
Source validation passed 135 checks and all 51 targeted packaged controls.
The scoped 557-directory/4407-file audit was clean. The compiled backend, clock, scheduler and
memory-helper source/binaries match verified build40. Live progress now records
native-backend counters without changing guest time. The frozen isolated real
replay under `output/vgk-upgrade-41` completed 570,070,553 instructions in
1663.471 seconds (27 minutes 43 seconds), then returned `0xC000007A`.
The System process lookup and three previously queried type exports resolve;
the next absent native query is `IoFileObjectType`. There were no stopping
errors or native callback errors. Report integrity and worker bindings passed;
the final 78-directory/482-file containment audit was clean. The prior build38
run took 3415.316 seconds alongside heavy validation jobs, so this wall-clock
improvement is not a controlled speedup measurement. No unpacked driver is
confirmed. See `output/driver-upgrade-41-inspection.json` and
`output/vgk-41-native-lookups.json`.

Candidate42 adds the missing file type global and gives all four queried
Thread/Process/Driver/File type exports one read-only/NX pointer location shared
by imports, dynamic lookup and the native PE export table. Their distinct
opaque identities have no readable or executable private fields. KernelMode
reference counts and type mismatch checks remain enforced. This does not add
device stacks, private OBJECT_TYPE layouts or file bodies for unsupported
handles. See the WDK's
[object reference contract](https://learn.microsoft.com/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbyhandle).
The expanded 14-method preflight, all 142 broader source checks and 131 targeted
packaged controls passed. The final audit scanned 1200 directories and 9929
files with zero explicit AppContainer grants, private journals or remaining
worker processes. The frozen isolated replay under `output/vgk-upgrade-42`
completed 570,073,346 instructions in 1619.734 seconds (26 minutes 59 seconds).
`IoFileObjectType` resolves; the next absent native query is
`MmSectionObjectType`. DriverEntry returned `0xC000007A` with no stopping or
native callback errors. Report/worker bindings passed, and the final
78-directory/482-file audit was clean. The compiled backend is unchanged from
build41. No unpacked driver is confirmed.
The generated scan's 1,286,009 instructions and observed results agree with
Python tracing. These checks establish the modeled exports and tracing
agreement; driver initialization and unpacking remain pending.

Candidate43 adds the observed section type and the object-type globals listed
by the WDK's ObReferenceObjectByHandle contract (Event, Semaphore, Token and
four transaction-related types). All twelve type identities remain opaque;
their globals have consistent native/import/dynamic addresses and read-only/NX
storage. No section memory manager, transaction manager or private OBJECT_TYPE
layout is implied by an exported type identity. ReactOS independently declares
the observed [section type global](https://github.com/reactos/reactos/blob/master/ntoskrnl/mm/section.c)
as a POBJECT_TYPE. The 14-method catalog preflight, all 142 broader source
checks and all 227 split packaged controls passed. The generated scan's
1,286,009 instructions and observations agree with Python tracing. The
1969-directory/16554-file audit was clean. The frozen isolated replay under
`output/vgk-upgrade-43` completed 570,114,326 instructions in 1638.328 seconds
(27 minutes 18 seconds). Section type resolution succeeds; the next absent
native query is `MmUserProbeAddress`, followed by a genuine `0xC000007A` return.
Report/worker bindings passed and the final 78-directory/482-file audit was
clean. There were no stopping/native callback errors and no confirmed unpacked
driver. The compiled tracing backend remains unchanged.

Candidate44 supplies the pointer-sized `MmUserProbeAddress` boundary and moves
both it and `MmHighestUserAddress` into read-only/NX native kernel export data.
Imports, dynamic lookup and native binary lookup share the same storage.
Probe is the first byte beyond Highest in each modeled address-space profile;
the existing x86/modern x64/legacy x64 values are preserved. The eight-method
boundary preflight and all 146 broader source checks passed. Legacy build 7601
is an internal source-fixture profile; the CLI intentionally accepts Windows 11
profiles only. A package harness that initially tried 7601 was rejected before
guest execution, then continued with 22000/22631 without repeating the completed
type cases. All 139 packaged controls passed; generated scan observations
match Python tracing. The 1267-directory/10525-file audit was clean, and a
frozen isolated replay under `output/vgk-upgrade-44` completed 570,117,229
instructions in 1620.45 seconds (27 minutes). Both address boundaries resolve;
the next missing native export is `HalPrivateDispatchTable`, followed by a
genuine `0xC000007A` return. Report bindings and the final containment audit
passed. No unpacked driver was confirmed.
Read-only inspection of the
installed 26100 kernel's disk initializers independently matches the modern
Highest/Probe values; that is not a live snapshot or proof of guest 22631 private
layout. See `output/local-kernel-boundary-initializers.json`.

Candidate45 adds metadata for the private `HalPrivateDispatchTable` symbol.
Its version, fields and callbacks remain unmodeled. The reserved data page has
no read, write or execute permission; native accesses stop with the symbol and
offset recorded. API memory helpers explicitly reject accesses to that page
because host-side Unicorn memory APIs bypass guest page permissions. This
exposes the next required behavior without guessing a private HAL layout.
All 154 source checks and 157 packaged controls passed. Generated scan
observations match Python tracing. The 1411-directory/11766-file containment
audit was clean. The frozen isolated replay under `output/vgk-upgrade-45`
completed 570,120,041 instructions in 1634.364 seconds (27 minutes 14 seconds).
The private HAL symbol resolves without a field access. The next absent native
export is `ExCreateCallback`, followed by a genuine `0xC000007A` return. Report
integrity and the final 78-directory/482-file containment audit passed. There
were no stopping or native callback errors and no confirmed unpacked driver.

Candidate46 adds named executive callback objects in the Callback directory.
It supports documented system object names, create/open identity, case-sensitive
and insensitive leaf lookup, permanent namespace references, single/multiple
registration rules and removal. Object-manager references keep registrations
alive after caller dereference; object bodies and registration tokens remain
opaque protected kernel addresses. Both native and API-mediated accesses are
checked. No system event is synthesized. Empty driver-defined notifications
complete; notification of registered routines stops explicitly because guest
callback dispatch is not yet implemented. System-defined notifications,
unsupported security/root attributes and invalid IRQL stop visibly.
All 166 source methods (15 preflight, 113 remaining kernel and 38 related) and
243 packaged controls passed. The generated scan retains exact Python/native
observations. The 2101-directory/17702-file containment audit was clean. A
frozen isolated replay under `output/vgk-upgrade-46` completed 570,163,890
instructions in 2248.802 seconds (37 minutes 29 seconds). It overlapped
candidate47 build/source/packaged validation and a reverted affinity experiment;
this timing is not a controlled comparison with the earlier quiet 27-minute
runs. Callback exports and `ExQueueWorkItem` resolve; the next missing native
export is `IoAllocateWorkItem`, followed by a genuine `0xC000007A` return.
Report bindings and the final 78-directory/482-file audit passed. No unpacked
driver was confirmed.

Candidate47 extends native export-name metadata for x64 build22631 using the
authenticated Microsoft kernel 10.0.22621.2506 shared with the 23H2 family
([Microsoft KB5027397](https://support.microsoft.com/en-gb/servicing/os/windows-11/2023/05/kb5027397-feature-update-to-windows-11-version-23h2-by-using-an-enablement-package)).
The reference was downloaded from Microsoft's symbol server and Windows
Authenticode reported a valid Microsoft Windows signature. Only 3,180 code
names and 77 data names/classifications are included; no Microsoft code bytes
or private field values are distributed in the worker. Existing modeled APIs
retain their handlers. Unimplemented exports have distinct protected pages,
so native calls, function-byte reads and private-data accesses stop with the
symbol and offset. API memory helpers enforce the same guard. Addresses and
ordinals remain synthetic. Native denials record a fault-point span; API
denials record the requested span. The profile is disabled for x86 and other
builds.

All 178 source methods and 263 packaged controls passed. The generated scan
retains exact Python/native observations. The 2404-directory/19893-file scoped
audit was clean. Verified replay47 completed 604,722,892 instructions in
1795.809 seconds and returned `0xC000007A`, with no native callback or stopping
errors. Its 2,603 strcmp calls and first CI/CNG native lookups advanced beyond
the earlier NTOS failures; the last strcmp matched ObFindHandleForObject.
No protected catalog symbol was accessed. Bounded first-per-PC snapshots and
the global tail do not establish which later lookup or initialization check
failed. Successful initialization and unpacking remain unproven.

Candidate48 retains the latest snapshot for each tracked provider/PC, capped
at the same 256 keys as the first snapshots, and captures a bounded tail of
kernel wide-format output before callers transform or free the buffers.
Generated fixtures compare diagnostics enabled/disabled, including guest
memory, instruction counts and virtual clocks. The native tracer also caches
decoded instruction flags in per-offset slots, guarded by the canonical
decoded dictionary identity so invalidation and eviction invalidate the
slots. Misses and cross-page instructions retain the original reader. Three
alternating generated scan pairs (6,430,009 instructions each) retained exact
observations, with medians 14.179 seconds before and 11.205 after (1.265x).
This measures a generated scalar workload. The verified real replay48 took
1551.871 seconds for the same 604,722,892 instructions and entry failure as
replay47: 243.938 seconds less, or 1.157x. Host scheduling was not controlled.
CPU, scheduling, memory and package binding validation must be refreshed for
the changed native binary; prior unchanged-backend results are not inherited.
Candidate48 passed 181 source methods and 511 packaged controls, including the
refreshed native foundation, passive diagnostics and binding negatives. Two
disjoint containment audits covered 4,421 directories and 38,799 files with
zero residual grants, journals or packaged workers. Its frozen isolated replay
at `output/vgk-upgrade-48/20261017T051408Z-f9af47da` returned `0xC000007A`,
with no native callback or stopping errors. All 237 strcmp lookup groups
matched. The subsequent wildcard scan of generated NTOS code found no match.
Static inspection of the authenticated reference finds one matching pattern;
its call target is the unexported MmAllocateIndependentPages, identified by
the matching Microsoft PDB. Initialization and unpacking remain unproven.

Candidate49 adds an optional explicitly supplied kernel PE as static code
inspection data. The parent and worker bind its SHA-256; only file-backed
code sections are readable, all are non-executable, and other reference data
is inaccessible. Generated API stubs and modeled metadata retain separate
storage. Calls into reference code stop explicitly; no private allocator
behavior or private structure values are supplied. The authenticated
22621.2506 reference is identified by a pinned hash, while other supplied PEs
are reported as unverified data. Reference scan reads retain exact counts
and last-read metadata; full contexts are captured periodically in those
code ranges. Candidate49 passed 244 source methods and 195 packaged controls,
including authenticated reference reads, denied reference calls and seven
input rejections before guest execution. Its scoped audit covered 1,704
directories and 15,148 files with zero residual grants, journals or workers.
The isolated replay at `output/vgk-upgrade-49/20261017T062954Z-4dd1da2e`
finished after 697,902,358 instructions in 3,505.512 seconds with a partial
stop while inspecting the synthetic `PsSetContextThread` catalog address.
Final report, worker, input and reference hashes were verified; a scoped audit
covered 78 directories and 516 files with no residual grants, journals or
workers. Initialization and unpacking remain unconfirmed. The native backend
is unchanged from validated candidate48.

Candidate50 changes the native cached-access lookup. When the first execution
record does not cover the current instruction, it now checks the remaining
existing records before using the Python fallback, matching the upstream
lookup order and access-record identity. Three alternating generated fixture
pairs, each 1,286,011 instructions across two executable sections, retained
guest bytes, instruction counts, clocks, trace tails and cache misses. Median
engine runtime was 9.328 seconds before and 4.939 after (1.889x). Cache-hit
counts truthfully decrease because redundant lookups are eliminated. This
is a generated workload result, measured alongside the functional49 replay;
real-driver speedup is not established. The new x86/x64 source tests include
an exact64-instruction stop. Candidate50 passed 245 source methods and 534
packaged controls. Its scoped audit covered 4,605 directories and 40,698 files
with no residual grants, journals or workers. The frozen worker and source
snapshot are preserved. Real49's timing was affected by concurrent validation
and temporary task-process core placement and priority settings.

Candidate51 addresses the demonstrated export-inspection stop. With an
explicit reference, unimplemented code exports that have file-backed code in
that PE use its original RVAs for inspection. Implemented APIs keep their
generated stubs; data exports keep modeled storage or protected placeholders.
Reference code remains read-only/NX and calls still stop with the export name.
No private API behavior or runtime kernel state is invented. Thirty-three
focused source methods passed, including generated import/dynamic/EAT pointer
agreement, native/Python parity, data guards, call/write refusals and a bounded
export-table check. All 68 packaged controls passed, including actual
`PsSetContextThread` reference-byte reads through import, dynamic and EAT
lookup and denied calls/writes, plus retained default-catalog traps, native
diagnostics, scan parity and worker-binding negative controls. The real51
replay finished after 747,687,404 instructions in 2,624.015 seconds. It passed
the earlier export-inspection stop and stopped reading reference RVA0xc13098.
The matching Microsoft PDB identifies that address exactly as `MmUnloadedDrivers`.
Final report/input/reference/worker hashes and containment were verified;
the real-run audit covered 78 directories and 516 files with no residual
grants, journals or workers. A bounded generated prototype benchmark overlapped
its final stage, so this is not a controlled whole-run performance comparison.
Initialization and unpacking remain unconfirmed.

Candidate52 permits native tracing when the scheduler has no pending, queued,
runnable or active IPI work. Other-runs instruction counts are refreshed at
cold boundaries so budgets/progress remain global across contexts; busy
scheduling retains the original hook. Thirty generated controls preserved
Python/native/prototype guest observations, budgets, clocks, per-run API
events and scheduling. Three alternating generated benchmark pairs each ran
400,261 instructions: median engine runtime 4.387 to1.161 seconds (3.779x).
This is a generated workload measurement alongside the functional51 replay.

The pinned reference's `MiRememberUnloadedDriver` code shows lazy allocation
of the unload-history buffer. Candidate52 models a fresh guest with no actual
image-unload operations: its `MmUnloadedDrivers` pointer is NULL and
`MmLastUnloadedDriver` index is0. The storage is read-only/NX and byte guards
deny neighboring private fields, padding and crossing reads, including API
memory helpers. Calling DriverUnload alone does not unload an image or add
history. ZwUnloadDriver/MmUnloadSystemImage remain unimplemented; no host
history, invented prior unloads, private array records or reference instructions
are supplied. Forty-eight focused source methods and all 152 packaged controls
passed. Its scoped audit covered 1,803 directories and 16,062 files with no
residual grants, journals or workers. The frozen52 offline replay at
`output/vgk-upgrade-52/20261017T085258Z-723bc0f8` finished after 781,604,244
instructions in 2,106.490 seconds. Its final report records the exact formerly
blocked `MmUnloadedDrivers` read, then a refused call to `DbgPrompt` at reference
RVA0x5a5520. Final hashes, reference NX and containment were verified; its
78-directory/516-file real-run audit found no residual grants, journals or
workers. Different guest behavior and earlier research overlap prevent a
controlled whole-run performance claim. Initialization and unpacking remain
unconfirmed.

Candidate53 models the documented `DbgPrompt` no-input result in the existing
guest with no debugger transport: zero received characters and an unchanged
response buffer. It validates bounded guest pointers, requires the prompt NUL
within 512 bytes, accepts response capacities up to 512 bytes, and records at
most 64 prompts while retaining the full call count. It supplies no debugger
answers or host console access. Import, dynamic and EAT lookup use the modeled
API stub; the original reference bytes stay read-only/NX. Thirty-five focused
source methods and all 86 packaged controls passed. The scoped audit covered
1,116 directories and 9,909 files with no residual grants, private broker
journals or workers in the validation roots. The frozen53 replay is running
at `output/vgk-upgrade-53/20261017T160420Z-244b242b` in the packaged offline
AppContainer worker. Actual initialization and unpacking remain unconfirmed. Interrupted
fixture reports remain incomplete; their journals were preserved separately
with hashes, stale grants revoked, and only unfinished cases resumed. Existing
completed reports were integrity-checked and retained without re-emulation.
The API's return-value contract is documented by
[Microsoft](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-dbgprompt).
The variable's meaning follows Microsoft's
[kernel debugger documentation](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/user-space-and-system-space);
the supported Windows 11 x64 profile uses the documented
[128-TB user address-space limit](https://learn.microsoft.com/en-us/windows/win32/memory/memory-limits-for-windows-releases).
The verified default remains build31;
the full source suite and broader package matrix were not repeated for this
unpromoted candidates. Their targeted gates do not replace the default's full
verification.

The real supplied driver exposed a false user-mode path from a low-address PCR,
then a missing lock-array pointer, then the signature-only `RtlPcToFileHeader`
stub. Those observations are concrete compatibility gaps, not proof that every
later stop is an intentional anti-emulation check. The sample remains an
experimental stress case; neither successful execution of one driver nor a
fixture matrix establishes complete Windows kernel compatibility.

## PowerShell execution and command capture

The experimental `powershell` CLI accepts supplied scripts inside Docker
Desktop's offline Linux VM. It captures evaluated parameters from a pinned,
instrumented engine and native exec arguments through an external observer.
Its required guest-tools build exposes all 42 bundled Windows enumeration
utilities through the same persona-backed x64 PE CPU/API models inside the
guest. Dynamic command names, nested evaluation, splatting, native argument
boundaries, offline DNS/ICMP, timeout retention, and the dashboard have been
verified with harmless fixtures. Runs remain partial: engine and utility
payloads are guest-generated, general Windows APIs/providers and shared
mutable Windows state remain incomplete, and complete capture or hostile
tamper resistance is not established. See
[POWERSHELL_CONFINEMENT.md](POWERSHELL_CONFINEMENT.md) for evidence and limits.

The 2026-10-15 obfuscation corpus verifies exact bound parameters through
ordinary transformations, 120 compressed layers, dynamic script blocks,
runspaces, child encoded commands, native argv, and a denied real web request.
All 20 cases pass. A reproduced long-source record overflow is fixed with
explicit source previews; built-in URI/header values are now readable without
running custom getters. Nineteen observer regression checks and fifteen
focused source tests pass. See
`output/powershell-obfuscation/final-20-verification.json` and the detailed
reproduction command in the confinement document. These checks do not prove
capture of every .NET method or unbounded parameter value.

The public-obfuscator matrix uses pinned Invoke-Obfuscation and Obfell sources
and retains stock-runtime reference results. Its layered trace reproduced the
4 MiB host capture limit. Both capture and authenticated validation now use a
shared 8 MiB cap. The original layered trace finishes with the same script
failure as stock PowerShell; a valid public BXOR control retains its final
decoded invocation after more than 5 MiB of trace data. Sixteen focused source
tests and the Docker trace-budget/cleanup probe pass. The current rebuilt
artifacts also pass the long control. Evidence and unsupported upstream
outputs are documented in
[POWERSHELL_CONFINEMENT.md](POWERSHELL_CONFINEMENT.md#public-obfuscator-regression-runs).

PowerShell-bound .NET calls now record resolved method/constructor identities,
closed generic types, and ordered evaluated values in the dashboard. The binder
and adapter hooks cover the tested static, instance, virtual, ref/out, optional,
`params`, reflection, and delegate paths, including encoded values and deep
compression. Reflection targets are labeled as supplied before CLR conversion.
All 17 method cases, 20 earlier obfuscation cases, 19 fixed observer checks,
and the long public BXOR control pass with the rebuilt engine. The 24 focused
source tests also pass (12 Docker integration tests are separately opt-in).
Calls entirely inside compiled CLR code, custom/ETS property access, dynamic method bodies,
and arbitrary object snapshots remain incomplete. See the
[method capture scope and repeatable verifier](POWERSHELL_CONFINEMENT.md#readable-net-method-calls).

Covered .NET property reads/writes now retain resolved identities, actual getter
results or setter inputs, index arguments, and started/completed/failed states.
Successful null results are distinct from failed reads. The same access is
evaluated once; setters are not read back, and input snapshots survive setter
mutation. Reflection inputs are explicitly labeled before CLR conversion.
See [property capture scope and verifier](POWERSHELL_CONFINEMENT.md#readable-net-property-access)
for coverage and remaining CLR-internal, ETS/custom adapter, field, and byref gaps.
All 21 property cases pass, including encoded names, PowerShell class properties,
single-evaluation counters, mutation of a setter's array input, and 40 compressed
layers. The 17 method and 20 earlier obfuscation cases, 19 observer checks, long
public BXOR control, and 28 focused source tests also pass. Evidence is linked in
the confinement document. The final live dashboard check verifies the actual
returned Unicode value. Concurrent runs reuse a validated runtime image after
reproducing an image-rebuild race.

## Worker build receipt and packaged utility assets

On 2026-10-15 (Europe/Berlin), pathping and deterministic ICMP reply patterns
passed **89 source/integration tests** and **85 packaged utility cases** (42
utilities on each architecture plus source CLI ping). After correcting an
overflow in the displayed duration estimate, the final artifacts passed four
native pathping tests, the PowerShell loss/dashboard integration test, two
packaged routed-loss cases, and the CLI/live-dashboard example. Evidence is
`output/pathping-verification.log`,
`output/pathping-package/final-85/verification.json`,
`output/pathping-final-native-tests.log`,
`output/pathping-final-container-tests.log`,
`output/pathping-package/final-routed/verification.json`, and
`output/pathping-package/powershell-demo-verification.json`.
The final worker SHA-256 is
`4110c1052d927f0d5c447dd4ccded65f4c4d3d2a8b65fe9168e907ea0c06a0d6`;
its receipt matches current source and all 20 native assets. The scoped scan
found zero explicit AppContainer SID grants, private broker journals, or
packaged worker processes across 600 directories and 9,889 files
(`output/pathping-package/cleanup-scan.txt`). Link-loss attribution remains an
estimate derived from offline probe outcomes; parallel Windows probe timing
and correlated forwarding loss are not modeled.

The offline traceroute addition passed **84 source/integration tests** on
2026-10-14 UTC, including all 41 utilities called from confined PowerShell,
96-probe trace retention, native x86/x64 TTL-error reply layouts, and threaded
PowerShell shutdown. The rebuilt worker passed **83 packaged utility cases**
(41 utilities on each architecture plus source CLI ping), followed by two
custom routed traceroute cases with twelve probes each. Evidence is
`output/tracert-verification.log`,
`output/tracert-package/final-83/verification.json`, and
`output/tracert-package/route-fixture/verification.json`. Its worker SHA-256 is
`90fb476f9112d0d149a6b6120f5b0210f0b365ba81212988d2beb455d6fd8717`;
all 18 native assets match the current source receipt. A scoped cleanup scan
of the package and traceroute outputs found zero explicit AppContainer SID
grants, private broker journals, or packaged worker processes across 588
directories and 9,582 files (`output/tracert-package/cleanup-scan.txt`).
These fixtures verify the listed modeled forms; they do not establish full
Windows utility compatibility or complete PowerShell command capture.

The PyInstaller build explicitly includes the generated x86/x64 PE resources.
`build.ps1` verifies that packaged utility bytes match the source assets, then
writes a receipt with the worker executable hash, source input hashes, and
guest asset hashes. The source `run` command checks that receipt against current
source before it reads the analysis input or creates an AppContainer. The portable
CLI checks executable and asset integrity without requiring a source checkout.
Missing or stale receipts produce a rebuild instruction. Missing or altered
utility assets and executable corruption also fail the preflight check.

This is a compatibility and corruption check, not signed attestation. Existing
run manifests still bind the entire worker bundle and execution inputs before
launch. Changing the receipt cannot establish trust in an untrusted executable.

The repeatable enumeration package gate is:

```powershell
.\build.ps1
.venv\Scripts\python.exe -m tools.verify_enumeration_package --output output\enumeration-package-fresh
```

It uses a fresh output directory, a custom persona, and offline replay mode.
Each supported read command must create the expected guest child, finish with
exit 0, emit output, and use the exact generated persona PE bytes. It covers
all bundled utilities on x86/x64 plus the source CLI's guest ping path. Parent
exit status alone does not pass this gate.

On 2026-10-14 UTC, the rebuilt worker passed all 81 cases: 40 generated
utilities on each architecture and the source CLI's offline ping child.
Every case verified AppContainer/job/child-process restrictions and engine
report integrity. Four build-receipt tests passed, including early CLI
rejection before sample parsing or container creation. Evidence is
`output/guest-enumeration-package/final-81/verification.json`.
The tested worker SHA-256 is
`16510ce2fdd32a074d22a8165d7a4468a8fa2eaf766ebc8856cfb966bfd8ca5f`;
the receipt verifies all 16 packaged guest PE resources. These checks cover
the supported read forms in the inventory, not arbitrary Windows command
syntax or a representative malware corpus.

Twelve fresh packaged containment checks created no host markers and rejected
direct private-mode invocation outside AppContainer. Three AppContainer smoke
configurations denied outside file/registry access, bundle writes, parent
process reads, and host child creation. Network-disabled profiles could not
connect to the internet or host loopback. The scoped cleanup scan covered
1,384 directories and 12,242 files and found zero explicit AppContainer SID
grants, private broker journals, or packaged Emumee processes. Evidence is in
`output/containment-probe/containment-results.json`,
`output/guest-enumeration-package/final-81/sandbox-smoke.json`, and
`output/guest-enumeration-package/cleanup-scan.txt`.

## 2026-10-14 generated enumeration programs

The default native guest now includes generated x86/x64 `ipconfig.exe`,
`cmdkey.exe`,
`klist.exe`,
`nltest.exe`,
`wbadmin.exe`,
`manage-bde.exe`,
`getmac.exe`, `systeminfo.exe`, `tasklist.exe`, `driverquery.exe`, `pnputil.exe`, `gpresult.exe`, `dsregcmd.exe`, `fltmc.exe`, `wevtutil.exe`, `schtasks.exe`, `arp.exe`, `route.exe`, `netsh.exe`, `netstat.exe`, `mountvol.exe`, `vssadmin.exe`, `bcdedit.exe`, `tzutil.exe`, `query.exe`, `quser.exe`, `qwinsta.exe`, `net.exe`, `net1.exe`, `sc.exe`, `reg.exe`, and `where.exe` files
in guest System32, alongside the
existing generated `hostname.exe` and `whoami.exe`. The generated text PEs call
guest `GetCommandLineA`, `GetStdHandle`, `WriteFile`, and `ExitProcess`; their
argument dispatchers also call guest `lstrcmpiA`. Their output bytes are
derived only from the selected persona. Direct guest child launches through
`WinExec` on both architectures printed custom persona values and added a
guest child entry point.
The `tasklist` rows use the same names, PIDs, and session mapping as the persona
process configuration. `tasklist.exe /svc` assigns active persona service names
to the first matching process PID; disabled services are absent. The generated
utility has a 64 KiB total embedded-text limit across its command views.
`pnputil.exe` has a 256 KiB limit for its bounded package and device views.
Its `/enum-drivers`, `-e`, `/enum-devices`, `/enum-devices /connected`, and
`/enum-classes` output comes from persona driver packages and PnP devices.
Synthetic package INF metadata appears only in the guest file system.
Unsupported change commands exit 87 without host device access.
`gpresult.exe /r` and its user or computer scope variants list only the
persona's applied policy names. Remote queries, detailed reports, and report
file writes exit 87 without host Group Policy or RSoP access.
`dsregcmd.exe /status` reports only modeled device join, workplace join, and
Azure AD PRT state from the persona. Unsupported registration changes exit 87;
the generated PE does not contact a host or cloud tenant.
`vssadmin.exe` lists configured guest shadow copies, the guest C: volume,
and a fixed guest system provider. Delete and resize commands exit 87 without
host VSS access.
`cmdkey.exe /list` reports only configured guest credential metadata. The
default store is empty, password fields are rejected, and credential changes
exit 87 without host credential store access.
`klist.exe` default and `tickets` views use persona Kerberos cache metadata,
also returned by guest LSA current-session ticket-cache queries. Both native
pointer widths have bounded in-buffer strings and process-owned response
buffers. The default cache is empty; ticket requests and changes exit 87.
Encoded tickets and usable keys are not modeled.
`nltest.exe` reports configured domain controllers and trusts without DNS or
network discovery. Supported domain aliases come from the persona's DNS and
NetBIOS names. Missing controller records return exit code 1355; unsupported
targets and change commands exit 87. The generator stores a status per output
view, so a modeled domain failure is distinguishable from a successful query.
`wbadmin.exe get versions` reports only configured backup catalog metadata.
The persona admin flag gates access; non-admin views exit 5 without exposing
records. Remote targets and catalog changes exit 87. Backup targets are display
metadata and are never opened; live elevation and backup services are unmodeled.
`manage-bde.exe -status` and `-status C:` read guest capacity and BitLocker
metadata. `GetDiskFreeSpaceExA/W` uses the same configured capacity and free
space for guest directories on C:. Output buffers are validated before writes;
unknown volumes fail. Capacity is a snapshot without quotas or dynamic
accounting. BitLocker changes and remote queries exit 87.
Generated `ipconfig.exe /all` prints the persona's
hostname, adapter description, MAC address, DHCP flag, IPv4 settings, and DNS
servers. Bare-name and quoted full-path `WinExec` launches reached that output
on both architectures. A supplied `/release` argument exited 87 without output;
other switches are likewise unmodeled. Generated `arp.exe -a` prints the
same broadcast cache entry as guest `GetIpNetTable`, or no entries for a
`/31` or `/32` adapter; `-d` exits 87 and does not modify any cache.
Generated `route.exe print` and
`route.exe print -4` print the persona's IP Helper route snapshot; `route add`
exits 87 without changing guest or host routes. Generated `tzutil.exe /g`
prints the configured fixed-offset time zone; `/s` exits 87. Generated
`netsh.exe interface ipv4 show config` and `show dnsservers` read the persona
adapter snapshot; `interface ipv4 set address` exits 87. `getmac.exe`,
`systeminfo.exe`, and `tasklist.exe` currently support their no-switch view
only. Generated `query.exe user`, `query.exe session`, `quser.exe`, and
`qwinsta.exe` report the modeled console user in session 1 and services
session 0; the logon time comes from
the guest clock and uptime. Other `query` forms exit 87. These are bounded guest utilities, separate from the real
Microsoft binaries staged in earlier compatibility probes. They do not read or
launch host binaries. The text PEs render process and network data at setup,
so later changes are not reflected in those initial snapshots.

Generated `net.exe` and `net1.exe` list the persona user and fixed local
Administrator and Guest accounts. Their local Users and Administrators views
use the guest token's admin membership; account mutation forms such as
`net user Morgan /add` exit 87 with no output. This is a bounded snapshot,
not a general SAM or domain account implementation.

Generated `sc.exe` reads the configurable persona service list and prints
active, all, or named service queries. A service's running state follows its
named process in the persona process snapshot, and the same list generates
guest service registry keys. The default list has WinDefend and EventLog.
Only the first three configured services have named query variants; list
queries include all. Unsupported `stop` exits 87 without changing service
state. This is a setup snapshot, not a dynamic Service Control Manager.

The included `reg.exe` is built from the repository's small guest C source
without a C runtime. It calls guest `RegOpenKeyExW`, `RegEnumValueW`, and
`RegEnumKeyExW`, and `RegQueryValueExW`, so local key queries read current guest
registry values and subkeys. Quoted paths, named `/v` queries, default `/ve`
values, and recursive `/s` queries work on x86 and x64. Recursion is bounded
to 24 levels, 512 keys, and 256 Ki characters of output. `reg add` and `/f`
exit 87, and missing keys or values return error 2. It neither queries
nor modifies the host registry. A locally staged Microsoft `reg.exe` remains
a separate compatibility path with additional Windows command behavior.

The included `where.exe` uses guest `GetCurrentDirectoryW`,
`GetEnvironmentVariableW`, and `GetFileAttributesW` to search one simple file
name in the current directory and up to 32 guest `PATH` entries. It adds `.exe`
when no extension is supplied. A real host file in the guest current directory
was absent from the guest lookup on both architectures; a persona virtual file
in that same directory was found. Wildcards, `/r`, and multiple names exit 87.

The included `netstat.exe` reads a guest-owned IPv4 TCP table through
`GetExtendedTcpTable`. The default, `-an`, and `-ano` forms show live outbound
guest TCP connections only; `-ano` includes guest PIDs. The local address is
the persona address and the local port is synthetic, so broker socket ports
and host network state are not exposed. Guest socket closure and process exit
remove rows. UDP, listening sockets, IPv6, and other switches remain open.

The included `fsutil.exe` supports read-only `fsinfo drives`, `drivetype C:`,
and `volumeinfo C:` on x86 and x64. The volume query calls guest
`GetVolumeInformationW`, which supplies the same C: label, serial, filesystem,
and maximum component length seen by programs calling that API directly.
Other drives return path-not-found and unsupported commands exit 87. It does
not query host volumes.

Generated `mountvol.exe` lists the single guest `C:` mount and supports
`C:\ /L`. Its GUID is a configurable persona field and matches the guest
`GetVolumeNameForVolumeMountPointA/W` hook. Other mounts and mutation commands
exit 87 without reading or modifying host volume state.

Generated `bcdedit.exe` supports default active enumeration, `/enum`,
`/enum active`, `/v`, `/enum active /v`, and `/enum {current}`. The two entries
use validated persona `boot_config` values, the guest locale, and the sole
`C:` volume. `/set` and other unsupported commands exit 87 with no output
and no host BCD access. A full guest BCD hive and broader read modes remain
unmodeled.

The included `wevtutil.exe` uses guest registry APIs to enumerate configured
event channel names (`el`) and read each channel's enabled state, maximum
size, retention flag, and log path (`gl <channel>`). The persona's
`event_channels` list generates those guest keys unless a custom registry
replaces them. The packaged x86/x64 PEs import only Kernel32 and Advapi32;
they do not query the host Event Log. Event records and `.evtx` files remain
unmodeled, and `qe` exits 87.

Generated `driverquery.exe` reports bounded persona `drivers` records through
its default, `/v`, `/fo list`, `/fo csv`, and `/nh` views. The same records
create guest Services registry keys. A custom persona can replace the default
list; a child process cannot enumerate host drivers. `.sys` image content,
kernel execution, signed driver data, remote queries, and combined flags remain
unmodeled.

Generated `fltmc.exe` reports the persona's running file-system minifilters
through its default, `filters`, `instances`, and `volumes` views. Filter names,
altitudes, and instance counts agree with guest driver records and Services
registry instance keys; the sole volume agrees with the persona's `C:` GUID.
The default Defender persona includes `WdFilter`. Unsupported `unload` exits
87 without touching a host driver or Filter Manager.

Generated `schtasks.exe` prints the persona's bounded scheduled-task snapshot.
It supports the default query, `/query`, `/query /fo LIST`, `/query /fo CSV`,
and named queries for up to two ASCII task names. Custom task paths, status,
and next-run offsets are validated before emulation; dates derive from the
guest clock and fixed time-zone offset. An audit fixture's `/Create` command
now launches the guest PE and exits 87 without registering a task. Task
Scheduler APIs, task definition files, and execution remain unmodeled.

The default `whoami.exe` now uses the same generated, argument-aware guest PE
builder. Its default view still reports the persona computer and user; `/user`
reports the configured SID, `/groups` lists the guest token groups, `/priv`
lists the guest token privileges, and `/all` combines those views with the
modeled empty claims state. Administrators and debug privilege appear only for
an admin persona. Unsupported `/upn` exits 87 without output. The earlier small `GetUserNameA` PE remains a test
fixture, but is no longer installed as the default guest `whoami.exe`.

## 2026-10-14 native byte comparison and pantry revision

The default persona now has 54 virtual files. `pantry-inventory-updated.csv` changes the milk count from zero to one while keeping the file the same byte length as `pantry-inventory.csv`; both follow custom guest user names. Locally staged Microsoft x86 and x64 `comp.exe` programs, companion `ulib.dll` binaries, and MUI resource files complete `/M /D` comparisons of the two guest files. Both print `Compare error at OFFSET 18`, `file1 = 48`, and `file2 = 49`, with guest exit 1, empty stderr, no reported emulator errors, and no signature-only calls. A read-only host `comp.exe` comparison of the same bytes returned the same offset and values. Same-file `/M` controls print `Files compare OK` and exit 0 on both architectures; missing-file controls print an error and exit 2. The six reports are `output/probe-comp-pantry-x64`, `output/probe-comp-pantry-x86`, `output/probe-comp-x64-same`, `output/probe-comp-x86-same`, `output/probe-comp-x64-missing`, and `output/probe-comp-x86-missing`. Microsoft binaries are local inputs and are not distributed.

The initial `comp.exe` run stopped at `msvcrt._wcslwr`. A bounded guest-only ASCII model now lowercases its wide string in place and checks read and write access. Focused string and persona tests cover the new API and file pair. The initial `certutil.exe -hashfile` source probe at `output/probe-certutil-hash-initial` returned from CRT startup without reading the guest file or producing output; it is not counted as supported. Other `comp.exe` switches, non-ASCII case mapping, and general Windows utility coverage remain unverified.

## 2026-10-14 native file comparison and x64 file-handle failure

At that stage, the default persona had 53 virtual files. Four new files form a work-document revision pair, a pantry inventory consistent with the shopping list, and a grocery receipt. User-name overrides regenerate their guest paths. Locally staged Microsoft x86 and x64 `fc.exe` binaries, companion `ulib.dll` binaries, and MUI resource files complete a comparison of `project-brief-draft.txt` with `project-brief-final.txt`: stdout contains the changed lines and `msvcrt.exit` receives 1. Comparing the draft to itself prints `FC: no differences encountered` and exits 0. The missing-file control prints `cannot open ... ABSENT.TXT` and exits 2. The six final source reports are `output/probe-fc-persona-revisions`, `output/probe-fc-persona-identical`, `output/probe-fc-missing-fixed`, `output/probe-fc-persona-x86`, `output/probe-fc-persona-x86-identical`, and `output/probe-fc-persona-x86-missing`. Each has no reported emulator errors or signature-only calls. The Microsoft binaries are local test inputs and are not distributed.

`fc.exe` initially stopped at `msvcrt.wcsncmp`, then printed unformatted fragments because `CharUpperW` was signature-only and the explicitly staged companion DLL was absent from the guest resource-image index. The guest now has bounded `wcsncmp` and ASCII `CharUpperW` behavior and indexes staged companion bytes for MUI message lookup. A missing-file probe also found that failed x64 `CreateFileW` returned zero-extended `0x00000000FFFFFFFF`, so the program treated the invalid handle as usable. The bridge now returns pointer-width `INVALID_HANDLE_VALUE`; host `fc.exe` returned 2 for the same missing-file pattern. Focused tests cover the string calls, both file-handle widths, persona paths, MUI handling, and adjacent guest-file lifecycle behavior: 57 source tests and four acceptance cases pass. This establishes the tested x86/x64 text comparison paths; other `fc.exe` options, binary comparisons, Unicode case mapping, and general Windows program coverage remain unverified.

## 2026-10-14 registry enumeration and key metadata

The guest registry bridge now models `RegEnumValueA/W`, `RegEnumKeyExA/W`, and `RegQueryInfoKeyA/W` for configured persona keys and guest-created keys. Value enumeration returns encoded value bytes and types; child-key enumeration includes configured paths even when the registry manager has not opened them yet. Key metadata supplies counts, maximum name and data lengths, and a guest-clock FILETIME. Read-only host Windows API checks established the short-buffer behavior: a short name buffer leaves its length unchanged, while a short data buffer still receives the name and type and reports the required byte count. The implementation follows Microsoft's [RegEnumValue](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumvaluew), [RegEnumKeyEx](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regenumkeyexw), and [RegQueryInfoKey](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeya) contracts for these paths. Registry classes and security descriptors are represented as empty; real access control, full redirection, and transaction semantics remain unmodeled.

Successful guest registry writes now remain visible when a configured key is reopened during the same run; a focused test checks value enumeration and cross-encoding `RegQueryValueExA` after a wide-string write. The ten registry-hook tests and 22 persona tests pass. Locally staged Microsoft x64 and x86 `reg.exe` with matching MUI files complete `query HKCU\Control Panel\Desktop`, printing all four configured values, and `query HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer`, printing all six immediate child keys. Each of the four source probes has empty stderr, no reported errors, and no signature-only calls; their reports are under `output/probe-reg-enum-final-values`, `output/probe-reg-enum-final-subkeys`, `output/probe-reg-enum-final-x86-values`, and `output/probe-reg-enum-final-x86-subkeys`. These binaries are local test inputs and are not distributed. Recursive queries and unrelated registry paths remain unverified.

## 2026-10-14 public IP Helper tables and CRT uppercasing

The guest now models the documented `GetIfTable`, `GetIpAddrTable`, and `GetIpNetTable` buffer contracts. The interface row reports the persona Ethernet index, MTU, MAC, description, and 1 Gbit/s speed. The IPv4 address row uses the same address, mask, and index as the adapter and route models. The neighbor table contains a static subnet broadcast mapping; it does not invent a gateway MAC, and returns `ERROR_NO_DATA` for a `/31` network. These are bounded one-interface subsets; loopback and real network traffic counters remain unmodeled. The table layouts and size/error paths follow Microsoft's [GetIfTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getiftable), [GetIpAddrTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getipaddrtable), and [GetIpNetTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getipnettable) documentation. Focused source tests cover both pointer widths, exact row bytes, null and short buffers, unmapped outputs, custom persona addresses, and the `/31` case.

A bounded `msvcrt._strupr` model uppercases a guest string in place using single-byte CP1252 mappings and checks write access before changing the buffer. A locally staged x64 Microsoft `route.exe print -4` source probe advanced past its former `_strupr` blocker and printed the interface and route-table headings, then stopped at undocumented `nsi.NsiAllocateAndGetTable`; a `FormatMessageW` insert also remains unsupported on its error path. The staged Microsoft binary's route listing is not verified. A source x64 `ipconfig.exe` regression at `output/real-ipconfig-network-table-regression` printed the persona Ethernet address, mask, and gateway with no recorded errors. The 65 focused network, CRT, and persona tests pass. Microsoft binaries are local test inputs and are not distributed.

## 2026-10-14 guest IPv4 routes and API-set DLL loading

`GetIpForwardTable` now returns a bounded [MIB_IPFORWARDTABLE](https://learn.microsoft.com/en-us/windows/win32/api/ipmib/ns-ipmib-mib_ipforwardtable) derived from the persona adapter: default gateway, on-link subnet, and local address routes. It honors the null and undersized buffer query with `ERROR_INSUFFICIENT_BUFFER`, checks the entire caller buffer before writing, and keeps interface index and IPv4 byte order consistent with the [documented row layout](https://learn.microsoft.com/en-us/windows/win32/api/ipmib/ns-ipmib-mib_ipforwardrow). Unit tests cover exact bytes, custom address/prefix/index, short and invalid buffers, and x86/x64 guest widths. The guest loader now handles API-set `LoadLibraryA/W`, `LoadLibraryExA/W`, `GetProcAddress`, and `FreeLibrary` through the same guest-only DLL path as their `kernel32` names. Two existing DLL lifecycle tests and all ten network adapter tests pass; a packaged x64 `tzutil /g` regression at `output/real-tzutil-loader-regression/20261014T151320Z-9d6218e1` still prints the expected persona zone.

Locally staged Microsoft x64 `arp.exe -a` initially reported IPv4 unavailable because `GetIpForwardTable` was signature-only (`output/real-arp-x64-probe1/20261014T150723Z-eb425b62`). With the route model, `arp.exe` requests `inetmib1.dll`. An API-set loader path had delegated to Speakeasy's mapper and failed on a memory write; the guest loader alias now denies an absent guest System32 path cleanly (`output/real-arp-x64-probe5/20261014T151158Z-42a50b0a`). When a local probe persona places explicitly staged `inetmib1.dll` and `snmpapi.dll` at guest System32, both companion DLLs load and execute guest code, but `arp.exe` stops on undocumented `iphlpapi.InternalGetIfTable` (final rebuilt package: `output/real-arp-x64-final/20261014T151736Z-0ae9fb1e`). `RtlInitializeResource` and `RtlAcquireResourceExclusive` are also still signature-only on that path. **ARP listing is not yet supported.** The locally staged x64 `chcp.com` probe returned 0 with empty output, so its code-page display is likewise unverified. Microsoft binaries are not distributed.

## 2026-10-14 native time-zone query

The default persona now exposes a matching active Time Zones registry key and 44-byte `TZI` binary value. Configured `REG_BINARY` values with a `hex:` prefix decode to exact guest bytes, and configured `REG_DWORD`/`REG_QWORD` strings decode to bounded little-endian values through `RegQueryValueExA/W` and `RegGetValueA/W`. `GetTimeZoneInformation` and `GetDynamicTimeZoneInformation` return the documented [172-byte base layout](https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/ns-timezoneapi-time_zone_information) and [432-byte dynamic layout](https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/ns-timezoneapi-dynamic_time_zone_information) using the persona's fixed UTC offset and Windows time-zone name. The guest registry, both time-zone APIs, and `tzutil /g` agree that automatic daylight adjustment is disabled; transition rules and automatic seasonal changes remain unmodeled. A bounded `msvcrt.wprintf` hook captures literal output and `%s`/`%S` strings, and rejects other format specifiers visibly.

The final isolated package ran locally staged Microsoft x64 `tzutil.exe /g` at `output/real-tzutil-x64-release/20261014T150542Z-7203e709`: it returned 0 and captured `Eastern Standard Time_dstoff` on stdout, with empty stderr and zero reported errors or denied operations. An x86 run at `output/real-tzutil-x86-probe1/20261014T150400Z-fa837b37` returned the same stdout and status with zero errors or denials. A custom-persona x64 control at `output/real-tzutil-x64-custom/20261014T150310Z-5043a0a4` returned 0 and printed `W. Europe Standard Time_dstoff`, likewise without reported errors or denials. The 63 focused clock, CRT, registry, and persona tests pass. These observations establish the tested `/g` path only; other `tzutil` commands remain unverified. Microsoft binaries are local test inputs and are not distributed.

## 2026-10-14 guest machine GUID

The default persona now provides `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` as a `REG_SZ` GUID. It is deterministically derived from the configured guest hostname, has UUID version 4 and RFC variant bits, stays stable when only the guest account name changes, and never reads the host machine's identifier. Persona tests check the default registry value, repeatability, and hostname/account overrides. A locally staged Microsoft x64 `reg.exe` query at `output/real-reg-machineguid-final/20261014T144815Z-36df05f4` returned the exact generated GUID with guest exit 0, empty stderr, zero reported errors, and zero denied operations. The Microsoft binary is not distributed.

## 2026-10-14 large native reservation probe

Locally staged Microsoft x64 `sort.exe` requested a 0xFFFFE000-byte `VirtualAlloc` reservation while opening the persona shopping list. Speakeasy's installed handler maps even reserve-only requests immediately; the guest API map guard correctly stopped that 4 GiB backing attempt. The `VirtualAlloc` bridge now returns `NULL` with `ERROR_NOT_ENOUGH_MEMORY` for requests above its 32 MiB backing limit, with a failed-allocation event, instead of aborting the entire guest run. A focused test checks that the oversized request never reaches the engine. In the rebuilt package at `output/real-sort-x64-probe2/20261014T142145Z-58c61b85`, `sort.exe` continued to its error path and exited 1 without sorted output. Sparse address-space reservation remains unimplemented, so this is a resource-limit correctness fix, not `sort.exe` compatibility. The probe's error path also exposed signature-only `FormatMessageA` and NTDLL conversion handlers; their effects remain unverified.

The x64 `tree.com` probe at `output/real-tree-x64-probe1/20261014T141725Z-50e12e9f` accepted the native PE image but produced no tree listing. A staged x64 `find.exe` probe at `output/real-find-x64-probe1/20261014T142229Z-ca84d110` likewise returned from its entry point without search output. Neither utility is counted as functionally supported on that evidence. Microsoft binaries are local test inputs only and are not distributed.

## 2026-10-14 profile paths and expandable registry values

At this stage, the default desktop persona had 49 deterministic virtual files, including calendar, contact, household, receipt, download, and OneDrive documents. Two files are binary: a valid PDF train receipt and a ZIP archive containing the same checklist and expense CSV as the loose Downloads files. Persona overrides accept strict base64 for binary files with a 1 MiB decoded per-file limit and 16 MiB aggregate limit. A source x64 Microsoft `findstr.exe` run read the PDF through the guest file bridge, returned 0 with the receipt text on stdout and no recorded errors. This verifies file reading, not PDF rendering or ZIP extraction by a guest application. Its Program Files, Common Files, Windows INF/Media, and default profile directories are represented alongside matching environment and registry paths. HKLM `CurrentVersion` now has Program Files and Common Files values; `ProfileList` has its common profile roots. HKCU and HKLM shell-folder values include Start Menu, Programs, Startup, Recent, and SendTo paths. These are a consistent modeled desktop snapshot, not evidence that Windows installed or used the files.

The locally staged Microsoft x64 `reg.exe` completes `query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion /v ProgramFilesDir` with `C:\Program Files` at `output/real-reg-programfiles/20261014T140241Z-c127b339`. Its `ProfilesDirectory` query at `output/real-reg-profiles-final/20261014T140920Z-0ec5543a` prints `REG_EXPAND_SZ    %SystemDrive%\Users`; the `ProgramFilesPath` query at `output/real-reg-programfilespath/20261014T140945Z-f55e6f92` prints `REG_EXPAND_SZ    %ProgramFiles%`. A missing-value control at `output/real-reg-programfiles-missing/20261014T141051Z-b7b9f468` returns guest exit 1 and the expected missing-value error. On the final package, the `Startup` shell-folder query at `output/real-reg-startup/20261014T141333Z-dc5bbc6e` prints the persona user's roaming Startup path. The same package runs x64 `findstr.exe SUMMARY C:\Users\Alex\Documents\Work\schedule.ics` at `output/real-findstr-calendar/20261014T141310Z-968eedeb` and captures `SUMMARY:Weekly planning\n`. Each positive probe completed with zero reported errors or denied operations.

`RegGetValueA/W` now expands `REG_EXPAND_SZ` from the guest environment unless `RRF_NOEXPAND` is set, reports the expanded data as `REG_SZ`, and bounds the output. A read-only host API check found that Windows reports the larger of the unexpanded and expanded byte counts for these size-query paths; the guest model follows that behavior, allowing `reg.exe` to size a buffer and then request the unexpanded value. Type-specific `RRF_RT_*` filtering, `RRF_ZEROONFAILURE`, and complete registry redirection remain unmodeled. The 24 persona and registry hook tests and six existing registry acceptance cases pass; the packaged probes establish only the named commands and x64 paths.

## 2026-10-14 `find.exe` console and startup follow-up

The x64 Microsoft `find.exe` source probe at `output/real-find-coffee-control` uses the persona shopping list, staged `find.exe.mui`, `ulib.dll`, and `ulib.dll.mui`. With guest argument `Coffee` and quote index 0, its raw command line contains `"Coffee"` while CRT `argv[1]` contains `Coffee`. It prints the file header and `Coffee\r\n` with no reported errors. The `AbsentPhrase` control at `output/real-find-absentphrase-control` prints only the header. Speakeasy's `FindFirstFileW` originally returned zero size for the 18-byte file, `RtlIsTextUnicode` incorrectly classified its ASCII bytes as Unicode, and `WideCharToMultiByte` returned a stale upper 32-bit count. The guest model now supplies bounded file metadata and string conversion. A plain, unquoted raw term still produces the guest's “Parameter format not correct” message. Other switches, encodings, and x86 remain untested.

An API-set mapping follow-up at `output/real-find-mapping-ro` preserves that `Coffee` output and records a successful configured-file mapping create, read-only view, and mapping-handle close. Before this change, the same guest program closed its mapping handle with a failure because the API-set creation bypassed handle ownership tracking. The configured persona file path is restricted to staged guest bytes and a read-only mapping; a focused unit test rejects a writable mapping. Existing named pagefile, duplicate mapping, and inherited-handle fixtures pass. Other API-set mapping variants remain unverified.

A source-suite fail-fast run exposed a managed runner `KeyError` when a persona file used the existing validated base64 form. The managed file seed now uses the shared persona decoder; the managed file lifecycle test verifies both the PDF and ZIP magic bytes, and the previously failing managed exception-region test passes. A subsequent broad fail-fast run was stopped during long guest cases without a final result, so this change has focused test evidence rather than a completed full-suite pass.

The stricter console handles put the real x64 `hostname.exe` onto its CRT `fwprintf` path. Bounded wide standard-stream formatting now handles its `%ls` output. A source regression run prints `DESKTOP-7F4M2Q9\n` without reported errors; `findstr.exe` still prints `Coffee\n` in its named search probe. The 53 focused tests for CRT, console, startup, and strings pass.

## 2026-10-14 `attrib.exe` path follow-up

The staged x64 Microsoft `attrib.exe` previously reached an API-set `GetFullPathNameW` call through Speakeasy's default handler, which returned only 3 for the static `*.*` pattern. Registering the existing guest path model for `api-ms-win-core-file-l1-1-0` changed that return to the full guest path length and advanced execution to `msvcrt._wcsupr` and `wcscspn`. Bounded in-place wide uppercasing and wide reject-set scanning now handle those calls. The resulting named-file probe at `output/real-attrib-x64-wcscspn/20261014T135426Z-e7dfcbd2` completes after 20,281 instructions with no reported errors and reaches `FindFirstFileW`.

The report still has empty stdout. A missing-file control at `output/real-attrib-x64-missing/20261014T135723Z-d88fb216` also returns 0 with empty stdout, and both traces call `FindFirstFileW` on the persona Downloads directory. Attribute-query behavior remains unverified; the successful return must not be interpreted as a working file lookup.

The 57 focused source tests for the changed path, CRT, console, locale, delay-import, heap, and reporting models pass. This follow-up does not repeat the full source suite.

## 2026-10-14 x64 `findstr.exe` and `attrib.exe` probes

An isolated alternate worker package exercised locally staged Microsoft Windows binaries; the binaries and MUI files are not redistributed. The real x64 `findstr.exe` with `en-US/findstr.exe.mui` searched the default persona file `C:\Users\Alex\Documents\Household\shopping-list.txt` for `Coffee`. The final offline replay report at `output/real-findstr-x64-final/20261014T134622Z-33db5cb5` completed after 6,168 guest instructions, returned 0, captured `Coffee\n` on stdout, and recorded no errors or denied operations. The trace includes a successful virtual `CreateFileA` and a console `WriteFile` through `api-ms-win-core-file-l1-1-0`. A missing-pattern control at `output/real-findstr-x64-missing/20261014T134126Z-3fd9e442` returned 1 with empty stdout and no errors. Other switches, encodings, input sizes, and x86 remain untested.

The real x64 `attrib.exe` with `en-US/attrib.exe.mui` and companion `ulib.dll` completed its default invocation (`output/real-attrib-x64-probe9/20261014T133511Z-a0455291`) and a named shopping-list invocation, repeated on the final package (`output/real-attrib-x64-final/20261014T134641Z-68fa0240`). Both returned 0 with no reported errors, but stdout was empty and no attribute listing was verified. This is evidence for startup and the tested return paths only.

The changes that enabled these probes include bounded PE delay-import resolution to guest API call gates, selected legacy CRT and NTDLL string/heap hooks, single-byte persona code pages, console buffer and thread language models, and API-set file-write capture. Delay imports currently support named RVA descriptors only; ordinal and malformed descriptors fail visibly. OEM-to-Unicode and `CharToOemA` conversion currently support ASCII input only. These hooks are tested on the stated call paths, not a general implementation of Windows CRT, NLS, console, or delay loading.

The source discovery run executed 567 tests in 673 seconds with one skip and one failure in a concurrently edited, untracked audit-probe test. The failure was its initial expectation that no registry cleanup event would occur; the current test excludes the expected cleanup event and its two cases pass when rerun after the edit. The 51 focused native-loader, CRT, console, locale, heap, and reporting tests pass on the final source; the final packaged `findstr.exe` and `attrib.exe` probes also pass after the `_snwprintf_s` truncation correction.

## 2026-10-14 real Windows `where.exe` follow-up

The rebuilt AppContainer package completes locally staged Microsoft x64 and x86 `where.exe hostname.exe` with exact guest stdout `C:\Windows\System32\hostname.exe\n`, empty stderr, zero reported errors, denials, and network attempts. The runs are `output/real-where-x64-probe6/20261014T123639Z-9c827769` (30,814 instructions) and `output/real-where-x86-probe1/20261014T123709Z-a55c7681` (40,201). Both return 0 from the guest entry point. The x64 missing-name control `output/real-where-x64-missing2/20261014T123922Z-7a76ab9c` completes with no errors, stdout empty, stderr `INFO: Could not find files for the given pattern(s).\n`, and guest entry return 1. The x86 EXE came from local SysWOW64 and was paired with the local System32 en-US MUI resource because a SysWOW64 copy was unavailable; neither Microsoft file is distributed in Git.

The guest-owned `GetFullPathNameA/W` model resolves against the current guest directory and handles length queries and a bounded output buffer. `GetLongPathNameA/W` requires an existing guest path and supports the common case where no short-name expansion is needed. Explicit 8.3 alias expansion remains unsupported. A bounded legacy `msvcrt.towupper` model removed the last unsupported import on the successful path. The report's signature-only detector now excludes uppercase diagnostic labels such as `INFO:` while retaining modeled parameter labels. The source suite passed 545 tests with one skip in 585 seconds, and focused path tests passed after the last drive-root correction. A final rebuilt package repeated the x64 and x86 positive checks at `output/real-where-x64-final/20261014T125029Z-e55180df` and `output/real-where-x86-final/20261014T125044Z-b080174b`; both completed with the same exact stdout and zero errors or network attempts. These checks establish the tested search commands, not arbitrary `where.exe` switches or Windows path forms.

## 2026-10-14 native utility follow-up

A locally staged x64 Microsoft `tasklist.exe` and its MUI resource reached 33,186 guest instructions but remained partial in its COM and thread-token path. A locally staged x64 Microsoft `where.exe` initially reported a missing `PATH`; the persona now supplies Windows System32, Windows, and Wbem directories, with guest environment overrides retained. Bounded guest-only legacy `msvcrt.wcstok` and `shlwapi.StrTrimW` models were added. The rebuilt `where.exe hostname.exe` probe reached `GetFileAttributesW` and `GetFullPathNameW` at 10,161 instructions, then ended in an unmapped guest memory write. Its report is `output/real-where-x64-probe3/20261014T121720Z-59a90fc0`. Neither utility has a completed command result. The Microsoft binaries stay in ignored local output directories. The source suite passed 537 tests with one skip in 620 seconds.

## 2026-10-14 real Windows `ipconfig.exe` follow-up

The rebuilt AppContainer package completes locally staged Microsoft x64 and x86 `ipconfig.exe` under both the default and a changed persona. All four runs have empty error lists, stderr, denied operations, and network attempts. The default x64 and x86 runs are `output/real-ipconfig-x64-final/20261014T114833Z-776a0bb8` (2,422 guest instructions) and `output/real-ipconfig-x86-probe1/20261014T114857Z-3b7254a5` (2,593). Their stdout is identical and prints the persona Ethernet interface, `192.168.1.107`, `255.255.255.0`, and `192.168.1.1`. The changed-persona runs are `output/real-ipconfig-x64-custom/20261014T114930Z-c935ce1b` and `output/real-ipconfig-x86-custom/20261014T114941Z-808f7880`; their identical stdout prints `Office LAN`, DNS suffix `corp.example`, `10.44.8.57`, `255.255.240.0`, and `10.44.0.1`. The x86 EXE came from local SysWOW64 and was paired with the local System32 en-US MUI resource because a SysWOW64 copy was unavailable; neither Microsoft file is distributed in Git.

This path models `ConvertLengthToIpv4Mask`, `RtlIpv4AddressToStringExW`, `InetNtopW`, a bounded MUI message-table parser with wide string inserts, null `DnsFree`, and a guest feature-configuration store with no overrides. The packaged commands finish after `msvcrt.exit(0)` with `status=completed`; the summary's `guest_entry_return` is 1, so the evidence supports this printed command path and successful worker result rather than a general exit-code claim. The feature query models absent overrides and does not claim to represent arbitrary Windows feature states. The final rebuilt package repeated the default x64/x86 checks at `output/real-ipconfig-x64-final2/20261014T120238Z-d86d761c` and `output/real-ipconfig-x86-final2/20261014T120250Z-e7232fa5`, both completed with zero errors or network attempts. After the identity correction, x64 completed again at `output/real-ipconfig-x64-final3/20261014T120732Z-e2652ce3`. The source suite passed **531 tests with one skip** in 575 seconds before the last network and identity additions; 44 focused adapter, string, message, and persona tests passed across the final changes.

The x64 and x86 `/all` probes reached `GetNetworkParams` with a size query and a filled persona `FIXED_INFO`; both printed the host name, empty workgroup DNS suffix, hybrid node type, and disabled routing/proxy state. The final reports are `output/real-ipconfig-all-x64-probe5/20261014T120744Z-b7291a9c` and `output/real-ipconfig-all-x86-probe1/20261014T120829Z-bed831a9`. Both remain **partial** at the undocumented `DnsQueryConfigAllocEx` export. The new `CompareStringW` handling accepts the case, kana, and width flag combination for ASCII switch matching. Other `ipconfig` switches, multiple interfaces, IPv6 enumeration, DNS queries, and broader applications remain unverified.

## 2026-10-14 real Windows `ipconfig.exe` probe

The locally staged Windows x64 `ipconfig.exe` and its `en-US/ipconfig.exe.mui` resource file exercise a new persona-owned IPv4 adapter model. `GetAdaptersAddresses` now returns a required buffer size, then writes bounded guest-only adapter, unicast, DNS, and gateway structures with pointers into the caller's guest buffer. The default persona and its TCP/IP registry entries share the same address, subnet, gateway, DNS server, and adapter identity. A process-owned `msvcrt.setlocale` model also moves the program through its CRT startup. The rebuilt packaged run `output/real-ipconfig-x64-probe3/20261014T112545Z-ae44935d` progressed to 1,390 guest instructions and two adapter calls, with zero denied operations and network attempts. It remains **partial**: address formatting, subnet conversion, feature configuration, and resource message formatting need further coverage. Microsoft binaries are excluded from Git. The focused adapter graph and persona tests pass on x86 and x64 pointer layouts. The full source suite passed **523 tests with one skip** in 619 seconds; focused CRT and adapter tests passed again after the final guard changes. This probe does not establish a working `ipconfig.exe` command yet.

## 2026-10-14 real Windows `reg.exe` query follow-up

The locally staged Windows x64 and x86 `reg.exe` programs, with their matching `en-US/reg.exe.mui` files, now complete `query "HKCU\Control Panel\Desktop" /v ScreenSaveActive` against the default guest registry. Both returned 0 with stdout `HKEY_CURRENT_USER\Control Panel\Desktop` and `ScreenSaveActive    REG_SZ    1`, empty stderr, no reported errors, no denied operations, and no network attempts. The packaged reports are `output/real-reg-release-x64/20261014T111201Z-02ce1613` (13,752 guest instructions) and `output/real-reg-release-x86/20261014T111218Z-1a6f10cf` (16,811). Input binaries and MUI files came from the local Windows installation and are excluded from Git.

The compatibility work covers per-thread guest CRT errno storage, the UCRT x86 split 64-bit options ABI, bounded narrow and wide formatting with dynamic field widths, API-set registry and resource aliases, sign-extended predefined HKEYs, `RegGetValueW` size and data queries, and CRT process exit. The guest argument vector now uses the CLI's parsed arguments so paths with spaces reach the program without literal quote characters. `RegGetValueW` reports unsupported expansion of `REG_EXPAND_SZ` values rather than silently returning raw data. These probes establish this one query path, not general `reg.exe` command coverage or full Windows registry semantics.

The complete source suite passed **519 tests with one skip**. A focused registry case also checks that `RegGetValueW` reports the required size without overwriting a too-small guest buffer.

## 2026-10-14 desktop profile and registry-tool probe

The default desktop profile now has 41 guest files and 58 registry keys. Added work, household, receipt, calendar, media, shell, Run/RunOnce, desktop, timezone, and locale details derive from the configured persona where applicable. A custom de-DE test checks its date and time formats, paths, and timezone offset in Speakeasy's registry manager. Native startup now supplies process-owned CRT argument and initial-environment pointers. Registry and string APIs include the API-set imports used by a locally staged Windows x64 `reg.exe`; the registry bridge also accepts sign-extended predefined HKEY values. A real offline `reg.exe query` probe progressed from 234 to 6,961 guest instructions but remained partial at unsupported `_o__errno`. Its packaged report is `output/real-reg-x64-probe10/20261014T103616Z-d177d3f7`; no network attempts or denied operations occurred. The complete source suite passed 511 tests with one skip before the final API-set aliases, followed by their focused tests. Microsoft binaries remain outside the repository. The successful `reg.exe` query above supersedes this earlier partial probe.

## 2026-10-14 real Windows `hostname.exe` follow-up

The separately supplied x86 and x64 Windows `hostname.exe` programs now complete under a custom Morgan persona and print `DESKTOP-Q3R8V2A` to guest stdout with empty stderr. The packaged worker models Winsock `GetHostNameW` from persona data after `WSAStartup`, checks the guest output buffer, and keeps startup state per guest process. New bounded CRT `wcschr`/`strchr` family, `_setmode`, and standard-descriptor `_write` behavior let the programs reach their normal exit path. The imported localization API-set alias now uses the same thread UI language state as `kernel32`. The final rebuilt x64 run `output/real-hostname-final-x64/20261014T094909Z-0a5d2c6a` completed in 847 instructions and the x86 run `output/real-hostname-final-x86/20261014T094920Z-100369e8` completed in 896. Both ignored a conflicting guest `COMPUTERNAME=EVILHOST`, returned 0 with exact stdout `DESKTOP-Q3R8V2A\n`, empty stderr, and zero recorded errors, denied operations, and network attempts. A final packaged Windows `whoami.exe` identity regression also completed in `output/whoami-identity-regression-final/20261014T094937Z-a1317def` with zero errors. The source suite passed **504 tests with one skip** in 609 seconds, followed by 33 focused tests after the last string and buffer corrections. The real Microsoft binaries remain outside the repository in ignored output directories. This is a two-program compatibility check, not a representative software corpus.

## 2026-10-14 real Windows `whoami /all` follow-up

The real, explicitly staged Windows x86/x64 `whoami.exe` and matching `en-US/whoami.exe.mui` files now exercise additional guest CRT, token, and LSA paths. A bounded `msvcrt._ultow` conversion removed the prior unsupported-API stop. Guest `LookupPrivilegeNameA/W`, `LookupPrivilegeDisplayNameA/W`, and `LookupPrivilegeValueA/W` write actual privilege strings and LUIDs with checked size contracts. `InitializeSid` writes a bounded guest SID. The local-only LSA model uses process-owned handles and response buffers; it supports Kerberos empty ticket-cache queries and a local extended-domain-policy query reporting Dynamic Access Control and claims disabled. Unknown protocol messages and domain requests remain visibly unsupported, and no host LSA or credentials are accessed.

The final rebuilt AppContainer package completed the real x64 `/all` run at `output/real-whoami-all-final-x64/20261014T092516Z-c1a2dea9` in 840,065 instructions and the x86 run at `output/real-whoami-all-final-x86/20261014T092556Z-1e67a5d3` in 1,136,969 instructions. Both returned 0 with no reported errors, denied operations, or network attempts. Their 3,358-character stdout was identical and included the configured user, SID, groups, expanded privilege set, and local claims status; stderr was empty. The source suite passed **498 tests with one skip** in 590 seconds, and 14 focused CRT, token, and LSA tests passed after the final process-cleanup adjustment. These runs exercise one program and selected `/all` branches, not general Windows program or Kerberos compatibility.

## 2026-10-14 second runnable utility and environment API

The native persona now generates a second x86/x64 guest PE, `C:\Windows\System32\whoami.exe`. It calls the guest `GetUserNameA` API and writes `computer\user` to guest stdout, using the configured hostname as the local computer. Source and rebuilt AppContainer runs completed on both architectures under a custom Morgan persona with `USERNAME=Eve` in the environment; the output still named Morgan and reports had zero errors. This is a small Emumee utility rather than a Microsoft Windows binary. The first `hostname.exe` utility remains available. The default desktop profile now has 29 text files and 48 registry keys, including matching recent-document and Explorer activity. The clean 366-test native acceptance suite passed with one skip, along with 57 CPU/analyst tests and 16 focused persona tests.

Speakeasy's `GetEnvironmentVariableA/W` handler previously wrote past a caller-declared small buffer and returned a length including the terminator on success. A guest-only hook now bounds writes, returns the copied length or required size per the [Windows API contract](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentvariablew), and reports missing names explicitly. Unit and guest PE tests cover small buffers and missing values. Full Windows code-page behavior and environment inheritance into child processes remain incomplete.

## 2026-10-14 guest identity APIs and executable children

`GetComputerNameA/W`, `GetComputerNameExA/W`, and `GetUserNameA/W` now return persona-consistent strings with checked input and output buffer sizes, required-size updates, and distinct Win32 error codes. A harmless x86/x64 PE reached the `GetComputerNameW` hook through guest CPU execution. The child loader can now materialize only exact guest file mappings backed by worker-verified bytes. A harmless staged x86/x64 PE launched as a guest child in source tests, and an unregistered mapped path remains unavailable. The native worker also generates a small x86/x64 `hostname.exe` PE under the guest System32 directory. That PE calls `GetComputerNameA`, `GetStdHandle`, `WriteFile`, and `ExitProcess`; source `CreateProcessW` and bare-name `WinExec` child runs printed the persona hostname on both architectures. Rebuilt packaged `CreateProcessW` runs completed with zero errors on both architectures. The full 366-test native acceptance suite passed with one skip; the 36-case child regression set and 57 CPU/analyst tests also passed. Its code is an Emumee utility rather than Microsoft Windows binary content. Other modeled process-list entries remain snapshots without running programs. Broader Win32 name formats, code pages, child search order, and native application compatibility remain incomplete.

## 2026-10-14 desktop persona and disk APIs

The default Windows 11 persona now supplies 21 guest-only document and configuration files, common empty directories, 43 registry keys including parent keys, and 18 modeled process snapshots. User, host, build, and CPU overrides refresh dependent defaults. Speakeasy's sample wildcard files and demo registry entries are removed from the guest view. The process snapshots are metadata, not running Windows applications. Explicitly staged native PE children can resolve through `CreateProcessA/W` or `WinExec` by filename in the guest current, System32, or Windows directory, with an optional `.exe` suffix; no host process is launched. The default drive list is C: only. The new `GetVolumeInformationA/W` hook writes deterministic NTFS fields and checks buffer sizes; `GetTempPathA/W` selects guest environment values and returns the required buffer length when needed. These are bounded models of the [Windows volume](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationw) and [temporary-path](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-gettemppathw) APIs; not all advertised NTFS capabilities are implemented.

The 366-test native acceptance suite passed with one skip after a child-loader regression was fixed. Another 65 focused persona, CPU, and analyst tests passed. The rebuilt package completed a harmless x64 EXE and a harmless x64 guest child-process fixture with no reported errors. This does not establish compatibility with arbitrary Windows applications, broader path search, or all Windows API variants.

## 2026-10-14 MSI and alternate PE intake

The isolated worker statically inspects `.msi`, `.msp`, and `.mst` compound-file streams with bounded stream count and byte budgets. It saves directly embedded PEs and CAB streams and carves PEs from other streams. It does not run Windows Installer tables or custom actions or unpack CAB contents; MSI results remain `partial`. A packaged offline-replay run against a local 1 MiB MSI recovered two PE artifacts with zero guest instructions and a verified report. Direct native PE loading works under other extensions such as `.scr`; a packaged harmless x86 SCR completed. Native DLL-style PEs can opt into `--all-exports`, which invokes up to ten exports with placeholder arguments after attach; a packaged harmless x86 DLL reached its `ProbeValue` export and completed. These checks do not establish compatibility with arbitrary installer actions or export calling conventions.

## 2026-10-13 directory and additional-file input

The CLI now accepts `run DIRECTORY --launch RELATIVE_PATH`, or `run EXE` with repeatable `--file PATH` and `--files-dir DIRECTORY`. It stages the selected PE and every collected file with its relative guest path, sets the guest working directory to the launch file's directory, and discovers architecture-compatible native or managed companion DLLs by name. Both the native and managed guest filesystems receive the collected bytes. Collection rejects reparse points, hardlinks, ambiguous case-insensitive paths or DLL names, unsafe paths, and bundles above 2,048 files, 32 MiB per file, or 64 MiB total. The parent and contained worker independently verify staged hashes before execution; the parent checks them again afterward.

A rebuilt packaged run completed harmless nested x86 and x64 native EXEs with auto-discovered DLLs, a nested managed DLL, a managed apphost EXE with an adjacent DLL, and native `--file`/`--files-dir` cases. A disposable hardlink to an outside marker was rejected and left the marker intact. Focused source tests cover recursion, path normalization and collisions, hardlink rejection, tamper detection, native virtual-file replacement, and managed working-directory reads. The full source suite passed **468 tests with one skip**. AppContainer smoke, 12 reversible containment probes, and broker ACL probes passed. The residual scan covered 22,445 directories and 75,184 files with zero explicit AppContainer SID grants, private broker journals, or packaged Emumee processes. These tests establish the staged-file behavior on harmless fixtures, not compatibility with arbitrary DLL search behavior or a general absence of host escape paths.

## 2026-10-13 interrupted artifact recovery

Artifact catalogs now checkpoint a compact, bounded manifest after the first observation, every 32 observations, or after at least one second. The catalog stops adding observations when its 10,000-record or 1 MiB manifest budget is reached and records the omission. If the worker exits before its final summary, the parent reads the last complete manifest through its safe file reader, verifies every payload SHA-256, rebuilds groups from those bytes, and marks the recovery as a checkpoint. The CLI and dashboard explicitly mark the guest trace incomplete when no final engine report exists. This recovers retained artifacts only; API, process, file, console, and memory events since the last checkpoint may still be lost.

A rebuilt packaged AppContainer run of a harmless managed fixture wrote a 27-byte guest payload, then looped until the one-second guest timeout. The parent recovered the verified payload and reported `status=timeout`, `guest_trace_complete=false`, and `artifact_checkpoint_recovered=true`. Normal packaged x86/x64 controls completed. The full source suite passed **463 tests with one skip**. The reversible containment probe, broker-run ACL probe, AppContainer smoke, and private broker-journal ACL smoke passed. The final residual scan inspected **22,398 directories and 75,048 files** and found zero explicit AppContainer SID grants, private journals, or packaged Emumee processes. These bounded tests did not demonstrate a guest-to-host RCE.

Updated 2026-10-14. This file summarizes the current release gates and next work.

## Network broker write scope

The packaged parent now stages request/response streams and ready/stop markers under `broker-ipc`. The broker AppContainer receives a nonrecursive `RX` grant on the run directory for traversal, `M` on `broker-ipc` and its separate private journal, and `RX` on an exact fixture file only when supplied. It no longer writes `network-broker.json` directly in packaged runs; the parent recovers that report from its private journal handle. A disposable broker-token probe wrote its result inside `broker-ipc` but was denied reading the staged PE, overwriting a marker summary, writing the bundle, using a hardlink to the PE, changing host registry, reading the parent process, and creating a host child. The broker network capability connected as configured; host loopback remained denied. Rebuilt packaged harmless x86 and x64 PEs completed, an exact URLMon HTTP fixture matched and recovered two artifact observations, and a forced broker crash yielded failed status with an incomplete journal. These checks establish the tested ACL scope, not general broker compromise resistance. IPC stream bytes are still shared between worker and broker and are not independently bound to the final summary.

## Staged-input integrity and recursive ACL link checks

The parent now hashes the exact staged request bytes and rechecks that request, execution PE, managed apphost copy, and supplied DLLs against its original manifest before launch and after the worker stops. The packaged worker receives the parent-held request digest, verifies the bounded request, PE, and companions before parsing or executing the guest, and refuses files with unsafe links. Windows AppContainer denied `GetFinalPathNameByHandleW` during the first packaged smoke; the worker now uses a contained fallback that checks non-reparse path components and matches the opened file's identity, size, and single-link count. The host parent retains the stricter final-path check. Recursive AppContainer grant and revoke now refuse nested hardlinks or reparse points before `icacls /T`, and a suspended worker is terminated if job assignment or resume fails. Focused tests cover an ordinary nested file, a disposable hardlink, launch assignment failure, staged-file tampering, and contradictory completed-report flags.

The earlier source suite passed **458 tests with one skip**. The rebuilt package completed harmless x86 and x64 native PEs, all **12** reversible host-marker probes with no host marker, AppContainer smoke, and private broker-journal ACL smoke. The read-only scan inspected **22,311 directories and 74,837 files** and found zero explicit AppContainer SID grants, zero private journals, and zero packaged Emumee processes. These checks do not prove a general absence of guest-to-host RCE. The contained fallback's component checks are not atomic against a concurrent local filesystem writer. Stream contents and the mutable summary still lack an independent integrity anchor. Broad Windows API, managed, CPU, and transient-stage coverage remain incomplete.

## Named-stream output quota and residual file ACL scan

A disposable NTFS probe put 1,228,800 bytes in a named stream on a one-byte file under a 1 MiB output limit. The previous watchdog counted one byte and did not stop the job. The watchdog now uses Windows stream enumeration to add named `$DATA` stream sizes and counts for the run root, nested directories, files, and the private broker journal; unexpected inspection errors stop both worker and broker jobs. Focused tests cover those three locations and inspection failure. The residual AppContainer checker now inspects ordinary files as well as directories and refuses a reparse point that would make its scan incomplete. The full source suite passed **451 tests with one skip**. The rebuilt package completed the harmless x86/x64 transient PE fixtures, all **12** reversible host-marker probes with no host marker, AppContainer smoke, and private broker-journal ACL smoke. The final read-only scan inspected **22,227 directories and 74,566 files** and found zero explicit AppContainer SID grants, zero private journals, and zero packaged Emumee processes. Automatic approval review rejected a disposable positive file-ACL grant probe and a mocked positive-case command as blocked by policy, without a more specific reason; positive detection of a file-only grant is therefore not verified end to end. Polling can still miss a stream created and removed between scans, and this gate does not prove broad host-escape resistance.

## Transient native allocation capture

Successful `VirtualFree`/`VirtualFreeEx` releases now retain a bounded pre-release snapshot of the owned guest allocation. Successful `VirtualProtect`/`VirtualProtectEx` changes to executable protection retain a pre-change snapshot for owned `VirtualAlloc` allocations. Each snapshot is capped at 4 MiB, shares the 128 MiB process-memory artifact budget, and has a 128-observation scan limit; skipped observations have explicit reasons. Freed maps are excluded from the final live-memory scan, even when Speakeasy still keeps their backing bytes readable. The new harmless x86/x64 fixtures copied a valid PE into a guest allocation and freed it before reporting; source and rebuilt AppContainer runs recovered the PE from the release snapshot, with no final-memory observation for the freed map and zero capture omissions. A direct bridge test covers successful and failed executable-protection changes and foreign-owner rejection. Failed artifact-manifest verification now clears worker artifact claims from the host summary; dashboard detail, search, comparison, and downloads quarantine unverified claims in older failed reports. A source and packaged dashboard regression used fabricated harmless metadata to check that no fake PE hash appeared as recovered evidence. The complete source suite passed **449 tests with one skip**. The final rebuilt package passed both fixtures, the dashboard quarantine check, all **12 reversible host-marker probes** with no host marker, AppContainer and private broker-journal checks. The residual scan found **zero explicit AppContainer SID grants across 22,185 directories, zero private journals, and zero packaged Emumee processes**. These checks do not establish general host-escape resistance or capture bytes overwritten before either transition, released through other APIs, or inside allocations above the per-snapshot limit.

## Follow-up after the 12 independent analyst reviews

The native worker now handles `__getmainargs` with x86 cdecl stack cleanup and bounded guest-owned ANSI arguments and environment arrays. `GetEnvironmentStringsA/W` returns a process-owned, double-terminated guest block with `NAME=value` entries; `FreeEnvironmentStringsA/W` accepts only a matching block owned by the current guest process. `__acrt_iob_func` returns stable guest memory for the three standard UCRT streams. These are bounded models of the tested paths, not complete UCRT or code-page behavior. The dashboard rejects non-loopback Host headers and pages all engine and broker events instead of silently hiding events beyond 2,000. Final dropped-file bytes now retain a separate provenance observation even when an earlier write had the same hash.

The source suite passed **441 tests with one skip** after artifact omission accounting. Ten focused tests on the previous source revision passed after the environment trace was added. The rebuilt AppContainer package completed nine harmless x86/x64 fixtures for the startup and environment paths, then a fresh package completed native dropped-file and managed memory-only AES fixtures with zero reported capture omissions. Ten reversible host-command, file, and private-entry probes produced no host marker; AppContainer smoke and broker-journal ACL smoke passed. The final residual scan found **zero explicit AppContainer SID grants across 21,985 directories, zero private broker journals, and zero packaged Emumee processes**. No guest-to-host RCE was demonstrated by these bounded probes.

Artifact reports now count observations and bytes omitted by the 32 MiB per-artifact limit, 128 MiB memory-scan limits, and 4 MiB dynamic-segment snapshot limit. The dashboard shows bounded examples and reasons. A synthetic size/scan test and a native dropped-file run passed; that native run reported zero omissions. The later transient-allocation checkpoint above covers tested `VirtualFree` and executable `VirtualProtect` paths. Other overwrite and unmodeled-release gaps remain open.

The next high-value work remains independent compiler-produced benign validation, direct NTDLL DLL-loader parity and resource/MUI handling, transient executable-memory checkpoints, x64 exception dispatch and truthful CPU feature exposure, managed/native interop, wider offline network replay, coherent persona APIs, and suspended-child replacement. These gaps remain open; passing current fixtures cannot establish broad malware coverage or host-escape resistance.

A second read-only round used **16 additional independent analyst agents** with no access to the earlier research or plans. Their recurring recommendations reinforced direct NT API parity, transient capture, independently compiled behavior oracles, process/exception fidelity, common runtime/interop support, and searchable provenance with explicit limits. Concrete smaller candidates include x86 processor-mask overflow, process ownership checks on local `VirtualProtect`, socket argument validation, native current-directory behavior, and registry A/W conversion. This review made no code changes. The proposed offline-by-default network policy conflicts with the user's stated live-network preference, so live networking remains the current default.

The subsequent direct-loader change routes `LdrLoadDll`, `LdrGetProcedureAddress`, and `LdrUnloadDll` through the bounded guest DLL state, with validated counted strings and NTSTATUS/output-pointer results. Source fixtures cover x86/x64 direct export calls, TLS attach/detach, malformed names, and failed initialization; three isolated package runs returned 42 with no errors. The final gate passed **443 source tests with one skip**, **12 reversible host-marker/private-entry probes** with no host marker, AppContainer smoke, broker-journal ACL smoke, and a residual scan of **22,056 directories with zero explicit AppContainer SID grants, zero private journals, and zero packaged Emumee processes**. The new Ldr-to-`WinExec` probes reached the modeled API on both architectures and reported that the command executable was absent from the guest. These bounded observations do not prove general host-escape resistance. Custom NT search paths and load flags, direct NT process/file/registry calls, and raw syscalls remain open.

The next combined revision adds local `VirtualProtect` guest ownership checks and a representable x86 processor-group affinity mask for a 64-logical-processor persona. The final gate passed **446 source tests with one skip**, two isolated x86/x64 protection fixtures plus the NT loader TLS fixture, all **12 containment probes** with no host marker, AppContainer and broker-journal checks, and a residual scan of **22,101 directories with zero explicit AppContainer SID grants, zero private journals, and zero packaged Emumee processes**. The cross-process protection denial was tested against parent/child mapping objects for both pointer widths; an actual guest child invoking local `VirtualProtect` against a parent page remains a useful additional fixture. The broader host-escape objective remains open.

## Latest native CRT and Windows message observation

The packaged x86/x64 worker now executes bounded `msvcrt._initterm` and `_initterm_e` callback arrays in guest CPU, stops `_initterm_e` on a nonzero callback result, and builds process-owned UTF-16 argument and environment arrays for `__wgetmainargs`. It models bounded `FormatMessageW` system and guest-string messages, `LoadStringW` for embedded strings with correct character counts and termination, and `HeapValidate` for live mapped heap blocks. A previously signature-only `ntdll.VerSetConditionMask` path now uses the existing persona version model. Six harmless x86/x64 packaged fixtures completed with expected returns for all three CRT paths. Packaged Windows `whoami.exe` reached 14,036 x86 and 10,733 x64 instructions and returned 1; both reports remain `partial` because string 5001 is in an unavailable external MUI file and `version.GetFileVersionInfoSizeExW` is signature-only. The exact final-build reports are `output/verification-crt-startup/whoami-final/20261013T020726Z-0a7e08cd` and `output/verification-crt-startup/whoami-final/20261013T020732Z-7fd2aae6`. The formatter uses a bounded en-US message table and does not load system messages from the host. A targeted malformed initializer initially reached Unicorn at an unmapped all-ones callback address; this was a guest execution fault, not host RCE. The final build checks that each callback is mapped and executable before dispatch: x86 and x64 packaged mutations returned a clear partial error without executing the callback. Ten reversible host-marker and private-mode probes created no host marker on this build; AppContainer smoke and broker-journal ACL smoke passed. Subsequent source-suite and residual-scan evidence is recorded above. This work improves startup fidelity without establishing general Windows or malware coverage.

## Latest managed payload extraction observation

The managed AES model now retains each successful decrypt transform's combined plaintext, including output previously returned only in memory. Each saved artifact is linked to its transform event by SHA-256 and sequence, with mode, padding, total input size, and final input hash but no key or IV. Capture stops after 128 observations or 64 MiB per run; omitted transform counts and bytes remain in the report and dashboard. The harmless `ManagedAesMemoryOnly` .NET program decrypted a 63-byte JSON config and checked its length without writing any guest file. A final packaged offline-replay run completed in 40 CIL instructions, recovered the exact SHA-256 `832ab4ea5f2a9c8d526cdbec37f348ab4be3faec10d97e4acf1043a306753503`, and closed its broker journal (`output/managed-aes-memory-only-final/20261013T013540Z-dfcee883`). Source tests also verified streaming block assembly, PE carving, and the explicit budget-omission report. The complete source suite passed **419 tests with one skip**. Ten reversible host-marker and private-mode containment probes created no host marker, AppContainer smoke checks passed, and the private broker journal remained worker-inaccessible while the broker could read and write it. This covers modeled AES transform calls, not arbitrary decryptors or unmanaged memory decryption.

## Second blind review and current fixes

Six independent analysts tested the packaged CLI using fresh harmless runs. Confirmed gaps were reversed dashboard event order, transient managed PEs lost after buffer clearing, common .NET framework stops, truncated native file-write snapshots, weak network outcome summaries, and ambiguous guest/worker results. The source now:

- orders dashboard events by native execution ticks and labels ticks inferred from matching API calls; untimed events remain explicitly marked;
- carves decoded managed PE arrays before overwrites or `Array.Clear`, and models `SHA256.HashData`;
- models the tested .NET `GetTickCount64` P/Invoke, immediate async `Task Main`/`File.WriteAllTextAsync`, and a bounded `JsonSerializer.Deserialize<T>` path for local object types;
- captures large native `WriteFile` buffers before the engine's shortened profiler snapshot, labels profiler snapshots by observed and captured sizes, and attaches remote process write context and later thread starts to artifacts;
- groups artifacts with PE architecture, entry RVA, image size, import DLLs, and intermediate/final observation labels;
- records normalized HTTP, socket, and DNS attempts and their outcomes in the summary, including broker denials; rejects the persona hostname before host DNS resolution;
- distinguishes guest `ExitProcess`, entry return, and worker failure; records command elapsed time, UTC timestamps, and worker peak memory where available; adds dashboard filters, pagination, and behavior comparison.

Focused source regressions for these paths pass. A packaged large-write fixture recovered the full 1,536-byte buffer and labeled the engine's 1,024-byte snapshot as partial. A packaged loopback WinHTTP fixture reported one denied operation and one attempt. The full source suite passed **384 tests with one skip** in 504 seconds. The rebuilt package completed the harmless `ManagedAsync.dll` `Task Main` case with one virtual artifact and no errors. Previous release-gate counts below describe earlier builds.

### Harmless guest-to-host execution probes

`tools/containment_probe.py` creates unique temporary markers outside each run directory, then runs packaged x86/x64 guests that ask `CreateProcessW` to launch `cmd.exe`, a managed guest that asks `Process.Start` to launch it, and a managed P/Invoke guest that calls `kernel32!WinExec`. It also asks a managed guest to write an absolute host path through guest `File.WriteAllText`. The rebuilt package created no host marker in all five probes. Native process creation reported that `cmd.exe` was absent from the guest filesystem; managed `Process.Start` and `WinExec` stopped as unsupported; the managed file write completed in the virtual filesystem. The script removes any marker immediately and saves the report references in `output/containment-probe/containment-results.json`. This tests those routes only; it does not prove that malformed parser input, an emulator dependency, or another guest API cannot escape the AppContainer.

### Third blind review: twelve analyst workflows

Twelve independent agents reviewed the analyst-facing tool without consulting this research log. The most concrete findings were: the dashboard CSP blocked its own Filter and Compare forms; the packaged worker was older than current managed source and stopped a harmless async fixture; and the private worker entry point could be invoked directly outside AppContainer. The current rebuild fixes these three immediate faults. A direct host invocation now fails before sample input is read; a packaged AppContainer run records all three worker containment checks as true. The CSP permits same-origin form submissions. The source suite and package probes above cover the current rebuild; the CSP and direct-entry changes received focused checks after that full suite. The AppContainer smoke probe passed, and the residual scan found zero explicit AppContainer SID grants across **20,775 directories** and zero packaged Emumee processes.

The remaining plausible work from these reviews, ranked by analyst value and risk, is: canonical event IDs/ticks and causal links; mapped-image PE reconstruction and assembled-stage capture; a coverage frontier with structured stop reasons; explicit offline network replay and wider network API coverage; containment attestation and cleanup recovery; realistic wait/thread scheduling and cross-API persona consistency; batch intake and indexed run browsing; verified case export and complete truncation accounting. These are proposals, not completed capabilities. Several are supported by harmless reproductions, while broader malware impact remains an inference. In particular, a 12,288-byte mapped PE produced a 1,536-byte file-layout carve without section bytes; two writes containing one PE produced no individual carve; two registry writes acquired the same inferred dashboard tick; and the current comparison reduces behavior to a set, losing repetitions and order.

### Follow-up on the blind findings and private-entry audit

The source now validates every companion DLL, including case-insensitive duplicate names, before creating a run directory. An invalid x86 EXE offered as an x64 companion returned an error and left no output directory. Mapped PE carving now preserves the original memory image and writes a labeled PE reconstructed from section RVAs to raw offsets when the layout evidence is strong; a harmless x64 image test verifies exact section bytes. Native virtual events now carry capture-time instruction ticks, PID/TID, PC, and a cross-stream sequence. A harmless registry fixture records its write at tick 9 and query at tick 20 without inferred placement. Behavior comparison now counts repeats, reports source-order changes and truncation, and shows changes in guest arguments, environment, companions, fixtures, network mode, and worker bundle.

The CLI now has a bounded sequential `batch` command for EXEs, with optional recursive scanning and primary DLL inputs. It pre-enumerates without following directory links, rejects more than the configured 1–1,000 inputs before running any sample, and prints one JSON record per run plus totals. The final package completed a two-EXE batch through two isolated runs; a source test confirmed over-limit rejection makes zero run calls. The last focused suite passed **19 tests** after this CLI addition, all eight containment probes passed again on the final bundle, and a residual scan found **zero explicit AppContainer SID grants across 20,940 directories** and **zero packaged Emumee processes**. Parallel workers and an indexed dashboard run catalog remain open scaling work.

Guest remote-thread creation now snapshots the owned target allocation after successful thread creation, within the existing 32 MiB artifact and 128 MiB cumulative capture caps. Its context records the target process, start address, allocation, and up to 32 contributing write events with a total count. A harmless mapped PE assembled from two simulated writes yielded a reconstructed PE with exact section bytes; both source and rebuilt package runs of `child_remote_thread_x64.exe` captured a 4 KiB allocation and a 1,536-byte PE without errors. The packaged PE records two contributing writes. This does not capture a stage that is freed before thread creation, spans separate allocations, or exceeds the caps.

A direct invocation of the earlier packaged `_sandbox_probe` private mode **did** read a host file, write two disposable host files, and create a temporary host registry key. The mode accepted caller-provided paths and performed those probes without checking for an AppContainer token; its child-process mitigation blocked a `cmd.exe` launch but did not confine file and registry access. The test removed the files and registry key. This was a local private-mode invocation, **not** an observed malware guest escape. The rebuilt package requires an AppContainer token before `_sandbox_probe` can access those paths, including when called through its Python module entry; `_network_broker` likewise checks containment before opening run data. The normal `_worker` check remains before sample parsing. The packaged regression probe passed all eight checks: five guest-to-host marker paths created no host marker, and all three direct private modes were rejected before producing a report or marker.

An LPAC trial with the earlier package exited `0xFFFFFFFF` before writing a summary, so LPAC is not enabled for production. The ordinary no-network AppContainer boundary remains the tested configuration; its launch smoke test now uses the same network setting and a worker job as production. The final package passed that smoke test, including outside file and registry denials, host-child denial, direct-network denial for the worker, and zero loopback connections. The earlier package completed harmless `registry_x64.exe` with exact ticks 9 and 20, the async managed fixture, and both user-supplied ECSC26 x64 EXEs with 11 artifacts each and no errors. The final package passed all eight containment probes and bounded all fifteen malformed PE cases. The exact final source suite passed **390 tests with one skip** in 466 seconds, and the last residual scan found **zero explicit AppContainer SID grants across 21,010 directories** and **zero packaged Emumee processes**. Neither the host-boundary probes nor this result prove the absence of parser, emulator, dependency, or Windows-kernel escape paths.

Remaining coverage work includes managed `Process.Start` with execution of dropped guest PEs, pending asynchronous tasks, broader P/Invoke and JSON overloads, richer native event timestamps, and stronger memory-limit failure attribution. A `0xC0000142` worker exit means DLL initialization failed; a low cap may cause that outcome, but the exit code alone does not prove the memory limit was reached.

### Fourth blind review: sixteen independent analyst workflows

Sixteen agents independently examined current source, harmless fixtures, and selected reports without reading this file, earlier recommendations. They made no source changes. The most urgent directly observed report defects are that artifact-group metadata can disagree with a verified artifact manifest while `valid_summary` still accepts it, and a native entry-point error can coexist with a `ret_val` that the completion logic labels as an entry return. A saved harmless invalid-instruction report exhibits the latter combination. Dashboard behavior search also missed a URL present in a harmless managed engine/broker report, and event displays can omit rows without showing the full counts clearly.

The strongest coverage gaps found in code are signature-only native NT memory and thread APIs; `RegCreateKeyEx` handles not registered with the virtual registry owner map; service creation returning apparent success without modeled service state; finite and infinite guest waits with incorrect time/scheduling semantics; narrow managed P/Invoke, process, registry, networking, delegate, and delayed-task support; and DLL side-loading that requires explicit `--dll` staging. These are code-level findings or test proposals, not measured prevalence across malware families. A bounded benign differential corpus should measure how often they block ordinary programs and whether emulated results match Windows.

Fixture misses still fall through to live networking by default; exact fixtures alone do not imply offline replay. The later `--offline-replay` mode denies unmatched HTTP, DNS, and raw sockets and labels fixture responses and replay misses. Standard AppContainer plus the current containment checks does not establish the exact SID/capability set or deny every host system read; the live broker deliberately has public-internet capability. The blind boundary review found no demonstrated guest escape. The direct private-mode host side effect described above remains the only demonstrated host-side issue from this audit and is fixed in the rebuilt package.

Further analyst-facing proposals are capture at the first execution of a changed guest memory region; stronger PE validation and evidence labels for recovered artifacts; a consistent configurable persona; structured stop context; whole-run evidence sealing; static inspect-only intake; a durable case/run index with full behavior search; and source-linked detection-candidate export. Several are supported by harmless in-memory probes, but their payoff and order need validation against a broader benign corpus.

### Report-integrity, registry, and host-boundary follow-up

Artifact groups are now generated from the manifest plus artifact bytes by one shared implementation. The parent verifies the worker's groups against the verified manifest and bytes before accepting a completed run; the dashboard detail, comparison, and artifact download routes reject mismatched group provenance. Verification streams one artifact at a time rather than retaining all artifact payloads in host memory. A harmless tamper test confirmed that changing only a group preview causes verification and display to fail, while a manifest-only extra artifact cannot be downloaded. The basic summary validator also rejects group file/size mismatches and malformed hashes. This is a consistency check for artifact evidence, **not** a whole-run signature or a seal for engine/broker reports.

Native entry returns are now accepted only from an error-free primary entry. A harmless UD2 x64 executable has both an engine `ret_val` and an invalid-instruction error; source and packaged runs now report `guest_entry_return: null` and `completion_reason: error`. The packaged run is `partial` with the fault retained. This does not classify every unsupported instruction or establish that later behavior would have been absent.

`RegCreateKeyExA/W` now creates owned guest handles and records the requested access and created/existing disposition. Harmless x86/x64 PE fixtures complete a create/open/close/delete sequence through the emulator, and a unit probe verifies that a second guest process cannot reuse the first process's handle. `WinExec` now requires a valid same-architecture executable in the guest filesystem, records the attempted command and outcome, and queues a valid guest child rather than allowing Speakeasy's untracked success path. Harmless x86/x64 host-marker commands were denied because `cmd.exe` was absent from the guest filesystem; no host marker was created. Native `ShellExecute` and additional launch aliases still need the same policy review.

The exact final source suite passed **395 tests with one skip** in 464 seconds. The rebuilt package passed **ten reversible containment probes** (four native command attempts, two managed command attempts, one managed host-file attempt, and three direct private-mode checks), the AppContainer smoke test, two packaged `RegCreateKeyEx` fixtures, a packaged invalid-instruction fixture, and fifteen bounded malformed-PE cases. A packaged remote-thread fixture completed with 11 artifact observations and four unique payloads; its summary, dashboard detail, and artifact download verified. The final residual scan found **zero explicit AppContainer SID grants across 21,176 directories** and **zero packaged Emumee processes**. These bounded tests do not prove that unknown guest code, parsers, dependencies, or Windows itself cannot escape the sandbox.

### Fifth blind review: twenty independent analyst workflows

Twenty agents independently inspected the current implementation as malware analysts without reading this file, prior recommendations. They did not edit files or execute unknown samples. Repeated findings were narrow native CRT/API-set/DLL loader support, managed P/Invoke and IL gaps, incomplete process/injection scheduling, blind spots in network and persistence modeling, and misleading absence of artifacts after bounded collection. Several found the inherited Speakeasy default persona exposes implausible adapter, process, registry, and wildcard file state. The dashboard search and event caps can hide saved behavior. These are source-review priorities, not measured malware prevalence.

The review also found an assurance gap: the parent verified artifact bytes and groups but did not bind `engine-report.json` to a completed summary. A separate reviewer identified unrestricted parent parsing of worker-produced PE artifacts as a potential attack surface; no exploit was demonstrated. The later report-binding change and bounded PE metadata reader address these two paths, with remaining limits documented below. One reviewer cited an old saved fault report as evidence that `entry_return` still precedes errors. Current `native.py` checks errors first, and the recent packaged UD2 probe confirms the fix, so that claim is not an outstanding defect.

### Offline replay packaged gate on 2026-10-13

The broker now receives the network mode and local persona hostname directly from the parent launch arguments. The first packaged offline run had silently defaulted to live-mode broker logic because its AppContainer could not use the request-file read as the mode contract; the broker had no network capability, but the miss was logged as a local-address denial. The corrected package logged `network_replay_miss` and summary `outcome: replay_miss` for the unmatched harmless URL. The exact fixture run returned the 25-byte fixture payload, logged `source: fixture`, produced two artifact observations, and made no live HTTP request. The mode still must be explicitly selected with `--offline-replay`.

After this change, the source suite passed **399 tests with one skip** in 565 seconds. The final package passed the ten reversible containment probes, AppContainer smoke, and fifteen malformed-PE cases. The residual scan found **zero explicit AppContainer SID grants across 21,267 directories** and **zero packaged Emumee processes**. These checks bound the tested paths only; arbitrary-sample containment and broad Windows compatibility remain unproven.

### Parent report binding and bounded artifact metadata on 2026-10-13

New completed and partial summaries require a bounded SHA-256 and byte size for both `engine-report.json` and `network-broker.json`. The parent reads each through a verified regular-file handle after the worker and broker stop, and the dashboard checks the same bytes before rendering details or comparisons. Focused tamper tests replace each report after sealing and confirm that both views reject it. Legacy reports remain readable with an explicit unbound label. This is a post-run consistency check, not a signature: a compromised worker or broker may still falsify data before sealing, and a local actor who can rewrite both the summary and reports is outside this check.

Artifact grouping in the unrestricted parent no longer invokes `pefile.PE` on guest-produced artifact bytes. A bounded reader extracts only PE display fields; richer carving and PE parsing remain inside the AppContainer worker. A focused test replaces `pefile.PE` with a failing stub during host grouping, and 2,000 deterministic harmless header mutations completed without an exception. The source suite passed **401 tests with one skip** in 472 seconds before the final broker-binding test was added; the final focused analyst suite passed **30 tests**. The rebuilt package completed a remote-thread fixture with **11 artifact observations and four unique payloads**, an exact HTTP replay fixture, and an unmatched replay request recorded as `replay_miss`. All three runs passed summary, engine-report, broker-report, artifact, and dashboard checks. The same final package passed ten reversible containment probes, the AppContainer smoke, and fifteen bounded malformed-PE cases. The final residual scan found **zero explicit AppContainer SID grants across 21,387 directories** and **zero packaged Emumee processes**. No guest-to-host RCE was found in these bounded probes.

### Broker-only journal path on 2026-10-13

The raw broker journal now lives in a sibling file outside the worker-writable run directory during execution. The parent opens it before launch, grants that exact single-linked file to the broker SID, recovers events from its held handle after both processes stop, and removes the file. The first packaged attempt failed because the existing ACL helper used directory inheritance flags on a file; `icacls` returned success without an effective AppContainer ACE. The helper now uses a direct file ACE. A harmless packaged AppContainer probe confirmed worker read and write were denied while broker read and write succeeded. The packaged CLI then completed an exact offline HTTP fixture, left no raw journal in the run directory or sibling output root, and retained a valid sealed broker report. A broker-kill probe still produced a failed run with incomplete-journal evidence. This isolates the journal from a compromised worker; it cannot prevent a compromised broker from falsifying its own events before parent recovery.

The CLI now rejects an output root within the worker bundle, and the output watchdog includes the private journal in the configured size and file-count budget. A focused test confirmed that an oversized sibling journal stops both isolated jobs. The full source suite passed **403 tests with one skip** in 470 seconds before the final output-root and watchdog tests were added; the focused source tests for those paths passed **nine tests**. The final rebuilt packaged CLI completed exact fixture and unmatched offline-replay runs with validated hashes, artifact evidence, and dashboard details. It also passed the broker-only read/write probe, ten reversible containment probes, AppContainer smoke, broker-kill recovery, and fifteen bounded malformed-PE cases. The final scan found **zero explicit AppContainer SID grants across 21,489 directories**, **zero private broker journals**, and **zero packaged Emumee processes**. These are bounded observations, not proof against every emulator, parser, broker, or Windows escape.

## Analyst findings addressed on 2026-10-12

Three independent analysts exercised harmless packaged fixtures without reading the existing research or source. Their observed gaps led to the following changes:

| Finding | Change and current evidence |
|---|---|
| Instruction and time caps, plus guest outcomes, were hidden behind `completed` | Native instruction-capped runs now return `partial` with the executed count and explicit limit flag. A packaged one-instruction `console_output_x64.exe` run returned `partial`, count 1, and a limit error. A harmless infinite guest loop under a one-second emulation cap now returns `timeout` with the timeout flag. Normal runs expose guest exit codes when modeled; an invalid WinHTTP-handle fixture remained `completed` while separately reporting one denied operation. |
| Completed runs carried a misleading `fault.log` | The Windows worker no longer enables Python faulthandler, which reported Unicorn-handled access violations as fatal. A new completed packaged console run had no `fault.log`. Parent-side process exit, stage, and report checks still classify a failed worker. |
| In-memory decoded PE bytes were missed | The CIL interpreter retains up to 1,024 bounded byte arrays totaling 128 MiB and carves PEs after execution. A harmless .NET fixture decoded an entire native PE in memory without writing a file; the source test recovered its exact SHA-256. This does not cover every object graph or native memory layout. |
| Standard .NET apphost EXEs failed in native emulation | The CLI recognizes the .NET apphost binding marker, reads only the bound adjacent managed DLL, and runs it in the CIL interpreter. A packaged `ManagedConsole.exe` run completed and captured expected stdout/stderr; its manifest records both submitted and executed hashes. |
| `Encoding.ASCII` stopped a managed decompression path | The CIL model now handles `Encoding.ASCII.GetBytes` and `GetString` through its encoding object. The memory-only PE fixture uses ASCII setup and passed. |
| Duplicate payload rows hid unique content | Summaries now include SHA-256 artifact groups with type, bounded preview, and every observation. A packaged URLMon fixture produced two observations of one unique response body. The original observation list remains for exact provenance and manifest verification. |
| Persona-dependent behavior was hard to compare | The dashboard now filters by full sample SHA-256 and compares two runs' outcomes, limits, persona fields, observed API counts and return values, console output, and artifact hashes. A dashboard client test verified an exit-code, memory-persona, and API-result difference. |
| Downloader branches could not use local deterministic responses | `--network-fixtures` loads exact method, URL, complete headers, chunked flag, and body match rules into the broker before the worker starts. Response status, reason, HTTP version, ordered headers, and body are specified exactly; the normalized definitions are retained in each run. A packaged localhost URLMon fixture received the configured 25-byte body without a host connection and recovered its exact hash. Unmatched requests still use the normal broker policy. |
| Run provenance and invocation were incomplete | Summaries now record worker EXE and full bundle-tree SHA-256, submitted and effective inputs, companion hashes, persona hash, limits, guest args/environment, and fixture hash. A packaged managed apphost run with a guest argument and environment override captured both values and its return code. |

The final source suite passed **377 tests with one existing skip**. The final package rebuild and AppContainer containment smoke check passed. A packaged memory-only PE decoder recovered the exact harmless PE SHA-256 from a managed array after apphost routing. Final packaged URLMon and managed guest-invocation runs also completed with the expected artifacts, output, and metadata. A bounded infinite guest loop returned `timeout` under a one-second limit. The residual scan found zero explicit AppContainer SID grants across **20,386 directories** and zero packaged Emumee processes; an existing user dashboard process was left running.

## Latest real-program observation

On 2026-10-14 the rebuilt isolated package ran the host's Windows x64 and x86 `whoami.exe` bytes as guest PEs, each with an explicitly staged `en-US/whoami.exe.mui` resource file. The default persona runs returned 0 after 21,522 x64 and 30,692 x86 guest instructions, with stdout `desktop-7f4m2q9\alex`. On the final rebuilt package, a custom admin persona returned 0 after 21,849 x64 and 31,095 x86 instructions, with stdout `desktop-q3r8v2a\morgan`; all four reports had empty error lists and zero network attempts. The inputs came from the local Windows installation and are not distributed in this repository. These runs exercised guest RT_VERSION queries, MUI `LoadStringW`, ordinal and ASCII string APIs, token user/groups/privileges/empty claims, SID copy and lookup, and the x64 MSVC delete export. The full source suite passed 494 tests with one skip before a final version-resource bound check; the focused 30-test suite and both custom-persona packaged runs passed after that check. A residual scan found zero explicit AppContainer SID grants across 22,709 directories and 76,409 files, zero private broker journals, and zero packaged Emumee processes. Direct `whoami.exe` without its MUI file can still follow an error path. This is one real-program compatibility check, not a representative coverage measurement.

On 2026-10-13 the isolated package reran the saved harmless x86/x64 Windows `whoami.exe` inputs in offline replay mode. A process-owned legacy `msvcrt` stream array, `_memicmp`, `_vsnwprintf`, `_fileno`, `_get_osfhandle`, `fprintf`, and `fflush` models moved both runs past the old `__iob_func` stop. A persona-backed `SetThreadUILanguage`/`GetThreadUILanguage` model removed that signature-only call. The x86 run reached 5,802 instructions and 88 API events; x64 reached 3,672 instructions and 86 API events. Both returned 1 through the guest program's error path and stayed `partial`: `FormatMessageW` remains signature-only, and the captured stderr was only a space. The tested formatter handles bounded common specifiers and reports unsupported ones; the output does not prove that `whoami` can retrieve an identity or that arbitrary CRT use works. The exact rebuilt-package reports are `output/ordinary-whoami-crt-gate/20261013T012327Z-30e5c7f2` and `output/ordinary-whoami-crt-gate/20261013T012337Z-35918b4d`. The 414-test source suite passed with one existing skip before the final worker status refinement; 13 focused tests passed after it. The final package completed a harmless native x86 `ExitProcess` fixture with `status=completed`, and both `whoami` runs stayed `partial`. Reversible AppContainer probes denied worker host-child launch, outside file access, registry writes, direct internet and loopback, and parent-process reads; the network-capable broker's direct internet probe connected as designed. The private-journal ACL smoke denied worker read/write/link access and allowed the broker. The residual scan found zero explicit AppContainer SID grants, private journals, and packaged Emumee processes across 21,555 directories. No guest-to-host RCE was demonstrated by these bounded probes; they do not prove resistance to arbitrary hostile samples.

The 2026-10-12 console capture update records bounded guest stdout and stderr in summaries, engine reports, and the read-only dashboard. Harmless native x86/x64 fixtures verified `WriteFile` on both standard handles and Unicode `WriteConsoleW`; managed fixtures verified `Console.WriteLine` and `Console.Error.WriteLine`. Three packaged console cases passed with exact text, dashboard rendering, and broker closure. The two previously supplied x64 EXEs still completed in the rebuilt worker, and their newly captured stdout appeared on dashboard pages under the default output directory. The complete final-source suite passed **370 tests with one existing skip**, and the AppContainer smoke probe passed. A residual scan found **zero explicit AppContainer SID grants across 20,310 directories** and zero packaged worker processes. Its broad process check also saw one already-running user dashboard, which was left open. Captured text is a best-effort UTF-8 rendering for byte-oriented calls; unmodeled output APIs and code pages remain coverage gaps.

Two user-supplied x64 EXEs that previously stopped on Unicorn's unsupported `vinsertf128` now complete in the rebuilt AppContainer worker with empty error lists and 11 extracted artifacts each. A bounded guest-only fallback models the exact AVX startup operations exercised, with guest memory checks; other AVX instructions remain unsupported. Harmless packaged x86/x64 AVX fixtures, five direct AVX tests, thirteen guest-DLL lifecycle tests, and the AppContainer containment smoke probe passed. The full final-source suite passed **367 tests with one existing host-symlink skip**. The residual scan found **zero explicit AppContainer SID grants across 20,248 directories and zero Emumee processes**. These observations demonstrate the two submitted execution paths, not general Windows or malware coverage.

## Intended operating boundary

Emumee runs x86/x64 user-mode PE instructions in Unicorn/Speakeasy and selected .NET CIL in its interpreter. It models guest files, registry, processes, and supported WinAPI calls. It does not launch a guest PE, guest DLL, PowerShell, `cmd.exe`, or the host CLR as a host program. A Windows AppContainer without network capability holds the emulation worker; a separate network-capable AppContainer brokers supported outbound traffic and logs it. The local dashboard reads reports and extracted artifacts. The host VPN supplies routing; Emumee does not check whether it is connected.

This design is a practical analysis boundary for the tested paths, not proof that arbitrary hostile code cannot compromise the host. The emulation worker, broker, PE parser, and their native dependencies remain host code parsing untrusted input. Regular AppContainers also retain access to some common system resources. Keep a disposable, patched analysis host and avoid treating successful harmless probes as an escape-proof certification.

## Research that guides the next changes

| Primary source | Finding | Work item |
| --- | --- | --- |
| [Microsoft `DuplicateHandle`](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle) | Each process handle needs `PROCESS_DUP_HANDLE`; the new handle belongs to the target process, can cross x86/x64, and a duplicated file handle shares its cursor. | Implemented modeled cross-process process/thread/file/mapping entries. Continue with unsupported object types only when ownership and rights can be represented. |
| [Microsoft `TerminateProcess`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess), [`TerminateThread`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminatethread), [`GetExitCodeThread`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodethread), and [`WaitForSingleObject`](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject) | Termination, status queries, and waits require the matching handle rights. A completed thread becomes signaled and retains its exit value. | Issued-handle rights, pending-run cancellation, natural return values, and zero-timeout process/thread wait state are modeled. Add cooperative blocking waits and other wait objects. |
| [Microsoft file-mapping lifetime](https://learn.microsoft.com/en-us/windows/win32/memory/closing-a-file-mapping-object), [`UnmapViewOfFile`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile), and [`CloseHandle`](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle) | Views and handles keep separate references to a section; the object expires after its last reference. | Teardown now releases an exiting guest's file, mapping, process, and thread handles and unmaps its views. Audit registry, socket, snapshot, event, mutex, and other owned objects next. |
| [Microsoft AppContainer launch guidance](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer) and [isolation overview](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation) | Capabilities limit access, but regular AppContainers can still read some shared system resources. | Keep least-privilege worker and broker identities; test actual token capabilities, host file/registry/process access, direct network denial, and ACL cleanup after every package change. |
| [Speakeasy limitations](https://github.com/mandiant/speakeasy/blob/master/doc/limitations.md) | Signature-only APIs may return plausible values without effects, and unknown calls can stop execution. | Treat a clean exit as insufficient: report signature-only calls, inspect behavioral traces and extracted bytes, and build a coverage corpus from observed unsupported APIs. |
| [MITRE ATT&CK T1497.003](https://attack.mitre.org/techniques/T1497/003/), [Microsoft Windows Time](https://learn.microsoft.com/en-us/windows/win32/sysinfo/windows-time), and [`QueryPerformanceCounter`](https://learn.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter) | Malware can compare sleep and timer results; QPC should advance on a high-resolution timeline while tick counts have coarser resolution. | A shared virtual timeline now advances modestly on time API observations and supports multi-day sleeps. Add instruction-derived timing, delay/wait APIs, `RDTSC`, and cross-source consistency probes. |
| [Microsoft debugger checks](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-checkremotedebuggerpresent) and [`NtQueryInformationProcess`](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess) | Win32 remote queries require a process handle; NT ProcessDebugPort reports a pointer-sized debugger port. | Guest handle validation and no-debugger results are modeled for Win32 checks and NT classes 7, 30, and 31. Expand the anti-debug corpus to PEB flags, exceptions, direct syscalls, and unsupported classes. |
| [Microsoft `KUSER_SHARED_DATA`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-kuser_shared_data) | Guest code can read system time, interrupt time, tick count, and QPC frequency directly from the shared page. | Synchronize the engine's low/high shared-page aliases with the virtual clock. Continue with instruction-derived timing and other shared-page persona fields. |
| [Microsoft CPUID intrinsic](https://learn.microsoft.com/en-us/cpp/intrinsics/cpuid-cpuidex) and [Hyper-V feature discovery](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery) | CPU leaves report processor identity/features; leaf 1 ECX bit 31 advertises a conforming hypervisor. | Deterministic guest CPUID and `GetSystemInfo` now share a configurable processor count and Intel identity. Continue with RDTSC/RDTSCP, `XGETBV`, processor-feature API agreement, and instruction support before claiming anti-VM resistance. |
| [Microsoft PE format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format) | Executables can carry imports, TLS, resources, relocations, and malformed directory ranges. | Continue deterministic malformed native/.NET parsing tests and exact payload extraction checks. |

## Current observations

- The complete source suite passed **316 tests** with one existing host-symlink skip before the final report-only `guest_pid` addition. A subsequent **30 child-process tests** passed after that addition.
- The final rebuilt package passed the x86/x64 cross-process duplication fixtures. Each child failed `ReadFile` on parent-only handles `0x80` and `0x84`, then read `Pers` through its child-owned duplicate `0x88`. The verifier checked exact input, supplied DLL, embedded child bytes, artifacts, `guest_pid`, and broker closure.
- On the first rebuild, prior package matrices passed: **2** process-rights, **2** guest-file duplicate, **12** named-mapping, **4** file/view coherence, and **18** mapping-view cases. The final rebuild changed report metadata only; the cross-process package was rerun on it.
- Reversible AppContainer capability, x86/x64 guest host-process launch denial, and redirected ACL-root probes passed. The **15-case** malformed-PE package completed with bounded outcomes. The final scan found **zero explicit AppContainer SID grants across 16,689 bundle/output directories and zero Emumee processes**.
- The network-capable broker probe reached the internet, while the production emulation worker's direct network attempt was denied. This tests capability separation; it does not establish complete traffic logging after broker compromise or for unmodeled network APIs.
- Speakeasy's native trace field `entry_points[].pid` is its internal process object ID. Emumee now adds `guest_pid`, which matched the guest-visible child PID in source and packaged tests.
- A later x86/x64 audit reproduced an unguarded guest `TerminateProcess` call through a parent's uninherited process-handle number. Emumee now checks caller ownership and `PROCESS_TERMINATE`, records denials, removes a legitimately terminated modeled child from its pending execution queue, and clears pending runs when the caller terminates itself. The **318-test exact-final-source suite passed** with one existing host-symlink skip. Both packaged x86/x64 denial cases, AppContainer probes, and the fifteen-case malformed-PE corpus passed on the final build. The final residual scan found **zero explicit AppContainer SID grants across 16,851 directories and zero Emumee processes**.
- Harmless x86/x64 programs reproduced the installed engine's fixed-zero `GetExitCodeProcess` response for a live process. Emumee now validates guest handle ownership, query rights, and the output pointer, returns `STILL_ACTIVE` (259) while active, and tracks explicit `ExitProcess`/`TerminateProcess` codes. The **320-test exact-final-source suite passes** with one existing host-symlink skip. Both packaged x86/x64 status cases, termination and duplication controls, twelve named-mapping cases, AppContainer boundary probes, and the fifteen-case malformed-PE corpus pass on the final build. The last scan found **zero explicit AppContainer SID grants across 17,157 directories and zero Emumee processes**.
- The installed `TerminateThread` handler reported success without stopping code; `GetExitCodeThread` returned a fixed zero. Emumee now checks issued guest ownership and thread rights, cancels modeled pending/suspended runs, records explicit exit codes, and denies a child that guesses a parent's thread-handle number. Harmless x86/x64 source and packaged fixtures verify both cancellation and foreign-handle denial. The **324-test exact-final-source suite passes** with one existing host-symlink skip; **four new packaged cases**, two process-exit controls, two process-termination controls, and two cross-process-duplication controls pass on the rebuilt worker. AppContainer, host-process, ACL-redirect, and fifteen malformed-PE probes pass. The final scan found **zero explicit AppContainer SID grants across 17,270 directories and zero Emumee processes**. Natural thread returns, wait-state fidelity, and complete process lifetime accounting remain open.
- Harmless x86/x64 three-run fixtures then reproduced wrong status after a worker returned 42. Emumee now records `ExitThread` and natural worker returns, marks a thread signaled, and checks issued-handle ownership and `SYNCHRONIZE` for zero-timeout process/thread waits. The final **326-test source suite passed** with one existing skip; a separately added last-thread process-status test passed. The final package passed **six thread-lifetime cases**, two process-status cases, and twelve named-mapping controls. AppContainer, host-process, ACL-redirect, and fifteen malformed-PE probes passed; the final scan found **zero explicit AppContainer SID grants across 17,616 directories and zero Emumee processes**. Pending infinite waits, event/mutex wait objects, wait variants, DLL thread detach, and automatic process-handle/view cleanup remain open.
- Process exit now releases the exiting guest's file, mapping, process, and thread handle references and unmaps its views, while inherited child references survive. Harmless x86/x64 parent-child programs verify that a named section with no live references cannot be opened after parent exit; file and mapping inheritance matrices verify child survival when a reference exists. Protected guest handles are forced closed at process exit. The **328-test final-source suite passed** with one existing host-symlink skip. The rebuilt AppContainer worker completed **50 packaged process/thread/file/mapping cases**; three verifiers were updated to expect freed final views and passed against those run outputs. Capability, x86/x64 host-process denial, ACL redirect, and fifteen malformed-PE probes passed. The final scan found **zero explicit AppContainer SID grants across 17,942 directories and zero Emumee processes**. Registry, socket, snapshot, event, mutex, and other object lifetime remains open, as does arbitrary hostile-sample containment.
- Registry handles are now guest-process owned and retired on exit. Five focused tests and ten rebuilt AppContainer registry cases pass; exact submitted bytes, extracted values, event statuses, cleanup, artifacts, and broker closure were checked. Host-boundary and malformed-PE probes pass on that build. The final clock build passed all ten registry cases again with a 60-second per-case wall limit; a 20-second control exceeded its limit under concurrent source-suite load after reaching `ExitProcess`. The final serial **336-test source suite passed with one existing host-symlink skip**.
- Consecutive QPC reads now advance on the same virtual timeline as wall time, `GetSystemTimePreciseAsFileTime` uses that virtual timeline, and tick count has 16-ms resolution. Four focused clock tests and a harmless x86/x64 PE source probe pass. The final AppContainer package passed both QPC probes with exact bytes, branches, artifacts, no signature-only calls, and broker closure. The same build passed AppContainer capability, x86/x64 host-process denial, ACL redirect, fifteen malformed-PE probes, and all ten registry cases; the final scan found **zero explicit AppContainer SID grants across 18,243 directories and zero Emumee processes**. The final serial **336-test source suite passed with one existing skip**. A multi-day sleep no longer stops at 24 hours. CPU-loop timing and many other anti-analysis checks remain open.
- In the earlier baseline, a real Windows `whoami.exe` in both x86 and x64 form reached about 40 modeled API calls, then stopped with partial reports during startup. `SetThreadUILanguage` was signature-only and `msvcrt.__iob_func` was unsupported. The 2026-10-13 rerun above supersedes this execution result while confirming that an API count or clean fixture result cannot establish average-program compatibility.
- Win32 and NT debugger-query hooks now use guest process-handle ownership and no-debugger persona values. The x86/x64 PEB, current-process, remote-process, and NT class 7/30/31 source and twelve packaged AppContainer probes pass. The same build passed AppContainer capability, x86/x64 host-process denial, ACL redirect, and fifteen malformed-PE probes; the residual scan found **zero explicit AppContainer SID grants across 18,372 directories and zero Emumee processes**. The serial **341-test source suite passed with one existing host-symlink skip** before the shared-user-data change.
- The shared user-data timing page now follows the virtual clock rather than the installed engine's host wall/monotonic times. Harmless x86/x64 CPU probes compare both guest aliases with time APIs and check a two-second sleep advance; source and packaged AppContainer probes pass. The final build also passed all twelve debugger cases, capability, host-process denial, ACL redirect, and fifteen malformed-PE probes; the last residual scan found **zero explicit AppContainer SID grants across 18,503 directories and zero Emumee processes**. The final serial **343-test source suite passed with one existing host-symlink skip**. CPU-loop time and RDTSC remain open.
- The installed CPU engine's leaf-0 identity differed from a realistic Intel persona; both initial x86/x64 PE checks failed. A guest-only CPUID model now supplies deterministic vendor, hypervisor, feature, brand, cache, topology, and frequency leaves; `GetSystemInfo` shares its core/thread count. The rebuilt AppContainer package passed both CPU cases, both shared-time cases, and all twelve debugger cases, plus capability, host-process denial, ACL redirect, and fifteen bounded malformed-PE probes. The last scan found **zero explicit AppContainer SID grants across 18,645 directories and zero Emumee processes**. The complete source suite is running. Direct TSC instructions, `XGETBV`, and full advertised-instruction support are unverified.
- Direct `RDTSC`/`RDTSCP` now follow virtual sleep and modeled instruction progress; `XGETBV(0)` reports AVX-enabled XCR0 in agreement with the advertised CPUID feature bits. Harmless x86/x64 CPU programs and focused clock tests pass. The final packaged build passed four CPU/TSC, two shared-time, twelve debugger, and two QPC cases, plus capability, host-process denial, ACL redirect, and fifteen malformed-PE probes; the last scan found **zero explicit AppContainer SID grants across 18,808 directories and zero Emumee processes**. The clean complete source suite is running. Timing is approximate, and full vector-instruction/API consistency remains unverified.
- The installed engine populated several `KUSER_SHARED_DATA` OS/version and QPC fields at the wrong Windows offsets. The guest page now has persona build/version, processor features/count, Windows root, QPC frequency at `0x300`, and zero QPC bias at `0x3B8`; both x86/x64 harmless programs read the corrected values directly. The rebuilt package passed four CPU/TSC, two shared-page, twelve debugger, and two QPC cases plus the four host-boundary/malformed probes. The last cleanup scan found **zero explicit AppContainer SID grants across 18,971 directories and zero Emumee processes**. The clean complete source suite is running; other shared-page fields remain incomplete.
- The guest memory persona now reports a consistent 16 GB total and 7 GB available through `GlobalMemoryStatusEx`, legacy `GlobalMemoryStatus`, and the shared-page physical-page count. The latest packaged build passed six x86/x64 CPU, TSC, and memory cases, two shared-page cases, twelve debugger cases, two QPC cases, the AppContainer capability probe, x86/x64 host-process denial, redirected ACL-root probe, and fifteen bounded malformed-PE cases. The clean **349-test source suite passed with one existing host-symlink skip**. The final scan found **zero explicit AppContainer SID grants across 19,144 directories and zero Emumee processes**. The reported capacity is a persona value; actual guest allocations remain constrained by the worker/job budget.
- A cross-surface processor-feature probe reproduced two default-persona contradictions: CPUID omitted VMX while the guest said firmware virtualization was enabled, and the engine reported no second-level address translation for an Intel processor profile with EPT. The guest CPU now reports VMX and WinAPI and `KUSER_SHARED_DATA` share one feature table, including SLAT and ERMS. Harmless x86/x64 PEs compare CPUID, the API, and direct page reads; the new fixture failed before the change and passes afterward. The final AppContainer build passed **eight CPU/feature/TSC/memory, two shared-page, twelve debugger, and two QPC cases**, plus capability, x86/x64 host-process denial, redirected ACL-root, and fifteen malformed-PE probes. The clean **350-test source suite passed with one existing host-symlink skip**. The final scan found **zero explicit AppContainer SID grants across 19,327 directories and zero Emumee processes**. Other CPU and hardware-inventory surfaces remain unverified.
- The installed NTDLL version handlers reported build 19041 while the configured Windows 11 persona, PEB, and shared page reported 22631. Guest-only `RtlGetVersion` and `RtlGetNtVersionNumbers` now derive from the persona; a custom build also updates the default virtual registry `CurrentBuild` and known `DisplayVersion` values. Harmless x86/x64 PEs compare both NTDLL results with the direct shared-page build; they failed before the change and pass afterward for the default and a custom 26100 build. The final AppContainer worker passed **two version, eight CPU/feature/TSC/memory, twelve debugger, two shared-page, and two QPC cases**, plus capability, x86/x64 host-process denial, redirected ACL-root, and fifteen bounded malformed-PE probes. The clean **353-test source suite passed with one existing host-symlink skip**. The last scan found **zero explicit AppContainer SID grants across 19,715 directories and zero Emumee processes**. Manifest-dependent Win32 version behavior and other version surfaces remain incomplete.
- A harmless unmanifested PE reproduced the engine's incorrect `GetVersion`/`GetVersionExW` answer of 10.0/22631. The guest Win32 hooks now select Windows 8 compatibility (6.2), Windows 8.1 compatibility (6.3), or the persona's Windows 10/11 version from a bounded RT_MANIFEST resource reader; the NTDLL and shared-page paths continue to report the true build. Six x86/x64 source PEs cover those three manifest states, and unit tests cover malformed resource bounds and a child process with a distinct manifest. The final rebuilt AppContainer package passed those six cases, two NTDLL version, eight CPU/feature/TSC/memory, twelve debugger, two shared-page, and two QPC cases, plus capability, x86/x64 host-process denial, redirected ACL-root, and fifteen bounded malformed-PE probes. The clean **357-test source suite passed with one existing host-symlink skip**. The final scan found **zero explicit AppContainer SID grants across 19,948 directories and zero Emumee processes**. External sidecar manifests, other compatibility APIs, and real-program validation remain open.
- The installed version-comparison APIs gave unconditional or zero results. Guest-only `VerSetConditionMask`, `VerifyVersionInfoA/W`, and `RtlVerifyVersionInfo` now compare bounded request structures with manifest-selected Win32 or true NTDLL version values and report mismatch errors. The x86 engine instance uses corrected argument count and stdcall cleanup for its affected Win32 declarations. Six harmless x86/x64 PEs with three manifest states branch on helper output, Win32 success/failure and `GetLastError`, and NTDLL success/mismatch; all six pass from source and in the rebuilt AppContainer package with exact bytes, artifacts, API traces, and broker closure. The previous Win32 and NTDLL version packages, eight CPU cases, twelve debugger cases, AppContainer capability, x86/x64 host-process denial, ACL redirect, and fifteen bounded malformed-PE cases pass on the same build. The clean **361-test source suite passed with one existing host-symlink skip**. The final scan found **zero explicit AppContainer SID grants across 20,186 directories and zero Emumee processes**. Mixed operators and external activation contexts remain unverified.

## Priority work to reach broader plausibility

1. **Process lifetime and identity.** Extend the new file, mapping, process, thread, and registry cleanup to socket, snapshot, event, mutex, and other owned objects. Preserve references held by another live process. Test child exit before parent use, handle reuse, and nested children. Finish returned-main and exception exit statuses, cooperative blocking waits, wait-object variants, and DLL thread detach; preserve guest PID consistency across APIs, events, and trace entries.
2. **Ownership sweep.** Audit every remaining WinAPI model path that accepts a handle, pointer, section view, or process/thread identifier. Route it through the same owner and rights checks or mark it explicitly unsupported. Extend CPU and API-pointer probes beyond current read/write/execute and `RtlMoveMemory` cases.
3. **Behavioral coverage corpus.** Expand harmless x86/x64 and managed programs for common loaders, anti-debug, anti-VM, system, user-activity and timing checks, file/registry persistence attempts, network stacks, TLS, and DLL load patterns. For each case, assert branches, side effects, traces, and extracted bytes. Count signature-only and unsupported calls by family, then implement the highest-frequency paths.
4. **Broker and reporting integrity.** Keep the worker without direct network capability. Test malformed broker messages, DNS and redirect handling, large bodies, broker death, incomplete journals, and dashboard display using local listeners and disposable markers. Record every allowed or denied broker attempt; explicitly flag unsupported network APIs.
5. **Parser and dependency hardening.** Fuzz bounded PE/.NET metadata, import, resource, relocation, archive, and report inputs with harmless mutations. Require a bounded failure or partial report, valid artifact hashes, no host execution, and no leftover permission grants. Reassess native parser dependencies and privilege reductions where compatible with the packaged worker.

## Repeatable release gate

1. Regenerate harmless fixtures: `.venv\Scripts\python.exe tests\fixtures\build_native.py`.
2. Run the full source suite: `.venv\Scripts\python.exe -m unittest discover -s tests -p 'test_*.py'`.
3. Build the Windows package: `.\build.ps1`.
4. Run packaged matrices: `.\tools\run_qpc_cases.ps1`, `.\tools\run_registry_cases.ps1`, `.\tools\run_thread_termination.ps1`, `.\tools\run_process_exit_status.ps1`, `.\tools\run_terminate_process_boundary.ps1`, `.\tools\run_cross_process_duplicate.ps1`, `.\tools\run_process_duplicate_rights.ps1`, `.\tools\run_duplicate_guest_file.ps1`, `.\tools\run_named_mapping_cases.ps1`, `.\tools\run_file_view_coherence.ps1`, and `.\tools\run_mapping_view_cases.ps1`. Use fresh output directories and run package scripts serially because the bundle's temporary ACL changes are serialized.
   Also run `.\tools\run_debug_cases.ps1` for twelve harmless x86/x64 debugger checks.
   Run `.\tools\run_shared_time_cases.ps1` for two direct shared-page timing checks.
   Run `.\tools\run_cpu_cases.ps1` for eight direct CPUID, processor-feature, TSC, and memory-persona checks.
   Run `.\tools\run_version_cases.ps1` for two NTDLL/shared-page version checks.
   Run `.\tools\run_win32_version_cases.ps1` for six manifest-dependent Win32 version checks.
   Run `.\tools\run_version_verify_cases.ps1` for six Win32/NTDLL version-comparison checks.
   Run `.\tools\run_avx_cases.ps1` for the two harmless x86/x64 AVX startup checks, exact artifacts, and broker closure.
5. Probe containment with `.venv\Scripts\python.exe tools\sandbox_smoke.py`, `tools\guest_host_process_smoke.py`, `tools\reparse_acl_smoke.py`, and `tools\malformed_pe_package_smoke.py`. These use disposable markers, local listeners, and harmless guest binaries; the probes clean up their changes.
6. Run `.\tools\check_residual_appcontainer.ps1` last. Require zero explicit AppContainer SID grants and zero Emumee processes. Record the scanned directory count and any skipped probe.

Release claims must name the exact fixtures and build tested. A passing gate supports only those behaviors and host-boundary probes; it does not certify arbitrary malware containment or complete Windows 11 compatibility.

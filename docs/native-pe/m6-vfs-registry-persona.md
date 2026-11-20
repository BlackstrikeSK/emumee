# M6 VFS, registry and persona families

Started 2026-11-19 from committed M5 (`6cf1940`). The M6 obligations and the
milestone exit criterion are complete and qualified as described below. This
certifies no API partition row: all 510 contracts in these families stay open in
the ledger, and global qualification gates remain open.

## Partition coverage

| Family | Contracts | Modeled | Reviewed refusals | Unmodeled |
| --- | --- | --- | --- | --- |
| `registry` | 104 | 104 | 0 | 0 |
| `persona` | 96 | 84 | 12 | 0 |
| `filesystem` | 310 | 258 | 52 | 0 |
| Total | 510 | 446 | 64 | 0 |

Before this milestone 222 of those rows — 111 exports across both architectures
— had no binding at all: 12 registry, 54 persona and 156 filesystem rows.
Measured with `inspect-api-surface` over the exact partition, which reports the
dispatcher classification, not parity. Dispatcher coverage is not per-row
semantic evidence.

## Registry

`api/registry.rs` completes the advapi32 and `api-ms-win-core-registry-l1-1-0`
partition on the existing owned registry model.

`RegDeleteValueA/W` delete through the new `registry::delete_value`, which
requires `KEY_SET_VALUE`, folds the name exactly as the other value paths do,
corrects the stored byte and value accounting, and reports
`ERROR_FILE_NOT_FOUND` for a value that is not there. A null value name
addresses the key's default value, as it does on Windows.

`RegEnumKey` is the legacy spelling with no `Ex` tail: its fourth argument is a
by-value character capacity rather than a length pointer, so it has its own
adapter over the same `enum_key` model and answers `ERROR_MORE_DATA` when the
subkey name plus its terminator does not fit. The frozen reference ignores that
capacity and writes the name regardless, and it leaves the success path
unreachable when `lpName` is null; both are deliberate deviations recorded
below. `RegQueryInfoKey`, the generic spelling, routes to the existing
narrow-width information model.

`RegisterServiceCtrlHandler` and `RegisterServiceCtrlHandlerEx` return a
monotonic non-null `SERVICE_STATUS_HANDLE` and clear the thread's last error.
The handler procedure is recorded by the guest's own `ServiceMain` and is never
dispatched: no console or service control event exists in this profile. A null
procedure is the one rejected argument. `lpContext` is ignored, exactly as the
frozen reference ignores it.

## Persona

### Version predicates

`GetVersionExA/W` and `RtlGetVersion` already existed. The generic `GetVersionEx`
spelling joins them; because only the caller's own `dwOSVersionInfoSize` field
distinguishes the narrow from the wide structure, that field decides the layout
instead of the export name. All four now publish one shared modeled identity
(`modeled_version`), which also backs the new predicates, so a guest cannot read
one version out of the structure and get a different answer from
`VerifyVersionInfo`. The service-pack fields are written explicitly rather than
left as incidental zeroes.

`VerSetConditionMask` implements the documented bit packer exactly: the
condition is masked to three bits, a zero type mask or condition returns the
accumulated mask unchanged, and the highest set type bit selects the one
three-bit slot written. It replaces a frozen stub that returned zero for every
call, which would have made every later predicate meaningless.

`VerifyVersionInfo`, `VerifyVersionInfoA/W` and `RtlVerifyVersionInfo` are a
real comparison. Product type, suite mask, platform identifier and build number
compare independently, while major version, minor version and the service-pack
pair compare as one ordered sequence in which the first field that differs
decides the result — the documented hierarchical rule. `VER_AND` and `VER_OR`
are accepted only for the suite mask and are an invalid argument anywhere else,
and a condition of zero for a selected field is likewise invalid.
`OSVERSIONINFOEX` is required, because the shorter structure has no suite,
product or service-pack fields to read. Win32 failures are
`ERROR_OLD_WIN_VERSION` and `ERROR_BAD_ARGUMENTS`; the Rtl form answers
`STATUS_REVISION_MISMATCH` and `STATUS_INVALID_PARAMETER`. The frozen reference
returns TRUE for every request.

A `ULONGLONG` argument occupies two x86 stack slots and one x64 register, so
these three entry points take an architecture-dependent argument count and
reassemble the condition mask from both halves on x86. The frozen declarations
use one slot and a CDECL convention for `VerifyVersionInfo`; a compiler-produced
`WINAPI` caller would corrupt its own stack against that declaration, so this
profile uses the real stdcall contract and the real slot count.

`RtlGetNtVersionNumbers` writes the major and minor version and the build with
its documented high nibble set, skipping any null output.

### Locale, session, package and feature configuration

`PersonaConfig` gained a `locale` tag, a `session_id` and a `volume` record, and
the full-persona projection now fills the locale from the validated document's
own `locale` field instead of dropping it. New persona fields are also admitted
explicitly in the analysis-plan field allowlist, so an external plan can set
them and an unknown field still fails.

`GetSystemDefaultLCID`, `GetUserDefaultLCID`, `GetSystemDefaultLangID`,
`GetUserDefaultLangID`, `GetSystemDefaultUILanguage` and
`GetUserDefaultUILanguage`, including the `api-ms-win-core-localization-l1-2-0`
spelling, all report the configured locale. One modeled locale serves the system
and user defaults alike: this profile has no separate per-user regional
selection. The admitted tags are `en-US`, `en-GB`, `de-DE` and `fr-FR`, matching
the locales the full-persona validator accepts, and an unknown tag falls back to
`en-US` exactly as the frozen thread UI-language model does. The frozen
reference instead returns the `LOCALE_USER_DEFAULT` and `LOCALE_SYSTEM_DEFAULT`
sentinels from the LCID queries — values that mean "use the default" rather than
naming a locale — and a literal `1` from `GetSystemDefaultLangID`.

`IsValidLocale` accepts the configured locale and the invariant locale under
`LCID_INSTALLED` or `LCID_SUPPORTED`; no other locale is installed here, and an
unmodeled flag answers `ERROR_INVALID_FLAGS` rather than guessing. The frozen
reference answers TRUE for every LCID.

`WTSGetActiveConsoleSessionId` reports the persona session.
`GetCurrentPackageId` returns `APPMODEL_ERROR_NO_PACKAGE` and writes nothing,
because the modeled process has no package identity; the frozen reference
reports success without filling the buffer, which would hand the guest
uninitialized bytes it would then parse. `RtlQueryFeatureConfiguration` keeps
the frozen override's behaviour: an empty boot and runtime override store with a
stable change stamp, validated configuration kind and writable outputs, and
`STATUS_NOT_FOUND` for every feature.

The generic `GetWindowsDirectory` spelling joins the existing directory model.

## Filesystem

### Handle operations

`api/files.rs` gained the handle-directed operations beyond the existing
create, transfer, seek and close core. `GetFileSize` reports the low size and,
when asked, the high half. `SetFilePointerEx` takes its distance as a
`LARGE_INTEGER` by value — two stack slots on x86 — and publishes the resulting
position. `SetEndOfFile` moves the end of the file to the handle's current
position through the new `filesystem::set_end_of_file`, which requires write
access rather than accepting append-only access, grows with zeroes, discards a
tail, and keeps the filesystem's byte accounting and capacity bound correct.

`GetFileTime` and `SetFileTime` work over new per-path creation, access and
write times. Before this milestone every file reported the one seeded filesystem
time and nothing could change it; now a guest's own `SetFileTime` is observed by
every later metadata read, including `GetFileAttributesEx` and the find-data
enumerations. A null pointer and a zero `FILETIME` both leave a time unchanged,
and the documented "do not update" sentinel is not stored as a timestamp.
Changing a time writes the file's directory entry, so a read-only handle cannot
do it and unnamed storage left by the immediate-unlink profile has no entry to
carry times.

`GetFileInformationByHandle` publishes `BY_HANDLE_FILE_INFORMATION` in its exact
layout. The volume serial number comes from persona identity; the file index is
a deterministic function of the canonical path, identical on every read of the
same file and different for different files, because this profile has no master
file table. Hard links are not modeled, so every file has exactly one name.

`FlushFileBuffers` checks the handle and succeeds: guest bytes live in the owned
virtual filesystem, so there is no write-behind cache to flush. `_lopenA/W`,
`_lclose` and `_llseek` map the legacy file API onto the same model, including
`_lclose`'s zero-on-success result, which is the opposite of `CloseHandle`, and
`HFILE_ERROR` as the failure. `_lopen` never creates a file.

### Volume, drive and device identity

`api/volumes.rs` is new and reports the one modeled volume. Its GUID, label,
filesystem name, capacity and free space are persona identity taken from the
validated document, and the 32-bit volume serial number is derived from the
leading 32 bits of that GUID so one document field decides both the GUID a guest
reads and the serial it sees. Capacity and free space are reported figures, not
an allocator: writing a guest file never changes them, and the virtual
filesystem keeps its own separate byte bound.

`GetDiskFreeSpaceEx` and its spellings answer for any path on the volume, with
caller-available free space equal to total free space because no quota is
modeled. `GetDriveTypeA/W` reports a fixed drive for C: and `DRIVE_NO_ROOT_DIR`
for every other letter, and `GetLogicalDrives` returns the single C: bit.
`GetVolumeInformationA/W` reports the label, serial, a 255-character maximum
component length and a deliberately conservative capability mask: case-preserved
Unicode names only. The virtual filesystem has no ACLs, compression, sparse
files, reparse points, quotas, streams or encryption, so those bits are absent
rather than advertised. `GetVolumeNameForVolumeMountPointA/W` requires the
documented trailing backslash and answers the volume GUID path;
`GetVolumePathNamesForVolumeNameA/W` answers the multi-string mount list and
fills the required length before reporting `ERROR_MORE_DATA`. `FindFirstVolume`,
`FindNextVolume` and `FindVolumeClose` enumerate exactly one volume from their
own handle range, distinct from the file search handles, and the second request
ends the enumeration with `ERROR_NO_MORE_FILES`. `QueryDosDeviceA/W` maps C: to
one modeled device name, reported as a multi-string, and enumerates that single
entry for a null request; the device name is a model literal, not a host device
path.

`AreFileApisANSI` reports the ANSI code page, which nothing in this profile
switches. `Wow64DisableWow64FsRedirection` and
`Wow64RevertWow64FsRedirection` apply only to the x86 guest, which is the
modeled WOW64 process, and answer `ERROR_INVALID_FUNCTION` on x64. The virtual
filesystem performs no WOW64 path redirection, so the only observable effect is
the cookie's own round trip: only a cookie this model handed out and has not yet
taken back can be reverted, so an invented value cannot re-enable anything.

### Paths, enumeration and binary type

`GetShortPathNameA/W` answers the long path. The modeled volume generates no 8.3
aliases, exactly like a Windows volume with short-name creation disabled.
`FindFirstFileEx` admits the standard and basic information levels over a name
match with no filter and no additional flags, and otherwise behaves as
`FindFirstFile`; it reads its output structure from a different argument than the
plain spelling does. `GetTempFileNameA/W` composes the documented name from the
directory, the first three prefix characters and four hex digits, and a zero
unique request picks a free number and leaves the empty file behind while a
supplied number creates nothing. `GetBinaryType` classifies from the guest
file's own headers, answering `ERROR_BAD_EXE_FORMAT` for a non-PE file or a
machine this profile does not classify.

### Console session

`AllocConsole` reports `ERROR_ACCESS_DENIED`: a console is already attached to
the modeled process and Windows refuses a second one. `GetConsoleWindow`
answers null, the same answer Windows gives when the console has no associated
window; there is no window manager here. `GetConsoleTitleA/W` and
`SetConsoleTitleA/W` round-trip a guest-set title, truncating to the caller's
capacity and reporting the characters actually copied; no title is published
until the guest sets one, because nothing in this profile supplies a launcher's
caption. `SetConsoleCtrlHandler` records and removes handlers, including the
null-routine form that asks for Ctrl+C to be ignored, and never dispatches one:
no console control event exists here. `SetConsoleHistoryInfo` validates
`CONSOLE_HISTORY_INFO` and then has nothing to change, because the modeled
console keeps no command history.

## Provider export geometry

Modeling these exports pushed the synthetic `kernel32.dll` and `kernelbase.dll`
export namespaces past a hard limit in the generated provider image. Each export
owns a 16-byte jump stub and the stub section was exactly one page, so 256
exports filled it precisely; the modeled kernel32 surface is now 264.

`provider::image` therefore gained a second tier: past 256 exports the stub
section takes a second page, which shifts the export directory and all three
lookup arrays. The raw-to-virtual delta stays 0xe00 in both tiers and every
offset is now derived from the tier, so each provider image at 256 exports or
fewer — every module except kernel32 and kernelbase — is byte-for-byte what it
was. The new ceiling is 512 exports, and `user_providers` reserves the matching
image size rather than the old fixed one.

Typed data providers, which publish mutable CRT globals, keep the single-page
geometry because their data section sits at a fixed virtual address. Only
`msvcrt.dll` has data exports and it declares 155, so the typed path now refuses
a larger namespace explicitly instead of placing its data somewhere the guest
would not find it. The provider tests cover 257 and 512 exports, the 513
rejection and that typed refusal.

## Enumeration and injection are modeled, not refused

Two exports that an analysis runtime exists to observe were initially refused and
are now modeled, because refusing them blinds the tool to the exact behaviour it
is meant to watch.

`GetSystemFirmwareTable` is what sandbox-aware code reads to fingerprint its
environment: the `RSMB` provider returns the raw SMBIOS table, and malware scans
it for strings like a hypervisor vendor in the BIOS or system manufacturer.
Refusing it both stops that guest and hides the check. It is now modeled over a
new persona `firmware` block — BIOS vendor and version, system manufacturer,
product, serial and family, and the baseboard identity — from which
`persona::FirmwareConfig::raw_smbios` builds a well-formed table (Type 0 BIOS,
Type 1 system, Type 2 baseboard, Type 127 end) wrapped in the `RawSMBIOSData`
header. The strings are persona-controlled: the default presents a consumer OEM
machine, and a scenario can present any identity, including a deliberately
VM-like one. A null or short buffer reports the required size and writes nothing,
and a provider other than `RSMB` reports no table — the honest answer for a
machine without that firmware interface — rather than inventing bytes. The
earlier refusal reasoning was wrong: the persona document is exactly the place to
source firmware identity, the same way it sources the volume GUID and the network
adapter, so the bytes are modeled identity, not fabrication.

`NtUnmapViewOfSection` (and the `Zw` spelling) is the core of process hollowing
and RunPE: a loader unmaps a target's image and maps its own in that space.
Refusing it stops the injection at its first step and loses the behaviour. It is
now modeled as a real forced section unmap over the existing remote-process
machinery. Against another process the model enters that process's address space
exactly as `VirtualAllocEx` and `WriteProcessMemory` already do, finds the image
mapped at the requested base, and removes it whole: out of the module catalog,
out of the address-space model, out of the native mapping, with the instruction
cache invalidated. Against the calling process's own pseudo-handle it unmaps one
of the caller's own images, the self-replacement path. The address must be an
image's own base; an interior address, a private reservation or free memory is
`STATUS_NOT_MAPPED_VIEW`, a terminating target is
`STATUS_PROCESS_IS_TERMINATING`, and a handle that resolves to no process is
`STATUS_INVALID_HANDLE`. Unlike image retirement, the unmap runs no detach and
respects no lifecycle phase, because the native call does not either.

Every forced unmap is recorded as a run-wide observation at the moment it
happens and surfaced in the run report as `forced_unmaps`, attributed to the
process whose space held the image and flagged when it was that process's
primary image. A `was_primary` unmap against a process other than the caller — a
parent ripping out a suspended child's main image — is the process-hollowing
signature, and the report carries it even after that child exits.

## Instruction, cache and protection observation

A submitted sample writing inside its own image is what unpacking and
self-modifying code look like, so the existing passive image-write observation,
previously installed only for submitted drivers, now also covers the submitted
user route. It records every write attempt that overlaps an initially writable
region of the sample's own image, byte for byte in a bitmap, under the existing
region, byte and record bounds. It is passive: it changes no guest instruction,
no permission and no result.

Instructions a guest writes into its own executable reservation and then calls
run as written, and overwriting the same address and calling it again runs the
new bytes, which is what an invalidated instruction cache means. Both are
decided by the guest in the `observation` control family below.

## Guest control families

Every obligation above is decided by guest instructions or by a
compiler-produced program, never by inspecting model state alone. The ten
control families emit 154 contained outcomes. Each family selects the narrow or
the wide export independently of the architecture, so a width family emits four
controls per case.

| Family | Cases | What the guest decides |
| --- | --- | --- |
| `registry` | 5 | Value deletion including the default value, the legacy by-value enumeration capacity and its ERROR_MORE_DATA, generic key information counts and maxima, the class length query, service control handle issue and its one rejected argument, and the KEY_SET_VALUE boundary that must refuse and leave the value |
| `version` | 4 | One identity through every structure spelling and both widths, the basic and extended structures, the condition-mask bit packer, the hierarchical comparison and field independence, the old-version answer, and every undefined condition and short structure |
| `locale` | 4 | Every system and user default, the API-set spelling, which locales are installed, the unmodeled flag classes, the console session, a process with no package identity, and the SMBIOS table walked byte for byte |
| `file` | 5 | Size and its high half, pointer movement, moving the end of the file both ways, per-path times a guest sets and reads back through later metadata, by-handle information including a stable per-path index, the legacy file API, and the read-only and append-only access boundaries |
| `path` | 7 | The short path and its length query, both admitted extended-search information levels, temporary-name composition in both unique modes, binary classification from a file's own headers, and two contracts that must stop |
| `volume` | 6 | Label, serial, component length and capability mask, reported capacity and free space for any path on the volume, the single-volume enumeration and its own handle range, the mount-path multi-string and its required length, the DOS device name, and the WOW64 cookie round trip on the architecture that has one |
| `console` | 4 | A guest-set title, its truncation and its rejected arguments, the absent window handle, the refused second console, handler registration and removal including the ignore form, and history validation |
| `unmap` | 3 | A real forced unmap of the caller's own image, every address that is not a mapped section's base, and a parent unmapping a suspended child's primary image |
| `observation` | 2 | Writes inside the sample's own image and their exact byte accounting, guest-written instructions running and rerunning after an overwrite, and the image protection boundary |
| `compiled` | 2 | A compiler-produced program over all six paths end to end, and a compiler-produced negative control |

`tools/native_pe_m6.py` replays and independently checks all 154 contained
controls against the packaged worker, with `tests/test_native_pe_m6.py` guarding
the control set. Guest instruction assertions determine success: a wrong value
raises a breakpoint inside the guest, and the compiled program reports a distinct
exit code for each contract it checks.

`src/emumee/guest_native/m6_program.c` is the exit criterion. It is built for
both architectures by `tools/build_guest_m6_programs.ps1`, which generates the
legacy msvcrt import library from a module definition — so the program binds only
msvcrt exports this profile models — and links the Windows SDK's own kernel32 and
advapi32 libraries, so the Win32 imports are exactly the names a real compiler
would bind. The program reads the version structure and the predicate, the
locale defaults and installed set, the volume identity and its reported capacity,
a file through create/write/size/seek/end-of-file/times/by-handle-information and
a read-only stamping refusal, a registry key through
create/set/query/subkey-enumeration/information/delete, and the SMBIOS table
including its short-buffer and wrong-provider answers. Every failure path returns
its own code and the program exits with 23. `m6_refusal.c` asks for a file
mapping, which has no model here, and must stop.

## Defects the controls found

Five defects were found by these controls rather than by inspection. Each is
the kind of coupling a source-only change misses, so each is recorded.

1. `GetTempFileName` checked that its directory existed with
   `VirtualFileSystem::exists`, which answers only for files, so the call could
   never succeed for any directory. The new `VirtualFileSystem::is_directory` is
   the directory counterpart, and the adapter uses it; a file of that name is
   still not a directory.
2. `NtUnmapViewOfSection`'s `STATUS_PROCESS_IS_TERMINATING` answer was
   unreachable: the access-gated handle resolution refuses an exited target
   first, so a terminating process looked like an invalid handle. The adapter now
   resolves the handle with no access demand, answers the terminating status, and
   only then applies the `PROCESS_VM_OPERATION` check.
3. A forced unmap observed inside a child was lost as soon as that child exited,
   because the report read it back from the child's module catalog and the
   catalog goes away with the child's address-space snapshot. Unmaps are now
   recorded run-wide at the moment they happen, which is exactly the order a
   hollowing loader works in: unmap the child's image, then let it go.
4. Several adapters compared a `DWORD` argument against zero at full
   pointer width. A compiler-produced x64 caller stores a 32-bit argument into
   its eight-byte stack slot and leaves the upper half undefined, so
   `RegCreateKeyEx` refused every call the compiled program made. The sweep that
   followed fixed the registry create, open and set reserved and option fields,
   every volume buffer capacity, the console title capacity and the Ctrl-handler
   `BOOL`, and `FindFirstFileEx`'s information level, search operation and
   additional flags. The hand-written controls could not find this: they pass
   clean 64-bit zeroes, which is precisely why the exit criterion is a program a
   real compiler produced.
5. Adding persona fields requires the analysis-plan field allowlist to admit
   them, or every plan test fails on an unknown field; and the modeled identity
   validation rejected an empty volume label until the label was allowed to be
   empty, which an unnamed volume ordinarily is. Modeling more kernel32 exports
   then exhausted the provider export geometry described above, which failed 98
   engine tests until the second stub tier existed.

## Reviewed refusals

Sixty-four rows — 32 module-export pairs on both architectures — are reviewed
explicit refusals rather than models, because the frozen behaviour cannot be
reproduced without a model this profile does not have. Each stops with its
reason instead of returning a value the guest would act on.

| Refusal | Reason |
| --- | --- |
| `GetLocaleInfoA/W` | Locale information strings need a locale data model. The frozen reference answers two information types from literals and zero for the rest. |
| `GetDateFormatA/W`, `GetTimeFormatA/W` | Locale date and time pictures need a calendar and locale name model. The frozen reference delegates to the host C library's own locale, which is not an owned deterministic guest model. |
| `FreeConsole` | Detaching the console would retire the modeled standard handles and console streams, which this profile keeps for the life of the process. Reporting success while they stayed usable is a state the guest could catch. |
| `CreateFileMappingA/W`, `OpenFileMappingA/W`, `MapViewOfFile`, `UnmapViewOfFile`, `FlushViewOfFile` | Section objects and mapped views are not modeled. View storage would not be coherent with the virtual filesystem, and a returned view would be memory the guest could read and write with no backing contract. |
| `CreateNamedPipeA/W`, `ConnectNamedPipe`, `DisconnectNamedPipe` | No pipe namespace or peer exists in this offline single-process profile. The frozen `ConnectNamedPipe` reports a connected client whenever the pipe object exists, so following it would tell the guest a client is attached when none can ever write a byte. |
| `CreatePipe`, `PeekNamedPipe` | An unbuilt in-process buffer object, not an impossible contract: both ends of an anonymous pipe belong to the caller, so no peer is involved and the frozen reference models it with a real buffer. These two are deferred implementation and are the first candidates to leave this table. |
| `CreateIoCompletionPort` | Completion ports need the pending I/O model this profile does not have. |
| `GetMailslotInfo` | No mailslot can be opened, so every call would receive a handle that is not one. |
| `DeviceIoControl` | A control code's behaviour *is* its target device's behaviour, and this user profile has no device namespace. |
| `GetCommProperties`, `GetCommTimeouts` | The virtual filesystem already stops on DOS device names, so no serial handle can exist. Refusing keeps that one convention for the whole device family; answering `ERROR_INVALID_HANDLE` instead would also have been defensible. |

Three of these refusals are proved by a guest rather than argued from source:
the compiled negative control asks for a file mapping, and the `path` family
asks for a short-name alias expansion and for an extended-search information
level outside the modeled profile. Each of the three stops the guest, and each
has its own control that must not reach a successful return.

## Verification

| Gate | Result |
| --- | --- |
| Full source validation suite | passed; index under this qualification root |
| Strict workspace Clippy, all targets, warnings denied | passes |
| Canonical API partition check | 2,590 contracts over 151 batches, unchanged |
| Static inventory controls | passes |
| Native-PE accounting suite | 176 tests, 0 failed |
| Re-measured partition surface for the three families | 446 modeled, 64 reviewed refusals, 0 unmodeled |
| Contained replay | 154 controls, independently checked against the packaged worker |

To recheck the sealed milestone from the repository root:

```powershell
C:\Python313\python.exe tools/native_pe_m6.py --root output/rust-pe-m6-complete-20261120 --source-index output/rust-pe-m6-complete-20261120/source-validation-final/index.json --check
```

Only a passing, independently checked current-source index establishes source
validation; missing or failed output is not proof. Existing M3, M4 and M5 bundles
and seals remain historical, matching their own source. This replay covers the
M6 obligations and their exit criterion; it is not per-row semantic API parity,
package matrix qualification or M10.

## Limits

What this milestone does **not** establish:

1. All 510 contracts in these families remain open in the ledger. Dispatcher
   coverage, guest controls over a family and per-row semantic evidence are not
   the same thing, and no row's evidence entry is claimed.
2. `VirtualProtect` covers the reservations a guest made itself, not the mapped
   image, so a sample cannot change the protection of its own code page: the
   request is refused with `ERROR_INVALID_ADDRESS` and the `observation` control
   pins that. In-place unpacking therefore does not run here. Extending the
   virtual-memory model to image regions belongs with the allocation family, not
   with these three partition families.
3. The memory string capture behind N14 and the carving, group and context
   artifact attribution behind N15 remain shared M6/M8 work: the models exist but
   are reachable only from the closed indicator target, and the submitted request
   carries no capture configuration. The image-write, instruction-cache and
   protection observations behind N13 are what this milestone closes for the
   user route.
4. No commit of a submitted sample, host-native guest execution or legacy guest
   fallback is part of this milestone.

## Remaining work in order

1. M7 network, COM, crypto, security and resource families.
2. The N14 capture configuration and the N15 artifact attribution, with M8.
3. Per-contract semantic closure for all 510 rows, which no part of this
   milestone claims.

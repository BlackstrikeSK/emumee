# M7 network, COM, cryptography, security and resource families

Started 2026-11-20 from committed M6 (`ba8aaeb`). M7 closes the remaining
observation-surface families the frozen native user model needs: PE resources,
cryptography, COM/shell helpers, the security (SID/token/service) surface and
the network stack. The milestone was delivered family by family; each family is
a durable, verified increment (owned model or reviewed refusal for every
partition row, x86/x64 guest controls, Rust tests, strict clippy), and with the
last family landed the full qualification seal is produced below.

This milestone certifies no API partition row on its own: the contracts in these
families stay open in the ledger and the global qualification gates remain open
until M8–M11.

## Partition coverage

| Family | Contracts | Modeled | Reviewed refusals | Unmodeled | Status |
| --- | --- | --- | --- | --- | --- |
| `resources` | 18 | 18 | 0 | 0 | complete |
| `crypto` | 46 | 46 | 0 | 0 | complete |
| `com` | 142 | 142 | 0 | 0 | complete |
| `security` | 152 | 152 | 0 | 0 | complete |
| `network` | 276 | 276 | 0 | 0 | complete |

Counts are entries (one per architecture) as `inspect-api-surface` reports them
over the exact partition. Dispatcher coverage is not per-row semantic evidence.

## Resources

`api/resources.rs` models the kernel32 PE resource directory surface —
`FindResourceA/W`, `FindResourceExA/W`, `LoadResource`, `LockResource`,
`SizeofResource`, `FreeResource` — and the `LoadStringW` string-table loader
exported from `api-ms-win-core-libraryloader-l1-2-0` (and its kernel32 / user32
aliases). Before this family all 18 of those rows were unmodeled.

Every lookup walks the three-level resource tree (type → name → language)
directly out of the mapped image in guest memory: the resource data directory is
read from the module's own optional-header data directory entry 2, honoring a
header the sample rewrote. No host resource loader is consulted and no resource
storage is invented. A module with no resource directory, or a type / name /
language that is absent, fails with the Windows error the guest would see —
`ERROR_RESOURCE_TYPE_NOT_FOUND` (1813), `ERROR_RESOURCE_NAME_NOT_FOUND` (1814)
or `ERROR_RESOURCE_LANG_NOT_FOUND` (1815).

`MAKEINTRESOURCE` is decoded exactly: a selector whose value fits in the low word
is an integer id, otherwise it is a string compared case-insensitively against
the `IMAGE_RESOURCE_DIR_STRING_U` name, matching the loader's case folding.
`FindResource` takes the first (neutral/default) language leaf; `FindResourceEx`
matches the requested `LANGID` and falls back to that first leaf when the exact
language is absent, as the loader does. The returned `HRSRC` is the mapped
virtual address of the `IMAGE_RESOURCE_DATA_ENTRY`, so `LoadResource` and
`SizeofResource` read the entry back from that handle; `LoadResource` returns the
resource's mapped first byte (`base + OffsetToData`), `LockResource` is the
identity the modern loader makes it, and `FreeResource` is the documented no-op
that reports `FALSE`.

`LoadStringW` resolves the `RT_STRING` bundle that holds a string id —
`(id >> 4) + 1` — walks to the `id & 0xf`-th length-prefixed UTF-16 entry inside
it, and copies at most `cchBufferMax - 1` units plus a terminator, returning the
copied count. A zero capacity returns the documented read-only pointer to the
mapped string instead of copying.

### Controls

`m7_resource_probe` (`rust/emumee-core/src/fixtures/m7.rs`) is a generated
x86/x64 caller carrying a hand-laid `.rsrc` directory — `RT_RCDATA` id 101 in a
neutral and an en-US language, the named resource `CONFIG` in en-US, and the
`RT_STRING` bundle for ids 0–15 — mapped through `Probe::resources`. Four
controls decide their own outcomes with guest breakpoints:

- **ById** finds id 101, asserts the exact `HRSRC`, loads and locks it to the
  same mapped pointer, checks the payload bytes and the reported size, confirms
  `FreeResource` reports `FALSE`, and reaches the en-US entry through the `Ex`
  language argument.
- **ByName** finds `CONFIG` through `FindResourceExW`, sizes and loads it,
  checks the payload, and confirms a lowercase name still matches.
- **LoadString** loads string id 5 into a poisoned buffer and asserts the exact
  text, terminator and untouched tail.
- **Missing** confirms an absent type, an absent name and an out-of-range string
  id each fail with their own Windows error and return null/zero.

The model builder is additionally covered by `api/resources_tests.rs`, which
checks the fixture's resource tree is a well-formed three-level directory whose
data entries stay inside the blob.

## Cryptography

`api/crypto.rs` models the legacy CryptoAPI hash/key/random surface
(`advapi32`), the base64/hex decoder (`crypt32.CryptStringToBinaryA/W`), the
deterministic random providers (`SystemFunction036`/`RtlGenRandom`,
`bcryptprimitives.ProcessPrng`) and the CNG provider/key handle surface
(`bcrypt`, `ncrypt`). Before this family all 46 of those rows were unmodeled.

For a malware-analysis runtime cryptography is observed, not refused. Owned,
deterministic primitives back it: `emumee_core::crypto` provides reference MD5,
SHA-1 and RC4 (each with known-answer tests), and the `sha2` crate provides
SHA-256/384/512, so `CryptCreateHash` → `CryptHashData` → `CryptGetHashParam`
returns a real digest of the bytes the guest fed. `CryptDeriveKey` derives a
session key from the base hash value, truncated to the algorithm key length, and
`CryptDecrypt` carries out RC4 decryption in place against the real keystream, so
a sample that unpacks an RC4 payload through a hash-derived key is watched doing
it. Base64 and hex payloads are decoded for real through `CryptStringToBinary`,
honoring the in/out size protocol (a null buffer answers the required length and
an undersized buffer reports `ERROR_MORE_DATA`).

Randomness is a fixed-seed SplitMix64 stream shared by `CryptGenRandom`,
`SystemFunction036` and `ProcessPrng`: it is deterministic and reproducible
between a run and its replay, and — unlike the host clock — carries no state a
contained control could be caught disagreeing on, so a control can assert the
exact bytes each provider returns.

The CNG surface is modeled as observable handles: `BCryptOpenAlgorithmProvider`
records the requested algorithm and issues a handle, `BCryptGetProperty` answers
the common object/hash/block lengths, and `BCryptImportKeyPair` /
`NCryptImportKey` issue key handles so an imported key blob is recorded rather
than failing the guest. Properties this profile does not model answer
`STATUS_NOT_SUPPORTED` rather than a fabricated value.

### Controls

`m7_crypto_probe` (`rust/emumee-core/src/fixtures/m7.rs`) splits across five
generated x86/x64 controls, each reaching its exports through a real import
table and deciding its own outcome (the Probe skeleton binds at most two import
modules, so the family's five DLLs are split across controls):

- **Hash** acquires a context, MD5-hashes `"abc"` and asserts the exact digest
  and its reported size, with the tail of the output buffer left poisoned.
- **Random** draws eight bytes from each of the three providers and asserts the
  exact SplitMix64 stream, proving determinism and advance.
- **Decode** base64- and hex-decodes `"abc"` and asserts the bytes and length.
- **Rc4** derives an RC4 key from an MD5 hash, decrypts a buffer in place and
  asserts the recovered plaintext (the ciphertext is computed by the fixture
  from the same owned RC4).
- **Cng** opens a BCrypt SHA-256 provider, reads `HashDigestLength` (32),
  closes it, and opens and frees an NCrypt storage provider.

The owned primitives carry known-answer tests in `emumee_core::crypto`, and
`api/crypto.rs` unit-tests the digest table, the base64/hex decoders and the
deterministic random stream directly.

## COM, shell and path helpers

The `com` partition spans five concerns, and the models follow those lines
rather than the module boundaries: `api/path.rs` (shlwapi path strings),
`api/com.rs` (ole32 / oleaut32 / rpcrt4 and the synthetic guest interfaces),
`api/shell.rs` (shell32), plus additions to `api/winstrings.rs`,
`api/crt_format.rs` and `api/network.rs`. Before this family 136 of the 142
rows were unmodeled.

### shlwapi path and string helpers

`api/path.rs` models `PathAddBackslash`, `PathAppend`, `PathCanonicalize`,
`PathFindExtension`, `PathFindFileName`, `PathIsRelative`, `PathRemoveExtension`,
`PathRemoveFileSpec`, `PathRenameExtension` and `PathStripPath` in both widths.
These are pure string transforms over guest buffers: no filesystem is touched
and no host path API is called. Every function works on fixed-width code units,
so a pointer-returning call such as `PathFindFileName` answers an address
exactly inside the caller's own buffer, and an in-place edit writes the
shortened string back with its terminator where Windows would put it — the
bytes past that terminator are deliberately left alone, as the real functions
leave them.

`StrCmpIA/W` reuse the existing case-folding ordinal comparison in
`api/winstrings.rs`; `StrStrA/W` and `StrStrIA/W` are a new unit-aligned
substring search there that answers a pointer into the haystack, or null when
absent. `wnsprintfA/W` and `wvnsprintfA` are routed to the already-modeled
counted formatter in `api/crt_format.rs` — they are `WINAPIV` (cdecl) bounded
sprintf, which is exactly that model's contract, so they share its tested
rendering rather than growing a second formatter. Those three therefore have no
bespoke guest control of their own: the M6 probe skeleton issues stdcall calls,
and driving a cdecl variadic through it would test the harness, not the model.

### ole32, oleaut32 and rpcrt4

Apartment calls are tracked for real: the first `CoInitialize`/`CoInitializeEx`/
`OleInitialize` reports `S_OK` and a nested one reports `S_FALSE`, with
`CoUninitialize` unwinding the nesting. `CoInitializeSecurity` and
`CoSetProxyBlanket` are recorded and succeed without effect.

`CoCreateGuid` and `rpcrt4.UuidCreate` return deterministic, clearly synthetic
GUIDs from a per-run counter, so a control can assert them exactly and a replay
agrees; `StringFromCLSID` renders the braced upper-case form and
`UuidToStringA` the bare lower-case form, each into memory the model allocates
on the guest process heap.

`oleaut32` BSTRs are genuine: `SysAllocString`, `SysAllocStringLen` and
`SysAllocStringByteLen` allocate the four-byte byte-length prefix plus the
payload and terminator and answer a pointer past the prefix, `SysFreeString`
releases the base, and `VariantInit` clears the whole variant (16 bytes on x86,
24 on x64) to `VT_EMPTY`. Each is reachable by name and by the ordinal that
samples routinely import instead (`#2`, `#4`, `#6`, `#8`).

### Synthetic guest interfaces

Activation hands the guest a real object rather than a token: `CoCreateInstance`
builds a vtable of synthetic call gates on the guest heap and an interface
pointer to it, so a sample reaches `QueryInterface`, `AddRef`, `Release` and the
service methods *indirectly through the vtable*, the way compiled COM code does.
Slot indices match the real interfaces, so a sample built against the shipping
headers lands on the right method — `IWbemLocator::ConnectServer` at index 3 and
`IWbemServices::ExecQuery` at index 20. Slots this profile does not model share
one gate that stops with its reason instead of running into unmapped memory.

Reference counts are tracked for real. A successful `QueryInterface` for an
interface the object already exposes answers the same pointer and takes its own
reference; the last `Release` tears the object and its vtable down and records
the address, so a later call on that pointer is reported as a use-after-release
rather than silently tolerated. An IID the class does not expose is refused with
`E_NOINTERFACE` and the out pointer is cleared rather than left stale. A CLSID
with no modeled class still activates as a plain `IUnknown` and the class asked
for is recorded, so an unknown activation is observed instead of blinding the
run.

WMI is observed, not executed: `ConnectServer` records the namespace and answers
an `IWbemServices`, `ExecQuery` records the query language and the WQL text and
answers an enumerator, and that enumerator's `Next` reports `WBEM_S_FALSE` with
zero objects returned. No provider runs and no system is queried, so the
behavior is captured without being carried out.

### shell32

Known folders come from the persona and the process environment through the new
`Persona::known_folder`, so `SHGetFolderPathA/W` answers the same path on every
run and never consults a host folder; `CSIDL_FLAG_CREATE` is masked off and a
folder id this profile does not map fails rather than inventing a path.
`SHCreateDirectoryExA/W` creates the whole tree in the virtual filesystem and
treats an existing directory as success, as the Ex spelling does.
`CommandLineToArgvA/W` implements the documented splitting rules — `argv[0]`
takes no escapes, and elsewhere `2n` backslashes before a quote are `n`
backslashes plus a quote toggle while `2n+1` are `n` backslashes plus a literal
quote — then publishes a pointer array followed by the strings on the guest
heap. `IsUserAnAdmin` (also reached by its ordinal-only export `#680`) reports
the default persona's ordinary, non-elevated user.

Execution is the one place the model deliberately stops short of the effect:
`ShellExecuteA/W` and `ShellExecuteEx` record the verb, file and parameters and
report the success a caller tests for, while no process — host or guest — is
started. `ExtractIcon` reports "no icon", which is honest rather than fabricated,
and `SHChangeNotify` is recorded. `SHGetMalloc` hands back a working `IMalloc`
whose `Alloc`, `Realloc`, `Free` and `GetSize` run on the guest process heap, so
shell code that allocates through it works instead of stopping.

`urlmon.URLDownloadToCacheFileA/W` fetches through the same explicit offline
broker as `URLDownloadToFile`, into a cache path derived from the URL under the
persona's `INetCache` directory, creating the directory chain, capturing the body
as an artifact and reporting the path back to the caller (with `E_OUTOFMEMORY`
for a short buffer).

### Controls

`m7_path_probe` has two controls — **Query** (wide: filename and extension
pointers, relative/absolute, substring hit and miss, case-insensitive compare)
and **Edit** (narrow: the seven in-place edits, each verified by comparing the
result with `lstrcmp`, which stops at the terminator and so is indifferent to
the bytes the real functions leave behind).

`m7_com_probe` adds six, all deciding their own outcomes:

- **Activation** nests and unwinds the apartment, activates the locator, walks
  the reference count up and down through the vtable, proves a queried pointer
  is the same object by continuing its count, releases it to zero, and confirms
  a rejected IID returns `E_NOINTERFACE` with a cleared out pointer.
- **Wbem** drives locator → `ConnectServer` → `ExecQuery` → `Next` entirely
  through real vtable slots and confirms the enumeration is empty.
- **Bstr** allocates, measures, compares and frees BSTRs (including the null
  no-op) and checks `VariantInit` clears the variant.
- **Guid** and **Uuid** assert the exact deterministic GUID bytes and both
  rendered string forms.
- **Shell** checks the non-elevated user, the system/windows known folders and
  the create-flag and unknown-id paths, a directory tree created twice, the
  argv count, the recorded launch reporting success, and an `IMalloc` round
  trip.

The ordinal-only `oleaut32` and `shell32` imports are modeled and covered by the
dispatcher, but the probe skeleton builds its import table by name, so their
controls exercise the same models through the named spellings. `api/shell.rs`
additionally unit-tests the command-line splitter against the documented cases
and the CSIDL mapping.

## Security

Three models cover the `security` partition: `api/security.rs` (SIDs, tokens,
privileges, hardware profile, `secur32` user names), `api/services.rs` (the
service control manager) and `api/lsa.rs` (audit policy and the LSA
authentication packages). Before this family 148 of the 152 rows were
unmodeled.

### Identity

The persona owns one deterministic machine SID — `S-1-5-21-` plus three fixed
sub-authorities — and one ordinary interactive user at RID 1001, so every
identity answer is the same on every run. SIDs live entirely in guest memory in
their real binary layout (revision byte, count byte, six-byte big-endian
authority, little-endian sub-authority array), so a sample that walks a SID by
hand sees what Windows would hand it. `GetSidIdentifierAuthority`,
`GetSidSubAuthority` and `GetSidSubAuthorityCount` answer pointers *into the
caller's own SID*, as the real functions do, rather than into model storage.
`AllocateAndInitializeSid` allocates on the guest process heap and `FreeSid`
releases it, answering NULL as documented.

`LookupAccountName`/`LookupAccountSid` translate between the persona user and
its SID, plus the well-known `Everyone` and `Administrators` aliases, and the
referenced domain follows the account — the machine name for the local user,
nothing for a world group, `BUILTIN` for an alias. An account that does not
exist reports `ERROR_NONE_MAPPED` rather than being invented.
`secur32.GetUserNameEx` renders the SAM, display, DN and UPN forms from the same
persona identity.

### Tokens and privileges

`OpenProcessToken` issues a token for the persona's user. It is outside the M7
partition (it belongs to the `process` family) but is modeled here because
without it the token surface has no reachable entry point.

The token carries the privileges an ordinary interactive user actually holds —
`SeChangeNotify` and `SeIncreaseWorkingSet` enabled, `SeShutdown`, `SeUndock`
and `SeTimeZone` present but disabled — and deliberately **not**
`SeDebugPrivilege`. `LookupPrivilegeValue`/`LookupPrivilegeName` use the real
well-known LUIDs (`SeDebugPrivilege` is 20), so a sample's own constants line up.

`AdjustTokenPrivileges` is where the model earns its keep: a privilege the token
does not hold cannot be enabled, and the call reports the documented partial
success — `TRUE` with `ERROR_NOT_ALL_ASSIGNED` — which is exactly the signal an
elevation attempt reads. The attempt is recorded with the privilege names and
whether it was granted, so a `SeDebugPrivilege` grab is visible in evidence
without the run quietly acquiring rights it should not have.
`GetTokenInformation` answers `TokenUser`, `TokenGroups`, `TokenPrivileges`,
`TokenOwner`, `TokenPrimaryGroup`, `TokenElevation` (not elevated),
`TokenElevationType`, `TokenIntegrityLevel` (medium) and `TokenSessionId`, with
interior `PSID` pointers fixed up to address the caller's own buffer and the
documented `ERROR_INSUFFICIENT_BUFFER` plus required length for a short one.
`TokenStatistics` is refused rather than answered, because its LUIDs and quotas
would have to be invented. `CheckTokenMembership` compares against the real
group list, so the `BUILTIN\Administrators` check an elevation test makes
answers false — and that answer is recorded.

### Service control manager

`api/services.rs` keeps an owned service database. Service creation is the
classic persistence step, so it is observed in full — name, display name, type,
start mode, error control and binary path are recorded and stay queryable
through `QueryServiceConfig` and `QueryServiceStatus` — while nothing is ever
executed. `StartService` records the request and marks the record running so a
sample's own follow-up query agrees with what it asked for, but no process, host
or guest, is created. `DeleteService` retires the record, after which the name
no longer resolves (`ERROR_SERVICE_DOES_NOT_EXIST`), and a duplicate create
reports `ERROR_SERVICE_EXISTS`. `ControlService`, `ChangeServiceConfig`,
`ChangeServiceConfig2`, `EnumServicesStatus` and `SetServiceStatus` complete the
surface, with the `QUERY_SERVICE_CONFIG` and `ENUM_SERVICE_STATUS` layouts built
for each pointer width and their string pointers fixed up into the caller's
buffer.

`StartServiceCtrlDispatcher` reports `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`,
which is precisely what a service binary sees when it is run interactively
rather than launched by the real SCM. That keeps a sample on its non-service
path instead of waiting forever on a controller that does not exist.

### Audit policy and LSA

Audit categories are a fingerprinting surface, so `api/lsa.rs` answers them from
a fixed table of the nine well-known categories with their real GUIDs
(`{6997984N-797A-11D9-BED3-505054503030}`) and a clean default policy of
`POLICY_AUDIT_EVENT_NONE`. Category id and GUID translate both ways;
sub-categories report none rather than inventing GUIDs. Buffers are allocated on
the guest heap and released by `AuditFree`.

`LsaCallAuthenticationPackage` is the credential-enumeration path — the `MsV1_0`
logon-session and Kerberos ticket-cache queries. The attempt is recorded in full
and the call reports a protocol status of `STATUS_NOT_SUPPORTED` with no return
buffer: the behavior is observed while nothing credential-shaped is ever
synthesized or handed back. `LsaConnectUntrusted`,
`LsaLookupAuthenticationPackage` (stable ids for the packages a real system
has), `LsaFreeReturnBuffer` and `LsaDeregisterLogonProcess` complete the chain.
`EncryptMessage` reports `SEC_E_INVALID_HANDLE`, since no SSPI security context
is ever established in this profile and there is no key material to encrypt
under.

### Controls

`m7_security_probe` has six controls:

- **Sid** builds `S-1-5-32-544` through `AllocateAndInitializeSid`, checks its
  length and validity, proves the bytes equal the well-known Administrators SID,
  copies it, rejects a short copy and a bad revision, and frees it.
- **Token** opens a token, resolves `SeDebugPrivilege` to LUID 20, confirms the
  refused adjustment reports `TRUE` with `ERROR_NOT_ALL_ASSIGNED` while a held
  privilege adjusts cleanly, reads `TokenElevation` as not elevated, checks the
  short-buffer path, and confirms the user is in `Everyone` but not in
  `Administrators`.
- **Account** translates the persona user both ways (a 28-byte SID reported as
  `SidTypeUser`), does the same for `Everyone` as a well-known group, and
  confirms an unknown account reports `ERROR_NONE_MAPPED`.
- **UserName** checks the SAM and display forms and the refusal of an unmodeled
  format.
- **Service** creates an auto-start own-process service, sees it stopped, starts
  it and sees it running, reads its stored configuration back, hits
  `ERROR_SERVICE_EXISTS` on a duplicate, deletes it and confirms the name stops
  resolving, and confirms the interactive dispatcher reports
  `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT`.
- **Audit** enumerates the nine categories, round-trips two category GUIDs to
  their ids, queries the default policy, and drives the LSA package call to its
  recorded, empty answer.

Unit tests cover the SID binary layout, the privilege LUID table, the fact that
the persona user is not an administrator and does not hold `SeDebugPrivilege`,
and the audit category GUID round trip.

## Network

Six models cover the `network` partition: `api/sockets.rs` (Winsock),
`api/adapters.rs` (the IP Helper enumeration), `api/icmp.rs` (echo),
`api/dns.rs` (resolution), `api/lanman.rs` (workstation information and the
network redirector) and `api/http_config.rs` (the URL, option and proxy
surfaces WinINet and WinHTTP share). Before this family 108 of the 138
module/export pairs were unmodeled.

### Winsock

The profile is offline by construction. The model is built so the *intent* of
every socket operation is captured even though no packet can leave:

- `connect` reads the `sockaddr_in` and records the exact host and port the
  sample meant to reach, then reports `WSAENETUNREACH`.
- `send` captures the payload it was handed as a network artifact — the
  exfiltration attempt is preserved as evidence — then reports `WSAENOTCONN`,
  because the socket genuinely never connected.
- A DNS lookup records the name queried before answering.

Inbound networking stays refused, matching the frozen reference's
`_deny_inbound`: `listen` and `accept` report `WSAEOPNOTSUPP` and are recorded
as denials, so a sample is never handed a server socket that could not receive
anything.

Everything pure or local is answered for real: `htons`/`htonl`/`ntohs`/`ntohl`,
`inet_addr`, `inet_ntoa` (through the single static buffer Winsock documents),
`inet_pton`, `inet_ntop`/`InetNtopW`, `select` timing out with every descriptor
set emptied, `__WSAFDIsSet` scanning the caller's array, `ioctlsocket`'s
`FIONBIO` and `FIONREAD`, `setsockopt`/`getsockopt` (`SO_TYPE` reads back the
socket's own type), `bind` (a local address needs no network), and `gethostname`
/`GetHostNameW` from the persona.

`WSAStartup` negotiates a version, fills `WSADATA` for the caller's pointer
width, and is enforced: every other entry point reports `WSANOTINITIALISED`
until it has run, and `WSACleanup` unwinds the nesting.

Name resolution is deliberately conservative. `localhost` answers the loopback
address, a literal dotted quad parses, and the persona's own host name answers
the synthetic adapter address; anything else reports `WSAHOST_NOT_FOUND` with
the queried name recorded. The Rust broker protocol has no address reply, so
live resolution is an explicitly recorded gap rather than a fabricated answer.
`gethostbyname` and `getaddrinfo` build real `HOSTENT` and `ADDRINFOA`
structures on the guest heap, with the interior alias, address-list and
`sockaddr` pointers fixed up, so a caller that walks them finds what it expects.

Winsock is routinely imported by ordinal, so the model resolves the documented
export ordinals (1 `accept` through 181 `inet_pton`) to the same handlers as the
named spellings. The table is taken from the frozen reference's own oracle; an
ordinal outside it stays unmodeled rather than aliasing something arbitrary.

### Controls

`m7_socket_probe` has two controls:

- **Core** checks the byte-order helpers before initialization, confirms a
  socket call before `WSAStartup` reports `WSANOTINITIALISED`, negotiates 2.2
  and reads the version words back, round-trips an address through `inet_pton`
  and `inet_ntop`, reads the persona host name, sees `select` time out, and
  confirms the stack is uninitialized again after the last `WSACleanup`.
- **Transfer** refuses an unsupported address family, opens a TCP socket, reads
  `SO_TYPE` back, sets non-blocking mode, binds a local address, confirms
  `listen` is refused with `WSAEOPNOTSUPP`, drives `connect` to
  `WSAENETUNREACH` and `send` to `WSAENOTCONN`, resolves loopback but not an
  unknown name, and confirms a closed handle is no longer a socket. The
  engine-side test additionally asserts the recorded destination
  (`10.0.2.15:8080`), the fourteen bytes offered, the recorded inbound denial
  and the single captured payload artifact.

Unit tests cover the ordinal table against its documented argument counts and
the address-text round trip.

### The modeled adapter

Everything outside Winsock is derived from one persona-owned adapter, added as
`PersonaConfig::adapter` (`AdapterConfig`: connection name, hardware
description, adapter GUID, MAC, address, prefix length, gateway, DNS servers,
DHCP flag, MTU and interface index). The default is the NAT layout the Winsock
model already assumes — 10.0.2.15/24, gateway 10.0.2.2, DNS 10.0.2.3, MAC
00-15-5D-2E-4A-71, MTU 1500, interface index 12 — so the adapter tables, the
routing table, the DNS catalog and `gethostbyname` all describe the same
single-homed machine. A document may present any adapter the scenario needs;
`Persona::new` refuses one that could not exist (a reserved or colliding
address, a gateway outside its own subnet, a prefix with no usable broadcast, a
physical address that is not six octets, more than four DNS servers).

Network enumeration is a fingerprinting surface a sample uses to decide where
it has landed, so it is answered rather than refused — deterministically, from
the persona, with no host interface ever read.

### IP Helper

`api/adapters.rs` models `GetAdaptersInfo`, `GetAdaptersAddresses`,
`GetNetworkParams`, `GetIfTable`, `GetIpAddrTable`, `GetIpForwardTable`,
`GetIpNetTable`, `GetExtendedTcpTable` and `ConvertLengthToIpv4Mask`.

Each structure is built byte by byte at the offsets a compiler lays out for the
caller's pointer width, and the layouts were taken from MSVC itself rather than
guessed: `IP_ADAPTER_INFO` is 648 bytes on x86 and 704 on x64 (its lease times
are 64-bit `time_t`), `IP_ADDR_STRING` 40/48, `FIXED_INFO` 584/600,
`IP_ADAPTER_ADDRESSES` 376/448, `MIB_IFROW` 860 in both, and every
address-list node opens with the `ULONGLONG` alignment union that pads it to
eight bytes in both architectures. Interior pointers — `Next`, the adapter
name, the DNS suffix, the description and friendly name, and each
`SOCKET_ADDRESS` — are fixed up to address the caller's own buffer, so a
sample that walks the graph by hand finds what Windows would hand it.

The documented buffer protocol is honored exactly: a null buffer or a short one
learns the required size and reports `ERROR_BUFFER_OVERFLOW` (the adapter
calls) or `ERROR_INSUFFICIENT_BUFFER` (the MIB tables).
`GetAdaptersAddresses` honors `SKIP_UNICAST`, `SKIP_ANYCAST`,
`SKIP_MULTICAST`, `SKIP_DNS_SERVER`, `INCLUDE_PREFIX`, `SKIP_FRIENDLY_NAME`,
`INCLUDE_WINS_INFO` and `INCLUDE_GATEWAYS`, reports `ERROR_NO_DATA` for an
IPv6-only enumeration (this profile configures no IPv6 address) and
`ERROR_NOT_SUPPORTED` for a flag set it does not model, rather than returning a
graph that quietly ignores what was asked.

Two deliberate honesty points. Lease times, `dwLastChange` and every interface
counter stay zero: a contained run has no traffic history, and the host clock
must not leak into a table a control compares byte for byte. The ARP table
carries only the subnet broadcast's all-ones hardware address — the one mapping
that needs no invented neighbour — and the TCP table is genuinely empty,
because the Winsock model never completes a connection; `GetExtendedTcpTable`
reports that emptiness instead of a fabricated peer, and refuses a table class
or address family outside `TCP_TABLE_OWNER_PID_ALL` over IPv4.

The routing table is the three routes a single-homed DHCP workstation has: the
default route through the gateway (indirect, NETMGMT), the on-link subnet and
the host route for its own address (both direct, LOCAL), sorted by destination
and mask when the caller asks for an ordered table.

### ICMP

`api/icmp.rs` models `IcmpCreateFile`, `IcmpSendEcho` and `IcmpCloseHandle`,
reachable from both `iphlpapi` and the legacy `icmp` export set.

No packet can leave, so the model captures the *intent* of a ping: the
destination, the request size and the requested TTL are recorded, and a
non-empty payload is captured as a network artifact, because an echo request is
a documented covert channel. The call then reports `IP_REQ_TIMED_OUT`, which is
what an unreachable network genuinely produces.

The two destinations that need no network answer for real — the loopback
address and the adapter's own address, which a real stack replies to locally.
Their replies are built in the caller's `ICMP_ECHO_REPLY` (28 bytes on x86, 40
on x64) with the payload echoed back, the reply data pointer addressing the
caller's own buffer, a TTL of 128 and a round-trip time of zero, so a control
can assert the whole reply without touching the clock. A broadcast, multicast
or unspecified destination has no single peer and is refused; options other
than a plain IPv4 TTL are refused rather than interpreted against a network
that does not exist.

### DNS

`api/dns.rs` models `DnsQuery_A`, `DnsQuery_W`, `DnsQuery_UTF8`,
`DnsRecordListFree` and `DnsFree` against the guest's own record catalog, which
is derived from the persona: the machine's name and fully qualified name answer
with the adapter address, the matching reverse name answers with the machine
name, and loopback answers for itself. Every other name is reported absent with
`DNS_ERROR_RCODE_NAME_ERROR` and the exact name recorded, so an attempt to
resolve a command-and-control host is preserved as evidence instead of being
answered with a fabricated address. A name the catalog holds but with no record
of the requested type reports `DNS_INFO_NO_RECORDS`, which is the distinction a
resolver really draws.

Answers are real `DNS_RECORD` chains on the guest heap — a 24-byte header on
x86 and 32 on x64, the data union at that offset — with `pName` and a PTR
target addressing strings in the same block, in the character set the called
spelling implies (`DnsCharSetUnicode`, `Utf8` or `Ansi` in the record flags
beside the answer-section bits). An explicit server list, or any option beyond
the cache and wire-query controls, is refused rather than silently ignored;
`DnsRecordListFree` and `DnsFree` release exactly the blocks this model handed
out and nothing else, and each accepts only the free types it documents.

### Workstation information and the network redirector

`api/lanman.rs` models `netapi32`/`wkscli`/`netutils`
(`NetGetJoinInformation`, `NetWkstaGetInfo`, `NetUserAdd`,
`NetApiBufferFree`) and `mpr` (`WNetOpenEnum`, `WNetEnumResource`,
`WNetAddConnection2`, `WNetGetConnectionA/W`).

Join and workstation information are pure fingerprinting, so they are answered
from the persona in the real `WKSTA_INFO_100/101/102` layout for each pointer
width (20/24/28 bytes on x86, 32/40/48 on x64), with the computer and workgroup
names published beside the structure in one allocation that `NetApiBufferFree`
releases — and a pointer that allocation never handed out is refused rather
than freed. The default persona is in a workgroup, so `NetGetJoinInformation`
reports `NetSetupWorkgroupName` with the workgroup's name; a domain persona
reports `NetSetupDomainName`. A server name that is not this machine reports
`NERR_InvalidComputer`, because there is no network over which to ask another
one.

`NetUserAdd` is the account-persistence step, so it is observed in full: the
account name, privilege level, flags, home directory, logon script and comment
are recorded, along with whether a password was supplied — the password text
itself is never copied into evidence. Nothing is created, because this profile
keeps no account database, and the call reports the success that keeps the
sample on its own path.

The redirector is the lateral-movement surface, and what the sample *asked for*
is the evidence. `WNetAddConnection2` records the share, the device it would
have appeared as, the account it tried to authenticate as and that a password
was supplied, then reports `ERROR_NO_NETWORK` — the literal truth of this
profile. A remote name that is not a UNC path is refused with
`ERROR_BAD_NET_NAME` first. `WNetOpenEnum` records the container a sample
wanted to browse and reports `ERROR_NO_NETWORK` without issuing a handle, so
`WNetEnumResource` can only ever be handed an invalid one and says so.
`WNetGetConnection` reports `ERROR_NOT_CONNECTED` for a real drive letter —
the guest's only volume is local, so no device is redirected — and
`ERROR_BAD_DEVICE` for a string that is not a device at all.

### WinINet and WinHTTP URLs, options and proxies

`api/http_config.rs` carries the URL splitter, the per-handle option store and
the proxy answers that WinINet and WinHTTP share; the entry points stay in
`api/internet.rs` and `api/winhttp.rs`.

`InternetCrackUrlA/W` and `WinHttpCrackUrl` are pure string work, so they are
carried out for real. One parser answers both, and the caller's
`URL_COMPONENTS` (60 bytes on x86, 104 on x64) is filled in both documented
modes: a null component pointer with a zero length receives a pointer *into the
caller's own URL text* and the component's length, while a supplied buffer
receives a copy with its terminator — and a buffer one character short fails
the whole call with `ERROR_INSUFFICIENT_BUFFER` and the length it needed,
before anything is copied. Scheme numbers and default ports follow wininet.h
(`INTERNET_SCHEME_HTTPS` is 4, HTTP 3, FTP 1); a URL with no recognizable
scheme reports `ERROR_INTERNET_UNRECOGNIZED_SCHEME`, a structure size that is
not the real one reports `ERROR_INVALID_PARAMETER`, and `ICU_REJECT_USERPWD`
refuses a URL carrying credentials. Escaping and decoding flags are an explicit
model stop rather than a silent no-op.

`InternetQueryOption`/`InternetSetOption` keep a per-handle option store, so a
set is visible to the matching query and a sample's configuration is recorded:
the handle type (session, connection or request, with the real wininet.h
numbers), the connect/send/receive timeouts and retry count with their
documented defaults, the security flags a request's own URL implies, the
request's URL, the user agent its session opened with, and the proxy
configuration — reported as `INTERNET_OPEN_TYPE_DIRECT` with no proxy named.
An option outside that set reports `ERROR_INTERNET_INVALID_OPTION` instead of a
fabricated value, and a short output buffer learns the size it needed.
`WinHttpSetOption` accepts the documented timeouts, security flags, feature and
policy switches, the context value, the proxy information and the user agent,
records each, and refuses the rest with `ERROR_WINHTTP_INVALID_OPTION`.

`WinHttpAddRequestHeaders` applies the real modifier semantics to the request's
own header set — add, add-if-new (`ERROR_WINHTTP_HEADER_ALREADY_EXISTS` when
the header is present), replace, replace-with-empty-value to remove
(`ERROR_WINHTTP_HEADER_NOT_FOUND` when there is nothing to remove) and the
comma or semicolon coalesce — and `WinHttpSendRequest` transmits those headers
together with the ones passed to it.

Proxy discovery is answered honestly. `WinHttpGetIEProxyConfigForCurrentUser`
reports a direct connection: automatic detection off, and no script URL, proxy
or bypass list — so the caller has nothing to free, as the contract allows.
`WinHttpGetProxyForUrl` records the URL a sample wanted a route for and reports
`ERROR_WINHTTP_AUTODETECTION_FAILED`, because there is no WPAD server, DHCP
option or configuration script here to find. `InternetGetConnectedState`
reports a configured LAN connection, matching the modeled adapter, and
`InternetErrorDlg` reports `ERROR_SUCCESS` when told not to show a dialog and
`ERROR_CANCELLED` otherwise, since this profile has no interactive user. The
undecorated `wininet.HttpSendRequest` spelling a sample may import is bound to
the ANSI model.

### Controls

`m7_network_probe` adds ten generated x86/x64 controls, each deciding its own
outcome with guest breakpoints. Two new Probe helpers make the heap-returned
structures reachable: `indirect` copies a pointer-width field out of a
structure a model published at an address the control cannot predict, and
`indirect_dword` compares a word through such a pointer.

- **Adapter** turns a prefix length into a mask and refuses one past 32, learns
  the exact `IP_ADAPTER_INFO` size (648 or 704) from a null buffer, then reads
  back the interface index, type, physical address and the address, mask and
  gateway as the fixed-width text the structure carries, and confirms the lease
  times are zero. It then does the same for `FIXED_INFO`: the host name, the
  absent DNS suffix, the DNS server text, the hybrid node type and the
  routing/DNS switches.
- **Addresses** refuses an IPv6-only enumeration and an unmodeled flag set,
  learns the required size, then asserts the adapter's `Length`, index, MAC,
  MTU, type and operational status, that `FirstUnicastAddress` and
  `FirstDnsServerAddress` address the exact offsets inside its own buffer, the
  DHCP prefix origin and the on-link prefix length, and — through the interior
  pointers — that both `sockaddr_in`s carry the adapter's address and its DNS
  server.
- **Tables** walks all five MIB tables: the short-buffer size of `GetIfTable`
  (864) and then its row, the address row with its mask, the three sorted
  routes, the broadcast ARP entry, and the empty TCP table plus the refusal of
  an address family it does not model.
- **Icmp** opens a handle, pings loopback and asserts the entire reply —
  status, round-trip time, data size, the reply data pointer inside its own
  buffer, the TTL and the echoed payload — sees an unreachable peer time out,
  has a reply buffer too small refused, and confirms a closed handle cannot be
  closed twice. The engine-side test asserts the recorded destinations and that
  both payloads were captured.
- **Dns** resolves the machine's own name, walks the published record chain
  through its pointers (next, type and data length, the answer-section and
  character-set flags, the TTL and the address), compares the record's own name
  with `lstrcmpW`, frees the list, and confirms an absent name, a missing record
  type, an explicit server list and a non-null reserved argument each report
  their own status with nothing published.
- **Workstation** reads the workgroup join information and compares the name,
  frees the buffer and sees a second free refused, reads level 100 workstation
  information (platform 500, version 10.0, the computer and workgroup names),
  refuses an unsupported level, and records an account-creation attempt.
- **Redirector** records a share mapping with credentials, has a non-UNC remote
  name refused, confirms no enumeration handle is issued and that
  `WNetEnumResource` therefore reports an invalid handle, and distinguishes a
  real drive letter from a string that is not a device.
- **CrackUrl** cracks a full URL in pointer mode and asserts every component's
  pointer *into its own URL text* and length, then in buffer mode asserts the
  copied host with its terminator and poisoned tail, the short-buffer refusal
  with the required length, and the refusals of text that is not a URL and of a
  wrong structure size.
- **Options** checks the connected state and both error-dialog answers, opens a
  session, reads its handle type and user agent, reads a timeout default, sets
  it and reads the new value back, sees a short buffer learn its size, and
  confirms an option outside the profile is refused by both query and set.
- **WinHttp** cracks a wide URL, refuses one carrying credentials, reads the
  direct IE proxy configuration, sees proxy autodetection fail with the URL
  recorded, sets a documented option and has an undocumented one refused, and
  drives the header modifiers through add, add-if-new, replace and remove.

Unit tests cover the modeled structure sizes against the ones MSVC lays out,
the default adapter's geometry (including that it agrees with the Winsock
model's own `HOST_IP`), DNS name normalization and reverse-name order, the
`WKSTA_INFO`/`USER_INFO_1`/`NETRESOURCE` offsets, and the URL parser's
component split, default ports and refusals.

## Verification

| Gate | Result |
| --- | --- |
| Full source validation suite | passed; index under this qualification root |
| Strict workspace Clippy, all targets, warnings denied | passes |
| Canonical API partition check | 2,590 contracts over 151 batches, unchanged |
| Static inventory controls | passes |
| Native-PE accounting suite (`tests/test_native_pe_*.py`) | 179 tests, 0 failed |
| Re-measured partition surface for the five families | 634 modeled, 0 reviewed refusals, 0 unmodeled |
| Contained replay | 70 controls, independently checked against the packaged worker |

The replay set is the seven control families this milestone owns — `resource`
(4 cases), `crypto` (5), `path` (2), `com` (6), `security` (6), `socket` (2) and
`network` (10) — each emitted for x86 and x64. `tools/native_pe_m7.py` replays
every one through the packaged worker and the public CLI, reuses the M4
verifier for the request, result, input and cleanup accounting, and
additionally compares each report these families own (`com`, `shell`,
`security`, `services`, `lsa`, `sockets`, `adapters`, `icmp`, `dns`, `lanman`,
`http_config` and `network`) between the source-tested execution and its
contained replay, so an observation that differs under the packaged worker
fails the seal. `tests/test_native_pe_m7.py` guards the control set itself.

To recheck the sealed milestone from the repository root:

```powershell
C:\Python313\python.exe tools/native_pe_m7.py --root output/rust-pe-m7-complete-20261122 --source-index output/rust-pe-m7-complete-20261122/source-validation-final/index.json --check
```

Only a passing, independently checked current-source index establishes source
validation; missing or failed output is not proof. Existing M3 through M6
bundles and seals remain historical, matching their own source. This replay
covers the M7 obligations; it is not per-row semantic API parity, package
matrix qualification or M10.

## Limits

What this milestone does **not** establish:

1. All 634 contracts in these five families remain open in the ledger.
   Dispatcher coverage, guest controls over a family and per-row semantic
   evidence are not the same thing, and no row's evidence entry is claimed.
2. The network profile is offline by construction. Nothing resolves a name
   this guest does not already own, no socket connects, no ICMP packet leaves,
   no share is mapped and no proxy is discovered. Every one of those attempts
   is recorded with what the sample asked for, which is the point — but a
   sample whose next step depends on a real answer stops here rather than
   continuing against something invented.
3. One adapter, IPv4 only. `GetAdaptersAddresses` reports `ERROR_NO_DATA` for an
   IPv6-only enumeration, there is no anycast, multicast or WINS membership,
   and the ARP and TCP tables carry only what this profile can honestly know.
4. The DNS catalog is the machine's own identity. There is no persona field for
   extra records or for simulated ICMP peers, so a scenario that needs a
   resolvable command-and-control host or a replying peer is not expressible
   yet; the frozen Python model's `dns_records` and `icmp_responses` fixtures
   remain unported.
5. `WinHttpQueryOption` is outside this partition and is not modeled, so the
   WinHTTP option store is written and recorded but never read back by a guest;
   the WinINet store is read back by `InternetQueryOption`.
6. The `wininet` and `winhttp` transfer paths still require the explicit
   offline broker, and URL escaping and decoding flags remain explicit model
   stops rather than silent no-ops.
7. Service creation, account creation and share mapping are observed, not
   carried out: no service runs, no account exists afterwards, and no device is
   redirected. A sample that re-reads its own effect through an API outside
   these families may therefore disagree with what it was told.

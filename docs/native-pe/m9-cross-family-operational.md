# M9 cross-family operational controls

Started 2026-11-24 from committed M8 (`5ffa063` plus `aa9d026`). M9 is the
operational gate of the `M8-M11-qualification` batch: its exit test is
**cross-family x86/x64 programs**. Every milestone from M5 to M8 qualified its
API families one partition at a time — a registry control calls registry
exports, a crypto control calls crypto exports. None of them proved that two
families work in the *same* program, that a value one family produces survives
to be consumed by the next, or that their handles, scratch memory and import
thunks coexist in one image.

This milestone closes that gap with generated programs that each chain several
modeled families in a single contained execution and decide their own outcome
inline, in the M6/M7 style: every expected value is compared by guest
instructions, so a wrong answer raises a breakpoint inside the guest rather than
being handed back for a host assertion.

The controls are ordinary, harmless integration programs — reserve working
memory and write to it, read a staged file out of the owned filesystem, persist
and read back a registry value, hash a value, parse and render a network
address. None of them configures submitted-sample capture, so none produces a
memory-string report, a capture receipt or a carved artifact; that absence is
asserted, because the obligation here is family interoperation and not the M8
capture surface.

This milestone certifies no API partition row on its own, and the remaining
global qualification gates stay open until M10–M11.

## What this milestone closes

| Feature | Obligation | Status |
| --- | --- | --- |
| N19 | Cross-family x86/x64 programs through the public CLI and contained worker | closed for the three family chains below |
| N17 | Report extraction audited independently for these programs | closed as the seal-time report-field audit, reusing the M8 reviewed field set |

What it deliberately does **not** claim is in [Limits](#limits): no partition
row gains semantic closure from being exercised here.

## Why a chained program proves something a family control cannot

A single-family control resets the world for each call group it makes. A chained
program does not, so it is the first place these failures could surface:

- **Two import groups, two modules, one thunk array.** The provisioning and
  networking programs import from two modules at once (`kernel32.dll` with
  `advapi32.dll`, and `ws2_32.dll` with `kernel32.dll`). A call index numbers
  the exports across both groups, so a mis-placed null terminator between the
  groups would send a call to the wrong model.
- **A runtime pointer crossing a family boundary.** The networking program does
  not hand the network model a string from its own image. It reserves a buffer
  with `VirtualAlloc`, writes the address text into that reservation with
  `WriteProcessMemory`, and then has `inet_pton` parse the text *from the
  reservation*. The parse therefore consumes allocation-family output at an
  address the guest could not know when it was built.
- **One family's output as the next family's input.** The integrity program sets
  a registry value, reads it back, and feeds exactly those returned bytes to
  `CryptHashData`. The digest it checks is the MD5 of the four bytes the
  registry handed back, so the two families must agree on the same bytes for the
  control to pass.
- **Handles and scratch that must not collide.** A chained program holds a
  reservation, a process pseudo-handle, a file handle and a registry key handle
  in its own scratch at the same time, and the registry round trip runs after
  the file handle has been closed.

## The three programs

### Provisioning — allocation, filesystem, registry

Reserves a committed `PAGE_READWRITE` region, proves it is a real writable
reservation by copying sentinel bytes into it through `WriteProcessMemory`, then
opens the staged guest file `C:\emumee\m9-provision.bin` read-only, reads its
twelve bytes back into a poisoned buffer and checks them exactly, closes the
handle, and finally creates `HKCU\Software\EmumeeM9\Provisioning`, sets a
`REG_DWORD`, queries it back and checks the value, its type and its returned
size.

The file is **read, never written**. Staging it is also what makes its
`C:\emumee` directory exist — a guest cannot create a file in a directory the
owned filesystem does not have, and the submitted image is not seeded into the
filesystem. Reading a staged input retains no artifact, which is what keeps this
control capture free while still exercising the filesystem family.

### Integrity — registry, cryptography

Creates `HKCU\Software\EmumeeM9\Integrity`, sets a `REG_DWORD`, reads it back
and checks the value, type and size, then acquires an `PROV_RSA_FULL` context
with `CRYPT_VERIFYCONTEXT`, creates a `CALG_MD5` hash, feeds it the four bytes
the registry returned, reads `HP_HASHVAL` back and checks the digest against the
MD5 of those same bytes, then destroys the hash, releases the context and closes
the key.

Both families live in `advapi32.dll`, so this program is a single import group
whose cross-family content is entirely in the data flow.

### Networking — allocation, network address model

Reserves a region, writes the dotted address text into it, brings up Winsock
with `WSAStartup` and checks the negotiated version words, checks a `htons`
byte-order answer, has `inet_pton` parse the address **out of the reservation**
and checks the packed network-order result, renders it back with `inet_ntop` and
checks both the returned pointer and the rendered text, reads the persona host
name, and calls `WSACleanup`.

The network model is offline: `network.calls` stays zero, so the real host
network is never reached.

## Controls

Six contained controls, each emitted for x86 and x64:

| Control | Families chained | What it drives |
| --- | --- | --- |
| `operational-Provisioning` | allocation, filesystem, registry | A reservation written through `WriteProcessMemory`, a staged file read back and checked exactly, and a registry value set and queried — in one program, with the registry round trip after the file handle closed. |
| `operational-Integrity` | registry, cryptography | The MD5 the guest checks is computed over the exact bytes the registry query returned, so the two families must agree on those bytes. |
| `operational-Networking` | allocation, network | `inet_pton` parses the address text out of a guest reservation rather than the image, then `inet_ntop` renders it back; the persona host name and the Winsock version words are checked too. |

Every control returns 1 from its own entry, leaves no API event pending, reaches
no real network, and produces no artifact and no capture report. Each is emitted
as a contained fixture — image, staged input, arguments and limits — so the
packaged worker replays the same bytes through the public CLI.

## Qualification

| Gate | Result |
| --- | --- |
| Full source validation suite | passed; index under this qualification root |
| Strict workspace Clippy, all targets, warnings denied | passes |
| Native-PE accounting suite (`tests/test_native_pe_*.py`) | 185 tests, 0 failed |
| Workspace Rust tests | passes, including 538 `emumee-core` and 639 `emumee-engine` library tests |
| Contained replay | 6 controls, independently checked against the packaged worker |

`tools/native_pe_m9.py` replays every control through the packaged worker and
the public CLI, reuses the M4 verifier for the request, result, input and
cleanup accounting, applies the N17 report-field audit over the M8 reviewed
field set, requires the contained replay to reproduce the source-tested run's
exact report-field set, and asserts that no capture report or artifact exists.
`tests/test_native_pe_m9.py` guards the control set itself.

To recheck the sealed milestone from the repository root:

```powershell
C:\Python313\python.exe tools/native_pe_m9.py --root output/rust-pe-m9-complete-20261124 --source-index output/rust-pe-m9-complete-20261124/source-validation-final/index.json --check
```

Only a passing, independently checked current-source index establishes source
validation; missing or failed output is not proof. Existing M3 through M8
bundles and seals remain historical, matching their own source.

## Limits

What this milestone does **not** establish:

1. **No partition row gains semantic closure.** These programs call a handful of
   exports per family and check the answers they happen to use. Per-contract
   semantic parity for the 566 CRT/allocation/string rows, the 510
   registry/persona/filesystem rows and the 634 network/COM/crypto/security/
   resource rows remains exactly as open as it was after M7.
2. **Three chains, not a matrix.** The pairings exercised are
   allocation×filesystem×registry, registry×cryptography and
   allocation×network. COM, security, resources, the console, threads and
   processes are not chained with anything here, and no claim is made about
   pairings that were not run.
3. **The two-module ceiling.** The generated probe skeleton admits at most two
   import groups, so a single program cannot span more than two modules. The
   chains above reach three families only because `kernel32.dll` and
   `advapi32.dll` each host several. A chain needing three modules at once is
   not expressible without extending the skeleton.
4. **Single process, single thread.** No chained program creates a child, a
   thread or a callback, so cross-family interaction under the M4 scheduling
   surface is untested here.
5. **The filesystem family is exercised read-only.** A write would retain a
   `GuestFile` artifact, which is the M6 surface rather than this gate's; the
   reopen-after-close persistence of a guest-created file is not covered.
6. **Capture absence is asserted, not capture behavior.** These controls prove
   the operational chains need no capture configuration; the N14/N15 obligations
   keep their M8 qualification and are not re-established here.
7. **The N17 audit proves the report field set is reviewed and preserved.** It
   does not prove any individual family's field contents are semantically
   correct.
8. **The package/release matrix (M10) and the global gates with an independent
   audit of the full denominator (M11) remain open**, as does the remaining M8
   work its own Limits records.

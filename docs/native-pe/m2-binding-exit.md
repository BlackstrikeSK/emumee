# M2 input binding, resource bounds and rollback

## Contract

M2's fifth checkbox closes the trust boundary around the bounded submitted native
x86/x64 EXE/DLL route. This does not close M3 lifecycle fidelity, API semantic
parity, comprehensive M10 packaging or stable-release qualification.

The worker verifies the exact request hash before parsing. Every primary,
persona and fixed staged slot uses an identity-pinned, no-write/delete-sharing
regular-file read. Slot enumeration is bounded and must equal the declared
inventory; missing, substituted, swapped and extra slots refuse before execution.
The strict request binds sizes, hashes, kinds, guest paths, arguments, environment,
quoting, export selection, budgets, persona and clock seed. No host DLL lookup is
introduced. Captured bytes, not a producer's later pathname state, are authoritative.

The result contains the complete accepted request as `input_receipt`. The parent
compares it structurally, not merely a worker-provided hash. It rechecks request,
primary, every staged slot and persona after the worker stops, verifies identity,
containment, architecture, instruction ceiling, configured guest image/clock and
artifact hashes/metadata, and only then publishes `manifest.json`.

## Resource authorities

- Admission: 128 slots, 16 static companion DLLs, 32 MiB per staged file,
  128 MiB aggregate staged bytes, 128 MiB primary input and 512 MiB summed declared
  primary/static image sizes. Existing argument/environment/request bounds remain.
- The submitted engine's sole `AddressSpace` enforces 512 MiB aggregate live guest
  mappings, including image, dependency, heap and other modeled regions. Splitting
  permissions does not replenish capacity; actual unmapping does. Candidate clones
  retain the ceiling and attempts to enlarge it cannot weaken it. This is a guest
  mapping quota, not a claim about total host RSS.
- The existing User1024 job independently caps total worker process memory at
  1 GiB and active processes at one. AppContainer has no network capabilities.
  The controller records observed peak process memory and restored cleanup.
- Existing dynamic-loader authorities bound live DLLs to 32, aggregate raw bytes
  to 64 MiB, one image to 128 MiB, lifetime generations to 256 and routine/events
  to bounded collections. The new aggregate live-mapping ceiling also applies to
  dynamic images; it does not create a second module authority.
- Static dependency depth is eight. Module/export catalogs, loader events, VFS,
  capture/artifact totals, output bytes/entries/directories/depth, instruction and
  wall-clock horizons retain their existing independent bounds.

## Transaction and failure semantics

Host staging creates a new root and records only files/directories it owns. Any
staging write failure closes handles and removes these entries in reverse order,
using nonrecursive operations. Cleanup errors remain errors. An existing output
root is never overwritten or removed. Once launch begins, bounded error/stop/job
receipts are deliberately retained; a refusal is not a successful manifest.

VFS seed admission and static graph configuration build unpublished candidates.
Invalid paths, quotas, descriptors, duplicate dependencies, cycles or excessive
depth leave their original authority unchanged. Engine construction errors after
partial native mapping destroy the unpublished Unicorn instance and publish no
execution result. A later clean contained invocation must still succeed.

Dynamic preparation likewise builds candidate module/memory states. A failed
native map is terminal without publishing a candidate. A known-success native
map is recorded as actual state; subsequent native publication failure is
terminal rather than falsely reporting rollback. Existing failed-attach cleanup
retires only actually retired images. A native unmap/cache failure preserves the
actual surviving catalog and records terminal failure, never fabricated cleanup.

## Verification authorities

`user_input` tests mutate every request/receipt field, containment and execution
bound; persona presence/hash substitution is independently checked. Address-space
tests cover exact capacity, protection splits, atomic refusal, non-weakening
limits, candidate clones and capacity release in both architectures. CLI staging
tests inject failure after every created file, including an empty slot and persona,
then verify no partial root survives and an existing root is preserved.

Existing core static-count/depth/cycle and dynamic-reference/false-attach tests,
engine native-retirement failure controls and the complete workspace suite remain
mandatory. New submitted import fixtures exercise named, ordinal, shared mutable
data, named delay imports and DLL startup through explicit hashed
dependencies. EXE and DLL variants execute both architectures.

`user-binding-fixture` accepts only closed generated recipes, uses the ordinary
contained launcher/worker and production parent verifiers, and never publishes a
production manifest. It covers exact request/options binding, primary/slot/persona
substitution, swap/missing/extra slots, schema/quote/size/hash/path/quota/architecture
refusal, partial-load collision and parent option/artifact substitutions.

`tools/native_pe_m2.py` drives these controls and the public staged-import exit,
then independently validates job limits, measured peaks, containment, stop/error
receipts, exact input bytes/options and absence of successful publication on
refusal. The maintained staging seal separately qualifies all prior layout,
import, ABI and staging matrices against the same fresh release sources/binaries.
Final raw evidence, independent recheck, accounting and measured source-validation
receipts must be captured before the plan/worklist is marked complete.

## Reproduction

Use a fresh root; never overwrite prior failed or qualified evidence.

```powershell
$env:CARGO_NET_OFFLINE='true'
$env:RUST_TEST_THREADS='1'
$env:EMUMEE_USER_TEST_FIXTURES="$PWD\output\native-m2-next\fixtures-final"
.\tools\build_rust.ps1 -Validation -Test -Jobs 1
$env:EMUMEE_USER_TEST_FIXTURES=$null
.\tools\build_rust.ps1 -Lint -Jobs 1
.\tools\build_rust.ps1 -Release -Jobs 1
.\tools\package_rust.ps1 -Destination output/native-m2-next/bundle
.\tools\verify_rust_user_pe.ps1 -Bundle output/native-m2-next/bundle -Fixtures output/native-m2-next/fixtures-final -OutputRoot output/native-m2-next/qualification -Layout -Imports -Abi
python tools/native_pe_staging.py --bundle output/native-m2-next/bundle --fixtures output/native-m2-next/fixtures-final --output output/native-m2-next/staging
python tools/native_pe_m2.py --root output/native-m2-next
python tools/native_pe_staging_seal.py --root output/native-m2-next
python tools/native_pe_m2.py --root output/native-m2-next --seal
python tools/native_pe_m2.py --root output/native-m2-next --check
```

Dependency/registration reports and the preserved-history ledger must be refreshed
after source/tool changes. Dependency audit/check unsets both CARGO_NET_OFFLINE
and RUST_TEST_THREADS. Final full-source validation/check uses offline=true and
threads=1 after maintained source and documentation stabilize.

## Verified final outcome (2026-11-06)

All five M2 checkboxes and the bounded milestone exit are complete. The fresh
one-job release took 493.606s; freeze took 1.558s and strict all-target Clippy
26.819s. The serial workspace suite has 1,057 passing Rust tests. Final full-source
validation, accounting/inventory/partition/syntax/lint/whitespace receipts and
measured timings are in `output/rust-pe-m2-binding/final-validation/index.json`;
its independent check is mandatory and does not substitute for package evidence.

The fresh package passes 294 required outcomes: 120 prior contained cases and
28 refusals, 52 staging contained cases and 30 parent refusals, plus 64 new
controls (42 generated binding/rollback controls and 22 public staged EXE/DLL
import exits). The 42 include 34 required worker refusals, four parent verifier
rejections and four clean normal invocations, including recovery after refusals.
Both architectures execute named, ordinal, mutable data and named delay imports
with real explicitly staged dependencies; DLL startup also runs without any
companion. Frozen ordinal-delay refusal semantics remain tested rather than
silently broadening the baseline.

`qualified-smoke.json` independently binds 2,083 files; fingerprint
`20d0fb5f7f31a13b68d35aa133ae574cd2dc51ddbb158f9a2d68dbedcc91642c`.
`qualified-m2.json` binds 789 new-control files plus the prior seal hash;
fingerprint `01fdc837e098de620afec7d63668cb59df4fe2bdb358ee428e1f747023c5082d`.
Both seals pass independent repeat verification. Canonical build-source SHA-256:
`befbc76f4edbf71372056b2fdec5852f9e9ad3051556fc008fadf01f27a9ff2c`.
Exact controller/worker/Unicorn identities are in `bundle/rust-worker-build.json`.

Resolved development findings: explicit persona clocks take precedence over a
request seed; delay-only unused static companions correctly refuse, so the lazy
named-delay fixture establishes actual static ownership; standalone DLL startup
legitimately has no companions, so the seal requires exact empty inventories for
that case rather than an invented dependency. Failed source/fixture/seal captures
remain preserved, including `m2-seal.log`; subsequent successful seal/check logs
are authoritative. The failed delegated audit returned no findings; verification
was completed locally and is not represented as independent model review.

Fresh dependency integrity and registration audit/check receipts are in
`dependencies-complete/report.json`, `registration-complete/review.json` and
`audits-complete.json`. Fresh packaged dispatch and preserved-history final ledger
retain all 2,590 open semantic contracts, zero closures and no inventory loss.
The worklist closes only M2 and unlocks M3. No M2 blocker remains; M3 lifecycle,
API parity, comprehensive M10 and stable-release qualification remain separate
milestones, not qualifications implied by these results.

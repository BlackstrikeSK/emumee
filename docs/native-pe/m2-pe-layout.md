# M2 PE layout and mapping audit

## Objective and scope

Complete the first M2 checkbox: checked x86/x64 PE ranges, section overlap,
alignment, raw/virtual tails, placement, materialization and page protections.
This is not closure of companion staging, imports, ABI, loader lifecycle, all
of M2, any API semantic contract, M10 or stable-release qualification.

## Findings and implementation

- `rust/emumee-core/src/pe.rs` already bounds input to 128 MiB, images to
  512 MiB, PE header displacement, section count, optional-header reads, directory
  ranges and import traversal. It checks virtual section extents/overlaps using
  the larger of raw and virtual lengths, and distinguishes file-backed RVAs
  from virtual zero fill and unmapped image gaps.
- Missing checks now reject SizeOfImage inconsistent with SectionAlignment,
  SizeOfHeaders inconsistent with FileAlignment, and misaligned nonempty section
  file offsets. The first new regression failed on accepted header size 511
  before the fix. Existing bounded alignment support is otherwise unchanged.
- Raw source aliases, including header aliases, remain independent virtual
  copies, not shared writable mappings. Exact raw lengths remain supported,
  including lengths not divisible by FileAlignment. No rounding makes virtual
  zero fill available to file-backed metadata readers.
- Materialization now rechecks public metadata's image/header/section bounds,
  refuses zero or unaligned placement, checks address overflow and the x86
  address-space ceiling, uses fallible reservation, and bounds destination
  slices. Relocation-block RVA addition is checked instead of overflowing.
  Preferred and supported relocated high x64 addresses retain existing behavior.
- `map_image` materializes bytes as guest data. `protect_image` removes the
  temporary initialization permissions before guest startup, makes headers read
  only, applies section R/W/X bits and leaves gaps inaccessible. Actual CPU and
  AddressSpace permissions agree for every page of the audit image. No change
  to protection implementation was necessary; tests establish its behavior.
- A submitted image colliding with the runtime return mapping is refused before
  entry. No ambient DLL search, host image execution or new host access exists.

## Controls and observed regression

Six core tests in `rust/emumee-core/src/pe/tests.rs` cover both architectures:
malformed alignment/range/overlap mutations; independent raw aliases; exact raw
lengths 0/1/511/512; raw tails, zero fill and gaps; placement/overflow/relocation;
every input truncation and modified public materialization metadata.

Four engine tests in `rust/emumee-engine/src/pe_layout_tests.rs` compare CPU/model
permissions, run eight actual submitted guest programs per architecture, reject
three malformed layouts per architecture and refuse runtime address collisions.
Harmless source fixtures read raw tails/virtual zeros/aliases, write RW data,
attempt writes to RX text and read-only headers, execute NX data and read a gap.
Expected faults must occur rather than producing a successful entry return.

The first workspace run failed an existing managed-EH negative control because
an overly strict raw-length alignment check rejected its exact short backing.
That hypothesis was removed, not hidden by editing the managed test. Dedicated
exact-length controls now protect the preserved behavior. The next complete
workspace run passed 1,034 Rust tests. The interrupted PowerShell redirection
attempt is not a passing test: external capture avoids PS5 converting ordinary
native stderr into a terminating NativeCommandError.

`tools/verify_rust_user_pe.ps1 -Layout` adds the sixteen guest layout cases and
six parent-admission refusals to the existing smoke. Without the switch, the
original sixteen guest/four refusal contract remains unchanged. All cases bind
input hashes, require AppContainer/job/child-process/network restrictions and
successful cleanup, and reject malformed parent admission without run publication.

## Reproduction and evidence

Use fresh output paths and only generated harmless inputs:

```powershell
$env:CARGO_NET_OFFLINE='true'
$env:RUST_TEST_THREADS='1'
$env:EMUMEE_USER_TEST_FIXTURES="$PWD\output\native-layout-next\fixtures"
.\tools\build_rust.ps1 -Validation -Test -Package emumee-engine -TestFilter submitted -Jobs 2
$env:EMUMEE_USER_TEST_FIXTURES=$null
.\tools\build_rust.ps1 -Validation -Test -Jobs 2
.\tools\build_rust.ps1 -Release -Jobs 2
.\tools\package_rust.ps1 -Destination output/native-layout-next/bundle
.\tools\verify_rust_user_pe.ps1 -Bundle output/native-layout-next/bundle -Fixtures output/native-layout-next/fixtures -OutputRoot output/native-layout-next/qualification -Layout
python tools/native_pe_validation.py run --full --output output/native-layout-next/validation
```

The local continuation root is `output/rust-pe-m2-layout/`. Preserve failed and
superseded attempts. Current generated fixtures are `fixtures-final/`; final
workspace controls are `workspace-tests-final.json` and its hashed log. The
fresh bundle, `qualification/` records and independent `qualified-smoke.json`
seal bind exact binaries, both build-info results, canonical source fingerprint,
requests, input copies, results, containment and cleanup. Full current-source
validation is `final-validation/index.json`. Dependency and registration reports
are `dependencies/report.json` and `registration-final/review.json`; preserved
ledger/status are `final-ledger.json` and `final-status.json`.

The fresh release build (227.077s), freeze (1.072s) and expanded contained smoke
(5.708s) passed. All 32 guest records and ten refusals are verified; the independent
seal rechecked request/result/input bindings, both binaries and canonical source
hashes, and indexes 344 files. Its fingerprint is
`0c2fed85d31621a68d688dc5719a0549e396a4bfc3c318179f5cf5800ed8c002`.
Exact source/binary SHA-256 values:

| Item | SHA-256 |
| --- | --- |
| Build sources | `706327dc0e92a6be0d86c3c35a0eb0f4ff85cf7f5280b9eef99b5b79eb76e405` |
| Controller | `450c7199ab58b192994d823ad41d481f4d7756c840f0ab90a70c6419a8c35885` |
| Worker | `00b9b5bb60729a595a7eb9c13573fc7043cb8a570ceca4c7a6b0213188d47db3` |
| Unicorn | `f19546ed0d1b7ea0761768e9937334d4f6ba3a20eaed7c411655000b9154386e` |

The broad source snapshot changed during release compilation only because
maintained documentation was being updated. Packaging and the independent seal
verified that both compiled binaries match every current canonical build input;
the final full-source validation index is captured only after documentation stops
changing. The source-registration review was recaptured for the new runtime
scope, not carried forward under its old fingerprint. Its 2,590 dispositions and
fresh packaged dispatcher entries are unchanged; no semantic closure was added.

The sealed M0 package remains historical, not a current-source package after
these changes. Maintained findings and source controls are clone-safe; local
generated evidence is deliberately excluded from Git and must be recaptured
after cloning. Host protection settings and quarantined artifacts are unchanged.

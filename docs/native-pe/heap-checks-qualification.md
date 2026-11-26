# Guest heap validation and size qualification

The frozen hooks implement `HeapValidate` for `kernel32`, `kernelbase` and
`api-ms-win-core-heap-l1-1-0`, and `RtlSizeHeap` for `ntdll`. They accept
`HEAP_NO_SERIALIZE`, preserve last error and check live, readable heap bases.
A null pointer validates a known whole heap. `RtlSizeHeap` accepts a null heap
and returns all ones at guest pointer width when an allocation cannot be sized.

The previous release returned success for a live block protected with
`PAGE_NOACCESS`. The fix checks one byte of guest read access for both APIs.
A read-only allocation remains valid. The four failing x86/x64 controls are
preserved under `output/rust-pe-heap-checks-20261126/exploratory-before-fix/`.

The 2026-11-24 decision to retain tested Rust improvements applies to two
existing differences. Rust rejects queries against a different known heap,
while the frozen callbacks accept any known heap with a live tagged mapping.
Rust reports the requested block size. The frozen size hook reports the memory
manager's padded or page-rounded extent. The 33, 48 and 4097 byte controls
distinguish the models, including the extra 16-byte slot in the frozen 48-byte
case. The maintained policy and the specific comparison are part of each claim.

The proof exercises each named contract independently in both architectures.
Each of the 24 submitted PE controls has 14 calls covering positive, whole-heap,
null, wrong-heap, unknown-heap, invalid-flag, interior, non-heap, protected,
restored and freed cases. The checker repins the frozen source, regenerates each
guest, checks all 336 target-call arguments, return values and last errors,
and binds the reports to their contained request and exact release bundle.
The resulting proof qualifies eight intentional-change contracts under the
existing acceptance policy. It covers the bounded emulator heap model.

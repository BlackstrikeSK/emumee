# Expanded Windows string references and null-target reporting

The previous qualified runtime is preserved at
`output/rust-pe-interlocked-20261125/`: 228 closed, 2362 open of 2590,
1276 Rust tests, 253 accounting tests, five inventory tests, strict Clippy,
34 capture controls and a strict audit of 6007 semantic artifacts.

The next reference expands 428 historical synthetic observations into 1004
architecture/module-specific observations for 42 contracts. It
extracts source-pinned methods over bounded fake memory without importing the
legacy runtime. Scalar `CharUpperW` values and actual buffer addresses are
separate. Embedded Unicode pointers, null arguments and all four synthetic
read/write permission combinations are explicit. Five integrity tests check
reproduction, identity coverage, scalar/buffer behavior and pointer relocation.

An exploratory contained run passed its first 914 controls, then detected an
extra unsupported-operation report from `StrTrimW(NULL, ...)`. Review of the
remaining 48 controls found the same difference on both architectures and no
other difference in the checked results, error state, memory or unsupported
flag. The frozen handler returns zero immediately for a null target, without
reading the trim-character argument or adding a diagnostic. Rust now does the
same. This is a baseline correction, not an intentional departure from legacy.

The new direct Rust regression checks every one of the 1004 frozen observations,
including fake write-only pages. Windows `VirtualProtect` cannot represent
write-only pages; the corresponding 42 observations are direct source controls,
not invented submitted-route evidence. The other 962 generated PE callers use
real imports, native ABI arguments, guest assertions and a complete 64 KiB memory
artifact. The candidate checks request/result/artifact bindings, last error,
unsupported state, job limits and worker cleanup. Failed exploratory attempts
remain under `output/future-winstrings-20261125/`.

The qualification checker in `tools/native_pe_semantic_winstrings.py` regenerates
each guest from the frozen case and checks its actual named DLL or API-set
import, guest ABI, complete memory artifact and exact diagnostic list. The
diagnostic review maps frozen import-qualified messages to Rust's operation
names and distinguishes unreadable pointers from non-ASCII input. Tests reject
an incorrect diagnostic even when both reports mark the call unsupported.

The same release bytes from `output/rust-pe-winstrings-20261125/` were reused for
the proof integration because the Rust package source fingerprint was unchanged.
The existing 962 contained executions were independently rechecked in
`output/rust-pe-winstrings-proof-20261125/` against fresh source validation.
The seven semantic proof families publish atomically. The current ledger
qualifies 270 of 2590 contracts and leaves 2320 open. This batch covers the
frozen default-persona behavior and named submitted routes. The remaining
native contracts and global closure gates still apply.

Recheck the Windows-string seal from the repository root:

```powershell
$release = 'output/rust-pe-winstrings-proof-20261125'
python tools/native_pe_semantic_winstrings.py --root $release --source-index "$release/source-validation-final/index.json" --check
```

The current denominator is recorded in `audit/ledger.json`. The final
source receipt, semantic chain audit and release matrix are recorded beside
the per-family proof receipts.

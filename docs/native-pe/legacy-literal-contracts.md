# Frozen return-only legacy contracts

## Scope

The native port must preserve legacy placeholder behavior as well as stateful
models. This batch contains 156 architecture contracts for 78 named exports.
Every selected frozen body consists of one nonnegative integer or Boolean return,
with no parameter reads, memory writes, callbacks or state transitions. The
manifest is explicit and source-bound; it is never an unknown-API success policy.

| Module | Named exports |
| --- | ---: |
| gdi32 | 20 |
| kernel32 | 12 |
| mscoree | 1 |
| msi32 | 1 |
| msimg32 | 1 |
| msvfw32 | 1 |
| ntdll | 4 |
| sfc | 2 |
| user32 | 34 |
| winmm | 2 |

`rust/emumee-engine/src/api/legacy_literals.json` pins declaration identities,
argument counts, conventions, constants, body hashes and frozen source hashes.
`tools/native_pe_legacy_literals.py` independently parses every body and its
original decorator. It extracts only the reviewed import-miss normalization
method and runs that method against fake API lookups. No legacy engine imports,
PE execution or native Windows exports are involved in the oracle.

The original user-DLL miss rule folds one A/W suffix. The model preserves that
rule for these reviewed exports. NTDLL takes the original kernel-bridge branch
and does not inherit this rule. An exact frozen declaration cannot be displaced
by a miss alias. Existing stronger models and explicit refusals take precedence.
Void bodies, negative results, ordinal imports and nonliteral bodies stay outside
this batch and retain their existing dispositions.

## Runtime meaning

These are `verified_legacy_placeholder` candidates, not implementations of Windows
graphics, desktop, multimedia or installer services. The dispatch metadata marks
`legacy_placeholder=true`, and each successful call carries the
`frozen_legacy_placeholder` API-event effect. The named allowlist returns exactly
the frozen scalar and leaves error state and guest memory unchanged. Kernel-mode
invocation is refused; unknown names remain unsupported.

## Controls and qualification

There are 144 generated main programs: four-export groups, two architectures,
and three argument classes (zero, all-ones poison and valid arena pointers).
Every program fills and later extracts a complete 64 KiB canary arena, checks
pointer-width results and preserved last error, and calls the applicable A/W
aliases. Two additional programs resolve width aliases through GetProcAddress
without importing those aliases and invoke the returned guest pointers.

The independent verifier compares each API event and the complete arena hash
against the frozen body oracle. Negative controls reject modified returns,
argument lists, effect classifications and memory hashes; source controls also
cover unknown exports, explicit-refusal precedence and kernel authority.

`tools/native_pe_semantic_literals.py` publishes no claim before source validation,
contained replay, sealing and independent checking succeed. Proof filenames carry
the full runtime fingerprint so an archived claim cannot be overwritten by a new
qualification. The qualification root is
`output/rust-pe-legacy-literals-20261124/`; a missing or failed receipt is not proof.
The four earlier lstrlen contracts must be requalified against the same new
runtime before being carried forward. This requalification has now passed:
146 literal controls and 12 string controls passed contained execution and
independent sealing/checking against the current bundle. Maintained evidence
contains 156 verified legacy placeholders and four verified string models;
`audit/ledger-after-evidence.json` reports 160 closed and 2430 open contracts.
Initial and intermediate full source gates passed 1268 Rust tests, 219 accounting
tests and strict Clippy. Final post-publication receipts are
`source-validation-final/index.json` and `qualified-m8.json`; missing or failed
checks leave this batch incomplete. The full denominator remains 2590.

## Typed data accounting

The dispatcher now identifies `_acmdln` as noncallable mutable, aligned,
non-executable process-owned data, separately from the callable `__p__acmdln`
accessor. The ledger matches binding kind rather than forcing every data row to
`missing_binding`. Presence of a typed data model earns no semantic closure by
itself; the two data architecture contracts remain unverified until their own
independent proof is admitted.

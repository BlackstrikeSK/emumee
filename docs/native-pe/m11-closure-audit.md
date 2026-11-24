# M11 independent closure audit

Started 2026-11-24 from committed M10 (`25a3c9e`). M11 is the global gate of the
`M8-M11-qualification` batch. Its exit tests are **all required gates** and
**zero open or stale required contracts**, read against **an independent audit of
the full denominator**. This milestone is that audit.

## What an honest global gate can say here

The denominator is the frozen exact contract partition: 2590 contracts across 151
batches and 23 families. Every prior milestone states plainly that no partition
row has semantic closure, and the parity ledger confirms it exactly:

| Measure | Value |
| --- | ---: |
| Contracts in the denominator | 2590 |
| Open contracts | 2590 |
| — with a Rust model binding but no verified semantic evidence | 1899 |
| — unmodeled or explicitly unsupported | 691 |
| Contracts credited as closed | 0 |
| Required gates verified | 0 |
| Required gates stale | 1 (`effective_registration_review`) |
| Required gates unreviewed | 7 |
| Ledger `complete` | false |

An honest global gate over this evidence therefore **cannot report completion**,
and M11 does not. It would be a fabrication to flip `complete` to true, to mark
any contract closed, or to force a required gate to verified. What M11 certifies
instead is that the denominator **accounting** is reproducible, internally
consistent, tamper-evident, and credits nothing it has not earned.

This reading is the only one the evidence supports. The exit test "zero open or
stale required contracts" holds in the sense the audit can honestly establish —
**zero contracts are falsely closed** — while the count of genuinely open
contracts is reported in full rather than hidden. The model is not closed by this
milestone; the milestone program's own obligations are.

## What the audit does

`tools/native_pe_m11.py` performs five independent checks and then seals the
result:

1. **The denominator's left-hand side is intact.** The frozen legacy inventory is
   regenerated from source and must be byte-identical to the committed baseline
   `rust/api-parity/legacy-inventory.json` — 1320 declarations over 82 frozen
   source files, regenerated deterministically.
2. **The dispatcher is the same build the release matrix sealed.** The contract
   dispatch metadata is read from the M10 bundle's `emumee-rs.exe`
   (`inspect-api-surface`), so the audit and the M10 release matrix describe one
   build.
3. **The ledger is produced from those two inputs** by
   `native_api_parity_ledger.py`, giving the full-denominator status.
4. **A second opinion must agree.** The audit recomputes the completion status
   independently from the ledger's own entries and gates and requires it to match
   the ledger's self-report — `complete`, `open_contracts`, the semantic counts
   and the scope fingerprint. A ledger that disagreed with its own entries would
   fail here.
5. **The honesty invariant is asserted directly.** The denominator size must be
   exactly the frozen `contract_count`; the inventory and partition fingerprints
   must match the frozen partition; there must be no unreviewed inventory drift;
   the count of contracts credited as closed must be **zero**; and `complete`
   must be false with `open_contracts` equal to the contract count. An audit that
   reported otherwise against this evidence would itself be the failure.

The receipt `qualified-m11.json` binds the ledger fingerprint, the M10 release
matrix fingerprint and its `source_tree_sha256`, and the source index, so the
global gate is anchored to the same build as the release matrix. It records the
true state of every required gate and an explicit `honest_scope` statement.

## Qualification

| Gate | Result |
| --- | --- |
| Frozen inventory regenerates to the committed baseline | byte-identical |
| Denominator size and fingerprints match the frozen partition | 2590 contracts; inventory and partition fingerprints match |
| Independent completion recompute agrees with the ledger | agrees |
| Contracts falsely closed | 0 |
| Required gates reported in true state | 0 verified, 1 stale, 7 unreviewed |
| Strict workspace Clippy | passes (no Rust change in this milestone) |
| Native-PE accounting suite (`tests/test_native_pe_*.py`) | 194 tests, 0 failed |
| Same-build anchor | the M10 release-matrix fingerprint is bound into the receipt |

`tests/test_native_pe_m11.py` guards the honesty invariant (nothing credited as
closed, an all-open denominator never complete) and the audit's anchoring to a
bundle, matrix and index.

To recheck the sealed audit from the repository root:

```powershell
C:\Python313\python.exe tools/native_pe_m11.py --root output/rust-pe-m11-complete-20261124 --bundle output/rust-pe-m10-complete-20261124/bundle --matrix output/rust-pe-m10-complete-20261124/qualified-m10.json --source-index output/rust-pe-m10-complete-20261124/source-validation-final/index.json --check
```

## Limits

What this milestone does **not** establish:

1. **It closes nothing.** The 2590 contracts remain open and unreviewed after
   this audit exactly as before it. M11 reports the denominator; it does not
   qualify a single row of it.
2. **"All required gates" is reported, not satisfied.** Seven required gates are
   unreviewed and one is stale; the audit records this truthfully. A green global
   gate would require the per-contract semantic work the whole program has
   deferred.
3. **The batch stays open.** Because the denominator is open, the
   `M8-M11-qualification` batch is not marked closed: its milestone deliverables
   (M8 capture, M9 cross-family, M10 release matrix, M11 closure audit) are all
   in hand, but the model it audits is not complete.
4. **Semantic parity for every row, and a green `complete`, remain the standing
   future work** — the honest denominator the audit exists to keep visible.

# Interlocked transitions, accepted CRT data and semantic proof chains

This revision adds five guest-memory interlocked APIs (ten architecture
contracts), qualifies the accepted CRT command-line data/accessor departure
(four contracts), and strengthens the final semantic-evidence audit. The last
qualified runtime closed 214 of 2590 contracts. The current publication closes
228: 210 frozen placeholders, 14 models and four accepted intentional changes.
The unchanged denominator leaves 2362 contracts open. Final source and proof
checks below are required before this revision is qualified.

The interlocked reference extracts five source-pinned handler bodies over fake
memory without importing the legacy runtime. Its 378 observations distinguish
wrapping increment/decrement, masked exchange-add, full native-word comparison
and failed four-byte replacement conversion. Synthetic read/write denial
controls assert unchanged memory and error state; they do not claim exact
legacy exception text. The model uses the existing checked guest-write path,
executes the transition synchronously, and refuses kernel authority.

There are 133 submitted interlocked programs: 91 groups of frozen valid vectors,
40 overflow/access-denial programs, and two programs dynamically resolving all
five functions and their finite A/W aliases. Successful programs check return
width, intermediate words, preserved error state and a complete 64 KiB arena.
Error controls must stop at the actual target API without a normal guest return.

The CRT proof retains one mutable process-owned cell as accepted in
`behavior-decisions.md` and `behavior-decisions.json`. Frozen callback
observations demonstrate the fresh-cell departure. Sixteen existing submitted
controls check import/accessor/export identity, thread sharing, independent
children, long strings, lifetime ownership and actual CPU execution denial.
These four rows must use `verified_intentional_change`, with the accepted
decision and concrete expectations bound into the evidence.

M11 now traverses raw artifacts listed inside semantic receipts, checks exact
controller/worker/Unicorn bytes and current runtime/source identities, requires
the claimed contract in the proof, and invokes the registered independent
checker against the final source index. A proof file alone cannot hide changed
or missing raw output, another build, or another contract. Unknown proof
profiles fail closed. New negative tests cover these cases.

The qualification root is `output/rust-pe-interlocked-20261124/`. Focused runs
use `fixtures-focused`; only the fixed full source gate emits `fixtures-final`.
All six semantic families must be replayed and checked on one current bundle,
published atomically, and rechecked against the final source index. Required
capture and proof-chain checks remain mandatory. M10 and whole-port completion
remain open until every required contract and gate is qualified.

The fresh full gate at `source-validation-data-requalification-02/index.json`
passed 1276 Rust tests, 252 accounting tests, five inventory tests and strict
Clippy. All 377 contained semantic controls and 34 capture controls passed on
the current bundle. `evidence-publication-current.log` records atomic publication;
`audit/ledger-after-evidence.json` preserves prior history and reports 2121
represented bindings, 469 missing bindings and no inventory drift.

Inventory queries now include typed data bindings, so `_acmdln` is audited as
mutable, aligned, process-owned, nonexecutable storage rather than a function.
Controlled error programs correctly require CLI exit 1. Preserved interrupted
source runs and the earlier runner assertion remain under this root; neither
counts as passing evidence. The immutable fixture emitter was not weakened.

Required final receipts are `source-validation-final/index.json`,
`qualified-m8.json` and `strict-semantic-chain-check.json`. The final checker
rechecks every semantic family, nested raw artifact, contract identity and
exact release binary against the final source index. These receipts qualify
this revision only; full M10/M11 and all remaining APIs stay open.

The strict final check found that ledger gate invalidation mutated its in-memory
maintained evidence before fingerprinting it. The ledger now copies maintained
gates before invalidating them; a real CLI regression verifies both the stale
generated gate and the unchanged evidence-file fingerprint. The earlier final
source run passed, but its strict-chain attempt failed and remains preserved.
Current requalification is under `output/rust-pe-interlocked-20261125/`.
`preserved-raw-provenance.json` records byte-identical copies of the unchanged
release, fixtures and raw executions. All six proofs must be re-sealed against
the new accounting sources, published atomically and finally checked there.
The accounting suite now contains 253 tests. Required final receipt names stay
`source-validation-final/index.json`, `qualified-m8.json` and
`strict-semantic-chain-check.json` within that current root.

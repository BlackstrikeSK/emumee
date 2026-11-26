# M11 independent closure audit

The current audit also traverses semantic receipts' raw artifact records, binds
their contract identities and exact release bytes, and invokes the registered
independent proof checker. See `interlocked-crt-qualification.md`; earlier
receipts without these bindings must be refreshed before a current final audit.

## Current closure gate (2026-11-24)

The audit now accepts evidence-backed semantic progress and computes completion
from the full denominator. A completed accounting tool is not a completed port.
The required exit remains **zero open contracts and every required gate verified**.

The earlier audit hard-coded all 2590 contracts open, required `complete=false`,
and called the ledger's own completion function its independent recomputation.
That implementation could neither independently detect a completion-algorithm
error nor accept legitimate closed contracts. Its interpretation of "zero open"
as "zero falsely closed" did not satisfy the milestone exit test. The historical
receipt below is an accounting snapshot, not M11 completion.

`tools/native_pe_m11.py` now enforces:

1. Frozen inventory regeneration and exact partition identities, sizes and hashes.
2. Binding counts recomputed from every entry rather than merely summed.
3. A separately implemented completion calculation, compared with the ledger's
   counts, submitted-route counts, scope fingerprint and completion status.
4. Source/architecture-bound semantic evidence for every closed claim, plus
   nonempty proof artifacts checked for path containment, size and SHA-256.
5. A real same-build anchor: current source validation and bundle fingerprints,
   each existing M10 milestone seal, and the release matrix itself are checked.
   An audit check never creates a missing milestone seal.
6. Completion only when the denominator is closed, submitted routes are qualified,
   inventory has no unresolved entries and every required gate is current.

The schema-2 receipt reports actual open/closed counts, stale evidence and gate
states. Partial semantic closure is valid progress and does not imply global
completion. Tampered artifacts, duplicate contracts, stale evidence, missing
routes, unresolved inventory and stale or absent gates fail their applicable
checks. Tests include both a completely qualified synthetic denominator and
negative controls; neither a permanently-red gate nor fabricated green is valid.

## Semantic proof publication

The initial `kernel32.lstrlenA/W` qualification uses the immutable legacy string
corpus plus 580 additional observations from four AST-extracted frozen methods
running over bounded fake memory. No Speakeasy imports, PE loading or native
exports are needed for the oracle. It covers all narrow byte values, UTF-16
surrogates, odd and boundary addresses, unreadable/overflow/null pointers and the
32767-character limit. Twelve source-tested submitted-route controls check both
architectures' API results and last-error preservation, then retain the complete
64 KiB arena so its hash can be compared independently with the frozen oracle.

`tools/native_pe_semantic_strlen.py` replays and seals those controls before
publishing four maintained contract records. The proof binds the runtime
fingerprint, bundle, exact oracles and contained outputs. The final source index
validates the maintained records after publication. Proof filenames include the
complete runtime fingerprint, so a tooling/model revision cannot overwrite an
archived receipt. The synthetic CLI tests use their own evidence fixtures; real
maintained contracts must not leak into a synthetic denominator. This avoids a hash cycle between
an evidence file and a proof that would otherwise hash the same source index.

Qualification root: `output/rust-pe-semantic-closure-20261124/`. Only completed,
independently checked receipts at that root establish current qualification.
The complete API denominator remains the target; these tools do not waive any
unmodeled, stale or unreviewed contract.

## Historical all-open snapshot

The original receipt is
`output/rust-pe-m11-complete-20261124/qualified-m11.json`, anchored to the original
M10 bundle at `output/rust-pe-m10-complete-20261124/`. It reported:

| Measure | Historical value |
| --- | ---: |
| Contracts | 2590 |
| Open contracts | 2590 |
| Model-bound but semantically unverified | 1899 |
| Unmodeled or explicitly unsupported | 691 |
| Contracts credited closed | 0 |
| Required gates verified / stale / unreviewed | 0 / 1 / 7 |
| Complete | false |

Preserve that receipt with its exact source revision. It is superseded as a tool
contract by the schema-2 audit above and never established native-port completion.

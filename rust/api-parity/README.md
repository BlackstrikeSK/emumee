# Native API parity baseline

## Resumable completion accounting

The current forward plan is `.codex/plans/rust-pe-completion.md` (local).
Clone-safe scope and handoff live in `native-feature-matrix.md`,
`../../docs/native-pe/worklist.json`, `../../docs/native-pe/evidence.json` and
`native-session.md`. The exact API partition is `../../docs/native-pe/api-batches.json`.
M0 baseline and M1 source accounting are complete; M2's PE layout/mapping audit
is complete and request/staging remains active. The audit and controls are in
`../../docs/native-pe/m2-pe-layout.md`. Global semantic
and runtime qualification gates remain open. Bounded smoke and tooling completion
are not API behavioral or stable-release qualification.

Ledger schema 2 reads its existing output (or `--previous PATH`) before
regeneration. Module/export/kind/architecture identities preserve semantic and
submitted-route evidence when dependencies match. Source or binding changes
archive claims and mark them stale. Inventory additions/removals fail unless
reviewed using `--allow-inventory-change`; retired contracts remain in history.
Missing or changed frozen sources fail before writing. Atomic replacement
protects existing JSON evidence from interrupted publication.

Fingerprints conservatively cover Rust source/configuration/JSON fixtures,
lockfile, build/package/accounting tools and frozen legacy sources. Shared-state
changes therefore invalidate all consumers rather than retaining unsupported
claims. The partition supplies explicit family/foundation prerequisites; source
invalidation intentionally remains conservative across shared dependencies.

`docs/native-pe/evidence.json` holds sparse reviewed closures independently of
ignored generated output. Supply another file using `--evidence PATH`. Each
record carries identity, source fingerprint, semantic/submitted status and
behavioral evidence. Closed evidence requires architecture/source-bound test
IDs, oracle, baseline, structured limits and negative controls; intentional
changes also require an accepted deviation. Empty maintained evidence means no
qualified contracts. Do not place evidence metadata under `rust/`: it would
become its own runtime build/fingerprint dependency.

Binding, semantic and submitted-route status are separate. Data imports and
architectures have independent rows. Eight scope/registration/regression/safety/
package/operational gates require current scope-bound evidence. These checks
validate accounting structure, not the truth of supplied observations; reviewed
independent proof and retained raw-artifact indexes remain mandatory.

```powershell
python tools/audit_native_surface.py --output output/native-pe-session/native-surface.json
python tools/native_pe_batches.py --check
python tools/native_pe_status.py --ledger output/rust-pe-m1-index-inputs/current-ledger.json
python -m unittest discover -s tests -p 'test_native_pe_*.py' -v
python -m unittest discover -s tests -p test_native_api_inventory.py -v
```

Status hashes current sources without rebuilding and reports newly stale rows,
changed maintained evidence, remaining gates and dependency-ready batches.
Static audit preserves lexical install/hook sites and input/report fields; it
does not prove runtime activation. Neither tool imports the legacy pipeline or
executes a guest. Keep generated logs and full ledgers local.

## Exact API batches

The maintained partition assigns all 2,590 architecture-specific contracts to
151 bounded batches, exactly once. Stable membership IDs keep declared aliases,
ordinals, overlapping registrations and architecture pairs together. Reviewed
module/export policies separate shared-state families; unknown modules fail.
Every batch records source paths, shared state, an independent oracle strategy,
submitted-guest and negative-control obligations, prerequisites and exit tests.
Data imports require direct guest memory, ownership and lifetime controls rather
than function dispatch. These controls are planned obligations, not observations.
Native-facing CLR/MSI rows remain included and require explicit disposition.

`python tools/native_pe_batches.py` freezes the deterministic manifest; changes
to an existing partition fail unless explicitly reviewed with `--refresh`.
`--check` never writes. Ledger generation validates canonical policy and exact
coverage before publication; status binds the manifest fingerprint and refuses
old ledgers without partition metadata. Regenerate those ledgers, preserving
history with `--previous PATH`; do not bypass validation. Query the tools instead
of loading the large manifest into every session.

Status replaces the M5-M7 routing umbrella with real API batches and makes final
qualification depend on every batch. API closure is computed from current
validated semantic/submitted-route evidence for every member, never editable
progress flags. Missing, stale, blocked or unproved members keep a batch open.
Partition completion does not qualify any API. Source validation indexing and
affected-test selection are described below; runtime gates remain separate.

## Source validation receipts and affected suites

`tools/native_pe_validation.py` and `docs/native-pe/validation-policy.json`
provide a source-bound local index, conservative test selection and measured
command timing. The runner executes only the fixed safe suites: canonical
partition, native accounting controls, static inventory controls, Python syntax,
serial Rust validation-profile workspace tests, strict workspace Clippy and
diff whitespace checks. It never executes the legacy pipeline or submitted PEs.

```powershell
python tools/native_pe_validation.py plan --baseline output/rust-pe-m1-index/final/index.json
python tools/native_pe_validation.py run --full --output output/native-validation-next
python tools/native_pe_validation.py run --baseline output/rust-pe-m1-index/final/index.json --output output/native-validation-affected
python tools/native_pe_validation.py check --index output/rust-pe-m1-index/final/index.json
```

Use a new output directory for every run; existing evidence is never overwritten.
Source snapshots hash tracked and nonignored new files plus all frozen legacy
dependencies, retaining deletions. Missing baselines, policy/toolchain changes,
selector changes and unclassified files require the entire safe suite set.
Known accounting-only edits select all Python/partition controls; documentation
edits select whitespace. Rules are ordered and reviewed, not inferred from API
names. `--details` prints all changed paths/reasons; default output is bounded.
Explicitly supplied corrupt or unavailable artifacts are refused, never waived.

Each atomic `index.json` records source hashes, policy/environment fingerprints,
exact argv, exit codes, elapsed seconds and size/SHA-256 for every raw command
log. `--artifact repository/relative/path` adds a reference-only hashed artifact;
it does not promote old output into current qualification. Timeouts and interrupts
terminate/reap the command process tree and leave failed receipts. Source or
environment changes across a run prevent successful publication. `check` also
refuses missing/tampered logs, incomplete/failed receipts, mismatched commands and
stale sources/environment. The index checksum detects corruption, not provenance
or authenticity against an actor who can rewrite both logs and the index.

Only a successful run of every suite is a full baseline. A selected-only receipt
qualifies only those selected commands; use the latest full baseline for later
impact planning. A partial receipt cannot silently replace it. An unchanged full
baseline selects no tests; `--full` explicitly reruns everything. Toolchain versions,
test/build environment fingerprints and timings are retained; build values are
hashed rather than copying possible credentials. No performance threshold or
release/API qualification is inferred. Missing local output after a clone remains
missing proof: regenerate a full baseline instead of claiming prior success.

## Package availability

Package prerequisites and failures are classified in
`../../docs/native-pe/baseline-failures.md`, with explicit owners and release
actions. The dependency audit retains a read-only shell capability probe and
refuses missing/failed/malformed results; `pwsh` presence alone is not proof.
The helper now supports PowerShell 5 with equivalent digest/encoding behavior.
The exact fresh bundle passed bounded M0 smoke; see
`../../docs/native-pe/m0-package-smoke.md`. Static integrity and source validation
never clear a security incident; full semantic/M10 qualification remains open.

## Effective registrations

`tools/native_pe_registration.py audit --output output/native-registration-next/report.json`
and `check --report` provide the source-only M0 N18/N20 review. The maintained
findings and reproduction instructions are in
`docs/native-pe/effective-registration-review.md`; reviewed dispatch authorities
are pinned in `docs/native-pe/registration-policy.json`. The collector never imports
legacy modules or executes constructors/callbacks. It preserves the full 2,590-row
denominator, ordered hook chains, baseline/data/ordinal resolution, constructor
state expressions, original-handler delegation references and pre/post-load phases.
Do not infer single-hook override semantics: supported baseline APIs execute all
matching hooks; unsupported ones use only the final matching hook. Exact buckets
precede wildcard buckets. Review completion is not semantic or package completion.

## Static dependency baseline

Use the development Python, not the legacy virtual environment's interpreter:

```powershell
python tools/native_pe_baseline.py audit --output output/native-dependencies-next/report.json
python tools/native_pe_baseline.py check --report output/native-dependencies-next/report.json
```

The audit reads the 82 frozen legacy source hashes, installed Python METADATA
and RECORD files, active PEP 508 requirements (including transitive extras), and
Cargo.lock-selected offline registry archives and unpacked source bytes. It does
not import legacy code, extract archives, download packages, install dependencies,
execute submitted/native samples, restore quarantine or change security settings.
Only trusted development-tool version probes and locked offline Cargo metadata
resolution run. Configured rustc wrappers require review before metadata probing.
The requirement parser comes from system pip, never the legacy environment.

Reports hash repository source, parser/tool identities, virtualenv configuration,
installed files and locked archives/sources. `check` repeats the audit and refuses
stale or corrupt payloads and forged summary claims. Missing files, mismatched
bytes, unsafe paths, unrecorded sources, duplicate identities, incompatible/missing
requirements, unsupported direct URLs and archive link/special entries fail closed.
Unhashed RECORD self-rows and bytecode caches, and Cargo-generated extraction
metadata, are explicitly separate from verified dependency source bytes. Hashes
are point-in-time consistency evidence, not independent authenticity or a security
clearance. Keep the environment quiescent while auditing; later edits require a
fresh check. Individual hashes reject files modified during their read, and source
changes during collection prevent integrity success.

`integrity_verified`, `source_build_prerequisites_present` and
`packaging_prerequisites_present` are independent. Missing modern PowerShell is
recorded as a packaging prerequisite; it does not invalidate matching source bytes
or silently qualify a package. Local libclang, Ninja, MSVC and SDK header identities
are recorded alongside Cargo/rustc/Python/shell versions. Tool existence and hashes
are not a successful source build. The validation runner includes all baseline
controls in its accounting suite and selects all safe suites when this verifier
changes. Attach its final report with validation `--artifact` to bind the evidence.

## Frozen legacy declarations

`legacy-inventory.json` freezes installed Speakeasy user-mode declarations and
the static relative-import closure of `src/emumee/native.py`. It retains source
hashes, argument conventions, aliases, data imports, conditional registrations,
and narrowly identified literal placeholder bodies. `queries.json` is its
function-export query set. Neither file establishes semantic parity.

Generate the current dispatcher comparison without executing a guest:

```powershell
.\.venv\Scripts\python.exe tools\inventory_native_api.py --output rust\api-parity\legacy-inventory.json
.\target\debug\emumee-rs.exe inspect-api-surface rust\api-parity\queries.json > output\native-api-parity\rust-dispatch-current.json
.\.venv\Scripts\python.exe tools\native_api_parity_ledger.py --inventory rust\api-parity\legacy-inventory.json --dispatch output\native-api-parity\rust-dispatch-current.json --output output\native-api-parity\ledger.json
```

Baseline changes fail unless deliberately refreshed with `--refresh-baseline`.
Review legacy source changes before using that option. Missing static sites,
data dependencies, dynamic import normalization, architecture-specific export
behavior, runtime restrictions and conditional hooks still require explicit
review. A dispatcher model is a binding, not a verified behavioral contract.

`tools/reference_native_strings.py` captures trusted Python string handlers over
synthetic byte arrays. It executes no PE, guest instructions or native export.
The Rust differential corpus is `emumee-engine/src/api/winstrings_reference.json`;
its test verifies the Python source hash, results, last-error state, complete
synthetic memory hashes and unsupported markers. Native x86/x64 PE controls
separately verify actual import marshalling and buffer effects.

Full parity remains incomplete. User PEB/TEB/loader-list and static TLS state,
general process/thread scheduling, remaining CRT, security, resource, socket,
UI/COM and other legacy API families, alias/data imports and final contained
bundle qualification remain open. The ledger must retain these gaps.

# Effective native registration review

## Scope and reproduction

The M0 N18/N20 source review is implemented by
`tools/native_pe_registration.py`. It parses source only: no legacy imports,
constructors, callbacks, guest/native samples, installation, network access,
quarantine recovery or security-setting changes. The reviewed condition is
successful initialization of the existing configured `run_native` route.
An exception exposes only the completed registration prefix, not the final map.
Registration availability is not successful guest dispatch or API semantics.

```powershell
python tools/native_pe_registration.py audit --output output/native-registration-next/report.json
python tools/native_pe_registration.py check --report output/native-registration-next/report.json
```

Use a new audit destination. `check` recomputes the complete map and rejects
payload/summary corruption, source drift and stale reports. The maintained
`registration-policy.json` pins the frozen inventory and the seven additional
dispatch/normalization authorities, including the kernel declaration file used
only by ntdll normalization. Those dependencies also enter the common runtime
fingerprint and validation source index; an ignored virtualenv source change
cannot silently preserve a prior receipt. Kernel fallback declarations do not
expand the frozen user-mode contract denominator.

## Findings

- Both x86 and x64 install **24 bridge objects and 514 API hooks**. Of those,
  493 hooks are queued before the main `se.load_module` call and flushed by lazy
  engine initialization; 21 module-enumeration/toolhelp hooks are added after
  successful loading. The report retains both module-load and final maps.
- All **2,590 frozen architecture contracts** have final dispositions: 1,504
  baseline-only, 596 baseline-with-hooks, 472 last-hook-only, two data-handler
  slots and 16 without a registered handler or hook. None is semantic closure.
- Baseline construction examines `dir(self)`, which is sorted by Python attribute
  name, not source declaration order. Of 806 inventoried declarations, 798 retain
  their selected metadata, two are shadowed by later methods with the same Python
  name (`msvcrt._wcsicmp` and `_crt_atexit`), and six stacked A/W decorators have
  their metadata overwritten by the outer decorator. Outer `apihook` metadata
  and function-before-data precedence are reflected in the selected tables.
- Function and data export tables are distinct and case-sensitive. Ordinal
  aliases target the same baseline function tuple. A successful ordinal lookup
  rewrites hook lookup to the baseline's declared name; a hook on `ordinal_N`
  alone does not override an already resolved named baseline function.
- Hook names and modules are lowercased. Exact module/API buckets precede
  insertion-ordered wildcard buckets. This can differ from global FIFO order;
  ordering within each bucket remains FIFO. With a baseline function, **every
  matched hook runs**, and the last matched return is retained. Each `original`
  points to the baseline function, not the preceding hook. Without a baseline,
  **only the last matched hook runs**, `original` is `None`, and that hook supplies
  argument count/convention. No registration means signature lookup/unsupported
  handling remains separate; it is not a modeled API success.
- A/W generic resolution, CRT/API-set/socket module folding and ntdll-to-kernel
  Nt/Zw fallback follow the pinned source. Normalization selects the baseline;
  it does not redirect the requested module/name for ordinary hook lookup.
- `run_native` conditionally inserts an `ntdll.LdrUnloadDll` baseline tuple after
  loading if the handler exists and that key is absent. Its literal fallback is
  `STATUS_NOT_SUPPORTED`; the preinstalled hook then uses supported-handler
  dispatch rather than the unsupported-hook path. The report records this guard,
  fallback identity and before/after dispatch change, not just the assignment.
- The `??3@YAXPEAX@Z` delete decoration is registered on **both architectures**.
  Its comment describes x64 decoration, not an x64 registration guard. Neither
  architecture is silently removed from the contract denominator.
- `mscoree.CorExitProcess`, `msi32.MsiDatabaseMergeA` and its ordinal 29 alias are
  literal-zero baseline placeholders on both architectures: six contracts.
  This establishes neither process-exit behavior nor a general CLR/MSI model.
- The inventory's character-width expansion also generated doubled suffixes
  (`GetModuleBaseNameAA/AW/WA/WW` and `GetModuleFileNameExAA/AW/WA/WW`). These
  account for the 16 no-registration contracts. Preserve them pending an explicit
  denominator/semantic disposition; do not label them implemented or drop them.

## Evidence and controls

The report includes ordered installation and hook sites, constructor call/state
expressions and guards, selected/shadowed declaration identities, callback body
fingerprints, direct original calls/forwarding/guards, effective ABI metadata,
ordinal/alias resolution and one disposition per frozen architecture contract.
Constructor expressions are source evidence, not observed runtime memory.
The current installers have no conditional API registrations; the conditional
table mutation above is explicitly modeled. Unknown guards, dynamic/unbounded
registration loops, nested runtime registrations and unreviewed exception paths
are refused instead of guessed. Resolved early returns stop installer collection.

The 43 dedicated controls cover ordering, exact/wildcard precedence, both dispatch
paths, original delegation, ABI provenance, data/ordinal separation, aliases,
architecture/pointer guards, early return/refusal, Python/decorator shadowing,
constructor nonexecution, path/source drift, report corruption and the live frozen
scope. They are included in the accounting suite. Changes to the collector/policy
select every safe validation suite. The maintained `effective_registration_review`
gate records this source-only review and its exact contract-scope fingerprint;
scope drift makes it stale. No API semantics or other qualification gate is
promoted. The maintained review/policy/controls are the clone-safe evidence;
the local generated map is a reproducible detail capture, not sole proof.

Current local report: `output/rust-pe-m2-layout/registration-final/review.json`.
Full safe-source receipt: `output/rust-pe-m2-layout/final-validation/index.json`.
Dependency recheck and preserved-history ledger/status are under the same output
root. Missing local artifacts after a clone require fresh captures; the maintained
policy, findings and controls remain usable without them.

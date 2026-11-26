# Frozen void placeholder contracts

This batch covers 18 architecture contracts for nine missing named exports:
`comctl32!InitCommonControls`, `user32!PostQuitMessage`, and kernel32's
`InitializeSRWLock`, shared/exclusive acquire/release, `WakeAllConditionVariable`
and `RtlUnwind`. Their frozen bodies contain only a void return after docstrings.
They do not implement Windows locking, unwinding or message-queue operations.

The explicit `legacy_voids.json` manifest binds both architectures to frozen
declarations, source hashes, body hashes, argument counts and conventions.
`native_pe_legacy_voids.py` independently parses the declarations and original
A/W miss rule. It also extracts only the pinned `do_call_return` and
`clean_stack_args` methods from the frozen CPU bookkeeping source. Fake registers
produce 54 observations covering architectures, argument counts, seeded return
registers, void returns and scalar overwrite controls. No legacy emulator,
submitted PE or native Windows export executes in this oracle.

A void return preserves EAX/RAX rather than replacing it with zero. The new model
therefore uses `ReturnType::Void`, records a null API result, and leaves memory
and last error unchanged. The existing user-placeholder guard refuses kernel
authority. Existing stronger models and explicit refusals win before the finite
void allowlist. Unknown names and repeated width suffixes remain unsupported.

There are 24 grouped submitted controls covering zero, poisoned and valid-arena
arguments on both architectures. Each sets the return register after argument
marshalling, calls actual IAT gates, checks the full register and last error, and
extracts a complete preserved 64 KiB canary arena. Two more programs resolve A/W
aliases dynamically and preserve all return-register bits through indirect calls.
An altered scalar result, argument list, error state, arena hash or failed guest
assertion cannot pass the independent verifier.

The evidence root is `output/rust-pe-void-20261124-02/`. Required receipts are a full
source index, current bundle, all 26 contained controls and the independently
checked `qualified-semantic-voids-<runtime-fingerprint>.json` proof. Earlier
literal and string proofs must also be refreshed against this revision, together
with the separate 36-contract local-constant batch described in
`legacy-local-constant-contracts.md`.
Prepared or source-tested candidates alone close no contracts.

`native_pe_semantic_evidence.py` collects claims from all four qualifiers only
after each independently checks its proof and current source gate. It validates
identities and evidence, rejects overlapping families, then atomically publishes
one maintained document. A later proof failure leaves the old evidence unchanged.
This avoids invalidating the source index between sequential family publications.
Final source validation must include the resulting maintained evidence.

The full denominator remains 2590. The four current proofs and 228 semantic contained controls passed and were
published atomically: 214 contracts, including these 18 void placeholders. The
initial full source gate passed 1271 Rust and 235 accounting tests plus strict
Clippy. Final source and M8 receipts must still pass checking. Data, stateful APIs,
remaining aliases and ordinals retain their unresolved dispositions.

# Frozen handlers with local constant returns

This explicit batch contains 36 architecture contracts for 18 missing exports:
13 user32 exports, three kernel32 exports, and one each in comctl32 and msvfw32.
These handlers only unpack their argument list, assign integer or Boolean
constants to local variables and return a constant. They do not read or write
guest memory, invoke callbacks, access emulator state or perform Windows work.

`legacy_locals.json` binds declarations, argument counts, conventions, values,
body hashes and frozen source hashes. `native_pe_legacy_locals.py` independently
proves a finite AST grammar. Before the terminal return, it admits only exact
argument unpacking and assignments of integer/Boolean literals to local names.
It rejects calls, attributes, subscripts, branches, early returns, changed argv,
unknown returned arguments and unpacking with a different arity. Nothing from
the handlers executes. The separately pinned original normalizer proves the
reviewed finite A/W miss aliases and rejects exact-declaration collisions.

The compiled scalar-placeholder allowlist includes these explicit rows alongside
the earlier 156 return-only rows. Stronger models and explicit refusals retain
precedence; unknown imports never receive a success fallback. The shared guard
refuses kernel authority. Dispatch metadata and API events mark these as frozen
legacy placeholders rather than claim Windows functionality.

There are 42 grouped submitted programs: seven four-export groups, both
architectures and zero/poison/valid-arena arguments. Each checks pointer-width
results, preserved last error and a complete 64 KiB canary arena. Two more
programs dynamically resolve and invoke InitCommonControlsExA/W without static
alias imports. Seven Python tests cover the oracle and independent observation
checker, including mutations that must fail.

Qualification shares `output/rust-pe-void-20261124-02/` with the 18 void contracts.
The required proof is `qualified-semantic-locals-<runtime-fingerprint>.json`.
All four semantic families passed contained replay, sealing and independent
checking, and 214 claims were published atomically. Initial full source validation
passed 1271 Rust tests, 235 accounting tests and strict Clippy. Final source and
M8 receipts must pass checking before this batch is complete. The denominator
remains 2590, with 2376 open; missing receipts, source-only checks and dispatcher
presence close no row.

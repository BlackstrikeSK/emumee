# Accepted native behavior policy

On 2026-11-24 the user selected **Keep documented Rust improvements** in response
to the concrete CRT command-line cell comparison. Retain existing tested Rust
improvements and qualify each documented departure as an intentional change.
This acceptance does not establish parity or close a contract without evidence.
Unsupported required behavior and unverified routes remain open.

The demonstrated decision retains one mutable CRT command-line cell per logical
process, shared by imports, export lookup, accessors and threads. Frozen legacy
allocates a new cell on each accessor call. Current Rust also retains its tested
process isolation, storage ownership, mutability and non-executable data model.
These expectations must be checked independently and through contained guests.

The reviewed comparison and actual two-architecture release controls are at
`output/rust-pe-void-20261124-02/crt-cell-review/`. Its `accepted-decision.json`
records the user's exact selection. A claim using this decision must identify
the specific departure, retain its baseline observations and negative controls,
and use `verified_intentional_change` rather than claim exact legacy equivalence.

# Contributing

Emumee's active build is Rust. Changes must preserve the boundary between
guest execution and the host: submitted guest bytes run only in a confined
worker, and tests use harmless generated fixtures.

## Development setup

1. Use Windows 11 with Rust 1.85 or newer, MSVC Build Tools, the Windows SDK,
   CMake, Ninja, and libclang.
2. Run `./setup.ps1` from PowerShell to build and package the Rust workspace.
3. Run focused tests with `cargo test --locked -p emumee-core` and
   `./tools/build_rust.ps1 -Test -Package emumee-engine` as appropriate.
4. Rebuild with `./build.ps1` before testing packaged worker behavior.

For changes to isolation, input parsing, or guest process launching, include a
small harmless fixture that exercises the behavior and a packaged AppContainer
check. Record unmodeled behavior as a partial result. The Rust CLI still
rejects general `run`; do not represent closed fixtures as arbitrary PE
execution. Historical Python coverage is in
[COVERAGE_AND_SAFETY.md](COVERAGE_AND_SAFETY.md).

Do not commit live malware, collected run outputs, local credentials, or generated
build artifacts. Python fixture tools may remain useful during the migration,
but the active launcher and release bundle must not call the Python runtime.

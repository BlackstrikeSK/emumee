# Contributing

Emumee is a Windows user-mode malware analysis project. Changes should preserve
the boundary between guest execution and the host: guest PE code runs only in
the isolated worker, and tests should use harmless generated fixtures.

## Development setup

1. Use Windows 11 with Python 3.11 or newer.
2. Run `./setup.ps1` from PowerShell to install dependencies and build the worker.
3. Regenerate native fixtures with `.venv/Scripts/python.exe tests/fixtures/build_native.py`.
4. Run `.venv/Scripts/python.exe -m unittest discover -s tests -p 'test_*.py'`.
5. Rebuild with `./build.ps1` before testing packaged behavior.

For changes to isolation, input parsing, or guest process launching, include a
small harmless fixture that exercises the behavior and a packaged AppContainer
check. Record any unmodeled behavior as a partial result rather than claiming
general Windows compatibility. See [COVERAGE_AND_SAFETY.md](COVERAGE_AND_SAFETY.md)
for the existing verification approach.

Do not commit live malware, collected run outputs, local credentials, or generated
build artifacts. The fixture generator produces the PE binaries needed by tests.

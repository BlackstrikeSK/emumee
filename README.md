# Emumee

Emumee is an experimental Rust binary-analysis runtime. The active Windows
launcher and portable bundle use `emumee-rs` and a separately packaged worker.
The worker runs under AppContainer and a job object. A bounded Linux ELF worker
is also available on x86-64 Linux hosts that pass its namespace, capability,
and seccomp checks.

## Current scope

| Command | Current behavior |
| --- | --- |
| `persona` | Print the default modeled Windows identity. |
| `inspect PATH [--details]` | Read-only PE or ELF metadata inspection. |
| `inspect-msi PATH`, `inspect-managed PATH` | Bounded read-only format inspection. |
| `linux-elf SOURCE_ELF FRESH_OUTPUT_DIR [--library SONAME=PATH]` | Execute the admitted static, PIE, and staged shared-object ELF profiles in a confined worker. |
| `submitted-driver SOURCE_SYS FRESH_OUTPUT_DIR --service NAME` | Bounded Windows driver diagnostics in the offline worker. |
| `fixture`, `analysis-fixture`, and other verifier commands | Closed generated cases for development and containment checks. |
| `run`, `batch`, `dashboard`, `powershell` | General product workflows are not yet implemented in Rust. `run` fails explicitly; the launcher never falls back to Python. |

The Rust runtime is not yet a general PE emulator or a replacement for every
workflow in the former Python application. General `run` is the next migration
milestone. The [legacy Python documentation](docs/legacy-python.md) records
earlier behavior but does not describe the active launcher.

## Build and launch on Windows

Use Windows 11, Rust 1.85 or newer, MSVC Build Tools, the Windows SDK, CMake,
Ninja, and libclang. Set `LIBCLANG_PATH` if libclang is not discoverable. The
build helper also recognizes locally provisioned dependencies under
`output/rust-toolchain/`.

```powershell
.\setup.ps1
.\emumee.ps1 persona
.\emumee.ps1 inspect .\sample.exe --details
.\emumee.ps1 inspect-msi .\installer.msi
```

`setup.ps1` builds the release Rust workspace and packages a matching
controller, worker, and Unicorn library. After source changes, run
`.\build.ps1`. Each build creates a new immutable bundle under `dist/` and
updates `dist/current-rust-bundle.txt` only after the package fingerprint
checks pass. `emumee.ps1` launches that bundle and checks the controller hash
against its receipt. No Python virtual environment or PyInstaller build is
used by the active path.

For direct development checks, use `tools/build_rust.ps1` and
`tools/package_rust.ps1`. The package receipt binds the source and three
binaries; it does not certify broad guest compatibility.

## Linux ELF profiles

`linux-elf` admits bounded x86-64 static executables and PIE, i386 static
executables and dependency-free dynamic PIE, and x86-64 executables with up to
four directly staged shared objects (8 MiB each). The shared profile handles
bounded `RELA`, `JUMP_SLOT`, `GLOB_DAT`, and initial-thread TLS `TPOFF64`
relocations. Guest dependency names resolve only against staged, hashed bytes,
never host library paths. Transitive dependencies, constructors, glibc startup,
i386 TLS, dynamic TLS allocation, and broad Linux syscall compatibility remain
unsupported.

On a supported x86-64 Linux host, package a matching controller, worker, and
Unicorn library into a fresh directory:

```bash
LIBCLANG_PATH=/usr/lib/llvm-18/lib bash tools/package_rust_linux.sh /absolute/fresh/bundle --release
LD_LIBRARY_PATH=/absolute/fresh/bundle /absolute/fresh/bundle/emumee-rs linux-elf sample.elf /absolute/fresh/run
```

The native worker requires user, mount, network, and IPC namespaces, a confined
root, dropped capabilities, no-new-privileges, resource limits, and seccomp.
It rejects execution if those controls are unavailable. WSL Ubuntu is the
qualified Linux host; other distributions are not yet qualified. See
[issue #1](https://github.com/BlackstrikeSK/emumee/issues/1) for the completed
bounded milestone and its evidence.

## Security and development

Treat unknown inputs as hostile and use a disposable analysis machine. See
[SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md). The legacy
Python sources and historical tests remain in the repository as migration
references; they are not invoked by `setup.ps1`, `build.ps1`, or `emumee.ps1`.
Emumee is licensed under [MIT](LICENSE).

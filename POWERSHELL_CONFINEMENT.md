# PowerShell confinement and command capture

Emumee has an experimental `powershell` command for supplied `.ps1` files.
It runs PowerShell 7.5.12 inside Docker Desktop's Linux VM using the pinned,
instrumented engine, guest Windows enumeration tools, and an external
native-process observer. It does not run host `powershell.exe` or `pwsh.exe`.
The PE worker's `CreateProcess` path still
rejects managed child PEs; it does not route PowerShell into this separate mode.

## Supplied scripts

Build the observer and instrumented engine using the commands in the
instrumented-engine section below. Docker Desktop must be running its Linux
backend, with the pinned SDK image already pulled. Build the Windows utility
bridge from trusted project sources and a local wheel:

```powershell
.\tools\build_powershell_guest_tool_shim.ps1
.venv\Scripts\python.exe -m pip wheel . --no-deps --no-build-isolation --wheel-dir output\powershell-guest-tools\wheel
.venv\Scripts\python.exe -m tools.build_powershell_guest_tools `
  --wheel output\powershell-guest-tools\wheel\emumee-0.1.0-py3-none-any.whl `
  --shim output\powershell-guest-tools\shim `
  --output output\powershell-guest-tools\build.json
```

This explicit build stage downloads Debian Python/venv packages and pinned
Python dependencies. Its context contains only the wheel, shim, requirements,
bootstrap, and Dockerfile. Submitted scripts and personas do not enter the
image. The build manifest records the image ID, input hashes, utility list,
and installed dependency versions. Runtime verifies its image labels and the
derived observer image's base layers. Execution itself remains offline.

Then run:

```powershell
.venv\Scripts\python.exe -m emumee powershell examples\powershell-capture.ps1 `
  --observer output\powershell-exec-observer\observer `
  --instrumented-engine output\powershell-instrumented-engine\System.Management.Automation.dll `
  --guest-tools-build output\powershell-guest-tools\build.json `
  --output output\powershell-dashboard-probe --timeout 60
```

The script is limited to 1 MiB and the deadline to 1–300 seconds. Only the
selected file and validated Windows persona enter the guest through a bounded
channel on observer stdin after the private authentication key. Script bytes
are written to `/work/input.ps1` and persona JSON to `/work/persona.json` in a
fresh temporary filesystem. They are never added to an image layer, and no
source directory is mounted. Host environment variables and profiles
are not passed into PowerShell. Both the script and native descendants execute
inside the guest. The runtime root is read-only, network mode is `none`, all
capabilities are dropped, and no-new-privileges is enabled. It uses private PID
and IPC namespaces, UID/GID 65534, a 64-process limit, one CPU, 512 MiB memory
with the same memory-plus-swap limit, and two 16 MiB noexec temporary filesystems.
The CLI inspects these settings before starting the observer. Docker documents
the [run controls](https://docs.docker.com/reference/cli/docker/container/run/),
[resource limits](https://docs.docker.com/engine/containers/resource_constraints/),
and [temporary filesystems](https://docs.docker.com/engine/storage/tmpfs/).

The external observer blocks network socket creation and selected connection,
message, namespace, and observer-access syscalls before execution. Socket
denials appear in the dashboard network timeline. A fresh key authenticates
record order and transport. On timeout or trace-budget exhaustion the CLI
terminates the container, checks that execution stopped, and removes it.
Whole authenticated records received before termination are retained and
marked incomplete. Host trace buffering is capped at 4 MiB and Docker attach
diagnostics at 64 KiB. Invalid engine payloads are rejected individually;
they do not discard independent native exec records.

Console capture observes successful `write`/`writev` calls to the guest's
stdout/stderr backing files, including duplicated descriptors used by .NET.
These backing files live only in the bounded `/work` temporary filesystem.
Snapshots are limited to 4096 bytes per syscall and 64 KiB per stream, with
explicit truncation flags. Other output redirections and writes through
different syscall families are not covered.

Reports retain decoded source, exact original input bytes as base64, the input
hash, evaluated command records, raw observer records, console output, exit
status, and configuration evidence. The dashboard shows the submitted source,
evaluated parameters, native argv arrays, errors, and denied network calls.
Every run is marked partial because command capture is incomplete. The CLI
returns 0 for an observed zero PowerShell exit without run errors, 1 for a
recorded execution error or timeout, and 2 for setup/reporting failures.

**Remaining requirements:** this is Linux PowerShell, with Linux identity and
native binaries underneath the Windows utility bridge. General Windows APIs,
PowerShell's Windows providers, and persistent shared Windows state are not integrated.
Arbitrary .NET method calls are not fully observed. Engine parameter records
are guest-generated and can be forged or bypassed; authenticated transport
does not prove their truth. Native argv snapshots can race concurrent mutation
between syscall entry and the kernel's argument copy. Hostile observer
tampering, all exec edge cases, complete network intent, and container escape
resistance remain unproven. The overall Windows persona and complete-command
capture goal is still open.

The harmless example exercises a constructed command name, base64-decoded
value, splatting, nested `Invoke-Expression`, pipeline binding, Unicode and
empty native arguments, and a denied network socket. Integration tests are
opt-in because they require the built artifacts and running Docker Desktop:

```powershell
$env:EMUMEE_POWERSHELL_INTEGRATION = '1'
.venv\Scripts\python.exe -m unittest tests.test_powershell_guest_tools tests.test_powershell tests.test_powershell_exec_observer tests.test_command_dashboard tests.test_persona -q
```

### Windows enumeration bridge

The PowerShell CLI requires `--guest-tools-build`; it does not silently use
Linux `whoami` or `hostname` when Windows enumeration tools are unavailable.
`--persona <file.json>` accepts the same overrides as PE analysis. Without
that option it uses the default Windows persona. The validated persona is
limited to 4 MiB in transfer, and never becomes an image layer or host mount.

All 40 bundled utilities listed in [the enumeration inventory](ENUMERATION_COVERAGE.md)
are exposed as native Linux shims. Each shim invokes the guest's isolated
Python and Emumee CPU emulator with the generated x64 Windows PE and original
argument array. There is no host process, host resolver, arbitrary PE path,
or live network broker fallback. Utilities retain their documented supported
forms and error behavior. `examples/powershell-persona.ps1` exercises identity,
adapter, registry, DNS, and ICMP queries through these same models.

The guest bootstrap sets persona COMPUTERNAME, USERNAME, USERDOMAIN (the local
account's computer name), USERPROFILE, SystemRoot, and windir values. Native
shim names are placed first in guest PATH; `.exe` aliases provide PowerShell's
case-insensitive lookup. A guest C: drive maps the System32 and Wbem utility
paths to the same shims. This drive is a utility namespace, not a complete
Windows filesystem or registry provider. Direct .NET Windows path handling
still follows the underlying Linux runtime.

Each utility starts with a fresh Windows persona, process, registry, file,
and clock snapshot. Changes do not persist into the next utility invocation,
and the utility's process list does not include the Linux PowerShell process.
Native code that deliberately bypasses the shims can still inspect the Linux
guest. Complete Windows environment fidelity remains open.

Utility result records use `guest_windows_emulation`, distinct from external
kernel exec observations. They contain the program and arguments, generated
PE hash, persona hash, full Windows exit code, and bounded model network events.
DNS and ICMP observations enter the dashboard timeline with `network_used: false`.
Linux native exit status exposes only the low eight bits of the Windows code;
the full code remains visible in the utility record. A known shim that starts
without returning a valid model record is reported as incomplete.

Persona hash comparisons flag ordinary modification of the guest persona file.
The file and these records remain guest-accessible; arbitrary guest code can
forge model data or output. The comparison is diagnostic, not attestation.
Malformed model payloads cannot claim kernel provenance and do not discard
independent native-exec evidence.

### Verified Windows utility bridge (2026-10-14 UTC)

The 67-test combined gate passed with Docker integration enabled. A custom
persona completed supported queries through all 40 utilities, plus a second
`whoami.exe` invocation through `Start-Process`. The test verified every
reported PE hash against the generated bytes and every persona hash against
the supplied snapshot. It also checked mixed-case `.exe` lookup, System32
and Wbem paths, offline ICMP, and container removal. Local evidence is
`output/powershell-persona-gate/20261014T223205Z-6bc2cd3b`.

Separate live cases checked alternate identity, IPv4, registry, DNS, ping,
environment values, unsupported-argument exit 87, full Windows exit 1355
with Linux status 75, and detection of a modified guest persona file.
Existing timeout, console-budget, network-denial, malformed-engine-record,
filesystem-isolation, dashboard, and persona-validation tests also passed.

A separate CLI run of `examples/powershell-persona.ps1` used OFFICE-PS-42,
Morgan, and 192.168.1.148. All six utility calls reported the supplied persona,
exit 0, and no run errors. The live dashboard displayed their reported Windows
exit codes and persona comparisons, together with registry, DNS, and ICMP
observations. Evidence is
`output/powershell-dashboard-probe/20261014T223525Z-b4e9d826`.

The sections below document the earlier fixed feasibility probes and the
engine build used by the supplied-script mode.

### Verified supplied-script gate (2026-10-14 UTC)

The 20-test PowerShell/observer/dashboard gate passed with Docker integration
enabled. Live cases verified evaluated values and native argv bytes, ordinary
PowerShell and native console output, a denied IPv4 socket, an absent host-only
file and host environment value, no Docker socket, a denied root write and
observer-memory read, UID 65534, nonzero exit 13, retained command/console
records after an eight-second timeout, rejected malformed engine data with
continued native capture, console truncation, and termination at a reduced
host trace budget. Every integration case checked container removal.

A separate invocation through `emumee powershell` completed the example with
38 invocation records, exit 0, no run errors, and all configuration checks true.
The live dashboard showed its submitted source, evaluated Unicode values,
pipeline argument, native argv, and denied socket. Its local evidence is
`output/powershell-dashboard-probe/20261014T221028Z-060b40db`.

## Execution boundary

A working path must execute the full PowerShell engine in a separate guest
boundary with guest-only filesystem, registry, processes, identity, and clock.
One candidate is an ephemeral Windows VM with no virtual network adapter or
host shares, a bounded input and result channel, and a clean snapshot for each
run. Another is extending Emumee's managed runtime enough to host the engine
and broker every system call. Neither candidate is implemented or verified.

A fixed harmless Linux-container probe is now available in
[`tools/probe_powershell_container.py`](tools/probe_powershell_container.py).
It accepts only an already pulled official .NET SDK image pinned by digest,
and executes its own fixed script. It creates an unprivileged container with
network disabled, a read-only root, no host mounts, all capabilities dropped,
no-new-privileges, process and memory limits, and small temporary filesystems.
Docker's configuration is inspected before execution, and the container is
removed after the probe. An observed create timeout can be resumed using the
same named container, after its image, command, and created state are verified.

On 2026-10-14 the probe ran PowerShell 7.5.12 inside Docker Desktop's Linux VM,
using `mcr.microsoft.com/dotnet/sdk@sha256:2f5eb32870b4c0074a3d5b5191a03553bcab7b74463a76a7c0a5f3ef65c90fe5`.
The fixed script evaluated a constructed cmdlet name and argument, nested
`Invoke-Expression`, and a native `/bin/echo` argument. Its raw trace contained
successful runtime bindings for all three expanded values. The outbound TCP
probe and root filesystem write failed; host drive and Docker socket paths
were absent, and capability and no-new-privileges checks passed. No probe
container remained. The local evidence is
`output/powershell-container-probe/probe.json`.

This verifies a prototype execution and trace path for fixed benign code.
Linux PowerShell still exposes a Linux guest environment, not the Windows
persona. Script-controllable tracing is not a sufficient audit boundary for
submitted scripts, and these probes do not establish resistance to container
escape. Microsoft documents
[PowerShell in official SDK images](https://learn.microsoft.com/en-us/powershell/scripting/install/powershell-in-docker),
and Docker documents the [container run controls](https://docs.docker.com/reference/cli/docker/container/run/).

The runtime must deny direct network access and record every attempted
network operation before deciding whether to block it. It must also prevent
PowerShell's native-process calls from reaching a host executable. If native
children are allowed, they must resolve to verified guest bytes and use the
same guest persona.

## Command evidence

The probe now hosts the fixture in a separate PowerShell runspace and observes
the engine debugger's current command processor. The public debugger-stop
invocation is a copy without bound parameters; the pinned engine's actual
`MyInvocation` record supplies the evaluated values. Native command binders
supply argument arrays directly, preserving spaces, quotes, and empty values.
This uses private engine fields and must be revalidated for each engine version.

The fixed fixtures passed direct checks for a constructed command name,
nested `Invoke-Expression`, a splatted array, an alias, and quoted and empty
native arguments. Structured `command_events` retain the resolved command,
bound parameters, native argument array, source expression, and invocation
order. Records describe the point before execution, without claiming successful
completion. Snapshots have explicit depth, length, and event bounds; unsupported
value types are marked. Breakpoints can still be removed or bypassed, and
DebuggerHidden paths, new runspaces, and native descendants are not completely
traced. This remains a fixed-probe tool, not an arbitrary-script analysis mode.

A separate benign tamper fixture disables and removes the observer breakpoint.
The observer records these updates and checks whether the breakpoint remains
enabled at the end. The fixture confirms that commands after disabling it are
absent from the invocation log; the report and dashboard explicitly mark this
interruption. This detects the tested interruption, without establishing a
tamper-resistant observer. Evidence is saved in
`output/powershell-capture-integrity-probe/probe.json`.

Use `--dashboard-root <directory>` on the probe tool to save a partial run in
the usual integrity-checked report format. The dashboard's Commands section
shows these records with capture limitations, alongside guest native process
command lines from existing runs. Real fixture evidence is saved in
`output/powershell-command-capture-probe/probe.json`; its dashboard run lives
under `output/powershell-dashboard-probe`. The dashboard remains read-only.

Capture execution at command discovery and parameter binding, after variable
expansion, alias resolution, splatting, and dynamic evaluation. Record the
resolved command name, bound argument values, invocation order, source script
location when available, and result or error. Capture nested commands from
`Invoke-Expression` and native child command lines at the process boundary.
Retain the original script separately; its text is not proof of what ran.
PowerShell's `Trace-Command` parameter-binding trace is a useful prototype,
but the final record must come from instrumentation the analyzed script cannot
turn off.

Microsoft documents runtime parameter tracing in
[`Trace-Command`](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/trace-command)
and script block invocation logging in
[PowerShell Group Policy settings](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_group_policy_settings).

## Separate native-process observer prototype

`tools/probe_powershell_exec_observer.py` runs a second fixed benign probe with
a separate Linux x86-64 observer process. It captures `execve`/`execveat` argument
bytes at syscall entry and projects only kernel-confirmed execs into the
dashboard's Commands section. Spaces, quotes, empty arguments, and UTF-8 bytes
are preserved; full argument bytes remain available as hexadecimal data. A
successful exec does not establish successful program completion.

The observer traces process/thread descendants, requests `PTRACE_O_EXITKILL`,
rejects other syscall architectures and untraced clone requests, and blocks
selected network and observer-access syscalls. It runs with no capabilities
inside the existing no-network, read-only, unprivileged container boundary.
Neither ptrace privileges nor a host filesystem mount are added. The helper is
baked into a local derived image from the pinned SDK image before runtime;
Docker does not allow copying it into an already read-only container root.
The local image/cache and compiled helper remain available for repeat probes.

The observer makes itself non-dumpable. A fresh host-generated HMAC key arrives
over stdin, is erased from the forked child's key buffer before exec, and is
never placed in command arguments, environment, or reports. Host verification
rejects unsigned, changed, missing, or reordered records and requires a complete
observer lifecycle. This protects the tested record channel from ordinary
script output; it is not proof against every possible observer attack. Child
stdout/stderr are discarded in this prototype and the report says no console
capture is available. Linux documents the underlying
[ptrace controls](https://man7.org/linux/man-pages/man2/ptrace.2.html) and
[dumpable attribute](https://man7.org/linux/man-pages/man2/pr_set_dumpable.2const.html).

On 2026-10-14 the fixed probe passed all ten observed checks. It captured the
argument array `['space value', 'quote"value', '', 'café-✓']`, a native call
after breakpoint removal, an access-denied exception when opening observer
memory, and a blocked IPv4 socket syscall. Evidence is
`output/powershell-exec-observer/probe.json`; the dashboard run is
`output/powershell-dashboard-probe/20261014T210945Z-358cad7c`.
No observer probe container remained after execution.

Build with an existing Linux x86-64 WSL distribution containing GCC, libc
development files, and `libssl-dev`, then run the fixed probe:

```powershell
.\tools\build_powershell_exec_observer.ps1
.venv\Scripts\python.exe -m tools.probe_powershell_exec_observer `
  --image mcr.microsoft.com/dotnet/sdk@sha256:2f5eb32870b4c0074a3d5b5191a03553bcab7b74463a76a7c0a5f3ef65c90fe5 `
  --observer output\powershell-exec-observer\observer `
  --output output\powershell-exec-observer\probe.json `
  --dashboard-root output\powershell-dashboard-probe
```

This prototype still accepts no submitted script. It captures native execs,
not PowerShell cmdlet/function calls or arbitrary .NET method invocations.
Linux identity still differs from the Windows persona. `execveat` descriptor
paths, all multithreaded exec edge cases, broader syscall coverage, complete
network intent, hostile observer tampering, and container escape resistance
remain unverified. Engine-level evaluated-parameter logging and a Windows
persona execution boundary remain requirements for complete Windows behavior.

## Instrumented-engine experiment

`tools/build_powershell_instrumented_engine.py` builds an experimental
`System.Management.Automation.dll` from upstream PowerShell 7.5.12 commit
`3ad470239de5c9c52d470917b071831f16b02fc3` and annotated tag object
`f8c5ff6aaeca83dc1e08eeb0b55d8e88d0133ac7`. It requires a clean matching source
checkout and the pinned SDK image above. Compilation and the upstream resource
and type-catalog generators execute in Docker. Only tracked upstream files and
two public Git version objects enter the build context; local Git configuration,
hooks, reflogs, ignored files, and the Emumee workspace are excluded. The build
uses public NuGet packages without credentials. Dependency restore uses network
access in the build stage; the probe runtime retains its no-network boundary.

The injected logger observes command-line binding, per-record pipeline binding,
and simple-script argument binding. These events are independent of debugger
breakpoint registration. Snapshots include evaluated primitives, bounded strings,
arrays, concrete built-in object/PSObject lists, and switch values. Other objects
are marked opaque, rather than enumerating arbitrary collections or invoking
custom getters and `ToString` methods. Bounds are explicit, and a broken event
transport or exceeded event budget terminates the instrumented guest process.

The engine writes bounded JSON to a dedicated guest `/dev/null` descriptor.
The separate observer reads those write buffers at syscall stops and signs the
transport records. Engine records and kernel-confirmed native execs share the
Commands view, with their distinct capture sources and binding phases.
**Authenticated transport does not authenticate the origin or truth of engine
payloads.** Guest code with arbitrary .NET/native access can write forged engine
records or bypass the hooks. Such records are labeled `guest_engine_instrumentation`
and `in_process_data`; the dashboard explicitly explains this distinction. A
guest payload cannot claim external provenance or supply native argument records
through the engine-record decoder.

For a fresh source checkout, then a build and fixed probe:

```powershell
git clone --depth 1 --branch v7.5.12 --filter=blob:none https://github.com/PowerShell/PowerShell.git output\powershell-source-7.5.12
.venv\Scripts\python.exe -m tools.build_powershell_instrumented_engine `
  --source output\powershell-source-7.5.12 `
  --output output\powershell-instrumented-engine\System.Management.Automation.dll
.\tools\build_powershell_exec_observer.ps1
.venv\Scripts\python.exe -m tools.probe_powershell_exec_observer `
  --image mcr.microsoft.com/dotnet/sdk@sha256:2f5eb32870b4c0074a3d5b5191a03553bcab7b74463a76a7c0a5f3ef65c90fe5 `
  --observer output\powershell-exec-observer\observer `
  --instrumented-engine output\powershell-instrumented-engine\System.Management.Automation.dll `
  --output output\powershell-engine-capture\probe.json `
  --dashboard-root output\powershell-dashboard-probe
```

The assembly build sidecar records source, patch, and assembly hashes. The
runtime image verifies that evidence and replaces only the matching pinned
SDK's engine assembly. The supplied-script mode now uses this same assembly.
General method-call capture, a Windows persona, native child PowerShell engine
propagation checks, and resistance to hostile engine/observer tampering remain
unverified.

On 2026-10-14 the combined fixed probe passed 19 checks, including cmdlet values
after breakpoint removal, nested `Invoke-Expression`, a splatted array, simple
and advanced functions, a pipeline-bound parameter, a debugger-hidden function,
and another runspace. A script-property trap was not invoked by snapshotting;
its object was explicitly marked opaque. The native argument, observer-memory,
and denied-socket checks also passed. Evidence is
`output/powershell-engine-capture/probe.json`, with dashboard run
`output/powershell-dashboard-probe/20261014T213021Z-de711504`. The tested engine
assembly SHA-256 is
`3e73cf7dccb36ce42247ec004526c9c6b597b193da70335b72de0fa07bf474cc`.

Show these invocation records in a dedicated dashboard section and keep the
raw event list in the integrity-checked engine report. Verify it with benign
scripts that construct a command name and arguments at runtime, invoke a
nested script block, use splatting, attempt a network connection, and try to
launch a native child. The dashboard must show the actual resolved calls and
the denied operations, with no host filesystem or network effects.

# PowerShell guest execution: feasibility gates

PowerShell feasibility work follows native enumeration coverage. It is not an
Emumee execution mode today. Guest `CreateProcess` rejects managed child PEs,
and the bounded managed interpreter does not implement the PowerShell engine.
Running host `powershell.exe` or `pwsh.exe` from the worker would not satisfy
guest execution or persona isolation.

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
persona execution boundary remain required before enabling general scripts.

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
SDK's engine assembly. It remains a fixed-probe experiment: arbitrary submitted
scripts, general method-call capture, a Windows persona, native child PowerShell
engine propagation, and resistance to hostile engine/observer tampering remain
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

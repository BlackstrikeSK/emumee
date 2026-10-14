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

Show these invocation records in a dedicated dashboard section and keep the
raw event list in the integrity-checked engine report. Verify it with benign
scripts that construct a command name and arguments at runtime, invoke a
nested script block, use splatting, attempt a network connection, and try to
launch a native child. The dashboard must show the actual resolved calls and
the denied operations, with no host filesystem or network effects.

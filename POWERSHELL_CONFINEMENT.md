# PowerShell guest execution: feasibility gates

PowerShell is a later goal after native enumeration coverage. It is not an
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

The runtime must deny direct network access and record every attempted
network operation before deciding whether to block it. It must also prevent
PowerShell's native-process calls from reaching a host executable. If native
children are allowed, they must resolve to verified guest bytes and use the
same guest persona.

## Command evidence

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

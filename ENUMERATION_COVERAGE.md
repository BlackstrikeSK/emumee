# Guest enumeration programs

Emumee runs native child programs only from verified guest bytes. It never
launches a host Windows utility to answer a guest command. The default guest
utilities below are generated PEs, not copies of Microsoft binaries. Their
output is a snapshot of the configured persona at run setup; later guest
changes may not appear in that output. The nine argument-aware enumeration
utilities reject unmodeled arguments with exit code 87; `hostname.exe` does
not yet parse switches. Guest commands never change host state.

| Guest program | Included by default | Modeled read commands |
| --- | --- | --- |
| `hostname.exe` | Yes | Default hostname |
| `whoami.exe` | Yes | Default user name, `/user`, `/groups`, `/priv`, `/all` from the modeled token |
| `ipconfig.exe` | Yes | Default, `/all` |
| `getmac.exe` | Yes | Default adapter MAC and transport name |
| `systeminfo.exe` | Yes | Default system identity and resources |
| `tasklist.exe` | Yes | Default persona process snapshot |
| `arp.exe` | Yes | `-a` for the modeled IPv4 ARP entry |
| `route.exe` | Yes | `print`, `print -4` |
| `netsh.exe` | Yes | `interface ipv4 show config`, `interface ipv4 show dnsservers` |
| `tzutil.exe` | Yes | `/g` |

## Tracked gaps

These are candidate native Windows enumeration commands. The list is a
working inventory, not a claim that every Windows build or optional feature
ships every binary. A staged real utility may run through guest CPU emulation,
but it is not included by default unless the table above says so.

| Program | Read use | Data or behavior still needed |
| --- | --- | --- |
| [`netstat.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat) | `-ano` | Guest socket, listener, and PID state that changes during the run. |
| [`net.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/net-user) | `user`, `localgroup` | A coherent guest account and group database. |
| [`driverquery.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/driverquery) | Default, `/v` | A guest driver inventory consistent with services and device state. |
| [`schtasks.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-query) | `/query` | A virtual scheduled-task store and query semantics. |
| [`query.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-user) | `user`, `session` | Session and logon records beyond the current process snapshot. |
| `reg.exe` | `query` | General guest registry command parsing; locally staged Microsoft `reg.exe` already works on some tested keys. |
| `sc.exe` | `query` | A guest service-control database rather than process names alone. |

The included generated `arp.exe -a` uses the broadcast row from the guest
`GetIpNetTable` model; it does not invent a gateway hardware address. A locally
staged Microsoft `arp.exe` remains partial at an undocumented NSI API. Other
[ARP command forms](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/arp)
are unmodeled.

Generated `netsh.exe` covers only two IPv4 interface views for the modeled
adapter. Other [network shell commands](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
remain unmodeled, including interface changes and profile displays.

`cmd.exe`, PowerShell, VBScript, JavaScript, and Python are outside this native
utility inventory. No entry in this file authorizes a guest command to execute
on the host. See [COVERAGE_AND_SAFETY.md](COVERAGE_AND_SAFETY.md) for tested
paths and containment limits.

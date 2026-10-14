# Guest enumeration programs

Emumee runs native child programs only from verified guest bytes. It never
launches a host Windows utility to answer a guest command. The default guest
utilities below are generated PEs, not copies of Microsoft binaries. Most
text output is a snapshot of the configured persona at run setup; `reg.exe`
reads the current guest registry. All listed utilities except
`hostname.exe` reject unmodeled arguments with exit code 87. Guest commands
never change host state.

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
| `query.exe` | Yes | `user`, `session` for the modeled console and services sessions |
| [`quser.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/quser) | Yes | Default user session view |
| [`qwinsta.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/qwinsta) | Yes | Default session view |
| [`net.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/net-user) | Yes | `user`, `user <persona user>`, `localgroup`, `localgroup administrators`, `localgroup users` |
| `net1.exe` | Yes | Same modeled local account and group views as `net.exe` |
| [`sc.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-query) | Yes | `query`, `query state= all`, and named queries for up to three modeled services |
| [`reg.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-query) | Yes | `query <local key>` using guest registry APIs for any modeled key |

## Tracked gaps

These are candidate native Windows enumeration commands. The list is a
working inventory, not a claim that every Windows build or optional feature
ships every binary. A staged real utility may run through guest CPU emulation,
but it is not included by default unless the table above says so.

| Program | Read use | Data or behavior still needed |
| --- | --- | --- |
| [`netstat.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat) | `-ano` | Guest socket, listener, and PID state that changes during the run. |
| [`driverquery.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/driverquery) | Default, `/v` | A guest driver inventory consistent with service, device, and driver file probes. |
| [`schtasks.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-query) | `/query` | A virtual scheduled-task store and query semantics. |
| `reg.exe` beyond the listed form | `/v`, `/s`, remote keys, and writes | More guest command parsing; locally staged Microsoft `reg.exe` already works on some tested keys. |
| `sc.exe` beyond the listed forms | More query options and service changes | A dynamic Service Control Manager model and parser. |

The included generated `arp.exe -a` uses the broadcast row from the guest
`GetIpNetTable` model; it does not invent a gateway hardware address. A locally
staged Microsoft `arp.exe` remains partial at an undocumented NSI API. Other
[ARP command forms](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/arp)
are unmodeled.

Generated `netsh.exe` covers only two IPv4 interface views for the modeled
adapter. Other [network shell commands](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface)
remain unmodeled, including interface changes and profile displays.

Generated `query.exe`, `quser.exe`, and `qwinsta.exe` report the persona's active console user in session 1
and the service session 0. Its logon time is derived from the guest clock and
uptime. Other [user](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-user)
and [session](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/query-session)
queries, remote servers, and session changes are unmodeled.

Generated `net.exe` and `net1.exe` list the persona user alongside fixed local
Administrator and Guest accounts. Their Users and Administrators memberships
match the guest token's admin flag. The named user query requires an ASCII
persona user name; [other account commands](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/net-user),
remote domains, account changes, and a general guest SAM database remain
unmodeled.

Generated `sc.exe` reads the persona's configurable service list. A service is
reported as running when its named process appears in the persona process
snapshot and it is not disabled. The same entries generate guest service
registry keys unless a custom registry replaces them. Named `sc query` covers
the first three services; the list forms cover all configured services.

The included `reg.exe` is compiled from repository C source and calls guest
registry APIs for any existing local key. It accepts quoted paths and displays
current guest values and immediate subkeys. `/v`, `/s`, remote keys, and writes
remain unmodeled. The packaged x86/x64 PEs import only guest Kernel32 and
Advapi32 APIs and do not invoke the host registry.

`cmd.exe`, PowerShell, VBScript, JavaScript, and Python are outside this native
utility inventory. No entry in this file authorizes a guest command to execute
on the host. See [COVERAGE_AND_SAFETY.md](COVERAGE_AND_SAFETY.md) for tested
paths and containment limits.

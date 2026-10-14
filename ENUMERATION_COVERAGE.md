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
| [`cmdkey.exe`](https://learn.microsoft.com/windows-server/administration/windows-commands/cmdkey) | Yes | `/list` from guest stored credential metadata, with no password data |
| [`manage-bde.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/manage-bde-status) | Yes | `-status` and `-status C:` from guest capacity and BitLocker metadata |
| `where.exe` | Yes | One simple file name in the guest current directory and guest `PATH`; `.exe` is added when no extension is supplied |
| [`fsutil.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-fsinfo) | Yes | `fsinfo drives`, `fsinfo drivetype C:`, and `fsinfo volumeinfo C:` for the guest volume |
| [`mountvol.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mountvol) | Yes | Default volume listing and `C:\ /L` from the guest volume GUID |
| [`bcdedit.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/bcdedit) | Yes | Default, `/enum`, `/enum active`, `/v`, `/enum active /v`, `/enum {current}` from persona boot settings |
| [`vssadmin.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin) | Yes | `list shadows`, `list shadows /for=C:`, `list volumes`, and `list providers` from guest shadow and volume metadata |
| `whoami.exe` | Yes | Default user name, `/user`, `/groups`, `/priv`, `/all` from the modeled token |
| `ipconfig.exe` | Yes | Default, `/all` |
| [`netstat.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat) | Yes | Default, `-an`, `-ano` for live guest IPv4 TCP connections |
| `getmac.exe` | Yes | Default adapter MAC and transport name |
| `systeminfo.exe` | Yes | Default system identity and resources |
| [`wevtutil.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil) | Yes | `el` and `gl <simple channel>` through guest registry APIs |
| [`driverquery.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/driverquery) | Yes | Default, `/v`, `/fo list`, `/fo csv`, `/nh` from configured guest drivers |
| [`pnputil.exe`](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/pnputil-command-syntax) | Yes | `/enum-drivers`, legacy `-e`, `/enum-devices`, `/enum-devices /connected`, `/enum-classes` from guest driver packages and devices |
| [`gpresult.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/gpresult) | Yes | `/r`, `/scope user /r`, `/scope computer /r` and the equivalent `/r /scope ...` order from guest applied policy lists |
| [`dsregcmd.exe`](https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-device-dsregcmd) | Yes | `/status` device join, user registration, and SSO state from guest registration fields |
| [`fltmc.exe`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/development-and-testing-tools) | Yes | Default, `filters`, `instances`, `volumes` from guest minifilters and C: volume |
| `tasklist.exe` | Yes | Default persona process snapshot and `/svc` service to process view |
| [`schtasks.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/schtasks-query) | Yes | Default, `/query`, `/query /fo LIST`, `/query /fo CSV`, and named queries for up to two ASCII task names |
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
| [`reg.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/reg-query) | Yes | `query <local key>`, `/v <value>`, `/ve`, `/s` using guest registry APIs |

## Tracked gaps

These are candidate native Windows enumeration commands. The list is a
working inventory, not a claim that every Windows build or optional feature
ships every binary. A staged real utility may run through guest CPU emulation,
but it is not included by default unless the table above says so.

| Program | Read use | Data or behavior still needed |
| --- | --- | --- |
| `cmdkey.exe` beyond `/list` | Target filters and credential changes | A dynamic guest credential store and command parser; unsupported forms exit 87. |
| [`klist.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/klist) | Default ticket list, `tickets`, `sessions`, and `query_bind` | Not included. Needs guest logon IDs and Kerberos cache metadata consistent with the LSA model. |
| [`nltest.exe`](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935%28v%3Dws.11%29) | `/domain_trusts`, `/dclist`, and `/dsgetdc` | Not included. Needs explicit guest domain, trust, site, and controller records; discovery must not query host DNS or domain services. Availability depends on Windows installation. |
| `manage-bde.exe` beyond the listed forms | Protection error-level flags, other volumes, conversion progress, protector details, and changes | Full BitLocker state and key material are not modeled; unsupported forms exit 87. |
| [`wbadmin.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin-get-versions) | `get versions` | Not included. Needs guest backup catalog and permission behavior; no host or remote backup access. |
| `netstat.exe` beyond the listed forms | UDP, listening sockets, IPv6, and more options | Additional guest endpoint models and output modes. Inbound listening is currently denied. |
| `fsutil.exe` beyond the listed forms | Other `fsinfo` queries, volumes, and changes | More guest volume data and bounded read command parsing. |
| `mountvol.exe` beyond the listed forms | Other volume mount points and changes | Multiple volumes and mount mutations remain unmodeled. |
| `vssadmin.exe` beyond the listed forms | Shadow IDs and other filters, writers, shadow storage, and changes | More guest VSS metadata and dynamic shadow storage remain unmodeled; delete and resize exit 87. |
| `pnputil.exe` beyond the listed forms | Device filters and properties, other package views, and changes | More guest PnP properties and a dynamic driver store. Change commands exit 87. |
| `fltmc.exe` beyond the listed forms | Named filters or instances, frames, loading, unloading, and attachment changes | A dynamic guest Filter Manager and more than one volume. |
| `wevtutil.exe` beyond the listed forms | `qe`, `gli`, publishers, remote queries, and changes | A guest event record store and live status model; only channel names and configuration are modeled. |
| `bcdedit.exe` beyond the listed forms | `/enum all`, other identifiers, BCD store paths, and changes | A full guest Boot Configuration Data store; the included PE currently renders two configured active entries. |
| `gpresult.exe` beyond the listed forms | `/v`, `/z`, `/h`, `/x`, remote targets, and other users | Guest policy settings and RSoP details, report files, and remote policy data are not modeled. |
| `dsregcmd.exe` beyond the listed fields | Device and tenant details, diagnostics, prerequisites, and join or leave operations | A full guest registration and tenant model; status output currently includes only the modeled state fields. |
| `driverquery.exe` beyond the listed forms | `/si`, combined flags, and remote queries | Signed driver data, more output modes, and `.sys` guest files remain unmodeled; driver images are not executed. |
| `schtasks.exe` beyond the listed forms | `/v`, `/xml`, more `/tn` forms, remote queries, and task changes | Task Scheduler APIs and task definition files remain unmodeled. |
| `reg.exe` beyond the listed forms | `/f`, remote keys, and writes | More guest command parsing; locally staged Microsoft `reg.exe` already works on some tested keys. |
| `sc.exe` beyond the listed forms | More query options and service changes | A dynamic Service Control Manager model and parser. |

Generated `cmdkey.exe /list` reads only the persona's `stored_credentials`
metadata: target, user, type, and persistence. The default guest has no stored
credentials. The schema accepts no password field, and the utility never
opens a host credential store. Add and delete operations exit 87.

Generated `manage-bde.exe -status` reports the guest C: volume as unlocked,
with either fully encrypted or fully decrypted state from `bitlocker` metadata.
Only protector type names are modeled; no recovery keys or encryption keys
are stored. Capacity comes from `volume_capacity_bytes`, which also backs
guest `GetDiskFreeSpaceExA/W`. That API returns `volume_free_bytes` for both
free-space outputs, without quotas or dynamic space accounting. The default
guest has a 512 GiB volume, 320 GiB free, and BitLocker off. Unsupported remote
queries and changes exit 87 without host volume access.

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

Generated `tasklist.exe /svc` joins the persona process snapshot with active
persona services by process name. If a process name occurs more than once, the
services appear on the first matching PID, using the same deterministic PID
assignment as the default `tasklist.exe` view. Disabled or absent services are
not listed.

The included `reg.exe` is compiled from repository C source and calls guest
registry APIs for any existing local key. It accepts quoted paths and displays
current guest values and immediate subkeys; `/v` selects one named value,
`/ve` selects the default value, and `/s` traverses subkeys. Traversal is
bounded to 24 levels, 512 keys, and 256 Ki characters of output. `/f`, remote
keys, and writes remain unmodeled. The packaged x86/x64 PEs import only guest Kernel32 and
Advapi32 APIs and do not invoke the host registry.

The included `where.exe` is also compiled from repository C source. It calls
guest `GetCurrentDirectoryW`, `GetEnvironmentVariableW`, and
`GetFileAttributesW`, so a lookup sees only guest files. It accepts one simple
file name, searches at most 32 guest `PATH` directories, and prints only paths
found in the virtual filesystem. Wildcards, recursive searches, multiple
patterns, and switches are not modeled.

The included `fsutil.exe` is compiled from repository C source. Its read-only
`fsinfo` forms show the guest `C:` drive. `volumeinfo` calls the guest
`GetVolumeInformationW` model at runtime, so its label, serial, maximum
component length, and filesystem name agree with that API. An unmodeled drive
returns path-not-found; unsupported commands exit 87. No host volume is read.

Generated `mountvol.exe` lists the single guest `C:` mount and supports
`C:\ /L`. Its volume GUID comes from the persona and matches the guest
`GetVolumeNameForVolumeMountPointA/W` response. Other mounts and mutation
commands exit 87 without changing guest or host volumes.

Generated `vssadmin.exe` reads the persona's `shadow_copies` list and single
guest `C:` volume. Shadow IDs, set IDs, creation times, the guest hostname,
and volume GUID come from the persona; the Microsoft system provider is a
fixed guest record. The default guest has no shadow copies. Delete and resize
commands exit 87 without accessing host VSS or volume data.

Generated `bcdedit.exe` renders a boot manager and current loader from the
persona's `boot_config`, guest locale, and single `C:` volume. `/v` expands
the configured loader GUID. Explicit debug, safe boot, and hypervisor launch
settings appear only when configured. Other identifiers, full BCD hive data,
and mutation commands remain unmodeled; unsupported forms exit 87 without
opening the host BCD store.

The included `wevtutil.exe` is compiled from repository C source. `el`
enumerates guest EventLog registry subkeys and `gl <channel>` reads their
enabled state, maximum size, retention flag, and log path at runtime. These
keys derive from the persona's `event_channels` list unless the caller
provides a custom registry. Channel names are simple and bounded; event
records and `.evtx` files are not modeled. Unsupported forms exit 87 and no
host Event Log APIs or files are accessed.

Generated `driverquery.exe` reads only the persona's `drivers` list. Each
configured driver also creates a guest Services registry key with its type,
start mode, display name, and image path. The listed `.sys` path is metadata;
the image file and kernel execution are not modeled. The supported local read
forms are default table, `/v`, `/fo list`, `/fo csv`, and `/nh`. Remote and
unmodeled arguments exit 87 without contacting the host.

Generated `pnputil.exe` reads the persona's `driver_packages` and
`pnp_devices` lists. The default network device shares its description and
instance ID with the network adapter, and each package has synthetic guest
INF metadata under `C:\Windows\INF`. The package store is separate from the
running-driver list used by `driverquery.exe`. Unsupported queries and change
commands exit 87 without accessing a host device or driver store.

Generated `gpresult.exe /r` reads the persona's `group_policy` computer and
user applied-policy lists. The scope forms show only the selected list.
Remote targets, detailed policy settings, and report file writes exit 87;
the utility never queries host Group Policy or RSoP data.

Generated `dsregcmd.exe /status` reads only the persona's
`device_registration` flags. The default workgroup guest reports NO for
device join, workplace join, and Azure AD PRT. A supplied DNS domain sets
the default domain-joined flag unless registration is explicitly configured.
Unsupported changes exit 87 without contacting a host or cloud tenant.

Generated `fltmc.exe` reads the persona's `minifilters` list, whose names must
refer to running file-system driver records. The same records create guest
Services `Instances` registry keys with altitudes. `filters` and `instances`
report those guest records; `volumes` reports the sole `C:` NTFS volume and
its configured GUID. The default Defender persona includes `WdFilter`.
Unsupported changes exit 87 without loading or unloading a host filter.

The included `netstat.exe` is compiled from repository C source and calls a
guest-only `GetExtendedTcpTable` model. Successful outbound TCP connections
appear with the persona IPv4 address, a synthetic guest local port, the guest
destination, and the owning guest PID. The guest table is cleared as sockets
close or their owning process exits. It never queries the host socket table or
reports the broker's host-assigned local port. The default and `-an` forms omit
the PID; `-ano` includes it. Unmodeled options exit 87.

Generated `schtasks.exe` lists the bounded `scheduled_tasks` persona snapshot.
Each entry has a task path, Ready or Disabled status, and a next-run offset
relative to the guest clock; Disabled entries show N/A. The generated program
does not register, run, or modify tasks. Unsupported `/Create` exits 87 after
a guest child launch, with no host Task Scheduler call. Task Scheduler APIs,
on-disk definitions, and live scheduling are not modeled yet.

`cmd.exe`, VBScript, JavaScript, and Python are outside this native utility
inventory. PowerShell is a separate future confinement target: the current
guest child loader rejects managed PEs, and the bounded managed interpreter
does not run the PowerShell engine. A usable implementation must run script
code inside a guest execution boundary, deny or broker network operations,
record the command and arguments at each actual invocation after dynamic
expansion, and display those records in the dashboard. Source text or static
deobfuscation alone cannot establish which command ran. No entry in this file
authorizes a guest command to execute on the host. See
[COVERAGE_AND_SAFETY.md](COVERAGE_AND_SAFETY.md) for tested paths and
containment limits. The required execution and command-capture gates are
tracked in [POWERSHELL_CONFINEMENT.md](POWERSHELL_CONFINEMENT.md).

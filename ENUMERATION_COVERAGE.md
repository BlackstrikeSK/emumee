# Guest enumeration programs

Emumee runs native child programs only from verified guest bytes. It never
launches a host Windows utility to answer a guest command. The default guest
utilities below are generated PEs, not copies of Microsoft binaries. Most
text output is a snapshot of the configured persona at run setup; `reg.exe`
reads the current guest registry. All listed utilities except
`hostname.exe` reject unmodeled arguments with exit code 87. Guest commands
never change host state.

The experimental PowerShell CLI can call all bundled utilities through native
Linux shims and the same x64 PE CPU/API models inside its offline guest. It
requires a trusted guest-tools build and accepts the same persona overrides.
Each call starts from a fresh snapshot; complete Windows PowerShell providers
and shared mutable Windows state are not modeled. See
[PowerShell confinement](POWERSHELL_CONFINEMENT.md#windows-enumeration-bridge).

| Guest program | Included by default | Modeled read commands |
| --- | --- | --- |
| `hostname.exe` | Yes | Default hostname |
| [`cmdkey.exe`](https://learn.microsoft.com/windows-server/administration/windows-commands/cmdkey) | Yes | `/list` from guest stored credential metadata, with no password data |
| [`klist.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/klist) | Yes | Default and `tickets` from guest Kerberos cache metadata |
| [`wbadmin.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wbadmin-get-versions) | Yes | `get versions` from the guest backup catalog, gated by persona admin status |
| [`nltest.exe`](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731935%28v%3Dws.11%29) | Yes | `/domain_trusts`, `/dclist:<persona domain>`, and `/dsgetdc:<persona domain>` with DNS and NetBIOS aliases |
| [`manage-bde.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/manage-bde-status) | Yes | `-status` and `-status C:` from guest capacity and BitLocker metadata |
| `where.exe` | Yes | One simple file name in the guest current directory and guest `PATH`; `.exe` is added when no extension is supplied |
| [`fsutil.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-fsinfo) | Yes | `fsinfo drives`, `fsinfo drivetype C:`, and `fsinfo volumeinfo C:` for the guest volume |
| [`mountvol.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mountvol) | Yes | Default volume listing and `C:\ /L` from the guest volume GUID |
| [`bcdedit.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/bcdedit) | Yes | Default, `/enum`, `/enum active`, `/v`, `/enum active /v`, `/enum {current}` from persona boot settings |
| [`vssadmin.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/vssadmin) | Yes | `list shadows`, `list shadows /for=C:`, `list volumes`, and `list providers` from guest shadow and volume metadata |
| `whoami.exe` | Yes | Default user name, `/user`, `/groups`, `/priv`, `/all` from the modeled token |
| `ipconfig.exe` | Yes | Default, `/all` |
| [`nslookup.exe`](https://learn.microsoft.com/windows-server/administration/windows-commands/nslookup) | Yes | Noninteractive A, AAAA, and PTR queries against the offline guest DNS catalog; IPv4 reverse lookup; optional explicit primary persona DNS server |
| [`ping.exe`](https://learn.microsoft.com/windows-server/administration/windows-commands/ping) | Yes | IPv4 address or offline DNS name, optional `-4`, `-n 1..16`, `-l 0..4096`, and `-w 0..60000`; replies from guest identity or explicit ICMP fixtures |
| [`tracert.exe`](https://learn.microsoft.com/windows-server/administration/windows-commands/tracert) | Yes | IPv4 address or offline DNS name, `-d`, `-4`, `-h 1..255`, `-w 0..60000`; three probes per hop, offline PTR names, configured router replies and silent hops |
| [`pathping.exe`](https://learn.microsoft.com/windows-server/administration/windows-commands/pathping) | Yes | IPv4 route discovery, independent router echo statistics, `-n`, `-4`, `-h`, `-q`, `-p`, `-w`, offline names and persona loss patterns |
| [`netstat.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netstat) | Yes | Default, `-an`, `-ano` for live guest IPv4 TCP connections |
| `getmac.exe` | Yes | Default adapter MAC and transport name |
| `systeminfo.exe` | Yes | Default system identity and resources |
| [`auditpol.exe`](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get) | Yes | `/get /category:*`, CSV with `/r`, `/list /category`, `/list /subcategory:*`, and verbose subcategory GUID listing with `/v` |
| [`wmic.exe`](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmic) | Yes | Local `os`, `computersystem`, `cpu`, and `logicaldisk` `get` views, selected modeled properties, table or `/value` output, and equivalent `path Win32_*` forms |
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
| [`w32tm.exe`](https://learn.microsoft.com/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings) | Yes | `/query /source`, `/query /status`, `/query /status /verbose`, `/query /configuration`, and `/query /peers` from guest time metadata |
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
| `wmic.exe` beyond the listed views | More aliases, properties, filters, and formats | WMI COM providers, remote targets, changes, and arbitrary WQL remain unmodeled. Unsupported requests exit 87. |
| `auditpol.exe` beyond the listed forms | Named category/subcategory filters, per-user policy, options, ACLs, and changes | An effective-token permission check and dynamic policy changes remain unmodeled. Unsupported command forms exit 87. |
| `w32tm.exe` beyond the listed forms | Remote status, other formats, monitoring, resync, and configuration changes | Dynamic Windows Time/RPC APIs, NTP packet exchange, clock discipline, effective-token checks, and complete configuration/status fields remain unmodeled. Unsupported forms exit 87. |
| `netsh.exe` beyond the listed views | Firewall, wireless, proxy, and interface inventory | Additional guest firewall, wireless, and WinHTTP configuration. Unsupported forms exit 87. |
| `ping.exe` beyond the listed forms | IPv6, continuous probing, other IP options, and error replies | ICMPv6, errors other than TTL expiry in transit, fragmentation, and additional flags remain unmodeled; unsupported command forms exit 87. |
| `tracert.exe` beyond the listed forms | IPv6, source routing, and other IP options | ICMPv6, source address/route selection, ECMP, and non-TTL ICMP errors remain unmodeled; unsupported flags exit 87. |
| `pathping.exe` beyond the listed forms | IPv6, source address and loose source route selection | Parallel probe scheduling, correlated forwarding loss, and topology changes are not modeled. |
| `nslookup.exe` beyond the listed forms | Other record types, search suffixes, other servers, and interactive commands | SRV, MX, TXT, CNAME chains, recursive resolution, and interactive mode remain unmodeled; unsupported command forms exit 87. |
| `cmdkey.exe` beyond `/list` | Target filters and credential changes | A dynamic guest credential store and command parser; unsupported forms exit 87. |
| `klist.exe` beyond the listed forms | Other logon IDs, sessions, `tgt`, bindings, and cache changes | More guest LSA session and cache models are needed. Encoded tickets and usable keys are not modeled; unsupported forms exit 87. |
| `nltest.exe` beyond the listed forms | Other domains, server targets, discovery flags, secure channels, and changes | Dynamic domain services and Windows domain APIs remain unmodeled; unsupported forms exit 87. |
| `manage-bde.exe` beyond the listed forms | Protection error-level flags, other volumes, conversion progress, protector details, and changes | Full BitLocker state and key material are not modeled; unsupported forms exit 87. |
| `wbadmin.exe` beyond `get versions` | Target filters, item queries, backup status, and changes | A dynamic guest backup service, permissions, and backup file contents remain unmodeled. Unsupported forms exit 87. |
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

Generated `w32tm.exe` uses `time_service` metadata and the guest clock at setup.
The default service snapshot includes W32Time in `svchost.exe`, with manual start,
NoSync, no peers, and an unsynchronized local clock. This describes the chosen
guest profile, rather than every Windows installation's default policy. Its
service presence/state follows the same configured process and service list as
`sc.exe` and `tasklist.exe /svc`. Matching W32Time Config, Parameters, and NtpClient/
NtpServer provider keys are generated in the guest registry.

The model supports NoSync, explicit NTP peers, and NT5DS for domain-joined
profiles. The configured source, reference IPv4 address, stratum, selected active
peer, and last synchronization time must agree. Known guest DNS A records must
agree with that reference address. At most eight unique peers are accepted;
each has name, Active/Pending state, stratum, poll exponent, and client (3) or
symmetric-active (1) mode. Poll exponents are bounded to 4–17, timestamps cannot
be later than the guest clock, and delays/dispersion use bounded milliseconds.
Last-sync display applies the persona UTC offset; labels and date formatting
are English. Precision and timing fields are configured snapshots, not measured
network performance or a running clock-discipline algorithm.

The local query permission view uses the persona admin flag. Denied queries
return `0x80070005`; an admin query returns `0x80070424` for a missing service or
`0x80070426` when it is disabled or its configured process is absent. This is a
static access view, without Windows token elevation or RPC security evaluation.
Read commands do not resolve names or contact NTP servers. `/resync`, `/config`,
`/register`, `/unregister`, remote targets, and `/stripchart` return 87 without
host or network effects. See [the time persona example](examples/time-persona.json).
Configuration and verbose status output include only modeled fields. Other
Windows Time APIs and changes remain separate coverage gaps.

Guest `nslookup.exe` calls the emulated `DnsQuery_W` API. The same offline record
catalog supplies `DnsQuery_A`, `DnsQuery_UTF8`, and known-name `gethostbyname`
answers. Local hostname/FQDN A records, the persona IPv4 reverse record, and
domain-controller A/PTR records derive from persona identity. Up to 64 additional
`dns_records` entries can supply A, AAAA, and PTR answers; contradictory identity
records and duplicate records are rejected. A record has `name`, `type`, `data`,
and `ttl` fields (TTL is 0–604800 seconds). DNS names are ASCII, case-insensitive,
and may have a trailing dot. Internationalized names are not modeled.
The catalog also includes localhost A/PTR records for 127.0.0.1 unless the
persona uses `localhost` as its own hostname.

Guest `ping.exe` calls the emulated synchronous `IcmpSendEcho` API through
process-owned `IcmpCreateFile`/`IcmpCloseHandle` handles. The same hooks are
available to other guest programs through `iphlpapi.dll` and `icmp.dll`.
Replies echo at most 4096 bytes into checked guest memory, with native x86
and x64 reply structures. Up to 128 handles can be open across guest processes;
process exit releases its handles. Asynchronous echo APIs and ICMPv6 are not
modeled. Only a plain TTL request option is accepted. Configured intermediate
hops return native reply structures with `IP_TTL_EXPIRED_TRANSIT` (11013),
the router's IPv4 address and reply TTL, and zero data size/pointer. Other
ICMP error types and fragmentation are not simulated.

The guest's own IPv4 address and loopback addresses reply with zero RTT and
TTL 128. Other addresses time out unless configured in `icmp_responses`, a
list of at most 64 unique records with these required fields:

```json
{"address": "203.0.113.5", "round_trip_ms": 12, "ttl": 57}
```

RTT must be 0–60000 milliseconds and TTL 1–255. Optional `responds` is a boolean
(default true); false makes the destination silent. Optional `hops` contains
up to 254 intermediate hop records with the same three required fields, or
null for a silent hop. Intermediate addresses cannot be the destination or
guest-owned, loopback, broadcast, multicast, or unspecified addresses. Repeated
router addresses are allowed. Hop RTTs need not be monotonic. Hop fixtures
describe TTL-expired replies; they do not implicitly enable direct echo replies
to those router addresses. See [the route persona](examples/route-persona.json).
An omitted or empty hop list models a direct simulated reply at TTL 1; supply
intermediates to describe the desired routed topology.

Fixtures cannot replace
guest-owned or loopback replies, or target unspecified, multicast, limited
broadcast, or the guest subnet's directed broadcast address. A fixture whose
RTT exceeds the caller's timeout also times out. DNS names must separately
resolve through the guest catalog. Replies, timeouts, and the utility's
between-request waits advance virtual time. They never sleep on the host,
open a socket, or use the host resolver or network broker. Attempts appear
as `guest_icmp_echo` events in the report and dashboard network timeline,
including status, timeout, payload hash when valid, and `network_used: false`.
The utility accepts `/` aliases for the listed flags and exits 0 if at least
one timely reply arrives, or 1 if none arrives. Missing DNS names exit 1;
duplicate flags, unsupported flags, and out-of-range arguments exit 87.
TTL-expired replies count as received packets in `ping.exe`, but do not enter
its successful-echo RTT statistics or establish destination reachability.

Guest `tracert.exe` defaults to 30 hops and a 4000 ms timeout per probe. It
increments request TTL from 1, sends three probes per hop, and stops after
the destination replies or the hop limit is reached. Silent/late hops display
asterisks. Names come only from offline A/PTR queries; `-d` suppresses PTR
queries, while `-4`, `/4`, and slash aliases of the supported flags are accepted.
It exits 0 when a resolved target's bounded trace finishes, including a hop-limit
finish with no destination reply; exit 0 is not evidence of reachability.
Name resolution and modeled API failures exit 1; invalid/unsupported arguments
exit 87. Traceroute uses no raw socket, resolver, or host executable. Its ICMP
events include destination, requested TTL, status, and responding router address,
and advance only virtual time. The generated x86/x64 PEs are built with
[`tools/build_guest_tracert.ps1`](tools/build_guest_tracert.ps1).

Guest `pathping.exe` discovers up to 30 hops by default, retrying a silent hop
up to three times. It then sends 100 echo requests to each discovered address.
The supported case-sensitive switches accept `-` or `/`: `n` disables PTR
lookups, `4` selects IPv4, `h` accepts 1..255, `q` accepts 1..1000 queries,
and `p` and `w` accept 0..60000 milliseconds (defaults 250 and 3000).
No arguments or `/?` prints help. Unsupported forms exit 87, name/API failures
exit 1, and a completed bounded trace exits 0 regardless of reachability.

An ICMP destination fixture can optionally supply `reply_pattern`, a nonempty
list of at most 1024 booleans. Valid destination echo probes cycle through
this pattern in order, independently per process and address. False entries
time out; true entries still obey `responds` and the configured RTT/timeout.
TTL-expired hop responses do not consume the destination's pattern. Patterns
also affect `ping.exe` and `tracert.exe` destination probes. Process exit clears
the counters. Set separate `icmp_responses` entries for discovered routers to
control their echo responses: a TTL-expired router fixture does not itself
enable direct pings to that router.

Pathping's Source to Here loss and RTT come from its actual modeled echo
results. Its This Node/Link columns infer sustained downstream loss using
suffix minima of measured loss counts, and local loss from the remainder.
Unknown hops leave affected link estimates unknown. These estimates cannot
establish a physical link fault or correlated packet forwarding behavior.
The model schedules probes sequentially and advances virtual time for replies,
timeouts, and `p`; it does not reproduce Windows' parallel timing. Large query
sets can exhaust the existing instruction, time, or trace budgets and are
reported as incomplete. The PowerShell bridge allows 60 seconds and ten
million instructions for pathping; network observations beyond 2048 are
explicitly flagged as truncated. No host wait, executable, DNS resolver, or
socket is used. See [the loss persona](examples/loss-persona.json) and
[`tools/build_guest_pathping.ps1`](tools/build_guest_pathping.ps1).

The utility supports `nslookup <name>`, `-type=A`, `-type=AAAA`, `-type=PTR`, and
IPv4 reverse lookups. An explicit server must be the configured primary guest
DNS IPv4 address; other servers exit 87. It prints the configured server address
with the display name `UnKnown`; server-name discovery is not simulated. No
interactive prompt, search-list expansion, or default combined A/AAAA query is
implemented. Missing names and missing record types fail with exit code 1.

`DnsQuery_*` logs success, missing records, unsupported flags/server arrays, and
invalid inputs as `guest_dns_query` events. Query records and their linked string
data live in bounded, process-owned guest memory; `DnsFree`/`DnsRecordListFree`
and process exit release owned responses. Queries never call the host resolver,
create sockets, or contact the network broker. The normal report and dashboard
network timeline include the query, status, answers, and `network_used: false`.
Legacy `gethostbyname` gives known persona names precedence over its existing
optional network broker; only its first A record is returned. Other names keep
the existing broker policy. Other resolver APIs remain separate coverage gaps.

```json
{"dns_records": [
  {"name": "files.corp.example", "type": "A", "data": "192.168.1.20", "ttl": 300},
  {"name": "ipv6.corp.example", "type": "AAAA", "data": "2001:db8::20", "ttl": 300}
]}
```

Generated `auditpol.exe` renders nine categories and 59 Windows 11 audit
subcategories, including their SDK GUIDs. `audit_policy.subcategories` maps
English names to `No Auditing`, `Success`, `Failure`, or `Success and Failure`;
omitted names use `No Auditing`. This is an explicit guest snapshot, not a claim
about the default policy of every Windows edition. `audit_policy.read_allowed`
defaults to false; system-policy queries return access denied and exit code 5
unless this flag or the persona admin flag is set. Category and subcategory
names can be listed without that grant. This permission view does not evaluate
Windows policy security descriptors or current-token elevation. Text and CSV
derive from the same snapshot; host policy is never read. Names are English,
and policy mutation, per-user policy, SACLs, and security descriptors remain
separate coverage gaps.

Guest `AuditQuerySystemPolicy` returns the same settings as contiguous
`AUDIT_POLICY_INFORMATION` records, in the requested GUID order. Guest
`AuditEnumerateCategories`, `AuditEnumerateSubCategories`, ANSI/Unicode
category/subcategory name lookup, and category GUID/ID conversion share the
same category catalog. These APIs use the same static read-permission view as
the command. Responses are bounded, allocated in guest memory, owned by the
requesting guest process, and released by `AuditFree` or process exit. Invalid
or foreign pointers cannot release another guest process's response. The
current model rejects `AuditSetSystemPolicy` with `ERROR_NOT_SUPPORTED`.

Build and run the harmless x86/x64 API fixtures with:

```powershell
.\tools\build_audit_api_probe.ps1
.venv\Scripts\python.exe -m tools.verify_audit_api
```

The verifier uses CPU emulation for both direct and child execution and saves
evidence under `output/audit-api-verification`. Fixture executables are never
started as host processes. See Microsoft's [policy query API](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-auditquerysystempolicy)
and [policy record layout](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-audit_policy_information).

For example:

```json
{"audit_policy": {"read_allowed": true, "subcategories": {
  "Logon": "Success and Failure", "Process Creation": "Success"
}}}
```

The included `wmic.exe` is a guest PE, despite Microsoft's deprecation and
removal of the original tool from newer Windows installations. It reads guest
Win32/NTDLL, registry, and workstation APIs at invocation time. Modeled fields:

- `os`: `BuildNumber`, `CSName`, `FreePhysicalMemory`, `TotalVisibleMemorySize`,
  `Version`, `WindowsDirectory` (memory values are KiB).
- `computersystem`: `Domain`, `Name`, `NumberOfLogicalProcessors`,
  `TotalPhysicalMemory`, `UserName` (physical memory is bytes).
- `cpu`: `Name`, `NumberOfLogicalProcessors`.
- `logicaldisk`: `DeviceID`, `FileSystem`, `FreeSpace`, `Name`, `Size`
  (the single modeled C: volume, with capacity in bytes).

Omitting properties lists only those modeled fields; it does not imply full WMI
class coverage. Comma-separated selection, spaces around commas, case-insensitive
names, and the equivalent `path Win32_OperatingSystem`, `Win32_ComputerSystem`,
`Win32_Processor`, and `Win32_LogicalDisk` forms are supported. Other properties,
remote switches, output files, filters, and mutations fail before reading data.
Its console uses guest Unicode output; it does not reproduce Microsoft's original
WMIC encoding conventions for every redirection or pipe. It never opens a host
WMI connection. Guest WMI COM providers remain an independent coverage gap.
The same verified guest image is available at both
`C:\Windows\System32\wmic.exe` and `C:\Windows\System32\Wbem\wmic.exe`.

Generated `wbadmin.exe get versions` lists the persona's `backup_versions`
metadata, without opening backup targets. Creation times produce a UTC version
identifier and a display time using the persona's UTC offset. An admin persona
can view the catalog; a non-admin persona receives access denied and exit code
5 without catalog details. The default catalog is empty, and an admin guest's
empty listing succeeds. This is a static permission view rather than a live
elevation or Backup Operators model. Remote filters and backup changes exit 87.

Generated `klist.exe` reads the persona's `kerberos` current logon ID and
bounded ticket metadata. The same server, realm, times, encryption type, and
flags populate the current-session `KerbQueryTicketCacheMessage` response
through guest LSA. The default cache is empty. Client names come from the
persona user, and output times use its UTC offset. Ticket requests and purge
commands exit 87 without contacting an authentication server. LSA packages
other than Kerberos, cache query variants, other logon IDs, and usable ticket
or key material remain unsupported.

Generated `nltest.exe` reads only the persona's `domain_discovery` controller,
site, forest, GUID, and directional trust metadata for its configured joined
domain. It performs no DNS lookup or domain-server connection. Missing guest
controller data returns `ERROR_NO_SUCH_DOMAIN` and exit code 1355; the default
workgroup guest has no controllers or trusts. Windows domain APIs, secure
channels, other targets, and discovery flags remain unmodeled.
See [the domain persona example](examples/domain-persona.json) for the record
format; its addresses and names are guest metadata and are never contacted.

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
inventory. The separate `powershell` CLI accepts submitted scripts in Docker
Desktop's offline Linux VM. Its required utility bridge runs these same
persona-backed x64 Windows PEs inside that guest. The native PE child loader
still rejects managed PEs and does not launch this PowerShell mode itself.
The dashboard displays instrumented-engine evaluated parameters and external
native exec argument records. General Windows APIs/providers, shared mutable
Windows state, and complete command capture remain incomplete. Source text or
static deobfuscation alone cannot establish which command ran. No entry in
this file authorizes a guest command to execute on the host. See
[COVERAGE_AND_SAFETY.md](COVERAGE_AND_SAFETY.md) for tested paths and
containment limits. The required execution and command-capture gates are
tracked in [POWERSHELL_CONFINEMENT.md](POWERSHELL_CONFINEMENT.md).

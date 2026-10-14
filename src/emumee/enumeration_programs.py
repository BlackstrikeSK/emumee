"""Persona-owned console PEs for common Windows enumeration commands.

These images contain only guest instructions, imports, and text derived from
the selected persona. No host executable or host identity is copied into them.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import struct
from importlib.resources import files

from .clock import VirtualClock
from .persona_content import PROCESS_PATHS, oem_code_page
from .tokens import GuestTokens, PRIVILEGE_DESCRIPTIONS, PRIVILEGE_NAMES


_MAX_TEXT = 64 * 1024


def _align(value: int, boundary: int) -> int:
    return (value + boundary - 1) // boundary * boundary


def enumeration_text(name: str, persona: dict, arguments: str = "") -> str:
    """Render one supported command view from the persona snapshot."""
    if name == "cmdkey.exe":
        if not arguments:
            return "Usage: cmdkey /list\r\n"
        if arguments.casefold() != "/list":
            raise ValueError("unsupported cmdkey arguments")
        credentials = persona["stored_credentials"]
        if not credentials:
            return "\r\nCurrently stored credentials:\r\n\r\n* NONE *\r\n"
        rows = ["\r\nCurrently stored credentials:\r\n"]
        for credential in credentials:
            rows.append(f"    Target: {credential['target']}\r\n"
                        f"    Type: {credential['type']}\r\n"
                        f"    User: {credential['user']}\r\n"
                        f"    {credential['persistence']} persistence\r\n")
        return "\r\n".join(rows)
    if name == "manage-bde.exe":
        if not arguments:
            return "Usage: manage-bde -status [C:]\r\n"
        if arguments.casefold() not in {"-status", "-status c:"}:
            raise ValueError("unsupported manage-bde arguments")
        bitlocker = persona["bitlocker"]
        encrypted = bitlocker["encryption_method"] != "None"
        protectors = "\r\n".join("        " + value for value in bitlocker["key_protectors"]) or "        None Found"
        return ("BitLocker Drive Encryption: Configuration Tool\r\n\r\n"
                "Volume C: [Windows]\r\n[OS Volume]\r\n\r\n"
                f"    Size:                 {persona['volume_capacity_bytes'] / 1024 ** 3:.2f} GB\r\n"
                f"    BitLocker Version:    {'2.0' if encrypted else 'None'}\r\n"
                f"    Conversion Status:    {'Fully Encrypted' if encrypted else 'Fully Decrypted'}\r\n"
                f"    Percentage Encrypted: {'100.0' if encrypted else '0.0'}%\r\n"
                f"    Encryption Method:    {bitlocker['encryption_method']}\r\n"
                f"    Protection Status:    Protection {'On' if bitlocker['protection_enabled'] else 'Off'}\r\n"
                "    Lock Status:          Unlocked\r\n"
                f"    Key Protectors:\r\n{protectors}\r\n")
    if name in {"quser.exe", "qwinsta.exe"}:
        if arguments:
            raise ValueError("unsupported session query arguments")
        return enumeration_text("query.exe", persona,
                                "user" if name == "quser.exe" else "session")
    if name in {"net.exe", "net1.exe"}:
        if not arguments:
            return "The syntax of this command is:\r\nNET USER | NET LOCALGROUP\r\n"
        argument = arguments.casefold()
        heading = f"\\\\{persona['hostname']}\r\n\r\n"
        if argument == "user":
            account_names = {name.casefold(): name for name in
                             ("Administrator", "Guest", persona["user_name"])}
            users = sorted(account_names.values(), key=str.casefold)
            return (f"User accounts for {heading}"
                    "-------------------------------------------------------------------------------\r\n"
                    + "  ".join(users) + "\r\n"
                    "The command completed successfully.\r\n")
        if argument == f"user {persona['user_name'].casefold()}":
            memberships = "*Users"
            if persona["user_is_admin"]:
                memberships += "  *Administrators"
            return (f"User name                    {persona['user_name']}\r\n"
                    "Account active               Yes\r\n"
                    f"Local Group Memberships      {memberships}\r\n"
                    "The command completed successfully.\r\n")
        if argument == "localgroup":
            return (f"Aliases for {heading}"
                    "-------------------------------------------------------------------------------\r\n"
                    "*Administrators\r\n*Users\r\n"
                    "The command completed successfully.\r\n")
        if argument in {"localgroup administrators", "localgroup users"}:
            admin_group = argument.endswith("administrators")
            group = "Administrators" if admin_group else "Users"
            members = (["Administrator"] if admin_group and
                       persona["user_name"].casefold() != "administrator" else [])
            if not admin_group or persona["user_is_admin"]:
                members.append(persona["user_name"])
            members = sorted(set(members), key=str.casefold)
            return (f"Alias name     {group}\r\n"
                    f"Comment        Local {group} group\r\n\r\n"
                    "Members\r\n\r\n"
                    "-------------------------------------------------------------------------------\r\n"
                    + "\r\n".join(members) + "\r\n"
                    "The command completed successfully.\r\n")
        raise ValueError("unsupported net arguments")
    if name == "whoami.exe":
        identity = f"{persona['hostname']}\\{persona['user_name']}"
        if not arguments:
            return identity
        argument = arguments.casefold()
        if argument not in {"/user", "/groups", "/priv", "/all"}:
            raise ValueError("unsupported whoami arguments")
        tokens = GuestTokens(persona)
        user = ("\r\nUSER INFORMATION\r\n"
                "----------------\r\n"
                "User Name                 SID\r\n"
                "========================= =============================================\r\n"
                f"{identity:25} {persona['user_sid']}\r\n")
        if argument == "/user":
            return user
        rows = []
        for sid, encoded in zip(tokens.group_sids, tokens.groups, strict=True):
            group_name, domain, _ = tokens.sid_names[encoded]
            group = f"{domain}\\{group_name}" if domain else group_name
            rows.append(f"{group:32} {sid}\r\n")
        groups = ("\r\nGROUP INFORMATION\r\n"
                  "-----------------\r\n"
                  "Group Name                       SID\r\n"
                  "================================ =============================================\r\n"
                  + "".join(rows))
        if argument == "/groups":
            return groups
        privilege_rows = "".join(
            f"{PRIVILEGE_NAMES[luid]:35} {PRIVILEGE_DESCRIPTIONS[luid]:44} "
            f"{'Enabled' if flags & 2 else 'Disabled'}\r\n"
            for luid, flags in tokens.privileges)
        privileges = ("\r\nPRIVILEGES INFORMATION\r\n"
                      "----------------------\r\n"
                      "Privilege Name                      Description                                  State\r\n"
                      "=================================== ============================================ ========\r\n"
                      + privilege_rows)
        if argument == "/priv":
            return privileges
        return (user + groups + privileges +
                "\r\nUSER CLAIMS INFORMATION\r\n"
                "-----------------------\r\n"
                "User claims are not present.\r\n")
    if name == "ipconfig.exe":
        adapter = persona["network_adapter"]
        mask = ipaddress.IPv4Network(
            (adapter["ipv4"], adapter["prefix_length"]), strict=False).netmask
        suffix = "" if persona["domain"] == "WORKGROUP" else persona["domain"]
        basic = ("\r\nWindows IP Configuration\r\n\r\n"
                f"Ethernet adapter {adapter['name']}:\r\n\r\n"
                f"   Connection-specific DNS Suffix  . : {suffix}\r\n"
                f"   IPv4 Address. . . . . . . . . . . : {adapter['ipv4']}\r\n"
                f"   Subnet Mask . . . . . . . . . . . : {mask}\r\n"
                f"   Default Gateway . . . . . . . . : {adapter['gateway']}\r\n")
        if not arguments:
            return basic
        if arguments.casefold() == "/all":
            dns = "\r\n".join(
                f"   DNS Servers . . . . . . . . . . : {server}" if index == 0
                else f"                                       {server}"
                for index, server in enumerate(adapter["dns_servers"]))
            return ("\r\nWindows IP Configuration\r\n\r\n"
                    f"   Host Name . . . . . . . . . . . : {persona['hostname']}\r\n"
                    f"   Primary Dns Suffix  . . . . . . : {suffix}\r\n\r\n"
                    f"Ethernet adapter {adapter['name']}:\r\n\r\n"
                    f"   Description . . . . . . . . . . : {adapter['description']}\r\n"
                    f"   Physical Address. . . . . . . . : {adapter['mac']}\r\n"
                    f"   DHCP Enabled. . . . . . . . . . : {'Yes' if adapter['dhcp_enabled'] else 'No'}\r\n"
                    f"   Connection-specific DNS Suffix  . : {suffix}\r\n"
                    f"   IPv4 Address. . . . . . . . . . . : {adapter['ipv4']}\r\n"
                    f"   Subnet Mask . . . . . . . . . . . : {mask}\r\n"
                    f"   Default Gateway . . . . . . . . : {adapter['gateway']}\r\n"
                    f"{dns}\r\n")
        raise ValueError("unsupported ipconfig arguments")
    if name == "getmac.exe" and not arguments:
        adapter = persona["network_adapter"]
        return ("\r\nPhysical Address    Transport Name\r\n"
                "=================== ==========================================================\r\n"
                f"{adapter['mac']:19} \\Device\\Tcpip_{adapter['guid']}\r\n")
    if name == "arp.exe":
        if not arguments:
            return "Displays and modifies the IP-to-physical address translation tables.\r\nUsage: arp -a\r\n"
        if arguments.casefold() != "-a":
            raise ValueError("unsupported arp arguments")
        adapter = persona["network_adapter"]
        if adapter["prefix_length"] >= 31:
            return "No ARP Entries Found.\r\n"
        subnet = ipaddress.IPv4Network(
            (adapter["ipv4"], adapter["prefix_length"]), strict=False)
        return (f"\r\nInterface: {adapter['ipv4']} --- 0x{adapter['if_index']:x}\r\n"
                "  Internet Address      Physical Address      Type\r\n"
                f"  {str(subnet.broadcast_address):<21} ff-ff-ff-ff-ff-ff     static\r\n")
    if name == "route.exe":
        if not arguments:
            return "Manipulates network routing tables.\r\nUsage: route print\r\n"
        if arguments.casefold() not in {"print", "print -4"}:
            raise ValueError("unsupported route arguments")
        adapter = persona["network_adapter"]
        subnet = ipaddress.IPv4Network(
            (adapter["ipv4"], adapter["prefix_length"]), strict=False)
        mac = adapter["mac"].replace("-", " ").lower()
        rows = (
            ("0.0.0.0", "0.0.0.0", adapter["gateway"], adapter["ipv4"]),
            (str(subnet.network_address), str(subnet.netmask), "On-link", adapter["ipv4"]),
            (adapter["ipv4"], "255.255.255.255", "On-link", adapter["ipv4"]),
        )
        table = "".join(f"{dest:>20} {mask:>20} {gateway:>20} {interface:>20}     25\r\n"
                        for dest, mask, gateway, interface in rows)
        return ("===========================================================================\r\n"
                "Interface List\r\n"
                f" {adapter['if_index']:2}...{mac} ......{adapter['description']}\r\n"
                "===========================================================================\r\n"
                "IPv4 Route Table\r\n"
                "===========================================================================\r\n"
                "Active Routes:\r\n"
                "Network Destination        Netmask          Gateway       Interface  Metric\r\n"
                f"{table}"
                "===========================================================================\r\n")
    if name == "netsh.exe":
        if not arguments:
            return "Network Shell\r\nUsage: netsh interface ipv4 show config\r\n"
        adapter = persona["network_adapter"]
        if arguments.casefold() == "interface ipv4 show config":
            mask = ipaddress.IPv4Network(
                (adapter["ipv4"], adapter["prefix_length"]), strict=False).netmask
            dns = "".join(f"    {server}\r\n" for server in adapter["dns_servers"])
            return (f"Configuration for interface \"{adapter['name']}\"\r\n"
                    f"    DHCP enabled:                         {'Yes' if adapter['dhcp_enabled'] else 'No'}\r\n"
                    f"    IP Address:                           {adapter['ipv4']}\r\n"
                    f"    Subnet Prefix:                        {adapter['ipv4']}/{adapter['prefix_length']} (mask {mask})\r\n"
                    f"    Default Gateway:                      {adapter['gateway']}\r\n"
                    f"    DNS servers configured:               \r\n{dns}")
        if arguments.casefold() == "interface ipv4 show dnsservers":
            dns = "".join(f"    {server}\r\n" for server in adapter["dns_servers"])
            return (f"Configuration for interface \"{adapter['name']}\"\r\n"
                    f"    DNS servers configured:               \r\n{dns}")
        raise ValueError("unsupported netsh arguments")
    if name == "tzutil.exe":
        if not arguments:
            return "Displays or configures the system time zone.\r\nUsage: tzutil /g\r\n"
        if arguments.casefold() == "/g":
            return persona["timezone"] + "_dstoff\r\n"
        raise ValueError("unsupported tzutil arguments")
    if name == "mountvol.exe":
        volume = "\\\\?\\Volume" + persona["volume_guid"] + "\\"
        if not arguments:
            return f"Possible values for VolumeName along with current mount points are:\r\n\r\n    {volume}\r\n        C:\\\r\n"
        if arguments.casefold() in {"c: /l", "c:\\ /l"}:
            return volume + "\r\n"
        raise ValueError("unsupported mountvol arguments")
    if name == "vssadmin.exe":
        argument = arguments.casefold()
        heading = "Volume Shadow Copy Service administrative command-line tool\r\n\r\n"
        volume = "\\\\?\\Volume" + persona["volume_guid"] + "\\"
        if not argument:
            return heading + "Usage: vssadmin list shadows | list volumes | list providers\r\n"
        if argument in {"list shadows", "list shadows /for=c:",
                        "list shadows /for=c:\\"}:
            shadows = persona["shadow_copies"]
            if not shadows:
                return heading + "No items found that satisfy the query.\r\n"
            groups: dict[str, list[tuple[int, dict]]] = {}
            for index, shadow in enumerate(shadows, 1):
                groups.setdefault(shadow["set_id"].casefold(), []).append((index, shadow))
            rows = []
            for entries in groups.values():
                first = entries[0][1]
                set_id = first["set_id"]
                created = dt.datetime.strptime(first["created_utc"],
                                               "%Y-%m-%dT%H:%M:%SZ")
                created += dt.timedelta(minutes=persona["utc_offset_minutes"])
                stamp = created.strftime("%m/%d/%Y %I:%M:%S %p")
                rows.append(f"Contents of shadow copy set ID: {set_id}\r\n"
                            f"   Contained {len(entries)} shadow copies at creation time: {stamp}\r\n")
                for index, shadow in entries:
                    rows.append(f"      Shadow Copy ID: {shadow['id']}\r\n"
                                f"         Original Volume: (C:)\\\\?\\Volume{persona['volume_guid']}\\\r\n"
                                f"         Shadow Copy Volume: \\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy{index}\r\n"
                                f"         Originating Machine: {persona['hostname']}\r\n"
                                f"         Service Machine: {persona['hostname']}\r\n"
                                "         Provider: 'Microsoft Software Shadow Copy provider 1.0'\r\n"
                                "         Type: ClientAccessible\r\n")
            return heading + "\r\n".join(rows) + "\r\n"
        if argument == "list volumes":
            return (heading + "Volume path: C:\\\r\n"
                    f"Volume name: {volume}\r\n")
        if argument == "list providers":
            return (heading + "Provider name: 'Microsoft Software Shadow Copy provider 1.0'\r\n"
                    "   Provider type: System\r\n"
                    "   Provider Id: {b5946137-7b9f-4925-af80-51abd60b20d5}\r\n")
        raise ValueError("unsupported vssadmin arguments")
    if name == "fltmc.exe":
        argument = arguments.casefold()
        filters = persona["minifilters"]
        if argument in {"", "filters"}:
            lines = ["Filter Name                     Num Instances    Altitude    Frame",
                     "------------------------------  -------------  ----------  -----"]
            lines.extend(f"{item['name']:<30}  {item['instances']:<13}  "
                         f"{item['altitude']:<10}  0" for item in filters)
            return "\r\n".join(lines) + "\r\n"
        if argument == "instances":
            lines = ["Instance Name                   Altitude    Volume Name",
                     "------------------------------  ----------  -----------"]
            for item in filters:
                for index in range(item["instances"]):
                    instance = item["name"] + " Instance" + (
                        f" {index + 1}" if item["instances"] > 1 else "")
                    lines.append(f"{instance:<30}  {item['altitude']:<10}  C:\\")
            return "\r\n".join(lines) + "\r\n"
        if argument == "volumes":
            volume = "\\\\?\\Volume" + persona["volume_guid"] + "\\"
            return ("Volume Name                                      Dos Name  File System\r\n"
                    "-----------------------------------------------  --------  -----------\r\n"
                    f"{volume:<47}  C:\\       NTFS\r\n")
        raise ValueError("unsupported fltmc arguments")
    if name == "pnputil.exe":
        argument = arguments.casefold()
        if not argument:
            return ("Microsoft PnP Utility\r\n\r\n"
                    "Usage: pnputil /enum-drivers | /enum-devices | /enum-classes\r\n")
        if argument in {"/enum-drivers", "-e"}:
            rows = ["Microsoft PnP Utility\r\n"]
            for package in persona["driver_packages"]:
                rows.append(
                    f"Published Name:     {package['published_name']}\r\n"
                    f"Original Name:      {package['original_name']}\r\n"
                    f"Provider Name:      {package['provider']}\r\n"
                    f"Class Name:         {package['class_name']}\r\n"
                    f"Class GUID:         {package['class_guid']}\r\n"
                    f"Driver Version:     {package['version']}\r\n"
                    f"Signer Name:        {package['signer']}\r\n")
            return "\r\n".join(rows) + "\r\n"
        if argument in {"/enum-devices", "/enum-devices /connected"}:
            devices = persona["pnp_devices"]
            if argument.endswith("/connected"):
                devices = [device for device in devices
                           if device["status"] != "Disconnected"]
            rows = ["Microsoft PnP Utility\r\n"]
            for device in devices:
                rows.append(
                    f"Instance ID:         {device['instance_id']}\r\n"
                    f"Device Description:  {device['description']}\r\n"
                    f"Class Name:          {device['class_name']}\r\n"
                    f"Class GUID:          {device['class_guid']}\r\n"
                    f"Status:              {device['status']}\r\n"
                    f"Driver Name:         {device['driver'] or 'N/A'}\r\n")
            return "\r\n".join(rows) + "\r\n"
        if argument == "/enum-classes":
            rows = ["Microsoft PnP Utility\r\n"]
            classes: dict[str, tuple[str, str, int]] = {}
            for device in persona["pnp_devices"]:
                key = device["class_guid"].casefold()
                name, guid, count = classes.get(key,
                                                (device["class_name"], device["class_guid"], 0))
                classes[key] = (name, guid, count + 1)
            for name, guid, count in classes.values():
                rows.append(f"Class Name:         {name}\r\n"
                            f"Class GUID:         {guid}\r\n"
                            f"Device Count:       {count}\r\n")
            return "\r\n".join(rows) + "\r\n"
        raise ValueError("unsupported pnputil arguments")
    if name == "gpresult.exe":
        argument = arguments.casefold()
        if not argument:
            return ("Microsoft (R) Windows (R) Operating System Group Policy Result tool\r\n"
                    "Usage: gpresult /r [/scope user | /scope computer]\r\n")
        scopes = {"/r": ("computer", "user"),
                  "/scope user /r": ("user",),
                  "/r /scope user": ("user",),
                  "/scope computer /r": ("computer",),
                  "/r /scope computer": ("computer",)}.get(argument)
        if scopes is None:
            raise ValueError("unsupported gpresult arguments")
        hostname = persona["hostname"]
        user = persona["user_name"]
        rows = ["Microsoft (R) Windows (R) Operating System Group Policy Result tool",
                f"RSOP data for {hostname}\\{user} on {hostname} : Logging Mode", ""]
        for scope in scopes:
            target = hostname if scope == "computer" else f"{hostname}\\{user}"
            rows.extend((f"{scope.upper()} SETTINGS", "-----------------",
                         f"Applied Group Policy Objects for {target}",
                         "-------------------------------------------"))
            names = persona["group_policy"][scope]
            rows.extend(f"    {name}" for name in names)
            if not names:
                rows.append("    N/A")
            rows.append("")
        return "\r\n".join(rows) + "\r\n"
    if name == "dsregcmd.exe":
        if not arguments:
            return "Usage: dsregcmd /status\r\n"
        if arguments.casefold() != "/status":
            raise ValueError("unsupported dsregcmd arguments")
        state = persona["device_registration"]
        def yes_no(value: bool) -> str:
            return "YES" if value else "NO"
        rows = ["+----------------------------------------------------------------------+",
                "| Device State                                                         |",
                "+----------------------------------------------------------------------+",
                f"             AzureAdJoined : {yes_no(state['azure_ad_joined'])}",
                f"          EnterpriseJoined : {yes_no(state['enterprise_joined'])}",
                f"              DomainJoined : {yes_no(state['domain_joined'])}"]
        if state["domain_joined"]:
            rows.append(f"                DomainName : {persona['domain']}")
        rows.extend(("", "+----------------------------------------------------------------------+",
                     "| User State                                                           |",
                     "+----------------------------------------------------------------------+",
                     f"           WorkplaceJoined : {yes_no(state['workplace_joined'])}",
                     "", "+----------------------------------------------------------------------+",
                     "| SSO State                                                            |",
                     "+----------------------------------------------------------------------+",
                     f"                AzureAdPrt : {yes_no(state['azure_ad_prt'])}"))
        return "\r\n".join(rows) + "\r\n"
    if name == "bcdedit.exe":
        argument = arguments.casefold()
        if argument not in {"", "/enum", "/enum active", "/v",
                            "/enum active /v", "/enum {current}"}:
            raise ValueError("unsupported bcdedit arguments")
        boot = persona["boot_config"]
        verbose = argument in {"/v", "/enum active /v"}
        loader_id = boot["loader_guid"] if verbose else "{current}"
        manager_id = ("{9dea862c-5cdd-4e70-acc1-f32b344d4795}" if verbose
                      else "{bootmgr}")
        manager = ("Windows Boot Manager\r\n--------------------\r\n"
                   f"identifier              {manager_id}\r\n"
                   "device                  partition=C:\r\n"
                   "description             Windows Boot Manager\r\n"
                   f"locale                  {persona['locale']}\r\n"
                   f"default                 {loader_id}\r\n"
                   f"displayorder            {loader_id}\r\n"
                   f"timeout                 {boot['timeout_seconds']}\r\n")
        loader = ("Windows Boot Loader\r\n-------------------\r\n"
                  f"identifier              {loader_id}\r\n"
                  "device                  partition=C:\r\n"
                  "path                    \\Windows\\system32\\winload.efi\r\n"
                  f"description             {boot['description']}\r\n"
                  f"locale                  {persona['locale']}\r\n"
                  "osdevice                partition=C:\r\n"
                  "systemroot              \\Windows\r\n"
                  "nx                      OptIn\r\n")
        if boot["hypervisor_launch_type"] is not None:
            loader += f"hypervisorlaunchtype    {boot['hypervisor_launch_type']}\r\n"
        if boot["debug"]:
            loader += "debug                   Yes\r\n"
        if boot["safe_boot"] is not None:
            loader += f"safeboot                {boot['safe_boot']}\r\n"
        if argument == "/enum {current}":
            return loader
        return manager + "\r\n" + loader
    if name == "driverquery.exe":
        argument = arguments.casefold()
        if argument not in {"", "/v", "/fo list", "/fo csv", "/nh"}:
            raise ValueError("unsupported driverquery arguments")
        drivers = persona["drivers"]
        if argument == "/fo list" or argument == "/v":
            return ("".join(
                f"Module Name: {driver['name']}\r\n"
                f"Display Name: {driver['display_name']}\r\n"
                f"Driver Type: {'Kernel' if driver['type'] == 1 else 'File System'}\r\n"
                f"Start Mode: {driver['start']}\r\n"
                f"State: {'Running' if driver['running'] else 'Stopped'}\r\n"
                + (f"Path: C:\\Windows\\{driver['path']}\r\n" if argument == "/v" else "")
                + "\r\n" for driver in drivers) or "INFO: No drivers found.\r\n")
        if argument == "/fo csv":
            def csv(value: str) -> str:
                return '"' + value.replace('"', '""') + '"'

            rows = ['"Module Name","Display Name","Driver Type","State"']
            rows.extend(",".join(map(csv, (driver["name"], driver["display_name"],
                                         "Kernel" if driver["type"] == 1 else "File System",
                                         "Running" if driver["running"] else "Stopped")))
                        for driver in drivers)
            return "\r\n".join(rows) + "\r\n"
        rows = [] if argument == "/nh" else [
            "Module Name          Display Name                             Driver Type     State",
            "==================== ======================================== =============== ======="]
        rows.extend(f"{driver['name'][:20]:20} {driver['display_name'][:40]:40} "
                    f"{'Kernel' if driver['type'] == 1 else 'File System':15} "
                    f"{'Running' if driver['running'] else 'Stopped'}"
                    for driver in drivers)
        return "\r\n".join(rows) + "\r\n"
    if name == "systeminfo.exe":
        cpu = persona["cpu"]
        return (f"Host Name:                 {persona['hostname']}\r\n"
                "OS Name:                   Microsoft Windows 11 Pro\r\n"
                f"OS Version:                10.0.{persona['windows_build']}\r\n"
                f"Registered Owner:          {persona['user_name']}\r\n"
                f"System Locale:             {persona['locale']}\r\n"
                f"Time Zone:                 {persona['timezone']}\r\n"
                f"Total Physical Memory:     {persona['physical_memory_mb']:,} MB\r\n"
                f"Available Physical Memory: {persona['available_memory_mb']:,} MB\r\n"
                f"Processor(s):              {cpu['cores'] * cpu['threads_per_core']} logical processors\r\n"
                f"                           {cpu['brand']}\r\n")
    if name == "tasklist.exe":
        if arguments and arguments.casefold() != "/svc":
            raise ValueError("unsupported tasklist arguments")
        if arguments:
            lines = ["Image Name                     PID Services",
                     "========================= ======== ============================================"]
            process_names = [process.casefold() for process in persona["processes"]]
            services_by_index: dict[int, list[str]] = {}
            for service in persona["services"]:
                if service["start"] == 4:
                    continue
                try:
                    index = process_names.index(service["process"].casefold())
                except ValueError:
                    continue
                services_by_index.setdefault(index, []).append(service["name"])
            for index, process in enumerate(persona["processes"]):
                pid = 4 if process.casefold() == "system" else 420 + index * 168
                services = ", ".join(services_by_index.get(index, ())) or "N/A"
                lines.append(f"{process:25} {pid:8} {services}")
            return "\r\n".join(lines) + "\r\n"
        lines = ["Image Name                     PID Session Name        Session#    Mem Usage",
                 "========================= ======== ================ =========== ============"]
        for index, process in enumerate(persona["processes"]):
            pid = 4 if process.casefold() == "system" else 420 + index * 168
            session_id = PROCESS_PATHS.get(process.casefold(), ("", 1))[1]
            session = "Services" if session_id == 0 else "Console"
            lines.append(f"{process:25} {pid:8} {session:16} {session_id:11}        N/A")
        return "\r\n".join(lines) + "\r\n"
    if name == "query.exe":
        if not arguments:
            return "Displays information about user sessions.\r\nUsage: query user | query session\r\n"
        if arguments.casefold() == "session":
            return (" SESSIONNAME       USERNAME                 ID  STATE   TYPE        DEVICE\r\n"
                    " services                                   0  Disc\r\n"
                    f">console           {persona['user_name']:<24} 1  Active\r\n")
        if arguments.casefold() == "user":
            clock = VirtualClock(persona)
            logged_on = (clock.utc + clock.offset -
                         dt.timedelta(milliseconds=clock.uptime_ms))
            stamp = logged_on.strftime("%m/%d/%Y %I:%M %p").lstrip("0")
            return (" USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME\r\n"
                    f">{persona['user_name']:<21} console             1  Active      none   {stamp}\r\n")
        raise ValueError("unsupported query arguments")
    if name == "schtasks.exe":
        selected = persona["scheduled_tasks"]
        argument = arguments.casefold()
        if argument.startswith("/query /tn "):
            task_name = arguments[len("/query /tn "):].strip('"')
            selected = [task for task in selected
                        if task["name"].casefold() == task_name.casefold()]
            if not selected:
                raise ValueError("unknown guest scheduled task")
            argument = "/query"
        if argument not in {"", "/query", "/query /fo list", "/query /fo csv"}:
            raise ValueError("unsupported schtasks arguments")
        clock = VirtualClock(persona)

        def next_run(task: dict) -> str:
            minutes = task["next_run_minutes"]
            if minutes is None:
                return "N/A"
            when = clock.utc + clock.offset + dt.timedelta(minutes=minutes)
            return when.strftime("%m/%d/%Y %I:%M:%S %p")

        if argument == "/query /fo csv":
            lines = ['"TaskName","Next Run Time","Status"']
            for task in selected:
                lines.append(f'"{task["name"]}","{next_run(task)}","{task["status"]}"')
            return "\r\n".join(lines) + "\r\n"
        if argument == "/query /fo list":
            return "".join(f"TaskName:      {task['name']}\r\n"
                           f"Next Run Time: {next_run(task)}\r\n"
                           f"Status:        {task['status']}\r\n\r\n"
                           for task in selected) or "INFO: There are no scheduled tasks available.\r\n"
        lines = ["TaskName                                 Next Run Time          Status",
                 "======================================== ====================== ==============="]
        lines.extend(f"{task['name']:<40} {next_run(task):<22} {task['status']}"
                     for task in selected)
        return "\r\n".join(lines) + "\r\n"
    if name == "sc.exe":
        if not arguments:
            return "DESCRIPTION:\r\n        SC is a command line program used for communicating with the Service Control Manager.\r\n"
        running_processes = {process.casefold() for process in persona["processes"]}
        argument = arguments.casefold()
        if argument == "query":
            services = [service for service in persona["services"]
                        if service["process"].casefold() in running_processes and
                        service["start"] != 4]
        elif argument == "query state= all":
            services = persona["services"]
        elif argument.startswith("query "):
            services = [service for service in persona["services"]
                        if service["name"].casefold() == argument[6:]]
            if not services:
                raise ValueError("unknown guest service")
        else:
            raise ValueError("unsupported sc arguments")
        rows = []
        for service in services:
            running = (service["process"].casefold() in running_processes and
                       service["start"] != 4)
            service_type = ("WIN32_OWN_PROCESS" if service["type"] == 16 else
                            "WIN32_SHARE_PROCESS")
            rows.append(
                f"SERVICE_NAME: {service['name']}\r\n"
                f"DISPLAY_NAME: {service['display_name']}\r\n"
                f"        TYPE               : {service['type']:2X}  {service_type}\r\n"
                f"        STATE              : {4 if running else 1}  {'RUNNING' if running else 'STOPPED'}\r\n"
                "        WIN32_EXIT_CODE    : 0  (0x0)\r\n"
                "        SERVICE_EXIT_CODE  : 0  (0x0)\r\n\r\n")
        return "".join(rows) or "Enum: no matching services.\r\n"
    raise ValueError(f"unknown guest enumeration program: {name}")


def console_text_exe(is_x64: bool, output: str, *, code_page: int = 437,
                     variants: dict[str, str] | None = None,
                     max_text: int = _MAX_TEXT) -> bytes:
    """Build a PE that selects bounded guest text by exact command argument."""
    variants = variants or {}
    if len(variants) > 5 or any(not key or not key.isascii() or "\0" in key
                               for key in variants):
        raise ValueError("guest utility argument variants are invalid")
    outputs = [("", output), *variants.items()]
    data = bytearray()
    output_records = []
    for argument, text in outputs:
        encoded = text.encode(f"cp{code_page}", errors="replace")
        output_records.append((argument, 0x3000 + len(data), len(encoded)))
        data.extend(encoded)
    argument_rvas = {}
    for argument in variants:
        argument_rvas[argument] = 0x3000 + len(data)
        data.extend(argument.encode("ascii") + b"\0")
    if not output or len(data) > max_text:
        raise ValueError("guest utility output exceeds limit")
    machine = 0x8664 if is_x64 else 0x14C
    base = 0x190000000 if is_x64 else 0x600000
    optional_size = 0xF0 if is_x64 else 0xE0
    data_size = _align(len(data) + 8, 0x200)
    image = bytearray(0x600 + data_size)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, 0x84, machine, 3, 0, 0, 0,
                     optional_size, 0x0022 if is_x64 else 0x0102)
    opt = 0x98
    struct.pack_into("<HBBIII", image, opt, 0x20B if is_x64 else 0x10B,
                     14, 0, 0x200, 0x200 + data_size, 0)
    struct.pack_into("<II", image, opt + 16, 0x1000, 0x1000)
    if is_x64:
        struct.pack_into("<Q", image, opt + 24, base)
    else:
        struct.pack_into("<II", image, opt + 24, 0x3000, base)
    struct.pack_into("<II", image, opt + 32, 0x1000, 0x200)
    struct.pack_into("<HHHHHH", image, opt + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<III", image, opt + 56, 0x3000 + _align(data_size, 0x1000),
                     0x200, 0)
    struct.pack_into("<H", image, opt + 68, 3)
    if is_x64:
        struct.pack_into("<QQQQII", image, opt + 72,
                         0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
        dd = opt + 112
    else:
        struct.pack_into("<IIIIII", image, opt + 72,
                         0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
        dd = opt + 96
    struct.pack_into("<II", image, dd + 8, 0x2000, 0x80)
    sh = opt + optional_size
    for section_name, virtual_size, rva, raw_size, raw_offset, flags in (
            (b".text\0\0\0", 0x200, 0x1000, 0x200, 0x200, 0x60000020),
            (b".idata\0\0", 0x200, 0x2000, 0x200, 0x400, 0xC0000040),
            (b".data\0\0\0", len(data) + 8, 0x3000, data_size, 0x600, 0xC0000040)):
        image[sh:sh + 8] = section_name
        struct.pack_into("<IIIIIIHHI", image, sh + 8,
                         virtual_size, rva, raw_size, raw_offset, 0, 0, 0, 0, flags)
        sh += 40
    image[0x600:0x600 + len(data)] = data
    count_rva = 0x3000 + len(data)

    step = 8 if is_x64 else 4
    struct.pack_into("<IIIII", image, 0x400, 0x2040, 0, 0, 0x20C0, 0x2080)
    image[0x4C0:0x4CD] = b"KERNEL32.dll\0"
    names = (b"GetStdHandle", b"WriteFile", b"ExitProcess", b"GetCommandLineA",
             b"lstrcmpiA")
    cursor = 0x4E0
    for index, name in enumerate(names):
        rva = 0x2000 + cursor - 0x400
        for table in (0x2040, 0x2080):
            struct.pack_into("<Q" if is_x64 else "<I", image,
                             0x400 + table - 0x2000 + index * step, rva)
        entry = b"\0\0" + name + b"\0"
        image[cursor:cursor + len(entry)] = entry
        cursor += _align(len(entry), 2)

    code = bytearray()
    labels: dict[str, int] = {}
    branches: list[tuple[int, str]] = []

    def label(name: str) -> None:
        labels[name] = len(code)

    def branch(opcode: bytes, target: str) -> None:
        code.extend(opcode + b"\0\0\0\0")
        branches.append((len(code) - 4, target))

    def call(index: int) -> None:
        iat = 0x2080 + index * step
        if is_x64:
            code.extend(b"\xff\x15" + struct.pack("<i", iat - (0x1000 + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + iat))

    if is_x64:
        code.extend(b"\x48\x83\xec\x38")
    call(3)  # GetCommandLineA; inspect only the arguments after the image name.
    code.extend(b"\x48\x89\xc6" if is_x64 else b"\x89\xc6")
    code.extend(b"\x80\x3e\x22")
    branch(b"\x0f\x85", "unquoted")
    code.extend(b"\x48\xff\xc6" if is_x64 else b"\x46")
    label("quoted")
    code.extend(b"\x80\x3e\x00")
    branch(b"\x0f\x84", "no_args")
    code.extend(b"\x80\x3e\x22")
    branch(b"\x0f\x84", "after_quote")
    code.extend(b"\x48\xff\xc6" if is_x64 else b"\x46")
    branch(b"\xe9", "quoted")
    label("after_quote")
    code.extend(b"\x48\xff\xc6" if is_x64 else b"\x46")
    branch(b"\xe9", "after_token")
    label("unquoted")
    code.extend(b"\x80\x3e\x00")
    branch(b"\x0f\x84", "no_args")
    code.extend(b"\x80\x3e\x20")
    branch(b"\x0f\x84", "after_token")
    code.extend(b"\x80\x3e\x09")
    branch(b"\x0f\x84", "after_token")
    code.extend(b"\x48\xff\xc6" if is_x64 else b"\x46")
    branch(b"\xe9", "unquoted")
    label("after_token")
    code.extend(b"\x80\x3e\x00")
    branch(b"\x0f\x84", "no_args")
    code.extend(b"\x80\x3e\x20")
    branch(b"\x0f\x84", "skip_space")
    code.extend(b"\x80\x3e\x09")
    branch(b"\x0f\x84", "skip_space")
    branch(b"\xe9", "check_variants")
    label("skip_space")
    code.extend(b"\x48\xff\xc6" if is_x64 else b"\x46")
    branch(b"\xe9", "after_token")
    label("check_variants")
    for index, argument in enumerate(variants, 1):
        if is_x64:
            code.extend(b"\x48\x89\xf1\x48\xba" +
                        struct.pack("<Q", base + argument_rvas[argument]))
        else:
            code.extend(b"\x68" + struct.pack("<I", base + argument_rvas[argument]) +
                        b"\x56")
        call(4)  # lstrcmpiA
        code.extend(b"\x85\xc0")
        branch(b"\x0f\x84", f"variant_{index}")
    branch(b"\xe9", "unsupported_args")

    def select_output(rva: int, length: int) -> None:
        if is_x64:
            code.extend(b"\x48\xbf" + struct.pack("<Q", base + rva) +
                        b"\xbb" + struct.pack("<I", length))
        else:
            code.extend(b"\xbf" + struct.pack("<I", base + rva) +
                        b"\xbd" + struct.pack("<I", length))
        branch(b"\xe9", "write_output")

    label("no_args")
    select_output(output_records[0][1], output_records[0][2])
    for index, (_, rva, length) in enumerate(output_records[1:], 1):
        label(f"variant_{index}")
        select_output(rva, length)
    label("write_output")
    if is_x64:
        code.extend(b"\xb9\xf5\xff\xff\xff")
        call(0)
        code.extend(b"\x48\x89\xc1\x48\x89\xfa\x41\x89\xd8")
        code.extend(b"\x49\xb9" + struct.pack("<Q", base + count_rva))
        code.extend(b"\x48\xc7\x44\x24\x20\0\0\0\0")
        call(1)
        code.extend(b"\x85\xc0")
        branch(b"\x0f\x84", "write_failed")
        code.extend(b"\x31\xc9")
        call(2)
        label("write_failed")
        code.extend(b"\xb9\x01\0\0\0")
        call(2)
    else:
        code.extend(b"\x68\xf5\xff\xff\xff")
        call(0)
        code.extend(b"\x89\xc3\x6a\0")
        code.extend(b"\x68" + struct.pack("<I", base + count_rva))
        code.extend(b"\x55\x57\x53")
        call(1)
        code.extend(b"\x85\xc0")
        branch(b"\x0f\x84", "write_failed")
        code.extend(b"\x6a\0")
        call(2)
        label("write_failed")
        code.extend(b"\x6a\x01")
        call(2)
    label("unsupported_args")
    code.extend(b"\xb9\x57\0\0\0" if is_x64 else b"\x6a\x57")
    call(2)
    code.extend(b"\xc3")
    for offset, target in branches:
        struct.pack_into("<i", code, offset, labels[target] - offset - 4)
    if len(code) > 0x200:
        raise ValueError("guest utility entry exceeds PE text section")
    image[0x200:0x200 + len(code)] = code
    return bytes(image)


def enumeration_programs(is_x64: bool, persona: dict) -> dict[str, bytes]:
    """Return generated guest executables for the current persona snapshot."""
    code_page = oem_code_page(persona["locale"])
    render_persona = dict(persona)
    if render_persona.get("clock_utc") is None:
        render_persona["clock_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
    result = {}
    for name in ("whoami.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe", "getmac.exe",
                 "arp.exe", "route.exe", "netsh.exe", "tzutil.exe", "query.exe",
                 "quser.exe", "qwinsta.exe", "net.exe", "net1.exe", "sc.exe",
                 "schtasks.exe", "driverquery.exe", "mountvol.exe", "bcdedit.exe",
                 "fltmc.exe", "pnputil.exe", "gpresult.exe", "dsregcmd.exe",
                 "vssadmin.exe", "cmdkey.exe", "manage-bde.exe"):
        commands = ({"whoami.exe": ("/user", "/groups", "/priv", "/all"),
                     "ipconfig.exe": ("/all",),
                     "tasklist.exe": ("/svc",),
                     "arp.exe": ("-a",),
                     "route.exe": ("print", "print -4"),
                     "netsh.exe": ("interface ipv4 show config",
                                   "interface ipv4 show dnsservers"),
                     "query.exe": ("user", "session"),
                     "net.exe": ("user", f"user {persona['user_name']}",
                                 "localgroup", "localgroup administrators",
                                 "localgroup users"),
                     "net1.exe": ("user", f"user {persona['user_name']}",
                                  "localgroup", "localgroup administrators",
                                  "localgroup users"),
                     "sc.exe": ("query", "query state= all",
                                *(f"query {service['name']}"
                                  for service in persona["services"][:3])),
                     "schtasks.exe": ("/query", "/query /fo LIST", "/query /fo CSV",
                                      *("/query /tn " +
                                        (f'"{task["name"]}"' if " " in task["name"]
                                         else task["name"])
                                        for task in persona["scheduled_tasks"][:2])),
                     "tzutil.exe": ("/g",),
                     "mountvol.exe": ("C: /L", "C:\\ /L"),
                     "bcdedit.exe": ("/enum", "/enum active", "/v",
                                     "/enum active /v", "/enum {current}"),
                     "fltmc.exe": ("filters", "instances", "volumes"),
                     "pnputil.exe": ("/enum-drivers", "-e", "/enum-devices",
                                     "/enum-devices /connected", "/enum-classes"),
                     "gpresult.exe": ("/r", "/scope user /r", "/r /scope user",
                                      "/scope computer /r", "/r /scope computer"),
                     "dsregcmd.exe": ("/status",),
                     "cmdkey.exe": ("/list",),
                     "manage-bde.exe": ("-status", "-status C:"),
                     "vssadmin.exe": ("list shadows", "list shadows /for=C:",
                                      "list shadows /for=C:\\", "list volumes",
                                      "list providers"),
                     "driverquery.exe": ("/v", "/fo list", "/fo csv", "/nh")}.get(name, ()))
        commands = tuple(argument for argument in commands if argument.isascii())
        variants = {argument: enumeration_text(name, render_persona, argument)
                    for argument in commands}
        result[name] = console_text_exe(
            is_x64, enumeration_text(name, render_persona), code_page=code_page,
            variants=variants,
            max_text=256 * 1024 if name == "pnputil.exe" else _MAX_TEXT)
    arch = "x64" if is_x64 else "x86"
    result["reg.exe"] = files("emumee").joinpath(
        "guest_native", f"reg_query_{arch}.exe").read_bytes()
    result["where.exe"] = files("emumee").joinpath(
        "guest_native", f"where_query_{arch}.exe").read_bytes()
    result["netstat.exe"] = files("emumee").joinpath(
        "guest_native", f"netstat_query_{arch}.exe").read_bytes()
    result["fsutil.exe"] = files("emumee").joinpath(
        "guest_native", f"fsutil_query_{arch}.exe").read_bytes()
    result["wevtutil.exe"] = files("emumee").joinpath(
        "guest_native", f"wevtutil_query_{arch}.exe").read_bytes()
    return result

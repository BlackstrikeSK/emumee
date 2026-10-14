"""Deterministic, guest-only Windows 11 desktop background data."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import io
import struct
import uuid
import zipfile


DISPLAY_VERSIONS = {
    22000: "21H2", 22621: "22H2", 22631: "23H2",
    26100: "24H2", 26200: "25H2", 26300: "26H2",
}

INTERNATIONAL_FORMATS = {
    "en-us": ("M/d/yyyy", "h:mm:ss tt"),
    "en-gb": ("dd/MM/yyyy", "HH:mm:ss"),
    "de-de": ("dd.MM.yyyy", "HH:mm:ss"),
    "fr-fr": ("dd/MM/yyyy", "HH:mm:ss"),
}

OEM_CODE_PAGES = {
    "en-us": 437, "en-gb": 850, "de-de": 850, "fr-fr": 850,
}


def oem_code_page(locale: str) -> int:
    return OEM_CODE_PAGES.get(locale.casefold(), 437)


def _receipt_pdf() -> bytes:
    stream = (b"BT /F1 12 Tf 54 750 Td (Train ticket receipt) Tj "
              b"0 -24 Td (12 April 2026) Tj "
              b"0 -24 Td (Rail fare: 24.50) Tj ET\n")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") +
        b" >>\nstream\n" + stream + b"endstream",
    ]
    document = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, body in enumerate(objects, 1):
        offsets.append(len(document))
        document.extend(f"{index} 0 obj\n".encode("ascii") + body + b"\nendobj\n")
    xref = len(document)
    document.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    document.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        document.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    document.extend((f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\n"
                     f"startxref\n{xref}\n%%EOF\n").encode("ascii"))
    return bytes(document)


def _travel_archive() -> bytes:
    contents = {
        "trip-checklist.txt": "Tickets\nPhone charger\nTravel card\n",
        "travel-expenses.csv": "Date,Item,Amount\n2026-04-12,Train,24.50\n2026-04-12,Lunch,13.20\n",
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, text in contents.items():
            info = zipfile.ZipInfo(name, date_time=(2026, 4, 12, 9, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, text.encode("utf-8"))
    return buffer.getvalue()


def desktop_files(user_name: str, hostname: str) -> list[dict[str, str]]:
    home = rf"C:\Users\{user_name}"
    roaming = home + r"\AppData\Roaming"
    local = home + r"\AppData\Local"
    files = [
        (home + r"\Documents\readme.txt", "Personal notes\n"),
        (home + r"\Documents\Household\shopping-list.txt",
         "Milk\nCoffee\nBread\n"),
        (home + r"\Documents\Household\budget-2026.csv",
         "Month,Category,Amount\nJanuary,Groceries,420.00\nFebruary,Groceries,397.50\n"),
        (home + r"\Documents\Work\meeting-notes.txt",
         "Weekly planning\nReview tasks and calendar.\n"),
        (home + r"\Documents\Work\project-plan.txt",
         "Project notes\nDraft outline\nReview milestones\n"),
        (home + r"\Documents\Work\weekly-status.txt",
         "This week: review milestones and update the project plan.\n"),
        (home + r"\Documents\Work\project-brief-draft.txt",
         "Project brief\nGoal: organize the shared schedule.\n"
         "Next: review the timeline with Jordan.\n"),
        (home + r"\Documents\Work\project-brief-final.txt",
         "Project brief\nGoal: organize the shared schedule.\n"
         "Next: confirm the timeline with Jordan and Casey.\n"),
        (home + r"\Documents\Work\contacts.csv",
         "Name,Role\nJordan,Design\nCasey,Operations\n"),
        (home + r"\Documents\Work\schedule.ics",
         "BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//Personal Calendar//EN\n"
         "BEGIN:VEVENT\nUID:planning-2026@example.invalid\n"
         "DTSTART:20261020T090000\nDTEND:20261020T100000\n"
         "SUMMARY:Weekly planning\nEND:VEVENT\nEND:VCALENDAR\n"),
        (home + r"\Documents\Work\team-contacts.vcf",
         "BEGIN:VCARD\nVERSION:3.0\nFN:Jordan\nNOTE:Design contact\nEND:VCARD\n"
         "BEGIN:VCARD\nVERSION:3.0\nFN:Casey\nNOTE:Operations contact\nEND:VCARD\n"),
        (home + r"\Documents\Household\warranty-notes.txt",
         "Keep receipts and warranty documents in the Receipts folder.\n"),
        (home + r"\Documents\Household\maintenance-log.csv",
         "Date,Item,Notes\n2026-03-08,Kitchen,Replaced light bulb\n"
         "2026-09-14,Bicycle,Checked tires\n"),
        (home + r"\Documents\Household\pantry-inventory.csv",
         "Item,Quantity,Unit\nMilk,0,carton\nCoffee,0,bag\nBread,1,loaf\n"),
        (home + r"\Documents\Household\pantry-inventory-updated.csv",
         "Item,Quantity,Unit\nMilk,1,carton\nCoffee,0,bag\nBread,1,loaf\n"),
        (home + r"\Documents\Receipts\train-apr-2026.txt",
         "2026-04-12 Train 24.50\n"),
        (home + r"\Documents\Receipts\expense-summary.csv",
         "Month,Category,Amount\nApril,Travel,24.50\nApril,Meals,13.20\n"),
        (home + r"\Documents\Receipts\groceries-sep-2026.csv",
         "Date,Item,Amount\n2026-09-12,Milk,2.40\n2026-09-12,Bread,3.10\n"),
        (home + r"\Desktop\Welcome.txt",
         f"Welcome to {hostname}.\n"),
        (home + r"\Desktop\notes.txt",
         "Remember to review the project plan.\n"),
        (home + r"\Desktop\Projects.url",
         "[InternetShortcut]\nURL=https://example.com/projects\n"),
        (home + r"\Desktop\Calendar.url",
         "[InternetShortcut]\nURL=https://example.com/calendar\n"),
        (home + r"\Downloads\download-history.txt",
         "Recent downloads are saved in this folder.\n"),
        (home + r"\Downloads\travel-expenses.csv",
         "Date,Item,Amount\n2026-04-12,Train,24.50\n2026-04-12,Lunch,13.20\n"),
        (home + r"\Downloads\trip-checklist.txt",
         "Tickets\nPhone charger\nTravel card\n"),
        (home + r"\Pictures\album-index.txt",
         "2025\n2026\n"),
        (home + r"\Pictures\2026\album-notes.txt",
         "Spring photos\n"),
        (home + r"\Music\Playlists\favorites.m3u",
         "#EXTM3U\n"),
        (home + r"\Music\Playlists\commute.m3u",
         "#EXTM3U\n"),
        (home + r"\Videos\notes.txt",
         "Family videos are organized by year.\n"),
        (roaming + r"\Microsoft\Windows\Start Menu\Programs\desktop.ini",
         "[.ShellClassInfo]\nLocalizedResourceName=@%SystemRoot%\\system32\\shell32.dll,-21782\n"),
        (roaming + r"\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini",
         "[.ShellClassInfo]\nLocalizedResourceName=@%SystemRoot%\\system32\\shell32.dll,-21787\n"),
        (roaming + r"\Microsoft\Windows\Start Menu\Programs\Accessories\desktop.ini",
         "[.ShellClassInfo]\nLocalizedResourceName=Accessories\n"),
        (roaming + r"\Microsoft\Windows\SendTo\desktop.ini",
         "[.ShellClassInfo]\nLocalizedResourceName=SendTo\n"),
        (local + r"\Microsoft\Edge\User Data\Local State",
         '{"browser":{"enabled_labs_experiments":[]},"profile":{"last_used":"Default"}}\n'),
        (local + r"\Microsoft\Edge\User Data\Default\Preferences",
         '{"profile":{"name":"Personal","exit_type":"Normal"},"session":{"restore_on_startup":5}}\n'),
        (local + r"\Microsoft\Edge\User Data\Default\Bookmarks",
         '{"roots":{"bookmark_bar":{"children":[{"name":"Reference","type":"url",'
         '"url":"https://example.com/"}],"name":"Favorites bar","type":"folder"}}}\n'),
        (local + r"\Microsoft\OneDrive\settings\Personal\ClientPolicy.ini",
         "[General]\nEnableSync=1\n"),
        (home + r"\OneDrive\Documents\readme.txt",
         "Personal documents synced here.\n"),
        (home + r"\OneDrive\Documents\project-summary.txt",
         "Project notes are kept in Documents\\Work.\n"),
        (roaming + r"\Microsoft\Windows\Recent\desktop.ini",
         "[.ShellClassInfo]\nLocalizedResourceName=@%SystemRoot%\\system32\\shell32.dll,-21741\n"),
        (r"C:\Windows\win.ini", "[fonts]\n[extensions]\n[mci extensions]\n[files]\n"),
        (r"C:\Windows\system.ini", "[boot]\nshell=explorer.exe\n[drivers]\n"),
        (r"C:\Windows\System32\drivers\etc\hosts",
         "# Windows TCP/IP hosts file\n127.0.0.1 localhost\n::1 localhost\n"),
        (r"C:\Windows\System32\drivers\etc\networks",
         "loopback 127\n"),
        (r"C:\Windows\System32\drivers\etc\services",
         "ftp 21/tcp\nssh 22/tcp\nsmtp 25/tcp\ndomain 53/udp\n"
         "http 80/tcp\nntp 123/udp\nhttps 443/tcp\nmicrosoft-ds 445/tcp\n"
         "ms-wbt-server 3389/tcp\n"),
        (r"C:\Windows\System32\drivers\etc\protocol",
         "ip 0 IP\nicmp 1 ICMP\ntcp 6 TCP\nudp 17 UDP\n"),
        (r"C:\ProgramData\Microsoft\Windows\Start Menu\desktop.ini",
         "[.ShellClassInfo]\nLocalizedResourceName=@%SystemRoot%\\system32\\shell32.dll,-21786\n"),
        (r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\desktop.ini",
         "[.ShellClassInfo]\nLocalizedResourceName=@%SystemRoot%\\system32\\shell32.dll,-21782\n"),
        (r"C:\Users\Public\Documents\readme.txt",
         "Shared documents can be placed here.\n"),
        (r"C:\Users\Public\Desktop\readme.txt",
         "Shared shortcuts appear on this desktop.\n"),
        (r"C:\Users\Public\Pictures\desktop.ini",
         "[.ShellClassInfo]\nLocalizedResourceName=Public Pictures\n"),
    ]
    result = [{"path": path, "text": text} for path, text in files]
    result.extend((
        {"path": home + r"\Documents\Receipts\train-apr-2026.pdf",
         "base64": base64.b64encode(_receipt_pdf()).decode("ascii")},
        {"path": home + r"\Downloads\trip-documents.zip",
         "base64": base64.b64encode(_travel_archive()).decode("ascii")},
    ))
    return result


def desktop_directories(user_name: str) -> list[str]:
    home = rf"C:\Users\{user_name}"
    return [
        r"C:\Windows", r"C:\Windows\System32", r"C:\Windows\SysWOW64",
        r"C:\Windows\Temp", r"C:\Windows\INF", r"C:\Windows\Media",
        r"C:\Program Files", r"C:\Program Files\Common Files",
        r"C:\Program Files (x86)", r"C:\Program Files (x86)\Common Files",
        r"C:\ProgramData", r"C:\Users\Public\Desktop",
        r"C:\Users\Default",
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        home + r"\Desktop", home + r"\Documents", home + r"\Downloads",
        home + r"\Documents\Household", home + r"\Documents\Work",
        home + r"\Documents\Receipts",
        home + r"\Pictures", home + r"\Music", home + r"\Videos",
        home + r"\Pictures\2026", home + r"\Music\Playlists",
        home + r"\AppData\Local\Temp",
        home + r"\OneDrive\Documents",
        home + r"\AppData\Roaming\Microsoft\Windows\Recent",
        home + r"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
        home + r"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessories",
        home + r"\AppData\Roaming\Microsoft\Windows\SendTo",
        r"C:\Users\Public\Pictures",
    ]


def registry_keys(persona: dict) -> list[dict]:
    """Build mutually consistent common registry probes from persona fields."""
    name = persona["user_name"]
    home = rf"C:\Users\{name}"
    build = persona["windows_build"]
    display = DISPLAY_VERSIONS.get(build)
    cpu = persona["cpu"]
    adapter = persona["network_adapter"]
    machine_digest = hashlib.sha256(
        ("emumee-machine:" + persona["hostname"].casefold()).encode("utf-8")).digest()
    machine_guid = str(uuid.UUID(bytes=machine_digest[:16], version=4))
    fixed_tzi = struct.pack("<iii32s", -persona["utc_offset_minutes"], 0, 0,
                            b"\0" * 32).hex()
    subnet_mask = str(ipaddress.IPv4Network(
        (adapter["ipv4"], adapter["prefix_length"]), strict=False).netmask)

    def value(key: str, data, kind: str = "REG_SZ") -> dict:
        return {"name": key, "type": kind, "data": str(data)}

    def entry(path: str, *values: dict) -> dict:
        return {"path": path, "values": list(values)}

    version_values = [
        value("ProductName", "Windows 11 Pro"),
        value("EditionID", "Professional"),
        value("InstallationType", "Client"),
        value("CurrentBuild", str(build)),
        value("CurrentBuildNumber", str(build)),
        value("CurrentVersion", "6.3"),
        value("SystemRoot", r"C:\Windows"),
        value("ProductId", "00330-80000-00000-AA000"),
        value("RegisteredOwner", name),
        value("UBR", 1, "REG_DWORD"),
        value("InstallDate", 1690000000, "REG_DWORD"),
    ]
    if display:
        version_values.append(value("DisplayVersion", display))
    international_values = [value("LocaleName", persona["locale"])]
    formats = INTERNATIONAL_FORMATS.get(persona["locale"].casefold())
    if formats is not None:
        international_values.extend((value("sShortDate", formats[0]),
                                     value("sTimeFormat", formats[1])))

    keys = [
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
              *version_values),
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography",
              value("MachineGuid", machine_guid)),
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion",
              value("ProgramFilesDir", r"C:\Program Files"),
              value("ProgramFilesDir (x86)", r"C:\Program Files (x86)"),
              value("ProgramW6432Dir", r"C:\Program Files"),
              value("CommonFilesDir", r"C:\Program Files\Common Files"),
              value("CommonFilesDir (x86)", r"C:\Program Files (x86)\Common Files"),
              value("CommonW6432Dir", r"C:\Program Files\Common Files"),
              value("ProgramFilesPath", r"%ProgramFiles%", "REG_EXPAND_SZ"),
              value("DevicePath", r"%SystemRoot%\inf", "REG_EXPAND_SZ"),
              value("MediaPathUnexpanded", r"%SystemRoot%\Media", "REG_EXPAND_SZ")),
        entry(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName",
              value("ComputerName", persona["hostname"])),
        entry(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName",
              value("ComputerName", persona["hostname"])),
        entry(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
              value("Hostname", persona["hostname"]),
              value("NV Hostname", persona["hostname"]),
              value("Domain", "" if persona["domain"] == "WORKGROUP" else persona["domain"]),
              value("NV Domain", "" if persona["domain"] == "WORKGROUP" else persona["domain"])),
        entry(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces" +
              "\\" + adapter["guid"],
              value("EnableDHCP", int(adapter["dhcp_enabled"]), "REG_DWORD"),
              value("DhcpIPAddress", adapter["ipv4"]),
              value("DhcpSubnetMask", subnet_mask),
              value("DhcpDefaultGateway", adapter["gateway"], "REG_MULTI_SZ"),
              value("DhcpNameServer", " ".join(adapter["dns_servers"]))),
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards\1",
              value("Description", adapter["description"]),
              value("ServiceName", adapter["guid"])),
        entry(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}" +
              "\\" + adapter["guid"] + r"\Connection",
              value("Name", adapter["name"]),
              value("PnpInstanceID", r"PCI\VEN_8086&DEV_0D4F&SUBSYS_087B1028")),
        entry(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
              value("TimeZoneKeyName", persona["timezone"]),
              value("ActiveTimeBias", (-persona["utc_offset_minutes"]) & 0xFFFFFFFF,
                    "REG_DWORD"),
              value("DynamicDaylightTimeDisabled", 1, "REG_DWORD")),
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones"),
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones" +
              "\\" + persona["timezone"],
              value("Display", persona["timezone"]),
              value("Std", persona["timezone"]),
              value("Dlt", persona["timezone"]),
              value("TZI", "hex:" + fixed_tzi, "REG_BINARY")),
        entry(r"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\CentralProcessor\0",
              value("ProcessorNameString", cpu["brand"]),
              value("VendorIdentifier", "GenuineIntel"),
              value("~MHz", cpu["base_mhz"], "REG_DWORD")),
        entry(r"HKEY_LOCAL_MACHINE\HARDWARE\DESCRIPTION\System\BIOS",
              value("SystemManufacturer", "Dell Inc."),
              value("SystemProductName", "OptiPlex 7080"),
              value("BIOSVendor", "Dell Inc.")),
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
              value("Common AppData", r"C:\ProgramData"),
              value("Common Desktop", r"C:\Users\Public\Desktop"),
              value("Common Documents", r"C:\Users\Public\Documents"),
              value("Common Start Menu", r"C:\ProgramData\Microsoft\Windows\Start Menu"),
              value("Common Programs", r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs"),
              value("Common Startup", r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")),
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
              value("DisableRealtimeMonitoring", 0, "REG_DWORD")),
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList",
              value("Default", r"%SystemDrive%\Users\Default", "REG_EXPAND_SZ"),
              value("ProfilesDirectory", r"%SystemDrive%\Users", "REG_EXPAND_SZ"),
              value("ProgramData", r"%SystemDrive%\ProgramData", "REG_EXPAND_SZ"),
              value("Public", r"%SystemDrive%\Users\Public", "REG_EXPAND_SZ")),
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" + "\\" + persona["user_sid"],
              value("ProfileImagePath", home, "REG_EXPAND_SZ")),
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
              value("Shell", "explorer.exe"),
              value("Userinit", r"C:\Windows\system32\userinit.exe,")),
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
              value("AppInit_DLLs", ""),
              value("LoadAppInit_DLLs", 0, "REG_DWORD")),
        entry(r"HKEY_CURRENT_USER\Volatile Environment",
              value("USERPROFILE", home), value("USERNAME", name),
              value("APPDATA", home + r"\AppData\Roaming"),
              value("LOCALAPPDATA", home + r"\AppData\Local")),
        entry(r"HKEY_CURRENT_USER\Environment",
              value("TEMP", home + r"\AppData\Local\Temp", "REG_EXPAND_SZ"),
              value("TMP", home + r"\AppData\Local\Temp", "REG_EXPAND_SZ")),
        entry(r"HKEY_CURRENT_USER\Control Panel\International",
              *international_values),
        entry(r"HKEY_CURRENT_USER\Control Panel\Desktop",
              value("MenuShowDelay", "400"),
              value("ScreenSaveActive", "1"),
              value("ScreenSaveTimeOut", "600"),
              value("DragFullWindows", "1")),
        entry(r"HKEY_CURRENT_USER\Control Panel\Mouse",
              value("MouseSpeed", "1"),
              value("MouseThreshold1", "6"),
              value("MouseThreshold2", "10"),
              value("DoubleClickSpeed", "500")),
        entry(r"HKEY_CURRENT_USER\Control Panel\Keyboard",
              value("KeyboardDelay", "1"),
              value("KeyboardSpeed", "31")),
        entry(r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
              value("Desktop", home + r"\Desktop"),
              value("Personal", home + r"\Documents"),
              value("AppData", home + r"\AppData\Roaming"),
              value("Local AppData", home + r"\AppData\Local"),
              value("My Pictures", home + r"\Pictures"),
              value("My Music", home + r"\Music"),
              value("My Video", home + r"\Videos"),
              value("Downloads", home + r"\Downloads"),
              value("Start Menu", home + r"\AppData\Roaming\Microsoft\Windows\Start Menu"),
              value("Programs", home + r"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs"),
              value("Startup", home + r"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"),
              value("SendTo", home + r"\AppData\Roaming\Microsoft\Windows\SendTo"),
              value("Recent", home + r"\AppData\Roaming\Microsoft\Windows\Recent")),
        entry(r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
              value("Desktop", r"%USERPROFILE%\Desktop", "REG_EXPAND_SZ"),
              value("Personal", r"%USERPROFILE%\Documents", "REG_EXPAND_SZ"),
              value("AppData", r"%USERPROFILE%\AppData\Roaming", "REG_EXPAND_SZ"),
              value("Local AppData", r"%USERPROFILE%\AppData\Local", "REG_EXPAND_SZ"),
              value("My Pictures", r"%USERPROFILE%\Pictures", "REG_EXPAND_SZ"),
              value("My Music", r"%USERPROFILE%\Music", "REG_EXPAND_SZ"),
              value("My Video", r"%USERPROFILE%\Videos", "REG_EXPAND_SZ"),
              value("Start Menu", r"%APPDATA%\Microsoft\Windows\Start Menu", "REG_EXPAND_SZ"),
              value("Programs", r"%APPDATA%\Microsoft\Windows\Start Menu\Programs", "REG_EXPAND_SZ"),
              value("Startup", r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup", "REG_EXPAND_SZ"),
              value("SendTo", r"%APPDATA%\Microsoft\Windows\SendTo", "REG_EXPAND_SZ"),
              value("Recent", r"%APPDATA%\Microsoft\Windows\Recent", "REG_EXPAND_SZ"),
              value("{374DE290-123F-4565-9164-39C4925E467B}",
                    r"%USERPROFILE%\Downloads", "REG_EXPAND_SZ")),
        entry(r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"),
        entry(r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        entry(r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
              value("AppsUseLightTheme", 1, "REG_DWORD"),
              value("SystemUsesLightTheme", 1, "REG_DWORD"),
              value("EnableTransparency", 1, "REG_DWORD")),
        entry(r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"),
        entry(r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
              value("a", r"notepad.exe " + home + r"\Documents\Work\meeting-notes.txt\1"),
              value("MRUList", "a")),
        entry(r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
              value("url1", home + r"\Documents"),
              value("url2", home + r"\Downloads")),
        entry(r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
              value("HideFileExt", 1, "REG_DWORD"),
              value("Hidden", 2, "REG_DWORD"),
              value("ShowSuperHidden", 0, "REG_DWORD")),
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
              value("EnableLUA", 1, "REG_DWORD"),
              value("ConsentPromptBehaviorAdmin", 5, "REG_DWORD"),
              value("PromptOnSecureDesktop", 1, "REG_DWORD")),
    ]
    for service in persona["services"]:
        keys.append(entry(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services" +
                          "\\" + service["name"],
                          value("Start", service["start"], "REG_DWORD"),
                          value("Type", service["type"], "REG_DWORD"),
                          value("DisplayName", service["display_name"])))
    for driver in persona["drivers"]:
        keys.append(entry(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services" +
                          "\\" + driver["name"],
                          value("Start", driver["start"], "REG_DWORD"),
                          value("Type", driver["type"], "REG_DWORD"),
                          value("DisplayName", driver["display_name"]),
                          value("ImagePath", driver["path"], "REG_EXPAND_SZ")))
    for channel in persona["event_channels"]:
        keys.append(entry(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog" +
                          "\\" + channel["name"],
                          value("Enabled", int(channel["enabled"]), "REG_DWORD"),
                          value("MaxSize", channel["max_size"], "REG_DWORD"),
                          value("Retention", int(channel["retention"]), "REG_DWORD"),
                          value("File", "C:\\Windows\\System32\\winevt\\Logs\\" +
                                channel["name"] + ".evtx", "REG_EXPAND_SZ")))
    seen = {item["path"].casefold() for item in keys}
    for item in tuple(keys):
        parts = item["path"].split("\\")
        for length in range(2, len(parts)):
            parent = "\\".join(parts[:length])
            if parent.casefold() not in seen:
                keys.append(entry(parent))
                seen.add(parent.casefold())
    return keys


PROCESS_PATHS = {
    "system": ("[System Process]", 0),
    "smss.exe": (r"C:\Windows\System32\smss.exe", 0),
    "csrss.exe": (r"C:\Windows\System32\csrss.exe", 0),
    "wininit.exe": (r"C:\Windows\System32\wininit.exe", 0),
    "services.exe": (r"C:\Windows\System32\services.exe", 0),
    "lsass.exe": (r"C:\Windows\System32\lsass.exe", 0),
    "svchost.exe": (r"C:\Windows\System32\svchost.exe", 0),
    "winlogon.exe": (r"C:\Windows\System32\winlogon.exe", 1),
    "dwm.exe": (r"C:\Windows\System32\dwm.exe", 1),
    "explorer.exe": (r"C:\Windows\explorer.exe", 1),
    "sihost.exe": (r"C:\Windows\System32\sihost.exe", 1),
    "searchhost.exe": (r"C:\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\SearchHost.exe", 1),
    "startmenuexperiencehost.exe": (r"C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe", 1),
    "runtimebroker.exe": (r"C:\Windows\System32\RuntimeBroker.exe", 1),
    "msmpeng.exe": (r"C:\Program Files\Windows Defender\MsMpEng.exe", 0),
    "securityhealthsystray.exe": (r"C:\Windows\System32\SecurityHealthSystray.exe", 1),
    "onedrive.exe": (r"C:\Users\{user}\AppData\Local\Microsoft\OneDrive\OneDrive.exe", 1),
}

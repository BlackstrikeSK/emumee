"""Deterministic, guest-only Windows 11 desktop background data."""

from __future__ import annotations


DISPLAY_VERSIONS = {
    22000: "21H2", 22621: "22H2", 22631: "23H2",
    26100: "24H2", 26200: "25H2", 26300: "26H2",
}


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
        (home + r"\Desktop\Welcome.txt",
         f"Welcome to {hostname}.\n"),
        (home + r"\Desktop\notes.txt",
         "Remember to review the project plan.\n"),
        (home + r"\Desktop\Projects.url",
         "[InternetShortcut]\nURL=https://example.com/projects\n"),
        (home + r"\Downloads\download-history.txt",
         "Recent downloads are saved in this folder.\n"),
        (home + r"\Downloads\travel-expenses.csv",
         "Date,Item,Amount\n2026-04-12,Train,24.50\n2026-04-12,Lunch,13.20\n"),
        (home + r"\Pictures\album-index.txt",
         "2025\n2026\n"),
        (home + r"\Music\Playlists\favorites.m3u",
         "#EXTM3U\n"),
        (home + r"\Videos\notes.txt",
         "Family videos are organized by year.\n"),
        (roaming + r"\Microsoft\Windows\Start Menu\Programs\desktop.ini",
         "[.ShellClassInfo]\nLocalizedResourceName=@%SystemRoot%\\system32\\shell32.dll,-21782\n"),
        (roaming + r"\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini",
         "[.ShellClassInfo]\nLocalizedResourceName=@%SystemRoot%\\system32\\shell32.dll,-21787\n"),
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
        (roaming + r"\Microsoft\Windows\Recent\desktop.ini",
         "[.ShellClassInfo]\nLocalizedResourceName=@%SystemRoot%\\system32\\shell32.dll,-21741\n"),
        (r"C:\Windows\win.ini", "[fonts]\n[extensions]\n[mci extensions]\n[files]\n"),
        (r"C:\Windows\system.ini", "[boot]\nshell=explorer.exe\n[drivers]\n"),
        (r"C:\Windows\System32\drivers\etc\hosts",
         "# Windows TCP/IP hosts file\n127.0.0.1 localhost\n::1 localhost\n"),
        (r"C:\Windows\System32\drivers\etc\networks",
         "loopback 127\n"),
        (r"C:\Windows\System32\drivers\etc\services",
         "http 80/tcp\nhttps 443/tcp\n"),
        (r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\desktop.ini",
         "[.ShellClassInfo]\nLocalizedResourceName=@%SystemRoot%\\system32\\shell32.dll,-21782\n"),
        (r"C:\Users\Public\Documents\readme.txt",
         "Shared documents can be placed here.\n"),
        (r"C:\Users\Public\Desktop\readme.txt",
         "Shared shortcuts appear on this desktop.\n"),
    ]
    return [{"path": path, "text": text} for path, text in files]


def desktop_directories(user_name: str) -> list[str]:
    home = rf"C:\Users\{user_name}"
    return [
        r"C:\Windows", r"C:\Windows\System32", r"C:\Windows\SysWOW64",
        r"C:\Windows\Temp", r"C:\Program Files", r"C:\Program Files (x86)",
        r"C:\ProgramData", r"C:\Users\Public\Desktop",
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
        home + r"\Desktop", home + r"\Documents", home + r"\Downloads",
        home + r"\Pictures", home + r"\Music", home + r"\Videos",
        home + r"\AppData\Local\Temp",
        home + r"\OneDrive\Documents",
        home + r"\AppData\Roaming\Microsoft\Windows\Recent",
        home + r"\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
    ]


def registry_keys(persona: dict) -> list[dict]:
    """Build mutually consistent common registry probes from persona fields."""
    name = persona["user_name"]
    home = rf"C:\Users\{name}"
    build = persona["windows_build"]
    display = DISPLAY_VERSIONS.get(build)
    cpu = persona["cpu"]

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

    keys = [
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
              *version_values),
        entry(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName",
              value("ComputerName", persona["hostname"])),
        entry(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName",
              value("ComputerName", persona["hostname"])),
        entry(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
              value("Hostname", persona["hostname"]),
              value("NV Hostname", persona["hostname"]),
              value("Domain", "" if persona["domain"] == "WORKGROUP" else persona["domain"])),
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
              value("Common Documents", r"C:\Users\Public\Documents")),
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
              value("DisableRealtimeMonitoring", 0, "REG_DWORD")),
        entry(r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend",
              value("Start", 2, "REG_DWORD"),
              value("DisplayName", "Microsoft Defender Antivirus Service")),
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" + "\\" + persona["user_sid"],
              value("ProfileImagePath", home, "REG_EXPAND_SZ")),
        entry(r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
              value("Shell", "explorer.exe"),
              value("Userinit", r"C:\Windows\system32\userinit.exe,")),
        entry(r"HKEY_CURRENT_USER\Volatile Environment",
              value("USERPROFILE", home), value("USERNAME", name),
              value("APPDATA", home + r"\AppData\Roaming"),
              value("LOCALAPPDATA", home + r"\AppData\Local")),
        entry(r"HKEY_CURRENT_USER\Environment",
              value("TEMP", home + r"\AppData\Local\Temp", "REG_EXPAND_SZ"),
              value("TMP", home + r"\AppData\Local\Temp", "REG_EXPAND_SZ")),
        entry(r"HKEY_CURRENT_USER\Control Panel\International",
              value("LocaleName", persona["locale"]),
              value("sShortDate", "M/d/yyyy"),
              value("sTimeFormat", "h:mm:ss tt")),
        entry(r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
              value("Desktop", home + r"\Desktop"),
              value("Personal", home + r"\Documents"),
              value("AppData", home + r"\AppData\Roaming"),
              value("Local AppData", home + r"\AppData\Local"),
              value("My Pictures", home + r"\Pictures")),
        entry(r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
              value("Desktop", r"%USERPROFILE%\Desktop", "REG_EXPAND_SZ"),
              value("Personal", r"%USERPROFILE%\Documents", "REG_EXPAND_SZ"),
              value("AppData", r"%USERPROFILE%\AppData\Roaming", "REG_EXPAND_SZ"),
              value("Local AppData", r"%USERPROFILE%\AppData\Local", "REG_EXPAND_SZ")),
        entry(r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"),
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

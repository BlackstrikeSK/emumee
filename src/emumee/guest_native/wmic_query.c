/* Guest WMIC read views. All identity and capacity values come from guest APIs.
 * No COM provider, host process, remote target, or change command is used. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <lm.h>

__declspec(dllimport) LONG NTAPI RtlGetVersion(OSVERSIONINFOW *);

static WCHAR tokens[16][256];
static WCHAR fields[12][256];
static const WCHAR *names[12];
static DWORD selected[12], widths[12];
static WCHAR properties[256];
static WCHAR number[32];

static DWORD length(const WCHAR *s) { DWORD n = 0; while (s[n]) ++n; return n; }
static int equals(const WCHAR *a, const WCHAR *b) {
    while (*a && *b) {
        WCHAR x = *a++, y = *b++;
        if (x >= L'A' && x <= L'Z') x += L'a' - L'A';
        if (y >= L'A' && y <= L'Z') y += L'a' - L'A';
        if (x != y) return 0;
    }
    return !*a && !*b;
}
static void append(WCHAR *out, const WCHAR *s) {
    DWORD n = length(out);
    while (*s && n < 255) out[n++] = *s++;
    if (*s) ExitProcess(ERROR_INVALID_PARAMETER);
    out[n] = 0;
}
static void print(const WCHAR *s) {
    DWORD written = 0, n = length(s);
    if (n && !WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), s, n, &written, 0))
        ExitProcess(GetLastError());
}
/* Base-65536 long division avoids CRT 64-bit division helpers on x86. */
static void decimal(WCHAR *out, ULONGLONG value) {
    ULARGE_INTEGER v; DWORD limbs[4], n = 0;
    v.QuadPart = value;
    limbs[0] = v.HighPart >> 16; limbs[1] = v.HighPart & 65535;
    limbs[2] = v.LowPart >> 16; limbs[3] = v.LowPart & 65535;
    do {
        DWORD remainder = 0;
        for (DWORD i = 0; i < 4; ++i) {
            DWORD current = remainder * 65536 + limbs[i];
            limbs[i] = current / 10; remainder = current % 10;
        }
        number[n++] = (WCHAR)(L'0' + remainder);
    } while (limbs[0] || limbs[1] || limbs[2] || limbs[3]);
    for (DWORD i = 0; i < n; ++i) out[i] = number[n - i - 1];
    out[n] = 0;
}
static int next_arg(const WCHAR **cursor, WCHAR *out) {
    const WCHAR *s = *cursor; DWORD n = 0; int quoted = 0;
    while (*s == L' ' || *s == L'\t') ++s;
    if (!*s) return 0;
    while (*s && (quoted || (*s != L' ' && *s != L'\t'))) {
        if (*s == L'"') quoted = !quoted;
        else if (n < 255) out[n++] = *s;
        else return -1;
        ++s;
    }
    if (quoted || !n) return -1;
    out[n] = 0; *cursor = s; return 1;
}
static void computer_name(COMPUTER_NAME_FORMAT format, WCHAR *out) {
    DWORD capacity = 256;
    if (!GetComputerNameExW(format, out, &capacity)) ExitProcess(GetLastError());
}

void WINAPI entry(void) {
    const WCHAR *cursor = GetCommandLineW();
    WCHAR executable[256]; DWORD count = 0, start = 1, nfields = 0, nselected = 0;
    int status, value_format = 0, kind = 0;
    if (next_arg(&cursor, executable) != 1) ExitProcess(ERROR_INVALID_PARAMETER);
    while ((status = next_arg(&cursor, tokens[count])) == 1) {
        if (++count == 16) ExitProcess(ERROR_INVALID_PARAMETER);
    }
    if (status < 0 || count < 2) ExitProcess(ERROR_INVALID_PARAMETER);
    if (equals(tokens[0], L"path")) {
        if (count < 3) ExitProcess(ERROR_INVALID_PARAMETER);
        start = 2;
    }
    const WCHAR *alias = tokens[start - 1];
    if (equals(alias, L"os") || equals(alias, L"Win32_OperatingSystem")) kind = 1;
    else if (equals(alias, L"computersystem") || equals(alias, L"Win32_ComputerSystem")) kind = 2;
    else if (equals(alias, L"cpu") || equals(alias, L"Win32_Processor")) kind = 3;
    else if (equals(alias, L"logicaldisk") || equals(alias, L"Win32_LogicalDisk")) kind = 4;
    if (!kind || !equals(tokens[start], L"get")) ExitProcess(ERROR_INVALID_PARAMETER);
    for (DWORD i = start + 1; i < count; ++i) {
        if (equals(tokens[i], L"/value")) {
            if (value_format || i + 1 != count) ExitProcess(ERROR_INVALID_PARAMETER);
            value_format = 1;
        } else {
            if (tokens[i][0] == L'/') ExitProcess(ERROR_INVALID_PARAMETER);
            if (properties[0]) append(properties, L" ");
            append(properties, tokens[i]);
        }
    }
    if (kind == 1) {
        names[0] = L"BuildNumber"; names[1] = L"CSName";
        names[2] = L"FreePhysicalMemory"; names[3] = L"TotalVisibleMemorySize";
        names[4] = L"Version"; names[5] = L"WindowsDirectory"; nfields = 6;
    } else if (kind == 2) {
        names[0] = L"Domain"; names[1] = L"Name";
        names[2] = L"NumberOfLogicalProcessors"; names[3] = L"TotalPhysicalMemory";
        names[4] = L"UserName"; nfields = 5;
    } else if (kind == 3) {
        names[0] = L"Name"; names[1] = L"NumberOfLogicalProcessors"; nfields = 2;
    } else {
        names[0] = L"DeviceID"; names[1] = L"FileSystem"; names[2] = L"FreeSpace";
        names[3] = L"Name"; names[4] = L"Size"; nfields = 5;
    }
    if (!properties[0]) {
        for (DWORD i = 0; i < nfields; ++i) selected[nselected++] = i;
    } else {
        WCHAR *p = properties;
        while (*p) {
            WCHAR *field = p; DWORD found = 0;
            while (*field == L' ' || *field == L'\t') ++field;
            while (*p && *p != L',') ++p;
            if (*p) { *p++ = 0; if (!*p) ExitProcess(ERROR_INVALID_PARAMETER); }
            DWORD end = length(field);
            while (end && (field[end - 1] == L' ' || field[end - 1] == L'\t')) field[--end] = 0;
            for (DWORD i = 0; i < nfields; ++i) if (equals(field, names[i])) {
                for (DWORD j = 0; j < nselected; ++j)
                    if (selected[j] == i) ExitProcess(ERROR_INVALID_PARAMETER);
                selected[nselected++] = i; found = 1; break;
            }
            if (!found) ExitProcess(ERROR_INVALID_PARAMETER);
        }
    }
    /* Only read APIs after the entire request has been validated. */
    if (kind == 1) {
        static OSVERSIONINFOW version; static MEMORYSTATUSEX memory; WCHAR minor[32];
        version.dwOSVersionInfoSize = sizeof(version); memory.dwLength = sizeof(memory);
        if (RtlGetVersion(&version) != 0 || !GlobalMemoryStatusEx(&memory)) ExitProcess(1);
        decimal(fields[0], version.dwBuildNumber); computer_name(ComputerNameNetBIOS, fields[1]);
        decimal(fields[2], memory.ullAvailPhys >> 10); decimal(fields[3], memory.ullTotalPhys >> 10);
        decimal(fields[4], version.dwMajorVersion); append(fields[4], L".");
        decimal(minor, version.dwMinorVersion); append(fields[4], minor); append(fields[4], L".");
        append(fields[4], fields[0]);
        if (!GetWindowsDirectoryW(fields[5], 256)) ExitProcess(GetLastError());
    } else if (kind == 2) {
        SYSTEM_INFO system; static MEMORYSTATUSEX memory; WCHAR user[256]; DWORD size = 256;
        WKSTA_INFO_100 *workstation = 0;
        DWORD result = NetWkstaGetInfo(0, 100, (BYTE **)&workstation);
        if (result != NERR_Success || !workstation) ExitProcess(result ? result : 1);
        append(fields[0], workstation->wki100_langroup);
        NetApiBufferFree(workstation);
        computer_name(ComputerNameNetBIOS, fields[1]);
        GetNativeSystemInfo(&system); decimal(fields[2], system.dwNumberOfProcessors);
        memory.dwLength = sizeof(memory);
        if (!GlobalMemoryStatusEx(&memory) || !GetUserNameW(user, &size)) ExitProcess(GetLastError());
        decimal(fields[3], memory.ullTotalPhys);
        /* GetUserNameW returns a leaf name; the configured logon domain is in guest environment. */
        if (!GetEnvironmentVariableW(L"USERDOMAIN", fields[4], 256)) ExitProcess(GetLastError());
        append(fields[4], L"\\"); append(fields[4], user);
    } else if (kind == 3) {
        HKEY key; DWORD type = 0, bytes = sizeof(fields[0]); SYSTEM_INFO system;
        LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", 0, KEY_READ, &key);
        if (result != ERROR_SUCCESS) ExitProcess(result);
        result = RegQueryValueExW(key, L"ProcessorNameString", 0, &type, (BYTE *)fields[0], &bytes);
        RegCloseKey(key);
        if (result != ERROR_SUCCESS || type != REG_SZ || bytes > sizeof(fields[0])) ExitProcess(1);
        fields[0][255] = 0;
        GetNativeSystemInfo(&system); decimal(fields[1], system.dwNumberOfProcessors);
    } else {
        ULARGE_INTEGER available, total, free_bytes; DWORD serial, max_component, flags; WCHAR label[64];
        append(fields[0], L"C:"); append(fields[3], L"C:");
        if (!GetVolumeInformationW(L"C:\\", label, 64, &serial, &max_component, &flags, fields[1], 256) ||
            !GetDiskFreeSpaceExW(L"C:\\", &available, &total, &free_bytes)) ExitProcess(GetLastError());
        decimal(fields[2], free_bytes.QuadPart); decimal(fields[4], total.QuadPart);
    }
    /* WMI emits properties alphabetically regardless of selection order. */
    for (DWORD i = 0; i < nselected; ++i) for (DWORD j = i + 1; j < nselected; ++j)
        if (selected[j] < selected[i]) { DWORD t = selected[i]; selected[i] = selected[j]; selected[j] = t; }
    if (value_format) {
        print(L"\r\n\r\n");
        for (DWORD i = 0; i < nselected; ++i) {
            DWORD k = selected[i]; print(names[k]); print(L"="); print(fields[k]); print(L"\r\n");
        }
        print(L"\r\n");
    } else {
        for (DWORD i = 0; i < nselected; ++i) {
            DWORD k = selected[i], a = length(names[k]), b = length(fields[k]);
            widths[i] = (a > b ? a : b) + 2;
            print(names[k]); for (DWORD j = a; j < widths[i]; ++j) print(L" ");
        }
        print(L"\r\n");
        for (DWORD i = 0; i < nselected; ++i) {
            DWORD k = selected[i]; print(fields[k]);
            for (DWORD j = length(fields[k]); j < widths[i]; ++j) print(L" ");
        }
        print(L"\r\n");
    }
    ExitProcess(0);
}

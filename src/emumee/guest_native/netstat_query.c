/* Guest-only netstat subset; reads a modeled IPv4 TCP table through IP Helper. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>

static BYTE table_bytes[8192];
static WCHAR argument[1024];
static WCHAR option[32];
static WCHAR digits[12];

static DWORD length(const WCHAR *text) {
    DWORD n = 0;
    while (text[n] && n < 65535) ++n;
    return n;
}

static void print(const WCHAR *text) {
    DWORD written = 0, n = length(text);
    if (n && !WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), text, n,
                            &written, 0)) ExitProcess(GetLastError());
}

static void print_number(DWORD value) {
    DWORD n = 0;
    do { digits[n++] = (WCHAR)(L'0' + value % 10); value /= 10; }
    while (value && n < 10);
    for (DWORD i = 0; i < n / 2; ++i) {
        WCHAR t = digits[i]; digits[i] = digits[n - i - 1]; digits[n - i - 1] = t;
    }
    digits[n] = 0;
    print(digits);
}

static int next_arg(const WCHAR **cursor, WCHAR *out, DWORD capacity) {
    const WCHAR *read = *cursor;
    DWORD count = 0;
    int quoted = 0;
    while (*read == L' ' || *read == L'\t') ++read;
    if (!*read) return 0;
    while (*read && (quoted || (*read != L' ' && *read != L'\t'))) {
        if (*read == L'"') quoted = !quoted;
        else if (count + 1 < capacity) out[count++] = *read;
        else return -1;
        ++read;
    }
    if (quoted) return -1;
    out[count] = 0;
    *cursor = read;
    return 1;
}

static int equals(const WCHAR *a, const WCHAR *b) {
    DWORD i = 0;
    while (a[i] && b[i]) {
        WCHAR x = a[i], y = b[i];
        if (x >= L'A' && x <= L'Z') x += L'a' - L'A';
        if (y >= L'A' && y <= L'Z') y += L'a' - L'A';
        if (x != y) return 0;
        ++i;
    }
    return !a[i] && !b[i];
}

static void print_endpoint(DWORD address, DWORD port) {
    const BYTE *ip = (const BYTE *)&address;
    const BYTE *network_port = (const BYTE *)&port;
    for (DWORD i = 0; i < 4; ++i) {
        if (i) print(L".");
        print_number(ip[i]);
    }
    print(L":");
    print_number(((DWORD)network_port[0] << 8) | network_port[1]);
}

void WINAPI entry(void) {
    const WCHAR *cursor = GetCommandLineW();
    if (next_arg(&cursor, argument, 1024) != 1) ExitProcess(ERROR_INVALID_PARAMETER);
    int option_present = next_arg(&cursor, option, 32);
    if (option_present < 0 || next_arg(&cursor, argument, 1024) != 0 ||
        (option_present && !equals(option, L"-an") && !equals(option, L"-ano")))
        ExitProcess(ERROR_INVALID_PARAMETER);
    int show_pid = option_present && equals(option, L"-ano");
    DWORD size = sizeof(table_bytes);
    DWORD result = GetExtendedTcpTable(table_bytes, &size, FALSE, AF_INET,
                                       TCP_TABLE_OWNER_PID_ALL, 0);
    if (result) ExitProcess(result);
    if (size < sizeof(DWORD)) ExitProcess(ERROR_INVALID_DATA);
    MIB_TCPTABLE_OWNER_PID *table = (MIB_TCPTABLE_OWNER_PID *)table_bytes;
    if (table->dwNumEntries > 128 ||
        table->dwNumEntries > (size - sizeof(DWORD)) / sizeof(MIB_TCPROW_OWNER_PID))
        ExitProcess(ERROR_INVALID_DATA);
    print(L"\r\nActive Connections\r\n\r\n");
    print(show_pid ? L"  Proto  Local Address       Foreign Address     State           PID\r\n" :
                     L"  Proto  Local Address       Foreign Address     State\r\n");
    for (DWORD i = 0; i < table->dwNumEntries; ++i) {
        const MIB_TCPROW_OWNER_PID *row = &table->table[i];
        print(L"  TCP    ");
        print_endpoint(row->dwLocalAddr, row->dwLocalPort);
        print(L"    ");
        print_endpoint(row->dwRemoteAddr, row->dwRemotePort);
        print(L"    ");
        print(row->dwState == 5 ? L"ESTABLISHED" : L"UNKNOWN");
        if (show_pid) { print(L"    "); print_number(row->dwOwningPid); }
        print(L"\r\n");
    }
    ExitProcess(0);
}

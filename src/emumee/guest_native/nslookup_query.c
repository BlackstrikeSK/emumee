/* Noninteractive guest DNS lookup. Never creates sockets or host processes. */
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <windns.h>

static WCHAR image[1024], args[4][256], server[64], query[256], number[16];
static BYTE network[4096];

static DWORD length(const WCHAR *s) { DWORD n = 0; while (s[n]) ++n; return n; }
static void print(const WCHAR *s) {
    DWORD written, n = length(s);
    if (n && !WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), s, n, &written, 0)) ExitProcess(GetLastError());
}
static void decimal(DWORD value) {
    DWORD n = 0;
    do { number[n++] = (WCHAR)(L'0' + value % 10); value /= 10; } while (value);
    for (DWORD i = 0; i < n / 2; ++i) {
        WCHAR t = number[i]; number[i] = number[n - i - 1]; number[n - i - 1] = t;
    }
    number[n] = 0;
}
static int equals(const WCHAR *a, const WCHAR *b) {
    while (*a && *b) {
        WCHAR x = *a++, y = *b++;
        if (x >= L'A' && x <= L'Z') x += 32;
        if (y >= L'A' && y <= L'Z') y += 32;
        if (x != y) return 0;
    }
    return !*a && !*b;
}
static int next_arg(const WCHAR **cursor, WCHAR *out, DWORD capacity) {
    const WCHAR *s = *cursor; DWORD n = 0; int quoted = 0;
    while (*s == L' ' || *s == L'\t') ++s;
    if (!*s) return 0;
    while (*s && (quoted || (*s != L' ' && *s != L'\t'))) {
        if (*s == L'"') quoted = !quoted;
        else if (n + 1 < capacity) out[n++] = *s;
        else return -1;
        ++s;
    }
    if (quoted || !n) return -1;
    out[n] = 0; *cursor = s; return 1;
}
static void append(const WCHAR *s) {
    DWORD n = length(query);
    while (*s && n < 255) query[n++] = *s++;
    if (*s) ExitProcess(ERROR_INVALID_PARAMETER);
    query[n] = 0;
}
static int ipv4(const WCHAR *s, DWORD *bytes) {
    for (DWORD i = 0; i < 4; ++i) {
        DWORD value = 0, digits = 0;
        while (*s >= L'0' && *s <= L'9') { value = value * 10 + (*s++ - L'0'); if (++digits > 3) return 0; }
        if (!digits || value > 255) return 0;
        bytes[i] = value;
        if (i < 3) { if (*s++ != L'.') return 0; }
        else if (*s) return 0;
    }
    return 1;
}
static void address(const BYTE *bytes, int v6) {
    if (!v6) {
        for (DWORD i = 0; i < 4; ++i) {
            if (i) print(L"."); decimal(bytes[i]); print(number);
        }
    } else {
        static const WCHAR digits[] = L"0123456789abcdef";
        DWORD words[8], best = 8, best_len = 0;
        for (DWORD i = 0; i < 8; ++i) words[i] = ((DWORD)bytes[2 * i] << 8) | bytes[2 * i + 1];
        for (DWORD i = 0; i < 8;) {
            if (words[i]) { ++i; continue; }
            DWORD start = i; while (i < 8 && !words[i]) ++i;
            if (i - start > best_len && i - start >= 2) { best = start; best_len = i - start; }
        }
        for (DWORD i = 0; i < 8;) {
            if (i == best) { print(L"::"); i += best_len; continue; }
            if (i && i != best + best_len) print(L":");
            DWORD n = 0; int started = 0;
            for (int shift = 12; shift >= 0; shift -= 4) {
                DWORD nibble = (words[i] >> shift) & 15;
                if (nibble || started || !shift) { number[n++] = digits[nibble]; started = 1; }
            }
            number[n] = 0; print(number); ++i;
        }
    }
}

void WINAPI entry(void) {
    const WCHAR *cursor = GetCommandLineW(); DWORD argc = 0, start = 0, ip[4];
    WORD type = DNS_TYPE_A; int status;
    if (next_arg(&cursor, image, 1024) != 1) ExitProcess(ERROR_INVALID_PARAMETER);
    while ((status = next_arg(&cursor, args[argc], 256)) == 1)
        if (++argc == 4) ExitProcess(ERROR_INVALID_PARAMETER);
    if (status < 0 || !argc) ExitProcess(ERROR_INVALID_PARAMETER);
    if (equals(args[0], L"-type=A")) start = 1;
    else if (equals(args[0], L"-type=AAAA")) { start = 1; type = DNS_TYPE_AAAA; }
    else if (equals(args[0], L"-type=PTR")) { start = 1; type = DNS_TYPE_PTR; }
    else if (args[0][0] == L'-') ExitProcess(ERROR_INVALID_PARAMETER);
    if (argc <= start || argc > start + 2 || args[start][0] == L'-') ExitProcess(ERROR_INVALID_PARAMETER);
    DWORD bytes = sizeof(network);
    if (GetNetworkParams((FIXED_INFO *)network, &bytes) != ERROR_SUCCESS) ExitProcess(1);
    const char *dns = ((FIXED_INFO *)network)->DnsServerList.IpAddress.String;
    DWORD n = 0; while (dns[n] && n < 63) { server[n] = (WCHAR)(BYTE)dns[n]; ++n; }
    server[n] = 0;
    /* Explicit targets must match the configured primary guest server. */
    if (argc == start + 2 && !equals(args[start + 1], server)) ExitProcess(ERROR_INVALID_PARAMETER);
    int reverse = type != DNS_TYPE_AAAA && ipv4(args[start], ip);
    if (reverse) {
        type = DNS_TYPE_PTR;
        for (int i = 3; i >= 0; --i) { decimal(ip[i]); append(number); append(L"."); }
        append(L"in-addr.arpa");
    } else append(args[start]);
    print(L"Server:  UnKnown\r\nAddress:  "); print(server); print(L"\r\n\r\n");
    DNS_RECORDW *records = 0;
    DNS_STATUS result = DnsQuery_W(query, type, DNS_QUERY_NO_WIRE_QUERY, 0, &records, 0);
    if (result != ERROR_SUCCESS) {
        print(L"*** UnKnown can't find "); print(args[start]);
        print(result == DNS_ERROR_RCODE_NAME_ERROR ? L": Nonexistent domain\r\n" :
              result == DNS_INFO_NO_RECORDS ? L": No records\r\n" : L": Query not available\r\n");
        ExitProcess(1);
    }
    if (!records) ExitProcess(1);
    if (type == DNS_TYPE_PTR) {
        print(L"Name:  "); print(records->Data.PTR.pNameHost); print(L"\r\n");
        if (reverse) { print(L"Address:  "); print(args[start]); print(L"\r\n"); }
    } else {
        print(L"Name:  "); print(records->pName); print(L"\r\nAddresses:  ");
        DWORD count = 0;
        for (DNS_RECORDW *record = records; record && count < 128; record = record->pNext, ++count) {
            if (count) print(L"\r\n          ");
            if (record->wType == DNS_TYPE_A) address((BYTE *)&record->Data.A.IpAddress, 0);
            else if (record->wType == DNS_TYPE_AAAA) address((BYTE *)&record->Data.AAAA.Ip6Address, 1);
            else ExitProcess(1);
        }
        print(L"\r\n");
    }
    DnsRecordListFree(records, DnsFreeRecordList);
    ExitProcess(0);
}

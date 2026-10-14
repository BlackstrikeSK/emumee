/* Offline guest IPv4 traceroute using modeled DNS and ICMP APIs. */
#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <windns.h>

static WCHAR image[1024], args[9][256], number[12], target[256];
static BYTE request[32], reply[4200];
static IP_OPTION_INFORMATION options;

static DWORD length(const WCHAR *s) { DWORD n = 0; while (s[n]) ++n; return n; }
static void print(const WCHAR *s) {
    DWORD written, n = length(s);
    if (n && !WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), s, n, &written, 0)) ExitProcess(GetLastError());
}
static void print_number(DWORD value) {
    DWORD n = 0;
    do { number[n++] = (WCHAR)(L'0' + value % 10); value /= 10; } while (value);
    for (DWORD i = 0; i < n / 2; ++i) {
        WCHAR t = number[i]; number[i] = number[n - i - 1]; number[n - i - 1] = t;
    }
    number[n] = 0; print(number);
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
static int decimal(const WCHAR *s, DWORD maximum, DWORD *value) {
    DWORD result = 0;
    if (!*s) return 0;
    while (*s) {
        if (*s < L'0' || *s > L'9') return 0;
        DWORD digit = *s++ - L'0';
        if (result > maximum / 10 || (result == maximum / 10 && digit > maximum % 10)) return 0;
        result = result * 10 + digit;
    }
    *value = result; return 1;
}
static int ipv4(const WCHAR *s, IPAddr *result) {
    BYTE *bytes = (BYTE *)result;
    for (DWORD i = 0; i < 4; ++i) {
        DWORD value = 0, n = 0;
        while (*s >= L'0' && *s <= L'9') { value = value * 10 + (*s++ - L'0'); if (++n > 3) return 0; }
        if (!n || value > 255) return 0;
        bytes[i] = (BYTE)value;
        if (i < 3) { if (*s++ != L'.') return 0; }
        else if (*s) return 0;
    }
    return 1;
}
static void print_address(IPAddr ip) {
    const BYTE *bytes = (const BYTE *)&ip;
    for (DWORD i = 0; i < 4; ++i) { if (i) print(L"."); print_number(bytes[i]); }
}

static int reverse_name(IPAddr ip, WCHAR *name) {
    WCHAR query[64]; DWORD n = 0;
    const BYTE *bytes = (const BYTE *)&ip;
    for (DWORD i = 0; i < 4; ++i) {
        DWORD value = bytes[3 - i], digits = 0;
        do { number[digits++] = (WCHAR)(L'0' + value % 10); value /= 10; } while (value);
        while (digits) query[n++] = number[--digits];
        query[n++] = L'.';
    }
    const WCHAR *suffix = L"in-addr.arpa";
    do { query[n++] = *suffix; } while (*suffix++);
    DNS_RECORDW *records = 0;
    if (DnsQuery_W(query, DNS_TYPE_PTR, DNS_QUERY_NO_WIRE_QUERY, 0, &records, 0) ||
        !records || records->wType != DNS_TYPE_PTR) return 0;
    const WCHAR *answer = records->Data.PTR.pNameHost;
    DWORD count = 0;
    if (answer) while (answer[count] && count < 254) { name[count] = answer[count]; ++count; }
    name[count] = 0;
    DnsRecordListFree(records, DnsFreeRecordList);
    return count != 0;
}

void WINAPI entry(void) {
    const WCHAR *cursor = GetCommandLineW();
    DWORD argc = 0, max_hops = 30, timeout = 4000, flags = 0;
    int status;
    if (next_arg(&cursor, image, 1024) != 1) ExitProcess(ERROR_INVALID_PARAMETER);
    while ((status = next_arg(&cursor, args[argc], 256)) == 1)
        if (++argc == 9) ExitProcess(ERROR_INVALID_PARAMETER);
    if (status < 0 || !argc) ExitProcess(ERROR_INVALID_PARAMETER);
    for (DWORD i = 0; i < argc; ++i) {
        if (args[i][0] == L'-' || args[i][0] == L'/') {
            DWORD flag = equals(args[i] + 1, L"d") ? 1 : equals(args[i] + 1, L"4") ? 2 :
                         equals(args[i] + 1, L"h") ? 4 : equals(args[i] + 1, L"w") ? 8 : 0;
            if (!flag || flags & flag) ExitProcess(ERROR_INVALID_PARAMETER);
            flags |= flag;
            if (flag <= 2) continue;
            DWORD value;
            if (i + 1 == argc || !decimal(args[++i], flag == 4 ? 255 : 60000, &value) ||
                (flag == 4 && !value)) ExitProcess(ERROR_INVALID_PARAMETER);
            if (flag == 4) max_hops = value; else timeout = value;
        } else {
            if (target[0]) ExitProcess(ERROR_INVALID_PARAMETER);
            DWORD n = 0; do { target[n] = args[i][n]; } while (args[i][n++]);
        }
    }
    if (!target[0]) ExitProcess(ERROR_INVALID_PARAMETER);
    IPAddr ip = 0;
    int literal = ipv4(target, &ip);
    if (!literal) {
        DNS_RECORDW *records = 0;
        if (DnsQuery_W(target, DNS_TYPE_A, DNS_QUERY_NO_WIRE_QUERY, 0, &records, 0) ||
            !records || records->wType != DNS_TYPE_A) {
            print(L"Unable to resolve target system name "); print(target); print(L".\r\n"); ExitProcess(1);
        }
        ip = records->Data.A.IpAddress;
        DnsRecordListFree(records, DnsFreeRecordList);
    }
    WCHAR resolved[256];
    int named = !literal;
    if (literal && !(flags & 1)) named = reverse_name(ip, resolved);
    print(L"\r\nTracing route to ");
    if (named) { print(literal ? resolved : target); print(L" ["); print_address(ip); print(L"]"); }
    else print_address(ip);
    print(L"\r\nover a maximum of "); print_number(max_hops); print(L" hops:\r\n\r\n");
    HANDLE handle = IcmpCreateFile();
    if (handle == INVALID_HANDLE_VALUE) ExitProcess(1);
    for (DWORD i = 0; i < 32; ++i) request[i] = (BYTE)('a' + i % 23);
    for (DWORD hop = 1; hop <= max_hops; ++hop) {
        IPAddr address = 0; int any = 0, reached = 0, failed = 0;
        options.Ttl = (BYTE)hop;
        print(L"  "); print_number(hop);
        for (DWORD probe = 0; probe < 3; ++probe) {
            DWORD count = IcmpSendEcho(handle, ip, request, 32, &options, reply, sizeof(reply), timeout);
            DWORD error = count ? 0 : GetLastError();
            ICMP_ECHO_REPLY *echo = (ICMP_ECHO_REPLY *)reply;
            if (count && (echo->Status == IP_SUCCESS || echo->Status == IP_TTL_EXPIRED_TRANSIT)) {
                if (echo->Status == IP_SUCCESS && (echo->DataSize != 32 || !echo->Data ||
                    ((BYTE *)echo->Data)[0] != request[0] || ((BYTE *)echo->Data)[31] != request[31])) {
                    failed = 1; print(L"     *   "); continue;
                }
                any = 1; address = echo->Address;
                if (echo->Status == IP_SUCCESS && address == ip) reached = 1;
                print(L"    ");
                if (echo->RoundTripTime == 0) print(L"<1 ms");
                else { print_number(echo->RoundTripTime); print(L" ms"); }
            } else {
                print(L"     *   ");
                if (count || error != IP_REQ_TIMED_OUT) failed = 1;
            }
        }
        print(L"  ");
        if (any) {
            if (!(flags & 1) && reverse_name(address, resolved)) {
                print(resolved); print(L" ["); print_address(address); print(L"]");
            } else print_address(address);
        } else print(failed ? L"General failure." : L"Request timed out.");
        print(L"\r\n");
        if (failed) { IcmpCloseHandle(handle); ExitProcess(1); }
        if (reached) break;
    }
    IcmpCloseHandle(handle);
    print(L"\r\nTrace complete.\r\n");
    ExitProcess(0);
}


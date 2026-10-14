/* Bounded guest IPv4 ping. DNS and ICMP calls are handled by guest API models. */
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
static BYTE request[4096], reply[4200];

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

void WINAPI entry(void) {
    const WCHAR *cursor = GetCommandLineW(); DWORD argc = 0, count = 4, size = 32, timeout = 4000, flags = 0;
    int status;
    if (next_arg(&cursor, image, 1024) != 1) ExitProcess(ERROR_INVALID_PARAMETER);
    while ((status = next_arg(&cursor, args[argc], 256)) == 1)
        if (++argc == 9) ExitProcess(ERROR_INVALID_PARAMETER);
    if (status < 0 || !argc) ExitProcess(ERROR_INVALID_PARAMETER);
    for (DWORD i = 0; i < argc; ++i) {
        if (args[i][0] == L'-' || args[i][0] == L'/') {
            if (equals(args[i] + 1, L"4")) {
                if (flags & 8) ExitProcess(ERROR_INVALID_PARAMETER);
                flags |= 8; continue;
            }
            DWORD flag = equals(args[i] + 1, L"n") ? 1 : equals(args[i] + 1, L"l") ? 2 :
                         equals(args[i] + 1, L"w") ? 4 : 0;
            if (!flag || flags & flag || i + 1 == argc) ExitProcess(ERROR_INVALID_PARAMETER);
            flags |= flag;
            DWORD value, maximum = flag == 1 ? 16 : flag == 2 ? 4096 : 60000;
            if (!decimal(args[++i], maximum, &value) || (flag == 1 && !value)) ExitProcess(ERROR_INVALID_PARAMETER);
            if (flag == 1) count = value; else if (flag == 2) size = value; else timeout = value;
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
            print(L"Ping request could not find host "); print(target);
            print(L". Please check the name and try again.\r\n"); ExitProcess(1);
        }
        ip = records->Data.A.IpAddress;
        DnsRecordListFree(records, DnsFreeRecordList);
    }
    HANDLE handle = IcmpCreateFile();
    if (handle == INVALID_HANDLE_VALUE) ExitProcess(1);
    for (DWORD i = 0; i < size; ++i) request[i] = (BYTE)('a' + i % 23);
    print(L"\r\nPinging ");
    if (!literal) { print(target); print(L" ["); print_address(ip); print(L"]"); }
    else print_address(ip);
    print(L" with "); print_number(size); print(L" bytes of data:\r\n");
    DWORD received = 0, total = 0, minimum = 0xffffffff, maximum = 0;
    for (DWORD i = 0; i < count; ++i) {
        DWORD replies = IcmpSendEcho(handle, ip, request, (WORD)size, 0, reply, sizeof(reply), timeout);
        ICMP_ECHO_REPLY *echo = (ICMP_ECHO_REPLY *)reply;
        DWORD wait = timeout;
        if (replies && echo->Status == IP_SUCCESS && echo->DataSize == size &&
            (!size || (echo->Data && ((BYTE *)echo->Data)[0] == request[0] && ((BYTE *)echo->Data)[size - 1] == request[size - 1]))) {
            ++received; wait = echo->RoundTripTime; total += wait;
            if (wait < minimum) minimum = wait;
            if (wait > maximum) maximum = wait;
            print(L"Reply from "); print_address(echo->Address); print(L": bytes="); print_number(echo->DataSize);
            if (!wait) print(L" time<1ms"); else { print(L" time="); print_number(wait); print(L"ms"); }
            print(L" TTL="); print_number(echo->Options.Ttl); print(L"\r\n");
        } else if (!replies && GetLastError() == IP_REQ_TIMED_OUT) print(L"Request timed out.\r\n");
        else { print(L"General failure.\r\n"); wait = 0; }
        if (i + 1 < count && wait < 1000) Sleep(1000 - wait);
    }
    IcmpCloseHandle(handle);
    print(L"\r\nPing statistics for "); print_address(ip); print(L":\r\n    Packets: Sent = "); print_number(count);
    print(L", Received = "); print_number(received); print(L", Lost = "); print_number(count - received);
    print(L" ("); print_number((count - received) * 100 / count); print(L"% loss),\r\n");
    if (received) {
        print(L"Approximate round trip times in milli-seconds:\r\n    Minimum = "); print_number(minimum);
        print(L"ms, Maximum = "); print_number(maximum); print(L"ms, Average = "); print_number(total / received); print(L"ms\r\n");
    }
    ExitProcess(received ? 0 : 1);
}

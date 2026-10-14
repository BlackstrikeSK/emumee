/* Offline route discovery followed by measured, guest-only echo statistics. */
#define EMUMEE_ROUTE_HELPERS_ONLY
#include "tracert_query.c"

static IPAddr addresses[256];
static DWORD received[256], elapsed[256], losses[256], forwarding[256];
static BYTE adapters[16384];

static void show_address(IPAddr ip, int numeric) {
    WCHAR resolved[256];
    if (!numeric && reverse_name(ip, resolved)) {
        print(resolved); print(L" ["); print_address(ip); print(L"]");
    } else print_address(ip);
}
static void show_loss(DWORD lost, DWORD sent) {
    print_number(lost); print(L"/"); print_number(sent); print(L" = ");
    print_number(lost * 100 / sent); print(L"%");
}
static int probe(HANDLE handle, IPAddr ip, DWORD ttl, DWORD timeout, IPAddr *peer, DWORD *rtt) {
    options.Ttl = (BYTE)ttl;
    DWORD count = IcmpSendEcho(handle, ip, request, 32, &options, reply, sizeof(reply), timeout);
    DWORD error = count ? 0 : GetLastError();
    if (!count) return error == IP_REQ_TIMED_OUT ? 0 : -1;
    ICMP_ECHO_REPLY *echo = (ICMP_ECHO_REPLY *)reply;
    if (echo->Status != IP_SUCCESS && echo->Status != IP_TTL_EXPIRED_TRANSIT) return -1;
    if (echo->Status == IP_SUCCESS && (echo->DataSize != 32 || !echo->Data ||
            ((BYTE *)echo->Data)[0] != request[0] || ((BYTE *)echo->Data)[31] != request[31])) return -1;
    *peer = echo->Address; *rtt = echo->RoundTripTime;
    return echo->Status == IP_SUCCESS ? 1 : 2;
}

void WINAPI entry(void) {
    const WCHAR *cursor = GetCommandLineW();
    DWORD argc = 0, max_hops = 30, timeout = 3000, queries = 100, period = 250, flags = 0;
    int status;
    if (next_arg(&cursor, image, 1024) != 1) ExitProcess(ERROR_INVALID_PARAMETER);
    while ((status = next_arg(&cursor, args[argc], 256)) == 1)
        if (++argc == 17) ExitProcess(ERROR_INVALID_PARAMETER);
    if (status < 0) ExitProcess(ERROR_INVALID_PARAMETER);
    if (!argc || (argc == 1 && equals(args[0], L"/?"))) {
        print(L"Usage: pathping [-n] [-4] [-h maximum_hops] [-p period_ms] [-q queries] [-w timeout_ms] target\r\n");
        ExitProcess(0);
    }
    for (DWORD i = 0; i < argc; ++i) {
        if (args[i][0] == L'-' || args[i][0] == L'/') {
            /* The documented pathping switches are case sensitive. */
            WCHAR option = args[i][1];
            if (!option || args[i][2]) ExitProcess(ERROR_INVALID_PARAMETER);
            DWORD flag = option == L'n' ? 1 : option == L'4' ? 2 : option == L'h' ? 4 :
                         option == L'w' ? 8 : option == L'q' ? 16 : option == L'p' ? 32 : 0;
            if (!flag || flags & flag) ExitProcess(ERROR_INVALID_PARAMETER);
            flags |= flag;
            if (flag <= 2) continue;
            DWORD value, bound = flag == 4 ? 255 : flag == 16 ? 1000 : 60000;
            if (i + 1 == argc || !decimal(args[++i], bound, &value) ||
                    ((flag == 4 || flag == 16) && !value)) ExitProcess(ERROR_INVALID_PARAMETER);
            if (flag == 4) max_hops = value;
            else if (flag == 8) timeout = value;
            else if (flag == 16) queries = value;
            else period = value;
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
    ULONG capacity = sizeof(adapters);
    if (GetAdaptersAddresses(AF_INET, 0, 0, (IP_ADAPTER_ADDRESSES *)adapters, &capacity)) ExitProcess(1);
    IP_ADAPTER_UNICAST_ADDRESS *local = ((IP_ADAPTER_ADDRESSES *)adapters)->FirstUnicastAddress;
    if (!local || !local->Address.lpSockaddr || local->Address.lpSockaddr->sa_family != AF_INET) ExitProcess(1);
    addresses[0] = ((struct sockaddr_in *)local->Address.lpSockaddr)->sin_addr.s_addr;
    print(L"\r\nTracing route to ");
    if (!literal) { print(target); print(L" ["); print_address(ip); print(L"]"); }
    else show_address(ip, flags & 1);
    print(L"\r\nover a maximum of "); print_number(max_hops); print(L" hops:\r\n");
    print(L"  0  "); show_address(addresses[0], flags & 1); print(L"\r\n");
    HANDLE handle = IcmpCreateFile();
    if (handle == INVALID_HANDLE_VALUE) ExitProcess(1);
    for (DWORD i = 0; i < 32; ++i) request[i] = (BYTE)('a' + i % 23);
    DWORD hops = 0, known = 0;
    for (DWORD hop = 1; hop <= max_hops; ++hop) {
        IPAddr peer = 0; DWORD rtt = 0;
        int answer = 0;
        for (DWORD attempt = 0; attempt < 3 && !answer; ++attempt) {
            answer = probe(handle, ip, hop, timeout, &peer, &rtt);
            if (answer < 0) { IcmpCloseHandle(handle); ExitProcess(1); }
        }
        hops = hop; addresses[hop] = answer ? peer : 0;
        print(L"  "); print_number(hop); print(L"  ");
        if (answer) { show_address(peer, flags & 1); ++known; }
        else print(L"* * *");
        print(L"\r\n");
        if (answer == 1 && peer == ip) break;
    }
    DWORD count = queries * known;
    print(L"\r\nComputing statistics for ");
    print_number(count * (period / 1000) + (count * (period % 1000) + 999) / 1000);
    print(L" seconds...\r\n");
    /* Sequential guest probes advance virtual time. They never wait on the host. */
    for (DWORD query = 0; query < queries; ++query) {
        for (DWORD hop = 1; hop <= hops; ++hop) {
            if (!addresses[hop]) continue;
            IPAddr peer = 0; DWORD rtt = 0;
            int answer = probe(handle, addresses[hop], 255, timeout, &peer, &rtt);
            if (answer < 0) { IcmpCloseHandle(handle); ExitProcess(1); }
            if (answer == 1 && peer == addresses[hop]) { ++received[hop]; elapsed[hop] += rtt; }
            if (period) Sleep(period);
        }
    }
    IcmpCloseHandle(handle);
    /* Suffix minima separate excess local echo loss from sustained downstream
       loss. These are inferred statistics, not an independent link sensor. */
    DWORD downstream = queries;
    int gap = 0;
    for (DWORD hop = hops; hop; --hop) {
        losses[hop] = queries - received[hop];
        if (!addresses[hop]) { gap = 1; continue; }
        if (losses[hop] < downstream) downstream = losses[hop];
        forwarding[hop] = gap ? queries + 1 : downstream;
    }
    print(L"            Source to Here   This Node/Link\r\n");
    print(L"Hop  RTT    Lost/Sent = Pct  Lost/Sent = Pct  Address\r\n");
    print(L"  0                                         "); show_address(addresses[0], flags & 1); print(L"\r\n");
    DWORD previous = 0;
    for (DWORD hop = 1; hop <= hops; ++hop) {
        print(L"                            ");
        if (!addresses[hop] || forwarding[hop] > queries || previous > queries) print(L"---");
        else show_loss(forwarding[hop] > previous ? forwarding[hop] - previous : 0, queries);
        print(L"  |\r\n  "); print_number(hop); print(L"  ");
        if (received[hop]) { print_number(elapsed[hop] / received[hop]); print(L"ms"); }
        else print(L"---");
        print(L"    ");
        if (!addresses[hop]) {
            print(L"---              ---              * * *\r\n"); previous = queries + 1; continue;
        }
        show_loss(losses[hop], queries); print(L"    ");
        if (forwarding[hop] > queries) print(L"---");
        else show_loss(losses[hop] - forwarding[hop], queries);
        print(L"  "); show_address(addresses[hop], flags & 1); print(L"\r\n");
        previous = forwarding[hop];
    }
    print(L"\r\nTrace complete.\r\n");
    ExitProcess(0);
}

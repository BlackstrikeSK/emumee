/* Guest-only event channel reader. Registry calls are handled by the guest. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#pragma function(memcpy)

void *__cdecl memcpy(void *destination, const void *source, size_t count) {
    volatile BYTE *write = (volatile BYTE *)destination;
    const volatile BYTE *read = (const volatile BYTE *)source;
    for (size_t i = 0; i < count; ++i) write[i] = read[i];
    return destination;
}

static const WCHAR root_path[] = L"SYSTEM\\CurrentControlSet\\Services\\EventLog";
static WCHAR args[3][128];
static WCHAR key_path[256];
static WCHAR channel_name[128];
static WCHAR file_path[512];
static WCHAR number[12];

static DWORD length(const WCHAR *value) {
    DWORD count = 0;
    while (value[count] && count < 512) ++count;
    return count;
}

static void print(const WCHAR *value) {
    DWORD count = length(value), written = 0;
    if (count && !WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), value, count,
                                &written, 0)) ExitProcess(GetLastError());
}

static void print_decimal(DWORD value) {
    DWORD count = 0;
    do { number[count++] = (WCHAR)(L'0' + value % 10); value /= 10; }
    while (value && count < 10);
    for (DWORD i = 0; i < count / 2; ++i) {
        WCHAR temp = number[i]; number[i] = number[count - 1 - i];
        number[count - 1 - i] = temp;
    }
    number[count] = 0;
    print(number);
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

static WCHAR lower(WCHAR value) {
    return value >= L'A' && value <= L'Z' ? value + L'a' - L'A' : value;
}

static int equals(const WCHAR *left, const WCHAR *right) {
    DWORD i = 0;
    while (left[i] && right[i]) {
        if (lower(left[i]) != lower(right[i])) return 0;
        ++i;
    }
    return !left[i] && !right[i];
}

static DWORD read_dword(HKEY key, const WCHAR *name) {
    DWORD value = 0, size = sizeof(value), kind = 0;
    DWORD result = RegQueryValueExW(key, name, 0, &kind, (BYTE *)&value, &size);
    if (result != ERROR_SUCCESS) ExitProcess(result);
    if (kind != REG_DWORD || size != sizeof(value)) ExitProcess(ERROR_INVALID_DATA);
    return value;
}

static void read_file(HKEY key) {
    DWORD size = sizeof(file_path), kind = 0;
    DWORD result = RegQueryValueExW(key, L"File", 0, &kind,
                                    (BYTE *)file_path, &size);
    if (result != ERROR_SUCCESS) ExitProcess(result);
    if (kind != REG_EXPAND_SZ || size < sizeof(WCHAR) ||
        size > sizeof(file_path) || size % sizeof(WCHAR)) ExitProcess(ERROR_INVALID_DATA);
    file_path[size / sizeof(WCHAR) - 1] = 0;
}

void WINAPI entry(void) {
    const WCHAR *cursor = GetCommandLineW();
    if (next_arg(&cursor, args[0], 128) != 1 ||
        next_arg(&cursor, args[1], 128) != 1) ExitProcess(ERROR_INVALID_PARAMETER);
    int has_channel = next_arg(&cursor, args[2], 128);
    if (has_channel < 0 || next_arg(&cursor, channel_name, 128) != 0)
        ExitProcess(ERROR_INVALID_PARAMETER);
    if (equals(args[1], L"el") && !has_channel) {
        HKEY key = 0;
        DWORD result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, root_path, 0,
                                     KEY_READ, &key);
        if (result != ERROR_SUCCESS) ExitProcess(result);
        for (DWORD index = 0; index < 32; ++index) {
            DWORD name_size = 127;
            result = RegEnumKeyExW(key, index, channel_name, &name_size,
                                   0, 0, 0, 0);
            if (result == ERROR_NO_MORE_ITEMS) break;
            if (result != ERROR_SUCCESS) ExitProcess(result);
            channel_name[name_size] = 0;
            print(channel_name); print(L"\r\n");
        }
        RegCloseKey(key);
        ExitProcess(0);
    }
    if (!equals(args[1], L"gl") || has_channel != 1)
        ExitProcess(ERROR_INVALID_PARAMETER);
    DWORD name_size = length(args[2]);
    if (!name_size || name_size > 64) ExitProcess(ERROR_INVALID_PARAMETER);
    for (DWORD i = 0; i < name_size; ++i) {
        WCHAR c = args[2][i];
        if (!((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') ||
              (c >= L'0' && c <= L'9') || c == L'_' || c == L'.' || c == L'-'))
            ExitProcess(ERROR_INVALID_PARAMETER);
    }
    DWORD prefix_size = length(root_path);
    for (DWORD i = 0; i < prefix_size; ++i) key_path[i] = root_path[i];
    key_path[prefix_size] = L'\\';
    for (DWORD i = 0; i < name_size; ++i) key_path[prefix_size + 1 + i] = args[2][i];
    key_path[prefix_size + 1 + name_size] = 0;
    HKEY key = 0;
    DWORD result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_path, 0,
                                 KEY_READ, &key);
    if (result != ERROR_SUCCESS) ExitProcess(result);
    DWORD enabled = read_dword(key, L"Enabled");
    DWORD max_size = read_dword(key, L"MaxSize");
    DWORD retention = read_dword(key, L"Retention");
    read_file(key);
    RegCloseKey(key);
    print(L"name: "); print(args[2]); print(L"\r\n");
    print(L"enabled: "); print(enabled ? L"true" : L"false"); print(L"\r\n");
    print(L"logging:\r\n  logFileName: "); print(file_path); print(L"\r\n");
    print(L"  retention: "); print(retention ? L"true" : L"false"); print(L"\r\n");
    print(L"  maxSize: "); print_decimal(max_size); print(L"\r\n");
    ExitProcess(0);
}

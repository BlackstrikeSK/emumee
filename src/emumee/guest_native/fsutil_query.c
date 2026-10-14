/* Guest-only fsutil fsinfo subset. Volume data comes from guest WinAPI. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static WCHAR image[1024];
static WCHAR arg[4][64];
static WCHAR label[64];
static WCHAR fs_name[64];
static WCHAR number[12];

static DWORD length(const WCHAR *value) {
    DWORD n = 0;
    while (value[n] && n < 4096) ++n;
    return n;
}

static void print(const WCHAR *value) {
    DWORD written = 0, n = length(value);
    if (n && !WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), value, n,
                            &written, 0)) ExitProcess(GetLastError());
}

static void print_decimal(DWORD value) {
    DWORD n = 0;
    do { number[n++] = (WCHAR)(L'0' + value % 10); value /= 10; }
    while (value && n < 10);
    for (DWORD i = 0; i < n / 2; ++i) {
        WCHAR temp = number[i]; number[i] = number[n - i - 1]; number[n - i - 1] = temp;
    }
    number[n] = 0;
    print(number);
}

static void print_hex(DWORD value) {
    static const WCHAR digits[] = L"0123456789abcdef";
    for (DWORD i = 0; i < 8; ++i) number[i] = digits[(value >> (28 - i * 4)) & 15];
    number[8] = 0;
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

static int equals(const WCHAR *left, const WCHAR *right) {
    DWORD i = 0;
    while (left[i] && right[i]) {
        WCHAR a = left[i], b = right[i];
        if (a >= L'A' && a <= L'Z') a += L'a' - L'A';
        if (b >= L'A' && b <= L'Z') b += L'a' - L'A';
        if (a != b) return 0;
        ++i;
    }
    return !left[i] && !right[i];
}

void WINAPI entry(void) {
    const WCHAR *cursor = GetCommandLineW();
    if (next_arg(&cursor, image, 1024) != 1 ||
        next_arg(&cursor, arg[0], 64) != 1 ||
        next_arg(&cursor, arg[1], 64) != 1 ||
        !equals(arg[0], L"fsinfo")) ExitProcess(ERROR_INVALID_PARAMETER);
    int has_drive = next_arg(&cursor, arg[2], 64);
    if (has_drive < 0 || next_arg(&cursor, arg[3], 64) != 0)
        ExitProcess(ERROR_INVALID_PARAMETER);
    if (equals(arg[1], L"drives") && !has_drive) {
        print(L"Drives: C:\\\r\n");
        ExitProcess(0);
    }
    if (!has_drive ||
        (!equals(arg[1], L"drivetype") && !equals(arg[1], L"volumeinfo")))
        ExitProcess(ERROR_INVALID_PARAMETER);
    if (!equals(arg[2], L"C:") && !equals(arg[2], L"C:\\"))
        ExitProcess(ERROR_PATH_NOT_FOUND);
    if (equals(arg[1], L"drivetype")) {
        print(L"Fixed Drive\r\n");
        ExitProcess(0);
    }
    DWORD serial = 0, max_component = 0, flags = 0;
    if (!GetVolumeInformationW(L"C:\\", label, 64, &serial, &max_component,
                               &flags, fs_name, 64)) ExitProcess(GetLastError());
    print(L"Volume Name : "); print(label); print(L"\r\n");
    print(L"Serial Number : 0x"); print_hex(serial); print(L"\r\n");
    print(L"Max Component Length : "); print_decimal(max_component); print(L"\r\n");
    print(L"File System Name : "); print(fs_name); print(L"\r\n");
    ExitProcess(0);
}

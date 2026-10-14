/* Guest-only where.exe subset. Every file check goes through guest WinAPI. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static WCHAR argument[256];
static WCHAR directory[4096];
static WCHAR path_env[4096];
static WCHAR candidate[4352];
static DWORD output_chars;

static DWORD length(const WCHAR *value) {
    DWORD n = 0;
    while (value[n] && n < 4352) ++n;
    return n;
}

static void print_to(DWORD destination, const WCHAR *value) {
    DWORD written = 0, count = length(value);
    if (count > 65536 - output_chars) ExitProcess(ERROR_MORE_DATA);
    output_chars += count;
    if (count && !WriteConsoleW(GetStdHandle(destination), value,
                                count, &written, 0)) ExitProcess(GetLastError());
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

static int file_name_allowed(const WCHAR *name) {
    if (!name[0] || name[0] == L'.') return 0;
    for (DWORD i = 0; name[i]; ++i) {
        WCHAR c = name[i];
        if (!((c >= L'A' && c <= L'Z') || (c >= L'a' && c <= L'z') ||
              (c >= L'0' && c <= L'9') || c == L'_' || c == L'-' || c == L'.'))
            return 0;
    }
    return 1;
}

static int has_extension(const WCHAR *name) {
    for (DWORD i = 0; name[i]; ++i) if (name[i] == L'.') return 1;
    return 0;
}

static int check_directory(const WCHAR *dir, const WCHAR *name, int append_exe) {
    DWORD n = length(dir), m = length(name), offset;
    if (!n || n + m + 6 >= 4352) return 0;
    for (DWORD i = 0; i < n; ++i) candidate[i] = dir[i];
    offset = n;
    if (candidate[offset - 1] != L'\\') candidate[offset++] = L'\\';
    for (DWORD i = 0; i < m; ++i) candidate[offset++] = name[i];
    if (append_exe) {
        candidate[offset++] = L'.'; candidate[offset++] = L'e';
        candidate[offset++] = L'x'; candidate[offset++] = L'e';
    }
    candidate[offset] = 0;
    DWORD attributes = GetFileAttributesW(candidate);
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY))
        return 0;
    print_to(STD_OUTPUT_HANDLE, candidate);
    print_to(STD_OUTPUT_HANDLE, L"\r\n");
    return 1;
}

void WINAPI entry(void) {
    const WCHAR *cursor = GetCommandLineW();
    int found = 0;
    if (next_arg(&cursor, directory, 4096) != 1 ||
        next_arg(&cursor, argument, 256) != 1 ||
        next_arg(&cursor, directory, 4096) != 0 ||
        !file_name_allowed(argument)) ExitProcess(ERROR_INVALID_PARAMETER);
    int append_exe = !has_extension(argument);
    DWORD size = GetCurrentDirectoryW(4096, directory);
    if (size && size < 4096) found += check_directory(directory, argument, append_exe);
    size = GetEnvironmentVariableW(L"PATH", path_env, 4096);
    if (size && size < 4096) {
        DWORD position = 0, entries = 0;
        while (path_env[position] && entries++ < 32) {
            DWORD count = 0;
            while (path_env[position] && path_env[position] != L';') {
                if (count + 1 < 4096) directory[count++] = path_env[position];
                ++position;
            }
            if (path_env[position] == L';') ++position;
            directory[count] = 0;
            if (count) found += check_directory(directory, argument, append_exe);
        }
    }
    if (!found) {
        print_to(STD_ERROR_HANDLE, L"INFO: Could not find files for the given pattern(s).\r\n");
        ExitProcess(1);
    }
    ExitProcess(0);
}

/* Guest-only registry reader. Build with MSVC /NODEFAULTLIB; no host calls. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static WCHAR arg[5][1024];
static WCHAR name_buf[512];
static BYTE data_buf[8192];
static WCHAR line[2048];

static DWORD length(const WCHAR *value) {
    DWORD count = 0;
    while (value[count] && count < 65535) ++count;
    return count;
}

static WCHAR lower(WCHAR value) {
    if (value >= L'A' && value <= L'Z') return value + (L'a' - L'A');
    return value;
}

static int equals(const WCHAR *left, const WCHAR *right) {
    DWORD i = 0;
    while (left[i] && right[i]) {
        if (lower(left[i]) != lower(right[i])) return 0;
        ++i;
    }
    return !left[i] && !right[i];
}

static int root_prefix(const WCHAR *value, const WCHAR *prefix) {
    DWORD i = 0;
    while (prefix[i]) {
        if (lower(value[i]) != lower(prefix[i])) return 0;
        ++i;
    }
    return value[i] == L'\\';
}

static void write_text(const WCHAR *value) {
    DWORD written = 0;
    DWORD size = length(value);
    if (size) WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), value, size, &written, 0);
}

static void write_number(DWORD value) {
    WCHAR digits[11];
    DWORD count = 0;
    do {
        digits[count++] = (WCHAR)(L'0' + value % 10);
        value /= 10;
    } while (value && count < 10);
    for (DWORD i = 0; i < count / 2; ++i) {
        WCHAR temp = digits[i];
        digits[i] = digits[count - i - 1];
        digits[count - i - 1] = temp;
    }
    digits[count] = 0;
    write_text(digits);
}

static int next_arg(const WCHAR **cursor, WCHAR *output, DWORD capacity) {
    const WCHAR *read = *cursor;
    DWORD count = 0;
    int quoted = 0;
    while (*read == L' ' || *read == L'\t') ++read;
    if (!*read) return 0;
    while (*read && (quoted || (*read != L' ' && *read != L'\t'))) {
        if (*read == L'"') quoted = !quoted;
        else if (count + 1 < capacity) output[count++] = *read;
        else return -1;
        ++read;
    }
    if (quoted) return -1;
    output[count] = 0;
    *cursor = read;
    return 1;
}

static void fail(DWORD status) {
    ExitProcess(status);
}

static void print_value(const WCHAR *name, DWORD kind, DWORD data_size) {
    write_text(L"    ");
    write_text(name[0] ? name : L"(Default)");
    if (kind == REG_SZ || kind == REG_EXPAND_SZ) {
        write_text(kind == REG_SZ ? L"    REG_SZ    " : L"    REG_EXPAND_SZ    ");
        if (data_size >= sizeof(WCHAR)) {
            ((WCHAR *)data_buf)[data_size / 2 - 1] = 0;
            write_text((WCHAR *)data_buf);
        }
    } else if (kind == REG_MULTI_SZ) {
        write_text(L"    REG_MULTI_SZ    ");
        DWORD words = data_size / sizeof(WCHAR);
        WCHAR *value = (WCHAR *)data_buf;
        DWORD out = 0;
        for (DWORD i = 0; i < words; ++i) {
            if (!value[i] && i + 1 < words && !value[i + 1]) break;
            if (out + 2 >= 2048) fail(ERROR_MORE_DATA);
            if (value[i]) line[out++] = value[i];
            else { line[out++] = L'\\'; line[out++] = L'0'; }
        }
        line[out] = 0;
        write_text(line);
    } else if (kind == REG_DWORD && data_size >= sizeof(DWORD)) {
        write_text(L"    REG_DWORD    ");
        write_number(*(DWORD *)data_buf);
    } else {
        write_text(kind == REG_QWORD ? L"    REG_QWORD    " : L"    REG_BINARY    ");
        const WCHAR hex[] = L"0123456789abcdef";
        for (DWORD offset = 0; offset < data_size; offset += 512) {
            DWORD count = data_size - offset < 512 ? data_size - offset : 512;
            for (DWORD i = 0; i < count; ++i) {
                line[i * 2] = hex[data_buf[offset + i] >> 4];
                line[i * 2 + 1] = hex[data_buf[offset + i] & 15];
            }
            line[count * 2] = 0;
            write_text(line);
        }
    }
    write_text(L"\r\n");
}

void WINAPI entry(void) {
    const WCHAR *cursor = GetCommandLineW();
    HKEY root = 0, opened = 0;
    const WCHAR *subkey = 0;
    DWORD result;
    if (next_arg(&cursor, line, 2048) != 1 ||
        next_arg(&cursor, arg[0], 1024) != 1 ||
        next_arg(&cursor, arg[1], 1024) != 1 ||
        !equals(arg[0], L"query")) fail(87);
    int has_option = next_arg(&cursor, arg[2], 1024);
    int has_value = next_arg(&cursor, arg[3], 1024);
    if (has_option < 0 || has_value < 0 ||
        next_arg(&cursor, arg[4], 1024) != 0) fail(87);
    int named_value = has_option == 1 && equals(arg[2], L"/v") && has_value == 1;
    int default_value = has_option == 1 && equals(arg[2], L"/ve") && has_value == 0;
    if (has_option && !named_value && !default_value) fail(87);
    subkey = arg[1];
    if (root_prefix(subkey, L"HKLM")) {
        root = HKEY_LOCAL_MACHINE; subkey += 5;
    } else if (root_prefix(subkey, L"HKEY_LOCAL_MACHINE")) {
        root = HKEY_LOCAL_MACHINE; subkey += 19;
    } else if (root_prefix(subkey, L"HKCU")) {
        root = HKEY_CURRENT_USER; subkey += 5;
    } else if (root_prefix(subkey, L"HKEY_CURRENT_USER")) {
        root = HKEY_CURRENT_USER; subkey += 18;
    } else if (root_prefix(subkey, L"HKCR")) {
        root = HKEY_CLASSES_ROOT; subkey += 5;
    } else if (root_prefix(subkey, L"HKEY_CLASSES_ROOT")) {
        root = HKEY_CLASSES_ROOT; subkey += 18;
    } else if (root_prefix(subkey, L"HKU")) {
        root = HKEY_USERS; subkey += 4;
    } else if (root_prefix(subkey, L"HKEY_USERS")) {
        root = HKEY_USERS; subkey += 11;
    } else if (root_prefix(subkey, L"HKCC")) {
        root = HKEY_CURRENT_CONFIG; subkey += 5;
    } else if (root_prefix(subkey, L"HKEY_CURRENT_CONFIG")) {
        root = HKEY_CURRENT_CONFIG; subkey += 20;
    } else fail(87);
    result = RegOpenKeyExW(root, subkey, 0, KEY_READ, &opened);
    if (result != ERROR_SUCCESS) fail(result);
    if (named_value || default_value) {
        DWORD kind = 0, data_size = sizeof(data_buf);
        const WCHAR *value_name = named_value ? arg[3] : L"";
        result = RegQueryValueExW(opened, value_name, 0, &kind, data_buf, &data_size);
        if (result != ERROR_SUCCESS) fail(result);
        write_text(L"\r\n");
        write_text(arg[1]);
        write_text(L"\r\n");
        print_value(value_name, kind, data_size);
        RegCloseKey(opened);
        fail(0);
    }
    write_text(L"\r\n");
    write_text(arg[1]);
    write_text(L"\r\n");
    for (DWORD index = 0; index < 256; ++index) {
        DWORD name_size = 511, data_size = sizeof(data_buf), kind = 0;
        result = RegEnumValueW(opened, index, name_buf, &name_size, 0,
                               &kind, data_buf, &data_size);
        if (result == ERROR_NO_MORE_ITEMS) break;
        if (result != ERROR_SUCCESS) fail(result);
        name_buf[name_size] = 0;
        print_value(name_buf, kind, data_size);
    }
    for (DWORD index = 0; index < 256; ++index) {
        DWORD name_size = 511;
        result = RegEnumKeyExW(opened, index, name_buf, &name_size,
                               0, 0, 0, 0);
        if (result == ERROR_NO_MORE_ITEMS) break;
        if (result != ERROR_SUCCESS) fail(result);
        name_buf[name_size] = 0;
        write_text(L"\r\n");
        write_text(arg[1]);
        write_text(L"\\");
        write_text(name_buf);
        write_text(L"\r\n");
    }
    RegCloseKey(opened);
    fail(0);
}

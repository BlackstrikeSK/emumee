/* Harmless compiler-produced program for the M6 exit criterion.
 *
 * It walks the registry, volume, file-handle, version, locale and firmware
 * paths end to end through a real compiler's own calling sequences, structure
 * layouts and import table. Every failure path returns a distinct nonzero code
 * so a wrong model shows up as that code rather than as a crash. Nothing here
 * touches the host: the only paths it names are guest paths on the one modeled
 * volume, and the only registry it writes is the owned guest registry. */

/* GetVersionExA is deprecated for applications that should use a manifest;
 * reading the modeled structure is exactly what this control is for. */
#define _CRT_NONSTDC_NO_WARNINGS 1
#pragma warning(disable : 4996)

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Provider signature 'RSMB': the raw SMBIOS table. */
#define RSMB 0x52534D42u
#define GUEST_FILE "C:\\emumee\\m6c.bin"
#define GUEST_KEY "Software\\EmumeeM6Compiled"

static int version_identity(void)
{
    OSVERSIONINFOEXA info;
    ULONGLONG mask;

    memset(&info, 0, sizeof(info));
    info.dwOSVersionInfoSize = sizeof(info);
    if (!GetVersionExA((LPOSVERSIONINFOA)&info)) {
        return 10;
    }
    if (info.dwMajorVersion != 10 || info.dwPlatformId != VER_PLATFORM_WIN32_NT) {
        return 11;
    }
    if (info.dwBuildNumber == 0 || info.wProductType == 0) {
        return 12;
    }
    /* The same identity must answer the predicate, so a guest cannot read one
     * version out of the structure and get another from VerifyVersionInfo. */
    mask = VerSetConditionMask(0, VER_MAJORVERSION, VER_GREATER_EQUAL);
    mask = VerSetConditionMask(mask, VER_MINORVERSION, VER_GREATER_EQUAL);
    if (mask == 0) {
        return 13;
    }
    memset(&info, 0, sizeof(info));
    info.dwOSVersionInfoSize = sizeof(info);
    info.dwMajorVersion = 10;
    info.dwMinorVersion = 0;
    if (!VerifyVersionInfoA(&info, VER_MAJORVERSION | VER_MINORVERSION, mask)) {
        return 14;
    }
    info.dwMajorVersion = 99;
    if (VerifyVersionInfoA(&info, VER_MAJORVERSION | VER_MINORVERSION, mask)) {
        return 15;
    }
    if (GetLastError() != ERROR_OLD_WIN_VERSION) {
        return 16;
    }
    return 0;
}

static int locale_identity(void)
{
    LCID system;
    LCID user;

    system = GetSystemDefaultLCID();
    user = GetUserDefaultLCID();
    if (system == 0 || system != user) {
        return 20;
    }
    if ((LANGID)system != GetSystemDefaultLangID()) {
        return 21;
    }
    if (!IsValidLocale(system, LCID_INSTALLED)) {
        return 22;
    }
    /* No other locale is installed in this profile. */
    if (IsValidLocale(system == 0x0409 ? 0x0407 : 0x0409, LCID_INSTALLED)) {
        return 23;
    }
    if (WTSGetActiveConsoleSessionId() == 0xFFFFFFFFu) {
        return 24;
    }
    return 0;
}

static int volume_identity(char *line, size_t line_bytes)
{
    char label[64];
    char filesystem[64];
    DWORD serial;
    DWORD component;
    DWORD flags;
    ULARGE_INTEGER available;
    ULARGE_INTEGER total;
    ULARGE_INTEGER free_space;

    memset(label, 0, sizeof(label));
    memset(filesystem, 0, sizeof(filesystem));
    serial = 0;
    component = 0;
    flags = 0;
    if (!GetVolumeInformationA("C:\\", label, sizeof(label), &serial, &component,
                               &flags, filesystem, sizeof(filesystem))) {
        return 30;
    }
    if (serial == 0 || component != 255 || strcmp(filesystem, "NTFS") != 0) {
        return 31;
    }
    if (GetDriveTypeA("C:\\") != DRIVE_FIXED || GetDriveTypeA("D:\\") != DRIVE_NO_ROOT_DIR) {
        return 32;
    }
    if (GetLogicalDrives() != (1u << 2)) {
        return 33;
    }
    if (!GetDiskFreeSpaceExA("C:\\", &available, &total, &free_space)) {
        return 34;
    }
    /* No quota is modeled, so caller-available free space is total free space,
     * and the reported capacity is identity rather than an allocator. */
    if (available.QuadPart != free_space.QuadPart || free_space.QuadPart > total.QuadPart) {
        return 35;
    }
    if (total.QuadPart == 0) {
        return 36;
    }
    sprintf(line, "volume serial=%08lX fs=%s", (unsigned long)serial, filesystem);
    if (strlen(line) + 1 > line_bytes) {
        return 37;
    }
    return 0;
}

static int file_handle_paths(void)
{
    HANDLE file;
    DWORD written;
    DWORD size;
    DWORD high;
    LARGE_INTEGER distance;
    LARGE_INTEGER position;
    FILETIME created;
    FILETIME accessed;
    FILETIME written_at;
    FILETIME stamp;
    BY_HANDLE_FILE_INFORMATION information;
    BY_HANDLE_FILE_INFORMATION again;
    const char payload[10] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };

    file = CreateFileA(GUEST_FILE, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                       CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return 40;
    }
    if (!WriteFile(file, payload, sizeof(payload), &written, NULL) || written != sizeof(payload)) {
        CloseHandle(file);
        return 41;
    }
    high = 0xFFFFFFFFu;
    size = GetFileSize(file, &high);
    if (size != sizeof(payload) || high != 0) {
        CloseHandle(file);
        return 42;
    }
    /* The end of the file follows the handle's own position. */
    distance.QuadPart = 4;
    if (!SetFilePointerEx(file, distance, &position, FILE_BEGIN) || position.QuadPart != 4) {
        CloseHandle(file);
        return 43;
    }
    if (!SetEndOfFile(file)) {
        CloseHandle(file);
        return 44;
    }
    if (GetFileSize(file, NULL) != 4) {
        CloseHandle(file);
        return 45;
    }
    if (!GetFileTime(file, &created, &accessed, &written_at)) {
        CloseHandle(file);
        return 46;
    }
    stamp = written_at;
    stamp.dwLowDateTime = created.dwLowDateTime + 1;
    if (!SetFileTime(file, NULL, NULL, &stamp)) {
        CloseHandle(file);
        return 47;
    }
    if (!GetFileTime(file, &created, &accessed, &written_at)) {
        CloseHandle(file);
        return 48;
    }
    if (written_at.dwLowDateTime != stamp.dwLowDateTime
        || written_at.dwHighDateTime != stamp.dwHighDateTime) {
        CloseHandle(file);
        return 49;
    }
    if (!GetFileInformationByHandle(file, &information)) {
        CloseHandle(file);
        return 50;
    }
    if (information.nFileSizeLow != 4 || information.nFileSizeHigh != 0) {
        CloseHandle(file);
        return 51;
    }
    if (information.nNumberOfLinks != 1 || information.dwVolumeSerialNumber == 0) {
        CloseHandle(file);
        return 52;
    }
    if (!FlushFileBuffers(file)) {
        CloseHandle(file);
        return 53;
    }
    if (!CloseHandle(file)) {
        return 54;
    }
    /* The file index is a function of the path, so reopening reports the same
     * value. */
    file = CreateFileA(GUEST_FILE, GENERIC_READ, 0, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return 55;
    }
    if (!GetFileInformationByHandle(file, &again)) {
        CloseHandle(file);
        return 56;
    }
    if (again.nFileIndexLow != information.nFileIndexLow
        || again.nFileIndexHigh != information.nFileIndexHigh) {
        CloseHandle(file);
        return 57;
    }
    /* A read-only handle cannot stamp the directory entry. */
    if (SetFileTime(file, NULL, NULL, &stamp)) {
        CloseHandle(file);
        return 58;
    }
    if (GetLastError() != ERROR_ACCESS_DENIED) {
        CloseHandle(file);
        return 59;
    }
    if (!CloseHandle(file)) {
        return 60;
    }
    return 0;
}

static int registry_paths(void)
{
    HKEY key;
    HKEY child;
    DWORD disposition;
    DWORD value;
    DWORD kind;
    DWORD size;
    DWORD subkeys;
    DWORD longest;
    DWORD values;
    char name[64];
    DWORD name_size;

    if (RegCreateKeyExA(HKEY_CURRENT_USER, GUEST_KEY, 0, NULL, 0, KEY_ALL_ACCESS,
                        NULL, &key, &disposition) != ERROR_SUCCESS) {
        return 70;
    }
    if (disposition != REG_CREATED_NEW_KEY) {
        RegCloseKey(key);
        return 71;
    }
    value = 0x11223344;
    if (RegSetValueExA(key, "Alpha", 0, REG_DWORD, (const BYTE *)&value, sizeof(value))
        != ERROR_SUCCESS) {
        RegCloseKey(key);
        return 72;
    }
    value = 0;
    size = sizeof(value);
    if (RegQueryValueExA(key, "Alpha", NULL, &kind, (BYTE *)&value, &size) != ERROR_SUCCESS) {
        RegCloseKey(key);
        return 73;
    }
    if (kind != REG_DWORD || size != sizeof(value) || value != 0x11223344) {
        RegCloseKey(key);
        return 74;
    }
    if (RegCreateKeyExA(key, "Nested", 0, NULL, 0, KEY_ALL_ACCESS, NULL, &child, NULL)
        != ERROR_SUCCESS) {
        RegCloseKey(key);
        return 75;
    }
    RegCloseKey(child);
    name_size = sizeof(name);
    memset(name, 0, sizeof(name));
    if (RegEnumKeyExA(key, 0, name, &name_size, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
        RegCloseKey(key);
        return 76;
    }
    if (strcmp(name, "Nested") != 0) {
        RegCloseKey(key);
        return 77;
    }
    if (RegQueryInfoKeyA(key, NULL, NULL, NULL, &subkeys, &longest, NULL, &values,
                         NULL, NULL, NULL, NULL) != ERROR_SUCCESS) {
        RegCloseKey(key);
        return 78;
    }
    if (subkeys != 1 || longest != 6 || values != 1) {
        RegCloseKey(key);
        return 79;
    }
    if (RegDeleteValueA(key, "Alpha") != ERROR_SUCCESS) {
        RegCloseKey(key);
        return 80;
    }
    size = sizeof(value);
    if (RegQueryValueExA(key, "Alpha", NULL, &kind, (BYTE *)&value, &size)
        != ERROR_FILE_NOT_FOUND) {
        RegCloseKey(key);
        return 81;
    }
    if (RegDeleteValueA(key, "Alpha") != ERROR_FILE_NOT_FOUND) {
        RegCloseKey(key);
        return 82;
    }
    if (RegCloseKey(key) != ERROR_SUCCESS) {
        return 83;
    }
    return 0;
}

static int firmware_identity(char *line, size_t line_bytes)
{
    static BYTE table[1024];
    UINT required;
    UINT taken;

    required = GetSystemFirmwareTable(RSMB, 0, NULL, 0);
    if (required == 0 || required > sizeof(table)) {
        return 90;
    }
    /* A short buffer reports the size and writes nothing. */
    memset(table, 0xCC, sizeof(table));
    if (GetSystemFirmwareTable(RSMB, 0, table, required - 1) != required) {
        return 91;
    }
    if (table[0] != 0xCC) {
        return 92;
    }
    taken = GetSystemFirmwareTable(RSMB, 0, table, required);
    if (taken != required) {
        return 93;
    }
    /* RawSMBIOSData: the length field covers the table that follows it. */
    if (*(const DWORD *)(table + 4) != required - 8) {
        return 94;
    }
    /* The first structure is the Type 0 BIOS record. */
    if (table[8] != 0 || table[9] < 4) {
        return 95;
    }
    /* A provider this machine does not have reports no table rather than
     * inventing bytes. */
    if (GetSystemFirmwareTable(0x41435049u, 0, table, sizeof(table)) != 0) {
        return 96;
    }
    sprintf(line, "firmware bytes=%u", (unsigned)required);
    if (strlen(line) + 1 > line_bytes) {
        return 97;
    }
    return 0;
}

int entry(void)
{
    char line[96];
    int failure;

    failure = version_identity();
    if (failure != 0) {
        return failure;
    }
    failure = locale_identity();
    if (failure != 0) {
        return failure;
    }
    failure = volume_identity(line, sizeof(line));
    if (failure != 0) {
        return failure;
    }
    puts(line);
    failure = file_handle_paths();
    if (failure != 0) {
        return failure;
    }
    failure = registry_paths();
    if (failure != 0) {
        return failure;
    }
    failure = firmware_identity(line, sizeof(line));
    if (failure != 0) {
        return failure;
    }
    puts(line);
    puts("m6-ok");
    /* exit never returns, so there is no statement after it. */
    exit(23);
}

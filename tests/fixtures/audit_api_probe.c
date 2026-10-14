/* Harmless audit API fixture. Run only through guest CPU emulation. */
#define WIN32_LEAN_AND_MEAN
#define INITGUID
#include <windows.h>
#include <ntsecapi.h>

typedef char checked_policy_size[(sizeof(AUDIT_POLICY_INFORMATION) == 36) ? 1 : -1];

static void check(int condition, DWORD error) { if (!condition) ExitProcess(error); }
static int wide_equals(const WCHAR *a, const WCHAR *b) {
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}
static int ascii_equals(const char *a, const char *b) {
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}
static void print(const WCHAR *s, DWORD n) {
    DWORD written;
    check(WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), s, n, &written, 0), 90);
}

void WINAPI entry(void) {
    GUID *categories = 0, *subcategories = 0, category;
    ULONG count = 0;
    POLICY_AUDIT_EVENT_TYPE id;
    WCHAR *name = 0;
    char *ansi = 0;
    AUDIT_POLICY_INFORMATION *policy = 0;
    static GUID requested[4];

    check(AuditEnumerateCategories(&categories, &count) && count == 9, 10);
    check(categories[0].Data1 == 0x69979848 && categories[8].Data1 == 0x69979850, 11);
    check(AuditLookupCategoryGuidFromCategoryId(AuditCategoryDetailedTracking, &category), 12);
    check(AuditLookupCategoryIdFromCategoryGuid(&category, &id) && id == AuditCategoryDetailedTracking, 13);
    check(AuditLookupCategoryNameW(&category, &name) && wide_equals(name, L"Detailed Tracking"), 14);
    AuditFree(name);
    check(AuditLookupCategoryNameA(&category, &ansi) && ascii_equals(ansi, "Detailed Tracking"), 15);
    AuditFree(ansi);
    check(AuditEnumerateSubCategories(&category, FALSE, &subcategories, &count) && count == 6, 16);
    check(subcategories[0].Data1 == 0x0cce922b, 17);
    check(AuditLookupSubCategoryNameW(subcategories, &name) && wide_equals(name, L"Process Creation"), 18);
    AuditFree(name);
    check(AuditLookupSubCategoryNameA(subcategories, &ansi) && ascii_equals(ansi, "Process Creation"), 19);
    AuditFree(ansi);
    AuditFree(subcategories);
    check(AuditEnumerateSubCategories(0, TRUE, &subcategories, &count) && count == 59, 20);
    AuditFree(subcategories);
    AuditFree(categories);

    requested[0] = Audit_DetailedTracking_ProcessCreation;
    requested[1] = Audit_ObjectAccess_FileSystem;
    requested[2] = Audit_Logon_Logon;
    requested[3] = Audit_ObjectAccess_Registry;
    if (!AuditQuerySystemPolicy(requested, 4, &policy)) {
        check(GetLastError() == ERROR_ACCESS_DENIED, 21);
        print(L"audit-policy-denied\r\n", 21);
    } else {
        check(policy[0].AuditSubCategoryGuid.Data1 == requested[0].Data1 &&
              policy[0].AuditingInformation == POLICY_AUDIT_EVENT_SUCCESS &&
              policy[0].AuditCategoryGuid.Data1 == 0x6997984c, 22);
        check(policy[1].AuditingInformation == POLICY_AUDIT_EVENT_FAILURE &&
              policy[1].AuditCategoryGuid.Data1 == 0x6997984a, 23);
        check(policy[2].AuditingInformation == (POLICY_AUDIT_EVENT_SUCCESS | POLICY_AUDIT_EVENT_FAILURE), 24);
        check(policy[3].AuditingInformation == POLICY_AUDIT_EVENT_NONE, 25);
        AuditFree(policy);
        print(L"audit-policy-ok\r\n", 17);
    }
    check(!AuditSetSystemPolicy(0, 0) && GetLastError() == ERROR_NOT_SUPPORTED, 26);
    print(L"audit-metadata-ok\r\n", 19);
    ExitProcess(0);
}

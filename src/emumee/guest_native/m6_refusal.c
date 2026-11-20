/* Harmless compiler-produced negative control for M6. Section objects and
 * mapped views are not modeled: a returned view would be memory the guest could
 * read and write with no backing contract, and view storage would not be
 * coherent with the virtual filesystem. The call must stop explicitly instead
 * of handing back a handle the program would then map. */

#include <windows.h>

int entry(void)
{
    HANDLE section;

    section = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, NULL);
    return section == NULL ? 1 : 0;
}

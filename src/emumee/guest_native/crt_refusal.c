/* Harmless compiler-produced negative control. The new-handler allocation mode
 * changes what a failed allocation does, which this profile does not model, so
 * the call must stop explicitly instead of reporting a value the program would
 * then act on. */

extern int __cdecl _set_new_mode(int mode);

int entry(void)
{
    return _set_new_mode(1);
}

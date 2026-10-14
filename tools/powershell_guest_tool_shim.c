/* Native Linux entrypoint for generated Windows utilities. Executes only the
 * container's isolated Python and CPU emulator, never a Windows host binary. */
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 1 || argc > 65) return 87;
    size_t total = 0;
    for (int i = 0; i < argc; ++i) {
        size_t size = strlen(argv[i]);
        if (size > 16000 || total + size > 60000) return 87;
        total += size;
    }
    const char *name = strrchr(argv[0], '/');
    name = name ? name + 1 : argv[0];
    int fd = open("/dev/null", O_WRONLY);
    if (fd < 0 || dup2(fd, 197) < 0) return 1;
    if (fd != 197) close(fd);
    char *call[72] = {"/opt/emumee-python/bin/python", "-I", "-m", "emumee.powershell_guest_tools", (char *)name};
    for (int i = 1; i < argc; ++i) call[4 + i] = argv[i];
    call[4 + argc] = 0;
    execv(call[0], call);
    return 1;
}

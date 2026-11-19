/* Harmless compiler-produced legacy CRT program for native PE qualification.
 *
 * It exercises the modeled startup accessors, string helpers, heap allocation,
 * narrow formatting, file streams, console output and exit-time teardown. Every
 * failure path returns a distinct nonzero code so a wrong model is visible in
 * the process exit code rather than in a crash. Nothing here touches the host:
 * the only file it opens is a staged guest path. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int *__cdecl __p___argc(void);
extern char ***__cdecl __p___argv(void);
extern char **__cdecl __p__acmdln(void);
extern int __cdecl _crt_atexit(void(__cdecl *function)(void));

static void __cdecl teardown(void)
{
    puts("teardown");
}

int entry(void)
{
    int argc;
    char **argv;
    char *command;
    char *buffer;
    char line[128];
    char content[16];
    FILE *stream;
    size_t taken;

    argc = *__p___argc();
    argv = *__p___argv();
    command = *__p__acmdln();
    if (argc < 1 || argv == 0 || argv[0] == 0 || command == 0) {
        return 10;
    }
    if (strstr(command, "sample.exe") == 0) {
        return 11;
    }

    buffer = (char *)malloc(64);
    if (buffer == 0) {
        return 12;
    }
    memset(buffer, 0, 64);
    strcpy(buffer, "crt");
    strcat(buffer, "-ok");
    if (strlen(buffer) != 6 || strcmp(buffer, "crt-ok") != 0) {
        free(buffer);
        return 13;
    }
    sprintf(line, "argc=%d name=%s", argc, buffer);
    puts(line);
    free(buffer);

    stream = fopen("C:\\emumee\\data.txt", "rb");
    if (stream == 0) {
        return 14;
    }
    taken = fread(content, 1, 5, stream);
    if (taken != 5) {
        fclose(stream);
        return 15;
    }
    content[taken] = 0;
    if (ftell(stream) != 5) {
        fclose(stream);
        return 16;
    }
    if (fclose(stream) != 0) {
        return 17;
    }
    if (strcmp(content, "hello") != 0) {
        return 18;
    }
    puts(content);

    if (_crt_atexit(teardown) != 0) {
        return 19;
    }
    /* exit never returns, so there is no statement after it. */
    exit(7);
}

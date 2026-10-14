/* Linux x86-64 process observer. Built statically in WSL; executed only inside
 * a verified unprivileged, offline container. --script reads bounded source
 * after the host-provided key, which authenticates observer records. */
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <linux/audit.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <stdint.h>
#include <setjmp.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

#if !defined(__x86_64__)
#error This probe observer supports Linux x86-64 only
#endif

static unsigned char key[32];
static char payload[300000];
static size_t used;
static unsigned long sequence;
static pid_t root_pid;
static jmp_buf trace_exit;
static int allow_exit_race;
static const char *exit_operation;
static int script_mode;
static int persona_mode;
static size_t console_totals[2];
static struct stat console_identity[2];
static struct { pid_t pid; int blocked; int console_fd; size_t console_size;
                int console_truncated; unsigned char console[4096]; } tasks[64];

static void emit(void) {
    unsigned char digest[EVP_MAX_MD_SIZE]; unsigned int length = 0;
    if (++sequence > 2048 || !used || payload[used - 1] != '}') _exit(96);
    int added = snprintf(payload + used - 1, sizeof(payload) - used + 1,
                         ",\"sequence\":%lu}", sequence);
    if (added < 0 || (size_t)added >= sizeof(payload) - used + 1) _exit(96);
    used = used - 1 + (size_t)added;
    if (!HMAC(EVP_sha256(), key, sizeof(key),
            (unsigned char *)payload, used, digest, &length) || length != 32) _exit(96);
    for (unsigned int i = 0; i < length; ++i) printf("%02x", digest[i]);
    printf(" %s\n", payload); fflush(stdout);
}
static void begin(void) { used = 0; payload[0] = 0; }
static void add(const char *format, ...) {
    va_list args; va_start(args, format);
    int n = vsnprintf(payload + used, sizeof(payload) - used, format, args);
    va_end(args);
    if (n < 0 || (size_t)n >= sizeof(payload) - used) _exit(97);
    used += (size_t)n;
}
static void fail(const char *reason) {
    int native_error = errno;
    if (root_pid > 0) kill(root_pid, SIGKILL);
    for (int i = 0; i < 64; ++i) if (tasks[i].pid > 0) kill(tasks[i].pid, SIGKILL);
    begin(); add("{\"event\":\"observer_error\",\"reason\":\"%s\",\"native_errno\":%d}", reason, native_error); emit();
    _exit(95);
}
static void trace_error(const char *reason) {
    if (errno == ESRCH && allow_exit_race) {
        exit_operation = reason;
        longjmp(trace_exit, 1);
    }
    fail(reason);
}
static int task(pid_t pid) {
    for (int i = 0; i < 64; ++i) if (tasks[i].pid == pid) return i;
    for (int i = 0; i < 64; ++i) if (!tasks[i].pid) { tasks[i].pid = pid; tasks[i].blocked = 0; return i; }
    fail("tracee_limit"); return -1;
}
static unsigned long peek(pid_t pid, unsigned long address) {
    errno = 0;
    long value = ptrace(PTRACE_PEEKDATA, pid, (void *)address, 0);
    if (value == -1 && errno) trace_error("tracee_memory_unreadable");
    return (unsigned long)value;
}
static void hex_memory(pid_t pid, unsigned long address, size_t limit, int terminated) {
    add("\"");
    size_t i = 0;
    while (i < limit) {
        unsigned long current = address + i;
        unsigned long word = peek(pid, current & ~(sizeof(unsigned long) - 1));
        for (size_t j = current & (sizeof(unsigned long) - 1); j < sizeof(word) && i < limit; ++j, ++i) {
            unsigned int c = (word >> (j * 8)) & 255;
            if (terminated && !c) { add("\""); return; }
            add("%02x", c);
        }
    }
    if (terminated) fail("argument_limit");
    add("\"");
}
static void hex_string(pid_t pid, unsigned long address) { hex_memory(pid, address, 16384, 1); }
static void exec_event(pid_t pid, const struct ptrace_syscall_info *info) {
    int at = info->entry.nr == SYS_execveat;
    unsigned long file = info->entry.args[at ? 1 : 0];
    unsigned long argv = info->entry.args[at ? 2 : 1];
    begin(); add("{\"event\":\"native_exec_attempt\",\"pid\":%d,\"syscall\":\"%s\",\"path_hex\":",
                  pid, at ? "execveat" : "execve");
    hex_string(pid, file); add(",\"argv_hex\":[");
    for (size_t i = 0; i < 128; ++i) {
        unsigned long argument = peek(pid, argv + i * sizeof(unsigned long));
        if (!argument) { add("]}"); emit(); return; }
        if (i) add(",");
        hex_string(pid, argument);
    }
    fail("argument_count_limit");
}
static int denied(const struct ptrace_syscall_info *info) {
    unsigned long nr = info->entry.nr;
    if (nr == SYS_clone3) return ENOSYS; /* libc may fall back to traced clone. */
    if (nr == SYS_clone && (info->entry.args[0] & 0x00800000UL)) return EPERM; /* CLONE_UNTRACED */
    if (nr == SYS_socket || nr == SYS_socketpair)
        return info->entry.args[0] == AF_UNIX ? 0 : EPERM;
    if (nr == SYS_connect || nr == SYS_bind || nr == SYS_listen || nr == SYS_accept ||
        nr == SYS_accept4 || nr == SYS_sendto || nr == SYS_sendmsg || nr == SYS_sendmmsg ||
        nr == SYS_recvfrom || nr == SYS_recvmsg || nr == SYS_recvmmsg ||
        nr == SYS_ptrace || nr == SYS_process_vm_writev || nr == SYS_pidfd_getfd ||
        nr == SYS_unshare || nr == SYS_setns || nr == SYS_io_uring_setup ||
        nr == SYS_io_uring_enter || nr == SYS_io_uring_register) return EPERM;
    return 0;
}

static int framed_input(const char *path, uint32_t maximum) {
    unsigned char header[4]; size_t count = 0;
    while (count < 4) {
        ssize_t n = read(0, header + count, 4 - count);
        if (n <= 0) return -1;
        count += (size_t)n;
    }
    uint32_t size = ((uint32_t)header[0] << 24) | ((uint32_t)header[1] << 16) |
                    ((uint32_t)header[2] << 8) | header[3];
    if (!size || size > maximum) return -1;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0400);
    if (fd < 0) return -1;
    unsigned char data[4096];
    while (size) {
        ssize_t n = read(0, data, size < sizeof(data) ? size : sizeof(data));
        if (n <= 0) { close(fd); return -1; }
        size_t offset = 0;
        while (offset < (size_t)n) {
            ssize_t written = write(fd, data + offset, (size_t)n - offset);
            if (written <= 0) { close(fd); return -1; }
            offset += (size_t)written;
        }
        size -= (uint32_t)n;
    }
    return close(fd);
}

static void console_entry(pid_t pid, int index, const struct ptrace_syscall_info *info) {
    tasks[index].console_fd = 0;
    if (!script_mode || (info->entry.nr != SYS_write && info->entry.nr != SYS_writev)) return;
    /* .NET duplicates standard handles. Identify their backing inode rather
       than assuming that output always uses descriptor 1 or 2. */
    char path[96]; struct stat identity;
    snprintf(path, sizeof(path), "/proc/%d/fd/%llu", pid, (unsigned long long)info->entry.args[0]);
    if (stat(path, &identity)) return;
    int stream = -1;
    for (int i = 0; i < 2; ++i)
        if (identity.st_dev == console_identity[i].st_dev && identity.st_ino == console_identity[i].st_ino) stream = i;
    if (stream < 0) return;
    if (console_totals[stream] > 65536) return;
    size_t limit = 65536 - console_totals[stream];
    if (limit > sizeof(tasks[index].console)) limit = sizeof(tasks[index].console);
    size_t size = 0, total = 0;
    unsigned long count = info->entry.nr == SYS_writev ? info->entry.args[2] : 1;
    if (count > 1024) return; /* invalid iov count; let the kernel reject it */
    for (unsigned long i = 0; i < count; ++i) {
        unsigned long address = info->entry.args[1], length = info->entry.args[2];
        if (info->entry.nr == SYS_writev) {
            unsigned long vector = info->entry.args[1] + i * 16;
            address = peek(pid, vector);
            length = peek(pid, vector + 8);
        }
        if (length > SIZE_MAX - total) { total = SIZE_MAX; break; }
        total += length;
        size_t copied = length < limit - size ? length : limit - size;
        for (size_t j = 0; j < copied; ++j) {
            unsigned long current = address + j;
            tasks[index].console[size++] = (unsigned char)(peek(pid, current & ~7UL) >> ((current & 7) * 8));
        }
    }
    if (!total) return;
    tasks[index].console_fd = stream + 1;
    tasks[index].console_size = size;
    tasks[index].console_truncated = size < total;
    if (!limit) console_totals[stream]++; /* report exhausted stream only once */
}

int main(int argc, char **argv) {
    if (argc < 2) return 90;
    size_t count = 0;
    while (count < sizeof(key)) {
        ssize_t n = read(STDIN_FILENO, key + count, sizeof(key) - count);
        if (n <= 0) return 91;
        count += (size_t)n;
    }
    persona_mode = argc == 2 && !strcmp(argv[1], "--script-persona");
    script_mode = persona_mode || (argc == 2 && !strcmp(argv[1], "--script"));
    if (script_mode && framed_input("/work/input.ps1", 1024 * 1024)) return 91;
    if (persona_mode && framed_input("/work/persona.json", 4 * 1024 * 1024)) return 91;
    int console_fds[2] = {-1, -1};
    if (script_mode) {
        const char *paths[] = {"/work/stdout", "/work/stderr"};
        for (int i = 0; i < 2; ++i) {
            console_fds[i] = open(paths[i], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (console_fds[i] < 0 || fstat(console_fds[i], &console_identity[i])) return 91;
        }
    }
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core) || prctl(PR_SET_DUMPABLE, 0)) return 92;
    root_pid = fork();
    if (root_pid == -1) return 93;
    if (!root_pid) {
        OPENSSL_cleanse(key, sizeof(key));
        int fd = open("/dev/null", O_RDWR);
        if (fd < 0 || dup2(fd, 0) < 0 || dup2(script_mode ? console_fds[0] : fd, 1) < 0 ||
                dup2(script_mode ? console_fds[1] : fd, 2) < 0 || dup2(fd, 198) < 0) _exit(94);
        for (int i = 0; i < 2; ++i) if (console_fds[i] > 2) close(console_fds[i]);
        if (fd > 2) close(fd);
        if (prctl(PR_SET_DUMPABLE, 1) || ptrace(PTRACE_TRACEME, 0, 0, 0)) _exit(94);
        raise(SIGSTOP);
        char *script_argv[] = {"pwsh", "-NoLogo", "-NoProfile", "-NonInteractive",
                               "-File", "/work/input.ps1", NULL};
        if (persona_mode) script_argv[5] = "/opt/emumee/bootstrap.ps1";
        char **launch = script_mode ? script_argv : argv + 1;
        execvp(launch[0], launch);
        _exit(94);
    }
    for (int i = 0; i < 2; ++i) if (console_fds[i] >= 0) close(console_fds[i]);
    int status;
    if (waitpid(root_pid, &status, 0) != root_pid || !WIFSTOPPED(status)) fail("trace_setup_failed");
    unsigned long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                            PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL;
    if (ptrace(PTRACE_SETOPTIONS, root_pid, 0, (void *)options)) fail("trace_options_failed");
    task(root_pid);
    begin(); add("{\"event\":\"observer_ready\",\"pid\":%d,\"observer_pid\":%d,\"dumpable\":0,\"exitkill\":true}",
                  root_pid, getpid()); emit();
    if (ptrace(PTRACE_SYSCALL, root_pid, 0, 0)) fail("trace_resume_failed");
    int root_exit = -1;
    while (1) {
        pid_t pid = waitpid(-1, &status, __WALL);
        if (pid < 0) {
            if (errno == EINTR) continue;
            if (errno == ECHILD) {
                for (int i = 0; i < 64; ++i) if (tasks[i].pid) fail("tracee_exit_notification_missing");
                break;
            }
            fail("trace_wait_failed");
        }
        int index = task(pid);
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            int result = WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
            if (pid == root_pid) root_exit = result;
            tasks[index].pid = 0;
            begin(); add("{\"event\":\"native_process_exit\",\"pid\":%d,\"exit_code\":%d}", pid, result); emit();
            continue;
        }
        if (!WIFSTOPPED(status)) fail("unexpected_trace_state");
        /* SIGKILL/group exit can remove a stopped thread before a ptrace
           request. Keep it tracked until waitpid confirms its terminal state. */
        if (setjmp(trace_exit)) {
            allow_exit_race = 0;
            begin(); add("{\"event\":\"tracee_exit_pending\",\"pid\":%d,\"operation\":\"%s\"}", pid, exit_operation); emit();
            continue;
        }
        allow_exit_race = 1;
        int signal = WSTOPSIG(status), event = status >> 16;
        if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE) {
            unsigned long child = 0;
            if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &child)) trace_error("trace_child_unreadable");
            task((pid_t)child);
        } else if (event == PTRACE_EVENT_EXEC) {
            begin(); add("{\"event\":\"native_exec_committed\",\"pid\":%d}", pid); emit();
        } else if (signal == (SIGTRAP | 0x80)) {
            struct ptrace_syscall_info info;
            memset(&info, 0, sizeof(info));
            if (ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(info), &info) < 0) trace_error("syscall_info_unavailable");
            if (info.arch != AUDIT_ARCH_X86_64 ||
                    (info.op == PTRACE_SYSCALL_INFO_ENTRY && info.entry.nr & 0x40000000UL))
                fail("unsupported_tracee_architecture");
            if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
                console_entry(pid, index, &info);
                if (info.entry.nr == SYS_execve || info.entry.nr == SYS_execveat) exec_event(pid, &info);
                if (info.entry.nr == SYS_write && (info.entry.args[0] == 198 || info.entry.args[0] == 197)) {
                    unsigned long length = info.entry.args[2];
                    if (!length || length > 65536) fail("engine_record_limit");
                    begin(); add("{\"event\":\"%s\",\"pid\":%d,\"data_hex\":",
                                 info.entry.args[0] == 198 ? "guest_engine_record" : "guest_tool_record", pid);
                    hex_memory(pid, info.entry.args[1], length, 0); add("}"); emit();
                }
                int error = denied(&info);
                if (error) {
                    struct user_regs_struct registers;
                    if (ptrace(PTRACE_GETREGS, pid, 0, &registers)) trace_error("register_read_failed");
                    registers.orig_rax = (unsigned long)-1;
                    if (ptrace(PTRACE_SETREGS, pid, 0, &registers)) trace_error("syscall_block_failed");
                    tasks[index].blocked = error;
                    begin(); add("{\"event\":\"native_syscall_denied\",\"pid\":%d,\"syscall_number\":%llu,\"errno\":%d}",
                                  pid, (unsigned long long)info.entry.nr, error); emit();
                }
            } else if (info.op == PTRACE_SYSCALL_INFO_EXIT && tasks[index].console_fd) {
                if (!info.exit.is_error && info.exit.rval > 0) {
                    size_t size = tasks[index].console_size;
                    if ((unsigned long long)info.exit.rval < size) size = (size_t)info.exit.rval;
                    int stream = tasks[index].console_fd - 1;
                    size_t remaining = console_totals[stream] < 65536 ? 65536 - console_totals[stream] : 0;
                    if (size > remaining) { size = remaining; tasks[index].console_truncated = 1; }
                    console_totals[tasks[index].console_fd - 1] += size;
                    begin(); add("{\"event\":\"native_console_write\",\"pid\":%d,\"fd\":%d,\"truncated\":%s,\"data_hex\":\"",
                        pid, tasks[index].console_fd, tasks[index].console_truncated ? "true" : "false");
                    for (size_t j = 0; j < size; ++j) add("%02x", tasks[index].console[j]);
                    add("\"}"); emit();
                }
                tasks[index].console_fd = 0;
            } else if (info.op == PTRACE_SYSCALL_INFO_EXIT && tasks[index].blocked) {
                struct user_regs_struct registers;
                if (ptrace(PTRACE_GETREGS, pid, 0, &registers)) trace_error("register_read_failed");
                registers.rax = (unsigned long)-tasks[index].blocked;
                if (ptrace(PTRACE_SETREGS, pid, 0, &registers)) trace_error("syscall_result_failed");
                tasks[index].blocked = 0;
            }
        }
        int deliver = (signal == (SIGTRAP | 0x80) || signal == SIGTRAP || signal == SIGSTOP) ? 0 : signal;
        if (ptrace(PTRACE_SYSCALL, pid, 0, (void *)(long)deliver)) trace_error("trace_resume_failed");
        allow_exit_race = 0;
    }
    begin(); add("{\"event\":\"observer_finished\",\"root_exit_code\":%d}", root_exit); emit();
    OPENSSL_cleanse(key, sizeof(key));
    return root_exit == 0 ? 0 : 1;
}

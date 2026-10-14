/* Fixed-probe Linux x86-64 process observer. Built statically in WSL; executed
 * only in the unprivileged, no-network probe container. Not a sandbox launcher
 * for submitted scripts. A host-provided key authenticates observer records. */
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
static struct { pid_t pid; int blocked; } tasks[64];

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
    if (root_pid > 0) kill(root_pid, SIGKILL);
    for (int i = 0; i < 64; ++i) if (tasks[i].pid > 0) kill(tasks[i].pid, SIGKILL);
    begin(); add("{\"event\":\"observer_error\",\"reason\":\"%s\"}", reason); emit();
    _exit(95);
}
static int task(pid_t pid) {
    for (int i = 0; i < 64; ++i) if (tasks[i].pid == pid) return i;
    for (int i = 0; i < 64; ++i) if (!tasks[i].pid) { tasks[i].pid = pid; tasks[i].blocked = 0; return i; }
    fail("tracee_limit"); return -1;
}
static unsigned long peek(pid_t pid, unsigned long address) {
    errno = 0;
    long value = ptrace(PTRACE_PEEKDATA, pid, (void *)address, 0);
    if (value == -1 && errno) fail("tracee_memory_unreadable");
    return (unsigned long)value;
}
static void hex_string(pid_t pid, unsigned long address) {
    add("\"");
    for (size_t i = 0; i < 16384; i += sizeof(unsigned long)) {
        unsigned long word = peek(pid, address + i);
        for (size_t j = 0; j < sizeof(word); ++j) {
            unsigned int c = (word >> (j * 8)) & 255;
            if (!c) { add("\""); return; }
            add("%02x", c);
        }
    }
    fail("argument_limit");
}
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

int main(int argc, char **argv) {
    if (argc < 2) return 90;
    size_t count = 0;
    while (count < sizeof(key)) {
        ssize_t n = read(STDIN_FILENO, key + count, sizeof(key) - count);
        if (n <= 0) return 91;
        count += (size_t)n;
    }
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core) || prctl(PR_SET_DUMPABLE, 0)) return 92;
    root_pid = fork();
    if (root_pid == -1) return 93;
    if (!root_pid) {
        OPENSSL_cleanse(key, sizeof(key));
        int fd = open("/dev/null", O_RDWR);
        if (fd < 0 || dup2(fd, 0) < 0 || dup2(fd, 1) < 0 || dup2(fd, 2) < 0) _exit(94);
        if (fd > 2) close(fd);
        if (prctl(PR_SET_DUMPABLE, 1) || ptrace(PTRACE_TRACEME, 0, 0, 0)) _exit(94);
        raise(SIGSTOP);
        execvp(argv[1], argv + 1);
        _exit(94);
    }
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
            if (errno == ECHILD) break;
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
        int signal = WSTOPSIG(status), event = status >> 16;
        if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE) {
            unsigned long child = 0;
            if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &child)) fail("trace_child_unreadable");
            task((pid_t)child);
        } else if (event == PTRACE_EVENT_EXEC) {
            begin(); add("{\"event\":\"native_exec_committed\",\"pid\":%d}", pid); emit();
        } else if (signal == (SIGTRAP | 0x80)) {
            struct ptrace_syscall_info info;
            memset(&info, 0, sizeof(info));
            if (ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(info), &info) < 0) fail("syscall_info_unavailable");
            if (info.arch != AUDIT_ARCH_X86_64 ||
                    (info.op == PTRACE_SYSCALL_INFO_ENTRY && info.entry.nr & 0x40000000UL))
                fail("unsupported_tracee_architecture");
            if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
                if (info.entry.nr == SYS_execve || info.entry.nr == SYS_execveat) exec_event(pid, &info);
                int error = denied(&info);
                if (error) {
                    struct user_regs_struct registers;
                    if (ptrace(PTRACE_GETREGS, pid, 0, &registers)) fail("register_read_failed");
                    registers.orig_rax = (unsigned long)-1;
                    if (ptrace(PTRACE_SETREGS, pid, 0, &registers)) fail("syscall_block_failed");
                    tasks[index].blocked = error;
                    begin(); add("{\"event\":\"native_syscall_denied\",\"pid\":%d,\"syscall_number\":%llu,\"errno\":%d}",
                                  pid, (unsigned long long)info.entry.nr, error); emit();
                }
            } else if (info.op == PTRACE_SYSCALL_INFO_EXIT && tasks[index].blocked) {
                struct user_regs_struct registers;
                if (ptrace(PTRACE_GETREGS, pid, 0, &registers)) fail("register_read_failed");
                registers.rax = (unsigned long)-tasks[index].blocked;
                if (ptrace(PTRACE_SETREGS, pid, 0, &registers)) fail("syscall_result_failed");
                tasks[index].blocked = 0;
            }
        }
        int deliver = (signal == (SIGTRAP | 0x80) || signal == SIGTRAP || signal == SIGSTOP) ? 0 : signal;
        if (ptrace(PTRACE_SYSCALL, pid, 0, (void *)(long)deliver) && errno != ESRCH) fail("trace_resume_failed");
    }
    begin(); add("{\"event\":\"observer_finished\",\"root_exit_code\":%d}", root_exit); emit();
    OPENSSL_cleanse(key, sizeof(key));
    return root_exit == 0 ? 0 : 1;
}

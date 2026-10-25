//! Fail-closed host boundary for the static Linux guest worker.
use anyhow::{Context, Result, ensure};
use libc::{self, c_long};
use serde::Serialize;
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

#[derive(Debug, Serialize)]
pub struct Containment {
    pub user_namespace: bool,
    pub mount_namespace: bool,
    pub network_namespace: bool,
    pub ipc_namespace: bool,
    pub root_confined: bool,
    pub no_new_privileges: bool,
    pub capabilities_dropped: bool,
    pub seccomp_filter: bool,
    pub child_process_blocked: bool,
    pub network_syscalls_blocked: bool,
}

fn namespace_inode(name: &str) -> Result<u64> {
    Ok(fs::metadata(format!("/proc/self/ns/{name}"))?.ino())
}

fn write_map(path: &str, data: String) -> Result<()> {
    fs::write(path, data).with_context(|| format!("Cannot set {path}"))
}

fn syscall_ok(value: libc::c_int, operation: &str) -> Result<()> {
    if value == -1 {
        Err(std::io::Error::last_os_error()).with_context(|| operation.to_owned())
    } else {
        Ok(())
    }
}

fn limit(resource: u32, value: u64) -> Result<()> {
    let bound = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: bound is a valid rlimit structure for this process.
    syscall_ok(
        unsafe { libc::setrlimit(resource, &bound) },
        "Cannot set worker resource limit",
    )
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn clear_capabilities() -> Result<()> {
    let header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let empty = [CapData::default(); 2];
    // SAFETY: pointers match Linux capability v3's header and two data words.
    syscall_ok(
        unsafe { libc::syscall(libc::SYS_capset, &header, empty.as_ptr()) as i32 },
        "Cannot drop worker capabilities",
    )?;
    let mut observed = [CapData::default(); 2];
    syscall_ok(
        unsafe { libc::syscall(libc::SYS_capget, &header, observed.as_mut_ptr()) as i32 },
        "Cannot inspect worker capabilities",
    )?;
    ensure!(
        observed
            .iter()
            .all(|word| { word.effective == 0 && word.permitted == 0 && word.inheritable == 0 }),
        "Worker still has capabilities"
    );
    Ok(())
}

fn statement(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn branch(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

fn install_seccomp() -> Result<()> {
    // Arch and x32 checks precede the blocked syscall list. Keep this list
    // limited to host-facing operations; Unicorn still needs memory and IO.
    let denied: &[c_long] = &[
        libc::SYS_fork,
        libc::SYS_vfork,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_open,
        libc::SYS_pidfd_getfd,
        libc::SYS_kill,
        libc::SYS_tkill,
        libc::SYS_tgkill,
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_bpf,
        libc::SYS_userfaultfd,
        libc::SYS_io_uring_setup,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
    ];
    let load = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let jump = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    let ge = (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16;
    let set = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
    let ret = (libc::BPF_RET | libc::BPF_K) as u16;
    let mut filter = vec![
        statement(load, 4),
        branch(jump, AUDIT_ARCH_X86_64, 1, 0),
        statement(ret, SECCOMP_RET_KILL_PROCESS),
        statement(load, 0),
        branch(ge, 0x4000_0000, 0, 1),
        statement(ret, SECCOMP_RET_KILL_PROCESS),
    ];
    for &number in denied {
        filter.push(branch(jump, number as u32, 0, 1));
        filter.push(statement(ret, SECCOMP_RET_ERRNO | libc::EPERM as u32));
    }
    // glibc retries clone after clone3 reports ENOSYS. Permit only threads
    // sharing the calling process; a clone without CLONE_THREAD is denied.
    filter.push(branch(jump, libc::SYS_clone3 as u32, 0, 1));
    filter.push(statement(ret, SECCOMP_RET_ERRNO | libc::ENOSYS as u32));
    filter.push(branch(jump, libc::SYS_clone as u32, 0, 4));
    filter.push(statement(load, 16)); // seccomp_data.args[0], low 32 bits
    filter.push(branch(set, libc::CLONE_THREAD as u32, 0, 1));
    filter.push(statement(ret, SECCOMP_RET_ALLOW));
    filter.push(statement(ret, SECCOMP_RET_ERRNO | libc::EPERM as u32));
    filter.push(statement(ret, SECCOMP_RET_ALLOW));
    let program = libc::sock_fprog {
        len: u16::try_from(filter.len()).context("Seccomp program too large")?,
        filter: filter.as_mut_ptr(),
    };
    // SAFETY: the kernel copies the BPF instructions before this call returns.
    syscall_ok(
        unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0,
                &program,
            ) as i32
        },
        "Cannot install worker seccomp filter",
    )?;
    ensure!(
        unsafe { libc::prctl(libc::PR_GET_SECCOMP, 0, 0, 0, 0) }
            == libc::SECCOMP_MODE_FILTER as i32,
        "Worker seccomp filter is inactive"
    );
    Ok(())
}

fn expect_denied(value: c_long, operation: &str) -> Result<()> {
    ensure!(value == -1, "{operation} unexpectedly succeeded");
    ensure!(
        std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
        "{operation} did not return EPERM"
    );
    Ok(())
}

/// Enter confinement before any untrusted request or ELF byte is read.
pub fn prepare_worker(root: &Path) -> Result<Containment> {
    ensure!(cfg!(target_arch = "x86_64"), "Linux worker requires x86-64");
    let root = fs::canonicalize(root)?;
    ensure!(root.is_dir(), "Linux run root is not a directory");
    let before = [
        namespace_inode("user")?,
        namespace_inode("mnt")?,
        namespace_inode("net")?,
        namespace_inode("ipc")?,
    ];
    let host_uid = unsafe { libc::getuid() };
    let host_gid = unsafe { libc::getgid() };
    // SAFETY: unshare affects only this single-threaded worker process.
    syscall_ok(
        unsafe { libc::unshare(libc::CLONE_NEWUSER) },
        "Cannot create user namespace",
    )?;
    write_map("/proc/self/setgroups", "deny\n".into())?;
    write_map("/proc/self/uid_map", format!("0 {host_uid} 1\n"))?;
    write_map("/proc/self/gid_map", format!("0 {host_gid} 1\n"))?;
    syscall_ok(
        unsafe { libc::unshare(libc::CLONE_NEWNS | libc::CLONE_NEWNET | libc::CLONE_NEWIPC) },
        "Cannot create mount, network, and IPC namespaces",
    )?;
    let after = [
        namespace_inode("user")?,
        namespace_inode("mnt")?,
        namespace_inode("net")?,
        namespace_inode("ipc")?,
    ];
    ensure!(
        before.iter().zip(after).all(|(old, new)| *old != new),
        "Linux namespace identity did not change"
    );
    syscall_ok(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        "No new privileges",
    )?;
    syscall_ok(
        unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) },
        "Disable worker dumps",
    )?;
    std::env::set_current_dir(&root)?;
    // SAFETY: root is a canonical, fresh run directory and the worker has
    // user-namespace CAP_SYS_CHROOT only until capabilities are dropped.
    syscall_ok(
        unsafe { libc::chroot(c".".as_ptr()) },
        "Cannot confine worker root",
    )?;
    std::env::set_current_dir("/")?;
    syscall_ok(
        unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) as i32 },
        "Cannot close inherited worker descriptors",
    )?;
    // Unicorn reserves a 1 GiB translator arena before guest mappings.
    limit(libc::RLIMIT_AS, 2 * 1024 * 1024 * 1024)?;
    limit(libc::RLIMIT_FSIZE, 4 * 1024 * 1024)?;
    limit(libc::RLIMIT_NOFILE, 64)?;
    limit(libc::RLIMIT_CPU, 40)?;
    limit(libc::RLIMIT_CORE, 0)?;
    clear_capabilities()?;
    install_seccomp()?;
    ensure!(
        unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) } == 1,
        "No-new-privileges inactive"
    );
    expect_denied(
        unsafe { libc::syscall(libc::SYS_socket, libc::AF_INET, libc::SOCK_STREAM, 0) },
        "Worker network socket",
    )?;
    expect_denied(
        unsafe { libc::syscall(libc::SYS_clone, libc::SIGCHLD, 0, 0, 0, 0) },
        "Worker child process",
    )?;
    ensure!(
        fs::metadata("/etc/passwd").is_err(),
        "Worker can still see host filesystem"
    );
    Ok(Containment {
        user_namespace: true,
        mount_namespace: true,
        network_namespace: true,
        ipc_namespace: true,
        root_confined: true,
        no_new_privileges: true,
        capabilities_dropped: true,
        seccomp_filter: true,
        child_process_blocked: true,
        network_syscalls_blocked: true,
    })
}

pub fn read_regular(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= maximum as u64,
        "Invalid regular input"
    );
    let mut data = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum as u64 + 1).read_to_end(&mut data)?;
    ensure!(data.len() <= maximum, "Input exceeds bound");
    Ok(data)
}

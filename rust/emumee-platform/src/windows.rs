//! Windows-only worker confinement and bounded file operations.
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    mem::{size_of, zeroed},
    os::windows::{
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, Isolation::*, *},
    Storage::FileSystem::*,
    System::{
        JobObjects::*, SystemServices::PROCESS_MITIGATION_CHILD_PROCESS_POLICY, Threading::*,
    },
};
mod output;
mod recovery;
pub use output::{OutputLimitExceeded, OutputLimits, OutputUsage, inspect_output};
pub use recovery::{RecoveryReport, RecoverySession};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerStop {
    Exited,
    Timeout,
    OutputLimit,
    OutputInspectionFailed,
}
#[derive(Debug, Serialize)]
pub struct WorkerExit {
    pub exit_code: u32,
    pub reason: WorkerStop,
    pub detail: Option<String>,
    pub output_usage: Option<OutputUsage>,
    pub output_checks: u64,
    pub elapsed_ms: u128,
}

fn win(ok: i32) -> Result<()> {
    if ok == 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}
fn wide(text: &std::ffi::OsStr) -> Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    let mut data: Vec<u16> = text.encode_wide().collect();
    ensure!(!data.contains(&0), "Embedded NUL in Windows path/name");
    data.push(0);
    Ok(data)
}
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

pub struct BundleLock {
    handle: Handle,
    held: bool,
}
impl BundleLock {
    pub fn acquire(bundle: &Path) -> Result<Self> {
        let key = format!(
            "{:x}",
            Sha256::digest(normalized(&std::fs::canonicalize(bundle)?).as_bytes())
        );
        let name = wide(std::ffi::OsStr::new(&format!(
            "Local\\Emumee.Rust.Bundle.{}",
            &key[..24]
        )))?;
        let handle = Handle(unsafe { CreateMutexW(null(), 0, name.as_ptr()) });
        ensure!(!handle.0.is_null(), "Cannot create bundle lock");
        let mut lock = Self {
            handle,
            held: false,
        };
        let status = unsafe { WaitForSingleObject(lock.handle.0, 180000) };
        lock.held = status == WAIT_OBJECT_0 || status == WAIT_ABANDONED;
        ensure!(lock.held, "Bundle lock unavailable:0x{status:x}");
        Ok(lock)
    }
}
impl Drop for BundleLock {
    fn drop(&mut self) {
        if self.held {
            unsafe {
                ReleaseMutex(self.handle.0);
            }
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Containment {
    pub app_container: bool,
    pub job_object: bool,
    pub child_process_blocked: bool,
    pub network_capabilities: u32,
}
/// The job already limits the process tree to one process during startup.
/// Activate the token's child mitigation before reading any worker input.
pub fn prepare_worker() -> Result<Containment> {
    unsafe {
        let mut token = null_mut();
        win(OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut token,
        ))?;
        let token = Handle(token);
        let mut container = 0u32;
        let mut bytes = 0;
        win(GetTokenInformation(
            token.0,
            TokenIsAppContainer,
            (&mut container as *mut u32).cast(),
            4,
            &mut bytes,
        ))?;
        ensure!(container != 0, "Worker is outside AppContainer");
        let flags = 1u32;
        win(SetProcessMitigationPolicy(
            ProcessChildProcessPolicy,
            (&flags as *const u32).cast(),
            4,
        ))?;
    }
    verify_containment()
}
pub fn verify_containment() -> Result<Containment> {
    // SAFETY: all pointers reference initialized local structs with their exact
    // SDK sizes; pseudo handles are queried but never owned/closed.
    unsafe {
        let process = GetCurrentProcess();
        let mut token = null_mut();
        win(OpenProcessToken(process, TOKEN_QUERY, &mut token))?;
        let token = Handle(token);
        let mut container = 0u32;
        let mut needed = 0;
        win(GetTokenInformation(
            token.0,
            TokenIsAppContainer,
            (&mut container as *mut u32).cast(),
            4,
            &mut needed,
        ))?;
        let mut job = 0;
        win(IsProcessInJob(process, null_mut(), &mut job))?;
        let mut capability_bytes = 0;
        GetTokenInformation(
            token.0,
            TokenCapabilities,
            null_mut(),
            0,
            &mut capability_bytes,
        );
        ensure!(
            (4..=4096).contains(&capability_bytes),
            "Invalid capability token buffer"
        );
        let mut capabilities =
            vec![0usize; (capability_bytes as usize).div_ceil(size_of::<usize>())];
        win(GetTokenInformation(
            token.0,
            TokenCapabilities,
            capabilities.as_mut_ptr().cast(),
            capability_bytes,
            &mut capability_bytes,
        ))?;
        let network_capabilities = *(capabilities.as_ptr() as *const u32);
        let mut policy: PROCESS_MITIGATION_CHILD_PROCESS_POLICY = zeroed();
        win(GetProcessMitigationPolicy(
            process,
            ProcessChildProcessPolicy,
            (&mut policy as *mut PROCESS_MITIGATION_CHILD_PROCESS_POLICY).cast(),
            size_of::<PROCESS_MITIGATION_CHILD_PROCESS_POLICY>(),
        ))?;
        let state = Containment {
            app_container: container != 0,
            job_object: job != 0,
            child_process_blocked: policy.Anonymous.Flags & 1 != 0,
            network_capabilities,
        };
        ensure!(
            state.app_container
                && state.job_object
                && state.child_process_blocked
                && network_capabilities == 0,
            "Worker confinement is incomplete: {state:?}"
        );
        Ok(state)
    }
}

fn normalized(path: &Path) -> String {
    let text = path.as_os_str().to_string_lossy().replace('/', "\\");
    let text = if let Some(rest) = text.strip_prefix("\\\\?\\UNC\\") {
        format!("\\\\{rest}")
    } else {
        text.strip_prefix("\\\\?\\").unwrap_or(&text).to_owned()
    };
    text.to_lowercase()
}
fn file_info(file: &File) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info = unsafe { zeroed() };
    unsafe {
        win(GetFileInformationByHandle(
            file.as_raw_handle().cast(),
            &mut info,
        ))?;
    }
    Ok(info)
}
fn same_file(a: &BY_HANDLE_FILE_INFORMATION, b: &BY_HANDLE_FILE_INFORMATION) -> bool {
    a.dwVolumeSerialNumber == b.dwVolumeSerialNumber
        && a.nFileIndexHigh == b.nFileIndexHigh
        && a.nFileIndexLow == b.nFileIndexLow
        && b.nNumberOfLinks == 1
}
fn open_read(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?)
}
/// Parent keeps this no-delete-share handle until both isolated roles stop.
pub fn create_pinned(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?)
}
/// Open an existing fixed RPC/journal endpoint. Directory grants are read-only;
/// writers receive FILE_APPEND_DATA, not permission to overwrite earlier bytes.
pub fn open_pinned(path: &Path, root: &Path, append: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .append(append)
        .access_mode(FILE_GENERIC_READ | if append { FILE_APPEND_DATA } else { 0 })
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let info = file_info(&file)?;
    ensure!(
        info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) == 0
            && info.nNumberOfLinks == 1,
        "Invalid pinned RPC file"
    );
    contained_identity(path, root, &info)?;
    Ok(file)
}
/// Trusted broker journal requires GENERIC_WRITE for FlushFileBuffers. This
/// separate handle is never given to the guest worker or used for RPC streams.
pub fn open_pinned_journal(path: &Path, root: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let info = file_info(&file)?;
    ensure!(
        info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) == 0
            && info.nNumberOfLinks == 1,
        "Invalid private journal file"
    );
    contained_identity(path, root, &info)?;
    Ok(file)
}
fn contained_identity(
    path: &Path,
    root: &Path,
    expected: &BY_HANDLE_FILE_INFORMATION,
) -> Result<()> {
    let root = std::path::absolute(root)?;
    let path = std::path::absolute(path)?;
    let relative = path
        .strip_prefix(&root)
        .context("Worker file is outside its run root")?;
    ensure!(
        relative
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_))),
        "Invalid contained path"
    );
    let mut current = root;
    for part in relative.parent().unwrap_or(Path::new("")).components() {
        let metadata = std::fs::symlink_metadata(&current)?;
        ensure!(
            metadata.is_dir() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "Reparse point in worker path"
        );
        current.push(part);
    }
    let metadata = std::fs::symlink_metadata(&current)?;
    ensure!(
        metadata.is_dir() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "Invalid worker parent"
    );
    let metadata = std::fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "Invalid worker file"
    );
    let second = open_read(&path)?;
    ensure!(
        same_file(expected, &file_info(&second)?),
        "Worker path identity changed"
    );
    Ok(())
}
fn regular_scope<T>(
    path: &Path,
    limit: usize,
    root: Option<&Path>,
    locked: bool,
    operation: impl FnOnce(&File, u64) -> Result<T>,
) -> Result<T> {
    ensure!(limit <= 512 * 1024 * 1024, "Invalid bounded read limit");
    let target = std::path::absolute(path)?;
    let file = if locked {
        OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&target)?
    } else {
        open_read(&target)?
    };
    let before = file_info(&file)?;
    let length = ((before.nFileSizeHigh as u64) << 32) | before.nFileSizeLow as u64;
    ensure!(
        before.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) == 0
            && before.nNumberOfLinks == 1
            && length <= limit as u64,
        "Worker file type, links or size rejected"
    );
    let mut name = vec![0u16; 32768];
    let count = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle().cast(),
            name.as_mut_ptr(),
            name.len() as u32,
            0,
        )
    };
    if count == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(5) {
            contained_identity(
                &target,
                root.context("Handle name unavailable without a containment root")?,
                &before,
            )?;
        } else {
            return Err(error.into());
        }
    } else {
        ensure!(
            (count as usize) < name.len(),
            "Worker handle path exceeds bound"
        );
        let actual = PathBuf::from(String::from_utf16(&name[..count as usize])?);
        ensure!(
            normalized(&actual) == normalized(&target),
            "Worker handle resolves to another path"
        );
    }
    let data = operation(&file, length)?;
    let after = file_info(&file)?;
    ensure!(
        same_file(&before, &after)
            && after.nFileSizeHigh == before.nFileSizeHigh
            && after.nFileSizeLow == before.nFileSizeLow
            && after.ftLastWriteTime.dwHighDateTime == before.ftLastWriteTime.dwHighDateTime
            && after.ftLastWriteTime.dwLowDateTime == before.ftLastWriteTime.dwLowDateTime,
        "Worker file changed during read"
    );
    Ok(data)
}
pub fn read_regular(path: &Path, limit: usize, root: Option<&Path>) -> Result<Vec<u8>> {
    regular_scope(path, limit, root, false, |file, length| {
        let mut data = Vec::with_capacity(length as usize);
        file.take(limit as u64 + 1).read_to_end(&mut data)?;
        ensure!(data.len() <= limit, "Worker file exceeds bounded read");
        Ok(data)
    })
}
/// Driver128 payload hashing/header reads share one locked, identity-pinned
/// regular handle. No write/delete sharing; <=8MiB/read and length+1MiB work.
pub fn with_driver_regular<T>(
    path: &Path,
    length: u64,
    root: &Path,
    operation: impl FnOnce(&mut dyn FnMut(u64, usize) -> Result<Vec<u8>>) -> Result<T>,
) -> Result<T> {
    use std::io::{Seek, SeekFrom};
    ensure!(
        length > 0 && length <= 128 * 1024 * 1024,
        "Driver128 file length bound"
    );
    regular_scope(path, length as usize, Some(root), true, |file, actual| {
        ensure!(actual == length, "Driver128 declared/actual length differs");
        let mut work = 0u64;
        let mut read = |offset: u64, count: usize| -> Result<Vec<u8>> {
            ensure!(
                count <= 8 * 1024 * 1024
                    && offset
                        .checked_add(count as u64)
                        .is_some_and(|end| end <= length),
                "Driver128 range bound"
            );
            work = work
                .checked_add(count as u64)
                .context("Driver128 read work overflow")?;
            ensure!(work <= length + 1024 * 1024, "Driver128 read work bound");
            let mut handle = file;
            handle.seek(SeekFrom::Start(offset))?;
            let mut bytes = vec![0u8; count];
            handle.read_exact(&mut bytes)?;
            Ok(bytes)
        };
        operation(&mut read)
    })
}

pub struct WorkerJob {
    handle: Handle,
}
impl WorkerJob {
    pub fn new(memory_mib: usize) -> Result<Self> {
        Self::create(memory_mib, None)
    }
    pub fn new_tracked(memory_mib: usize, recovery: &mut RecoverySession) -> Result<Self> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let name = format!(
            "Local\\Emumee.Rust.Job.{}.{now}.{sequence}",
            std::process::id()
        );
        recovery.job(&name)?;
        Self::create(memory_mib, Some(&name))
    }
    fn create(memory_mib: usize, name: Option<&str>) -> Result<Self> {
        ensure!(
            (64..=16384).contains(&memory_mib),
            "Job memory bound must be64..16384MiB"
        );
        unsafe {
            let name = name
                .map(|name| wide(std::ffi::OsStr::new(name)))
                .transpose()?;
            SetLastError(0);
            let handle = Handle(CreateJobObjectW(
                null(),
                name.as_ref().map_or(null(), |name| name.as_ptr()),
            ));
            let existed = std::io::Error::last_os_error().raw_os_error() == Some(183);
            ensure!(!existed, "Named recovery job already exists");
            ensure!(
                !handle.0.is_null(),
                "Cannot create worker job: {}",
                std::io::Error::last_os_error()
            );
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | JOB_OBJECT_LIMIT_PROCESS_MEMORY
                | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            limits.BasicLimitInformation.ActiveProcessLimit = 1;
            limits.ProcessMemoryLimit = memory_mib * 1024 * 1024;
            win(SetInformationJobObject(
                handle.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ))?;
            Ok(Self { handle })
        }
    }
    /// Actual Windows job accounting; available only while the tracked job lives.
    pub fn peak_process_memory_bytes(&self) -> Result<u64> {
        unsafe {
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = zeroed();
            win(QueryInformationJobObject(
                self.handle.0,
                JobObjectExtendedLimitInformation,
                (&mut info as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                null_mut(),
            ))?;
            Ok(info.PeakProcessMemoryUsed as u64)
        }
    }
    pub fn terminate(&self) -> Result<()> {
        unsafe { win(TerminateJobObject(self.handle.0, 1)) }
    }
}

/// A unique zero-capability profile. It is never given internet capability.
pub struct OfflineProfile {
    name: Vec<u16>,
    sid: PSID,
    deleted: bool,
}
impl OfflineProfile {
    pub fn new() -> Result<Self> {
        Self::create(None)
    }
    pub fn new_tracked(recovery: &mut RecoverySession) -> Result<Self> {
        Self::create(Some(recovery))
    }
    fn create(recovery: Option<&mut RecoverySession>) -> Result<Self> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let name = format!("Emumee.Rust.Worker.{}.{now}.{sequence}", std::process::id());
        if let Some(recovery) = recovery {
            recovery.profile(&name)?;
        }
        let name = wide(std::ffi::OsStr::new(&name))?;
        let label = wide(std::ffi::OsStr::new("Emumee Rust offline analysis worker"))?;
        let mut sid = null_mut();
        let hr = unsafe {
            CreateAppContainerProfile(
                name.as_ptr(),
                label.as_ptr(),
                label.as_ptr(),
                null(),
                0,
                &mut sid,
            )
        };
        ensure!(
            hr >= 0,
            "CreateAppContainerProfile failed:0x{:08x}",
            hr as u32
        );
        ensure!(!sid.is_null(), "AppContainer returned no SID");
        Ok(Self {
            name,
            sid,
            deleted: false,
        })
    }
    pub fn close(&mut self) -> Result<()> {
        if !self.deleted {
            let hr = unsafe { DeleteAppContainerProfile(self.name.as_ptr()) };
            ensure!(
                hr >= 0,
                "DeleteAppContainerProfile failed:0x{:08x}",
                hr as u32
            );
            self.deleted = true;
        }
        Ok(())
    }
    pub fn grant(&self, path: &Path, write: bool) -> Result<AccessGrant> {
        AccessGrant::new(
            path,
            self.sid,
            if write {
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE
            } else {
                FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
            },
            None,
        )
    }
    pub fn grant_append(&self, path: &Path) -> Result<AccessGrant> {
        ensure!(path.is_file(), "Append grant requires a regular file");
        AccessGrant::new(path, self.sid, FILE_GENERIC_READ | FILE_APPEND_DATA, None)
    }
    pub fn grant_tracked(
        &self,
        path: &Path,
        write: bool,
        recovery: &mut RecoverySession,
    ) -> Result<AccessGrant> {
        AccessGrant::new(
            path,
            self.sid,
            if write {
                FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE
            } else {
                FILE_GENERIC_READ | FILE_GENERIC_EXECUTE
            },
            Some(recovery),
        )
    }
    /// Grant directory traversal/metadata without inheriting read access to children.
    pub fn grant_traverse_tracked(
        &self,
        path: &Path,
        recovery: &mut RecoverySession,
    ) -> Result<AccessGrant> {
        ensure!(path.is_dir(), "Traverse grant requires a directory");
        AccessGrant::new_with_inheritance(
            path,
            self.sid,
            FILE_GENERIC_EXECUTE,
            Some(recovery),
            false,
        )
    }
    pub fn grant_append_tracked(
        &self,
        path: &Path,
        recovery: &mut RecoverySession,
    ) -> Result<AccessGrant> {
        ensure!(path.is_file(), "Append grant requires a regular file");
        AccessGrant::new(
            path,
            self.sid,
            FILE_GENERIC_READ | FILE_APPEND_DATA,
            Some(recovery),
        )
    }
}
impl Drop for OfflineProfile {
    fn drop(&mut self) {
        let _ = self.close();
        if !self.sid.is_null() {
            unsafe {
                FreeSid(self.sid);
            }
        }
    }
}

/// Restore the exact original DACL. This edits no SACL or machine policy.
pub struct AccessGrant {
    path: Vec<u16>,
    descriptor: PSECURITY_DESCRIPTOR,
    original: *mut ACL,
    restored: bool,
}
impl AccessGrant {
    fn new(
        path: &Path,
        sid: PSID,
        permissions: u32,
        recovery: Option<&mut RecoverySession>,
    ) -> Result<Self> {
        Self::new_with_inheritance(path, sid, permissions, recovery, true)
    }
    fn new_with_inheritance(
        path: &Path,
        sid: PSID,
        permissions: u32,
        recovery: Option<&mut RecoverySession>,
        inherit: bool,
    ) -> Result<Self> {
        let path = std::path::absolute(path)?;
        let canonical = std::fs::canonicalize(&path)?;
        ensure!(
            normalized(&path) == normalized(&canonical),
            "AppContainer grant target redirects"
        );
        check_grant_tree(&path)?;
        let directory = path.is_dir();
        let text = wide(path.as_os_str())?;
        let mut descriptor = null_mut();
        let mut original = null_mut();
        let status = unsafe {
            GetNamedSecurityInfoW(
                text.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut original,
                null_mut(),
                &mut descriptor,
            )
        };
        ensure!(status == 0, "Cannot read grant DACL:Win32{status}");
        let guard = Self {
            path: text,
            descriptor,
            original,
            restored: false,
        };
        if let Some(recovery) = recovery {
            recovery.dacl(&path, descriptor)?;
        }
        let access = EXPLICIT_ACCESS_W {
            grfAccessPermissions: permissions,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: if directory && inherit {
                SUB_CONTAINERS_AND_OBJECTS_INHERIT
            } else {
                NO_INHERITANCE
            },
            Trustee: TRUSTEE_W {
                pMultipleTrustee: null_mut(),
                MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_UNKNOWN,
                ptstrName: sid.cast(),
            },
        };
        let mut updated = null_mut();
        let status = unsafe { SetEntriesInAclW(1, &access, original, &mut updated) };
        if status != 0 {
            bail!("Cannot construct grant DACL:Win32{status}");
        }
        let status = unsafe {
            SetNamedSecurityInfoW(
                guard.path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                updated,
                null(),
            )
        };
        unsafe {
            LocalFree(updated.cast());
        }
        if status != 0 {
            bail!("Cannot apply grant DACL:Win32{status}");
        }
        Ok(guard)
    }
    pub fn restore(&mut self) -> Result<()> {
        if !self.restored {
            let status = unsafe {
                SetNamedSecurityInfoW(
                    self.path.as_ptr(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    self.original,
                    null(),
                )
            };
            ensure!(status == 0, "Cannot restore grant DACL:Win32{status}");
            // SetNamedSecurityInfo propagates removal to descendants, but also
            // enables automatic inheritance on the root. Restore its original
            // descriptor flags with the non-propagating file-security API.
            unsafe {
                win(SetFileSecurityW(
                    self.path.as_ptr(),
                    DACL_SECURITY_INFORMATION,
                    self.descriptor,
                ))?;
            }
            self.restored = true;
        }
        Ok(())
    }
}
impl Drop for AccessGrant {
    fn drop(&mut self) {
        let _ = self.restore();
        if !self.descriptor.is_null() {
            unsafe {
                LocalFree(self.descriptor);
            }
        }
    }
}
fn check_grant_tree(path: &Path) -> Result<()> {
    let mut pending = vec![path.to_owned()];
    let mut count = 0usize;
    while let Some(path) = pending.pop() {
        count += 1;
        ensure!(count <= 100_000, "Grant tree exceeds 100,000 entries");
        let info = std::fs::symlink_metadata(&path)?;
        ensure!(
            info.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "Reparse point prevents a bounded grant"
        );
        if info.is_dir() {
            for item in std::fs::read_dir(&path)? {
                ensure!(
                    count + pending.len() < 100_000,
                    "Grant tree exceeds 100,000 entries"
                );
                pending.push(item?.path());
            }
        } else {
            let file = open_read(&path)?;
            ensure!(
                file_info(&file)?.nNumberOfLinks == 1,
                "Grant target has multiple hardlinks"
            );
        }
    }
    Ok(())
}

/// Windows command-line quoting, including embedded quotes/trailing slashes.
fn command_line(args: &[std::ffi::OsString]) -> Result<Vec<u16>> {
    let mut command = Vec::new();
    for (index, arg) in args.iter().enumerate() {
        if index > 0 {
            command.push(32);
        }
        let value = wide(arg)?;
        command.push(34);
        let mut slashes = 0;
        for &unit in &value[..value.len() - 1] {
            if unit == 92 {
                slashes += 1;
                continue;
            }
            command.extend(std::iter::repeat_n(
                92,
                slashes * if unit == 34 { 2 } else { 1 },
            ));
            if unit == 34 {
                command.push(92);
            }
            command.push(unit);
            slashes = 0;
        }
        command.extend(std::iter::repeat_n(92, slashes * 2));
        command.push(34);
    }
    command.push(0);
    Ok(command)
}

struct Attributes {
    storage: Vec<usize>,
    initialized: bool,
}
impl Attributes {
    fn new(count: u32) -> Result<Self> {
        let mut bytes = 0;
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), count, 0, &mut bytes);
        }
        ensure!(
            bytes > 0 && bytes <= 65536,
            "Invalid process-attribute allocation size"
        );
        let mut list = Self {
            storage: vec![0; bytes.div_ceil(size_of::<usize>())],
            initialized: false,
        };
        unsafe {
            win(InitializeProcThreadAttributeList(
                list.pointer(),
                count,
                0,
                &mut bytes,
            ))?;
        }
        list.initialized = true;
        Ok(list)
    }
    fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
    fn set<T>(&mut self, key: u32, value: &T) -> Result<()> {
        unsafe {
            win(UpdateProcThreadAttribute(
                self.pointer(),
                0,
                key as usize,
                (value as *const T).cast(),
                size_of::<T>(),
                null_mut(),
                null(),
            ))
            .with_context(|| format!("UpdateProcThreadAttribute0x{key:x}"))
        }
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                DeleteProcThreadAttributeList(self.pointer());
            }
        }
    }
}

impl OfflineProfile {
    pub fn launch(
        &self,
        executable: &Path,
        args: &[std::ffi::OsString],
        cwd: &Path,
        timeout_ms: u32,
        job: &WorkerJob,
        output_limits: OutputLimits,
    ) -> Result<WorkerExit> {
        ensure!(
            (1..=7_200_000).contains(&timeout_ms),
            "Invalid worker timeout"
        );
        output_limits.validate()?;
        inspect_output(cwd, &[], output_limits).context("Output preflight failed")?;
        self.spawn(executable, args, cwd, job)?
            .wait(cwd, timeout_ms, output_limits)
    }
    pub fn spawn(
        &self,
        executable: &Path,
        args: &[std::ffi::OsString],
        cwd: &Path,
        job: &WorkerJob,
    ) -> Result<ContainedChild> {
        let exe = wide(executable.as_os_str())?;
        let directory = wide(cwd.as_os_str())?;
        let mut argv = vec![executable.as_os_str().to_owned()];
        argv.extend_from_slice(args);
        let mut command = command_line(&argv)?;
        let security = SECURITY_CAPABILITIES {
            AppContainerSid: self.sid,
            Capabilities: null_mut(),
            CapabilityCount: 0,
            Reserved: 0,
        };
        let mut attributes = Attributes::new(2)?;
        attributes.set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &security)?;
        // Assignment is atomic with creation, including suspended startup.
        attributes.set(PROC_THREAD_ATTRIBUTE_JOB_LIST, &job.handle.0)?;
        let mut environment = std::collections::BTreeMap::new();
        for key in [
            "SystemRoot",
            "WINDIR",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "SystemDrive",
            "ProgramData",
            "ProgramFiles",
            "USERNAME",
            "USERDOMAIN",
        ] {
            if let Some(value) = std::env::var_os(key) {
                environment.insert(key.to_ascii_uppercase(), value);
            }
        }
        ensure!(environment.contains_key("SYSTEMROOT"), "SystemRoot missing");
        environment.insert("TEMP".to_owned(), cwd.as_os_str().to_owned());
        environment.insert("TMP".to_owned(), cwd.as_os_str().to_owned());
        let mut search = executable
            .parent()
            .context("Executable has no bundle directory")?
            .as_os_str()
            .to_owned();
        search.push(";");
        search.push(Path::new(environment.get("SYSTEMROOT").unwrap()).join("System32"));
        environment.insert("PATH".to_owned(), search);
        let mut env = Vec::new();
        for (name, value) in environment {
            let mut entry = std::ffi::OsString::from(name);
            entry.push("=");
            entry.push(value);
            env.extend(wide(&entry)?);
        }
        env.push(0);
        let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attributes.pointer();
        let mut info: PROCESS_INFORMATION = unsafe { zeroed() };
        unsafe {
            win(CreateProcessW(
                exe.as_ptr(),
                command.as_mut_ptr(),
                null(),
                null(),
                0,
                EXTENDED_STARTUPINFO_PRESENT
                    | CREATE_NO_WINDOW
                    | CREATE_UNICODE_ENVIRONMENT
                    | CREATE_SUSPENDED,
                env.as_ptr().cast(),
                directory.as_ptr(),
                &startup.StartupInfo,
                &mut info,
            ))
            .context("CreateProcessW for offline AppContainer")?;
        }
        let child = ContainedChild {
            process: Handle(info.hProcess),
            started: std::time::Instant::now(),
        };
        let _thread = Handle(info.hThread);
        let mut assigned = 0;
        unsafe {
            win(IsProcessInJob(child.process.0, job.handle.0, &mut assigned))?;
        }
        ensure!(
            assigned != 0,
            "New contained process is not in its requested job"
        );
        ensure!(
            unsafe { ResumeThread(info.hThread) } != u32::MAX,
            "Cannot resume worker"
        );
        Ok(child)
    }
}

/// Owns a single contained process. Dropping it confirms exit before callers
/// restore ACLs; the independently held kill-on-close job is a second guard.
pub struct ContainedChild {
    process: Handle,
    started: std::time::Instant,
}
impl ContainedChild {
    pub fn id(&self) -> u32 {
        unsafe { GetProcessId(self.process.0) }
    }
    pub fn poll(&self) -> Result<Option<u32>> {
        let status = unsafe { WaitForSingleObject(self.process.0, 0) };
        if status == WAIT_TIMEOUT {
            return Ok(None);
        }
        ensure!(
            status == WAIT_OBJECT_0,
            "Contained process wait failed:0x{status:x}"
        );
        let mut exit = 0;
        unsafe {
            win(GetExitCodeProcess(self.process.0, &mut exit))?;
        }
        Ok(Some(exit))
    }
    pub fn terminate(&self) -> Result<u32> {
        if let Some(exit) = self.poll()? {
            return Ok(exit);
        }
        let terminated = unsafe { TerminateProcess(self.process.0, 1) };
        let error = std::io::Error::last_os_error();
        ensure!(
            unsafe { WaitForSingleObject(self.process.0, 5000) } == WAIT_OBJECT_0,
            "Contained process termination unconfirmed (TerminateProcess={terminated}): {error}"
        );
        self.poll()?
            .context("Contained process still active after termination")
    }
    pub fn wait(
        &self,
        output_root: &Path,
        timeout_ms: u32,
        limits: OutputLimits,
    ) -> Result<WorkerExit> {
        ensure!(
            (1..=7_200_000).contains(&timeout_ms),
            "Invalid worker timeout"
        );
        limits.validate()?;
        let timeout = std::time::Duration::from_millis(timeout_ms as u64);
        let mut checks = 0;
        loop {
            let remaining = timeout.saturating_sub(self.started.elapsed());
            let wait = unsafe {
                WaitForSingleObject(self.process.0, remaining.as_millis().min(250) as u32)
            };
            ensure!(
                wait == WAIT_OBJECT_0 || wait == WAIT_TIMEOUT,
                "Worker wait failed:0x{wait:x}"
            );
            checks += 1;
            let (reason, detail, usage) = match inspect_output(output_root, &[], limits) {
                Ok(usage) if wait == WAIT_OBJECT_0 => (WorkerStop::Exited, None, Some(usage)),
                Ok(usage) if self.started.elapsed() >= timeout => (
                    WorkerStop::Timeout,
                    Some("Worker exceeded wall-clock timeout".to_owned()),
                    Some(usage),
                ),
                Ok(_) => continue,
                Err(error) => {
                    let (reason, usage) =
                        if let Some(limit) = error.downcast_ref::<OutputLimitExceeded>() {
                            (WorkerStop::OutputLimit, Some(limit.usage))
                        } else {
                            (WorkerStop::OutputInspectionFailed, None)
                        };
                    (reason, Some(format!("{error:#}")), usage)
                }
            };
            let exit = if reason == WorkerStop::Exited {
                self.poll()?.context("Exited worker is still active")?
            } else {
                self.terminate()?
            };
            return Ok(WorkerExit {
                exit_code: exit,
                reason,
                detail,
                output_usage: usage,
                output_checks: checks,
                elapsed_ms: self.started.elapsed().as_millis(),
            });
        }
    }
}
impl Drop for ContainedChild {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_append_handles_preserve_prefix_and_prevent_path_replacement() {
        use std::io::{Seek, SeekFrom, Write};
        let root = std::env::temp_dir().join(format!(
            "emumee-pinned-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("stream.bin");
        let mut parent = create_pinned(&path).unwrap();
        parent.write_all(b"prefix").unwrap();
        let mut append = open_pinned(&path, &root, true).unwrap();
        append.seek(SeekFrom::Start(0)).unwrap();
        append.write_all(b"tail").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"prefixtail");
        assert!(std::fs::remove_file(&path).is_err());
        assert!(std::fs::rename(&path, root.join("replacement.bin")).is_err());
        drop(append);
        drop(parent);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
    #[test]
    fn host_process_is_not_accepted_as_a_contained_worker() {
        assert!(verify_containment().is_err());
        assert!(prepare_worker().is_err());
    }
    #[test]
    fn bounded_reads_reject_hardlinks_and_oversized_files() {
        let dir = std::env::temp_dir().join(format!(
            "emumee-rust-safeio-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("input.txt");
        let link = dir.join("linked.txt");
        std::fs::write(&file, b"harmless fixture").unwrap();
        assert_eq!(read_regular(&file, 64, None).unwrap(), b"harmless fixture");
        assert!(read_regular(&file, 3, None).is_err());
        std::fs::hard_link(&file, &link).unwrap();
        assert!(read_regular(&file, 64, None).is_err());
        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(file).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}

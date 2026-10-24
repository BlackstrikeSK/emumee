//! Private write-ahead cleanup plans. A complete flushed intent precedes each
//! profile/job/grant side effect. Recovery never consumes guest output as plans.
use super::*;
use serde::{Deserialize, Serialize};
use std::io::{Seek, SeekFrom, Write};
use windows_sys::Win32::System::SystemServices::{JOB_OBJECT_QUERY, JOB_OBJECT_TERMINATE};
const MAX_PLAN: usize = 1024 * 1024;
const MAX_RECORD: usize = 128 * 1024;
const MAX_RECORDS: usize = 128;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Record {
    Start {
        schema: u32,
        bundle: String,
        output: String,
    },
    Profile {
        name: String,
    },
    Job {
        name: String,
    },
    Dacl {
        path: String,
        volume: u32,
        high: u32,
        low: u32,
        sddl: String,
    },
    Done,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct RecoveryReport {
    pub recovered: bool,
    pub already_complete: bool,
    pub profiles: usize,
    pub jobs: usize,
    pub grants: usize,
    pub partial_tail: bool,
}
pub struct RecoverySession {
    path: PathBuf,
    file: Option<File>,
    _directory: File,
    bundle: PathBuf,
    output: PathBuf,
    bytes: usize,
    records: usize,
    failed: bool,
}
struct LocalBlock(*mut std::ffi::c_void);
impl Drop for LocalBlock {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}
fn copy_wide(pointer: *const u16, bound: usize) -> Result<String> {
    ensure!(!pointer.is_null(), "Missing SDK security string");
    let mut size = 0;
    while size < bound && unsafe { *pointer.add(size) } != 0 {
        size += 1;
    }
    ensure!(size < bound, "SDK security string exceeds bound");
    Ok(String::from_utf16(unsafe {
        std::slice::from_raw_parts(pointer, size)
    })?)
}
fn user_sid() -> Result<String> {
    let mut token = null_mut();
    unsafe {
        win(OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut token,
        ))?;
    }
    let token = Handle(token);
    let mut storage = vec![0usize; 128];
    let mut needed = 0;
    unsafe {
        win(GetTokenInformation(
            token.0,
            TokenUser,
            storage.as_mut_ptr().cast(),
            (storage.len() * size_of::<usize>()) as u32,
            &mut needed,
        ))?;
    }
    ensure!(
        (needed as usize) <= storage.len() * size_of::<usize>(),
        "Token user buffer exceeds bound"
    );
    let user = unsafe { &*storage.as_ptr().cast::<TOKEN_USER>() };
    let mut text = null_mut();
    unsafe {
        win(ConvertSidToStringSidW(user.User.Sid, &mut text))?;
    }
    let _text = LocalBlock(text.cast());
    copy_wide(text, 256)
}
fn descriptor(sddl: &str) -> Result<LocalBlock> {
    ensure!(
        sddl.len() <= 65536 && !sddl.contains('\0'),
        "Recovery DACL string exceeds bound"
    );
    let text = wide(std::ffi::OsStr::new(sddl))?;
    let mut sd = null_mut();
    unsafe {
        win(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut sd,
            null_mut(),
        ))?;
    }
    Ok(LocalBlock(sd))
}
fn apply_dacl(path: &Path, sddl: &str) -> Result<()> {
    let sd = descriptor(sddl)?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut acl = null_mut();
    let mut control = 0;
    let mut revision = 0;
    unsafe {
        win(GetSecurityDescriptorDacl(
            sd.0,
            &mut present,
            &mut acl,
            &mut defaulted,
        ))?;
        win(GetSecurityDescriptorControl(
            sd.0,
            &mut control,
            &mut revision,
        ))?;
    }
    ensure!(present != 0, "Recovery descriptor has no DACL");
    let flags = DACL_SECURITY_INFORMATION
        | if control & SE_DACL_PROTECTED != 0 {
            PROTECTED_DACL_SECURITY_INFORMATION
        } else {
            UNPROTECTED_DACL_SECURITY_INFORMATION
        };
    let path = wide(path.as_os_str())?;
    let status = unsafe {
        SetNamedSecurityInfoW(
            path.as_ptr(),
            SE_FILE_OBJECT,
            flags,
            null_mut(),
            null_mut(),
            acl,
            null(),
        )
    };
    ensure!(
        status == 0,
        "Cannot restore protected recovery DACL: Win32{status}"
    );
    // Preserve the recorded root control flags after propagating ACE removal.
    unsafe {
        win(SetFileSecurityW(
            path.as_ptr(),
            DACL_SECURITY_INFORMATION,
            sd.0,
        ))?;
    }
    Ok(())
}
fn attributes(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    ensure!(
        file_info(&file)?.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "Recovery target is a reparse point"
    );
    Ok(file)
}
fn private_path(bundle: &Path) -> Result<(PathBuf, File)> {
    let base = std::env::var_os("USERPROFILE").context("USERPROFILE is missing")?;
    let directory = PathBuf::from(base).join(".emumee-rust-recovery");
    match std::fs::create_dir(&directory) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
        Err(error) => return Err(error.into()),
    }
    // Use a stable user-profile location across packaged and standalone
    // launchers. Pin canonical object identity as well as rejecting a final
    // reparse point.
    let logical = attributes(&directory)?;
    let directory = std::fs::canonicalize(&directory)?;
    let guard = attributes(&directory)?;
    let before = file_info(&logical)?;
    let after = file_info(&guard)?;
    ensure!(
        before.dwVolumeSerialNumber == after.dwVolumeSerialNumber
            && before.nFileIndexHigh == after.nFileIndexHigh
            && before.nFileIndexLow == after.nFileIndexLow,
        "Private recovery directory identity changed"
    );
    ensure!(
        file_info(&guard)?.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
        "Private recovery root is not a directory"
    );
    apply_dacl(
        &directory,
        &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{})", user_sid()?),
    )?;
    let key = format!("{:x}", Sha256::digest(normalized(bundle).as_bytes()));
    Ok((directory.join(format!("{key}.jsonl")), guard))
}
fn contained(path: &Path, bundle: &Path, output: &Path) -> bool {
    let path = normalized(path);
    let under = |root: &Path| {
        let root = normalized(root);
        path == root || path.starts_with(&(root + "\\"))
    };
    under(bundle) || under(output)
}
fn text_path(path: &Path) -> Result<String> {
    Ok(path
        .to_str()
        .context("Recovery path requires valid Unicode")?
        .to_owned())
}
fn validate_name(name: &str, prefix: &str, max: usize) -> Result<()> {
    let rest = name
        .strip_prefix(prefix)
        .context("Invalid recorded recovery object prefix")?;
    ensure!(
        !rest.is_empty()
            && name.len() <= max
            && rest
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')),
        "Invalid recorded recovery object name"
    );
    Ok(())
}
fn stop_job(name: &str) -> Result<()> {
    validate_name(name, "Local\\Emumee.Rust.Job.", 160)?;
    let name = wide(std::ffi::OsStr::new(name))?;
    let raw = unsafe { OpenJobObjectW(JOB_OBJECT_QUERY | JOB_OBJECT_TERMINATE, 0, name.as_ptr()) };
    if raw.is_null() {
        let error = std::io::Error::last_os_error();
        ensure!(
            error.raw_os_error() == Some(2),
            "Cannot open recorded job: {error}"
        );
        return Ok(());
    }
    let job = Handle(raw);
    unsafe {
        win(TerminateJobObject(job.0, 1))?;
    }
    let started = std::time::Instant::now();
    loop {
        let mut accounting: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { zeroed() };
        unsafe {
            win(QueryInformationJobObject(
                job.0,
                JobObjectBasicAccountingInformation,
                (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                null_mut(),
            ))?;
        }
        if accounting.ActiveProcesses == 0 {
            return Ok(());
        }
        ensure!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "Recorded contained job has not terminated"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
impl RecoverySession {
    /// Metadata only. Contained roles receive this exact physical path for
    /// read-denial qualification, never a plan handle or plan contents.
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Caller holds the bundle lock, including an abandoned lock after crash.
    pub fn recover(bundle: &Path) -> Result<RecoveryReport> {
        let bundle = std::fs::canonicalize(bundle)?;
        let (path, _directory) = private_path(&bundle)?;
        if !path.exists() {
            return Ok(RecoveryReport::default());
        }
        let file = open_pinned(&path, path.parent().unwrap(), false)?;
        let mut raw = Vec::new();
        (&file).take(MAX_PLAN as u64 + 1).read_to_end(&mut raw)?;
        ensure!(raw.len() <= MAX_PLAN, "Cleanup plan exceeds bound");
        let mut records = Vec::new();
        let mut partial = false;
        for line in raw.split_inclusive(|b| *b == b'\n') {
            if !line.ends_with(b"\n") {
                partial = true;
                break;
            }
            ensure!(
                line.len() <= MAX_RECORD && records.len() < MAX_RECORDS,
                "Cleanup plan record bound exceeded"
            );
            records.push(
                serde_json::from_slice::<Record>(line)
                    .context("Malformed complete cleanup plan record")?,
            );
        }
        let mut report = RecoveryReport {
            recovered: true,
            partial_tail: partial,
            ..RecoveryReport::default()
        };
        if records.is_empty() {
            drop(file);
            std::fs::remove_file(path)?;
            return Ok(report);
        }
        let Record::Start {
            schema,
            bundle: recorded,
            output,
        } = &records[0]
        else {
            bail!("Cleanup plan has no initial header");
        };
        ensure!(
            *schema == 1 && normalized(Path::new(recorded)) == normalized(&bundle),
            "Cleanup plan belongs to another bundle/schema"
        );
        let recorded_output = output;
        let output = std::path::absolute(recorded_output)?;
        ensure!(
            Path::new(recorded_output).is_absolute()
                && normalized(Path::new(recorded_output)) == normalized(&output),
            "Cleanup output path is not absolute"
        );
        for (index, record) in records.iter().enumerate().skip(1) {
            match record {
                Record::Start { .. } => bail!("Duplicate cleanup header"),
                Record::Done => ensure!(
                    index == records.len() - 1 && !partial,
                    "Cleanup completion has unexpected following data"
                ),
                Record::Dacl { path, sddl, .. } => {
                    ensure!(
                        Path::new(path).is_absolute()
                            && !Path::new(path).components().any(|part| matches!(
                                part,
                                std::path::Component::ParentDir | std::path::Component::CurDir
                            )),
                        "Cleanup target is not an absolute normalized path"
                    );
                    ensure!(
                        contained(Path::new(path), &bundle, &output),
                        "Cleanup DACL target is outside recorded roots"
                    );
                    descriptor(sddl)?;
                }
                Record::Profile { name } => validate_name(name, "Emumee.Rust.Worker.", 64)?,
                Record::Job { name } => validate_name(name, "Local\\Emumee.Rust.Job.", 160)?,
            }
        }
        if matches!(records.last(), Some(Record::Done)) {
            report.already_complete = true;
        } else {
            for record in &records {
                if let Record::Job { name } = record {
                    stop_job(name)?;
                    report.jobs += 1;
                }
            }
            for record in records.iter().rev() {
                if let Record::Dacl {
                    path,
                    volume,
                    high,
                    low,
                    sddl,
                } = record
                {
                    let path = Path::new(path);
                    check_grant_tree(path)?;
                    let guard = attributes(path)?;
                    let info = file_info(&guard)?;
                    ensure!(
                        info.dwVolumeSerialNumber == *volume
                            && info.nFileIndexHigh == *high
                            && info.nFileIndexLow == *low,
                        "Cleanup target identity changed: {}",
                        path.display()
                    );
                    apply_dacl(path, sddl)?;
                    report.grants += 1;
                }
            }
            for record in records.iter().rev() {
                if let Record::Profile { name } = record {
                    let name = wide(std::ffi::OsStr::new(name))?;
                    let status = unsafe { DeleteAppContainerProfile(name.as_ptr()) };
                    ensure!(
                        status >= 0,
                        "Cannot delete recovered profile:0x{:08x}",
                        status as u32
                    );
                    report.profiles += 1;
                }
            }
        }
        drop(file);
        std::fs::remove_file(path)?;
        Ok(report)
    }
    pub fn begin(bundle: &Path, output: &Path) -> Result<Self> {
        let bundle = std::fs::canonicalize(bundle)?;
        let output = std::fs::canonicalize(output)?;
        let (path, directory) = private_path(&bundle)?;
        let file = create_pinned(&path)
            .context("A prior cleanup plan must be recovered before starting")?;
        let mut session = Self {
            path,
            file: Some(file),
            _directory: directory,
            bundle: bundle.clone(),
            output: output.clone(),
            bytes: 0,
            records: 0,
            failed: false,
        };
        session.append(&Record::Start {
            schema: 1,
            bundle: text_path(&bundle)?,
            output: text_path(&output)?,
        })?;
        Ok(session)
    }
    fn append(&mut self, record: &Record) -> Result<()> {
        ensure!(
            !self.failed,
            "A cleanup plan write previously failed; preserve it for recovery"
        );
        let mut raw = serde_json::to_vec(record)?;
        raw.push(b'\n');
        ensure!(
            raw.len() <= MAX_RECORD
                && self.records < MAX_RECORDS
                && self.bytes + raw.len() <= MAX_PLAN,
            "Cleanup plan bound exceeded"
        );
        let file = self.file.as_mut().context("Cleanup plan is closed")?;
        self.failed = true;
        file.seek(SeekFrom::End(0))?;
        file.write_all(&raw)?;
        file.sync_all()?;
        self.failed = false;
        self.bytes += raw.len();
        self.records += 1;
        Ok(())
    }
    pub(super) fn profile(&mut self, name: &str) -> Result<()> {
        validate_name(name, "Emumee.Rust.Worker.", 64)?;
        self.append(&Record::Profile {
            name: name.to_owned(),
        })
    }
    pub(super) fn job(&mut self, name: &str) -> Result<()> {
        validate_name(name, "Local\\Emumee.Rust.Job.", 160)?;
        self.append(&Record::Job {
            name: name.to_owned(),
        })
    }
    pub(super) fn dacl(&mut self, path: &Path, descriptor: PSECURITY_DESCRIPTOR) -> Result<()> {
        ensure!(
            contained(path, &self.bundle, &self.output),
            "Grant target outside tracked bundle/output"
        );
        let guard = attributes(path)?;
        let info = file_info(&guard)?;
        let mut text = null_mut();
        let mut size = 0;
        unsafe {
            win(ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                &mut size,
            ))?;
        }
        let _text = LocalBlock(text.cast());
        ensure!(size <= 65536, "Original DACL exceeds recovery bound");
        let sddl = copy_wide(text, size as usize)?;
        self.append(&Record::Dacl {
            path: text_path(path)?,
            volume: info.dwVolumeSerialNumber,
            high: info.nFileIndexHigh,
            low: info.nFileIndexLow,
            sddl,
        })
    }
    pub fn finish(&mut self) -> Result<()> {
        self.append(&Record::Done)?;
        drop(self.file.take());
        std::fs::remove_file(&self.path)?;
        Ok(())
    }
    /// Fixed controller-crash qualification fault; no action follows this
    /// incomplete intent and finish refuses to append anything afterwards.
    pub fn torn_intent_for_fixture(&mut self) -> Result<()> {
        self.failed = true;
        let file = self.file.as_mut().context("Cleanup plan is closed")?;
        file.write_all(b"{\"op\":\"profile\",\"name\":\"unfinished")?;
        file.sync_all()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    struct Fixture {
        root: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "emumee-recovery-{}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&root).unwrap();
            Self {
                root: std::fs::canonicalize(root).unwrap(),
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = RecoverySession::recover(&self.root);
            for name in ["file", "moved", "outside-marker"] {
                let _ = std::fs::remove_file(self.root.join(name));
            }
            std::fs::remove_dir(&self.root).unwrap();
        }
    }
    fn original(path: &Path) -> (LocalBlock, String) {
        let text = wide(path.as_os_str()).unwrap();
        let mut sd = null_mut();
        let mut acl = null_mut();
        let result = unsafe {
            GetNamedSecurityInfoW(
                text.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut acl,
                null_mut(),
                &mut sd,
            )
        };
        assert_eq!(result, 0);
        let guard = LocalBlock(sd);
        let mut text = null_mut();
        let mut size = 0;
        unsafe {
            win(ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                &mut size,
            ))
            .unwrap();
        }
        let _text = LocalBlock(text.cast());
        let sddl = copy_wide(text, size as usize).unwrap();
        (guard, sddl)
    }
    #[test]
    fn tracked_normal_cleanup_restores_dacl_and_removes_private_plan() {
        let fixture = Fixture::new();
        let before = original(&fixture.root).1;
        let mut plan = RecoverySession::begin(&fixture.root, &fixture.root).unwrap();
        let job = WorkerJob::new_tracked(64, &mut plan).unwrap();
        let mut profile = OfflineProfile::new_tracked(&mut plan).unwrap();
        let mut grant = profile
            .grant_tracked(&fixture.root, true, &mut plan)
            .unwrap();
        grant.restore().unwrap();
        profile.close().unwrap();
        drop(job);
        plan.finish().unwrap();
        assert!(!plan.path.exists());
        assert_eq!(original(&fixture.root).1, before);
        assert!(!RecoverySession::recover(&fixture.root).unwrap().recovered);
    }
    #[test]
    fn partial_intent_recovers_earlier_plans_and_missing_profiles_are_idempotent() {
        let fixture = Fixture::new();
        let mut plan = RecoverySession::begin(&fixture.root, &fixture.root).unwrap();
        let suffix = format!(
            "{}.{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        plan.profile(&format!("Emumee.Rust.Worker.Test.{suffix}"))
            .unwrap();
        plan.job(&format!("Local\\Emumee.Rust.Job.Test.{suffix}"))
            .unwrap();
        plan.torn_intent_for_fixture().unwrap();
        drop(plan);
        let report = RecoverySession::recover(&fixture.root).unwrap();
        assert!(report.recovered && report.partial_tail);
        assert_eq!((report.profiles, report.jobs, report.grants), (1, 1, 0));
        assert!(!RecoverySession::recover(&fixture.root).unwrap().recovered);
    }
    #[test]
    fn changed_file_identity_is_rejected_before_applying_an_old_dacl() {
        let fixture = Fixture::new();
        let path = fixture.root.join("file");
        std::fs::write(&path, b"original").unwrap();
        let (sd, _) = original(&path);
        let mut plan = RecoverySession::begin(&fixture.root, &fixture.root).unwrap();
        plan.dacl(&path, sd.0).unwrap();
        drop(plan);
        std::fs::rename(&path, fixture.root.join("moved")).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        assert!(
            RecoverySession::recover(&fixture.root)
                .unwrap_err()
                .to_string()
                .contains("identity changed")
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
        std::fs::remove_file(&path).unwrap();
        std::fs::rename(fixture.root.join("moved"), &path).unwrap();
        assert_eq!(RecoverySession::recover(&fixture.root).unwrap().grants, 1);
        assert_eq!(std::fs::read(path).unwrap(), b"original");
    }
    #[test]
    fn a_failed_plan_write_never_gets_a_following_completion_record() {
        let fixture = Fixture::new();
        let mut plan = RecoverySession::begin(&fixture.root, &fixture.root).unwrap();
        let path = plan.path.clone();
        drop(plan.file.take());
        plan.file = Some(File::open(&path).unwrap());
        let size = std::fs::metadata(&path).unwrap().len();
        assert!(plan.profile("Emumee.Rust.Worker.NeverCreated").is_err());
        drop(plan.file.take());
        plan.file = Some(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap(),
        );
        assert!(
            plan.finish()
                .unwrap_err()
                .to_string()
                .contains("previously failed")
        );
        assert_eq!(std::fs::metadata(&path).unwrap().len(), size);
        drop(plan);
        let result = RecoverySession::recover(&fixture.root).unwrap();
        assert_eq!(result.profiles, 0);
    }
    #[test]
    fn completed_plan_can_be_removed_after_a_crash_without_replaying_actions() {
        let fixture = Fixture::new();
        let mut plan = RecoverySession::begin(&fixture.root, &fixture.root).unwrap();
        plan.append(&Record::Done).unwrap();
        drop(plan);
        let result = RecoverySession::recover(&fixture.root).unwrap();
        assert!(result.already_complete);
        assert_eq!((result.profiles, result.jobs, result.grants), (0, 0, 0));
    }
    #[test]
    fn outside_roots_and_invalid_names_are_rejected_before_recovery_actions() {
        let fixture = Fixture::new();
        let outside = Fixture::new();
        let marker = outside.root.join("outside-marker");
        std::fs::write(&marker, b"unchanged").unwrap();
        assert!(validate_name("Emumee.Rust.Worker.bad\\name", "Emumee.Rust.Worker.", 64).is_err());
        let mut plan = RecoverySession::begin(&fixture.root, &fixture.root).unwrap();
        let path = plan.path.clone();
        plan.append(&Record::Dacl {
            path: text_path(&marker).unwrap(),
            volume: 0,
            high: 0,
            low: 0,
            sddl: "D:P(A;;FA;;;SY)".into(),
        })
        .unwrap();
        drop(plan);
        assert!(
            RecoverySession::recover(&fixture.root)
                .unwrap_err()
                .to_string()
                .contains("outside recorded roots")
        );
        assert_eq!(std::fs::read(marker).unwrap(), b"unchanged");
        std::fs::remove_file(path).unwrap();
    }
}

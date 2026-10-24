//! Bounded parent-side output inspection, including named NTFS data streams.
//! Polling is a watchdog, not a filesystem quota: writes can occur between scans.
use super::*;

#[derive(Clone, Copy, Debug, Serialize)]
pub struct OutputLimits {
    pub max_bytes: u64,
    pub max_entries: u64,
    pub max_directories: u64,
    pub max_depth: usize,
}
impl Default for OutputLimits {
    fn default() -> Self {
        Self {
            max_bytes: 140 * 1024 * 1024,
            max_entries: 10032,
            max_directories: 128,
            max_depth: 16,
        }
    }
}
impl OutputLimits {
    pub fn validate(self) -> Result<()> {
        ensure!(
            (1..=16 * 1024 * 1024 * 1024).contains(&self.max_bytes)
                && (1..=100032).contains(&self.max_entries)
                && (1..=1024).contains(&self.max_directories)
                && (1..=64).contains(&self.max_depth),
            "Invalid output watchdog limits"
        );
        Ok(())
    }
    fn check(self, usage: OutputUsage, depth: usize) -> Result<()> {
        let dimension = if usage.bytes > self.max_bytes {
            Some("bytes")
        } else if usage.files + usage.directories + usage.named_streams > self.max_entries {
            Some("entries")
        } else if usage.directories > self.max_directories {
            Some("directories")
        } else if depth > self.max_depth {
            Some("depth")
        } else {
            None
        };
        if let Some(dimension) = dimension {
            return Err(OutputLimitExceeded { dimension, usage }.into());
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct OutputUsage {
    pub bytes: u64,
    pub files: u64,
    pub directories: u64,
    pub named_streams: u64,
}
#[derive(Debug)]
pub struct OutputLimitExceeded {
    pub dimension: &'static str,
    pub usage: OutputUsage,
}
impl std::fmt::Display for OutputLimitExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Worker output exceeds {} limit: {:?}",
            self.dimension, self.usage
        )
    }
}
impl std::error::Error for OutputLimitExceeded {}

// A stream enumeration handle must use FindClose, never CloseHandle.
struct StreamSearch(HANDLE);
impl Drop for StreamSearch {
    fn drop(&mut self) {
        unsafe {
            FindClose(self.0);
        }
    }
}
fn add_streams(path: &Path, usage: &mut OutputUsage, limits: OutputLimits) -> Result<()> {
    let name = wide(path.as_os_str())?;
    let mut data: WIN32_FIND_STREAM_DATA = unsafe { zeroed() };
    let handle = unsafe {
        FindFirstStreamW(
            name.as_ptr(),
            FindStreamInfoStandard,
            (&mut data as *mut WIN32_FIND_STREAM_DATA).cast(),
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = std::io::Error::last_os_error();
        // Documented no-stream and unsupported-filesystem outcomes only.
        if matches!(error.raw_os_error(), Some(38 | 87)) {
            return Ok(());
        }
        return Err(error).context("Output stream enumeration failed");
    }
    let _search = StreamSearch(handle);
    loop {
        let end = data
            .cStreamName
            .iter()
            .position(|c| *c == 0)
            .context("Unterminated output stream name")?;
        let name = String::from_utf16(&data.cStreamName[..end])?;
        if !name.eq_ignore_ascii_case("::$DATA") {
            ensure!(data.StreamSize >= 0, "Negative output stream size");
            usage.bytes = usage
                .bytes
                .checked_add(data.StreamSize as u64)
                .context("Output stream byte count overflow")?;
            usage.named_streams += 1;
            limits.check(*usage, 0)?;
        }
        if unsafe { FindNextStreamW(handle, (&mut data as *mut WIN32_FIND_STREAM_DATA).cast()) }
            == 0
        {
            let error = std::io::Error::last_os_error();
            ensure!(
                error.raw_os_error() == Some(38),
                "Output stream enumeration interrupted: {error}"
            );
            return Ok(());
        }
    }
}

/// Holds a no-delete-share handle while enumerating this entry. Parent directory
/// handles stay open for the whole scan so rename/reparse replacement is refused.
fn inspect_entry(
    path: &Path,
    usage: &mut OutputUsage,
    limits: OutputLimits,
    depth: usize,
) -> Result<(File, bool)> {
    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .context("Could not open output entry for inspection")?;
    let info = file_info(&file)?;
    ensure!(
        info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "Output contains a reparse point"
    );
    let directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    if directory {
        usage.directories += 1;
    } else {
        ensure!(
            info.nNumberOfLinks == 1,
            "Output contains a multiply linked file"
        );
        usage.files += 1;
        usage.bytes = usage
            .bytes
            .checked_add(((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64)
            .context("Output byte count overflow")?;
    }
    limits.check(*usage, depth)?;
    add_streams(path, usage, limits)?;
    Ok((file, directory))
}

/// Includes optional private broker files. Callers must keep them outside root;
/// duplicates conservatively count twice. Missing/uninspectable data is an error.
pub fn inspect_output(
    root: &Path,
    extra_files: &[PathBuf],
    limits: OutputLimits,
) -> Result<OutputUsage> {
    limits.validate()?;
    ensure!(extra_files.len() <= 32, "Too many private output files");
    let root = std::path::absolute(root)?;
    let mut usage = OutputUsage::default();
    let (root_handle, directory) = inspect_entry(&root, &mut usage, limits, 0)?;
    ensure!(directory, "Output root is not a directory");
    let mut guards = vec![root_handle];
    let mut pending = vec![(root, 0usize)];
    while let Some((path, depth)) = pending.pop() {
        for entry in std::fs::read_dir(path).context("Could not enumerate output directory")? {
            let entry = entry?;
            let path = entry.path();
            let (handle, directory) = inspect_entry(&path, &mut usage, limits, depth + 1)?;
            if directory {
                pending.push((path, depth + 1));
                guards.push(handle);
            }
        }
    }
    for path in extra_files {
        let (_handle, directory) = inspect_entry(path, &mut usage, limits, 0)?;
        ensure!(!directory, "Private broker output must be a regular file");
    }
    Ok(usage)
}

#[cfg(test)]
mod tests {
    use super::*;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "emumee-watchdog-{}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&root).unwrap();
            Self(root)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[test]
    fn counts_named_streams_on_files_directories_and_private_journals() {
        let fixture = Fixture::new();
        let run = fixture.0.join("run");
        std::fs::create_dir(&run).unwrap();
        let carrier = run.join("carrier");
        let journal = fixture.0.join("private.journal");
        std::fs::write(&carrier, b"a").unwrap();
        std::fs::write(&journal, b"bc").unwrap();
        for (path, bytes) in [
            (&run, &b"123"[..]),
            (&carrier, &b"4567"[..]),
            (&journal, &b"89012"[..]),
        ] {
            let mut stream = path.as_os_str().to_owned();
            stream.push(":quota_probe");
            std::fs::write(PathBuf::from(stream), bytes).unwrap();
        }
        let usage = inspect_output(
            &run,
            std::slice::from_ref(&journal),
            OutputLimits::default(),
        )
        .unwrap();
        assert_eq!(
            (
                usage.bytes,
                usage.files,
                usage.directories,
                usage.named_streams
            ),
            (15, 2, 1, 3)
        );
        let limits = OutputLimits {
            max_bytes: 14,
            ..OutputLimits::default()
        };
        assert!(
            inspect_output(&run, &[journal], limits)
                .unwrap_err()
                .downcast_ref::<OutputLimitExceeded>()
                .is_some()
        );
    }
    #[test]
    fn bounds_empty_directories_depth_entries_and_stream_counts() {
        let fixture = Fixture::new();
        std::fs::create_dir_all(fixture.0.join("a/b")).unwrap();
        for limits in [
            OutputLimits {
                max_depth: 1,
                ..OutputLimits::default()
            },
            OutputLimits {
                max_directories: 2,
                ..OutputLimits::default()
            },
            OutputLimits {
                max_entries: 2,
                ..OutputLimits::default()
            },
        ] {
            assert!(
                inspect_output(&fixture.0, &[], limits)
                    .unwrap_err()
                    .downcast_ref::<OutputLimitExceeded>()
                    .is_some()
            );
        }
        let mut stream = fixture.0.as_os_str().to_owned();
        stream.push(":empty");
        std::fs::write(PathBuf::from(stream), b"").unwrap();
        let limits = OutputLimits {
            max_entries: 3,
            ..OutputLimits::default()
        };
        assert!(inspect_output(&fixture.0, &[], limits).is_err());
    }
    #[test]
    fn inspection_fails_for_missing_invalid_and_multiply_linked_output() {
        let fixture = Fixture::new();
        let file = fixture.0.join("file");
        std::fs::write(&file, b"safe").unwrap();
        assert!(inspect_output(&file, &[], OutputLimits::default()).is_err());
        assert!(
            inspect_output(
                &fixture.0,
                &[fixture.0.join("missing")],
                OutputLimits::default()
            )
            .is_err()
        );
        std::fs::hard_link(&file, fixture.0.join("link")).unwrap();
        assert!(
            inspect_output(&fixture.0, &[], OutputLimits::default())
                .unwrap_err()
                .to_string()
                .contains("multiply linked")
        );
    }
    #[test]
    fn invalid_watchdog_limits_fail_before_inspection() {
        for limits in [
            OutputLimits {
                max_bytes: 0,
                ..OutputLimits::default()
            },
            OutputLimits {
                max_entries: 0,
                ..OutputLimits::default()
            },
            OutputLimits {
                max_directories: 0,
                ..OutputLimits::default()
            },
            OutputLimits {
                max_depth: 0,
                ..OutputLimits::default()
            },
        ] {
            assert!(limits.validate().is_err());
        }
    }
}

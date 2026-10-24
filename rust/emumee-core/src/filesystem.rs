//! Bounded in-memory Windows files. Guest paths never designate host files.
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
#[path = "filesystem_metadata.rs"]
mod metadata;
#[path = "filesystem_seed.rs"]
mod seed;
pub use seed::SeedFile;
#[path = "filesystem_loader_snapshot.rs"]
mod loader_snapshot;
pub use loader_snapshot::LoaderFileSnapshot;
#[path = "filesystem_native.rs"]
mod native;
use native::FileDomain;
pub use native::{
    NATIVE_FILE_END, NATIVE_FILE_FIRST, NATIVE_FILE_HIGH, NATIVE_FILE_LIMIT,
    NATIVE_FILE_RESERVATIONS, NATIVE_MAX_TRANSFER, NativeFileClass, NativeFileError,
    NativeFileEvidence, NativeFileKind, NativeFileOpen, NativeFileOpened, NativeFileResult,
    NativeFilesReport, reserved_native_file_next,
};
#[path = "filesystem_mutation.rs"]
mod mutation;
pub use metadata::{
    DEFAULT_FILETIME, DirectoryPlan, Entry, EnumerationReport, FirstPlan, Metadata, PathPlan,
    SEARCH_END, SEARCH_FIRST, SearchReport, Searches, reserved_search,
};
pub use mutation::StorageReport;
const MAX_FILE: usize = 32 * 1024 * 1024;
const MAX_TOTAL: usize = 128 * 1024 * 1024;
const MAX_HANDLES: usize = 4096;
#[derive(Debug, Error)]
#[error("Guest file: {reason} (Win32 {win32})")]
pub struct FileError {
    pub win32: u32,
    pub reason: &'static str,
}
type Result<T> = std::result::Result<T, FileError>;
fn error(win32: u32, reason: &'static str) -> FileError {
    FileError { win32, reason }
}
#[derive(Clone, Copy, Debug)]
struct Access {
    read: bool,
    write: bool,
    append: bool,
    delete: bool,
}
impl Access {
    fn new(mask: u32) -> Self {
        Self {
            read: mask & 0x90000001 != 0,
            write: mask & 0x50000002 != 0,
            append: mask & 0x10000004 != 0,
            delete: mask & 0x10010000 != 0,
        }
    }
    fn shared_by(self, share: u32) -> bool {
        (!self.read || share & 1 != 0)
            && (!(self.write || self.append) || share & 2 != 0)
            && (!self.delete || share & 4 != 0)
    }
}
#[derive(Clone, Debug)]
struct OpenFile {
    path: String,
    unlinked: Option<u64>,
    position: u64,
    access: Access,
    share: u32,
    owner: u64,
    domain: FileDomain,
    kind: NativeFileKind,
    native_access: u32,
    native_requested_access: u32,
    native_options: u32,
}
#[derive(Clone, Debug)]
pub struct VirtualFileSystem {
    current_directory: String,
    metadata: metadata::MetadataState,
    mutations: mutation::MutationState,
    directories: BTreeSet<String>,
    files: BTreeMap<String, Vec<u8>>,
    handles: BTreeMap<u64, OpenFile>,
    next_handle: u64,
    native_file_issues: u64,
    total: usize,
}
impl Default for VirtualFileSystem {
    fn default() -> Self {
        Self::new()
    }
}
impl VirtualFileSystem {
    /// Exact live ownership in the sole file/directory table, without accepting aliases or retired identities.
    pub fn owns_handle(&self, handle: u64) -> bool {
        self.handles.contains_key(&handle)
    }
    pub fn new() -> Self {
        Self {
            current_directory: "C:\\workspace".into(),
            metadata: metadata::MetadataState::default(),
            mutations: mutation::MutationState::default(),
            directories: BTreeSet::from(["c:\\".into(), "c:\\workspace".into()]),
            files: BTreeMap::new(),
            handles: BTreeMap::new(),
            next_handle: 0x100,
            native_file_issues: 0,
            total: 0,
        }
    }
    pub fn path(&self, path: &str) -> Result<String> {
        self.normalize_path(path, true, false)
    }
    fn normalize_path(&self, path: &str, lowercase: bool, wildcards: bool) -> Result<String> {
        if path.is_empty() || path.len() > 32768 || path.chars().any(|c| c == '\0' || c < ' ') {
            return Err(error(123, "invalid path"));
        }
        let path = path.replace('/', "\\");
        let path = if let Some(extended) = path.strip_prefix("\\\\?\\") {
            if extended.as_bytes().get(1) != Some(&b':') || !extended[2..].starts_with('\\') {
                return Err(error(50, "extended device/UNC paths are not modeled"));
            }
            extended
        } else {
            &path
        };
        if path.starts_with("\\\\") || path.starts_with("\\??\\") {
            return Err(error(50, "UNC/device paths are not modeled"));
        }
        let absolute = if path.as_bytes().get(1) == Some(&b':') {
            if !path.as_bytes()[0].is_ascii_alphabetic() || !path[2..].starts_with('\\') {
                return Err(error(50, "drive-relative paths are not modeled"));
            }
            path.to_owned()
        } else if path.starts_with('\\') {
            format!("{}{}", &self.current_directory[..2], path)
        } else {
            format!("{}\\{}", self.current_directory, path)
        };
        if absolute.len() > 32768 {
            return Err(error(206, "expanded guest path exceeds modeled bound"));
        }
        let mut components = Vec::new();
        for part in absolute[3..].split('\\') {
            match part {
                "" | "." => {}
                ".." => {
                    components.pop();
                }
                part => {
                    if part.contains([':', '"', '<', '>', '|'])
                        || (!wildcards && part.contains(['*', '?']))
                    {
                        return Err(error(123, "invalid file component"));
                    }
                    let part = part.trim_end_matches([' ', '.']);
                    if part.is_empty() {
                        return Err(error(123, "empty file component"));
                    }
                    let stem = part.split('.').next().unwrap().to_ascii_uppercase();
                    if ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"].contains(&stem.as_str())
                        || (stem.len() == 4
                            && (stem.starts_with("COM") || stem.starts_with("LPT"))
                            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
                    {
                        return Err(error(50, "DOS device names are not modeled"));
                    }
                    components.push(if lowercase {
                        part.to_lowercase()
                    } else {
                        part.to_owned()
                    });
                }
            }
        }
        Ok(format!(
            "{}\\{}",
            if lowercase {
                absolute[..2].to_ascii_lowercase()
            } else {
                absolute[..2].to_owned()
            },
            components.join("\\")
        ))
    }
    /// Guest-only existence query. Unsupported namespaces remain explicit.
    pub fn exists(&self, path: &str) -> Result<bool> {
        match self.path(path) {
            Ok(path) => Ok(self.files.contains_key(&path)),
            Err(failure) if failure.win32 != 50 => Ok(false),
            Err(failure) => Err(failure),
        }
    }
    pub fn open(
        &mut self,
        path: &str,
        desired_access: u32,
        share: u32,
        disposition: u32,
        owner: u64,
    ) -> Result<(u64, u32)> {
        if share & !7 != 0 || !(1..=5).contains(&disposition) {
            return Err(error(87, "invalid sharing/disposition"));
        }
        if self.handles.len() >= MAX_HANDLES {
            return Err(error(4, "file/handle limit"));
        }
        let display = self.normalize_path(path, false, false)?;
        let path = self.path(path)?;
        if self.directories.contains(&path) {
            return Err(error(5, "file path names a directory"));
        }
        let parent = path
            .rsplit_once('\\')
            .map(|(parent, _)| {
                if parent.len() == 2 {
                    format!("{parent}\\")
                } else {
                    parent.to_owned()
                }
            })
            .ok_or_else(|| error(123, "invalid path"))?;
        if !self.directories.contains(&parent) {
            return Err(error(3, "parent directory does not exist"));
        }
        let exists = self.files.contains_key(&path);
        if !exists && self.files.len() >= 4096 {
            return Err(error(4, "file name limit"));
        }
        self.metadata
            .require_open(&path, desired_access, disposition)?;
        if exists && disposition == 1 {
            return Err(error(80, "file already exists"));
        }
        if !exists && [3, 5].contains(&disposition) {
            return Err(error(2, "file does not exist"));
        }
        let access = Access::new(desired_access);
        if [2, 5].contains(&disposition) && !access.write {
            return Err(error(5, "truncate requires write access"));
        }
        for handle in self
            .handles
            .values()
            .filter(|h| h.unlinked.is_none() && h.path == path)
        {
            if !handle.access.shared_by(share) || !access.shared_by(handle.share) {
                return Err(error(32, "sharing violation"));
            }
        }
        // Preflight namespace exhaustion before any insertion or truncation.
        let mut handle = self.next_handle;
        loop {
            let next = if reserved_search(handle) {
                Some(SEARCH_END)
            } else if crate::console::reserved_alias(handle) {
                Some(crate::console::ALIAS_END)
            } else if let Some(end) = reserved_native_file_next(handle) {
                Some(end)
            } else {
                crate::registry::reserved_file_handle_next(handle)
            };
            match next {
                Some(next) => handle = next,
                None => break,
            }
        }
        let next_handle = handle
            .checked_add(4)
            .ok_or_else(|| error(4, "handle namespace exhausted"))?;
        if !exists {
            self.metadata.require_display(&path, &display)?;
            self.metadata.record_display(path.clone(), display);
            self.files.insert(path.clone(), Vec::new());
        }
        if [2, 5].contains(&disposition) {
            self.total -= self.files.get(&path).unwrap().len();
            self.files.get_mut(&path).unwrap().clear();
        }
        // Reserved console aliases must never be reissued as ordinary files,
        // including retired aliases after many open/close cycles.
        self.next_handle = next_handle;
        self.handles.insert(
            handle,
            OpenFile {
                path,
                unlinked: None,
                position: 0,
                access,
                share,
                owner,
                domain: FileDomain::User,
                kind: NativeFileKind::File,
                native_access: 0,
                native_requested_access: 0,
                native_options: 0,
            },
        );
        Ok((
            handle,
            if exists && [2, 4].contains(&disposition) {
                183
            } else {
                0
            },
        ))
    }
    fn handle(&self, handle: u64, owner: u64) -> Result<&OpenFile> {
        self.handles
            .get(&handle)
            .filter(|h| h.owner == owner && h.domain == FileDomain::User)
            .ok_or_else(|| error(6, "invalid or foreign file handle"))
    }
    pub fn close(&mut self, handle: u64, owner: u64) -> Result<()> {
        self.handle(handle, owner)?;
        self.close_owned(handle);
        Ok(())
    }
    fn close_owned(&mut self, handle: u64) {
        let unlinked = self.handles[&handle].unlinked;
        self.handles.remove(&handle);
        if let Some(id) = unlinked {
            if !self.handles.values().any(|h| h.unlinked == Some(id)) {
                self.total -= self.mutations.unlinked.remove(&id).unwrap().len();
                self.mutations.unlinked_seeded.remove(&id);
            }
        }
    }
    pub fn size(&self, handle: u64, owner: u64) -> Result<u64> {
        let h = self.handle(handle, owner)?;
        Ok(self.file_bytes(h).len() as u64)
    }
    pub fn seek(&mut self, handle: u64, owner: u64, offset: i64, method: u32) -> Result<u64> {
        let h = self.handle(handle, owner)?;
        let base = match method {
            0 => 0,
            1 => h.position,
            2 => self.file_bytes(h).len() as u64,
            _ => return Err(error(87, "invalid seek method")),
        };
        let position = base
            .checked_add_signed(offset)
            .filter(|n| *n <= MAX_FILE as u64)
            .ok_or_else(|| error(131, "negative or excessive seek"))?;
        self.handles.get_mut(&handle).unwrap().position = position;
        Ok(position)
    }
    pub fn read(&mut self, handle: u64, owner: u64, count: usize) -> Result<Vec<u8>> {
        let h = self.handle(handle, owner)?;
        if !h.access.read {
            return Err(error(5, "file handle lacks read access"));
        }
        if count > MAX_FILE {
            return Err(error(8, "read exceeds modeled bound"));
        }
        let data = self.file_bytes(h);
        let start = (h.position as usize).min(data.len());
        let end = start.saturating_add(count).min(data.len());
        let result = data[start..end].to_vec();
        self.handles.get_mut(&handle).unwrap().position += result.len() as u64;
        Ok(result)
    }
    pub fn write(&mut self, handle: u64, owner: u64, data: &[u8]) -> Result<usize> {
        let h = self.handle(handle, owner)?;
        if !h.access.write && !h.access.append {
            return Err(error(5, "file handle lacks write access"));
        }
        if data.is_empty() {
            return Ok(0);
        }
        let file = self.file_bytes(h);
        let position = if h.access.append && !h.access.write {
            file.len()
        } else {
            h.position as usize
        };
        let end = position
            .checked_add(data.len())
            .filter(|n| *n <= MAX_FILE)
            .ok_or_else(|| error(223, "file exceeds modeled bound"))?;
        let growth = end.saturating_sub(file.len());
        if self.total.checked_add(growth).is_none_or(|n| n > MAX_TOTAL) {
            return Err(error(8, "guest filesystem capacity"));
        }
        let file = self.file_bytes_mut(handle);
        if end > file.len() {
            file.resize(end, 0);
        }
        file[position..end].copy_from_slice(data);
        self.total += growth;
        self.handles.get_mut(&handle).unwrap().position = end as u64;
        Ok(data.len())
    }
    pub fn contents(&self, path: &str) -> Result<Option<&[u8]>> {
        Ok(self.files.get(&self.path(path)?).map(Vec::as_slice))
    }
    pub fn into_files(self) -> impl Iterator<Item = (String, Vec<u8>)> {
        self.files.into_iter()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_handle_allocator_preflight_cannot_truncate_or_publish_names() {
        let mut fs = VirtualFileSystem::new();
        let (h, _) = fs.open("Keep.bin", 0xc0000000, 7, 2, 1024).unwrap();
        fs.write(h, 1024, b"KEEP").unwrap();
        fs.close(h, 1024).unwrap();
        fs.next_handle = u64::MAX - 2;
        assert_eq!(
            fs.open("keep.bin", 0xc0000000, 7, 2, 1024)
                .unwrap_err()
                .win32,
            4
        );
        assert_eq!(fs.contents("keep.bin").unwrap().unwrap(), b"KEEP");
        assert_eq!(
            fs.open("New.bin", 0xc0000000, 7, 2, 1024)
                .unwrap_err()
                .win32,
            4
        );
        assert!(!fs.exists("new.bin").unwrap());
        assert_eq!(fs.enumerate("keep.*").unwrap()[0].name, "Keep.bin");
        assert_eq!(fs.storage_report().accounted_bytes, 4);
    }
    #[test]
    fn file_handle_allocation_skips_live_and_retired_search_namespace() {
        let mut fs = VirtualFileSystem::new();
        fs.next_handle = SEARCH_FIRST;
        let (a, _) = fs
            .open("search-reserved.bin", 0xc0000000, 3, 2, 1024)
            .unwrap();
        assert_eq!(a, SEARCH_END);
        assert!(!reserved_search(a));
        assert!(!crate::console::reserved_alias(a));
    }
    #[test]
    fn file_handle_allocation_skips_live_and_retired_console_namespace() {
        let mut fs = VirtualFileSystem::new();
        fs.next_handle = crate::console::ALIAS_FIRST;
        let (a, _) = fs.open("reserved-a.bin", 0xc0000000, 3, 2, 1024).unwrap();
        assert_eq!(a, crate::console::ALIAS_END);
        fs.close(a, 1024).unwrap();
        let (b, _) = fs.open("reserved-b.bin", 0xc0000000, 3, 2, 1024).unwrap();
        assert_eq!(b, crate::console::ALIAS_END + 4);
        assert!(!crate::console::reserved_alias(b));
    }
    #[test]
    fn independent_cursors_shared_bytes_sparse_writes_and_append_are_guest_only() {
        let mut fs = VirtualFileSystem::new();
        let (a, _) = fs.open("probe.bin", 0xc0000000, 3, 4, 1024).unwrap();
        let (b, last) = fs
            .open("C:/workspace/./PROBE.bin", 0x80000000, 3, 3, 1024)
            .unwrap();
        assert_eq!(last, 0);
        fs.write(a, 1024, b"RUST").unwrap();
        assert_eq!(fs.read(b, 1024, 2).unwrap(), b"RU");
        fs.seek(a, 1024, 6, 0).unwrap();
        fs.write(a, 1024, b"!").unwrap();
        assert_eq!(fs.read(b, 1024, 20).unwrap(), b"ST\0\0!");
        let (append, _) = fs.open("probe.bin", 4, 3, 3, 1024).unwrap();
        fs.seek(append, 1024, 0, 0).unwrap();
        fs.write(append, 1024, b"+").unwrap();
        assert_eq!(fs.contents("probe.bin").unwrap().unwrap(), b"RUST\0\0!+");
        assert_eq!(fs.write(b, 1024, b"bad").unwrap_err().win32, 5);
        assert_eq!(fs.read(a, 2048, 1).unwrap_err().win32, 6);
        fs.close(a, 1024).unwrap();
        assert_eq!(fs.close(a, 1024).unwrap_err().win32, 6);
    }
    #[test]
    fn sharing_and_failed_truncation_preserve_existing_content() {
        let mut fs = VirtualFileSystem::new();
        let (a, _) = fs.open("shared", 0xc0000000, 1, 2, 1024).unwrap();
        fs.write(a, 1024, b"keep").unwrap();
        assert_eq!(
            fs.open("shared", 0x40000000, 3, 2, 1024).unwrap_err().win32,
            32
        );
        assert_eq!(fs.contents("shared").unwrap().unwrap(), b"keep");
        fs.close(a, 1024).unwrap();
        assert_eq!(
            fs.open("shared", 0x80000000, 3, 5, 1024).unwrap_err().win32,
            5
        );
        assert_eq!(
            fs.open("missing\\x", 0x40000000, 3, 2, 1024)
                .unwrap_err()
                .win32,
            3
        );
        assert_eq!(
            fs.open("absent", 0x80000000, 3, 3, 1024).unwrap_err().win32,
            2
        );
        assert!(fs.path("C:\\workspace\\NUL.txt").is_err());
        assert!(fs.path("\\\\server\\share\\file").is_err());
        assert_eq!(fs.path("..\\workspace\\x").unwrap(), "c:\\workspace\\x");
    }
}

#[cfg(test)]
#[path = "filesystem_registry_handles.rs"]
mod registry_handle_tests;

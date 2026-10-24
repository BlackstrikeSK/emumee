//! Native synchronous files over the sole VFS catalog and OpenFile table.
//! Handles are opaque values; no FILE_OBJECT, host file or async completion is invented.
use super::*;
use crate::pe::Architecture;
use serde::Serialize;
use sha2::{Digest, Sha256};
pub const NATIVE_FILE_FIRST: u64 = 0x90000000;
pub const NATIVE_FILE_LIMIT: u64 = 4096;
pub const NATIVE_FILE_END: u64 = NATIVE_FILE_FIRST + NATIVE_FILE_LIMIT * 8;
pub const NATIVE_FILE_HIGH: u64 = 0xffffffff00000000;
pub const NATIVE_FILE_RESERVATIONS: [(u64, u64); 2] = [
    (NATIVE_FILE_FIRST, NATIVE_FILE_END),
    (
        NATIVE_FILE_HIGH | NATIVE_FILE_FIRST,
        NATIVE_FILE_HIGH | NATIVE_FILE_END,
    ),
];
pub const NATIVE_MAX_TRANSFER: usize = MAX_FILE;
const INVALID: u32 = 0xc0000008;
const PARAMETER: u32 = 0xc000000d;
const DENIED: u32 = 0xc0000022;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FileDomain {
    User,
    Native(Architecture),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum NativeFileKind {
    File,
    Directory,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeFileClass {
    Live(NativeFileKind),
    Invalid,
    UserLive,
    Foreign,
}
#[derive(Debug, Error)]
#[error("Native file: {reason}")]
pub struct NativeFileError {
    pub status: Option<u32>,
    pub information: u64,
    pub reason: &'static str,
}
pub type NativeFileResult<T> = std::result::Result<T, NativeFileError>;
fn unsupported(reason: &'static str) -> NativeFileError {
    NativeFileError {
        status: None,
        information: 0,
        reason,
    }
}
fn status(code: u32, information: u64, reason: &'static str) -> NativeFileError {
    NativeFileError {
        status: Some(code),
        information,
        reason,
    }
}
impl From<FileError> for NativeFileError {
    fn from(value: FileError) -> Self {
        let code = match value.win32 {
            2 => 0xc0000034,
            3 => 0xc000003a,
            4 | 8 => 0xc000009a,
            5 => DENIED,
            6 => INVALID,
            32 => 0xc0000043,
            80 | 183 => 0xc0000035,
            87 | 123 | 131 | 206 | 223 => PARAMETER,
            _ => return unsupported(value.reason),
        };
        status(code, 0, value.reason)
    }
}
pub fn reserved_native_file_next(handle: u64) -> Option<u64> {
    NATIVE_FILE_RESERVATIONS
        .into_iter()
        .find_map(|(a, b)| (a..b).contains(&handle).then_some(b))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn request(arch: Architecture, name: &str, disposition: u32) -> NativeFileOpen<'_> {
        NativeFileOpen {
            architecture: arch,
            owner: 4,
            root: 0,
            name,
            access: 0xc0010000,
            share: 7,
            disposition,
            options: 0x60,
            attributes: 0x80,
        }
    }
    fn opened(fs: &mut VirtualFileSystem, arch: Architecture, name: &str) -> u64 {
        fs.native_open_file(request(arch, name, 3)).unwrap().handle
    }
    #[test]
    fn complete_derived_reservations_are_disjoint_and_user_allocator_skips_their_far_ends_before_mutation()
     {
        let mut ranges = crate::registry::FILE_HANDLE_RESERVATIONS.to_vec();
        ranges.extend(NATIVE_FILE_RESERVATIONS);
        ranges.push((crate::console::ALIAS_FIRST, crate::console::ALIAS_END));
        ranges.push((SEARCH_FIRST, SEARCH_END));
        for (i, (a, b)) in ranges.iter().enumerate() {
            assert!(a < b);
            for (c, d) in &ranges[..i] {
                assert!(
                    b <= c || d <= a,
                    "reservation overlap {a:x}..{b:x} with {c:x}..{d:x}"
                );
            }
        }
        assert_eq!(
            crate::registry::NATIVE_HANDLE_END,
            crate::registry::NATIVE_HANDLE_FIRST + crate::registry::MAX_HANDLES as u64 * 8
        );
        const { assert!(crate::registry::NATIVE_HANDLE_END > 0x80020000) };
        for (a, b) in ranges {
            for at in [a, b - 1] {
                let mut fs = VirtualFileSystem::new();
                let (h, _) = fs.open("keep", 0xc0000000, 7, 2, 1).unwrap();
                fs.write(h, 1, b"KEEP").unwrap();
                fs.close(h, 1).unwrap();
                fs.next_handle = at;
                let (h, _) = fs.open("keep", 0x80000000, 7, 3, 1).unwrap();
                assert_eq!(h, b);
                assert_eq!(fs.contents("keep").unwrap().unwrap(), b"KEEP");
            }
        }
    }
    #[test]
    fn all_six_dispositions_information_and_atomic_capacity_failure() {
        for arch in [Architecture::X86, Architecture::X64] {
            for disposition in 0..=5 {
                let mut fs = VirtualFileSystem::new();
                let h = opened(&mut fs, arch, r"C:\workspace\a");
                fs.native_write_file(arch, 4, h, b"KEEP", None).unwrap();
                fs.native_close_file(arch, 4, h).unwrap();
                let result = fs.native_open_file(request(arch, r"C:\workspace\a", disposition));
                if disposition == 2 {
                    assert_eq!(result.unwrap_err().status, Some(0xc0000035));
                } else {
                    assert_eq!(
                        result.unwrap().information,
                        match disposition {
                            0 => 0,
                            4 | 5 => 3,
                            _ => 1,
                        }
                    );
                }
                assert_eq!(
                    fs.contents("a").unwrap().unwrap(),
                    if [0, 4, 5].contains(&disposition) {
                        &b""[..]
                    } else {
                        &b"KEEP"[..]
                    }
                );
            }
            let mut fs = VirtualFileSystem::new();
            let h = opened(&mut fs, arch, r"C:\workspace\keep");
            fs.native_write_file(arch, 4, h, b"KEEP", None).unwrap();
            fs.native_close_file(arch, 4, h).unwrap();
            fs.native_file_issues = NATIVE_FILE_LIMIT;
            assert_eq!(
                fs.native_open_file(request(arch, r"C:\workspace\keep", 5))
                    .unwrap_err()
                    .status,
                Some(0xc000009a)
            );
            assert_eq!(fs.contents("keep").unwrap().unwrap(), b"KEEP");
            assert!(
                fs.native_open_file(request(arch, r"C:\workspace\new", 3))
                    .is_err()
            );
            assert!(!fs.exists("new").unwrap());
        }
    }
    #[test]
    fn real_directories_relative_roots_sharing_and_typed_handle_domains() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut fs = VirtualFileSystem::new();
            let mut dir = request(arch, r"C:\workspace\dir", 2);
            dir.options = 0x21;
            let root = fs.native_open_file(dir).unwrap().handle;
            assert_eq!(
                fs.native_file_class(arch, 4, root),
                NativeFileClass::Live(NativeFileKind::Directory)
            );
            assert_eq!(
                fs.native_read_file(arch, 4, root, 1, None)
                    .unwrap_err()
                    .status,
                Some(0xc00000ba)
            );
            let mut child = request(arch, "child", 3);
            child.root = root;
            let h = fs.native_open_file(child).unwrap().handle;
            assert_eq!(fs.handle_path(h, 4).unwrap_err().win32, 6);
            assert_eq!(fs.close(h, 4).unwrap_err().win32, 6);
            fs.native_write_file(arch, 4, h, b"shared", None).unwrap();
            let (u, _) = fs.open("dir/child", 0x80000000, 7, 3, 1024).unwrap();
            assert_eq!(fs.read(u, 1024, 6).unwrap(), b"shared");
            assert_eq!(fs.native_file_class(arch, 4, u), NativeFileClass::UserLive);
            assert!(
                fs.native_read_file(arch, 4, u, 1, None)
                    .unwrap_err()
                    .status
                    .is_none()
            );
            fs.native_close_file(arch, 4, h).unwrap();
            assert_eq!(fs.native_file_class(arch, 4, h), NativeFileClass::Invalid);
            if arch == Architecture::X64 {
                assert_eq!(
                    fs.native_file_class(arch, 4, h as u32 as u64),
                    NativeFileClass::Invalid
                );
            }
            fs.native_close_file(arch, 4, root).unwrap();
            fs.close(u, 1024).unwrap();
        }
    }
    #[test]
    fn seed_policy_follows_actual_backing_move_copy_and_unnamed_lifetime() {
        for arch in [Architecture::X86, Architecture::X64] {
            let seed = b"SEED".to_vec();
            let mut fs = VirtualFileSystem::from_seed(
                123,
                r"C:\",
                &[],
                &[SeedFile {
                    path: r"C:\seed",
                    bytes: &seed,
                }],
            )
            .unwrap();
            let writable = fs.native_open_file(request(arch, r"C:\seed", 1)).unwrap();
            assert_eq!(writable.information, 1);
            fs.native_write_file(arch, 4, writable.handle, b"NATI", Some(0))
                .unwrap();
            assert_eq!(fs.contents(r"C:\seed").unwrap().unwrap(), b"NATI");
            assert_eq!(seed, b"SEED");
            fs.native_close_file(arch, 4, writable.handle).unwrap();
            let mut read = request(arch, r"C:\seed", 1);
            read.access = 0x80000000;
            let h = fs.native_open_file(read).unwrap().handle;
            assert_eq!(fs.native_read_file(arch, 4, h, 4, None).unwrap().1, b"NATI");
            let (u, _) = fs.open(r"C:\seed", 0xc0000000, 7, 3, 1024).unwrap();
            fs.write(u, 1024, b"USER").unwrap();
            fs.close(u, 1024).unwrap();
            assert_eq!(
                fs.native_read_file(arch, 4, h, 4, Some(0)).unwrap().1,
                b"USER"
            );
            fs.move_file(r"C:\seed", r"C:\moved", 0).unwrap();
            assert!(fs.native_files_report().live[0].configured_backing);
            fs.copy_file(r"C:\moved", r"C:\copy", false).unwrap();
            let c = opened(&mut fs, arch, r"C:\copy");
            fs.native_write_file(arch, 4, c, b"COPY", Some(0)).unwrap();
            fs.delete_file(r"C:\moved").unwrap();
            let row = fs
                .native_files_report()
                .live
                .into_iter()
                .find(|e| e.handle == h)
                .unwrap();
            assert!(row.configured_backing && row.unlinked);
            assert_eq!(
                fs.native_read_file(arch, 4, h, 4, Some(0)).unwrap().1,
                b"USER"
            );
            fs.native_close_file(arch, 4, h).unwrap();
            assert!(fs.mutations.unlinked_seeded.is_empty());
            assert_eq!(fs.contents(r"C:\copy").unwrap().unwrap(), b"COPY");
        }
    }
    #[test]
    fn offsets_append_eof_zero_length_and_prepublication_failures_preserve_bytes_and_cursors() {
        let arch = Architecture::X64;
        let mut fs = VirtualFileSystem::new();
        let h = opened(&mut fs, arch, r"C:\workspace\x");
        fs.native_write_file(arch, 4, h, b"DATA", None).unwrap();
        assert_eq!(
            fs.native_read_file(arch, 4, h, 1, None).unwrap().0,
            0xc0000011
        );
        assert_eq!(fs.native_read_file(arch, 4, h, 0, Some(9)).unwrap().0, 0);
        assert_eq!(fs.native_files_report().live[0].position, 9);
        let before = fs.native_files_report().live[0].position;
        assert!(
            fs.native_write_file(arch, 4, h, b"!", Some(MAX_FILE as i64))
                .is_err()
        );
        assert_eq!(fs.native_files_report().live[0].position, before);
        assert!(fs.native_read_file(arch, 4, h, 1, Some(-1)).is_err());
        let mut append = request(arch, r"C:\workspace\x", 1);
        append.access = 0x100004;
        let a = fs.native_open_file(append).unwrap().handle;
        fs.native_write_file(arch, 4, a, b"+", Some(0)).unwrap();
        assert_eq!(fs.contents("x").unwrap().unwrap(), b"DATA+");
        fs.native_write_file(arch, 4, h, b"", Some(20)).unwrap();
        assert_eq!(fs.contents("x").unwrap().unwrap(), b"DATA+");
        assert_eq!(
            fs.native_files_report()
                .live
                .iter()
                .find(|r| r.handle == h)
                .unwrap()
                .position,
            20
        );
    }
    #[test]
    fn rejected_names_options_permissions_and_sharing_cannot_create_or_truncate() {
        let arch = Architecture::X86;
        let mut fs = VirtualFileSystem::new();
        for name in [
            r"C:\workspace\..\x",
            r"C:\workspace\x.",
            r"\Device\HarddiskVolume1\x",
            r"\\server\share\x",
        ] {
            assert!(fs.native_open_file(request(arch, name, 3)).is_err());
        }
        let mut r = request(arch, r"C:\workspace\x", 3);
        r.access = 1;
        assert_eq!(fs.native_open_file(r).unwrap_err().status, Some(PARAMETER));
        let (h, _) = fs.open("x", 0xc0000000, 1, 2, 1024).unwrap();
        fs.write(h, 1024, b"KEEP").unwrap();
        assert_eq!(
            fs.native_open_file(request(arch, r"C:\workspace\x", 5))
                .unwrap_err()
                .status,
            Some(0xc0000043)
        );
        assert_eq!(fs.contents("x").unwrap().unwrap(), b"KEEP");
        assert_eq!(fs.native_files_report().lifetime_issues, 0);
    }
    #[test]
    fn directory_open_accepts_one_final_separator_without_normalizing_ambiguous_paths() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut fs = VirtualFileSystem::new();
            let mut directory = request(arch, r"C:\workspace\Logs\", 2);
            directory.options = 0x21;
            directory.attributes = 0x10;
            let opened = fs.native_open_file(directory).unwrap();
            assert_eq!(opened.information, 2);
            assert!(fs.directories.contains(r"c:\workspace\logs"));
            fs.native_close_file(arch, 4, opened.handle).unwrap();

            let mut same = request(arch, r"\??\C:\workspace\Logs\", 1);
            same.options = 0x21;
            let opened = fs.native_open_file(same).unwrap();
            assert_eq!(opened.information, 1);
            fs.native_close_file(arch, 4, opened.handle).unwrap();

            let mut root = request(arch, r"C:\workspace\Logs", 1);
            root.options = 0x21;
            let root = fs.native_open_file(root).unwrap().handle;
            let mut child = request(arch, r"Child\", 2);
            child.options = 0x21;
            child.root = root;
            assert_eq!(fs.native_open_file(child).unwrap().information, 2);
            assert!(fs.directories.contains(r"c:\workspace\logs\child"));

            let count = fs.directories.len();
            for (name, reason) in [
                (r"C:\workspace\Logs\\", "empty interior"),
                (r"C:\\", "empty interior"),
                (r"C:\workspace\\Inner\", "empty interior"),
                (r"C:\workspace\..\Escape\", "parent"),
                (r"C:\workspace\.\Same\", "dot"),
            ] {
                let mut bad = request(arch, name, 2);
                bad.options = 0x21;
                let error = fs.native_open_file(bad).unwrap_err();
                assert!(error.reason.contains(reason), "{name}: {}", error.reason);
            }
            for name in [r"\Device\HarddiskVolume1\Logs\", r"\\server\share\Logs\"] {
                let mut bad = request(arch, name, 2);
                bad.options = 0x21;
                assert!(fs.native_open_file(bad).is_err());
            }
            assert!(
                fs.native_open_file(request(arch, r"C:\workspace\file.bin\", 3))
                    .unwrap_err()
                    .reason
                    .contains("empty final")
            );
            assert_eq!(fs.directories.len(), count);
        }
    }
}
fn first(architecture: Architecture) -> u64 {
    NATIVE_FILE_FIRST
        | if architecture == Architecture::X64 {
            NATIVE_FILE_HIGH
        } else {
            0
        }
}
pub struct NativeFileOpen<'a> {
    pub architecture: Architecture,
    pub owner: u64,
    pub root: u64,
    pub name: &'a str,
    pub access: u32,
    pub share: u32,
    pub disposition: u32,
    pub options: u32,
    pub attributes: u32,
}
#[derive(Clone, Copy, Debug)]
pub struct NativeFileOpened {
    pub handle: u64,
    pub information: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct NativeFileEvidence {
    pub handle: u64,
    pub owner: u64,
    pub architecture: Architecture,
    pub kind: NativeFileKind,
    pub path_preview: String,
    pub path_utf16_units: usize,
    pub path_utf8_sha256: String,
    pub unlinked: bool,
    pub configured_backing: bool,
    pub position: u64,
    pub requested_access: u32,
    pub granted_access: u32,
    pub share: u32,
    pub synchronous_options: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct NativeFilesReport {
    pub lifetime_issues: u64,
    pub live: Vec<NativeFileEvidence>,
}
fn granted(mask: u32) -> u32 {
    let mut access = mask & 0x01ffffff;
    if mask & 0x80000000 != 0 {
        access |= 0x120089;
    }
    if mask & 0x40000000 != 0 {
        access |= 0x120116;
    }
    if mask & 0x20000000 != 0 {
        access |= 0x1200a0;
    }
    if mask & 0x10000000 != 0 {
        access |= 0x1f01ff;
    }
    access
}
impl VirtualFileSystem {
    pub fn native_file_class(
        &self,
        architecture: Architecture,
        owner: u64,
        handle: u64,
    ) -> NativeFileClass {
        if let Some(h) = self.handles.get(&handle) {
            return match h.domain {
                FileDomain::User => NativeFileClass::UserLive,
                FileDomain::Native(arch) if arch == architecture && h.owner == owner => {
                    NativeFileClass::Live(h.kind)
                }
                FileDomain::Native(_) => NativeFileClass::Invalid,
            };
        }
        if handle == 0 || reserved_native_file_next(handle).is_some() {
            NativeFileClass::Invalid
        } else {
            NativeFileClass::Foreign
        }
    }
    fn native_handle(
        &self,
        architecture: Architecture,
        owner: u64,
        handle: u64,
    ) -> NativeFileResult<&OpenFile> {
        match self.native_file_class(architecture, owner, handle) {
            NativeFileClass::Live(_) => Ok(&self.handles[&handle]),
            NativeFileClass::Invalid => Err(status(INVALID, 0, "invalid native file handle")),
            NativeFileClass::UserLive => Err(unsupported(
                "ordinary file handle is outside native file domain",
            )),
            NativeFileClass::Foreign => {
                Err(unsupported("foreign handle has no native file authority"))
            }
        }
    }
    fn native_seed_backing(&self, h: &OpenFile) -> bool {
        h.unlinked.map_or_else(
            || self.metadata.native_seeded.contains(&h.path),
            |id| self.mutations.unlinked_seeded.contains(&id),
        )
    }
    fn native_path(&self, request: &NativeFileOpen<'_>) -> NativeFileResult<(String, String)> {
        let mut name = request.name.replace('/', "\\");
        // Persona aliases require installed adapter authority; the core has no
        // guessed Windows directory or host namespace.
        if let Some(rest) = name.strip_prefix("\\??\\") {
            name = rest.into();
        }
        if name.is_empty() || name.encode_utf16().count() > 16383 || name.contains('\0') {
            return Err(status(PARAMETER, 0, "invalid counted native file name"));
        }
        if name.starts_with("\\\\") || name.starts_with('\\') {
            return Err(unsupported(
                "native device/UNC/root-relative namespace is not modeled",
            ));
        }
        let absolute = name.as_bytes().get(1) == Some(&b':');
        if absolute && request.root != 0 {
            return Err(status(
                PARAMETER,
                0,
                "absolute native name cannot carry RootDirectory",
            ));
        }
        // A final separator names the same directory for FILE_DIRECTORY_FILE
        // opens. Strip exactly one; repeated and interior empty components
        // still fail the strict validation below.
        if request.options & 1 != 0
            && name.ends_with('\\')
            && !name.ends_with("\\\\")
            && !(absolute && name.len() == 3)
        {
            name.pop();
        }
        let mut components = name
            .split('\\')
            .skip(usize::from(absolute))
            .filter(|s| !(absolute && name.len() == 3 && s.is_empty()))
            .peekable();
        while let Some(component) = components.next() {
            let reason = if component.is_empty() {
                Some(if components.peek().is_none() {
                    "ambiguous native path component: empty final"
                } else {
                    "ambiguous native path component: empty interior"
                })
            } else if component == "." {
                Some("ambiguous native path component: dot")
            } else if component == ".." {
                Some("ambiguous native path component: parent")
            } else if component.ends_with([' ', '.']) {
                Some("ambiguous native path component: trailing space or dot")
            } else {
                None
            };
            if let Some(reason) = reason {
                return Err(unsupported(reason));
            }
        }
        if !absolute {
            if request.root == 0 {
                return Err(unsupported(
                    "relative native file name requires an owned directory handle",
                ));
            }
            let root = self.native_handle(request.architecture, request.owner, request.root)?;
            if root.kind != NativeFileKind::Directory {
                return Err(status(
                    0xc0000024,
                    0,
                    "RootDirectory is not a directory handle",
                ));
            }
            name = format!("{}\\{}", root.path.trim_end_matches('\\'), name);
        }
        Ok((self.path(&name)?, self.normalize_path(&name, false, false)?))
    }
    /// Every fallible check precedes mutation, including handle issue, sharing and backing policy.
    pub fn native_open_file(
        &mut self,
        request: NativeFileOpen<'_>,
    ) -> NativeFileResult<NativeFileOpened> {
        if request.share & !7 != 0
            || request.disposition > 5
            || request.options & 0x30 == 0x30
            || request.options & 0x41 == 0x41
        {
            return Err(status(
                PARAMETER,
                0,
                "invalid native share/disposition/options combination",
            ));
        }
        if request.options & !0x73 != 0 || request.attributes & !0xb7 != 0 {
            return Err(unsupported(
                "native create options/attributes outside bounded legacy profile",
            ));
        }
        if request.access & !(0xf0000000 | 0x1f01ff) != 0 {
            return Err(unsupported(
                "MAXIMUM_ALLOWED/system-security/reserved access needs security authority",
            ));
        }
        let directory = request.options & 1 != 0;
        if directory && ![1, 2, 3].contains(&request.disposition) {
            return Err(status(
                PARAMETER,
                0,
                "directory disposition must be OPEN/CREATE/OPEN_IF",
            ));
        }
        if !directory && request.options & 0x30 == 0 {
            return Err(unsupported("asynchronous native files are not implemented"));
        }
        let mask = granted(request.access);
        if request.options & 0x30 != 0 && mask & 0x100000 == 0 {
            return Err(status(
                PARAMETER,
                0,
                "synchronous native handle requires SYNCHRONIZE",
            ));
        }
        if request.attributes & 0x10 != 0 && !directory {
            return Err(status(
                PARAMETER,
                0,
                "directory attribute without directory create option",
            ));
        }
        let (path, display) = self.native_path(&request)?;
        let is_dir = self.directories.contains(&path);
        let exists = is_dir || self.files.contains_key(&path);
        if exists && directory != is_dir {
            return Err(status(
                if directory { 0xc0000103 } else { 0xc00000ba },
                0,
                "native create kind disagrees with actual object",
            ));
        }
        if exists && request.disposition == 2 {
            return Err(status(0xc0000035, 4, "native file already exists"));
        }
        self.parent_directory(&path).map_err(|e| {
            let mut e: NativeFileError = e.into();
            e.information = 5;
            e
        })?;
        if !exists && [1, 4].contains(&request.disposition) {
            return Err(status(0xc0000034, 5, "native file name not found"));
        }
        let access = Access::new(mask);
        let truncate = exists && [0, 4, 5].contains(&request.disposition);
        if request.disposition == 0 && !access.delete {
            return Err(status(DENIED, 0, "supersede requires DELETE"));
        }
        if [4, 5].contains(&request.disposition) && !access.write {
            return Err(status(DENIED, 0, "overwrite requires WRITE_DATA"));
        }
        if exists
            && self.metadata.attributes_for(&path) & 1 != 0
            && (access.write || access.append || access.delete || truncate)
        {
            return Err(status(
                DENIED,
                0,
                "read-only native file cannot be opened for mutation",
            ));
        }
        for h in self
            .handles
            .values()
            .filter(|h| h.unlinked.is_none() && h.path == path)
        {
            if !h.access.shared_by(request.share) || !access.shared_by(h.share) {
                return Err(status(
                    0xc0000043,
                    0,
                    "cross-channel file sharing violation",
                ));
            }
        }
        if self.handles.len() >= MAX_HANDLES
            || self.native_file_issues >= NATIVE_FILE_LIMIT
            || (!exists
                && if directory {
                    self.directories.len() >= 4096
                } else {
                    self.files.len() >= 4096
                })
        {
            return Err(status(0xc000009a, 0, "native file/namespace capacity"));
        }
        let handle = first(request.architecture)
            .checked_add(self.native_file_issues * 8)
            .ok_or_else(|| status(0xc000009a, 0, "native handle arithmetic"))?;
        if self.handles.contains_key(&handle) {
            return Err(unsupported(
                "native file namespace collision before mutation",
            ));
        }
        self.metadata.require_display(&path, &display)?;
        let information = if !exists {
            2
        } else if request.disposition == 0 {
            0
        } else if truncate {
            3
        } else {
            1
        };
        if !exists {
            if directory {
                self.create_directory(&display)?;
            } else {
                self.metadata.record_display(path.clone(), display);
                self.files.insert(path.clone(), Vec::new());
            }
        } else if truncate {
            self.total -= self.files[&path].len();
            self.files.get_mut(&path).unwrap().clear();
        }
        if !exists || truncate {
            self.metadata
                .set_native_attributes(&path, request.attributes, directory);
        }
        self.native_file_issues += 1;
        self.handles.insert(
            handle,
            OpenFile {
                path,
                unlinked: None,
                position: 0,
                access,
                share: request.share,
                owner: request.owner,
                domain: FileDomain::Native(request.architecture),
                kind: if directory {
                    NativeFileKind::Directory
                } else {
                    NativeFileKind::File
                },
                native_access: mask,
                native_requested_access: request.access,
                native_options: request.options,
            },
        );
        Ok(NativeFileOpened {
            handle,
            information,
        })
    }
    fn transfer_access(&self, h: &OpenFile, write: bool) -> NativeFileResult<()> {
        if h.kind == NativeFileKind::Directory {
            return Err(status(
                0xc00000ba,
                0,
                "directory handles do not expose file bytes",
            ));
        }
        if (write && !h.access.write && !h.access.append) || (!write && !h.access.read) {
            return Err(status(DENIED, 0, "native transfer access denied"));
        }
        Ok(())
    }
    /// Immutable handle/kind/rights check, preceding guest buffer probing.
    pub fn native_transfer_rights(
        &self,
        arch: Architecture,
        owner: u64,
        handle: u64,
        write: bool,
    ) -> NativeFileResult<()> {
        self.transfer_access(self.native_handle(arch, owner, handle)?, write)
    }
    fn transfer_position(
        &self,
        h: &OpenFile,
        offset: Option<i64>,
        write: bool,
    ) -> NativeFileResult<u64> {
        self.transfer_access(h, write)?;
        let position = match offset {
            None | Some(-2) => h.position,
            Some(-1) if write => self.file_bytes(h).len() as u64,
            Some(n) if n >= 0 => n as u64,
            _ => return Err(status(PARAMETER, 0, "invalid native byte offset")),
        };
        if position > MAX_FILE as u64 {
            return Err(status(PARAMETER, 0, "native byte offset exceeds bound"));
        }
        Ok(if write && h.access.append && !h.access.write {
            self.file_bytes(h).len() as u64
        } else {
            position
        })
    }
    pub fn native_read_file(
        &mut self,
        arch: Architecture,
        owner: u64,
        handle: u64,
        count: usize,
        offset: Option<i64>,
    ) -> NativeFileResult<(u32, Vec<u8>)> {
        if count > MAX_FILE {
            return Err(unsupported("native transfer exceeds 32 MiB bound"));
        }
        let h = self.native_handle(arch, owner, handle)?;
        let position = self.transfer_position(h, offset, false)?;
        let data = self.file_bytes(h);
        let start = (position as usize).min(data.len());
        let end = start.saturating_add(count).min(data.len());
        let bytes = data[start..end].to_vec();
        let status = if count > 0 && bytes.is_empty() {
            0xc0000011
        } else {
            0
        };
        self.handles.get_mut(&handle).unwrap().position = position + bytes.len() as u64;
        Ok((status, bytes))
    }
    pub fn native_write_file(
        &mut self,
        arch: Architecture,
        owner: u64,
        handle: u64,
        bytes: &[u8],
        offset: Option<i64>,
    ) -> NativeFileResult<usize> {
        if bytes.len() > MAX_FILE {
            return Err(unsupported("native transfer exceeds 32 MiB bound"));
        }
        let h = self.native_handle(arch, owner, handle)?;
        let position = self.transfer_position(h, offset, true)?;
        let end = (position as usize)
            .checked_add(bytes.len())
            .filter(|n| *n <= MAX_FILE)
            .ok_or_else(|| status(PARAMETER, 0, "native write end exceeds 32 MiB"))?;
        let growth = if bytes.is_empty() {
            0
        } else {
            end.saturating_sub(self.file_bytes(h).len())
        };
        if self.total.checked_add(growth).is_none_or(|n| n > MAX_TOTAL) {
            return Err(status(0xc000009a, 0, "native VFS capacity"));
        }
        if !bytes.is_empty() {
            let file = self.file_bytes_mut(handle);
            if end > file.len() {
                file.resize(end, 0);
            }
            file[position as usize..end].copy_from_slice(bytes);
            self.total += growth;
        }
        self.handles.get_mut(&handle).unwrap().position = if bytes.is_empty() {
            position
        } else {
            end as u64
        };
        Ok(bytes.len())
    }
    pub fn native_flush_file(
        &self,
        arch: Architecture,
        owner: u64,
        handle: u64,
    ) -> NativeFileResult<()> {
        self.native_handle(arch, owner, handle)?;
        Ok(())
    }
    pub fn native_close_file(
        &mut self,
        arch: Architecture,
        owner: u64,
        handle: u64,
    ) -> NativeFileResult<()> {
        self.native_handle(arch, owner, handle)?;
        self.close_owned(handle);
        Ok(())
    }
    pub fn native_files_report(&self) -> NativeFilesReport {
        NativeFilesReport {
            lifetime_issues: self.native_file_issues,
            live: self
                .handles
                .iter()
                .filter_map(|(handle, h)| match h.domain {
                    FileDomain::Native(architecture) => Some(NativeFileEvidence {
                        handle: *handle,
                        owner: h.owner,
                        architecture,
                        kind: h.kind,
                        path_preview: h.path.chars().take(128).collect(),
                        path_utf16_units: h.path.encode_utf16().count(),
                        path_utf8_sha256: format!("{:x}", Sha256::digest(h.path.as_bytes())),
                        unlinked: h.unlinked.is_some(),
                        configured_backing: self.native_seed_backing(h),
                        position: h.position,
                        requested_access: h.native_requested_access,
                        granted_access: h.native_access,
                        share: h.share,
                        synchronous_options: h.native_options,
                    }),
                    FileDomain::User => None,
                })
                .collect(),
        }
    }
}

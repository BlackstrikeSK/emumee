//! Guest VFS metadata, directories and bounded deterministic searches. This is
//! a child module of filesystem, so it extends its actual catalog authority;
//! it never consults host paths or invents configured/system files.
use super::*;
#[path = "filesystem_mutation_metadata.rs"]
mod mutation_metadata;
use crate::persona::Encoding;
use serde::Serialize;
pub const DEFAULT_FILETIME: u64 = 133000000000000000;
pub const SEARCH_FIRST: u64 = 0x70000000;
pub const SEARCH_END: u64 = 0x70010000;
const MAX_SEARCHES: usize = 128;
const MAX_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;
const MAX_MATCH_WORK: usize = 4 * 1024 * 1024;
const MAX_DISPLAY_BYTES: usize = 8 * 1024 * 1024;
#[derive(Clone, Debug)]
pub(super) struct MetadataState {
    attributes: BTreeMap<String, u32>,
    pub(in crate::filesystem) native_seeded: BTreeSet<String>,
    created_directories: BTreeSet<String>,
    filetime: u64,
    display: BTreeMap<String, String>,
    display_bytes: usize,
}
impl Default for MetadataState {
    fn default() -> Self {
        Self {
            attributes: BTreeMap::new(),
            native_seeded: BTreeSet::new(),
            created_directories: BTreeSet::new(),
            filetime: DEFAULT_FILETIME,
            display: BTreeMap::from([
                ("c:\\".into(), "C:\\".into()),
                ("c:\\workspace".into(), "C:\\workspace".into()),
            ]),
            display_bytes: 15,
        }
    }
}
impl MetadataState {
    pub(super) fn require_display(&self, path: &str, display: &str) -> Result<()> {
        if !self.display.contains_key(path)
            && self
                .display_bytes
                .checked_add(display.len())
                .is_none_or(|n| n > MAX_DISPLAY_BYTES)
        {
            return Err(error(8, "guest display-name metadata capacity"));
        }
        Ok(())
    }
    pub(super) fn record_display(&mut self, path: String, display: String) {
        if let std::collections::btree_map::Entry::Vacant(entry) = self.display.entry(path) {
            self.display_bytes += display.len();
            entry.insert(display);
        }
    }
    pub(super) fn require_open(&self, path: &str, access: u32, disposition: u32) -> Result<()> {
        if self.attributes.get(path).is_some_and(|a| a & 1 != 0)
            && (access & 0x50010006 != 0 || matches!(disposition, 2 | 5))
        {
            return Err(error(
                5,
                "read-only guest file cannot be opened for mutation",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Metadata {
    pub attributes: u32,
    pub times: [u64; 3],
    pub size: u64,
}
impl Metadata {
    pub fn image(&self) -> Vec<u8> {
        let mut output = self.attributes.to_le_bytes().to_vec();
        for time in self.times {
            output.extend(time.to_le_bytes());
        }
        output.extend(((self.size >> 32) as u32).to_le_bytes());
        output.extend((self.size as u32).to_le_bytes());
        output
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Entry {
    pub path: String,
    pub name: String,
    pub metadata: Metadata,
}
fn encode(text: &str, wide: bool) -> Result<Vec<u8>> {
    let encoding = if wide {
        Encoding::Utf16
    } else {
        Encoding::Cp1252
    };
    let bytes = encoding.encode(text, false);
    if !encoding
        .decode(&bytes)
        .is_ok_and(|roundtrip| roundtrip == text)
    {
        return Err(error(
            50,
            "guest name is not exactly representable in requested encoding",
        ));
    }
    Ok(bytes)
}
impl Entry {
    pub fn find_data(&self, wide: bool) -> Result<Vec<u8>> {
        let name = encode(&self.name, wide)?;
        let width = if wide { 2 } else { 1 };
        if name.len() / width >= 260 {
            return Err(error(50, "guest basename exceeds WIN32_FIND_DATA capacity"));
        }
        let mut image = vec![0; if wide { 592 } else { 320 }];
        image[..36].copy_from_slice(&self.metadata.image());
        image[44..44 + name.len()].copy_from_slice(&name);
        Ok(image)
    }
}
#[derive(Clone, Debug)]
pub struct DirectoryPlan {
    display: String,
    canonical: String,
}
impl DirectoryPlan {
    pub fn display(&self) -> &str {
        &self.display
    }
}
#[derive(Clone, Debug)]
pub struct PathPlan {
    pub result: u32,
    pub bytes: Option<Vec<u8>>,
    pub file_part_offset: Option<u64>,
}
fn sized_path(text: &str, wide: bool, capacity: u32, file_part: Option<usize>) -> Result<PathPlan> {
    if capacity > 32768 {
        return Err(error(87, "path output capacity exceeds profile"));
    }
    let mut bytes = encode(text, wide)?;
    let width = if wide { 2 } else { 1 };
    let units = bytes.len() / width;
    if units + 1 > 32768 {
        return Err(error(87, "expanded path exceeds profile"));
    }
    if units + 1 > capacity as usize {
        return Ok(PathPlan {
            result: (units + 1) as u32,
            bytes: None,
            file_part_offset: None,
        });
    }
    let offset = file_part
        .map(|index| encode(&text[..index], wide).map(|b| b.len() as u64))
        .transpose()?;
    bytes.extend(std::iter::repeat_n(0, width));
    Ok(PathPlan {
        result: units as u32,
        bytes: Some(bytes),
        file_part_offset: offset,
    })
}
impl VirtualFileSystem {
    pub fn current_directory(&self) -> &str {
        &self.current_directory
    }
    pub fn with_filetime(filetime: u64) -> Self {
        let mut fs = Self::new();
        fs.metadata.filetime = filetime;
        fs
    }
    pub fn metadata(&self, path: &str) -> Result<Metadata> {
        let path = self.path(path)?;
        let directory = self.directories.contains(&path);
        let size = if directory {
            0
        } else {
            self.files
                .get(&path)
                .ok_or_else(|| error(2, "guest path does not exist"))?
                .len() as u64
        };
        Ok(Metadata {
            attributes: self
                .metadata
                .attributes
                .get(&path)
                .copied()
                .unwrap_or(if directory { 0x10 } else { 0x80 }),
            times: [self.metadata.filetime; 3],
            size,
        })
    }
    pub fn set_attributes(&mut self, path: &str, requested: u32) -> Result<()> {
        let path = self.path(path)?;
        let directory = self.directories.contains(&path);
        if !directory && !self.files.contains_key(&path) {
            return Err(error(2, "guest path does not exist"));
        }
        let supported = 1 | 2 | 4 | 0x20 | 0x80 | 0x100 | 0x2000 | if directory { 0x10 } else { 0 };
        if requested & !supported != 0 {
            return Err(error(50, "file attributes outside modeled mutable profile"));
        }
        let value = requested & !(0x80 | 0x10);
        let value = if directory {
            value | 0x10
        } else if value == 0 {
            0x80
        } else {
            value
        };
        self.metadata.attributes.insert(path, value);
        Ok(())
    }
    pub fn create_directory(&mut self, path: &str) -> Result<()> {
        let display = self.normalize_path(path, false, false)?;
        let path = self.path(path)?;
        if self.directories.contains(&path) || self.files.contains_key(&path) {
            return Err(error(183, "guest path already exists"));
        }
        if self.directories.len() >= 4096 {
            return Err(error(8, "guest directory capacity"));
        }
        let parent = parent(&path)?;
        if !self.directories.contains(&parent) {
            return Err(error(3, "parent directory does not exist"));
        }
        self.metadata.require_display(&path, &display)?;
        self.metadata.record_display(path.clone(), display);
        self.directories.insert(path.clone());
        self.metadata.created_directories.insert(path);
        Ok(())
    }
    pub fn remove_directory(&mut self, path: &str) -> Result<()> {
        let path = self.path(path)?;
        if !self.directories.contains(&path) {
            return Err(error(3, "guest directory does not exist"));
        }
        if !self.metadata.created_directories.contains(&path) {
            return Err(error(
                50,
                "preset guest directory removal is outside profile",
            ));
        }
        if self.path(&self.current_directory)? == path || path.len() == 3 {
            return Err(error(
                5,
                "current directory or volume root cannot be removed",
            ));
        }
        let prefix = format!("{path}\\");
        if self.directories.iter().any(|p| p.starts_with(&prefix))
            || self.files.keys().any(|p| p.starts_with(&prefix))
        {
            return Err(error(145, "guest directory is not empty"));
        }
        if self
            .handles
            .values()
            .any(|h| h.kind == NativeFileKind::Directory && h.path == path)
        {
            return Err(error(
                50,
                "live directory handle deletion requires an unported directory lifetime policy",
            ));
        }
        self.directories.remove(&path);
        self.metadata.created_directories.remove(&path);
        self.metadata.attributes.remove(&path);
        if let Some(display) = self.metadata.display.remove(&path) {
            self.metadata.display_bytes -= display.len();
        }
        Ok(())
    }
    pub fn directory_plan(&self, path: &str) -> Result<DirectoryPlan> {
        let display = self.normalize_path(path, false, false)?;
        let canonical = self.path(&display)?;
        if !self.directories.contains(&canonical) {
            return Err(error(
                if self.files.contains_key(&canonical) {
                    267
                } else {
                    3
                },
                "requested current directory is not a guest directory",
            ));
        }
        Ok(DirectoryPlan { display, canonical })
    }
    pub fn commit_directory(&mut self, plan: DirectoryPlan) -> Result<()> {
        if !self.directories.contains(&plan.canonical) {
            return Err(error(3, "planned current directory is no longer present"));
        }
        self.current_directory = plan.display;
        Ok(())
    }
    pub fn full_path(&self, path: &str, wide: bool, capacity: u32) -> Result<PathPlan> {
        let display = self.normalize_path(path, false, true)?;
        let part = if path.ends_with(['\\', '/']) {
            None
        } else {
            display
                .rfind('\\')
                .filter(|index| *index + 1 < display.len())
                .map(|index| index + 1)
        };
        sized_path(&display, wide, capacity, part)
    }
    pub fn long_path(&self, path: &str, wide: bool, capacity: u32) -> Result<PathPlan> {
        if path.contains('~') {
            return Err(error(50, "short-name expansion is not modeled"));
        }
        self.metadata(path)?;
        sized_path(path, wide, capacity, None)
    }
    /// Actual immediate entries only. Lookup/order use existing lowercase keys;
    /// basenames retain recorded first spelling, falling back to canonical keys
    /// only when no display metadata exists. No invented . or .. entries.
    pub fn enumerate(&self, query: &str) -> Result<Vec<Entry>> {
        if query.is_empty() || query.ends_with(['\\', '/']) {
            return Err(error(123, "empty or trailing-separator search pattern"));
        }
        let query = query.replace('/', "\\");
        if query.as_bytes().get(1) == Some(&b':') && !query[2..].starts_with('\\') {
            return Err(error(50, "drive-relative search paths are not modeled"));
        }
        let (split, mask) = query
            .rsplit_once('\\')
            .map_or((".", query.as_str()), |(p, m)| (p, m));
        let split = if split.len() == 2 && split.as_bytes()[1] == b':' {
            format!("{split}\\")
        } else {
            split.to_owned()
        };
        let directory = self.path(&split)?;
        if !self.directories.contains(&directory) {
            return Err(error(3, "search directory is absent"));
        }
        let pattern = Pattern::parse(mask)?;
        let prefix = if directory.ends_with('\\') {
            directory.clone()
        } else {
            format!("{directory}\\")
        };
        let mut entries = BTreeMap::new();
        let mut work = 0usize;
        let mut snapshot_bytes = query.len();
        for path in self.directories.iter().chain(self.files.keys()) {
            let Some(name) = path.strip_prefix(&prefix) else {
                continue;
            };
            if name.is_empty() || name.contains('\\') {
                continue;
            }
            let cost = pattern.cost(name);
            work = work
                .checked_add(cost)
                .filter(|n| *n <= MAX_MATCH_WORK)
                .ok_or_else(|| error(8, "search wildcard work capacity"))?;
            if pattern.matches(name) {
                let display_name = self
                    .metadata
                    .display
                    .get(path)
                    .and_then(|display| display.rsplit_once('\\').map(|(_, name)| name))
                    .unwrap_or(name);
                snapshot_bytes = snapshot_bytes
                    .checked_add(path.len() + display_name.len() + 80)
                    .filter(|n| *n <= MAX_SNAPSHOT_BYTES)
                    .ok_or_else(|| error(8, "search snapshot capacity"))?;
                entries.insert(
                    name.to_owned(),
                    Entry {
                        path: path.clone(),
                        name: display_name.to_owned(),
                        metadata: self.metadata(path)?,
                    },
                );
            }
        }
        Ok(entries.into_values().collect())
    }
}
fn parent(path: &str) -> Result<String> {
    let (p, _) = path
        .rsplit_once('\\')
        .ok_or_else(|| error(123, "invalid directory path"))?;
    Ok(if p.len() == 2 {
        format!("{p}\\")
    } else {
        p.to_owned()
    })
}
#[derive(Clone, Copy, Debug)]
enum Token {
    Literal(u16),
    Star,
    DosStar,
    DosQuestion,
    DosDot,
}
#[derive(Debug)]
struct Pattern {
    tokens: Vec<Token>,
}
impl Pattern {
    fn parse(mask: &str) -> Result<Self> {
        if mask.is_empty() || mask.encode_utf16().count() > 260 {
            return Err(error(123, "empty or excessive search mask"));
        }
        if mask.contains(['[', ']', '<', '>', '"', '~'])
            || mask.ends_with(' ')
            || (mask.ends_with('.') && !mask.ends_with("*."))
        {
            return Err(error(
                50,
                "search grammar or short-name matching is not modeled",
            ));
        }
        let text = mask.to_lowercase();
        let units: Vec<_> = text.encode_utf16().collect();
        if text == "*.*" || text == "*" {
            return Ok(Self {
                tokens: vec![Token::Star],
            });
        }
        let mut tokens = Vec::new();
        for (index, unit) in units.iter().copied().enumerate() {
            match unit {
                42 => tokens.push(Token::Star),
                63 => tokens.push(Token::DosQuestion),
                46 if index + 1 == units.len() && index > 0 && units[index - 1] == 42 => {
                    *tokens.last_mut().unwrap() = Token::DosStar;
                }
                46 if units.get(index + 1).is_some_and(|u| matches!(*u, 42 | 63)) => {
                    tokens.push(Token::DosDot)
                }
                0..=31 | 58 | 92 | 124 => {
                    return Err(error(123, "invalid search mask character"));
                }
                value => tokens.push(Token::Literal(value)),
            }
        }
        Ok(Self { tokens })
    }
    fn cost(&self, name: &str) -> usize {
        (self.tokens.len() + 1) * (name.encode_utf16().count() + 1)
    }
    fn matches(&self, name: &str) -> bool {
        let name: Vec<_> = name.encode_utf16().collect();
        let last_dot = name.iter().rposition(|u| *u == 46);
        let mut states = vec![false; name.len() + 1];
        states[0] = true;
        for token in &self.tokens {
            let mut next = vec![false; name.len() + 1];
            for index in 0..=name.len() {
                match token {
                    Token::Star | Token::DosStar => {
                        next[index] |= states[index];
                        if index < name.len()
                            && next[index]
                            && (!matches!(token, Token::DosStar) || Some(index) != last_dot)
                        {
                            next[index + 1] = true;
                        }
                    }
                    Token::DosQuestion => {
                        if states[index] {
                            if index == name.len() || name[index] == 46 {
                                next[index] = true;
                            } else {
                                next[index + 1] = true;
                            }
                        }
                    }
                    Token::DosDot => {
                        if states[index] {
                            if index == name.len() {
                                next[index] = true;
                            } else if name[index] == 46 {
                                next[index + 1] = true;
                            }
                        }
                    }
                    Token::Literal(value) => {
                        if states[index] && index < name.len() && name[index] == *value {
                            next[index + 1] = true;
                        }
                    }
                }
            }
            states = next;
        }
        states[name.len()]
    }
}
pub fn reserved_search(handle: u64) -> bool {
    (SEARCH_FIRST..SEARCH_END).contains(&handle)
}
#[derive(Clone, Debug)]
struct Search {
    owner: u64,
    query: String,
    entries: Vec<Entry>,
    index: usize,
    bytes: usize,
}
#[derive(Debug)]
pub struct FirstPlan {
    pub handle: u64,
    search: Search,
}
impl FirstPlan {
    pub fn entry(&self) -> &Entry {
        &self.search.entries[0]
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct SearchReport {
    pub handle: u64,
    pub owner: u64,
    pub query: String,
    pub snapshot_entries: usize,
    pub consumed: usize,
}
#[derive(Clone, Debug, Serialize)]
pub struct EnumerationReport {
    pub active: Vec<SearchReport>,
    pub snapshot_bytes: usize,
    pub lifetime_handles: u64,
    pub scope: &'static str,
}
#[derive(Clone, Debug, Default)]
pub struct Searches {
    active: BTreeMap<u64, Search>,
    issued: u64,
    bytes: usize,
}
impl Searches {
    pub fn plan_first(&self, owner: u64, query: &str, entries: Vec<Entry>) -> Result<FirstPlan> {
        if owner == 0 {
            return Err(error(6, "invalid guest search owner"));
        }
        if entries.is_empty() {
            return Err(error(2, "no guest entries match the search"));
        }
        if self.active.len() >= MAX_SEARCHES || self.issued >= (SEARCH_END - SEARCH_FIRST) / 4 {
            return Err(error(4, "search handle lifetime/active capacity"));
        }
        let cost = entries
            .iter()
            .try_fold(query.len(), |sum, e| {
                sum.checked_add(e.path.len() + e.name.len() + 80)
            })
            .ok_or_else(|| error(8, "search snapshot capacity"))?;
        if self
            .bytes
            .checked_add(cost)
            .is_none_or(|n| n > MAX_SNAPSHOT_BYTES)
        {
            return Err(error(8, "search snapshot capacity"));
        }
        Ok(FirstPlan {
            handle: SEARCH_FIRST + self.issued * 4,
            search: Search {
                owner,
                query: query.into(),
                entries,
                index: 1,
                bytes: cost,
            },
        })
    }
    pub fn commit_first(&mut self, plan: FirstPlan) -> Result<u64> {
        if plan.handle != SEARCH_FIRST + self.issued * 4 || self.active.contains_key(&plan.handle) {
            return Err(error(6, "stale guest search plan"));
        }
        let handle = plan.handle;
        self.bytes += plan.search.bytes;
        self.active.insert(handle, plan.search);
        self.issued += 1;
        Ok(handle)
    }
    fn search(&self, owner: u64, handle: u64) -> Result<&Search> {
        self.active
            .get(&handle)
            .filter(|s| s.owner == owner)
            .ok_or_else(|| error(6, "invalid, foreign or retired search handle"))
    }
    pub fn peek_next(&self, owner: u64, handle: u64) -> Result<&Entry> {
        let search = self.search(owner, handle)?;
        search
            .entries
            .get(search.index)
            .ok_or_else(|| error(18, "no more guest entries"))
    }
    pub fn advance(&mut self, owner: u64, handle: u64) -> Result<()> {
        self.peek_next(owner, handle)?;
        self.active.get_mut(&handle).unwrap().index += 1;
        Ok(())
    }
    pub fn close(&mut self, owner: u64, handle: u64) -> Result<()> {
        self.search(owner, handle)?;
        let search = self.active.remove(&handle).unwrap();
        self.bytes -= search.bytes;
        Ok(())
    }
    pub fn cleanup_process(&mut self, owner: u64) -> usize {
        let handles: Vec<_> = self
            .active
            .iter()
            .filter(|(_, s)| s.owner == owner)
            .map(|(h, _)| *h)
            .collect();
        for handle in &handles {
            let search = self.active.remove(handle).unwrap();
            self.bytes -= search.bytes;
        }
        handles.len()
    }
    pub fn report(&self) -> EnumerationReport {
        EnumerationReport {
            active: self
                .active
                .iter()
                .map(|(handle, s)| SearchReport {
                    handle: *handle,
                    owner: s.owner,
                    query: s.query.clone(),
                    snapshot_entries: s.entries.len(),
                    consumed: s.index,
                })
                .collect(),
            snapshot_bytes: self.bytes,
            lifetime_handles: self.issued,
            scope: "Bounded snapshots of actual guest catalog entries, deterministic order using existing VFS lowercase authority. Typed process-owned search handles, no host filesystem/short aliases/manufactured dot entries. DOS wildcard translation supports literal,* and ? with explicit unsupported grammar refusal.",
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn file(fs: &mut VirtualFileSystem, path: &str, data: &[u8]) {
        let (h, _) = fs.open(path, 0xc0000000, 3, 2, 1).unwrap();
        fs.write(h, 1, data).unwrap();
        fs.close(h, 1).unwrap();
    }
    #[test]
    fn directories_metadata_readonly_and_cwd_share_actual_catalog_authority() {
        let mut fs = VirtualFileSystem::with_filetime(123);
        fs.create_directory("Child").unwrap();
        assert_eq!(fs.create_directory("child").unwrap_err().win32, 183);
        file(&mut fs, "Child\\a.txt", b"abc");
        assert_eq!(fs.metadata("CHILD/a.txt").unwrap().size, 3);
        assert_eq!(fs.metadata("Child").unwrap().attributes, 0x10);
        assert_eq!(fs.remove_directory("Child").unwrap_err().win32, 145);
        fs.set_attributes("Child/a.txt", 1).unwrap();
        assert_eq!(
            fs.open("Child/a.txt", 0x40000000, 3, 3, 1)
                .unwrap_err()
                .win32,
            5
        );
        let plan = fs.directory_plan("Child").unwrap();
        assert_eq!(plan.display(), "C:\\workspace\\Child");
        fs.commit_directory(plan).unwrap();
        assert_eq!(fs.metadata("a.txt").unwrap().times, [123; 3]);
        assert_eq!(fs.remove_directory(".").unwrap_err().win32, 5);
        assert_eq!(fs.directory_plan("a.txt").unwrap_err().win32, 267);
        assert_eq!(fs.directory_plan("missing").unwrap_err().win32, 3);
    }
    #[test]
    fn wildcard_vectors_include_extensionless_question_and_dos_dot_boundaries() {
        for (mask, name, expected) in [
            ("*.*", "readme", true),
            ("*.txt", "a.txt", true),
            ("*.txt", "a.txt.bak", false),
            ("a?.txt", "a.txt", true),
            ("a?.txt", "ab.txt", true),
            ("a?.txt", "abc.txt", false),
            ("*.", "readme", true),
            ("*.", "a.txt", false),
            ("a.*", "a", true),
            ("a.??", "a.txt", false),
            ("a.??", "a.tx", true),
            ("?.txt", "😀.txt", false),
            ("??.txt", "😀.txt", true),
        ] {
            assert_eq!(
                Pattern::parse(mask).unwrap().matches(name),
                expected,
                "{mask} {name}"
            );
        }
        for mask in ["[ab]*", "*.~1", "<", ">"] {
            assert_eq!(Pattern::parse(mask).unwrap_err().win32, 50);
        }
    }
    #[test]
    fn enumeration_is_immediate_sorted_bounded_snapshot_and_typed_owned_lifetime() {
        let mut fs = VirtualFileSystem::new();
        fs.create_directory("sub").unwrap();
        file(&mut fs, "z.txt", b"z");
        file(&mut fs, "readme", b"read");
        file(&mut fs, "sub/nested", b"no");
        let entries = fs.enumerate("*.*").unwrap();
        assert_eq!(
            entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
            ["readme", "sub", "z.txt"]
        );
        let mut searches = Searches::default();
        let plan = searches.plan_first(1, "*.*", entries).unwrap();
        assert_eq!(plan.entry().metadata.size, 4);
        let handle = searches.commit_first(plan).unwrap();
        assert!(reserved_search(handle));
        assert_eq!(searches.peek_next(2, handle).unwrap_err().win32, 6);
        fs.create_directory("later").unwrap();
        assert_eq!(searches.peek_next(1, handle).unwrap().name, "sub");
        searches.advance(1, handle).unwrap();
        assert_eq!(searches.peek_next(1, handle).unwrap().name, "z.txt");
        searches.advance(1, handle).unwrap();
        assert_eq!(searches.peek_next(1, handle).unwrap_err().win32, 18);
        searches.close(1, handle).unwrap();
        assert_eq!(searches.peek_next(1, handle).unwrap_err().win32, 6);
        assert_eq!(searches.report().snapshot_bytes, 0);
    }
    #[test]
    fn find_data_and_path_plans_preserve_exact_units_sizes_and_pointer_offsets() {
        let mut fs = VirtualFileSystem::new();
        file(&mut fs, "café.txt", b"abc");
        let e = fs.enumerate("*.TXT").unwrap().remove(0);
        let a = e.find_data(false).unwrap();
        let w = e.find_data(true).unwrap();
        assert_eq!(a.len(), 320);
        assert_eq!(w.len(), 592);
        assert_eq!(&a[44..53], b"caf\xe9.txt\0");
        assert_eq!(u32::from_le_bytes(a[32..36].try_into().unwrap()), 3);
        let p = fs.full_path("../workspace/café.txt", false, 1).unwrap();
        assert!(p.bytes.is_none());
        let p = fs.full_path("../workspace/café.txt", false, 100).unwrap();
        assert_eq!(p.bytes.unwrap(), b"C:\\workspace\\caf\xe9.txt\0");
        assert_eq!(p.file_part_offset, Some(13));
        assert_eq!(
            fs.full_path("é/a.txt", false, 100)
                .unwrap()
                .file_part_offset,
            Some(15)
        );
        assert_eq!(
            fs.full_path("é/a.txt", true, 100).unwrap().file_part_offset,
            Some(30)
        );
        assert_eq!(fs.full_path("*.*", true, 100).unwrap().result, 16);
        assert_eq!(fs.long_path("absent", true, 100).unwrap_err().win32, 2);
    }
    #[test]
    fn catalog_names_keep_first_display_case_across_case_insensitive_overwrite() {
        let mut fs = VirtualFileSystem::new();
        fs.create_directory("MiXeD").unwrap();
        file(&mut fs, "MiXeD/CAFé.TXT", b"first");
        file(&mut fs, "mixed/café.txt", b"next");
        let directory = fs.enumerate("*").unwrap();
        assert_eq!(directory[0].name, "MiXeD");
        let files = fs.enumerate("MIXED/*.txt").unwrap();
        assert_eq!(files[0].name, "CAFé.TXT");
        assert_eq!(files[0].metadata.size, 4);
        assert_eq!(
            &files[0].find_data(false).unwrap()[44..53],
            b"CAF\xe9.TXT\0"
        );
    }
    #[test]
    fn search_capacity_and_owner_cleanup_publish_no_unbounded_state() {
        let mut fs = VirtualFileSystem::new();
        file(&mut fs, "x", b"");
        let entries = fs.enumerate("*").unwrap();
        let mut searches = Searches::default();
        for _ in 0..MAX_SEARCHES {
            let plan = searches.plan_first(1, "*", entries.clone()).unwrap();
            searches.commit_first(plan).unwrap();
        }
        assert_eq!(
            searches
                .plan_first(1, "*", entries.clone())
                .unwrap_err()
                .win32,
            4
        );
        assert_eq!(searches.cleanup_process(1), MAX_SEARCHES);
        assert_eq!(searches.report().snapshot_bytes, 0);
        searches.issued = (SEARCH_END - SEARCH_FIRST) / 4;
        assert_eq!(searches.plan_first(1, "*", entries).unwrap_err().win32, 4);
    }
    #[test]
    fn readonly_attribute_does_not_revoke_already_granted_handle_rights() {
        let mut fs = VirtualFileSystem::new();
        let (handle, _) = fs.open("held", 0xc0000000, 3, 2, 1).unwrap();
        fs.set_attributes("held", 1).unwrap();
        assert_eq!(fs.write(handle, 1, b"kept").unwrap(), 4);
        assert_eq!(fs.open("held", 0x40000000, 3, 3, 1).unwrap_err().win32, 5);
        assert_eq!(fs.metadata("held").unwrap().size, 4);
    }
}

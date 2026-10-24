//! Bounded deterministic guest registry. No operation accesses the host registry.
//!
//! Lookup folds case; enumeration preserves insertion order. The four roots are
//! independent guest namespaces, not a host HKCR merge or a host current user.
//! WOW64 views, remote keys, security descriptors and notifications are outside
//! this profile. Unlike the legacy bridge, issued-handle access is enforced.
use std::collections::BTreeMap;
use thiserror::Error;
use unicode_casefold::UnicodeCaseFold;
#[path = "registry_native.rs"]
mod native;
pub use native::{
    FILE_HANDLE_RESERVATIONS, NATIVE_HANDLE_END, NATIVE_HANDLE_FIRST, NativeError,
    NativeHandleClass, NativeHandleEvidence, NativeHandleReport, NativeOpen, NativeOpenPlan,
    NativeQuery, NativeQueryPlan, NativeResult, STATUS_ACCESS_DENIED, STATUS_INVALID_HANDLE,
    STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
    USER_HANDLE_END, USER_HANDLE_FIRST, reserved_file_handle_next,
};

pub const HKCR: u64 = 0x80000000;
pub const HKCU: u64 = 0x80000001;
pub const HKLM: u64 = 0x80000002;
pub const HKU: u64 = 0x80000003;
pub const KEY_QUERY_VALUE: u32 = 1;
pub const KEY_SET_VALUE: u32 = 2;
pub const KEY_CREATE_SUB_KEY: u32 = 4;
pub const KEY_ENUMERATE_SUB_KEYS: u32 = 8;
pub const KEY_READ: u32 = 0x20019;
pub const KEY_WRITE: u32 = 0x20006;
pub const KEY_ALL_ACCESS: u32 = 0xf003f;
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 11;
pub const MAX_VALUE: usize = 1024 * 1024;
pub const MAX_KEYS: usize = 20_000;
pub const MAX_HANDLES: usize = 40_000;
pub const MAX_VALUES: usize = 40_000;
pub const MAX_TOTAL: usize = 64 * 1024 * 1024;
const ROOTS: [(u64, &str, &str); 4] = [
    (HKCR, "HKEY_CLASSES_ROOT", "HKCR"),
    (HKCU, "HKEY_CURRENT_USER", "HKCU"),
    (HKLM, "HKEY_LOCAL_MACHINE", "HKLM"),
    (HKU, "HKEY_USERS", "HKU"),
];

#[derive(Debug, Error)]
#[error("Guest registry: {reason} (Win32 {win32})")]
pub struct RegistryError {
    pub win32: u32,
    pub reason: &'static str,
}
pub type Result<T> = std::result::Result<T, RegistryError>;
fn error(win32: u32, reason: &'static str) -> RegistryError {
    RegistryError { win32, reason }
}
fn fold(text: &str) -> String {
    text.case_fold().collect()
}
pub fn canonical_handle(handle: u64) -> u64 {
    let low = handle & 0xffffffff;
    if handle >> 32 == 0xffffffff && ROOTS.iter().any(|root| root.0 == low) {
        low
    } else {
        handle
    }
}
fn valid_access(access: u32) -> Result<()> {
    if access & !KEY_ALL_ACCESS != 0 {
        return Err(error(50, "WOW64 views or unsupported registry access mask"));
    }
    Ok(())
}
fn valid_name(name: &str) -> Result<()> {
    if name.encode_utf16().count() > 16_383 || name.contains('\0') {
        return Err(error(50, "registry value name exceeds profile"));
    }
    Ok(())
}
fn subpath(parent: &str, subkey: &str) -> Result<String> {
    if subkey.is_empty() {
        return Ok(parent.into());
    }
    let subkey = subkey.trim_matches('\\');
    if subkey.is_empty()
        || subkey.split('\\').any(|part| {
            part.is_empty()
                || matches!(part, "." | "..")
                || part.encode_utf16().count() > 255
                || part.contains(['\0', '*', '?', '[', ']'])
        })
    {
        return Err(error(50, "unsupported registry path"));
    }
    let path = format!("{parent}\\{subkey}");
    if path.encode_utf16().count() > 32_767 {
        return Err(error(50, "registry path exceeds profile"));
    }
    Ok(path)
}
/// Config seed paths use this same existing authority normalizer.
pub fn canonical_seed_path(path: &str) -> Result<String> {
    full_path(path)
}
fn full_path(path: &str) -> Result<String> {
    let (root, tail) = path.split_once('\\').unwrap_or((path, ""));
    let root = ROOTS
        .iter()
        .find(|(_, long, short)| {
            root.eq_ignore_ascii_case(long) || root.eq_ignore_ascii_case(short)
        })
        .ok_or_else(|| error(50, "unsupported registry root"))?;
    subpath(root.1, tail)
}
fn text_type(value_type: u32) -> bool {
    matches!(value_type, REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ)
}
fn validate_value(value_type: u32, data: &[u8]) -> Result<()> {
    if !matches!(
        value_type,
        REG_SZ | REG_EXPAND_SZ | REG_BINARY | REG_DWORD | REG_MULTI_SZ | REG_QWORD
    ) || data.len() > MAX_VALUE
    {
        return Err(error(50, "unsupported registry type or value size"));
    }
    Ok(())
}

// Undefined CP1252 slots decode to U+FFFD, matching the legacy bridge's
// errors="replace" profile. A/W conversions never reinterpret binary data.
const CP1252: [char; 32] = [
    '\u{20ac}', '\u{fffd}', '\u{201a}', '\u{192}', '\u{201e}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{2c6}', '\u{2030}', '\u{160}', '\u{2039}', '\u{152}', '\u{fffd}', '\u{17d}', '\u{fffd}',
    '\u{fffd}', '\u{2018}', '\u{2019}', '\u{201c}', '\u{201d}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{2dc}', '\u{2122}', '\u{161}', '\u{203a}', '\u{153}', '\u{fffd}', '\u{17e}', '\u{178}',
];
/// Lossy value conversion matches the legacy bridge. Guest API names should
/// use `decode_name`, which rejects malformed UTF16 rather than inventing names.
pub fn decode_text(data: &[u8], wide: bool) -> String {
    if wide {
        let units = data
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
        let mut text: String = char::decode_utf16(units)
            .map(|unit| unit.unwrap_or('\u{fffd}'))
            .collect();
        if data.len() % 2 != 0 {
            text.push('\u{fffd}');
        }
        text
    } else {
        data.iter()
            .map(|byte| match byte {
                0x80..=0x9f => CP1252[usize::from(*byte - 0x80)],
                byte => char::from(*byte),
            })
            .collect()
    }
}
pub fn decode_name(data: &[u8], wide: bool) -> Result<String> {
    if wide {
        if data.len() % 2 != 0 {
            return Err(error(50, "odd-length UTF16 registry name"));
        }
        let units: Vec<_> = data
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16(&units).map_err(|_| error(50, "malformed UTF16 registry name"))
    } else {
        Ok(decode_text(data, false))
    }
}
/// Registry A encoding is the guest CP1252 profile; W lengths use UTF16 units.
/// Set `nul` for API names, not for raw values whose termination is caller owned.
pub fn encode_text(text: &str, wide: bool, nul: bool) -> Vec<u8> {
    let mut bytes = if wide {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    } else {
        text.chars()
            .map(|character| {
                if (character as u32) < 0x80 || (0xa0..=0xff).contains(&(character as u32)) {
                    character as u8
                } else {
                    CP1252
                        .iter()
                        .position(|candidate| *candidate == character && character != '\u{fffd}')
                        .map_or(b'?', |index| 0x80 + index as u8)
                }
            })
            .collect::<Vec<_>>()
    };
    if nul {
        bytes.extend(if wide { &[0, 0][..] } else { &[0][..] });
    }
    bytes
}
pub fn text_units(text: &str, wide: bool) -> u32 {
    if wide {
        text.encode_utf16().count() as u32
    } else {
        text.chars().count() as u32
    }
}

#[derive(Clone, Debug)]
struct StoredValue {
    name: String,
    value_type: u32,
    data: Vec<u8>,
    wide: bool,
}
impl StoredValue {
    fn encoded(&self, wide: bool) -> Result<RegistryValue> {
        let data = if text_type(self.value_type) && wide != self.wide {
            encode_text(&decode_text(&self.data, self.wide), wide, false)
        } else {
            self.data.clone()
        };
        if data.len() > MAX_VALUE {
            return Err(error(50, "converted registry value exceeds profile"));
        }
        Ok(RegistryValue {
            value_type: self.value_type,
            required_size: data.len() as u32,
            data,
        })
    }
}
#[derive(Clone, Debug)]
struct Key {
    path: String,
    preset: bool,
    values: Vec<StoredValue>,
}
#[derive(Clone, Debug)]
struct Handle {
    domain: native::Domain,
    key: u64,
    owner: u64,
    access: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryValue {
    pub value_type: u32,
    pub data: Vec<u8>,
    /// May exceed data.len() for legacy-compatible REG_EXPAND_SZ reads.
    pub required_size: u32,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnumeratedValue {
    pub name: String,
    pub value: RegistryValue,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpenResult {
    pub handle: u64,
    pub disposition: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyInfo {
    pub subkeys: u32,
    pub max_subkey_units: u32,
    pub values: u32,
    pub max_value_name_units: u32,
    pub max_value_data_bytes: u32,
    pub filetime: u64,
}
#[derive(Clone, Debug)]
pub struct Registry {
    keys: BTreeMap<u64, Key>,
    paths: BTreeMap<String, u64>,
    handles: BTreeMap<u64, Handle>,
    next_key: u64,
    next_handle: u64,
    native_issued: u64,
    native_architecture: Option<crate::pe::Architecture>,
    total: usize,
    values: usize,
    filetime: u64,
}
impl Default for Registry {
    fn default() -> Self {
        Self::new(0)
    }
}
impl Registry {
    pub fn new(filetime: u64) -> Self {
        let mut state = Self {
            keys: BTreeMap::new(),
            paths: BTreeMap::new(),
            handles: BTreeMap::new(),
            next_key: 5,
            next_handle: USER_HANDLE_FIRST,
            native_issued: 0,
            native_architecture: None,
            total: 0,
            values: 0,
            filetime,
        };
        for (index, (_, path, _)) in ROOTS.iter().enumerate() {
            let id = index as u64 + 1;
            state.paths.insert(fold(path), id);
            state.keys.insert(
                id,
                Key {
                    path: (*path).into(),
                    preset: true,
                    values: Vec::new(),
                },
            );
        }
        state
    }
    fn resolve(&self, owner: u64, handle: u64, access: u32) -> Result<u64> {
        let handle = canonical_handle(handle);
        let id = if let Some(index) = ROOTS.iter().position(|root| root.0 == handle) {
            index as u64 + 1
        } else {
            let issued = self
                .handles
                .get(&handle)
                .filter(|issued| issued.owner == owner && issued.domain == native::Domain::User)
                .ok_or_else(|| error(6, "unknown, closed or other-process registry handle"))?;
            if issued.access & access != access {
                return Err(error(5, "registry handle access denied"));
            }
            issued.key
        };
        if !self.keys.contains_key(&id) {
            return Err(error(1018, "registry key has been deleted"));
        }
        Ok(id)
    }
    pub fn path(&self, owner: u64, handle: u64) -> Result<&str> {
        Ok(&self.keys[&self.resolve(owner, handle, 0)?].path)
    }
    fn pending_paths(&self, path: &str) -> Vec<String> {
        let mut prefix = String::new();
        let mut missing = Vec::new();
        for part in path.split('\\') {
            if !prefix.is_empty() {
                prefix.push('\\');
            }
            prefix.push_str(part);
            if !self.paths.contains_key(&fold(&prefix)) {
                missing.push(prefix.clone());
            }
        }
        missing
    }
    fn add_paths(&mut self, paths: Vec<String>, preset: bool) {
        for path in paths {
            let id = self.next_key;
            self.next_key += 1;
            self.paths.insert(fold(&path), id);
            self.keys.insert(
                id,
                Key {
                    path,
                    preset,
                    values: Vec::new(),
                },
            );
        }
    }
    fn check_key_limit(&self, added: usize) -> Result<()> {
        if self.keys.len() + added > MAX_KEYS || self.next_key.checked_add(added as u64).is_none() {
            Err(error(50, "registry key limit"))
        } else {
            Ok(())
        }
    }
    fn check_handle_limit(&self) -> Result<()> {
        if self.handles.len() >= MAX_HANDLES
            || self.next_handle >= USER_HANDLE_END
            || self.next_handle.checked_add(8).is_none()
        {
            Err(error(50, "registry handle limit"))
        } else {
            Ok(())
        }
    }
    fn issue(&mut self, owner: u64, key: u64, access: u32) -> u64 {
        let handle = self.next_handle;
        self.next_handle += 8;
        self.handles.insert(
            handle,
            Handle {
                key,
                owner,
                access,
                domain: native::Domain::User,
            },
        );
        handle
    }
    /// Import configured guest keys. Intermediate parents are materialized in
    /// deterministic order. Preset deletion remains unsupported as in Python.
    pub fn seed_key(&mut self, path: &str) -> Result<()> {
        let path = full_path(path)?;
        let missing = self.pending_paths(&path);
        self.check_key_limit(missing.len())?;
        self.add_paths(missing, true);
        self.keys.get_mut(&self.paths[&fold(&path)]).unwrap().preset = true;
        Ok(())
    }
    /// Input is already decoded config bytes. The adapter owns config hex,
    /// base64 and integer parsing. Config `default` denotes the unnamed value.
    pub fn seed_value(
        &mut self,
        path: &str,
        name: &str,
        value_type: u32,
        data: &[u8],
        wide: bool,
    ) -> Result<()> {
        valid_name(name)?;
        validate_value(value_type, data)?;
        let path = full_path(path)?;
        let name = if name.eq_ignore_ascii_case("default") {
            ""
        } else {
            name
        };
        let previous = self
            .paths
            .get(&fold(&path))
            .and_then(|id| {
                self.keys[id]
                    .values
                    .iter()
                    .find(|value| fold(&value.name) == fold(name))
            })
            .map(|value| value.data.len());
        self.check_value_limit(previous, data.len())?;
        self.seed_key(&path)?;
        let id = self.paths[&fold(&path)];
        self.store(id, name, value_type, data, wide);
        Ok(())
    }
    pub fn open(
        &mut self,
        owner: u64,
        parent: u64,
        subkey: &str,
        desired_access: u32,
    ) -> Result<u64> {
        let id = self.resolve(owner, parent, 0)?;
        valid_access(desired_access)?;
        let path = subpath(&self.keys[&id].path, subkey)?;
        let key = *self
            .paths
            .get(&fold(&path))
            .ok_or_else(|| error(2, "registry key not found"))?;
        if subkey.is_empty() && ROOTS.iter().any(|root| root.0 == canonical_handle(parent)) {
            return Ok(canonical_handle(parent));
        }
        self.check_handle_limit()?;
        Ok(self.issue(owner, key, desired_access))
    }
    pub fn create(
        &mut self,
        owner: u64,
        parent: u64,
        subkey: &str,
        desired_access: u32,
    ) -> Result<OpenResult> {
        let id = self.resolve(
            owner,
            parent,
            if subkey.is_empty() {
                0
            } else {
                KEY_CREATE_SUB_KEY
            },
        )?;
        valid_access(desired_access)?;
        let path = subpath(&self.keys[&id].path, subkey)?;
        let existed = self.paths.contains_key(&fold(&path));
        let root_alias =
            subkey.is_empty() && ROOTS.iter().any(|root| root.0 == canonical_handle(parent));
        if !root_alias {
            self.check_handle_limit()?;
        }
        let missing = self.pending_paths(&path);
        self.check_key_limit(missing.len())?;
        self.add_paths(missing, false);
        let key = self.paths[&fold(&path)];
        let handle = if root_alias {
            canonical_handle(parent)
        } else {
            self.issue(owner, key, desired_access)
        };
        Ok(OpenResult {
            handle,
            disposition: if existed { 2 } else { 1 },
        })
    }
    pub fn close(&mut self, owner: u64, handle: u64) -> Result<()> {
        let handle = canonical_handle(handle);
        if ROOTS.iter().any(|root| root.0 == handle) {
            return Ok(());
        }
        if self
            .handles
            .get(&handle)
            .is_none_or(|issued| issued.owner != owner || issued.domain != native::Domain::User)
        {
            return Err(error(6, "unknown, closed or other-process registry handle"));
        }
        // Deleting a key does not prevent closing its outstanding handles.
        self.handles.remove(&handle);
        Ok(())
    }
    pub fn cleanup_process(&mut self, owner: u64) -> usize {
        let before = self.handles.len();
        self.handles.retain(|_, issued| issued.owner != owner);
        before - self.handles.len()
    }
    pub fn delete_key(&mut self, owner: u64, parent: u64, subkey: &str) -> Result<()> {
        let parent = self.resolve(owner, parent, 0)?;
        if subkey.is_empty() {
            return Err(error(87, "empty registry deletion path"));
        }
        let path = subpath(&self.keys[&parent].path, subkey)?;
        let normalized = fold(&path);
        let id = *self
            .paths
            .get(&normalized)
            .ok_or_else(|| error(2, "registry key not found"))?;
        let key = &self.keys[&id];
        if key.preset {
            return Err(error(50, "preset registry key deletion is not modeled"));
        }
        let prefix = format!("{normalized}\\");
        if self
            .paths
            .keys()
            .any(|candidate| candidate.starts_with(&prefix))
        {
            return Err(error(5, "registry key has subkeys"));
        }
        let key = self.keys.remove(&id).unwrap();
        self.total -= key
            .values
            .iter()
            .map(|value| value.data.len())
            .sum::<usize>();
        self.values -= key.values.len();
        self.paths.remove(&normalized);
        Ok(())
    }
    fn check_value_limit(&self, previous: Option<usize>, length: usize) -> Result<()> {
        if self.total - previous.unwrap_or(0) + length > MAX_TOTAL
            || (previous.is_none() && self.values >= MAX_VALUES)
        {
            return Err(error(50, "registry total value storage limit"));
        }
        Ok(())
    }
    fn store(&mut self, id: u64, name: &str, value_type: u32, data: &[u8], wide: bool) {
        let key = self.keys.get_mut(&id).unwrap();
        if let Some(value) = key
            .values
            .iter_mut()
            .find(|value| fold(&value.name) == fold(name))
        {
            self.total = self.total - value.data.len() + data.len();
            // Replacing data keeps original display name and enumeration slot.
            value.value_type = value_type;
            value.data = data.to_vec();
            value.wide = wide;
        } else {
            key.values.push(StoredValue {
                name: name.into(),
                value_type,
                data: data.to_vec(),
                wide,
            });
            self.total += data.len();
            self.values += 1;
        }
    }
    pub fn set_value(
        &mut self,
        owner: u64,
        handle: u64,
        name: &str,
        value_type: u32,
        data: &[u8],
        wide: bool,
    ) -> Result<()> {
        let id = self.resolve(owner, handle, KEY_SET_VALUE)?;
        valid_name(name)?;
        validate_value(value_type, data)?;
        let previous = self.keys[&id]
            .values
            .iter()
            .find(|value| fold(&value.name) == fold(name))
            .map(|value| value.data.len());
        self.check_value_limit(previous, data.len())?;
        self.store(id, name, value_type, data, wide);
        Ok(())
    }
    fn value(&self, id: u64, name: &str, wide: bool) -> Result<RegistryValue> {
        valid_name(name)?;
        self.keys[&id]
            .values
            .iter()
            .find(|value| fold(&value.name) == fold(name))
            .ok_or_else(|| error(2, "registry value not found"))?
            .encoded(wide)
    }
    pub fn query_value(
        &self,
        owner: u64,
        handle: u64,
        name: &str,
        wide: bool,
    ) -> Result<RegistryValue> {
        // https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexw
        // Raw query bytes are not guaranteed to have a string terminator.
        self.value(self.resolve(owner, handle, KEY_QUERY_VALUE)?, name, wide)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn get_value(
        &self,
        owner: u64,
        handle: u64,
        subkey: &str,
        name: &str,
        flags: u32,
        wide: bool,
        environment: &BTreeMap<String, String>,
    ) -> Result<RegistryValue> {
        if flags & !0x1000ffff != 0 || !matches!(flags & 0xffff, 0 | 0xffff) {
            return Err(error(
                50,
                "registry type filter or expansion flags are not modeled",
            ));
        }
        let mut id = self.resolve(owner, handle, KEY_QUERY_VALUE)?;
        if !subkey.is_empty() {
            let path = subpath(&self.keys[&id].path, subkey)?;
            id = *self
                .paths
                .get(&fold(&path))
                .ok_or_else(|| error(2, "registry key not found"))?;
        }
        let mut value = self.value(id, name, wide)?;
        if value.value_type == REG_EXPAND_SZ && flags & 0x10000000 == 0 {
            let original = value.data.len();
            let text = if wide {
                decode_name(&value.data, true)?
            } else {
                if value
                    .data
                    .iter()
                    .any(|byte| matches!(byte, 0x81 | 0x8d | 0x8f | 0x90 | 0x9d))
                {
                    return Err(error(50, "invalid CP1252 REG_EXPAND_SZ data"));
                }
                decode_text(&value.data, false)
            };
            let text = text.split('\0').next().unwrap_or("");
            let environment: BTreeMap<_, _> = environment
                .iter()
                .map(|(name, value)| (fold(name), value))
                .collect();
            let mut expanded = String::new();
            let mut remaining = text;
            while let Some(start) = remaining.find('%') {
                let after = &remaining[start + 1..];
                let Some(end) = after.find('%') else {
                    break;
                };
                expanded.push_str(&remaining[..start]);
                if end == 0 {
                    // Python's legacy %([^%]+)% match can begin at the second
                    // percent in %%NAME%; consume only the first empty marker.
                    expanded.push('%');
                    remaining = after;
                    continue;
                }
                let token = &after[..end];
                if let Some(replacement) = environment.get(&fold(token)) {
                    expanded.push_str(replacement);
                } else {
                    expanded.push_str(&remaining[start..start + end + 2]);
                }
                if expanded.len() > 4 * MAX_VALUE {
                    return Err(error(50, "expanded registry value exceeds profile"));
                }
                remaining = &after[end + 1..];
            }
            expanded.push_str(remaining);
            let data = encode_text(&expanded, wide, true);
            if data.len() > MAX_VALUE {
                return Err(error(50, "expanded registry value exceeds profile"));
            }
            value = RegistryValue {
                value_type: REG_SZ,
                required_size: original.max(data.len()) as u32,
                data,
            };
        }
        // https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-reggetvaluew
        // Deliberate correction to the legacy bridge: GetValue guarantees
        // terminated string data, while QueryValueEx returns exact raw bytes.
        if text_type(value.value_type) {
            let unit = if wide { 2 } else { 1 };
            if value.data.len() % unit != 0 {
                return Err(error(50, "odd-length UTF16 RegGetValue data"));
            }
            let required_nuls = if value.value_type == REG_MULTI_SZ {
                2
            } else {
                1
            };
            let existing_nuls = value
                .data
                .chunks_exact(unit)
                .rev()
                .take_while(|chunk| chunk.iter().all(|byte| *byte == 0))
                .count();
            for _ in existing_nuls..required_nuls {
                value.data.extend(std::iter::repeat_n(0, unit));
            }
            if value.data.len() > MAX_VALUE {
                return Err(error(50, "terminated registry value exceeds profile"));
            }
            value.required_size = value.required_size.max(value.data.len() as u32);
        }
        Ok(value)
    }
    pub fn enum_value(
        &self,
        owner: u64,
        handle: u64,
        index: u32,
        wide: bool,
    ) -> Result<EnumeratedValue> {
        let id = self.resolve(owner, handle, KEY_QUERY_VALUE)?;
        let value = self.keys[&id]
            .values
            .get(index as usize)
            .ok_or_else(|| error(259, "no more registry values"))?;
        Ok(EnumeratedValue {
            name: value.name.clone(),
            value: value.encoded(wide)?,
        })
    }
    fn children(&self, id: u64) -> Vec<String> {
        let parent = &self.keys[&id].path;
        let prefix = format!("{}\\", fold(parent));
        self.keys
            .values()
            .filter_map(|key| {
                let normalized = fold(&key.path);
                let rest = normalized.strip_prefix(&prefix)?;
                if rest.contains('\\') {
                    return None;
                }
                // Split at the final separator, rather than using folded byte
                // offsets; Unicode case folding can change UTF8 byte lengths.
                key.path.rsplit_once('\\').map(|(_, name)| name.to_owned())
            })
            .collect()
    }
    pub fn enum_key(&self, owner: u64, handle: u64, index: u32) -> Result<String> {
        let id = self.resolve(owner, handle, KEY_ENUMERATE_SUB_KEYS)?;
        self.children(id)
            .into_iter()
            .nth(index as usize)
            .ok_or_else(|| error(259, "no more registry subkeys"))
    }
    pub fn query_info(&self, owner: u64, handle: u64, wide: bool) -> Result<KeyInfo> {
        let id = self.resolve(owner, handle, KEY_QUERY_VALUE)?;
        let children = self.children(id);
        let values = &self.keys[&id].values;
        let max_value_data_bytes = values
            .iter()
            .map(|value| value.encoded(wide).map(|value| value.required_size))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max()
            .unwrap_or(0);
        Ok(KeyInfo {
            subkeys: children.len() as u32,
            max_subkey_units: children
                .iter()
                .map(|name| text_units(name, wide))
                .max()
                .unwrap_or(0),
            values: values.len() as u32,
            max_value_name_units: values
                .iter()
                .map(|value| text_units(&value.name, wide))
                .max()
                .unwrap_or(0),
            max_value_data_bytes,
            filetime: self.filetime,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn code<T>(result: Result<T>) -> u32 {
        result.err().unwrap().win32
    }
    #[test]
    fn aliases_owners_reopen_and_cleanup() {
        let mut registry = Registry::new(7);
        registry.seed_key("hkcu\\Software\\Example").unwrap();
        let key = registry
            .open(10, 0xffffffff80000001, "software\\EXAMPLE", KEY_ALL_ACCESS)
            .unwrap();
        registry
            .set_value(10, key, "Seen", REG_BINARY, b"\0\xff", false)
            .unwrap();
        assert_eq!(code(registry.query_value(11, key, "Seen", false)), 6);
        registry.close(10, key).unwrap();
        let next = registry
            .open(11, HKCU, "Software\\Example", KEY_READ)
            .unwrap();
        assert_ne!(key, next);
        assert_eq!(
            registry.query_value(11, next, "sEeN", true).unwrap().data,
            b"\0\xff"
        );
        assert_eq!(registry.cleanup_process(10), 0);
        assert_eq!(registry.cleanup_process(11), 1);
        assert_eq!(code(registry.close(11, next)), 6);
        assert_eq!(registry.open(10, HKCU, "", 0).unwrap(), HKCU);
        registry.close(10, 0xffffffff80000001).unwrap();
        assert_eq!(code(registry.open(10, 0x180000001, "", KEY_READ)), 6);
    }
    #[test]
    fn access_masks_and_unsupported_paths_are_explicit() {
        let mut registry = Registry::default();
        let key = registry.create(1, HKCU, "Guest", KEY_READ).unwrap().handle;
        assert_eq!(
            code(registry.set_value(1, key, "x", REG_BINARY, b"x", false)),
            5
        );
        assert_eq!(code(registry.create(1, key, "Child", KEY_READ)), 5);
        assert_eq!(code(registry.open(1, HKCU, "Guest", KEY_READ | 0x100)), 50);
        assert_eq!(
            code(registry.create(1, HKCU, "Bad\\..\\Escape", KEY_ALL_ACCESS)),
            50
        );
        assert_eq!(code(registry.open(1, HKCU, "Missing", KEY_READ)), 2);
        assert_eq!(code(registry.create(1, HKCU, "\\", KEY_READ)), 50);
        let write = registry.open(1, HKCU, "Guest", KEY_WRITE).unwrap();
        assert_eq!(code(registry.query_value(1, write, "x", false)), 5);
        assert_eq!(code(registry.enum_key(1, write, 0)), 5);
    }
    #[test]
    fn raw_values_preserve_bytes_and_convert_only_strings() {
        assert_eq!(code(decode_name(&[0, 0xd8], true)), 50);
        assert_eq!(code(decode_name(&[1], true)), 50);
        assert_eq!(
            decode_name(&encode_text("Guest😀", true, false), true).unwrap(),
            "Guest😀"
        );
        let mut registry = Registry::default();
        let key = registry
            .create(1, HKCU, "Guest", KEY_ALL_ACCESS)
            .unwrap()
            .handle;
        let ansi = [b'A', 0x80, 0xe9, 0];
        registry
            .set_value(1, key, "Text", REG_SZ, &ansi, false)
            .unwrap();
        assert_eq!(
            registry.query_value(1, key, "Text", false).unwrap().data,
            ansi
        );
        assert_eq!(
            registry.query_value(1, key, "Text", true).unwrap().data,
            encode_text("A€é\0", true, false)
        );
        let malformed = [0x00, 0xd8, 0x01];
        registry
            .set_value(1, key, "Raw", REG_SZ, &malformed, true)
            .unwrap();
        assert_eq!(
            registry.query_value(1, key, "Raw", true).unwrap().data,
            malformed
        );
        assert_eq!(
            registry.query_value(1, key, "Raw", false).unwrap().data,
            b"??"
        );
        registry
            .set_value(1, key, "Number", REG_DWORD, b"\x01\x02\x03\x04", false)
            .unwrap();
        assert_eq!(
            registry.query_value(1, key, "Number", true).unwrap().data,
            b"\x01\x02\x03\x04"
        );
        registry
            .set_value(1, key, "Multi", REG_MULTI_SZ, b"a\0b\0\0", false)
            .unwrap();
        assert_eq!(
            registry.query_value(1, key, "Multi", true).unwrap().data,
            encode_text("a\0b\0\0", true, false)
        );
        registry
            .set_value(1, key, "Empty", REG_BINARY, b"", false)
            .unwrap();
        assert_eq!(
            registry
                .query_value(1, key, "Empty", true)
                .unwrap()
                .required_size,
            0
        );
    }
    #[test]
    fn defaults_ordered_enumeration_and_info_use_encoded_units() {
        let mut registry = Registry::new(132000000000000000);
        registry
            .seed_value("HKCU\\Parent", "default", REG_SZ, b"seed\0", false)
            .unwrap();
        let parent = registry.open(1, HKCU, "Parent", KEY_ALL_ACCESS).unwrap();
        assert_eq!(
            registry.query_value(1, parent, "", false).unwrap().data,
            b"seed\0"
        );
        registry
            .set_value(1, parent, "default", REG_BINARY, b"literal", false)
            .unwrap();
        registry
            .set_value(
                1,
                parent,
                "😀",
                REG_SZ,
                &encode_text("wide\0", true, false),
                true,
            )
            .unwrap();
        registry
            .set_value(1, parent, "DEFAULT", REG_BINARY, b"changed", false)
            .unwrap();
        registry.create(1, parent, "Zed", KEY_READ).unwrap();
        registry
            .create(1, parent, "Alpha\\Nested", KEY_READ)
            .unwrap();
        assert_eq!(registry.enum_key(1, parent, 0).unwrap(), "Zed");
        assert_eq!(registry.enum_key(1, parent, 1).unwrap(), "Alpha");
        assert_eq!(code(registry.enum_key(1, parent, 2)), 259);
        assert_eq!(registry.enum_value(1, parent, 0, false).unwrap().name, "");
        assert_eq!(
            registry.enum_value(1, parent, 1, false).unwrap().name,
            "default"
        );
        assert_eq!(
            registry.enum_value(1, parent, 1, false).unwrap().value.data,
            b"changed"
        );
        assert_eq!(code(registry.enum_value(1, parent, 3, false)), 259);
        let info = registry.query_info(1, parent, true).unwrap();
        assert_eq!(
            info,
            KeyInfo {
                subkeys: 2,
                max_subkey_units: 5,
                values: 3,
                max_value_name_units: 7,
                max_value_data_bytes: 10,
                filetime: 132000000000000000
            }
        );
        assert_eq!(text_units("😀", true), 2);
        assert_eq!(text_units("😀", false), 1);
        assert_eq!(encode_text("😀", false, true), b"?\0");
    }
    #[test]
    fn get_expansion_is_guest_only_single_pass_and_size_conservative() {
        let mut registry = Registry::default();
        registry
            .seed_value(
                "HKCU\\Environment",
                "Path",
                REG_EXPAND_SZ,
                b"%TEMP%\0",
                false,
            )
            .unwrap();
        let env = BTreeMap::from([("temp".into(), "C:\\T".into())]);
        let expanded = registry
            .get_value(1, HKCU, "Environment", "Path", 0xffff, false, &env)
            .unwrap();
        assert_eq!(expanded.data, b"C:\\T\0");
        assert_eq!(expanded.required_size, 7);
        assert_eq!(expanded.value_type, REG_SZ);
        let raw = registry
            .get_value(1, HKCU, "Environment", "Path", 0x1000ffff, true, &env)
            .unwrap();
        assert_eq!(raw.value_type, REG_EXPAND_SZ);
        assert_eq!(raw.data, encode_text("%TEMP%\0", true, false));
        assert_eq!(
            code(registry.get_value(1, HKCU, "Environment", "Path", 1, false, &env)),
            50
        );
        registry
            .seed_value(
                "HKCU\\Environment",
                "Mixed",
                REG_EXPAND_SZ,
                b"%Unknown%|%TeMp%|%%\0",
                false,
            )
            .unwrap();
        let env = BTreeMap::from([
            ("temp".into(), "%Other%".into()),
            ("Other".into(), "recursive".into()),
        ]);
        assert_eq!(
            registry
                .get_value(1, HKCU, "Environment", "Mixed", 0, false, &env)
                .unwrap()
                .data,
            b"%Unknown%|%Other%|%%\0"
        );
        registry
            .seed_value(
                "HKCU\\Environment",
                "Adjacent",
                REG_EXPAND_SZ,
                b"%%TEMP%\0",
                false,
            )
            .unwrap();
        assert_eq!(
            registry
                .get_value(1, HKCU, "Environment", "Adjacent", 0, false, &env)
                .unwrap()
                .data,
            b"%%Other%\0"
        );
        registry
            .seed_value("HKCU\\Environment", "Unterminated", REG_SZ, b"raw", false)
            .unwrap();
        let handle = registry.open(1, HKCU, "Environment", KEY_READ).unwrap();
        assert_eq!(
            registry
                .query_value(1, handle, "Unterminated", false)
                .unwrap()
                .data,
            b"raw"
        );
        assert_eq!(
            registry
                .get_value(1, HKCU, "Environment", "Unterminated", 0, false, &env)
                .unwrap()
                .data,
            b"raw\0"
        );
    }
    #[test]
    fn delete_rejects_nonempty_preset_and_does_not_revive_old_handles() {
        let mut registry = Registry::default();
        let first = registry
            .create(1, HKCU, "Guest\\Child", KEY_ALL_ACCESS)
            .unwrap();
        assert_eq!(first.disposition, 1);
        assert_eq!(code(registry.delete_key(1, HKCU, "Guest")), 5);
        registry.delete_key(1, HKCU, "Guest\\Child").unwrap();
        assert_eq!(
            code(registry.query_value(1, first.handle, "x", false)),
            1018
        );
        let next = registry
            .create(1, HKCU, "Guest\\Child", KEY_ALL_ACCESS)
            .unwrap();
        assert_ne!(first.handle, next.handle);
        assert_eq!(
            code(registry.query_value(1, first.handle, "x", false)),
            1018
        );
        registry.close(1, first.handle).unwrap();
        assert_eq!(
            registry
                .create(1, HKCU, "Guest\\Child", KEY_READ)
                .unwrap()
                .disposition,
            2
        );
        registry.seed_key("HKCU\\Preset").unwrap();
        assert_eq!(code(registry.delete_key(1, HKCU, "Preset")), 50);
        assert_eq!(code(registry.delete_key(1, HKCU, "")), 87);
    }
    #[test]
    fn limits_are_transactional_and_replacement_reclaims_budget() {
        let mut registry = Registry::default();
        let key = registry
            .create(1, HKCU, "Guest", KEY_ALL_ACCESS)
            .unwrap()
            .handle;
        registry
            .set_value(1, key, "x", REG_BINARY, b"previous", false)
            .unwrap();
        assert_eq!(code(registry.set_value(1, key, "x", 5, b"bad", false)), 50);
        assert_eq!(
            code(registry.set_value(1, key, "x", REG_BINARY, &vec![0; MAX_VALUE + 1], false)),
            50
        );
        assert_eq!(
            registry.query_value(1, key, "x", false).unwrap().data,
            b"previous"
        );
        let previous = registry.total;
        registry.total = MAX_TOTAL;
        assert_eq!(
            code(registry.set_value(1, key, "new", REG_BINARY, b"x", false)),
            50
        );
        registry
            .set_value(1, key, "x", REG_BINARY, b"", false)
            .unwrap();
        assert_eq!(registry.total, MAX_TOTAL - previous);
        registry.total = 0;
        registry.values = MAX_VALUES;
        assert_eq!(
            code(registry.set_value(1, key, "new", REG_BINARY, b"", false)),
            50
        );
        registry.values = 1;
        registry.next_handle = u64::MAX;
        let keys = registry.keys.len();
        assert_eq!(code(registry.create(1, HKCU, "NotCreated", KEY_READ)), 50);
        assert_eq!(registry.keys.len(), keys);
    }
}

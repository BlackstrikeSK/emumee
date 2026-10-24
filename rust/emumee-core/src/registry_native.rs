//! Bounded native registry reads over this Registry's actual catalog/table.
//! Native handles are values, never host pointers or private CM objects.
use super::*;
use crate::pe::Architecture;
use serde::Serialize;
pub const USER_HANDLE_FIRST: u64 = 0x5d000000;
pub const USER_HANDLE_END: u64 = USER_HANDLE_FIRST + MAX_HANDLES as u64 * 8;
pub const NATIVE_HANDLE_FIRST: u64 = 0x80010000;
pub const NATIVE_HANDLE_END: u64 = NATIVE_HANDLE_FIRST + MAX_HANDLES as u64 * 8;
const HIGH: u64 = 0xffffffff00000000;
pub const STATUS_INVALID_HANDLE: u32 = 0xc0000008;
pub const STATUS_ACCESS_DENIED: u32 = 0xc0000022;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xc0000034;
pub const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xc000003a;
pub const STATUS_INVALID_PARAMETER: u32 = 0xc000000d;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Domain {
    User,
    Kernel(Architecture),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeHandleClass {
    KernelLive,
    Invalid,
    UserLive,
    Foreign,
}
#[derive(Debug, Error)]
#[error("Native registry: {reason}")]
pub struct NativeError {
    pub status: Option<u32>,
    pub reason: &'static str,
}
pub type NativeResult<T> = std::result::Result<T, NativeError>;
fn unsupported(reason: &'static str) -> NativeError {
    NativeError {
        status: None,
        reason,
    }
}
fn status(value: u32, reason: &'static str) -> NativeError {
    NativeError {
        status: Some(value),
        reason,
    }
}
impl From<RegistryError> for NativeError {
    fn from(error: RegistryError) -> Self {
        match error.win32 {
            2 => status(STATUS_OBJECT_NAME_NOT_FOUND, error.reason),
            5 => status(STATUS_ACCESS_DENIED, error.reason),
            6 => status(STATUS_INVALID_HANDLE, error.reason),
            87 => status(STATUS_INVALID_PARAMETER, error.reason),
            1018 => status(0xc000017c, error.reason),
            _ => unsupported(error.reason),
        }
    }
}
fn first(architecture: Architecture) -> u64 {
    NATIVE_HANDLE_FIRST
        | if architecture == Architecture::X64 {
            HIGH
        } else {
            0
        }
}
fn reserved_native(handle: u64) -> bool {
    (NATIVE_HANDLE_FIRST..NATIVE_HANDLE_END).contains(&handle)
        || ((HIGH | NATIVE_HANDLE_FIRST)..(HIGH | NATIVE_HANDLE_END)).contains(&handle)
}
/// A VFS allocator must skip all these values, including retired identities and
/// truncated native/thread aliases. Reapply until no reservation contains it.
pub const FILE_HANDLE_RESERVATIONS: [(u64, u64); 5] = [
    (USER_HANDLE_FIRST, USER_HANDLE_END),
    (NATIVE_HANDLE_FIRST, NATIVE_HANDLE_END),
    (HIGH | NATIVE_HANDLE_FIRST, HIGH | NATIVE_HANDLE_END),
    (
        crate::kernel_layout::NATIVE_THREAD_HANDLE_FIRST,
        crate::kernel_layout::NATIVE_THREAD_HANDLE_END,
    ),
    (
        HIGH | crate::kernel_layout::NATIVE_THREAD_HANDLE_FIRST,
        HIGH | crate::kernel_layout::NATIVE_THREAD_HANDLE_END,
    ),
];
pub fn reserved_file_handle_next(handle: u64) -> Option<u64> {
    FILE_HANDLE_RESERVATIONS
        .into_iter()
        .find_map(|(start, end)| (start..end).contains(&handle).then_some(end))
}
pub struct NativeOpen<'a> {
    pub architecture: Architecture,
    pub owner: u64,
    pub root: u64,
    pub name: &'a str,
    pub access: u32,
}
pub struct NativeOpenPlan {
    architecture: Architecture,
    owner: u64,
    key: u64,
    access: u32,
    index: u64,
    handle: u64,
}
impl NativeOpenPlan {
    pub fn handle(&self) -> u64 {
        self.handle
    }
}
pub struct NativeQuery<'a> {
    pub architecture: Architecture,
    pub owner: u64,
    pub handle: u64,
    pub name: &'a str,
    pub class: u32,
    pub capacity: u32,
}
#[derive(Debug)]
pub struct NativeQueryPlan {
    pub status: u32,
    pub required: u32,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Debug, Serialize)]
pub struct NativeHandleEvidence {
    pub handle: u64,
    pub owner: u64,
    pub access: u32,
    pub path_preview: String,
    pub path_truncated: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct NativeHandleReport {
    pub live: usize,
    pub lifetime_issues: u64,
    pub lifetime_limit: usize,
    pub handles: Vec<NativeHandleEvidence>,
    pub omitted_handles: usize,
    pub scope: &'static str,
}
fn access_mask(access: u32) -> NativeResult<u32> {
    let mut mapped = access & !0xf0000000;
    for (generic, specific) in [
        (0x80000000, KEY_READ),
        (0x40000000, KEY_WRITE),
        (0x20000000, KEY_READ),
        (0x10000000, KEY_ALL_ACCESS),
    ] {
        if access & generic != 0 {
            mapped |= specific;
        }
    }
    valid_access(mapped)?;
    Ok(mapped)
}
fn absolute(name: &str) -> NativeResult<String> {
    let parts = name.split('\\').collect::<Vec<_>>();
    if parts.len() < 3 || !parts[0].is_empty() || !parts[1].eq_ignore_ascii_case("Registry") {
        return Err(status(
            0xc0000033,
            "native absolute registry object name required",
        ));
    }
    let root = if parts[2].eq_ignore_ascii_case("Machine") {
        ROOTS[2].1
    } else if parts[2].eq_ignore_ascii_case("User") {
        ROOTS[3].1
    } else {
        return Err(unsupported(
            "native registry root outside Machine/User profile",
        ));
    };
    if parts.len() == 3 {
        return Ok(root.into());
    }
    if parts[3..].iter().any(|part| part.is_empty()) {
        return Err(unsupported("empty native registry path component"));
    }
    Ok(subpath(root, &parts[3..].join("\\"))?)
}
impl Registry {
    pub fn native_handle_class(
        &self,
        architecture: Architecture,
        owner: u64,
        handle: u64,
    ) -> NativeHandleClass {
        if let Some(entry) = self.handles.get(&handle) {
            return match entry.domain {
                Domain::Kernel(a) if a == architecture && entry.owner == owner => {
                    NativeHandleClass::KernelLive
                }
                Domain::Kernel(_) => NativeHandleClass::Invalid,
                Domain::User => NativeHandleClass::UserLive,
            };
        }
        if reserved_native(handle)
            || (USER_HANDLE_FIRST..USER_HANDLE_END).contains(&handle)
            || ROOTS.iter().any(|r| r.0 == canonical_handle(handle))
        {
            NativeHandleClass::Invalid
        } else {
            NativeHandleClass::Foreign
        }
    }
    fn native_key(
        &self,
        architecture: Architecture,
        owner: u64,
        handle: u64,
        access: u32,
    ) -> NativeResult<u64> {
        if self.native_handle_class(architecture, owner, handle) != NativeHandleClass::KernelLive {
            return Err(status(
                STATUS_INVALID_HANDLE,
                "invalid native registry handle",
            ));
        }
        let entry = &self.handles[&handle];
        if entry.access & access != access {
            return Err(status(
                STATUS_ACCESS_DENIED,
                "native registry handle access denied",
            ));
        }
        if !self.keys.contains_key(&entry.key) {
            return Err(status(0xc000017c, "registry key has been deleted"));
        }
        Ok(entry.key)
    }
    pub fn plan_native_open(&self, request: NativeOpen<'_>) -> NativeResult<NativeOpenPlan> {
        if request.owner != 4 {
            return Err(unsupported("native registry owner must be modeled System4"));
        }
        if self
            .native_architecture
            .is_some_and(|architecture| architecture != request.architecture)
        {
            return Err(unsupported(
                "native registry architecture changed after publication",
            ));
        }
        let access = access_mask(request.access)?;
        let path = if request.root == 0 {
            absolute(request.name)?
        } else {
            if request.name.is_empty() || request.name.starts_with('\\') {
                return Err(unsupported(
                    "native root-relative name must be a nonempty relative path",
                ));
            }
            let root = self.native_key(request.architecture, request.owner, request.root, 0)?;
            subpath(&self.keys[&root].path, request.name)?
        };
        let key = self.paths.get(&fold(&path)).copied().ok_or_else(|| {
            let parent = path
                .rsplit_once('\\')
                .map(|(parent, _)| parent)
                .unwrap_or(&path);
            if self.paths.contains_key(&fold(parent)) {
                status(
                    STATUS_OBJECT_NAME_NOT_FOUND,
                    "native registry final key absent",
                )
            } else {
                status(
                    STATUS_OBJECT_PATH_NOT_FOUND,
                    "native registry parent absent",
                )
            }
        })?;
        if self.handles.len() >= MAX_HANDLES || self.native_issued >= MAX_HANDLES as u64 {
            return Err(unsupported("native registry handle quota exhausted"));
        }
        let handle = first(request.architecture)
            .checked_add(
                self.native_issued
                    .checked_mul(8)
                    .ok_or_else(|| unsupported("native handle index overflow"))?,
            )
            .ok_or_else(|| unsupported("native handle address overflow"))?;
        if self.handles.contains_key(&handle) {
            return Err(unsupported("native handle identity already published"));
        }
        Ok(NativeOpenPlan {
            architecture: request.architecture,
            owner: request.owner,
            key,
            access,
            index: self.native_issued,
            handle,
        })
    }
    pub fn commit_native_open(&mut self, plan: NativeOpenPlan) -> NativeResult<u64> {
        if plan.index != self.native_issued
            || self.native_issued >= MAX_HANDLES as u64
            || self.handles.len() >= MAX_HANDLES
            || self.handles.contains_key(&plan.handle)
            || !self.keys.contains_key(&plan.key)
            || self
                .native_architecture
                .is_some_and(|a| a != plan.architecture)
        {
            return Err(unsupported("stale native registry open plan"));
        }
        self.handles.insert(
            plan.handle,
            Handle {
                key: plan.key,
                owner: plan.owner,
                access: plan.access,
                domain: Domain::Kernel(plan.architecture),
            },
        );
        self.native_issued += 1;
        self.native_architecture = Some(plan.architecture);
        Ok(plan.handle)
    }
    pub fn native_close(
        &mut self,
        architecture: Architecture,
        owner: u64,
        handle: u64,
    ) -> NativeResult<()> {
        if self.native_handle_class(architecture, owner, handle) != NativeHandleClass::KernelLive {
            return Err(status(
                STATUS_INVALID_HANDLE,
                "native key handle already closed or invalid",
            ));
        }
        // Deleted keys can still have their real outstanding handles closed.
        self.handles.remove(&handle);
        Ok(())
    }
    pub fn native_query(&self, request: NativeQuery<'_>) -> NativeResult<NativeQueryPlan> {
        if !matches!(request.class, 1 | 2) {
            return Err(if request.class >= 6 {
                status(
                    STATUS_INVALID_PARAMETER,
                    "invalid native value information class",
                )
            } else {
                unsupported("valid native value information class is not modeled")
            });
        }
        let key = self.native_key(
            request.architecture,
            request.owner,
            request.handle,
            KEY_QUERY_VALUE,
        )?;
        valid_name(request.name)?;
        let stored = self.keys[&key]
            .values
            .iter()
            .find(|value| fold(&value.name) == fold(request.name))
            .ok_or_else(|| status(STATUS_OBJECT_NAME_NOT_FOUND, "native registry value absent"))?;
        let value = stored.encoded(true)?;
        let name = if request.class == 1 {
            encode_text(&stored.name, true, false)
        } else {
            Vec::new()
        };
        let header = if request.class == 1 { 20usize } else { 12 };
        let offset = if request.class == 1 {
            (header + name.len()).div_ceil(4) * 4
        } else {
            header
        };
        let required = offset
            .checked_add(value.data.len())
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| unsupported("native query result size overflow"))?;
        if request.capacity < (header as u32) {
            return Ok(NativeQueryPlan {
                status: 0xc0000023,
                required,
                bytes: Vec::new(),
            });
        }
        let mut bytes = Vec::with_capacity(required as usize);
        bytes.extend(0u32.to_le_bytes());
        bytes.extend(value.value_type.to_le_bytes());
        if request.class == 1 {
            bytes.extend((offset as u32).to_le_bytes());
            bytes.extend((value.data.len() as u32).to_le_bytes());
            bytes.extend((name.len() as u32).to_le_bytes());
            bytes.extend(name);
            bytes.resize(offset, 0);
        } else {
            bytes.extend((value.data.len() as u32).to_le_bytes());
        }
        bytes.extend(value.data);
        let result = if request.capacity < required {
            bytes.truncate(request.capacity as usize);
            0x80000005
        } else {
            0
        };
        Ok(NativeQueryPlan {
            status: result,
            required,
            bytes,
        })
    }
    pub fn native_handle_report(&self) -> NativeHandleReport {
        let handles = self
            .handles
            .iter()
            .filter(|(_, entry)| matches!(entry.domain, Domain::Kernel(_)))
            .take(128)
            .map(|(handle, entry)| {
                let path = self
                    .keys
                    .get(&entry.key)
                    .map(|key| key.path.as_str())
                    .unwrap_or("<deleted-key>");
                NativeHandleEvidence {
                    handle: *handle,
                    owner: entry.owner,
                    access: entry.access,
                    path_preview: path.chars().take(256).collect(),
                    path_truncated: path.chars().count() > 256,
                }
            })
            .collect::<Vec<_>>();
        let live = self
            .handles
            .values()
            .filter(|entry| matches!(entry.domain, Domain::Kernel(_)))
            .count();
        NativeHandleReport {
            live,
            lifetime_issues: self.native_issued,
            lifetime_limit: MAX_HANDLES,
            omitted_handles: live - handles.len(),
            handles,
            scope: "One actual Registry handle table. System4 kernel-only native handles, finite monotonic identities, no CM object layout/ACL/transaction/current-user hive alias synthesis.",
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn key(registry: &mut Registry, architecture: Architecture, access: u32) -> u64 {
        let plan = registry
            .plan_native_open(NativeOpen {
                architecture,
                owner: 4,
                root: 0,
                name: r"\Registry\Machine\Guest",
                access,
            })
            .unwrap();
        registry.commit_native_open(plan).unwrap()
    }
    #[test]
    fn native_and_user_channels_share_exact_catalog_with_real_fullwidth_retirement() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut registry = Registry::default();
            registry
                .seed_value(r"HKLM\Guest", "MiXeD", REG_BINARY, &[1, 2, 3], true)
                .unwrap();
            let h = key(&mut registry, architecture, KEY_READ);
            assert_eq!(h, first(architecture));
            assert_eq!(
                registry.query_value(4, h, "mixed", true).unwrap_err().win32,
                6
            );
            assert_eq!(registry.close(4, h).unwrap_err().win32, 6);
            let value = registry
                .native_query(NativeQuery {
                    architecture,
                    owner: 4,
                    handle: h,
                    name: "mixed",
                    class: 1,
                    capacity: 99,
                })
                .unwrap();
            assert_eq!(&value.bytes[20..30], &encode_text("MiXeD", true, false));
            assert_eq!(
                u32::from_le_bytes(value.bytes[8..12].try_into().unwrap()),
                32
            );
            assert_eq!(&value.bytes[32..], &[1, 2, 3]);
            registry.native_close(architecture, 4, h).unwrap();
            assert_eq!(registry.native_handle_report().live, 0);
            assert_eq!(
                registry
                    .native_close(architecture, 4, h)
                    .unwrap_err()
                    .status,
                Some(STATUS_INVALID_HANDLE)
            );
            let next = key(&mut registry, architecture, KEY_READ);
            assert_eq!(next, h + 8);
            if architecture == Architecture::X64 {
                assert_eq!(
                    registry.native_handle_class(architecture, 4, next as u32 as u64),
                    NativeHandleClass::Invalid
                );
            }
            let user = registry.open(1024, HKLM, "Guest", KEY_READ).unwrap();
            assert_eq!(
                registry
                    .query_value(1024, user, "MiXeD", true)
                    .unwrap()
                    .data,
                [1, 2, 3]
            );
            assert_eq!(
                registry.native_handle_class(architecture, 4, user),
                NativeHandleClass::UserLive
            );
        }
    }
    #[test]
    fn query_sizes_prefixes_default_raw_text_access_and_class_errors_are_explicit() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut registry = Registry::default();
            registry
                .seed_value(r"HKLM\Guest", "", REG_SZ, &[65, 0, 66], true)
                .unwrap();
            let h = key(&mut registry, architecture, KEY_READ);
            for (capacity, result, copied) in [
                (0, 0xc0000023, 0),
                (11, 0xc0000023, 0),
                (12, 0x80000005, 12),
                (14, 0x80000005, 14),
                (15, 0, 15),
            ] {
                let q = registry
                    .native_query(NativeQuery {
                        architecture,
                        owner: 4,
                        handle: h,
                        name: "",
                        class: 2,
                        capacity,
                    })
                    .unwrap();
                assert_eq!(q.status, result);
                assert_eq!(q.required, 15);
                assert_eq!(q.bytes.len(), copied);
                if copied > 12 {
                    assert_eq!(&q.bytes[12..], &[65, 0, 66][..copied - 12]);
                }
            }
            let no = key(&mut registry, architecture, KEY_SET_VALUE);
            assert_eq!(
                registry
                    .native_query(NativeQuery {
                        architecture,
                        owner: 4,
                        handle: no,
                        name: "",
                        class: 2,
                        capacity: 99
                    })
                    .unwrap_err()
                    .status,
                Some(STATUS_ACCESS_DENIED)
            );
            for class in [0, 3, 4, 5] {
                assert!(
                    registry
                        .native_query(NativeQuery {
                            architecture,
                            owner: 4,
                            handle: h,
                            name: "",
                            class,
                            capacity: 99
                        })
                        .unwrap_err()
                        .status
                        .is_none()
                );
            }
            assert_eq!(
                registry
                    .native_query(NativeQuery {
                        architecture,
                        owner: 4,
                        handle: h,
                        name: "",
                        class: 6,
                        capacity: 99
                    })
                    .unwrap_err()
                    .status,
                Some(STATUS_INVALID_PARAMETER)
            );
        }
    }
    #[test]
    fn root_relative_paths_never_create_keys_and_do_not_guess_sid_hives() {
        let mut registry = Registry::default();
        registry.seed_key(r"HKLM\Guest\Child").unwrap();
        registry.seed_key(r"HKU\S-1-5-18\Actual").unwrap();
        registry.seed_key(r"HKCU\OnlyCurrent").unwrap();
        let arch = Architecture::X64;
        let h = key(&mut registry, arch, KEY_READ);
        let p = registry
            .plan_native_open(NativeOpen {
                architecture: arch,
                owner: 4,
                root: h,
                name: "Child",
                access: 0x80000000,
            })
            .unwrap();
        assert_eq!(registry.commit_native_open(p).unwrap(), h + 8);
        for (name, code) in [
            (r"\Registry\Machine\Absent", STATUS_OBJECT_NAME_NOT_FOUND),
            (
                r"\Registry\Machine\Absent\Child",
                STATUS_OBJECT_PATH_NOT_FOUND,
            ),
            (
                r"\Registry\User\S-1-5-18\OnlyCurrent",
                STATUS_OBJECT_NAME_NOT_FOUND,
            ),
        ] {
            assert_eq!(
                registry
                    .plan_native_open(NativeOpen {
                        architecture: arch,
                        owner: 4,
                        root: 0,
                        name,
                        access: KEY_READ
                    })
                    .err()
                    .unwrap()
                    .status,
                Some(code)
            );
        }
        assert!(
            registry
                .plan_native_open(NativeOpen {
                    architecture: arch,
                    owner: 4,
                    root: HKLM,
                    name: "Guest",
                    access: KEY_READ
                })
                .is_err()
        );
        assert_eq!(registry.native_handle_report().lifetime_issues, 2);
    }
    #[test]
    fn stale_plans_and_finite_quotas_leave_catalog_and_counters_unchanged() {
        let mut registry = Registry::default();
        registry.seed_key(r"HKLM\Guest").unwrap();
        let request = || NativeOpen {
            architecture: Architecture::X64,
            owner: 4,
            root: 0,
            name: r"\Registry\Machine\Guest",
            access: KEY_READ,
        };
        let first = registry.plan_native_open(request()).unwrap();
        let stale = registry.plan_native_open(request()).unwrap();
        registry.commit_native_open(first).unwrap();
        assert!(registry.commit_native_open(stale).is_err());
        registry.native_issued = MAX_HANDLES as u64;
        let before = registry.paths.clone();
        assert!(registry.plan_native_open(request()).is_err());
        assert_eq!(before, registry.paths);
        registry.next_handle = USER_HANDLE_END;
        assert!(registry.open(1024, HKLM, "Guest", KEY_READ).is_err());
        assert_eq!(registry.handles.len(), 1);
    }
    #[test]
    fn independently_packed_native_layout_vectors_cover_raw_bytes_full_padding_and_prefixes() {
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("registry_native_vectors.json")).unwrap();
        assert_eq!(corpus["version"], "emumee-native-registry-readonly-v1");
        for row in corpus["cases"].as_array().unwrap() {
            let bytes = |field: &str| {
                row[field]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|b| u8::try_from(b.as_u64().unwrap()).unwrap())
                    .collect::<Vec<_>>()
            };
            let mut registry = Registry::default();
            let name = row["name"].as_str().unwrap();
            registry
                .seed_value(
                    r"HKLM\Guest",
                    name,
                    row["value_type"].as_u64().unwrap() as u32,
                    &bytes("data"),
                    true,
                )
                .unwrap();
            let handle = key(&mut registry, Architecture::X64, KEY_READ);
            let actual = registry
                .native_query(NativeQuery {
                    architecture: Architecture::X64,
                    owner: 4,
                    handle,
                    name,
                    class: row["information_class"].as_u64().unwrap() as u32,
                    capacity: row["capacity"].as_u64().unwrap() as u32,
                })
                .unwrap();
            assert_eq!(
                actual.status as u64,
                row["status"].as_u64().unwrap(),
                "{row}"
            );
            assert_eq!(
                actual.required as u64,
                row["required"].as_u64().unwrap(),
                "{row}"
            );
            assert_eq!(actual.bytes, bytes("copied"), "{row}");
        }
    }
}

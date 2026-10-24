//! Decoded seed bytes and whole-model preflight over the existing authorities.
use super::*;
use base64::{Engine, engine::general_purpose::STANDARD};
#[derive(Clone, Debug, Serialize)]
pub struct GuestFileSeed {
    pub path: String,
    pub canonical_path: String,
    pub size: usize,
    pub sha256: String,
    #[serde(skip)]
    bytes: Vec<u8>,
}
impl GuestFileSeed {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct RegistryValueSeed {
    pub name: String,
    pub value_type: u32,
    pub size: usize,
    pub sha256: String,
    #[serde(skip)]
    bytes: Vec<u8>,
}
impl RegistryValueSeed {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct RegistryKeySeed {
    pub path: String,
    pub values: Vec<RegistryValueSeed>,
}
#[derive(Clone, Debug, Serialize)]
pub struct ProcessSeed {
    pub name: String,
    pub path: String,
    pub pid: u32,
    pub session: u32,
    pub base_address: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct SeedManifest {
    version: &'static str,
    sha256: String,
    #[serde(skip)]
    canonical: Vec<u8>,
    filetime: u64,
    custom_registry: bool,
    custom_files: bool,
    directories: Vec<String>,
    files: Vec<GuestFileSeed>,
    registry: Vec<RegistryKeySeed>,
    processes: Vec<ProcessSeed>,
}
impl SeedManifest {
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    /// Canonical seed payload excludes its own digest field.
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn files(&self) -> &[GuestFileSeed] {
        &self.files
    }
    pub fn registry(&self) -> &[RegistryKeySeed] {
        &self.registry
    }
    pub fn directories(&self) -> &[String] {
        &self.directories
    }
    pub fn processes(&self) -> &[ProcessSeed] {
        &self.processes
    }
    pub(super) fn prepare(&self, projection: &SupportProjection) -> Result<PreparedGuestState> {
        let persona = crate::persona::Persona::new(projection.persona.clone())
            .map_err(|e| error("seed.persona", e.to_string()))?;
        projection
            .cpu
            .validate()
            .map_err(|e| error("seed.cpu", e.to_string()))?;
        let clock = crate::clock::GuestClock::new(
            self.filetime,
            projection.clock.uptime_ms,
            projection.clock.utc_offset_minutes,
            projection.cpu.base_mhz,
        )
        .map_err(|e| error("seed.clock", e.to_string()))?;
        let mut registry = crate::registry::Registry::new(self.filetime);
        for key in &self.registry {
            registry
                .seed_key(&key.path)
                .map_err(|e| error("seed.registry", e.to_string()))?;
            for value in &key.values {
                registry
                    .seed_value(&key.path, &value.name, value.value_type, &value.bytes, true)
                    .map_err(|e| error("seed.registry", e.to_string()))?;
            }
        }
        let files = self
            .files
            .iter()
            .map(|f| crate::filesystem::SeedFile {
                path: &f.path,
                bytes: &f.bytes,
            })
            .collect::<Vec<_>>();
        let filesystem = crate::filesystem::VirtualFileSystem::from_seed(
            self.filetime,
            &projection.persona.current_directory,
            &self.directories,
            &files,
        )
        .map_err(|e| error("seed.filesystem", e.to_string()))?;
        Ok(PreparedGuestState {
            persona,
            cpu: projection.cpu.clone(),
            clock,
            registry,
            filesystem,
        })
    }
}
#[derive(Clone, Debug)]
pub struct PreparedGuestState {
    pub persona: crate::persona::Persona,
    pub cpu: crate::cpu::CpuProfile,
    pub clock: crate::clock::GuestClock,
    pub registry: crate::registry::Registry,
    pub filesystem: crate::filesystem::VirtualFileSystem,
}
fn registry_number(v: &Value, path: &str, max: u64) -> Result<u64> {
    let n = if let Some(n) = v.as_u64() {
        n
    } else {
        let s = text(v, path)?.trim();
        let s = s.strip_prefix('+').unwrap_or(s);
        let (radix, digits) = if let Some(s) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"))
        {
            (16, s)
        } else if let Some(s) = s.strip_prefix("0o").or_else(|| s.strip_prefix("0O")) {
            (8, s)
        } else if let Some(s) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
            (2, s)
        } else {
            require(
                !s.starts_with('0') || s.bytes().all(|b| b == b'0'),
                path,
                "ambiguous leading-zero registry integer",
            )?;
            (10, s)
        };
        u64::from_str_radix(digits, radix).map_err(|_| error(path, "invalid registry integer"))?
    };
    require(n <= max, path, "registry integer exceeds type width")?;
    Ok(n)
}
fn registry_bytes(v: &Value, path: &str) -> Result<(u32, Vec<u8>)> {
    fields(v, path, &["name", "type", "data"], &[])?;
    let kind = match text(&v["type"], path)? {
        "REG_SZ" => 1,
        "REG_EXPAND_SZ" => 2,
        "REG_BINARY" => 3,
        "REG_DWORD" => 4,
        "REG_MULTI_SZ" => 7,
        "REG_QWORD" => 11,
        _ => return Err(error(path, "unsupported registry type")),
    };
    let data: Vec<u8> = match kind {
        1 | 2 | 7 => {
            let s = text(&v["data"], path)?.trim_end_matches('\0');
            let ending = if kind == 7 { "\0\0" } else { "\0" };
            format!("{s}{ending}")
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect()
        }
        3 => {
            let s = text(&v["data"], path)?;
            if let Some(hex) = s.strip_prefix("hex:") {
                let mut bytes = Vec::new();
                let raw = hex.as_bytes();
                let mut at = 0;
                while at < raw.len() {
                    if raw[at].is_ascii_whitespace() {
                        at += 1;
                        continue;
                    }
                    require(
                        at + 1 < raw.len()
                            && raw[at].is_ascii_hexdigit()
                            && raw[at + 1].is_ascii_hexdigit(),
                        path,
                        "invalid registry hex bytes",
                    )?;
                    bytes.push(
                        u8::from_str_radix(std::str::from_utf8(&raw[at..at + 2]).unwrap(), 16)
                            .unwrap(),
                    );
                    at += 2;
                }
                bytes
            } else {
                s.as_bytes().to_vec()
            }
        }
        4 => (registry_number(&v["data"], path, u32::MAX as u64)? as u32)
            .to_le_bytes()
            .to_vec(),
        11 => registry_number(&v["data"], path, u64::MAX)?
            .to_le_bytes()
            .to_vec(),
        _ => unreachable!(),
    };
    require(
        data.len() <= crate::registry::MAX_VALUE,
        path,
        "registry value exceeds1MiB",
    )?;
    Ok((kind, data))
}
pub(super) fn resolve(
    p: &Value,
    custom_registry: bool,
    custom_files: bool,
    filetime: u64,
) -> Result<SeedManifest> {
    let mut files = Vec::new();
    let mut file_names = BTreeSet::new();
    let mut total = 0usize;
    for file in array(&p["virtual_files"], "virtual_files", 512)? {
        let path = text(&file["path"], "virtual_files[].path")?;
        let key = validate::guest_path(&file["path"], "virtual_files[].path")?;
        require(
            file_names.insert(key.clone()),
            "virtual_files[].path",
            "duplicate normalized guest path",
        )?;
        let bytes = if file.get("text").is_some() {
            fields(file, "virtual_files[]", &["path", "text"], &[])?;
            text(&file["text"], "virtual_files[].text")?
                .as_bytes()
                .to_vec()
        } else {
            fields(file, "virtual_files[]", &["path", "base64"], &[])?;
            let encoded = text(&file["base64"], "virtual_files[].base64")?;
            require(
                encoded.len() <= 4 * (1024 * 1024 + 2) / 3 + 4,
                "virtual_files[].base64",
                "encoded file exceeds bound",
            )?;
            STANDARD
                .decode(encoded)
                .map_err(|_| error("virtual_files[].base64", "invalid Base64 file bytes"))?
        };
        require(
            bytes.len() <= 1024 * 1024,
            "virtual_files[]",
            "file exceeds1MiB",
        )?;
        total += bytes.len();
        require(
            total <= 16 * 1024 * 1024,
            "virtual_files",
            "aggregate files exceed16MiB",
        )?;
        files.push(GuestFileSeed {
            path: path.into(),
            canonical_path: key,
            size: bytes.len(),
            sha256: digest(&bytes),
            bytes,
        });
    }
    let mut registry = Vec::new();
    let mut key_names = BTreeSet::new();
    let mut registry_total = 0usize;
    let mut value_count = 0usize;
    for key in array(
        &p["registry_keys"],
        "registry_keys",
        if custom_registry {
            512
        } else {
            crate::registry::MAX_KEYS
        },
    )? {
        fields(key, "registry_keys[]", &["path", "values"], &[])?;
        let path = text(&key["path"], "registry_keys[].path")?;
        let mut authority = crate::registry::Registry::new(filetime);
        authority
            .seed_key(path)
            .map_err(|e| error("registry_keys[].path", e.to_string()))?;
        let canonical = fold(
            &crate::registry::canonical_seed_path(path)
                .map_err(|e| error("registry_keys[].path", e.to_string()))?,
        );
        require(
            key_names.insert(canonical),
            "registry_keys[].path",
            "duplicate registry key authority",
        )?;
        let mut values = Vec::new();
        let mut names = BTreeSet::new();
        for value in array(
            &key["values"],
            "registry_keys[].values",
            crate::registry::MAX_VALUES,
        )? {
            value_count += 1;
            require(
                value_count <= crate::registry::MAX_VALUES,
                "registry_keys",
                "aggregate registry value count limit",
            )?;
            let name = text(&value["name"], "registry_keys[].values[].name")?;
            let normalized = if name.eq_ignore_ascii_case("default") {
                ""
            } else {
                name
            };
            require(
                names.insert(fold(normalized)),
                "registry_keys[].values[].name",
                "duplicate default/casefolded value",
            )?;
            let (kind, bytes) = registry_bytes(value, "registry_keys[].values[]")?;
            authority
                .seed_value(path, name, kind, &bytes, true)
                .map_err(|e| error("registry_keys[].values[]", e.to_string()))?;
            registry_total += bytes.len();
            require(
                registry_total <= crate::registry::MAX_TOTAL,
                "registry_keys",
                "registry data exceeds aggregate bound",
            )?;
            values.push(RegistryValueSeed {
                name: name.into(),
                value_type: kind,
                size: bytes.len(),
                sha256: digest(&bytes),
                bytes,
            });
        }
        registry.push(RegistryKeySeed {
            path: path.into(),
            values,
        });
    }
    let user = p["user_name"].as_str().unwrap();
    let mut directories: BTreeMap<String, String> = BTreeMap::new();
    let base: Vec<String> =
        serde_json::from_str(include_str!("../fullpersona_assets/directories.json"))
            .map_err(|e| error("directories", e.to_string()))?;
    let add = |directories: &mut BTreeMap<String, String>, path: &str| -> Result<()> {
        let mut parts = vec![String::from(r"C:\")];
        let normalized = path.replace('/', "\\");
        let mut current = String::from("C:");
        for part in normalized[3..].split('\\') {
            if part.is_empty() {
                continue;
            }
            current.push('\\');
            current.push_str(part);
            parts.push(current.clone());
        }
        for display in parts {
            let key = validate::guest_path(&json!(display), "seed.directories")?;
            directories.entry(key).or_insert(display);
        }
        Ok(())
    };
    for path in base {
        add(&mut directories, &path.replace("{user}", user))?;
    }
    add(&mut directories, p["current_dir"].as_str().unwrap())?;
    for file in &files {
        if let Some((parent, _)) = file.path.rsplit_once('\\') {
            let parent = if parent.len() == 2 {
                format!("{parent}\\")
            } else {
                parent.into()
            };
            add(&mut directories, &parent)?;
        }
    }
    if let Some(explicit) = p.get("virtual_directories") {
        let mut declared = BTreeSet::new();
        for value in array(explicit, "virtual_directories", 512)? {
            let key = validate::guest_path(value, "virtual_directories[]")?;
            require(
                declared.insert(key.clone()),
                "virtual_directories[]",
                "duplicate normalized guest directory",
            )?;
            require(
                !file_names.contains(&key),
                "virtual_directories[]",
                "directory aliases an explicit guest file",
            )?;
            // Feed the already canonical C-drive path to the existing parent
            // expansion and VFS preflight; raw slash/dot aliases cannot become
            // a second display authority for the same guest directory.
            add(&mut directories, &format!("C:{}", &key[2..]))?;
        }
    }
    let mut directories: Vec<String> = directories.into_values().collect();
    directories.sort_by_key(|p| (p.matches('\\').count(), p.to_lowercase()));
    let templates: BTreeMap<String, (String, u32)> =
        serde_json::from_str(include_str!("../fullpersona_assets/process_paths.json"))
            .map_err(|e| error("process_paths", e.to_string()))?;
    let mut processes = Vec::new();
    for (index, name) in p["processes"].as_array().unwrap().iter().enumerate() {
        let name = name.as_str().unwrap();
        let (path, session) = templates
            .get(&name.to_lowercase())
            .cloned()
            .unwrap_or_else(|| (format!(r"C:\Windows\System32\{name}"), 1));
        processes.push(ProcessSeed {
            name: name.into(),
            path: path.replace("{user}", user),
            pid: if name.eq_ignore_ascii_case("system") {
                4
            } else {
                420 + index as u32 * 168
            },
            session,
            base_address: 0x06000000 + index as u64 * 0x00100000,
        });
    }
    let mut seed = SeedManifest {
        version: VERSION,
        sha256: String::new(),
        canonical: Vec::new(),
        filetime,
        custom_registry,
        custom_files,
        directories,
        files,
        registry,
        processes,
    };
    let mut payload =
        serde_json::to_value(&seed).map_err(|e| error("seed_manifest", e.to_string()))?;
    payload.as_object_mut().unwrap().remove("sha256");
    seed.canonical = canonical(&payload)?;
    seed.sha256 = digest(&seed.canonical);
    Ok(seed)
}

//! Guest PE module lookup and bounded forwarded-export resolution. No host loads.
use crate::pe::{Architecture, Export, ExportTarget, ImportName, PeImage};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
mod dynamic;
mod lifecycle;
pub use dynamic::*;
mod provenance;
pub use lifecycle::*;
pub use provenance::{ModuleOrigin, ModuleProvenance};

#[derive(Debug, Error)]
#[error("Guest module: {0}")]
pub struct ModuleError(pub &'static str);
type Result<T> = std::result::Result<T, ModuleError>;
fn canonical(name: &str) -> Result<String> {
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(ModuleError("invalid module basename"));
    }
    let mut name = name.to_ascii_lowercase();
    if !name.contains('.') {
        name.push_str(".dll");
    }
    Ok(name)
}
#[derive(Clone, Debug, Serialize)]
pub struct LoadedModule {
    id: ModuleId,
    image_kind: crate::pe::Kind,
    entry_rva: u32,
    lifecycle: Option<ImageLifecycle>,
    dynamic: Option<DynamicImage>,
    api_references: u32,
    late_dependencies: Vec<ModuleId>,
    load_order: u16,
    provenance: Option<ModuleProvenance>,
    pub name: String,
    pub base: u64,
    pub size: u64,
    exports: Vec<Export>,
    by_name: BTreeMap<String, usize>,
    by_ordinal: BTreeMap<u32, usize>,
}
impl LoadedModule {
    pub fn entry_rva(&self) -> u32 {
        self.entry_rva
    }
    pub fn load_order(&self) -> u16 {
        self.load_order
    }
    pub fn provenance(&self) -> Option<&ModuleProvenance> {
        self.provenance.as_ref()
    }
    fn target(&self, symbol: &ImportName) -> Option<&ExportTarget> {
        let index = match symbol {
            ImportName::Name(name) => self.by_name.get(name),
            ImportName::Ordinal { ordinal } => self.by_ordinal.get(&(*ordinal as u32)),
        }?;
        Some(&self.exports[*index].target)
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct ModuleCatalog {
    architecture: Architecture,
    modules: BTreeMap<String, LoadedModule>,
    export_count: usize,
    next_module_id: u64,
    next_load_order: u32,
    primary: Option<ModuleId>,
    loader_events: Vec<LoaderEvent>,
    retired_images: Vec<RetiredImage>,
    ready_order: Vec<ModuleId>,
    dynamic_state: DynamicState,
}
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Resolution {
    Found { address: u64, chain: Vec<String> },
    MissingModule { module: String },
    MissingExport { module: String, symbol: ImportName },
}
impl ModuleCatalog {
    pub fn new(architecture: Architecture) -> Self {
        Self {
            architecture,
            modules: BTreeMap::new(),
            export_count: 0,
            next_module_id: 1,
            next_load_order: 0,
            primary: None,
            loader_events: Vec::new(),
            retired_images: Vec::new(),
            ready_order: Vec::new(),
            dynamic_state: DynamicState::default(),
        }
    }
    pub fn add(&mut self, name: &str, base: u64, pe: &PeImage) -> Result<()> {
        let name = canonical(name)?;
        let size = pe.image_size as u64;
        let end = base
            .checked_add(size)
            .ok_or(ModuleError("module address overflow"))?;
        if pe.sample.architecture != self.architecture
            || base == 0
            || base % 4096 != 0
            || (self.architecture == Architecture::X86 && end > 1u64 << 32)
        {
            return Err(ModuleError("module architecture or address mismatch"));
        }
        if self.modules.len() >= 256 || self.export_count + pe.exports.len() > 262144 {
            return Err(ModuleError("module/export catalog exceeds bound"));
        }
        if self.modules.contains_key(&name) {
            return Err(ModuleError("duplicate module basename"));
        }
        if self
            .modules
            .values()
            .any(|m| base < m.base + m.size && m.base < end)
        {
            return Err(ModuleError("overlapping loaded modules"));
        }
        let next_id = self
            .next_module_id
            .checked_add(1)
            .ok_or(ModuleError("module identity exhausted"))?;
        let load_order = u16::try_from(self.next_load_order)
            .map_err(|_| ModuleError("module load order exhausted"))?;
        let mut module = LoadedModule {
            id: ModuleId(self.next_module_id),
            image_kind: pe.sample.kind,
            entry_rva: pe.entry_rva,
            lifecycle: None,
            dynamic: None,
            api_references: 0,
            late_dependencies: Vec::new(),
            load_order,
            provenance: None,
            name: name.clone(),
            base,
            size,
            exports: pe.exports.clone(),
            by_name: BTreeMap::new(),
            by_ordinal: BTreeMap::new(),
        };
        for (index, export) in module.exports.iter().enumerate() {
            if module.by_ordinal.insert(export.ordinal, index).is_some() {
                return Err(ModuleError("duplicate export ordinal"));
            }
            if let ExportTarget::Address { rva } = export.target {
                if rva as u64 >= size {
                    return Err(ModuleError("export exceeds loaded module"));
                }
            }
            for name in &export.names {
                if module.by_name.insert(name.clone(), index).is_some() {
                    return Err(ModuleError("duplicate export name"));
                }
            }
        }
        self.next_module_id = next_id;
        self.next_load_order += 1;
        self.export_count += module.exports.len();
        self.modules.insert(name, module);
        Ok(())
    }
    pub fn architecture(&self) -> Architecture {
        self.architecture
    }
    pub fn add_with_path(
        &mut self,
        name: &str,
        base: u64,
        pe: &PeImage,
        path: &str,
        origin: ModuleOrigin,
    ) -> Result<()> {
        let name = canonical(name)?;
        let provenance = ModuleProvenance::new(&name, path, origin, pe)?;
        self.add(&name, base, pe)?;
        self.modules
            .get_mut(&name)
            .expect("just inserted module")
            .provenance = Some(provenance);
        Ok(())
    }
    pub fn containing(&self, pc: u64) -> Option<&LoadedModule> {
        self.modules
            .values()
            .find(|m| pc >= m.base && pc - m.base < m.size)
    }
    pub fn module(&self, name: &str) -> Result<Option<&LoadedModule>> {
        Ok(self.modules.get(&canonical(name)?))
    }
    pub fn modules(&self) -> impl Iterator<Item = &LoadedModule> {
        self.modules.values()
    }
    pub fn resolve(&self, module: &str, symbol: &ImportName) -> Result<Resolution> {
        let mut name = canonical(module)?;
        let mut symbol = symbol.clone();
        let mut chain = Vec::new();
        let mut seen = BTreeSet::new();
        for _ in 0..32 {
            let key = format!(
                "{}!{}",
                name,
                match &symbol {
                    ImportName::Name(name) => name.clone(),
                    ImportName::Ordinal { ordinal } => format!("#{ordinal}"),
                }
            );
            if !seen.insert(key.clone()) {
                return Err(ModuleError("export forwarder cycle"));
            }
            chain.push(key);
            let Some(module) = self.modules.get(&name) else {
                return Ok(Resolution::MissingModule { module: name });
            };
            let Some(target) = module.target(&symbol) else {
                return Ok(Resolution::MissingExport {
                    module: name,
                    symbol,
                });
            };
            match target {
                ExportTarget::Address { rva } => {
                    return Ok(Resolution::Found {
                        address: module.base + *rva as u64,
                        chain,
                    });
                }
                ExportTarget::Forwarder {
                    module,
                    symbol: next,
                } => {
                    name = canonical(module)?;
                    symbol = next.clone();
                }
            }
        }
        Err(ModuleError("export forwarder depth exceeds 32"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::counted_driver;
    fn pe(exports: Vec<Export>) -> PeImage {
        let mut pe = PeImage::parse(&counted_driver(Architecture::X64, 1), "guest.sys").unwrap();
        pe.exports = exports;
        pe
    }
    fn export(ordinal: u32, name: &str, target: ExportTarget) -> Export {
        Export {
            ordinal,
            names: vec![name.to_owned()],
            target,
        }
    }
    #[test]
    fn lookup_honors_case_sensitive_exports_and_relocated_forwarders() {
        let mut modules = ModuleCatalog::new(Architecture::X64);
        let forwarded = export(
            1,
            "Start",
            ExportTarget::Forwarder {
                module: "other".to_owned(),
                symbol: ImportName::Ordinal { ordinal: 17 },
            },
        );
        modules
            .add("FIRST.DLL", 0x10000000, &pe(vec![forwarded]))
            .unwrap();
        modules
            .add(
                "other",
                0x20000000,
                &pe(vec![export(
                    17,
                    "Target",
                    ExportTarget::Address { rva: 0x1000 },
                )]),
            )
            .unwrap();
        assert_eq!(modules.module("first").unwrap().unwrap().base, 0x10000000);
        assert_eq!(
            modules
                .resolve("FIRST", &ImportName::Name("Start".into()))
                .unwrap(),
            Resolution::Found {
                address: 0x20001000,
                chain: vec!["first.dll!Start".into(), "other.dll!#17".into()]
            }
        );
        assert!(matches!(
            modules
                .resolve("first", &ImportName::Name("start".into()))
                .unwrap(),
            Resolution::MissingExport { .. }
        ));
        assert!(matches!(
            modules
                .resolve("absent", &ImportName::Ordinal { ordinal: 1 })
                .unwrap(),
            Resolution::MissingModule { .. }
        ));
    }
    #[test]
    fn cycles_collisions_and_invalid_guest_paths_fail_without_host_fallback() {
        let mut modules = ModuleCatalog::new(Architecture::X64);
        let forward = ExportTarget::Forwarder {
            module: "self".into(),
            symbol: ImportName::Name("Loop".into()),
        };
        let image = pe(vec![export(1, "Loop", forward)]);
        modules.add("self", 0x10000000, &image).unwrap();
        assert!(
            modules
                .resolve("self", &ImportName::Name("Loop".into()))
                .is_err()
        );
        assert!(modules.add("SELF.dll", 0x20000000, &image).is_err());
        assert!(modules.add("overlap", 0x10001000, &image).is_err());
        assert!(modules.add("C:\\host.dll", 0x20000000, &image).is_err());
        assert_eq!(modules.modules().count(), 1);
    }
}

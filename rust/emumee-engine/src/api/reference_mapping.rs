//! Authenticated same-base reference inspection with modeled dispatch intact.
//! Production rebases file-backed READ/NX code into the generated provider and
//! redirects only unmodeled code exports. Existing separate-shadow mapping is
//! retained only for generated tests. Neither view admits reference execution.
use crate::{Trace, uc};
use anyhow::{Result, bail, ensure};
use emumee_core::{
    memory::{PAGE, Permissions as P},
    pe::Architecture,
    provider::{ReferenceHeaderIdentity, RelocatedCodeView, relocate_pinned_nt22631, relocate_pinned_nt26200},
};
use serde::Serialize;
use std::collections::BTreeMap;
#[cfg(test)]
use std::collections::BTreeSet;
use unicorn_engine::{Unicorn, unicorn_const::Prot};

const SHADOW_BASE: u64 = 0xffff_f800_1000_0000;
const MAX_IMAGE: u32 = 24 * 1024 * 1024;
#[cfg(test)]
const MAX_SECTIONS: usize = 24;
pub(crate) const PROVIDER_BASE: u64 = 0xffff_f800_0040_0000;
pub(crate) const REFERENCE_HAL_BASE: u64 = 0xffff_f800_0f40_0000;

pub(crate) struct IntegratedPrepared {
    pub view: RelocatedCodeView,
    pub header_identity: ReferenceHeaderIdentity,
    pub code_exports: BTreeMap<String, u32>,
    pub unload_authority: Option<super::reference_unload::Authority>,
}
#[cfg(test)]
pub(crate) fn generated_header_identity() -> ReferenceHeaderIdentity {
    let mut dos_prefix = vec![0u8; 0x80];
    dos_prefix[..2].copy_from_slice(b"MZ");
    dos_prefix[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    ReferenceHeaderIdentity {
        dos_prefix,
        pe_offset: 0x80,
        timestamp: 0,
        checksum: 0,
    }
}
pub(crate) fn prepare_integrated(bytes: &[u8], windows_build: u32) -> Result<IntegratedPrepared> {
    let (view, unload_authority) = match windows_build {
        22631 => (
            relocate_pinned_nt22631(bytes, windows_build, PROVIDER_BASE)?,
            super::reference_unload::Authority::PinnedNt22631,
        ),
        26200 => (
            relocate_pinned_nt26200(bytes, windows_build, PROVIDER_BASE)?,
            super::reference_unload::Authority::PinnedNt26200,
        ),
        _ => bail!("No exact kernel code reference profile for this Windows build"),
    };
    let pe = emumee_core::pe::PeImage::parse(bytes, "ntoskrnl.exe")?;
    let pe_offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into()?) as usize;
    ensure!(pe_offset <= 0x1000, "Reference PE header exceeds first page");
    let accepted = pe.accepted_headers();
    let header_identity = ReferenceHeaderIdentity {
        dos_prefix: bytes[..pe_offset].to_vec(),
        pe_offset,
        timestamp: accepted.timestamp,
        checksum: accepted.checksum,
    };
    let mut code_exports = BTreeMap::new();
    for export in pe.exports {
        if let emumee_core::pe::ExportTarget::Address { rva } = export.target {
            if view.read(rva, 1).is_some() {
                for name in export.names {
                    code_exports.insert(name, rva);
                }
            }
        }
    }
    ensure!(
        !code_exports.is_empty(),
        "Pinned reference has no named file-backed code"
    );
    Ok(IntegratedPrepared {
        view,
        header_identity,
        code_exports,
        unload_authority: Some(unload_authority),
    })
}

/// Host model writes bypass native page bits. Guard published integrated
/// inspection/private spans and the explicitly mapped legacy test shadow;
/// reserved addresses alone never affect runs without reference authority.
pub(crate) fn require_api_access(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
    permissions: P,
) -> Result<()> {
    if size == 0 || !(permissions.contains(P::WRITE) || permissions.contains(P::EXECUTE)) {
        return Ok(());
    }
    // Other access validators own malformed range reporting. Saturate only
    // for intersection testing so an unrelated overflowing probe retains
    // its established error and side-effect behavior.
    let end = address.saturating_add(size);
    if engine
        .get_data()
        .reference_spans
        .iter()
        .any(|(base, length)| address < base.saturating_add(*length) && end > *base)
    {
        bail!("Kernel reference inspection refuses write or execute");
    }
    if address < SHADOW_BASE + u64::from(MAX_IMAGE)
        && end > SHADOW_BASE
        && engine.get_data().apis.memory.regions().any(|region| {
            region.tag == "kernel reference READ/NX shadow"
                && address < region.base + region.size
                && end > region.base
        })
    {
        bail!("Kernel reference shadow refuses write or execute");
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct ReferenceSectionReceipt {
    pub name: String,
    pub rva: u32,
    pub bytes: usize,
    pub mapped_bytes: u64,
}
fn reference_sections(view: &RelocatedCodeView) -> Vec<ReferenceSectionReceipt> {
    view.sections
        .iter()
        .map(|section| ReferenceSectionReceipt {
            name: section.name.clone(),
            rva: section.rva,
            bytes: section.bytes.len(),
            mapped_bytes: (section.bytes.len() as u64 + PAGE - 1) & !(PAGE - 1),
        })
        .collect()
}
#[derive(Debug, Serialize)]
pub struct MappingReceipt {
    pub reference_sections: Vec<ReferenceSectionReceipt>,
    pub scope: &'static str,
    pub guest_unload_history_enabled: bool,
    pub mapping_mode: &'static str,
    pub redirected_code_exports: usize,
    pub source_sha256: String,
    pub target_base: u64,
    pub section_count: usize,
    pub file_backed_bytes: u64,
    pub mapped_bytes: u64,
    pub read_only: bool,
    pub non_executable: bool,
    pub provider_dispatch_replaced: bool,
    pub protected_data_replaced: bool,
    pub reference_execution_admitted: bool,
    pub reference_instructions_executed: bool,
}

#[cfg(test)]
pub(crate) fn map_generated_projection(
    engine: &mut Unicorn<Trace>,
    view: &RelocatedCodeView,
) -> Result<MappingReceipt> {
    map_projection(engine, view)
}

#[cfg(test)]
fn map_projection(engine: &mut Unicorn<Trace>, view: &RelocatedCodeView) -> Result<MappingReceipt> {
    ensure!(
        engine.get_data().architecture == Architecture::X64 && engine.get_data().apis.kernel_mode,
        "Kernel reference shadow requires x64 kernel context"
    );
    ensure!(
        view.target_base == SHADOW_BASE
            && view.image_size > 0
            && view.image_size <= MAX_IMAGE
            && view.image_size % PAGE as u32 == 0
            && (1..=MAX_SECTIONS).contains(&view.sections.len()),
        "Kernel reference shadow identity or bounds differ"
    );
    let mut planned_memory = engine.get_data().apis.memory.clone();
    let native = uc(engine.mem_regions())?;
    let mut names = BTreeSet::new();
    let mut ranges = Vec::with_capacity(view.sections.len());
    let mut file_backed_bytes = 0u64;
    let mut mapped_bytes = 0u64;
    for section in &view.sections {
        ensure!(
            !section.name.is_empty()
                && section.name.len() <= 8
                && section.name.is_ascii()
                && names.insert(section.name.as_str())
                && section.rva != 0
                && section.rva % PAGE as u32 == 0
                && !section.bytes.is_empty(),
            "Kernel reference shadow section invalid"
        );
        let size = u64::try_from(section.bytes.len())?;
        let mapped = size
            .checked_add(PAGE - 1)
            .map(|value| value & !(PAGE - 1))
            .ok_or_else(|| anyhow::anyhow!("Kernel reference shadow section overflow"))?;
        let end_rva = u64::from(section.rva)
            .checked_add(mapped)
            .ok_or_else(|| anyhow::anyhow!("Kernel reference shadow RVA overflow"))?;
        ensure!(
            end_rva <= u64::from(view.image_size),
            "Kernel reference shadow section exceeds image"
        );
        let base = SHADOW_BASE
            .checked_add(u64::from(section.rva))
            .ok_or_else(|| anyhow::anyhow!("Kernel reference shadow address overflow"))?;
        let end = base
            .checked_add(mapped)
            .ok_or_else(|| anyhow::anyhow!("Kernel reference shadow address overflow"))?;
        ensure!(
            native
                .iter()
                .all(|region| base > region.end || end <= region.begin),
            "Kernel reference shadow overlaps native provider or guest mapping"
        );
        planned_memory.map(
            base,
            mapped,
            P::READ,
            None,
            "kernel reference READ/NX shadow",
        )?;
        file_backed_bytes = file_backed_bytes
            .checked_add(size)
            .ok_or_else(|| anyhow::anyhow!("Kernel reference shadow byte sum overflow"))?;
        mapped_bytes = mapped_bytes
            .checked_add(mapped)
            .ok_or_else(|| anyhow::anyhow!("Kernel reference shadow mapped sum overflow"))?;
        ensure!(
            mapped_bytes <= u64::from(MAX_IMAGE),
            "Kernel reference shadow mapped bytes exceed bound"
        );
        ranges.push((base, mapped, section.bytes.as_slice()));
    }
    // Native pages are staged writable only for host initialization, then
    // switched to READ before the model state or receipt is published.
    let mut mapped = Vec::new();
    let result = (|| -> Result<()> {
        for (base, size, bytes) in &ranges {
            uc(engine.mem_map(*base, *size, Prot::READ | Prot::WRITE))?;
            mapped.push((*base, *size));
            uc(engine.mem_write(*base, bytes))?;
            uc(engine.mem_protect(*base, *size, Prot::READ))?;
        }
        Ok(())
    })();
    if let Err(error) = result {
        let mut rollback_failed = false;
        for (base, size) in mapped.into_iter().rev() {
            rollback_failed |= engine.mem_unmap(base, size).is_err();
        }
        if rollback_failed {
            bail!("Kernel reference shadow mapping failed and rollback failed: {error:#}");
        }
        return Err(error);
    }
    engine.get_data_mut().apis.memory = planned_memory;
    Ok(MappingReceipt {
        reference_sections: reference_sections(view),
        scope: "Generated-test separate shadow: file-backed READ/NX code only; provider exports, modeled data and dispatch retain their original addresses.",
        guest_unload_history_enabled: false,
        mapping_mode: "separate_shadow",
        redirected_code_exports: 0,
        source_sha256: view.source_sha256.clone(),
        target_base: SHADOW_BASE,
        section_count: view.sections.len(),
        file_backed_bytes,
        mapped_bytes,
        read_only: true,
        non_executable: true,
        provider_dispatch_replaced: false,
        protected_data_replaced: false,
        reference_execution_admitted: false,
        reference_instructions_executed: false,
    })
}

/// Commit the complete integrated provider with model/catalog publication only
/// after native initialization and final protections succeed. No guest runs in
/// this startup transaction, and rollback is bounded to its single owned map.
pub(crate) fn map_integrated_provider(
    engine: &mut Unicorn<Trace>,
    pe: &emumee_core::pe::PeImage,
    bytes: &[u8],
    prepared: &IntegratedPrepared,
    redirected_code_exports: usize,
) -> Result<MappingReceipt> {
    ensure!(
        pe.image_base == PROVIDER_BASE
            && prepared.view.target_base == PROVIDER_BASE
            && engine.get_data().architecture == Architecture::X64
            && engine.get_data().apis.kernel_mode
            && engine.get_data().reference_spans.is_empty(),
        "Integrated reference target or authority differs"
    );
    let base = pe.image_base;
    let size = u64::from(pe.image_size);
    let end = base
        .checked_add(size)
        .ok_or_else(|| anyhow::anyhow!("Provider extent overflow"))?;
    ensure!(
        size <= 40 * 1024 * 1024,
        "Integrated reference provider exceeds reservation"
    );
    ensure!(
        uc(engine.mem_regions())?
            .iter()
            .all(|r| base > r.end || end <= r.begin),
        "Integrated reference overlaps existing native memory"
    );
    let image = pe.materialize(bytes, base)?;
    let mut memory = engine.get_data().apis.memory.clone();
    let mut modules = engine.get_data().apis.modules.clone();
    memory.map(base, size, P::NONE, None, "integrated kernel provider")?;
    modules.add_with_path(
        "ntoskrnl.exe",
        base,
        pe,
        r"C:\Windows\system32\ntoskrnl.exe",
        emumee_core::modules::ModuleOrigin::SyntheticProvider,
    )?;
    let mut protections = vec![(
        base,
        (u64::from(pe.headers_size) + PAGE - 1) & !(PAGE - 1),
        P::READ,
    )];
    for section in &pe.sections {
        let length =
            (u64::from(section.virtual_size.max(section.raw_size)) + PAGE - 1) & !(PAGE - 1);
        if length == 0 {
            continue;
        }
        let flags = section.characteristics;
        let permissions = P(u8::from(flags & 0x40000000 != 0)
            | (u8::from(flags & 0x80000000 != 0) << 1)
            | (u8::from(flags & 0x20000000 != 0) << 2));
        memory.protect(base + u64::from(section.rva), length, permissions)?;
        protections.push((base + u64::from(section.rva), length, permissions));
    }
    // Header protection belongs to the cloned plan too.
    memory.protect(protections[0].0, protections[0].1, P::READ)?;
    let mut file_backed_bytes = 0;
    let mut mapped_bytes = 0;
    for section in &prepared.view.sections {
        let address = base + u64::from(section.rva);
        let length = (section.bytes.len() as u64 + PAGE - 1) & !(PAGE - 1);
        ensure!(
            memory.allows(address, length, P::READ)
                && !memory.allows(address, 1, P::WRITE)
                && !memory.allows(address, 1, P::EXECUTE),
            "Integrated reference section permissions differ from READ/NX"
        );
        ensure!(
            pe.rva(bytes, section.rva, section.bytes.len())? == section.bytes,
            "Integrated reference bytes differ from prepared projection"
        );
        file_backed_bytes += section.bytes.len() as u64;
        mapped_bytes += length;
    }
    let unload = super::reference_unload::plan(engine, prepared)?;
    if let Some(plan) = &unload {
        let offset = usize::try_from(plan.page - base)?;
        ensure!(
            !memory.allows(plan.page, PAGE, P::READ)
                && image
                    .get(offset..offset + PAGE as usize)
                    .is_some_and(|data| data.iter().all(|byte| *byte == 0)),
            "Guest unload backing must be an inaccessible zero-initialized private gap"
        );
        memory.protect(plan.page, PAGE, P::READ)?;
        protections.push((plan.page, PAGE, P::READ));
    }
    uc(engine.mem_map(base, size, Prot::ALL))?;
    let mut unload_hook = None;
    let staged = (|| -> Result<()> {
        if let Some(plan) = &unload {
            unload_hook = Some(super::reference_unload::install_guard(engine, plan)?);
        }
        uc(engine.mem_write(base, &image))?;
        uc(engine.mem_protect(base, size, Prot::NONE))?;
        for (address, length, permissions) in &protections {
            let mut native = Prot::NONE;
            if permissions.contains(P::READ) {
                native |= Prot::READ;
            }
            if permissions.contains(P::WRITE) {
                native |= Prot::WRITE;
            }
            if permissions.contains(P::EXECUTE) {
                native |= Prot::EXEC;
            }
            uc(engine.mem_protect(*address, *length, native))?;
        }
        Ok(())
    })();
    if let Err(error) = staged {
        let hook_cleanup_failed = unload_hook.is_some_and(|hook| engine.remove_hook(hook).is_err());
        let mapping_cleanup_failed = engine.mem_unmap(base, size).is_err();
        if hook_cleanup_failed || mapping_cleanup_failed {
            bail!("Integrated reference initialization and native rollback failed: {error:#}");
        }
        return Err(error);
    }
    engine.get_data_mut().apis.memory = memory;
    engine.get_data_mut().apis.modules = modules;
    // Guard host API writes/fetch admission over all reference inspection and
    // private gaps; ordinary guest reads still follow actual page permissions.
    engine.get_data_mut().reference_spans = vec![(
        base + 0x42000,
        u64::from(prepared.view.image_size) - 0x42000,
    )];
    let unload_enabled = unload.is_some();
    if let Some(plan) = unload {
        super::reference_unload::publish(engine, plan);
    }
    Ok(MappingReceipt {
        guest_unload_history_enabled: unload_enabled,
        reference_sections: reference_sections(&prepared.view),
        scope: "Authenticated same-base relocated file-backed READ/NX code; only covered unmodeled code EAT targets are redirected. Modeled stubs/public globals retain RVAs, private reference gaps are NONE except byte-guarded explicit fresh-session unload fields when enabled; fallback symbols use relocated protected pages. No reference instruction execution or private function implementation.",
        mapping_mode: "provider_same_base",
        redirected_code_exports,
        source_sha256: prepared.view.source_sha256.clone(),
        target_base: base,
        section_count: prepared.view.sections.len(),
        file_backed_bytes,
        mapped_bytes,
        read_only: true,
        non_executable: true,
        provider_dispatch_replaced: false,
        protected_data_replaced: false,
        reference_execution_admitted: false,
        reference_instructions_executed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use emumee_core::{
        pe::{ImportName, PeImage},
        provider::{RelocatedCodeSection, catalog_image},
    };
    use unicorn_engine::unicorn_const::Prot;

    fn generated_view() -> RelocatedCodeView {
        let mut bytes = vec![0x90; 512];
        bytes[0x100..0x108].copy_from_slice(&0x1_8000_1234u64.to_le_bytes());
        RelocatedCodeView {
            source_sha256: "a".repeat(64),
            source_size: 4096,
            preferred_base: 0x1_4000_0000,
            target_base: SHADOW_BASE,
            image_size: 0x4000,
            sections: vec![RelocatedCodeSection {
                name: ".text".into(),
                rva: 0x1000,
                bytes,
            }],
        }
    }

    #[test]
    fn shadow_mapping_preserves_synthetic_dispatch_and_protected_pages() {
        let mut engine = crate::new_engine(Architecture::X64).unwrap();
        engine.get_data_mut().apis.kernel_mode = true;
        let provider_base = 0xffff_f800_0040_0000;
        let provider = catalog_image(
            Architecture::X64,
            provider_base,
            &[("ExAllocatePool2", 0x6800_0010)],
        )
        .unwrap();
        let pe = PeImage::parse(&provider.bytes, "ntoskrnl.exe").unwrap();
        crate::map_image(&mut engine, &pe, &provider.bytes, provider_base).unwrap();
        crate::protect_image(&mut engine, &pe).unwrap();
        engine
            .get_data_mut()
            .apis
            .modules
            .add("ntoskrnl.exe", provider_base, &pe)
            .unwrap();
        let dispatch = engine
            .get_data()
            .apis
            .modules
            .resolve("ntoskrnl.exe", &ImportName::Name("ExAllocatePool2".into()))
            .unwrap();
        let protected = provider_base + u64::from(provider.metadata.protected_rva);
        let before_provider = engine.mem_read_as_vec(provider_base + 0x1000, 16).unwrap();
        let view = generated_view();
        let receipt = map_projection(&mut engine, &view).unwrap();
        assert_eq!(receipt.section_count, 1);
        assert_eq!(receipt.file_backed_bytes, 512);
        assert_eq!(receipt.mapped_bytes, PAGE);
        assert!(receipt.read_only && receipt.non_executable);
        assert!(!receipt.provider_dispatch_replaced && !receipt.protected_data_replaced);
        assert!(!receipt.reference_execution_admitted && !receipt.reference_instructions_executed);
        assert_eq!(
            engine
                .get_data()
                .apis
                .modules
                .resolve("ntoskrnl.exe", &ImportName::Name("ExAllocatePool2".into()))
                .unwrap(),
            dispatch
        );
        assert_eq!(
            engine.mem_read_as_vec(provider_base + 0x1000, 16).unwrap(),
            before_provider
        );
        assert!(
            engine
                .get_data()
                .apis
                .memory
                .allows(provider_base + 0x1000, 1, P::EXECUTE)
        );
        assert!(!engine.get_data().apis.memory.allows(protected, 1, P::READ));
        assert!(
            engine
                .get_data()
                .apis
                .memory
                .allows(SHADOW_BASE + 0x1000, 1, P::READ)
        );
        assert!(
            !engine
                .get_data()
                .apis
                .memory
                .allows(SHADOW_BASE + 0x1000, 1, P::WRITE)
        );
        assert!(
            !engine
                .get_data()
                .apis
                .memory
                .allows(SHADOW_BASE + 0x1000, 1, P::EXECUTE)
        );
        assert_eq!(
            engine.mem_read_as_vec(SHADOW_BASE + 0x1100, 8).unwrap(),
            0x1_8000_1234u64.to_le_bytes()
        );
        let region = engine
            .mem_regions()
            .unwrap()
            .into_iter()
            .find(|row| row.begin == SHADOW_BASE + 0x1000)
            .unwrap();
        assert_eq!(region.perms, Prot::READ.0 as u32);
        let protected_region = engine
            .mem_regions()
            .unwrap()
            .into_iter()
            .find(|row| row.begin <= protected && protected <= row.end)
            .unwrap();
        assert_eq!(protected_region.perms, Prot::NONE.0 as u32);
        assert!(require_api_access(&engine, SHADOW_BASE + 0x1100, 1, P::READ).is_ok());
        assert!(require_api_access(&engine, SHADOW_BASE + 0x1100, 1, P::WRITE).is_err());
        assert!(require_api_access(&engine, SHADOW_BASE + 0x1100, 1, P::EXECUTE).is_err());
        assert!(require_api_access(&engine, SHADOW_BASE + 0x3000, 1, P::WRITE).is_ok());
        let probe = 0x30000;
        engine
            .mem_map(probe, PAGE, Prot::READ | Prot::WRITE)
            .unwrap();
        let mut write = vec![0x48, 0xa3];
        write.extend((SHADOW_BASE + 0x1100).to_le_bytes());
        engine.mem_write(probe, &write).unwrap();
        engine
            .mem_protect(probe, PAGE, Prot::READ | Prot::EXEC)
            .unwrap();
        assert!(
            engine
                .emu_start(probe, probe + write.len() as u64, 0, 1)
                .is_err()
        );
        assert!(
            engine
                .emu_start(SHADOW_BASE + 0x1000, SHADOW_BASE + 0x1001, 0, 1)
                .is_err()
        );
        assert!(crate::cpu::write(&mut engine, SHADOW_BASE + 0x1100, &[1]).is_err());
        assert_eq!(
            engine.mem_read_as_vec(SHADOW_BASE + 0x1100, 8).unwrap(),
            0x1_8000_1234u64.to_le_bytes()
        );
        let regions_before = engine.mem_regions().unwrap();
        assert!(map_projection(&mut engine, &view).is_err());
        assert_eq!(engine.mem_regions().unwrap(), regions_before);
        assert_eq!(engine.get_data().apis.providers.len(), 0);
    }

    #[test]
    fn malformed_or_overlapping_sections_refuse_before_any_native_mapping() {
        let mut engine = crate::new_engine(Architecture::X64).unwrap();
        engine.get_data_mut().apis.kernel_mode = true;
        assert!(require_api_access(&engine, SHADOW_BASE + 0x1100, 1, P::WRITE).is_ok());
        assert!(require_api_access(&engine, u64::MAX - 7, 8, P::WRITE).is_ok());
        let mut view = generated_view();
        view.sections.push(RelocatedCodeSection {
            name: ".other".into(),
            rva: 0x1000,
            bytes: vec![0; 512],
        });
        assert!(map_projection(&mut engine, &view).is_err());
        assert!(engine.mem_regions().unwrap().is_empty());
        assert!(engine.get_data().apis.memory.regions().next().is_none());
        let mut view = generated_view();
        view.sections[0].rva = 0x3000;
        view.sections[0].bytes = vec![0; 4097];
        assert!(map_projection(&mut engine, &view).is_err());
        assert!(engine.mem_regions().unwrap().is_empty());
        let mut view = generated_view();
        view.target_base += PAGE;
        assert!(map_projection(&mut engine, &view).is_err());
        assert!(engine.mem_regions().unwrap().is_empty());
    }
}

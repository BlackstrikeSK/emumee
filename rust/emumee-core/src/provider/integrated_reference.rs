//! Same-base reference inspection alongside unchanged modeled dispatch.
use super::*;
use crate::pe::{ExportTarget, PeImage};
use std::collections::{BTreeMap, BTreeSet};

pub struct IntegratedReferenceImage {
    pub image: CatalogImage,
    pub lock_rva: u32,
    pub redirected_exports: usize,
}

/// Authenticated reference identity used for a bounded PE-header sensitivity
/// experiment. The provider's export directory and sections remain modeled.
pub struct ReferenceHeaderIdentity {
    pub dos_prefix: Vec<u8>,
    pub pe_offset: usize,
    pub timestamp: u32,
    pub checksum: u32,
}

/// Build the complete provider before any native mapping. Reference bytes are
/// already relocated to `base`; only validated named code targets are rebound.
/// The ordinary provider builder and its no-reference layout are unchanged.
pub fn integrate_reference(
    image: CatalogImage,
    base: u64,
    view: &RelocatedCodeView,
    code_exports: &BTreeMap<String, u32>,
) -> Result<IntegratedReferenceImage, ProviderError> {
    integrate_reference_with_header(image, base, view, code_exports, None)
}

pub fn integrate_reference_with_header(
    mut image: CatalogImage,
    base: u64,
    view: &RelocatedCodeView,
    code_exports: &BTreeMap<String, u32>,
    header_identity: Option<&ReferenceHeaderIdentity>,
) -> Result<IntegratedReferenceImage, ProviderError> {
    if let Some(identity) = header_identity {
        if identity.pe_offset < 0x80
            || identity.pe_offset > 0x1000
            || identity.dos_prefix.len() != identity.pe_offset
            || identity.dos_prefix.get(..2) != Some(b"MZ".as_slice())
            || identity
                .dos_prefix
                .get(0x3c..0x40)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_le_bytes)
                != Some(identity.pe_offset as u32)
        {
            return Err(ProviderError("reference DOS header identity invalid"));
        }
    }
    let old = PeImage::parse(&image.bytes, "ntoskrnl.exe")
        .map_err(|_| ProviderError("invalid provider before reference integration"))?;
    if old.sample.architecture != Architecture::X64
        || old.image_base != base
        || view.target_base != base
        || view.image_size == 0
        || view.image_size > 24 * 1024 * 1024
        || view.image_size % 4096 != 0
        || old.sections.len() != 4
        || old.sections[0].name != ".text"
        || old.sections[1].name != ".edata"
        || old.sections[2].name != ".unmodel"
        || old.sections[3].name != ".emulock"
        || view.sections.is_empty()
        || view.sections.len() > 24
    {
        return Err(ProviderError("reference integration profile differs"));
    }
    let protected = view.image_size;
    let protected_size = u32::try_from(image.symbols.len())
        .ok()
        .and_then(|count| count.checked_mul(4096))
        .ok_or(ProviderError("reference protected range overflow"))?;
    let lock_rva = protected
        .checked_add(protected_size)
        .ok_or(ProviderError("reference lock range overflow"))?;
    let size = lock_rva
        .checked_add(4096)
        .filter(|size| *size <= 40 * 1024 * 1024)
        .ok_or(ProviderError(
            "integrated provider exceeds 40 MiB reservation",
        ))?;
    let mut ranges = vec![(0x1000u32, 0x2000u32), (0x2000, 0x42000)];
    let mut names = BTreeSet::from([".emuapi", ".edata", ".unmodel", ".emulock"]);
    for section in &view.sections {
        let length = u32::try_from(section.bytes.len())
            .map_err(|_| ProviderError("reference code length overflow"))?;
        let end = section
            .rva
            .checked_add(length)
            .and_then(|end| end.checked_add(4095))
            .map(|end| end & !4095)
            .ok_or(ProviderError("reference code bounds overflow"))?;
        if section.name.is_empty()
            || section.name.len() > 8
            || !section.name.is_ascii()
            || !names.insert(section.name.as_str())
            || length == 0
            || section.rva % 4096 != 0
            || end > view.image_size
            || ranges.iter().any(|(a, b)| section.rva < *b && *a < end)
        {
            return Err(ProviderError(
                "reference code overlaps provider storage or another section",
            ));
        }
        ranges.push((section.rva, end));
    }
    for (name, rva) in code_exports {
        if name.is_empty() || name.len() > 512 || !name.is_ascii() || view.read(*rva, 1).is_none() {
            return Err(ProviderError(
                "reference named code target is outside readable code",
            ));
        }
    }
    let ordinals: BTreeMap<_, _> = old
        .exports
        .iter()
        .flat_map(|export| {
            export
                .names
                .iter()
                .map(move |name| (name.as_str(), export.ordinal))
        })
        .collect();
    let mut redirected_exports = 0;
    let edata_raw = old.sections[1].raw_offset as usize;
    for (index, symbol) in image.symbols.iter_mut().enumerate() {
        symbol.rva = protected + index as u32 * 4096;
        let target = if symbol.kind == "code" {
            code_exports
                .get(&symbol.name)
                .copied()
                .inspect(|_| redirected_exports += 1)
                .unwrap_or(symbol.rva)
        } else {
            symbol.rva
        };
        let ordinal = *ordinals
            .get(symbol.name.as_str())
            .ok_or(ProviderError("protected symbol has no provider ordinal"))?;
        if ordinal == 0 {
            return Err(ProviderError("provider ordinal zero"));
        }
        dword(
            &mut image.bytes,
            edata_raw + 0x40 + (ordinal as usize - 1) * 4,
            target,
        );
    }
    let count = 4 + view.sections.len();
    let pe_offset = header_identity.map_or(0x80, |identity| identity.pe_offset);
    let optional = pe_offset + 24;
    let table = optional + 0xf0;
    let headers = (table + count * 40 + 511) & !511;
    if headers > 4096 {
        return Err(ProviderError(
            "integrated section headers exceed first page",
        ));
    }
    let mut bytes = vec![0u8; headers];
    if let Some(identity) = header_identity {
        bytes[..pe_offset].copy_from_slice(&identity.dos_prefix);
    } else {
        bytes[..pe_offset].copy_from_slice(&image.bytes[..pe_offset]);
    }
    bytes[pe_offset..table].copy_from_slice(&image.bytes[0x80..0x188]);
    if let Some(identity) = header_identity {
        dword(&mut bytes, pe_offset + 8, identity.timestamp);
        dword(&mut bytes, optional + 64, identity.checksum);
    }
    word(&mut bytes, pe_offset + 6, count as u16);
    dword(&mut bytes, optional + 56, size);
    dword(&mut bytes, optional + 60, headers as u32);
    let code_size = view
        .sections
        .iter()
        .try_fold(0x1000u32, |size, section| {
            size.checked_add(section.bytes.len() as u32)
        })
        .ok_or(ProviderError("integrated code size overflow"))?;
    dword(&mut bytes, optional + 4, code_size);
    // Reserve the section table in the header, then append disjoint raw spans.
    let mut sections = Vec::with_capacity(count);
    for (index, name) in [(0, ".emuapi"), (1, ".edata")] {
        let section = &old.sections[index];
        let start = section.raw_offset as usize;
        let end = start + section.raw_size as usize;
        sections.push((
            name.to_owned(),
            section.rva,
            section.virtual_size,
            section.characteristics,
            image.bytes[start..end].to_vec(),
        ));
    }
    for section in &view.sections {
        sections.push((
            section.name.clone(),
            section.rva,
            section.bytes.len() as u32,
            0x40000020,
            section.bytes.clone(),
        ));
    }
    sections.push((
        ".unmodel".into(),
        protected,
        protected_size,
        0x40,
        Vec::new(),
    ));
    sections.push((".emulock".into(), lock_rva, 4096, 0xc0000040, Vec::new()));
    for (index, (name, rva, virtual_size, flags, raw)) in sections.into_iter().enumerate() {
        let at = table + index * 40;
        bytes[at..at + name.len()].copy_from_slice(name.as_bytes());
        let offset = bytes.len();
        let raw_size = (raw.len() + 511) & !511;
        for (field, value) in [
            (8, virtual_size),
            (12, rva),
            (16, raw_size as u32),
            (20, if raw.is_empty() { 0 } else { offset as u32 }),
            (36, flags),
        ] {
            dword(&mut bytes, at + field, value);
        }
        bytes.extend_from_slice(&raw);
        bytes.resize(offset + raw_size, 0);
    }
    let parsed = PeImage::parse(&bytes, "ntoskrnl.exe")
        .map_err(|_| ProviderError("integrated reference provider PE invalid"))?;
    // Every modeled code target retains its exact stub RVA; data exports were
    // already replaced by explicit configured values before integration.
    for export in &old.exports {
        if export
            .names
            .iter()
            .any(|name| image.symbols.iter().any(|s| s.name == *name))
        {
            continue;
        }
        let new = parsed
            .exports
            .iter()
            .find(|new| new.ordinal == export.ordinal)
            .ok_or(ProviderError("integration lost a modeled export"))?;
        if !matches!((&export.target, &new.target),
            (ExportTarget::Address { rva: a }, ExportTarget::Address { rva: b }) if a == b)
        {
            return Err(ProviderError("integration changed modeled export dispatch"));
        }
    }
    image.bytes = bytes;
    image.metadata.protected_rva = protected;
    image.metadata.protected_size = protected_size;
    image.metadata.scope = "Modeled stubs and configured public globals retain their RVAs. Authenticated same-base relocated code is READ/NX inspection data; covered unmodeled code exports point to reference RVAs. Other private data and fallback symbols remain inaccessible.";
    Ok(IntegratedReferenceImage {
        image,
        lock_rva,
        redirected_exports,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn generated(base: u64) -> RelocatedCodeView {
        let mut bytes = vec![0x90; 512];
        bytes[0x100..0x108].copy_from_slice(&(base + 0x1234).to_le_bytes());
        RelocatedCodeView {
            source_sha256: "a".repeat(64),
            source_size: 4096,
            preferred_base: 0x140000000,
            target_base: base,
            image_size: 0x300000,
            sections: vec![RelocatedCodeSection {
                name: ".text".into(),
                rva: 0x200000,
                bytes,
            }],
        }
    }
    fn catalog(base: u64) -> CatalogImage {
        let mut image = catalog_image_with_data(
            Architecture::X64,
            base,
            &[("ExAllocatePool2", 0xfffff80200000000)],
            &[DataExport {
                name: "KeNumberProcessors",
                bytes: vec![12],
                alignment: 1,
            }],
        )
        .unwrap();
        append_kernel_lock_storage(&mut image).unwrap();
        image
    }
    #[test]
    fn generated_same_base_reference_rebinds_only_unmodeled_code_and_preserves_protected_pages() {
        let base = 0xfffff80000400000;
        let old = catalog(base);
        let before = PeImage::parse(&old.bytes, "ntoskrnl.exe").unwrap();
        let exports = BTreeMap::from([("ObFindHandleForObject".into(), 0x200100)]);
        let result = integrate_reference(old, base, &generated(base), &exports).unwrap();
        let pe = PeImage::parse(&result.image.bytes, "ntoskrnl.exe").unwrap();
        let target = |pe: &PeImage, name: &str| {
            pe.exports
                .iter()
                .find(|e| e.names.iter().any(|n| n == name))
                .unwrap()
                .target
                .clone()
        };
        assert_eq!(
            target(&pe, "ObFindHandleForObject"),
            ExportTarget::Address { rva: 0x200100 }
        );
        for name in ["ExAllocatePool2", "KeNumberProcessors"] {
            assert_eq!(target(&pe, name), target(&before, name));
        }
        assert_eq!(result.redirected_exports, 1);
        assert_eq!(result.image.metadata.protected_rva, 0x300000);
        assert_eq!(pe.sections[0].name, ".emuapi");
        assert_eq!(pe.sections[2].characteristics, 0x40000020);
        assert_eq!(
            pe.rva(&result.image.bytes, 0x200100, 8).unwrap(),
            (base + 0x1234).to_le_bytes()
        );
        assert!(
            pe.rva(&result.image.bytes, result.image.metadata.protected_rva, 1)
                .is_err()
        );
        assert_eq!(pe.sections.last().unwrap().rva, result.lock_rva);
        for (index, symbol) in result.image.symbols.iter().enumerate() {
            assert_eq!(symbol.rva, 0x300000 + index as u32 * 4096);
        }
    }
    #[test]
    fn authenticated_dos_offset_and_identity_keep_modeled_export_directory_coherent() {
        let base = 0xfffff80000400000;
        let mut dos_prefix = vec![0u8; 0x120];
        dos_prefix[..2].copy_from_slice(b"MZ");
        dos_prefix[0x3c..0x40].copy_from_slice(&0x120u32.to_le_bytes());
        dos_prefix[0x80..0x88].copy_from_slice(b"HOSTSTUB");
        let identity = ReferenceHeaderIdentity {
            dos_prefix,
            pe_offset: 0x120,
            timestamp: 0xaff6_531f,
            checksum: 0x00c8_ad9c,
        };
        let result = integrate_reference_with_header(
            catalog(base),
            base,
            &generated(base),
            &BTreeMap::from([("ObFindHandleForObject".into(), 0x200100)]),
            Some(&identity),
        )
        .unwrap();
        let pe = PeImage::parse(&result.image.bytes, "ntoskrnl.exe").unwrap();
        assert_eq!(u32::from_le_bytes(result.image.bytes[0x3c..0x40].try_into().unwrap()), 0x120);
        assert_eq!(&result.image.bytes[0x80..0x88], b"HOSTSTUB");
        assert_eq!(pe.accepted_headers().timestamp, identity.timestamp);
        assert_eq!(pe.accepted_headers().checksum, identity.checksum);
        assert_eq!(pe.sections[0].name, ".emuapi");
        assert!(pe.exports.iter().any(|export| {
            export.names.iter().any(|name| name == "ObFindHandleForObject")
                && matches!(export.target, ExportTarget::Address { rva: 0x200100 })
        }));
        let mut bad = identity;
        bad.dos_prefix[0x3c] = 0;
        assert!(integrate_reference_with_header(catalog(base), base, &generated(base), &BTreeMap::new(), Some(&bad)).is_err());
    }
    #[test]
    fn overlapping_reference_and_out_of_code_export_targets_are_rejected_before_mapping() {
        let base = 0xfffff80000400000;
        let mut view = generated(base);
        view.sections[0].rva = 0x1000;
        assert!(integrate_reference(catalog(base), base, &view, &BTreeMap::new()).is_err());
        let bad = BTreeMap::from([("ObFindHandleForObject".into(), 0x280000)]);
        assert!(integrate_reference(catalog(base), base, &generated(base), &bad).is_err());
    }
}

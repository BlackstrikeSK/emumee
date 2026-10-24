//! Bounded typed READ/NX exports alongside modeled routine gates. Data RVAs
//! lie outside the export-directory range, so PE readers cannot treat values
//! as forwarder strings. Existing routine-only image helpers remain unchanged.
use super::*;
use crate::pe::{ExportTarget, PeImage};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct DataExport {
    pub name: &'static str,
    pub bytes: Vec<u8>,
    pub alignment: usize,
}
fn layout(routines: &[(&str, u64)], data: &[DataExport]) -> Result<Vec<usize>, ProviderError> {
    if data.len() > 32 {
        return Err(ProviderError("typed data export count exceeds 32"));
    }
    let mut names: BTreeSet<&str> = routines.iter().map(|(name, _)| *name).collect();
    let mut offsets = Vec::with_capacity(data.len());
    let mut cursor = 0usize;
    for item in data {
        if item.name.is_empty()
            || item.name.len() > 128
            || !item.name.bytes().all(|b| b.is_ascii_graphic())
            || !names.insert(item.name)
            || item.bytes.is_empty()
            || item.bytes.len() > 4096
            || !item.alignment.is_power_of_two()
            || item.alignment > 16
        {
            return Err(ProviderError(
                "invalid, duplicate or conflicting typed data export",
            ));
        }
        cursor = (cursor + item.alignment - 1) & !(item.alignment - 1);
        offsets.push(cursor);
        cursor = cursor
            .checked_add(item.bytes.len())
            .ok_or(ProviderError("typed data size overflow"))?;
        if cursor > 4096 {
            return Err(ProviderError("typed data exports exceed reserved page"));
        }
    }
    Ok(offsets)
}
fn ordinals(bytes: &[u8]) -> Result<BTreeMap<String, usize>, ProviderError> {
    let pe = PeImage::parse(bytes, "typed-provider.dll")
        .map_err(|_| ProviderError("invalid generated provider"))?;
    let mut result = BTreeMap::new();
    for export in pe.exports {
        if !matches!(export.target, ExportTarget::Address { .. }) || export.ordinal == 0 {
            return Err(ProviderError("unexpected generated ordinal or forwarder"));
        }
        for name in export.names {
            result.insert(name, export.ordinal as usize - 1);
        }
    }
    Ok(result)
}
pub fn image_with_data(
    architecture: Architecture,
    base: u64,
    module: &str,
    routines: &[(&str, u64)],
    data: &[DataExport],
) -> Result<Vec<u8>, ProviderError> {
    let offsets = layout(routines, data)?;
    if data.is_empty() {
        return image(architecture, base, module, routines);
    }
    let end = base
        .checked_add(0x7000)
        .ok_or(ProviderError("typed provider base overflow"))?;
    if architecture == Architecture::X86 && end > 1u64 << 32 {
        return Err(ProviderError("typed provider exceeds x86 address space"));
    }
    let mut all = routines.to_vec();
    all.extend(data.iter().map(|item| (item.name, 1)));
    let mut bytes = image(architecture, base, module, &all)?;
    let ordinals = ordinals(&bytes)?;
    bytes.resize(0x6200, 0);
    word(&mut bytes, 0x86, 3);
    dword(&mut bytes, 0x98 + 8, 0x5000);
    dword(&mut bytes, 0x98 + 56, 0x7000);
    let at =
        0x98 + if architecture == Architecture::X64 {
            0xf0
        } else {
            0xe0
        } + 80;
    bytes[at..at + 8].copy_from_slice(b".modeld\0");
    for (offset, value) in [
        (8, 0x1000),
        (12, 0x6000),
        (16, 0x1000),
        (20, 0x5200),
        (36, 0x40000040),
    ] {
        dword(&mut bytes, at + offset, value);
    }
    for (item, offset) in data.iter().zip(offsets) {
        let ordinal = *ordinals
            .get(item.name)
            .ok_or(ProviderError("missing typed data ordinal"))?;
        dword(&mut bytes, 0x1240 + ordinal * 4, 0x6000 + offset as u32);
        bytes[0x5200 + offset..0x5200 + offset + item.bytes.len()].copy_from_slice(&item.bytes);
    }
    Ok(bytes)
}
pub fn catalog_image_with_data(
    architecture: Architecture,
    base: u64,
    routines: &[(&str, u64)],
    data: &[DataExport],
) -> Result<CatalogImage, ProviderError> {
    let offsets = layout(routines, data)?;
    if data
        .iter()
        .any(|item| kernel_export_kind(item.name) != Some("data"))
    {
        return Err(ProviderError(
            "typed kernel global lacks reference data classification",
        ));
    }
    let mut image = catalog_image(architecture, base, routines)?;
    if data.is_empty() {
        return Ok(image);
    }
    let ordinals = ordinals(&image.bytes)?;
    let string_end = 0xb300 + 13 + ordinals.keys().map(|name| name.len() + 1).sum::<usize>();
    if string_end > 0x40200 {
        return Err(ProviderError(
            "reference strings overlap typed data reservation",
        ));
    }
    // The final existing .edata page remains READ/NX; exclude it from the
    // export directory itself. No fourth section/header or code relocation.
    dword(&mut image.bytes, 0x98 + 112 + 4, 0x3f000);
    for (item, offset) in data.iter().zip(offsets) {
        let ordinal = *ordinals
            .get(item.name)
            .ok_or(ProviderError("missing classified data ordinal"))?;
        dword(
            &mut image.bytes,
            0x1240 + ordinal * 4,
            0x41000 + offset as u32,
        );
        image.bytes[0x40200 + offset..0x40200 + offset + item.bytes.len()]
            .copy_from_slice(&item.bytes);
    }
    image
        .symbols
        .retain(|symbol| !data.iter().any(|item| item.name == symbol.name));
    // Keep protected pages contiguous: engine denial lookup indexes this list
    // by (fault-rva-protected_rva)/4096 and must retain exact name ownership.
    for (index, symbol) in image.symbols.iter_mut().enumerate() {
        symbol.rva = image.metadata.protected_rva + index as u32 * 4096;
        let ordinal = *ordinals
            .get(&symbol.name)
            .ok_or(ProviderError("missing protected data ordinal"))?;
        dword(&mut image.bytes, 0x1240 + ordinal * 4, symbol.rva);
    }
    image.metadata.protected_symbols = image.symbols.len();
    image.metadata.protected_size = image.symbols.len() as u32 * 4096;
    dword(
        &mut image.bytes,
        0x98 + 56,
        image.metadata.protected_rva + image.metadata.protected_size,
    );
    dword(
        &mut image.bytes,
        0x98 + 0xf0 + 80 + 8,
        image.metadata.protected_size,
    );
    image.metadata.scope = "x64 build 22631 reference-classified names; generated ordinals/addresses. Explicit configured globals use READ/NX data; other unimplemented code/data retain individual no-access pages. No reference binary bytes or private data values.";
    Ok(image)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn globals() -> Vec<DataExport> {
        vec![
            DataExport {
                name: "KeNumberProcessors",
                bytes: vec![12],
                alignment: 1,
            },
            DataExport {
                name: "MmHighestUserAddress",
                bytes: 0x7fff_fffe_ffffu64.to_le_bytes().to_vec(),
                alignment: 8,
            },
            DataExport {
                name: "MmUserProbeAddress",
                bytes: 0x7fff_ffff_0000u64.to_le_bytes().to_vec(),
                alignment: 8,
            },
        ]
    }
    fn check(bytes: &[u8], base: u64, data: &[DataExport]) {
        let pe = PeImage::parse(bytes, "ntoskrnl.exe").unwrap();
        let loaded = pe.materialize(bytes, base).unwrap();
        for item in data {
            let export = pe
                .exports
                .iter()
                .find(|e| e.names.iter().any(|name| name == item.name))
                .unwrap();
            let ExportTarget::Address { rva } = export.target else {
                panic!("global decoded as forwarder")
            };
            assert_eq!(rva as usize % item.alignment, 0);
            assert_eq!(
                &loaded[rva as usize..rva as usize + item.bytes.len()],
                &item.bytes
            );
            let section = pe
                .sections
                .iter()
                .find(|s| rva >= s.rva && rva < s.rva + s.virtual_size)
                .unwrap();
            assert_eq!(section.characteristics & 0xe0000000, 0x40000000);
        }
    }
    #[test]
    fn data_only_and_mixed_provider_exports_are_real_read_nx_addresses() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let base = if architecture == Architecture::X64 {
                0xfffff80000400000
            } else {
                0x80400000
            };
            let data = globals();
            for routines in [vec![], vec![("KeGetCurrentProcessorNumber", 0x82000000)]] {
                let bytes =
                    image_with_data(architecture, base, "ntoskrnl.exe", &routines, &data).unwrap();
                check(&bytes, base, &data);
                let pe = PeImage::parse(&bytes, "ntoskrnl.exe").unwrap();
                assert_eq!(pe.sections.len(), 3);
                assert_eq!(pe.image_size, 0x7000);
            }
        }
    }
    #[test]
    fn classified_data_replace_only_their_pages_and_repack_protected_denials() {
        let base = 0xfffff80000400000;
        let data = globals();
        let routines = [("KeGetCurrentProcessorNumber", 0xfffff80200000000)];
        let old = catalog_image(Architecture::X64, base, &routines).unwrap();
        let image = catalog_image_with_data(Architecture::X64, base, &routines, &data).unwrap();
        check(&image.bytes, base, &data);
        assert_eq!(old.symbols.len() - image.symbols.len(), 3);
        assert_eq!(image.metadata.reference_data_symbols, 77);
        let pe = PeImage::parse(&image.bytes, "ntoskrnl.exe").unwrap();
        assert_eq!(pe.exports.len(), 3258);
        assert_eq!(
            image.metadata.modeled_extensions,
            ["KeGetCurrentProcessorNumber"]
        );
        for (index, symbol) in image.symbols.iter().enumerate() {
            assert_eq!(
                symbol.rva,
                image.metadata.protected_rva + index as u32 * 4096
            );
            assert_eq!(
                pe.exports
                    .iter()
                    .find(|e| e.names.contains(&symbol.name))
                    .unwrap()
                    .target,
                ExportTarget::Address { rva: symbol.rva }
            );
        }
        assert!(
            image
                .symbols
                .iter()
                .any(|s| s.name == "PsInitialSystemProcess" && s.kind == "data")
        );
    }
    #[test]
    fn malformed_duplicate_classification_count_and_page_overflow_are_rejected() {
        let make = |data: &[DataExport]| {
            image_with_data(Architecture::X86, 0x80400000, "ntoskrnl.exe", &[], data)
        };
        let mut data = globals();
        data[0].alignment = 3;
        assert!(make(&data).is_err());
        data = globals();
        data[0].bytes.clear();
        assert!(make(&data).is_err());
        data = globals();
        data[0].bytes = vec![0; 4096];
        assert!(make(&data).is_err());
        data = globals();
        data.push(data[0].clone());
        assert!(make(&data).is_err());
        assert!(make(&vec![globals()[0].clone(); 33]).is_err());
        assert!(
            image_with_data(
                Architecture::X86,
                0xffff9000,
                "ntoskrnl.exe",
                &[],
                &globals()
            )
            .is_ok()
        );
        assert!(
            image_with_data(
                Architecture::X86,
                0xffffa000,
                "ntoskrnl.exe",
                &[],
                &globals()
            )
            .is_err()
        );
        assert!(
            image_with_data(
                Architecture::X86,
                0x80400000,
                "ntoskrnl.exe",
                &[("KeNumberProcessors", 1)],
                &globals()
            )
            .is_err()
        );
        let unknown = [DataExport {
            name: "NotAReferenceDataSymbol",
            bytes: vec![1],
            alignment: 1,
        }];
        assert!(
            catalog_image_with_data(
                Architecture::X64,
                0xfffff80000400000,
                &[("KeGetCurrentProcessorNumber", 1)],
                &unknown
            )
            .is_err()
        );
    }
}

//! Reference-classified names with generated ordinals and inaccessible pages
//! for unimplemented code/data. No genuine function bytes or data values.
use super::*;
use crate::pe::{ExportTarget, PeImage};
use serde::Serialize;
use std::collections::BTreeMap;
#[path = "kernel_exports.rs"]
mod kernel_exports;
use kernel_exports::*;

pub(super) const PINNED_REFERENCE_SHA256: &str = SOURCE_SHA256;

#[derive(Clone, Debug, Serialize)]
pub struct ProtectedSymbol {
    pub name: String,
    pub kind: &'static str,
    pub rva: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct CatalogMetadata {
    pub source_file_version: &'static str,
    pub source_image_sha256: &'static str,
    pub source_url: &'static str,
    pub catalog_metadata_sha256: &'static str,
    pub ported_classification_sha256: &'static str,
    pub reference_code_symbols: usize,
    pub reference_data_symbols: usize,
    pub modeled_extensions: Vec<String>,
    pub protected_symbols: usize,
    pub protected_rva: u32,
    pub protected_size: u32,
    pub scope: &'static str,
}
pub struct CatalogImage {
    pub bytes: Vec<u8>,
    pub symbols: Vec<ProtectedSymbol>,
    pub metadata: CatalogMetadata,
}

/// Append one zero-initialized, writable/NX page to the generated ntoskrnl
/// image for the PRCB queued-spin-lock backing. It is a real PE section so
/// ordinary image mapping, page protection and module extent all agree.
pub fn append_kernel_lock_storage(image: &mut CatalogImage) -> Result<u32, ProviderError> {
    let old = PeImage::parse(&image.bytes, "ntoskrnl.exe")
        .map_err(|_| ProviderError("invalid modeled ntoskrnl before lock storage"))?;
    if old.sample.architecture != Architecture::X64
        || old.sections.len() != 3
        || old.sections[0].name != ".text"
        || old.sections[1].name != ".edata"
        || old.sections[2].name != ".unmodel"
        || old.headers_size != 0x200
        || old.sections[0].raw_offset != 0x200
        || old.sections[1].raw_offset != 0x1200
        || old.sections[2].raw_size != 0
    {
        return Err(ProviderError(
            "modeled ntoskrnl layout differs from lock-storage profile",
        ));
    }
    let lock_rva = old.image_size;
    let end = lock_rva
        .checked_add(4096)
        .ok_or(ProviderError("lock storage image size overflow"))?;
    if end >= 16 * 1024 * 1024 {
        return Err(ProviderError(
            "lock storage exceeds ntoskrnl provider reservation",
        ));
    }
    // Four section headers require a second file-header block. Move the two
    // existing file-backed sections together; their guest RVAs do not change.
    image.bytes.splice(0x200..0x200, [0u8; 0x200]);
    let table = 0x98 + 0xf0;
    dword(&mut image.bytes, table + 20, 0x400);
    dword(&mut image.bytes, table + 40 + 20, 0x1400);
    word(&mut image.bytes, 0x86, 4);
    dword(&mut image.bytes, 0x98 + 56, end);
    dword(&mut image.bytes, 0x98 + 60, 0x400);
    let at = table + 3 * 40;
    image.bytes[at..at + 8].copy_from_slice(b".emulock");
    for (offset, value) in [(8, 4096), (12, lock_rva), (36, 0xc0000040)] {
        dword(&mut image.bytes, at + offset, value);
    }
    PeImage::parse(&image.bytes, "ntoskrnl.exe")
        .map_err(|_| ProviderError("invalid modeled ntoskrnl lock-storage section"))?;
    image.metadata.scope = "x64 build 22631 reference-classified names; generated ordinals/addresses. Explicit configured globals use READ/NX data, PRCB lock backing uses a separate RW/NX page, and other unimplemented code/data retain individual no-access pages. No reference binary bytes or private data values.";
    Ok(lock_rva)
}
pub fn kernel_export_kind(name: &str) -> Option<&'static str> {
    if CODE_EXPORTS.contains(&name) {
        Some("code")
    } else if DATA_EXPORTS.contains(&name) {
        Some("data")
    } else {
        None
    }
}
pub fn catalog_image(
    architecture: Architecture,
    base: u64,
    exports: &[(&str, u64)],
) -> Result<CatalogImage, ProviderError> {
    if architecture != Architecture::X64 {
        return Err(ProviderError(
            "reference classification requires x64 build 22631 profile",
        ));
    }
    let mut bytes = image(architecture, base, "ntoskrnl.exe", exports)?;
    let old = PeImage::parse(&bytes, "ntoskrnl.exe")
        .map_err(|_| ProviderError("invalid modeled provider"))?;
    let mut entries = BTreeMap::<String, (&'static str, Option<u32>)>::new();
    for name in CODE_EXPORTS {
        entries.insert((*name).into(), ("code", None));
    }
    for name in DATA_EXPORTS {
        entries.insert((*name).into(), ("data", None));
    }
    let mut extensions = Vec::new();
    for export in old.exports {
        let ExportTarget::Address { rva } = export.target else {
            return Err(ProviderError("modeled forwarder is not supported"));
        };
        for name in export.names {
            match entries.get(&name) {
                Some(("data", _)) => {
                    return Err(ProviderError(
                        "modeled routine conflicts with a classified data export",
                    ));
                }
                None => extensions.push(name.clone()),
                _ => {}
            }
            entries.insert(name, ("code", Some(rva)));
        }
    }
    if entries.len() > 4096 {
        return Err(ProviderError("reference catalog exceeds 4096 symbols"));
    }
    let unknown = entries.values().filter(|(_, rva)| rva.is_none()).count();
    let protected_rva = 0x42000u32;
    let protected_size = unknown as u32 * 4096;
    let image_size = protected_rva + protected_size;
    if image_size >= 16 * 1024 * 1024 || base.checked_add(image_size as u64).is_none() {
        return Err(ProviderError(
            "reference catalog exceeds provider reservation",
        ));
    }
    bytes.resize(0x41200, 0);
    bytes[0x1200..].fill(0);
    word(&mut bytes, 0x86, 3);
    dword(&mut bytes, 0x98 + 8, 0x40000);
    dword(&mut bytes, 0x98 + 56, image_size);
    dword(&mut bytes, 0x98 + 112 + 4, 0x40000);
    let sections = 0x98 + 0xf0;
    dword(&mut bytes, sections + 40 + 8, 0x40000);
    dword(&mut bytes, sections + 40 + 16, 0x40000);
    let at = sections + 80;
    bytes[at..at + 8].copy_from_slice(b".unmodel");
    for (offset, value) in [
        (8, protected_size),
        (12, protected_rva),
        (16, 0),
        (20, 0),
        (36, 0x40),
    ] {
        dword(&mut bytes, at + offset, value);
    }
    for (offset, value) in [
        (16, 1),
        (20, entries.len() as u32),
        (24, entries.len() as u32),
        (28, 0x2040),
        (32, 0x6040),
        (36, 0xa040),
    ] {
        dword(&mut bytes, 0x1200 + offset, value);
    }
    let mut string = 0xb300usize; // RVA 0xc100: after all three bounded tables.
    dword(&mut bytes, 0x120c, (string + 0xe00) as u32);
    bytes[string..string + 13].copy_from_slice(b"ntoskrnl.exe\0");
    string += 13;
    let mut symbols = Vec::with_capacity(unknown);
    for (index, (name, (kind, rva))) in entries.into_iter().enumerate() {
        if string + name.len() + 1 > bytes.len() {
            return Err(ProviderError("reference catalog strings exceed bound"));
        }
        let rva = rva.unwrap_or_else(|| {
            let rva = protected_rva + symbols.len() as u32 * 4096;
            symbols.push(ProtectedSymbol {
                name: name.clone(),
                kind,
                rva,
            });
            rva
        });
        dword(&mut bytes, 0x1240 + index * 4, rva);
        dword(&mut bytes, 0x5240 + index * 4, (string + 0xe00) as u32);
        word(&mut bytes, 0x9240 + index * 2, index as u16);
        bytes[string..string + name.len()].copy_from_slice(name.as_bytes());
        string += name.len() + 1;
    }
    Ok(CatalogImage {
        bytes,
        symbols,
        metadata: CatalogMetadata {
            source_file_version: SOURCE_FILE_VERSION,
            source_image_sha256: SOURCE_SHA256,
            source_url: SOURCE_URL,
            catalog_metadata_sha256: CATALOG_METADATA_SHA256,
            ported_classification_sha256: PORTED_CLASSIFICATION_SHA256,
            reference_code_symbols: CODE_EXPORTS.len(),
            reference_data_symbols: DATA_EXPORTS.len(),
            modeled_extensions: extensions,
            protected_symbols: unknown,
            protected_rva,
            protected_size,
            scope: "x64 build 22631 reference-classified names; generated ordinals/addresses, no reference bytes or private data values. Unimplemented code and data use individual no-access pages. Modeled compatibility extensions are listed separately.",
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    #[test]
    fn ported_classification_is_bounded_disjoint_and_digest_bound() {
        assert_eq!(CODE_EXPORTS.len(), 3180);
        assert_eq!(DATA_EXPORTS.len(), 77);
        let mut names = BTreeSet::new();
        let mut digest = Sha256::new();
        for (kind, group) in [("code", CODE_EXPORTS), ("data", DATA_EXPORTS)] {
            for name in group {
                assert!(names.insert(*name));
                digest.update(kind);
                digest.update([0]);
                digest.update(name);
                digest.update(b"\n");
            }
        }
        assert_eq!(
            format!("{:x}", digest.finalize()),
            PORTED_CLASSIFICATION_SHA256
        );
    }
    #[test]
    fn unimplemented_code_and_data_have_distinct_non_file_backed_protected_pages() {
        let base = 0xfffff80000400000;
        let image = catalog_image(
            Architecture::X64,
            base,
            &[
                ("MmGetSystemRoutineAddress", 0xfffff80200000000),
                ("EmumeeModelExtension", 0xfffff80200000010),
            ],
        )
        .unwrap();
        let pe = PeImage::parse(&image.bytes, "ntoskrnl.exe").unwrap();
        assert_eq!(pe.exports.len(), 3258);
        assert_eq!(image.metadata.modeled_extensions, ["EmumeeModelExtension"]);
        assert_eq!(image.symbols.len(), 3256);
        assert_eq!(pe.sections[2].characteristics, 0x40);
        let code = image
            .symbols
            .iter()
            .find(|s| s.name == "KeDelayExecutionThread")
            .unwrap();
        let data = image
            .symbols
            .iter()
            .find(|s| s.name == "PsInitialSystemProcess")
            .unwrap();
        assert_eq!(code.kind, "code");
        assert_eq!(data.kind, "data");
        assert_ne!(code.rva, data.rva);
        assert!(pe.rva(&image.bytes, code.rva, 1).is_err());
        assert!(pe.rva(&image.bytes, data.rva, 1).is_err());
        assert!(pe.image_size < 16 * 1024 * 1024);
        pe.materialize(&image.bytes, base).unwrap();
        assert!(catalog_image(Architecture::X86, 0x80400000, &[("A", 0x82000000)]).is_err());
    }

    #[test]
    fn lock_storage_is_separate_rw_nx_section_after_protected_symbols() {
        let base = 0xfffff80000400000;
        let mut image = crate::provider::catalog_image_with_data(
            Architecture::X64,
            base,
            &[("RtlPcToFileHeader", 0xfffff80200000000)],
            &[crate::provider::DataExport {
                name: "KeNumberProcessors",
                bytes: vec![6],
                alignment: 1,
            }],
        )
        .unwrap();
        let before = PeImage::parse(&image.bytes, "ntoskrnl.exe").unwrap();
        let lock_rva = append_kernel_lock_storage(&mut image).unwrap();
        let after = PeImage::parse(&image.bytes, "ntoskrnl.exe").unwrap();
        assert_eq!(lock_rva, before.image_size);
        assert_eq!(after.image_size, before.image_size + 4096);
        assert_eq!(after.headers_size, 0x400);
        assert_eq!(after.sections.len(), 4);
        assert_eq!(after.sections[3].name, ".emulock");
        assert_eq!(after.sections[3].rva, lock_rva);
        assert_eq!(after.sections[3].virtual_size, 4096);
        assert_eq!(after.sections[3].raw_size, 0);
        assert_eq!(after.sections[3].characteristics, 0xc0000040);
        let materialized = after.materialize(&image.bytes, base).unwrap();
        assert!(
            materialized[lock_rva as usize..]
                .iter()
                .all(|byte| *byte == 0)
        );
        assert_eq!(&materialized[0x1000..0x1002], &[0xff, 0x25]);
        assert_eq!(materialized[0x41000], 6);
        assert_eq!(
            image.metadata.protected_rva + image.metadata.protected_size,
            lock_rva
        );
    }
}

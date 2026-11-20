//! Synthetic guest PE providers. These are modeled export surfaces, not copies
//! of Windows binaries or evidence that an unlisted Windows export is absent.
use crate::pe::Architecture;
use std::collections::BTreeSet;
use thiserror::Error;
mod integrated_reference;
mod kernel;
mod metadata;
mod reference_code;
pub use integrated_reference::{IntegratedReferenceImage, ReferenceHeaderIdentity, integrate_reference, integrate_reference_with_header};
mod typed;
pub use kernel::{
    CatalogImage, CatalogMetadata, ProtectedSymbol, append_kernel_lock_storage, catalog_image,
    kernel_export_kind,
};
pub use metadata::{
    MetadataEvidence, MetadataExport, MetadataImage, MetadataProfile, metadata_image,
};
pub use reference_code::{
    CodeSection, CodeView, RelocatedCodeSection, RelocatedCodeView, inspect_pinned_nt22631,
    relocate_pinned_nt22631, relocate_pinned_nt26200,
};
pub use typed::{DataExport, catalog_image_with_data, image_with_data, image_with_mutable_data};

#[derive(Debug, Error)]
#[error("Synthetic PE provider: {0}")]
pub struct ProviderError(pub &'static str);

/// Virtual and raw size of the export-directory section in every provider.
pub(crate) const EDATA: usize = 0x4000;
/// Export count a provider image can hold before its stub section needs a
/// second page. Typed data providers keep this single-page geometry.
pub(crate) const SINGLE_PAGE_EXPORTS: usize = 256;

fn word(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn dword(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn qword(data: &mut [u8], at: usize, value: u64) {
    data[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// Every export is a register-preserving indirect jump to a guest-only gate.
pub fn image(
    architecture: Architecture,
    base: u64,
    module: &str,
    exports: &[(&str, u64)],
) -> Result<Vec<u8>, ProviderError> {
    let valid_name =
        |s: &str| !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_graphic());
    // Each export owns a 16-byte jump stub, so the stub section takes a second
    // page once a modeled namespace passes 256 exports. Everything else keeps
    // its original geometry, and the raw-to-virtual delta stays 0xe00 in both
    // tiers, so every smaller provider image is byte-for-byte unchanged.
    let stubs = if exports.len() <= 256 { 0x1000usize } else { 0x2000 };
    let directory = 0x200 + stubs;
    let directory_rva = 0x1000 + stubs;
    let image_size = 0x1000 + stubs + EDATA;
    let end = base
        .checked_add(image_size as u64)
        .ok_or(ProviderError("base overflow"))?;
    if base == 0
        || base % 4096 != 0
        || !valid_name(module)
        || exports.is_empty()
        || exports.len() > 512
    {
        return Err(ProviderError("invalid base, module or export count"));
    }
    let wide = architecture == Architecture::X64;
    if !wide && end > 1u64 << 32 {
        return Err(ProviderError("provider exceeds x86 address space"));
    }
    let mut seen = BTreeSet::new();
    for (name, gate) in exports {
        if !valid_name(name)
            || !seen.insert(*name)
            || *gate == 0
            || (!wide && *gate > u32::MAX as u64)
        {
            return Err(ProviderError("invalid or duplicate export/gate"));
        }
    }
    let mut exports = exports.to_vec();
    exports.sort_unstable_by_key(|(name, _)| *name);
    let mut data = vec![0u8; directory + EDATA];
    data[..2].copy_from_slice(b"MZ");
    dword(&mut data, 0x3c, 0x80);
    data[0x80..0x84].copy_from_slice(b"PE\0\0");
    word(&mut data, 0x84, if wide { 0x8664 } else { 0x14c });
    word(&mut data, 0x86, 2);
    word(&mut data, 0x94, if wide { 0xf0 } else { 0xe0 });
    word(&mut data, 0x96, 0x2023); // Fixed-base synthetic DLL; relocations stripped.
    let o = 0x98;
    word(&mut data, o, if wide { 0x20b } else { 0x10b });
    dword(&mut data, o + 4, stubs as u32);
    dword(&mut data, o + 8, EDATA as u32);
    dword(&mut data, o + 20, 0x1000);
    if wide {
        qword(&mut data, o + 24, base);
    } else {
        dword(&mut data, o + 24, directory_rva as u32);
        dword(&mut data, o + 28, base as u32);
    }
    dword(&mut data, o + 32, 4096);
    dword(&mut data, o + 36, 512);
    dword(&mut data, o + 56, image_size as u32);
    dword(&mut data, o + 60, 512);
    word(&mut data, o + 68, 3);
    dword(&mut data, o + if wide { 108 } else { 92 }, 16);
    let dd = o + if wide { 112 } else { 96 };
    dword(&mut data, dd, directory_rva as u32);
    dword(&mut data, dd + 4, EDATA as u32);
    let table = o + if wide { 0xf0 } else { 0xe0 };
    for (index, name, rva, raw, size, flags) in [
        (0, b".text\0\0\0", 0x1000u32, 0x200u32, stubs as u32, 0x60000020u32),
        (
            1,
            b".edata\0\0",
            directory_rva as u32,
            directory as u32,
            EDATA as u32,
            0x40000040,
        ),
    ] {
        let at = table + index * 40;
        data[at..at + 8].copy_from_slice(name);
        for (offset, value) in [(8, size), (12, rva), (16, size), (20, raw), (36, flags)] {
            dword(&mut data, at + offset, value);
        }
    }
    // Keep the original layout byte-for-byte for existing providers. A larger
    // ntoskrnl modeled surface needs disjoint export arrays; 256 stubs still
    // fit exactly in the dedicated .text page.
    let (address_table, name_table, ordinal_table, mut string) = if exports.len() <= 128 {
        (0x40usize, 0x240usize, 0x440usize, 0x600usize)
    } else if exports.len() <= 256 {
        (0x40usize, 0x440usize, 0x840usize, 0xa40usize)
    } else {
        (0x40usize, 0x840usize, 0x1040usize, 0x1440usize)
    };
    let (address_table, name_table, ordinal_table) = (
        directory + address_table,
        directory + name_table,
        directory + ordinal_table,
    );
    string += directory;
    for (offset, value) in [
        (16, 1),
        (20, exports.len() as u32),
        (24, exports.len() as u32),
        (28, (address_table + 0xe00) as u32),
        (32, (name_table + 0xe00) as u32),
        (36, (ordinal_table + 0xe00) as u32),
    ] {
        dword(&mut data, directory + offset, value);
    }
    dword(&mut data, directory + 0xc, (string + 0xe00) as u32);
    data[string..string + module.len()].copy_from_slice(module.as_bytes());
    string += module.len() + 1;
    for (index, (name, gate)) in exports.iter().enumerate() {
        if string + name.len() + 1 > data.len() {
            return Err(ProviderError("export strings exceed image"));
        }
        dword(
            &mut data,
            address_table + index * 4,
            0x1000 + index as u32 * 16,
        );
        dword(&mut data, name_table + index * 4, (string + 0xe00) as u32);
        word(&mut data, ordinal_table + index * 2, index as u16);
        data[string..string + name.len()].copy_from_slice(name.as_bytes());
        string += name.len() + 1;
        let at = 0x200 + index * 16;
        data[at..at + 16].fill(0xcc);
        data[at..at + 2].copy_from_slice(&[0xff, 0x25]);
        dword(
            &mut data,
            at + 2,
            if wide {
                0
            } else {
                (base + 0x1000 + index as u64 * 16 + 6) as u32
            },
        );
        if wide {
            qword(&mut data, at + 6, *gate);
        } else {
            dword(&mut data, at + 6, *gate as u32);
        }
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{ExportTarget, PeImage};
    #[test]
    fn providers_have_checked_sorted_exports_and_pointer_width_correct_guest_jumps() {
        for arch in [Architecture::X86, Architecture::X64] {
            let base = if arch == Architecture::X64 {
                0xfffff80000400000
            } else {
                0x80400000
            };
            let gate = if arch == Architecture::X64 {
                0xfffff80200000000
            } else {
                0x82000000
            };
            let bytes = image(
                arch,
                base,
                "ntoskrnl.exe",
                &[("Zulu", gate + 16), ("Alpha", gate)],
            )
            .unwrap();
            let pe = PeImage::parse(&bytes, "ntoskrnl.exe").unwrap();
            assert_eq!(pe.entry_rva, 0);
            assert_eq!(pe.exports[0].names, ["Alpha"]);
            assert_eq!(pe.exports[0].target, ExportTarget::Address { rva: 0x1000 });
            let loaded = pe.materialize(&bytes, base).unwrap();
            assert_eq!(&loaded[0x1000..0x1002], &[0xff, 0x25]);
            assert_eq!(
                &loaded[0x1006..0x1006 + arch.width()],
                &gate.to_le_bytes()[..arch.width()]
            );
            assert!(pe.materialize(&bytes, base + 0x10000).is_err());
        }
    }
    #[test]
    fn expanded_provider_export_arrays_keep_all_gates_and_names_disjoint() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let base = if architecture == Architecture::X64 {
                0xfffff80000400000
            } else {
                0x80400000
            };
            let gate = if architecture == Architecture::X64 {
                0xfffff80200000000
            } else {
                0x82000000
            };
            // 257 and above cross into the two-page stub tier, which shifts the
            // export directory and both lookup arrays.
            for count in [129usize, 256, 257, 512] {
                let names: Vec<_> = (0..count)
                    .map(|index| format!("Export{index:03}"))
                    .collect();
                let exports: Vec<_> = names
                    .iter()
                    .enumerate()
                    .map(|(index, name)| (name.as_str(), gate + index as u64 * 16))
                    .collect();
                let bytes = image(architecture, base, "ntoskrnl.exe", &exports).unwrap();
                let pe = PeImage::parse(&bytes, "ntoskrnl.exe").unwrap();
                assert_eq!(pe.exports.len(), count);
                for index in [0, 127, 128, count - 1] {
                    assert_eq!(pe.exports[index].names, [names[index].as_str()]);
                    assert_eq!(
                        pe.exports[index].target,
                        ExportTarget::Address {
                            rva: 0x1000 + index as u32 * 16
                        }
                    );
                }
                let loaded = pe.materialize(&bytes, base).unwrap();
                let last = 0x1000 + (count - 1) * 16;
                assert_eq!(&loaded[last..last + 2], &[0xff, 0x25]);
            }
            let names: Vec<_> = (0..513).map(|index| format!("Export{index:03}")).collect();
            let exports: Vec<_> = names.iter().map(|name| (name.as_str(), gate)).collect();
            assert!(image(architecture, base, "ntoskrnl.exe", &exports).is_err());
            // A typed data provider keeps the single-page geometry, so it must
            // refuse the larger namespace instead of relocating its data.
            let routines: Vec<_> = names[..256]
                .iter()
                .map(|name| (name.as_str(), gate))
                .collect();
            assert!(
                typed::image_with_mutable_data(
                    architecture,
                    base,
                    "ntoskrnl.exe",
                    &routines,
                    &[typed::DataExport {
                        name: "Datum",
                        alignment: 8,
                        bytes: vec![0; 8],
                    }],
                )
                .is_err()
            );
        }
    }
    #[test]
    fn invalid_provider_shapes_are_rejected() {
        let make =
            |base, exports: &[(&str, u64)]| image(Architecture::X86, base, "kernel32.dll", exports);
        assert!(make(0x500000, &[("A", 1), ("A", 2)]).is_err());
        assert!(make(0x500000, &[("A\0B", 1)]).is_err());
        assert!(make(0xfffff000, &[("A", 1)]).is_err());
        assert!(make(0x500000, &[("A", 1u64 << 32)]).is_err());
        assert!(make(0x500000, &[]).is_err());
        assert!(make(0x500001, &[("A", 1)]).is_err());
    }
}

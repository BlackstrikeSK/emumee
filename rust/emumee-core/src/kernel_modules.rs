//! Native module inventories derived only from the actual mapped catalog.
use crate::{
    modules::{ModuleCatalog, ModuleProvenance},
    pe::Architecture,
};
use serde::Serialize;
use thiserror::Error;
#[derive(Debug, Error)]
#[error("Guest kernel module query: {0}")]
pub struct QueryError(pub &'static str);
#[derive(Clone, Debug, Serialize)]
pub struct ModuleRow {
    pub name: String,
    pub base: u64,
    pub image_size: u64,
    pub load_order: u16,
    pub provenance: ModuleProvenance,
}
#[derive(Debug)]
pub struct ModuleBuffer {
    pub bytes: Vec<u8>,
    pub rows: Vec<ModuleRow>,
}
pub fn module_buffer(
    architecture: Architecture,
    catalog: &ModuleCatalog,
    class: u32,
) -> Result<ModuleBuffer, QueryError> {
    if architecture != catalog.architecture() {
        return Err(QueryError(
            "module catalog architecture disagrees with query ABI",
        ));
    }
    if !matches!(class, 11 | 77) {
        return Err(QueryError(
            "information class is outside the modeled 11/77 module profile",
        ));
    }
    let width = architecture.width();
    let extended = class == 77;
    let size = if width == 8 { 296 } else { 284 };
    let stride = if extended {
        if width == 8 { 320 } else { 300 }
    } else {
        size
    };
    let mut modules = catalog.modules().collect::<Vec<_>>();
    if modules.len() > 256 {
        return Err(QueryError(
            "module count exceeds authoritative catalog bound",
        ));
    }
    modules.sort_by_key(|m| {
        (
            match m.name.as_str() {
                "ntoskrnl.exe" => 0,
                "hal.dll" => 1,
                _ => 2,
            },
            m.load_order(),
        )
    });
    let count = modules.len();
    let required = count
        .checked_mul(stride)
        .and_then(|n| n.checked_add(if extended { 2 } else { width }))
        .ok_or(QueryError("module output length overflow"))?;
    let mut bytes = vec![0; required];
    let mut rows = Vec::with_capacity(count);
    if !extended {
        bytes[..4].copy_from_slice(&(count as u32).to_le_bytes());
    }
    for (index, module) in modules.into_iter().enumerate() {
        let provenance = module.provenance().ok_or(QueryError(
            "mapped module lacks explicit guest path/header provenance",
        ))?;
        if provenance.path_bytes.len() > 255 {
            return Err(QueryError(
                "module guest path does not fit FullPathName byte field",
            ));
        }
        if module.size > u32::MAX as u64 || (width == 4 && module.base > u32::MAX as u64) {
            return Err(QueryError("module row exceeds guest ABI width"));
        }
        let cursor = if extended {
            index * stride
        } else {
            width + index * stride
        };
        if extended {
            bytes[cursor..cursor + 2].copy_from_slice(&(stride as u16).to_le_bytes());
        }
        let base = cursor + if extended { width } else { 0 };
        bytes[base + 2 * width..base + 3 * width]
            .copy_from_slice(&module.base.to_le_bytes()[..width]);
        let at = base + 3 * width;
        bytes[at..at + 4].copy_from_slice(&(module.size as u32).to_le_bytes());
        for (offset, value) in [
            (8, index as u16),
            (10, index as u16),
            (12, 1),
            (14, provenance.basename_offset),
        ] {
            bytes[at + offset..at + offset + 2].copy_from_slice(&value.to_le_bytes());
        }
        bytes[at + 16..at + 16 + provenance.path_bytes.len()]
            .copy_from_slice(&provenance.path_bytes);
        if extended {
            let at = base + size;
            bytes[at..at + 4].copy_from_slice(&provenance.accepted_headers.checksum.to_le_bytes());
            bytes[at + 4..at + 8]
                .copy_from_slice(&provenance.accepted_headers.timestamp.to_le_bytes());
            bytes[cursor + stride - width..cursor + stride].copy_from_slice(
                &provenance.accepted_headers.preferred_base.to_le_bytes()[..width],
            );
        }
        rows.push(ModuleRow {
            name: module.name.clone(),
            base: module.base,
            image_size: module.size,
            load_order: module.load_order(),
            provenance: provenance.clone(),
        });
    }
    Ok(ModuleBuffer { bytes, rows })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fixtures::counted_driver, modules::ModuleOrigin, pe::PeImage};
    #[test]
    fn inventories_have_exact_layout_real_order_paths_and_immutable_relocated_headers() {
        for arch in [Architecture::X86, Architecture::X64] {
            let w = arch.width();
            let mut source = counted_driver(arch, 1);
            source[0x88..0x8c].copy_from_slice(&0x12345678u32.to_le_bytes());
            source[0xd8..0xdc].copy_from_slice(&0x98765432u32.to_le_bytes());
            let mut pe = PeImage::parse(&source, "owned.sys").unwrap();
            source[0x88..0x8c].fill(0); // Accepted metadata is not a later buffer view.
            let original = pe.image_base;
            pe.image_base = 0x70000000;
            let mut c = ModuleCatalog::new(arch);
            for (name, base) in [
                ("z.sys", 0x50000000),
                ("a.sys", 0x51000000),
                ("hal.dll", 0x52000000),
                ("ntoskrnl.exe", 0x53000000),
            ] {
                c.add_with_path(
                    name,
                    base,
                    &pe,
                    &format!(r"C:\owned\{name}"),
                    ModuleOrigin::OwnedGenerated,
                )
                .unwrap();
            }
            assert_eq!(
                c.modules().map(|m| m.name.as_str()).collect::<Vec<_>>(),
                ["a.sys", "hal.dll", "ntoskrnl.exe", "z.sys"]
            );
            for class in [11, 77] {
                let result = module_buffer(arch, &c, class).unwrap();
                assert_eq!(
                    result
                        .rows
                        .iter()
                        .map(|m| m.name.as_str())
                        .collect::<Vec<_>>(),
                    ["ntoskrnl.exe", "hal.dll", "z.sys", "a.sys"]
                );
                let stride = if class == 77 {
                    if w == 8 { 320 } else { 300 }
                } else if w == 8 {
                    296
                } else {
                    284
                };
                assert_eq!(
                    result.bytes.len(),
                    4 * stride + if class == 77 { 2 } else { w }
                );
                let mut at = w;
                assert_eq!(
                    u64::from_le_bytes({
                        let mut b = [0; 8];
                        b[..w].copy_from_slice(&result.bytes[at + 2 * w..at + 3 * w]);
                        b
                    }),
                    0x53000000
                );
                if class == 77 {
                    at = w + if w == 8 { 296 } else { 284 };
                    assert_eq!(&result.bytes[at..at + 4], &0x98765432u32.to_le_bytes());
                    assert_eq!(&result.bytes[at + 4..at + 8], &0x12345678u32.to_le_bytes());
                    assert_eq!(
                        &result.bytes[stride - w..stride],
                        &original.to_le_bytes()[..w]
                    );
                    assert_eq!(&result.bytes[result.bytes.len() - 2..], &[0, 0]);
                } else {
                    assert_eq!(&result.bytes[..4], &4u32.to_le_bytes());
                }
            }
            assert_eq!(c.containing(0x50000000).unwrap().base, 0x50000000);
            assert!(c.containing(0x50000000 + pe.image_size as u64).is_none());
        }
    }
    #[test]
    fn absent_provenance_unsupported_classes_and_failed_additions_are_not_invented() {
        let arch = Architecture::X64;
        let source = counted_driver(arch, 1);
        let pe = PeImage::parse(&source, "owned.sys").unwrap();
        let mut c = ModuleCatalog::new(arch);
        c.add("owned.sys", 0x50000000, &pe).unwrap();
        assert!(module_buffer(arch, &c, 11).is_err());
        assert!(module_buffer(arch, &c, 35).is_err());
        assert!(module_buffer(Architecture::X86, &c, 11).is_err());
        assert!(
            c.add_with_path(
                "owned.sys",
                0x51000000,
                &pe,
                r"C:\owned\owned.sys",
                ModuleOrigin::OwnedGenerated
            )
            .is_err()
        );
        assert!(
            c.module("owned.sys")
                .unwrap()
                .unwrap()
                .provenance()
                .is_none()
        );
        assert!(
            c.add_with_path(
                "next.sys",
                0x50001000,
                &pe,
                r"C:\owned\next.sys",
                ModuleOrigin::OwnedGenerated
            )
            .is_err()
        );
        for path in [
            r"C:\owned\wrong.sys",
            r"\SystemRoot\owned.sys",
            r"C:\owned\..\owned.sys",
        ] {
            assert!(
                c.add_with_path(
                    "next.sys",
                    0x51000000,
                    &pe,
                    path,
                    ModuleOrigin::OwnedGenerated
                )
                .is_err()
            );
        }
        assert_eq!(c.modules().count(), 1);
        c.add_with_path(
            "next.sys",
            0x51000000,
            &pe,
            r"C:\owned\next.sys",
            ModuleOrigin::OwnedGenerated,
        )
        .unwrap();
        assert_eq!(c.module("next.sys").unwrap().unwrap().load_order(), 1);
        let mut long = ModuleCatalog::new(arch);
        let path = format!("C:\\{}long.sys", "x\\".repeat(130));
        long.add_with_path(
            "long.sys",
            0x60000000,
            &pe,
            &path,
            ModuleOrigin::OwnedGenerated,
        )
        .unwrap();
        assert!(
            module_buffer(arch, &long, 77)
                .unwrap_err()
                .to_string()
                .contains("FullPathName")
        );
    }
}

//! Borrowed, read-only file-backed code view of exact pinned NT references.
//! No reference instruction is mapped or executed by this module.
use super::{ProviderError, kernel::PINNED_REFERENCE_SHA256};
use crate::pe::{Architecture, PeImage};
use sha2::{Digest, Sha256};

const MAX_FILE: usize = 32 * 1024 * 1024;
const MAX_IMAGE: u32 = 24 * 1024 * 1024;
const PINNED_SIZE: usize = 12_076_528;
const PINNED_IMAGE_SIZE: u32 = 0x1047000;
const HOST_26200_SHA256: &str =
    "4a6af9a3dbbeb440c4a9fbe8a4d6832eae751ac3a85860d860b8313a737a2e3a";
const HOST_26200_SIZE: usize = 13_131_136;
const HOST_26200_IMAGE_SIZE: u32 = 0x1450000;

#[derive(Debug)]
pub struct CodeSection<'a> {
    pub name: String,
    pub rva: u32,
    pub bytes: &'a [u8],
}

#[derive(Debug)]
pub struct CodeView<'a> {
    pub source_sha256: String,
    pub source_size: usize,
    pub image_base: u64,
    pub image_size: u32,
    pub sections: Vec<CodeSection<'a>>,
}

/// Owned executable bytes after checked PE relocations. This is a byte
/// projection, not a permission to execute the reference in a guest.
#[derive(Debug)]
pub struct RelocatedCodeView {
    pub source_sha256: String,
    pub source_size: usize,
    pub preferred_base: u64,
    pub target_base: u64,
    pub image_size: u32,
    pub sections: Vec<RelocatedCodeSection>,
}

#[derive(Debug)]
pub struct RelocatedCodeSection {
    pub name: String,
    pub rva: u32,
    pub bytes: Vec<u8>,
}

impl RelocatedCodeView {
    pub fn read(&self, rva: u32, size: usize) -> Option<&[u8]> {
        let size = u32::try_from(size).ok()?;
        if size == 0 {
            return None;
        }
        let end = rva.checked_add(size)?;
        let section = self.sections.iter().find(|section| {
            rva >= section.rva && end <= section.rva + section.bytes.len() as u32
        })?;
        let offset = (rva - section.rva) as usize;
        section.bytes.get(offset..offset + size as usize)
    }
}

impl CodeView<'_> {
    /// Reads raw file-backed executable bytes within one validated section.
    /// Relocations are not applied; a future mapper must validate them.
    pub fn read_raw(&self, rva: u32, size: usize) -> Option<&[u8]> {
        let size = u32::try_from(size).ok()?;
        if size == 0 {
            return None;
        }
        let end = rva.checked_add(size)?;
        let section = self.sections.iter().find(|section| {
            rva >= section.rva && end <= section.rva + section.bytes.len() as u32
        })?;
        let offset = (rva - section.rva) as usize;
        section.bytes.get(offset..offset + size as usize)
    }
}

/// The only production entry point. A caller must supply exact Microsoft
/// reference bytes and select the supported x64 build 22631 persona.
pub fn inspect_pinned_nt22631(
    data: &[u8],
    windows_build: u32,
) -> Result<CodeView<'_>, ProviderError> {
    if windows_build != 22631
        || data.len() != PINNED_SIZE
        || format!("{:x}", Sha256::digest(data)) != PINNED_REFERENCE_SHA256
    {
        return Err(ProviderError(
            "kernel code reference identity or persona differs",
        ));
    }
    let view = inspect_file_backed_code(data)?;
    if view.image_size != PINNED_IMAGE_SIZE {
        return Err(ProviderError("kernel code reference image size differs"));
    }
    Ok(view)
}

/// Relocates the exact pinned reference as data. Callers must separately
/// preserve the modeled provider's gates and protected data; this function
/// never maps guest pages or enables guest execution.
pub fn relocate_pinned_nt22631(
    data: &[u8],
    windows_build: u32,
    target_base: u64,
) -> Result<RelocatedCodeView, ProviderError> {
    inspect_pinned_nt22631(data, windows_build)?;
    project_file_backed_code(data, target_base)
}

/// A separate exact host profile: build 26200 with the authenticated
/// 26100.9711 kernel image. It does not broaden the older 22631 authority.
pub fn relocate_pinned_nt26200(
    data: &[u8],
    windows_build: u32,
    target_base: u64,
) -> Result<RelocatedCodeView, ProviderError> {
    if windows_build != 26200
        || data.len() != HOST_26200_SIZE
        || format!("{:x}", Sha256::digest(data)) != HOST_26200_SHA256
    {
        return Err(ProviderError("host kernel code reference identity or persona differs"));
    }
    let view = inspect_file_backed_code(data)?;
    if view.image_size != HOST_26200_IMAGE_SIZE {
        return Err(ProviderError("host kernel code reference image size differs"));
    }
    project_file_backed_code(data, target_base)
}

fn project_file_backed_code(
    data: &[u8],
    target_base: u64,
) -> Result<RelocatedCodeView, ProviderError> {
    let view = inspect_file_backed_code(data)?;
    if target_base == 0
        || target_base % 4096 != 0
        || target_base.checked_add(view.image_size as u64).is_none()
    {
        return Err(ProviderError("kernel code reference target base invalid"));
    }
    let pe = PeImage::parse(data, "ntoskrnl.exe")
        .map_err(|_| ProviderError("kernel code reference PE invalid"))?;
    if pe.sections.iter().any(|section| {
        section.characteristics & 0x2000_0000 != 0 && section.characteristics & 0x8000_0000 != 0
    }) {
        return Err(ProviderError("kernel code reference has writable code"));
    }
    let image = pe
        .materialize(data, target_base)
        .map_err(|_| ProviderError("kernel code reference relocation invalid"))?;
    let mut sections = Vec::with_capacity(view.sections.len());
    for section in view.sections {
        let start = section.rva as usize;
        let end = start
            .checked_add(section.bytes.len())
            .ok_or(ProviderError("kernel code reference section overflow"))?;
        let bytes = image
            .get(start..end)
            .ok_or(ProviderError("kernel code reference section exceeds image"))?
            .to_vec();
        sections.push(RelocatedCodeSection {
            name: section.name,
            rva: section.rva,
            bytes,
        });
    }
    Ok(RelocatedCodeView {
        source_sha256: view.source_sha256,
        source_size: view.source_size,
        preferred_base: view.image_base,
        target_base,
        image_size: view.image_size,
        sections,
    })
}

fn inspect_file_backed_code(data: &[u8]) -> Result<CodeView<'_>, ProviderError> {
    if data.is_empty() || data.len() > MAX_FILE {
        return Err(ProviderError("kernel code reference exceeds file bound"));
    }
    let pe = PeImage::parse(data, "ntoskrnl.exe")
        .map_err(|_| ProviderError("kernel code reference PE invalid"))?;
    if pe.sample.architecture != Architecture::X64 || pe.image_size > MAX_IMAGE {
        return Err(ProviderError(
            "kernel code reference architecture or image size unsupported",
        ));
    }
    let mut sections = Vec::new();
    for section in &pe.sections {
        if section.characteristics & 0x2000_0000 == 0 || section.raw_size == 0 {
            continue;
        }
        if section.name.is_empty()
            || section.name.len() > 8
            || !section.name.is_ascii()
            || section.virtual_size == 0
            || section.virtual_size > section.raw_size
            || section.rva % 4096 != 0
        {
            return Err(ProviderError(
                "kernel code reference executable section invalid",
            ));
        }
        let start = section.raw_offset as usize;
        let end = start
            .checked_add(section.virtual_size as usize)
            .ok_or(ProviderError("kernel code reference raw offset overflow"))?;
        let bytes = data
            .get(start..end)
            .ok_or(ProviderError("kernel code reference code exceeds file"))?;
        if sections
            .iter()
            .any(|old: &CodeSection<'_>| old.name == section.name)
        {
            return Err(ProviderError(
                "kernel code reference code section name repeated",
            ));
        }
        sections.push(CodeSection {
            name: section.name.clone(),
            rva: section.rva,
            bytes,
        });
        if sections.len() > 24 {
            return Err(ProviderError(
                "kernel code reference has too many code sections",
            ));
        }
    }
    if sections.is_empty() {
        return Err(ProviderError(
            "kernel code reference has no file-backed code",
        ));
    }
    Ok(CodeView {
        source_sha256: pe.sample.sha256,
        source_size: data.len(),
        image_base: pe.image_base,
        image_size: pe.image_size,
        sections,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::image;

    fn generated() -> Vec<u8> {
        image(
            Architecture::X64,
            0x140000000,
            "ntoskrnl.exe",
            &[("HarmlessGeneratedCall", 0x100000)],
        )
        .unwrap()
    }

    #[test]
    fn generated_file_backed_code_has_only_bounded_raw_read_access() {
        let raw = generated();
        let view = inspect_file_backed_code(&raw).unwrap();
        assert_eq!(view.source_size, raw.len());
        assert_eq!(view.sections.len(), 1);
        assert_eq!(view.sections[0].name, ".text");
        assert_eq!(view.read_raw(0x1000, 2), Some(&[0xff, 0x25][..]));
        assert_eq!(view.read_raw(0x1fff, 2), None);
        assert_eq!(view.read_raw(0x2000, 1), None);
        assert_eq!(view.read_raw(0, 1), None);
        assert_eq!(view.read_raw(u32::MAX, 2), None);
        assert_eq!(view.read_raw(0x1000, 0), None);
        assert!(inspect_pinned_nt22631(&raw, 22631).is_err());
        assert!(inspect_pinned_nt22631(&raw, 19045).is_err());
    }

    #[test]
    fn generated_malformed_code_sections_fail_without_leaking_data() {
        let raw = generated();
        let table = 0x98 + 0xf0;
        let mut bad = raw.clone();
        bad[table + 8..table + 12].copy_from_slice(&0x1001u32.to_le_bytes());
        assert!(inspect_file_backed_code(&bad).is_err());
        let mut bad = raw.clone();
        bad[table + 16..table + 20].copy_from_slice(&0x200u32.to_le_bytes());
        assert!(inspect_file_backed_code(&bad).is_err());
        let mut bad = raw.clone();
        bad[table + 20..table + 24].copy_from_slice(&0xfffffff0u32.to_le_bytes());
        assert!(inspect_file_backed_code(&bad).is_err());
        let mut bad = raw;
        bad[table + 36..table + 40].copy_from_slice(&0x40000040u32.to_le_bytes());
        assert!(inspect_file_backed_code(&bad).is_err());
    }

    #[test]
    fn generated_code_relocation_is_owned_bounded_and_does_not_change_raw_input() {
        let mut raw = crate::fixtures::counted_driver(Architecture::X64, 3);
        let preferred = 0x1_4000_0000u64;
        let target = 0x1_8000_0000u64;
        raw[0x300..0x308].copy_from_slice(&(preferred + 0x1234).to_le_bytes());
        let dd = 0x98 + 112 + 5 * 8;
        raw[dd..dd + 4].copy_from_slice(&0x2080u32.to_le_bytes());
        raw[dd + 4..dd + 8].copy_from_slice(&12u32.to_le_bytes());
        raw[0x480..0x484].copy_from_slice(&0x1000u32.to_le_bytes());
        raw[0x484..0x488].copy_from_slice(&12u32.to_le_bytes());
        raw[0x488..0x48a].copy_from_slice(&0xa100u16.to_le_bytes());
        let projection = project_file_backed_code(&raw, target).unwrap();
        assert_eq!(projection.sections.len(), 1);
        assert_eq!(
            projection.read(0x1100, 8),
            Some(&(target + 0x1234).to_le_bytes()[..])
        );
        assert_eq!(
            u64::from_le_bytes(raw[0x300..0x308].try_into().unwrap()),
            preferred + 0x1234
        );
        assert_eq!(projection.read(0x2000, 1), None);
        assert_eq!(projection.read(0x1fff, 2), None);
        assert!(project_file_backed_code(&raw, 0).is_err());
        assert!(project_file_backed_code(&raw, u64::MAX - 4094).is_err());
        assert!(relocate_pinned_nt22631(&raw, 22631, target).is_err());

        let mut unsupported = raw.clone();
        unsupported[0x488..0x48a].copy_from_slice(&0x3100u16.to_le_bytes());
        assert!(project_file_backed_code(&unsupported, target).is_err());
        let mut writable = raw;
        let table = 0x98 + 0xf0;
        writable[table + 36..table + 40].copy_from_slice(&0xe0000020u32.to_le_bytes());
        assert!(project_file_backed_code(&writable, target).is_err());
    }
}

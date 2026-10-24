//! Finite legacy/default kernel metadata; no callable handlers or host loads.
use super::*;
use emumee_core::provider::{MetadataEvidence, MetadataProfile, metadata_image};
pub(super) fn initialize(engine: &mut Unicorn<Trace>, pe: &PeImage) -> Result<()> {
    if !engine.get_data().apis.kernel_mode {
        return Ok(());
    }
    let mut requested = Vec::new();
    if pe
        .imports
        .iter()
        .any(|i| MetadataProfile::requested(&i.module).is_some())
    {
        requested.extend(MetadataProfile::ALL.into_iter().enumerate());
    }
    requested.extend(
        MetadataProfile::DEFAULTS
            .into_iter()
            .enumerate()
            .map(|(i, p)| (i + 2, p)),
    );
    let mut pending = Vec::new();
    for (index, profile) in requested {
        let complete = engine.get_data().apis.providers.iter().any(|row| {
            row.module == profile.module()
                && row.metadata_only.as_ref().is_some_and(|m| {
                    m.module == profile.module()
                        && m.guest_path == profile.path()
                        && m.catalog_sha256 == profile.catalog_sha256()
                })
        });
        if complete {
            continue;
        }
        // A guest collision cannot be overwritten or treated as our catalog.
        ensure!(
            engine
                .get_data()
                .apis
                .modules
                .module(profile.module())?
                .is_none(),
            "Metadata-only provider {} conflicts with existing guest/partial module",
            profile.module()
        );
        pending.push((index, profile));
    }
    let architecture = engine.get_data().architecture;
    let first = if architecture == Architecture::X64 {
        let large_authenticated_nt = engine.get_data().apis.providers.iter().any(|provider| {
            provider.module == "ntoskrnl.exe"
                && provider.reference_catalog.is_some()
                && provider.image_size > 32 * 1024 * 1024
        });
        if large_authenticated_nt {
            // The exact 26200 host NT provider grows past the old 32-MiB
            // slot. Keep metadata-only modules beyond its mapped extent.
            0xfffff80003400000u64
        } else {
            0xfffff80002400000u64
        }
    } else {
        0x82400000u64
    };
    let mut memory = engine.get_data().apis.memory.clone();
    let mut modules = engine.get_data().apis.modules.clone();
    let mut planned = Vec::new();
    // Existing CNG/CI base slots and all modeled API gate addresses are stable.
    for (index, profile) in pending {
        let base = first
            .checked_add(index as u64 * 0x1000000)
            .ok_or_else(|| anyhow::anyhow!("Metadata provider address overflow"))?;
        let image = metadata_image(architecture, base, profile)?;
        let parsed = image.parsed();
        memory.map(
            base,
            parsed.image_size as u64,
            P::READ,
            None,
            "finite metadata-only kernel provider",
        )?;
        modules.add_with_path(
            profile.module(),
            base,
            parsed,
            profile.path(),
            emumee_core::modules::ModuleOrigin::SyntheticProvider,
        )?;
        planned.push((profile, base, image));
    }
    for (profile, base, image) in planned {
        let parsed = image.parsed();
        crate::map_image(engine, parsed, &image.bytes, base)?;
        crate::protect_image(engine, parsed)?;
        ensure!(
            engine
                .get_data()
                .apis
                .memory
                .allows(base, parsed.image_size as u64, P::READ)
                && !engine.get_data().apis.memory.allows(base, 1, P::WRITE)
                && !engine
                    .get_data()
                    .apis
                    .memory
                    .allows(base + 0x1000, 1, P::EXECUTE),
            "Metadata provider permissions differ from READ/NX profile"
        );
        engine.get_data_mut().apis.modules.add_with_path(
            profile.module(),
            base,
            parsed,
            profile.path(),
            emumee_core::modules::ModuleOrigin::SyntheticProvider,
        )?;
        engine.get_data_mut().apis.providers.push(providers::ProviderEvidence{module:profile.module().into(),base,exports:parsed.exports.len(),image_size:parsed.image_size,reference_catalog:None,metadata_only:Some(image.evidence),scope:"Synthetic guest PE; finite legacy/default metadata-only provider, READ/NX inert export addresses. Zero-export default-driver decoys and NETIO/NDIS generated names preserve Python inventory scope. No callable handlers, function code or host provider data."});
    }
    Ok(())
}
fn intersect(address: u64, size: u64, base: u64, length: u64) -> bool {
    size != 0 && address < base + length && address.checked_add(size).is_none_or(|end| end > base)
}
fn symbol(evidence: &MetadataEvidence, offset: u64) -> &str {
    evidence
        .named_exports
        .iter()
        .find(|export| offset >= u64::from(export.rva) && offset < u64::from(export.rva) + 16)
        .map_or("<image-metadata>", |export| export.name)
}
pub(super) fn describe(
    engine: &Unicorn<Trace>,
    address: u64,
    size: usize,
    access: &'static str,
) -> Option<providers::ProviderDenial> {
    for provider in &engine.get_data().apis.providers {
        let Some(metadata) = provider.metadata_only.as_ref() else {
            continue;
        };
        if intersect(
            address,
            size as u64,
            provider.base,
            u64::from(provider.image_size),
        ) {
            let offset = address.saturating_sub(provider.base);
            return Some(providers::ProviderDenial {
                name: format!("{}!{}", metadata.module, symbol(metadata, offset)),
                kind: "metadata-only",
                access,
                address,
                size,
                offset,
            });
        }
    }
    None
}
pub(crate) fn require_api_access(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
    permissions: P,
) -> Result<()> {
    if size == 0 || !permissions.contains(P::WRITE) && !permissions.contains(P::EXECUTE) {
        return Ok(());
    }
    if let Some(row) = describe(
        engine,
        address,
        usize::try_from(size).unwrap_or(usize::MAX),
        if permissions.contains(P::WRITE) {
            "write"
        } else {
            "execute"
        },
    ) {
        bail!(
            "Metadata-only provider {} refuses {} at image offset0x{:x}",
            row.name,
            row.access,
            row.offset
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn low_level_model_writes_cannot_bypass_metadata_native_readonly_protection() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = crate::new_engine(architecture).unwrap();
            engine.get_data_mut().apis.kernel_mode = true;
            let bytes = emumee_core::fixtures::provider_metadata_probe(
                architecture,
                emumee_core::fixtures::MetadataFixture::Read,
            );
            let pe = PeImage::parse(&bytes, "owned-metadata.sys").unwrap();
            initialize(&mut engine, &pe).unwrap();
            let provider = engine
                .get_data()
                .apis
                .providers
                .iter()
                .find(|p| p.module == "cng.sys")
                .unwrap();
            let metadata = provider.metadata_only.as_ref().unwrap();
            let export = metadata
                .named_exports
                .iter()
                .find(|e| e.name == "BCryptVerifySignature")
                .unwrap();
            let address = provider.base + u64::from(export.rva);
            assert!(
                crate::cpu::write(&mut engine, address, &[1])
                    .unwrap_err()
                    .to_string()
                    .contains("cng.sys!BCryptVerifySignature refuses write")
            );
            assert_eq!(uc(engine.mem_read_as_vec(address, 1)).unwrap(), [0]);
            assert!(require_api_access(&engine, address, 1, P::EXECUTE).is_err());
            require_api_access(&engine, address, 1, P::READ).unwrap();
        }
    }
}

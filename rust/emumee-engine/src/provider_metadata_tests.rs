use super::*;
use emumee_core::{
    fixtures::{ApiFixture, MetadataFixture as M},
    provider::MetadataProfile,
};
#[test]
fn finite_legacy_metadata_group_rebinds_real_imports_and_preserves_paths_hashes_ordinals_and_readonly_nx()
 {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in [M::Read, M::CiRead] {
            let result = run_api_fixture(architecture, ApiFixture::Metadata(kind), 10000).unwrap();
            assert_eq!(result.error, None, "{architecture:?} {kind:?}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(1));
            assert_eq!(result.api_calls, 0);
            assert_eq!(result.synthetic_providers.len(), 10);
            for profile in MetadataProfile::ALL {
                let provider = result
                    .synthetic_providers
                    .iter()
                    .find(|p| p.module == profile.module())
                    .unwrap();
                let metadata = provider.metadata_only.as_ref().unwrap();
                assert_eq!(metadata.guest_path, profile.path());
                assert_eq!(metadata.permissions, "r--");
                assert_eq!(
                    (metadata.entry_rva, metadata.timestamp, metadata.checksum),
                    (0, 0, 0)
                );
                assert_eq!(metadata.catalog_sha256, profile.catalog_sha256());
                assert_eq!(metadata.generated_image_sha256.len(), 64);
                assert_eq!(metadata.legacy_source_sha256.len(), 64);
                assert_eq!(metadata.named_exports.len(), profile.names().len());
                assert_eq!(provider.exports, profile.names().len());
                assert_eq!(metadata.ordinal_base, profile.ordinal_base());
                assert!(provider.reference_catalog.is_none());
                for (index, export) in metadata.named_exports.iter().enumerate() {
                    assert_eq!(export.name, profile.names()[index]);
                    assert_eq!(export.ordinal, profile.ordinal_base() + index as u32);
                    assert_eq!(export.rva, 0x1000 + index as u32 * 16);
                }
            }
            let partial = run_api_fixture(
                architecture,
                ApiFixture::Metadata(kind),
                result.instruction_count - 1,
            )
            .unwrap();
            assert_eq!(partial.error, None);
            assert_eq!(partial.completion_reason, "instruction_budget");
            assert_eq!(partial.guest_entry_return, None);
            assert_eq!(partial.api_calls, 0);
        }
    }
}
#[test]
fn default_kernel_metadata_imports_read_real_pages_aliases_and_refuse_native_execution_or_writes() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in [M::NetioRead, M::NdisRead, M::NetioExecute, M::NdisWrite] {
            let result = run_api_fixture(architecture, ApiFixture::Metadata(kind), 10_000).unwrap();
            assert_eq!(result.api_calls, 0);
            assert_eq!(result.synthetic_providers.len(), 8);
            assert_eq!(result.network.calls, 0);
            assert!(result.artifacts.is_empty());
            if kind.negative() {
                let (name, error) = if matches!(kind, M::NetioExecute) {
                    ("netio.sys!WskRegister", "FETCH_PROT")
                } else {
                    ("ndis.sys!NdisGetVersion", "WRITE_PROT")
                };
                assert!(
                    result.error.as_deref().is_some_and(|e| e.contains(error)),
                    "{architecture:?}/{kind:?}: {result:#?}"
                );
                assert_eq!(result.guest_entry_return, None);
                assert!(
                    result
                        .provider_denials
                        .iter()
                        .any(|d| d.name == name && d.kind == "metadata-only")
                );
            } else {
                assert_eq!(result.error, None, "{architecture:?}/{kind:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1));
            }
            for profile in MetadataProfile::DEFAULTS {
                let provider = result
                    .synthetic_providers
                    .iter()
                    .find(|p| p.module == profile.module())
                    .unwrap();
                let evidence = provider.metadata_only.as_ref().unwrap();
                assert_eq!(evidence.guest_path, profile.path());
                assert_eq!(evidence.permissions, "r--");
                assert_eq!(evidence.named_exports.len(), profile.names().len());
                assert_eq!(
                    evidence.legacy_source_sha256,
                    profile.legacy_source_sha256()
                );
            }
        }
    }
}
#[test]
fn real_cpu_fetch_store_and_api_write_cannot_turn_metadata_addresses_into_crypto_code_or_mutable_data()
 {
    for architecture in [Architecture::X86, Architecture::X64] {
        for (kind, message, api) in [
            (M::Execute, "FETCH_PROT", false),
            (M::Write, "WRITE_PROT", false),
            (
                M::ApiWrite,
                "Metadata-only provider cng.sys!BCryptVerifySignature refuses write",
                true,
            ),
            (M::HeaderExecute, "FETCH_PROT", false),
            (
                M::HeaderApiWrite,
                "Metadata-only provider cng.sys!<image-metadata> refuses write",
                true,
            ),
            (M::CiExecute, "FETCH_PROT", false),
        ] {
            let result = run_api_fixture(architecture, ApiFixture::Metadata(kind), 10000).unwrap();
            assert_eq!(result.completion_reason, "error");
            assert_eq!(result.guest_entry_return, None);
            assert!(
                result.error.as_deref().unwrap().contains(message),
                "{architecture:?} {kind:?}: {result:#?}"
            );
            assert_eq!(result.api_calls, u64::from(api));
            assert!(
                !result
                    .api_events
                    .iter()
                    .any(|e| e.api.starts_with("cng") || e.api.starts_with("ci."))
            );
            if !api {
                let module = if matches!(kind, M::CiExecute) {
                    "ci.dll!CiCheckSignedFile"
                } else if matches!(kind, M::HeaderExecute) {
                    "cng.sys!<image-metadata>"
                } else {
                    "cng.sys!BCryptVerifySignature"
                };
                assert!(
                    result
                        .provider_denials
                        .iter()
                        .any(|d| d.name == module && d.kind == "metadata-only")
                );
            }
            assert!(result.artifacts.is_empty());
            assert_eq!(result.network.calls, 0);
        }
    }
}

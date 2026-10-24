//! Finite legacy kernel provider metadata, never callable implementations.
use super::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
#[path = "default_metadata.rs"]
mod defaults;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum MetadataProfile {
    Cng,
    Ci,
    Ntfs,
    Netio,
    Volmgr,
    Disk,
    Tcpip,
    Ndis,
}
impl MetadataProfile {
    pub const ALL: [Self; 2] = [Self::Cng, Self::Ci];
    /// Default Python kernel environment identities, independent of imports.
    pub const DEFAULTS: [Self; 6] = [
        Self::Ntfs,
        Self::Netio,
        Self::Volmgr,
        Self::Disk,
        Self::Tcpip,
        Self::Ndis,
    ];
    pub fn module(self) -> &'static str {
        match self {
            Self::Cng => "cng.sys",
            Self::Ci => "ci.dll",
            Self::Ntfs => "ntfs.sys",
            Self::Netio => "netio.sys",
            Self::Volmgr => "volmgr.sys",
            Self::Disk => "disk.sys",
            Self::Tcpip => "tcpip.sys",
            Self::Ndis => "ndis.sys",
        }
    }
    pub fn path(self) -> &'static str {
        match self {
            Self::Cng => r"C:\Windows\system32\drivers\cng.sys",
            Self::Ci => r"C:\Windows\system32\ci.dll",
            Self::Ntfs => r"C:\Windows\system32\drivers\ntfs.sys",
            Self::Netio => r"C:\Windows\system32\drivers\netio.sys",
            Self::Volmgr => r"C:\Windows\system32\drivers\volmgr.sys",
            Self::Disk => r"C:\Windows\system32\drivers\disk.sys",
            Self::Tcpip => r"C:\Windows\system32\drivers\tcpip.sys",
            Self::Ndis => r"C:\Windows\system32\drivers\ndis.sys",
        }
    }
    pub fn ordinal_base(self) -> u32 {
        match self {
            Self::Ci => 4,
            _ => 1,
        }
    }
    pub fn names(self) -> &'static [&'static str] {
        match self {
            Self::Cng => CNG_NAMES,
            Self::Ci => CI_NAMES,
            Self::Netio => defaults::NETIO_NAMES,
            Self::Ndis => defaults::NDIS_NAMES,
            _ => &[],
        }
    }
    pub fn catalog_sha256(self) -> &'static str {
        match self {
            Self::Cng => CNG_NAMES_SHA256,
            Self::Ci => CI_NAMES_SHA256,
            Self::Netio => defaults::NETIO_NAMES_SHA256,
            Self::Ndis => defaults::NDIS_NAMES_SHA256,
            _ => defaults::EMPTY_NAMES_SHA256,
        }
    }
    pub fn legacy_source_sha256(self) -> &'static str {
        match self {
            Self::Ci | Self::Cng => LEGACY_PROVIDER_SOURCE_SHA256,
            Self::Netio => defaults::NETIO_SOURCE_SHA256,
            Self::Ndis => defaults::NDIS_SOURCE_SHA256,
            _ => defaults::DEFAULT_DRIVER_SHA256,
        }
    }
    /// Activation accepts exact basenames only. No invented bcrypt.dll alias,
    /// path search or arbitrary native provider can acquire these semantics.
    pub fn requested(module: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|p| p.module().eq_ignore_ascii_case(module))
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct MetadataExport {
    pub name: &'static str,
    pub ordinal: u32,
    pub rva: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct MetadataEvidence {
    pub module: &'static str,
    pub guest_path: &'static str,
    pub ordinal_base: u32,
    pub named_exports: Vec<MetadataExport>,
    pub legacy_source_sha256: &'static str,
    pub catalog_sha256: &'static str,
    pub generated_image_sha256: String,
    pub permissions: &'static str,
    pub entry_rva: u32,
    pub timestamp: u32,
    pub checksum: u32,
    pub scope: &'static str,
}
pub struct MetadataImage {
    pub bytes: Vec<u8>,
    pub evidence: MetadataEvidence,
    parsed: crate::pe::PeImage,
}
impl MetadataImage {
    /// Layout of generator-owned inert export metadata, not a loadable driver.
    /// Canonical kernel module names remain catalog/evidence identities; the
    /// ordinary input parser still requires native drivers to have an entry.
    pub fn parsed(&self) -> &crate::pe::PeImage {
        &self.parsed
    }
}
pub fn metadata_image(
    architecture: Architecture,
    base: u64,
    profile: MetadataProfile,
) -> Result<MetadataImage, ProviderError> {
    let names = profile.names();
    if names.len() > 128 || !names.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(ProviderError("invalid ordered metadata profile"));
    }
    let mut digest = Sha256::new();
    for (index, name) in names.iter().enumerate() {
        digest.update(format!(
            "{} {name}\n",
            profile.ordinal_base() + index as u32
        ));
    }
    if format!("{:x}", digest.finalize()) != profile.catalog_sha256() {
        return Err(ProviderError("metadata names/ordinals digest mismatch"));
    }
    // Reuse only the bounded PE table/layout writer. Every generated text byte
    // is erased before publication; export RVAs identify zero metadata slots,
    // not callable function bodies or fake bcrypt instruction streams.
    // Empty default-driver decoys expose no exports. Use one temporary entry
    // only to construct the bounded PE layout, then erase the directory and
    // all its backing bytes before parsing/publication.
    let dummy = if names.is_empty() {
        vec![("EmumeeEmptyMetadata", 1)]
    } else {
        names.iter().map(|name| (*name, 1)).collect::<Vec<_>>()
    };
    let mut bytes = super::image(architecture, base, profile.module(), &dummy)?;
    bytes[0x200..0x1200].fill(0);
    dword(&mut bytes, 0x98 + 16, 0);
    dword(&mut bytes, 0x88, 0);
    dword(&mut bytes, 0x98 + 64, 0);
    dword(&mut bytes, 0x1200 + 16, profile.ordinal_base());
    if names.is_empty() {
        let dd = 0x98
            + if architecture == Architecture::X64 {
                112
            } else {
                96
            };
        dword(&mut bytes, dd, 0);
        dword(&mut bytes, dd + 4, 0);
        bytes[0x1200..].fill(0);
    }
    let section = 0x98
        + if architecture == Architecture::X64 {
            0xf0
        } else {
            0xe0
        };
    bytes[section..section + 8].copy_from_slice(b".meta\0\0\0");
    dword(&mut bytes, section + 36, 0x40000040);
    let evidence = MetadataEvidence {
        module: profile.module(),
        guest_path: profile.path(),
        ordinal_base: profile.ordinal_base(),
        named_exports: names
            .iter()
            .enumerate()
            .map(|(index, name)| MetadataExport {
                name,
                ordinal: profile.ordinal_base() + index as u32,
                rva: 0x1000 + index as u32 * 16,
            })
            .collect(),
        legacy_source_sha256: profile.legacy_source_sha256(),
        catalog_sha256: profile.catalog_sha256(),
        generated_image_sha256: format!("{:x}", Sha256::digest(&bytes)),
        permissions: "r--",
        entry_rva: 0,
        timestamp: 0,
        checksum: 0,
        scope: "Finite synthetic legacy provider metadata only. Default NETIO/NDIS names preserve Python generated bare/A/W aliases; NTFS/volmgr/disk/TCPIP decoys have zero exports. READ/NX inert slots, no callable handlers, boot initialization, private provider data or unlisted ordinal support.",
    };
    let parsed = crate::pe::PeImage::parse(&bytes, "synthetic-provider.dll")
        .map_err(|_| ProviderError("invalid generated metadata container"))?;
    Ok(MetadataImage {
        bytes,
        evidence,
        parsed,
    })
}
const LEGACY_PROVIDER_SOURCE_SHA256: &str =
    "4f20fe9c08a7956f1673c585198c8658cb8e9404e896c8d0f75508610b398814";
const CI_NAMES_SHA256: &str = "8416c5cf965100293ea3c2edaadddd6af2a47c0c6f89c7723e740b18ffec12c0";
const CI_NAMES: &[&str] = &[
    "CiCheckSignedFile",
    "CiFindPageHashesInCatalog",
    "CiFindPageHashesInSignedFile",
    "CiFreePolicyInfo",
    "CiGetCertPublisherName",
    "CiGetPEInformation",
    "CiInitialize",
    "CiSetTrustedOriginClaimId",
    "CiValidateFileObject",
    "CiVerifyHashInCatalog",
];
const CNG_NAMES_SHA256: &str = "3f0d2df8dec0ca5d42da691013e5e7ca8288f3bd361714fa9643e354040a2d29";
const CNG_NAMES: &[&str] = &[
    "BCryptAddContextFunctionProvider",
    "BCryptCloseAlgorithmProvider",
    "BCryptCreateHash",
    "BCryptCreateMultiHash",
    "BCryptDecapsulate",
    "BCryptDecrypt",
    "BCryptDeriveKey",
    "BCryptDeriveKeyCapi",
    "BCryptDeriveKeyPBKDF2",
    "BCryptDestroyHash",
    "BCryptDestroyKey",
    "BCryptDestroySecret",
    "BCryptDuplicateHash",
    "BCryptDuplicateKey",
    "BCryptEncapsulate",
    "BCryptEncrypt",
    "BCryptEnumAlgorithms",
    "BCryptEnumProviders",
    "BCryptExportKey",
    "BCryptFinalizeKeyPair",
    "BCryptFinishHash",
    "BCryptFreeBuffer",
    "BCryptGenRandom",
    "BCryptGenerateKeyPair",
    "BCryptGenerateSymmetricKey",
    "BCryptGetFipsAlgorithmMode",
    "BCryptGetProperty",
    "BCryptHash",
    "BCryptHashData",
    "BCryptImportKey",
    "BCryptImportKeyPair",
    "BCryptKeyDerivation",
    "BCryptOpenAlgorithmProvider",
    "BCryptProcessMultiOperations",
    "BCryptRegisterConfigChangeNotify",
    "BCryptRegisterProvider",
    "BCryptResolveProviders",
    "BCryptSecretAgreement",
    "BCryptSetProperty",
    "BCryptSignHash",
    "BCryptUnregisterConfigChangeNotify",
    "BCryptUnregisterProvider",
    "BCryptVerifySignature",
    "CngGetFipsAlgorithmMode",
    "EntropyPoolTriggerReseedForIum",
    "EntropyProvideData",
    "EntropyRegisterCallback",
    "EntropyRegisterSource",
    "EntropyUnregisterSource",
    "SslDecrementProviderReferenceCount",
    "SslDecryptPacket",
    "SslEncryptPacket",
    "SslExpandNextGenTrafficKey",
    "SslExpandWriteKey",
    "SslExportKey",
    "SslExportKeyingMaterial",
    "SslFreeObject",
    "SslImportKey",
    "SslIncrementProviderReferenceCount",
    "SslLookupCipherLengths",
    "SslLookupCipherSuiteInfo",
    "SslOpenProvider",
    "SymCrypt802_11SaeCustomCommitCreate",
    "SymCrypt802_11SaeCustomCommitProcess",
    "SymCrypt802_11SaeCustomCreatePT",
    "SymCrypt802_11SaeCustomDestroy",
    "SymCrypt802_11SaeCustomInit",
    "SymCrypt802_11SaeCustomInitH2E",
    "SystemPrng",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        modules::{ModuleCatalog, Resolution},
        pe::ImportName,
        pe::{ExportTarget, PeImage},
    };
    #[test]
    fn frozen_legacy_names_order_counts_digests_and_exact_requests_are_preserved() {
        assert_eq!(
            (
                MetadataProfile::Cng.names().len(),
                MetadataProfile::Ci.names().len()
            ),
            (69, 10)
        );
        assert_eq!(
            MetadataProfile::requested("CNG.SYS"),
            Some(MetadataProfile::Cng)
        );
        for bad in [
            "cng",
            "cng.dll",
            "C:\\cng.sys",
            "bcrypt.dll",
            "ci",
            "ci.sys",
            "unknown.dll",
        ] {
            assert_eq!(MetadataProfile::requested(bad), None);
        }
        for profile in MetadataProfile::ALL
            .into_iter()
            .chain(MetadataProfile::DEFAULTS)
        {
            let mut digest = Sha256::new();
            for (index, name) in profile.names().iter().enumerate() {
                digest.update(format!(
                    "{} {name}\n",
                    profile.ordinal_base() + index as u32
                ));
            }
            assert_eq!(format!("{:x}", digest.finalize()), profile.catalog_sha256());
        }
    }
    #[test]
    fn metadata_pe_has_real_export_addresses_ordinal_holes_and_no_callable_or_writable_pages() {
        for architecture in [Architecture::X86, Architecture::X64] {
            for profile in MetadataProfile::ALL
                .into_iter()
                .chain(MetadataProfile::DEFAULTS)
            {
                let base = if architecture == Architecture::X64 {
                    0xfffff80002400000
                } else {
                    0x82400000
                };
                let image = metadata_image(architecture, base, profile).unwrap();
                let pe = image.parsed();
                assert_eq!(pe.sample.kind, crate::pe::Kind::Dll);
                assert_eq!(pe.sample.subsystem, 3);
                if profile == MetadataProfile::Cng {
                    assert!(PeImage::parse(&image.bytes, profile.module()).is_err());
                }
                assert_eq!(pe.entry_rva, 0);
                assert_eq!(&image.bytes[0x88..0x8c], &[0; 4]);
                assert_eq!(&image.bytes[0x98 + 64..0x98 + 68], &[0; 4]);
                assert!(image.bytes[0x200..0x1200].iter().all(|byte| *byte == 0));
                assert!(
                    pe.sections
                        .iter()
                        .all(|s| s.characteristics & 0xa0000000 == 0
                            && s.characteristics & 0x40000000 != 0)
                );
                assert_eq!(pe.exports.len(), profile.names().len());
                for (index, export) in pe.exports.iter().enumerate() {
                    assert_eq!(export.ordinal, profile.ordinal_base() + index as u32);
                    assert_eq!(export.names, vec![profile.names()[index].to_owned()]);
                    assert!(
                        matches!(export.target,ExportTarget::Address{rva}if rva==0x1000+index as u32*16)
                    );
                }
                let mut modules = ModuleCatalog::new(architecture);
                modules.add(profile.module(), base, pe).unwrap();
                for ordinal in 1..profile.ordinal_base() {
                    assert!(matches!(
                        modules
                            .resolve(
                                profile.module(),
                                &ImportName::Ordinal {
                                    ordinal: ordinal as u16
                                }
                            )
                            .unwrap(),
                        Resolution::MissingExport { .. }
                    ));
                }
                assert_eq!(
                    image.evidence.generated_image_sha256,
                    format!("{:x}", Sha256::digest(&image.bytes))
                );
            }
        }
        assert!(metadata_image(Architecture::X86, 0xfffff000, MetadataProfile::Cng).is_err());
    }
    #[test]
    fn default_inventory_preserves_frozen_generated_aliases_and_zero_export_decoys() {
        assert_eq!(MetadataProfile::Netio.names().len(), 54);
        assert_eq!(MetadataProfile::Ndis.names().len(), 48);
        for (profile, name) in [
            (MetadataProfile::Netio, "WskRegister"),
            (MetadataProfile::Ndis, "NdisGetVersion"),
        ] {
            for alias in [name.to_owned(), format!("{name}A"), format!("{name}W")] {
                assert!(profile.names().contains(&alias.as_str()));
            }
            assert_eq!(profile.legacy_source_sha256().len(), 64);
        }
        assert!(
            MetadataProfile::Netio
                .names()
                .contains(&"callback_WskSocket")
        );
        for profile in [
            MetadataProfile::Ntfs,
            MetadataProfile::Volmgr,
            MetadataProfile::Disk,
            MetadataProfile::Tcpip,
        ] {
            let image = metadata_image(Architecture::X64, 0xfffff80004400000, profile).unwrap();
            assert!(image.parsed().exports.is_empty());
            assert_eq!(image.parsed().directories[0].rva, 0);
            assert_eq!(image.parsed().directories[0].size, 0);
            assert!(image.bytes[0x1200..].iter().all(|byte| *byte == 0));
        }
    }
}

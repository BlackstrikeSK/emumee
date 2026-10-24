//! Submitted service metadata uses only the already validated guest registry.
//! RegGetValue supplies its documented string termination normalization; this
//! does not prove raw stored termination or import any host registry/file state.
use anyhow::{Result, bail, ensure};
use emumee_core::registry::{HKLM, REG_EXPAND_SZ, REG_SZ, Registry};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const NO_EXPAND: u32 = 0x10000000;

#[derive(Clone, Debug, Serialize)]
pub struct Receipt {
    pub service: String,
    pub registry_key: String,
    pub value_name: &'static str,
    pub source: &'static str,
    pub declared_path: Option<String>,
    pub value_type: Option<u32>,
    pub registry_value_sha256: Option<String>,
    pub normalized_path: String,
    pub normalization: &'static str,
    pub scope: &'static str,
}

fn normalize(declared: &str, service: &str) -> Result<(String, &'static str)> {
    let (path, normalization) = if let Some(path) = declared.strip_prefix(r"\??\") {
        (path, "nt_dos_prefix_removed")
    } else {
        (declared, "absolute_dos_preserved")
    };
    let bytes = path.as_bytes();
    ensure!(
        bytes.len() >= 4 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\',
        "Submitted service ImagePath requires an absolute DOS path"
    );
    ensure!(
        path.encode_utf16().count() <= crate::kernel_loader::MAX_FULL_NAME_UNITS
            && !path.chars().any(|c| c.is_control()
                || matches!(c, '\0' | '/' | '*' | '?' | '"' | '<' | '>' | '|' | '%')),
        "Submitted service ImagePath exceeds bounded loader name capacity or contains unsupported characters or variables"
    );
    ensure!(
        path[3..].split('\\').all(|component| {
            !component.is_empty()
                && !matches!(component, "." | "..")
                && !component.contains(':')
                && !component.ends_with([' ', '.'])
        }),
        "Submitted service ImagePath contains an ambiguous DOS component"
    );
    let basename = path.rsplit('\\').next().unwrap_or_default();
    ensure!(
        basename.eq_ignore_ascii_case(&format!("{service}.sys")),
        "Submitted service ImagePath basename differs from bound service identity"
    );
    Ok((path.to_owned(), normalization))
}

pub(super) fn resolve(registry: &Registry, service: &str) -> Result<Receipt> {
    ensure!(
        emumee_core::driver_input::service_name_valid(service),
        "Submitted service identity invalid"
    );
    let subkey = format!(r"SYSTEM\CurrentControlSet\Services\{service}");
    let registry_key = format!(r"HKEY_LOCAL_MACHINE\{subkey}");
    let value = match registry.get_value(
        0,
        HKLM,
        &subkey,
        "ImagePath",
        NO_EXPAND,
        true,
        &BTreeMap::new(),
    ) {
        Ok(value) => value,
        Err(error) if error.win32 == 2 => {
            return Ok(Receipt {
                service: service.into(),
                registry_key,
                value_name: "ImagePath",
                source: "documented_absent_service_image_path_fallback",
                declared_path: None,
                value_type: None,
                registry_value_sha256: None,
                normalized_path: format!(r"C:\Windows\System32\drivers\{service}.sys"),
                normalization: "documented_default",
                scope: "The exact bound guest service key/value is absent. Uses the documented synthetic DOS metadata path only; no host lookup or file-existence claim.",
            });
        }
        Err(error) => return Err(error.into()),
    };
    ensure!(
        matches!(value.value_type, REG_SZ | REG_EXPAND_SZ),
        "Submitted service ImagePath requires REG_SZ or REG_EXPAND_SZ"
    );
    ensure!(
        value.data.len() % 2 == 0,
        "Submitted service ImagePath has odd-length UTF16 data"
    );
    let mut units = value
        .data
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    if units.pop() != Some(0) || units.is_empty() || units.contains(&0) {
        bail!("Submitted service ImagePath requires exactly one normalized UTF16 string");
    }
    let declared = String::from_utf16(&units)
        .map_err(|_| anyhow::anyhow!("Submitted service ImagePath contains malformed UTF16"))?;
    let (normalized_path, normalization) = normalize(&declared, service)?;
    Ok(Receipt {
        service: service.into(),
        registry_key,
        value_name: "ImagePath",
        source: "validated_guest_registry_image_path",
        declared_path: Some(declared),
        value_type: Some(value.value_type),
        registry_value_sha256: Some(format!("{:x}", Sha256::digest(&value.data))),
        normalized_path,
        normalization,
        scope: "Readonly RegGetValueW with RRF_NOEXPAND over the exact bound service in the validated prepared guest registry. The declared path and hash describe its RegGetValue-normalized UTF16 value, not raw stored termination. Optional NT DOS prefix removal produces a declared DOS metadata projection shared by the receipt, mapped module catalog and owned loader names, bounded to that owned loader's 1919 UTF16-unit name capacity. No environment expansion, host state, file existence or full private-loader path ABI is asserted.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use emumee_core::registry::{REG_BINARY, encode_text};

    fn registry(path: &str, kind: u32, bytes: &[u8]) -> Registry {
        let mut registry = Registry::new(0);
        registry
            .seed_value(path, "ImagePath", kind, bytes, true)
            .unwrap();
        registry
    }

    fn service_registry(kind: u32, text: &str, terminated: bool) -> Registry {
        registry(
            r"HKLM\SYSTEM\CurrentControlSet\Services\CaseService",
            kind,
            &encode_text(text, true, terminated),
        )
    }

    #[test]
    fn exact_guest_key_projects_declared_dos_and_nt_paths_without_expansion() {
        for (kind, text, expected, normalization) in [
            (
                REG_SZ,
                r"C:\Program Files\Fixture Driver\CaseService.sys",
                r"C:\Program Files\Fixture Driver\CaseService.sys",
                "absolute_dos_preserved",
            ),
            (
                REG_EXPAND_SZ,
                r"\??\D:\Declared\caseservice.SYS",
                r"D:\Declared\caseservice.SYS",
                "nt_dos_prefix_removed",
            ),
        ] {
            let registry = service_registry(kind, text, true);
            let before = format!("{registry:?}");
            let result = resolve(&registry, "CaseService").unwrap();
            assert_eq!(result.source, "validated_guest_registry_image_path");
            assert_eq!(result.declared_path.as_deref(), Some(text));
            assert_eq!(result.normalized_path, expected);
            assert_eq!(result.normalization, normalization);
            assert_eq!(result.value_type, Some(kind));
            assert_eq!(result.registry_value_sha256.as_ref().unwrap().len(), 64);
            assert_eq!(
                before,
                format!("{registry:?}"),
                "Readonly binding changed registry"
            );
        }
        // RegGetValue's documented terminator repair is explicitly accepted.
        let normalized = resolve(
            &service_registry(REG_SZ, r"C:\Declared\CaseService.sys", false),
            "CaseService",
        )
        .unwrap();
        assert_eq!(normalized.normalized_path, r"C:\Declared\CaseService.sys");
    }

    #[test]
    fn only_absent_exact_key_or_value_uses_fallback() {
        let mut registry = Registry::new(0);
        registry
            .seed_value(
                r"HKLM\SYSTEM\CurrentControlSet\Services\Other",
                "ImagePath",
                REG_SZ,
                &encode_text(r"C:\Wrong\CaseService.sys", true, true),
                true,
            )
            .unwrap();
        registry
            .seed_value(
                r"HKCU\SYSTEM\CurrentControlSet\Services\CaseService",
                "ImagePath",
                REG_SZ,
                &encode_text(r"C:\Wrong\CaseService.sys", true, true),
                true,
            )
            .unwrap();
        for key_exists in [false, true] {
            if key_exists {
                registry
                    .seed_key(r"HKLM\SYSTEM\CurrentControlSet\Services\CaseService")
                    .unwrap();
            }
            let fallback = resolve(&registry, "CaseService").unwrap();
            assert_eq!(
                fallback.source,
                "documented_absent_service_image_path_fallback"
            );
            assert_eq!(
                fallback.normalized_path,
                r"C:\Windows\System32\drivers\CaseService.sys"
            );
            assert!(fallback.declared_path.is_none());
        }
        assert!(
            resolve(
                &service_registry(REG_BINARY, "invalid", true),
                "CaseService"
            )
            .is_err()
        );
        assert!(resolve(&registry, "../Invalid").is_err());
    }

    #[test]
    fn malformed_ambiguous_unresolved_and_foreign_basename_values_fail_closed() {
        for text in [
            r"%SystemRoot%\CaseService.sys",
            r"\SystemRoot\CaseService.sys",
            r"C:CaseService.sys",
            r"\\server\share\CaseService.sys",
            r"C:/Driver/CaseService.sys",
            r#""C:\Driver\CaseService.sys""#,
            r"C:\Driver\CaseService.sys -arg",
            r"C:\Driver\Other.sys",
            r"C:\Driver\..\CaseService.sys",
            r"C:\Driver\\CaseService.sys",
            r"C:\Driver.\CaseService.sys",
            r"C:\Driver \CaseService.sys",
            r"C:\Driver\CaseService.sys:stream",
            r"C:\Driver\CaseService.sys ",
            "C:\\Driver\\CaseService.sys\0trailing",
            "C:\\Driver\\CaseService.sys\0",
        ] {
            assert!(
                resolve(&service_registry(REG_SZ, text, true), "CaseService").is_err(),
                "{text:?}"
            );
        }
        for bytes in [vec![0, 0], vec![0x41], vec![0x00, 0xd8, 0, 0]] {
            let registry = registry(
                r"HKLM\SYSTEM\CurrentControlSet\Services\CaseService",
                REG_SZ,
                &bytes,
            );
            assert!(resolve(&registry, "CaseService").is_err());
        }
    }

    #[test]
    fn normalized_path_bound_matches_owned_loader_name_capacity() {
        let fixed = r"C:\\CaseService.sys".encode_utf16().count();
        let component = "a".repeat(crate::kernel_loader::MAX_FULL_NAME_UNITS - fixed);
        let exact = format!(r"C:\{component}\CaseService.sys");
        assert_eq!(
            exact.encode_utf16().count(),
            crate::kernel_loader::MAX_FULL_NAME_UNITS
        );
        assert!(resolve(&service_registry(REG_SZ, &exact, true), "CaseService").is_ok());
        let over = format!(r"C:\a{component}\CaseService.sys");
        assert!(resolve(&service_registry(REG_SZ, &over, true), "CaseService").is_err());
        // The removable NT DOS prefix is provenance, not part of the projected
        // FullDllName storage. Count UTF16 units after that normalization.
        let prefixed = format!(r"\??\{exact}");
        assert!(
            resolve(
                &service_registry(REG_EXPAND_SZ, &prefixed, true),
                "CaseService"
            )
            .is_ok()
        );
    }

    fn persona_document(path: &str) -> Vec<u8> {
        let mut document: serde_json::Value =
            serde_json::from_slice(&emumee_core::fixtures::configured_document(
                emumee_core::fixtures::ConfiguredFixture::Kernel,
            ))
            .unwrap();
        document["registry_keys"] = serde_json::json!([{
            "path": "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\CaseService",
            "values": [{"name": "ImagePath", "type": "REG_EXPAND_SZ", "data": path}]
        }]);
        serde_json::to_vec(&document).unwrap()
    }

    fn module_query_driver() -> Vec<u8> {
        use emumee_core::{
            fixtures::{ModuleFixture, kernel_modules_probe},
            pe::{Architecture, ImportName, PeImage},
        };
        let mut bytes = kernel_modules_probe(Architecture::X64, ModuleFixture::Standard);
        let pe = PeImage::parse(&bytes, "generated-service.sys").unwrap();
        let slot = pe.imports.iter().find(|import|
            matches!(&import.name, ImportName::Name(name) if name == "ZwQuerySystemInformation")
        ).unwrap().iat_rva;
        // ZwQuerySystemInformation(11,NULL,0,NULL) records authoritative module
        // rows while returning a normal length retry; no output buffer is read.
        let mut code = vec![
            0x48, 0x83, 0xec, 0x28, 0xb9, 11, 0, 0, 0, 0x31, 0xd2, 0x45, 0x31, 0xc0, 0x45, 0x31,
            0xc9, 0xff, 0x15,
        ];
        code.extend_from_slice(&((slot as i32) - (0x1000 + code.len() as i32 + 4)).to_le_bytes());
        code.extend_from_slice(&[0xb8, 1, 0, 0, 0, 0x48, 0x83, 0xc4, 0x28, 0xc3]);
        bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
        bytes
    }

    #[test]
    fn submitted_and_generated_loader_catalog_share_the_declared_path() {
        let declared = r"\??\C:\Program Files\Fixture Driver\CaseService.sys";
        let expected = r"C:\Program Files\Fixture Driver\CaseService.sys";
        let persona = persona_document(declared);
        let bytes = module_query_driver();
        let submitted = crate::run_submitted_driver_with_persona_and_reference_and_broker(
            &bytes,
            "CaseService",
            100,
            30_000_000,
            Some(&persona),
            None,
            None,
        )
        .unwrap();
        assert_eq!(submitted.error, None);
        assert_eq!(submitted.guest_entry_return, Some(1));
        let receipt = submitted.configuration.as_ref().unwrap();
        assert_eq!(receipt.guest_image_path.as_deref(), Some(expected));
        assert_eq!(
            receipt
                .submitted_service_image_path
                .as_ref()
                .unwrap()
                .declared_path
                .as_deref(),
            Some(declared)
        );
        let inventory = &submitted.kernel_modules.as_ref().unwrap().last_inventory;
        assert_eq!(
            inventory
                .iter()
                .find(|module| module.name == "caseservice.sys")
                .unwrap()
                .provenance
                .guest_path,
            expected
        );
        assert!(
            submitted.kernel_loader.is_none(),
            "Path declaration granted unpinned private ABI"
        );

        // A harmless generated configuration exercises the same catalog-to-KLDR
        // projection without requiring the authenticated production reference.
        let validated = emumee_core::fullpersona::decode(
            &persona,
            &emumee_core::fullpersona::ResolveContext::default(),
        )
        .unwrap();
        let prepared = super::super::Prepared::new(
            validated,
            super::super::Request {
                architecture: crate::Architecture::X64,
                kernel: true,
                initial_processor: 0,
                process: None,
                budget: 100,
                timeout_us: 30_000_000,
            },
        )
        .unwrap()
        .bind_submitted_service("CaseService")
        .unwrap();
        let generated = crate::run_generated_with_fixture_configuration(
            &bytes,
            &[],
            100,
            30_000_000,
            crate::GeneratedConfiguration {
                configured: Some(prepared),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(generated.error, None);
        let loader = generated.kernel_loader.as_ref().unwrap();
        assert!(loader.generated_fixture);
        let primary = loader
            .nodes
            .iter()
            .find(|node| node.address == loader.driver_section)
            .unwrap();
        assert_eq!(primary.guest_path, expected);
        assert_eq!(primary.image_base, generated.image_load.base);
        assert_eq!(
            generated
                .kernel_modules
                .as_ref()
                .unwrap()
                .last_inventory
                .iter()
                .find(|module| module.name == "caseservice.sys")
                .unwrap()
                .provenance
                .guest_path,
            expected
        );
        assert_eq!(
            generated
                .configuration
                .as_ref()
                .unwrap()
                .guest_image_path
                .as_deref(),
            Some(expected)
        );

        let rejected = persona_document(r"C:\Declared\Other.sys");
        assert!(
            crate::run_submitted_driver_with_persona_and_reference_and_broker(
                &bytes,
                "CaseService",
                100,
                30_000_000,
                Some(&rejected),
                None,
                None,
            )
            .is_err()
        );
    }
}

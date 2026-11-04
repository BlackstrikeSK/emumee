use super::*;
use emumee_core::{
    fixtures::{PeLayoutFixture as Fixture, pe_layout_probe},
    report_bundle::digest,
    user_input::{PROFILE, Request},
};

fn request(bytes: &[u8]) -> Request {
    Request {
        schema: 1,
        profile: PROFILE.into(),
        run_id: "20261104T120000Z-12345678".into(),
        input_sha256: digest(bytes),
        input_size: bytes.len() as u64,
        module_name: "layout.exe".into(),
        arguments: vec![],
        max_instructions: 1000,
        timeout_us: 1_000_000,
        persona_sha256: None,
        clock_utc_filetime: 134377488000000000,
    }
}

#[test]
fn submitted_pe_layout_cpu_enforces_section_and_header_permissions() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for (case, expected, fault) in [
            (Fixture::RawTail, Some(42), None),
            (Fixture::VirtualTail, Some(0), None),
            (Fixture::RawAlias, Some(42), None),
            (Fixture::WriteData, Some(42), None),
            (Fixture::WriteText, None, Some("WRITE_PROT")),
            (Fixture::WriteHeaders, None, Some("WRITE_PROT")),
            (Fixture::ExecuteData, None, Some("FETCH_PROT")),
            (Fixture::ReadGap, None, Some("READ_PROT")),
        ] {
            let bytes = pe_layout_probe(architecture, case);
            if let Ok(root) = std::env::var("EMUMEE_USER_TEST_FIXTURES") {
                let directory = std::path::PathBuf::from(root)
                    .join(format!("{architecture:?}-layout-{case:?}"));
                std::fs::create_dir_all(&directory).unwrap();
                std::fs::write(directory.join("layout.exe"), &bytes).unwrap();
            }
            let result = user::run(&request(&bytes), &bytes, None).unwrap();
            assert_eq!(
                result.guest_entry_return, expected,
                "{architecture:?}/{case:?}: {result:#?}"
            );
            if let Some(fault) = fault {
                assert!(
                    result.error.as_ref().unwrap().contains(fault),
                    "{result:#?}"
                );
            } else {
                assert_eq!(result.error, None, "{result:#?}");
                assert_eq!(result.completion_reason, "entry_return");
            }
        }
    }
}

#[test]
fn pe_layout_model_and_cpu_permissions_agree_on_every_image_page() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let bytes = pe_layout_probe(architecture, Fixture::VirtualTail);
        let pe = PeImage::parse(&bytes, "layout.exe").unwrap();
        let mut engine = new_engine(architecture).unwrap();
        map_image(&mut engine, &pe, &bytes, pe.image_base).unwrap();
        protect_image(&mut engine, &pe).unwrap();
        let regions = engine.mem_regions().unwrap();
        for (offset, permissions) in [
            (0, Permissions::READ),
            (0x1000, Permissions::RX),
            (0x2000, Permissions::NONE),
            (0x3000, Permissions::RW),
            (0x4000, Permissions::NONE),
        ] {
            let address = pe.image_base + offset;
            let model = engine.get_data().apis.memory.region(address).unwrap();
            let native = regions
                .iter()
                .find(|region| address >= region.begin && address <= region.end)
                .unwrap();
            assert_eq!(model.permissions, permissions);
            assert_eq!(native.perms, u32::from(permissions.0));
        }
    }
}

#[test]
fn submitted_pe_layout_rejects_runtime_address_collisions() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let mut bytes = pe_layout_probe(architecture, Fixture::RawTail);
        if architecture == Architecture::X64 {
            bytes[0x98 + 24..0x98 + 32].copy_from_slice(&RETURN.to_le_bytes());
        } else {
            bytes[0x98 + 28..0x98 + 32].copy_from_slice(&(RETURN as u32).to_le_bytes());
        }
        assert!(user::run(&request(&bytes), &bytes, None).is_err());
    }
}

#[test]
fn submitted_pe_layout_rejects_malformed_admission() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let table = 0x98
            + if architecture == Architecture::X64 {
                0xf0
            } else {
                0xe0
            };
        for (case, offset, value) in [
            ("Headers", 0x98 + 60, 0x1ffu32),
            ("Raw", table + 20, 0x201),
            ("Overlap", table + 40 + 12, 0x1000),
        ] {
            let mut bytes = pe_layout_probe(architecture, Fixture::RawTail);
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            if let Ok(root) = std::env::var("EMUMEE_USER_TEST_FIXTURES") {
                let directory = std::path::PathBuf::from(root)
                    .join(format!("{architecture:?}-layout-invalid-{case}"));
                std::fs::create_dir_all(&directory).unwrap();
                std::fs::write(directory.join("layout.exe"), &bytes).unwrap();
            }
            assert!(request(&bytes).verify_input(&bytes).is_err());
            assert!(user::run(&request(&bytes), &bytes, None).is_err());
        }
    }
}

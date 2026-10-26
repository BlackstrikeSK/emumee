//! Generated x86/x64 callers for explicit namespace lookup, without host I/O.
use super::*;
use emumee_core::{
    fixtures::{ApiFixture, ConfiguredFixture, EnvironmentFixture, configured_document},
    fullpersona::{ResolveContext, decode},
};

fn fixture(arch: Architecture, name: &str, nt: bool, readonly: bool, status: u32) -> Vec<u8> {
    let mut image = emumee_core::fixtures::api_probe(
        arch,
        ApiFixture::Environment(EnvironmentFixture::DataOnly),
    );
    image[0x1500..0x1540].fill(0);
    let import = if nt {
        b"NtOpenSection\0" as &[u8]
    } else {
        b"ZwOpenSection\0"
    };
    image[0x1502..0x1502 + import.len()].copy_from_slice(import);
    let wide = arch == Architecture::X64;
    let width = arch.width();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let output = base + if readonly { 0x1800 } else { 0x2b00 };
    image[0x1d00..0x1d10].fill(0xa5);
    image[0x1d20..0x1d50].fill(0);
    image[0x1d20..0x1d24].copy_from_slice(&(if wide { 48u32 } else { 24 }).to_le_bytes());
    let ptr = if wide { 16 } else { 8 };
    image[0x1d20 + ptr..0x1d20 + ptr + width]
        .copy_from_slice(&(base + 0x2b60).to_le_bytes()[..width]);
    let flags = if wide { 24 } else { 12 };
    image[0x1d20 + flags..0x1d24 + flags].copy_from_slice(&0x240u32.to_le_bytes());
    let bytes: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert!(bytes.len() <= 96);
    image[0x1d60..0x1d62].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
    // Large MaximumLength does not authorize reading beyond Length.
    image[0x1d62..0x1d64].copy_from_slice(&32766u16.to_le_bytes());
    let ptr = if wide { 8 } else { 4 };
    image[0x1d60 + ptr..0x1d60 + ptr + width]
        .copy_from_slice(&(base + 0x2ba0).to_le_bytes()[..width]);
    image[0x1da0..0x1da0 + bytes.len()].copy_from_slice(&bytes);
    let mut code = vec![];
    if wide {
        code.extend([0x48, 0x83, 0xec, 0x28]);
        for (prefix, value) in [[0x48, 0xb9], [0x48, 0xba], [0x49, 0xb8]].into_iter().zip([
            output,
            0xf001f,
            base + 0x2b20,
        ]) {
            code.extend(prefix);
            code.extend(value.to_le_bytes());
        }
        code.extend([0xff, 0x15]);
        code.extend((0x2080i32 - (0x1000 + code.len() + 4) as i32).to_le_bytes());
    } else {
        for value in [base + 0x2b20, 0xf001f, output] {
            code.push(0x68);
            code.extend((value as u32).to_le_bytes());
        }
        code.extend([0xff, 0x15]);
        code.extend(((base + 0x2080) as u32).to_le_bytes());
    }
    code.push(0x3d);
    code.extend(status.to_le_bytes());
    code.extend([0x74, 2, 0x0f, 0x0b]);
    for (address, value) in [
        (base + 0x2b00, 0u32),
        (base + 0x2b04, if wide { 0 } else { 0xa5a5a5a5 }),
        (base + 0x2b08, 0xa5a5a5a5),
    ] {
        code.push(0xa1);
        if wide {
            code.extend(address.to_le_bytes());
        } else {
            code.extend((address as u32).to_le_bytes());
        }
        code.push(0x3d);
        code.extend(value.to_le_bytes());
        code.extend([0x74, 2, 0x0f, 0x0b]);
    }
    code.extend([0xb8, 42, 0, 0, 0]);
    if wide {
        code.extend([0x48, 0x83, 0xc4, 0x28]);
    }
    code.push(0xc3);
    assert!(code.len() < 0x200);
    image[0x200..0x1200].fill(0xcc);
    image[0x200..0x200 + code.len()].copy_from_slice(&code);
    image
}
fn document() -> serde_json::Value {
    let mut doc: serde_json::Value =
        serde_json::from_slice(&configured_document(ConfiguredFixture::Kernel)).unwrap();
    doc["boot_config"] = serde_json::json!({"object_directories":[
        {"path":"\\","entries":[{"name":"Device","object_type":"Directory"},{"name":"Unknown","object_type":"Directory"}]},
        {"path":"\\Device","entries":[{"name":"Existing","object_type":"Section"}]}
    ]});
    doc
}
fn run(
    arch: Architecture,
    name: &str,
    nt: bool,
    readonly: bool,
    status: u32,
    doc: serde_json::Value,
    budget: u64,
) -> Execution {
    let validated = decode(
        &serde_json::to_vec(&doc).unwrap(),
        &ResolveContext::default(),
    )
    .unwrap();
    let prepared = configured::Prepared::new(
        validated,
        configured::Request {
            architecture: arch,
            kernel: true,
            initial_processor: 0,
            process: None,
            budget,
            timeout_us: 30_000_000,
        },
    )
    .unwrap();
    run_generated_with_fixture_configuration(
        &fixture(arch, name, nt, readonly, status),
        &[],
        budget,
        30_000_000,
        GeneratedConfiguration {
            configured: Some(prepared),
            ..Default::default()
        },
    )
    .unwrap()
}
#[test]
fn section_lookup_guest_abi_clears_only_the_pointer_width_on_verified_negative_results() {
    for arch in [Architecture::X86, Architecture::X64] {
        for nt in [false, true] {
            for (name, status) in [
                ("\\Device\\Missing", 0xc0000034),
                ("\\Absent\\leaf", 0xc000003a),
                ("\\Device", 0xc0000024),
            ] {
                let e = run(arch, name, nt, false, status, document(), 1000);
                assert_eq!(e.error, None, "{arch:?}/{name}: {e:#?}");
                assert_eq!(e.guest_entry_return, Some(42));
                let r = e.kernel_sections.unwrap();
                assert_eq!(r.events.len(), 1);
                assert_eq!(r.events[0].status, status);
                assert_eq!(r.events[0].name, name);
                assert!(r.events[0].output_cleared);
                assert!(!r.native_effect_failure);
            }
        }
    }
}
#[test]
fn section_unknown_inventory_existing_objects_and_readonly_outputs_never_invent_a_result() {
    for arch in [Architecture::X86, Architecture::X64] {
        for (name, readonly, configured, expected) in [
            ("\\Unknown\\leaf", false, true, "not owned"),
            ("\\Device\\Existing", false, true, "lifetime"),
            ("\\Device\\Missing", true, true, "permission"),
            (
                "\\Device\\Missing",
                false,
                false,
                "not explicitly configured",
            ),
        ] {
            let mut doc = document();
            if !configured {
                doc["boot_config"] = serde_json::json!({});
            }
            let e = run(arch, name, false, readonly, 0xc0000034, doc, 1000);
            assert!(
                e.error
                    .as_deref()
                    .is_some_and(|err| err.to_ascii_lowercase().contains(expected)),
                "{arch:?}/{name}: {e:#?}"
            );
            assert_eq!(e.guest_entry_return, None);
            assert!(e.kernel_sections.is_none());
            assert_eq!(e.api_events.last().unwrap().result, None);
        }
    }
}
#[test]
fn section_snapshot_schema_rejects_partial_ambiguous_and_non_array_configuration() {
    for value in [
        serde_json::json!([]),
        serde_json::json!({}),
        serde_json::json!([
            {"path":"\\Device","entries":[]}
        ]),
        serde_json::json!([
            {"path":"\\","entries":[{"name":"Device","object_type":"Directory"},{"name":"device","object_type":"Directory"}]}
        ]),
    ] {
        let mut doc = document();
        doc["boot_config"]["object_directories"] = value;
        assert!(
            decode(
                &serde_json::to_vec(&doc).unwrap(),
                &ResolveContext::default()
            )
            .is_err()
        );
    }
    for arch in [Architecture::X86, Architecture::X64] {
        let e = run(
            arch,
            "\\Device\\Missing",
            false,
            false,
            0xc0000034,
            document(),
            2,
        );
        assert_eq!(e.guest_entry_return, None);
        assert!(e.kernel_sections.is_none());
        assert!(e.api_events.is_empty());
    }
}

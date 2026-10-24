//! Owned generated callers for the documented eight-byte query contract.
use super::*;
use emumee_core::{
    fixtures::{ApiFixture, ConfiguredFixture, EnvironmentFixture, configured_document},
    fullpersona::{ResolveContext, decode},
};
fn fixture(architecture: Architecture, kind: u8, options: u32, nt_alias: bool) -> Vec<u8> {
    let mut image = emumee_core::fixtures::api_probe(
        architecture,
        ApiFixture::Environment(EnvironmentFixture::DataOnly),
    );
    image[0x1500..0x1540].fill(0);
    let name = if nt_alias {
        b"NtQuerySystemInformation\0"
    } else {
        b"ZwQuerySystemInformation\0"
    };
    image[0x1502..0x1502 + name.len()].copy_from_slice(name);
    let wide = architecture == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let buffer = if kind == 4 {
        base + 0x1800
    } else if kind == 1 {
        0xdeadbeef
    } else {
        base + 0x2b40
    };
    let needed = if kind == 3 {
        0
    } else if kind == 5 {
        buffer + 4
    } else {
        base + 0x2b60
    };
    let capacity = if kind == 1 { 7 } else { 8 };
    let declared = if kind == 2 { 0u32 } else { 8 };
    image[0x1d40..0x1d70].fill(0xa5);
    image[0x1d40..0x1d44].copy_from_slice(&declared.to_le_bytes());
    image[0x1d60..0x1d64].fill(0xa5);
    let mut code = Vec::new();
    if wide {
        code.extend([0x48, 0x83, 0xec, 0x28]);
        for (prefix, value) in [[0x48, 0xb9], [0x48, 0xba], [0x49, 0xb8], [0x49, 0xb9]]
            .into_iter()
            .zip([103, buffer, capacity, needed])
        {
            code.extend(prefix);
            code.extend(value.to_le_bytes());
        }
        code.extend([0xff, 0x15]);
        code.extend((0x2080i32 - (0x1000 + code.len() + 4) as i32).to_le_bytes());
    } else {
        for value in [103, buffer, capacity, needed].into_iter().rev() {
            code.push(0x68);
            code.extend((value as u32).to_le_bytes());
        }
        code.extend([0xff, 0x15]);
        code.extend(((base + 0x2080) as u32).to_le_bytes());
    }
    let expected = if matches!(kind, 1 | 2) {
        0xc0000004u32
    } else {
        0
    };
    code.push(0x3d);
    code.extend(expected.to_le_bytes());
    code.extend([0x74, 2, 0x0f, 0x0b]);
    // Verify actual guest output bytes; these assertions execute after the API.
    for (address, value) in [
        (base + 0x2b40, declared),
        (
            base + 0x2b44,
            if expected == 0 { options } else { 0xa5a5a5a5 },
        ),
        (base + 0x2b48, 0xa5a5a5a5),
        (base + 0x2b60, if kind == 3 { 0xa5a5a5a5 } else { 8 }),
        (base + 0x2b64, 0xa5a5a5a5),
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
    image[0x200..0x1200].fill(0xcc);
    image[0x200..0x200 + code.len()].copy_from_slice(&code);
    if kind == 4 {
        image[0xa00..0xa08].fill(0xa5);
        image[0xa00..0xa04].copy_from_slice(&8u32.to_le_bytes());
    }
    image
}
fn run(image: &[u8], architecture: Architecture, options: Option<u32>, budget: u64) -> Execution {
    let mut document: serde_json::Value =
        serde_json::from_slice(&configured_document(ConfiguredFixture::Kernel)).unwrap();
    if let Some(options) = options {
        document["boot_config"] = serde_json::json!({"code_integrity_options":options});
    }
    let persona = decode(
        &serde_json::to_vec(&document).unwrap(),
        &ResolveContext::default(),
    )
    .unwrap();
    let prepared = configured::Prepared::new(
        persona,
        configured::Request {
            architecture,
            kernel: true,
            initial_processor: 0,
            process: None,
            budget,
            timeout_us: 30_000_000,
        },
    )
    .unwrap();
    run_generated_with_fixture_configuration(
        image,
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
fn code_integrity_guest_abi_length_status_options_and_optional_return_length_are_observed() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for alias in [false, true] {
            for options in [0, 0xe001, u32::MAX] {
                for kind in 0..4 {
                    let e = run(
                        &fixture(architecture, kind, options, alias),
                        architecture,
                        Some(options),
                        1000,
                    );
                    assert_eq!(e.error, None, "{architecture:?}/{kind}/{options:x}: {e:#?}");
                    assert_eq!(e.guest_entry_return, Some(42));
                    let report = e.kernel_code_integrity.unwrap();
                    assert_eq!(report.events.len(), 1);
                    let event = &report.events[0];
                    let success = matches!(kind, 0 | 3);
                    assert_eq!(event.copied, if success { 8 } else { 0 });
                    assert_eq!(event.required, 8);
                    assert_eq!(event.return_length_written, kind != 3);
                    assert_eq!(event.options, success.then_some(options));
                    assert_eq!(event.status, if success { 0 } else { 0xc0000004 });
                    assert!(e.kernel_modules.unwrap().events.is_empty());
                }
            }
        }
    }
}
#[test]
fn code_integrity_unconfigured_readonly_and_aliasing_queries_cannot_succeed() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let unknown = run(
            &fixture(architecture, 0, 0, false),
            architecture,
            None,
            1000,
        );
        assert!(
            unknown
                .error
                .as_deref()
                .is_some_and(|e| e.contains("not explicitly configured")),
            "{unknown:#?}"
        );
        assert_eq!(unknown.guest_entry_return, None);
        assert!(unknown.kernel_code_integrity.is_none());
        for (kind, expected) in [(4, "permission"), (5, "aliases")] {
            let e = run(
                &fixture(architecture, kind, 0xe001, false),
                architecture,
                Some(0xe001),
                1000,
            );
            assert!(
                e.error
                    .as_deref()
                    .is_some_and(|e| e.to_ascii_lowercase().contains(expected)),
                "{e:#?}"
            );
            assert_eq!(e.guest_entry_return, None);
            assert!(e.kernel_code_integrity.is_none());
            assert_eq!(e.api_events[0].result, None);
        }
        let mismatch = run(
            &fixture(architecture, 2, 0, false),
            architecture,
            None,
            1000,
        );
        assert_eq!(mismatch.error, None);
        assert_eq!(mismatch.guest_entry_return, Some(42));
    }
}
#[test]
fn code_integrity_budget_prefixes_never_imply_a_completed_driver_entry() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let image = fixture(architecture, 0, 0xe001, false);
        let full = run(&image, architecture, Some(0xe001), 1000);
        assert_eq!(full.error, None);
        for budget in [1, full.instruction_count - 1] {
            let partial = run(&image, architecture, Some(0xe001), budget);
            assert_eq!(partial.error, None);
            assert_eq!(partial.completion_reason, "instruction_budget");
            assert_eq!(partial.instruction_count, budget);
            assert_eq!(partial.guest_entry_return, None);
            if budget == 1 {
                assert!(partial.kernel_code_integrity.is_none());
            }
        }
    }
}

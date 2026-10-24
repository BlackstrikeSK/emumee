use super::*;
use emumee_core::fixtures::{ApiFixture, EnvironmentFixture as F};

fn change_option_fixture(architecture: Architecture, variant: u8) -> Vec<u8> {
    let mut image =
        emumee_core::fixtures::api_probe(architecture, ApiFixture::Environment(F::DataOnly));
    image[0x1500..0x1540].fill(0);
    image[0x1502..0x1511].copy_from_slice(b"KdChangeOption\0");
    image[0x1d40..0x1d44].fill(0xa5);
    let wide = architecture == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let args = match variant {
        0 => [0, 1, 0, 0, 0, base + 0x2b40],
        1 => [
            u32::MAX as u64,
            u32::MAX as u64,
            0xdeadbeef,
            u32::MAX as u64,
            0xdeadbeef,
            0xdeadbeef,
        ],
        _ => [0, 8, base + 0x1000, 8, base + 0x1000, base + 0x1000],
    };
    let mut code = Vec::new();
    if wide {
        code.extend([0x48, 0x83, 0xec, 0x38]);
        for (prefix, value) in [[0x48, 0xb9], [0x48, 0xba], [0x49, 0xb8], [0x49, 0xb9]]
            .into_iter()
            .zip(args)
        {
            code.extend(prefix);
            code.extend(value.to_le_bytes());
        }
        for (offset, value) in [(0x20, args[4]), (0x28, args[5])] {
            code.extend([0x48, 0xb8]);
            code.extend(value.to_le_bytes());
            code.extend([0x48, 0x89, 0x44, 0x24, offset]);
        }
        code.extend([0xff, 0x15]);
        code.extend((0x2080i32 - (0x1000 + code.len() + 4) as i32).to_le_bytes());
    } else {
        for arg in args.into_iter().rev() {
            code.push(0x68);
            code.extend((arg as u32).to_le_bytes());
        }
        code.extend([0xff, 0x15]);
        code.extend(((base + 0x2080) as u32).to_le_bytes());
    }
    code.push(0x3d);
    code.extend(0xc0000354u32.to_le_bytes());
    code.extend([0x74, 2, 0x0f, 0x0b]);
    code.push(0xa1);
    if wide {
        code.extend((base + 0x2b40).to_le_bytes());
    } else {
        code.extend(((base + 0x2b40) as u32).to_le_bytes());
    }
    code.push(0x3d);
    code.extend(0xa5a5a5a5u32.to_le_bytes());
    code.extend([0x74, 2, 0x0f, 0x0b, 0xb8]);
    code.extend(0xc0000354u32.to_le_bytes());
    if wide {
        code.extend([0x48, 0x83, 0xc4, 0x38]);
    }
    code.push(0xc3);
    image[0x200..0x1200].fill(0xcc);
    image[0x200..0x200 + code.len()].copy_from_slice(&code);
    image
}

#[test]
fn kernel_environment_kd_change_option_no_debug_controls_returns_inactive_before_buffer_access() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for variant in 0..3 {
            let e = run_generated_image(
                &change_option_fixture(architecture, variant),
                1000,
                30_000_000,
            )
            .unwrap();
            assert_eq!(e.error, None, "{architecture:?}/{variant}: {e:#?}");
            assert_eq!(e.guest_entry_return, Some(0xc0000354));
            assert_eq!(e.api_calls, 1);
            assert_eq!(e.api_events[0].api, "ntoskrnl.KdChangeOption");
            assert_eq!(e.api_events[0].arguments.len(), 6);
            assert_eq!(e.api_events[0].result, Some(0xc0000354));
        }
    }
}

#[test]
fn kernel_environment_kd_change_option_enabled_profile_is_explicitly_unsupported() {
    use emumee_core::{
        fixtures::{ConfiguredFixture, configured_document},
        fullpersona::{ResolveContext, decode},
    };
    for architecture in [Architecture::X86, Architecture::X64] {
        let original = configured_document(ConfiguredFixture::Kernel);
        let mut document: serde_json::Value = serde_json::from_slice(&original).unwrap();
        document["boot_config"] = decode(&original, &ResolveContext::default())
            .unwrap()
            .effective_json()["boot_config"]
            .clone();
        document["boot_config"]["debug"] = serde_json::json!(true);
        let validated = decode(
            &serde_json::to_vec(&document).unwrap(),
            &ResolveContext::default(),
        )
        .unwrap();
        let prepared = configured::Prepared::new(
            validated,
            configured::Request {
                architecture,
                kernel: true,
                initial_processor: 0,
                process: None,
                budget: 1000,
                timeout_us: 30_000_000,
            },
        )
        .unwrap();
        let e = run_generated_with_fixture_configuration(
            &change_option_fixture(architecture, 0),
            &[],
            1000,
            30_000_000,
            GeneratedConfiguration {
                configured: Some(prepared),
                ..Default::default()
            },
        )
        .unwrap();
        assert!(
            e.error
                .as_deref()
                .is_some_and(|e| e.contains("enabled-debugger option mutation")),
            "{e:#?}"
        );
        assert_eq!(e.guest_entry_return, None);
        assert_eq!(e.api_events[0].result, None);
    }
}

#[test]
fn kernel_environment_debugger_globals_follow_boot_policy_and_native_reads_obey_protection() {
    use emumee_core::{
        fixtures::{ConfiguredFixture, configured_document},
        fullpersona::{ResolveContext, decode},
    };
    for architecture in [Architecture::X86, Architecture::X64] {
        for enabled in [false, true] {
            for operation in [0, 1, 2] {
                let mut image = emumee_core::fixtures::api_probe(
                    architecture,
                    ApiFixture::Environment(F::DataOnly),
                );
                for (at, name) in [
                    (0x1500, "KdDebuggerEnabled"),
                    (0x1540, "KdDebuggerNotPresent"),
                ] {
                    image[at..at + 64].fill(0);
                    image[at + 2..at + 2 + name.len()].copy_from_slice(name.as_bytes());
                }
                let wide = architecture == Architecture::X64;
                let base = if wide { 0x140000000u64 } else { 0x400000 };
                let mut code = Vec::new();
                let load = |code: &mut Vec<u8>, address: u64| {
                    if wide {
                        code.push(0x48);
                    }
                    code.push(0xa1);
                    if wide {
                        code.extend(address.to_le_bytes());
                    } else {
                        code.extend((address as u32).to_le_bytes());
                    }
                };
                let check = |code: &mut Vec<u8>, expected: u8| {
                    code.extend([0x3c, expected, 0x74, 2, 0x0f, 0x0b]);
                };
                load(&mut code, base + 0x2080);
                if operation == 1 {
                    code.extend([0xc6, 0, 0xff]);
                } // Native byte write denied.
                if operation == 2 {
                    code.extend([0xff, 0xd0]);
                } // Native execute denied.
                code.extend([0x0f, 0xb6, 0]);
                check(&mut code, u8::from(enabled));
                load(&mut code, base + 0x2080 + architecture.width() as u64);
                code.extend([0x0f, 0xb6, 0]);
                check(&mut code, 1); // Enabled does not imply attached.
                code.extend(if wide {
                    vec![0x0f, 0xb6, 4, 0x25]
                } else {
                    vec![0x0f, 0xb6, 5]
                });
                code.extend(0x7ffe02d4u32.to_le_bytes());
                check(&mut code, u8::from(enabled));
                code.extend([0xb8, 1, 0, 0, 0, 0xc3]);
                image[0x200..0x1200].fill(0xcc);
                image[0x200..0x200 + code.len()].copy_from_slice(&code);
                let original = configured_document(ConfiguredFixture::Kernel);
                let boot = decode(&original, &ResolveContext::default())
                    .unwrap()
                    .effective_json()["boot_config"]
                    .clone();
                let mut document: serde_json::Value = serde_json::from_slice(&original).unwrap();
                document["boot_config"] = boot;
                document["boot_config"]["debug"] = serde_json::json!(enabled);
                let validated = decode(
                    &serde_json::to_vec(&document).unwrap(),
                    &ResolveContext::default(),
                )
                .unwrap();
                let prepared = configured::Prepared::new(
                    validated,
                    configured::Request {
                        architecture,
                        kernel: true,
                        initial_processor: 0,
                        process: None,
                        budget: 1000,
                        timeout_us: 30_000_000,
                    },
                )
                .unwrap();
                let e = run_generated_with_fixture_configuration(
                    &image,
                    &[],
                    1000,
                    30_000_000,
                    GeneratedConfiguration {
                        configured: Some(prepared),
                        ..Default::default()
                    },
                )
                .unwrap();
                if operation == 0 {
                    assert_eq!(e.error, None, "{architecture:?}/{enabled}: {e:#?}");
                    assert_eq!(e.guest_entry_return, Some(1));
                } else {
                    assert!(
                        e.error.is_some(),
                        "{architecture:?}/{enabled}/{operation}: {e:#?}"
                    );
                    assert_eq!(e.guest_entry_return, None);
                }
                let globals = &e.kernel_environment.unwrap().globals;
                assert_eq!(
                    globals
                        .iter()
                        .find(|g| g.name == "KdDebuggerEnabled")
                        .unwrap()
                        .value,
                    u64::from(enabled)
                );
                assert_eq!(
                    globals
                        .iter()
                        .find(|g| g.name == "KdDebuggerNotPresent")
                        .unwrap()
                        .value,
                    1
                );
            }
        }
    }
}
#[test]
fn kernel_environment_owned_driver_callers_check_data_iat_optional_output_and_faults() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in [
            F::Identity,
            F::NullOutput,
            F::BadOutput,
            F::ReadonlyOutput,
            F::CrossPageOutput,
            F::Limits,
            F::DataOnly,
            F::GlobalWrite,
            F::GlobalCall,
            F::ApiGlobalWrite,
        ] {
            let result =
                run_api_fixture(architecture, ApiFixture::Environment(kind), 1000).unwrap();
            assert_eq!(result.network.calls, 0);
            assert!(result.artifacts.is_empty());
            let report = result.kernel_environment.as_ref().unwrap();
            let identity = report.identity.as_ref().unwrap();
            assert_eq!(identity.logical_processors, 12);
            assert_eq!(identity.current_processor, 0);
            assert_eq!(identity.windows_build, 22631);
            assert_eq!(report.globals.len(), 5);
            assert_eq!(
                report.processor_number_writes,
                if matches!(kind, F::Identity) { 1 } else { 0 }
            );
            assert_eq!(report.globals[0].value, 12);
            for global in &report.globals {
                assert_eq!(global.permissions, "r--");
                assert_eq!(
                    global.width,
                    if matches!(
                        global.name,
                        "KeNumberProcessors" | "KdDebuggerEnabled" | "KdDebuggerNotPresent"
                    ) {
                        1
                    } else {
                        architecture.width()
                    }
                );
            }
            if kind.negative() {
                assert!(
                    result.error.is_some(),
                    "{architecture:?} {kind:?}: {result:#?}"
                );
                assert_eq!(result.guest_entry_return, None);
            } else {
                assert_eq!(result.error, None, "{architecture:?} {kind:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1));
            }
            if matches!(kind, F::DataOnly) {
                assert_eq!(
                    result.api_calls, 0,
                    "Data imports were dispatched as functions"
                );
                assert_eq!(result.synthetic_providers.len(), 8);
            }
        }
    }
}
#[test]
fn kernel_environment_budget_prefixes_do_not_fabricate_return_or_output() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in [F::Identity, F::NullOutput, F::Limits, F::DataOnly] {
            let full = run_api_fixture(architecture, ApiFixture::Environment(kind), 1000).unwrap();
            assert_eq!(full.error, None, "{architecture:?} {kind:?}: {full:#?}");
            for budget in [1, full.instruction_count - 1] {
                let partial =
                    run_api_fixture(architecture, ApiFixture::Environment(kind), budget).unwrap();
                assert_eq!(partial.completion_reason, "instruction_budget");
                assert_eq!(partial.error, None);
                assert_eq!(partial.guest_entry_return, None);
                if budget == 1 {
                    assert_eq!(
                        partial
                            .kernel_environment
                            .as_ref()
                            .unwrap()
                            .processor_number_writes,
                        0
                    );
                }
            }
        }
    }
}

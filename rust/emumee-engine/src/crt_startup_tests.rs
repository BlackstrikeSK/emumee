//! Submitted user callers inspect actual guest CRT structures and callback effects.
use super::*;
use emumee_core::{
    fixtures::{StartupFixture as F, crt_startup_probe},
    report_bundle::digest,
    user_input::{PROFILE, Request},
};
fn request(bytes: &[u8], kind: F, budget: u64) -> Request {
    Request {
        schema: 1,
        profile: PROFILE.into(),
        run_id: "20261029T170000Z-12345678".into(),
        input_sha256: digest(bytes),
        input_size: bytes.len() as u64,
        module_name: "sample.exe".into(),
        arguments: vec![
            if kind == F::Wildcard {
                "*.txt".into()
            } else {
                "two words".into()
            },
            "é😀".into(),
        ],
        max_instructions: budget,
        timeout_us: 30_000_000,
        persona_sha256: None,
        clock_utc_filetime: 134377488000000000,
        staged: vec![],
        invocation: Default::default(),
    }
}
fn run(arch: Architecture, kind: F, budget: u64) -> Execution {
    let bytes = crt_startup_probe(arch, kind);
    user::run(&request(&bytes, kind, budget), &bytes, None).unwrap()
}
#[test]
fn crt_startup_real_guest_arrays_snapshots_and_initializer_effects_match_both_abis() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in F::ALL.into_iter().filter(|k| k.positive()) {
            let bytes = crt_startup_probe(arch, kind);
            if let Ok(root) = std::env::var("EMUMEE_CRT_STARTUP_FIXTURES") {
                let root = std::path::PathBuf::from(root).join(format!("{arch:?}-{}", kind.name()));
                std::fs::create_dir_all(&root).unwrap();
                std::fs::write(root.join("sample.exe"), &bytes).unwrap();
            }
            let result = user::run(&request(&bytes, kind, 20000), &bytes, None).unwrap();
            assert_eq!(result.error, None, "{arch:?}/{kind:?}: {result:#?}");
            assert_eq!(
                result.completion_reason, "entry_return",
                "{arch:?}/{kind:?}"
            );
            assert_eq!(result.guest_entry_return, Some(1));
            assert!(result.api_events.iter().all(|e| !e.pending));
            let report = result.crt_startup.as_ref();
            if kind == F::InitializersEmpty {
                assert!(report.is_none());
                continue;
            }
            let report = report.unwrap();
            assert!(!report.initializer_pending);
            if matches!(
                kind,
                F::InitializersVoid
                    | F::InitializersError
                    | F::InitializersMutate
                    | F::InitializersFail
                    | F::InitializersReentrant
            ) {
                assert_eq!(
                    report.initializers.len(),
                    if kind == F::InitializersFail { 1 } else { 2 }
                );
                assert!(
                    report
                        .initializers
                        .iter()
                        .all(|e| e.stopped_instruction.is_some() && e.error.is_none())
                );
            } else {
                assert_eq!(report.argc, 3);
                assert!(report.owned_backing.iter().all(|b| b.size <= 1024 * 1024));
            }
        }
    }
}
#[test]
fn crt_startup_invalid_memory_mapping_ownership_and_callback_contracts_stop_explicitly() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in F::ALL
            .into_iter()
            .filter(|k| !k.positive() && *k != F::InitializersInfinite)
        {
            let bytes = crt_startup_probe(arch, kind);
            if let Ok(root) = std::env::var("EMUMEE_CRT_STARTUP_FIXTURES") {
                let root = std::path::PathBuf::from(root).join(format!("{arch:?}-{}", kind.name()));
                std::fs::create_dir_all(&root).unwrap();
                std::fs::write(root.join("sample.exe"), &bytes).unwrap();
            }
            let result = user::run(&request(&bytes, kind, 20000), &bytes, None).unwrap();
            assert!(result.error.is_some(), "{arch:?}/{kind:?}: {result:#?}");
            assert_eq!(result.completion_reason, "error");
            assert!(result.guest_entry_return.is_none());
            if matches!(
                kind,
                F::InitializersFault
                    | F::InitializersBadStack
                    | F::InitializersNonvolatile
                    | F::InitializersNx
            ) {
                let report = result.crt_startup.as_ref().unwrap();
                assert!(!report.initializer_pending && report.suspended_initializers == 0);
                assert_eq!(report.interrupted_initializers.len(), 1);
                assert!(
                    result
                        .api_events
                        .iter()
                        .any(|e| e.api.ends_with("._initterm_e")
                            && !e.pending
                            && e.result.is_none()
                            && e.effect == Some("crt_initializers_aborted")
                            && e.error.is_some())
                );
            }
        }
    }
}
#[test]
fn crt_startup_every_initializer_budget_prefix_retains_only_executed_effects() {
    for arch in [Architecture::X86, Architecture::X64] {
        let complete = run(arch, F::InitializersError, 20000);
        assert_eq!(complete.error, None);
        for budget in 1..complete.instruction_count {
            let result = run(arch, F::InitializersError, budget);
            assert_eq!(result.instruction_count, budget, "{arch:?}/{budget}");
            assert_eq!(
                result.completion_reason, "instruction_budget",
                "{arch:?}/{budget}: {result:#?}"
            );
            assert!(result.error.is_none());
            assert!(result.guest_entry_return.is_none());
        }
        let infinite = run(arch, F::InitializersInfinite, 100);
        assert_eq!(infinite.instruction_count, 100);
        assert_eq!(infinite.completion_reason, "instruction_budget");
        assert!(!infinite.crt_startup.as_ref().unwrap().initializer_pending);
        assert_eq!(
            infinite
                .crt_startup
                .as_ref()
                .unwrap()
                .interrupted_initializers
                .len(),
            1
        );
        assert_eq!(
            infinite.crt_startup.as_ref().unwrap().initializers[0].result,
            None
        );
    }
}
#[test]
fn crt_startup_msvcrt_and_ucrt_aliases_bind_only_the_intended_modules() {
    for arch in [Architecture::X86, Architecture::X64] {
        for module in [
            "ucrtbase.dll",
            "api-ms-win-crt-runtime-l1-1-0.dll",
            "api-ms-win-crt-private-l1-1-0.dll",
        ] {
            // Rebuild only the import-name storage in the owned fixture; the guest
            // instruction and pointer checks stay independent of the dispatcher.
            let mut bytes = crt_startup_probe(arch, F::ArgumentsWide);
            bytes[0x120c..0x1210].copy_from_slice(&0x2b00u32.to_le_bytes());
            bytes[0x1d00..0x1d80].fill(0);
            bytes[0x1d00..0x1d00 + module.len()].copy_from_slice(module.as_bytes());
            if module.contains("private") {
                for index in [3, 5, 13] {
                    let at = 0x1500 + index * 64 + 2;
                    let len = bytes[at..at + 62].iter().position(|b| *b == 0).unwrap();
                    let alias = [b"_o_".as_slice(), &bytes[at..at + len]].concat();
                    bytes[at..at + 62].fill(0);
                    bytes[at..at + alias.len()].copy_from_slice(&alias);
                }
            }
            let result =
                user::run(&request(&bytes, F::ArgumentsWide, 20000), &bytes, None).unwrap();
            assert_eq!(result.error, None, "{arch:?}/{module}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(1));
        }
        let mut bytes = crt_startup_probe(arch, F::ArgumentsWide);
        bytes[0x1220..0x1224].copy_from_slice(&0x2240u32.to_le_bytes());
        let refused = user::run(&request(&bytes, F::ArgumentsWide, 20000), &bytes, None).unwrap();
        assert!(
            refused
                .error
                .as_ref()
                .unwrap()
                .contains("Unsupported Windows API: ucrtbase.__wgetmainargs")
        );
        assert!(refused.guest_entry_return.is_none());
    }
}

#[test]
fn crt_startup_msvcrt_x86_globals_share_legacy_args_without_sharing_ucrt_state() {
    let mut bytes = crt_startup_probe(Architecture::X86, F::ArgumentsWide);
    // All accessor calls in this control resolve to the real legacy runtime.
    bytes[0x120c..0x1210].copy_from_slice(&0x2260u32.to_le_bytes());
    // This control does not call UCRT-only _configure_wide_argv. Its initial
    // CDECL call/cleanup plus result assertion occupy exactly22 fixture bytes.
    assert_eq!(&bytes[0x200..0x205], &[0x68, 1, 0, 0, 0]);
    assert_eq!(&bytes[0x20b..0x20e], &[0x83, 0xc4, 4]);
    assert_eq!(&bytes[0x213..0x216], &[0x74, 1, 0xcc]);
    bytes[0x200..0x216].fill(0x90);
    let comparison = [0x3b, 0x05, 0x08, 0x2d, 0x40, 0x00, 0x75, 1, 0xcc];
    let at = bytes
        .windows(comparison.len())
        .position(|w| w == comparison)
        .unwrap();
    bytes[at + 6] = 0x74; // Accessors and mainargs now belong to the same MSVCRT instance.
    let r = request(&bytes, F::ArgumentsWide, 20000);
    let result = user::run(&r, &bytes, None).unwrap();
    assert_eq!(result.error, None, "{result:#?}");
    assert_eq!(result.guest_entry_return, Some(1));
    let report = result.crt_startup.unwrap();
    assert!(report.argument_globals.is_none());
    assert!(report.msvcrt_argument_globals.is_some());
    assert!(report.argument_arrays.iter().all(Option::is_none));
    assert!(report.msvcrt_argument_arrays.iter().all(Option::is_some));
    if let Ok(root) = std::env::var("EMUMEE_CRT_STARTUP_FIXTURES") {
        let root = std::path::PathBuf::from(root).join("X86-legacy-arguments");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("sample.exe"), bytes).unwrap();
    }
}

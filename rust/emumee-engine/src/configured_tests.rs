use super::*;
use emumee_core::{
    fixtures::{ApiFixture, ConfiguredFixture as F, configured_document},
    fullpersona::{ResolveContext, decode},
    persona::ProcessConfig,
};
use sha2::{Digest, Sha256};
fn user_process() -> ProcessConfig {
    ProcessConfig {
        image_path: r"C:\Users\Morgan\Downloads\configured-probe.exe".into(),
        arguments: vec!["two words".into()],
        force_quotes: vec![],
        command_line: None,
        current_directory: None,
        environment_overrides: vec![("TOKEN".into(), Some("é".into()))],
    }
}
fn prepared(arch: Architecture, kind: F) -> configured::Prepared {
    configured::Prepared::new(
        decode(&configured_document(kind), &ResolveContext::default()).unwrap(),
        configured::Request {
            architecture: arch,
            kernel: kind.kernel(),
            initial_processor: 0,
            process: (!kind.kernel()).then(user_process),
            budget: 20000,
            timeout_us: 30_000_000,
        },
    )
    .unwrap()
}
#[test]
fn configured_programs_observe_actual_identity_invocation_seed_bytes_clock_machine_and_ipi() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::User, F::Empty, F::Kernel, F::Ipi] {
            for unicode in if kind.kernel() {
                vec![false]
            } else {
                vec![false, true]
            } {
                let result =
                    run_api_fixture(arch, ApiFixture::Configured(kind, unicode), 20000).unwrap();
                assert_eq!(
                    result.error, None,
                    "{arch:?} {kind:?}/{unicode}: {result:#?}"
                );
                assert_eq!(
                    result.guest_entry_return,
                    Some(kind.expected_return()),
                    "{arch:?} {kind:?}/{unicode}: actual configured root return"
                );
                let receipt = result.configuration.as_ref().unwrap();
                assert!(receipt.generated_only && receipt.initialized);
                assert_eq!(receipt.windows_build, 26100);
                assert_eq!(receipt.physical_memory_mb, 8192);
                assert_eq!(receipt.available_memory_mb, 4096);
                assert!(receipt.pending.len() >= 42);
                assert_eq!(receipt.initial_processor, 0);
                let reference =
                    decode(&configured_document(kind), &ResolveContext::default()).unwrap();
                assert!(!reference.projection().data.engine_applied);
                assert_eq!(
                    receipt.input_json_sha256,
                    format!("{:x}", Sha256::digest(configured_document(kind)))
                );
                assert_eq!(receipt.effective_sha256, reference.sha256());
                assert_eq!(receipt.projection_sha256, reference.projection().sha256);
                assert_eq!(
                    receipt.seed_manifest_sha256,
                    reference.seed_manifest().sha256()
                );
                assert_eq!(receipt.seeded_files, usize::from(!matches!(kind, F::Empty)));
                assert_eq!(
                    receipt.seeded_registry_keys,
                    usize::from(!matches!(kind, F::Empty))
                );
                assert!(
                    result.artifacts.is_empty(),
                    "unchanged configured inputs cannot be execution artifacts"
                );
                assert_eq!(result.network.calls, 0);
                assert_eq!(
                    receipt.user_process_owner,
                    if kind.kernel() { None } else { Some(1024) }
                );
                if kind.kernel() {
                    let identity = result
                        .kernel_environment
                        .as_ref()
                        .unwrap()
                        .identity
                        .as_ref()
                        .unwrap();
                    assert_eq!(identity.windows_build, 26100);
                    assert_eq!(identity.current_processor, 0);
                    assert_eq!(
                        identity.logical_processors,
                        if matches!(kind, F::Ipi) { 4 } else { 6 }
                    );
                } else {
                    let blocks = result.environment_blocks.as_ref().unwrap();
                    assert_eq!(blocks.lifetime_allocations, 1);
                    assert_eq!(blocks.mapped_bytes, 0);
                    assert!(blocks.live.is_empty());
                    assert_eq!(blocks.events.len(), 2);
                    assert_eq!(blocks.events[0].operation, "allocated");
                    assert_eq!(blocks.events[1].operation, "freed");
                    assert_eq!(result.file_storage.as_ref().unwrap().open_handles, 0);
                    assert_eq!(
                        receipt.guest_image_path.as_deref(),
                        Some(r"C:\Users\Morgan\Downloads\configured-probe.exe")
                    );
                }
                if matches!(kind, F::Ipi) {
                    let ipi = result.kernel_ipi.as_ref().unwrap();
                    assert_eq!(ipi.current_processor, 0);
                    assert_eq!(ipi.rendezvous.broadcasts.len(), 1);
                    let b = &ipi.rendezvous.broadcasts[0];
                    assert!(b.completed);
                    assert_eq!(b.members.len(), 4);
                    assert!(
                        b.members
                            .iter()
                            .all(|m| m.started && m.instruction_count > 0 && m.result.is_some())
                    );
                }
            }
        }
    }
}
#[test]
fn configured_initialization_is_not_a_fabricated_entry_return_under_budget_prefixes() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::User, F::Empty, F::Kernel, F::Ipi] {
            for unicode in if kind.kernel() {
                vec![false]
            } else {
                vec![false, true]
            } {
                let full =
                    run_api_fixture(arch, ApiFixture::Configured(kind, unicode), 20000).unwrap();
                assert!(full.guest_entry_return.is_some(), "{:?}", full.error);
                let budget = full.instruction_count - 1;
                let prefix =
                    run_api_fixture(arch, ApiFixture::Configured(kind, unicode), budget).unwrap();
                assert_eq!(prefix.completion_reason, "instruction_budget");
                assert_eq!(prefix.guest_entry_return, None);
                assert_eq!(prefix.error, None);
                assert_eq!(prefix.instruction_count, budget);
                assert!(prefix.configuration.unwrap().initialized);
            }
        }
    }
}
#[test]
fn candidate_failures_are_pure_and_cannot_publish_fixture_or_incoherent_process_state() {
    let old = Trace::new(Architecture::X64);
    assert_eq!(old.apis.files.current_directory(), r"C:\workspace");
    for arch in [Architecture::X86, Architecture::X64] {
        let mut request = configured::Request {
            architecture: arch,
            kernel: false,
            initial_processor: 0,
            process: Some(user_process()),
            budget: 1000,
            timeout_us: 1000,
        };
        request.process.as_mut().unwrap().current_directory = Some(r"C:\does-not-exist".into());
        assert!(
            configured::Prepared::new(
                decode(&configured_document(F::User), &ResolveContext::default()).unwrap(),
                request
            )
            .is_err()
        );
        let request = configured::Request {
            architecture: arch,
            kernel: true,
            initial_processor: 1,
            process: None,
            budget: 1000,
            timeout_us: 1000,
        };
        assert!(
            configured::Prepared::new(
                decode(&configured_document(F::Kernel), &ResolveContext::default()).unwrap(),
                request
            )
            .is_err()
        );
        let request = configured::Request {
            architecture: arch,
            kernel: true,
            initial_processor: 0,
            process: Some(user_process()),
            budget: 1000,
            timeout_us: 1000,
        };
        assert!(
            configured::Prepared::new(
                decode(&configured_document(F::Kernel), &ResolveContext::default()).unwrap(),
                request
            )
            .is_err()
        );
        let mut document: serde_json::Value =
            serde_json::from_slice(&configured_document(F::User)).unwrap();
        document["uptime_ms"] = serde_json::json!(u64::MAX / 10_000);
        let candidate = decode(
            &serde_json::to_vec(&document).unwrap(),
            &ResolveContext::default(),
        )
        .unwrap();
        assert!(
            configured::Prepared::new(
                candidate,
                configured::Request {
                    architecture: arch,
                    kernel: false,
                    initial_processor: 0,
                    process: Some(user_process()),
                    budget: 1000,
                    timeout_us: 30_000_000
                }
            )
            .is_err()
        );
        let trace = prepared(arch, F::User).into_trace().unwrap();
        assert!(trace.apis.files.metadata(r"C:\workspace").is_err());
        assert!(
            !trace
                .apis
                .files
                .exists(r"C:\Users\Morgan\Downloads\configured-probe.exe")
                .unwrap()
        );
        assert_eq!(
            trace
                .apis
                .persona
                .model
                .environment(1024)
                .unwrap()
                .get("TOKEN")
                .unwrap(),
            Some("é")
        );
        assert!(
            trace
                .apis
                .persona
                .model
                .environment_block(1024, emumee_core::persona::Encoding::Cp437)
                .unwrap()
                .windows(8)
                .any(|v| v == b"TOKEN=\x82\0")
        );
        assert_eq!(trace.apis.files.storage_report().open_handles, 0);
        assert!(configured::require_unpublished(&trace).is_ok());
    }
    assert_eq!(old.apis.files.current_directory(), r"C:\workspace");
    assert_eq!(old.cpu.profile.base_mhz, 2900);
    assert!(old.machine.receipt().is_none());
}
#[test]
fn native_failure_and_late_publication_guards_preserve_unpublished_receipt_and_exact_machine_values()
 {
    for arch in [Architecture::X86, Architecture::X64] {
        let mut engine =
            new_engine_with_trace(prepared(arch, F::Kernel).into_trace().unwrap()).unwrap();
        engine.get_data_mut().apis.target(arch, true).unwrap();
        // A real native collision causes shared-page initialization to fail.
        // The generated runner propagates this error before hooks/execute.
        uc(engine.mem_map(0x7ffe0000, 4096, Prot::READ)).unwrap();
        assert!(time::initialize(&mut engine).is_err());
        assert_eq!(engine.get_data().instructions, 0);
        assert!(!engine.get_data().machine.receipt().unwrap().initialized);
        assert!(configured::require_unpublished(engine.get_data()).is_err());
        drop(engine);
        let mut engine =
            new_engine_with_trace(prepared(arch, F::Kernel).into_trace().unwrap()).unwrap();
        engine.get_data_mut().apis.target(arch, true).unwrap();
        time::initialize(&mut engine).unwrap();
        configured::initialized(&mut engine).unwrap();
        let before = engine.get_data().machine.receipt().unwrap();
        assert!(configured::initialized(&mut engine).is_err());
        let after = engine.get_data().machine.receipt().unwrap();
        assert_eq!(before.seed_manifest_sha256, after.seed_manifest_sha256);
        assert!(after.initialized);
        assert!(configured::require_unpublished(engine.get_data()).is_err());
        let page = time::page(&engine);
        assert_eq!(
            u32::from_le_bytes(page[0x260..0x264].try_into().unwrap()),
            26100
        );
        assert_eq!(
            u32::from_le_bytes(page[0x2e8..0x2ec].try_into().unwrap()),
            8192 * 256
        );
    }
}
#[test]
fn seed_capture_distinguishes_unchanged_input_and_real_changed_or_new_file_bytes() {
    let trace = prepared(Architecture::X64, F::User).into_trace().unwrap();
    assert!(
        !trace
            .machine
            .capture_file(r"c:\users\morgan\downloads\mixed.bin", &[1, 2, 3, 4])
    );
    assert!(
        trace
            .machine
            .capture_file(r"c:\users\morgan\downloads\mixed.bin", &[1, 2, 3, 5])
    );
    assert!(trace.machine.capture_file(r"c:\new.bin", &[1, 2, 3, 4]));
    let fixture = Trace::new(Architecture::X64);
    assert!(
        fixture
            .machine
            .capture_file(r"c:\workspace\new.bin", &[1, 2, 3, 4])
    );
}

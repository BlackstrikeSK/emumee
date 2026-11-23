use super::*;
use emumee_core::{
    fixtures::{CrtRuntimeFixture as F, crt_runtime_probe},
    report_bundle::digest,
    user_input::{PROFILE, Request},
};

fn run(arch: Architecture, kind: F) -> Execution {
    let bytes = crt_runtime_probe(arch, kind);
    // Validate fixture structure before entering any native engine.
    PeImage::parse(&bytes, "sample.exe").unwrap();
    let request = Request {
        schema: 1,
        profile: PROFILE.into(),
        run_id: "20261119T170000Z-12345678".into(),
        input_sha256: digest(&bytes),
        input_size: bytes.len() as u64,
        module_name: "sample.exe".into(),
        arguments: vec![],
        max_instructions: 40000,
        timeout_us: 30_000_000,
        persona_sha256: None,
        clock_utc_filetime: 134377488000000000,
        staged: vec![],
        invocation: Default::default(),
        capture: None,
    };
    let label = format!("{arch:?}-m5-crt-runtime-{kind:?}");
    crate::user_test_fixtures::fixture(&label, &request, &bytes, &[], None);
    let result = user::run(&request, &bytes, None).unwrap();
    crate::user_test_fixtures::execution(&label, &result);
    result
}

#[test]
fn m5_crt_global_cells_are_stable_mutable_and_shared_with_their_setters() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = run(arch, F::Globals);
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1));
        assert!(result.api_events.iter().all(|e| !e.pending));
        let report = result.crt_startup.unwrap();
        assert!(report.commode.is_some_and(|cell| cell % 4096 == 0));
        assert!(report.file_mode.is_some());
        assert!(report.initial_environment_pointer.is_some());
        assert_eq!(report.application_type, None);
        assert_eq!(report.thread_locale_mode, 2);
        assert!(report.held_locks.is_empty());
    }
}

#[test]
fn m5_registered_exit_functions_run_in_reverse_order_before_the_process_exits() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = run(arch, F::Atexit);
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        assert_eq!(result.process_exit_code, Some(7));
        assert_eq!(result.completion_reason, "process_exit");
        assert!(result.api_events.iter().all(|e| !e.pending));
        let report = result.crt_startup.unwrap();
        // All four registrations ran; the thread-local callback did not.
        assert_eq!(report.registered_exit_functions, 0);
        assert_eq!(report.thread_local_exit_callbacks.len(), 1);
        assert_eq!(report.requested_exit_code, Some(7));
        let targets: Vec<u64> = report.initializers.iter().map(|e| e.target).collect();
        assert_eq!(targets.len(), 4);
        assert!(
            targets.windows(2).all(|pair| pair[0] > pair[1]),
            "{targets:?} must run in reverse registration order"
        );
        assert!(report.initializers.iter().all(|e| e.error.is_none()));
    }
}

#[test]
fn m5_crt_exit_family_terminates_with_the_documented_code() {
    for arch in [Architecture::X86, Architecture::X64] {
        for (kind, code, handlers) in [
            (F::ExitImmediate, 5, 0),
            (F::CleanExit, 0, 1),
            (F::Terminate, 3, 0),
        ] {
            let result = run(arch, kind);
            assert_eq!(result.error, None, "{arch:?}/{kind:?}: {result:#?}");
            assert_eq!(result.process_exit_code, Some(code), "{arch:?}/{kind:?}");
            let report = result.crt_startup.unwrap();
            assert_eq!(report.initializers.len(), handlers, "{arch:?}/{kind:?}");
        }
    }
}

#[test]
fn m5_crt_runtime_refuses_unbalanced_locks_reentrant_exit_and_unmodeled_modes() {
    for arch in [Architecture::X86, Architecture::X64] {
        for (kind, message) in [
            (F::UnbalancedUnlock, "released without being acquired"),
            (F::ExitReentrant, "exit reentrancy"),
            (F::NewMode, "new-handler allocation mode"),
            (F::ThreadLocale, "Per-thread CRT locales"),
            (F::AppType, "application type"),
        ] {
            let result = run(arch, kind);
            assert_eq!(result.completion_reason, "error", "{arch:?}/{kind:?}");
            assert!(
                result.error.as_deref().unwrap().contains(message),
                "{arch:?}/{kind:?}: {:?}",
                result.error
            );
        }
    }
}

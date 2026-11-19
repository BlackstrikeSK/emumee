use super::*;
use emumee_core::{
    fixtures::{CrtServiceFixture as F, crt_service_probe},
    report_bundle::digest,
    user_input::{PROFILE, Request},
};

fn run(arch: Architecture, kind: F) -> Execution {
    execute(arch, kind, true)
}
/// Controls whose results follow the run's own persona clock cannot be replayed
/// byte for byte in containment, so they stay source-only and emit no fixture.
fn run_source_only(arch: Architecture, kind: F) -> Execution {
    execute(arch, kind, false)
}
fn execute(arch: Architecture, kind: F, contained: bool) -> Execution {
    let bytes = crt_service_probe(arch, kind);
    // Validate fixture structure before entering any native engine.
    PeImage::parse(&bytes, "sample.exe").unwrap();
    let request = Request {
        schema: 1,
        profile: PROFILE.into(),
        run_id: "20261119T200000Z-12345678".into(),
        input_sha256: digest(&bytes),
        input_size: bytes.len() as u64,
        module_name: "sample.exe".into(),
        arguments: vec![],
        max_instructions: 60000,
        timeout_us: 30_000_000,
        persona_sha256: None,
        clock_utc_filetime: 134377488000000000,
        staged: vec![],
        invocation: Default::default(),
    };
    let label = format!("{arch:?}-m5-crt-service-{kind:?}");
    if contained {
        crate::user_test_fixtures::fixture(&label, &request, &bytes, &[], None);
    }
    let result = user::run(&request, &bytes, None).unwrap();
    if contained {
        crate::user_test_fixtures::execution(&label, &result);
    }
    result
}

#[test]
fn m5_narrow_formatting_and_scanning_write_only_checked_guest_memory() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::Format, F::Scan] {
            let result = run(arch, kind);
            assert_eq!(result.error, None, "{arch:?}/{kind:?}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(1));
            assert!(result.api_events.iter().all(|e| !e.pending));
        }
    }
}

#[test]
fn m5_crt_runtime_services_derive_from_modeled_state_and_the_persona_clock() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = run(arch, F::Services);
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1));
        let report = result.crt_runtime.unwrap();
        assert!(report.random_seed.is_some());
        assert_eq!(report.signal_handlers, vec![(2, 1)]);
        assert_eq!(report.refused_commands.len(), 1);
        assert!(report.refused_commands[0].starts_with("cmd.exe"));
        assert_eq!(
            report.floating_control,
            Some(if arch == Architecture::X86 {
                0x9001f
            } else {
                0x8001f
            })
        );
    }
}

#[test]
fn m5_crt_epoch_seconds_follow_the_persona_clock() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = run_source_only(arch, F::EpochTime);
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1));
    }
}

#[test]
fn m5_crt_refuses_exception_dispatch_x87_conversion_and_control_changes() {
    for arch in [Architecture::X86, Architecture::X64] {
        for (kind, message) in [
            (F::ThrowUnsupported, "C++ exception dispatch is not modeled"),
            (F::FloatUnsupported, "x87 stack floating-point conversion"),
            (
                F::ControlUnsupported,
                "Changing the CRT floating-point control word",
            ),
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

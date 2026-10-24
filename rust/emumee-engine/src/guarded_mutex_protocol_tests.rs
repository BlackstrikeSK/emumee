use super::*;
use emumee_core::fixtures::{ApiFixture, ConfiguredFixture, api_probe, configured_document};

fn run(build: u32, fixture: ApiFixture) -> Execution {
    let mut persona: serde_json::Value =
        serde_json::from_slice(&configured_document(ConfiguredFixture::Kernel)).unwrap();
    persona["windows_build"] = build.into();
    let validated = emumee_core::fullpersona::decode(
        &serde_json::to_vec(&persona).unwrap(),
        &emumee_core::fullpersona::ResolveContext::default(),
    )
    .unwrap();
    let prepared = configured::Prepared::new(
        validated,
        configured::Request {
            architecture: Architecture::X64,
            kernel: true,
            initial_processor: 0,
            process: None,
            budget: 10000,
            timeout_us: 30_000_000,
        },
    )
    .unwrap();
    run_generated_with_fixture_configuration(
        &api_probe(Architecture::X64, fixture),
        &[],
        10000,
        30_000_000,
        GeneratedConfiguration {
            configured: Some(prepared),
            capture: Some(capture::Prepared::submitted()),
            ..Default::default()
        },
    )
    .unwrap()
}

#[test]
fn guarded_mutex_count_protocol_preserves_real_owner_handoff_for_each_target() {
    for (build, blocked_count, label) in [
        (22631, -1, "legacy-signed-waiters-v1"),
        (26200, 4, "windows26200-x64-fast-mutex-stable-v1"),
    ] {
        let execution = run(build, ApiFixture::MutexHandoff);
        assert_eq!(
            execution.completion_reason, "entry_return",
            "{:?}",
            execution.error
        );
        assert_eq!(execution.guest_entry_return, Some(1));
        let kernel = execution.kernel_state.as_ref().unwrap();
        assert_eq!(kernel.guarded_mutex_count_protocol, label);
        let blocked = kernel
            .guarded_mutex_trace
            .iter()
            .find(|row| row.operation == "blocked")
            .unwrap();
        assert_eq!(blocked.guest_count, Some(blocked_count));
        assert_ne!(blocked.guest_owner, Some(0));
        assert!(kernel.guarded_mutex_trace.iter().any(
            |row| row.operation == "release_attempt" && row.guest_count == Some(blocked_count)
        ));
        let threads = execution.kernel_threads.as_ref().unwrap();
        assert_eq!(threads.waits, 1);
        assert_eq!(threads.resumed_waits, 1);
        assert_eq!(kernel.owned_mutexes, 0);
        assert_eq!(kernel.irql, 0);
        if build == 26200 {
            let capture = execution.capture_runtime.as_ref().unwrap();
            let image = execution
                .artifacts
                .iter()
                .find(|item| Some(item.sha256.as_str()) == capture.post_image_sha256.as_deref())
                .unwrap();
            assert_eq!(&image.data[0x2b10..0x2b14], &1u32.to_le_bytes());
            assert_eq!(&image.data[0x2b00..0x2b04], &1u32.to_le_bytes());
        }
    }
}

#[test]
fn guarded_mutex_build26200_does_not_grant_ownerless_zero_object() {
    let execution = run(26200, ApiFixture::GuardedBusy);
    assert_eq!(execution.completion_reason, "error");
    assert!(
        execution
            .error
            .as_ref()
            .unwrap()
            .contains("guarded mutex"),
        "{:?}", execution.error
    );
    assert_eq!(execution.guest_entry_return, None);
    let kernel = execution.kernel_state.unwrap();
    assert!(
        kernel
            .guarded_mutex_trace
            .iter()
            .any(|row| row.operation == "acquire_attempt"
                && row.guest_count == Some(0)
                && row.guest_owner == Some(0))
    );
    assert!(
        !kernel
            .guarded_mutex_trace
            .iter()
            .any(|row| row.operation == "acquired")
    );
}

#[test]
fn guarded_mutex_count_protocol_bounds_and_architecture_are_explicit() {
    use threads::GuardedMutexCountProtocol as P;
    assert_eq!(
        P::for_target(Architecture::X86, 26200).label(),
        "legacy-signed-waiters-v1"
    );
    assert_eq!(P::Windows26200X64.for_waiters(2).unwrap(), 8);
    assert_eq!(P::Windows26200X64.blocked_count(8).unwrap(), 12);
    assert!(!P::Windows26200X64.owned_count(3));
    assert!(P::Windows26200X64.blocked_count(3).is_err());
    assert!(P::Windows26200X64.for_waiters(i32::MAX as usize).is_err());
    assert!(P::LegacySigned.blocked_count(i32::MIN).is_err());
}

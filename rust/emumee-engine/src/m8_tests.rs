//! M8 guest controls for the submitted-sample capture obligations.
//!
//! Unlike the API-family controls, an M8 control's outcome is decided by the
//! request's capture configuration, not the guest: the control embeds indicator
//! strings (or, later, drops an executable payload) in its own image and returns
//! 1, and the submitted-sample capture the request configures recovers them.
//! Every control is emitted as a contained fixture so the packaged worker
//! replays the same bytes — and the same capture configuration — through the
//! public CLI.
use super::*;
use crate::m6_tests::CLOCK;
use crate::user_test_fixtures as emit;
use emumee_core::{
    fixtures,
    memory_strings::Format,
    report_bundle::digest,
    user_input::{CaptureRequest, MemoryStringRequest, Request, PROFILE},
    user_memory_observation,
};

const SCAN_BYTES: u64 = 128 * 1024 * 1024;

/// Run one M8 control with its capture configuration and emit the contained
/// fixture plus its source-tested outcome.
fn run(label: &str, bytes: Vec<u8>, capture: CaptureRequest, budget: u64) -> Execution {
    PeImage::parse(&bytes, "sample.exe").unwrap();
    let request = Request {
        schema: 2,
        profile: PROFILE.into(),
        run_id: "20261123T120000Z-12345678".into(),
        input_sha256: digest(&bytes),
        input_size: bytes.len() as u64,
        module_name: "sample.exe".into(),
        arguments: vec![],
        max_instructions: budget,
        timeout_us: 30_000_000,
        persona_sha256: None,
        clock_utc_filetime: CLOCK,
        staged: vec![],
        invocation: Default::default(),
        capture: Some(capture),
    };
    emit::fixture(label, &request, &bytes, &[], None);
    let result = user::run_staged(&request, &bytes, None, &[]).unwrap();
    emit::execution(label, &result);
    result
}

#[test]
fn memory_string_controls_recover_builtin_and_custom_indicators() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for custom in [false, true] {
            let label = format!(
                "{architecture:?}-m8-strings-{}",
                if custom { "Custom" } else { "Builtin" }
            );
            let bytes = fixtures::memory_string_probe(architecture, custom);
            let patterns = if custom {
                vec!["[a-f0-9]{32}".to_string()]
            } else {
                vec![]
            };
            let capture = CaptureRequest {
                memory_strings: Some(MemoryStringRequest {
                    enabled: true,
                    patterns,
                    scan_bytes: SCAN_BYTES,
                }),
                carve_executable_regions: false,
            };
            let result = run(&label, bytes, capture, 2000);
            assert_eq!(result.guest_entry_return, Some(1), "{label}");
            assert_eq!(result.completion_reason, "entry_return", "{label}");
            assert_eq!(result.error, None, "{label}: {result:#?}");
            let json = serde_json::to_value(&result).unwrap();
            assert!(
                user_memory_observation::valid_execution(&json),
                "{label}: {json:#}"
            );
            let report = result.user_memory_strings.as_ref().unwrap();
            let has = |format: Format, value: &str| {
                report
                    .matches()
                    .iter()
                    .any(|m| m.format == format && m.value == value)
            };
            assert!(has(Format::Ipv4, "203.0.113.1"), "{label}: missing IPv4");
            assert!(
                has(Format::Url, "http://indicator.test/payload"),
                "{label}: missing URL"
            );
            if custom {
                assert!(
                    has(Format::Custom(1), "d41d8cd98f00b204e9800998ecf8427e"),
                    "{label}: missing custom digest"
                );
            } else {
                // With no custom patterns configured, the regex array is empty
                // and no custom match is reported.
                assert!(report.matches().iter().all(|m| !matches!(m.format, Format::Custom(_))));
            }
        }
    }
}

#[test]
fn executable_region_control_carves_a_shellcode_artifact_with_attribution() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let label = format!("{architecture:?}-m8-carve-Shellcode");
        let bytes = fixtures::executable_region_probe(architecture);
        let capture = CaptureRequest {
            memory_strings: None,
            carve_executable_regions: true,
        };
        let result = run(&label, bytes, capture, 4000);
        assert_eq!(
            (result.error.as_deref(), result.completion_reason),
            (None, "entry_return"),
            "{label}: {:#?} / events {:#?}",
            result.error,
            result.api_events
        );
        assert_eq!(result.guest_entry_return, Some(1), "{label}");
        // The transition into executable protection retained the staged payload
        // as a distinct shellcode region, not a generic memory snapshot.
        let observations: Vec<_> = result
            .artifacts
            .iter()
            .flat_map(|artifact| artifact.observations.iter())
            .filter(|observation| {
                observation.kind == emumee_core::artifacts::ArtifactKind::ExecutableRegion
            })
            .collect();
        assert_eq!(observations.len(), 1, "{label}: {:#?}", result.artifacts);
        let context = observations[0].context.as_ref().unwrap();
        assert_eq!(context["executable"], serde_json::json!(true), "{label}");
        assert_eq!(
            context["transition"],
            serde_json::json!("virtual_protect_executable"),
            "{label}"
        );
        assert_eq!(
            context["region_bytes"],
            serde_json::json!(0x1000),
            "{label}"
        );
        // The retained bytes are the staged payload inside the protected page.
        let carved = result
            .artifacts
            .iter()
            .find(|artifact| {
                artifact
                    .observations
                    .iter()
                    .any(|o| o.kind == emumee_core::artifacts::ArtifactKind::ExecutableRegion)
            })
            .unwrap();
        let payload = fixtures::executable_payload();
        assert!(
            carved.data.windows(payload.len()).any(|w| w == payload),
            "{label}: staged payload absent from the carved region"
        );
    }
}

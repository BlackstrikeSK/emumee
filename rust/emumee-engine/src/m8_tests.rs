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
    run_with_staged(label, bytes, &[], capture, budget)
}

/// As `run`, with guest input files staged into the sample's virtual filesystem.
fn run_with_staged(
    label: &str,
    bytes: Vec<u8>,
    staged: &[(emumee_core::user_input::InputKind, &str, Vec<u8>)],
    capture: CaptureRequest,
    budget: u64,
) -> Execution {
    PeImage::parse(&bytes, "sample.exe").unwrap();
    let files: Vec<emumee_core::user_input::StagedFile> = staged
        .iter()
        .map(|(kind, path, data)| emumee_core::user_input::StagedFile {
            kind: *kind,
            guest_path: (*path).into(),
            size: data.len() as u64,
            sha256: digest(data),
        })
        .collect();
    let contents: Vec<Vec<u8>> = staged.iter().map(|(_, _, data)| data.clone()).collect();
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
        staged: files,
        invocation: Default::default(),
        capture: Some(capture),
        output: None,
    };
    emit::fixture(label, &request, &bytes, &contents, None);
    let result = user::run_staged(&request, &bytes, None, &contents).unwrap();
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
fn private_mapping_control_recovers_an_indicator_only_the_live_scan_reaches() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let label = format!("{architecture:?}-m8-strings-Private");
        let bytes = fixtures::private_mapping_probe(architecture);
        let capture = CaptureRequest {
            memory_strings: Some(MemoryStringRequest {
                enabled: true,
                patterns: vec![],
                scan_bytes: SCAN_BYTES,
            }),
            carve_executable_regions: false,
        };
        let result = run(&label, bytes, capture, 4000);
        assert_eq!(
            (result.error.as_deref(), result.completion_reason),
            (None, "entry_return"),
            "{label}: {:#?}",
            result.error
        );
        assert_eq!(result.guest_entry_return, Some(1), "{label}");
        let json = serde_json::to_value(&result).unwrap();
        assert!(
            user_memory_observation::valid_execution(&json),
            "{label}: {json:#}"
        );
        let receipt = result.user_memory_capture.as_ref().unwrap();
        // The live private reservation the guest committed was scanned.
        assert!(receipt.private_runs >= 1, "{label}: no private run scanned");
        assert!(receipt.private_bytes > 0, "{label}");
        assert!(receipt.selected_bytes > receipt.private_bytes, "{label}");
        // The same indicator is recovered from the image and, separately, from
        // the live private run; only the second proves the live scan ran.
        let report = result.user_memory_strings.as_ref().unwrap();
        let private: Vec<_> = report
            .matches()
            .iter()
            .filter(|m| m.source.starts_with("guest_private_at_stop:"))
            .collect();
        assert!(
            private.iter().any(|m| m.value == "198.51.100.7"),
            "{label}: private IPv4 absent from {:#?}",
            report.matches()
        );
        assert!(
            private.iter().any(|m| m.value == "http://private.test/stage"),
            "{label}: private URL absent"
        );
        assert!(
            report
                .matches()
                .iter()
                .any(|m| m.source == "guest_image_at_stop" && m.value == "198.51.100.7"),
            "{label}: image-sourced copy absent"
        );
    }
}

#[test]
fn dropped_pe_control_carves_structural_evidence_out_of_the_drop() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let label = format!("{architecture:?}-m8-carve-DroppedPe");
        let bytes = fixtures::dropped_pe_probe(architecture);
        let payload = fixtures::counted_driver(Architecture::X64, 1);
        let staged = [(
            emumee_core::user_input::InputKind::File,
            fixtures::DROP_SOURCE,
            payload.clone(),
        )];
        let capture = CaptureRequest {
            memory_strings: None,
            carve_executable_regions: true,
        };
        let result = run_with_staged(&label, bytes, &staged, capture, 4000);
        assert_eq!(
            (result.error.as_deref(), result.completion_reason),
            (None, "entry_return"),
            "{label}: {:#?}",
            result.error
        );
        assert_eq!(result.guest_entry_return, Some(1), "{label}");
        // The drop is retained as a guest file *and* carved as structural image
        // evidence attributed to the path it was dropped at.
        let carved: Vec<_> = result
            .artifacts
            .iter()
            .flat_map(|artifact| artifact.observations.iter())
            .filter(|observation| {
                observation.kind == emumee_core::artifacts::ArtifactKind::CarvedImage
                    && observation.context.as_ref().is_some_and(|context| {
                        // The virtual filesystem normalizes a guest path's case.
                        context
                            .get("dropped_guest_path")
                            .and_then(|value| value.as_str())
                            .is_some_and(|path| {
                                path.eq_ignore_ascii_case(fixtures::DROP_DESTINATION)
                            })
                    })
            })
            .collect();
        let summary: Vec<String> = result
            .artifacts
            .iter()
            .flat_map(|artifact| {
                artifact.observations.iter().map(move |o| {
                    format!(
                        "{:?} path={:?} size={} ctx={:?}",
                        o.kind,
                        o.guest_path,
                        artifact.size,
                        o.context.as_ref().map(|c| c.keys().collect::<Vec<_>>())
                    )
                })
            })
            .collect();
        assert!(
            !carved.is_empty(),
            "{label}: no carved image for the drop: {summary:#?}"
        );
        assert!(
            result.artifacts.iter().any(|artifact| artifact
                .observations
                .iter()
                .any(|o| o.kind == emumee_core::artifacts::ArtifactKind::GuestFile
                    && o.guest_path.eq_ignore_ascii_case(fixtures::DROP_DESTINATION))),
            "{label}: dropped file itself not retained"
        );
    }
}

#[test]
fn released_payload_control_carves_the_payload_before_free_loses_it() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let label = format!("{architecture:?}-m8-carve-Released");
        let bytes = fixtures::released_payload_probe(architecture);
        let capture = CaptureRequest {
            memory_strings: None,
            carve_executable_regions: true,
        };
        let result = run(&label, bytes, capture, 4000);
        assert_eq!(
            (result.error.as_deref(), result.completion_reason),
            (None, "entry_return"),
            "{label}: {:#?}",
            result.error
        );
        assert_eq!(result.guest_entry_return, Some(1), "{label}");
        // The reservation was already executable, so no protection transition
        // fired: only the release carve can account for this artifact.
        let released: Vec<_> = result
            .artifacts
            .iter()
            .flat_map(|artifact| artifact.observations.iter())
            .filter(|observation| {
                observation.context.as_ref().is_some_and(|context| {
                    context["transition"] == serde_json::json!("released_before_free")
                })
            })
            .collect();
        assert_eq!(released.len(), 1, "{label}: {:#?}", result.artifacts);
        assert_eq!(
            released[0].kind,
            emumee_core::artifacts::ArtifactKind::ExecutableRegion,
            "{label}"
        );
        assert!(
            result.artifacts.iter().all(|artifact| artifact
                .observations
                .iter()
                .all(|o| o.context.as_ref().is_none_or(|c| c["transition"]
                    != serde_json::json!("virtual_protect_executable")))),
            "{label}: an unexpected protection transition fired"
        );
        let payload = fixtures::executable_payload();
        assert!(
            result
                .artifacts
                .iter()
                .any(|a| a.data.windows(payload.len()).any(|w| w == payload)),
            "{label}: released payload bytes absent"
        );
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

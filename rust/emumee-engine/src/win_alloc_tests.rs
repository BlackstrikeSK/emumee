use super::*;
use emumee_core::{
    fixtures::{WinAllocFixture as F, win_alloc_probe},
    report_bundle::digest,
    user_input::{PROFILE, Request},
};

fn run(arch: Architecture, kind: F) -> Execution {
    let bytes = win_alloc_probe(arch, kind);
    // Validate fixture structure before entering any native engine.
    PeImage::parse(&bytes, "sample.exe").unwrap();
    let request = Request {
        schema: 1,
        profile: PROFILE.into(),
        run_id: "20261119T160000Z-12345678".into(),
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
    let label = format!("{arch:?}-m5-win-alloc-{kind:?}");
    crate::user_test_fixtures::fixture(&label, &request, &bytes, &[], None);
    let result = user::run(&request, &bytes, None).unwrap();
    crate::user_test_fixtures::execution(&label, &result);
    result
}

#[test]
fn submitted_capture_request_drives_user_memory_strings_profile() {
    for arch in [Architecture::X86, Architecture::X64] {
        let bytes = win_alloc_probe(arch, F::Probe);
        PeImage::parse(&bytes, "sample.exe").unwrap();
        let request = Request {
            schema: 2,
            profile: PROFILE.into(),
            run_id: "20261119T160000Z-12345678".into(),
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
            capture: Some(emumee_core::user_input::CaptureRequest {
                memory_strings: Some(emumee_core::user_input::MemoryStringRequest {
                    enabled: true,
                    patterns: vec!["[ -~]{5,}".into()],
                    scan_bytes: 128 * 1024 * 1024,
                }),
                carve_executable_regions: true,
            }),
        };
        let result = user::run(&request, &bytes, None).unwrap();
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        let json = serde_json::to_value(&result).unwrap();
        assert!(
            emumee_core::user_memory_observation::valid_execution(&json),
            "{arch:?}: {json:#}"
        );
        assert!(emumee_core::user_memory_observation::present(&json));
        let receipt = result.user_memory_capture.as_ref().unwrap();
        assert!(receipt.selected_bytes > 0, "{arch:?}");
        assert_eq!(receipt.patterns, vec!["[ -~]{5,}".to_string()]);
    }
}

#[test]
fn m5_global_local_blocks_share_the_process_heap_with_identity_handles() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::Global, F::Local] {
            let result = run(arch, kind);
            assert_eq!(result.error, None, "{arch:?}/{kind:?}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(1));
            assert!(result.api_events.iter().all(|e| !e.pending));
            // Every control frees what it allocated.
            let heaps = serde_json::to_value(result.user_heaps.unwrap()).unwrap();
            assert_eq!(heaps["blocks"].as_object().unwrap().len(), 0);
        }
    }
}

#[test]
fn m5_address_probes_and_region_queries_report_actual_guest_backing() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::Probe, F::RtlSize] {
            let result = run(arch, kind);
            assert_eq!(result.error, None, "{arch:?}/{kind:?}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(1));
            assert!(result.api_events.iter().all(|e| !e.pending));
        }
    }
}

#[test]
fn m5_win32_allocation_apis_refuse_foreign_interior_and_owned_blocks() {
    for arch in [Architecture::X86, Architecture::X64] {
        for (kind, message) in [
            (F::ForeignFree, "wrong-heap"),
            (F::InteriorFree, "wrong-heap"),
            (F::OwnedFree, "CRT startup-owned"),
            (F::BadFlags, "are not modeled"),
        ] {
            let result = run(arch, kind);
            assert_eq!(result.completion_reason, "error", "{arch:?}/{kind:?}");
            assert!(
                result.error.as_deref().unwrap().contains(message),
                "{arch:?}/{kind:?}: {:?}",
                result.error
            );
            assert_eq!(result.guest_entry_return, None);
        }
    }
}

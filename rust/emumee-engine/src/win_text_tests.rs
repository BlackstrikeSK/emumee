use super::*;
use emumee_core::{
    fixtures::{WinTextFixture as F, win_text_probe},
    report_bundle::digest,
    user_input::{PROFILE, Request},
};

fn run(arch: Architecture, kind: F) -> Execution {
    let bytes = win_text_probe(arch, kind);
    // Validate fixture structure before entering any native engine.
    PeImage::parse(&bytes, "sample.exe").unwrap();
    let request = Request {
        schema: 1,
        profile: PROFILE.into(),
        run_id: "20261119T190000Z-12345678".into(),
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
        capture: None,
        output: None,
    };
    let label = format!("{arch:?}-m5-win-text-{kind:?}");
    crate::user_test_fixtures::fixture(&label, &request, &bytes, &[], None);
    let result = user::run(&request, &bytes, None).unwrap();
    crate::user_test_fixtures::execution(&label, &result);
    result
}

#[test]
fn m5_win32_string_copies_comparisons_types_and_mappings_follow_their_contracts() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::Copy, F::Map, F::Message] {
            let result = run(arch, kind);
            assert_eq!(result.error, None, "{arch:?}/{kind:?}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(1));
            assert!(result.api_events.iter().all(|e| !e.pending));
        }
    }
}

#[test]
fn m5_win32_string_apis_refuse_unmodeled_type_and_mapping_requests() {
    for arch in [Architecture::X86, Architecture::X64] {
        for (kind, message) in [
            (F::BadType, "information type"),
            (F::BadFlags, "flags 0x400 are not modeled"),
            (
                F::MessageModule,
                "message-table resources from a module are not modeled",
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

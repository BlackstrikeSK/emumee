use super::*;
use emumee_core::{
    fixtures::{CrtTextFixture as F, crt_text_probe},
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
    let bytes = crt_text_probe(arch, kind);
    // Validate fixture structure before entering any native engine.
    PeImage::parse(&bytes, "sample.exe").unwrap();
    let request = Request {
        schema: 1,
        profile: PROFILE.into(),
        run_id: "20261119T180000Z-12345678".into(),
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
    };
    let label = format!("{arch:?}-m5-crt-text-{kind:?}");
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
fn m5_crt_text_models_concatenation_spans_searches_and_case_mapping() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::Text, F::Fold] {
            let result = run(arch, kind);
            assert_eq!(result.error, None, "{arch:?}/{kind:?}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(1));
            assert!(result.api_events.iter().all(|e| !e.pending));
        }
    }
}

#[test]
fn m5_crt_conversions_tokenizer_clock_text_and_locale_share_process_state() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::Convert, F::Clock] {
            let result = run(arch, kind);
            assert_eq!(result.error, None, "{arch:?}/{kind:?}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(1));
            assert!(result.api_events.iter().all(|e| !e.pending));
        }
    }
}

#[test]
fn m5_crt_date_and_time_text_follow_the_persona_clock() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = run_source_only(arch, F::ClockText);
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1));
    }
}

#[test]
fn m5_crt_text_refuses_unmodeled_locales_and_null_strings() {
    for arch in [Architecture::X86, Architecture::X64] {
        for (kind, message) in [
            (F::BadLocale, "is not modeled"),
            (F::NullString, "pointer is null"),
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

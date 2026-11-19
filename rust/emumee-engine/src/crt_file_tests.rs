use super::*;
use emumee_core::{
    fixtures::{CrtFileFixture as F, crt_file_probe},
    report_bundle::digest,
    user_input::{InputKind, PROFILE, Request, StagedFile},
};

const CONTENT: &[u8] = b"hello world";

fn run(arch: Architecture, kind: F) -> Execution {
    let bytes = crt_file_probe(arch, kind);
    // Validate fixture structure before entering any native engine.
    PeImage::parse(&bytes, "sample.exe").unwrap();
    let staged = vec![CONTENT.to_vec()];
    let request = Request {
        schema: 2,
        profile: PROFILE.into(),
        run_id: "20261119T210000Z-12345678".into(),
        input_sha256: digest(&bytes),
        input_size: bytes.len() as u64,
        module_name: "sample.exe".into(),
        arguments: vec![],
        max_instructions: 60000,
        timeout_us: 30_000_000,
        persona_sha256: None,
        clock_utc_filetime: 134377488000000000,
        staged: vec![StagedFile {
            kind: InputKind::File,
            guest_path: r"C:\emumee\data.txt".into(),
            size: CONTENT.len() as u64,
            sha256: digest(CONTENT),
        }],
        invocation: Default::default(),
    };
    let label = format!("{arch:?}-m5-crt-file-{kind:?}");
    crate::user_test_fixtures::fixture(&label, &request, &bytes, &staged, None);
    let result = user::run_staged(&request, &bytes, None, &staged).unwrap();
    crate::user_test_fixtures::execution(&label, &result);
    result
}

#[test]
fn m5_crt_streams_read_and_position_actual_virtual_file_content() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = run(arch, F::Streams);
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1));
        assert!(result.api_events.iter().all(|e| !e.pending));
        // The stream the guest closed is no longer registered.
        let report = result.crt_stdio.unwrap();
        assert!(report.streams.is_empty(), "{:?}", report.streams);
    }
}

#[test]
fn m5_crt_streams_write_through_the_virtual_file_system_and_console() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = run(arch, F::Output);
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1));
        let console = result.console.unwrap();
        assert!(
            console.stdout.contains("hi\n"),
            "{arch:?}: {:?}",
            console.stdout
        );
        // The written byte reached the virtual file, not a host file.
        let artifact = result
            .artifacts
            .iter()
            .find(|artifact| {
                artifact
                    .observations
                    .iter()
                    .any(|observation| observation.guest_path.ends_with("out.txt"))
            })
            .unwrap_or_else(|| panic!("{arch:?}: {:?}", result.artifacts));
        assert_eq!(artifact.size, 1);
        assert_eq!(artifact.data, b"A");
    }
}

#[test]
fn m5_crt_streams_refuse_unmodeled_modes_foreign_files_and_wrong_access() {
    for arch in [Architecture::X86, Architecture::X64] {
        for (kind, message) in [
            (F::BadMode, "stream mode is not modeled"),
            (F::BadClose, "unknown or retired guest FILE"),
            (F::WriteOnlyRead, "not opened for reading"),
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

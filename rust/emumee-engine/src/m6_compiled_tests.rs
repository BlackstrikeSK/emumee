//! The M6 exit criterion: a harmless compiler-produced program that walks the
//! registry, volume, file-handle, version, locale and firmware paths end to end
//! must run on both architectures, and a program that asks for an unmodeled
//! contract must stop explicitly.
use super::*;
use emumee_core::{
    report_bundle::digest,
    user_input::{InputKind, PROFILE, Request, StagedFile},
};

const CONTENT: &[u8] = b"emumee-m6";

fn program(arch: Architecture, name: &str) -> Vec<u8> {
    let suffix = if arch == Architecture::X64 { "x64" } else { "x86" };
    let path = format!(
        "{}/../../src/emumee/guest_native/{name}_{suffix}.exe",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|error| panic!("{path}: {error}"))
}
fn run(arch: Architecture, name: &str) -> Execution {
    let bytes = program(arch, name);
    // Validate the compiled image before entering any native engine.
    let parsed = PeImage::parse(&bytes, "sample.exe").unwrap();
    assert_eq!(parsed.sample.architecture, arch);
    let staged = vec![CONTENT.to_vec()];
    let request = Request {
        schema: 2,
        profile: PROFILE.into(),
        run_id: "20261120T140000Z-12345678".into(),
        input_sha256: digest(&bytes),
        input_size: bytes.len() as u64,
        module_name: "sample.exe".into(),
        arguments: vec![],
        max_instructions: 2_000_000,
        timeout_us: 60_000_000,
        persona_sha256: None,
        clock_utc_filetime: crate::m6_tests::CLOCK,
        staged: vec![StagedFile {
            kind: InputKind::File,
            // The staged file is what creates the guest directory the program
            // writes its own file into.
            guest_path: r"C:\emumee\data.txt".into(),
            size: CONTENT.len() as u64,
            sha256: digest(CONTENT),
        }],
        invocation: Default::default(),
        capture: None,
    };
    let label = format!("{arch:?}-m6-compiled-{name}");
    crate::user_test_fixtures::fixture(&label, &request, &bytes, &staged, None);
    let result = user::run_staged(&request, &bytes, None, &staged).unwrap();
    crate::user_test_fixtures::execution(&label, &result);
    result
}

#[test]
fn m6_compiler_produced_program_walks_registry_volume_file_version_and_firmware_paths() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = run(arch, "m6_program");
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        // Every failure path in the program returns its own code, so the exit
        // code pins which contract was wrong.
        assert_eq!(result.process_exit_code, Some(23), "{arch:?}");
        assert_eq!(result.completion_reason, "process_exit");
        assert!(result.api_events.iter().all(|e| !e.pending));
        let console = result.console.as_ref().unwrap();
        for expected in ["volume serial=6F2A9E4D fs=NTFS", "firmware bytes=", "m6-ok"] {
            assert!(
                console.stdout.contains(expected),
                "{arch:?}: {expected:?} missing from {:?}",
                console.stdout
            );
        }
        // The program's own guest file is in the owned filesystem, shortened to
        // the four bytes its SetEndOfFile left behind.
        let storage = result.file_storage.as_ref().unwrap();
        assert_eq!(storage.open_handles, 0, "{arch:?}: {storage:#?}");
        assert!(
            result.artifacts.iter().any(|artifact| artifact.data == b"0123"),
            "{arch:?}: {:?}",
            result.artifacts
        );
    }
}

#[test]
fn m6_compiler_produced_negative_control_stops_on_an_unmodeled_contract() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = run(arch, "m6_refusal");
        assert_eq!(result.completion_reason, "error", "{arch:?}: {result:#?}");
        assert!(
            result
                .error
                .as_deref()
                .unwrap()
                .contains("File mapping objects are not modeled"),
            "{arch:?}: {:?}",
            result.error
        );
        assert_eq!(result.process_exit_code, None);
    }
}

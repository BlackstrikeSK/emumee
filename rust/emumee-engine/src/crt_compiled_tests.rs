//! The M5 exit criterion: harmless compiler-produced C programs that use the
//! modeled legacy CRT must run on both architectures, and a program that asks
//! for an unmodeled contract must stop explicitly.
use super::*;
use emumee_core::{
    report_bundle::digest,
    user_input::{InputKind, PROFILE, Request, StagedFile},
};

const CONTENT: &[u8] = b"hello world";

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
        run_id: "20261119T220000Z-12345678".into(),
        input_sha256: digest(&bytes),
        input_size: bytes.len() as u64,
        module_name: "sample.exe".into(),
        arguments: vec![],
        max_instructions: 2_000_000,
        timeout_us: 60_000_000,
        persona_sha256: None,
        clock_utc_filetime: 134377488000000000,
        staged: vec![StagedFile {
            kind: InputKind::File,
            guest_path: r"C:\emumee\data.txt".into(),
            size: CONTENT.len() as u64,
            sha256: digest(CONTENT),
        }],
        invocation: Default::default(),
        capture: None,
    };
    let label = format!("{arch:?}-m5-compiled-{name}");
    crate::user_test_fixtures::fixture(&label, &request, &bytes, &staged, None);
    let result = user::run_staged(&request, &bytes, None, &staged).unwrap();
    crate::user_test_fixtures::execution(&label, &result);
    result
}

#[test]
fn m5_compiler_produced_crt_program_runs_startup_strings_heap_stdio_and_teardown() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = run(arch, "crt_program");
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        // Every failure path in the program returns its own code, so the exit
        // code pins which contract was wrong.
        assert_eq!(result.process_exit_code, Some(7), "{arch:?}");
        assert_eq!(result.completion_reason, "process_exit");
        assert!(result.api_events.iter().all(|e| !e.pending));
        let console = result.console.unwrap();
        for expected in ["argc=1 name=crt-ok", "hello", "teardown"] {
            assert!(
                console.stdout.contains(expected),
                "{arch:?}: {expected:?} missing from {:?}",
                console.stdout
            );
        }
        // The exit-time function ran before the process exited.
        let startup = result.crt_startup.unwrap();
        assert_eq!(startup.requested_exit_code, Some(7));
        assert_eq!(startup.initializers.len(), 1);
        assert!(startup.initializers[0].error.is_none());
    }
}

#[test]
fn m5_compiler_produced_negative_control_stops_on_an_unmodeled_contract() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = run(arch, "crt_refusal");
        assert_eq!(result.completion_reason, "error", "{arch:?}: {result:#?}");
        assert!(
            result
                .error
                .as_deref()
                .unwrap()
                .contains("new-handler allocation mode is not modeled"),
            "{arch:?}: {:?}",
            result.error
        );
        assert_eq!(result.process_exit_code, None);
    }
}

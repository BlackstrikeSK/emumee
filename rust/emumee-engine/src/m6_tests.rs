//! M6 guest control families for the registry, persona and filesystem API
//! partitions.
//!
//! Each control is a generated x86/x64 caller that reaches the modeled exports
//! through a real import table and decides its own outcome: every expected
//! value is compared by guest instructions, so a wrong answer raises a
//! breakpoint inside the guest rather than being reported back for a host
//! assertion. Every control is emitted as a contained fixture so the packaged
//! worker replays the same bytes through the public CLI.
use super::*;
use crate::user_test_fixtures as emit;
use emumee_core::{
    report_bundle::digest,
    user_input::{InputKind, PROFILE, Request, StagedFile},
};

mod files;
mod observation;
mod persona;
mod registry;
mod unmap;
mod volumes;

/// The request clock every M6 control uses; the seeded registry and filesystem
/// times are this value, so a guest can assert them exactly.
pub(crate) const CLOCK: u64 = 134_377_488_000_000_000;

/// A staged guest input: its kind, its guest path and its bytes.
pub(crate) struct Staged {
    pub kind: InputKind,
    pub path: &'static str,
    pub bytes: Vec<u8>,
}

/// Run one control and emit its exact contained inputs and outcome.
pub(crate) fn run(label: &str, bytes: Vec<u8>, staged: &[Staged], budget: u64) -> Execution {
    // Validate the generated image before entering any native engine.
    PeImage::parse(&bytes, "sample.exe").unwrap();
    let request = Request {
        schema: 2,
        profile: PROFILE.into(),
        run_id: "20261120T120000Z-12345678".into(),
        input_sha256: digest(&bytes),
        input_size: bytes.len() as u64,
        module_name: "sample.exe".into(),
        arguments: vec![],
        max_instructions: budget,
        timeout_us: 30_000_000,
        persona_sha256: None,
        clock_utc_filetime: CLOCK,
        staged: staged
            .iter()
            .map(|file| StagedFile {
                kind: file.kind,
                guest_path: file.path.into(),
                size: file.bytes.len() as u64,
                sha256: digest(&file.bytes),
            })
            .collect(),
        invocation: Default::default(),
        capture: None,
    };
    let contents = staged
        .iter()
        .map(|file| file.bytes.clone())
        .collect::<Vec<_>>();
    emit::fixture(label, &request, &bytes, &contents, None);
    let result = user::run_staged(&request, &bytes, None, &contents).unwrap();
    emit::execution(label, &result);
    result
}

/// Every successful control returns 1 from its own entry and leaves no API
/// event pending.
pub(crate) fn succeeded(label: &str, result: &Execution) {
    assert_eq!(result.error, None, "{label}: {result:#?}");
    assert_eq!(result.completion_reason, "entry_return", "{label}");
    assert_eq!(result.guest_entry_return, Some(1), "{label}");
    assert!(
        result.api_events.iter().all(|event| !event.pending),
        "{label} retains a pending API event"
    );
    assert_eq!(result.network.calls, 0, "{label} reached the network");
}

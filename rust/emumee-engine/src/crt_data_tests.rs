use super::*;
use crate::user_test_fixtures as emit;
use emumee_core::{
    fixtures::{CrtDataFixture as F, crt_data_probe},
    report_bundle::digest,
    user_input::{InputKind, PROFILE, Request, StagedFile},
};

fn run(arch: Architecture, kind: F, budget: u64) -> Execution {
    let bytes = crt_data_probe(arch, kind);
    // Validate fixture structure before entering any native engine.
    PeImage::parse(&bytes, "sample.exe").unwrap();
    let staged = if kind == F::Parent {
        vec![crt_data_probe(arch, F::Child)]
    } else {
        vec![]
    };
    let request = Request {
        schema: 2,
        profile: PROFILE.into(),
        run_id: "20261119T150000Z-12345678".into(),
        input_sha256: digest(&bytes),
        input_size: bytes.len() as u64,
        module_name: "sample.exe".into(),
        arguments: if kind == F::Long {
            vec!["x".repeat(5000)]
        } else {
            vec!["two words".into(), "é😀".into()]
        },
        max_instructions: budget,
        timeout_us: 30_000_000,
        persona_sha256: None,
        clock_utc_filetime: 134377488000000000,
        staged: staged
            .iter()
            .map(|child| StagedFile {
                kind: InputKind::File,
                guest_path: r"C:\emumee\child.exe".into(),
                size: child.len() as u64,
                sha256: digest(child),
            })
            .collect(),
        invocation: Default::default(),
        capture: None,
        output: None,
    };
    let label = format!("{arch:?}-m5-crt-data-{kind:?}-{budget}");
    emit::fixture(&label, &request, &bytes, &staged, None);
    let result = user::run_staged(&request, &bytes, None, &staged).unwrap();
    emit::execution(&label, &result);
    result
}

#[test]
fn m5_crt_data_import_accessor_lookup_and_thread_mutations_share_real_guest_storage() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::Alias, F::Thread, F::Long, F::Parent] {
            let result = run(arch, kind, 20000);
            assert_eq!(result.error, None, "{arch:?}/{kind:?}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(1));
            assert!(result.api_events.iter().all(|e| !e.pending));
            let storage = result
                .crt_startup
                .as_ref()
                .unwrap()
                .msvcrt_command_line
                .as_ref()
                .unwrap();
            assert_eq!(storage.address % 4096, 0);
            assert_eq!(storage.size, if kind == F::Long { 8192 } else { 4096 });
            if kind == F::Parent {
                let child = result.user_processes.iter().find(|p| p.id == 1025).unwrap();
                assert_eq!(child.failure, None, "{child:#?}");
                assert_eq!(child.exit_code, Some(42));
                assert!(child.backing_released);
                let parent = result
                    .api_events
                    .iter()
                    .find(|e| e.api == "msvcrt.__p__acmdln" && e.process_id == Some(1024))
                    .unwrap();
                let child = result
                    .api_events
                    .iter()
                    .find(|e| e.api == "msvcrt.__p__acmdln" && e.process_id == Some(1025))
                    .unwrap();
                assert_eq!(
                    parent.result, child.result,
                    "same virtual pointer, distinct address spaces"
                );
            }
        }
    }
}

#[test]
fn m5_crt_data_cannot_be_freed_reprotected_or_executed_by_guest_apis() {
    for arch in [Architecture::X86, Architecture::X64] {
        for (kind, message) in [
            (F::Release, "CRT startup-owned"),
            (F::Protect, "CRT startup-owned"),
            (F::Free, "no owned allocation"),
            (F::Nx, ""),
        ] {
            let result = run(arch, kind, 20000);
            assert!(
                result.error.as_ref().is_some_and(|s| s.contains(message)),
                "{arch:?}/{kind:?}: {result:#?}"
            );
            assert_eq!(result.guest_entry_return, None);
            if kind == F::Nx {
                let fault = result.native_memory_fault.as_ref().unwrap();
                assert_eq!(fault.access, "execute");
                assert_eq!(
                    fault.address,
                    result
                        .crt_startup
                        .unwrap()
                        .msvcrt_command_line
                        .unwrap()
                        .address
                );
            }
        }
    }
}

#[test]
fn m5_crt_data_budget_stops_preserve_only_executed_mutations() {
    for arch in [Architecture::X86, Architecture::X64] {
        for budget in [1, 10, 50, 100] {
            let result = run(arch, F::Alias, budget);
            assert_eq!(
                result.completion_reason, "instruction_budget",
                "{arch:?}/{budget}: {result:#?}"
            );
            assert_eq!(result.guest_entry_return, None);
        }
    }
}

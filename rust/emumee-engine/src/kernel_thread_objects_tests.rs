use super::*;
use emumee_core::fixtures::{ApiFixture, ThreadObjectFixture as F};
const CASES: [F; 24] = [
    F::Lifecycle,
    F::ChildReturn,
    F::CloseAfterExit,
    F::InvalidHandle,
    F::ClosedHandle,
    F::TypeMismatch,
    F::UserTypeMismatch,
    F::KernelAccess,
    F::UserMode,
    F::ReadonlyOutput,
    F::InformationOutput,
    F::Irql,
    F::ForeignHandle,
    F::ReleasedWait,
    F::ReleasedReference,
    F::ReleasedRead,
    F::RootHeader,
    F::RootPrivateCross,
    F::RootPreviousPageCross,
    F::RootHeaderWrite,
    F::RootApiWrite,
    F::RootTerminate,
    F::HeaderReadBenchmark,
    F::OrdinaryReadBenchmark,
];
fn process_field_fixture(offset: u32, dereference_process: bool, write: bool) -> Vec<u8> {
    use emumee_core::fixtures::EnvironmentFixture;
    let mut image = emumee_core::fixtures::api_probe(
        Architecture::X64,
        ApiFixture::Environment(EnvironmentFixture::DataOnly),
    );
    image[0x1500..0x1580].fill(0);
    for (i, name) in ["IoGetCurrentProcess", "KeGetCurrentThread"]
        .into_iter()
        .enumerate()
    {
        let at = 0x1502 + i * 64;
        image[at..at + name.len()].copy_from_slice(name.as_bytes());
    }
    let mut code = vec![0x48, 0x83, 0xec, 0x28];
    fn call(code: &mut Vec<u8>, rva: i32) {
        code.extend([0xff, 0x15]);
        code.extend((rva - (0x1000 + code.len() + 4) as i32).to_le_bytes());
    }
    call(&mut code, 0x2080);
    code.extend([0x48, 0x89, 0x44, 0x24, 0x20]);
    call(&mut code, 0x2088);
    code.extend([0x49, 0x89, 0xc2]);
    code.extend([0x65, 0x48, 0x8b, 0x04, 0x25, 0x88, 0x01, 0, 0]);
    code.extend([0x4c, 0x39, 0xd0, 0x74, 2, 0x0f, 0x0b]);
    if write {
        code.extend([0x48, 0xc7, 0x80]);
        code.extend(offset.to_le_bytes());
        code.extend(0u32.to_le_bytes());
    } else {
        code.extend([0x48, 0x8b, 0x80]);
        code.extend(offset.to_le_bytes());
        if dereference_process {
            code.extend([0x48, 0x8b, 0x00]);
        }
        code.extend([0x48, 0x3b, 0x44, 0x24, 0x20, 0x74, 2, 0x0f, 0x0b]);
    }
    code.extend([0xb8, 42, 0, 0, 0, 0x48, 0x83, 0xc4, 0x28, 0xc3]);
    image[0x200..0x1200].fill(0xcc);
    image[0x200..0x200 + code.len()].copy_from_slice(&code);
    image
}
fn run_process_field(build: u32, offset: u32, dereference: bool, write: bool) -> Execution {
    run_pinned_thread_image(build, &process_field_fixture(offset, dereference, write))
}
fn run_pinned_thread_image(build: u32, image: &[u8]) -> Execution {
    run_pinned_thread_image_budget(build, image, 1000)
}
pub(super) fn run_pinned_thread_image_budget(build: u32, image: &[u8], budget: u64) -> Execution {
    use emumee_core::{
        fixtures::{ConfiguredFixture, configured_document},
        fullpersona::{ResolveContext, decode},
    };
    let mut document: serde_json::Value =
        serde_json::from_slice(&configured_document(ConfiguredFixture::Kernel)).unwrap();
    document["windows_build"] = serde_json::json!(build);
    let persona = decode(
        &serde_json::to_vec(&document).unwrap(),
        &ResolveContext::default(),
    )
    .unwrap();
    let prepared = configured::Prepared::new(
        persona,
        configured::Request {
            architecture: Architecture::X64,
            kernel: true,
            initial_processor: 0,
            process: None,
            budget,
            timeout_us: 30_000_000,
        },
    )
    .unwrap();
    run_generated_with_fixture_configuration(
        image,
        &[],
        budget,
        30_000_000,
        GeneratedConfiguration {
            configured: Some(prepared),
            ..Default::default()
        },
    )
    .unwrap()
}
#[test]
fn thread_stack_fields_match_root_and_child_live_native_stack_pointers() {
    let image = emumee_core::fixtures::api_probe(
        Architecture::X64,
        ApiFixture::ThreadObjects(F::StackBounds),
    );
    let e = run_pinned_thread_image(26200, &image);
    assert_eq!(e.error, None, "{e:#?}");
    assert_eq!(e.guest_entry_return, Some(1));
    let threads = e.kernel_thread_objects.as_ref().unwrap();
    assert_eq!(threads.stack_fields.len(), 1); // Child returned, closed and retired.
    assert_eq!(
        threads.stack_fields[0].thread,
        emumee_core::kernel_layout::KernelLayout::for_architecture(Architecture::X64).root_thread
    );
    assert!(threads.threads.iter().any(|t| t.slot == 2 && t.retired));
    assert!(threads.private_accesses.is_empty());
    let other = run_pinned_thread_image(26100, &image);
    assert!(other.error.is_some());
    assert_eq!(other.guest_entry_return, None);
    assert!(
        other
            .kernel_thread_objects
            .as_ref()
            .unwrap()
            .stack_fields
            .is_empty()
    );
}
#[test]
fn thread_stack_fields_refuse_adjacent_bytes_crossing_reads_writes_and_unknown_flags() {
    for (offset, write) in [
        (0x28, false),
        (0x2f, false),
        (0x39, false),
        (0x78, false),
        (0x30, true),
        (0x38, true),
    ] {
        let e = run_process_field(26200, offset, false, write);
        assert!(e.error.is_some(), "{offset:x}/{write}: {e:#?}");
        let error = e.error.as_deref().unwrap();
        assert!(
            error.contains("private or released kernel thread body")
                || (write && error.contains("WRITE_PROT")),
            "Unexpected refusal at {offset:x}: {error}"
        );
        assert_eq!(e.guest_entry_return, None);
    }
}
#[test]
fn thread_system_process_projection_matches_actual_gs_identity_and_current_process_api() {
    let e = run_process_field(26200, 0xb8, false, false);
    assert_eq!(e.error, None, "{e:#?}");
    assert_eq!(e.guest_entry_return, Some(42));
    let objects = e.kernel_objects.as_ref().unwrap();
    let threads = e.kernel_thread_objects.as_ref().unwrap();
    let field = threads.system_process_field.unwrap();
    assert_eq!(Some(field.process), objects.system_process);
    assert_eq!(field.offset, 0xb8);
    assert!(threads.private_accesses.is_empty());
    assert!(!threads.native_effect_failure);
    assert_eq!(e.api_events[0].result, Some(field.process));
}
#[test]
fn thread_process_field_does_not_open_private_gaps_writes_or_the_opaque_process_body() {
    for (build, offset, dereference, write) in [
        (26100, 0xb8, false, false),
        (26200, 0xb4, false, false),
        (26200, 0xb8, true, false),
        (26200, 0xb8, false, true),
    ] {
        let e = run_process_field(build, offset, dereference, write);
        assert!(e.error.is_some(), "{build}/{offset:x}: {e:#?}");
        assert_eq!(e.guest_entry_return, None);
    }
}
fn budget(kind: F) -> u64 {
    if kind.benchmark() { 100000 } else { 1000 }
}
#[test]
fn generated_x64_system_thread_accepts_unnamed_kernel_handle_attributes_only() {
    let accepted = run_api_fixture(
        Architecture::X64,
        ApiFixture::ThreadObjects(F::ObjectAttributes),
        1000,
    )
    .unwrap();
    assert_eq!(accepted.error, None);
    assert_eq!(accepted.guest_entry_return, Some(1));
    assert!(accepted.api_events.iter().any(|event| {
        event.api == "ntoskrnl.PsCreateSystemThread"
            && event.arguments[1] == 0x1fffff
            && event.arguments[2] == 0x140002e00
            && event.arguments[3] == 0
            && event.result == Some(0)
    }));
    let report = accepted.kernel_thread_objects.as_ref().unwrap();
    assert!(
        report
            .threads
            .iter()
            .any(|thread| thread.slot == 2 && thread.terminated)
    );

    let named = run_api_fixture(
        Architecture::X64,
        ApiFixture::ThreadObjects(F::ObjectAttributesNamed),
        1000,
    )
    .unwrap();
    assert!(
        named
            .error
            .as_deref()
            .unwrap_or("")
            .contains("System-thread OBJECT_ATTRIBUTES name/root/security/flags are not modeled")
    );
    assert_eq!(named.guest_entry_return, None);
    assert!(
        !named.api_events.iter().any(|event| {
            event.api == "ntoskrnl.PsCreateSystemThread" && event.result == Some(0)
        })
    );
    let report = named.kernel_thread_objects.as_ref().unwrap();
    assert_eq!(report.threads.len(), 1);
    assert!(report.handles.is_empty());
}
#[test]
fn actual_scheduler_handles_joins_and_refcounts_share_the_same_thread_object_lifetime() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in CASES {
            let result =
                run_api_fixture(architecture, ApiFixture::ThreadObjects(kind), budget(kind))
                    .unwrap();
            let report = result.kernel_thread_objects.as_ref().unwrap();
            let objects = result.kernel_objects.as_ref().unwrap();
            let layout = emumee_core::kernel_layout::KernelLayout::for_architecture(architecture);
            assert!(report.read_guard_installed);
            assert!(!report.native_effect_failure);
            assert_eq!(result.network.calls, 0);
            assert!(result.artifacts.is_empty());
            let root = report
                .threads
                .iter()
                .find(|record| record.slot == 1)
                .unwrap();
            assert_eq!(root.address, layout.root_thread);
            assert!(root.root_caller && root.executing && !root.terminated && !root.retired);
            assert_eq!(root.open_handles, 0);
            if kind.negative() {
                let error = result.error.as_deref().unwrap_or("");
                let expected = match kind {
                    F::UserMode => "UserMode thread handle security",
                    F::ReadonlyOutput => "lacks permission",
                    F::InformationOutput => "handle-information",
                    F::Irql => "PASSIVE_LEVEL",
                    F::ForeignHandle => "Foreign process/file",
                    F::ReleasedWait => "released thread object",
                    F::ReleasedReference => "live owned object body",
                    F::ReleasedRead => "READ_PROT",
                    F::RootPrivateCross | F::RootPreviousPageCross => {
                        "private or released kernel thread body read"
                    }
                    F::RootHeaderWrite => "WRITE_PROT",
                    F::RootApiWrite => "private or released kernel thread body access",
                    F::RootTerminate => "outside a spawned system thread",
                    _ => unreachable!(),
                };
                assert!(
                    error.contains(expected)
                        || matches!(kind, F::ReleasedRead)
                            && error.contains("private or released kernel thread body read"),
                    "{architecture:?} {kind:?}: {result:#?}"
                );
                assert_eq!(result.guest_entry_return, None);
            } else {
                assert_eq!(result.error, None, "{architecture:?} {kind:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1));
            }
            if kind.root_only() {
                assert_eq!(report.threads.len(), 1);
                assert!(report.handles.is_empty());
                if matches!(kind, F::RootTerminate) {
                    assert!(
                        result
                            .kernel_threads
                            .as_ref()
                            .is_none_or(|threads| threads.exited == 0
                                && threads.root_entry_return.is_none())
                    );
                }
            } else {
                let child = report
                    .threads
                    .iter()
                    .find(|record| record.slot == 2)
                    .unwrap();
                assert_eq!(child.address, layout.thread_object(2).unwrap());
                let record = objects
                    .objects
                    .iter()
                    .find(|record| record.address == child.address)
                    .unwrap();
                if !kind.negative()
                    || matches!(
                        kind,
                        F::ReleasedWait | F::ReleasedReference | F::ReleasedRead
                    )
                {
                    assert!(child.terminated && child.retired && !child.executing);
                    assert_eq!(child.open_handles, 0);
                    assert!(report.handles.is_empty());
                    assert_eq!(record.api_references, 0);
                    assert_eq!(record.permanent_references, 0);
                    assert!(!record.live);
                    assert!(
                        result
                            .api_events
                            .iter()
                            .any(|event| event.effect == Some("thread_signaled") && !event.pending)
                    );
                } else {
                    assert!(child.executing && !child.terminated && !child.retired);
                    assert_eq!(child.open_handles, 1);
                    assert_eq!(report.handles.len(), 1);
                    assert_eq!(report.handles[0].object, child.address);
                    assert_eq!(report.handles[0].owner, 4);
                    assert!(report.handles[0].kernel_only);
                    assert_eq!(record.api_references, 0);
                    assert_eq!(record.permanent_references, 2);
                }
                if matches!(kind, F::KernelAccess) {
                    assert!(
                        result
                            .api_events
                            .iter()
                            .any(|event| event.api == "ntoskrnl.PsCreateSystemThread"
                                && event.arguments[1] == 0)
                    );
                    assert!(
                        result
                            .api_events
                            .iter()
                            .any(|event| event.api == "ntoskrnl.ObReferenceObjectByHandle"
                                && event.arguments[1] == 0x100000
                                && event.result == Some(0))
                    );
                }
            }
        }
    }
}
#[test]
fn actual_thread_reference_budget_prefixes_preserve_caller_and_do_not_invent_child_exit() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in CASES.into_iter().filter(|kind| !kind.negative()) {
            let full = run_api_fixture(architecture, ApiFixture::ThreadObjects(kind), budget(kind))
                .unwrap();
            assert_eq!(full.error, None);
            for budget in [1, full.instruction_count - 1] {
                let partial =
                    run_api_fixture(architecture, ApiFixture::ThreadObjects(kind), budget).unwrap();
                assert_eq!(partial.completion_reason, "instruction_budget");
                assert_eq!(partial.guest_entry_return, None);
                assert_eq!(partial.error, None);
                let report = partial.kernel_thread_objects.as_ref().unwrap();
                assert!(!report.threads[0].retired && !report.threads[0].terminated);
                if budget == 1 {
                    assert_eq!(report.threads.len(), 1);
                    assert!(report.handles.is_empty());
                }
            }
        }
    }
}
#[test]
fn owned_repeat_read_programs_record_guard_cost_without_claiming_a_speedup() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let header = run_api_fixture(
            architecture,
            ApiFixture::ThreadObjects(F::HeaderReadBenchmark),
            100000,
        )
        .unwrap();
        let ordinary = run_api_fixture(
            architecture,
            ApiFixture::ThreadObjects(F::OrdinaryReadBenchmark),
            100000,
        )
        .unwrap();
        assert_eq!(header.error, None);
        assert_eq!(ordinary.error, None);
        assert_eq!(header.instruction_count, ordinary.instruction_count);
        assert!(
            header
                .kernel_thread_objects
                .as_ref()
                .unwrap()
                .read_guard_checks
                >= 10000
        );
        assert!(
            ordinary
                .kernel_thread_objects
                .as_ref()
                .unwrap()
                .read_guard_checks
                >= 10000
        );
        assert!(header.engine_seconds > 0.0 && ordinary.engine_seconds > 0.0);
    }
}

#[test]
fn actual_child_priority_returns_previous_base_in_both_architectures() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let layout = emumee_core::kernel_layout::KernelLayout::for_architecture(architecture);
        let child = layout.thread_object(2).unwrap();
        for (kind, valid) in [
            (F::Priority, true),
            (F::PriorityInvalid, false),
            (F::PriorityForeign, false),
        ] {
            let result =
                run_api_fixture(architecture, ApiFixture::ThreadObjects(kind), 1000).unwrap();
            let thread = result
                .kernel_threads
                .as_ref()
                .unwrap()
                .states
                .iter()
                .find(|thread| thread.slot == 2)
                .unwrap();
            assert_eq!(thread.priority, if valid { 15 } else { 8 });
            let event = result
                .api_events
                .iter()
                .find(|event| event.api == "ntoskrnl.KeSetActualBasePriorityThread")
                .unwrap();
            assert_eq!(
                event.arguments,
                vec![
                    if matches!(kind, F::PriorityForeign) {
                        if architecture == Architecture::X64 {
                            0x140002c30
                        } else {
                            0x402c30
                        }
                    } else {
                        child
                    },
                    if matches!(kind, F::PriorityInvalid) {
                        0
                    } else {
                        15
                    }
                ]
            );
            assert_eq!(event.result, if valid { Some(8) } else { None });
            assert_eq!(event.thread_id, 2);
            if valid {
                assert_eq!(result.completion_reason, "entry_return", "{result:#?}");
                assert_eq!(result.guest_entry_return, Some(1));
                assert_eq!(event.error, None);
            } else {
                assert_eq!(result.completion_reason, "error");
                assert_eq!(result.guest_entry_return, None);
                assert!(event.error.is_some());
            }
        }
    }
}

use super::*;
use emumee_core::{
    fixtures::{ApiFixture, IpiFixture as I},
    ipi::Phase,
    kernel_thread_objects::Ownership,
};
const CASES: [I; 27] = [
    I::Basic,
    I::One,
    I::Four,
    I::Twelve,
    I::GroupBoundary,
    I::Barrier,
    I::Repeat,
    I::Wide,
    I::Background,
    I::ChildCaller,
    I::MsrIsolation,
    I::Fault,
    I::Invalid,
    I::Nested,
    I::Terminate,
    I::Irql,
    I::Budget,
    I::HighIrql,
    I::Marker,
    I::ControlMutation,
    I::DescriptorMutation,
    I::UnownedMsr,
    I::LowerWait,
    I::LowerDelay,
    I::LowerMutex,
    I::LowerCreate,
    I::PcrIrql,
];
fn refusal(kind: I, architecture: Architecture) -> Option<&'static str> {
    Some(match kind {
        I::GroupBoundary if architecture == Architecture::X86 => {
            "one bounded configured processor group"
        }
        I::Invalid => "not executable guest code",
        I::Nested => "nested broadcast",
        I::Terminate => "IPI callback cannot terminate",
        I::HighIrql => "below IPI_LEVEL",
        I::Marker => "return marker",
        I::PcrIrql => {
            if architecture == Architecture::X64 {
                "corrupted current-thread/IRQL"
            } else {
                "requires actual IPI_LEVEL"
            }
        }
        I::ControlMutation => "non-MSR processor control mutation",
        I::DescriptorMutation => "descriptor mutation",
        I::UnownedMsr => "MSR ownership is not modeled",
        I::LowerWait | I::LowerDelay | I::LowerMutex | I::LowerCreate => {
            "IPI member API entry requires actual IPI_LEVEL"
        }
        I::Fault | I::Irql | I::Budget => return None,
        _ => return None,
    })
}
#[test]
fn real_guest_members_agree_on_processor_contexts_returns_and_caller_ownership() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in CASES {
            let budget = if matches!(kind, I::Budget) {
                512
            } else {
                100000
            };
            let result = run_api_fixture(architecture, ApiFixture::Ipi(kind), budget).unwrap();
            let ipi = result.kernel_ipi.as_ref().unwrap();
            let groups = &ipi.rendezvous.broadcasts;
            let threads = result.kernel_thread_objects.as_ref().unwrap();
            let objects = result.kernel_objects.as_ref().unwrap();
            let root = threads
                .threads
                .iter()
                .find(|entry| entry.root_caller)
                .unwrap();
            assert!(root.executing && !root.terminated && !root.retired);
            assert_eq!(root.role, Ownership::InitialCaller);
            assert_eq!(result.network.calls, 0);
            assert!(result.artifacts.is_empty());
            if kind.negative(architecture) {
                assert_eq!(result.guest_entry_return, None);
                if matches!(kind, I::Budget) {
                    assert_eq!(result.completion_reason, "instruction_budget");
                    assert_eq!(result.instruction_count, 512);
                    assert_eq!(result.error, None);
                    assert_eq!(groups.len(), 1);
                    assert!(
                        groups[0]
                            .members
                            .iter()
                            .any(|member| member.started && member.instruction_count > 0)
                    );
                } else {
                    assert_eq!(result.completion_reason, "error");
                    assert!(
                        result.error.is_some(),
                        "{architecture:?} {kind:?}: {result:#?}"
                    );
                    if let Some(expected) = refusal(kind, architecture) {
                        assert!(
                            result.error.as_deref().unwrap().contains(expected),
                            "{architecture:?} {kind:?}: {result:#?}"
                        );
                    }
                }
                assert!(
                    groups
                        .iter()
                        .all(|group| !group.completed && group.source_result.is_none()),
                    "{architecture:?} {kind:?}: {result:#?}"
                );
                if kind.lowered_scheduler_probe() {
                    let scheduler = result.kernel_threads.as_ref().unwrap();
                    assert_eq!(
                        (
                            scheduler.count,
                            scheduler.exited,
                            scheduler.open_thread_handles,
                            scheduler.waits,
                            scheduler.resumed_waits
                        ),
                        (2, 0, 1, 2, 1)
                    );
                    assert_eq!(scheduler.root_entry_return, None);
                    assert!(matches!(
                        scheduler
                            .states
                            .iter()
                            .find(|row| row.slot == 1)
                            .unwrap()
                            .state,
                        emumee_core::scheduler::ThreadState::Running
                    ));
                    assert!(matches!(
                        scheduler
                            .states
                            .iter()
                            .find(|row| row.slot == 2)
                            .unwrap()
                            .state,
                        emumee_core::scheduler::ThreadState::Waiting { .. }
                    ));
                    assert_eq!(
                        result.api_calls,
                        if matches!(kind, I::LowerMutex) {
                            12
                        } else {
                            11
                        }
                    );
                    assert_eq!(threads.handles.len(), 1);
                    assert!(
                        threads
                            .threads
                            .iter()
                            .filter(|row| !matches!(row.role, Ownership::ParkedProcessor { .. }))
                            .all(|row| row.executing && !row.terminated && !row.retired)
                    );
                    assert!(!result.api_events.iter().any(|event| event.execution_domain
                        == "ipi_member"
                        && !matches!(
                            event.api.as_str(),
                            "ntoskrnl.KeGetCurrentProcessorNumberEx" | "ntoskrnl.KeGetCurrentIrql"
                        )));
                }
                if matches!(kind, I::DescriptorMutation) {
                    assert!(ipi.descriptor_guard_installed && ipi.descriptor_denials > 0);
                }
                for group in groups {
                    for member in &group.members {
                        if member.phase != Phase::Returned {
                            assert_eq!(member.result, None);
                        }
                    }
                }
                if matches!(kind, I::Invalid | I::HighIrql | I::Marker)
                    || matches!(kind, I::GroupBoundary) && architecture == Architecture::X86
                {
                    assert!(groups.is_empty());
                    assert_eq!(objects.objects.len(), 3);
                }
            } else {
                assert_eq!(result.error, None, "{architecture:?} {kind:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1));
                assert_eq!(result.completion_reason, "entry_return");
                assert!(!ipi.native_effect_failure);
                assert_eq!(ipi.current_processor, 0);
                assert!(ipi.rendezvous.active.is_none() && ipi.rendezvous.current.is_none());
                let logical = kind.logical();
                let group_count = if kind.repeated() { 2 } else { 1 };
                assert_eq!(groups.len(), group_count);
                let expected = if matches!(kind, I::Wide) && architecture == Architecture::X64 {
                    0x1234567800001234
                } else {
                    0x1234
                };
                let layout =
                    emumee_core::kernel_layout::KernelLayout::for_architecture(architecture);
                let source_thread = if matches!(kind, I::ChildCaller) {
                    layout.thread_object(2).unwrap()
                } else {
                    layout.root_thread
                };
                for group in groups {
                    assert!(group.completed);
                    assert_eq!(group.source_processor, 0);
                    assert_eq!(group.caller_thread, source_thread);
                    assert_eq!(group.members.len(), logical as usize);
                    assert_eq!(group.source_result, Some(expected));
                    for member in &group.members {
                        assert!(
                            member.started
                                && member.phase == Phase::Returned
                                && member.instruction_count > 0
                        );
                        assert_eq!(member.result, Some(expected + member.processor as u64));
                    }
                }
                let completed = result
                    .api_events
                    .iter()
                    .filter(|event| {
                        event.api == "ntoskrnl.KeIpiGenericCall"
                            && !event.pending
                            && event.effect == Some("ipi_broadcast_complete")
                    })
                    .collect::<Vec<_>>();
                assert_eq!(completed.len(), group_count);
                assert!(completed.iter().all(|event| event.result == Some(expected)
                    && event.execution_domain == "ordinary_thread"));
                let callbacks = result
                    .api_events
                    .iter()
                    .filter(|event| event.execution_domain == "ipi_member")
                    .collect::<Vec<_>>();
                assert_eq!(callbacks.len(), logical as usize * group_count * 3);
                assert!(
                    callbacks
                        .iter()
                        .all(|event| event.thread_id == 0 && event.processor < logical)
                );
                let parked = threads
                    .threads
                    .iter()
                    .filter(|entry| matches!(entry.role, Ownership::ParkedProcessor { .. }))
                    .collect::<Vec<_>>();
                assert_eq!(parked.len(), logical as usize - 1);
                for entry in parked {
                    assert_eq!(entry.slot, 0);
                    assert!(
                        !entry.root_caller
                            && !entry.executing
                            && !entry.terminated
                            && !entry.retired
                    );
                    assert_eq!(entry.open_handles, 0);
                    let record = objects
                        .objects
                        .iter()
                        .find(|record| record.address == entry.address)
                        .unwrap();
                    assert!(record.live);
                    assert_eq!((record.permanent_references, record.api_references), (1, 0));
                }
                assert_eq!(
                    objects.objects.len(),
                    logical as usize + 2 + usize::from(kind.child())
                );
                assert!(threads.handles.is_empty());
                let processors = ipi.processors.as_ref().unwrap();
                assert!(!processors.native_effect_failure);
                assert_eq!(processors.current_processor, 0);
                assert_eq!(processors.processors.len(), logical as usize);
                assert!(
                    processors
                        .processors
                        .iter()
                        .all(|processor| processor.prepared)
                );
                if matches!(kind, I::MsrIsolation) {
                    for processor in &processors.processors {
                        let number = processor.layout.processor as u64;
                        assert_eq!(processor.msrs.get(&0xc0000103), Some(&(0x80 + number)));
                        assert_eq!(processor.tsc_adjust, 0x100 + number);
                    }
                }
                if kind.child() {
                    let scheduler = result.kernel_threads.as_ref().unwrap();
                    assert_eq!(
                        (
                            scheduler.count,
                            scheduler.exited,
                            scheduler.open_thread_handles
                        ),
                        (2, 2, 0)
                    );
                } else {
                    assert!(result.kernel_threads.is_none());
                }
            }
        }
    }
}
#[test]
fn barrier_budget_prefixes_share_one_global_counter_and_never_complete_unreturned_members() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let full = run_api_fixture(architecture, ApiFixture::Ipi(I::Barrier), 100000).unwrap();
        assert_eq!(full.error, None);
        for budget in [1, 64, 512, full.instruction_count - 1] {
            let partial =
                run_api_fixture(architecture, ApiFixture::Ipi(I::Barrier), budget).unwrap();
            assert_eq!(
                partial.error, None,
                "{architecture:?} {budget}: {partial:#?}"
            );
            assert_eq!(partial.completion_reason, "instruction_budget");
            assert_eq!(partial.instruction_count, budget);
            assert_eq!(partial.guest_entry_return, None);
            let ipi = partial.kernel_ipi.as_ref().unwrap();
            for group in &ipi.rendezvous.broadcasts {
                if !group.completed {
                    assert_eq!(group.source_result, None);
                    for member in &group.members {
                        if member.phase != Phase::Returned {
                            assert_eq!(member.result, None);
                        }
                    }
                }
                assert!(
                    group
                        .members
                        .iter()
                        .map(|member| member.instruction_count)
                        .sum::<u64>()
                        <= partial.instruction_count
                );
            }
            for event in partial.api_events.iter().filter(|event| event.pending) {
                assert_eq!(event.result, None);
            }
            assert!(
                !partial
                    .kernel_thread_objects
                    .as_ref()
                    .unwrap()
                    .threads
                    .iter()
                    .find(|entry| entry.root_caller)
                    .unwrap()
                    .terminated
            );
        }
    }
}

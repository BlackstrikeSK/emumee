//! Owned programs execute their actual initializer instructions and return frames.
use super::*;
use emumee_core::{
    fixtures::{ApiFixture as A, LoaderFixture as F},
    modules::{ImagePhase, LoaderRoutine},
};
fn run(arch: Architecture, kind: F, budget: u64) -> Execution {
    run_api_fixture(arch, A::NativeLoader(kind), budget).unwrap()
}
fn names(report: &NativeLoaderReport) -> Vec<String> {
    report
        .events
        .iter()
        .map(|e| {
            report
                .images
                .iter()
                .find(|m| m.identity() == e.invocation.module)
                .map(|m| m.name.clone())
                .or_else(|| {
                    report
                        .retired_images
                        .iter()
                        .find(|m| m.id == e.invocation.module)
                        .map(|m| m.name.clone())
                })
                .unwrap()
        })
        .collect()
}
#[test]
fn actual_static_dll_tls_forwarder_and_primary_frames_complete_under_one_budget() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in F::ALL.into_iter().filter(|k| k.positive()) {
            let result = run(arch, kind, 10000);
            assert_eq!(
                result.completion_reason, "entry_return",
                "{arch:?}/{kind:?}: {result:#?}"
            );
            assert_eq!(
                result.guest_entry_return,
                Some(if kind == F::RootDll { 1 } else { 42 })
            );
            assert!(result.error.is_none());
            assert_eq!(result.api_calls, u64::from(kind == F::Basic));
            if kind == F::Basic {
                assert_eq!(result.api_events[0].api, "kernel32.GetModuleHandleA");
                assert_eq!(result.api_events[0].arguments, [0]);
                assert_eq!(result.api_events[0].result, Some(result.image_load.base));
            }
            let report = result.native_loader.as_ref().unwrap();
            assert_eq!(report.profile, "legacy-static-unwind-v1");
            assert!(report.preparation_error.is_none());
            assert!(report.native_effect_failure.is_none());
            assert!(report.retired_images.is_empty());
            assert!(
                report
                    .images
                    .iter()
                    .all(|m| m.lifecycle().unwrap().phase == ImagePhase::Ready
                        && m.lifecycle().unwrap().static_anchor)
            );
            assert!(report.events.iter().all(|e| e.returned_value.is_some()
                && e.failure.is_none()
                && e.stopped_instructions.is_some()));
            let expected = match kind {
                F::Basic => 1,
                F::Tls => 2,
                F::TlsOnly => 1,
                F::Nested => 4,
                F::Forwarded => 2,
                F::RootDll => 2,
                F::RootTls => 1,
                F::Entryless => 0,
                _ => unreachable!(),
            };
            assert_eq!(report.events.len(), expected);
            if matches!(kind, F::Nested | F::Forwarded) {
                let order = names(report);
                assert_eq!(order.first().unwrap(), "other.dll");
                assert_eq!(order.last().unwrap(), "guest.dll");
            }
            for e in &report.events {
                assert!(matches!(
                    e.invocation.routine,
                    LoaderRoutine::TlsAttach | LoaderRoutine::DllAttach
                ));
                assert_eq!(e.invocation.arguments[1], 1);
                assert_eq!(
                    e.invocation.arguments[2],
                    u64::from(
                        e.invocation.routine == LoaderRoutine::DllAttach && kind != F::RootDll
                    )
                );
            }
            let partial = run(arch, kind, result.instruction_count - 1);
            assert_eq!(
                partial.completion_reason, "instruction_budget",
                "{arch:?}/{kind:?}: {partial:#?}"
            );
            assert_eq!(partial.instruction_count, result.instruction_count - 1);
            assert!(partial.guest_entry_return.is_none());
            assert!(partial.error.is_none());
            assert!(
                partial
                    .native_loader
                    .as_ref()
                    .unwrap()
                    .retired_images
                    .is_empty()
            );
        }
    }
}
#[test]
fn failed_attach_fault_budget_and_refusal_preserve_exact_real_phase_prefixes() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in F::ALL.into_iter().filter(|k| !k.positive()) {
            let result = run(arch, kind, 10000);
            assert!(
                result.guest_entry_return.is_none(),
                "{arch:?}/{kind:?}: {result:#?}"
            );
            let report = result.native_loader.as_ref().unwrap();
            assert!(report.native_effect_failure.is_none());
            if kind.preparation_refusal() {
                assert_eq!(result.completion_reason, "error");
                assert_eq!(result.instruction_count, 0);
                assert_eq!(result.api_calls, 0);
                assert!(report.events.is_empty());
                assert!(report.preparation_error.is_some());
                assert!(report.retired_images.is_empty());
                continue;
            }
            assert!(report.preparation_error.is_none());
            if kind.budget() {
                assert_eq!(
                    result.completion_reason, "instruction_budget",
                    "{arch:?}/{kind:?}: {result:#?}"
                );
                assert_eq!(result.instruction_count, 10000);
                assert!(result.error.is_none());
                assert!(report.events.last().unwrap().returned_value.is_none());
                assert!(report.events.last().unwrap().failure.is_some());
            } else {
                assert_eq!(
                    result.completion_reason, "error",
                    "{arch:?}/{kind:?}: {result:#?}"
                );
                assert!(result.error.is_some());
            }
            match kind {
                F::False | F::NestedFalse | F::RootFalse => {
                    let nested = kind == F::NestedFalse;
                    assert_eq!(report.events.len(), if nested { 8 } else { 4 });
                    assert_eq!(report.retired_images.len(), if nested { 2 } else { 1 });
                    assert!(report.events.iter().all(|e| e.returned_value.is_some()));
                    assert!(
                        result
                            .error
                            .as_ref()
                            .unwrap()
                            .contains("DllMain returned FALSE")
                    );
                    let false_index = if nested { 3 } else { 1 };
                    assert_eq!(report.events[false_index].returned_value, Some(0));
                    assert_eq!(report.events[false_index + 1].invocation.arguments[2], 0);
                    assert_eq!(report.events[false_index + 2].invocation.arguments[2], 0);
                    if nested {
                        assert_eq!(report.events[7].invocation.arguments[2], 1);
                        assert_eq!(
                            names(report),
                            [
                                "other.dll",
                                "other.dll",
                                "guest.dll",
                                "guest.dll",
                                "guest.dll",
                                "guest.dll",
                                "other.dll",
                                "other.dll"
                            ]
                        );
                    }
                    if kind == F::RootFalse {
                        assert!(report.primary.is_none());
                    }
                }
                F::CleanupBudget => {
                    assert_eq!(report.events.len(), 8);
                    assert_eq!(report.events[3].returned_value, Some(0));
                    assert_eq!(report.retired_images.len(), 1);
                    assert_eq!(report.retired_images[0].name, "guest.dll");
                    assert!(report.images.iter().any(|m| m.name == "other.dll"
                        && m.lifecycle().unwrap().phase == ImagePhase::Interrupted));
                }
                F::AttachBudget | F::Fault | F::TlsMutation => {
                    assert_eq!(report.events.len(), 2);
                    assert!(report.events[0].returned_value.is_some());
                    assert!(report.events[1].returned_value.is_none());
                    assert!(report.retired_images.is_empty());
                    if kind == F::TlsMutation {
                        assert!(
                            result
                                .error
                                .as_ref()
                                .unwrap()
                                .contains("TLS callback directory/array differs")
                        );
                    }
                }
                F::BadStack | F::Nonvolatile => {
                    assert_eq!(report.events.len(), 1);
                    assert!(report.events[0].returned_value.is_none());
                    assert!(report.retired_images.is_empty());
                    assert!(
                        result
                            .error
                            .as_ref()
                            .unwrap()
                            .contains(if kind == F::BadStack {
                                "stack return contract"
                            } else {
                                "protected/nonvolatile register"
                            })
                    );
                }
                F::DetachFault => {
                    assert_eq!(report.events.len(), 3);
                    assert_eq!(report.events[1].returned_value, Some(0));
                    assert!(report.events[2].returned_value.is_none());
                    assert!(report.retired_images.is_empty());
                }
                _ => unreachable!(),
            }
        }
    }
}

#[test]
fn a_real_nonreturning_initializer_obeys_the_single_wall_horizon_without_fake_cleanup() {
    for arch in [Architecture::X86, Architecture::X64] {
        let (root, companions) = emumee_core::fixtures::native_loader_probe(arch, F::AttachBudget);
        let result =
            run_generated_modules(&root, &companions, 1_000_000_000, 100_000, None).unwrap();
        assert_eq!(result.completion_reason, "timeout", "{arch:?}: {result:#?}");
        assert!(result.instruction_count < result.max_instructions);
        assert!(result.guest_entry_return.is_none());
        assert!(result.error.is_none());
        let report = result.native_loader.unwrap();
        assert_eq!(report.events.len(), 2);
        assert!(report.events[0].returned_value.is_some());
        assert!(report.retired_images.is_empty());
        assert!(report.events.iter().all(|e| matches!(
            e.invocation.routine,
            LoaderRoutine::TlsAttach | LoaderRoutine::DllAttach
        )));
        assert!(report.events.last().unwrap().returned_value.is_none());
    }
}

#[test]
fn kernel_export_only_companions_never_gain_user_initializer_execution() {
    for arch in [Architecture::X86, Architecture::X64] {
        let (root, mut companions) =
            emumee_core::fixtures::linked_probe(arch, emumee_core::fixtures::LinkedFixture::Direct);
        companions[0].1[0xa8..0xac].copy_from_slice(&0x1000u32.to_le_bytes());
        let result = run_generated_modules(&root, &companions, 10000, 30_000_000, None).unwrap();
        assert_eq!(result.guest_entry_return, None);
        assert_eq!(result.instruction_count, 0);
        assert!(
            result
                .error
                .as_deref()
                .unwrap()
                .contains("Kernel static companion initialization is not modeled")
        );
    }
}

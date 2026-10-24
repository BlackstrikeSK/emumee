//! Actual harmless VFS -> DLL -> ABI frames -> export -> detach/unmap programs.
use super::*;
use emumee_core::{
    fixtures::{ApiFixture as A, DynamicLoaderFixture as F},
    modules::{DynamicPhase, LoaderRoutine},
};
fn run(arch: Architecture, kind: F, budget: u64) -> Execution {
    run_api_fixture(arch, A::DynamicLoader(kind), budget).unwrap()
}
fn report(e: &Execution) -> &DynamicLoaderReport {
    e.dynamic_loader.as_ref().unwrap()
}
fn structural(kind: F) -> bool {
    matches!(
        kind,
        F::LdrBadBounds
            | F::LdrBadMaximum
            | F::LdrBadOutput
            | F::LdrFlags
            | F::LdrNull
            | F::LdrCountedNul
    )
}
#[test]
fn genuine_vfs_dll_load_use_retention_unload_and_nt_abi_programs_return() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in F::ALL.into_iter().filter(|k| k.positive()) {
            let e = run(arch, kind, 10000);
            assert_eq!(
                e.completion_reason, "entry_return",
                "{arch:?}/{kind:?}: {e:#?}"
            );
            assert_eq!(e.guest_entry_return, Some(42));
            assert!(e.error.is_none());
            assert!(e.kernel_threads.is_none() && e.kernel_ipi.is_none());
            if structural(kind) {
                assert!(e.dynamic_loader.is_none());
                continue;
            }
            let r = report(&e);
            assert_eq!(r.profile, "bounded-vfs-leaf-dll-v1");
            assert!(r.pending_api.is_none());
            assert!(r.state.active.is_none());
            assert!(r.native_effect_failure.is_none());
            assert_eq!(r.requests, r.resumed);
            assert_eq!(r.state.owner, Some(1024));
            assert!(r.state.routines.iter().all(|s| {
                s.returned_value.is_some()
                    && s.failure.is_none()
                    && s.stopped_instructions
                        .is_some_and(|n| n >= s.started_instructions && n <= e.instruction_count)
            }));
            assert!(
                e.api_events
                    .iter()
                    .filter(|event| event.effect == Some("dynamic_loader_return_ready"))
                    .all(|event| !event.pending && event.result.is_some())
            );
            let retired = if matches!(kind, F::Missing | F::Malformed | F::StaticRetain) {
                0
            } else if matches!(kind, F::Reload | F::Dependency | F::Forwarder) {
                2
            } else {
                1
            };
            assert_eq!(r.state.retired.len(), retired, "{arch:?}/{kind:?}");
            for image in &r.state.retired {
                assert!(
                    !e.loaded_modules
                        .iter()
                        .any(|m| m.name == image.name && m.base == image.base)
                );
                assert_eq!(image.image.owner, 1024);
                assert_eq!(image.image.phase, DynamicPhase::Detaching);
            }
        }
    }
}
#[test]
fn real_dll_false_executes_own_cleanup_and_ldr_reports_deferred_failure() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::False, F::LdrFalse] {
            let e = run(arch, kind, 10000);
            assert_eq!(e.guest_entry_return, Some(42), "{e:#?}");
            let r = report(&e);
            assert_eq!(r.state.routines.len(), 4);
            assert_eq!(r.state.retired.len(), 1);
            assert_eq!(
                r.state.routines[1].invocation.routine,
                LoaderRoutine::DllAttach
            );
            assert_eq!(r.state.routines[1].returned_value, Some(0));
            assert_eq!(
                r.state.routines[2].invocation.routine,
                LoaderRoutine::TlsDetach
            );
            assert_eq!(
                r.state.routines[3].invocation.routine,
                LoaderRoutine::DllDetach
            );
            assert!(
                r.state
                    .routines
                    .iter()
                    .all(|s| s.invocation.arguments[2] == 0)
            );
            let api = e
                .api_events
                .iter()
                .find(|event| event.effect == Some("dynamic_loader_return_ready"))
                .unwrap();
            assert_eq!(
                api.result,
                Some(if kind == F::LdrFalse { 0xc0000142 } else { 0 })
            );
            assert_eq!(api.last_error, 1114);
            assert!(e.native_loader.as_ref().is_none_or(|s| s.events.is_empty()));
        }
    }
}
#[test]
fn actual_iat_and_late_forwarder_edges_hold_then_cascade_same_catalog_images() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::Dependency, F::Forwarder] {
            let e = run(arch, kind, 10000);
            assert_eq!(e.guest_entry_return, Some(42), "{e:#?}");
            let r = report(&e);
            assert_eq!(
                r.state
                    .retired
                    .iter()
                    .map(|m| m.name.as_str())
                    .collect::<Vec<_>>(),
                ["guest.dll", "other.dll"]
            );
            let owner = r.state.retired[0].id;
            let target = r.state.retired[1].id;
            assert_eq!(r.state.retired[0].released_dependencies, [target]);
            if kind == F::Dependency {
                assert_eq!(r.state.retired[0].image.dependencies, [target]);
            } else {
                assert!(
                    r.state.events.iter().any(|e| e.module == owner
                        && e.kind == "followed_forwarder_dependencies_acquired")
                );
            }
            assert!(r.state.events.iter().any(|event| event.module == target
                && event.kind == "api_reference_released"
                && event.api_references == 0));
            assert_eq!(r.state.routines.len(), 4);
            assert_eq!(r.state.routines[2].invocation.module, owner);
            assert_eq!(r.state.routines[3].invocation.module, target);
        }
    }
}
#[test]
fn static_process_anchor_retains_identity_and_reload_gets_a_fresh_generation() {
    for arch in [Architecture::X86, Architecture::X64] {
        let e = run(arch, F::StaticRetain, 10000);
        assert_eq!(e.guest_entry_return, Some(42), "{e:#?}");
        let r = report(&e);
        assert!(r.state.routines.is_empty() && r.state.retired.is_empty());
        let module = e
            .native_loader
            .as_ref()
            .unwrap()
            .images
            .iter()
            .find(|m| m.name == "guest.dll")
            .unwrap();
        assert_eq!(module.api_references(), 0);
        assert!(module.lifecycle().unwrap().static_anchor);
        assert_eq!(e.native_loader.as_ref().unwrap().events.len(), 1);
        let e = run(arch, F::Reload, 10000);
        assert_eq!(e.guest_entry_return, Some(42), "{e:#?}");
        let retired = &report(&e).state.retired;
        assert_eq!(retired.len(), 2);
        assert_eq!(retired[0].base, retired[1].base);
        assert!(retired[0].id < retired[1].id);
        assert_eq!(
            retired[0]
                .provenance
                .as_ref()
                .unwrap()
                .accepted_image_sha256,
            retired[1]
                .provenance
                .as_ref()
                .unwrap()
                .accepted_image_sha256
        );
    }
}
#[test]
fn shared_horizon_preserves_pending_call_and_actual_attach_detach_return_prefixes() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::AttachBudget, F::DetachBudget] {
            let e = run(arch, kind, 2000);
            assert_eq!(
                e.completion_reason, "instruction_budget",
                "{arch:?}/{kind:?}: {e:#?}"
            );
            assert_eq!(e.instruction_count, 2000);
            assert_eq!(e.guest_entry_return, None);
            assert!(e.error.is_none());
            let r = report(&e);
            assert!(r.pending_api.is_some());
            assert_eq!(r.pending_result, None);
            assert!(r.state.retired.is_empty());
            assert!(r.state.active.as_ref().unwrap().interrupted);
            let last = r.state.routines.last().unwrap();
            assert_eq!(last.returned_value, None);
            assert!(last.failure.as_ref().unwrap().contains("horizon"));
            assert!(e.api_events.iter().any(|e| e.pending
                && e.result.is_none()
                && e.effect == Some("dynamic_loader_pending")));
            assert_eq!(
                r.state.routines.len(),
                if kind == F::AttachBudget { 2 } else { 4 }
            );
            assert_eq!(r.images[0].api_references(), 0);
        }
    }
    // Exact budget at successful attach's real callback-return boundary stops
    // before the suspended API RET; ready image/reference and pending API differ.
    for arch in [Architecture::X86, Architecture::X64] {
        let full = run(arch, F::Tls, 10000);
        let boundary = report(&full)
            .state
            .events
            .iter()
            .find(|e| e.kind == "caller_api_result_published")
            .unwrap()
            .instruction;
        let e = run(arch, F::Tls, boundary);
        assert_eq!(e.completion_reason, "instruction_budget", "{e:#?}");
        assert_eq!(e.instruction_count, boundary);
        let r = report(&e);
        assert!(r.pending_api.is_some());
        assert!(r.state.active.as_ref().unwrap().returning);
        assert_eq!(
            r.images[0].dynamic_image().unwrap().phase,
            DynamicPhase::Ready
        );
        assert_eq!(r.images[0].api_references(), 1);
        assert!(e.api_events.iter().any(|e| e.pending && e.result.is_none()));
    }
}
#[test]
fn actual_fault_reentrancy_storage_nx_and_missing_dependency_never_complete_a_load() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [
            F::Fault,
            F::Reentry,
            F::StorageTls,
            F::NxCallback,
            F::MissingDependency,
            F::Flags,
        ] {
            let e = run(arch, kind, 10000);
            assert_eq!(e.completion_reason, "error", "{arch:?}/{kind:?}: {e:#?}");
            assert_eq!(e.guest_entry_return, None);
            assert!(e.error.is_some());
            if kind == F::Flags {
                assert!(e.dynamic_loader.is_none());
                continue;
            }
            let r = report(&e);
            assert!(r.pending_api.is_some());
            assert_eq!(r.pending_result, None);
            assert!(r.state.retired.is_empty());
            assert!(r.images.iter().all(|m| m.api_references() == 0));
            if matches!(kind, F::Fault | F::Reentry) {
                assert!(
                    r.state.active.as_ref().is_some_and(|a| a.interrupted),
                    "{arch:?}/{kind:?}: {e:#?}"
                );
                assert_eq!(r.state.routines.last().unwrap().returned_value, None);
            } else {
                assert!(r.state.routines.is_empty());
                assert!(r.images.is_empty());
            }
        }
    }
}
#[test]
fn real_callback_output_permission_change_preserves_acquired_ref_and_unmapped_export_faults() {
    for arch in [Architecture::X86, Architecture::X64] {
        let e = run(arch, F::LdrOutputReadonly, 10000);
        assert_eq!(e.completion_reason, "error", "{e:#?}");
        assert!(e.error.as_ref().unwrap().contains("lacks permission2"));
        let r = report(&e);
        assert!(r.pending_api.is_some());
        assert_eq!(r.pending_result, None);
        assert_eq!(r.images.len(), 1);
        assert_eq!(r.images[0].api_references(), 1);
        assert_eq!(
            r.images[0].dynamic_image().unwrap().phase,
            DynamicPhase::Ready
        );
        assert!(r.state.retired.is_empty());
        assert!(r.state.routines.iter().all(|e| e.returned_value.is_some()));
        assert!(
            e.api_events
                .iter()
                .any(|e| e.api == "ntdll.LdrLoadDll" && e.pending && e.result.is_none())
        );
        let e = run(arch, F::UnmappedFetch, 10000);
        assert_eq!(e.completion_reason, "error", "{e:#?}");
        assert_eq!(e.guest_entry_return, None);
        let r = report(&e);
        assert!(r.pending_api.is_none());
        assert_eq!(r.state.retired.len(), 1);
        assert!(r.state.active.is_none());
        assert!(r.images.is_empty());
        assert!(e.error.as_ref().unwrap().contains("FETCH_UNMAPPED"));
    }
}

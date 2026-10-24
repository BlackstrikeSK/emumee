use super::*;
use emumee_core::fixtures::{ApiFixture, ProviderMixedFixture as P};
#[test]
fn modeled_kernel_imports_resolve_and_execute_after_provider_rebinding_with_owned_lifecycle() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let result =
            run_api_fixture(architecture, ApiFixture::ProviderMixed(P::Lifecycle), 10000).unwrap();
        assert_eq!(result.error, None, "{architecture:?}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1));
        assert_eq!(result.api_calls, 37);
        assert_eq!(result.completion_reason, "entry_return");
        assert!(!result.synthetic_providers.is_empty());
        assert!(result.provider_denials.is_empty());
        let resolves = result
            .api_events
            .iter()
            .filter(|event| event.api == "ntoskrnl.MmGetSystemRoutineAddress")
            .collect::<Vec<_>>();
        assert_eq!(resolves.len(), 19);
        assert!(
            resolves
                .iter()
                .all(|event| event.result.is_some_and(|address| address != 0))
        );
        let mdl = result.kernel_mdls.as_ref().unwrap();
        assert!(!mdl.native_effect_failure);
        assert_eq!(mdl.owned_backing_pages, 0);
        assert!(mdl.model.descriptors().is_empty() && mdl.model.aliases().is_empty());
        let rundown = result.kernel_cache_aware_rundown.as_ref().unwrap();
        assert!(!rundown.native_effect_failure);
        assert!(rundown.references.is_empty() && rundown.blocked_teardowns.is_empty());
        let callback = result.kernel_callbacks.as_ref().unwrap();
        assert!(!callback.native_effect_failure);
        assert!(callback.owned_list_head_initialized && callback.bugcheck.registered.is_empty());
        assert_eq!(callback.bugcheck.callbacks_executed, 0);
        assert_eq!(callback.named.callbacks_executed, 0);
        let pool = result.kernel_pool.as_ref().unwrap();
        assert!(pool.allocations.is_empty());
        assert_eq!(pool.total_allocations, pool.total_frees);
        assert!(result.artifacts.is_empty());
        assert_eq!(result.network.calls, 0);
        let partial = run_api_fixture(
            architecture,
            ApiFixture::ProviderMixed(P::Lifecycle),
            result.instruction_count - 1,
        )
        .unwrap();
        assert_eq!(partial.error, None);
        assert_eq!(partial.completion_reason, "instruction_budget");
        assert_eq!(partial.guest_entry_return, None);
        assert_eq!(partial.api_calls, 37);
    }
}
#[test]
fn publishing_modeled_delegates_preserves_unmodeled_catalog_code_protection() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let result = run_api_fixture(
            architecture,
            ApiFixture::ProviderMixed(P::UnmodeledCode),
            10000,
        )
        .unwrap();
        assert_eq!(result.api_calls, 38, "{architecture:?}: {result:#?}");
        if architecture == Architecture::X64 {
            assert_eq!(result.guest_entry_return, None);
            assert_eq!(result.completion_reason, "error");
            assert!(result.error.as_deref().unwrap().contains("FETCH_PROT"));
            assert!(
                result
                    .provider_denials
                    .iter()
                    .any(|row| row.name == "KeInsertQueueDpc" && row.kind == "code")
            );
        } else {
            assert_eq!(result.completion_reason, "error");
            assert_eq!(result.guest_entry_return, None);
            assert!(
                result
                    .error
                    .as_deref()
                    .unwrap()
                    .contains("Unmodeled synthetic provider export")
            );
            assert_eq!(result.api_events.last().unwrap().result, None);
        }
        assert!(
            result
                .kernel_cache_aware_rundown
                .as_ref()
                .unwrap()
                .references
                .is_empty()
        );
        assert!(
            result
                .kernel_callbacks
                .as_ref()
                .unwrap()
                .bugcheck
                .registered
                .is_empty()
        );
    }
}

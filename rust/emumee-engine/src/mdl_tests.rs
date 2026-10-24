use super::*;
use emumee_core::fixtures::{ApiFixture, MdlFixture as F};
#[test]
fn mdl_generated_kernel_callers_check_geometry_pfn_coherence_and_lifecycle() {
    for arch in [Architecture::X86, Architecture::X64] {
        for fixture in [F::Lifecycle, F::Alias] {
            let result = run_api_fixture(arch, ApiFixture::Mdl(fixture), 2000).unwrap();
            assert_eq!(result.error, None, "{arch:?} {fixture:?}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(1));
            assert_eq!(result.network.calls, 0);
            assert!(result.kernel_mdls.is_some());
            assert!(!result.kernel_mdls.as_ref().unwrap().native_effect_failure);
            for budget in 1..result.instruction_count {
                let partial = run_api_fixture(arch, ApiFixture::Mdl(fixture), budget).unwrap();
                assert_eq!(
                    partial.error, None,
                    "{arch:?} {fixture:?}/{budget}: {:?}",
                    partial.error
                );
                assert_eq!(partial.completion_reason, "instruction_budget");
                assert_eq!(partial.guest_entry_return, None);
            }
        }
        for fixture in [
            F::ReadOnlyCpu,
            F::ReadOnlyApi,
            F::Nx,
            F::Unmapped,
            F::FreeActive,
            F::PoolFreeActive,
            F::Flags,
            F::Geometry,
            F::Unbuilt,
        ] {
            let result = run_api_fixture(arch, ApiFixture::Mdl(fixture), 2000).unwrap();
            assert!(result.error.is_some(), "{arch:?} {fixture:?}: {result:#?}");
            assert_eq!(result.completion_reason, "error");
            assert_eq!(result.guest_entry_return, None);
            assert!(result.kernel_mdls.is_some());
        }
    }
}

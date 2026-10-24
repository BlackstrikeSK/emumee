use super::*;
use emumee_core::fixtures::{ApiFixture, Cr8Fixture as C};
#[test]
fn actual_guest_mov_cr8_preserves_flags_extended_gprs_pcr_api_and_decoder_invalidation() {
    for kind in [C::Lifecycle, C::Extended, C::SelfModify] {
        let result = run_api_fixture(Architecture::X64, ApiFixture::Cr8(kind), 3000).unwrap();
        assert_eq!(result.error, None, "{kind:?}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1));
        assert_eq!(result.api_calls, 2);
        assert_eq!(result.api_events[0].result, Some(13));
        assert_eq!(result.api_events[1].result, Some(0));
        assert_eq!(result.kernel_state.as_ref().unwrap().irql, 0);
        assert_eq!(result.kernel_cpu.as_ref().unwrap().pcr_irql, 0);
        assert_eq!(result.cpu.cr8_writes, 2);
        assert!(result.cpu.cr8_reads >= 2);
        let partial = run_api_fixture(
            Architecture::X64,
            ApiFixture::Cr8(kind),
            result.instruction_count - 1,
        )
        .unwrap();
        assert_eq!(partial.error, None);
        assert_eq!(partial.completion_reason, "instruction_budget");
        assert_eq!(partial.guest_entry_return, None);
    }
}
#[test]
fn reserved_cr8_bits_and_non_driver_context_refuse_before_state_or_api_effects() {
    for (kind, message) in [
        (C::Invalid, "MOV CR8 value has reserved bits"),
        (C::UserMode, "MOV CR8 requires an initialized CPL0 driver"),
    ] {
        let result = run_api_fixture(Architecture::X64, ApiFixture::Cr8(kind), 3000).unwrap();
        assert_eq!(result.completion_reason, "error");
        assert_eq!(result.guest_entry_return, None);
        assert!(
            result.error.as_deref().unwrap().contains(message),
            "{kind:?}: {result:#?}"
        );
        assert_eq!(result.api_calls, 0);
        assert_eq!(result.cpu.cr8_writes, 0);
        if let Some(kernel) = &result.kernel_cpu {
            assert_eq!(kernel.pcr_irql, 0);
            assert_eq!(result.kernel_state.as_ref().unwrap().irql, 0);
        }
    }
}

use super::*;
use emumee_core::fixtures::{ApiFixture, TimeFixture as F};
const POSITIVE: [F; 11] = [
    F::Local,
    F::Fields,
    F::Signed,
    F::Bounds,
    F::AliasLocal,
    F::PartialLocal,
    F::AliasFields,
    F::PartialFields,
    F::ResidentHigh,
    F::ConfiguredPositive,
    F::ConfiguredNegative,
];
const NEGATIVE: [F; 10] = [
    F::LocalOverflow,
    F::CalendarLow,
    F::CalendarHigh,
    F::ReadonlyLocal,
    F::ReadonlyFields,
    F::CrossPageLocal,
    F::CrossPageFields,
    F::UnmappedInput,
    F::PagedInput,
    F::PagedOutput,
];
fn metadata(result: &Execution, arch: Architecture, kind: F) {
    let rtl = result.kernel_rtl.as_ref().unwrap();
    assert!(!rtl.native_effect_failure, "{arch:?} {kind:?}");
    assert!(rtl.events.is_empty() && rtl.owned.is_empty() && rtl.formatting.is_empty());
    assert_eq!(
        (
            rtl.lifetime_allocations,
            rtl.events_omitted,
            rtl.formatting_omitted,
            rtl.capture_errors
        ),
        (0, 0, 0, 0)
    );
    let pool = result.kernel_pool.as_ref().unwrap();
    let paged = matches!(kind, F::PagedInput | F::PagedOutput);
    assert_eq!(pool.total_allocations, u64::from(paged));
    assert_eq!(pool.total_frees, 0);
    assert_eq!(pool.allocations.len(), usize::from(paged));
    assert_eq!(result.api_events_omitted, 0);
    assert!(
        result.api_events.iter().all(|e| e.last_error == 0x12345678
            && e.thread_id == 1
            && e.execution_domain == "ordinary_thread"),
        "{arch:?} {kind:?}: {:?}",
        result.api_events
    );
    assert_eq!(result.kernel_state.as_ref().unwrap().irql, kind.irql());
    if arch == Architecture::X64 {
        assert_eq!(result.cpu.cr8_writes, u64::from(kind.irql() != 0));
    }
    assert!(result.artifacts.is_empty());
    assert_eq!(result.network.calls, 0);
    if kind.configured_offset().is_some() {
        let receipt = result.configuration.as_ref().unwrap();
        assert!(receipt.generated_only && receipt.initialized);
        assert_eq!(receipt.windows_build, 26100);
        assert_eq!(receipt.initial_processor, 0);
        assert!(receipt.user_process_owner.is_none());
        assert!(receipt.installed_components.contains(&"native_guest_clock"));
        assert_eq!(receipt.effective_sha256.len(), 64);
    } else {
        assert!(result.configuration.is_none());
    }
}
#[test]
fn real_generated_kernel_conversions_check_all_bytes_poison_abi_and_configured_offsets() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in POSITIVE {
            let result =
                run_api_fixture(arch, ApiFixture::KernelTimeConversion(kind), 20000).unwrap();
            assert_eq!(result.error, None, "{arch:?} {kind:?}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(17), "{arch:?} {kind:?}");
            assert_eq!(result.completion_reason, "entry_return");
            metadata(&result, arch, kind);
            assert!(result.api_events.iter().all(|e| e.error.is_none()));
            let last = result.api_events.last().unwrap();
            assert!(last.api.ends_with(".GetLastError"));
            assert_eq!(last.result, Some(0x12345678));
            let calls = result
                .api_events
                .iter()
                .filter(|e| {
                    e.api.ends_with(".RtlTimeToTimeFields")
                        || e.api.ends_with(".ExSystemTimeToLocalTime")
                })
                .count();
            assert!(
                result
                    .api_events
                    .iter()
                    .filter(|e| e.api.ends_with(".RtlTimeToTimeFields")
                        || e.api.ends_with(".ExSystemTimeToLocalTime"))
                    .all(|e| e.result.is_none()),
                "{arch:?} {kind:?}: void result must remain absent"
            );
            let expected = match kind {
                F::Fields => 4,
                F::Signed => 3,
                F::Bounds
                | F::Local
                | F::ResidentHigh
                | F::ConfiguredPositive
                | F::ConfiguredNegative => 2,
                _ => 1,
            };
            assert_eq!(calls, expected, "{arch:?} {kind:?}");
        }
    }
}
#[test]
fn generated_signed_bounds_preflight_and_real_irql_paged_refusals_never_fabricate_status_or_return()
{
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in NEGATIVE {
            let result =
                run_api_fixture(arch, ApiFixture::KernelTimeConversion(kind), 20000).unwrap();
            assert!(
                result
                    .error
                    .as_deref()
                    .unwrap()
                    .contains(kind.error().unwrap()),
                "{arch:?} {kind:?}: {result:#?}"
            );
            assert_eq!(result.guest_entry_return, None);
            assert_eq!(result.completion_reason, "error");
            metadata(&result, arch, kind);
            assert!(result.api_events.last().unwrap().error.is_some());
            assert!(
                !result
                    .api_events
                    .iter()
                    .any(|e| e.api.ends_with(".GetLastError"))
            );
        }
    }
}
#[test]
fn exact_before_return_prefix_keeps_actual_effects_and_configured_receipt_without_entry_success() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in POSITIVE {
            let full =
                run_api_fixture(arch, ApiFixture::KernelTimeConversion(kind), 20000).unwrap();
            assert_eq!(
                full.guest_entry_return,
                Some(17),
                "{arch:?} {kind:?}: {full:#?}"
            );
            let budget = full.instruction_count - 1;
            let prefix =
                run_api_fixture(arch, ApiFixture::KernelTimeConversion(kind), budget).unwrap();
            assert_eq!(prefix.error, None, "{arch:?} {kind:?}: {prefix:#?}");
            assert_eq!(prefix.completion_reason, "instruction_budget");
            assert_eq!(prefix.guest_entry_return, None);
            assert_eq!(prefix.instruction_count, budget);
            metadata(&prefix, arch, kind);
        }
    }
}

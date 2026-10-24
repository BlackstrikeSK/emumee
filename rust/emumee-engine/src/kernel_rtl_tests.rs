use super::*;
use emumee_core::fixtures::{ApiFixture, RtlFixture as F};
const POSITIVE: [F; 13] = [
    F::Strings,
    F::Init,
    F::FlagsEmpty,
    F::Counted,
    F::InvalidDescriptor,
    F::Overflow,
    F::Lifecycle,
    F::GenericFree,
    F::FormatSecure,
    F::FormatSecureSmall,
    F::FormatList,
    F::FormatListExact,
    F::FormatListSmall,
];
const NEGATIVE: [F; 13] = [
    F::BorrowedFree,
    F::InteriorFree,
    F::StaleFree,
    F::SameTagReuse,
    F::ReadonlyOutput,
    F::CrossPageOutput,
    F::IrqlDuplicate,
    F::IrqlFree,
    F::IrqlPagedRead,
    F::FormatUnsupported,
    F::ReadonlyFormat,
    F::RetiredRead,
    F::RetiredExecute,
];
fn metadata(result: &Execution, arch: Architecture, kind: F) {
    let report = result.kernel_rtl.as_ref().unwrap();
    let pool = result.kernel_pool.as_ref().unwrap();
    assert_eq!(report.lifetime_limit, 4096);
    assert!(
        !report.native_effect_failure,
        "{arch:?} {kind:?}: {report:#?}"
    );
    assert_eq!(report.events_omitted, 0);
    assert_eq!(report.formatting_omitted, 0);
    assert_eq!(report.capture_errors, 0);
    let owned = matches!(
        kind,
        F::FlagsEmpty
            | F::Counted
            | F::Lifecycle
            | F::GenericFree
            | F::InteriorFree
            | F::StaleFree
            | F::SameTagReuse
            | F::IrqlFree
            | F::IrqlPagedRead
            | F::RetiredRead
            | F::RetiredExecute
    );
    let live = matches!(kind, F::InteriorFree | F::IrqlFree | F::IrqlPagedRead);
    assert_eq!(
        report.lifetime_allocations,
        u64::from(owned),
        "{arch:?} {kind:?}"
    );
    assert_eq!(
        report.live_allocations,
        usize::from(live),
        "{arch:?} {kind:?}"
    );
    assert_eq!(report.owned.len(), usize::from(owned));
    assert_eq!(
        pool.total_allocations,
        u64::from(owned) + u64::from(matches!(kind, F::SameTagReuse))
    );
    assert_eq!(pool.total_frees, u64::from(owned && !live));
    assert_eq!(
        pool.allocations.len(),
        usize::from(live || matches!(kind, F::SameTagReuse))
    );
    for record in &report.owned {
        assert!(record.initialized);
        assert_eq!(record.live, live);
        assert_eq!(record.allocation_ordinal, 1);
        if arch == Architecture::X64 {
            assert!(record.base > u32::MAX as u64);
        }
    }
    assert_eq!(
        report.formatting.len(),
        usize::from(kind.formatting() && !kind.negative())
    );
    for output in &report.formatting {
        assert_eq!(output.raw_utf16_sha256.len(), 64);
        assert!(output.captured_units <= 1024);
        assert!(output.text.encode_utf16().count() <= 1024);
    }
    assert_eq!(result.api_events_omitted, 0);
    assert!(
        result.api_events.iter().all(|e| e.last_error == 0x12345678
            && e.thread_id == 1
            && e.execution_domain == "ordinary_thread"),
        "{arch:?} {kind:?}: {:?}",
        result.api_events
    );
    assert_eq!(result.network.calls, 0);
    assert!(result.artifacts.is_empty());
}
#[test]
fn real_ntos_unicode_pool_lifetimes_crt_bytes_and_fixed_variadic_abis_match_guest_assertions() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in POSITIVE {
            let result = run_api_fixture(arch, ApiFixture::KernelRtl(kind), 20000).unwrap();
            assert_eq!(result.error, None, "{arch:?} {kind:?}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(17), "{arch:?} {kind:?}");
            assert_eq!(result.completion_reason, "entry_return");
            metadata(&result, arch, kind);
            assert!(result.api_events.iter().all(|e| e.error.is_none()));
            let last = result.api_events.last().unwrap();
            assert!(last.api.ends_with(".GetLastError"));
            assert_eq!(last.result, Some(0x12345678));
            let report = result.kernel_rtl.as_ref().unwrap();
            if matches!(kind, F::Init) {
                assert_eq!(report.events.len(), 2);
                assert_eq!((report.events[0].length, report.events[0].maximum), (8, 10));
                assert_eq!(report.events[1].buffer, 0);
            }
            if matches!(kind, F::Counted) {
                assert_eq!((report.events[0].length, report.events[0].maximum), (6, 8));
            }
            if matches!(kind, F::InvalidDescriptor | F::Overflow) {
                assert_eq!(report.events.len(), 1);
                assert_eq!(report.events[0].status, 0xc000000d);
            }
            if kind.formatting() {
                let output = &report.formatting[0];
                let short = matches!(kind, F::FormatSecureSmall | F::FormatListSmall);
                assert_eq!(output.truncated, short);
                if short {
                    assert_eq!(output.result, -1);
                }
                if matches!(kind, F::FormatSecureSmall) {
                    assert_eq!(output.text, "");
                }
                if matches!(kind, F::FormatListSmall) {
                    assert_eq!(output.text, "-46");
                }
            }
        }
    }
}
#[test]
fn borrowed_unknown_reused_or_retired_buffers_protected_outputs_irql_and_unported_formats_stop_honestly()
 {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in NEGATIVE {
            let result = run_api_fixture(arch, ApiFixture::KernelRtl(kind), 20000).unwrap();
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
            if matches!(kind, F::IrqlDuplicate | F::IrqlFree | F::IrqlPagedRead) {
                assert_eq!(result.kernel_state.as_ref().unwrap().irql, 2);
                if arch == Architecture::X64 {
                    assert_eq!(result.cpu.cr8_writes, 1);
                }
            }
            if matches!(kind, F::RetiredRead | F::RetiredExecute) {
                assert!(result.api_events.iter().all(|e| e.error.is_none()));
            }
        }
    }
}
#[test]
fn every_positive_rtl_exact_before_return_prefix_retains_effects_without_inventing_entry_completion()
 {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in POSITIVE {
            let full = run_api_fixture(arch, ApiFixture::KernelRtl(kind), 20000).unwrap();
            assert_eq!(
                full.guest_entry_return,
                Some(17),
                "{arch:?} {kind:?}: {full:#?}"
            );
            let budget = full.instruction_count - 1;
            let prefix = run_api_fixture(arch, ApiFixture::KernelRtl(kind), budget).unwrap();
            assert_eq!(prefix.error, None, "{arch:?} {kind:?}: {prefix:#?}");
            assert_eq!(prefix.completion_reason, "instruction_budget");
            assert_eq!(prefix.guest_entry_return, None);
            assert_eq!(prefix.instruction_count, budget);
            metadata(&prefix, arch, kind);
        }
    }
}

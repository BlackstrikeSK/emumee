use super::*;
use emumee_core::fixtures::{ApiFixture, CrtFixture as F};
#[test]
fn crt_cdecl_memory_strings_unsigned_units_page_edges_and_rewrite_are_guest_effects() {
    for arch in [Architecture::X86, Architecture::X64] {
        for fixture in [
            F::Copy,
            F::Memory,
            F::Strings,
            F::Wide,
            F::Boundary,
            F::Rewrite,
        ] {
            let result = run_api_fixture(arch, ApiFixture::Crt(fixture), 1000).unwrap();
            assert_eq!(result.error, None, "{arch:?} {fixture:?}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(1));
            assert!(result.artifacts.is_empty());
            assert_eq!(result.network.calls, 0);
            assert!(result.api_events.iter().all(|e| e.last_error == 0));
        }
        for (fixture, error) in [
            (F::StringOverlap, "overlapping"),
            (F::CopyInvalid, "invalid-parameter"),
            (F::ReadFault, "lacks permission"),
            (F::WriteFault, "lacks permission"),
            (F::Overlap, "overlapping"),
            (F::Overflow, "CRT transfer count"),
        ] {
            let result = run_api_fixture(arch, ApiFixture::Crt(fixture), 1000).unwrap();
            assert_eq!(result.completion_reason, "error");
            assert!(
                result.error.as_deref().unwrap().contains(error),
                "{arch:?} {fixture:?}: {:?}",
                result.error
            );
            assert_eq!(result.guest_entry_return, None);
        }
    }
}
#[test]
fn crt_cdecl_calls_and_self_modification_obey_every_instruction_budget_prefix() {
    for arch in [Architecture::X86, Architecture::X64] {
        for fixture in [F::Copy, F::Memory, F::Boundary, F::Rewrite] {
            let full = run_api_fixture(arch, ApiFixture::Crt(fixture), 1000).unwrap();
            assert_eq!(
                full.guest_entry_return,
                Some(1),
                "{arch:?} {fixture:?}: {:?}",
                full.error
            );
            for budget in 1..full.instruction_count {
                let partial = run_api_fixture(arch, ApiFixture::Crt(fixture), budget).unwrap();
                assert_eq!(partial.completion_reason, "instruction_budget");
                assert_eq!(partial.error, None);
                assert_eq!(partial.guest_entry_return, None);
            }
        }
    }
}

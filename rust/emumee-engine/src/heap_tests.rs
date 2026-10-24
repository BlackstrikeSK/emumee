use super::*;
use emumee_core::fixtures::{ApiFixture, HeapFixture as H};
#[test]
fn native_heaps_validate_actual_bytes_ownership_and_permissions_on_both_abis() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [
            H::Lifecycle,
            H::Resize,
            H::Move,
            H::InPlace,
            H::Executable,
            H::Zero,
        ] {
            let result = run_api_fixture(arch, ApiFixture::Heap(kind), 10000).unwrap();
            assert_eq!(
                result.completion_reason, "entry_return",
                "{arch:?} {kind:?}: {:?}",
                result.error
            );
            assert_eq!(result.guest_entry_return, Some(1), "{arch:?} {kind:?}");
            let heaps = serde_json::to_value(result.user_heaps.unwrap()).unwrap();
            assert_eq!(heaps["blocks"].as_object().unwrap().len(), 0);
        }
        for (kind, error) in [
            (H::Nx, "FETCH_PROT"),
            (H::Freed, "READ_UNMAPPED"),
            (H::WrongOwner, "wrong-heap"),
            (H::DoubleFree, "freed"),
            (H::VirtualFree, "heap-owned"),
            (H::Flags, "flags"),
            (H::Fixed, "fixed arenas"),
        ] {
            let result = run_api_fixture(arch, ApiFixture::Heap(kind), 10000).unwrap();
            assert_eq!(result.completion_reason, "error", "{arch:?} {kind:?}");
            assert!(
                result.error.as_deref().unwrap().contains(error),
                "{arch:?} {kind:?}: {:?}",
                result.error
            );
            assert_eq!(result.guest_entry_return, None);
        }
    }
}
#[test]
fn heap_resize_budget_prefixes_preserve_report_and_never_invent_entry_return() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [H::Resize, H::Move] {
            let full = run_api_fixture(arch, ApiFixture::Heap(kind), 10000).unwrap();
            assert_eq!(full.guest_entry_return, Some(1));
            for budget in 1..full.instruction_count {
                let partial = run_api_fixture(arch, ApiFixture::Heap(kind), budget).unwrap();
                assert_eq!(
                    partial.completion_reason, "instruction_budget",
                    "{arch:?} {kind:?} {budget}: {:?}",
                    partial.error
                );
                assert_eq!(partial.guest_entry_return, None);
                assert!(partial.user_heaps.is_some());
            }
        }
    }
}

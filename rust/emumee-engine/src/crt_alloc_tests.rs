use super::*;
use emumee_core::{
    fixtures::{CrtAllocFixture as F, crt_alloc_probe},
    report_bundle::digest,
    user_input::{PROFILE, Request},
};

fn run(arch: Architecture, kind: F, modern: bool) -> Execution {
    let bytes = crt_alloc_probe(arch, kind, modern);
    run_bytes(&bytes)
}
fn run_bytes(bytes: &[u8]) -> Execution {
    let request = Request {
        schema: 1,
        profile: PROFILE.into(),
        run_id: "20261119T120000Z-12345678".into(),
        input_sha256: digest(bytes),
        input_size: bytes.len() as u64,
        module_name: "sample.exe".into(),
        arguments: vec![],
        max_instructions: 10000,
        timeout_us: 30_000_000,
        persona_sha256: None,
        clock_utc_filetime: 134377488000000000,
        staged: vec![],
        invocation: Default::default(),
    };
    user::run(&request, bytes, None).unwrap()
}
#[test]
fn m5_crt_allocations_use_actual_guest_zeroing_alignment_and_cdecl_ownership() {
    for arch in [Architecture::X86, Architecture::X64] {
        for modern in [false, true] {
            for kind in [F::Normal, F::Overflow] {
                let result = run(arch, kind, modern);
                assert_eq!(
                    result.error, None,
                    "{arch:?}/{modern}/{kind:?}: {result:#?}"
                );
                assert_eq!(result.guest_entry_return, Some(1));
                assert!(result.api_events.iter().all(|e| !e.pending));
                let heaps = serde_json::to_value(result.user_heaps.unwrap()).unwrap();
                assert_eq!(heaps["blocks"].as_object().unwrap().len(), 0);
            }
        }
    }
}
#[test]
fn m5_crt_invalid_frees_and_virtual_release_stop_before_retiring_owned_backing() {
    for arch in [Architecture::X86, Architecture::X64] {
        for modern in [false, true] {
            for (kind, error, live) in [
                (F::Interior, "wrong-heap", 1),
                (F::DoubleFree, "freed", 0),
                (F::OwnedRelease, "heap-owned", 1),
                (F::CrossFamily, "no owned allocation", 1),
                (F::Win32Free, "CRT-owned heap", 1),
            ] {
                let result = run(arch, kind, modern);
                assert_eq!(result.completion_reason, "error");
                assert!(
                    result.error.as_deref().unwrap().contains(error),
                    "{arch:?}/{modern}/{kind:?}: {:?}",
                    result.error
                );
                assert_eq!(result.guest_entry_return, None);
                let heaps = serde_json::to_value(result.user_heaps.unwrap()).unwrap();
                assert_eq!(heaps["blocks"].as_object().unwrap().len(), live);
            }
        }
    }
}

#[test]
fn m5_crt_ucrt_heap_api_set_and_o_aliases_share_allocation_ownership() {
    for arch in [Architecture::X86, Architecture::X64] {
        let mut bytes = crt_alloc_probe(arch, F::Normal, true);
        bytes[0x1240..0x1270].fill(0);
        let module = b"api-ms-win-crt-heap-l1-1-0.dll\0";
        bytes[0x1240..0x1240 + module.len()].copy_from_slice(module);
        for (i, name) in ["_o_malloc", "_o_calloc", "free", "malloc", "_o_free"]
            .iter()
            .enumerate()
        {
            let raw = 0x1500 + i * 64;
            bytes[raw..raw + 64].fill(0);
            bytes[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
        }
        let result = run_bytes(&bytes);
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1));
    }
}

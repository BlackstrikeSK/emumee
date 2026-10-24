use super::*;
use emumee_core::fixtures::{ApiFixture, ModuleFixture as M};
#[test]
fn actual_module_queries_and_pc_lookup_match_native_bytes_headers_inventory_and_budget() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [
            M::Standard,
            M::Extended,
            M::RelocatedExtended,
            M::AliasStandard,
            M::AliasExtended,
            M::OptionalLength,
            M::Short,
            M::PcOnly,
        ] {
            let e = run_api_fixture(arch, ApiFixture::Modules(kind), 10000).unwrap();
            assert_eq!(e.error, None, "{arch:?}/{kind:?}: {e:#?}");
            assert_eq!(e.completion_reason, "entry_return");
            assert_eq!(e.guest_entry_return, Some(1));
            assert_eq!(e.api_calls, kind.api_calls());
            let report = e.kernel_modules.as_ref().unwrap();
            assert!(!report.native_effect_failure);
            assert_eq!(report.events_omitted, 0);
            assert_eq!(report.events.len() as u64, kind.api_calls());
            assert_eq!(e.loaded_modules.len(), 11);
            assert_eq!(
                report
                    .events
                    .iter()
                    .filter(|event| event.operation == "system_information")
                    .count() as u64,
                kind.query_calls()
            );
            if !matches!(kind, M::PcOnly) {
                assert_eq!(report.last_inventory.len(), 11);
                assert_eq!(
                    report
                        .last_inventory
                        .iter()
                        .map(|m| m.name.as_str())
                        .collect::<Vec<_>>(),
                    [
                        "ntoskrnl.exe",
                        "hal.dll",
                        "generated-fixture.exe",
                        "cng.sys",
                        "ci.dll",
                        "ntfs.sys",
                        "netio.sys",
                        "volmgr.sys",
                        "disk.sys",
                        "tcpip.sys",
                        "ndis.sys"
                    ]
                );
                for row in &report.last_inventory {
                    assert!(e.loaded_modules.iter().any(|m| m.name == row.name
                        && m.base == row.base
                        && m.size == row.image_size));
                    assert_eq!(row.provenance.accepted_image_sha256.len(), 64);
                }
                let first = &report.events[0];
                assert_eq!(first.status, 0xc0000004);
                assert_eq!(first.copied, 0);
                if !matches!(kind, M::Short) {
                    assert_eq!(report.events[1].status, 0);
                    assert_eq!(report.events[1].copied, first.required);
                }
                let root = &report.last_inventory[2];
                let expected = if arch == Architecture::X64 {
                    0x140000000
                } else {
                    0x400000
                };
                assert_eq!(root.base, expected);
                assert_eq!(root.provenance.accepted_headers.timestamp, 0x12345678);
                assert_eq!(root.provenance.accepted_headers.checksum, 0x98765432);
                assert_eq!(
                    root.provenance.accepted_headers.preferred_base,
                    expected
                        + if matches!(kind, M::RelocatedExtended) {
                            0x200000
                        } else {
                            0
                        }
                );
            } else {
                assert!(report.last_inventory.is_empty());
            }
            assert_eq!(e.network.calls, 0);
            assert!(e.artifacts.is_empty());
            assert!(e.kernel_threads.is_none());
            let partial =
                run_api_fixture(arch, ApiFixture::Modules(kind), e.instruction_count - 1).unwrap();
            assert_eq!(partial.error, None);
            assert_eq!(partial.completion_reason, "instruction_budget");
            assert_eq!(partial.guest_entry_return, None);
            assert_eq!(partial.api_calls, e.api_calls);
        }
    }
}
#[test]
fn queued_lock_backing_is_ntoskrnl_owned_and_pc_lookup_uses_catalog() {
    let execution = run_api_fixture(
        Architecture::X64,
        ApiFixture::Modules(M::QueuedLockPc),
        10_000,
    )
    .unwrap();
    assert_eq!(execution.error, None, "{execution:#?}");
    assert_eq!(execution.completion_reason, "entry_return");
    assert_eq!(execution.guest_entry_return, Some(1));
    let nt = execution
        .loaded_modules
        .iter()
        .find(|module| module.name == "ntoskrnl.exe")
        .unwrap();
    let events = &execution.kernel_modules.as_ref().unwrap().events;
    assert_eq!(events.len(), 4);
    let lock = events.last().unwrap();
    assert_eq!(lock.operation, "pc_to_file_header");
    assert_eq!(lock.found_base, Some(nt.base));
    let pc = lock.pc.unwrap();
    assert!(pc >= nt.base && pc < nt.base + nt.size);
    assert_eq!(pc & 4095, 0);
    assert_eq!(pc, nt.base + nt.size - 4096);
}
#[test]
fn unsupported_module_classes_provenance_and_protected_outputs_never_fabricate_inventory() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [
            M::ReadOnlyOutput,
            M::ReadOnlyLength,
            M::UnmappedOutput,
            M::UnmappedLength,
            M::NullOutput,
            M::Overlap,
            M::UnknownTime,
            M::UnknownDebugger,
            M::UnknownCi,
            M::UnknownProcess,
            M::HighIrql,
            M::MissingProvenance,
        ] {
            let e = run_api_fixture(arch, ApiFixture::Modules(kind), 10000).unwrap();
            assert_eq!(e.guest_entry_return, None, "{arch:?}/{kind:?}: {e:#?}");
            assert_eq!(e.completion_reason, "error");
            assert!(
                e.error.as_deref().unwrap().contains(kind.error().unwrap()),
                "{arch:?}/{kind:?}: {e:#?}"
            );
            assert_eq!(e.api_calls, kind.api_calls());
            assert_eq!(e.api_events.last().unwrap().result, None);
            let report = e.kernel_modules.as_ref().unwrap();
            assert!(report.last_inventory.is_empty());
            assert!(!report.native_effect_failure);
            assert_eq!(report.events_omitted, 0);
            if matches!(kind, M::MissingProvenance) {
                assert!(e.kernel_loader.is_none(), "malformed generated catalog published loader metadata");
                assert_eq!(report.events.len(), 1);
                assert_eq!(report.events[0].operation, "pc_to_file_header");
                assert_ne!(report.events[0].found_base, Some(0));
            } else {
                assert!(report.events.is_empty());
            }
            assert!(e.kernel_threads.is_none());
            assert!(e.artifacts.is_empty());
            assert_eq!(e.network.calls, 0);
        }
    }
}

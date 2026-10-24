use super::*;
use emumee_core::fixtures::{ApiFixture, NativeFilesFixture as F};
const POSITIVE: &[F] = &[
    F::Basic,
    F::Supersede,
    F::CreateCollision,
    F::Overwrite,
    F::OverwriteIf,
    F::OpenExisting,
    F::Directory,
    F::Offsets,
    F::Sharing,
    F::TypedClose,
    F::Readonly,
    F::Missing,
    F::Unlink,
    F::SeedRead,
    F::SeedWrite,
    F::UserCoherence,
    F::Bounds,
];
const NEGATIVE: &[F] = &[
    F::Async,
    F::Event,
    F::Apc,
    F::Key,
    F::Ea,
    F::Security,
    F::Context,
    F::BadLength,
    F::OddUnicode,
    F::ReadonlyHandle,
    F::ReadonlyIosb,
    F::ReadonlyRead,
    F::Overlap,
    F::CrossBoundary,
    F::HighIrql,
    F::FileReference,
];
#[test]
fn actual_native_file_calls_verify_iosb_bytes_shared_backing_directories_and_finite_lifetimes() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in POSITIVE {
            let e = run_api_fixture(arch, ApiFixture::NativeFiles(*kind), 10000).unwrap();
            assert_eq!(e.error, None, "{arch:?}/{kind:?}: {e:#?}");
            assert_eq!(e.completion_reason, "entry_return");
            assert_eq!(e.guest_entry_return, Some(1));
            assert!(e.kernel_threads.is_none());
            assert_eq!(e.network.calls, 0);
            let r = e.kernel_files.as_ref().unwrap();
            assert!(!r.native_effect_failure);
            assert_eq!(r.events_omitted, 0);
            let creates = r
                .events
                .iter()
                .filter(|event| event.operation == "create")
                .collect::<Vec<_>>();
            assert_eq!(r.completed_create_requests as usize, creates.len());
            assert_eq!(r.create_request_receipts.len(), creates.len());
            assert_eq!(r.create_request_receipts_omitted, 0);
            assert_eq!(r.create_request_receipt_limit, 64);
            for (receipt, event) in r.create_request_receipts.iter().zip(&creates) {
                assert_eq!(
                    (receipt.status, receipt.information),
                    (event.status, event.information)
                );
                assert!(!receipt.name_truncated);
                assert_eq!(
                    receipt.name_utf16_units,
                    receipt.name.encode_utf16().count()
                );
                assert!(receipt.instruction_count < e.instruction_count);
            }
            assert!(r.handles.live.is_empty(), "{arch:?}/{kind:?}: {r:#?}");
            assert!(r.events.iter().all(|ev| matches!(
                ev.operation,
                "create" | "read" | "write" | "flush" | "close"
            )));
            if matches!(kind, F::Missing) {
                assert_eq!(r.handles.lifetime_issues, 0);
                assert_eq!(
                    r.events
                        .iter()
                        .map(|ev| (ev.status, ev.information))
                        .collect::<Vec<_>>(),
                    [(0xc0000034, 5), (0xc000003a, 5)]
                );
                assert_eq!(
                    r.create_request_receipts[0].name,
                    r"C:\Users\Morgan\Downloads\nt-file.bin"
                );
                assert_eq!(
                    r.create_request_receipts[1].name,
                    r"C:\Users\Morgan\Downloads\absent\file.bin"
                );
                for receipt in &r.create_request_receipts {
                    assert_eq!(receipt.root_handle, 0);
                    assert_eq!(receipt.desired_access, 0xc0010000);
                    assert_eq!(receipt.share_access, 7);
                    assert_eq!(receipt.create_options, 0x60);
                }
                assert_eq!(r.create_request_receipts[0].create_disposition, 1);
                assert_eq!(r.create_request_receipts[1].create_disposition, 3);
            }
            if matches!(kind, F::SeedRead) {
                assert!(e.artifacts.is_empty());
                assert_eq!(
                    r.events.iter().map(|ev| ev.operation).collect::<Vec<_>>(),
                    ["create", "read", "close"]
                );
            }
            if matches!(kind, F::SeedWrite) {
                assert_eq!(r.create_request_receipts[0].information, 1);
                assert!(r.events.iter().any(|ev| ev.operation == "write" && ev.information == 4));
                assert!(r.events.iter().any(|ev| ev.operation == "read" && ev.information == 4));
            }
            if matches!(kind, F::UserCoherence) {
                assert!(
                    e.api_events
                        .iter()
                        .any(|ev| ev.api.ends_with("WriteFile") && ev.result == Some(1))
                );
                assert!(
                    r.events
                        .iter()
                        .any(|ev| ev.operation == "read" && ev.information == 4)
                );
            }
            let partial = run_api_fixture(
                arch,
                ApiFixture::NativeFiles(*kind),
                e.instruction_count - 1,
            )
            .unwrap();
            assert_eq!(partial.error, None, "{arch:?}/{kind:?}: {partial:#?}");
            assert_eq!(partial.completion_reason, "instruction_budget");
            assert_eq!(partial.guest_entry_return, None);
            assert_eq!(partial.api_calls, e.api_calls);
            assert_eq!(
                partial.kernel_files.as_ref().unwrap().events.len(),
                r.events.len()
            );
            assert!(
                partial
                    .kernel_files
                    .as_ref()
                    .unwrap()
                    .handles
                    .live
                    .is_empty()
            );
        }
    }
}
#[test]
fn rejected_native_file_profiles_and_outputs_never_fabricate_handles_references_or_completion() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in NEGATIVE {
            let e = run_api_fixture(arch, ApiFixture::NativeFiles(*kind), 10000).unwrap();
            let expected = kind.error().unwrap();
            assert!(
                e.error.as_deref().is_some_and(|s| s.contains(expected)),
                "{arch:?}/{kind:?} expected {expected}: {e:#?}"
            );
            assert_eq!(e.completion_reason, "error");
            assert_eq!(e.guest_entry_return, None);
            assert!(e.api_events.last().unwrap().result.is_none());
            assert!(e.kernel_threads.is_none());
            let r = e.kernel_files.as_ref().unwrap();
            assert!(!r.native_effect_failure);
            assert_eq!(
                r.handles.lifetime_issues,
                u64::from(kind.initial_open_succeeds())
            );
            assert_eq!(
                r.handles.live.len(),
                usize::from(kind.initial_open_succeeds())
            );
            assert_eq!(r.events.len(), usize::from(kind.initial_open_succeeds()));
            assert_eq!(
                r.completed_create_requests,
                u64::from(kind.initial_open_succeeds())
            );
            assert_eq!(
                r.create_request_receipts.len(),
                usize::from(kind.initial_open_succeeds())
            );
            assert_eq!(r.create_request_receipts_omitted, 0);
            for row in &r.handles.live {
                assert_eq!(row.position, 0);
                assert!(!row.unlinked);
                assert!(!row.configured_backing);
            }
            assert_eq!(e.network.calls, 0);
        }
    }
}

fn completed_create_fixture(arch: Architecture, name: &str, count: u32, status: u32) -> Vec<u8> {
    use emumee_core::{
        fixtures::native_files_probe,
        pe::{ImportName, PeImage},
    };
    let mut image = native_files_probe(arch, F::Missing);
    let pe = PeImage::parse(&image, "create-receipt.sys").unwrap();
    let base = pe.image_base;
    let slot = pe
        .imports
        .iter()
        .find(|import| matches!(&import.name, ImportName::Name(name) if name == "IoCreateFileEx"))
        .unwrap()
        .iat_rva;
    let wide = arch == Architecture::X64;
    let encoded = name
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    assert!(encoded.len() < 0x2000);
    // Existing generated OBJECT_ATTRIBUTES points at the descriptor at2a80.
    image[0x1c80..0x1c82].copy_from_slice(&(encoded.len() as u16).to_le_bytes());
    image[0x1c82..0x1c84].copy_from_slice(&(encoded.len() as u16).to_le_bytes());
    let pointer = (base + 0x3000).to_le_bytes();
    let pointer_offset = if wide { 0x1c88 } else { 0x1c84 };
    image[pointer_offset..pointer_offset + arch.width()].copy_from_slice(&pointer[..arch.width()]);
    image[0x2200..0x2200 + encoded.len()].copy_from_slice(&encoded);
    let mut code = vec![0x53]; // Preserve actual caller RBX/EBX across the loop.
    if wide {
        code.extend_from_slice(&[0x48, 0x81, 0xec, 0x80, 0, 0, 0]);
    }
    code.push(0xbb);
    code.extend_from_slice(&count.to_le_bytes());
    let loop_at = code.len();
    let args = [
        base + 0x2c00,
        0x12345678c0010000,
        base + 0x2a00,
        base + 0x2c40,
        0,
        0x80,
        0x1234567800000007,
        0x1234567800000001,
        0x1234567800000060,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    if wide {
        for (opcode, value) in [[0x48, 0xb9], [0x48, 0xba], [0x49, 0xb8], [0x49, 0xb9]]
            .into_iter()
            .zip(args.iter())
        {
            code.extend_from_slice(&opcode);
            code.extend_from_slice(&value.to_le_bytes());
        }
        for (index, value) in args.iter().enumerate().skip(4) {
            code.extend_from_slice(&[0x48, 0xb8]);
            code.extend_from_slice(&value.to_le_bytes());
            code.extend_from_slice(&[0x48, 0x89, 0x44, 0x24, (0x20 + (index - 4) * 8) as u8]);
        }
        let displacement = slot as i32 - (0x1000 + code.len() as i32 + 6);
        code.extend_from_slice(&[0xff, 0x15]);
        code.extend_from_slice(&displacement.to_le_bytes());
    } else {
        for value in args.iter().rev() {
            code.push(0x68);
            code.extend_from_slice(&(*value as u32).to_le_bytes());
        }
        code.extend_from_slice(&[0xff, 0x15]);
        code.extend_from_slice(&((base + u64::from(slot)) as u32).to_le_bytes());
    }
    code.push(0x3d);
    code.extend_from_slice(&status.to_le_bytes());
    code.extend_from_slice(&[0x0f, 0x85]);
    let failure_jump = code.len();
    code.extend_from_slice(&[0; 4]);
    code.extend_from_slice(&[0xff, 0xcb, 0x0f, 0x85]);
    let loop_displacement = loop_at as i32 - (code.len() as i32 + 4);
    code.extend_from_slice(&loop_displacement.to_le_bytes());
    code.extend_from_slice(&[0xb8, 1, 0, 0, 0]);
    if wide {
        code.extend_from_slice(&[0x48, 0x81, 0xc4, 0x80, 0, 0, 0]);
    }
    code.extend_from_slice(&[0x5b, 0xc3]);
    let failure = code.len();
    code.extend_from_slice(&[0xb8, 0x0d, 0, 0, 0xc0]);
    if wide {
        code.extend_from_slice(&[0x48, 0x81, 0xc4, 0x80, 0, 0, 0]);
    }
    code.extend_from_slice(&[0x5b, 0xc3]);
    code[failure_jump..failure_jump + 4]
        .copy_from_slice(&(failure as i32 - failure_jump as i32 - 4).to_le_bytes());
    assert!(code.len() < 0x1000);
    image[0x200..0x200 + code.len()].copy_from_slice(&code);
    image
}

#[test]
fn completed_native_create_receipts_use_consumed_alias_name_exact_status_and_bounded_prefix() {
    use sha2::{Digest, Sha256};
    for arch in [Architecture::X86, Architecture::X64] {
        let name = r"\SystemRoot\missing-create-receipt.bin";
        // The unconfigured fixture VFS has no Windows directory. Preserve its
        // actual missing-parent status while observing the resolved name.
        let bytes = completed_create_fixture(arch, name, 65, 0xc000003a);
        let e = run_generated_image(&bytes, 10000, 30_000_000).unwrap();
        assert_eq!(e.error, None, "{arch:?}: {:#?}", e.error);
        assert_eq!(e.guest_entry_return, Some(1));
        let report = e.kernel_files.as_ref().unwrap();
        assert_eq!(report.completed_create_requests, 65);
        assert_eq!(report.create_request_receipts.len(), 64);
        assert_eq!(report.create_request_receipts_omitted, 1);
        let consumed = r"C:\Windows\missing-create-receipt.bin";
        let hash = format!(
            "{:x}",
            Sha256::digest(
                consumed
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>()
            )
        );
        for row in &report.create_request_receipts {
            assert_eq!(row.name, consumed);
            assert_eq!(row.name_utf16_sha256, hash);
            assert_eq!(
                (
                    row.desired_access,
                    row.share_access,
                    row.create_disposition,
                    row.create_options
                ),
                (0xc0010000, 7, 1, 0x60)
            );
            assert_eq!((row.status, row.information), (0xc000003a, 5));
            assert_eq!(row.root_handle, 0);
            assert!(!row.name_truncated);
        }
        assert!(
            report
                .create_request_receipts
                .windows(2)
                .all(|pair| pair[0].instruction_count < pair[1].instruction_count)
        );

        let suffix = "é😀".repeat(300);
        let declared = format!(r"\SystemRoot\unseeded\{suffix}.bin");
        let consumed = format!(r"C:\Windows\unseeded\{suffix}.bin");
        let long = completed_create_fixture(arch, &declared, 1, 0xc000003a);
        let e = run_generated_image(&long, 1000, 30_000_000).unwrap();
        assert_eq!(e.error, None, "{arch:?}: {:#?}", e.error);
        assert_eq!(e.guest_entry_return, Some(1));
        let row = &e.kernel_files.as_ref().unwrap().create_request_receipts[0];
        assert_eq!(row.name.chars().count(), 512);
        assert_eq!(row.name, consumed.chars().take(512).collect::<String>());
        assert!(row.name_truncated);
        assert_eq!(row.name_utf16_units, consumed.encode_utf16().count());
        assert_eq!(
            row.name_utf16_sha256,
            format!(
                "{:x}",
                Sha256::digest(
                    consumed
                        .encode_utf16()
                        .flat_map(u16::to_le_bytes)
                        .collect::<Vec<_>>()
                )
            )
        );
        assert_eq!((row.status, row.information), (0xc000003a, 5));
    }
}

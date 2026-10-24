use super::*;

#[test]
fn submitted_image_write_observer_records_native_store_and_untouched_bytes() {
    let mut bytes = emumee_core::fixtures::counted_driver(Architecture::X64, 17);
    let mut code = vec![0xc7, 0x05];
    code.extend((0x2001i32 - 0x100a).to_le_bytes());
    code.extend(0x11223344u32.to_le_bytes());
    code.extend([0xb8, 17, 0, 0, 0, 0xc3]);
    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
    let result = run_submitted_driver(&bytes, "WriteControl", 100, 30_000_000).unwrap();
    assert_eq!(result.guest_entry_return, Some(17));
    let report = result.image_writes.as_ref().unwrap();
    assert_eq!(report.installed_instruction_count, 0);
    assert_eq!(report.native_overlapping_attempts, 1);
    assert_eq!(report.model_overlapping_writes, 0);
    assert!(report.omitted_regions.is_empty());
    assert_eq!(report.observations_omitted, 0);
    let data = report
        .watched_regions
        .iter()
        .find(|region| region.base == result.image_load.base + 0x2000)
        .unwrap();
    assert_eq!(data.touched_byte_bitmap[0], 0x1e);
    assert!(data.touched_byte_bitmap[1..].iter().all(|byte| *byte == 0));
    let event = &report.observations[0];
    assert_eq!(event.pc, Some(result.image_load.base + 0x1000));
    assert_eq!(event.write_address, data.base + 1);
    assert_eq!(event.write_size, 4);
    assert_eq!(event.source, "native_prewrite_attempt");
    let capture = result.capture_runtime.as_ref().unwrap();
    let image = result
        .artifacts
        .iter()
        .find(|artifact| Some(artifact.sha256.as_str()) == capture.post_image_sha256.as_deref())
        .unwrap();
    assert_eq!(&image.data[0x2001..0x2005], &0x11223344u32.to_le_bytes());
}

#[test]
fn submitted_x64_driver_uses_exact_service_identity_and_actual_entry() {
    let bytes = emumee_core::fixtures::counted_driver(Architecture::X64, 17);
    for service in ["TestDrv", "case_check-2"] {
        let result = run_submitted_driver(&bytes, service, 1000, 30_000_000).unwrap();
        assert_eq!(result.completion_reason, "entry_return");
        assert_eq!(result.guest_entry_return, Some(17));
        let entry = result.kernel_entry.as_ref().unwrap();
        assert_eq!(
            entry.registry_name,
            format!(r"\Registry\Machine\System\CurrentControlSet\Services\{service}")
        );
        assert!(
            result
                .loaded_modules
                .iter()
                .any(|m| m.name == format!("{service}.sys").to_ascii_lowercase())
        );
        let capture = result.capture_runtime.as_ref().unwrap();
        assert_eq!(
            capture.input_sha256,
            emumee_core::report_bundle::digest(&bytes)
        );
        assert_eq!(capture.image_bytes, result.image_load.size as u64);
        assert_eq!(capture.boundary_instructions, result.instruction_count);
        assert_eq!(capture.boundary_pc, result.final_pc);
        assert!(capture.markers.is_empty());
        assert!(capture.selected_read_complete);
        assert!(capture.scope.contains("not confirmed unpacking"));
        let regions = result.modeled_guest_regions.as_ref().unwrap();
        assert!(regions.iter().any(|region| {
            region.base == result.image_load.base
                && region.permissions.contains(Permissions::READ)
                && region.size > 0
        }));
        assert!(
            result
                .modeled_guest_regions_scope
                .unwrap()
                .contains("metadata only")
        );
        assert!(result.artifacts.iter().any(|artifact| {
            artifact.size as u64 == capture.image_bytes
                && Some(artifact.sha256.as_str()) == capture.post_image_sha256.as_deref()
                && artifact.observations.iter().any(|observation| {
                    observation.kind == ArtifactKind::MemorySnapshot
                        && observation.source == "settled_root_image"
                })
        }));
    }
}

#[test]
fn submitted_driver_rejects_wrong_architecture_or_service_before_entry() {
    let x86 = emumee_core::fixtures::counted_driver(Architecture::X86, 17);
    assert!(run_submitted_driver(&x86, "TestDrv", 1000, 30_000_000).is_err());
    let x64 = emumee_core::fixtures::counted_driver(Architecture::X64, 17);
    assert!(run_submitted_driver(&x64, "..\\escape", 1000, 30_000_000).is_err());
    assert!(run_submitted_driver(&x64, "TestDrv", 0, 30_000_000).is_err());
    let mut oversized_image = x64;
    oversized_image[0x98 + 56..0x98 + 60]
        .copy_from_slice(&(128u32 * 1024 * 1024 + 4096).to_le_bytes());
    assert!(run_submitted_driver(&oversized_image, "TestDrv", 1000, 30_000_000).is_err());
}

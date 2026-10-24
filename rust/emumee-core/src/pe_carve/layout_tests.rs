//! Small adversarial layout controls; no large allocations or external inputs.
use super::*;
fn word(raw: &mut [u8], at: usize, value: u16) {
    raw[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn dword(raw: &mut [u8], at: usize, value: usize) {
    raw[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
}
fn image(length: usize, sections: &[(usize, usize, usize, u8)]) -> Vec<u8> {
    let mut raw = vec![0; length];
    raw[..2].copy_from_slice(b"MZ");
    dword(&mut raw, 60, 128);
    raw[128..132].copy_from_slice(b"PE\0\0");
    word(&mut raw, 132, 0x8664);
    word(&mut raw, 134, sections.len() as u16);
    word(&mut raw, 148, 240);
    word(&mut raw, 152, 0x20b);
    dword(&mut raw, 208, length);
    dword(&mut raw, 212, 512);
    for (i, (file, rva, size, fill)) in sections.iter().enumerate() {
        let row = 392 + i * 40;
        dword(&mut raw, row + 8, *size);
        dword(&mut raw, row + 12, *rva);
        dword(&mut raw, row + 16, *size);
        dword(&mut raw, row + 20, *file);
        if rva + size <= length {
            raw[*rva..rva + size].fill(*fill);
        }
    }
    raw
}
fn mapped(raw: Vec<u8>) -> Scan {
    let limits = CaptureProfile::Driver128V1.limits();
    scan_owned_mapped_root(
        raw,
        "root",
        None,
        CaptureProfile::Driver128V1,
        limits.scan,
        limits.work,
    )
    .unwrap()
}
#[test]
fn overlapping_raw_and_rva_windows_use_authoritative_root_mapping_not_zero_guess() {
    let raw = image(8192, &[(512, 4096, 4096, 0x52)]);
    // The raw window overlaps512 bytes of real mapped section content. Legacy's
    // all-zero raw test therefore fails, exactly as in the frozen64MiB receipt.
    let inferred =
        scan_with_profile(&raw, "unknown", false, None, CaptureProfile::Driver128V1).unwrap();
    assert_eq!(inferred.observations.len(), 1);
    assert_eq!(inferred.payloads[0].size, 4608);
    let pointer = raw.as_ptr();
    let expected = raw.clone();
    let result = mapped(raw);
    let memory = result
        .observations
        .iter()
        .find(|o| o.kind == CaptureKind::Memory)
        .unwrap();
    let pe = result
        .observations
        .iter()
        .find(|o| o.kind == CaptureKind::Pe)
        .unwrap();
    assert_eq!(memory.source, "root");
    assert_eq!(pe.source, "root");
    assert_eq!(result.payloads[memory.payload].data, expected);
    assert_eq!(result.payloads[memory.payload].data.as_ptr(), pointer);
    let recovered = &result.payloads[pe.payload].data;
    assert_eq!(recovered.len(), 4608);
    assert_eq!(&recovered[..512], &expected[..512]);
    assert!(recovered[512..].iter().all(|b| *b == 0x52));
    assert_eq!(
        pe.context.as_ref().unwrap()["layout_authority"],
        "caller_verified_root_mapping"
    );
    assert_eq!(result.artifact_capture.omitted_observations, 0);
}
#[test]
fn cross_section_file_offsets_cannot_corrupt_mapped_reconstruction() {
    let raw = image(16384, &[(512, 8192, 8192, 0x52), (8704, 4096, 512, 0x31)]);
    let expected = raw.clone();
    let result = mapped(raw);
    let pe = result
        .observations
        .iter()
        .find(|o| o.kind == CaptureKind::Pe)
        .unwrap();
    let recovered = &result.payloads[pe.payload].data;
    assert_eq!(recovered.len(), 9216);
    assert_eq!(&recovered[..512], &expected[..512]);
    assert!(recovered[512..8704].iter().all(|b| *b == 0x52));
    assert!(recovered[8704..].iter().all(|b| *b == 0x31));
}
#[test]
fn raw_pe_in_memory_and_padded_raw_files_are_not_forced_to_mapped_by_origin() {
    for padded in [false, true] {
        let mut raw = image(8192, &[(512, 4096, 4096, 0x52)]);
        raw[512..].fill(0);
        raw[512..4608].fill(0x73);
        if !padded {
            raw.truncate(4608)
        }
        let expected = raw[..4608].to_vec();
        let mut catalog =
            crate::artifacts::ArtifactCatalog::with_profile(CaptureProfile::Driver128V1);
        crate::artifact_bridge::capture_owned_budgeted(
            &mut catalog,
            raw,
            "raw-in-memory",
            None,
            crate::artifact_bridge::Origin::Memory,
            false,
        )
        .unwrap();
        assert_eq!(catalog.items.len(), 1);
        assert_eq!(catalog.items[0].data, expected);
        assert_eq!(
            catalog.items[0].observations[0].kind,
            crate::artifacts::ArtifactKind::CarvedImage
        );
        assert!(
            catalog.items[0].observations[0]
                .context
                .as_ref()
                .unwrap()
                .get("source_layout")
                .is_none()
        );
    }
}
#[test]
fn mapped_root_layout_does_not_override_embedded_raw_candidates() {
    let mut root = image(32768, &[(512, 16384, 4096, 0x52)]);
    let mut embedded = image(8192, &[(512, 4096, 4096, 0x41)]);
    embedded[512..].fill(0);
    embedded[512..4608].fill(0x66);
    embedded.truncate(4608);
    root[8192..8192 + embedded.len()].copy_from_slice(&embedded);
    let result = mapped(root);
    let observation = result
        .observations
        .iter()
        .find(|o| o.source == "root@0x2000")
        .unwrap();
    assert_eq!(observation.kind, CaptureKind::Pe);
    assert_eq!(result.payloads[observation.payload].data, embedded);
    assert!(observation.context.is_none());
}
#[test]
fn incomplete_extent_bad_sections_and_work_exhaustion_preserve_actual_snapshot_only() {
    for invalid in [0, 1, 2, 3] {
        let mut raw = image(8192, &[(512, 4096, 4096, 0x52)]);
        if invalid == 0 {
            dword(&mut raw, 208, 12288)
        } else if invalid == 1 {
            dword(&mut raw, 392 + 12, 8000)
        } else if invalid == 2 {
            raw[128] = b'X'
        }
        let expected = raw.clone();
        let limits = CaptureProfile::Driver128V1.limits();
        let result = scan_owned_mapped_root(
            raw,
            "bad",
            None,
            CaptureProfile::Driver128V1,
            limits.scan,
            if invalid == 3 { 0 } else { limits.work },
        )
        .unwrap();
        assert_eq!(result.observations.len(), 1, "{invalid}");
        assert_eq!(result.observations[0].kind, CaptureKind::Memory);
        assert_eq!(result.payloads[0].data, expected);
        assert!(result.artifact_capture.omitted_observations > 0);
    }
}
#[test]
fn explicit_mapped_bridge_keeps_typed_full_snapshot_and_section_source_bindings() {
    let raw = image(8192, &[(512, 4096, 4096, 0x52)]);
    let expected = raw.clone();
    let mut catalog = crate::artifacts::ArtifactCatalog::with_profile(CaptureProfile::Driver128V1);
    crate::artifact_bridge::capture_owned_mapped_root(&mut catalog, raw, "actual-root", None)
        .unwrap();
    assert_eq!(catalog.items.len(), 2);
    let snapshot = catalog
        .items
        .iter()
        .find(|p| p.observations[0].kind == crate::artifacts::ArtifactKind::MemorySnapshot)
        .unwrap();
    let pe = catalog
        .items
        .iter()
        .find(|p| p.observations[0].kind == crate::artifacts::ArtifactKind::CarvedImage)
        .unwrap();
    assert_eq!(snapshot.observations[0].source, "actual-root");
    assert_eq!(pe.observations[0].source, "actual-root");
    assert_eq!(snapshot.data, expected);
    let context = pe.observations[0].context.as_ref().unwrap();
    assert_eq!(context["source_snapshot_sha256"], snapshot.sha256);
    assert_eq!(context["source_layout"], "mapped_image");
    assert_eq!(context["layout"], "raw_file");
    assert_eq!(context["structural_only"], true);
    assert_eq!(context["no_fixups"], true);
    for segment in context["reconstruction_segments"].as_array().unwrap() {
        let source = segment["source"].as_u64().unwrap() as usize;
        let destination = segment["destination"].as_u64().unwrap() as usize;
        let size = segment["size"].as_u64().unwrap() as usize;
        assert_eq!(
            &snapshot.data[source..source + size],
            &pe.data[destination..destination + size]
        );
    }
}

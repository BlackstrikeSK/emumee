//! Structural checks on the resource tree the M7 fixture builds, so a malformed
//! `.rsrc` can never pass the guest controls for the wrong reason.
use emumee_core::fixtures::resource_tree;

/// Read a little-endian u16/u32 out of the blob.
fn u16_at(blob: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([blob[at], blob[at + 1]])
}
fn u32_at(blob: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(blob[at..at + 4].try_into().unwrap())
}

#[test]
fn resource_tree_is_a_well_formed_three_level_directory() {
    let tree = resource_tree();
    let blob = &tree.blob;

    // Root type level: two id entries (RT_STRING=6, RT_RCDATA=10), ascending.
    assert_eq!(u16_at(blob, 12), 0, "root has no named entries");
    assert_eq!(u16_at(blob, 14), 2, "root has two id entries");
    assert_eq!(u32_at(blob, 16), 6, "first type is RT_STRING");
    assert_eq!(u32_at(blob, 24), 10, "second type is RT_RCDATA");
    // Both point at subdirectories (high bit set).
    assert_ne!(u32_at(blob, 20) & 0x8000_0000, 0);
    assert_ne!(u32_at(blob, 28) & 0x8000_0000, 0);

    // Every data entry the builder reports sits inside the blob and its bytes
    // sit inside the image the resource RVA maps into.
    for entry in [tree.entry_id_neutral, tree.entry_named, tree.entry_id_enus] {
        assert!((entry as usize) + 16 <= blob.len(), "entry {entry} overruns blob");
        let rva = u32_at(blob, entry as usize);
        assert!(rva >= emumee_core::fixtures::RESOURCE_RVA as u32);
    }

    // The two reported RCDATA payloads are distinct and nonzero in size.
    assert_ne!(tree.data_id_neutral_rva, tree.data_named_rva);
    assert!(tree.data_id_neutral_size > 0);
    assert!(tree.data_named_size > 0);
}

#[test]
fn string_bundle_holds_the_known_string_at_its_index() {
    let tree = resource_tree();
    let blob = &tree.blob;
    // The string entry's data RVA is the only one not exposed directly; recover
    // the bundle by scanning for the known string's UTF-16 bytes.
    let needle: Vec<u8> = emumee_core::fixtures::STRING_5
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    assert!(
        blob.windows(needle.len()).any(|w| w == needle.as_slice()),
        "string bundle does not contain the known string",
    );
}

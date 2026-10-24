//! Generated layout proofs only; no actual driver or private kernel data.
use super::*;
use api::{
    reference_mapping::{IntegratedPrepared, PROVIDER_BASE},
    reference_unload::Authority,
};
use emumee_core::provider::{RelocatedCodeSection, RelocatedCodeView};
use std::collections::BTreeMap;

pub(crate) fn reference() -> IntegratedPrepared {
    IntegratedPrepared {
        header_identity: api::reference_mapping::generated_header_identity(),
        view: RelocatedCodeView {
            source_sha256: "generated-unload-layout".into(),
            source_size: 4096,
            preferred_base: 0x140000000,
            target_base: PROVIDER_BASE,
            image_size: 0x1047000,
            sections: vec![RelocatedCodeSection {
                name: ".text".into(),
                rva: 0x200000,
                bytes: vec![0x90; 512],
            }],
        },
        code_exports: BTreeMap::new(),
        unload_authority: Some(Authority::GeneratedNt22631Layout),
    }
}
fn probe(address: u64, tail: &[u8]) -> Vec<u8> {
    let mut image = counted_driver(Architecture::X64, 1);
    let mut code = vec![0x48, 0xb8];
    code.extend(address.to_le_bytes());
    code.extend(tail);
    image[0x200..0x200 + code.len()].copy_from_slice(&code);
    image
}
fn run(image: &[u8]) -> Execution {
    run_generated_with_fixture_configuration(
        image,
        &[],
        100,
        1_000_000,
        GeneratedConfiguration {
            kernel_reference: Some(KernelReferenceInput::IntegratedGenerated(reference())),
            ..Default::default()
        },
    )
    .unwrap()
}

#[test]
fn generated_fresh_unload_fields_allow_exact_and_partial_zero_reads_only() {
    for (rva, width, instruction) in [
        (0xc13098, 8, vec![0x48, 0x8b, 0x00, 0xc3]),
        (0xc13098, 4, vec![0x8b, 0x00, 0xc3]),
        (0xc1309f, 1, vec![0x0f, 0xb6, 0x00, 0xc3]),
        (0xc13090, 4, vec![0x8b, 0x00, 0xc3]),
        (0xc13092, 2, vec![0x0f, 0xb7, 0x00, 0xc3]),
    ] {
        let result = run(&probe(PROVIDER_BASE + rva, &instruction));
        assert_eq!(result.error, None);
        assert_eq!(result.guest_entry_return, Some(0));
        let report = result.kernel_reference_unload_history.unwrap();
        assert!(report.generated_fixture && report.native_read_guard_installed);
        assert_eq!(report.modeled_image_unloads, 0);
        assert_eq!(report.fields.len(), 2);
        assert_eq!(report.native_reads, 1);
        assert_eq!(report.observations[0].size, width);
        assert!(report.denials.is_empty());
        assert!(
            result
                .kernel_reference
                .unwrap()
                .guest_unload_history_enabled
        );
    }
}
#[test]
fn generated_private_padding_crossings_writes_and_fetches_never_complete_successfully() {
    for (rva, code) in [
        (0xc13094, vec![0x8b, 0x00, 0xc3]),       // private padding
        (0xc13097, vec![0x0f, 0xb7, 0x00, 0xc3]), // prefix crosses into pointer
        (0xc1309f, vec![0x0f, 0xb7, 0x00, 0xc3]), // pointer crosses suffix
        (0xc13093, vec![0x0f, 0xb7, 0x00, 0xc3]), // index crosses padding
    ] {
        let result = run(&probe(PROVIDER_BASE + rva, &code));
        assert_eq!(result.completion_reason, "error");
        assert_eq!(result.guest_entry_return, None);
        assert!(
            result
                .error
                .unwrap()
                .contains("outside modeled unload-history fields")
        );
        let report = result.kernel_reference_unload_history.unwrap();
        assert_eq!(report.native_reads, 0);
        assert!(!report.denials.is_empty());
    }
    for (code, error, access) in [
        (vec![0xc6, 0x00, 0, 0xc3], "WRITE_PROT", "write"),
        (vec![0xff, 0xe0], "FETCH_PROT", "execute"),
    ] {
        let address = PROVIDER_BASE + 0xc13098;
        let result = run(&probe(address, &code));
        assert_eq!(result.completion_reason, "error");
        assert_eq!(result.guest_entry_return, None);
        assert!(result.error.unwrap().contains(error));
        let fault = result.native_memory_fault.unwrap();
        assert_eq!(fault.address, address);
        assert_eq!(fault.access, access);
    }
}
#[test]
fn first_native_invalid_memory_receipt_also_covers_unmapped_addresses_outside_providers() {
    let address = 0x12345000;
    let result =
        run_generated_image(&probe(address, &[0x48, 0x8b, 0x00, 0xc3]), 100, 1_000_000).unwrap();
    assert!(result.error.as_deref().unwrap().contains("READ_UNMAPPED"));
    let fault = result.native_memory_fault.unwrap();
    assert_eq!(
        (fault.access, fault.address, fault.size),
        ("read", address, 8)
    );
    assert_eq!(fault.pc, 0x14000100a);
    assert!(result.kernel_reference_unload_history.is_none());
    assert_eq!(result.guest_entry_return, None);
}

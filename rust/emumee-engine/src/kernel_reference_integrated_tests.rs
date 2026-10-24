//! Generated evidence for same-base exports and inspection-only reference code.
use super::*;
use api::reference_mapping::{IntegratedPrepared, PROVIDER_BASE, REFERENCE_HAL_BASE};
use emumee_core::{
    memory::Permissions as P,
    pe::ImportName,
    provider::{RelocatedCodeSection, RelocatedCodeView},
};
use std::collections::BTreeMap;

fn reference() -> IntegratedPrepared {
    let mut code = vec![0x90; 512];
    code[0x100..0x108].copy_from_slice(&(PROVIDER_BASE + 0x1234).to_le_bytes());
    IntegratedPrepared {
        header_identity: api::reference_mapping::generated_header_identity(),
        view: RelocatedCodeView {
            source_sha256: "a".repeat(64),
            source_size: 4096,
            preferred_base: 0x140000000,
            target_base: PROVIDER_BASE,
            image_size: 0x300000,
            sections: vec![RelocatedCodeSection {
                name: ".text".into(),
                rva: 0x200000,
                bytes: code,
            }],
        },
        code_exports: BTreeMap::from([("KeInsertQueueDpc".into(), 0x200100)]),
        unload_authority: None,
    }
}
fn run(bytes: &[u8], reference: IntegratedPrepared) -> Execution {
    run_generated_with_fixture_configuration(
        bytes,
        &[],
        10000,
        30_000_000,
        GeneratedConfiguration {
            kernel_reference: Some(KernelReferenceInput::IntegratedGenerated(reference)),
            ..Default::default()
        },
    )
    .unwrap()
}
fn probe(tail: &[u8], address: u64) -> Vec<u8> {
    let mut bytes = counted_driver(Architecture::X64, 1);
    let mut code = vec![0x48, 0xb8];
    code.extend(address.to_le_bytes());
    code.extend(tail);
    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
    bytes
}

#[test]
fn generated_same_base_reference_keeps_modeled_dispatch_and_inspection_only_export_targets() {
    use emumee_core::fixtures::{ProviderMixedFixture as F, provider_mixed_probe};
    let success = run(
        &provider_mixed_probe(Architecture::X64, F::Lifecycle),
        reference(),
    );
    assert_eq!(success.error, None);
    assert_eq!(success.guest_entry_return, Some(1));
    assert_eq!(success.api_calls, 37);
    let receipt = success.kernel_reference.unwrap();
    assert_eq!(receipt.mapping_mode, "provider_same_base");
    assert_eq!(receipt.target_base, PROVIDER_BASE);
    assert_eq!(receipt.redirected_code_exports, 1);
    assert!(receipt.read_only && receipt.non_executable);
    assert!(!receipt.provider_dispatch_replaced && !receipt.protected_data_replaced);
    assert!(!receipt.reference_execution_admitted && !receipt.reference_instructions_executed);
    let failure = run(
        &provider_mixed_probe(Architecture::X64, F::UnmodeledCode),
        reference(),
    );
    assert!(failure.error.as_deref().unwrap().contains("FETCH_PROT"));
    assert!(
        failure
            .api_events
            .iter()
            .any(|e| e.api == "ntoskrnl.MmGetSystemRoutineAddress"
                && e.result == Some(PROVIDER_BASE + 0x200100))
    );
    let read = run(
        &probe(&[0x48, 0x8b, 0x00, 0xc3], PROVIDER_BASE + 0x200100),
        reference(),
    );
    assert_eq!(read.error, None);
    assert_eq!(read.guest_entry_return, Some(PROVIDER_BASE + 0x1234));
    let write = run(
        &probe(&[0xc6, 0x00, 0x00, 0xc3], PROVIDER_BASE + 0x200100),
        reference(),
    );
    assert!(write.error.as_deref().unwrap().contains("WRITE_PROT"));
    let private = run(
        &probe(&[0x48, 0x8b, 0x00, 0xc3], PROVIDER_BASE + 0x280000),
        reference(),
    );
    assert!(private.error.as_deref().unwrap().contains("READ_PROT"));
}

#[test]
fn generated_integrated_reference_catalog_permissions_host_guards_and_rejection_are_consistent() {
    let mut engine = new_engine(Architecture::X64).unwrap();
    engine
        .get_data_mut()
        .apis
        .target(Architecture::X64, true)
        .unwrap();
    api::kernel_objects::initialize(&mut engine).unwrap();
    let prepared = reference();
    let receipt = api::initialize_providers_with_reference(&mut engine, &prepared)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.redirected_code_exports, 1);
    let resolved = engine
        .get_data()
        .apis
        .modules
        .resolve("ntoskrnl.exe", &ImportName::Name("KeInsertQueueDpc".into()))
        .unwrap();
    assert!(
        matches!(resolved, emumee_core::modules::Resolution::Found { address, .. }
        if address == PROVIDER_BASE + 0x200100)
    );
    assert_eq!(
        engine
            .get_data()
            .apis
            .modules
            .module("hal.dll")
            .unwrap()
            .unwrap()
            .base,
        REFERENCE_HAL_BASE
    );
    assert!(
        engine
            .get_data()
            .apis
            .memory
            .allows(PROVIDER_BASE + 0x200100, 8, P::READ)
    );
    assert!(
        !engine
            .get_data()
            .apis
            .memory
            .allows(PROVIDER_BASE + 0x200100, 1, P::WRITE)
    );
    assert!(
        !engine
            .get_data()
            .apis
            .memory
            .allows(PROVIDER_BASE + 0x200100, 1, P::EXECUTE)
    );
    assert!(cpu::write(&mut engine, PROVIDER_BASE + 0x200100, &[0]).is_err());
    assert!(cpu::write(&mut engine, PROVIDER_BASE + 0x280000, &[0]).is_err());
    let regions = engine.mem_regions().unwrap();
    assert!(api::initialize_providers_with_reference(&mut engine, &prepared).is_err());
    assert_eq!(engine.mem_regions().unwrap(), regions);
    drop(engine);

    // Core geometry rejection occurs before the integrated provider mapping.
    let mut bad = reference();
    bad.view.sections[0].rva = 0x1000;
    let mut engine = new_engine(Architecture::X64).unwrap();
    engine
        .get_data_mut()
        .apis
        .target(Architecture::X64, true)
        .unwrap();
    api::kernel_objects::initialize(&mut engine).unwrap();
    assert!(api::initialize_providers_with_reference(&mut engine, &bad).is_err());
    assert!(
        engine
            .get_data()
            .apis
            .modules
            .module("ntoskrnl.exe")
            .unwrap()
            .is_none()
    );
    assert!(
        engine
            .get_data()
            .apis
            .memory
            .region(PROVIDER_BASE)
            .is_none()
    );
    assert!(engine.get_data().reference_spans.is_empty());
}

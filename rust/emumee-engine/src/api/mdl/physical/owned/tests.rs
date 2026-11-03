use super::super::tests::{engine_with_owned, map, query};
use super::*;

#[test]
fn owned_query_exposes_actual_words_native_abi_and_consistent_root_identity() {
    let mut engine = engine_with_owned(true);
    map(&mut engine, 0x140000000, 4096);
    for raw in [0x140000321, 0x1234000140000321, 0xf6fb7dbed321] {
        uc(engine.reg_write(RegisterX86::RCX, raw)).unwrap();
        let before = registers(&engine).unwrap();
        let state = &engine.get_data().apis;
        let (plan, walk) = state
            .mdls
            .model
            .prepare_physical_walk(&state.memory, raw)
            .unwrap();
        let projected = projection::project(
            &walk,
            before,
            uc(engine.reg_read(RegisterX86::EFLAGS)).unwrap(),
        )
        .unwrap();
        let result = query(&mut engine, raw).unwrap();
        assert_eq!(result, plan.result);
        assert_ne!(result, 0);
        let mut after = registers(&engine).unwrap();
        after.rsp += 8;
        assert_eq!(after, projected.registers);
        assert_eq!(
            uc(engine.reg_read(RegisterX86::EFLAGS)).unwrap(),
            projected.flags
        );
        let mut bytes = std::collections::BTreeMap::new();
        for spill in &projected.spills {
            for (offset, byte) in spill.bytes.iter().enumerate() {
                bytes.insert(spill.address + offset as u64, *byte);
            }
        }
        for (address, byte) in bytes {
            assert_eq!(uc(engine.mem_read_as_vec(address, 1)).unwrap(), [byte]);
        }
        for (level, word) in walk.entries.iter().enumerate() {
            let address = projected.pte_addresses[3 - level];
            assert_eq!(
                uc(engine.mem_read_as_vec(address, 8)).unwrap(),
                word.unwrap().to_le_bytes()
            );
        }
        let event = report(&engine).events.last().unwrap().clone();
        assert_eq!(event.walk, walk);
        assert_eq!(event.physical_address, result);
        assert_eq!(event.stack_spills, 16);
        assert_eq!(event.structural_reads, 4);
        assert!(!engine.get_data().apis.mdls.poisoned);
    }
    let cr3 = engine.get_data().apis.mdls.model.physical().unwrap().cr3();
    assert_eq!(query(&mut engine, 0xf6fb7dbed000).unwrap(), cr3);
    assert!(super::super::report(&engine).events.is_empty());
}

#[test]
fn owned_absent_queries_cover_each_missing_level_without_legacy_ancestor_profile() {
    let mut engine = engine_with_owned(true);
    let raw = 0x8040201000;
    for (missing, ancestor) in [
        (0, None),
        (1, Some(0x8000000000)),
        (2, Some(0x8040000000)),
        (3, Some(0x8040200000)),
    ] {
        if let Some(address) = ancestor {
            map(&mut engine, address, 4096);
        }
        assert_eq!(query(&mut engine, raw).unwrap(), 0);
        let event = report(&engine).events.last().unwrap().clone();
        assert_eq!(event.walk.entries[missing], Some(0));
        assert_eq!(event.structural_reads, missing + 1);
        assert!(
            event.walk.entries[..missing]
                .iter()
                .all(|word| word.unwrap() > 4096)
        );
        assert_eq!(event.stack_spills, 14);
        assert_eq!(
            uc(engine.reg_read(RegisterX86::EFLAGS)).unwrap() & 0x8d5,
            0x44
        );
    }
}

#[test]
fn owned_query_reconciles_remapping_and_permission_changes() {
    let mut engine = engine_with_owned(true);
    let address = 0x140000000;
    map(&mut engine, address, 4096);
    let first = query(&mut engine, address).unwrap();
    engine.mem_protect(address, 4096, Prot::READ).unwrap();
    engine
        .get_data_mut()
        .apis
        .memory
        .protect(address, 4096, P::READ)
        .unwrap();
    assert_eq!(query(&mut engine, address).unwrap(), first);
    engine.mem_unmap(address, 4096).unwrap();
    engine
        .get_data_mut()
        .apis
        .memory
        .unmap(address, 4096)
        .unwrap();
    assert_eq!(query(&mut engine, address).unwrap(), 0);
    map(&mut engine, address, 4096);
    assert_ne!(query(&mut engine, address).unwrap(), first);
}

#[test]
fn owned_query_refuses_unproduced_classification_context_and_permission_disagreement() {
    let mut engine = engine_with_owned(true);
    map(&mut engine, 0xffffa00012345000, 4096);
    assert!(
        query(&mut engine, 0xffffa00012345000)
            .unwrap_err()
            .to_string()
            .contains("Classification")
    );
    assert!(report(&engine).events.is_empty());
    assert!(engine.get_data().apis.mdls.paging.backing.is_empty());
    assert!(!engine.get_data().apis.mdls.poisoned);
    let cr3 = uc(engine.reg_read(RegisterX86::CR3)).unwrap();
    engine.reg_write(RegisterX86::CR3, cr3 + 4096).unwrap();
    assert!(
        query(&mut engine, 0x140000000)
            .unwrap_err()
            .to_string()
            .contains("paging context")
    );
    engine.reg_write(RegisterX86::CR3, cr3).unwrap();
    map(&mut engine, 0x140000000, 4096);
    engine.mem_protect(0x140000000, 4096, Prot::READ).unwrap();
    assert!(
        query(&mut engine, 0x140000000)
            .unwrap_err()
            .to_string()
            .contains("disagree")
    );
    assert!(report(&engine).events.is_empty());
}

#[test]
fn owned_query_native_failure_is_sticky_and_retains_uncertain_backing() {
    let mut engine = engine_with_owned(true);
    map(&mut engine, 0x140000000, 4096);
    engine.get_data_mut().apis.mdls.physical.fail_before_spill = Some(2);
    assert!(query(&mut engine, 0x140000321).is_err());
    assert!(engine.get_data().apis.mdls.poisoned);
    let retained = engine.get_data().apis.mdls.paging.backing.len();
    assert!(retained > 0);
    assert!(report(&engine).events.is_empty());
    assert!(
        query(&mut engine, 0x140000321)
            .unwrap_err()
            .to_string()
            .contains("cannot resume")
    );
    assert_eq!(engine.get_data().apis.mdls.paging.backing.len(), retained);
}

#[test]
fn owned_query_clock_aliases_share_one_physical_identity() {
    let mut engine = engine_with_owned(true);
    crate::time::initialize(&mut engine).unwrap();
    let user = query(&mut engine, 0x7ffe0321).unwrap();
    assert_eq!(query(&mut engine, 0xf78000000321).unwrap(), user);
}

#[test]
fn owned_generated_guest_calls_physical_api_and_compares_root_with_cr3() {
    use emumee_core::fixtures::{ApiFixture, MdlFixture};
    let mut image =
        emumee_core::fixtures::api_probe(Architecture::X64, ApiFixture::Mdl(MdlFixture::Lifecycle));
    let mut code = vec![0x48, 0x83, 0xec, 0x68, 0x48, 0xb9];
    code.extend(0xf6fb7dbed000u64.to_le_bytes());
    let next = 0x1000 + code.len() as i32 + 6;
    code.extend([0xff, 0x15]);
    code.extend((0x20a0i32 - next).to_le_bytes());
    code.extend([
        0x0f, 0x20, 0xda, 0x48, 0x39, 0xd0, 0x74, 0x02, 0x0f, 0x0b, 0xb8, 42, 0, 0, 0, 0x48, 0x83,
        0xc4, 0x68, 0xc3,
    ]);
    image[0x200..0x1200].fill(0);
    image[0x200..0x200 + code.len()].copy_from_slice(&code);
    let result = crate::run_generated_with_fixture_configuration(
        &image,
        &[],
        10000,
        30000000,
        crate::GeneratedConfiguration {
            owned_paging_requested: true,
            configured: Some(crate::kernel_capture_tests::prepared(26200, false)),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(result.error, None);
    assert_eq!(result.guest_entry_return, Some(42));
    let mdls = result.kernel_mdls.unwrap();
    let event = &mdls.physical_queries.owned_queries.events[0];
    assert_eq!(
        event.physical_address,
        result.kernel_cpu.unwrap().current.cr3
    );
    assert!(mdls.physical_queries.events.is_empty());
    assert!(!mdls.native_effect_failure);
}

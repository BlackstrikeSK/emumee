use super::*;

const CODE: u64 = 0x140000000;
const DATA: u64 = 0x280400000;

fn map(engine: &mut Unicorn<Trace>, address: u64, permissions: P) {
    engine
        .mem_map(address, PAGE, Prot(u32::from(permissions.0) as _))
        .unwrap();
    engine
        .get_data_mut()
        .apis
        .memory
        .map(address, PAGE, permissions, Some(4), "PFN control")
        .unwrap();
}

fn engine() -> crate::NativeEngine {
    let trace = crate::kernel_capture_tests::prepared(26200, false)
        .into_trace()
        .unwrap();
    let mut engine = crate::new_engine_with_trace(trace).unwrap();
    engine
        .get_data_mut()
        .apis
        .target(Architecture::X64, true)
        .unwrap();
    map(&mut engine, CODE, P::RX);
    map(&mut engine, DATA, P::RW);
    engine.get_data_mut().apis.mdls.owned_paging_requested = true;
    engine.get_data_mut().apis.mdls.pfn.requested = true;
    crate::kernel_cpu::initialize(&mut engine).unwrap();
    engine
}

fn field(engine: &Unicorn<Trace>, depth: u8) -> (u64, u64) {
    let authority = engine.get_data().apis.mdls.model.physical().unwrap();
    let table = authority
        .tables()
        .find(|table| table.depth == depth)
        .unwrap();
    (
        contract::field_address(table.pfn).unwrap(),
        contract::table_backlink(authority, table.pfn).unwrap(),
    )
}

fn run(engine: &mut Unicorn<Trace>, code: &[u8]) -> Result<()> {
    engine.mem_write(CODE, code).unwrap();
    engine.ctl_remove_cache(CODE, CODE + PAGE).unwrap();
    uc(engine.emu_start(CODE, CODE + code.len() as u64, 0, 100))
}

fn load(engine: &mut Unicorn<Trace>, address: u64, opcode: &[u8]) -> Result<()> {
    let mut code = vec![0x49, 0xbb];
    code.extend(address.to_le_bytes());
    code.extend(opcode);
    run(engine, &code)
}

#[test]
fn native_qwords_and_subreads_publish_only_live_nonroot_backlinks() {
    let mut engine = engine();
    for depth in 1..=3 {
        let (address, expected) = field(&engine, depth);
        load(&mut engine, address, &[0x49, 0x8b, 0x03]).unwrap();
        assert_eq!(engine.reg_read(RegisterX86::RAX).unwrap(), expected);
        assert!(!failed(&engine));
        for offset in 0..8 {
            load(&mut engine, address + offset, &[0x41, 0x0f, 0xb6, 0x03]).unwrap();
            assert_eq!(
                engine.reg_read(RegisterX86::RAX).unwrap(),
                (expected >> (offset * 8)) & 255
            );
        }
    }
    assert_eq!(report(&engine).native_field_reads, 27);
    paging::audit(&engine).unwrap();
    assert!(
        engine
            .get_data()
            .apis
            .memory
            .allows(contract::BASE, contract::LENGTH, P::READ)
    );
    assert!(
        !engine
            .get_data()
            .apis
            .memory
            .allows(contract::BASE, 1, P::WRITE)
    );
    assert!(
        !engine
            .get_data()
            .apis
            .memory
            .allows(contract::BASE, 1, P::EXECUTE)
    );
}

#[test]
fn native_unsupported_root_padding_unknown_and_vector_loads_stop_before_consumption() {
    for case in 0..5 {
        let mut engine = engine();
        let (address, _) = field(&engine, 3);
        let root = engine
            .get_data()
            .apis
            .mdls
            .model
            .physical()
            .unwrap()
            .root_pfn();
        let (address, opcode): (_, &[u8]) = match case {
            0 => (contract::field_address(root).unwrap(), &[0x49, 0x8b, 0x03]),
            1 => (address - 1, &[0x49, 0x8b, 0x03]),
            2 => (contract::BASE, &[0x49, 0x8b, 0x03]),
            3 => (
                contract::field_address(250000).unwrap(),
                &[0x49, 0x8b, 0x03],
            ),
            _ => (address, &[0xf3, 0x41, 0x0f, 0x6f, 0x03]),
        };
        engine.reg_write(RegisterX86::RAX, 0xdeadbeef).unwrap();
        let _ = load(&mut engine, address, opcode);
        assert!(failed(&engine), "case {case}");
        assert_eq!(engine.reg_read(RegisterX86::RAX).unwrap(), 0xdeadbeef);
        assert_eq!(report(&engine).native_field_reads, 0);
        assert!(super::super::completion_error(&engine).is_some());
    }
}

#[test]
fn native_cross_boundary_load_and_direct_api_copies_are_refused() {
    let mut engine = engine();
    map(&mut engine, contract::BASE - PAGE, P::READ);
    engine.reg_write(RegisterX86::RAX, 0xdeadbeef).unwrap();
    let _ = load(&mut engine, contract::BASE - 1, &[0x41, 0x0f, 0xb7, 0x03]);
    assert!(failed(&engine));
    assert_eq!(engine.reg_read(RegisterX86::RAX).unwrap(), 0xdeadbeef);
    drop(engine);
    let mut engine = self::engine();
    let (address, _) = field(&engine, 3);
    load(&mut engine, address, &[0x49, 0x8b, 0x03]).unwrap();
    assert!(crate::api::read(&engine, address, 8).is_err());
    assert!(failed(&engine));
}

#[test]
fn retired_field_cannot_be_read_from_published_stale_backing() {
    let mut engine = engine();
    let authority = engine.get_data().apis.mdls.model.physical().unwrap();
    let table = authority
        .tables()
        .find(|table| table.depth == 3 && table.prefix == (DATA >> 21))
        .unwrap();
    let address = contract::field_address(table.pfn).unwrap();
    load(&mut engine, address, &[0x49, 0x8b, 0x03]).unwrap();
    engine.mem_unmap(DATA, PAGE).unwrap();
    engine.get_data_mut().apis.memory.unmap(DATA, PAGE).unwrap();
    engine.reg_write(RegisterX86::RAX, 0xdeadbeef).unwrap();
    let _ = load(&mut engine, address, &[0x49, 0x8b, 0x03]);
    assert!(failed(&engine));
    assert_eq!(engine.reg_read(RegisterX86::RAX).unwrap(), 0xdeadbeef);
    assert_eq!(report(&engine).native_field_reads, 1);
}

#[test]
fn api_write_and_mapping_attempts_do_not_mutate_metadata() {
    for case in 0..4 {
        let mut engine = engine();
        let (address, _) = field(&engine, 3);
        let memory = engine.get_data().apis.memory.clone();
        let bytes = engine.mem_read_as_vec(address, 8).unwrap();
        let result = match case {
            0 => crate::cpu::write(&mut engine, address, &[42]),
            1 => {
                crate::api::allocation::free(&mut engine, &[contract::BASE, 0, 0x8000]).map(|_| ())
            }
            2 => crate::api::allocation::protect(&mut engine, &[contract::BASE, PAGE, 0x40, DATA])
                .map(|_| ()),
            _ => {
                crate::api::allocation::allocate(&mut engine, &[contract::BASE, PAGE, 0x3000, 0x40])
                    .map(|_| ())
            }
        };
        assert!(result.is_err());
        assert!(failed(&engine));
        assert_eq!(engine.get_data().apis.memory, memory);
        assert_eq!(engine.mem_read_as_vec(address, 8).unwrap(), bytes);
    }
}

#[test]
fn native_write_and_execute_remain_protected() {
    let mut engine = engine();
    let (address, _) = field(&engine, 3);
    assert!(load(&mut engine, address, &[0x49, 0xc7, 0x03, 1, 0, 0, 0]).is_err());
    assert_eq!(engine.mem_read_as_vec(address, 8).unwrap(), [0; 8]);
    assert!(engine.emu_start(address, address + 1, 0, 1).is_err());
}

#[test]
fn publication_failure_retains_backing_and_poison_while_mirror_corruption_is_refused() {
    let mut engine = engine();
    let (address, _) = field(&engine, 3);
    engine.get_data_mut().apis.mdls.pfn.fail_after_write = true;
    let _ = load(&mut engine, address, &[0x49, 0x8b, 0x03]);
    assert!(failed(&engine));
    assert!(engine.get_data().apis.mdls.poisoned);
    assert!(
        engine
            .get_data()
            .apis
            .memory
            .allows(contract::BASE, contract::LENGTH, P::READ)
    );
    assert_eq!(report(&engine).native_field_reads, 0);
    drop(engine);
    let mut engine = self::engine();
    let (address, _) = field(&engine, 3);
    load(&mut engine, address, &[0x49, 0x8b, 0x03]).unwrap();
    engine.mem_write(address, &[0x42; 8]).unwrap();
    let _ = load(&mut engine, address, &[0x49, 0x8b, 0x03]);
    assert!(failed(&engine));
    assert_eq!(engine.mem_read_as_vec(address, 8).unwrap(), [0x42; 8]);
    assert_eq!(report(&engine).native_field_reads, 1);
}

#[test]
fn reservation_collision_and_missing_paging_authority_fail_before_mapping() {
    let mut engine = engine();
    assert!(initialize(&mut engine).is_err());
    drop(engine);
    let trace = crate::kernel_capture_tests::prepared(26200, false)
        .into_trace()
        .unwrap();
    let mut engine = crate::new_engine_with_trace(trace).unwrap();
    engine
        .get_data_mut()
        .apis
        .target(Architecture::X64, true)
        .unwrap();
    engine.get_data_mut().apis.mdls.pfn.requested = true;
    assert!(initialize(&mut engine).is_err());
    assert!(
        !engine
            .get_data()
            .apis
            .memory
            .allows(contract::BASE, 1, P::READ)
    );
    engine.get_data_mut().apis.mdls.owned_paging_requested = true;
    map(&mut engine, contract::BASE, P::RW);
    let before = engine.get_data().apis.memory.clone();
    assert!(initialize(&mut engine).is_err());
    assert_eq!(engine.get_data().apis.memory, before);
}

#[test]
fn system_thread_timeout_reader_refuses_metadata_without_using_filler() {
    let mut engine = engine();
    let (address, _) = field(&engine, 3);
    let error = crate::threads::delay(&mut engine, &[0, 0, address]).unwrap_err();
    assert!(error.to_string().contains("API copies are not admitted"));
    assert!(failed(&engine));
    assert_eq!(report(&engine).native_field_reads, 0);
}

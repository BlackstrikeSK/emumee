//! Owned synthetic programs and explicit native/model fault injection only.
use super::*;
use emumee_core::{
    fixtures::{ApiFixture, MdlFixture},
    kernel_layout::{ENTRY_STACK_SIZE, KernelLayout},
};

pub(super) fn map(engine: &mut Unicorn<Trace>, base: u64, size: u64) {
    uc(engine.mem_map(base, size, Prot::READ | Prot::WRITE)).unwrap();
    engine
        .get_data_mut()
        .apis
        .memory
        .map(base, size, P::RW, Some(4), "owned physical-query test")
        .unwrap();
}
fn engine() -> crate::NativeEngine {
    engine_with_owned(false)
}
pub(super) fn engine_with_owned(owned: bool) -> crate::NativeEngine {
    let trace = crate::kernel_capture_tests::prepared(26200, false)
        .into_trace()
        .unwrap();
    let mut e = crate::new_engine_with_trace(trace).unwrap();
    e.get_data_mut()
        .apis
        .target(Architecture::X64, true)
        .unwrap();
    crate::api::kernel_objects::initialize(&mut e).unwrap();
    let layout = KernelLayout::for_architecture(Architecture::X64);
    map(&mut e, layout.driver_object, 3 * 4096);
    map(&mut e, layout.entry_stack, ENTRY_STACK_SIZE);
    crate::api::kernel_thread_objects::initialize_root(&mut e).unwrap();
    e.get_data_mut().apis.mdls.owned_paging_requested = owned;
    crate::kernel_cpu::initialize(&mut e).unwrap();
    uc(e.reg_write(
        RegisterX86::RSP,
        layout.entry_stack + ENTRY_STACK_SIZE - 0x108,
    ))
    .unwrap();
    e
}
pub(super) fn query(e: &mut Unicorn<Trace>, raw: u64) -> Result<u64> {
    uc(e.reg_write(RegisterX86::RCX, raw))?;
    super::super::call(e, Call::Physical, &[raw])
}

#[test]
fn nonpresent_queries_audit_native_topology_spill_exactly_and_never_allocate_frames() {
    let mut e = engine();
    let raw = 0x8040201000;
    let rsp = uc(e.reg_read(RegisterX86::RSP)).unwrap();
    assert!(enabled(&e));
    for (level, ancestor) in [
        (0, None),
        (1, Some(0x8000000000)),
        (2, Some(0x8040000000)),
        (3, Some(0x8040200000)),
    ] {
        if let Some(at) = ancestor {
            map(&mut e, at, 4096);
        }
        uc(e.reg_write(RegisterX86::RCX, raw)).unwrap();
        let regs = registers(&e).unwrap();
        let flags = uc(e.reg_read(RegisterX86::EFLAGS)).unwrap();
        let projected = core::project_absent(
            core::Absent {
                virtual_address: raw,
                first_missing_level: level,
            },
            regs,
            flags,
            0,
            None,
        )
        .unwrap();
        assert_eq!(query(&mut e, raw).unwrap(), 0);
        // Common API dispatch owns RET; direct calls must not advance RSP.
        assert_eq!(uc(e.reg_read(RegisterX86::RSP)).unwrap(), rsp);
        assert_eq!(e.get_data().apis.mdls.model.frame_count(), 0);
        for spill in &projected.spills {
            assert_eq!(
                uc(e.mem_read_as_vec(spill.address, 8)).unwrap(),
                spill.bytes
            );
        }
        let mut after = registers(&e).unwrap();
        after.rsp += 8;
        assert_eq!(after, projected.registers);
        assert_eq!(
            uc(e.reg_read(RegisterX86::EFLAGS)).unwrap(),
            projected.flags
        );
        assert_eq!(report(&e).events.last().unwrap().first_missing_level, level);
    }
    assert_eq!(report(&e).events.len(), 4);
    let a = 0x1234008040201000;
    assert_eq!(core::paging_alias(a), raw);
    assert_eq!(query(&mut e, a).unwrap(), 0);
    assert_eq!(report(&e).events.last().unwrap().raw_address, a);
    // A mapped positive address keeps the existing stable synthetic PFN path.
    map(&mut e, raw, 4096);
    let physical = query(&mut e, raw).unwrap();
    assert_ne!(physical, 0);
    assert_eq!(query(&mut e, raw + 123).unwrap(), physical + 123);
    assert_eq!(e.get_data().apis.mdls.model.frame_count(), 1);
    assert!(
        query(&mut e, a)
            .unwrap_err()
            .to_string()
            .contains("Positive noncanonical")
    );
    assert_eq!(report(&e).events.len(), 5);
    e.mem_unmap(raw, 4096).unwrap();
    e.get_data_mut().apis.memory.unmap(raw, 4096).unwrap();
    assert_eq!(query(&mut e, raw).unwrap(), 0);
    assert_eq!(report(&e).events.last().unwrap().first_missing_level, 3);
}

#[test]
fn mapping_disagreement_control_context_and_unknown_native_inputs_refuse_before_spills() {
    let raw = 0x8040201000;
    let mut e = engine();
    let rsp = uc(e.reg_read(RegisterX86::RSP)).unwrap();
    let before = uc(e.mem_read_as_vec(rsp - 0x78, 0xa0)).unwrap();
    e.mem_map(raw, 4096, Prot::READ).unwrap();
    assert!(
        query(&mut e, raw)
            .unwrap_err()
            .to_string()
            .contains("presence disagreement")
    );
    assert_eq!(uc(e.mem_read_as_vec(rsp - 0x78, 0xa0)).unwrap(), before);
    e.mem_unmap(raw, 4096).unwrap();
    e.get_data_mut()
        .apis
        .memory
        .map(
            raw,
            4096,
            P::READ,
            None,
            "deliberately missing native mapping",
        )
        .unwrap();
    assert!(
        query(&mut e, raw)
            .unwrap_err()
            .to_string()
            .contains("presence disagreement")
    );
    e.get_data_mut().apis.memory.unmap(raw, 4096).unwrap();
    // A disagreement elsewhere inside this PML4 subtree cannot hide behind
    // matching boolean prefix presence.
    map(&mut e, 0x8000000000, 4096);
    e.mem_map(0x8000002000, 4096, Prot::READ).unwrap();
    assert!(
        query(&mut e, raw)
            .unwrap_err()
            .to_string()
            .contains("presence disagreement")
    );
    e.mem_unmap(0x8000002000, 4096).unwrap();
    let view = 0xfffff6fb7dbed000;
    map(&mut e, view, 4096);
    assert!(
        query(&mut e, raw)
            .unwrap_err()
            .to_string()
            .contains("PTE view overlaps")
    );
    e.mem_unmap(view, 4096).unwrap();
    e.get_data_mut().apis.memory.unmap(view, 4096).unwrap();
    let stack_page = rsp & !4095;
    e.mem_protect(stack_page, 4096, Prot::READ).unwrap();
    assert!(
        query(&mut e, raw)
            .unwrap_err()
            .to_string()
            .contains("native stack write permissions")
    );
    assert!(!e.get_data().apis.mdls.poisoned);
    assert_eq!(uc(e.mem_read_as_vec(rsp - 0x78, 0xa0)).unwrap(), before);
    e.mem_protect(stack_page, 4096, Prot::READ | Prot::WRITE)
        .unwrap();
    let cr3 = uc(e.reg_read(RegisterX86::CR3)).unwrap();
    uc(e.reg_write(RegisterX86::CR3, cr3 ^ 4096)).unwrap();
    assert!(
        query(&mut e, raw)
            .unwrap_err()
            .to_string()
            .contains("paging context differs")
    );
    uc(e.reg_write(RegisterX86::CR3, cr3)).unwrap();
    let cr4 = uc(e.reg_read(RegisterX86::CR4)).unwrap();
    uc(e.reg_write(RegisterX86::CR4, cr4 | 4096)).unwrap();
    assert!(
        query(&mut e, raw)
            .unwrap_err()
            .to_string()
            .contains("paging context differs")
    );
    uc(e.reg_write(RegisterX86::CR4, cr4)).unwrap();
    let kernel_leaf = 0xffffa00000110000;
    assert!(
        query(&mut e, kernel_leaf)
            .unwrap_err()
            .to_string()
            .contains("NeedsKernelClassification")
    );
    assert!(
        query(&mut e, 0xfffff6fb7dbed000)
            .unwrap_err()
            .to_string()
            .contains("AliasedPteAddresses")
    );
    e.get_data_mut().apis.mdls.process = 8;
    assert!(
        query(&mut e, raw)
            .unwrap_err()
            .to_string()
            .contains("system-process")
    );
    assert_eq!(uc(e.mem_read_as_vec(rsp - 0x78, 0xa0)).unwrap(), before);
    assert_eq!(e.get_data().apis.mdls.model.frame_count(), 0);
    assert!(!e.get_data().apis.mdls.poisoned);
}

#[test]
fn partial_native_stack_failure_latches_completion_and_preserves_prior_effects() {
    let mut e = engine();
    let rsp = uc(e.reg_read(RegisterX86::RSP)).unwrap();
    // Both permission inventories pass preflight. A test-only native unmap
    // before the second save forces a genuine partial write failure.
    let boundary = rsp & !4095;
    uc(e.reg_write(RegisterX86::RSP, boundary - 0x18)).unwrap();
    e.get_data_mut().apis.mdls.physical.fail_before_spill = Some(1);
    let raw = 0x8040201000;
    uc(e.reg_write(RegisterX86::RBX, 0x1122334455667788)).unwrap();
    assert!(query(&mut e, raw).is_err());
    assert!(e.get_data().apis.mdls.poisoned);
    assert!(super::super::completion_error(&e).is_some());
    assert_eq!(
        uc(e.mem_read_as_vec(boundary - 8, 8)).unwrap(),
        0x1122334455667788u64.to_le_bytes()
    );
    assert_eq!(e.get_data().apis.mdls.model.frame_count(), 0);
    assert!(report(&e).events.is_empty());
    assert!(
        query(&mut e, raw)
            .unwrap_err()
            .to_string()
            .contains("cannot resume")
    );
}

#[test]
fn generated_native_caller_observes_zero_then_returns_with_its_stack_intact() {
    let mut image =
        emumee_core::fixtures::api_probe(Architecture::X64, ApiFixture::Mdl(MdlFixture::Lifecycle));
    let mut code = vec![0x48, 0x83, 0xec, 0x68, 0x48, 0xb9];
    code.extend(0x8040201000u64.to_le_bytes());
    let next = 0x1000 + code.len() as i32 + 6;
    code.extend([0xff, 0x15]);
    code.extend((0x20a0i32 - next).to_le_bytes());
    code.extend([
        0x48, 0x85, 0xc0, 0x74, 0x02, 0x0f, 0x0b, 0xb8, 42, 0, 0, 0, 0x48, 0x83, 0xc4, 0x68, 0xc3,
    ]);
    image[0x200..0x1200].fill(0);
    image[0x200..0x200 + code.len()].copy_from_slice(&code);
    let execution = crate::run_generated_with_fixture_configuration(
        &image,
        &[],
        10000,
        30_000_000,
        crate::GeneratedConfiguration {
            configured: Some(crate::kernel_capture_tests::prepared(26200, false)),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(execution.error, None);
    assert_eq!(execution.guest_entry_return, Some(42));
    let mdls = execution.kernel_mdls.unwrap();
    assert_eq!(mdls.model.frame_count(), 0);
    assert_eq!(mdls.physical_queries.events.len(), 1);
}

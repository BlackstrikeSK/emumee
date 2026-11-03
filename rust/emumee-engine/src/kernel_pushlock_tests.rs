//! Owned generated programs only; no submitted/reference code execution.
use super::*;
use emumee_core::fixtures::{ApiFixture, SyncFixture as S};
#[test]
fn owned_exclusive_release_preserves_dispatch_level_until_caller_lowers_it() {
    let mut image = emumee_core::fixtures::api_probe(Architecture::X64, ApiFixture::Sync(S::Push));
    let mut code = vec![0x48, 0x83, 0xec, 0x68];
    fn call(code: &mut Vec<u8>, index: u32) {
        let next = 0x1000 + code.len() as i32 + 6;
        code.extend([0xff, 0x15]);
        code.extend((0x2080 + index as i32 * 8 - next).to_le_bytes());
    }
    fn lock(code: &mut Vec<u8>) {
        code.extend([0x48, 0xb9]);
        code.extend(0x140003000u64.to_le_bytes());
        code.extend([0x31, 0xd2]);
    }
    lock(&mut code);
    call(&mut code, 4);
    call(&mut code, 12);
    lock(&mut code);
    call(&mut code, 5);
    code.extend([0xb8, 2, 0, 0, 0, 0x44, 0x0f, 0x22, 0xc0]);
    lock(&mut code);
    call(&mut code, 6);
    // Read CR8 before lowering it: a final-state-only assertion could miss an
    // incorrect implicit lowering inside the release adapter.
    code.extend([0x44, 0x0f, 0x20, 0xc0, 0x3c, 2, 0x74, 2, 0x0f, 0x0b]);
    code.extend([0x31, 0xc0, 0x44, 0x0f, 0x22, 0xc0]);
    call(&mut code, 13);
    code.extend([0xb8, 42, 0, 0, 0, 0x48, 0x83, 0xc4, 0x68, 0xc3]);
    image[0x200..0x1200].fill(0);
    image[0x200..0x200 + code.len()].copy_from_slice(&code);
    let e = run_generated_with_fixture_configuration(
        &image,
        &[],
        10000,
        30_000_000,
        GeneratedConfiguration {
            configured: Some(crate::kernel_capture_tests::prepared(26200, false)),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(e.error, None);
    assert_eq!(e.guest_entry_return, Some(42));
    assert_eq!(e.kernel_state.unwrap().irql, 0);
    assert!(
        e.kernel_pushlocks
            .unwrap()
            .state
            .locks
            .values()
            .all(|l| l.held.is_none())
    );
}
#[test]
fn push_epilogue_flags_match_an_owned_native_add_instruction() {
    use emumee_core::kernel_autoboost::abi;
    let mut e = crate::new_engine(Architecture::X64).unwrap();
    uc(e.mem_map(0x100000, 4096, Prot::ALL)).unwrap();
    uc(e.mem_write(0x100000, &[0x48, 0x83, 0xc4, 0x30])).unwrap();
    for rsp in [
        0x88,
        0xff,
        0x100,
        0x1008,
        0x7fff_ffff_ffff_fff8,
        0x8000_0000_0000_0008,
        0xffff_a000_000f_f488,
    ] {
        for flags in [2, 0x202, 0x602, 0xad7] {
            uc(e.reg_write(RegisterX86::RSP, rsp - 0x38)).unwrap();
            uc(e.reg_write(RegisterX86::EFLAGS, flags | 0x200)).unwrap();
            let old = uc(e.reg_read(RegisterX86::EFLAGS)).unwrap();
            uc(e.emu_start(0x100000, 0x100004, 0, 1)).unwrap();
            let regs = abi::Registers {
                rax: 0,
                rbx: 0,
                rcx: 0,
                rdx: 0,
                rbp: 0,
                rsi: 0,
                rdi: 0,
                rsp,
                r8: 0,
                r9: 0,
                r10: 0,
                r11: 0,
                r14: 0,
            };
            let projected = abi::stable(
                "acquire",
                regs,
                old,
                0xffff_f800_0040_0000,
                0,
                0xffff_a100_0000_2000,
                Some(0xffff_a100_0000_2810),
            )
            .unwrap();
            assert_eq!(
                projected.flags,
                uc(e.reg_read(RegisterX86::EFLAGS)).unwrap()
            );
        }
    }
}
fn run(kind: S, drop_leave: bool) -> Execution {
    let mut image = emumee_core::fixtures::api_probe(Architecture::X64, ApiFixture::Sync(kind));
    if drop_leave {
        let mut changed = 0;
        for at in 0x200..0x11f0 {
            if image[at..at + 2] == [0xff, 0x15] {
                let disp = i32::from_le_bytes(image[at + 2..at + 6].try_into().unwrap()) as i64;
                if 0x1000 + (at as i64 - 0x200) + 6 + disp == 0x20e8 {
                    // This legacy negative fixture ends in INT3. Give the now
                    // supported native path an owned balanced epilogue instead.
                    image[at..at + 10]
                        .copy_from_slice(&[0xb8, 1, 0, 0, 0, 0x48, 0x83, 0xc4, 0x68, 0xc3]);
                    changed += 1;
                }
            }
        }
        assert_eq!(changed, 1);
    }
    run_generated_with_fixture_configuration(
        &image,
        &[],
        10000,
        30_000_000,
        GeneratedConfiguration {
            configured: Some(crate::kernel_capture_tests::prepared(26200, false)),
            ..Default::default()
        },
    )
    .unwrap()
}
#[test]
fn pinned_owned_pushlocks_preserve_apc_state_and_report_native_contract_diagnostics() {
    for (kind, drop_leave, critical) in [
        (S::Push, false, true),
        (S::PushFlagWidth, false, true),
        (S::PushApcs, true, false),
    ] {
        let e = run(kind, drop_leave);
        assert_eq!(e.error, None, "{kind:?}");
        assert_eq!(e.guest_entry_return, Some(1));
        let report = e.kernel_pushlocks.unwrap();
        assert!(!report.native_effect_failure);
        assert_eq!(report.events.len(), 3);
        assert_eq!(report.events[1].operation, "acquire");
        assert_eq!(report.events[2].operation, "release");
        assert_eq!(report.events[1].documented_apc_contract_satisfied, critical);
        assert_eq!(report.events[2].documented_apc_contract_satisfied, critical);
        let root = report.state.threads.values().find(|t| t.slot == 1).unwrap();
        assert_eq!(&root.bytes[8..10], &[0x3f, 0]);
        assert!(report.state.locks.values().all(|l| l.held.is_none()));
        assert_eq!(e.kernel_state.unwrap().critical_depth, 0);
        let fields = &e.kernel_thread_objects.unwrap().thread_fields;
        assert_eq!(fields[0].raw_kernel_apc_disable, 0);
    }
}
#[test]
fn pinned_owned_pushlocks_refuse_recursion_flags_corruption_and_wrong_release() {
    for (kind, expected) in [
        (S::PushBlocked, "recursive"),
        (S::PushFlags, "nonzero push flags"),
        (S::PushRelease, "ownership"),
        (S::PushTamper, "Direct guest mutation"),
    ] {
        let e = run(kind, false);
        assert!(
            e.error.as_deref().is_some_and(|s| s.contains(expected)),
            "{kind:?}:{:?}",
            e.error
        );
        assert_eq!(e.guest_entry_return, None);
        let report = e.kernel_pushlocks.unwrap();
        if matches!(kind, S::PushTamper) {
            assert!(report.native_effect_failure);
        } else {
            assert!(!report.native_effect_failure);
        }
    }
}

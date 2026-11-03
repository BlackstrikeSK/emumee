use super::*;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize, Debug, PartialEq, Eq)]
struct NativeWrite {
    address: u64,
    before: Vec<u8>,
    after: Vec<u8>,
}
#[derive(Deserialize)]
struct NativeEvent {
    operation: String,
    index: u64,
    before: u64,
    after: u64,
    writes: Vec<NativeWrite>,
    block_sha256: String,
    interrupts_enabled: bool,
    before_registers: crate::kernel_autoboost::abi::Registers,
    after_registers: crate::kernel_autoboost::abi::Registers,
    stack_writes: Vec<NativeWrite>,
}
#[derive(Deserialize)]
struct NativeCase {
    raw_kernel_apc_disable: u16,
    initial_block_sha256: String,
    events: Vec<NativeEvent>,
}
#[derive(Deserialize)]
struct Fixture {
    cases: Vec<NativeCase>,
}

#[test]
fn complete_stable_data_effects_match_independent_native_call_sequences() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/native_autoboost_protocol.json"
    ))
    .unwrap();
    assert_eq!(fixture.cases.len(), 16);
    let mut events = 0;
    for case in fixture.cases {
        let mut state = State::default().register_thread(&life(1)).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&state.threads[&THREAD].bytes)),
            case.initial_block_sha256
        );
        for event in case.events {
            let mut i = input(THREAD, BASE + 0x1000 + event.index * 16, event.before);
            i.normal_apcs_disabled = case.raw_kernel_apc_disable != 0;
            let plan = match event.operation.as_str() {
                "initialize" => state.initialize_lock(i),
                "acquire" => state.acquire(i),
                "release" => state.release(i),
                _ => panic!("unknown fixture operation"),
            }
            .unwrap();
            let abi = crate::kernel_autoboost::abi::stable(
                &event.operation,
                event.before_registers,
                0x202,
                0xffff_f800_0040_0000,
                0x70000000,
                THREAD,
                plan.entry_address,
            )
            .unwrap();
            assert_eq!(
                abi.registers, event.after_registers,
                "{} register ABI",
                event.operation
            );
            assert_eq!(
                abi.spills
                    .iter()
                    .map(|w| (w.address, w.bytes.clone()))
                    .collect::<Vec<_>>(),
                event
                    .stack_writes
                    .iter()
                    .map(|w| (w.address, w.after.clone()))
                    .collect::<Vec<_>>(),
                "{} stack ABI",
                event.operation
            );
            let writes: Vec<_> = plan
                .writes
                .iter()
                .map(|w| NativeWrite {
                    address: w.address,
                    before: w.before.clone(),
                    after: w.after.clone(),
                })
                .collect();
            assert_eq!(
                writes, event.writes,
                "{} at{:x}",
                event.operation, i.address
            );
            assert_eq!(
                format!("{:x}", Sha256::digest(&plan.state.threads[&THREAD].bytes)),
                event.block_sha256
            );
            assert_eq!(
                u64::from(plan.state.locks[&i.address].held.is_some()),
                event.after
            );
            if event.operation != "initialize" {
                assert_eq!(plan.enables_interrupts, event.interrupts_enabled);
            }
            state = plan.state;
            events += 1;
        }
        state.require_thread_exit(THREAD).unwrap();
    }
    assert_eq!(events, 344);
}

const THREAD: u64 = 0xffff_a100_0000_2000;
const BASE: u64 = 0xffff_f801_0000_0000;
fn life(slot: u64) -> Lifetime {
    Lifetime {
        slot,
        guest_id: slot,
        address: THREAD + (slot - 1) * 4096,
        owner: 0xffff_a100_0000_4000,
        root_caller: slot == 1,
        role: if slot == 1 {
            Ownership::InitialCaller
        } else {
            Ownership::CreatedSystemThread
        },
        executing: true,
        open_handles: 1,
        terminated: false,
        retired: false,
    }
}
fn input(thread: u64, address: u64, word: u64) -> Input {
    Input {
        thread,
        address,
        word,
        backing: Backing::Image {
            base: BASE,
            size: 0x100000,
        },
        flags: 0,
        work_priority_kick: Some(0),
        normal_apcs_disabled: false,
    }
}
fn setup(count: usize) -> State {
    let mut s = State::default().register_thread(&life(1)).unwrap();
    for i in 0..count {
        s = s
            .initialize_lock(input(THREAD, BASE + 0x1000 + i as u64 * 16, 0x55))
            .unwrap()
            .state;
    }
    s
}

#[test]
fn owned_entries_reserve_all_six_reuse_holes_and_never_fake_exhaustion_or_recursion() {
    let mut s = setup(7);
    assert_eq!(s.threads[&THREAD].bytes[8], 0x3f);
    for i in 0..6 {
        let at = BASE + 0x1000 + i * 16;
        let plan = s.acquire(input(THREAD, at, 0)).unwrap();
        assert_eq!(plan.entry_address, Some(THREAD + 0x810 + i * 0x58));
        assert_eq!(plan.writes.len(), 4);
        assert!(plan.enables_interrupts);
        assert!(!plan.normal_apcs_disabled);
        s = plan.state;
        assert!(
            s.acquire(input(THREAD, at, 1))
                .unwrap_err()
                .0
                .contains("recursive")
        );
    }
    assert!(
        s.acquire(input(THREAD, BASE + 0x1060, 0))
            .unwrap_err()
            .0
            .contains("exhaustion")
    );
    assert!(s.require_thread_exit(THREAD).is_err());
    let released = s.release(input(THREAD, BASE + 0x1020, 1)).unwrap();
    assert_eq!(released.writes.len(), 6);
    s = released.state;
    assert_eq!(s.threads[&THREAD].bytes[8], 4);
    let next = s.acquire(input(THREAD, BASE + 0x1060, 0)).unwrap();
    assert_eq!(next.entry_address, Some(THREAD + 0x8c0));
    assert!(next.state.require_thread_exit(THREAD).is_err());
}

#[test]
fn ownership_lifetime_and_backing_boundaries_do_not_reset_or_repair_state() {
    let s = setup(2).register_thread(&life(2)).unwrap();
    let at = BASE + 0x1000;
    for address in [
        0x8000_0000_0000_0000,
        0x0000_8000_0000_0000,
        0xffff_7fff_ffff_fff8,
    ] {
        let mut invalid = input(THREAD, address, 0);
        invalid.backing = Backing::Image {
            base: address,
            size: 4096,
        };
        assert!(
            s.initialize_lock(invalid)
                .unwrap_err()
                .0
                .contains("noncanonical")
        );
    }
    let mut invalid_life = life(1);
    invalid_life.address = u64::MAX - 4095;
    assert!(State::default().register_thread(&invalid_life).is_err());
    let held = s.acquire(input(THREAD, at, 0)).unwrap().state;
    assert!(held.release(input(THREAD + 4096, at, 1)).is_err());
    assert!(
        held.acquire(input(THREAD + 4096, at, 1))
            .unwrap_err()
            .0
            .contains("contended")
    );
    assert!(held.initialize_lock(input(THREAD, at, 1)).is_err());
    assert!(held.retire_backing(at, 8).is_err());
    assert!(
        held.acquire(input(THREAD, BASE + 0x1010, 1))
            .unwrap_err()
            .0
            .contains("diverged")
    );
    for kick in [None, Some(1)] {
        let mut i = input(THREAD, BASE + 0x1010, 0);
        i.work_priority_kick = kick;
        assert!(held.acquire(i).is_err());
    }
    let mut other = input(THREAD, BASE + 0x1010, 0);
    other.backing = Backing::Image {
        base: BASE + 0x100,
        size: 0x100000,
    };
    assert!(held.acquire(other).is_err());
    for flags in [1, 2, 4, 8, u32::MAX] {
        let mut i = input(THREAD, BASE + 0x1010, 0);
        i.flags = flags;
        assert!(held.acquire(i).is_err());
    }
    let free = held.release(input(THREAD, at, 1)).unwrap().state;
    free.require_thread_exit(THREAD).unwrap();
    let mut ended = life(1);
    ended.executing = false;
    ended.terminated = true;
    let ended_state = free.finish_thread(&ended).unwrap();
    assert!(ended_state.acquire(input(THREAD, at, 0)).is_err());
    ended.retired = true;
    let retired = ended_state.finish_thread(&ended).unwrap();
    assert!(!retired.threads[&THREAD].live);
    assert!(retired.register_thread(&life(1)).is_err());
    let retired = free.retire_backing(BASE, 0x100000).unwrap();
    assert!(retired.acquire(input(THREAD, at, 0)).is_err());
    let initialized = retired.initialize_lock(input(THREAD, at, 0)).unwrap();
    assert_eq!(initialized.state.locks[&at].initialization, 2);
    let mut parked = life(3);
    parked.role = Ownership::ParkedProcessor { processor: 1 };
    assert!(s.register_thread(&parked).is_err());
}

#[test]
fn corrupted_entry_metadata_never_selects_a_favorable_native_cold_path() {
    let s = setup(1);
    let at = BASE + 0x1000;
    for offset in [0x10, 0x18, 0x19, 0x1a, 0x60] {
        let mut bad = s.clone();
        bad.threads.get_mut(&THREAD).unwrap().bytes[offset] ^= 0x80;
        assert!(
            bad.acquire(input(THREAD, at, 0)).is_err(),
            "offset{offset:x}"
        );
    }
    let held = s.acquire(input(THREAD, at, 0)).unwrap().state;
    for offset in [0x10, 0x17, 0x19, 0x1a, 0x60] {
        let mut bad = held.clone();
        bad.threads.get_mut(&THREAD).unwrap().bytes[offset] ^= 0x80;
        assert!(
            bad.release(input(THREAD, at, 1)).is_err(),
            "offset{offset:x}"
        );
    }
    assert_eq!(s.threads[&THREAD].bytes[8], 0x3f);
}

//! Pinned stable path native ABI side effects, separate from the data/owner plan.
//! Internal helper return addresses are virtual kernel addresses, never calls
//! into reference code. Ordinary stack bounds and nonaliasing are adapter facts.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Registers {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r14: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Spill {
    pub address: u64,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Effects {
    pub registers: Registers,
    pub spills: Vec<Spill>,
    pub flags: u64,
}
fn add_flags(a: u64, b: u64, old: u64) -> u64 {
    let (r, cf) = a.overflowing_add(b);
    let of = (!(a ^ b) & (a ^ r)) >> 63 != 0;
    (old & !0x8d5)
        | u64::from(cf)
        | (u64::from((r as u8).count_ones() % 2 == 0) << 2)
        | (u64::from((a ^ b ^ r) & 0x10 != 0) << 4)
        | (u64::from(r == 0) << 6)
        | ((r >> 63) << 7)
        | (u64::from(of) << 11)
}
pub fn stable(
    operation: &str,
    old: Registers,
    old_flags: u64,
    kernel_base: u64,
    prcb: u64,
    thread: u64,
    entry: Option<u64>,
) -> Option<Effects> {
    let mut registers = old;
    let mut spills = Vec::new();
    let mut put = |address: u64, value: u64, size: usize| {
        spills.push(Spill {
            address,
            bytes: value.to_le_bytes()[..size].to_vec(),
        })
    };
    let s = old.rsp;
    if s < 0x88 || s.checked_add(0x10).is_none() {
        return None;
    }
    registers.rsp = s + 8;
    if operation == "initialize" {
        return Some(Effects {
            registers,
            spills,
            flags: (old_flags & !0x8d5) | 0x44,
        });
    }
    let at = entry?;
    let block = thread.checked_add(super::owned::BLOCK_PAGE_OFFSET + super::HEADER_BYTES as u64)?;
    let offset = at.checked_sub(block)?;
    if offset % super::ENTRY_BYTES as u64 != 0
        || offset / super::ENTRY_BYTES as u64 >= super::owned::KERNEL_ENTRY_COUNT as u64
    {
        return None;
    }
    // Caller checks the subtraction/addition domain against its owned stack.
    put(s + 8, old.rbx, 8);
    put(s - 8, old.rdi, 8);
    if operation == "acquire" {
        put(s - 0x40, kernel_base.checked_add(0x20fc4e)?, 8);
        put(s - 0x48, old.rcx, 8);
        put(s - 0x50, old.rbp, 8);
        put(s - 0x58, old.rdi, 8);
        put(s - 0x38, old.rsi, 8);
        put(s - 0x30, 0, 4);
        put(s - 0x20, 0, 8);
        // The stored index follows from the owned six-entry allocation geometry.
        let index = offset / super::ENTRY_BYTES as u64;
        put(s - 0x30, index, 4);
        registers.rax = at;
        registers.rcx = old.rcx & 0x7fff_ffff_ffff_fffc;
        registers.rdx = 0;
        registers.r8 = 0;
    } else if operation == "release" {
        put(s - 0x18, 0, 8);
        put(s - 0x40, kernel_base.checked_add(0x263600)?, 8);
        put(s - 0x38, 0x7fff_ffff_ffff_fffc, 8);
        put(s - 0x30, old.rbp, 8);
        put(s - 0x28, old.rsi, 8);
        put(s - 0x20, old.rcx, 8);
        put(s - 0x48, old.r14, 8);
        registers.rax = 0;
        registers.rcx = prcb;
        registers.rdx = thread;
        registers.r8 = 0;
        registers.r9 = 1;
        registers.r10 = thread;
        registers.r11 = at - 0x10;
    } else {
        return None;
    }
    Some(Effects {
        registers,
        spills,
        flags: add_flags(s - 0x38, 0x30, old_flags | 0x200),
    })
}

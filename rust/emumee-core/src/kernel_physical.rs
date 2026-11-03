//! Pinned x64 nonpresent physical-query effects over an explicit owned walk.
//!
//! Present ancestors have the declared ordinary value0x23; the first missing
//! entry is zero. This is an abstract owned four-level page-table profile, not
//! a reconstruction of host page tables, a CR3 value, or native boot state.
//! The adapter must prove this profile and publish all returned stack effects
//! before committing. Unknown region classification and logging stay explicit.
use crate::memory::AddressSpace;
use crate::pe::Architecture;
use serde::Serialize;

pub mod owned;

const PTE_BASE: u64 = 0xffff_f680_0000_0000;
const PML4_START: u64 = 0xffff_f6fb_7dbe_d000;
const PML4_END: u64 = 0xffff_f6fb_7dbe_d7f8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    InvalidLevel,
    AliasedPteAddresses,
    StackGeometry,
    NeedsKernelClassification,
    NeedsDriverAddressLog,
    ArgumentMismatch,
    WrongArchitecture,
    KernelGeometry,
    NeedsEntryRepair,
    NeedsLargePage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Absent {
    pub virtual_address: u64,
    ///0=PML4E,1=PDPTE,2=PDE,3=PTE.
    pub first_missing_level: u8,
}

pub fn canonical(address: u64) -> bool {
    address <= 0x0000_7fff_ffff_ffff || address >= 0xffff_8000_0000_0000
}

/// The native routine masks bits48..63 while deriving its PTE addresses. It
/// does not dereference the original argument, so noncanonical arguments are
/// not CPU faults here. The original raw argument still controls classification.
pub fn paging_alias(address: u64) -> u64 {
    ((address << 16) as i64 >> 16) as u64
}

/// Absence in the logical owned4KiB mapping hierarchy. It does not manufacture
/// native PTE bytes. The adapter separately authorizes the ordinary0x23 profile.
pub fn absent_in_owned_space(
    memory: &AddressSpace,
    address: u64,
) -> Result<Option<Absent>, Refusal> {
    if memory.architecture() != Architecture::X64 {
        return Err(Refusal::WrongArchitecture);
    }
    let raw_address = address;
    let address = paging_alias(address);
    for (level, shift) in [39, 30, 21, 12].into_iter().enumerate() {
        let size = 1u64 << shift;
        let base = address & !(size - 1);
        // Saturation includes the final canonical block ending at2^64.
        let last = base | (size - 1);
        let present = memory
            .regions()
            .any(|r| r.base <= last && r.base.saturating_add(r.size - 1) >= base);
        if !present {
            return Ok(Some(Absent {
                virtual_address: raw_address,
                first_missing_level: level as u8,
            }));
        }
    }
    Ok(None)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
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
    pub r15: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Spill {
    pub address: u64,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Projection {
    pub registers: Registers,
    pub flags: u64,
    pub spills: Vec<Spill>,
    /// Leaf-first PTE, PDE, PDPTE and PML4E virtual read addresses.
    pub pte_addresses: [u64; 4],
    pub classification_read: Option<u64>,
}

fn low_byte(value: u64, byte: u8) -> u64 {
    value & !255 | u64::from(byte)
}

/// Project the pinned native nonpresent path. The caller supplies valid complete
/// nonaliasing stack geometry, actual entry registers and optional classification
/// as an established fact. Native callee-saved registers are restored, RSP advances
/// through RET, and AF is undefined by the final TEST (represented as zero).
pub fn project_absent(
    absent: Absent,
    before: Registers,
    flags: u64,
    kernel_base: u64,
    classification: Option<u8>,
) -> Result<Projection, Refusal> {
    let va = absent.virtual_address;
    if absent.first_missing_level > 3 {
        return Err(Refusal::InvalidLevel);
    }
    if before.rcx != va {
        return Err(Refusal::ArgumentMismatch);
    }
    if before.rsp < 0x78
        || before.rsp.checked_add(0x28).is_none()
        || !canonical(before.rsp - 0x78)
        || !canonical(before.rsp + 0x27)
    {
        return Err(Refusal::StackGeometry);
    }
    let mut ptes = [0; 4];
    let mut address = va;
    for at in &mut ptes {
        address = PTE_BASE + ((address >> 9) & 0x7f_ffff_fff8);
        *at = address;
    }
    for (i, at) in ptes.iter().enumerate() {
        if ptes[..i].contains(at) {
            return Err(Refusal::AliasedPteAddresses);
        }
        if *at < before.rsp + 0x28 && at + 8 > before.rsp - 0x78 {
            return Err(Refusal::StackGeometry);
        }
    }
    let class_read = if absent.first_missing_level == 3 && va >= 0xffff_8000_0000_0000 {
        let class = classification.ok_or(Refusal::NeedsKernelClassification)?;
        if class == 11 {
            return Err(Refusal::NeedsDriverAddressLog);
        }
        Some(
            kernel_base
                .checked_add(0xe3_8aa8 + ((va >> 39) & 511) - 256)
                .ok_or(Refusal::KernelGeometry)?,
        )
    } else {
        None
    };
    if let Some(at) = class_read {
        if !canonical(at)
            || (before.rsp - 0x78..before.rsp + 0x28).contains(&at)
            || ptes.iter().any(|pte| (*pte..*pte + 8).contains(&at))
        {
            return Err(Refusal::KernelGeometry);
        }
    }
    let stack = before.rsp - 0x78;
    let mut spills = Vec::with_capacity(14);
    let mut save = |address, value: u64| {
        spills.push(Spill {
            address,
            bytes: value.to_le_bytes().to_vec(),
        });
    };
    for (address, value) in [
        (before.rsp + 0x10, before.rbx),
        (before.rsp + 0x18, before.rbp),
        (before.rsp + 0x20, before.rsi),
        (before.rsp - 8, before.rdi),
        (before.rsp - 0x10, before.r14),
        (before.rsp - 0x18, before.r15),
        (stack + 0x20, ptes[0]),
        (stack + 0x28, ptes[1]),
        (stack + 0x30, ptes[2]),
        (stack + 0x40, ptes[0]),
        (stack + 0x38, ptes[3]),
        (stack + 0x58, ptes[3]),
        (stack + 0x48, ptes[1]),
        (stack + 0x50, ptes[2]),
    ] {
        save(address, value);
    }
    let missing = usize::from(absent.first_missing_level);
    let mut after = before;
    after.r8 = ptes[2];
    after.r10 = 4;
    // The native first scan inspects ancestors, then repeats from the top before
    // the leaf read. The range checks and byte writes affect volatile registers.
    for level in 0..=missing.min(2) {
        let at = ptes[3 - level];
        after.r9 = at;
        after.r10 -= 1;
        if level < missing && (PML4_START..=PML4_END).contains(&at) {
            after.r8 = low_byte(after.r8, 1);
        }
    }
    for level in 0..=missing.min(2) {
        let at = ptes[3 - level];
        after.rdx = at;
        after.rcx = if at < PML4_START {
            PML4_START
        } else if at > PML4_END {
            PML4_END
        } else if level == missing {
            0
        } else {
            after.r8 = low_byte(after.r8, 1);
            after.r9 = low_byte(after.r9, 1);
            0x23
        };
    }
    if let Some(at) = class_read {
        after.rcx = at - (((va >> 39) & 511) - 256);
    }
    after.rax = 0;
    after.r11 = before.rsp - 0x18;
    after.rsp = before.rsp + 8;
    Ok(Projection {
        registers: after,
        flags: flags & !0x8d5 | 0x44,
        spills,
        pte_addresses: ptes,
        classification_read: class_read,
    })
}

#[cfg(test)]
mod tests;

use super::{Projection, Refusal, Registers, Spill, canonical, low_byte};
use serde::Serialize;

const PTE_BASE: u64 = 0xffff_f680_0000_0000;
const PML4_START: u64 = 0xffff_f6fb_7dbe_d000;
const PML4_END: u64 = PML4_START + 0x7f8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Walk {
    pub virtual_address: u64,
    pub entries: [Option<u64>; 4],
}

pub fn project(walk: &Walk, before: Registers, flags: u64) -> Result<Projection, Refusal> {
    let address = walk.virtual_address;
    if before.rcx != address {
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
    let mut pointer = address;
    for slot in &mut ptes {
        pointer = PTE_BASE + ((pointer >> 9) & 0x7f_ffff_fff8);
        *slot = pointer;
        if pointer < before.rsp + 0x28 && pointer + 8 > before.rsp - 0x78 {
            return Err(Refusal::StackGeometry);
        }
    }
    for level in 0..4 {
        if let Some(word) = walk.entries[level] {
            for prior in 0..level {
                if ptes[3 - prior] == ptes[3 - level] && walk.entries[prior] != Some(word) {
                    return Err(Refusal::AliasedPteAddresses);
                }
            }
        }
    }
    let stack = before.rsp - 0x78;
    let mut spills = Vec::with_capacity(16);
    for (at, value) in [
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
        spills.push(Spill {
            address: at,
            bytes: value.to_le_bytes().to_vec(),
        });
    }
    let mut after = before;
    after.r8 = ptes[2];
    after.rdx = ptes[3];
    let mut missing = false;
    for level in 0..3 {
        let word = walk.entries[level].ok_or(Refusal::InvalidLevel)?;
        let at = ptes[3 - level];
        after.r9 = at;
        after.r10 = 3 - level as u64;
        if (PML4_START..=PML4_END).contains(&at) && word & 1 != 0 {
            let writable = u8::from(word & 0x42 != 0);
            let accessed = u8::from(word & 0x20 != 0);
            after.r8 = low_byte(after.r8, writable);
            after.rdx = low_byte(after.rdx, accessed);
            if writable & accessed == 0 {
                return Err(Refusal::NeedsEntryRepair);
            }
        }
        if word & 1 == 0 {
            break;
        }
        if word & 0x80 != 0 {
            return Err(Refusal::NeedsLargePage);
        }
    }
    for level in 0..3 {
        let word = walk.entries[level].ok_or(Refusal::InvalidLevel)?;
        let at = ptes[3 - level];
        after.rdx = at;
        after.rcx = if at < PML4_START {
            PML4_START
        } else if at > PML4_END {
            PML4_END
        } else {
            if word & 1 != 0 {
                let writable = u8::from(word & 0x42 != 0);
                let accessed = u8::from(word & 0x20 != 0);
                after.r9 = low_byte(after.r9, writable);
                after.r8 = low_byte(after.r8, accessed);
                if writable & accessed == 0 {
                    return Err(Refusal::NeedsEntryRepair);
                }
            }
            word
        };
        if word & 1 == 0 {
            missing = true;
            break;
        }
    }
    let mut result = 0;
    let mut succeeded = false;
    if !missing {
        let leaf = walk.entries[3].ok_or(Refusal::InvalidLevel)?;
        if address >= 0xffff_8000_0000_0000 {
            return Err(Refusal::NeedsKernelClassification);
        }
        if leaf & 1 != 0 {
            succeeded = true;
            let base = leaf & 0x000f_ffff_ffff_f000;
            result = base | (address & 4095);
            spills.push(Spill {
                address: before.rsp + 8,
                bytes: base.to_le_bytes().to_vec(),
            });
            spills.push(Spill {
                address: before.rsp + 8,
                bytes: (result as u32).to_le_bytes().to_vec(),
            });
        }
    }
    after.rax = result;
    after.r11 = before.rsp - 0x18;
    after.rsp = before.rsp + 8;
    Ok(Projection {
        registers: after,
        flags: flags & !0x8d5 | if succeeded { 0 } else { 0x44 },
        spills,
        pte_addresses: ptes,
        classification_read: None,
    })
}

#[cfg(test)]
mod tests;

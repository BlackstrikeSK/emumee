//! Pinned build26200 AutoBoost initialization over explicitly supplied bytes.
//! This projects KeAbInitializeThreadState; it neither allocates guest blocks
//! nor supplies unknown thread, scheduler, acquisition or release state.
use serde::{Deserialize, Serialize};
use thiserror::Error;
pub mod owned;
pub mod abi;

pub const HEADER_BYTES: usize = 0x10;
pub const ENTRY_BYTES: usize = 0x58;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Inputs {
    pub misc_flags: u32,
    pub kernel_entries: Vec<u8>,
    pub user_entries: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Outcome {
    pub misc_flags: u32,
    pub kernel_entries: Vec<u8>,
    pub user_entries: Option<Vec<u8>>,
    pub propagate_boosts_entry: u64,
    pub io_self_boosts_entry: u64,
}

#[derive(Debug, Error)]
#[error("Kernel AutoBoost initialization: {0}")]
pub struct AutoBoostError(pub &'static str);

fn initialize_block(bytes: &[u8], user_mode: bool) -> Result<Vec<u8>, AutoBoostError> {
    if bytes.len() < HEADER_BYTES {
        return Err(AutoBoostError(
            "incomplete explicitly supplied entries header",
        ));
    }
    let count = bytes[0xc];
    let extent = HEADER_BYTES + usize::from(count) * ENTRY_BYTES;
    if bytes.len() < extent {
        return Err(AutoBoostError(
            "entry count exceeds explicitly supplied bytes",
        ));
    }
    let mut output = bytes.to_vec();
    for index in 0..usize::from(count) {
        let at = HEADER_BYTES + index * ENTRY_BYTES + 8;
        // The native helper preserves both high bits on kernel entries; only
        // user entries force UserModeBit. It does not clear PreWaiting.
        output[at] = (output[at] & 0xc0) | (index as u8 & 0x3f) | (u8::from(user_mode) * 0x80);
    }
    // Native SHL RAX,CL masks the count to six bits, then SUB AX,1 wraps
    // the low word. Keep that behavior even for explicitly supplied odd counts.
    let available = ((1u64 << (count & 63)) as u16).wrapping_sub(1);
    output[8..10].copy_from_slice(&available.to_le_bytes());
    output[10..12].copy_from_slice(&0u16.to_le_bytes());
    Ok(output)
}

/// Nonaliasing, complete logical blocks only. Callers must establish their
/// allocation/lifetime provenance and actual KernelAbEntries/UserAbEntries
/// pointers separately. No native memory writes or pointer defaults occur here.
pub fn initialize(input: &Inputs) -> Result<Outcome, AutoBoostError> {
    let kernel_entries = initialize_block(&input.kernel_entries, false)?;
    let user_entries = input
        .user_entries
        .as_deref()
        .map(|bytes| initialize_block(bytes, true))
        .transpose()?;
    Ok(Outcome {
        misc_flags: input.misc_flags | 1,
        kernel_entries,
        user_entries,
        propagate_boosts_entry: 1,
        io_self_boosts_entry: 1,
    })
}

#[cfg(test)]
mod tests;

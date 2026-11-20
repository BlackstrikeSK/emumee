//! M6 instruction, cache and protection observation control family.
//!
//! A sample writing inside its own image is what unpacking looks like, so the
//! first control writes to its own image and the observation must see every
//! byte. The second control writes real instructions into a private executable
//! region, runs them, overwrites them and runs them again: the second answer is
//! only correct if the instruction cache saw the second write. It also pins the
//! protection boundary this profile has — the mapped image's own protection is
//! not guest-changeable here.
use super::m6::Probe;
use super::winhttp::Arg::{Memory as M, Value as V};
use crate::pe::Architecture;

#[derive(Clone, Copy, Debug)]
pub enum M6ObservationFixture {
    /// Writes inside the sample's own image, which the observation records.
    ImageWrite,
    /// Guest-written instructions, run, overwritten and run again.
    WrittenCode,
}
/// The private region the written-code control asks for by address, so the
/// guest can name the bytes it writes at build time.
const REGION: u64 = 0x2000_0000;
/// Values only the written instruction sequences can produce.
const FIRST: u32 = 0x5a5a_5a5a;
const SECOND: u32 = 0x3c3c_3c3c;
/// MEM_COMMIT|MEM_RESERVE, MEM_RELEASE and PAGE_EXECUTE_READWRITE.
const COMMIT: u64 = 0x3000;
const RELEASE: u64 = 0x8000;
const EXECUTE_READWRITE: u64 = 0x40;

const ALLOC: usize = 0;
const FREE: usize = 1;
const PROTECT: usize = 2;
const LAST_ERROR: usize = 3;

fn imports() -> [(&'static str, Vec<String>); 1] {
    [(
        "kernel32.dll",
        vec![
            "VirtualAlloc".into(),
            "VirtualFree".into(),
            "VirtualProtect".into(),
            "GetLastError".into(),
        ],
    )]
}
/// `mov eax, value; ret` as the two words a guest writes to form it.
fn stub(value: u32) -> [u32; 2] {
    let bytes = value.to_le_bytes();
    [
        u32::from_le_bytes([0xb8, bytes[0], bytes[1], bytes[2]]),
        u32::from_le_bytes([bytes[3], 0xc3, 0, 0]),
    ]
}

pub fn m6_observation_probe(architecture: Architecture, kind: M6ObservationFixture) -> Vec<u8> {
    use M6ObservationFixture as K;
    let mut p = Probe::new(architecture, false, &imports());
    let base = p.base;
    let saved = p.scratch(32);
    let old = p.scratch(32);
    let cell = p.scratch(64);
    match kind {
        K::ImageWrite => {
            // The data section is writable from the start, so these are plain
            // guest instructions with no protection change at all.
            for index in 0..4u64 {
                p.set_dword(cell + index * 4, 0x1100_0000 + index as u32);
            }
            for index in 0..4u64 {
                p.dword(cell + index * 4, 0x1100_0000 + index as u32);
            }
            // Overwriting the same bytes again is a second write to the same
            // guest addresses, not a second address range.
            p.set_dword(cell, 0x2200_0000);
            p.dword(cell, 0x2200_0000);
            // The mapped image's own protection is not guest-changeable in this
            // profile: VirtualProtect covers the reservations a guest made
            // itself, so an in-place unpack of this code page is refused rather
            // than quietly reported as done.
            p.poison(old, 1);
            p.call(
                PROTECT,
                &[V(base + 0x1000), V(0x1000), V(EXECUTE_READWRITE), V(old)],
            );
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(487);
            p.intact(old, 1);
        }
        K::WrittenCode => {
            // A preferred base lets the guest name at build time the addresses
            // it is about to write instructions to.
            p.call(ALLOC, &[V(REGION), V(0x1000), V(COMMIT), V(EXECUTE_READWRITE)]);
            p.rax(REGION);
            p.save(saved);
            for value in [FIRST, SECOND] {
                let words = stub(value);
                p.set_dword(REGION, words[0]);
                p.set_dword(REGION + 4, words[1]);
                // The bytes the guest just wrote are the bytes that run. On the
                // second pass the same address already held executed code, so
                // only an invalidated instruction cache can answer correctly.
                p.call_absolute(REGION);
                p.eax(value);
            }
            // The region is the guest's own, so it can take it back.
            p.call(FREE, &[M(saved), V(0), V(RELEASE)]);
            p.eax(1);
            // Its protection is no longer anyone's to change.
            p.call(
                PROTECT,
                &[V(REGION), V(0x1000), V(EXECUTE_READWRITE), V(old)],
            );
            p.eax(0);
            p.call(LAST_ERROR, &[]);
            p.eax(487);
        }
    }
    p.finish()
}

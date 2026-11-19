//! Legacy Windows x87/SSE CONTEXT layout transport. Never executes guest code.
use super::*;
use RegisterX86::*;
const FLOAT: [RegisterX86; 8] = [ST0, ST1, ST2, ST3, ST4, ST5, ST6, ST7];
const XMM: [RegisterX86; 16] = [
    XMM0, XMM1, XMM2, XMM3, XMM4, XMM5, XMM6, XMM7, XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14,
    XMM15,
];
fn value(b: &[u8], at: usize, width: usize) -> u64 {
    let mut raw = [0; 8];
    raw[..width].copy_from_slice(&b[at..at + width]);
    u64::from_le_bytes(raw)
}
fn put(b: &mut [u8], at: usize, width: usize, v: u64) {
    b[at..at + width].copy_from_slice(&v.to_le_bytes()[..width]);
}
fn scalar(
    e: &mut Unicorn<Trace>,
    b: &mut [u8],
    at: usize,
    width: usize,
    reg: RegisterX86,
    set: bool,
) -> Result<()> {
    if set {
        uc(e.reg_write(reg, value(b, at, width)))?;
    } else {
        put(b, at, width, uc(e.reg_read(reg))?);
    }
    Ok(())
}
pub(super) fn transfer(
    e: &mut Unicorn<Trace>,
    b: &mut [u8],
    flags: u32,
    wide: bool,
    set: bool,
) -> Result<bool> {
    let fx = if wide {
        (flags & 8 != 0).then_some(256)
    } else {
        (flags & 32 != 0).then_some(204)
    };
    // Validate before publishing the staged CPU snapshot. Reserved MXCSR and
    // x87 bits must not become backend faults on the next guest instruction.
    if set {
        if let Some(at) = fx {
            let mxcsr = value(b, if wide { 52 } else { at + 24 }, 4);
            if mxcsr & !0xffff != 0 || value(b, at, 2) & !0x1f7f != 0 {
                return Ok(false);
            }
        }
        if !wide && flags & 8 != 0 && value(b, 28, 4) & !0x1f7f != 0 {
            return Ok(false);
        }
    }
    if !wide && flags & 8 != 0 {
        for (at, reg) in [(28, FPCW), (32, FPSW), (36, FPTAG), (40, FIP), (48, FDP)] {
            scalar(e, b, at, 4, reg, set)?;
        }
        if !set {
            put(b, 44, 4, 0);
            put(b, 52, 4, 0);
            put(b, 136, 4, 0);
        }
        for (i, reg) in FLOAT.iter().enumerate() {
            let at = 56 + i * 10;
            if set {
                uc(e.reg_write_long(*reg, &b[at..at + 10]))?;
            } else {
                b[at..at + 10].copy_from_slice(&uc(e.reg_read_long(*reg))?);
            }
        }
    }
    if let Some(at) = fx {
        for (offset, width, reg) in [
            (0, 2, FPCW),
            (2, 2, FPSW),
            (6, 2, FOP),
            (8, if wide { 8 } else { 4 }, FIP),
            (16, if wide { 8 } else { 4 }, FDP),
        ] {
            scalar(e, b, at + offset, width, reg, set)?;
        }
        let mxcsr_at = if wide { 52 } else { at + 24 };
        scalar(e, b, mxcsr_at, 4, MXCSR, set)?;
        if !set {
            let mxcsr = value(b, mxcsr_at, 4);
            put(b, at + 24, 4, mxcsr);
            put(b, at + 28, 4, 0xffff);
        }
        if set {
            let tag = b[at + 4];
            let full = (0..8).fold(0u64, |v, i| {
                v | (if tag & (1 << i) == 0 { 3 } else { 0 }) << (2 * i)
            });
            uc(e.reg_write(FPTAG, full))?;
        } else {
            let tag = uc(e.reg_read(FPTAG))?;
            b[at + 4] = (0..8).fold(0, |v, i| v | u8::from((tag >> (i * 2)) & 3 != 3) << i);
        }
        for (i, reg) in FLOAT.iter().enumerate() {
            let offset = at + 32 + i * 16;
            if set {
                uc(e.reg_write_long(*reg, &b[offset..offset + 10]))?;
            } else {
                b[offset..offset + 10].copy_from_slice(&uc(e.reg_read_long(*reg))?);
                b[offset + 10..offset + 16].fill(0);
            }
        }
        for (i, reg) in XMM.iter().take(if wide { 16 } else { 8 }).enumerate() {
            let offset = at + 160 + i * 16;
            if set {
                uc(e.reg_write_long(*reg, &b[offset..offset + 16]))?;
            } else {
                b[offset..offset + 16].copy_from_slice(&uc(e.reg_read_long(*reg))?);
            }
        }
    }
    Ok(true)
}

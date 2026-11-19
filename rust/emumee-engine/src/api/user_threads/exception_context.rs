//! Checked live CONTEXT transport for user exception continuations.
use super::*;

pub(crate) fn capture(engine: &mut Unicorn<Trace>) -> Result<Vec<u8>> {
    let wide = engine.get_data().architecture == Architecture::X64;
    let flags: u32 = if wide { 0x10001f } else { 0x1003f };
    let mut bytes = vec![0; if wide { 1232 } else { 716 }];
    let at = if wide { 48 } else { 0 };
    bytes[at..at + 4].copy_from_slice(&flags.to_le_bytes());
    for (at, reg, width, _) in scheduling::context_fields(wide) {
        bytes[at..at + width].copy_from_slice(&uc(engine.reg_read(reg))?.to_le_bytes()[..width]);
    }
    ensure!(
        floating_context::transfer(engine, &mut bytes, flags, wide, false)?,
        "Could not capture user exception floating context"
    );
    Ok(bytes)
}

pub(crate) fn restore(engine: &mut Unicorn<Trace>, before: &[u8], after: &[u8]) -> Result<()> {
    let wide = engine.get_data().architecture == Architecture::X64;
    ensure!(
        before.len() == after.len() && after.len() == if wide { 1232 } else { 716 },
        "User exception CONTEXT size changed"
    );
    let at = if wide { 48 } else { 0 };
    ensure!(
        before[at..at + 4] == after[at..at + 4],
        "User exception CONTEXT flags changed"
    );
    let flags = u32::from_le_bytes(after[at..at + 4].try_into().unwrap());
    let mut edits = Vec::new();
    use RegisterX86::*;
    for (at, reg, width, group) in scheduling::context_fields(wide) {
        let mut value = [0; 8];
        value[..width].copy_from_slice(&after[at..at + width]);
        let value = u64::from_le_bytes(value);
        if matches!(reg, CS | SS | DS | ES | FS | GS) || group == 16 {
            ensure!(
                before[at..at + width] == after[at..at + width],
                "User exception changed segment/debug context"
            );
        } else {
            let mut old = [0; 8];
            old[..width].copy_from_slice(&before[at..at + width]);
            ensure!(
                reg != EFLAGS || (value ^ u64::from_le_bytes(old)) & !0xcd5 == 0,
                "User exception changed protected flags"
            );
            if matches!(reg, EIP | RIP) {
                require(engine, value, 1, P::EXECUTE)?;
            }
            if matches!(reg, ESP | RSP) {
                require(engine, value, if wide { 8 } else { 4 }, P::RW)?;
            }
            edits.push((reg, value));
        }
    }
    let saved = uc(engine.context_init())?;
    let result = (|| -> Result<()> {
        let mut bytes = after.to_vec();
        ensure!(
            floating_context::transfer(engine, &mut bytes, flags, wide, true)?,
            "Invalid user exception floating context"
        );
        for (reg, value) in edits {
            uc(engine.reg_write(reg, value))?;
        }
        Ok(())
    })();
    if result.is_err() {
        uc(engine.context_restore(&saved))?;
    }
    result
}

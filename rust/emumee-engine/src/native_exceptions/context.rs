//! Windows AMD64 legacy CONTEXT. Kernel capture follows the pinned
//! KeContextFromKframes contract: canonical data selectors, XMM/MXCSR, no x87
//! save in KernelMode, and zero debug fields when DR7 has no active controls.
//! No XSTATE/CET extension is advertised without its backing record.
use super::*;
const SEGMENTS: [R; 4] = [R::DS, R::ES, R::FS, R::GS];
const DEBUG: [R; 6] = [R::DR0, R::DR1, R::DR2, R::DR3, R::DR6, R::DR7];
const FLOAT: [R; 8] = [
    R::ST0,
    R::ST1,
    R::ST2,
    R::ST3,
    R::ST4,
    R::ST5,
    R::ST6,
    R::ST7,
];
fn word(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
}
fn dword(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
}
fn qword(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
}
fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn capture(engine: &Unicorn<Trace>) -> Result<ContextRecord> {
    let mut c = Context {
        rip: uc(engine.pc_read())?,
        eflags: uc(engine.reg_read(R::EFLAGS))? as u32,
        cs: uc(engine.reg_read(R::CS))? as u16,
        ss: uc(engine.reg_read(R::SS))? as u16,
        ..Context::default()
    };
    for (reg, value) in INTEGER.iter().zip(&mut c.integer) {
        *value = uc(engine.reg_read(*reg))?;
    }
    for (reg, value) in XMM.iter().zip(&mut c.xmm) {
        *value = u128::from_le_bytes(uc(engine.reg_read_long(*reg))?.as_ref().try_into().unwrap());
    }
    let mut raw = [0; 1232];
    put32(&mut raw, 48, 0x10001f);
    for (i, reg) in SEGMENTS.iter().enumerate() {
        let selector = if engine.get_data().apis.kernel_mode {
            [0x2b, 0x2b, 0x53, 0x2b][i]
        } else {
            uc(engine.reg_read(*reg))? as u16
        };
        put16(&mut raw, 58 + i * 2, selector);
    }
    if uc(engine.reg_read(R::DR7))? & 0x355 != 0 {
        for (i, reg) in DEBUG.iter().enumerate() {
            put64(&mut raw, 72 + i * 8, uc(engine.reg_read(*reg))?);
        }
    }
    let mxcsr = uc(engine.reg_read(R::MXCSR))? as u32;
    put32(&mut raw, 52, mxcsr);
    put32(&mut raw, 280, mxcsr);
    if !engine.get_data().apis.kernel_mode {
        put16(&mut raw, 256, uc(engine.reg_read(R::FPCW))? as u16);
        put16(&mut raw, 258, uc(engine.reg_read(R::FPSW))? as u16);
        let tag = uc(engine.reg_read(R::FPTAG))? as u16;
        raw[260] = (0..8).fold(0, |value, i| {
            value | u8::from((tag >> (i * 2)) & 3 != 3) << i
        });
        put16(&mut raw, 262, uc(engine.reg_read(R::FOP))? as u16);
        put64(&mut raw, 264, uc(engine.reg_read(R::FIP))?);
        put64(&mut raw, 272, uc(engine.reg_read(R::FDP))?);
        put32(&mut raw, 284, 0xffff); // Unicorn2.1.5 legacy SSE capability mask.
        for (i, reg) in FLOAT.iter().enumerate() {
            let value = uc(engine.reg_read_long(*reg))?;
            raw[288 + i * 16..298 + i * 16].copy_from_slice(&value);
        }
    }
    let mut record = ContextRecord::from_bytes(&raw)?;
    record.update(&c);
    Ok(record)
}
pub(super) fn restore(
    engine: &mut Unicorn<Trace>,
    before: &ContextRecord,
    after: &ContextRecord,
) -> Result<()> {
    let old = before.registers();
    let c = after.registers();
    for (i, (old, new)) in before.bytes().iter().zip(after.bytes()).enumerate() {
        if !(52..672).contains(&i) {
            ensure!(old == new, "Unsupported native CONTEXT edit at byte {i}");
        }
    }
    ensure!(
        before.bytes()[56..68] == after.bytes()[56..68],
        "Segment-selector CONTEXT edits are not yet supported"
    );
    ensure!(
        before.bytes()[72..120] == after.bytes()[72..120],
        "Debug-register CONTEXT edits are not yet supported"
    );
    ensure!(
        (old.eflags ^ c.eflags) & 0x003f7000 == 0,
        "Handler changed protected context state"
    );
    let raw = after.bytes();
    let mxcsr = dword(raw, 52);
    ensure!(mxcsr & !0xffff == 0, "CONTEXT MXCSR has reserved bits set");
    if !engine.get_data().apis.kernel_mode {
        ensure!(
            word(raw, 256) & !0x1f7f == 0,
            "Unsupported CONTEXT x87 control bits"
        );
    }
    require(engine, c.rip, 1, P::EXECUTE)?;
    require(engine, c.integer[4], 8, P::READ)?;
    // All supported validation precedes publication; a failing native write
    // remains terminal and never falls back to a fabricated caught exception.
    for (reg, value) in INTEGER.iter().zip(c.integer) {
        uc(engine.reg_write(*reg, value))?;
    }
    for (reg, value) in XMM.iter().zip(c.xmm) {
        uc(engine.reg_write_long(*reg, &value.to_le_bytes()))?;
    }
    uc(engine.reg_write(R::MXCSR, mxcsr as u64))?;
    if !engine.get_data().apis.kernel_mode {
        uc(engine.reg_write(R::FPCW, word(raw, 256) as u64))?;
        uc(engine.reg_write(R::FPSW, word(raw, 258) as u64))?;
        uc(engine.reg_write(R::FOP, word(raw, 262) as u64))?;
        uc(engine.reg_write(R::FIP, qword(raw, 264)))?;
        uc(engine.reg_write(R::FDP, qword(raw, 272)))?;
        for (i, reg) in FLOAT.iter().enumerate() {
            uc(engine.reg_write_long(*reg, &raw[288 + i * 16..298 + i * 16]))?;
        }
        let full_tag = (0..8).fold(0u16, |value, i| {
            value
                | if raw[260] & (1 << i) == 0 {
                    3 << (i * 2)
                } else {
                    0
                }
        });
        uc(engine.reg_write(R::FPTAG, full_tag as u64))?;
    }
    uc(engine.reg_write(R::EFLAGS, c.eflags as u64))?;
    uc(engine.reg_write(R::RIP, c.rip))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use unicorn_engine::unicorn_const::Prot;
    const CODE: u64 = 0x100000;
    const DATA: u64 = 0x200000;
    const STACK: u64 = 0x300000;
    fn setup() -> Result<crate::NativeEngine> {
        let mut e = crate::new_engine(Architecture::X64)?;
        e.get_data_mut().apis.target(Architecture::X64, false)?;
        for (base, p, tag) in [
            (CODE, P::RX, "generated FXSAVE oracle"),
            (DATA, P::RW, "generated FXSAVE data"),
            (STACK, P::RW, "generated context stack"),
        ] {
            uc(e.mem_map(base, 4096, Prot::ALL))?;
            e.get_data_mut().apis.memory.map(base, 4096, p, None, tag)?;
        }
        super::super::install(&mut e)?;
        uc(e.reg_write(R::RSP, STACK + 0xf00))?;
        Ok(e)
    }
    fn fxsave_code(address: u64) -> Vec<u8> {
        let mut code = vec![0x48, 0xb8];
        code.extend(address.to_le_bytes());
        code.extend([0x48, 0x0f, 0xae, 0]);
        code
    }
    #[test]
    fn native_exception_user_context_matches_guest_fxsave_and_restores_edited_x87_sse_state() {
        let observations = (|| -> Result<_> {
            let mut e = setup()?;
            let mut code = vec![
                0xdb, 0xe3, 0xd9, 0xe8, 0xd9, 0xee, 0xd9, 0xeb, 0xb8, 0x78, 0x56, 0x34, 0x12, 0x66,
                0x0f, 0x6e, 0xc0,
            ];
            code.extend(fxsave_code(DATA));
            let after_code = fxsave_code(DATA + 0x400);
            uc(e.mem_write(CODE, &code))?;
            uc(e.mem_write(CODE + 0x100, &after_code))?;
            uc(e.emu_start(CODE, CODE + code.len() as u64, 0, 128))?;
            ensure!(
                e.get_data().cpu.fault.is_none(),
                "Generated FXSAVE fault: {:?}",
                e.get_data().cpu.fault
            );
            let before = capture(&e)?;
            let first = uc(e.mem_read_as_vec(DATA, 512))?;
            let mut edited = *before.bytes();
            put64(&mut edited, 248, CODE + 0x100);
            put16(&mut edited, 256, 0x027f);
            put32(&mut edited, 52, 0x3f80);
            let one: Vec<u8> = edited[320..336].to_vec();
            edited[288..304].copy_from_slice(&one);
            let vector = 0x778899aabbccddeeff00112233445566u128.to_le_bytes();
            edited[416..432].copy_from_slice(&vector);
            restore(&mut e, &before, &ContextRecord::from_bytes(&edited)?)?;
            uc(e.emu_start(CODE + 0x100, CODE + 0x100 + after_code.len() as u64, 0, 128))?;
            let second = uc(e.mem_read_as_vec(DATA + 0x400, 512))?;
            Ok((before, first, second, one, vector))
        })()
        .unwrap(); // Drop the native lease before assertions can panic.
        let (before, first, second, one, vector) = observations;
        assert_eq!(&before.bytes()[256..768], first.as_slice());
        assert_eq!(word(&first, 0), 0x037f);
        assert_eq!(first[4], 0xe0);
        assert_eq!(word(&second, 0), 0x027f);
        assert_eq!(dword(&second, 24), 0x3f80);
        assert_eq!(&second[32..48], one.as_slice());
        assert_eq!(&second[160..176], vector);
    }
    #[test]
    fn native_exception_kernel_context_uses_pinned_segment_debug_and_sse_contract() {
        let observed = (|| -> Result<_> {
            let mut e = setup()?;
            uc(e.reg_write(R::MXCSR, 0x3f80))?;
            uc(e.reg_write(R::FPCW, 0x037f))?;
            let vector = 0x112233445566778899aabbccddeeff00u128.to_le_bytes();
            uc(e.reg_write_long(R::XMM7, &vector))?;
            e.get_data_mut().apis.target(Architecture::X64, true)?;
            let record = capture(&e)?;
            Ok((record, vector))
        })()
        .unwrap();
        let (record, vector) = observed;
        let bytes = record.bytes();
        assert_eq!(dword(bytes, 48), 0x10001f);
        assert_eq!(&bytes[58..66], &[0x2b, 0, 0x2b, 0, 0x53, 0, 0x2b, 0]);
        assert!(bytes[72..120].iter().all(|b| *b == 0));
        assert_eq!(dword(bytes, 52), 0x3f80);
        assert_eq!(dword(bytes, 280), 0x3f80);
        // KernelMode does not execute the user-mode FXSAVE branch.
        assert_eq!(word(bytes, 256), 0);
        assert_eq!(&bytes[528..544], vector);
    }
    #[test]
    fn native_exception_context_rejects_unsupported_edits_before_register_publication() {
        let native: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/native_x64_exception_context.json"
        ))
        .unwrap();
        let observed = (|| -> Result<_> {
            let mut e = setup()?;
            uc(e.reg_write(R::RIP, CODE))?;
            let before = capture(&e)?;
            let mut results = Vec::new();
            for (offset, value) in [(52, 0x10000), (48, 0x10005f), (112, 1), (58, 0x1234)] {
                let mut raw = *before.bytes();
                put32(&mut raw, offset, value);
                // A valid integer change must not leak through a failed restore.
                put64(&mut raw, 120, 0xdeadbeef);
                let result = restore(&mut e, &before, &ContextRecord::from_bytes(&raw)?);
                let after = capture(&e)?;
                results.push((result.is_err(), after == before));
            }
            Ok((
                results,
                word(before.bytes(), 256),
                dword(before.bytes(), 52),
            ))
        })()
        .unwrap();
        assert!(observed.0.iter().all(|v| *v == (true, true)));
        assert_eq!(
            observed.1 as u64,
            native["sdk_initial_fpcsr"].as_u64().unwrap()
        );
        assert_eq!(
            observed.2 as u64,
            native["sdk_initial_mxcsr"].as_u64().unwrap()
        );
    }
}

//! Pause the API gate, execute actual zero-argument CDECL callbacks, resume RET.
use super::*;
use anyhow::Context;
#[derive(Clone)]
pub(crate) struct Pending {
    pc: u64,
    sp: u64,
    frame: Vec<u8>,
    begin: u64,
    count: u64,
    error_returning: bool,
    event: Option<usize>,
    result: Option<u32>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub table_index: u64,
    pub target: u64,
    pub started_instruction: u64,
    pub stopped_instruction: Option<u64>,
    pub result: Option<u32>,
    pub error: Option<String>,
}
fn sp_register(arch: Architecture) -> RegisterX86 {
    if arch == Architecture::X64 {
        RegisterX86::RSP
    } else {
        RegisterX86::ESP
    }
}
fn pc_register(arch: Architecture) -> RegisterX86 {
    if arch == Architecture::X64 {
        RegisterX86::RIP
    } else {
        RegisterX86::EIP
    }
}
pub(super) fn queue(
    engine: &mut Unicorn<Trace>,
    args: &[u64],
    error_returning: bool,
) -> Result<u64> {
    let arch = engine.get_data().architecture;
    let count = initializer_count(arch, args[0], args[1]).map_err(anyhow::Error::msg)?;
    ensure!(
        engine.get_data().threads.is_none(),
        "CRT initializers require ordinary user execution"
    );
    let state = &engine.get_data().apis.crt_startup;
    ensure!(
        !state.active && state.pending.is_none(),
        "Reentrant CRT initializer execution is not modeled"
    );
    if count == 0 {
        return Ok(0);
    }
    require(engine, args[0], args[1] - args[0], P::READ)?;
    let sp = uc(engine.reg_read(sp_register(arch)))?;
    ensure!(
        arch != Architecture::X64 || sp % 16 == 8,
        "Win64 CRT initializer API stack is misaligned"
    );
    let frame = read(engine, sp, if arch == Architecture::X64 { 40 } else { 12 })?;
    let pending = Pending {
        pc: uc(engine.pc_read())?,
        sp,
        frame,
        begin: args[0],
        count,
        error_returning,
        event: engine.get_data().apis.next_event_index(),
        result: None,
    };
    let state = &mut engine.get_data_mut().apis.crt_startup;
    state.pending = Some(pending);
    state.action = true;
    Ok(0)
}
pub(crate) fn queued(engine: &Unicorn<Trace>) -> bool {
    engine.get_data().apis.crt_startup.action
}
fn registers(arch: Architecture) -> &'static [RegisterX86] {
    use RegisterX86::*;
    if arch == Architecture::X64 {
        &[
            RBX, RBP, RSI, RDI, R12, R13, R14, R15, CS, SS, DS, ES, FS, GS, FS_BASE, GS_BASE, CR0,
            CR3, CR4, FPCW,
        ]
    } else {
        &[
            EBX, EBP, ESI, EDI, CS, SS, DS, ES, FS, GS, CR0, CR3, CR4, FPCW,
        ]
    }
}
fn invoke(
    engine: &mut Unicorn<Trace>,
    target: u64,
    caller_sp: u64,
    horizon: &ExecutionHorizon,
) -> Result<Outcome> {
    require(engine, target, 1, P::EXECUTE)?;
    let arch = engine.get_data().architecture;
    let marker = engine.get_data().return_marker + 0x600;
    require(engine, marker, 1, P::EXECUTE)?;
    let saved = registers(arch)
        .iter()
        .map(|r| uc(engine.reg_read(*r)).map(|v| (*r, v)))
        .collect::<Result<Vec<_>>>()?;
    let vectors = if arch == Architecture::X64 {
        use RegisterX86::*;
        [
            XMM6, XMM7, XMM8, XMM9, XMM10, XMM11, XMM12, XMM13, XMM14, XMM15,
        ]
        .iter()
        .map(|r| uc(engine.reg_read_long(*r)).map(|v| (*r, v)))
        .collect::<Result<Vec<_>>>()?
    } else {
        vec![]
    };
    let flags = uc(engine.reg_read(RegisterX86::EFLAGS))?;
    ensure!(
        flags & 0x400 == 0,
        "CRT initializer caller has direction flag set"
    );
    let control = uc(engine.reg_read(RegisterX86::MXCSR))?;
    let sp = (caller_sp
        .checked_sub(0x80)
        .context("CRT callback stack underflow")?
        & !15)
        .checked_sub(arch.width() as u64)
        .context("CRT callback aligned stack underflow")?;
    let width = arch.width();
    let mut frame = vec![0; if width == 8 { 40 } else { 4 }];
    frame[..width].copy_from_slice(&marker.to_le_bytes()[..width]);
    require(engine, sp, frame.len() as u64, P::WRITE)?;
    crate::cpu::write(engine, sp, &frame)?;
    uc(engine.reg_write(sp_register(arch), sp))?;
    let outcome = crate::threads::execute_horizon(engine, target, marker, horizon)?;
    if outcome.returned {
        ensure!(
            uc(engine.pc_read())? == marker
                && uc(engine.reg_read(sp_register(arch)))? == sp + width as u64,
            "CRT initializer violated CDECL/Win64 return frame"
        );
        for (r, v) in saved {
            ensure!(
                uc(engine.reg_read(r))? == v,
                "CRT initializer changed nonvolatile register {r:?}"
            );
        }
        for (r, v) in vectors {
            ensure!(
                uc(engine.reg_read_long(r))? == v,
                "CRT initializer changed nonvolatile vector register {r:?}"
            );
        }
        let after = uc(engine.reg_read(RegisterX86::EFLAGS))?;
        ensure!(
            after & 0x400 == 0 && (after ^ flags) & 0x3200 == 0,
            "CRT initializer changed protected flags"
        );
        ensure!(
            (uc(engine.reg_read(RegisterX86::MXCSR))? ^ control) & 0xffc0 == 0,
            "CRT initializer changed MXCSR control bits"
        );
    }
    Ok(outcome)
}
pub(crate) fn transition(
    engine: &mut Unicorn<Trace>,
    horizon: &ExecutionHorizon,
) -> Result<Option<Outcome>> {
    let pending = engine
        .get_data()
        .apis
        .crt_startup
        .pending
        .clone()
        .context("CRT pending caller absent")?;
    ensure!(queued(engine), "CRT initializer action absent");
    engine.get_data_mut().apis.crt_startup.action = false;
    engine.get_data_mut().apis.crt_startup.active = true;
    let width = engine.get_data().architecture.width();
    let mut result = 0;
    for index in 0..pending.count {
        if horizon.expired(engine.get_data().instructions) {
            return Ok(Some(Outcome {
                returned: false,
                value: None,
                error: None,
            }));
        }
        // Read at the real walk position: earlier callbacks may mutate later slots.
        let bytes = read(engine, pending.begin + index * width as u64, width as u64)?;
        let mut pointer = [0; 8];
        pointer[..width].copy_from_slice(&bytes);
        let target = u64::from_le_bytes(pointer);
        if target == 0 {
            continue;
        }
        let event = Event {
            table_index: index,
            target,
            started_instruction: engine.get_data().instructions,
            stopped_instruction: None,
            result: None,
            error: None,
        };
        let state = &mut engine.get_data_mut().apis.crt_startup;
        let event_index = if state.events.len() < 512 {
            state.events.push(event);
            Some(state.events.len() - 1)
        } else {
            state.events_omitted += 1;
            None
        };
        let outcome = invoke(engine, target, pending.sp, horizon);
        let stopped = engine.get_data().instructions;
        if let Some(i) = event_index {
            let event = &mut engine.get_data_mut().apis.crt_startup.events[i];
            event.stopped_instruction = Some(stopped);
            match &outcome {
                Ok(o) => {
                    event.result = o.value.map(|v| v as u32);
                    event.error = o.error.clone();
                }
                Err(e) => event.error = Some(format!("{e:#}")),
            }
        }
        let outcome = outcome?;
        if !outcome.returned {
            return Ok(Some(outcome));
        }
        if pending.error_returning {
            result = outcome.value.unwrap() as u32;
            if result != 0 {
                break;
            }
        }
    }
    let arch = engine.get_data().architecture;
    uc(engine.reg_write(sp_register(arch), pending.sp))?;
    uc(engine.reg_write(pc_register(arch), pending.pc))?;
    let state = &mut engine.get_data_mut().apis.crt_startup;
    state.active = false;
    state.resume = true;
    state.pending.as_mut().unwrap().result = Some(result);
    Ok(None)
}
pub(crate) fn resume_api(engine: &mut Unicorn<Trace>, pc: u64) -> Result<bool> {
    if !engine.get_data().apis.crt_startup.resume {
        return Ok(false);
    }
    let pending = engine
        .get_data()
        .apis
        .crt_startup
        .pending
        .clone()
        .context("CRT resume caller absent")?;
    let arch = engine.get_data().architecture;
    ensure!(
        pc == pending.pc
            && uc(engine.reg_read(sp_register(arch)))? == pending.sp
            && read(engine, pending.sp, pending.frame.len() as u64)? == pending.frame,
        "CRT callback changed suspended API frame"
    );
    let value = pending
        .result
        .context("CRT API resumed without completed callbacks")?;
    if pending.error_returning {
        uc(engine.reg_write(
            if arch == Architecture::X64 {
                RegisterX86::RAX
            } else {
                RegisterX86::EAX
            },
            u64::from(value),
        ))?;
    }
    let last_error = engine.get_data().apis.last_error;
    if let Some(event) = pending
        .event
        .and_then(|i| engine.get_data_mut().apis.events.get_mut(i))
    {
        ensure!(event.pending, "CRT API observation already completed");
        event.pending = false;
        event.result = pending.error_returning.then_some(u64::from(value));
        event.last_error = last_error;
        event.effect = Some("crt_initializers_completed");
    }
    let state = &mut engine.get_data_mut().apis.crt_startup;
    state.pending = None;
    state.resume = false;
    Ok(true)
}

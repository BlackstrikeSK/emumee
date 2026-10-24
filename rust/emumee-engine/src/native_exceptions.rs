//! AMD64 search/unwind exception dispatch. Guest handlers execute only after the
//! outer Unicorn start has stopped, using its shared execution horizon.
use crate::threads::{ExecutionHorizon, Outcome};
use crate::{Architecture, RegisterX86 as R, Trace, Unicorn, uc};
use anyhow::{Context as _, Result, bail, ensure};
use emumee_core::{
    memory::Permissions as P,
    x64_exception::{ContextRecord, DispatcherContext, ExceptionRecord},
    x64_unwind::{self as unwind, Context, Image, Stack},
};
use serde::Serialize;
use std::collections::BTreeSet;
pub(crate) mod api_frame;
pub(crate) mod c_scope;
mod context;
mod unwind_phase;
use context::{capture, restore};
// Other runtime owners use +100(thread), +200(IPI), +300(loader), +400(DPC).
const LANGUAGE_RETURN: u64 = 0x700;
const SCOPE_RETURN: u64 = 0x800;
const UNWIND_RETURN: u64 = 0x900;

const INTEGER: [R; 16] = [
    R::RAX,
    R::RCX,
    R::RDX,
    R::RBX,
    R::RSP,
    R::RBP,
    R::RSI,
    R::RDI,
    R::R8,
    R::R9,
    R::R10,
    R::R11,
    R::R12,
    R::R13,
    R::R14,
    R::R15,
];
const XMM: [R; 16] = [
    R::XMM0,
    R::XMM1,
    R::XMM2,
    R::XMM3,
    R::XMM4,
    R::XMM5,
    R::XMM6,
    R::XMM7,
    R::XMM8,
    R::XMM9,
    R::XMM10,
    R::XMM11,
    R::XMM12,
    R::XMM13,
    R::XMM14,
    R::XMM15,
];
#[derive(Default)]
pub(crate) struct State {
    pending: Option<ExceptionRecord>,
    active: bool,
    events: Vec<Event>,
    raised: u64,
    handler_arguments: Option<[u64; 4]>,
    scope: c_scope::State,
    unwind: Option<unwind_phase::Request>,
    owner: Option<(u64, u32, u64)>,
    unwinds_started: u64,
    unwinds_completed: u64,
    transient_unwind_frames: u64,
    dispatcher_boundaries_crossed: u64,
    api_frame: Option<api_frame::Frame>,
    api_exceptions: Vec<api_frame::Evidence>,
    pending_resume_flag: bool,
    cpu_faults: Vec<CpuFault>,
    cpu_faults_omitted: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct CpuFault {
    pub pc: u64,
    pub instruction_size: u32,
    pub vector: u8,
    pub error_code: u32,
    pub msr_index: u32,
    pub write: bool,
    pub saved_resume_flag: bool,
    pub instruction_count: u64,
    pub scope: &'static str,
}
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub phase: &'static str,
    pub flags: u32,
    pub code: u32,
    pub exception_address: u64,
    pub control_pc: u64,
    pub establisher: u64,
    pub handler: u64,
    pub disposition: Option<u32>,
    pub parameters: Vec<u64>,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub cpu_faults: Vec<CpuFault>,
    pub cpu_faults_omitted: u64,
    pub profile: &'static str,
    pub active: bool,
    pub pending: bool,
    pub events: Vec<Event>,
    pub exceptions_raised: u64,
    pub c_scope_requests: u64,
    pub guest_filters: u64,
    pub guest_finally: u64,
    pub unwinds_started: u64,
    pub unwinds_completed: u64,
    pub transient_unwind_frames: u64,
    pub dispatcher_boundaries_crossed: u64,
    pub api_exceptions: Vec<api_frame::Evidence>,
    pub scope: &'static str,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    let state = &engine.get_data().native_exceptions;
    if state.raised == 0 && state.events.is_empty() && !state.active && state.pending.is_none() {
        return None;
    }
    Some(Report {
        cpu_faults: state.cpu_faults.clone(),
        cpu_faults_omitted: state.cpu_faults_omitted,
        profile: "amd64-guest-exception-search-unwind-v2",
        active: state.active,
        pending: state.pending.is_some(),
        events: state.events.clone(),
        exceptions_raised: state.raised,
        c_scope_requests: state.scope.requests,
        guest_filters: state.scope.filters,
        guest_finally: state.scope.terminations,
        unwinds_started: state.unwinds_started,
        unwinds_completed: state.unwinds_completed,
        transient_unwind_frames: state.transient_unwind_frames,
        dispatcher_boundaries_crossed: state.dispatcher_boundaries_crossed,
        api_exceptions: state.api_exceptions.clone(),
        scope: "INT3 and unavailable non-KVM-backend MSR #GP search/unwind through actual guest handlers, C filters and finally routines. Legacy CONTEXT uses mode-specific x87/selector/debug rules; fault contexts preserve the resume flag and pre-instruction registers. No physical-host MSR availability is claimed. x86 hardware-fault dispatch, advertised KVM backend, selector/debug edits, nested/collided dispatch, C++ destruction and XSTATE/CET remain unsupported.",
    })
}
pub(crate) fn install(engine: &mut Unicorn<Trace>) -> Result<()> {
    if engine.get_data().architecture != Architecture::X64 {
        return Ok(());
    }
    // Windows SDK INITIAL_FPCSR / INITIAL_MXCSR, independent of backend reset.
    uc(engine.reg_write(R::FPCW, 0x027f))?;
    uc(engine.reg_write(R::MXCSR, 0x1f80))?;
    uc(engine.add_intr_hook(|engine, number| {
        let result = (|| -> Result<()> {
            ensure!(number == 3, "Unsupported guest CPU interrupt {number}");
            ensure!(
                !engine.get_data().native_exceptions.active,
                "Nested native exception dispatch is not yet supported"
            );
            ensure!(
                engine.get_data().native_exceptions.pending.is_none(),
                "An exception is already pending"
            );
            let pc = uc(engine.pc_read())?;
            let address = pc.checked_sub(1).context("Breakpoint address underflow")?;
            let mut byte = [0];
            read(engine, address, &mut byte)?;
            ensure!(byte == [0xcc], "Unsupported breakpoint encoding");
            // Windows normalizes the trap RIP back to the INT3 byte before
            // invoking handlers; the native probe also supplies parameter0=0.
            uc(engine.reg_write(R::RIP, address))?;
            engine.get_data_mut().native_exceptions.raised += 1;
            engine.get_data_mut().native_exceptions.pending = Some(ExceptionRecord {
                code: 0x80000003,
                flags: 0,
                nested_record: 0,
                address,
                parameters: vec![0],
            });
            Ok(())
        })();
        if let Err(error) = result {
            engine.get_data_mut().cpu.fault = Some(format!("{error:#}"));
        }
        let _ = engine.emu_stop();
    }))?;
    Ok(())
}
pub(crate) fn queued(engine: &Unicorn<Trace>) -> bool {
    engine.get_data().native_exceptions.pending.is_some() || c_scope::queued(engine)
}
pub(crate) fn queue_msr_gp(
    engine: &mut Unicorn<Trace>,
    pc: u64,
    size: u32,
    index: u32,
    write: bool,
) -> Result<()> {
    ensure!(
        engine.get_data().architecture == Architecture::X64,
        "MSR #GP exception dispatch requires AMD64"
    );
    ensure!(
        !engine.get_data().native_exceptions.active
            && engine.get_data().native_exceptions.pending.is_none(),
        "Nested native fault dispatch is not yet supported"
    );
    ensure!(
        uc(engine.pc_read())? == pc,
        "CPU fault instruction identity changed"
    );
    let evidence = CpuFault {
        pc,
        instruction_size: size,
        vector: 13,
        error_code: 0,
        msr_index: index,
        write,
        saved_resume_flag: true,
        instruction_count: engine.get_data().instructions,
        scope: "Configured CPU backend has no KVM MSR device; #GP(0) before register/memory effects. Bounded evidence only; no physical-host capability inference.",
    };
    let state = &mut engine.get_data_mut().native_exceptions;
    if state.cpu_faults.len() < 64 {
        state.cpu_faults.push(evidence);
    } else {
        state.cpu_faults_omitted = state.cpu_faults_omitted.saturating_add(1);
    }
    state.pending_resume_flag = true;
    state.raised += 1;
    // Pinned KiPreprocessFault/KiOp_Priv lower the #GP from RDMSR/WRMSR
    // to STATUS_PRIVILEGED_INSTRUCTION with NumberParameters=0.
    state.pending = Some(ExceptionRecord {
        code: 0xc0000096,
        flags: 0,
        nested_record: 0,
        address: pc,
        parameters: vec![],
    });
    Ok(())
}
fn require(engine: &Unicorn<Trace>, address: u64, size: usize, p: P) -> Result<()> {
    crate::api::require_without_timer_guard(engine, address, size as u64, p)
}
fn read(engine: &Unicorn<Trace>, address: u64, bytes: &mut [u8]) -> Result<()> {
    require(engine, address, bytes.len(), P::READ)?;
    uc(engine.mem_read(address, bytes))
}
fn owned_stack(engine: &Unicorn<Trace>, sp: u64) -> Result<Stack> {
    if let Some((low, high)) = crate::threads::dpc::active_stack(engine) {
        ensure!(
            sp >= low && sp < high,
            "Exception RSP left the active DPC stack"
        );
        return Ok(Stack { low, high });
    }
    let region = engine
        .get_data()
        .apis
        .memory
        .region(sp)
        .context("Exception stack is not mapped")?;
    ensure!(
        region.tag.contains("stack"),
        "Exception RSP is not on an owned stack"
    );
    Ok(Stack {
        low: region.base,
        high: region.base + region.size,
    })
}
fn memory<'a, 'uc>(engine: &'a Unicorn<'uc, Trace>) -> impl unwind::Memory + 'a {
    move |address, bytes: &mut [u8]| {
        read(engine, address, bytes).map_err(|_| unwind::Error::Read {
            address,
            size: bytes.len(),
        })
    }
}
fn image(engine: &Unicorn<Trace>, pc: u64) -> Result<(Image, u64)> {
    let m = engine
        .get_data()
        .apis
        .modules
        .containing(pc)
        .context("Exception PC has no loaded guest image")?;
    let mut dos = [0; 64];
    read(engine, m.base, &mut dos)?;
    ensure!(&dos[..2] == b"MZ", "Exception module has no DOS header");
    let nt = u32::from_le_bytes(dos[60..64].try_into().unwrap()) as u64;
    ensure!(
        nt + 168 <= m.size,
        "Exception module header outside mapping"
    );
    let mut header = [0; 168];
    read(engine, m.base + nt, &mut header)?;
    ensure!(
        &header[..4] == b"PE\0\0" && header[24..26] == [0x0b, 0x02],
        "Exception module is not AMD64 PE32+"
    );
    let rva = u32::from_le_bytes(header[160..164].try_into().unwrap());
    let size = u32::from_le_bytes(header[164..168].try_into().unwrap());
    Ok((
        Image::parse(
            &mut memory(engine),
            m.base,
            u32::try_from(m.size)?,
            rva,
            size,
        )?,
        m.base + rva as u64,
    ))
}
pub(crate) fn transition(
    engine: &mut Unicorn<Trace>,
    horizon: &ExecutionHorizon,
) -> Result<Option<Outcome>> {
    if c_scope::queued(engine) {
        return c_scope::transition(engine, horizon);
    }
    let exception = engine
        .get_data_mut()
        .native_exceptions
        .pending
        .take()
        .context("No pending exception")?;
    api_frame::deliver(engine)?;
    ensure!(
        !engine.get_data().native_exceptions.active,
        "Nested native dispatch"
    );
    engine.get_data_mut().native_exceptions.active = true;
    engine.get_data_mut().native_exceptions.owner = Some((
        crate::threads::current_id(engine),
        engine.get_data().cpu.processor,
        crate::threads::thread_address(engine),
    ));
    let resume_flag =
        std::mem::take(&mut engine.get_data_mut().native_exceptions.pending_resume_flag);
    let result = dispatch(engine, &exception, horizon, resume_flag);
    if !matches!(&result, Ok(Some(_))) {
        engine.get_data_mut().native_exceptions.active = false;
    }
    result.with_context(|| format!("Native EXCEPTION {:#010x} dispatch failed", exception.code))
}
fn dispatch(
    engine: &mut Unicorn<Trace>,
    exception: &ExceptionRecord,
    horizon: &ExecutionHorizon,
    resume_flag: bool,
) -> Result<Option<Outcome>> {
    let mut original = capture(engine)?;
    if resume_flag {
        let mut bytes = *original.bytes();
        let flags = original.registers().eflags | 0x10000;
        bytes[68..72].copy_from_slice(&flags.to_le_bytes());
        original = ContextRecord::from_bytes(&bytes)?;
    }
    let saved = uc(engine.context_init())?;
    let mut context = original.registers();
    let stack = owned_stack(engine, context.integer[4])?;
    let anchor = context.integer[4]
        .checked_sub(0xc00)
        .context("Exception stack underflow")?
        & !15;
    ensure!(anchor >= stack.low + 0x1000, "Exception stack overflow");
    let fault = anchor;
    let original_pointer = anchor + 0xa0;
    let search_pointer = anchor + 0x570;
    let dispatcher_pointer = anchor + 0xa40;
    crate::cpu::write(engine, fault, &exception.bytes()?)?;
    crate::cpu::write(engine, original_pointer, original.bytes())?;
    let marker = engine.get_data().return_marker + LANGUAGE_RETURN;
    let mut visited = BTreeSet::new();
    for _ in 0..128 {
        ensure!(
            visited.insert((context.rip, context.integer[4])),
            "Exception frame cycle"
        );
        if context.rip == engine.get_data().return_marker {
            break;
        }
        if let Some(caller) = api_frame::caller(engine, &context, stack)? {
            context = caller;
            continue;
        }
        let (image, table) = image(engine, context.rip)?;
        let frame = unwind::unwind(&mut memory(engine), &image, &context, stack, 1)?;
        if let Some(handler) = frame.handler {
            ensure!(
                engine.get_data().native_exceptions.events.len() < 256,
                "Native exception event bound exceeded"
            );
            let event = engine.get_data().native_exceptions.events.len();
            engine.get_data_mut().native_exceptions.events.push(Event {
                phase: "search",
                flags: exception.flags,
                code: exception.code,
                exception_address: exception.address,
                control_pc: context.rip,
                establisher: frame.establisher,
                handler: handler.address,
                disposition: None,
                parameters: exception.parameters.clone(),
            });
            let function = frame.function.context("Handler missing runtime function")?;
            let index = image
                .functions
                .binary_search_by_key(&function.begin, |f| f.begin)
                .map_err(|_| anyhow::anyhow!("Runtime function identity lost"))?;
            let dispatcher = DispatcherContext {
                control_pc: context.rip,
                image_base: image.base,
                function_entry: table + index as u64 * 12,
                establisher_frame: frame.establisher,
                context_record: search_pointer,
                language_handler: handler.address,
                handler_data: handler.data,
                ..DispatcherContext::default()
            };
            let mut search = original.clone();
            search.update(&frame.caller);
            crate::cpu::write(engine, search_pointer, search.bytes())?;
            crate::cpu::write(engine, dispatcher_pointer, &dispatcher.bytes())?;
            let arguments = [
                fault,
                frame.establisher,
                original_pointer,
                dispatcher_pointer,
            ];
            engine.get_data_mut().native_exceptions.handler_arguments = Some(arguments);
            let result = invoke(
                engine,
                handler.address,
                &arguments,
                anchor - 0x28,
                marker,
                horizon,
            )?;
            engine.get_data_mut().native_exceptions.handler_arguments = None;
            if !result.returned {
                if let Some(request) = engine.get_data_mut().native_exceptions.unwind.take() {
                    return unwind_phase::execute(
                        engine, request, &original, &saved, anchor, stack, horizon,
                    );
                }
                return Ok(Some(result));
            }
            let disposition = result.value.context("Missing handler disposition")? as u32;
            engine.get_data_mut().native_exceptions.events[event].disposition = Some(disposition);
            uc(engine.context_restore(&saved))?;
            match disposition {
                0 => {
                    let mut live = [0; 152];
                    read(engine, fault, &mut live)?;
                    let live = ExceptionRecord::from_bytes(&live)?;
                    ensure!(
                        live.flags & 1 == 0,
                        "Handler attempted to resume a noncontinuable exception"
                    );
                    let mut bytes = [0; 1232];
                    read(engine, original_pointer, &mut bytes)?;
                    restore(engine, &original, &ContextRecord::from_bytes(&bytes)?)?;
                    return Ok(None);
                }
                1 => {}
                _ => bail!("Unsupported exception-handler disposition {disposition}"),
            }
        }
        context = frame.caller;
    }
    bail!(
        "Unhandled native exception {:#010x} at {:#x}",
        exception.code,
        exception.address
    )
}

/// Shared Win64 guest routine boundary for language handlers and filters.
fn invoke(
    engine: &mut Unicorn<Trace>,
    address: u64,
    arguments: &[u64],
    call_sp: u64,
    marker: u64,
    horizon: &ExecutionHorizon,
) -> Result<Outcome> {
    ensure!(
        arguments.len() <= 4 && call_sp % 16 == 8,
        "Invalid exception routine call frame"
    );
    let saved = uc(engine.context_init())?;
    if engine.get_data().apis.kernel_mode {
        let address = uc(engine.reg_read(R::GS_BASE))?
            .checked_add(0x180)
            .context("Kernel handler MXCSR address overflow")?;
        let mut value = [0; 4];
        read(engine, address, &mut value)?;
        let value = u32::from_le_bytes(value);
        ensure!(
            value & !0xffff == 0,
            "Kernel handler MXCSR contains reserved bits"
        );
        uc(engine.reg_write(R::MXCSR, value as u64))?;
    }
    let nonvolatile = [
        R::RBX,
        R::RBP,
        R::RSI,
        R::RDI,
        R::R12,
        R::R13,
        R::R14,
        R::R15,
    ]
    .into_iter()
    .map(|reg| uc(engine.reg_read(reg)).map(|value| (reg, value)))
    .collect::<Result<Vec<_>>>()?;
    let vectors = XMM[6..]
        .iter()
        .map(|reg| uc(engine.reg_read_long(*reg)).map(|value| (*reg, value)))
        .collect::<Result<Vec<_>>>()?;
    let flags = uc(engine.reg_read(R::EFLAGS))?;
    let mxcsr = uc(engine.reg_read(R::MXCSR))?;
    let fpcw = uc(engine.reg_read(R::FPCW))?;
    require(engine, address, 1, P::EXECUTE)?;
    require(engine, call_sp, 40, P::WRITE)?;
    let mut call = [0; 40];
    call[..8].copy_from_slice(&marker.to_le_bytes());
    crate::cpu::write(engine, call_sp, &call)?;
    uc(engine.reg_write(R::RSP, call_sp))?;
    for (reg, value) in [R::RCX, R::RDX, R::R8, R::R9]
        .into_iter()
        .zip(arguments.iter().copied())
    {
        uc(engine.reg_write(reg, value))?;
    }
    let thread = crate::threads::current_id(engine);
    let processor = engine.get_data().cpu.processor;
    let result = crate::threads::execute_horizon(engine, address, marker, horizon)?;
    if !result.returned {
        return Ok(result);
    }
    ensure!(
        uc(engine.reg_read(R::RSP))? == call_sp + 8,
        "Exception handler violated Win64 stack ABI"
    );
    for (reg, value) in nonvolatile {
        ensure!(
            uc(engine.reg_read(reg))? == value,
            "Exception handler changed nonvolatile register {reg:?}"
        );
    }
    for (reg, value) in vectors {
        ensure!(
            uc(engine.reg_read_long(reg))? == value,
            "Exception handler changed nonvolatile vector {reg:?}"
        );
    }
    let after_flags = uc(engine.reg_read(R::EFLAGS))?;
    ensure!(
        after_flags & 0x400 == 0 && (after_flags ^ flags) & 0x3200 == 0,
        "Exception handler changed protected flags"
    );
    ensure!(
        (uc(engine.reg_read(R::MXCSR))? ^ mxcsr) & 0xffc0 == 0,
        "Exception handler changed nonvolatile MXCSR"
    );
    ensure!(
        uc(engine.reg_read(R::FPCW))? == fpcw,
        "Exception routine changed nonvolatile x87 control"
    );
    ensure!(
        thread == crate::threads::current_id(engine)
            && processor == engine.get_data().cpu.processor,
        "Exception handler returned in a different execution context"
    );

    uc(engine.context_restore(&saved))?;
    Ok(result)
}

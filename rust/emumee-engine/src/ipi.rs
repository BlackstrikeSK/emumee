//! Actual guest callback contexts for a bounded cooperative IPI broadcast.
//! Ordinary scheduler handles/threads remain authoritative and parked throughout.
use super::*;
use anyhow::Context as _;
use emumee_core::ipi::{QUANTUM, Rendezvous};
use std::collections::BTreeMap;
use unicorn_engine::Context;
#[derive(Clone, Copy, Debug)]
pub(crate) enum Action {
    Begin,
    Yield,
    Return,
}
struct Caller {
    context: Context,
    gate: u64,
    thread: u64,
    processor: u32,
    irql: u8,
    critical: u16,
    last_error: u32,
    observation: Option<usize>,
}
struct Frame {
    caller: Caller,
    members: BTreeMap<u32, Context>,
    quantum_end: u64,
}
pub(crate) struct State {
    pub model: Rendezvous,
    frame: Option<Frame>,
    pending_observation: Option<usize>,
    resume_gate: Option<u64>,
    pub native_effect_failure: bool,
    descriptor_guard_installed: bool,
    descriptor_denials: u64,
}
impl State {
    pub(crate) fn new(architecture: Architecture) -> Self {
        Self {
            model: Rendezvous::new(architecture),
            frame: None,
            pending_observation: None,
            resume_gate: None,
            native_effect_failure: false,
            descriptor_guard_installed: false,
            descriptor_denials: 0,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub rendezvous: Rendezvous,
    pub current_processor: u32,
    pub current_thread: u64,
    pub native_effect_failure: bool,
    pub descriptor_guard_installed: bool,
    pub descriptor_denials: u64,
    pub processors: Option<crate::kernel_cpu::ipi_processors::Report>,
    pub scope: &'static str,
}
pub(crate) fn active(engine: &Unicorn<Trace>) -> bool {
    engine.get_data().ipi.model.active.is_some()
}
pub(crate) fn member_running(engine: &Unicorn<Trace>) -> bool {
    engine.get_data().ipi.model.current.is_some()
}
pub(crate) fn current_thread(engine: &Unicorn<Trace>) -> Option<u64> {
    let state = &engine.get_data().ipi;
    let processor = state.model.current?;
    let group = state.model.active_broadcast().ok()?;
    if processor == group.source_processor {
        Some(group.caller_thread)
    } else {
        emumee_core::ipi::processor_layout(engine.get_data().architecture, processor)
            .and_then(|layout| layout.parked_thread)
    }
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Report {
    let mut model = engine.get_data().ipi.model.clone();
    if let (Some(index), Some(processor)) = (model.active, model.current) {
        if let Ok(delta) = model.observed_current_instructions(engine.get_data().instructions) {
            model.broadcasts[index].members[processor as usize].instruction_count =
                model.broadcasts[index].members[processor as usize]
                    .instruction_count
                    .saturating_add(delta);
        }
    }
    Report {
        rendezvous: model,
        current_processor: engine.get_data().cpu.processor,
        current_thread: crate::threads::thread_address(engine),
        native_effect_failure: engine.get_data().ipi.native_effect_failure,
        descriptor_guard_installed: engine.get_data().ipi.descriptor_guard_installed,
        descriptor_denials: engine.get_data().ipi.descriptor_denials,
        processors: crate::kernel_cpu::ipi_processors::report(engine),
        scope: "Actual guest IPI callback contexts on one configured logical processor group, separate owned stack/KPCR/borrowed parked Thread environments, cooperative high-IRQL rendezvous and shared global budgets. Ordinary created threads stay parked during the broadcast. No host parallel execution, general interrupts, APC/DPC delivery or fabricated callback returns.",
    }
}
fn descriptor_intersection(engine: &Unicorn<Trace>, address: u64, size: u64) -> bool {
    if !member_running(engine) || size == 0 {
        return false;
    }
    let tables =
        emumee_core::kernel_layout::KernelLayout::for_architecture(engine.get_data().architecture)
            .descriptor_tables;
    address < tables + 8192 && address.checked_add(size).is_none_or(|end| end > tables)
}
pub(crate) fn require_api_access(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
    permissions: Permissions,
) -> Result<()> {
    ensure!(
        !permissions.contains(Permissions::WRITE)
            || !descriptor_intersection(engine, address, size),
        "IPI guest/API descriptor mutation is outside the owned processor profile"
    );
    Ok(())
}
fn install_descriptor_guard(engine: &mut Unicorn<Trace>) -> Result<()> {
    if engine.get_data().ipi.descriptor_guard_installed {
        return Ok(());
    }
    uc(
        engine.add_mem_hook(HookType::MEM_WRITE, 1, 0, |engine, _, address, size, _| {
            if descriptor_intersection(engine, address, size as u64) {
                let denials = engine.get_data().ipi.descriptor_denials.saturating_add(1);
                engine.get_data_mut().ipi.descriptor_denials = denials;
                engine.get_data_mut().apis.fault = Some(
                    "IPI guest descriptor mutation is outside the owned processor profile".into(),
                );
                let _ = engine.emu_stop();
            }
            true
        }),
    )?;
    engine.get_data_mut().ipi.descriptor_guard_installed = true;
    Ok(())
}
pub(crate) fn call(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    ensure!(args.len() == 2, "Kernel IPI argument count mismatch");
    ensure!(
        !crate::threads::dpc::active(engine),
        "IPI rendezvous during a DPC callback is unsupported"
    );
    ensure!(
        engine.get_data().apis.kernel_mode,
        "IPI requires native kernel target"
    );
    ensure!(
        !engine.get_data().ipi.native_effect_failure,
        "IPI native effect failed; execution cannot resume"
    );
    ensure!(
        engine.get_data().ipi.resume_gate.is_none(),
        "IPI caller has not consumed its completed API gate"
    );
    ensure!(
        !active(engine),
        "Kernel IPI nested broadcast is not supported"
    );
    crate::api::kernel_spin::require_no_held(engine)?;
    let source = engine.get_data().cpu.processor;
    ensure!(
        source == 0,
        "Ordinary caller routing outside logical CPU0 is not modeled"
    );
    let profile = &engine.get_data().cpu.profile;
    profile.validate()?;
    engine.get_data().apis.persona.validate_cpu(profile)?;
    let logical = profile
        .cores
        .checked_mul(profile.threads_per_core)
        .context("Configured processor topology overflow")?;
    let caller = crate::threads::thread_address(engine);
    let pcr = crate::kernel_cpu::current_pcr(engine)
        .context("IPI source lacks initialized kernel processor context")?;
    let wide = engine.get_data().architecture == Architecture::X64;
    let irql = if wide {
        uc(engine.reg_read(RegisterX86::CR8))? as u8
    } else {
        uc(engine.mem_read_as_vec(pcr + 0x24, 1))?[0]
    };
    let critical = engine.get_data().apis.kernel.save().1;
    engine.get_data_mut().apis.kernel.restore((irql, critical));
    if wide {
        crate::cpu::write(engine, pcr + 0x50, &[irql])?;
    }
    let next = engine
        .get_data()
        .ipi
        .model
        .begin(args[0], args[1], logical, source, caller, irql)?;
    let marker = engine.get_data().return_marker;
    ensure!(
        args[0] < marker || args[0] >= marker + 4096,
        "IPI callback cannot be an emulator return marker"
    );
    ensure!(
        engine
            .get_data()
            .apis
            .memory
            .allows(args[0], 1, Permissions::EXECUTE),
        "IPI callback is not executable guest code"
    );
    crate::kernel_cpu::ipi_processors::validate_profile(engine, caller, irql)?;
    // All accepted resources are owned guest mappings. Any partial native
    // preparation is terminal and never produces an accepted completed group.
    crate::kernel_cpu::ipi_processors::prepare(engine, logical)?;
    install_descriptor_guard(engine)?;
    let observation = engine.get_data().apis.next_event_index();
    engine.get_data_mut().ipi.model = next;
    engine.get_data_mut().ipi.pending_observation = observation;
    engine.get_data_mut().ipi_action = Some(Action::Begin);
    Ok(0)
}
pub(crate) fn before_instruction(engine: &mut Unicorn<Trace>, pc: u64) -> bool {
    if !active(engine) {
        return false;
    }
    if engine.get_data().ipi.model.current.is_none() {
        return false;
    }
    if pc == engine.get_data().return_marker + 0x100 {
        engine.get_data_mut().apis.fault =
            Some("IPI callback escaped into an ordinary thread return marker".into());
        return true;
    }
    if pc == engine.get_data().return_marker + 0x200 {
        engine.get_data_mut().ipi_action = Some(Action::Return);
        return true;
    }
    if engine.get_data().instructions
        >= engine
            .get_data()
            .ipi
            .frame
            .as_ref()
            .map(|frame| frame.quantum_end)
            .unwrap_or(u64::MAX)
        && engine.get_data().ipi.model.has_ready_member()
    {
        engine.get_data_mut().ipi_action = Some(Action::Yield);
        return true;
    }
    false
}
pub(crate) fn observe_native_irql(engine: &mut Unicorn<Trace>) -> Result<()> {
    if !active(engine) || engine.get_data().ipi.model.current.is_none() {
        return Ok(());
    }
    let pcr = crate::kernel_cpu::current_pcr(engine).context("IPI API lacks processor context")?;
    let wide = engine.get_data().architecture == Architecture::X64;
    let actual = if wide {
        uc(engine.reg_read(RegisterX86::CR8))? as u8
    } else {
        uc(engine.mem_read_as_vec(pcr + 0x24, 1))?[0]
    };
    ensure!(
        actual == engine.get_data().ipi.model.level(),
        "IPI member API entry requires actual IPI_LEVEL; ordinary scheduler continuations are unsupported"
    );
    // Validate both independently owned IRQL views and actual identity before
    // any PCR mirror; a corrupted byte cannot be repaired into fake success.
    let thread = current_thread(engine).context("IPI API lost its owned current Thread")?;
    crate::kernel_cpu::ipi_processors::validate_member_return(
        engine,
        thread,
        engine.get_data().ipi.model.level(),
    )?;
    let critical = engine.get_data().apis.kernel.save().1;
    engine
        .get_data_mut()
        .apis
        .kernel
        .restore((actual, critical));
    if wide {
        crate::cpu::write(engine, pcr + 0x50, &[actual])?;
    }
    Ok(())
}
fn ax(engine: &Unicorn<Trace>) -> Result<u64> {
    uc(
        engine.reg_read(if engine.get_data().architecture == Architecture::X64 {
            RegisterX86::RAX
        } else {
            RegisterX86::EAX
        }),
    )
}
fn make_frame(engine: &mut Unicorn<Trace>) -> Result<Frame> {
    ensure!(
        engine.get_data().ipi.frame.is_none(),
        "IPI native frame already active"
    );
    let group = engine.get_data().ipi.model.active_broadcast()?.clone();
    let (irql, critical) = engine.get_data().apis.kernel.save();
    let caller = Caller {
        context: uc(engine.context_init())?,
        gate: uc(engine.pc_read())?,
        thread: group.caller_thread,
        processor: group.source_processor,
        irql,
        critical,
        last_error: engine.get_data().apis.last_error,
        observation: engine.get_data().ipi.pending_observation,
    };
    let architecture = engine.get_data().architecture;
    let width = architecture.width();
    let marker = engine.get_data().return_marker + 0x200;
    let registers: &[RegisterX86] = if width == 8 {
        &[
            RegisterX86::RAX,
            RegisterX86::RBX,
            RegisterX86::RCX,
            RegisterX86::RDX,
            RegisterX86::RSI,
            RegisterX86::RDI,
            RegisterX86::RBP,
            RegisterX86::R8,
            RegisterX86::R9,
            RegisterX86::R10,
            RegisterX86::R11,
            RegisterX86::R12,
            RegisterX86::R13,
            RegisterX86::R14,
            RegisterX86::R15,
        ]
    } else {
        &[
            RegisterX86::EAX,
            RegisterX86::EBX,
            RegisterX86::ECX,
            RegisterX86::EDX,
            RegisterX86::ESI,
            RegisterX86::EDI,
            RegisterX86::EBP,
        ]
    };
    let mut members = BTreeMap::new();
    for member in &group.members {
        let (stack, size) = crate::kernel_cpu::ipi_processors::stack(engine, member.processor)?;
        // Legacy callback stacks start clear on each accepted broadcast. This
        // guest allocation is bounded by count*STACK_SIZE, never a host pointer.
        crate::cpu::write(engine, stack, &vec![0u8; size as usize])?;
        let mut context = uc(engine.context_init())?;
        for register in registers {
            uc(context.reg_write(*register, 0))?;
        }
        uc(context.reg_write(RegisterX86::EFLAGS, 2))?;
        let sp = stack + size - if width == 8 { 0x108 } else { 0x10c };
        crate::cpu::write(engine, sp, &marker.to_le_bytes()[..width])?;
        if width == 8 {
            uc(context.reg_write(RegisterX86::RSP, sp))?;
            uc(context.reg_write(RegisterX86::RCX, group.argument))?;
        } else {
            uc(context.reg_write(RegisterX86::ESP, sp))?;
            crate::cpu::write(engine, sp + 4, &(group.argument as u32).to_le_bytes())?;
        }
        uc(context.reg_write(
            if width == 8 {
                RegisterX86::RIP
            } else {
                RegisterX86::EIP
            },
            group.routine,
        ))?;
        members.insert(member.processor, context);
    }
    Ok(Frame {
        caller,
        members,
        quantum_end: 0,
    })
}
fn run_member(engine: &mut Unicorn<Trace>, frame: &mut Frame, processor: u32) -> Result<()> {
    let next = engine
        .get_data()
        .ipi
        .model
        .dispatch(processor, engine.get_data().instructions)?;
    uc(engine.context_restore(
        frame
            .members
            .get(&processor)
            .context("Ready IPI member has no native context")?,
    ))?;
    let level = next.level();
    let critical = if processor == frame.caller.processor {
        frame.caller.critical
    } else {
        0
    };
    let thread = crate::kernel_cpu::ipi_processors::thread(
        engine,
        processor,
        frame.caller.processor,
        frame.caller.thread,
    )?;
    engine.get_data_mut().ipi.model = next;
    engine.get_data_mut().apis.kernel.restore((level, critical));
    engine.get_data_mut().apis.last_error = 0;
    crate::kernel_cpu::ipi_processors::activate(engine, processor, thread)?;
    frame.quantum_end = engine
        .get_data()
        .instructions
        .checked_add(QUANTUM)
        .context("IPI instruction quantum overflow")?;
    Ok(())
}
fn restore_caller(engine: &mut Unicorn<Trace>, frame: &Frame) -> Result<()> {
    let result = engine.get_data().ipi.model.pending_source_result()?;
    uc(engine.context_restore(&frame.caller.context))?;
    engine
        .get_data_mut()
        .apis
        .kernel
        .restore((frame.caller.irql, frame.caller.critical));
    engine.get_data_mut().apis.last_error = frame.caller.last_error;
    crate::kernel_cpu::ipi_processors::activate(
        engine,
        frame.caller.processor,
        frame.caller.thread,
    )?;
    ensure!(
        uc(engine.pc_read())? == frame.caller.gate,
        "IPI caller restored to a different API continuation"
    );
    ensure!(
        crate::threads::thread_address(engine) == frame.caller.thread,
        "IPI caller restored to a different Thread object"
    );
    uc(engine.reg_write(
        if engine.get_data().architecture == Architecture::X64 {
            RegisterX86::RAX
        } else {
            RegisterX86::EAX
        },
        result,
    ))?;
    if let Some(index) = frame.caller.observation {
        let event = engine
            .get_data_mut()
            .apis
            .events
            .get_mut(index)
            .context("IPI caller lost its exact API observation")?;
        ensure!(
            event.api == "ntoskrnl.KeIpiGenericCall" && event.pending,
            "IPI caller observation does not represent its pending broadcast"
        );
        event.result = Some(result);
        event.pending = false;
        event.effect = Some("ipi_broadcast_complete");
    }
    let committed = engine.get_data().ipi.model.commit_restored_caller()?;
    engine.get_data_mut().ipi.model = committed;
    engine.get_data_mut().ipi.resume_gate = Some(frame.caller.gate);
    Ok(())
}
/// Executes only in the outer CPU loop, never recursively from a native hook.
pub(crate) fn transition(engine: &mut Unicorn<Trace>, action: Action) -> Result<()> {
    ensure!(
        !engine.get_data().ipi.native_effect_failure,
        "IPI native effect failed"
    );
    engine.get_data_mut().ipi.native_effect_failure = true;
    let mut frame = match action {
        Action::Begin => make_frame(engine)?,
        _ => engine
            .get_data_mut()
            .ipi
            .frame
            .take()
            .context("IPI transition lacks native frame")?,
    };
    let result = (|| -> Result<bool> {
        match action {
            Action::Begin => {}
            Action::Yield => {
                let processor = engine
                    .get_data()
                    .ipi
                    .model
                    .current
                    .context("IPI yield lacks current member")?;
                uc(engine.context_save(
                    frame
                        .members
                        .get_mut(&processor)
                        .context("IPI yield member context missing")?,
                ))?;
                let yielded = engine
                    .get_data()
                    .ipi
                    .model
                    .yield_member(processor, engine.get_data().instructions)?;
                engine.get_data_mut().ipi.model = yielded;
            }
            Action::Return => {
                let processor = engine
                    .get_data()
                    .ipi
                    .model
                    .current
                    .context("IPI return lacks current member")?;
                let thread = crate::kernel_cpu::ipi_processors::thread(
                    engine,
                    processor,
                    frame.caller.processor,
                    frame.caller.thread,
                )?;
                let level = engine.get_data().ipi.model.level();
                crate::kernel_cpu::ipi_processors::validate_profile(engine, thread, level)?;
                let value = ax(engine)?;
                let returned = engine.get_data().ipi.model.return_member(
                    processor,
                    engine.get_data().instructions,
                    value,
                    engine.get_data().apis.kernel.save().0,
                )?;
                engine.get_data_mut().ipi.model = returned;
            }
        }
        if let Some(processor) = engine.get_data().ipi.model.next_ready()? {
            run_member(engine, &mut frame, processor)?;
            Ok(false)
        } else {
            restore_caller(engine, &frame)?;
            Ok(true)
        }
    })();
    let completed = result.as_ref().copied().unwrap_or(false);
    if !completed {
        engine.get_data_mut().ipi.frame = Some(frame);
    }
    if result.is_ok() {
        engine.get_data_mut().ipi.native_effect_failure = false;
    }
    result.map(|_| ())
}
pub(crate) fn resume_api(engine: &mut Unicorn<Trace>, pc: u64) -> Result<bool> {
    if let Some(expected) = engine.get_data().ipi.resume_gate {
        ensure!(pc == expected, "IPI resumed at another API gate");
        ensure!(
            !engine.get_data().ipi.native_effect_failure,
            "IPI caller native restore failed"
        );
        engine.get_data_mut().ipi.resume_gate = None;
        return Ok(true);
    }
    Ok(false)
}

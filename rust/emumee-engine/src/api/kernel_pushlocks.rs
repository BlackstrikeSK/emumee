//! Owned pinned stable AutoBoost effects. No invented disabled APCs, waiters,
//! boosts or scheduler kicks. Guest publication failures latch refusal.
use super::*;
use emumee_core::kernel_autoboost::{abi, owned};
use emumee_core::kernel_thread_objects::{Lifetime, Ownership};
#[derive(Default)]
pub(crate) struct State {
    model: owned::State,
    native_failure: bool,
    guard_installed: bool,
    native_write: Option<(u64, u64)>,
    events: Vec<Event>,
    omitted: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub instruction_ordinal: u64,
    pub operation: &'static str,
    pub thread: u64,
    pub lock: u64,
    pub entry: Option<u64>,
    pub data_writes: usize,
    pub stack_spills: usize,
    pub normal_apcs_disabled: bool,
    pub documented_apc_contract_satisfied: bool,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub state: owned::State,
    pub native_effect_failure: bool,
    pub events: Vec<Event>,
    pub events_omitted: u64,
    pub scope: &'static str,
}
pub(crate) fn enabled(engine: &Unicorn<Trace>) -> bool {
    engine.get_data().apis.kernel_mode
        && engine.get_data().architecture == Architecture::X64
        && engine.get_data().machine.is_configured()
        && engine.get_data().machine.windows_build() == 26200
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    enabled(engine).then(||{let s=&engine.get_data().apis.kernel_pushlocks;Report {
        state:s.model.clone(),native_effect_failure:s.native_failure,events:s.events.clone(),events_omitted:s.omitted,
        scope:"Owned x64 build26200 ordinary CPU0 stable exclusive push locks and six-entry kernel AutoBoost allocation inside owned thread pages. Fresh allocation has no preexisting lock history; current scheduler has no priority-boost/kick or APC-delivery producer. Flags0, initialized writable resident image/nonpaged-Pool words only. Stable native data/stack/GPR/ADD-flag effects include IF enablement; core model owns entry/lock lifetimes and refuses recursion, contention, exhaustion, unknown kick/boost/tree/alias/backing changes. APC-disable state is preserved; documented caller-contract violations are diagnostic, not fabricated native exceptions. Private block/pointer bytes remain unavailable to guest inline access. No full native boot, guest inline lock mutation, contended waits, AutoBoost trees/boost removal, APC/interrupt delivery or arbitrary native caller equivalence.",
    }})
}
pub(crate) fn ready(engine: &Unicorn<Trace>) -> Result<()> {
    ensure!(
        !engine.get_data().apis.kernel_pushlocks.native_failure,
        "AutoBoost native effect failed; execution cannot resume"
    );
    Ok(())
}
pub(crate) fn completion_error(engine: &Unicorn<Trace>) -> Option<String> {
    ready(engine).err().map(|e| e.to_string())
}
fn privileged(engine: &mut Unicorn<Trace>, address: u64, bytes: &[u8]) -> Result<()> {
    super::reference_mapping::require_api_access(engine, address, bytes.len() as u64, P::WRITE)?;
    let result = uc(engine.mem_write(address, bytes));
    crate::instruction_window::model_write(engine, address, bytes, result.is_ok());
    result?;
    ensure!(
        uc(engine.mem_read_as_vec(address, bytes.len()))? == bytes,
        "AutoBoost privileged write readback failed"
    );
    Ok(())
}
pub(crate) fn initialize_thread(engine: &mut Unicorn<Trace>, life: &Lifetime) -> Result<()> {
    if !enabled(engine) || matches!(life.role, Ownership::ParkedProcessor { .. }) {
        return Ok(());
    }
    ready(engine)?;
    let next = engine
        .get_data()
        .apis
        .kernel_pushlocks
        .model
        .register_thread(life)?;
    let thread = &next.threads[&life.address];
    ensure!(
        engine
            .get_data()
            .apis
            .memory
            .allows(life.address, 4096, P::NONE),
        "AutoBoost lacks exclusively owned thread page backing"
    );
    engine.get_data_mut().apis.kernel_pushlocks.native_failure = true;
    // Only the separately allocated block and its two typed pointer fields are
    // written. Unknown MiscFlags/ThreadFlags/PRCB words are never zeroed.
    privileged(engine, thread.block, &thread.bytes)?;
    privileged(engine, life.address + 0x470, &thread.block.to_le_bytes())?;
    privileged(engine, life.address + 0x478, &0u64.to_le_bytes())?;
    engine.get_data_mut().apis.kernel_pushlocks.model = next;
    engine.get_data_mut().apis.kernel_pushlocks.native_failure = false;
    Ok(())
}
pub(crate) fn finish_thread(engine: &mut Unicorn<Trace>, life: &Lifetime) -> Result<()> {
    if !engine
        .get_data()
        .apis
        .kernel_pushlocks
        .model
        .threads
        .contains_key(&life.address)
    {
        return Ok(());
    }
    ready(engine)?;
    let next = engine
        .get_data()
        .apis
        .kernel_pushlocks
        .model
        .finish_thread(life)?;
    engine.get_data_mut().apis.kernel_pushlocks.model = next;
    Ok(())
}
pub(crate) fn require_exit(engine: &Unicorn<Trace>) -> Result<()> {
    ready(engine)?;
    engine
        .get_data()
        .apis
        .kernel_pushlocks
        .model
        .require_thread_exit(crate::threads::thread_address(engine))?;
    Ok(())
}
pub(crate) fn require_write(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    let s = &engine.get_data().apis.kernel_pushlocks;
    if s.native_write == Some((address, size)) {
        return Ok(());
    }
    ensure!(
        !s.model.overlaps(address, size),
        "API mutation of an initialized exclusive push word is unsupported"
    );
    Ok(())
}
pub(crate) fn require_mapping(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    ensure!(
        !engine
            .get_data()
            .apis
            .kernel_pushlocks
            .model
            .overlaps(address, size.max(1)),
        "Mapping/alias change overlaps an initialized exclusive push word"
    );
    Ok(())
}
pub(crate) fn require_release(engine: &Unicorn<Trace>, base: u64, size: u64) -> Result<()> {
    ready(engine)?;
    engine
        .get_data()
        .apis
        .kernel_pushlocks
        .model
        .require_release(base, size)?;
    Ok(())
}
pub(crate) fn retire(engine: &mut Unicorn<Trace>, base: u64, size: u64) -> Result<()> {
    let next = engine
        .get_data()
        .apis
        .kernel_pushlocks
        .model
        .retire_backing(base, size)?;
    engine.get_data_mut().apis.kernel_pushlocks.model = next;
    Ok(())
}
fn install_guard(engine: &mut Unicorn<Trace>) -> Result<()> {
    if engine.get_data().apis.kernel_pushlocks.guard_installed {
        return Ok(());
    }
    uc(engine.add_mem_hook(unicorn_engine::unicorn_const::HookType::MEM_WRITE,1,0,|engine,_,address,size,_|{
        if require_write(engine,address,size as u64).is_err() {
            engine.get_data_mut().apis.kernel_pushlocks.native_failure=true;
            engine.get_data_mut().apis.fault=Some("Direct guest mutation of an initialized exclusive push word; native effects uncertain".into());
            let _=engine.emu_stop();
        }
        true
    }))?;
    engine.get_data_mut().apis.kernel_pushlocks.guard_installed = true;
    Ok(())
}
fn registers(engine: &Unicorn<Trace>) -> Result<abi::Registers> {
    let r = |reg| uc(engine.reg_read(reg));
    Ok(abi::Registers {
        rax: r(RegisterX86::RAX)?,
        rbx: r(RegisterX86::RBX)?,
        rcx: r(RegisterX86::RCX)?,
        rdx: r(RegisterX86::RDX)?,
        rbp: r(RegisterX86::RBP)?,
        rsi: r(RegisterX86::RSI)?,
        rdi: r(RegisterX86::RDI)?,
        rsp: r(RegisterX86::RSP)?,
        r8: r(RegisterX86::R8)?,
        r9: r(RegisterX86::R9)?,
        r10: r(RegisterX86::R10)?,
        r11: r(RegisterX86::R11)?,
        r14: r(RegisterX86::R14)?,
    })
}
pub(super) fn call(
    engine: &mut Unicorn<Trace>,
    call: super::kernel_sync::Call,
    args: &[u64],
) -> Result<u64> {
    ready(engine)?;
    ensure!(
        enabled(engine)
            && engine.get_data().cpu.processor == 0
            && !crate::ipi::active(engine)
            && !crate::threads::dpc::active(engine),
        "AutoBoost stable native profile requires ordinary owned CPU0"
    );
    let thread = crate::threads::thread_address(engine);
    super::kernel_thread_objects::validate_owned_thread(engine, thread)?;
    let irql = super::kernel_sync::observe_irql(engine)?;
    let normal_apcs_disabled = engine.get_data().apis.kernel.save().1 > 0 || irql >= 1;
    use super::kernel_sync::Call::{PushAcquire, PushInitialize, PushRelease};
    let init = matches!(call, PushInitialize);
    ensure!(
        irql <= if init {
            15
        } else if matches!(call, PushRelease) {
            2
        } else {
            1
        },
        "AutoBoost stable operation exceeds qualified IRQL"
    );
    ensure!(
        args.len() == if init { 1 } else { 2 },
        "AutoBoost argument count mismatch"
    );
    let backing = super::kernel_spin::backing(engine, args[0], 8)?;
    let word = u64::from_le_bytes(read(engine, args[0], 8)?.try_into().unwrap());
    let input = owned::Input {
        thread,
        address: args[0],
        word,
        backing,
        flags: args.get(1).copied().unwrap_or(0) as u32,
        // The owned scheduler has no priority-kick producer. A future producer
        // must replace this profile and invalidate its absent-kick authority.
        work_priority_kick: Some(0),
        normal_apcs_disabled,
    };
    let state = &engine.get_data().apis.kernel_pushlocks.model;
    let plan = match call {
        PushInitialize => state.initialize_lock(input)?,
        PushAcquire => state.acquire(input)?,
        PushRelease => state.release(input)?,
        _ => bail!("Not an exclusive push operation"),
    };
    let regs = registers(engine)?;
    let bounds = super::kernel_thread_objects::ordinary_stack_fields(engine, thread)?
        .ok_or_else(|| anyhow::anyhow!("AutoBoost requires an ordinary owned stack"))?;
    ensure!(
        regs.rsp >= bounds.limit + 0x88
            && regs
                .rsp
                .checked_add(0x10)
                .is_some_and(|end| end <= bounds.base),
        "AutoBoost native ABI exceeds owned stack"
    );
    let kernel_base = engine
        .get_data()
        .apis
        .modules
        .module("ntoskrnl.exe")?
        .ok_or_else(|| anyhow::anyhow!("Owned kernel module missing"))?
        .base;
    let pcr = crate::kernel_cpu::current_pcr(engine)?;
    let prcb = u64::from_le_bytes(read(engine, pcr + 0x20, 8)?.try_into().unwrap());
    ensure!(
        uc(engine.reg_read(RegisterX86::GS_BASE))? == pcr,
        "AutoBoost GS differs from owned CPU"
    );
    let effects = abi::stable(
        plan.operation,
        regs,
        uc(engine.reg_read(RegisterX86::EFLAGS))?,
        kernel_base,
        prcb,
        thread,
        plan.entry_address,
    )
    .ok_or_else(|| anyhow::anyhow!("AutoBoost native ABI geometry unsupported"))?;
    let block = &state.threads[&thread];
    ensure!(
        uc(engine.mem_read_as_vec(block.block, block.bytes.len()))? == block.bytes,
        "AutoBoost native block diverged from owned state"
    );
    for spill in &effects.spills {
        require(engine, spill.address, spill.bytes.len() as u64, P::WRITE)?;
    }
    install_guard(engine)?;
    engine.get_data_mut().apis.kernel_pushlocks.native_failure = true;
    for spill in &effects.spills {
        crate::cpu::write(engine, spill.address, &spill.bytes)?;
    }
    for w in &plan.writes {
        ensure!(
            uc(engine.mem_read_as_vec(w.address, w.before.len()))? == w.before,
            "AutoBoost native prefix differs from planned bytes"
        );
        if w.address >= thread + owned::BLOCK_PAGE_OFFSET
            && w.address + (w.after.len() as u64)
                <= thread + owned::BLOCK_PAGE_OFFSET + owned::BLOCK_BYTES as u64
        {
            privileged(engine, w.address, &w.after)?;
        } else {
            ensure!(
                w.address == args[0] && w.after.len() == 8,
                "AutoBoost plan escapes typed data effects"
            );
            engine.get_data_mut().apis.kernel_pushlocks.native_write = Some((w.address, 8));
            let result = crate::cpu::write(engine, w.address, &w.after);
            engine.get_data_mut().apis.kernel_pushlocks.native_write = None;
            result?;
            ensure!(
                uc(engine.mem_read_as_vec(w.address, 8))? == w.after,
                "Push word write readback failed"
            );
        }
    }
    let r = effects.registers;
    for (reg, value) in [
        (RegisterX86::RAX, r.rax),
        (RegisterX86::RCX, r.rcx),
        (RegisterX86::RDX, r.rdx),
        (RegisterX86::R8, r.r8),
        (RegisterX86::R9, r.r9),
        (RegisterX86::R10, r.r10),
        (RegisterX86::R11, r.r11),
    ] {
        uc(engine.reg_write(reg, value))?;
    }
    uc(engine.reg_write(RegisterX86::EFLAGS, effects.flags))?;
    let event = Event {
        instruction_ordinal: engine.get_data().instructions,
        operation: plan.operation,
        thread,
        lock: plan.lock,
        entry: plan.entry_address,
        data_writes: plan.writes.len(),
        stack_spills: effects.spills.len(),
        normal_apcs_disabled,
        documented_apc_contract_satisfied: init || normal_apcs_disabled,
    };
    let s = &mut engine.get_data_mut().apis.kernel_pushlocks;
    s.model = plan.state;
    if s.events.len() < 256 {
        s.events.push(event);
    } else {
        s.omitted += 1;
    }
    s.native_failure = false;
    Ok(0)
}

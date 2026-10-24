//! One native DPC frame over the Scheduler's sole FIFO and actual CPU0 Thread.
//! No emu_start recursion, host work queue, extra Thread or reset execution budget.
use super::*;
use emumee_core::scheduler::{DpcCounters, DpcPolicy, DpcWork};
use unicorn_engine::unicorn_const::HookType;
const RESERVATION: u64 = 0x14000;
const STACK_SIZE: u64 = 0x10000;
const HISTORY: usize = 512;
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Layout {
    pub base: u64,
    pub stack: u64,
    pub stack_size: u64,
    pub timer_arguments: [u64; 2],
}
impl Layout {
    pub(crate) fn new(arch: Architecture) -> Self {
        let base = if arch == Architecture::X64 {
            0xffffc50000000000
        } else {
            0xc5000000
        };
        Self {
            base,
            stack: base + 4096,
            stack_size: STACK_SIZE,
            timer_arguments: [base + 0x11010, base + 0x12020],
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) enum Continuation {
    Instruction,
    Action(Action),
    SchedulerPump,
}
struct Frame {
    caller: Context,
    pc: u64,
    thread: u64,
    slot: u64,
    irql: u8,
    critical: u16,
    last_error: u32,
    msr_version: u64,
    expected_sp: u64,
    address: u64,
    work: DpcWork,
    start: u64,
    continuation: Continuation,
}
#[derive(Clone, Debug, Serialize)]
pub struct Invocation {
    pub address: u64,
    pub work: DpcWork,
    pub thread: u64,
    pub thread_slot: u64,
    pub processor: u32,
    pub start_instruction: u64,
    pub return_instruction: Option<u64>,
    pub caller_restored: bool,
    pub continuation: &'static str,
}
pub(crate) struct State {
    layout: Layout,
    prepared: bool,
    guard_installed: bool,
    native_mirror: bool,
    frame: Option<Frame>,
    wake: bool,
    returned: bool,
    pub native_effect_failure: bool,
    observations: Vec<Invocation>,
    omitted: u64,
}
impl State {
    pub(crate) fn new(arch: Architecture) -> Self {
        Self {
            layout: Layout::new(arch),
            prepared: false,
            guard_installed: false,
            native_mirror: false,
            frame: None,
            wake: false,
            returned: false,
            native_effect_failure: false,
            observations: Vec::new(),
            omitted: 0,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub version: &'static str,
    pub policy: DpcPolicy,
    pub layout: Layout,
    pub environment_prepared: bool,
    pub active: bool,
    pub queued: Vec<u64>,
    pub counters: DpcCounters,
    pub invocations: Vec<Invocation>,
    pub omitted_invocations: u64,
    pub native_effect_failure: bool,
    pub timer_argument_provenance: &'static str,
    pub scope: &'static str,
}
pub(super) fn report(t: &ThreadExecution) -> Report {
    Report {
        version: "cpu0-dpc-dispatch-v1",
        policy: t.model.dpc_policy(),
        layout: t.dpc.layout,
        environment_prepared: t.dpc.prepared,
        active: t.dpc.frame.is_some(),
        queued: t.model.queued_dpcs().collect(),
        counters: t.model.dpc_counters().clone(),
        invocations: t.dpc.observations.clone(),
        omitted_invocations: t.dpc.omitted,
        native_effect_failure: t.dpc.native_effect_failure,
        timer_argument_provenance: "Timer-origin SystemArgument1/2 are version1 synthetic unspecified opaque pointers into owned NOACCESS pages; never timestamps, native Windows pointers, or dereferenceable data. Caller-origin arguments are exact guest values.",
        scope: "Actual CPU0 DISPATCH_LEVEL callbacks on a separate guest-owned stack, preserving the actual interrupted Thread, full native caller context and shared execution horizon. FIFO default importance/current CPU only; no nested execution, self-running requeue, shared timer/direct origins, remote targeting, APC or general hardware interrupt delivery.",
    }
}
pub(super) fn queued(engine: &Unicorn<Trace>) -> bool {
    engine
        .get_data()
        .threads
        .as_ref()
        .is_some_and(|t| t.model.queued_dpcs().next().is_some())
}
pub(crate) fn active(engine: &Unicorn<Trace>) -> bool {
    engine
        .get_data()
        .threads
        .as_ref()
        .is_some_and(|t| t.dpc.frame.is_some())
}
pub(crate) fn active_stack(engine:&Unicorn<Trace>)->Option<(u64,u64)> {
    if !active(engine) {return None;}
    let layout=state(engine).ok()?.layout;
    Some((layout.stack,layout.stack+layout.stack_size))
}
fn state<'a>(engine: &'a Unicorn<'_, Trace>) -> Result<&'a State> {
    Ok(&engine
        .get_data()
        .threads
        .as_ref()
        .context("DPC lacks scheduler")?
        .dpc)
}
fn overlap(a: u64, n: u64, b: u64, m: u64) -> bool {
    n != 0
        && m != 0
        && a.checked_add(n).is_none_or(|e| b < e)
        && b.checked_add(m).is_none_or(|e| a < e)
}
pub(crate) fn require_ready(engine: &Unicorn<Trace>) -> Result<()> {
    if let Some(t) = &engine.get_data().threads {
        ensure!(
            !t.dpc.native_effect_failure,
            "DPC native effect failed; execution cannot resume"
        );
    }
    Ok(())
}
pub(crate) fn require_mapping_change(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
) -> Result<()> {
    if let Some(t) = &engine.get_data().threads {
        ensure!(
            !t.dpc.prepared || !overlap(address, size.max(1), t.dpc.layout.base, RESERVATION),
            "Memory mapping change overlaps owned DPC environment"
        );
    }
    Ok(())
}
pub(crate) fn require_alias(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    require_mapping_change(engine, address, size)
}
fn processor_storage(engine: &Unicorn<Trace>, address: u64, size: u64) -> bool {
    if !active(engine) || size == 0 {
        return false;
    }
    crate::kernel_cpu::current_pcr(engine).is_ok_and(|pcr| {
        let tables =
            KernelLayout::for_architecture(engine.get_data().architecture).descriptor_tables;
        overlap(address, size, pcr, 4096) || overlap(address, size, tables, 8192)
    })
}
pub(crate) fn require_api_access(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
    permissions: P,
) -> Result<()> {
    ensure!(
        !permissions.contains(P::WRITE)
            || !processor_storage(engine, address, size)
            || state(engine)?.native_mirror,
        "DPC guest/API processor identity or descriptor mutation is unsupported"
    );
    Ok(())
}
fn fail(engine: &mut Unicorn<Trace>, error: anyhow::Error) {
    let message = format!("{error:#}");
    if let Some(t) = &mut engine.get_data_mut().threads {
        t.dpc.native_effect_failure = true;
    }
    engine.get_data_mut().apis.fault = Some(message);
    let _ = engine.emu_stop();
}
pub(super) fn prepare_environment(engine: &mut Unicorn<Trace>) -> Result<()> {
    require_ready(engine)?;
    if state(engine)?.prepared {
        return Ok(());
    }
    let layout = state(engine)?.layout;
    let mut memory = engine.get_data().apis.memory.clone();
    memory.map(
        layout.base,
        RESERVATION,
        P::NONE,
        Some(1),
        "owned CPU0 DPC reservation and opaque arguments",
    )?;
    memory.protect(layout.stack, STACK_SIZE, P::RW)?;
    // Prove that the gate is inside the same executable owned return page and is
    // distinct from root, child, IPI and loader gates before the first mapping.
    let marker = engine.get_data().return_marker;
    let gate = marker.checked_add(0x400).context("DPC gate overflow")?;
    ensure!(
        marker % 4096 == 0
            && gate < marker + 4096
            && engine
                .get_data()
                .apis
                .memory
                .allows(marker, 4096, P::EXECUTE),
        "DPC return gate lacks owned executable return page"
    );
    for offset in [0, 0x100, 0x200, 0x300] {
        ensure!(
            gate != marker + offset,
            "DPC return gate collides with existing native continuation"
        );
    }
    engine
        .get_data_mut()
        .threads
        .as_mut()
        .unwrap()
        .dpc
        .native_effect_failure = true;
    uc(engine.mem_map(layout.base, RESERVATION, Prot::NONE))?;
    uc(engine.mem_protect(layout.stack, STACK_SIZE, Prot::READ | Prot::WRITE))?;
    engine.get_data_mut().apis.memory = memory;
    if !state(engine)?.guard_installed {
        uc(
            engine.add_mem_hook(HookType::MEM_WRITE, 1, 0, |e, _, address, size, _| {
                if processor_storage(e, address, size as u64) {
                    fail(
                        e,
                        anyhow::anyhow!(
                            "DPC direct processor/descriptor write; native effects uncertain"
                        ),
                    );
                }
                true
            }),
        )?;
        engine
            .get_data_mut()
            .threads
            .as_mut()
            .unwrap()
            .dpc
            .guard_installed = true;
    }
    let t = engine.get_data_mut().threads.as_mut().unwrap();
    t.dpc.prepared = true;
    t.dpc.native_effect_failure = false;
    Ok(())
}
fn identity(engine: &Unicorn<Trace>, thread: u64, irql: u8) -> Result<()> {
    ensure!(
        engine.get_data().apis.kernel_mode
            && uc(engine.reg_read(RegisterX86::CS))? & 3 == 0
            && engine.get_data().cpu.processor == 0,
        "DPC requires initialized CPL0 CPU0 context"
    );
    ensure!(
        thread == crate::api::kernel_thread_objects::current_thread(engine)?,
        "DPC current Thread authority mismatch"
    );
    crate::api::kernel_thread_objects::validate_owned_thread(engine, thread)?;
    crate::kernel_cpu::ipi_processors::validate_profile(engine, thread, irql)
}
pub(crate) fn observe_api(engine: &mut Unicorn<Trace>) -> Result<()> {
    require_ready(engine)?;
    if let Some(frame) = engine
        .get_data()
        .threads
        .as_ref()
        .and_then(|t| t.dpc.frame.as_ref())
    {
        identity(engine, frame.thread, 2)?;
    }
    Ok(())
}
pub(crate) fn before_instruction(engine: &mut Unicorn<Trace>, pc: u64, size: u32) -> bool {
    if engine.get_data().threads.is_none() {
        return false;
    }
    if let Err(error) = require_ready(engine) {
        fail(engine, error);
        return true;
    }
    if active(engine) {
        let marker = engine.get_data().return_marker;
        if pc == marker + 0x400 {
            engine.get_data_mut().threads.as_mut().unwrap().dpc.returned = true;
            return true;
        }
        if pc >= marker && pc < marker + 4096 {
            fail(
                engine,
                anyhow::anyhow!("DPC callback escaped into a foreign return gate"),
            );
            return true;
        }
        if forbidden_processor_instruction_cached(engine, pc, size) {
            fail(
                engine,
                anyhow::anyhow!("DPC architectural processor mutation is unsupported"),
            );
            return true;
        }
        return false;
    }
    if crate::ipi::active(engine)
        || engine
            .get_data()
            .threads
            .as_ref()
            .unwrap()
            .model
            .queued_dpcs()
            .next()
            .is_none()
    {
        return false;
    }
    match crate::api::kernel_sync::observe_irql(engine) {
        Ok(level) if level < 2 => {
            engine.get_data_mut().threads.as_mut().unwrap().dpc.wake = true;
            true
        }
        Ok(_) => false,
        Err(error) => {
            fail(engine, error);
            true
        }
    }
}
// Reuse the CPU page cache's invalidation boundary. A failed guest read is
// never cached, preserving the original retry/fault behavior. The size key
// prevents a stale decision if Unicorn presents a different decode length.
fn forbidden_processor_instruction_cached(engine: &mut Unicorn<Trace>, pc: u64, size: u32) -> bool {
    if !(1..=15).contains(&size) {
        return false;
    }
    if let Some(forbidden) = engine.get_data().cpu.cache.dpc_lookup(pc, size) {
        return forbidden;
    }
    let mut bytes = [0u8; 15];
    if engine.mem_read(pc, &mut bytes[..size as usize]).is_err() {
        return false;
    }
    let forbidden =
        forbidden_processor_instruction(engine.get_data().architecture, &bytes[..size as usize]);
    engine
        .get_data_mut()
        .cpu
        .cache
        .dpc_store(pc, size, forbidden);
    forbidden
}
pub(super) fn wake_pending(engine: &Unicorn<Trace>) -> bool {
    engine
        .get_data()
        .threads
        .as_ref()
        .is_some_and(|t| t.dpc.wake || t.dpc.returned)
}
pub(super) fn observe_root(engine: &mut Unicorn<Trace>, value: u64) -> Result<()> {
    if let Some(t) = &mut engine.get_data_mut().threads {
        ensure!(t.current_slot == 1, "Child reached root return marker");
        if let Some(old) = t.root_return {
            ensure!(
                old == value,
                "Root return observation changed after deferred work"
            );
        } else {
            t.root_return = Some(value);
        }
    }
    Ok(())
}
pub(super) fn offer(engine: &mut Unicorn<Trace>, continuation: Continuation) -> Result<bool> {
    require_ready(engine)?;
    if active(engine) || crate::ipi::active(engine) {
        return Ok(false);
    }
    if engine.get_data().threads.is_none() {
        return Ok(false);
    }
    timers::refresh(engine)?;
    if engine
        .get_data()
        .threads
        .as_ref()
        .unwrap()
        .model
        .next_dpc()?
        .is_none()
    {
        return Ok(false);
    }
    let irql = crate::api::kernel_sync::observe_irql(engine)?;
    if irql >= 2 {
        return Ok(false);
    }
    crate::api::kernel_spin::require_no_held(engine)?;
    let thread = thread_address(engine);
    identity(engine, thread, irql)?;
    prepare_environment(engine)?;
    let t = engine.get_data().threads.as_ref().unwrap();
    let dpc = t.model.next_dpc()?.context("DPC FIFO lost head")?.clone();
    let work = dpc
        .phase
        .work()
        .context("DPC head lacks queued work")?
        .clone();
    let slot = t.current_slot;
    let layout = t.dpc.layout;
    let mut admitted = t.model.clone();
    ensure!(
        admitted.start_dpc(dpc.address)? == work,
        "DPC native admission lost exact FIFO work"
    );
    let critical = engine.get_data().apis.kernel.save().1;
    let arch = engine.get_data().architecture;
    let width = arch.width();
    ensure!(
        engine
            .get_data()
            .apis
            .memory
            .allows(dpc.routine, 1, P::EXECUTE),
        "Queued DPC callback lost executable backing"
    );
    let pc = uc(engine.pc_read())?;
    let caller = uc(engine.context_init())?;
    let marker = engine.get_data().return_marker + 0x400;
    let sp = layout.stack + STACK_SIZE - if width == 8 { 0x108 } else { 0x110 };
    let expected_sp = sp + if width == 8 { 8 } else { 20 };
    let frame = Frame {
        caller,
        pc,
        thread,
        slot,
        irql,
        critical,
        last_error: engine.get_data().apis.last_error,
        msr_version: crate::kernel_cpu::msr_version(engine),
        expected_sp,
        address: dpc.address,
        work: work.clone(),
        start: engine.get_data().instructions,
        continuation,
    };
    // Retain the frame and terminal flag before any write/register/native effect.
    engine.get_data_mut().threads.as_mut().unwrap().dpc.frame = Some(frame);
    engine
        .get_data_mut()
        .threads
        .as_mut()
        .unwrap()
        .dpc
        .native_effect_failure = true;
    let mut payload = vec![0u8; if width == 8 { 40 } else { 20 }];
    payload[..width].copy_from_slice(&marker.to_le_bytes()[..width]);
    let args = [
        dpc.address,
        dpc.context,
        work.arguments[0],
        work.arguments[1],
    ];
    if width == 4 {
        for (i, arg) in args.iter().enumerate() {
            payload[4 + i * 4..8 + i * 4].copy_from_slice(&(*arg as u32).to_le_bytes());
        }
    }
    cpu::write(engine, sp, &payload)?;
    uc(engine.reg_write(
        if width == 8 {
            RegisterX86::RSP
        } else {
            RegisterX86::ESP
        },
        sp,
    ))?;
    if width == 8 {
        for (register, arg) in [
            RegisterX86::RCX,
            RegisterX86::RDX,
            RegisterX86::R8,
            RegisterX86::R9,
        ]
        .into_iter()
        .zip(args)
        {
            uc(engine.reg_write(register, arg))?;
        }
    }
    engine.get_data_mut().apis.kernel.restore((2, critical));
    mirror_identity(engine, thread)?;
    uc(engine.reg_write(pc_register(arch), dpc.routine))?;
    timers::with_threads(engine, |engine, t| timers::publish(engine, t, admitted))?;
    let instructions = engine.get_data().instructions;
    let t = engine.get_data_mut().threads.as_mut().unwrap();
    if t.dpc.observations.len() < HISTORY {
        t.dpc.observations.push(Invocation {
            address: dpc.address,
            work,
            thread,
            thread_slot: slot,
            processor: 0,
            start_instruction: instructions,
            return_instruction: None,
            caller_restored: false,
            continuation: match continuation {
                Continuation::Instruction => "instruction",
                Continuation::Action(_) => "deferred_scheduler_action",
                Continuation::SchedulerPump => "scheduler_pump",
            },
        });
    } else {
        t.dpc.omitted = t.dpc.omitted.saturating_add(1);
    }
    t.dpc.wake = false;
    t.dpc.native_effect_failure = false;
    Ok(true)
}
pub(super) fn finish(engine: &mut Unicorn<Trace>) -> Result<Continuation> {
    require_ready(engine)?;
    let t = engine
        .get_data()
        .threads
        .as_ref()
        .context("DPC return lacks scheduler")?;
    let frame = t
        .dpc
        .frame
        .as_ref()
        .context("DPC return lacks native frame")?;
    ensure!(
        t.dpc.returned && uc(engine.pc_read())? == engine.get_data().return_marker + 0x400,
        "DPC did not reach its actual owned return gate"
    );
    identity(engine, frame.thread, 2)?;
    ensure!(
        t.current_slot == frame.slot && engine.get_data().apis.kernel.save().1 == frame.critical,
        "DPC changed interrupted Thread/critical depth"
    );
    ensure!(
        uc(
            engine.reg_read(if engine.get_data().architecture == Architecture::X64 {
                RegisterX86::RSP
            } else {
                RegisterX86::ESP
            })
        )? == frame.expected_sp,
        "DPC callback violated its actual VOID stdcall4 stack ABI"
    );
    ensure!(
        engine.get_data().instructions > frame.start,
        "DPC callback returned without executing guest instructions"
    );
    crate::api::kernel_spin::require_no_held(engine)?;
    timers::validate_all(engine)?;
    let address = frame.address;
    let sequence = frame.work.sequence;
    let at = engine.get_data().instructions;
    engine
        .get_data_mut()
        .threads
        .as_mut()
        .unwrap()
        .dpc
        .native_effect_failure = true;
    timers::with_threads(engine, |e, t| {
        let mut candidate = t.model.clone();
        candidate.returned_dpc(address, sequence)?;
        timers::publish(e, t, candidate)
    })?;
    if let Some(row) = engine
        .get_data_mut()
        .threads
        .as_mut()
        .unwrap()
        .dpc
        .observations
        .iter_mut()
        .rev()
        .find(|r| r.work.sequence == sequence)
    {
        row.return_instruction = Some(at);
    }
    // Keep frame retained across all failure paths; RAX is restored from the exact
    // caller Context and never imported from this VOID callback.
    let frame = engine
        .get_data_mut()
        .threads
        .as_mut()
        .unwrap()
        .dpc
        .frame
        .take()
        .unwrap();
    let result = (|| -> Result<Continuation> {
        uc(engine.context_restore(&frame.caller))?;
        crate::kernel_cpu::restore_msrs(engine, frame.msr_version)?;
        engine
            .get_data_mut()
            .apis
            .kernel
            .restore((frame.irql, frame.critical));
        engine.get_data_mut().apis.last_error = frame.last_error;
        mirror_identity(engine, frame.thread)?;
        identity(engine, frame.thread, frame.irql)?;
        ensure!(
            uc(engine.pc_read())? == frame.pc,
            "DPC restored a different caller continuation"
        );
        timers::with_threads(engine, |e, t| {
            let mut candidate = t.model.clone();
            candidate.restored_dpc(address, sequence)?;
            timers::publish(e, t, candidate)
        })?;
        Ok(frame.continuation)
    })();
    match result {
        Ok(continuation) => {
            let t = engine.get_data_mut().threads.as_mut().unwrap();
            if let Some(row) = t
                .dpc
                .observations
                .iter_mut()
                .rev()
                .find(|r| r.work.sequence == sequence)
            {
                row.caller_restored = true;
            }
            t.dpc.returned = false;
            t.dpc.native_effect_failure = false;
            Ok(continuation)
        }
        Err(error) => {
            engine.get_data_mut().threads.as_mut().unwrap().dpc.frame = Some(frame);
            Err(error)
        }
    }
}
pub(crate) fn call(engine: &mut Unicorn<Trace>, insert: bool, args: &[u64]) -> Result<u64> {
    ensure!(
        args.len() == if insert { 3 } else { 1 },
        "DPC queue API argument count mismatch"
    );
    require_ready(engine)?;
    crate::api::kernel_spin::require_ready(engine)?;
    ensure!(
        engine.get_data().apis.kernel_mode,
        "DPC queue API requires kernel target"
    );
    let level = crate::api::kernel_sync::observe_irql(engine)?;
    ensure!(
        level <= 2,
        "DPC queue above DISPATCH_LEVEL is outside the CPU0 profile"
    );
    ensure!(
        !crate::ipi::active(engine),
        "DPC queue mutation during IPI rendezvous is unsupported"
    );
    timers::validate_all(engine)?;
    let model = &engine
        .get_data()
        .threads
        .as_ref()
        .context("DPC queue lacks initialized scheduler")?
        .model;
    let mut candidate = model.clone();
    let result = if insert {
        candidate.insert_queue_dpc(args[0], [args[1], args[2]])?
    } else {
        candidate.remove_queue_dpc(args[0])?
    };
    timers::with_threads(engine, |e, t| timers::publish(e, t, candidate))?;
    Ok(u64::from(result))
}

fn mirror_identity(engine: &mut Unicorn<Trace>, thread: u64) -> Result<()> {
    engine
        .get_data_mut()
        .threads
        .as_mut()
        .unwrap()
        .dpc
        .native_mirror = true;
    let result = crate::kernel_cpu::sync(engine, thread);
    engine
        .get_data_mut()
        .threads
        .as_mut()
        .unwrap()
        .dpc
        .native_mirror = false;
    result
}

// A narrow refusal decoder, not an instruction executor. Read-only SGDT/SIDT,
// segment queries and SIMD operations keep the native CPU implementation.
fn forbidden_processor_instruction(arch: Architecture, bytes: &[u8]) -> bool {
    let mut offset = 0;
    let mut f3 = false;
    while let Some(byte) = bytes.get(offset) {
        if matches!(
            *byte,
            0xf0 | 0xf2 | 0xf3 | 0x2e | 0x36 | 0x3e | 0x26 | 0x64 | 0x65 | 0x66 | 0x67
        ) || arch == Architecture::X64 && (0x40..=0x4f).contains(byte)
        {
            f3 |= *byte == 0xf3;
            offset += 1;
        } else {
            break;
        }
    }
    let b = &bytes[offset..];
    if b.first().is_some_and(|v| {
        matches!(
            *v,
            0x8e | 0x07 | 0x17 | 0x1f | 0x9a | 0xea | 0xca | 0xcb | 0xcf
        )
    }) {
        return true;
    }
    if b.first() != Some(&0x0f) {
        return false;
    }
    if b.get(1)
        .is_some_and(|v| matches!(*v, 0x06 | 0x23 | 0xa1 | 0xa9 | 0xb2 | 0xb4 | 0xb5))
    {
        return true;
    }
    match (b.get(1), b.get(2)) {
        (Some(0x01), Some(0xf8)) => true,
        (Some(0x01), Some(modrm)) => matches!((modrm >> 3) & 7, 2 | 3 | 6) && modrm >> 6 != 3,
        (Some(0x00), Some(modrm)) => matches!((modrm >> 3) & 7, 2 | 3),
        (Some(0xae), Some(modrm)) => f3 && modrm >> 6 == 3 && matches!((modrm >> 3) & 7, 2 | 3),
        _ => false,
    }
}
#[cfg(test)]
mod processor_tests {
    use super::*;
    #[test]
    fn real_processor_writes_are_refused_before_native_effect_including_prefixes() {
        for bytes in [
            &[0x0f, 0x01, 0xf8][..],
            &[0x48, 0x0f, 0x01, 0x10],
            &[0x66, 0x0f, 0x01, 0x18],
            &[0x0f, 0x00, 0xd8],
            &[0x8e, 0xe0],
            &[0xf3, 0x48, 0x0f, 0xae, 0xd0],
            &[0x0f, 0x23, 0xc0],
        ] {
            assert!(
                forbidden_processor_instruction(Architecture::X64, bytes),
                "{bytes:02x?}"
            );
        }
        for bytes in [
            &[0x0f, 0x01, 0x00][..],
            &[0x0f, 0x01, 0x08],
            &[0x0f, 0x01, 0xd0],
            &[0x66, 0x0f, 0x6e, 0xc0],
            &[0x0f, 0xae, 0x10],
            &[0x90],
        ] {
            assert!(
                !forbidden_processor_instruction(Architecture::X64, bytes),
                "{bytes:02x?}"
            );
        }
    }
    #[test]
    fn generated_guest_write_across_page_reclassifies_cached_dpc_opcode() {
        let mut engine = crate::new_engine(Architecture::X64).unwrap();
        engine.mem_map(0x1000, 0x3000, Prot::ALL).unwrap();
        let pc = 0x2ffe;
        // SGDT [RAX] is allowed; changing only the third byte to F8 makes
        // SWAPGS, which must be refused before any native effect.
        crate::cpu::write(&mut engine, pc, &[0x0f, 0x01, 0x00]).unwrap();
        crate::cpu::observe(&mut engine, pc, 3).unwrap();
        assert!(!forbidden_processor_instruction_cached(&mut engine, pc, 3));
        assert_eq!(engine.get_data().cpu.cache.dpc_lookup(pc, 3), Some(false));
        // A different native decode size cannot reuse the decision.
        assert_eq!(engine.get_data().cpu.cache.dpc_lookup(pc, 2), None);
        crate::cpu::watch(&mut engine, 0x2000, 0x2000).unwrap();
        // Generated RIP-relative guest store: mov byte ptr [0x3000], F8.
        crate::cpu::write(
            &mut engine,
            0x1000,
            &[0xc6, 0x05, 0xf9, 0x1f, 0x00, 0x00, 0xf8],
        )
        .unwrap();
        engine.emu_start(0x1000, 0x1007, 0, 2).unwrap();
        assert_eq!(engine.get_data().cpu.cache.dpc_lookup(pc, 3), None);
        // The first post-write hook reads live bytes; the CPU observer then
        // repopulates the page, allowing subsequent DPC hits to be cached.
        assert!(forbidden_processor_instruction_cached(&mut engine, pc, 3));
        crate::cpu::observe(&mut engine, pc, 3).unwrap();
        assert!(forbidden_processor_instruction_cached(&mut engine, pc, 3));
        assert_eq!(engine.get_data().cpu.cache.dpc_lookup(pc, 3), Some(true));
        crate::cpu::write(&mut engine, 0x3000, &[0x00]).unwrap();
        assert_eq!(engine.get_data().cpu.cache.dpc_lookup(pc, 3), None);
        assert!(!forbidden_processor_instruction_cached(&mut engine, pc, 3));
        crate::cpu::observe(&mut engine, pc, 3).unwrap();
        assert!(!forbidden_processor_instruction_cached(&mut engine, pc, 3));
        assert_eq!(engine.get_data().cpu.cache.dpc_lookup(pc, 3), Some(false));
    }
}
#[cfg(test)]
mod environment_tests {
    use super::*;
    fn engine(arch: Architecture) -> crate::NativeEngine {
        let mut e = crate::new_engine(arch).unwrap();
        e.get_data_mut().apis.target(arch, true).unwrap();
        crate::kernel_cpu::initialize(&mut e).unwrap();
        let marker = e.get_data().return_marker;
        e.get_data_mut()
            .apis
            .memory
            .map(marker, 4096, P::RX, None, "generated source return page")
            .unwrap();
        e.mem_map(marker, 4096, Prot::READ | Prot::EXEC).unwrap();
        e.get_data_mut().threads = Some(ThreadExecution::new(0, arch).unwrap());
        e
    }
    #[test]
    fn environment_is_actual_owned_stack_noaccess_arguments_and_shared_mapping_alias_guards() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut e = engine(arch);
            prepare_environment(&mut e).unwrap();
            let t = e.get_data().threads.as_ref().unwrap();
            let layout = t.dpc.layout;
            assert!(
                matches!(t.model.dpc_policy(),DpcPolicy::Cpu0Dispatch{timer_arguments}if timer_arguments==layout.timer_arguments)
            );
            assert!(t.dpc.prepared);
            assert!(!t.dpc.native_effect_failure);
            assert!(
                e.get_data()
                    .apis
                    .memory
                    .allows(layout.stack, STACK_SIZE, P::RW)
            );
            for address in layout.timer_arguments {
                assert!(!e.get_data().apis.memory.allows(address, 1, P::READ));
                assert!(!e.get_data().apis.memory.allows(address, 1, P::WRITE));
                assert!(!e.get_data().apis.memory.allows(address, 1, P::EXECUTE));
                assert!(require_alias(&e, address, 1).is_err());
            }
            for (address, size) in [
                (layout.base, 0),
                (layout.base, RESERVATION),
                (layout.stack, 4096),
                (layout.base + RESERVATION - 1, 1),
            ] {
                assert!(require_mapping_change(&e, address, size).is_err());
                assert!(timers::require_mapping_change(&e, address, size).is_err());
            }
            assert!(require_mapping_change(&e, layout.base - 4096, 4096).is_ok());
        }
    }
    #[test]
    fn planned_environment_collision_does_not_publish_mapping_or_native_failure() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut e = engine(arch);
            let base = Layout::new(arch).base;
            e.get_data_mut()
                .apis
                .memory
                .map(base, 4096, P::NONE, None, "existing guest mapping")
                .unwrap();
            e.mem_map(base, 4096, Prot::NONE).unwrap();
            let before = e.get_data().apis.memory.clone();
            assert!(prepare_environment(&mut e).is_err());
            assert_eq!(e.get_data().apis.memory, before);
            let t = e.get_data().threads.as_ref().unwrap();
            assert!(!t.dpc.prepared);
            assert!(!t.dpc.native_effect_failure);
            assert_eq!(t.model.dpc_initializations(), 0);
        }
    }
    #[test]
    fn real_native_map_failure_is_sticky_without_publishing_prepared_environment_or_callback() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut e = engine(arch);
            let base = Layout::new(arch).base; /* native/model divergence is deliberate source fault injection */
            e.mem_map(base, 4096, Prot::NONE).unwrap();
            let before = e.get_data().apis.memory.clone();
            assert!(prepare_environment(&mut e).is_err());
            assert_eq!(e.get_data().apis.memory, before);
            let t = e.get_data().threads.as_ref().unwrap();
            assert!(!t.dpc.prepared);
            assert!(t.dpc.native_effect_failure);
            assert_eq!(t.model.dpc_counters().started, 0);
            assert!(require_ready(&e).is_err());
            assert!(prepare_environment(&mut e).is_err());
        }
    }
}

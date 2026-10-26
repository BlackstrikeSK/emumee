//! Generated system-thread execution with saved native Unicorn contexts.
//! Wait/synchronization handoff integration is separate from context switching.
use super::*;
use anyhow::{Context as _, bail};
pub(crate) mod dpc;
mod events;
mod object_references;
pub(crate) mod timers;
mod waits;
use emumee_core::{
    memory::Permissions as P,
    scheduler::{Dispatch, Object, Scheduler, ThreadState, WaitOutcome},
};
pub(crate) use events::{initialize_event, reset_event, set_event, wait_event};
use object_references::HandleRecord;
pub(crate) use object_references::{HandleLookup, lookup_reference_handle, thread_handle_evidence};
use std::collections::BTreeMap;
use unicorn_engine::Context;
pub(crate) use waits::{delay, wait_many};
const QUANTUM: u64 = 256;
#[derive(Clone, Copy, Debug)]
pub(crate) enum GuardedMutexCountProtocol {
    LegacySigned,
    Windows26200X64,
}
impl GuardedMutexCountProtocol {
    pub(crate) fn for_target(architecture: Architecture, build: u32) -> Self {
        if architecture == Architecture::X64 && build == 26200 {
            Self::Windows26200X64
        } else {
            Self::LegacySigned
        }
    }
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::LegacySigned => "legacy-signed-waiters-v1",
            Self::Windows26200X64 => "windows26200-x64-fast-mutex-stable-v1",
        }
    }
    pub(crate) fn owned_count(self, count: i32) -> bool {
        match self {
            Self::LegacySigned => count <= 0,
            Self::Windows26200X64 => count >= 0 && count & 3 == 0,
        }
    }
    pub(crate) fn for_waiters(self, waiters: usize) -> Result<i32> {
        let waiters = i32::try_from(waiters).context("Guarded mutex waiter count overflow")?;
        match self {
            Self::LegacySigned => Ok(-waiters),
            Self::Windows26200X64 => waiters.checked_mul(4).context("Guarded mutex bit-count overflow"),
        }
    }
    pub(crate) fn blocked_count(self, count: i32) -> Result<i32> {
        ensure!(self.owned_count(count), "Guarded mutex count is not a stable owned state");
        match self {
            Self::LegacySigned => count.checked_sub(1),
            Self::Windows26200X64 => count.checked_add(4),
        }.context("Guarded mutex blocked count overflow")
    }
}
pub(crate) fn guarded_mutex_count_protocol(engine: &Unicorn<Trace>) -> GuardedMutexCountProtocol {
    GuardedMutexCountProtocol::for_target(engine.get_data().architecture, engine.get_data().machine.windows_build())
}
use emumee_core::kernel_layout::{KernelLayout, THREAD_STACK_SIZE as CHILD_STACK_SIZE};
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) enum Action {
    Pump,
    Yield,
    Exit(u32),
    RootReturn(u64),
    Wait { thread: u64 },
}
#[derive(Clone, Copy, Default)]
struct SavedApi {
    irql: u8,
    critical: u16,
    last_error: u32,
}
struct WaitContinuation {
    address: u64,
    pc: u64,
    old_irql: u8,
    event: Option<usize>,
    event_object: bool,
    thread_object: bool,
}
pub(crate) struct ThreadExecution {
    model: Scheduler,
    dpc: dpc::State,
    contexts: BTreeMap<u64, Context>,
    context_versions: BTreeMap<u64, u64>,
    saved: BTreeMap<u64, SavedApi>,
    handles: BTreeMap<u64, HandleRecord>,
    closed_handles: std::collections::BTreeSet<u64>,
    quantum_end: u64,
    switches: u64,
    suppressed_quanta: u64,
    root_return: Option<u64>,
    active: usize,
    current_slot: u64,
    waiting: BTreeMap<u64, WaitContinuation>,
    extended_waiting: BTreeMap<u64, waits::Continuation>,
    wait_effect_failed: bool,
    timer_effect_failed: bool,
    timer_guards_installed: bool,
    timer_guest_denials: u64,
    timer_stop: Option<String>,
    waits: u64,
    resumed: u64,
}
#[derive(Debug, Serialize)]
pub struct ThreadReport {
    pub dpc: dpc::Report,
    pub count: usize,
    pub exited: usize,
    pub switches: u64,
    pub suppressed_quanta: u64,
    pub root_entry_return: Option<u64>,
    pub states: Vec<ThreadEvidence>,
    pub waits: u64,
    pub resumed_waits: u64,
    pub open_thread_handles: usize,
    pub native_wait_effect_failure: bool,
    pub timers: Vec<emumee_core::scheduler::Timer>,
    pub dpcs_initialized: Vec<emumee_core::scheduler::Dpc>,
    pub timer_initializations: u64,
    pub dpc_initializations: u64,
    pub timer_native_effect_failure: bool,
    pub timer_guards_installed: bool,
    pub timer_guest_denials: u64,
    pub timer_stop: Option<String>,
    pub scope: &'static str,
}
#[derive(Debug, Serialize)]
pub struct ThreadEvidence {
    pub slot: u64,
    pub priority: u8,
    pub role: &'static str,
    pub irql: u8,
    pub critical_depth: u16,
    pub state: ThreadState,
}
impl ThreadExecution {
    fn new(instructions: u64, architecture: Architecture) -> Result<Self> {
        let mut model = Scheduler::new(8)?;
        model.configure_dpc_dispatch(dpc::Layout::new(architecture).timer_arguments)?;
        Ok(Self {
            model,
            dpc: dpc::State::new(architecture),
            contexts: BTreeMap::new(),
            context_versions: BTreeMap::new(),
            saved: BTreeMap::new(),
            handles: BTreeMap::new(),
            closed_handles: std::collections::BTreeSet::new(),
            quantum_end: instructions + QUANTUM,
            switches: 0,
            suppressed_quanta: 0,
            root_return: None,
            active: 1,
            current_slot: 1,
            waiting: BTreeMap::new(),
            extended_waiting: BTreeMap::new(),
            wait_effect_failed: false,
            timer_effect_failed: false,
            timer_guards_installed: false,
            timer_guest_denials: 0,
            timer_stop: None,
            waits: 0,
            resumed: 0,
        })
    }
    pub fn report(&self, current: (u8, u16)) -> ThreadReport {
        ThreadReport {
            dpc: dpc::report(self),
            count: self.model.threads().count(),
            exited: self
                .model
                .threads()
                .filter(|t| matches!(t.state, ThreadState::Exited { .. }))
                .count(),
            switches: self.switches,
            suppressed_quanta: self.suppressed_quanta,
            root_entry_return: self.root_return,
            waits: self.waits,
            resumed_waits: self.resumed,
            open_thread_handles: self.handles.len(),
            native_wait_effect_failure: self.wait_effect_failed,
            timers: self.model.timers().cloned().collect(),
            dpcs_initialized: self.model.dpcs().cloned().collect(),
            timer_initializations: self.model.timer_initializations(),
            dpc_initializations: self.model.dpc_initializations(),
            timer_native_effect_failure: self.timer_effect_failed,
            timer_guards_installed: self.timer_guards_installed,
            timer_guest_denials: self.timer_guest_denials,
            timer_stop: self.timer_stop.clone(),
            states: self
                .model
                .threads()
                .map(|thread| {
                    let saved = self.saved.get(&thread.id).copied().unwrap_or_default();
                    let (irql, critical_depth) = if self.model.current() == Some(thread.id) {
                        current
                    } else {
                        (saved.irql, saved.critical)
                    };
                    ThreadEvidence {
                        slot: thread.id,
                        priority: thread.priority,
                        role: if thread.id == 1 {
                            "driver_entry_task"
                        } else {
                            "system_thread"
                        },
                        irql,
                        critical_depth,
                        state: thread.state.clone(),
                    }
                })
                .collect(),
            scope: "Single-CPU generated system threads, actual handle/object lifetimes, guarded mutex and non-alertable Executive/KernelMode single-event/thread continuations. Root task completion is not termination of the borrowed System caller object; virtual deadlines and global budgets. Dynamic priority boosts, Wait=TRUE, APC execution and full kernel thread layouts remain pending. Legacy-layout notification/synchronization timers share this scheduler, guest clock and Any/All waits; CPU0 DPC dispatch shares the actual interrupted Thread, global horizon and sole scheduler queue. Future inserted work and unsupported dispatch profiles remain explicit.",
        }
    }
}
pub(crate) fn thread_address(engine: &Unicorn<Trace>) -> u64 {
    if let Some(address) = crate::ipi::current_thread(engine) {
        return address;
    }
    address_for(engine.get_data().architecture, current_id(engine))
}
fn address_for(architecture: Architecture, id: u64) -> u64 {
    KernelLayout::for_architecture(architecture)
        .thread_object(id)
        .expect("bounded modeled kernel thread id")
}
pub(crate) fn current_id(engine: &Unicorn<Trace>) -> u64 {
    engine
        .get_data()
        .threads
        .as_ref()
        .map(|t| t.current_slot)
        .unwrap_or(1)
}
fn pc_register(arch: Architecture) -> RegisterX86 {
    if arch == Architecture::X64 {
        RegisterX86::RIP
    } else {
        RegisterX86::EIP
    }
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
pub(crate) fn before_instruction(engine: &mut Unicorn<Trace>, pc: u64) -> bool {
    if crate::ipi::active(engine) || dpc::active(engine) {
        return false;
    }
    if engine.get_data().threads.is_none() {
        return false;
    }
    if pc == engine.get_data().return_marker + 0x100 {
        engine.get_data_mut().thread_action = Some(Action::Exit(0));
        return true;
    }
    let trace = engine.get_data();
    if trace.threads.as_ref().unwrap().active > 1
        && trace.instructions >= trace.threads.as_ref().unwrap().quantum_end
    {
        match crate::api::kernel_spin::quantum_eligible(engine) {
            Ok(true) => {
                engine.get_data_mut().thread_action = Some(Action::Yield);
                return true;
            }
            Ok(false) => {
                let instructions = engine.get_data().instructions;
                let t = engine.get_data_mut().threads.as_mut().unwrap();
                t.suppressed_quanta = t.suppressed_quanta.saturating_add(1);
                t.quantum_end = instructions.saturating_add(QUANTUM);
            }
            Err(error) => {
                engine.get_data_mut().apis.fault = Some(format!("{error:#}"));
                return true;
            }
        }
    }
    false
}
fn range(engine: &Unicorn<Trace>, address: u64, size: u64, permissions: P) -> Result<()> {
    if permissions.contains(P::WRITE) {
        crate::api::kernel_spin::require_write(engine, address, size)?;
        timers::require_write(engine, address, size)?;
    }
    crate::api::kernel_thread_objects::require_api_access(engine, address, size, permissions)?;
    ensure!(
        engine
            .get_data()
            .apis
            .memory
            .allows(address, size, permissions),
        "System-thread argument range is not accessible: address={address:#x} size={size} permissions={permissions:?}"
    );
    Ok(())
}
pub(crate) fn require_event_pool_release(
    engine: &Unicorn<Trace>,
    base: u64,
    size: u64,
) -> Result<()> {
    if let Some(threads) = &engine.get_data().threads {
        let layout = if engine.get_data().architecture == Architecture::X64 {
            24
        } else {
            16
        };
        threads.model.require_event_release(base, size, layout)?;
    }
    Ok(())
}
pub(crate) fn retire_event_pool(engine: &mut Unicorn<Trace>, base: u64, size: u64) -> Result<()> {
    let layout = if engine.get_data().architecture == Architecture::X64 {
        24
    } else {
        16
    };
    if let Some(threads) = &mut engine.get_data_mut().threads {
        threads.model.retire_event_backing(base, size, layout)?;
    }
    Ok(())
}
pub(crate) fn initialize_mutex(engine: &mut Unicorn<Trace>, address: u64) -> Result<()> {
    if let Some(threads) = &mut engine.get_data_mut().threads {
        threads.model.initialize_mutex(address)?;
    }
    Ok(())
}
pub(crate) fn acquire_mutex(
    engine: &mut Unicorn<Trace>,
    address: u64,
    count: i32,
    owner: u64,
    old_irql: u8,
) -> Result<bool> {
    let protocol = guarded_mutex_count_protocol(engine);
    if engine.get_data().threads.is_none() {
        ensure!(
            count == 1 && owner == 0,
            "Kernel guarded mutex is busy; kernel thread scheduling is required"
        );
        return Ok(true);
    }
    let architecture = engine.get_data().architecture;
    let pc = uc(engine.pc_read())?;
    let event = engine.get_data().apis.next_event_index();
    let threads = engine.get_data_mut().threads.as_mut().unwrap();
    let owner_id = if owner == 0 {
        ensure!(
            count == 1,
            "Kernel guarded mutex has no tracked owner; scheduling is required"
        );
        None
    } else {
        ensure!(protocol.owned_count(count), "Invalid owned guarded mutex count for target protocol");
        Some(
            threads
                .model
                .threads()
                .find(|thread| address_for(architecture, thread.id) == owner)
                .context("Guarded mutex owner is not a modeled thread")?
                .id,
        )
    };
    threads.model.adopt_mutex(address, owner_id)?;
    let waiters = threads.model.mutex_waiters(address);
    ensure!(
        owner_id.is_none() || count == protocol.for_waiters(waiters)?,
        "Guest guarded mutex wait count diverges from scheduler"
    );
    match threads
        .model
        .wait(&[Object::Mutex(address)], false, None, old_irql)?
    {
        WaitOutcome::Immediate(_) => Ok(true),
        WaitOutcome::Blocked => {
            let thread = threads.current_slot;
            threads.waiting.insert(
                thread,
                WaitContinuation {
                    address,
                    pc,
                    old_irql,
                    event,
                    event_object: false,
                    thread_object: false,
                },
            );
            threads.waits += 1;
            engine.get_data_mut().thread_action = Some(Action::Wait { thread });
            Ok(false)
        }
    }
}
pub(crate) struct Handoff {
    pub owner: u64,
    pub old_irql: u8,
    pub count: i32,
}
pub(crate) fn release_mutex(engine: &mut Unicorn<Trace>, address: u64, count: i32) -> Result<Option<Handoff>> {
    let architecture = engine.get_data().architecture;
    let protocol = guarded_mutex_count_protocol(engine);
    let Some(threads) = &mut engine.get_data_mut().threads else {
        return Ok(None);
    };
    ensure!(count == protocol.for_waiters(threads.model.mutex_waiters(address))?,
        "Guest guarded mutex release count diverges from scheduler");
    threads
        .model
        .adopt_mutex(address, Some(threads.current_slot))?;
    threads.model.release_mutex(address)?;
    let Some(owner) = threads.model.mutex_owner(address)? else {
        return Ok(None);
    };
    let wait = threads
        .waiting
        .get(&owner)
        .context("Mutex handoff has no waiting CPU continuation")?;
    ensure!(
        wait.address == address,
        "Mutex handoff targets a different wait"
    );
    threads
        .saved
        .get_mut(&owner)
        .context("Mutex waiter has no saved API state")?
        .irql = 1;
    Ok(Some(Handoff {
        owner: address_for(architecture, owner),
        old_irql: wait.old_irql,
        count: protocol.for_waiters(threads.model.mutex_waiters(address))?,
    }))
}
pub(crate) fn resume_api(engine: &mut Unicorn<Trace>, pc: u64) -> Result<bool> {
    ensure!(
        !engine
            .get_data()
            .threads
            .as_ref()
            .is_some_and(|threads| threads.wait_effect_failed),
        "Kernel event mirror failed; execution cannot resume"
    );
    if waits::resume(engine, pc)? {
        return Ok(true);
    }
    object_references::validate_thread_wait_resume(engine, pc)?;
    let Some(threads) = &mut engine.get_data_mut().threads else {
        return Ok(false);
    };
    let current = threads.current_slot;
    let Some(wait) = threads.waiting.get(&current) else {
        return Ok(false);
    };
    if wait.pc != pc {
        return Ok(false);
    }
    let (value, effect) = if wait.thread_object {
        match threads
            .model
            .thread(current)
            .and_then(|t| t.wait_result.as_ref())
        {
            Some(emumee_core::scheduler::WaitResult::Satisfied(0)) => (0, "thread_signaled"),
            Some(emumee_core::scheduler::WaitResult::Timeout) => (0x102, "wait_timeout"),
            _ => bail!("Thread wait resumed without a scheduler result"),
        }
    } else if wait.event_object {
        match threads
            .model
            .thread(current)
            .and_then(|t| t.wait_result.as_ref())
        {
            Some(emumee_core::scheduler::WaitResult::Satisfied(0)) => (0, "event_signaled"),
            Some(emumee_core::scheduler::WaitResult::Timeout) => (0x102, "wait_timeout"),
            _ => bail!("Event wait resumed without a scheduler result"),
        }
    } else {
        ensure!(
            threads.model.mutex_owner(wait.address)? == Some(current),
            "Resumed mutex continuation lacks ownership"
        );
        (0, "mutex_acquired")
    };
    let wait = threads.waiting.remove(&current).unwrap();
    threads.resumed += 1;
    if let Some(index) = wait.event {
        let event = &mut engine.get_data_mut().apis.events[index];
        event.pending = false;
        event.result = Some(value);
        event.effect = Some(effect);
    }
    uc(engine.reg_write(
        if engine.get_data().architecture == Architecture::X64 {
            RegisterX86::RAX
        } else {
            RegisterX86::EAX
        },
        value,
    ))?;
    Ok(true)
}
pub(crate) fn set_actual_base_priority(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    ensure!(
        engine.get_data().apis.kernel_mode,
        "Thread priority requires a driver target"
    );
    ensure!(
        crate::api::kernel_sync::observe_irql(engine)? <= 2,
        "Thread priority requires IRQL at most DISPATCH_LEVEL"
    );
    let priority = u8::try_from(args[1]).context("invalid thread priority")?;
    ensure!((1..=31).contains(&priority), "invalid thread priority");
    crate::api::kernel_thread_objects::validate_owned_thread(engine, args[0])?;
    if engine.get_data().threads.is_none() {
        engine.get_data_mut().threads = Some(ThreadExecution::new(
            engine.get_data().instructions,
            engine.get_data().architecture,
        )?);
    }
    let architecture = engine.get_data().architecture;
    let id = engine
        .get_data()
        .threads
        .as_ref()
        .unwrap()
        .model
        .threads()
        .find(|thread| address_for(architecture, thread.id) == args[0])
        .map(|thread| thread.id)
        .context("priority target is not an active scheduler Thread")?;
    let previous = engine
        .get_data()
        .threads
        .as_ref()
        .unwrap()
        .model
        .thread(id)
        .context("priority target is not an active scheduler Thread")?
        .priority;
    engine
        .get_data_mut()
        .threads
        .as_mut()
        .unwrap()
        .model
        .priority(id, priority)?;
    Ok(u64::from(previous))
}
fn system_thread_attributes(engine: &Unicorn<Trace>, address: u64) -> Result<()> {
    if address == 0 {
        return Ok(());
    }
    ensure!(
        engine.get_data().architecture == Architecture::X64,
        "Non-null x86 system-thread OBJECT_ATTRIBUTES are not modeled"
    );
    // x64 OBJECT_ATTRIBUTES: Length, padding, RootDirectory, ObjectName,
    // Attributes, padding, SecurityDescriptor, SecurityQualityOfService.
    // Only the unnamed, default-security System4 handle class is modeled.
    range(engine, address, 48, P::READ)?;
    let mut bytes = [0u8; 48];
    uc(engine.mem_read(address, &mut bytes))?;
    let word = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let pointer = |offset: usize| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    let attributes = word(24);
    ensure!(
        word(0) == 48
            && pointer(8) == 0
            && pointer(16) == 0
            && attributes & !0x240 == 0
            && pointer(32) == 0
            && pointer(40) == 0,
        "System-thread OBJECT_ATTRIBUTES name/root/security/flags are not modeled"
    );
    Ok(())
}
pub(crate) fn create(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    ensure!(
        engine.get_data().apis.kernel_mode,
        "System threads require a native driver target"
    );
    ensure!(
        args[3] == 0,
        "System-thread process selection is not modeled"
    );
    system_thread_attributes(engine, args[2])?;
    ensure!(
        engine.get_data().apis.kernel.save().0 == 0,
        "System-thread creation requires PASSIVE_LEVEL"
    );
    let arch = engine.get_data().architecture;
    let width = arch.width();
    range(engine, args[0], width as u64, P::WRITE)?;
    range(engine, args[5], 1, P::EXECUTE)?;
    if args[4] != 0 {
        range(engine, args[4], 2 * width as u64, P::WRITE)?;
    }
    if engine.get_data().threads.is_none() {
        engine.get_data_mut().threads = Some(ThreadExecution::new(
            engine.get_data().instructions,
            engine.get_data().architecture,
        )?);
    }
    if engine
        .get_data()
        .threads
        .as_ref()
        .unwrap()
        .model
        .threads()
        .count()
        >= emumee_core::kernel_layout::NATIVE_THREAD_LIMIT as usize
    {
        return Ok(0xc000009a);
    }
    let id = engine
        .get_data_mut()
        .threads
        .as_mut()
        .unwrap()
        .model
        .create_thread(8)?;
    engine.get_data_mut().threads.as_mut().unwrap().active += 1;
    let layout = KernelLayout::for_architecture(arch);
    let stack = layout
        .thread_stack(id)
        .context("Kernel thread stack id bound")?;
    let object = layout
        .thread_object(id)
        .context("Kernel thread object id bound")?;
    uc(engine.mem_map(stack, CHILD_STACK_SIZE, Prot::READ | Prot::WRITE))?;
    uc(engine.mem_map(object, 4096, Prot::READ | Prot::WRITE))?;
    engine.get_data_mut().apis.memory.map(
        stack,
        CHILD_STACK_SIZE,
        P::RW,
        Some(4),
        "system thread stack",
    )?;
    engine.get_data_mut().apis.memory.map(
        object,
        4096,
        P::RW,
        Some(4),
        "opaque system thread identity",
    )?;
    // Initialize the detached context. Restoring the live CPU from inside its
    // API hook would invalidate the active translated block and replay the gate.
    let mut context = uc(engine.context_init())?;
    let prepared = (|| -> Result<()> {
        let registers: &[RegisterX86] = if arch == Architecture::X64 {
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
        for register in registers {
            uc(context.reg_write(*register, 0))?;
        }
        uc(context.reg_write(RegisterX86::EFLAGS, 0x202))?;
        let sp = stack + CHILD_STACK_SIZE
            - if arch == Architecture::X64 {
                0x108
            } else {
                0x10c
            };
        let child_return = engine.get_data().return_marker + 0x100;
        crate::cpu::write(engine, sp, &child_return.to_le_bytes()[..width])?;
        if arch == Architecture::X64 {
            uc(context.reg_write(RegisterX86::RSP, sp))?;
            uc(context.reg_write(RegisterX86::RCX, args[6]))?;
        } else {
            uc(context.reg_write(RegisterX86::ESP, sp))?;
            crate::cpu::write(engine, sp + 4, &(args[6] as u32).to_le_bytes())?;
        }
        uc(context.reg_write(pc_register(arch), args[5]))?;
        Ok(())
    })();
    prepared?;
    let handle = emumee_core::kernel_layout::native_thread_handle_first(arch) | (id * 4);
    let version = crate::kernel_cpu::msr_version(engine);
    let threads = engine.get_data_mut().threads.as_mut().unwrap();
    threads.contexts.insert(id, context);
    threads.context_versions.insert(id, version);
    // PsCreateSystemThread starts at PASSIVE_LEVEL in a critical region.
    threads.saved.insert(
        id,
        SavedApi {
            critical: 1,
            ..SavedApi::default()
        },
    );
    threads.handles.insert(
        handle,
        HandleRecord {
            id,
            granted_access: args[1] as u32,
            owner: 4,
            kernel_only: true,
        },
    );
    crate::api::kernel_thread_objects::created(engine, id, 1)?;
    crate::cpu::write(engine, args[0], &handle.to_le_bytes()[..width])?;
    if args[4] != 0 {
        let guest_id = crate::api::kernel_thread_objects::guest_id_for_slot(engine, id)?;
        crate::cpu::write(engine, args[4], &4u64.to_le_bytes()[..width])?;
        crate::cpu::write(
            engine,
            args[4] + width as u64,
            &guest_id.to_le_bytes()[..width],
        )?;
    }
    Ok(0)
}
pub(crate) fn terminate(engine: &mut Unicorn<Trace>, status: u32) -> Result<u64> {
    ensure!(
        !crate::ipi::active(engine),
        "IPI callback cannot terminate an ordinary system thread"
    );
    ensure!(
        current_id(engine) != 1,
        "PsTerminateSystemThread outside a spawned system thread"
    );
    ensure!(
        engine.get_data().apis.kernel.save().0 == 0,
        "System-thread termination requires PASSIVE_LEVEL"
    );
    ensure!(
        engine.get_data().apis.kernel_mode && engine.get_data().threads.is_some(),
        "System-thread termination has no modeled system-thread context"
    );
    engine.get_data_mut().thread_action = Some(Action::Exit(status));
    Ok(0)
}
pub(crate) fn close(engine: &mut Unicorn<Trace>, handle: u64) -> Result<u64> {
    object_references::close_reference_handle(engine, handle)
}
fn transition(engine: &mut Unicorn<Trace>, action: Action) -> Result<Dispatch> {
    ensure!(
        !crate::ipi::active(engine),
        "Ordinary scheduler transition during an IPI member is unsupported"
    );
    crate::api::kernel_spin::require_ready(engine)?;
    if matches!(action, Action::Exit(_) | Action::RootReturn(_)) {
        crate::api::kernel_spin::require_exit(engine)?;
    }
    waits::validate_all(engine)?;
    let architecture = engine.get_data().architecture;
    let thread_address = thread_address(engine);
    let mut threads = engine
        .get_data_mut()
        .threads
        .take()
        .context("Thread transition without scheduler")?;
    let result = (|| -> Result<Dispatch> {
        let id = threads.current_slot;
        let (irql, critical) = engine.get_data().apis.kernel.save();
        if !matches!(action, Action::Pump) {
            threads.saved.insert(
                id,
                SavedApi {
                    irql,
                    critical,
                    last_error: engine.get_data().apis.last_error,
                },
            );
        }
        match action {
            Action::Pump => {}
            Action::Yield => {
                if let Some(context) = threads.contexts.get_mut(&id) {
                    uc(engine.context_save(context))?;
                } else {
                    threads.contexts.insert(id, uc(engine.context_init())?);
                }
                threads.model.yield_current()?;
            }
            Action::Wait { thread } => {
                ensure!(
                    thread == id && threads.model.current().is_none(),
                    "Wait continuation has inconsistent scheduler state"
                );
                if let Some(context) = threads.contexts.get_mut(&id) {
                    uc(engine.context_save(context))?;
                } else {
                    threads.contexts.insert(id, uc(engine.context_init())?);
                }
            }
            Action::Exit(_) | Action::RootReturn(_) => {
                let status = match action {
                    Action::Exit(status) => status,
                    Action::RootReturn(status) => status as u32,
                    _ => unreachable!(),
                };
                let width = engine.get_data().architecture.width();
                for address in engine.get_data().apis.kernel.owned_addresses() {
                    range(engine, address + width as u64, width as u64, P::READ)?;
                    let raw = uc(engine.mem_read_as_vec(address + width as u64, width))?;
                    let mut owner = [0u8; 8];
                    owner[..width].copy_from_slice(&raw);
                    ensure!(
                        u64::from_le_bytes(owner) != thread_address,
                        "System thread exited while owning a guarded mutex"
                    );
                }
                if let Action::RootReturn(value) = action {
                    ensure!(id == 1, "Child thread returned to root entry marker");
                    if let Some(old) = threads.root_return {
                        ensure!(old == value, "Root return changed after DPC drain");
                    } else {
                        threads.root_return = Some(value);
                    }
                }
                threads.model.terminate(status)?;
                events::mirror_model(engine, &mut threads)?;
                if id != 1 {
                    let handles = threads
                        .handles
                        .values()
                        .filter(|entry| entry.id == id)
                        .count() as u32;
                    crate::api::kernel_thread_objects::exited(engine, id, handles)?;
                }
                threads.active -= 1;
            }
        }
        if matches!(action, Action::Yield | Action::Wait { .. }) {
            threads
                .context_versions
                .insert(id, crate::kernel_cpu::msr_version(engine));
        }
        engine.get_data_mut().clock.flush_cycles()?;
        let now = engine.get_data().clock.qpc();
        timers::advance_model(engine, &mut threads, now)?;
        events::mirror_model(engine, &mut threads)?;
        let next = loop {
            // A queued callback interrupts the actual still-live processor
            // context before a saved ordinary thread context is selected.
            if threads.model.next_dpc()?.is_some() {
                break Dispatch::Dpc;
            }
            match threads.model.dispatch() {
                Dispatch::AdvanceTo(deadline) => {
                    let now = engine.get_data().clock.qpc();
                    engine.get_data_mut().clock.advance_100ns(
                        deadline
                            .checked_sub(now)
                            .context("Scheduler deadline moved backwards")?,
                    )?;
                    crate::time::sync(engine)?;
                    timers::advance_model(engine, &mut threads, deadline)?;
                    events::mirror_model(engine, &mut threads)?;
                }
                next => break next,
            }
        };
        if engine.get_data().cpu.debug_control.active() {
            ensure!(
                matches!(action, Action::Yield) && next == Dispatch::Run(id),
                "DEBUGCTL active scheduler ownership transition requires architectural tracing support"
            );
        }
        if let Dispatch::Run(next_id) = next {
            threads.current_slot = next_id;
            uc(engine.context_restore(
                threads
                    .contexts
                    .get(&next_id)
                    .context("Missing saved thread context")?,
            ))?;
            crate::kernel_cpu::restore_msrs(
                engine,
                threads.context_versions.get(&next_id).copied().unwrap_or(0),
            )?;
            threads
                .context_versions
                .insert(next_id, crate::kernel_cpu::msr_version(engine));
            let saved = threads.saved.get(&next_id).copied().unwrap_or_default();
            engine
                .get_data_mut()
                .apis
                .kernel
                .restore((saved.irql, saved.critical));
            engine.get_data_mut().apis.last_error = saved.last_error;
            crate::kernel_cpu::sync(engine, address_for(architecture, next_id))?;
            threads.switches += 1;
            threads.quantum_end = engine.get_data().instructions + QUANTUM;
        }
        Ok(next)
    })();
    engine.get_data_mut().threads = Some(threads);
    result
}
pub(crate) struct Outcome {
    pub returned: bool,
    pub value: Option<u64>,
    pub error: Option<String>,
}
pub(crate) struct ExecutionHorizon {
    start: Instant,
    timeout_us: u64,
    budget: u64,
}
impl ExecutionHorizon {
    fn expired(&self, instructions: u64) -> bool {
        instructions >= self.budget || self.start.elapsed().as_micros() >= self.timeout_us as u128
    }
    pub(crate) fn new(timeout_us: u64, budget: u64) -> Self {
        Self {
            start: Instant::now(),
            timeout_us,
            budget,
        }
    }
}
pub(crate) fn execute_horizon(
    engine: &mut Unicorn<Trace>,
    entry: u64,
    stop_marker: u64,
    horizon: &ExecutionHorizon,
) -> Result<Outcome> {
    let arch = engine.get_data().architecture;
    uc(engine.reg_write(pc_register(arch), entry))?;
    loop {
        let count = engine.get_data().instructions;
        let budget = horizon.budget;
        let elapsed = horizon.start.elapsed().as_micros();
        if count >= budget || elapsed >= horizon.timeout_us as u128 {
            return Ok(Outcome {
                returned: false,
                value: None,
                error: None,
            });
        }
        let pc = uc(engine.pc_read())?;
        // A timed Unicorn start creates/joins a host watchdog thread each time.
        // Bound every start by4096 instructions instead, so outer wall/budget
        // checks also cover single-thread and virtual-timeout continuations.
        let slice = (budget - count).min(4096) as usize;
        let result = engine.emu_start(pc, stop_marker, 0, slice);
        if let Err(error) = result {
            return Ok(Outcome {
                returned: false,
                value: None,
                error: Some(format!("{error:?}")),
            });
        }
        if !engine.get_data().clock_error
            && engine.get_data().apis.fault.is_none()
            && engine.get_data().cpu.fault.is_none()
            && crate::kernel_cpu::has_pending_msr(engine)
        {
            if let Err(error) = crate::kernel_cpu::complete_msr_write(engine) {
                return Ok(Outcome {
                    returned: false,
                    value: None,
                    error: Some(format!("{error:#}")),
                });
            }
        }
        if engine.get_data().clock_error
            || engine.get_data().apis.fault.is_some()
            || engine.get_data().cpu.fault.is_some()
        {
            return Ok(Outcome {
                returned: false,
                value: None,
                error: None,
            });
        }
        if crate::native_exceptions::queued(engine) {
            match crate::native_exceptions::transition(engine, horizon) {
                Ok(Some(outcome)) => return Ok(outcome),
                Ok(None) => continue,
                Err(error) => return Ok(Outcome {
                    returned: false, value: None, error: Some(format!("{error:#}")),
                }),
            }
        }
        let mut deferred = None;
        if dpc::wake_pending(engine) {
            if dpc::active(engine) {
                match dpc::finish(engine) {
                    Ok(continuation) => match continuation {
                        dpc::Continuation::Instruction => continue,
                        dpc::Continuation::Action(action) => deferred = Some(action),
                        dpc::Continuation::SchedulerPump => deferred = Some(Action::Pump),
                    },
                    Err(error) => {
                        return Ok(Outcome {
                            returned: false,
                            value: None,
                            error: Some(format!("{error:#}")),
                        });
                    }
                }
            } else {
                if horizon.expired(engine.get_data().instructions) {
                    return Ok(Outcome {
                        returned: false,
                        value: None,
                        error: None,
                    });
                }
                match dpc::offer(engine, dpc::Continuation::Instruction) {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(error) => {
                        return Ok(Outcome {
                            returned: false,
                            value: None,
                            error: Some(format!("{error:#}")),
                        });
                    }
                }
            }
        }
        let pc = uc(engine.pc_read())?;
        if crate::api::dynamic_loader::queued(engine) {
            match crate::api::dynamic_loader::transition(engine, horizon) {
                Ok(Some(outcome)) => return Ok(outcome),
                Ok(None) => continue,
                Err(error) => {
                    return Ok(Outcome {
                        returned: false,
                        value: None,
                        error: Some(format!("{error:#}")),
                    });
                }
            }
        }
        if let Some(action) = engine.get_data_mut().ipi_action.take() {
            if let Err(error) = crate::ipi::transition(engine, action) {
                return Ok(Outcome {
                    returned: false,
                    value: None,
                    error: Some(format!("{error:#}")),
                });
            }
            continue;
        }
        if (crate::ipi::active(engine) || dpc::active(engine))
            && pc == engine.get_data().return_marker
        {
            return Ok(Outcome {
                returned: false,
                value: None,
                error: Some("IPI callback escaped into DriverEntry return marker".into()),
            });
        }
        if pc == stop_marker && stop_marker != engine.get_data().return_marker {
            return Ok(Outcome {
                returned: true,
                value: Some(ax(engine)?),
                error: None,
            });
        }
        let action = deferred.or_else(|| engine.get_data_mut().thread_action.take());
        let action = if pc == engine.get_data().return_marker {
            if let Err(error) = crate::api::kernel_spin::require_exit(engine) {
                return Ok(Outcome {
                    returned: false,
                    value: None,
                    error: Some(format!("{error:#}")),
                });
            }
            if engine.get_data().threads.is_none() {
                return Ok(Outcome {
                    returned: true,
                    value: Some(ax(engine)?),
                    error: None,
                });
            }
            let value = ax(engine)?;
            if let Err(error) = dpc::observe_root(engine, value) {
                return Ok(Outcome {
                    returned: false,
                    value: None,
                    error: Some(format!("{error:#}")),
                });
            }
            Some(Action::RootReturn(value))
        } else {
            action
        };
        let continuation = action
            .map(dpc::Continuation::Action)
            .unwrap_or(dpc::Continuation::Instruction);
        if !dpc::active(engine) {
            if let Err(error) = timers::refresh(engine) {
                return Ok(Outcome {
                    returned: false,
                    value: None,
                    error: Some(format!("{error:#}")),
                });
            }
            if horizon.expired(engine.get_data().instructions) && dpc::queued(engine) {
                return Ok(Outcome {
                    returned: false,
                    value: None,
                    error: None,
                });
            }
            if engine.get_data().cpu.debug_control.active() && dpc::queued(engine) {
                return Ok(Outcome {
                    returned: false,
                    value: None,
                    error: Some("DEBUGCTL active DPC transition requires architectural tracing support".into()),
                });
            }
            match dpc::offer(engine, continuation) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(error) => {
                    return Ok(Outcome {
                        returned: false,
                        value: None,
                        error: Some(format!("{error:#}")),
                    });
                }
            }
        }
        let Some(action) = action else {
            if engine.get_data().instructions - count == slice as u64 || dpc::wake_pending(engine) {
                continue;
            }
            return Ok(Outcome {
                returned: false,
                value: None,
                error: Some(
                    "Guest CPU halted or stopped before its instruction slice completed".into(),
                ),
            });
        };
        match transition(engine, action) {
            Ok(Dispatch::Dpc) => {
                if horizon.expired(engine.get_data().instructions) {
                    return Ok(Outcome {
                        returned: false,
                        value: None,
                        error: None,
                    });
                }
                match dpc::offer(engine, dpc::Continuation::SchedulerPump) {
                    Ok(true) => continue,
                    Ok(false) => return Ok(Outcome {
                        returned: false,
                        value: None,
                        error: Some(
                            "Queued DPC cannot dispatch from actual interrupted processor state"
                                .into(),
                        ),
                    }),
                    Err(error) => {
                        return Ok(Outcome {
                            returned: false,
                            value: None,
                            error: Some(format!("{error:#}")),
                        });
                    }
                }
            }
            Ok(Dispatch::Run(_)) => {}
            Ok(Dispatch::Finished) => {
                let value = engine.get_data().threads.as_ref().unwrap().root_return;
                return Ok(Outcome {
                    returned: value.is_some(),
                    value,
                    error: if value.is_none() {
                        Some("System-thread root exited before DriverEntry returned".into())
                    } else {
                        None
                    },
                });
            }
            Ok(Dispatch::Deadlocked(waiting)) => {
                return Ok(Outcome {
                    returned: false,
                    value: None,
                    error: Some(format!("Kernel thread deadlock: {waiting:?}")),
                });
            }
            Ok(other) => {
                return Ok(Outcome {
                    returned: false,
                    value: None,
                    error: Some(format!("Pending thread wait integration: {other:?}")),
                });
            }
            Err(error) => {
                return Ok(Outcome {
                    returned: false,
                    value: None,
                    error: Some(format!("{error:#}")),
                });
            }
        }
    }
}

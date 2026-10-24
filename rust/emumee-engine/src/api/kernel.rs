//! Initial current-thread kernel synchronization. Blocking waits are explicit.
use super::*;
use anyhow::Context;
use std::collections::BTreeSet;
use unicorn_engine::unicorn_const::HookType;

const GUARDED_WATCH_LIMIT: usize = 64;
const GUARDED_TRACE_LIMIT: usize = 256;

/// Bounded observation only. A guest-write hook records the pending write,
/// while API rows contain the bytes actually read at the API boundary.
#[derive(Clone, Debug, Serialize)]
pub struct GuardedMutexObservation {
    pub operation: &'static str,
    pub mutex: u64,
    pub instruction: u64,
    pub pc: Option<u64>,
    pub thread: u64,
    pub irql: u8,
    pub guest_count: Option<i32>,
    pub guest_owner: Option<u64>,
    pub modeled_owned: bool,
    pub initialized_since_watch: bool,
    pub write_address: Option<u64>,
    pub write_size: Option<usize>,
    pub write_value_low64: Option<u64>,
}
#[derive(Default)]
pub(crate) struct KernelState {
    irql: u8,
    critical_depth: u16,
    owned: BTreeMap<u64, u8>,
    pub(super) spin: emumee_core::kernel_spin::State,
    pub(super) spin_native_write: Option<(u64, u64)>,
    pub(super) spin_guard_installed: bool,
    pub(super) spin_guest_denials: u64,
    scalar_sync: Vec<super::kernel_sync::Observation>,
    scalar_sync_omitted: u64,
    guarded_watched: BTreeSet<u64>,
    guarded_initialized: BTreeSet<u64>,
    guarded_trace: Vec<GuardedMutexObservation>,
    guarded_trace_omitted: u64,
    guarded_watch_omitted: u64,
    guarded_watch_failures: u64,
}
#[derive(Debug, Serialize)]
pub struct KernelReport {
    pub irql: u8,
    pub critical_depth: u16,
    pub owned_mutexes: usize,
    pub spin: emumee_core::kernel_spin::State,
    pub spin_guard_installed: bool,
    pub spin_guest_denials: u64,
    pub scalar_sync: Vec<super::kernel_sync::Observation>,
    pub scalar_sync_omitted: u64,
    pub guarded_mutex_trace: Vec<GuardedMutexObservation>,
    pub guarded_mutex_trace_omitted: u64,
    pub guarded_mutex_watch_omitted: u64,
    pub guarded_mutex_watch_failures: u64,
    pub guarded_mutex_trace_scope: &'static str,
    pub guarded_mutex_count_protocol: &'static str,
    pub guarded_mutex_count_scope: &'static str,
    pub scope: &'static str,
}
impl KernelState {
    fn record_guarded(&mut self, row: GuardedMutexObservation) {
        if self.guarded_trace.len() < GUARDED_TRACE_LIMIT {
            self.guarded_trace.push(row);
        } else {
            self.guarded_trace_omitted = self.guarded_trace_omitted.saturating_add(1);
        }
    }
    pub(super) fn record_scalar(&mut self, row: super::kernel_sync::Observation) {
        if self.scalar_sync.len() < 64 {
            self.scalar_sync.push(row);
        } else {
            self.scalar_sync_omitted = self.scalar_sync_omitted.saturating_add(1);
        }
    }
    pub(crate) fn save(&self) -> (u8, u16) {
        (self.irql, self.critical_depth)
    }
    pub(crate) fn restore(&mut self, state: (u8, u16)) {
        self.irql = state.0;
        self.critical_depth = state.1;
    }
    pub(crate) fn owned_addresses(&self) -> impl Iterator<Item = u64> {
        self.owned.keys().copied()
    }
    pub fn report(&self, protocol: crate::threads::GuardedMutexCountProtocol) -> KernelReport {
        KernelReport {
            irql: self.irql,
            critical_depth: self.critical_depth,
            owned_mutexes: self.owned.len(),
            spin: self.spin.clone(),
            spin_guard_installed: self.spin_guard_installed,
            spin_guest_denials: self.spin_guest_denials,
            scalar_sync: self.scalar_sync.clone(),
            scalar_sync_omitted: self.scalar_sync_omitted,
            guarded_mutex_trace: self.guarded_trace.clone(),
            guarded_mutex_trace_omitted: self.guarded_trace_omitted,
            guarded_mutex_watch_omitted: self.guarded_watch_omitted,
            guarded_mutex_watch_failures: self.guarded_watch_failures,
            guarded_mutex_trace_scope: "Only guarded-mutex addresses first seen at modeled APIs are watched. Up to 64 address-specific guest-write hooks and 256 total observations; counters expose omitted watch attempts, failed hook installs and omitted rows. Guest-write rows carry the pending low 64 bits, not a post-write memory snapshot. Host model writes do not fire guest hooks. Earlier writes, unobserved addresses and complete mutation history are not claimed; this trace never changes lock decisions.",
            guarded_mutex_count_protocol: protocol.label(),
            guarded_mutex_count_scope: "Stable modeled API boundaries only: x64 build26200 uses count4 per blocked waiter with bit0 clear while owned, based on the pinned kernel fast-mutex implementation; other targets retain the legacy signed-waiter model. Release directly hands ownership to a modeled waiter. Native atomic races, transient handoff/barging bits, instrumentation callbacks and uninitialized/ownerless contended objects remain unsupported; no lock is granted without ownership evidence.",
            scope: "Current-thread actual IRQL, genuine bounded initialized spin words/processor+thread ownership and guarded mutex state, including available modeled system-thread waits. Pointer-word rundown and uncontended push-lock legacy effects are reported separately; no push-lock owner tracking, contended rundown/push continuation, full kernel layouts or APC delivery is claimed. Spin profile synthetic-guest-spin-v1 uses opaque modeled word0/1, CPU0 ownership, resident guest-image or nonpaged-Pool backing and explicit busy/inline/alias refusal; it is not a Windows private-layout or contended-spin implementation.",
        }
    }
}
fn record_guarded(
    engine: &mut Unicorn<Trace>,
    operation: &'static str,
    mutex: u64,
    guest: Option<(i32, Option<u64>)>,
    write: Option<(u64, usize, u64)>,
) {
    if engine.get_data().apis.kernel.guarded_trace.len() >= GUARDED_TRACE_LIMIT {
        let state = &mut engine.get_data_mut().apis.kernel;
        state.guarded_trace_omitted = state.guarded_trace_omitted.saturating_add(1);
        return;
    }
    let state = engine.get_data();
    let row = GuardedMutexObservation {
        operation,
        mutex,
        instruction: state.instructions,
        pc: engine.pc_read().ok(),
        thread: crate::threads::thread_address(engine),
        irql: state.apis.kernel.irql,
        guest_count: guest.map(|(count, _)| count),
        guest_owner: guest.and_then(|(_, owner)| owner),
        modeled_owned: state.apis.kernel.owned.contains_key(&mutex),
        initialized_since_watch: state.apis.kernel.guarded_initialized.contains(&mutex),
        write_address: write.map(|(address, _, _)| address),
        write_size: write.map(|(_, size, _)| size),
        write_value_low64: write.map(|(_, _, value)| value),
    };
    engine.get_data_mut().apis.kernel.record_guarded(row);
}
fn watch_guarded(engine: &mut Unicorn<Trace>, address: u64, size: usize) {
    if engine
        .get_data()
        .apis
        .kernel
        .guarded_watched
        .contains(&address)
    {
        return;
    }
    if engine.get_data().apis.kernel.guarded_trace.len() >= GUARDED_TRACE_LIMIT {
        let state = &mut engine.get_data_mut().apis.kernel;
        state.guarded_watch_omitted = state.guarded_watch_omitted.saturating_add(1);
        return;
    }
    if engine.get_data().apis.kernel.guarded_watched.len() >= GUARDED_WATCH_LIMIT {
        let state = &mut engine.get_data_mut().apis.kernel;
        state.guarded_watch_omitted = state.guarded_watch_omitted.saturating_add(1);
        return;
    }
    let Some(last) = (size as u64)
        .checked_sub(1)
        .and_then(|span| address.checked_add(span))
    else {
        let state = &mut engine.get_data_mut().apis.kernel;
        state.guarded_watch_failures = state.guarded_watch_failures.saturating_add(1);
        return;
    };
    if engine
        .add_mem_hook(
            HookType::MEM_WRITE,
            address,
            last,
            move |engine, _, write_at, size, value| {
                record_guarded(
                    engine,
                    "guest_write_pending",
                    address,
                    None,
                    Some((write_at, size, value as u64)),
                );
                true
            },
        )
        .is_ok()
    {
        engine
            .get_data_mut()
            .apis
            .kernel
            .guarded_watched
            .insert(address);
    } else {
        let state = &mut engine.get_data_mut().apis.kernel;
        state.guarded_watch_failures = state.guarded_watch_failures.saturating_add(1);
    }
}
fn layout(engine: &Unicorn<Trace>, address: u64) -> Result<(usize, usize, usize, usize)> {
    let width = engine.get_data().architecture.width();
    let (event, old, size) = if width == 8 {
        (24, 48, 56)
    } else {
        (12, 28, 32)
    };
    require(engine, address, size as u64, P::RW)?;
    Ok((width, event, old, size))
}
fn integer(engine: &Unicorn<Trace>, address: u64, width: usize) -> Result<u64> {
    let raw = read(engine, address, width as u64)?;
    let mut data = [0u8; 8];
    data[..width].copy_from_slice(&raw);
    Ok(u64::from_le_bytes(data))
}
fn write_integer(
    engine: &mut Unicorn<Trace>,
    address: u64,
    width: usize,
    value: u64,
) -> Result<()> {
    crate::cpu::write(engine, address, &value.to_le_bytes()[..width])
}
pub(super) fn call(engine: &mut Unicorn<Trace>, model: Model, args: &[u64]) -> Result<u64> {
    ensure!(
        engine.get_data().apis.kernel_mode,
        "Kernel synchronization requires a native driver target"
    );
    let irql = super::kernel_sync::observe_irql(engine)?;
    match model {
        Model::Irql => return Ok(irql as u64),
        Model::EnterCritical => {
            ensure!(irql <= 1, "Critical region entry above APC_LEVEL");
            let depth = engine
                .get_data()
                .apis
                .kernel
                .critical_depth
                .checked_add(1)
                .context("Critical region depth overflow")?;
            engine.get_data_mut().apis.kernel.critical_depth = depth;
            return Ok(0);
        }
        Model::LeaveCritical => {
            ensure!(irql <= 1, "Critical region exit above APC_LEVEL");
            let depth = engine
                .get_data()
                .apis
                .kernel
                .critical_depth
                .checked_sub(1)
                .context("Critical region depth underflow")?;
            engine.get_data_mut().apis.kernel.critical_depth = depth;
            return Ok(0);
        }
        Model::RaiseIrql => {
            let new = args[0] as u8;
            let maximum = if engine.get_data().architecture == Architecture::X64 {
                15
            } else {
                31
            };
            ensure!(new >= irql && new <= maximum, "Invalid IRQL raise");
            require(engine, args[1], 1, P::WRITE)?;
            crate::cpu::write(engine, args[1], &[irql])?;
            engine.get_data_mut().apis.kernel.irql = new;
            return Ok(0);
        }
        Model::LowerIrql => {
            let new = args[0] as u8;
            super::kernel_spin::require_lower(engine, new)?;
            ensure!(new <= irql, "Invalid IRQL lower");
            engine.get_data_mut().apis.kernel.irql = new;
            return Ok(0);
        }
        _ => {}
    }
    let address = args[0];
    let thread = crate::threads::thread_address(engine);
    let (width, event, old, size) = layout(engine, address)?;
    watch_guarded(engine, address, size);
    match model {
        Model::InitGuardedMutex => {
            record_guarded(engine, "initialize_attempt", address, None, None);
            ensure!(
                !engine.get_data().apis.kernel.owned.contains_key(&address),
                "Reinitializing an owned guarded mutex"
            );
            crate::threads::initialize_mutex(engine, address)?;
            let mut data = vec![0u8; size];
            data[..4].copy_from_slice(&1u32.to_le_bytes());
            data[event] = 1;
            data[event + 2] = if width == 8 { 6 } else { 4 };
            let head = address + event as u64 + 8;
            for offset in [event + 8, event + 8 + width] {
                data[offset..offset + width].copy_from_slice(&head.to_le_bytes()[..width]);
            }
            crate::cpu::write(engine, address, &data)?;
            if engine
                .get_data()
                .apis
                .kernel
                .guarded_watched
                .contains(&address)
            {
                engine
                    .get_data_mut()
                    .apis
                    .kernel
                    .guarded_initialized
                    .insert(address);
            }
            record_guarded(engine, "initialized", address, Some((1, Some(0))), None);
        }
        Model::AcquireGuardedMutex => {
            let protocol = crate::threads::guarded_mutex_count_protocol(engine);
            ensure!(irql <= 1, "Guarded mutex acquisition above APC_LEVEL");
            let count = integer(engine, address, 4)? as u32 as i32;
            let owner = integer(engine, address + width as u64, width)?;
            record_guarded(
                engine,
                "acquire_attempt",
                address,
                Some((count, Some(owner))),
                None,
            );
            if !crate::threads::acquire_mutex(engine, address, count, owner, irql)? {
                let blocked_count = protocol.blocked_count(count)?;
                write_integer(engine, address, 4, blocked_count as u32 as u64)?;
                if matches!(protocol, crate::threads::GuardedMutexCountProtocol::Windows26200X64) {
                    let contention = integer(engine, address + 0x10, 4)? as u32;
                    write_integer(engine, address + 0x10, 4, contention.wrapping_add(1) as u64)?;
                }
                engine.get_data_mut().apis.kernel.irql = 1;
                record_guarded(
                    engine,
                    "blocked",
                    address,
                    Some((blocked_count, Some(owner))),
                    None,
                );
                return Ok(0);
            }
            ensure!(
                engine.get_data().apis.kernel.owned.len() < 4096,
                "Guarded mutex ownership bound"
            );
            ensure!(
                !engine.get_data().apis.kernel.owned.contains_key(&address),
                "Recursive guarded mutex acquisition"
            );
            write_integer(engine, address, 4, 0)?;
            write_integer(engine, address + width as u64, width, thread)?;
            write_integer(engine, address + old as u64, 4, irql as u64)?;
            engine
                .get_data_mut()
                .apis
                .kernel
                .owned
                .insert(address, irql);
            engine.get_data_mut().apis.kernel.irql = 1;
            record_guarded(engine, "acquired", address, Some((0, Some(thread))), None);
        }
        Model::ReleaseGuardedMutex => {
            let protocol = crate::threads::guarded_mutex_count_protocol(engine);
            let count = integer(engine, address, 4)? as u32 as i32;
            let owner = protocol.owned_count(count)
                .then(|| integer(engine, address + width as u64, width).ok())
                .flatten();
            record_guarded(
                engine,
                "release_attempt",
                address,
                Some((count, owner)),
                None,
            );
            ensure!(
                protocol.owned_count(count) && integer(engine, address + width as u64, width)? == thread,
                "Current thread does not own guarded mutex"
            );
            let previous = integer(engine, address + old as u64, 4)?;
            ensure!(
                previous <= 1
                    && irql == 1
                    && engine.get_data().apis.kernel.owned.get(&address) == Some(&(previous as u8)),
                "Guarded mutex saved/current IRQL is invalid"
            );
            let handoff = crate::threads::release_mutex(engine, address, count)?;
            write_integer(
                engine,
                address + width as u64,
                width,
                handoff.as_ref().map_or(0, |h| h.owner),
            )?;
            write_integer(
                engine,
                address,
                4,
                handoff.as_ref().map_or(1, |h| h.count as u32 as u64),
            )?;
            engine.get_data_mut().apis.kernel.owned.remove(&address);
            if let Some(handoff) = handoff {
                write_integer(engine, address + old as u64, 4, handoff.old_irql as u64)?;
                engine
                    .get_data_mut()
                    .apis
                    .kernel
                    .owned
                    .insert(address, handoff.old_irql);
            }
            engine.get_data_mut().apis.kernel.irql = previous as u8;
            if let (Ok(count), Ok(owner)) = (
                integer(engine, address, 4),
                integer(engine, address + width as u64, width),
            ) {
                record_guarded(
                    engine,
                    "released",
                    address,
                    Some((count as u32 as i32, Some(owner))),
                    None,
                );
            }
        }
        _ => bail!("Kernel API dispatch mismatch"),
    }
    Ok(0)
}

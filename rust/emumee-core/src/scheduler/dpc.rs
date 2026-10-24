//! One CPU0 queue indexing the Scheduler's existing initialized DPC records.
//! Native adapters alone may confirm actual guest return and caller restoration.
use super::*;
pub const DPC_WORK_LIMIT: u64 = 65_536;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum DpcPolicy {
    Unselected,
    LegacyMetadataOnly,
    Cpu0Dispatch { timer_arguments: [u64; 2] },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum DpcOrigin {
    Caller,
    Timer {
        address: u64,
        arm: u64,
        initialization: u64,
        deadline: u64,
        observed: u64,
        periodic: bool,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DpcWork {
    pub sequence: u64,
    pub arguments: [u64; 2],
    pub origin: DpcOrigin,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum DpcPhase {
    Idle,
    Queued(DpcWork),
    Running(DpcWork),
    Returning(DpcWork),
}
impl DpcPhase {
    pub fn work(&self) -> Option<&DpcWork> {
        match self {
            Self::Idle => None,
            Self::Queued(w) | Self::Running(w) | Self::Returning(w) => Some(w),
        }
    }
    pub fn busy(&self) -> bool {
        !matches!(self, Self::Idle)
    }
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct DpcCounters {
    pub accepted: u64,
    pub duplicates: u64,
    pub removed: u64,
    pub started: u64,
    pub returned: u64,
    pub restored: u64,
}
fn increment(value: &mut u64) -> Result<()> {
    *value = value
        .checked_add(1)
        .ok_or(SchedulerError("DPC observation counter overflow"))?;
    Ok(())
}
impl Scheduler {
    /// Policy is installed once before any dispatcher/DPC publication. The
    /// engine attests actual owned NOACCESS timer argument storage before InitDpc.
    pub fn configure_dpc_dispatch(&mut self, timer_arguments: [u64; 2]) -> Result<()> {
        if !matches!(self.dpc_policy, DpcPolicy::Unselected)
            || self.threads.len() != 1
            || self.current != Some(1)
            || self.sequence != 0
            || self.now != 0
            || !self.events.is_empty()
            || !self.mutexes.is_empty()
            || !self.timers.is_empty()
            || !self.dpcs.is_empty()
            || self.dpc_counters.accepted != 0
        {
            return Err(SchedulerError(
                "DPC policy changes after dispatcher publication",
            ));
        }
        if timer_arguments.contains(&0) || timer_arguments[0] == timer_arguments[1] {
            return Err(SchedulerError(
                "DPC timer opaque argument policy is invalid",
            ));
        }
        self.dpc_policy = DpcPolicy::Cpu0Dispatch { timer_arguments };
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn select_legacy_reference_policy(&mut self) -> Result<()> {
        if !matches!(self.dpc_policy, DpcPolicy::Unselected)
            || self.threads.len() != 1
            || self.current != Some(1)
            || self.sequence != 0
            || self.now != 0
            || !self.events.is_empty()
            || !self.mutexes.is_empty()
            || !self.timers.is_empty()
            || !self.dpcs.is_empty()
        {
            return Err(SchedulerError(
                "legacy reference policy after object publication",
            ));
        }
        self.dpc_policy = DpcPolicy::LegacyMetadataOnly;
        Ok(())
    }
    pub fn dpc_policy(&self) -> DpcPolicy {
        self.dpc_policy
    }
    pub fn dpc_counters(&self) -> &DpcCounters {
        &self.dpc_counters
    }
    pub fn queued_dpcs(&self) -> impl Iterator<Item = u64> + '_ {
        self.dpc_queue.iter().copied()
    }
    pub fn active_dpc(&self) -> Option<&Dpc> {
        self.dpcs()
            .find(|d| matches!(d.phase, DpcPhase::Running(_) | DpcPhase::Returning(_)))
    }
    fn insert_dpc_work(
        &mut self,
        address: u64,
        arguments: [u64; 2],
        origin: DpcOrigin,
    ) -> Result<bool> {
        if !matches!(self.dpc_policy, DpcPolicy::Cpu0Dispatch { .. }) {
            return Err(SchedulerError("DPC execution policy is metadata-only"));
        }
        let dpc = self.dpc(address)?;
        match &dpc.phase {
            DpcPhase::Queued(old) => {
                if old.origin != origin {
                    return Err(SchedulerError(
                        "DPC queued work has ambiguous timer/caller origin",
                    ));
                }
                increment(&mut self.dpc_counters.duplicates)?;
                return Ok(false);
            }
            DpcPhase::Running(_) | DpcPhase::Returning(_) => {
                return Err(SchedulerError(
                    "requeue of running DPC requires a separate execution profile",
                ));
            }
            DpcPhase::Idle => {}
        }
        if self.dpc_counters.accepted >= DPC_WORK_LIMIT || self.dpc_queue.len() >= 4096 {
            return Err(SchedulerError("DPC accepted work/lifetime bound"));
        }
        let sequence = self
            .dpc_counters
            .accepted
            .checked_add(1)
            .ok_or(SchedulerError("DPC work sequence overflow"))?;
        self.dpcs.get_mut(&address).unwrap().phase = DpcPhase::Queued(DpcWork {
            sequence,
            arguments,
            origin,
        });
        self.dpc_queue.push_back(address);
        self.dpc_counters.accepted = sequence;
        Ok(true)
    }
    pub fn insert_queue_dpc(&mut self, address: u64, arguments: [u64; 2]) -> Result<bool> {
        if self.timers().any(|t| t.inserted && t.dpc == address) {
            return Err(SchedulerError("direct insert shares an active timer DPC"));
        }
        self.insert_dpc_work(address, arguments, DpcOrigin::Caller)
    }
    pub fn remove_queue_dpc(&mut self, address: u64) -> Result<bool> {
        if !matches!(self.dpc(address)?.phase, DpcPhase::Queued(_)) {
            return Ok(false);
        }
        let position = self
            .dpc_queue
            .iter()
            .position(|p| *p == address)
            .ok_or(SchedulerError("queued DPC lost its sole ordering index"))?;
        let removed = self
            .dpc_counters
            .removed
            .checked_add(1)
            .ok_or(SchedulerError("DPC remove counter overflow"))?;
        self.dpc_queue.remove(position);
        self.dpcs.get_mut(&address).unwrap().phase = DpcPhase::Idle;
        self.dpc_counters.removed = removed;
        Ok(true)
    }
    pub fn next_dpc(&self) -> Result<Option<&Dpc>> {
        if self.active_dpc().is_some() {
            return Ok(None);
        }
        let Some(address) = self.dpc_queue.front() else {
            return Ok(None);
        };
        let dpc = self.dpc(*address)?;
        if !matches!(dpc.phase, DpcPhase::Queued(_)) {
            return Err(SchedulerError(
                "DPC queue phase diverges from ordering index",
            ));
        }
        Ok(Some(dpc))
    }
    pub fn start_dpc(&mut self, address: u64) -> Result<DpcWork> {
        if self.next_dpc()?.map(|d| d.address) != Some(address) {
            return Err(SchedulerError(
                "DPC start does not name the actual FIFO head",
            ));
        }
        let work = match &self.dpc(address)?.phase {
            DpcPhase::Queued(work) => work.clone(),
            _ => return Err(SchedulerError("DPC start lacks queued work")),
        };
        let started = self
            .dpc_counters
            .started
            .checked_add(1)
            .ok_or(SchedulerError("DPC start counter overflow"))?;
        self.dpc_queue.pop_front();
        self.dpcs.get_mut(&address).unwrap().phase = DpcPhase::Running(work.clone());
        self.dpc_counters.started = started;
        Ok(work)
    }
    pub fn returned_dpc(&mut self, address: u64, sequence: u64) -> Result<()> {
        let work = match &self.dpc(address)?.phase {
            DpcPhase::Running(work) if work.sequence == sequence => work.clone(),
            _ => {
                return Err(SchedulerError(
                    "DPC return lacks actual matching running work",
                ));
            }
        };
        let returned = self
            .dpc_counters
            .returned
            .checked_add(1)
            .ok_or(SchedulerError("DPC return counter overflow"))?;
        self.dpcs.get_mut(&address).unwrap().phase = DpcPhase::Returning(work);
        self.dpc_counters.returned = returned;
        Ok(())
    }
    pub fn restored_dpc(&mut self, address: u64, sequence: u64) -> Result<()> {
        if !matches!(&self.dpc(address)?.phase,DpcPhase::Returning(w)if w.sequence==sequence) {
            return Err(SchedulerError(
                "DPC restore lacks actual matching returned work",
            ));
        }
        let restored = self
            .dpc_counters
            .restored
            .checked_add(1)
            .ok_or(SchedulerError("DPC restore counter overflow"))?;
        self.dpcs.get_mut(&address).unwrap().phase = DpcPhase::Idle;
        self.dpc_counters.restored = restored;
        Ok(())
    }
    pub(super) fn queue_timer_expiration(&mut self, address: u64, observed: u64) -> Result<bool> {
        let timer = self.timer(address)?.clone();
        if timer.dpc == 0 {
            return Ok(false);
        }
        let arguments = match self.dpc_policy {
            DpcPolicy::Unselected => {
                return Err(SchedulerError("DPC dispatch policy was not installed"));
            }
            DpcPolicy::LegacyMetadataOnly => {
                return Err(SchedulerError("due timer DPC requires callback scheduling"));
            }
            DpcPolicy::Cpu0Dispatch { timer_arguments } => timer_arguments,
        };
        if self
            .timers()
            .any(|t| t.address != address && t.inserted && t.dpc == timer.dpc)
        {
            return Err(SchedulerError("multiple active timers share one DPC"));
        }
        let origin = DpcOrigin::Timer {
            address,
            arm: timer.arm_generation,
            initialization: timer.initialization,
            deadline: timer.due,
            observed,
            periodic: timer.period_ms != 0,
        };
        if let DpcPhase::Queued(old) = &self.dpc(timer.dpc)?.phase
            && matches!(&old.origin,DpcOrigin::Timer{address:a,arm,initialization,..}if *a==address&&*arm==timer.arm_generation&&*initialization==timer.initialization)
        {
            increment(&mut self.dpc_counters.duplicates)?;
            return Ok(false);
        }
        self.insert_dpc_work(timer.dpc, arguments, origin)
    }
    pub(super) fn cancel_associated_queued_dpc(&mut self, timer: &Timer) -> Result<()> {
        if timer.dpc == 0 {
            return Ok(());
        }
        let Some(work) = self.dpc(timer.dpc)?.phase.work() else {
            return Ok(());
        };
        if matches!(&work.origin,DpcOrigin::Timer{address,arm,initialization,..}if *address==timer.address&&*arm==timer.arm_generation&&*initialization==timer.initialization)
            && matches!(self.dpc(timer.dpc)?.phase, DpcPhase::Queued(_))
        {
            self.remove_queue_dpc(timer.dpc)?;
        }
        Ok(())
    }
    pub(super) fn require_timer_rearm_dpc(&self, address: u64, dpc: u64) -> Result<()> {
        if self
            .timers()
            .any(|t| t.address != address && t.inserted && t.dpc == dpc && dpc != 0)
        {
            return Err(SchedulerError("multiple active timers share one DPC"));
        }
        if dpc != 0 && self.dpc(dpc)?.phase.busy() {
            return Err(SchedulerError(
                "timer rearm overlaps queued/running DPC work",
            ));
        }
        if let Some(old) = self.timers.get(&address)
            && old.dpc != 0
            && self.dpcs.get(&old.dpc).is_some_and(|d| d.phase.busy())
        {
            return Err(SchedulerError(
                "timer replacement overlaps prior queued/running DPC work",
            ));
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::Architecture;
    fn model() -> Scheduler {
        let mut s = Scheduler::new(8).unwrap();
        s.configure_dpc_dispatch([0xffffc50000011010, 0xffffc50000012020])
            .unwrap();
        for address in [0x11000, 0x12000] {
            s.initialize_dpc(Dpc {
                address,
                architecture: Architecture::X64,
                backing: TimerBacking::Image {
                    base: 0x10000,
                    size: 0x10000,
                },
                routine: 0x10000,
                context: 0xffff112233445566,
                phase: DpcPhase::Idle,
            })
            .unwrap();
        }
        s
    }
    #[test]
    fn fifo_duplicate_keeps_first_arguments_and_real_running_return_restore_are_distinct() {
        let mut s = model();
        assert!(s.insert_queue_dpc(0x11000, [1, 2]).unwrap());
        assert!(s.insert_queue_dpc(0x12000, [3, 4]).unwrap());
        assert!(!s.insert_queue_dpc(0x11000, [9, 8]).unwrap());
        assert_eq!(s.queued_dpcs().collect::<Vec<_>>(), [0x11000, 0x12000]);
        let work = s.start_dpc(0x11000).unwrap();
        assert_eq!(work.arguments, [1, 2]);
        assert!(s.next_dpc().unwrap().is_none());
        assert!(!s.remove_queue_dpc(0x11000).unwrap());
        assert!(s.insert_queue_dpc(0x11000, [5, 6]).is_err());
        assert!(s.restored_dpc(0x11000, work.sequence).is_err());
        assert!(s.returned_dpc(0x11000, work.sequence + 1).is_err());
        s.returned_dpc(0x11000, work.sequence).unwrap();
        assert!(s.next_dpc().unwrap().is_none());
        s.restored_dpc(0x11000, work.sequence).unwrap();
        assert_eq!(s.next_dpc().unwrap().unwrap().address, 0x12000);
        assert_eq!(
            (
                s.dpc_counters.started,
                s.dpc_counters.returned,
                s.dpc_counters.restored
            ),
            (1, 1, 1)
        );
    }
    #[test]
    fn queued_removal_retirement_and_work_bound_fail_without_mutation() {
        let mut s = model();
        s.insert_queue_dpc(0x11000, [1, 2]).unwrap();
        assert!(s.retire_timer_backing(0x11000, 64).is_err());
        assert!(s.remove_queue_dpc(0x11000).unwrap());
        assert!(!s.remove_queue_dpc(0x11000).unwrap());
        s.retire_timer_backing(0x11000, 64).unwrap();
        assert!(s.dpc(0x11000).is_err());
        s.dpc_counters.accepted = DPC_WORK_LIMIT;
        assert!(s.insert_queue_dpc(0x12000, [8, 9]).is_err());
        assert_eq!(s.dpc(0x12000).unwrap().phase, DpcPhase::Idle);
        assert_eq!(s.queued_dpcs().count(), 0);
    }
    #[test]
    fn timer_expiration_origin_atomic_coalescence_and_cancel_match_real_pending_work() {
        let mut s = model();
        s.initialize_timer(
            0x13000,
            Architecture::X64,
            TimerBacking::Image {
                base: 0x10000,
                size: 0x10000,
            },
            true,
        )
        .unwrap();
        s.set_timer(0x13000, 10, false, 1, 0x11000).unwrap();
        s.advance_to(10).unwrap();
        let first = s.dpc(0x11000).unwrap().phase.work().unwrap().clone();
        assert_eq!(first.arguments, [0xffffc50000011010, 0xffffc50000012020]);
        assert!(matches!(
            first.origin,
            DpcOrigin::Timer {
                address: 0x13000,
                deadline: 10,
                observed: 10,
                periodic: true,
                ..
            }
        ));
        s.advance_to(100_010).unwrap();
        assert_eq!(s.dpc(0x11000).unwrap().phase.work(), Some(&first));
        assert_eq!(s.timer(0x13000).unwrap().due, 110_010);
        assert!(s.cancel_timer(0x13000).unwrap());
        assert_eq!(s.queued_dpcs().count(), 0);
        s.set_timer(0x13000, 100_020, false, 0, 0x11000).unwrap();
        s.advance_to(100_020).unwrap();
        assert!(!s.cancel_timer(0x13000).unwrap());
        assert_eq!(s.queued_dpcs().count(), 1);
    }
    #[test]
    fn ambiguous_origins_rearm_and_running_periodic_expiration_refuse_atomically() {
        let mut s = model();
        for a in [0x13000, 0x14000] {
            s.initialize_timer(
                a,
                Architecture::X64,
                TimerBacking::Image {
                    base: 0x10000,
                    size: 0x10000,
                },
                true,
            )
            .unwrap();
        }
        s.set_timer(0x13000, 10, false, 1, 0x11000).unwrap();
        assert!(s.insert_queue_dpc(0x11000, [1, 2]).is_err());
        assert!(s.set_timer(0x14000, 12, false, 0, 0x11000).is_err());
        assert!(!s.timer(0x14000).unwrap().inserted);
        s.advance_to(10).unwrap();
        let work = s.start_dpc(0x11000).unwrap();
        assert!(s.advance_to(10_010).is_err());
        assert_eq!(s.now, 10);
        assert_eq!(s.timer(0x13000).unwrap().due, 10_010);
        assert!(s.set_timer(0x13000, 50, false, 0, 0).is_err());
        s.returned_dpc(0x11000, work.sequence).unwrap();
        s.restored_dpc(0x11000, work.sequence).unwrap();
        s.advance_to(10_010).unwrap();
        assert_eq!(s.queued_dpcs().count(), 1);
    }
    #[test]
    fn all_due_timer_batch_preflights_work_quota_before_any_signal_or_clock() {
        let mut s = model();
        for (timer, dpc) in [(0x13000, 0x11000), (0x14000, 0x12000)] {
            s.initialize_timer(
                timer,
                Architecture::X64,
                TimerBacking::Image {
                    base: 0x10000,
                    size: 0x10000,
                },
                true,
            )
            .unwrap();
            s.set_timer(timer, 10, false, 0, dpc).unwrap();
        }
        s.dpc_counters.accepted = DPC_WORK_LIMIT - 1;
        assert!(s.advance_to(10).is_err());
        assert_eq!(s.now, 0);
        assert!(s.timers().all(|t| t.inserted && !t.signaled));
        assert_eq!(s.queued_dpcs().count(), 0);
        assert_eq!(s.dpc_counters.accepted, DPC_WORK_LIMIT - 1);
    }
    #[test]
    fn execution_policy_cannot_change_after_publication_or_be_selected_by_caller() {
        let mut s = Scheduler::new(8).unwrap();
        s.initialize_event(0x3000, true, false).unwrap();
        assert!(s.configure_dpc_dispatch([1, 2]).is_err());
        let mut s = model();
        assert!(s.configure_dpc_dispatch([3, 4]).is_err());
        assert!(!s.remove_queue_dpc(0x11000).unwrap());
    }
    #[test]
    fn inactive_retired_dpc_does_not_pin_timer_and_new_initialization_disambiguates_old_origin() {
        let mut s = model();
        let backing = TimerBacking::Image {
            base: 0x10000,
            size: 0x10000,
        };
        s.initialize_timer(0x13000, Architecture::X64, backing, true)
            .unwrap();
        s.set_timer(0x13000, 10, false, 0, 0x11000).unwrap();
        s.cancel_timer(0x13000).unwrap();
        s.retire_timer_backing(0x11000, 64).unwrap();
        s.set_timer(0x13000, 20, false, 0, 0).unwrap();
        s.cancel_timer(0x13000).unwrap();
        let initialization = s.timer(0x13000).unwrap().initialization;
        s.retire_timer_backing(0x13000, 64).unwrap();
        s.initialize_timer(0x13000, Architecture::X64, backing, true)
            .unwrap();
        assert!(s.timer(0x13000).unwrap().initialization > initialization);
    }
}

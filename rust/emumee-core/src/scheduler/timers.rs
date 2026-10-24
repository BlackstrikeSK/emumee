//! Bounded timer bodies and DPC records on the sole cooperative scheduler.
//! Native execution is separately attested; pure legacy comparisons opt into metadata policy.
use super::*;
use crate::pe::Architecture;
pub const TIMER_LIFETIME_LIMIT: u64 = 65_536;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum TimerBacking {
    Image {
        base: u64,
        size: u64,
    },
    NonpagedPool {
        base: u64,
        requested: u64,
        mapped: u64,
    },
}
#[derive(Clone, Debug, Serialize)]
pub struct Timer {
    pub address: u64,
    pub architecture: Architecture,
    pub backing: TimerBacking,
    pub manual_reset: bool,
    pub signaled: bool,
    pub inserted: bool,
    pub due: u64,
    pub period_ms: u32,
    pub dpc: u64,
    pub absolute: bool,
    pub arm_generation: u64,
    pub initialization: u64,
}
impl Timer {
    pub fn size(&self) -> usize {
        if self.architecture == Architecture::X64 {
            64
        } else {
            40
        }
    }
    /// Explicit legacy modeled layout, not an unrestricted Windows KTIMER ABI.
    pub fn bytes(&self) -> Vec<u8> {
        let width = self.architecture.width();
        let mut b = vec![0; self.size()];
        b[0] = if self.manual_reset { 8 } else { 9 };
        b[1] = u8::from(self.absolute);
        b[2] = (self.size() / 4) as u8;
        b[3] = if self.inserted { 0x40 } else { 0 };
        b[4..8].copy_from_slice(&u32::from(self.signaled).to_le_bytes());
        for at in [8, 8 + width] {
            b[at..at + width].copy_from_slice(&(self.address + 8).to_le_bytes()[..width]);
        }
        let due = if width == 8 { 24 } else { 16 };
        b[due..due + 8].copy_from_slice(&self.due.to_le_bytes());
        let dpc = if width == 8 { 48 } else { 32 };
        b[dpc..dpc + width].copy_from_slice(&self.dpc.to_le_bytes()[..width]);
        let last = b.len() - 4;
        b[last..].copy_from_slice(&self.period_ms.to_le_bytes());
        b
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Dpc {
    pub address: u64,
    pub architecture: Architecture,
    pub backing: TimerBacking,
    pub routine: u64,
    pub context: u64,
    pub phase: DpcPhase,
}
impl Dpc {
    pub fn size(&self) -> usize {
        if self.architecture == Architecture::X64 {
            64
        } else {
            32
        }
    }
    pub fn bytes(&self) -> Vec<u8> {
        let width = self.architecture.width();
        let mut b = vec![0; self.size()];
        b[..2].copy_from_slice(&[0x13, 1]);
        let at = if width == 8 { 24 } else { 12 };
        b[at..at + width].copy_from_slice(&self.routine.to_le_bytes()[..width]);
        b[at + width..at + 2 * width].copy_from_slice(&self.context.to_le_bytes()[..width]);
        if let Some(work) = self.phase.work() {
            let first = if width == 8 { 40 } else { 20 };
            b[first..first + width].copy_from_slice(&work.arguments[0].to_le_bytes()[..width]);
            b[first + width..first + 2 * width]
                .copy_from_slice(&work.arguments[1].to_le_bytes()[..width]);
        }
        b
    }
}
fn overlap(a: u64, n: u64, b: u64, m: u64) -> bool {
    if n == 0 || m == 0 {
        return false;
    }
    a.checked_add(n).is_none_or(|e| b < e) && b.checked_add(m).is_none_or(|e| a < e)
}
fn location(
    address: u64,
    size: u64,
    architecture: Architecture,
    backing: TimerBacking,
) -> Result<()> {
    let end = address
        .checked_add(size)
        .ok_or(SchedulerError("timer/DPC location overflow"))?;
    let (base, length) = match backing {
        TimerBacking::Image { base, size } => (base, size),
        TimerBacking::NonpagedPool {
            base,
            requested,
            mapped,
        } => {
            if requested > mapped {
                return Err(SchedulerError("timer/DPC Pool extent mismatch"));
            }
            (base, requested)
        }
    };
    if address == 0
        || address % architecture.width() as u64 != 0
        || architecture == Architecture::X86 && end > 1u64 << 32
        || address < base
        || base.checked_add(length).is_none_or(|limit| end > limit)
    {
        return Err(SchedulerError(
            "timer/DPC location outside backing/guest width",
        ));
    }
    Ok(())
}
impl Scheduler {
    pub fn timers(&self) -> impl Iterator<Item = &Timer> {
        self.timers.values()
    }
    pub fn dpcs(&self) -> impl Iterator<Item = &Dpc> {
        self.dpcs.values()
    }
    pub fn timer(&self, address: u64) -> Result<&Timer> {
        self.timers
            .get(&address)
            .ok_or(SchedulerError("unsupported or uninitialized timer"))
    }
    pub fn dpc(&self, address: u64) -> Result<&Dpc> {
        self.dpcs
            .get(&address)
            .ok_or(SchedulerError("uninitialized timer DPC"))
    }
    pub fn timer_initializations(&self) -> u64 {
        self.timer_initializations
    }
    pub fn dpc_initializations(&self) -> u64 {
        self.dpc_initializations
    }
    pub fn timer_read_overlap(&self, address: u64, size: u64) -> bool {
        if size == 0 {
            return false;
        }
        let end = address.saturating_add(size);
        self.timers
            .range(..end)
            .next_back()
            .is_some_and(|(_, t)| overlap(address, size, t.address, t.size() as u64))
    }
    pub fn timer_metadata_overlap(&self, address: u64, size: u64) -> bool {
        if size == 0 {
            return false;
        }
        let end = address.saturating_add(size);
        self.timer_read_overlap(address, size)
            || self
                .dpcs
                .range(..end)
                .next_back()
                .is_some_and(|(_, d)| overlap(address, size, d.address, d.size() as u64))
    }
    fn metadata_range(&self, address: u64, size: u64, replacing: u64) -> Result<()> {
        if address == 0 || address.checked_add(size).is_none() {
            return Err(SchedulerError("invalid timer/DPC metadata range"));
        }
        if self
            .timers()
            .any(|t| t.address != replacing && overlap(address, size, t.address, t.size() as u64))
            || self.dpcs().any(|d| {
                d.address != replacing && overlap(address, size, d.address, d.size() as u64)
            })
            || self.events.keys().any(|a| overlap(address, size, *a, 24))
            || self.mutexes.keys().any(|a| overlap(address, size, *a, 56))
        {
            return Err(SchedulerError("timer/DPC dispatcher backing collision"));
        }
        Ok(())
    }
    pub fn initialize_timer(
        &mut self,
        address: u64,
        architecture: Architecture,
        backing: TimerBacking,
        manual_reset: bool,
    ) -> Result<()> {
        if self.events.contains_key(&address)
            || self.mutexes.contains_key(&address)
            || self.dpcs.contains_key(&address)
        {
            return Err(SchedulerError("dispatcher object kind collision"));
        }
        if !self.timers.contains_key(&address)
            && self.events.len() + self.mutexes.len() + self.timers.len() >= 4096
        {
            return Err(SchedulerError("timer dispatcher object bound"));
        }
        if self.timer_initializations >= TIMER_LIFETIME_LIMIT {
            return Err(SchedulerError("timer initialization lifetime bound"));
        }
        if self.waits_on(Object::Timer(address))
            || self.timers.get(&address).is_some_and(|t| t.inserted)
        {
            return Err(SchedulerError("reinitializing inserted/waited timer"));
        }
        let t = Timer {
            address,
            architecture,
            backing,
            manual_reset,
            signaled: false,
            inserted: false,
            due: 0,
            period_ms: 0,
            dpc: 0,
            absolute: false,
            arm_generation: 0,
            initialization: self.timer_initializations + 1,
        };
        location(address, t.size() as u64, architecture, backing)?;
        self.metadata_range(address, t.size() as u64, address)?;
        self.timers.insert(address, t);
        self.timer_initializations += 1;
        Ok(())
    }
    pub fn initialize_dpc(&mut self, dpc: Dpc) -> Result<()> {
        if self.events.contains_key(&dpc.address)
            || self.mutexes.contains_key(&dpc.address)
            || self.timers.contains_key(&dpc.address)
        {
            return Err(SchedulerError("DPC dispatcher object kind collision"));
        }
        if !self.dpcs.contains_key(&dpc.address) && self.dpcs.len() >= 4096 {
            return Err(SchedulerError("DPC object bound"));
        }
        if self.dpc_initializations >= TIMER_LIFETIME_LIMIT {
            return Err(SchedulerError("DPC initialization lifetime bound"));
        }
        if self.dpcs.get(&dpc.address).is_some_and(|d| d.phase.busy()) || dpc.phase.busy() {
            return Err(SchedulerError("reinitializing queued/running DPC"));
        }
        if self.timers().any(|t| t.inserted && t.dpc == dpc.address) {
            return Err(SchedulerError("reinitializing referenced timer DPC"));
        }
        location(
            dpc.address,
            dpc.size() as u64,
            dpc.architecture,
            dpc.backing,
        )?;
        self.metadata_range(dpc.address, dpc.size() as u64, dpc.address)?;
        self.dpcs.insert(dpc.address, dpc);
        self.dpc_initializations += 1;
        Ok(())
    }
    pub fn set_timer(
        &mut self,
        address: u64,
        due: u64,
        absolute: bool,
        period: i32,
        dpc: u64,
    ) -> Result<bool> {
        if period < 0 {
            return Err(SchedulerError("negative timer period"));
        }
        if dpc != 0 {
            self.dpc(dpc)?;
        }
        self.require_timer_rearm_dpc(address, dpc)?;
        let arm = self
            .timer(address)?
            .arm_generation
            .checked_add(1)
            .ok_or(SchedulerError("timer arm generation exhausted"))?;
        let timer = self
            .timers
            .get_mut(&address)
            .ok_or(SchedulerError("unsupported or uninitialized timer"))?;
        let previous = timer.inserted;
        timer.arm_generation = arm;
        timer.inserted = true;
        timer.signaled = false;
        timer.due = due;
        timer.absolute = absolute;
        timer.period_ms = period as u32;
        timer.dpc = dpc;
        Ok(previous)
    }
    pub fn cancel_timer(&mut self, address: u64) -> Result<bool> {
        let prior = self.timer(address)?.clone();
        if prior.inserted && matches!(self.dpc_policy, DpcPolicy::Cpu0Dispatch { .. }) {
            self.cancel_associated_queued_dpc(&prior)?;
        }
        let t = self.timers.get_mut(&address).unwrap();
        let old = t.inserted;
        t.inserted = false;
        Ok(old)
    }
    /// All arithmetic and unsupported due callbacks are checked before effects.
    pub(super) fn refresh_timers(&mut self, now: u64) -> Result<()> {
        if matches!(self.dpc_policy, DpcPolicy::Cpu0Dispatch { .. }) {
            return self.refresh_timers_queued(now);
        }
        let mut due = Vec::new();
        for t in self.timers().filter(|t| t.inserted && t.due <= now) {
            if t.dpc != 0 {
                return Err(SchedulerError("due timer DPC requires callback scheduling"));
            }
            let next = if t.period_ms == 0 {
                None
            } else {
                let period = u64::from(t.period_ms) * 10_000;
                let skipped = (now - t.due) / period + 1;
                Some(
                    t.due
                        .checked_add(
                            skipped
                                .checked_mul(period)
                                .ok_or(SchedulerError("periodic timer horizon overflow"))?,
                        )
                        .ok_or(SchedulerError("periodic timer horizon overflow"))?,
                )
            };
            due.push((t.address, next));
        }
        for (address, next) in due {
            let t = self.timers.get_mut(&address).unwrap();
            t.signaled = true;
            if let Some(next) = next {
                t.due = next
            } else {
                t.inserted = false
            }
        }
        Ok(())
    }
    fn refresh_timers_queued(&mut self, now: u64) -> Result<()> {
        // Plan the whole batch including queue quotas before publishing one signal.
        let mut candidate = self.clone();
        let mut due = self
            .timers()
            .filter(|t| t.inserted && t.due <= now)
            .map(|t| (t.due, t.address))
            .collect::<Vec<_>>();
        due.sort_unstable();
        for (_, address) in due {
            let timer = candidate.timer(address)?.clone();
            let next = if timer.period_ms == 0 {
                None
            } else {
                let period = u64::from(timer.period_ms) * 10_000;
                let skipped = (now - timer.due) / period + 1;
                Some(
                    timer
                        .due
                        .checked_add(
                            skipped
                                .checked_mul(period)
                                .ok_or(SchedulerError("periodic timer horizon overflow"))?,
                        )
                        .ok_or(SchedulerError("periodic timer horizon overflow"))?,
                )
            };
            candidate.queue_timer_expiration(address, now)?;
            let timer = candidate.timers.get_mut(&address).unwrap();
            timer.signaled = true;
            if let Some(next) = next {
                timer.due = next
            } else {
                timer.inserted = false;
            }
        }
        *self = candidate;
        Ok(())
    }
    pub(super) fn waiting_timer_deadline(&self) -> Option<u64> {
        let waiters = self
            .threads
            .values()
            .filter_map(|t| {
                if let ThreadState::Waiting { objects, .. } = &t.state {
                    Some(objects)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if waiters.is_empty() {
            return None;
        }
        self.timers()
            .filter(|t| {
                t.inserted
                    && (t.dpc != 0
                        || (!t.signaled
                            && waiters
                                .iter()
                                .any(|objects| objects.contains(&Object::Timer(t.address)))))
            })
            .map(|t| t.due)
            .min()
    }
    pub fn pending_timer_dpc(&self) -> Option<&Timer> {
        self.timers().find(|t| t.inserted && t.dpc != 0)
    }
    pub fn require_timer_release(&self, address: u64, size: u64) -> Result<()> {
        for t in self
            .timers()
            .filter(|t| overlap(address, size, t.address, t.size() as u64))
        {
            if t.inserted || self.waits_on(Object::Timer(t.address)) || self.active_dpc().is_some_and(|d|matches!(d.phase.work().map(|w|&w.origin),Some(DpcOrigin::Timer{address,periodic:true,..})if *address==t.address)) {
                return Err(SchedulerError(
                    "memory release overlaps inserted/waited timer",
                ));
            }
        }
        if self.dpcs().any(|d| {
            overlap(address, size, d.address, d.size() as u64)
                && (d.phase.busy() || self.timers().any(|t| t.inserted && t.dpc == d.address))
        }) {
            return Err(SchedulerError(
                "memory release overlaps referenced timer DPC",
            ));
        }
        Ok(())
    }
    pub fn retire_timer_backing(&mut self, address: u64, size: u64) -> Result<()> {
        self.require_timer_release(address, size)?;
        self.timers
            .retain(|_, t| !overlap(address, size, t.address, t.size() as u64));
        self.dpcs
            .retain(|_, d| !overlap(address, size, d.address, d.size() as u64));
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn timer(s: &mut Scheduler, key: u64, manual: bool) {
        s.initialize_timer(
            key,
            Architecture::X64,
            TimerBacking::Image {
                base: 0x10000,
                size: 0x10000,
            },
            manual,
        )
        .unwrap();
    }
    #[test]
    fn timer_wait_any_all_consumption_timeout_ties_and_deadline_authority() {
        let mut s = Scheduler::new(8).unwrap();
        timer(&mut s, 0x11000, false);
        timer(&mut s, 0x12000, true);
        s.initialize_event(0x13000, false, true).unwrap();
        s.set_timer(0x11000, 50, false, 0, 0).unwrap();
        s.set_timer(0x12000, 50, false, 0, 0).unwrap();
        assert_eq!(
            s.wait(
                &[
                    Object::Timer(0x11000),
                    Object::Timer(0x12000),
                    Object::Event(0x13000)
                ],
                true,
                Some(50),
                0
            )
            .unwrap(),
            WaitOutcome::Blocked
        );
        assert_eq!(s.dispatch(), Dispatch::AdvanceTo(50));
        s.advance_to(50).unwrap();
        assert_eq!(s.dispatch(), Dispatch::Run(1));
        assert_eq!(
            s.thread(1).unwrap().wait_result,
            Some(WaitResult::Satisfied(0))
        );
        assert!(!s.timer(0x11000).unwrap().signaled);
        assert!(s.timer(0x12000).unwrap().signaled);
        assert_eq!(
            s.wait(
                &[Object::Timer(0x11000), Object::Timer(0x12000)],
                false,
                Some(50),
                0
            )
            .unwrap(),
            WaitOutcome::Immediate(WaitResult::Satisfied(1))
        );
    }
    #[test]
    fn replacement_cancel_periodic_coalescence_and_unsupported_due_dpc_are_atomic() {
        let mut s = Scheduler::new(8).unwrap();
        timer(&mut s, 0x11000, true);
        assert!(!s.set_timer(0x11000, 10, false, 1, 0).unwrap());
        assert!(s.set_timer(0x11000, 20, false, 1, 0).unwrap());
        s.advance_to(1_000_020).unwrap();
        assert_eq!(s.timer(0x11000).unwrap().due, 1_010_020);
        assert!(s.cancel_timer(0x11000).unwrap());
        assert!(!s.cancel_timer(0x11000).unwrap());
        s.initialize_dpc(Dpc {
            address: 0x12000,
            architecture: Architecture::X64,
            backing: TimerBacking::Image {
                base: 0x10000,
                size: 0x10000,
            },
            routine: 0x140001000,
            context: 0xffff123456789abc,
            phase: DpcPhase::Idle,
        })
        .unwrap();
        s.set_timer(0x11000, 1_000_021, false, 0, 0x12000).unwrap();
        let before = s.now;
        assert!(s.advance_to(1_000_021).is_err());
        assert_eq!(s.now, before);
        assert!(!s.timer(0x11000).unwrap().signaled);
        assert!(s.pending_timer_dpc().is_some());
        assert!(s.require_timer_release(0x12000, 64).is_err());
    }
    #[test]
    fn unrelated_periodic_timer_does_not_create_an_infinite_scheduler_drain() {
        let mut s = Scheduler::new(8).unwrap();
        timer(&mut s, 0x11000, true);
        s.set_timer(0x11000, 10, false, 1, 0).unwrap();
        s.initialize_event(0x12000, true, false).unwrap();
        s.wait(&[Object::Event(0x12000)], false, None, 0).unwrap();
        assert_eq!(s.dispatch(), Dispatch::Deadlocked(vec![1]));
        s.advance_to(20).unwrap();
        assert_eq!(s.dispatch(), Dispatch::Deadlocked(vec![1]));
    }
    #[test]
    fn timer_and_actual_thread_object_wait_all_preserve_atomic_consumption() {
        let mut s = Scheduler::new(8).unwrap();
        timer(&mut s, 0x11000, false);
        s.set_timer(0x11000, 0, true, 0, 0).unwrap();
        s.advance_to(0).unwrap();
        let child = s.create_thread(8).unwrap();
        assert_eq!(
            s.wait(
                &[Object::Timer(0x11000), Object::Thread(child)],
                true,
                None,
                0
            )
            .unwrap(),
            WaitOutcome::Blocked
        );
        assert!(s.timer(0x11000).unwrap().signaled);
        assert_eq!(s.dispatch(), Dispatch::Run(child));
        s.terminate(0).unwrap();
        assert!(!s.timer(0x11000).unwrap().signaled);
        assert_eq!(s.dispatch(), Dispatch::Run(1));
        assert_eq!(
            s.thread(1).unwrap().wait_result,
            Some(WaitResult::Satisfied(0))
        );
    }
    #[test]
    fn actual_layout_fullwidth_links_dpc_context_and_retirement_boundaries() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut s = Scheduler::new(8).unwrap();
            let address = if architecture == Architecture::X64 {
                0xffffb00000000000
            } else {
                0xe0000000
            };
            s.initialize_timer(
                address,
                architecture,
                TimerBacking::NonpagedPool {
                    base: address,
                    requested: 128,
                    mapped: 4096,
                },
                true,
            )
            .unwrap();
            let b = s.timer(address).unwrap().bytes();
            assert_eq!(b[0], 8);
            assert_eq!(b[2] as usize, b.len() / 4);
            let w = architecture.width();
            assert_eq!(&b[8..8 + w], &(address + 8).to_le_bytes()[..w]);
            assert!(s.initialize_event(address, true, false).is_err());
            s.retire_timer_backing(address, 4096).unwrap();
            assert!(s.timer(address).is_err());
        }
    }
    #[test]
    fn shared_quotas_invalid_width_periodic_overflow_and_waited_release_preflight_atomically() {
        let origin = TimerBacking::Image {
            base: 0x10000,
            size: 0x10000,
        };
        let mut s = Scheduler::new(8).unwrap();
        for key in 1..=4096 {
            s.initialize_event(key, true, false).unwrap();
        }
        assert!(
            s.initialize_timer(0x11000, Architecture::X64, origin, true)
                .is_err()
        );
        assert_eq!(s.timer_initializations, 0);
        assert!(s.timers.is_empty());
        let mut s = Scheduler::new(8).unwrap();
        assert!(
            s.initialize_timer(
                1u64 << 32,
                Architecture::X86,
                TimerBacking::Image {
                    base: 1u64 << 32,
                    size: 4096
                },
                true
            )
            .is_err()
        );
        timer(&mut s, 0x11000, true);
        s.set_timer(0x11000, u64::MAX - 5000, false, 1, 0).unwrap();
        assert!(s.advance_to(u64::MAX - 1).is_err());
        assert_eq!(s.now, 0);
        assert_eq!(s.timer(0x11000).unwrap().due, u64::MAX - 5000);
        assert!(!s.timer(0x11000).unwrap().signaled);
        s.cancel_timer(0x11000).unwrap();
        assert_eq!(
            s.wait(&[Object::Timer(0x11000)], false, None, 0).unwrap(),
            WaitOutcome::Blocked
        );
        assert!(s.retire_timer_backing(0x11000, 64).is_err());
        assert!(s.timer(0x11000).is_ok());
    }
    #[test]
    fn pinned_twenty_legacy_timer_rows_match_raw_bodies_returns_consumption_and_refusals() {
        let reference: serde_json::Value =
            serde_json::from_str(include_str!("timer_legacy_reference.json")).unwrap();
        let cases = reference["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 20);
        fn arm(s: &mut Scheduler, now: &mut u64, due: i64, period: i32, dpc: u64) -> Result<u64> {
            if period < 0 {
                return Err(SchedulerError("negative timer period"));
            }
            if dpc != 0 {
                s.dpc(dpc)?;
            }
            *now += 10;
            s.advance_to(*now)?;
            let deadline = if due < 0 {
                *now + due.unsigned_abs()
            } else {
                *now
            };
            let result = s.set_timer(0x2000, deadline, due >= 0, period, dpc)?;
            s.advance_to(*now)?;
            Ok(u64::from(result))
        }
        fn cancel(s: &mut Scheduler, now: &mut u64) -> Result<u64> {
            *now += 10;
            s.advance_to(*now)?;
            s.cancel_timer(0x2000).map(u64::from)
        }
        fn poll(s: &mut Scheduler, now: &mut u64) -> Result<u64> {
            *now += 10;
            s.advance_to(*now)?;
            Ok(
                match s.wait(&[Object::Timer(0x2000)], false, Some(*now), 0)? {
                    WaitOutcome::Immediate(WaitResult::Satisfied(index)) => index as u64,
                    WaitOutcome::Immediate(WaitResult::Timeout) => 0x102,
                    _ => panic!("Literal legacy poll must not block"),
                },
            )
        }
        for row in cases {
            let arch = if row["width"] == 8 {
                Architecture::X64
            } else {
                Architecture::X86
            };
            let name = row["case"].as_str().unwrap();
            let mut s = Scheduler::new(8).unwrap();
            s.select_legacy_reference_policy().unwrap();
            let origin = TimerBacking::Image {
                base: 0x1000,
                size: 0x4000,
            };
            s.initialize_timer(0x2000, arch, origin, name != "synchronization")
                .unwrap();
            let mut now = 0;
            let mut results = Vec::new();
            let outcome = (|| -> Result<()> {
                match name {
                    "replace" => {
                        results.push(arm(&mut s, &mut now, -10000000, 0, 0)?);
                        results.push(arm(&mut s, &mut now, -10000000, 0, 0)?);
                    }
                    "cancel" => {
                        results.push(arm(&mut s, &mut now, -10000000, 0, 0)?);
                        results.push(cancel(&mut s, &mut now)?);
                        results.push(cancel(&mut s, &mut now)?);
                    }
                    "notification" | "synchronization" => {
                        results.push(arm(&mut s, &mut now, 0, 0, 0)?);
                        results.push(poll(&mut s, &mut now)?);
                        results.push(poll(&mut s, &mut now)?);
                    }
                    "wait-before-timeout" => {
                        results.push(arm(&mut s, &mut now, -100000, 0, 0)?);
                        now += 10;
                        s.advance_to(now)?;
                        assert_eq!(
                            s.wait(&[Object::Timer(0x2000)], false, Some(now + 200000), 0)?,
                            WaitOutcome::Blocked
                        );
                        assert_eq!(s.dispatch(), Dispatch::AdvanceTo(100010));
                        now = 100010;
                        s.advance_to(now)?;
                        assert_eq!(s.dispatch(), Dispatch::Run(1));
                        assert_eq!(
                            s.thread(1).unwrap().wait_result,
                            Some(WaitResult::Satisfied(0))
                        );
                        results.push(0);
                    }
                    "periodic" => {
                        results.push(arm(&mut s, &mut now, -100, 10, 0)?);
                        now = 250000;
                        s.advance_to(now)?;
                        results.push(u64::from(s.timer(0x2000)?.signaled));
                    }
                    "invalid-period" => {
                        results.push(arm(&mut s, &mut now, -100000, -1, 0)?);
                    }
                    "timer-dpc-missing" => {
                        results.push(arm(&mut s, &mut now, -100000, 0, 0x2100)?);
                    }
                    "dpc-not-due-cancel" | "due-dpc-refusal" => {
                        s.initialize_dpc(Dpc {
                            address: 0x2100,
                            architecture: arch,
                            backing: origin,
                            routine: 0x1000,
                            context: 0x3456,
                            phase: DpcPhase::Idle,
                        })?;
                        results.push(arm(
                            &mut s,
                            &mut now,
                            if name == "due-dpc-refusal" {
                                0
                            } else {
                                -100000
                            },
                            0,
                            0x2100,
                        )?);
                        if name == "dpc-not-due-cancel" {
                            results.push(cancel(&mut s, &mut now)?);
                        }
                    }
                    _ => panic!("Unknown pinned legacy timer case"),
                };
                Ok(())
            })();
            assert_eq!(outcome.is_err(), !row["error"].is_null(), "{arch:?} {name}");
            assert_eq!(
                serde_json::json!(results),
                row["results"],
                "{arch:?} {name}"
            );
            assert_eq!(
                now,
                row["interrupt_ticks"].as_u64().unwrap(),
                "{arch:?} {name}"
            );
            let t = s.timer(0x2000).unwrap();
            let bytes = t
                .bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            assert_eq!(
                bytes,
                row["timer_header_hex"].as_str().unwrap(),
                "{arch:?} {name}"
            );
            assert_eq!(s.dpcs().count(), row["dpcs"].as_object().unwrap().len());
        }
    }
}

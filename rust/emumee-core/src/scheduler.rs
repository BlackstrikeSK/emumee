//! Single-CPU cooperative kernel state, independent of CPU context storage.
//! Waits acquire only available guest objects; deadlocks are explicit outcomes.
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use thiserror::Error;
mod dpc;
mod timers;
pub use dpc::{DPC_WORK_LIMIT, DpcCounters, DpcOrigin, DpcPhase, DpcPolicy, DpcWork};
pub use timers::{Dpc, TIMER_LIFETIME_LIMIT, Timer, TimerBacking};
pub type ThreadId = u64;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Object {
    Mutex(u64),
    Event(u64),
    Timer(u64),
    Thread(ThreadId),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum WaitResult {
    Satisfied(usize),
    Timeout,
}
#[derive(Clone, Debug, Serialize)]
pub enum ThreadState {
    Running,
    Ready,
    Waiting {
        objects: Vec<Object>,
        all: bool,
        deadline: Option<u64>,
        sequence: u64,
    },
    Exited {
        status: u32,
    },
}
#[derive(Clone, Debug, Serialize)]
pub struct Thread {
    pub id: ThreadId,
    pub priority: u8,
    pub state: ThreadState,
    pub wait_result: Option<WaitResult>,
}
#[derive(Clone, Debug)]
struct Event {
    manual_reset: bool,
    signaled: bool,
}
#[derive(Debug, Error)]
#[error("Kernel scheduler: {0}")]
pub struct SchedulerError(pub &'static str);
type Result<T> = std::result::Result<T, SchedulerError>;
#[derive(Debug, PartialEq, Eq)]
pub enum Dispatch {
    Dpc,
    Run(ThreadId),
    AdvanceTo(u64),
    Deadlocked(Vec<ThreadId>),
    Finished,
}
#[derive(Debug, PartialEq, Eq)]
pub enum WaitOutcome {
    Immediate(WaitResult),
    Blocked,
}
#[derive(Clone)]
pub struct Scheduler {
    threads: BTreeMap<ThreadId, Thread>,
    ready: BTreeMap<u8, VecDeque<ThreadId>>,
    current: Option<ThreadId>,
    next_thread: ThreadId,
    sequence: u64,
    mutexes: BTreeMap<u64, Option<ThreadId>>,
    events: BTreeMap<u64, Event>,
    now: u64,
    timers: BTreeMap<u64, Timer>,
    dpcs: BTreeMap<u64, Dpc>,
    timer_initializations: u64,
    dpc_initializations: u64,
    dpc_policy: DpcPolicy,
    dpc_queue: VecDeque<u64>,
    dpc_counters: DpcCounters,
}
impl Scheduler {
    pub fn new(root_priority: u8) -> Result<Self> {
        if !(1..=31).contains(&root_priority) {
            return Err(SchedulerError("invalid root priority"));
        }
        Ok(Self {
            threads: BTreeMap::from([(
                1,
                Thread {
                    id: 1,
                    priority: root_priority,
                    state: ThreadState::Running,
                    wait_result: None,
                },
            )]),
            ready: BTreeMap::new(),
            current: Some(1),
            next_thread: 2,
            sequence: 0,
            mutexes: BTreeMap::new(),
            events: BTreeMap::new(),
            now: 0,
            timers: BTreeMap::new(),
            dpcs: BTreeMap::new(),
            timer_initializations: 0,
            dpc_initializations: 0,
            dpc_policy: DpcPolicy::Unselected,
            dpc_queue: VecDeque::new(),
            dpc_counters: DpcCounters::default(),
        })
    }
    pub fn current(&self) -> Option<ThreadId> {
        self.current
    }
    pub fn event_states(&self) -> impl Iterator<Item = (u64, bool, bool)> + '_ {
        self.events
            .iter()
            .map(|(address, event)| (*address, event.manual_reset, event.signaled))
    }
    pub fn event_state(&self, key: u64) -> Result<(bool, bool)> {
        let event = self
            .events
            .get(&key)
            .ok_or(SchedulerError("unknown event"))?;
        Ok((event.manual_reset, event.signaled))
    }
    pub fn require_event_release(&self, base: u64, size: u64, layout: u64) -> Result<()> {
        let end = base
            .checked_add(size)
            .ok_or(SchedulerError("event backing release range overflow"))?;
        if size == 0 || layout == 0 {
            return Err(SchedulerError("invalid event backing release range"));
        }
        for &address in self.events.keys() {
            let event_end = address
                .checked_add(layout)
                .ok_or(SchedulerError("event layout overflow"))?;
            if address < end && base < event_end {
                if address < base || event_end > end {
                    return Err(SchedulerError("memory release splits initialized event"));
                }
                if self.waits_on(Object::Event(address)) {
                    return Err(SchedulerError("memory release overlaps waited event"));
                }
            }
        }
        Ok(())
    }
    pub fn retire_event_backing(&mut self, base: u64, size: u64, layout: u64) -> Result<()> {
        self.require_event_release(base, size, layout)?;
        let end = base + size;
        self.events
            .retain(|&address, _| address < base || address >= end);
        Ok(())
    }
    pub fn threads(&self) -> impl Iterator<Item = &Thread> {
        self.threads.values()
    }
    pub fn thread(&self, id: ThreadId) -> Option<&Thread> {
        self.threads.get(&id)
    }
    pub fn mutex_owner(&self, key: u64) -> Result<Option<ThreadId>> {
        self.mutexes
            .get(&key)
            .copied()
            .ok_or(SchedulerError("unknown mutex"))
    }
    /// Import a validated live guest mutex before the CPU adapter first waits.
    pub fn adopt_mutex(&mut self, key: u64, owner: Option<ThreadId>) -> Result<()> {
        if let Some(id) = owner {
            if self
                .threads
                .get(&id)
                .is_none_or(|t| matches!(t.state, ThreadState::Exited { .. }))
            {
                return Err(SchedulerError("mutex owner is not a live thread"));
            }
        }
        if let Some(previous) = self.mutexes.get(&key) {
            if *previous != owner {
                return Err(SchedulerError("guest mutex owner diverges from scheduler"));
            }
            return Ok(());
        }
        self.initialize_mutex(key)?;
        self.mutexes.insert(key, owner);
        Ok(())
    }
    pub fn mutex_waiters(&self, key: u64) -> usize {
        self.threads.values().filter(|thread|matches!(&thread.state,ThreadState::Waiting{objects,..} if objects.contains(&Object::Mutex(key)))).count()
    }
    pub fn create_thread(&mut self, priority: u8) -> Result<ThreadId> {
        if !(1..=31).contains(&priority) {
            return Err(SchedulerError("invalid thread priority"));
        }
        if self.threads.len() >= 256 {
            return Err(SchedulerError("thread count exceeds 256"));
        }
        let id = self.next_thread;
        self.next_thread += 1;
        self.threads.insert(
            id,
            Thread {
                id,
                priority,
                state: ThreadState::Ready,
                wait_result: None,
            },
        );
        self.ready.entry(priority).or_default().push_back(id);
        Ok(id)
    }
    pub fn priority(&mut self, id: ThreadId, priority: u8) -> Result<()> {
        if !(1..=31).contains(&priority) {
            return Err(SchedulerError("invalid thread priority"));
        }
        let thread = self
            .threads
            .get_mut(&id)
            .ok_or(SchedulerError("unknown thread"))?;
        if matches!(thread.state, ThreadState::Exited { .. }) {
            return Err(SchedulerError("thread has exited"));
        }
        thread.priority = priority;
        for queue in self.ready.values_mut() {
            queue.retain(|entry| *entry != id);
        }
        if matches!(thread.state, ThreadState::Ready) {
            self.ready.entry(priority).or_default().push_back(id);
        }
        Ok(())
    }
    pub fn initialize_mutex(&mut self, key: u64) -> Result<()> {
        if self.events.contains_key(&key)
            || self.timers.contains_key(&key)
            || self.dpcs.contains_key(&key)
        {
            return Err(SchedulerError("dispatcher object kind collision"));
        }
        if key == 0
            || (!self.mutexes.contains_key(&key)
                && self.mutexes.len() + self.events.len() + self.timers.len() >= 4096)
        {
            return Err(SchedulerError("invalid mutex/object bound"));
        }
        if self.mutexes.get(&key).is_some_and(Option::is_some) || self.waits_on(Object::Mutex(key))
        {
            return Err(SchedulerError("reinitializing a live mutex"));
        }
        self.mutexes.insert(key, None);
        Ok(())
    }
    pub fn initialize_event(&mut self, key: u64, manual_reset: bool, signaled: bool) -> Result<()> {
        if self.mutexes.contains_key(&key)
            || self.timers.contains_key(&key)
            || self.dpcs.contains_key(&key)
        {
            return Err(SchedulerError("dispatcher object kind collision"));
        }
        if key == 0
            || (!self.events.contains_key(&key)
                && self.mutexes.len() + self.events.len() + self.timers.len() >= 4096)
        {
            return Err(SchedulerError("invalid event/object bound"));
        }
        if self.waits_on(Object::Event(key)) {
            return Err(SchedulerError("reinitializing a waited event"));
        }
        self.events.insert(
            key,
            Event {
                manual_reset,
                signaled,
            },
        );
        Ok(())
    }
    fn waits_on(&self, object: Object) -> bool {
        self.threads.values().any(
            |t| matches!(&t.state,ThreadState::Waiting{objects,..} if objects.contains(&object)),
        )
    }
    fn valid(&self, object: Object) -> bool {
        match object {
            Object::Mutex(key) => self.mutexes.contains_key(&key),
            Object::Event(key) => self.events.contains_key(&key),
            Object::Timer(key) => self.timers.contains_key(&key),
            Object::Thread(id) => self.threads.contains_key(&id),
        }
    }
    fn available(&self, object: Object) -> bool {
        match object {
            Object::Mutex(key) => self.mutexes.get(&key) == Some(&None),
            Object::Event(key) => self.events.get(&key).is_some_and(|e| e.signaled),
            Object::Timer(key) => self.timers.get(&key).is_some_and(|t| t.signaled),
            Object::Thread(id) => self
                .threads
                .get(&id)
                .is_some_and(|t| matches!(t.state, ThreadState::Exited { .. })),
        }
    }
    fn acquire(&mut self, id: ThreadId, objects: &[Object], all: bool) -> Option<usize> {
        let selected = if all {
            if !objects.iter().all(|object| self.available(*object)) {
                return None;
            }
            (0..objects.len()).collect::<Vec<_>>()
        } else {
            vec![objects.iter().position(|object| self.available(*object))?]
        };
        let result = if all { 0 } else { selected[0] };
        for index in selected {
            match objects[index] {
                Object::Mutex(key) => {
                    self.mutexes.insert(key, Some(id));
                }
                Object::Event(key) => {
                    let event = self.events.get_mut(&key).unwrap();
                    if !event.manual_reset {
                        event.signaled = false;
                    }
                }
                Object::Timer(key) => {
                    let t = self.timers.get_mut(&key).unwrap();
                    if !t.manual_reset {
                        t.signaled = false;
                    }
                }
                Object::Thread(_) => {}
            }
        }
        Some(result)
    }
    pub fn wait(
        &mut self,
        objects: &[Object],
        all: bool,
        deadline: Option<u64>,
        irql: u8,
    ) -> Result<WaitOutcome> {
        let id = self.current.ok_or(SchedulerError("no current thread"))?;
        if objects.is_empty()
            || objects.len() > 64
            || objects.iter().copied().collect::<BTreeSet<_>>().len() != objects.len()
        {
            return Err(SchedulerError("invalid or duplicate wait objects"));
        }
        if objects.iter().any(|object| !self.valid(*object)) {
            return Err(SchedulerError("unknown wait object"));
        }
        if objects
            .iter()
            .any(|object| matches!(object,Object::Mutex(key) if self.mutexes[key]==Some(id)))
        {
            return Err(SchedulerError("recursive guarded mutex wait"));
        }
        if let Some(index) = self.acquire(id, objects, all) {
            self.threads.get_mut(&id).unwrap().wait_result = Some(WaitResult::Satisfied(index));
            return Ok(WaitOutcome::Immediate(WaitResult::Satisfied(index)));
        }
        if deadline.is_some_and(|time| time <= self.now) {
            self.threads.get_mut(&id).unwrap().wait_result = Some(WaitResult::Timeout);
            return Ok(WaitOutcome::Immediate(WaitResult::Timeout));
        }
        if irql > 1 {
            return Err(SchedulerError("blocking wait above APC_LEVEL"));
        }
        let sequence = self.sequence;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(SchedulerError("wait sequence overflow"))?;
        let thread = self.threads.get_mut(&id).unwrap();
        thread.wait_result = None;
        thread.state = ThreadState::Waiting {
            objects: objects.to_vec(),
            all,
            deadline,
            sequence,
        };
        self.current = None;
        Ok(WaitOutcome::Blocked)
    }
    /// Internal delay wait. Empty objects are reserved for this primitive;
    /// public wait() still rejects every zero-count guest object wait.
    pub fn delay_until(&mut self, deadline: u64, irql: u8) -> Result<WaitOutcome> {
        if irql > 1 {
            return Err(SchedulerError("delay above APC_LEVEL"));
        }
        let id = self.current.ok_or(SchedulerError("no current thread"))?;
        if deadline <= self.now {
            self.threads.get_mut(&id).unwrap().wait_result = Some(WaitResult::Timeout);
            return Ok(WaitOutcome::Immediate(WaitResult::Timeout));
        }
        let sequence = self.sequence;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(SchedulerError("wait sequence overflow"))?;
        let thread = self.threads.get_mut(&id).unwrap();
        thread.wait_result = None;
        thread.state = ThreadState::Waiting {
            objects: Vec::new(),
            all: false,
            deadline: Some(deadline),
            sequence,
        };
        self.current = None;
        Ok(WaitOutcome::Blocked)
    }
    fn wake(&mut self, id: ThreadId, result: WaitResult) {
        let thread = self.threads.get_mut(&id).unwrap();
        thread.wait_result = Some(result);
        thread.state = ThreadState::Ready;
        self.ready.entry(thread.priority).or_default().push_back(id);
    }
    fn wake_available(&mut self) {
        let mut waiters = self
            .threads
            .values()
            .filter_map(|t| match &t.state {
                ThreadState::Waiting {
                    objects,
                    all,
                    sequence,
                    ..
                } => Some((*sequence, t.id, objects.clone(), *all)),
                _ => None,
            })
            .collect::<Vec<_>>();
        waiters.sort_by_key(|w| w.0);
        for (_, id, objects, all) in waiters {
            if objects.is_empty() {
                continue;
            } // Internal delays wake only at their deadline.
            if let Some(index) = self.acquire(id, &objects, all) {
                self.wake(id, WaitResult::Satisfied(index));
            }
        }
    }
    pub fn advance_to(&mut self, now: u64) -> Result<()> {
        if now < self.now {
            return Err(SchedulerError("guest time moved backwards"));
        }
        self.refresh_timers(now)?;
        self.now = now;
        self.wake_available();
        let expired = self
            .threads
            .values()
            .filter_map(|t| match t.state {
                ThreadState::Waiting {
                    deadline: Some(deadline),
                    ..
                } if deadline <= now => Some(t.id),
                _ => None,
            })
            .collect::<Vec<_>>();
        for id in expired {
            self.wake(id, WaitResult::Timeout);
        }
        self.wake_available();
        Ok(())
    }
    pub fn release_mutex(&mut self, key: u64) -> Result<()> {
        let id = self.current.ok_or(SchedulerError("no current thread"))?;
        let owner = self
            .mutexes
            .get_mut(&key)
            .ok_or(SchedulerError("unknown mutex"))?;
        if *owner != Some(id) {
            return Err(SchedulerError("mutex released by non-owner"));
        }
        *owner = None;
        self.wake_available();
        Ok(())
    }
    pub fn set_event(&mut self, key: u64) -> Result<bool> {
        let event = self
            .events
            .get_mut(&key)
            .ok_or(SchedulerError("unknown event"))?;
        let previous = event.signaled;
        event.signaled = true;
        self.wake_available();
        Ok(previous)
    }
    pub fn reset_event(&mut self, key: u64) -> Result<bool> {
        let event = self
            .events
            .get_mut(&key)
            .ok_or(SchedulerError("unknown event"))?;
        let previous = event.signaled;
        event.signaled = false;
        Ok(previous)
    }
    pub fn yield_current(&mut self) -> Result<()> {
        let id = self.current.ok_or(SchedulerError("no current thread"))?;
        let thread = self.threads.get_mut(&id).unwrap();
        thread.state = ThreadState::Ready;
        self.ready.entry(thread.priority).or_default().push_back(id);
        self.current = None;
        Ok(())
    }
    pub fn terminate(&mut self, status: u32) -> Result<()> {
        let id = self.current.ok_or(SchedulerError("no current thread"))?;
        if self.mutexes.values().any(|owner| *owner == Some(id)) {
            return Err(SchedulerError("thread exit while owning guarded mutex"));
        }
        self.threads.get_mut(&id).unwrap().state = ThreadState::Exited { status };
        self.current = None;
        self.wake_available();
        Ok(())
    }
    pub fn dispatch(&mut self) -> Dispatch {
        if let Some(id) = self.current {
            return Dispatch::Run(id);
        }
        for queue in self.ready.values_mut().rev() {
            if let Some(id) = queue.pop_front() {
                self.threads.get_mut(&id).unwrap().state = ThreadState::Running;
                self.current = Some(id);
                return Dispatch::Run(id);
            }
        }
        if let Some(deadline) = self
            .threads
            .values()
            .filter_map(|t| match t.state {
                ThreadState::Waiting { deadline, .. } => deadline,
                _ => None,
            })
            .chain(self.waiting_timer_deadline())
            .min()
        {
            return Dispatch::AdvanceTo(deadline);
        }
        let waiting = self
            .threads
            .values()
            .filter(|t| matches!(t.state, ThreadState::Waiting { .. }))
            .map(|t| t.id)
            .collect::<Vec<_>>();
        if waiting.is_empty() {
            Dispatch::Finished
        } else {
            Dispatch::Deadlocked(waiting)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mutex_contention_blocks_then_hands_ownership_to_the_waiting_thread() {
        let mut s = Scheduler::new(8).unwrap();
        s.initialize_mutex(0x1000).unwrap();
        assert_eq!(
            s.wait(&[Object::Mutex(0x1000)], false, None, 0).unwrap(),
            WaitOutcome::Immediate(WaitResult::Satisfied(0))
        );
        let child = s.create_thread(8).unwrap();
        s.yield_current().unwrap();
        assert_eq!(s.dispatch(), Dispatch::Run(child));
        assert_eq!(
            s.wait(&[Object::Mutex(0x1000)], false, None, 0).unwrap(),
            WaitOutcome::Blocked
        );
        assert_eq!(s.dispatch(), Dispatch::Run(1));
        s.release_mutex(0x1000).unwrap();
        assert_eq!(s.mutex_owner(0x1000).unwrap(), Some(child));
        s.yield_current().unwrap();
        assert_eq!(s.dispatch(), Dispatch::Run(child));
        assert_eq!(
            s.thread(child).unwrap().wait_result,
            Some(WaitResult::Satisfied(0))
        );
        assert!(s.terminate(0).is_err());
        s.release_mutex(0x1000).unwrap();
        s.terminate(0).unwrap();
        assert_eq!(s.dispatch(), Dispatch::Run(1));
    }
    #[test]
    fn wait_all_does_not_partially_consume_auto_reset_events() {
        let mut s = Scheduler::new(8).unwrap();
        s.initialize_event(1, false, true).unwrap();
        s.initialize_event(2, false, false).unwrap();
        assert_eq!(
            s.wait(&[Object::Event(1), Object::Event(2)], true, Some(50), 0)
                .unwrap(),
            WaitOutcome::Blocked
        );
        let child = s.create_thread(8).unwrap();
        assert_eq!(s.dispatch(), Dispatch::Run(child));
        assert_eq!(
            s.wait(&[Object::Event(1)], false, None, 0).unwrap(),
            WaitOutcome::Immediate(WaitResult::Satisfied(0))
        );
        s.set_event(2).unwrap();
        assert!(matches!(
            s.thread(1).unwrap().state,
            ThreadState::Waiting { .. }
        ));
        s.set_event(1).unwrap();
        assert!(matches!(s.thread(1).unwrap().state, ThreadState::Ready));
        assert_eq!(
            s.wait(&[Object::Event(1), Object::Event(2)], false, Some(0), 0)
                .unwrap(),
            WaitOutcome::Immediate(WaitResult::Timeout)
        );
    }
    #[test]
    fn deadlines_advance_virtual_time_and_infinite_deadlocks_never_succeed() {
        let mut s = Scheduler::new(8).unwrap();
        s.initialize_event(1, true, false).unwrap();
        assert_eq!(
            s.wait(&[Object::Event(1)], false, Some(100), 0).unwrap(),
            WaitOutcome::Blocked
        );
        assert_eq!(s.dispatch(), Dispatch::AdvanceTo(100));
        s.advance_to(100).unwrap();
        assert_eq!(s.dispatch(), Dispatch::Run(1));
        assert_eq!(s.thread(1).unwrap().wait_result, Some(WaitResult::Timeout));
        assert_eq!(
            s.wait(&[Object::Event(1)], false, None, 0).unwrap(),
            WaitOutcome::Blocked
        );
        assert_eq!(s.dispatch(), Dispatch::Deadlocked(vec![1]));
        assert!(s.advance_to(99).is_err());
    }
    #[test]
    fn priority_and_fifo_order_are_bounded_and_thread_exit_signals_waiters() {
        let mut s = Scheduler::new(8).unwrap();
        let low = s.create_thread(4).unwrap();
        let high = s.create_thread(12).unwrap();
        s.yield_current().unwrap();
        assert_eq!(s.dispatch(), Dispatch::Run(high));
        s.terminate(0x1234).unwrap();
        assert_eq!(s.dispatch(), Dispatch::Run(1));
        assert_eq!(
            s.wait(&[Object::Thread(high)], false, None, 0).unwrap(),
            WaitOutcome::Immediate(WaitResult::Satisfied(0))
        );
        s.priority(low, 16).unwrap();
        s.yield_current().unwrap();
        assert_eq!(s.dispatch(), Dispatch::Run(low));
        s.terminate(0).unwrap();
        assert_eq!(s.dispatch(), Dispatch::Run(1));
        s.terminate(0).unwrap();
        assert_eq!(s.dispatch(), Dispatch::Finished);
    }
    #[test]
    fn invalid_waits_preserve_current_thread_and_object_ownership() {
        let mut s = Scheduler::new(8).unwrap();
        s.initialize_mutex(1).unwrap();
        s.initialize_event(2, false, false).unwrap();
        assert!(
            s.wait(&[Object::Event(2), Object::Event(2)], true, None, 0)
                .is_err()
        );
        assert!(s.wait(&[Object::Event(2)], false, None, 2).is_err());
        assert!(s.wait(&[Object::Mutex(3)], false, None, 0).is_err());
        assert_eq!(s.current(), Some(1));
        s.wait(&[Object::Mutex(1)], false, None, 0).unwrap();
        assert!(s.wait(&[Object::Mutex(1)], false, None, 0).is_err());
        assert!(s.initialize_mutex(1).is_err());
        assert_eq!(s.mutex_owner(1).unwrap(), Some(1));
        assert!(s.initialize_event(1, false, false).is_err());
    }
    #[test]
    fn event_broadcast_and_fifo_autoreset_wakes_do_not_reuse_old_results() {
        for manual in [false, true] {
            let mut s = Scheduler::new(8).unwrap();
            s.initialize_event(1, manual, false).unwrap();
            s.wait(&[Object::Event(1)], false, None, 0).unwrap();
            let child = s.create_thread(8).unwrap();
            assert_eq!(s.dispatch(), Dispatch::Run(child));
            s.wait(&[Object::Event(1)], false, None, 0).unwrap();
            s.set_event(1).unwrap();
            assert_eq!(s.dispatch(), Dispatch::Run(1));
            if manual {
                assert!(matches!(s.thread(child).unwrap().state, ThreadState::Ready));
                assert_eq!(
                    s.wait(&[Object::Event(1)], false, None, 0).unwrap(),
                    WaitOutcome::Immediate(WaitResult::Satisfied(0))
                );
                assert!(s.reset_event(1).unwrap());
            } else {
                assert!(matches!(
                    s.thread(child).unwrap().state,
                    ThreadState::Waiting { .. }
                ));
                s.wait(&[Object::Event(1)], false, None, 0).unwrap();
                assert_eq!(s.thread(1).unwrap().wait_result, None);
                s.set_event(1).unwrap();
                assert_eq!(s.dispatch(), Dispatch::Run(child));
                assert!(matches!(
                    s.thread(1).unwrap().state,
                    ThreadState::Waiting { .. }
                ));
            }
        }
    }
}

#[cfg(test)]
mod delay_and_multiple_wait_tests {
    use super::*;
    #[test]
    fn delay_uses_only_deadline_and_never_consumes_a_guest_event_signal() {
        let mut scheduler = Scheduler::new(8).unwrap();
        scheduler.initialize_event(0x1000, false, true).unwrap();
        assert!(scheduler.wait(&[], false, None, 0).is_err());
        assert_eq!(scheduler.delay_until(50, 0).unwrap(), WaitOutcome::Blocked);
        scheduler.advance_to(49).unwrap();
        assert!(matches!(
            scheduler.thread(1).unwrap().state,
            ThreadState::Waiting { .. }
        ));
        scheduler.set_event(0x1000).unwrap();
        assert!(matches!(
            scheduler.thread(1).unwrap().state,
            ThreadState::Waiting { .. }
        ));
        assert_eq!(scheduler.dispatch(), Dispatch::AdvanceTo(50));
        scheduler.advance_to(50).unwrap();
        assert_eq!(scheduler.dispatch(), Dispatch::Run(1));
        assert_eq!(
            scheduler.thread(1).unwrap().wait_result,
            Some(WaitResult::Timeout)
        );
        assert_eq!(scheduler.event_state(0x1000).unwrap(), (false, true));
        assert_eq!(
            scheduler.delay_until(50, 0).unwrap(),
            WaitOutcome::Immediate(WaitResult::Timeout)
        );
        assert!(scheduler.delay_until(60, 2).is_err());
    }
    #[test]
    fn wait_all_preserves_partial_auto_signals_and_consumes_them_atomically() {
        let mut scheduler = Scheduler::new(8).unwrap();
        scheduler.initialize_event(0x1000, false, true).unwrap();
        scheduler.initialize_event(0x2000, false, false).unwrap();
        let child = scheduler.create_thread(8).unwrap();
        assert_eq!(
            scheduler
                .wait(
                    &[Object::Event(0x1000), Object::Event(0x2000)],
                    true,
                    None,
                    0
                )
                .unwrap(),
            WaitOutcome::Blocked
        );
        assert_eq!(scheduler.event_state(0x1000).unwrap(), (false, true));
        assert_eq!(scheduler.dispatch(), Dispatch::Run(child));
        scheduler.set_event(0x2000).unwrap();
        assert_eq!(scheduler.event_state(0x1000).unwrap(), (false, false));
        assert_eq!(scheduler.event_state(0x2000).unwrap(), (false, false));
        assert_eq!(
            scheduler.thread(1).unwrap().wait_result,
            Some(WaitResult::Satisfied(0))
        );
    }
}

#[cfg(test)]
mod event_backing_lifetime_tests {
    use super::*;

    #[test]
    fn freeing_backing_retires_unwaited_events_without_touching_other_pages() {
        let mut scheduler = Scheduler::new(8).unwrap();
        scheduler.initialize_event(0x1080, true, false).unwrap();
        scheduler.initialize_event(0x10a0, false, true).unwrap();
        scheduler.initialize_event(0x2080, true, true).unwrap();
        assert!(scheduler.require_event_release(0x1088, 4096, 24).is_err());
        assert_eq!(scheduler.event_states().count(), 3);
        scheduler.retire_event_backing(0x1000, 4096, 24).unwrap();
        assert!(scheduler.event_state(0x1080).is_err());
        assert!(scheduler.event_state(0x10a0).is_err());
        assert_eq!(scheduler.event_state(0x2080).unwrap(), (true, true));
    }

    #[test]
    fn freeing_waited_event_backing_refuses_without_losing_the_wait() {
        let mut scheduler = Scheduler::new(8).unwrap();
        scheduler.initialize_event(0x1080, false, false).unwrap();
        assert_eq!(
            scheduler
                .wait(&[Object::Event(0x1080)], false, None, 0)
                .unwrap(),
            WaitOutcome::Blocked
        );
        assert!(scheduler.retire_event_backing(0x1000, 4096, 24).is_err());
        assert_eq!(scheduler.event_state(0x1080).unwrap(), (false, false));
        assert!(matches!(
            scheduler.thread(1).unwrap().state,
            ThreadState::Waiting { .. }
        ));
    }
}

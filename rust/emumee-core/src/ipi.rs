//! Bounded cooperative IPI rendezvous bookkeeping. Only adapters executing actual
//! guest contexts may submit return values or observed instruction totals.
use crate::pe::Architecture;
use serde::Serialize;
use std::collections::VecDeque;
use thiserror::Error;
pub const MAX_BROADCASTS: usize = 64;
pub const QUANTUM: u64 = 256;
pub const STACK_SIZE: u64 = 0x20000;
#[derive(Clone, Copy, Debug, Serialize)]
pub struct ProcessorLayout {
    pub processor: u32,
    pub pcr: u64,
    pub stack: u64,
    pub parked_thread: Option<u64>,
}
pub fn processor_layout(architecture: Architecture, processor: u32) -> Option<ProcessorLayout> {
    if processor >= architecture.width() as u32 * 8 {
        return None;
    }
    let layout = crate::kernel_layout::KernelLayout::for_architecture(architecture);
    let (pcr, stack, parked) = if architecture == Architecture::X64 {
        (
            0xfffff80010000000u64,
            0xffffc40000000000u64,
            0xffffa20000000000u64,
        )
    } else {
        (0xff800000, 0xc4000000, 0xd1000000)
    };
    Some(ProcessorLayout {
        processor,
        pcr: if processor == 0 {
            layout.pcr
        } else {
            pcr.checked_add(processor as u64 * 0x10000)?
        },
        stack: stack.checked_add(processor as u64 * STACK_SIZE)?,
        parked_thread: if processor == 0 {
            None
        } else {
            Some(parked.checked_add(processor as u64 * 4096)?)
        },
    })
}
#[derive(Debug, Error)]
#[error("Kernel IPI: {0}")]
pub struct IpiError(pub &'static str);
type Result<T> = std::result::Result<T, IpiError>;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Phase {
    Ready,
    Running,
    Suspended,
    Returned,
}
#[derive(Clone, Debug, Serialize)]
pub struct Member {
    pub processor: u32,
    pub phase: Phase,
    pub started: bool,
    pub instruction_count: u64,
    pub slices: u64,
    pub result: Option<u64>,
    #[serde(skip)]
    slice_start: Option<u64>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Broadcast {
    pub id: u64,
    pub routine: u64,
    pub argument: u64,
    pub source_processor: u32,
    pub caller_thread: u64,
    pub caller_irql: u8,
    pub completed: bool,
    pub members: Vec<Member>,
    pub source_result: Option<u64>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Rendezvous {
    architecture: Architecture,
    pub broadcasts: Vec<Broadcast>,
    pub active: Option<usize>,
    pub current: Option<u32>,
    #[serde(skip)]
    ready: VecDeque<u32>,
}
impl Rendezvous {
    pub fn new(architecture: Architecture) -> Self {
        Self {
            architecture,
            broadcasts: Vec::new(),
            active: None,
            current: None,
            ready: VecDeque::new(),
        }
    }
    pub fn level(&self) -> u8 {
        if self.architecture == Architecture::X64 {
            14
        } else {
            29
        }
    }
    pub fn begin(
        &self,
        routine: u64,
        argument: u64,
        logical: u32,
        source: u32,
        caller_thread: u64,
        irql: u8,
    ) -> Result<Self> {
        if self.active.is_some() {
            return Err(IpiError("nested broadcast is not supported"));
        }
        if irql >= self.level() {
            return Err(IpiError("broadcast requires IRQL below IPI_LEVEL"));
        }
        if logical == 0 || logical > self.architecture.width() as u32 * 8 || source >= logical {
            return Err(IpiError(
                "broadcast requires one bounded configured processor group",
            ));
        }
        if self.broadcasts.len() >= MAX_BROADCASTS {
            return Err(IpiError("broadcast limit exceeded"));
        }
        if routine == 0
            || caller_thread == 0
            || self.architecture == Architecture::X86
                && (routine > u32::MAX as u64
                    || argument > u32::MAX as u64
                    || caller_thread > u32::MAX as u64)
        {
            return Err(IpiError(
                "callback/caller address exceeds guest pointer width",
            ));
        }
        let mut next = self.clone();
        let members = (0..logical)
            .map(|processor| Member {
                processor,
                phase: Phase::Ready,
                started: false,
                instruction_count: 0,
                slices: 0,
                result: None,
                slice_start: None,
            })
            .collect();
        next.active = Some(next.broadcasts.len());
        next.current = None;
        next.ready = (0..logical).collect();
        next.broadcasts.push(Broadcast {
            id: next.broadcasts.len() as u64 + 1,
            routine,
            argument,
            source_processor: source,
            caller_thread,
            caller_irql: irql,
            completed: false,
            members,
            source_result: None,
        });
        Ok(next)
    }
    pub fn active_broadcast(&self) -> Result<&Broadcast> {
        self.active
            .and_then(|index| self.broadcasts.get(index))
            .ok_or(IpiError("no active broadcast"))
    }
    pub fn next_ready(&self) -> Result<Option<u32>> {
        let group = self.active_broadcast()?;
        if self.current.is_some() {
            return Err(IpiError(
                "running member must yield or return before dispatch",
            ));
        }
        if let Some(processor) = self.ready.front() {
            return Ok(Some(*processor));
        }
        if group
            .members
            .iter()
            .all(|member| member.phase == Phase::Returned)
        {
            Ok(None)
        } else {
            Err(IpiError("incomplete callback without runnable processor"))
        }
    }
    pub fn has_ready_member(&self) -> bool {
        !self.ready.is_empty()
    }
    pub fn dispatch(&self, processor: u32, total: u64) -> Result<Self> {
        if self.next_ready()? != Some(processor) {
            return Err(IpiError("dispatch does not match actual ready processor"));
        }
        let mut next = self.clone();
        let index = next.active.unwrap();
        let member = next.broadcasts[index]
            .members
            .get_mut(processor as usize)
            .ok_or(IpiError("unknown processor member"))?;
        if !matches!(member.phase, Phase::Ready | Phase::Suspended) || member.result.is_some() {
            return Err(IpiError("processor member is not runnable"));
        }
        member.phase = Phase::Running;
        member.started = true;
        member.slices = member
            .slices
            .checked_add(1)
            .ok_or(IpiError("slice count overflow"))?;
        member.slice_start = Some(total);
        next.ready.pop_front();
        next.current = Some(processor);
        Ok(next)
    }
    fn stop(&self, processor: u32, total: u64, result: Option<(u64, u8)>) -> Result<Self> {
        if self.current != Some(processor) {
            return Err(IpiError(
                "callback completed outside its actual processor context",
            ));
        }
        let mut next = self.clone();
        let index = next.active.ok_or(IpiError("no active broadcast"))?;
        let level = next.level();
        let member = next.broadcasts[index]
            .members
            .get_mut(processor as usize)
            .ok_or(IpiError("unknown processor member"))?;
        if member.phase != Phase::Running {
            return Err(IpiError("callback member is not running"));
        }
        let start = member
            .slice_start
            .ok_or(IpiError("running callback lacks observation start"))?;
        let delta = total
            .checked_sub(start)
            .ok_or(IpiError("global instruction total moved backwards"))?;
        if let Some((_, irql)) = result {
            if delta == 0 {
                return Err(IpiError("callback has no observed guest instruction"));
            }
            if irql != level {
                return Err(IpiError("callback returned outside IPI_LEVEL"));
            }
        }
        member.instruction_count = member
            .instruction_count
            .checked_add(delta)
            .ok_or(IpiError("callback instruction count overflow"))?;
        member.slice_start = None;
        if let Some((value, _)) = result {
            member.result = Some(if next.architecture == Architecture::X86 {
                value as u32 as u64
            } else {
                value
            });
            member.phase = Phase::Returned;
        } else {
            member.phase = Phase::Suspended;
            next.ready.push_back(processor);
        }
        next.current = None;
        Ok(next)
    }
    pub fn yield_member(&self, processor: u32, total: u64) -> Result<Self> {
        self.stop(processor, total, None)
    }
    pub fn return_member(&self, processor: u32, total: u64, value: u64, irql: u8) -> Result<Self> {
        self.stop(processor, total, Some((value, irql)))
    }
    pub fn pending_source_result(&self) -> Result<u64> {
        if self.current.is_some() || !self.ready.is_empty() {
            return Err(IpiError("IPI members have not all returned"));
        }
        let group = self.active_broadcast()?;
        if !group.members.iter().all(|member| {
            member.started && member.phase == Phase::Returned && member.result.is_some()
        }) {
            return Err(IpiError("IPI members have no verified complete return set"));
        }
        group.members[group.source_processor as usize]
            .result
            .ok_or(IpiError("source processor has no actual return"))
    }
    /// Adapter calls only after actual caller/native restoration succeeds.
    pub fn commit_restored_caller(&self) -> Result<Self> {
        let result = self.pending_source_result()?;
        let mut next = self.clone();
        let group = &mut next.broadcasts[next.active.unwrap()];
        group.completed = true;
        group.source_result = Some(result);
        next.active = None;
        next.current = None;
        next.ready.clear();
        Ok(next)
    }
    pub fn observed_current_instructions(&self, total: u64) -> Result<u64> {
        let group = self.active_broadcast()?;
        let processor = self.current.ok_or(IpiError("no running callback"))?;
        let member = &group.members[processor as usize];
        total
            .checked_sub(
                member
                    .slice_start
                    .ok_or(IpiError("callback missing instruction anchor"))?,
            )
            .ok_or(IpiError("global instruction total moved backwards"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn initial(architecture: Architecture, logical: u32) -> Rendezvous {
        Rendezvous::new(architecture)
            .begin(0x1000, 0x2000, logical, 0, 0x80001000, 0)
            .unwrap()
    }
    #[test]
    fn actual_return_set_and_restoration_are_required_for_source_result() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut model = initial(architecture, 4);
            assert!(model.pending_source_result().is_err());
            for processor in 0..4 {
                model = model
                    .dispatch(processor, 1000 + processor as u64 * 10)
                    .unwrap();
                assert!(
                    model
                        .return_member(processor, 999, 1, model.level())
                        .is_err()
                );
                model = model
                    .return_member(
                        processor,
                        1005 + processor as u64 * 10,
                        0x1234567800000000 + processor as u64,
                        model.level(),
                    )
                    .unwrap();
                assert!(!model.broadcasts[0].completed);
            }
            assert_eq!(
                model.pending_source_result().unwrap(),
                if architecture == Architecture::X64 {
                    0x1234567800000000
                } else {
                    0
                }
            );
            assert_eq!(model.next_ready().unwrap(), None);
            model = model.commit_restored_caller().unwrap();
            assert!(model.broadcasts[0].completed);
            assert!(model.active.is_none());
            assert!(
                model.broadcasts[0]
                    .members
                    .iter()
                    .all(|member| member.started && member.instruction_count == 5)
            );
        }
    }
    #[test]
    fn high_irql_rendezvous_round_robin_does_not_fake_completion_on_yield_or_fault() {
        let mut model = initial(Architecture::X64, 12);
        model = model.dispatch(0, 10).unwrap();
        assert_eq!(model.observed_current_instructions(266).unwrap(), QUANTUM);
        model = model.yield_member(0, 266).unwrap();
        for processor in 1..12 {
            assert_eq!(model.next_ready().unwrap(), Some(processor));
            model = model.dispatch(processor, 300 + processor as u64).unwrap();
            assert!(
                model
                    .return_member(processor, 301 + processor as u64, processor as u64, 0)
                    .is_err()
            );
            model = model
                .yield_member(processor, 301 + processor as u64)
                .unwrap();
        }
        assert_eq!(model.next_ready().unwrap(), Some(0));
        assert!(!model.broadcasts[0].completed);
        assert!(model.pending_source_result().is_err());
        assert!(model.begin(0x1000, 0, 1, 0, 0x80001000, 0).is_err());
    }
    #[test]
    fn preflight_pointer_width_group_irql_and_broadcast_bounds_preserve_original() {
        let base = Rendezvous::new(Architecture::X86);
        for (logical, source, irql) in [(0, 0, 0), (33, 0, 0), (4, 4, 0), (4, 0, 29)] {
            assert!(
                base.begin(0x1000, 0, logical, source, 0x80001000, irql)
                    .is_err()
            );
            assert!(base.broadcasts.is_empty());
        }
        assert!(
            base.begin(u32::MAX as u64 + 1, 0, 4, 0, 0x80001000, 0)
                .is_err()
        );
        assert!(
            base.begin(0x1000, u32::MAX as u64 + 1, 4, 0, 0x80001000, 0)
                .is_err()
        );
        let mut model = base;
        for _ in 0..MAX_BROADCASTS {
            model = model
                .begin(0x1000, 0, 1, 0, 0x80001000, 0)
                .unwrap()
                .dispatch(0, 0)
                .unwrap()
                .return_member(0, 1, 7, 29)
                .unwrap()
                .commit_restored_caller()
                .unwrap();
        }
        assert!(model.begin(0x1000, 0, 1, 0, 0x80001000, 0).is_err());
        assert_eq!(model.broadcasts.len(), MAX_BROADCASTS);
    }
}

#[cfg(test)]
mod layout_tests {
    use super::*;
    #[test]
    fn all_processor_resources_are_pairwise_disjoint_from_owned_boot_and_provider_reservations() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let boot = crate::kernel_layout::KernelLayout::for_architecture(architecture);
            let mut reserved = vec![
                (boot.entry_stack, crate::kernel_layout::ENTRY_STACK_SIZE),
                (boot.driver_object, 0x20000),
                (boot.descriptor_tables, 0x4000),
                (boot.return_marker, 0x1000),
            ];
            for slot in 2..=64 {
                reserved.push((
                    boot.thread_stack(slot).unwrap(),
                    crate::kernel_layout::THREAD_STACK_SIZE,
                ));
                reserved.push((boot.thread_object(slot).unwrap(), 0x1000));
            }
            // Provider profile: reserve the full16MiB ntoskrnl catalog bound
            // plus HAL and API gate pages; no dependency on today's name count.
            if architecture == Architecture::X64 {
                reserved.extend([
                    (0xfffff80000400000, 0x1000000),
                    (0xfffff80001400000, 0x10000),
                    (0xffffc00000000000, 0x100000),
                    (0xffffc10000000000, 0x1000),
                    (0xffffb00000000000, 0x10000000),
                ]);
            } else {
                reserved.extend([
                    (0x80400000, 0x1000000),
                    (0x81400000, 0x10000),
                    (0xc0000000, 0x100000),
                    (0xc1000000, 0x1000),
                    (0xe0000000, 0x10000000),
                ]);
            }
            let maximum = architecture.width() as u32 * 8;
            let mut resources = Vec::new();
            for cpu in 0..maximum {
                let layout = processor_layout(architecture, cpu).unwrap();
                resources.push((layout.stack, STACK_SIZE));
                resources.push((layout.pcr, 0x1000));
                if let Some(thread) = layout.parked_thread {
                    resources.push((thread, 0x1000));
                }
            }
            for (at, (base, size)) in resources.iter().copied().enumerate() {
                let end = base.checked_add(size).unwrap();
                assert_eq!(base & 4095, 0);
                if architecture == Architecture::X86 {
                    assert!(end <= 1u64 << 32);
                }
                for &(other, len) in reserved.iter().chain(resources[..at].iter()) {
                    assert!(
                        end <= other || base >= other.checked_add(len).unwrap(),
                        "{architecture:?}: {base:x}+{size:x} overlaps {other:x}+{len:x}"
                    );
                }
            }
            assert!(processor_layout(architecture, maximum).is_none());
        }
    }
}

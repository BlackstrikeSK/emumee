//! Architectural debug-control state, independent of native backend defaults.
//! This is one processor's device. The engine must supply actual retired edges
//! and own processor selection. No hardware-specific LBR MSR encoding is implied.
use serde::Serialize;
use std::collections::VecDeque;
use thiserror::Error;

pub const IA32_DEBUGCTL: u32 = 0x1d9;
const LBR: u64 = 1;
const BTF: u64 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum EdgeKind {
    Branch,
    Interrupt,
    Exception,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Edge {
    pub from: u64,
    pub to: u64,
    pub kind: EdgeKind,
}
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("Last-branch capacity must come from a supported processor profile")]
    Capacity,
    #[error("DEBUGCTL controls other than LBR/BTF require separate implementation")]
    UnsupportedControls,
    #[error("BTF with EFLAGS.TF requires architectural branch-step exception dispatch")]
    BranchStep,
}

#[derive(Clone, Debug, Serialize)]
pub struct DebugControl {
    value: u64,
    capacity: usize,
    // Oldest first. Overflow is architectural circular replacement, not loss
    // caused by a diagnostic reporting limit.
    edges: VecDeque<Edge>,
    recorded_edges: u64,
}
impl DebugControl {
    pub fn new(capacity: usize) -> Result<Self, Error> {
        if !(1..=32).contains(&capacity) {
            return Err(Error::Capacity);
        }
        Ok(Self {
            value: 0,
            capacity,
            edges: VecDeque::with_capacity(capacity),
            recorded_edges: 0,
        })
    }
    pub fn read(&self) -> u64 {
        self.value
    }
    /// Unknown controls are unsupported, not automatically reserved-bit #GP.
    /// The processor profile must determine those architectural distinctions.
    pub fn write(&mut self, value: u64, trap_flag: bool) -> Result<(), Error> {
        if value & !(LBR | BTF) != 0 {
            return Err(Error::UnsupportedControls);
        }
        if value & BTF != 0 && trap_flag {
            return Err(Error::BranchStep);
        }
        self.value = value;
        Ok(())
    }
    pub fn recording(&self) -> bool {
        self.value & LBR != 0
    }
    /// Call before executing an instruction, including after a POPF/IRET that
    /// might have changed TF. Unsupported stepping cannot silently continue.
    pub fn validate_execution(&self, trap_flag: bool) -> Result<(), Error> {
        if self.value & BTF != 0 && trap_flag {
            return Err(Error::BranchStep);
        }
        Ok(())
    }
    /// Only committed taken edges belong here. Fallthroughs and attempted
    /// transfers that fault before retirement must never be submitted.
    pub fn record_taken(&mut self, edge: Edge) {
        if !self.recording() {
            return;
        }
        if self.edges.len() == self.capacity {
            self.edges.pop_front();
        }
        self.edges.push_back(edge);
        self.recorded_edges = self.recorded_edges.saturating_add(1);
    }
    pub fn edges(&self) -> impl ExactSizeIterator<Item = &Edge> {
        self.edges.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn edge(from: u64) -> Edge {
        Edge {
            from,
            to: from + 10,
            kind: EdgeKind::Branch,
        }
    }
    #[test]
    fn debugctl_readback_and_restore_preserve_existing_branch_history() {
        let mut cpu = DebugControl::new(32).unwrap();
        assert_eq!(cpu.read(), 0);
        cpu.write(3, false).unwrap();
        assert_eq!(cpu.read(), 3);
        cpu.record_taken(edge(0x1000));
        cpu.write(0, false).unwrap();
        cpu.record_taken(edge(0x2000));
        assert_eq!(cpu.read(), 0);
        assert_eq!(cpu.edges().copied().collect::<Vec<_>>(), [edge(0x1000)]);
    }
    #[test]
    fn debugctl_circular_branch_history_is_bounded_and_processor_local() {
        let mut first = DebugControl::new(2).unwrap();
        let mut second = DebugControl::new(2).unwrap();
        first.write(1, false).unwrap();
        for from in [1, 2, 3] {
            first.record_taken(edge(from));
        }
        second.record_taken(edge(4));
        assert_eq!(
            first.edges().copied().collect::<Vec<_>>(),
            [edge(2), edge(3)]
        );
        assert_eq!(first.recorded_edges, 3);
        assert_eq!(second.read(), 0);
        assert_eq!(second.edges().len(), 0);
    }
    #[test]
    fn debugctl_unsupported_controls_and_branch_stepping_preserve_committed_state() {
        let mut cpu = DebugControl::new(16).unwrap();
        cpu.write(1, false).unwrap();
        assert_eq!(cpu.write(0x80, false), Err(Error::UnsupportedControls));
        assert_eq!(cpu.write(3, true), Err(Error::BranchStep));
        assert_eq!(cpu.read(), 1);
        cpu.write(3, false).unwrap();
        assert_eq!(cpu.validate_execution(true), Err(Error::BranchStep));
        assert_eq!(cpu.validate_execution(false), Ok(()));
        assert_eq!(cpu.read(), 3);
        assert!(matches!(DebugControl::new(0), Err(Error::Capacity)));
        assert!(matches!(DebugControl::new(33), Err(Error::Capacity)));
    }
}

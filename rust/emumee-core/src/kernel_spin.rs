//! Genuine bounded API spin-word ownership. The CPU adapter must publish the
//! planned word/actual IRQL together; this is not a contended wait scheduler.
use crate::pe::Architecture;
use serde::Serialize;
use std::collections::BTreeMap;
use thiserror::Error;
pub const RECORD_LIMIT: usize = 4096;
pub const INITIALIZATION_LIMIT: u64 = 65_536;
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("Kernel spin profile: {0}")]
pub struct SpinError(pub &'static str);
type Result<T> = std::result::Result<T, SpinError>;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Backing {
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Owner {
    pub processor: u32,
    pub thread: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Held {
    pub owner: Owner,
    pub saved_irql: u8,
}
#[derive(Clone, Debug, Serialize)]
pub struct Record {
    pub address: u64,
    pub width: usize,
    pub backing: Backing,
    pub initialization: u64,
    pub live: bool,
    pub held: Option<Held>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Operation {
    Initialize,
    Acquire,
    Release { new_irql: u8 },
}
#[derive(Clone, Copy, Debug)]
pub struct Input {
    pub architecture: Architecture,
    pub address: u64,
    pub word: u64,
    pub backing: Backing,
    pub owner: Owner,
    pub irql: u8,
}
#[derive(Clone, Debug, Serialize)]
pub struct Attempt {
    pub operation: Operation,
    pub address: u64,
    pub before: u64,
    pub after: u64,
    pub owner: Owner,
    pub old_irql: u8,
    pub new_irql: u8,
    pub completed: bool,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct State {
    records: BTreeMap<u64, Record>,
    pub initializations: u64,
    pub transitions: u64,
    pub native_effect_failure: bool,
    pub last_attempt: Option<Attempt>,
}
pub struct Plan {
    pub state: State,
    pub attempt: Attempt,
    pub result: u64,
}
fn overlap(a: u64, n: u64, b: u64, m: u64) -> bool {
    a.checked_add(n).is_none_or(|end| b < end) && b.checked_add(m).is_none_or(|end| a < end)
}
impl State {
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.records.values()
    }
    pub fn held(&self) -> impl Iterator<Item = &Record> {
        self.records.values().filter(|r| r.live && r.held.is_some())
    }
    pub fn overlaps(&self, base: u64, size: u64) -> bool {
        self.records
            .values()
            .any(|r| r.live && overlap(base, size, r.address, r.width as u64))
    }
    pub fn ready(&self) -> Result<()> {
        if self.native_effect_failure {
            Err(SpinError("native effect failed; execution cannot resume"))
        } else {
            Ok(())
        }
    }
    pub fn require_lower(&self, owner: Owner, new: u8) -> Result<()> {
        if new < 2 && self.held().any(|r| r.held.unwrap().owner == owner) {
            return Err(SpinError(
                "owner lowered below DISPATCH_LEVEL while holding a spin lock",
            ));
        }
        Ok(())
    }
    pub fn require_exit(&self, owner: Owner) -> Result<()> {
        if self.held().any(|r| r.held.unwrap().owner == owner) {
            return Err(SpinError("thread exit while owning a spin lock"));
        }
        Ok(())
    }
    pub fn require_release(&self, base: u64, size: u64) -> Result<()> {
        self.ready()?;
        if self
            .held()
            .any(|r| overlap(base, size, r.address, r.width as u64))
        {
            return Err(SpinError("memory release overlaps a held spin lock"));
        }
        Ok(())
    }
    pub fn retire(&mut self, base: u64, size: u64) -> Result<()> {
        self.require_release(base, size)?;
        for record in self.records.values_mut() {
            if record.live && overlap(base, size, record.address, record.width as u64) {
                record.live = false;
            }
        }
        Ok(())
    }
    pub fn plan(&self, operation: Operation, input: Input) -> Result<Plan> {
        self.ready()?;
        let width = input.architecture.width();
        if width == 4 && input.word > u32::MAX as u64 {
            return Err(SpinError("word exceeds guest pointer width"));
        }
        if input.address == 0
            || input.address % width as u64 != 0
            || input.address.checked_add(width as u64).is_none()
            || input.architecture == Architecture::X86 && input.address + width as u64 > 1u64 << 32
        {
            return Err(SpinError("null, unaligned or overflowing spin word"));
        }
        if input.owner.thread == 0 || input.owner.processor != 0 {
            return Err(SpinError("unsupported spin owner/processor profile"));
        }
        let mut next = self.clone();
        let (after, new_irql, result) = match operation {
            Operation::Initialize => {
                if self
                    .records
                    .get(&input.address)
                    .is_some_and(|r| r.live && r.held.is_some())
                {
                    return Err(SpinError("reinitializing a held spin lock"));
                }
                if !self.records.contains_key(&input.address) && self.records.len() >= RECORD_LIMIT
                {
                    return Err(SpinError("spin record quota"));
                }
                if self.initializations >= INITIALIZATION_LIMIT {
                    return Err(SpinError("spin initialization lifetime quota"));
                }
                if self.records.values().any(|r| {
                    r.live
                        && r.address != input.address
                        && overlap(r.address, r.width as u64, input.address, width as u64)
                }) {
                    return Err(SpinError("overlapping spin identities"));
                }
                next.initializations += 1;
                next.records.insert(
                    input.address,
                    Record {
                        address: input.address,
                        width,
                        backing: input.backing,
                        initialization: next.initializations,
                        live: true,
                        held: None,
                    },
                );
                (0, input.irql, 0)
            }
            Operation::Acquire | Operation::Release { .. } => {
                let record = next
                    .records
                    .get_mut(&input.address)
                    .filter(|r| r.live)
                    .ok_or(SpinError("uninitialized or retired spin lock"))?;
                if record.width != width || record.backing != input.backing {
                    return Err(SpinError("spin backing authority diverged"));
                }
                match operation {
                    Operation::Acquire => {
                        if input.irql > 2 {
                            return Err(SpinError("acquisition above DISPATCH_LEVEL"));
                        }
                        if record.held.is_some() {
                            return Err(SpinError(
                                "busy or recursive spin acquisition is unsupported",
                            ));
                        }
                        if input.word != 0 {
                            return Err(SpinError("divergent or busy spin word"));
                        }
                        record.held = Some(Held {
                            owner: input.owner,
                            saved_irql: input.irql,
                        });
                        (1, 2, u64::from(input.irql))
                    }
                    Operation::Release { new_irql } => {
                        let held = record
                            .held
                            .ok_or(SpinError("release without a spin owner"))?;
                        if held.owner != input.owner {
                            return Err(SpinError("spin release by wrong processor/thread owner"));
                        }
                        if input.word != 1 {
                            return Err(SpinError("divergent held spin word"));
                        }
                        if input.irql != 2 || new_irql != held.saved_irql {
                            return Err(SpinError("spin release saved/current IRQL mismatch"));
                        }
                        record.held = None;
                        if new_irql < 2 && next.held().any(|r| r.held.unwrap().owner == input.owner)
                        {
                            return Err(SpinError(
                                "out-of-order spin release would lower while another lock is held",
                            ));
                        }
                        (0, new_irql, 0)
                    }
                    _ => unreachable!(),
                }
            }
        };
        next.transitions = next
            .transitions
            .checked_add(1)
            .ok_or(SpinError("transition counter overflow"))?;
        let attempt = Attempt {
            operation,
            address: input.address,
            before: input.word,
            after,
            owner: input.owner,
            old_irql: input.irql,
            new_irql,
            completed: false,
        };
        Ok(Plan {
            state: next,
            attempt,
            result,
        })
    }
    /// Called immediately before any native effect. A failed effect leaves
    /// truthful old records plus the incomplete intended transition and stops.
    pub fn begin(&mut self, attempt: Attempt) {
        self.native_effect_failure = true;
        self.last_attempt = Some(attempt);
    }
    pub fn complete(&mut self, mut plan: Plan) {
        plan.attempt.completed = true;
        plan.state.native_effect_failure = false;
        plan.state.last_attempt = Some(plan.attempt);
        *self = plan.state;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn input(architecture: Architecture, address: u64, word: u64, irql: u8) -> Input {
        Input {
            architecture,
            address,
            word,
            irql,
            backing: Backing::Image {
                base: 0x10000,
                size: 0x2000,
            },
            owner: Owner {
                processor: 0,
                thread: 0xd0002000,
            },
        }
    }
    fn apply(state: &mut State, op: Operation, input: Input) -> (u64, u8, u64) {
        let p = state.plan(op, input).unwrap();
        let out = (p.attempt.after, p.attempt.new_irql, p.result);
        state.begin(p.attempt.clone());
        state.complete(p);
        out
    }
    #[test]
    fn real_word_owner_saved_irql_and_nested_release_are_one_checked_authority() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut s = State::default();
            apply(&mut s, Operation::Initialize, input(arch, 0x10000, 55, 0));
            apply(&mut s, Operation::Initialize, input(arch, 0x10010, 66, 0));
            assert_eq!(
                apply(&mut s, Operation::Acquire, input(arch, 0x10000, 0, 1)),
                (1, 2, 1)
            );
            assert_eq!(
                apply(&mut s, Operation::Acquire, input(arch, 0x10010, 0, 2)),
                (1, 2, 2)
            );
            assert!(
                s.plan(
                    Operation::Release { new_irql: 1 },
                    input(arch, 0x10000, 1, 2)
                )
                .is_err()
            );
            assert_eq!(
                apply(
                    &mut s,
                    Operation::Release { new_irql: 2 },
                    input(arch, 0x10010, 1, 2)
                ),
                (0, 2, 0)
            );
            assert_eq!(
                apply(
                    &mut s,
                    Operation::Release { new_irql: 1 },
                    input(arch, 0x10000, 1, 2)
                ),
                (0, 1, 0)
            );
            assert_eq!(s.held().count(), 0);
            assert_eq!(s.transitions, 6);
        }
    }
    #[test]
    fn blocked_divergent_wrong_owner_and_refree_never_plan_fake_acquisition() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut s = State::default();
            apply(&mut s, Operation::Initialize, input(arch, 0x10000, 0, 0));
            assert!(
                s.plan(Operation::Acquire, input(arch, 0x10000, 1, 0))
                    .is_err()
            );
            apply(&mut s, Operation::Acquire, input(arch, 0x10000, 0, 0));
            let before = serde_json::to_value(&s).unwrap();
            for (op, mut i) in [
                (Operation::Acquire, input(arch, 0x10000, 1, 2)),
                (Operation::Initialize, input(arch, 0x10000, 1, 2)),
                (
                    Operation::Release { new_irql: 0 },
                    input(arch, 0x10000, 0, 2),
                ),
                (
                    Operation::Release { new_irql: 1 },
                    input(arch, 0x10000, 1, 2),
                ),
            ] {
                assert!(s.plan(op, i).is_err());
                i.owner.thread += 4096;
                assert!(s.plan(Operation::Release { new_irql: 0 }, i).is_err());
            }
            assert!(s.require_release(0x10000, 4096).is_err());
            assert!(s.require_lower(input(arch, 0, 0, 0).owner, 0).is_err());
            assert!(s.require_exit(input(arch, 0, 0, 0).owner).is_err());
            assert_eq!(serde_json::to_value(&s).unwrap(), before);
        }
    }
    #[test]
    fn retirement_quota_and_failed_native_attempt_do_not_mint_new_ownership() {
        let arch = Architecture::X64;
        let mut s = State::default();
        apply(&mut s, Operation::Initialize, input(arch, 0x10000, 0, 0));
        s.retire(0x10000, 4096).unwrap();
        assert!(
            s.plan(Operation::Acquire, input(arch, 0x10000, 0, 0))
                .is_err()
        );
        apply(&mut s, Operation::Initialize, input(arch, 0x10000, 0, 0));
        let p = s
            .plan(Operation::Acquire, input(arch, 0x10000, 0, 0))
            .unwrap();
        s.begin(p.attempt);
        assert!(s.ready().is_err());
        assert_eq!(s.held().count(), 0);
        assert!(!s.last_attempt.unwrap().completed);
        let mut q = State {
            initializations: INITIALIZATION_LIMIT,
            ..State::default()
        };
        assert!(
            q.plan(Operation::Initialize, input(arch, 0x20000, 0, 0))
                .is_err()
        );
        q.initializations = 0;
        for n in 0..RECORD_LIMIT {
            q.records.insert(
                0x10000 + n as u64 * 8,
                Record {
                    address: 0x10000 + n as u64 * 8,
                    width: 8,
                    backing: input(arch, 0, 0, 0).backing,
                    initialization: 1,
                    live: true,
                    held: None,
                },
            );
        }
        assert!(
            q.plan(Operation::Initialize, input(arch, 0x30000, 0, 0))
                .is_err()
        );
    }
}

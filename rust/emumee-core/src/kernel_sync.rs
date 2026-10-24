//! Bounded legacy pointer-word synchronization, not a dispatcher or owner map.
//! The caller supplies actual guest memory and publishes each checked effect.
use crate::pe::Architecture;
use thiserror::Error;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    RundownInitialize,
    RundownAcquire,
    RundownRelease,
    RundownWait,
    PushInitialize,
    PushAcquire,
    PushRelease,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Blocked {
    Rundown,
    PushLock,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Effect {
    pub write: Option<u64>,
    pub result: u64,
    pub blocked: Option<Blocked>,
}
#[derive(Debug, Error)]
#[error("Guest bounded synchronization: {0}")]
pub struct SyncError(pub &'static str);
pub fn transition(
    architecture: Architecture,
    operation: Operation,
    value: u64,
    flags: u64,
) -> Result<Effect, SyncError> {
    use Operation::*;
    let maximum = if architecture == Architecture::X64 {
        u64::MAX
    } else {
        u32::MAX as u64
    };
    if value > maximum {
        return Err(SyncError("word exceeds guest pointer width"));
    }
    if matches!(operation, PushAcquire | PushRelease) && flags as u32 != 0 {
        return Err(SyncError("Unsupported push-lock flags"));
    }
    let mut effect = Effect {
        write: None,
        result: 0,
        blocked: None,
    };
    match operation {
        RundownInitialize | PushInitialize => effect.write = Some(0),
        RundownAcquire => {
            if value & 1 == 0 {
                if value > maximum - 2 {
                    return Err(SyncError("Rundown reference count overflow"));
                }
                effect.write = Some(value + 2);
                effect.result = 1;
            }
        }
        RundownRelease => {
            if value < 2 {
                return Err(SyncError("Rundown release without a reference"));
            }
            effect.write = Some(value - 2);
        }
        RundownWait => {
            effect.write = Some(value | 1);
            if value > 1 {
                effect.blocked = Some(Blocked::Rundown);
            }
        }
        PushAcquire => {
            if value == 0 {
                effect.write = Some(1);
            } else {
                effect.blocked = Some(Blocked::PushLock);
            }
        }
        PushRelease => {
            if value != 1 {
                return Err(SyncError(
                    "Exclusive push-lock release without exclusive ownership",
                ));
            }
            effect.write = Some(0);
        }
    }
    Ok(effect)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rundown_real_words_preserve_reference_pending_and_blocked_effects() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut value = transition(arch, Operation::RundownInitialize, 55, 0)
                .unwrap()
                .write
                .unwrap();
            for expected in [2, 4] {
                let e = transition(arch, Operation::RundownAcquire, value, 0).unwrap();
                assert_eq!(e.result, 1);
                value = e.write.unwrap();
                assert_eq!(value, expected);
            }
            let waiting = transition(arch, Operation::RundownWait, value, 0).unwrap();
            assert_eq!(waiting.write, Some(5));
            assert_eq!(waiting.blocked, Some(Blocked::Rundown));
            value = waiting.write.unwrap();
            assert_eq!(
                transition(arch, Operation::RundownAcquire, value, 0).unwrap(),
                Effect {
                    write: None,
                    result: 0,
                    blocked: None
                }
            );
            for expected in [3, 1] {
                value = transition(arch, Operation::RundownRelease, value, 0)
                    .unwrap()
                    .write
                    .unwrap();
                assert_eq!(value, expected);
            }
            assert_eq!(
                transition(arch, Operation::RundownWait, value, 0)
                    .unwrap()
                    .blocked,
                None
            );
            assert!(transition(arch, Operation::RundownRelease, value, 0).is_err());
            let max = if arch == Architecture::X64 {
                u64::MAX
            } else {
                u32::MAX as u64
            };
            assert!(transition(arch, Operation::RundownAcquire, max - 1, 0).is_err());
            assert_eq!(
                transition(arch, Operation::RundownAcquire, max, 0)
                    .unwrap()
                    .result,
                0
            );
        }
        assert!(
            transition(
                Architecture::X86,
                Operation::RundownInitialize,
                1u64 << 32,
                0
            )
            .is_err()
        );
    }
    #[test]
    fn push_words_never_grant_contention_or_accept_shared_state() {
        for arch in [Architecture::X86, Architecture::X64] {
            assert_eq!(
                transition(arch, Operation::PushInitialize, 7, 0)
                    .unwrap()
                    .write,
                Some(0)
            );
            assert_eq!(
                transition(arch, Operation::PushAcquire, 0, 0)
                    .unwrap()
                    .write,
                Some(1)
            );
            for value in [1, 2, 3, 8] {
                let e = transition(arch, Operation::PushAcquire, value, 0).unwrap();
                assert_eq!(e.write, None);
                assert_eq!(e.blocked, Some(Blocked::PushLock));
            }
            assert_eq!(
                transition(arch, Operation::PushRelease, 1, 0)
                    .unwrap()
                    .write,
                Some(0)
            );
            assert!(transition(arch, Operation::PushRelease, 2, 0).is_err());
            for op in [Operation::PushAcquire, Operation::PushRelease] {
                assert!(transition(arch, op, 1, 1).is_err());
                assert!(transition(arch, op, 1, 1u64 << 32).is_ok());
            }
        }
    }
}

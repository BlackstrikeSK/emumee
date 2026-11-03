//! Owned six-entry kernel AutoBoost blocks and stable exclusive push locks.
//! Plans cover data effects only. The native adapter owns actual backing,
//! lifetimes, interrupts/ABI and journaled publication; unsupported cold paths
//! are never replaced with an acquired lock or a synthetic waiter.
use super::{ENTRY_BYTES, HEADER_BYTES, Inputs, initialize};
use crate::{
    kernel_spin::Backing,
    kernel_thread_objects::{Lifetime, Ownership},
};
use serde::Serialize;
use std::collections::BTreeMap;
use thiserror::Error;

pub const KERNEL_ENTRY_COUNT: usize = 6;
pub const BLOCK_BYTES: usize = HEADER_BYTES + KERNEL_ENTRY_COUNT * ENTRY_BYTES;
pub const BLOCK_PAGE_OFFSET: u64 = 0x800;
const LOCK_MASK: u64 = 0x7fff_ffff_ffff_fffc;
const RECORD_LIMIT: usize = 4096;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("Owned kernel AutoBoost: {0}")]
pub struct Error(pub &'static str);
type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug, Serialize)]
pub struct Thread {
    pub address: u64,
    pub slot: u64,
    pub guest_id: u64,
    pub owner_process: u64,
    pub block: u64,
    pub bytes: Vec<u8>,
    pub live: bool,
    pub exited: bool,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct Held {
    pub thread: u64,
    pub entry: u8,
}

#[derive(Clone, Debug, Serialize)]
pub struct Lock {
    pub address: u64,
    pub backing: Backing,
    pub initialization: u64,
    pub live: bool,
    pub held: Option<Held>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct State {
    pub threads: BTreeMap<u64, Thread>,
    pub locks: BTreeMap<u64, Lock>,
    pub transitions: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Write {
    pub address: u64,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
    pub kind: &'static str,
}

#[derive(Clone, Copy, Debug)]
pub struct Input {
    pub thread: u64,
    pub address: u64,
    pub word: u64,
    pub backing: Backing,
    pub flags: u32,
    /// Explicit observation, never an unknown-to-zero default.
    pub work_priority_kick: Option<u64>,
    /// A caller contract observation; native stable data paths do not read it.
    /// The adapter decides whether its complete execution profile supports it.
    pub normal_apcs_disabled: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Plan {
    pub state: State,
    pub writes: Vec<Write>,
    pub operation: &'static str,
    pub thread: u64,
    pub lock: u64,
    pub entry_address: Option<u64>,
    pub normal_apcs_disabled: bool,
    pub enables_interrupts: bool,
}

fn overlap(a: u64, n: u64, b: u64, m: u64) -> bool {
    a.checked_add(n).is_none_or(|end| b < end) && b.checked_add(m).is_none_or(|end| a < end)
}

fn range(backing: Backing, address: u64) -> Result<()> {
    let canonical = |a: u64| a >> 48 == if a & (1 << 47) != 0 { 0xffff } else { 0 };
    if !canonical(address) || address.checked_add(7).is_none_or(|end| !canonical(end)) {
        return Err(Error("noncanonical exclusive push word"));
    }
    let (base, size) = match backing {
        Backing::Image { base, size } => (base, size),
        Backing::NonpagedPool {
            base,
            requested,
            mapped,
        } => {
            if requested > mapped {
                return Err(Error("pool requested extent exceeds mapped backing"));
            }
            (base, requested)
        }
    };
    if address == 0
        || address & 7 != 0
        || address < base
        || address
            .checked_add(8)
            .is_none_or(|end| base.checked_add(size).is_none_or(|limit| end > limit))
    {
        return Err(Error("unaligned or out-of-backing push word"));
    }
    Ok(())
}

fn write(address: u64, before: &[u8], after: &[u8], kind: &'static str) -> Write {
    Write {
        address,
        before: before.to_vec(),
        after: after.to_vec(),
        kind,
    }
}

impl State {
    /// A separate known allocation inside the exclusively owned synthetic
    /// thread page, not an assertion about Windows' variable tail offset.
    /// Only the new block is zero allocated; no opaque KTHREAD words are read
    /// or defaulted. Source180 supplies its exact initialization transform.
    pub fn register_thread(&self, life: &Lifetime) -> Result<Self> {
        if !life.executing
            || life.terminated
            || life.retired
            || !matches!(
                life.role,
                Ownership::InitialCaller | Ownership::CreatedSystemThread
            )
            || life.address < 0xffff_8000_0000_0000
            || life.address & 0xfff != 0
            || !(1..=64).contains(&life.slot)
            || life.guest_id == 0
            || life.owner == 0
            || (life.root_caller != matches!(life.role, Ownership::InitialCaller))
            || self.threads.contains_key(&life.address)
            || self.threads.len() >= 64
        {
            return Err(Error(
                "thread registration lacks a fresh owned ordinary lifetime",
            ));
        }
        let block = life
            .address
            .checked_add(BLOCK_PAGE_OFFSET)
            .ok_or(Error("thread block address overflow"))?;
        let page_end = life
            .address
            .checked_add(4096)
            .ok_or(Error("thread page address overflow"))?;
        if block
            .checked_add(BLOCK_BYTES as u64)
            .is_none_or(|end| end > page_end)
        {
            return Err(Error("AutoBoost allocation escapes its owned page"));
        }
        let mut bytes = vec![0; BLOCK_BYTES];
        bytes[..8].copy_from_slice(&life.address.to_le_bytes());
        bytes[12] = KERNEL_ENTRY_COUNT as u8;
        // MiscFlags is not projected here. Only the block result is consumed;
        // no value is chosen for the unknown complete KTHREAD MiscFlags word.
        let bytes = initialize(&Inputs {
            misc_flags: 0,
            kernel_entries: bytes,
            user_entries: None,
        })
        .map_err(|_| Error("owned six-entry initializer failed"))?
        .kernel_entries;
        let mut next = self.clone();
        next.threads.insert(
            life.address,
            Thread {
                address: life.address,
                slot: life.slot,
                guest_id: life.guest_id,
                owner_process: life.owner,
                block,
                bytes,
                live: true,
                exited: false,
            },
        );
        Ok(next)
    }

    fn thread(&self, address: u64) -> Result<&Thread> {
        self.threads
            .get(&address)
            .filter(|t| t.live && !t.exited)
            .ok_or(Error("unknown, exited or retired AutoBoost thread"))
    }

    pub fn require_thread_exit(&self, address: u64) -> Result<()> {
        if self
            .locks
            .values()
            .any(|r| r.live && r.held.is_some_and(|h| h.thread == address))
        {
            return Err(Error("thread exit while holding an exclusive push lock"));
        }
        Ok(())
    }

    pub fn finish_thread(&self, life: &Lifetime) -> Result<Self> {
        self.require_thread_exit(life.address)?;
        let current = self
            .threads
            .get(&life.address)
            .ok_or(Error("unknown AutoBoost lifetime"))?;
        if current.slot != life.slot
            || current.guest_id != life.guest_id
            || current.owner_process != life.owner
        {
            return Err(Error("thread lifetime identity changed"));
        }
        let mut next = self.clone();
        let t = next.threads.get_mut(&life.address).unwrap();
        t.exited = life.terminated;
        t.live = !life.retired;
        Ok(next)
    }

    pub fn overlaps(&self, base: u64, size: u64) -> bool {
        self.locks
            .values()
            .any(|r| r.live && overlap(base, size, r.address, 8))
    }

    pub fn require_release(&self, base: u64, size: u64) -> Result<()> {
        if self
            .locks
            .values()
            .any(|r| r.live && r.held.is_some() && overlap(base, size, r.address, 8))
        {
            return Err(Error("backing release overlaps a held exclusive push lock"));
        }
        Ok(())
    }

    pub fn retire_backing(&self, base: u64, size: u64) -> Result<Self> {
        self.require_release(base, size)?;
        let mut next = self.clone();
        for r in next.locks.values_mut() {
            if r.live && overlap(base, size, r.address, 8) {
                r.live = false;
            }
        }
        Ok(next)
    }

    pub fn initialize_lock(&self, input: Input) -> Result<Plan> {
        self.thread(input.thread)?;
        range(input.backing, input.address)?;
        if self
            .locks
            .get(&input.address)
            .is_some_and(|r| r.live && r.held.is_some())
        {
            return Err(Error("reinitialization of a held exclusive push lock"));
        }
        if !self.locks.contains_key(&input.address) && self.locks.len() >= RECORD_LIMIT {
            return Err(Error("push-lock record limit exceeded"));
        }
        let mut next = self.clone();
        let initialization = self
            .locks
            .get(&input.address)
            .map_or(1, |r| r.initialization + 1);
        if initialization > 65_536 {
            return Err(Error("push-lock initialization limit exceeded"));
        }
        next.locks.insert(
            input.address,
            Lock {
                address: input.address,
                backing: input.backing,
                initialization,
                live: true,
                held: None,
            },
        );
        next.transitions += 1;
        Ok(Plan {
            state: next,
            writes: vec![write(
                input.address,
                &input.word.to_le_bytes(),
                &0u64.to_le_bytes(),
                "push_initialize",
            )],
            operation: "initialize",
            thread: input.thread,
            lock: input.address,
            entry_address: None,
            normal_apcs_disabled: input.normal_apcs_disabled,
            enables_interrupts: false,
        })
    }

    fn checked(&self, input: Input) -> Result<(&Thread, &Lock)> {
        let thread = self.thread(input.thread)?;
        range(input.backing, input.address)?;
        if input.flags != 0 {
            return Err(Error(
                "nonzero push flags require a separate native profile",
            ));
        }
        match input.work_priority_kick {
            Some(0) => {}
            Some(_) => return Err(Error("scheduler priority-kick path is not qualified")),
            None => return Err(Error("scheduler priority-kick state is unknown")),
        }
        let lock = self
            .locks
            .get(&input.address)
            .filter(|r| r.live)
            .ok_or(Error("push lock was not initialized in live owned backing"))?;
        if lock.backing != input.backing {
            return Err(Error("push-lock backing lifetime changed"));
        }
        if input.word != u64::from(lock.held.is_some()) {
            return Err(Error("actual push word diverged from owned state"));
        }
        Ok((thread, lock))
    }

    pub fn acquire(&self, input: Input) -> Result<Plan> {
        let (thread, lock) = self.checked(input)?;
        if let Some(held) = lock.held {
            return Err(Error(if held.thread == input.thread {
                "recursive push-lock acquisition"
            } else {
                "contended push lock requires native waiter/boost scheduling"
            }));
        }
        let bitmap = u16::from_le_bytes(thread.bytes[8..10].try_into().unwrap());
        if bitmap == 0 {
            return Err(Error(
                "AutoBoost entry exhaustion requires native flag/trace effects",
            ));
        }
        let index = bitmap.trailing_zeros() as usize;
        if index >= KERNEL_ENTRY_COUNT {
            return Err(Error("available bitmap names an unowned entry"));
        }
        let at = HEADER_BYTES + index * ENTRY_BYTES;
        if thread.bytes[at..at + ENTRY_BYTES]
            .iter()
            .enumerate()
            .any(|(i, b)| *b != if i == 8 { index as u8 } else { 0 })
        {
            return Err(Error(
                "available entry is not the qualified fresh/unboosted state",
            ));
        }
        let mut next = self.clone();
        let target = next.threads.get_mut(&input.thread).unwrap();
        let available = bitmap & !(1 << index);
        let state = input.address & LOCK_MASK;
        let entry_address = thread.block + at as u64;
        let writes = vec![
            write(
                thread.block + 8,
                &thread.bytes[8..10],
                &available.to_le_bytes(),
                "reserve_available_entry",
            ),
            write(
                entry_address,
                &thread.bytes[at..at + 8],
                &state.to_le_bytes(),
                "entry_lock_state",
            ),
            write(
                input.address,
                &input.word.to_le_bytes(),
                &1u64.to_le_bytes(),
                "push_bts",
            ),
            write(
                entry_address + 10,
                &thread.bytes[at + 10..at + 11],
                &[1],
                "entry_acquired",
            ),
        ];
        target.bytes[8..10].copy_from_slice(&available.to_le_bytes());
        target.bytes[at..at + 8].copy_from_slice(&state.to_le_bytes());
        target.bytes[at + 10] = 1;
        next.locks.get_mut(&input.address).unwrap().held = Some(Held {
            thread: input.thread,
            entry: index as u8,
        });
        next.transitions += 1;
        Ok(Plan {
            state: next,
            writes,
            operation: "acquire",
            thread: input.thread,
            lock: input.address,
            entry_address: Some(entry_address),
            normal_apcs_disabled: input.normal_apcs_disabled,
            enables_interrupts: true,
        })
    }

    pub fn release(&self, input: Input) -> Result<Plan> {
        let (thread, lock) = self.checked(input)?;
        let held = lock.held.filter(|h| h.thread == input.thread).ok_or(Error(
            "exclusive push-lock release lacks current-thread ownership",
        ))?;
        let index = usize::from(held.entry);
        let at = HEADER_BYTES + index * ENTRY_BYTES;
        let entry = &thread.bytes[at..at + ENTRY_BYTES];
        let raw = u64::from_le_bytes(entry[..8].try_into().unwrap());
        if raw != input.address & LOCK_MASK
            || entry[10] != 1
            || entry[9] != 0
            || entry[0] & 1 != 0
            || raw >> 63 != 0
            || entry[0x50..0x54] != [0; 4]
        {
            return Err(Error(
                "native entry release needs an unqualified tree/boost/cross-thread path",
            ));
        }
        let bitmap = u16::from_le_bytes(thread.bytes[8..10].try_into().unwrap());
        if bitmap & (1 << index) != 0 {
            return Err(Error("held entry is already available"));
        }
        // Native SHL AL,CL emits a byte mask. The qualified producer has six
        // entries, so all its indexes fit; do not generalize this to 16 slots.
        let available = bitmap | u16::from(1u8 << index);
        let entry_address = thread.block + at as u64;
        let writes = vec![
            write(
                input.address,
                &input.word.to_le_bytes(),
                &0u64.to_le_bytes(),
                "push_xadd",
            ),
            write(
                entry_address + 10,
                &entry[10..11],
                &[0],
                "entry_not_acquired",
            ),
            write(
                entry_address + 0x50,
                &entry[0x50..0x54],
                &[0; 4],
                "entry_clear_boosts",
            ),
            write(entry_address + 9, &entry[9..10], &[0], "entry_not_waiting"),
            write(
                entry_address,
                &entry[..8],
                &0u64.to_le_bytes(),
                "entry_clear_lock",
            ),
            write(
                thread.block + 8,
                &thread.bytes[8..10],
                &available.to_le_bytes(),
                "return_available_entry",
            ),
        ];
        let mut next = self.clone();
        let target = next.threads.get_mut(&input.thread).unwrap();
        target.bytes[at..at + 8].fill(0);
        target.bytes[at + 9] = 0;
        target.bytes[at + 10] = 0;
        target.bytes[at + 0x50..at + 0x54].fill(0);
        target.bytes[8..10].copy_from_slice(&available.to_le_bytes());
        next.locks.get_mut(&input.address).unwrap().held = None;
        next.transitions += 1;
        Ok(Plan {
            state: next,
            writes,
            operation: "release",
            thread: input.thread,
            lock: input.address,
            entry_address: Some(entry_address),
            normal_apcs_disabled: input.normal_apcs_disabled,
            enables_interrupts: true,
        })
    }
}

#[cfg(test)]
mod tests;

//! Process-owned Win32 slots and critical-section state. No host handles/locks.
use std::collections::BTreeMap;
pub const MAX_TLS: usize = 1088;
pub const MAX_FLS: usize = 128;
#[derive(Default)]
pub struct Slots {
    tls: Vec<Option<BTreeMap<u64, u64>>>,
    fls: Vec<Option<BTreeMap<u64, u64>>>,
}
impl Slots {
    pub fn allocate(&mut self, fiber: bool) -> Option<u32> {
        let slots = if fiber { &mut self.fls } else { &mut self.tls };
        let index = slots
            .iter()
            .position(Option::is_none)
            .unwrap_or(slots.len());
        if index >= if fiber { MAX_FLS } else { MAX_TLS } {
            return None;
        }
        if index == slots.len() {
            slots.push(Some(BTreeMap::new()));
        } else {
            slots[index] = Some(BTreeMap::new());
        }
        Some(index as u32)
    }
    pub fn free(&mut self, fiber: bool, index: u32) -> bool {
        let slots = if fiber { &mut self.fls } else { &mut self.tls };
        match slots.get_mut(index as usize) {
            Some(slot) if slot.is_some() => {
                *slot = None;
                true
            }
            _ => false,
        }
    }
    pub fn set(&mut self, fiber: bool, index: u32, thread: u64, value: u64) -> bool {
        let slots = if fiber { &mut self.fls } else { &mut self.tls };
        if let Some(Some(values)) = slots.get_mut(index as usize) {
            values.insert(thread, value);
            true
        } else {
            false
        }
    }
    pub fn get(&self, fiber: bool, index: u32, thread: u64) -> Option<u64> {
        let slots = if fiber { &self.fls } else { &self.tls };
        slots
            .get(index as usize)?
            .as_ref()
            .map(|values| values.get(&thread).copied().unwrap_or(0))
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CriticalSection {
    pub owner: Option<u64>,
    pub recursion: u32,
    pub spin: u32,
}
impl CriticalSection {
    pub fn enter(&mut self, thread: u64) -> Result<bool, &'static str> {
        if self.owner.is_some_and(|owner| owner != thread) {
            return Ok(false);
        }
        self.recursion = self
            .recursion
            .checked_add(1)
            .ok_or("Critical-section recursion overflow")?;
        self.owner = Some(thread);
        Ok(true)
    }
    pub fn leave(&mut self, thread: u64) -> Result<(), &'static str> {
        if self.owner != Some(thread) || self.recursion == 0 {
            return Err("Critical section released by nonowner");
        }
        self.recursion -= 1;
        if self.recursion == 0 {
            self.owner = None;
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn user_slots_are_thread_local_and_freed_indices_are_reused_without_stale_values() {
        let mut slots = Slots::default();
        for fiber in [false, true] {
            let id = slots.allocate(fiber).unwrap();
            assert_eq!(slots.get(fiber, id, 1), Some(0));
            assert!(slots.set(fiber, id, 1, 0x1234));
            assert_eq!(slots.get(fiber, id, 2), Some(0));
            assert!(slots.free(fiber, id));
            assert_eq!(slots.get(fiber, id, 1), None);
            assert!(!slots.set(fiber, id, 1, 1));
            assert_eq!(slots.allocate(fiber), Some(id));
            assert_eq!(slots.get(fiber, id, 1), Some(0));
        }
    }
    #[test]
    fn critical_sections_track_recursive_ownership_without_stealing_a_contended_lock() {
        let mut cs = CriticalSection::default();
        assert_eq!(cs.enter(1), Ok(true));
        assert_eq!(cs.enter(1), Ok(true));
        let before = cs.clone();
        assert_eq!(cs.enter(2), Ok(false));
        assert_eq!(cs, before);
        assert!(cs.leave(2).is_err());
        cs.leave(1).unwrap();
        assert_eq!(cs.owner, Some(1));
        cs.leave(1).unwrap();
        assert_eq!(cs.owner, None);
    }
}

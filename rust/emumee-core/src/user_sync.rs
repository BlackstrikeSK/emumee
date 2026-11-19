//! Deterministic process-owned dispatcher objects. No host synchronization.
use std::collections::BTreeMap;

pub const MAX_OBJECTS: usize = 256;
pub const MAX_HANDLES: usize = 1024;
pub const MAX_WAIT: usize = 64;
pub const TIMEOUT: u32 = 0x102;
pub const FAILED: u32 = u32::MAX;
const HANDLE_FIRST: u64 = 0x6e000000;
const HANDLE_LIMIT: u64 = 0x6f000000;
const HANDLE_SLOTS: u64 = (HANDLE_LIMIT - HANDLE_FIRST) / 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Object {
    Event {
        manual: bool,
        signaled: bool,
    },
    Mutex {
        owner: Option<u64>,
        recursion: u32,
        abandoned: bool,
    },
    Semaphore {
        count: u32,
        maximum: u32,
    },
}
#[derive(Default)]
pub struct Dispatcher {
    objects: BTreeMap<u64, Object>,
    handles: BTreeMap<u64, u64>,
    metadata: BTreeMap<u64, (u32, u32)>,
    names: BTreeMap<String, u64>,
    next: u64,
}
impl Dispatcher {
    pub fn create(&mut self, object: Object, name: Option<String>) -> Result<(u64, bool), u32> {
        if self.handles.len() >= MAX_HANDLES {
            return Err(8);
        }
        if let Some(id) = name.as_ref().and_then(|n| self.names.get(n)).copied() {
            if std::mem::discriminant(&self.objects[&id]) != std::mem::discriminant(&object) {
                return Err(6);
            }
            return Ok((self.handle(id)?, true));
        }
        if self.objects.len() >= MAX_OBJECTS {
            return Err(8);
        }
        self.preflight_handles(2)?;
        self.next += 1;
        let id = self.next;
        self.objects.insert(id, object);
        if let Some(name) = name {
            self.names.insert(name, id);
        }
        Ok((self.handle(id)?, false))
    }
    fn preflight_handles(&self, count: u64) -> Result<(), u32> {
        self.next
            .checked_add(count)
            .filter(|next| *next < HANDLE_SLOTS)
            .map(|_| ())
            .ok_or(8)
    }
    fn handle(&mut self, id: u64) -> Result<u64, u32> {
        self.preflight_handles(1)?;
        self.next += 1;
        let handle = HANDLE_FIRST + self.next * 4;
        self.handles.insert(handle, id);
        self.metadata.insert(handle, (0x1fffff, 0));
        Ok(handle)
    }
    pub fn duplicate(&mut self, handle: u64) -> Result<u64, u32> {
        let id = *self.handles.get(&handle).ok_or(6u32)?;
        if self.handles.len() >= MAX_HANDLES {
            return Err(8);
        }
        let access = self.metadata[&handle].0;
        let new = self.handle(id)?;
        self.metadata.insert(new, (access, 0));
        Ok(new)
    }
    pub fn access(&self, handle: u64, desired: u32) -> Result<(), u32> {
        let (access, _) = self.metadata.get(&handle).ok_or(6u32)?;
        if access & desired != desired {
            return Err(5);
        }
        Ok(())
    }
    pub fn flags(&self, handle: u64) -> Result<u32, u32> {
        self.metadata.get(&handle).map(|(_, f)| *f).ok_or(6)
    }
    pub fn set_flags(&mut self, handle: u64, mask: u32, flags: u32) -> Result<(), u32> {
        if mask & !3 != 0 || flags & !3 != 0 {
            return Err(87);
        }
        let (_, current) = self.metadata.get_mut(&handle).ok_or(6u32)?;
        *current = (*current & !mask) | (flags & mask);
        Ok(())
    }
    pub fn restrict(&mut self, handle: u64, desired: u32) -> Result<(), u32> {
        let (access, _) = self.metadata.get_mut(&handle).ok_or(6u32)?;
        if desired & !*access != 0 {
            return Err(5);
        }
        *access = desired;
        Ok(())
    }
    pub fn duplicate_access(
        &mut self,
        handle: u64,
        desired: Option<u32>,
        inherit: bool,
    ) -> Result<u64, u32> {
        let (access, _) = *self.metadata.get(&handle).ok_or(6u32)?;
        let desired = desired.unwrap_or(access);
        if desired & !access != 0 {
            return Err(5);
        }
        let new = self.duplicate(handle)?;
        self.metadata.insert(new, (desired, u32::from(inherit)));
        Ok(new)
    }
    pub fn close_checked(&mut self, handle: u64) -> Result<bool, u32> {
        if self.metadata.get(&handle).is_some_and(|(_, f)| f & 2 != 0) {
            return Err(5);
        }
        Ok(self.close(handle))
    }
    pub fn open(&mut self, name: &str, kind: &Object) -> Result<u64, u32> {
        let id = *self.names.get(name).ok_or(2u32)?;
        if std::mem::discriminant(&self.objects[&id]) != std::mem::discriminant(kind) {
            return Err(6);
        }
        if self.handles.len() >= MAX_HANDLES {
            return Err(8);
        }
        self.handle(id)
    }
    pub fn owns(&self, handle: u64) -> bool {
        self.handles.contains_key(&handle)
    }
    pub fn close(&mut self, handle: u64) -> bool {
        let Some(id) = self.handles.remove(&handle) else {
            return false;
        };
        self.metadata.remove(&handle);
        if !self.handles.values().any(|v| *v == id) {
            self.objects.remove(&id);
            self.names.retain(|_, v| *v != id);
        }
        true
    }
    pub fn object_mut(&mut self, handle: u64) -> Result<&mut Object, u32> {
        let id = self.handles.get(&handle).ok_or(6u32)?;
        self.objects.get_mut(id).ok_or(6)
    }
    pub fn event(&mut self, handle: u64, set: bool) -> Result<(), u32> {
        self.access(handle, 2)?;
        match self.object_mut(handle)? {
            Object::Event { signaled, .. } => {
                *signaled = set;
                Ok(())
            }
            _ => Err(6),
        }
    }
    pub fn release_mutex(&mut self, handle: u64, thread: u64) -> Result<(), u32> {
        self.access(handle, 1)?;
        match self.object_mut(handle)? {
            Object::Mutex {
                owner, recursion, ..
            } if *owner == Some(thread) => {
                *recursion -= 1;
                if *recursion == 0 {
                    *owner = None;
                }
                Ok(())
            }
            Object::Mutex { .. } => Err(288),
            _ => Err(6),
        }
    }
    pub fn release_semaphore(&mut self, handle: u64, amount: u32) -> Result<u32, u32> {
        self.access(handle, 2)?;
        match self.object_mut(handle)? {
            Object::Semaphore { count, maximum } => {
                let next = count
                    .checked_add(amount)
                    .filter(|n| amount != 0 && *n <= *maximum)
                    .ok_or(298u32)?;
                let previous = *count;
                *count = next;
                Ok(previous)
            }
            _ => Err(6),
        }
    }
    pub fn abandon(&mut self, thread: u64) {
        for object in self.objects.values_mut() {
            if let Object::Mutex {
                owner,
                recursion,
                abandoned,
            } = object
                && *owner == Some(thread)
            {
                *owner = None;
                *recursion = 0;
                *abandoned = true;
            }
        }
    }
    /// External readiness is used for immutable signaled thread/process objects.
    /// Validate the entire set before acquiring anything; WaitAll is atomic.
    pub fn wait(
        &mut self,
        handles: &[u64],
        all: bool,
        thread: u64,
        external: &BTreeMap<u64, bool>,
    ) -> Result<Option<u32>, u32> {
        if handles.is_empty() || handles.len() > MAX_WAIT {
            return Err(87);
        }
        let mut identities = Vec::new();
        let mut ready = Vec::new();
        for handle in handles {
            if let Some(id) = self.handles.get(handle) {
                self.access(*handle, 0x100000)?;
                if identities.contains(id) {
                    return Err(87);
                }
                identities.push(*id);
                let object = &self.objects[id];
                ready.push(match object {
                    Object::Event { signaled, .. } => *signaled,
                    Object::Mutex {
                        owner, recursion, ..
                    } => {
                        if *owner == Some(thread) && *recursion == u32::MAX {
                            return Err(8);
                        }
                        owner.is_none() || *owner == Some(thread)
                    }
                    Object::Semaphore { count, .. } => *count != 0,
                });
            } else {
                if handles.iter().filter(|h| *h == handle).count() != 1 {
                    return Err(87);
                }
                ready.push(*external.get(handle).ok_or(6u32)?);
            }
        }
        let selected = if all {
            if !ready.iter().all(|v| *v) {
                return Ok(None);
            }
            (0..handles.len()).collect::<Vec<_>>()
        } else {
            let Some(index) = ready.iter().position(|v| *v) else {
                return Ok(None);
            };
            vec![index]
        };
        let mut abandoned = None;
        for index in &selected {
            if let Some(id) = self.handles.get(&handles[*index]) {
                match self.objects.get_mut(id).unwrap() {
                    Object::Event { manual, signaled } => {
                        if !*manual {
                            *signaled = false;
                        }
                    }
                    Object::Mutex {
                        owner,
                        recursion,
                        abandoned: flag,
                    } => {
                        *owner = Some(thread);
                        *recursion += 1;
                        if *flag {
                            abandoned.get_or_insert(*index);
                            *flag = false;
                        }
                    }
                    Object::Semaphore { count, .. } => *count -= 1,
                }
            }
        }
        Ok(Some(
            abandoned.map_or(if all { 0 } else { selected[0] as u32 }, |i| {
                0x80 + i as u32
            }),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn handle_issuance_exhaustion_never_crosses_namespaces_or_publishes_partial_objects() {
        let mut dispatcher = Dispatcher {
            next: HANDLE_SLOTS - 3,
            ..Default::default()
        };
        let kind = Object::Event {
            manual: false,
            signaled: true,
        };
        let (handle, _) = dispatcher
            .create(kind.clone(), Some("last".into()))
            .unwrap();
        assert_eq!(handle, HANDLE_LIMIT - 4);
        assert_eq!(dispatcher.create(kind.clone(), Some("new".into())), Err(8));
        assert_eq!(dispatcher.create(kind.clone(), Some("last".into())), Err(8));
        assert_eq!(dispatcher.open("last", &kind), Err(8));
        assert_eq!(dispatcher.duplicate(handle), Err(8));
        assert_eq!(dispatcher.objects.len(), 1);
        assert_eq!(dispatcher.handles.len(), 1);
        assert_eq!(dispatcher.names.len(), 1);
        assert_eq!(
            dispatcher.wait(&[handle], false, 1, &BTreeMap::new()),
            Ok(Some(0))
        );
        dispatcher.next = u64::MAX;
        assert_eq!(dispatcher.create(kind, None), Err(8));
        assert_eq!(dispatcher.handles.len(), 1);
        assert!(dispatcher.close(handle));
    }
    #[test]
    fn wait_all_rolls_back_consumption_and_aliases_cannot_acquire_twice() {
        let mut d = Dispatcher::default();
        let (a, _) = d
            .create(
                Object::Semaphore {
                    count: 1,
                    maximum: 2,
                },
                None,
            )
            .unwrap();
        let (b, _) = d
            .create(
                Object::Event {
                    manual: false,
                    signaled: false,
                },
                None,
            )
            .unwrap();
        let e = BTreeMap::new();
        assert_eq!(d.wait(&[a, b], true, 1, &e), Ok(None));
        assert_eq!(d.wait(&[a], false, 1, &e), Ok(Some(0)));
        assert_eq!(d.wait(&[a], false, 1, &e), Ok(None));
        let alias = d.duplicate(a).unwrap();
        assert_eq!(d.wait(&[a, alias], true, 1, &e), Err(87));
    }
    #[test]
    fn dispatcher_handles_preserve_access_and_independent_flags() {
        let mut d = Dispatcher::default();
        let (h, _) = d
            .create(
                Object::Event {
                    manual: false,
                    signaled: true,
                },
                None,
            )
            .unwrap();
        let alias = d.duplicate_access(h, Some(0x100000), true).unwrap();
        assert_eq!(d.flags(alias), Ok(1));
        assert_eq!(d.event(alias, false), Err(5));
        assert_eq!(d.duplicate_access(alias, Some(0x1fffff), false), Err(5));
        d.set_flags(h, 2, 2).unwrap();
        assert_eq!(d.close_checked(h), Err(5));
        assert_eq!(d.wait(&[alias], false, 1, &BTreeMap::new()), Ok(Some(0)));
        d.set_flags(h, 2, 0).unwrap();
        assert_eq!(d.close_checked(h), Ok(true));
        assert_eq!(d.wait(&[alias], false, 1, &BTreeMap::new()), Ok(None));
        let denied = d.duplicate_access(alias, Some(0), false).unwrap();
        assert_eq!(d.wait(&[denied], false, 1, &BTreeMap::new()), Err(5));
        assert_eq!(d.close_checked(alias), Ok(true));
        assert_eq!(d.close_checked(denied), Ok(true));
    }
    #[test]
    fn mutex_recursion_abandonment_and_named_object_lifetime() {
        let mut d = Dispatcher::default();
        let kind = Object::Mutex {
            owner: None,
            recursion: 0,
            abandoned: false,
        };
        let (a, exists) = d.create(kind.clone(), Some("guard".into())).unwrap();
        assert!(!exists);
        let (b, exists) = d.create(kind, Some("guard".into())).unwrap();
        assert!(exists);
        let e = BTreeMap::new();
        assert_eq!(d.wait(&[a], false, 1, &e), Ok(Some(0)));
        assert_eq!(d.wait(&[b], false, 1, &e), Ok(Some(0)));
        assert_eq!(d.wait(&[b], false, 2, &e), Ok(None));
        assert_eq!(d.release_mutex(b, 2), Err(288));
        d.abandon(1);
        assert_eq!(d.wait(&[b], false, 2, &e), Ok(Some(0x80)));
        assert!(d.close(a));
        assert!(d.owns(b));
        assert!(d.close(b));
        assert_eq!(
            d.open(
                "guard",
                &Object::Event {
                    manual: false,
                    signaled: false
                }
            ),
            Err(2)
        );
    }
}

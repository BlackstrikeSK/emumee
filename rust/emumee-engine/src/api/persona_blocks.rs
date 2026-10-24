//! Process-owned environment snapshots, separate from mutable Persona state.
//! A returns OEM CP437; W returns UTF16. Pages are READ in this documented
//! initial profile (legacy bridge used RW). No host environment is consulted.
use super::*;
use emumee_core::memory::{AddressSpace, PAGE};
const MAX_LIVE: usize = 64;
const MAX_BYTES: u64 = 8 * 1024 * 1024;
const MAX_LIFETIME: u64 = 4096;
const MAX_EVENTS: usize = 256;
const GRANULARITY: u64 = 65536;
#[derive(Clone, Copy)]
pub(crate) enum Call {
    Get(Encoding),
    Free(Encoding),
}
#[derive(Clone, Debug)]
struct Backing {
    size: u64,
    bytes: usize,
    initialized: bool,
}
#[derive(Default)]
pub(super) struct State {
    backing: BTreeMap<u64, Backing>,
    bytes: u64,
    next: u64,
    lifetime: u64,
    events: Vec<Event>,
    omitted: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub operation: &'static str,
    pub owner: u64,
    pub address: u64,
    pub bytes: usize,
    pub encoding: Encoding,
}
#[derive(Clone, Debug, Serialize)]
pub struct Live {
    pub owner: u64,
    pub address: u64,
    pub size: u64,
    pub bytes: usize,
    pub encoding: Option<Encoding>,
    pub initialized: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub live: Vec<Live>,
    pub mapped_bytes: u64,
    pub lifetime_allocations: u64,
    pub events: Vec<Event>,
    pub events_omitted: u64,
    pub scope: &'static str,
}
impl State {
    fn size(&self, bytes: usize) -> Result<u64> {
        if bytes == 0 || bytes > persona::MAX_ENV_BYTES {
            return Err(PersonaError {
                win32: 8,
                reason: "environment snapshot byte limit",
            }
            .into());
        }
        let size = (bytes as u64).div_ceil(PAGE) * PAGE;
        if self.backing.len() >= MAX_LIVE
            || self.lifetime >= MAX_LIFETIME
            || self.bytes.checked_add(size).is_none_or(|n| n > MAX_BYTES)
        {
            return Err(PersonaError {
                win32: 8,
                reason: "environment snapshot count/byte/lifetime limit",
            }
            .into());
        }
        Ok(size)
    }
    fn address(
        &self,
        memory: &AddressSpace,
        architecture: Architecture,
        size: u64,
    ) -> Result<(u64, u64)> {
        let mut address = self.next.max(if architecture == Architecture::X64 {
            0x1_3000_0000
        } else {
            0x3000_0000
        });
        for region in memory.regions() {
            let end = address
                .checked_add(size)
                .ok_or_else(|| anyhow::anyhow!("Environment block reservation overflow"))?;
            if region.base >= end {
                break;
            }
            if region.base + region.size > address {
                address = (region.base + region.size)
                    .checked_add(GRANULARITY - 1)
                    .map(|n| n & !(GRANULARITY - 1))
                    .ok_or(PersonaError {
                        win32: 8,
                        reason: "environment snapshot guest address range exhausted",
                    })?;
            }
        }
        let next = address
            .checked_add(size)
            .and_then(|n| n.checked_add(GRANULARITY - 1))
            .map(|n| n & !(GRANULARITY - 1))
            .ok_or_else(|| anyhow::anyhow!("Environment block cursor overflow"))?;
        let limit = if architecture == Architecture::X64 {
            0x7fff00000000
        } else {
            0x7fff0000
        };
        if next > limit {
            return Err(PersonaError {
                win32: 8,
                reason: "environment snapshot guest address range exhausted",
            }
            .into());
        }
        Ok((address, next))
    }
    fn overlaps(&self, address: u64, size: u64) -> Result<bool> {
        let end = address
            .checked_add(size.max(1))
            .ok_or_else(|| anyhow::anyhow!("Environment block change range overflow"))?;
        Ok(self
            .backing
            .iter()
            .any(|(base, block)| address < *base + block.size && *base < end))
    }
    fn event(&mut self, operation: &'static str, address: u64, bytes: usize, encoding: Encoding) {
        if self.events.len() < MAX_EVENTS {
            self.events.push(Event {
                operation,
                owner: OWNER,
                address,
                bytes,
                encoding,
            });
        } else {
            self.omitted = self.omitted.saturating_add(1);
        }
    }
    fn report(&self, model: &Persona) -> Report {
        let live = self
            .backing
            .iter()
            .map(|(address, b)| {
                let encoding = if model.block(OWNER, *address, Encoding::Cp437).is_ok() {
                    Some(Encoding::Cp437)
                } else if model.block(OWNER, *address, Encoding::Utf16).is_ok() {
                    Some(Encoding::Utf16)
                } else {
                    None
                };
                Live {
                    owner: OWNER,
                    address: *address,
                    size: b.size,
                    bytes: b.bytes,
                    encoding,
                    initialized: b.initialized,
                }
            })
            .collect();
        Report {
            live,
            mapped_bytes: self.bytes,
            lifetime_allocations: self.lifetime,
            events: self.events.clone(),
            events_omitted: self.omitted,
            scope: "current guest process1024 only; independent current-environment snapshots; OEM CP437 A/UTF16 W; READ pages; exact owned FreeEnvironmentStrings only; environment allocator does not reissue addresses; unrelated VirtualAlloc may reuse retired ranges; live state at stop, no invented process-exit frees",
        }
    }
}
pub(super) fn report(state: &super::State) -> Report {
    state.environment_blocks.report(&state.model)
}
pub(super) fn require_change(state: &super::State, address: u64, size: u64) -> Result<()> {
    ensure!(
        !state.environment_blocks.overlaps(address, size)?,
        "Guest allocation change overlaps system-owned environment-block storage; use matching FreeEnvironmentStrings"
    );
    Ok(())
}
pub(super) fn definition(module: &str, name: &str) -> Option<(super::Call, usize, T)> {
    if !matches!(
        module,
        "kernel32"
            | "kernelbase"
            | "api-ms-win-core-processenvironment-l1-1-0"
            | "api-ms-win-core-processenvironment-l1-2-0"
    ) {
        return None;
    }
    let encoding = if name.ends_with('W') {
        Encoding::Utf16
    } else {
        Encoding::Cp437
    };
    Some(match name {
        "GetEnvironmentStrings" | "GetEnvironmentStringsA" | "GetEnvironmentStringsW" => {
            (super::Call::Blocks(Call::Get(encoding)), 0, T::Pointer)
        }
        "FreeEnvironmentStringsA" | "FreeEnvironmentStringsW" => {
            (super::Call::Blocks(Call::Free(encoding)), 1, T::U32)
        }
        _ => return None,
    })
}
fn get(engine: &mut Unicorn<Trace>, encoding: Encoding) -> Result<u64> {
    let state = &engine.get_data().apis;
    let payload = state.persona.model.environment_block(OWNER, encoding)?;
    let size = state.persona.environment_blocks.size(payload.len())?;
    let (address, next) = state.persona.environment_blocks.address(
        &state.memory,
        engine.get_data().architecture,
        size,
    )?;
    let plan = state
        .allocations
        .allocate(
            &state.memory,
            address,
            payload.len() as u64,
            vm::RESERVE | vm::COMMIT,
            2,
        )
        .map_err(|e| PersonaError {
            win32: e.win32,
            reason: "environment snapshot allocation plan rejected",
        })?;
    ensure!(
        plan.result == address,
        "Environment allocation changed selected owned base"
    );
    let mut candidate = state.persona.model.clone();
    candidate.track_block(OWNER, address, encoding)?;
    // Plan/quotas/candidate identity are validated before any native effect.
    // Native map/protect/write failure is fatal: execution cannot resume with
    // a fabricated pointer or retired ownership. Pending backing remains owned.
    allocation::apply(engine, plan)?;
    let state = &mut engine.get_data_mut().apis.persona;
    state.model = candidate;
    state.environment_blocks.backing.insert(
        address,
        Backing {
            size,
            bytes: payload.len(),
            initialized: false,
        },
    );
    state.environment_blocks.bytes += size;
    state.environment_blocks.next = next;
    state.environment_blocks.lifetime += 1;
    crate::cpu::write(engine, address, &payload)?;
    let state = &mut engine.get_data_mut().apis.persona;
    state
        .environment_blocks
        .backing
        .get_mut(&address)
        .unwrap()
        .initialized = true;
    state
        .environment_blocks
        .event("allocated", address, payload.len(), encoding);
    Ok(address)
}
fn free(engine: &mut Unicorn<Trace>, address: u64, encoding: Encoding) -> Result<u64> {
    let state = &engine.get_data().apis;
    state.persona.model.block(OWNER, address, encoding)?;
    let backing = state
        .persona
        .environment_blocks
        .backing
        .get(&address)
        .ok_or_else(|| anyhow::anyhow!("Owned environment block lost its reservation metadata"))?;
    ensure!(
        backing.initialized,
        "Uninitialized environment block cannot be returned or freed after native-effect failure"
    );
    let bytes = backing.bytes;
    let size = backing.size;
    let mut candidate = state.persona.model.clone();
    candidate.retire_block(OWNER, address, encoding)?;
    let plan = state
        .allocations
        .free(&state.memory, address, 0, vm::RELEASE)?;
    // Bypass generic owned-range guard only after exact identity/encoding check.
    // If the actual unmap fails, apply returns fatal error and nothing retires.
    allocation::apply(engine, plan)?;
    let state = &mut engine.get_data_mut().apis.persona;
    state.model = candidate;
    state.environment_blocks.backing.remove(&address);
    state.environment_blocks.bytes -= size;
    state
        .environment_blocks
        .event("freed", address, bytes, encoding);
    Ok(1)
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    match call {
        Call::Get(encoding) => get(engine, encoding),
        Call::Free(encoding) => free(engine, args[0], encoding),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_owned_snapshots_use_current_env_exact_owner_and_real_retired_memory() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = crate::new_engine(architecture).unwrap();
            engine
                .get_data_mut()
                .apis
                .persona
                .model
                .set_variable(OWNER, "PROBE", Some("é😀"))
                .unwrap();
            let a = get(&mut engine, Encoding::Cp437).unwrap();
            let expected = engine
                .get_data()
                .apis
                .persona
                .model
                .environment_block(OWNER, Encoding::Cp437)
                .unwrap();
            assert_eq!(read(&engine, a, expected.len() as u64).unwrap(), expected);
            if architecture == Architecture::X64 {
                assert!(a > u32::MAX as u64);
            }
            assert!(!engine.get_data().apis.memory.allows(a, 1, P::WRITE));
            assert!(!engine.get_data().apis.memory.allows(a, 1, P::EXECUTE));
            engine
                .get_data_mut()
                .apis
                .persona
                .model
                .set_variable(OWNER, "PROBE", Some("changed"))
                .unwrap();
            let w = get(&mut engine, Encoding::Utf16).unwrap();
            assert_ne!(a, w);
            assert_eq!(read(&engine, a, expected.len() as u64).unwrap(), expected);
            engine
                .get_data_mut()
                .apis
                .persona
                .model
                .add_process(2048, ProcessConfig::fixture())
                .unwrap();
            assert_eq!(
                engine
                    .get_data()
                    .apis
                    .persona
                    .model
                    .block(2048, a, Encoding::Cp437)
                    .unwrap_err()
                    .win32,
                87
            );
            for (address, encoding) in [
                (a, Encoding::Utf16),
                (a + 1, Encoding::Cp437),
                (0, Encoding::Cp437),
                (a + 0x1_0000_0000, Encoding::Cp437),
            ] {
                assert_eq!(
                    free(&mut engine, address, encoding)
                        .unwrap_err()
                        .downcast_ref::<PersonaError>()
                        .unwrap()
                        .win32,
                    87
                );
                assert_eq!(read(&engine, a, expected.len() as u64).unwrap(), expected);
            }
            engine.get_data_mut().apis.last_error = 0x12345678;
            free(&mut engine, a, Encoding::Cp437).unwrap();
            assert_eq!(engine.get_data().apis.last_error, 0x12345678);
            assert!(!engine.get_data().apis.memory.allows(a, 1, P::READ));
            assert!(engine.mem_read_as_vec(a, 1).is_err());
            assert!(engine.emu_start(a, a + 1, 0, 1).is_err());
            assert_eq!(
                free(&mut engine, a, Encoding::Cp437)
                    .unwrap_err()
                    .downcast_ref::<PersonaError>()
                    .unwrap()
                    .win32,
                87
            );
            free(&mut engine, w, Encoding::Utf16).unwrap();
            let new = get(&mut engine, Encoding::Cp437).unwrap();
            assert_ne!(new, a);
            free(&mut engine, new, Encoding::Cp437).unwrap();
            assert_eq!(report(&engine.get_data().apis.persona).mapped_bytes, 0);
        }
    }
    #[test]
    fn quota_preflight_failure_does_not_map_or_retire_anything_and_unmap_failure_is_fatal() {
        let mut engine = crate::new_engine(Architecture::X64).unwrap();
        let mut pointers = Vec::new();
        for _ in 0..MAX_LIVE {
            pointers.push(get(&mut engine, Encoding::Utf16).unwrap());
        }
        let before = report(&engine.get_data().apis.persona);
        assert_eq!(
            get(&mut engine, Encoding::Utf16)
                .unwrap_err()
                .downcast_ref::<PersonaError>()
                .unwrap()
                .win32,
            8
        );
        assert_eq!(
            report(&engine.get_data().apis.persona).mapped_bytes,
            before.mapped_bytes
        );
        for address in pointers {
            free(&mut engine, address, Encoding::Utf16).unwrap();
        }
        assert_eq!(report(&engine.get_data().apis.persona).mapped_bytes, 0);
        let address = get(&mut engine, Encoding::Cp437).unwrap();
        let size = engine.get_data().apis.persona.environment_blocks.backing[&address].size;
        uc(engine.mem_unmap(address, size)).unwrap();
        assert!(free(&mut engine, address, Encoding::Cp437).is_err());
        assert!(
            engine
                .get_data()
                .apis
                .persona
                .model
                .block(OWNER, address, Encoding::Cp437)
                .is_ok()
        );
        assert_eq!(report(&engine.get_data().apis.persona).live.len(), 1);
    }
    #[test]
    fn native_map_failure_cannot_return_a_pointer_or_publish_false_identity() {
        let mut engine = crate::new_engine(Architecture::X64).unwrap();
        uc(engine.mem_map(0x1_3000_0000, PAGE, Prot::READ)).unwrap();
        let error = get(&mut engine, Encoding::Utf16).unwrap_err();
        assert!(error.downcast_ref::<PersonaError>().is_none());
        assert!(
            engine
                .get_data()
                .apis
                .persona
                .model
                .block(OWNER, 0x1_3000_0000, Encoding::Utf16)
                .is_err()
        );
        assert!(report(&engine.get_data().apis.persona).live.is_empty());
    }
    #[test]
    fn bounded_planning_skips_actual_regions_enforces_byte_lifetime_and_allocation_guards() {
        let mut state = State::default();
        assert!(state.size(usize::MAX).is_err());
        for _ in 0..=MAX_EVENTS {
            state.event("allocated", 1, 2, Encoding::Cp437);
        }
        assert_eq!(state.events.len(), MAX_EVENTS);
        assert_eq!(state.omitted, 1);
        let mut memory = AddressSpace::new(Architecture::X64);
        memory
            .map(
                0x1_3000_0000,
                0x10000,
                P::READ,
                Some(OWNER),
                "occupied guest literal",
            )
            .unwrap();
        assert_eq!(
            state.address(&memory, Architecture::X64, PAGE).unwrap().0,
            0x1_3001_0000
        );
        state.bytes = MAX_BYTES;
        assert!(state.size(1).is_err());
        state.bytes = 0;
        state.lifetime = MAX_LIFETIME;
        assert!(state.size(1).is_err());
        state.lifetime = 0;
        state.backing.insert(
            0x1_3000_0000,
            Backing {
                size: PAGE,
                bytes: 4,
                initialized: true,
            },
        );
        assert!(state.overlaps(0x1_3000_0001, 0).unwrap());
        assert!(state.overlaps(0x1_2fff_ffff, 2).unwrap());
        assert!(!state.overlaps(0x1_3000_1000, 1).unwrap());
    }
}

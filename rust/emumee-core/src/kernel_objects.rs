//! Owned kernel object identities and typed reference accounting. Object body
//! addresses are guest tokens; no OBJECT_TYPE/EPROCESS private bytes or handles.
use crate::pe::Architecture;
use serde::Serialize;
use std::collections::BTreeMap;
use thiserror::Error;
pub const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xc0000024;
const MAX_OBJECTS: usize = 256;
const MAX_EVENTS: usize = 128;
#[derive(Debug, Error)]
#[error("Kernel object reference: {0}")]
pub struct ObjectError(pub &'static str);
type Result<T> = std::result::Result<T, ObjectError>;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum Kind {
    Thread,
    Process,
    Driver,
    File,
    Section,
    Event,
    Semaphore,
    Token,
    TmEnlistment,
    TmResourceManager,
    TmTransactionManager,
    TmTransaction,
}
impl Kind {
    pub const ALL: [Self; 12] = [
        Self::Thread,
        Self::Process,
        Self::Driver,
        Self::File,
        Self::Section,
        Self::Event,
        Self::Semaphore,
        Self::Token,
        Self::TmEnlistment,
        Self::TmResourceManager,
        Self::TmTransactionManager,
        Self::TmTransaction,
    ];
    pub fn export(self) -> &'static str {
        match self {
            Self::Thread => "PsThreadType",
            Self::Process => "PsProcessType",
            Self::Driver => "IoDriverObjectType",
            Self::File => "IoFileObjectType",
            Self::Section => "MmSectionObjectType",
            Self::Event => "ExEventObjectType",
            Self::Semaphore => "ExSemaphoreObjectType",
            Self::Token => "SeTokenObjectType",
            Self::TmEnlistment => "TmEnlistmentObjectType",
            Self::TmResourceManager => "TmResourceManagerObjectType",
            Self::TmTransactionManager => "TmTransactionManagerObjectType",
            Self::TmTransaction => "TmTransactionObjectType",
        }
    }
    pub fn from_export(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.export() == name)
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct TypeIdentity {
    pub kind: Kind,
    pub identity: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Object {
    pub address: u64,
    pub kind: Kind,
    pub permanent_references: u32,
    pub api_references: u32,
    pub live: bool,
}
impl Object {
    pub fn references(&self) -> u64 {
        u64::from(self.permanent_references) + u64::from(self.api_references)
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub operation: &'static str,
    pub object: u64,
    pub kind: Kind,
    pub permanent_references: u32,
    pub api_references: u32,
    pub references_after: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Objects {
    architecture: Architecture,
    pub system_process: u64,
    pub driver_object: u64,
    pub types: Vec<TypeIdentity>,
    pub records: BTreeMap<u64, Object>,
    pub events: Vec<Event>,
    pub omitted: u64,
}
#[derive(Clone, Copy, Debug)]
pub enum Operation {
    Reference,
    ByPointer { object_type: u64, mode: u64 },
    Dereference,
}
pub struct Plan {
    pub state: Objects,
    pub result: u64,
}
fn checked_pointer(architecture: Architecture, address: u64) -> Result<()> {
    let floor = if architecture == Architecture::X64 {
        0xffff800000000000
    } else {
        0x80000000
    };
    if address < floor
        || address % 4096 != 0
        || address.checked_add(4096).is_none()
        || architecture == Architecture::X86 && address + 4096 > 1u64 << 32
    {
        return Err(ObjectError("invalid kernel identity reservation"));
    }
    Ok(())
}
impl Objects {
    pub fn new(
        architecture: Architecture,
        system_process: u64,
        driver_object: u64,
        type_base: u64,
    ) -> Result<Self> {
        checked_pointer(architecture, system_process)?;
        checked_pointer(architecture, driver_object)?;
        let mut result = Self {
            architecture,
            system_process,
            driver_object,
            types: Vec::new(),
            records: BTreeMap::new(),
            events: Vec::new(),
            omitted: 0,
        };
        let mut used = std::collections::BTreeSet::from([system_process, driver_object]);
        if used.len() != 2 {
            return Err(ObjectError("System and Driver identities overlap"));
        }
        for (index, kind) in Kind::ALL.into_iter().enumerate() {
            let identity = type_base
                .checked_add(index as u64 * 4096)
                .ok_or(ObjectError("object type reservation overflow"))?;
            checked_pointer(architecture, identity)?;
            if !used.insert(identity) {
                return Err(ObjectError("object type identity overlaps an owned body"));
            }
            result.types.push(TypeIdentity { kind, identity });
        }
        result.register_owned(system_process, Kind::Process, 1)?;
        result.register_owned(driver_object, Kind::Driver, 1)?;
        Ok(result)
    }
    pub fn register_owned(
        &mut self,
        address: u64,
        kind: Kind,
        permanent_references: u32,
    ) -> Result<()> {
        checked_pointer(self.architecture, address)?;
        if self.records.len() >= MAX_OBJECTS
            || self.records.contains_key(&address)
            || self.types.iter().any(|item| item.identity == address)
            || permanent_references == 0
        {
            return Err(ObjectError(
                "invalid, duplicate or excessive owned object registration",
            ));
        }
        self.records.insert(
            address,
            Object {
                address,
                kind,
                permanent_references,
                api_references: 0,
                live: true,
            },
        );
        Ok(())
    }
    pub fn identity(&self, kind: Kind) -> u64 {
        self.types
            .iter()
            .find(|entry| entry.kind == kind)
            .expect("closed initialized kind catalog")
            .identity
    }
    pub fn object(&self, address: u64) -> Result<&Object> {
        self.records
            .get(&address)
            .filter(|object| object.live && object.references() > 0)
            .ok_or(ObjectError(
                "reference requires a live owned object body; foreign objects are not modeled",
            ))
    }
    pub fn plan(&self, irql: u8, address: u64, operation: Operation) -> Result<Plan> {
        if irql > 2 {
            return Err(ObjectError("reference operation above DISPATCH_LEVEL"));
        }
        let object = self.object(address)?;
        if let Operation::ByPointer { object_type, mode } = operation {
            match mode as u8 {
                0 => {} // KernelMode pointer references deliberately do not require a type match.
                1 => {
                    if object_type != 0 && object_type != self.identity(object.kind) {
                        return Ok(Plan {
                            state: self.clone(),
                            result: STATUS_OBJECT_TYPE_MISMATCH as u64,
                        });
                    }
                    return Err(ObjectError(
                        "UserMode object security/access validation is not modeled",
                    ));
                }
                _ => return Err(ObjectError("unsupported object reference access mode")),
            }
        }
        let mut state = self.clone();
        let object = state.records.get_mut(&address).unwrap();
        let name = match operation {
            Operation::Reference | Operation::ByPointer { .. } => {
                object.api_references = object
                    .api_references
                    .checked_add(1)
                    .ok_or(ObjectError("object reference count overflow"))?;
                if matches!(operation, Operation::Reference) {
                    "reference"
                } else {
                    "reference_by_pointer"
                }
            }
            Operation::Dereference => {
                object.api_references = object.api_references.checked_sub(1).ok_or(ObjectError(
                    "dereference cannot consume permanent System/Driver ownership",
                ))?;
                "dereference"
            }
        };
        let count = object.references();
        let event = Event {
            operation: name,
            object: address,
            kind: object.kind,
            permanent_references: object.permanent_references,
            api_references: object.api_references,
            references_after: count,
        };
        if state.events.len() < MAX_EVENTS {
            state.events.push(event);
        } else {
            state.omitted = state.omitted.saturating_add(1);
        }
        Ok(Plan {
            state,
            result: if matches!(operation, Operation::ByPointer { .. }) {
                0
            } else {
                count
            },
        })
    }
    /// No handle table is claimed by this slice. Scheduler/VFS handles require
    /// explicit ownership adapters before reference-by-handle may complete.
    pub fn require_handle_adapter(&self) -> Result<()> {
        Err(ObjectError(
            "thread/file handle ownership is not integrated with object references",
        ))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn model(architecture: Architecture) -> Objects {
        let base = if architecture == Architecture::X64 {
            0xffffa10000000000
        } else {
            0xd0000000
        };
        Objects::new(architecture, base + 0x3000, base, base + 0x10000).unwrap()
    }
    #[test]
    fn owned_identity_catalog_and_permanent_vs_transient_references_are_distinct() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let model = model(architecture);
            assert_eq!(model.types.len(), 12);
            assert_eq!(
                model
                    .types
                    .iter()
                    .map(|t| t.identity)
                    .collect::<std::collections::BTreeSet<_>>()
                    .len(),
                12
            );
            let address = model.system_process;
            let referenced = model
                .plan(
                    2,
                    address,
                    Operation::ByPointer {
                        object_type: model.identity(Kind::File),
                        mode: 0,
                    },
                )
                .unwrap();
            assert_eq!(referenced.result, 0);
            assert_eq!(referenced.state.object(address).unwrap().api_references, 1);
            let again = referenced
                .state
                .plan(0, address, Operation::Reference)
                .unwrap();
            assert_eq!(again.result, 3);
            let released = again
                .state
                .plan(0, address, Operation::Dereference)
                .unwrap();
            assert_eq!(released.result, 2);
            let released = released
                .state
                .plan(0, address, Operation::Dereference)
                .unwrap();
            assert_eq!(released.result, 1);
            assert!(
                released
                    .state
                    .plan(0, address, Operation::Dereference)
                    .is_err()
            );
            assert_eq!(released.state.records[&address].permanent_references, 1);
            assert_eq!(model.records[&address].api_references, 0);
        }
    }
    #[test]
    fn failures_do_not_change_counts_and_usermode_mismatch_has_exact_status() {
        let model = model(Architecture::X64);
        let address = model.system_process;
        let mismatch = model
            .plan(
                0,
                address,
                Operation::ByPointer {
                    object_type: model.identity(Kind::Thread),
                    mode: 1,
                },
            )
            .unwrap();
        assert_eq!(mismatch.result, STATUS_OBJECT_TYPE_MISMATCH as u64);
        assert!(mismatch.state.events.is_empty());
        for operation in [
            Operation::ByPointer {
                object_type: 0,
                mode: 1,
            },
            Operation::ByPointer {
                object_type: 0,
                mode: 2,
            },
            Operation::Dereference,
        ] {
            assert!(model.plan(0, address, operation).is_err());
        }
        assert!(model.plan(3, address, Operation::Reference).is_err());
        assert!(model.plan(0, address + 1, Operation::Reference).is_err());
        assert!(model.require_handle_adapter().is_err());
        assert_eq!(model.records[&address].api_references, 0);
    }
    #[test]
    fn reservation_width_collisions_event_bounds_and_reference_overflow_are_checked() {
        assert!(Objects::new(Architecture::X86, 0x1d0003000, 0xd0000000, 0xd0010000).is_err());
        assert!(
            Objects::new(
                Architecture::X64,
                0xffffa10000000000,
                0xffffa10000000000,
                0xffffa10000010000
            )
            .is_err()
        );
        let mut model = model(Architecture::X64);
        let address = model.system_process;
        model.records.get_mut(&address).unwrap().api_references = u32::MAX;
        assert!(model.plan(0, address, Operation::Reference).is_err());
        model.records.get_mut(&address).unwrap().api_references = 0;
        for _ in 0..140 {
            model = model.plan(0, address, Operation::Reference).unwrap().state;
        }
        assert_eq!(model.events.len(), 128);
        assert_eq!(model.omitted, 12);
        assert_eq!(model.records[&address].api_references, 140);
    }
}

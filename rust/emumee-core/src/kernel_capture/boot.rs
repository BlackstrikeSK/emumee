//! Pinned SecureDump_PrepareForInit projection for a fresh resource context.
//! Explicit helper observations are required; this never executes a native boot
//! function, allocates guest memory, emits events or establishes full boot parity.
use crate::{
    pe::Architecture,
    registry::{KEY_READ, NativeOpen, NativeResult, Registry},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Query {
    GuardedHost,
    EncryptionEnabled,
    ProvisionWithCertificate,
    PublicKey,
    Thumbprint,
}
impl Query {
    pub fn path(self) -> &'static str {
        match self {
            Self::GuardedHost => {
                r"\Registry\Machine\System\CurrentControlSet\Control\CrashControl\ForceDumpsDisabled"
            }
            Self::PublicKey | Self::Thumbprint => {
                r"\Registry\Machine\System\CurrentControlSet\Control\CrashControl\EncryptionCertificates\Certificate.1"
            }
            _ => r"\Registry\Machine\System\CurrentControlSet\Control\CrashControl",
        }
    }
    pub fn value_name(self) -> &'static str {
        match self {
            Self::GuardedHost => "GuardedHost",
            Self::EncryptionEnabled => "DumpEncryptionEnabled",
            Self::ProvisionWithCertificate => "ProvisionDumpKeyWithCertificate",
            Self::PublicKey => "PublicKey",
            Self::Thumbprint => "Thumbprint",
        }
    }
    pub fn value_type(self) -> u32 {
        match self {
            Self::PublicKey => 3,
            Self::Thumbprint => 1,
            _ => 4,
        }
    }
}
/// A completed SecureDump_ReadRegistry observation. Nonnegative status requires
/// a genuine nonempty copied allocation. Failed observations supply no new data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Observation {
    pub status: u32,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct Inputs {
    pub output_present: bool,
    pub initial_state: u32,
    pub initial_provisioning_flag: u8,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    pub force_dump_disabled: u8,
    pub state: u32,
    pub provisioning_flag: u8,
    pub output: Option<bool>,
    pub guarded_host: u32,
    pub encryption_enabled: u32,
    pub public_key: Option<Vec<u8>>,
    pub thumbprint: Option<Vec<u8>>,
    pub reads: Vec<Query>,
    pub release_intents: Vec<Query>,
    pub error_event_intent: Option<u32>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Progress {
    Needs(Query),
    Complete(Outcome),
}
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("Successful secure-dump helper observation has no copied data: {0:?}")]
    EmptySuccess(Query),
    #[error("Secure-dump DWORD consumer would read beyond its copied allocation: {0:?}")]
    ShortDword(Query),
}
enum Stop {
    Needs(Query),
    Invalid(Error),
}
enum Read<'a> {
    Value(&'a [u8]),
    Failed(u32),
}
struct Projection<'a> {
    observations: &'a BTreeMap<Query, Observation>,
    out: Outcome,
}
impl<'a> Projection<'a> {
    fn read(&mut self, query: Query) -> Result<Read<'a>, Stop> {
        let observation = self.observations.get(&query).ok_or(Stop::Needs(query))?;
        self.out.reads.push(query);
        if (observation.status as i32) < 0 {
            return Ok(Read::Failed(observation.status));
        }
        if observation.bytes.is_empty() {
            return Err(Stop::Invalid(Error::EmptySuccess(query)));
        }
        Ok(Read::Value(&observation.bytes))
    }
    fn dword(&mut self, query: Query) -> Result<Result<u32, u32>, Stop> {
        match self.read(query)? {
            Read::Failed(status) => Ok(Err(status)),
            Read::Value(bytes) => {
                let bytes: [u8; 4] = bytes
                    .get(..4)
                    .ok_or(Stop::Invalid(Error::ShortDword(query)))?
                    .try_into()
                    .unwrap();
                self.out.release_intents.push(query);
                Ok(Ok(u32::from_le_bytes(bytes)))
            }
        }
    }
    fn finish(mut self, code: u32) -> Outcome {
        if self.out.force_dump_disabled == 1 {
            if self.out.public_key.take().is_some() {
                self.out.release_intents.push(Query::PublicKey);
            }
            if self.out.thumbprint.take().is_some() {
                self.out.release_intents.push(Query::Thumbprint);
            }
            if code != 0 {
                self.out.state = 3;
                self.out.error_event_intent = Some(code);
            }
        } else {
            self.out.state = 1;
        }
        self.out
    }
    fn run(mut self, input: Inputs) -> Result<Outcome, Stop> {
        if !input.output_present {
            return Ok(self.out);
        }
        self.out.output = Some(false);
        match self.dword(Query::GuardedHost)? {
            Ok(value) => {
                self.out.guarded_host = value;
                if value != 0 {
                    return Ok(self.finish(0));
                }
            }
            Err(0xc0000034) => {}
            Err(_) => return Ok(self.finish(2)),
        }
        match self.dword(Query::EncryptionEnabled)? {
            Ok(value) => {
                self.out.encryption_enabled = value;
                if value == 0 {
                    self.out.force_dump_disabled = 0;
                    return Ok(self.finish(0));
                }
            }
            Err(0xc0000034) => {
                self.out.force_dump_disabled = 0;
                return Ok(self.finish(0));
            }
            Err(_) => return Ok(self.finish(2)),
        }
        self.out.output = Some(true);
        if let Ok(value) = self.dword(Query::ProvisionWithCertificate)? {
            self.out.provisioning_flag = u8::from(value > 0);
        }
        if self.out.provisioning_flag != 0 {
            self.out.force_dump_disabled = 0;
            return Ok(self.finish(2));
        }
        match self.read(Query::PublicKey)? {
            Read::Value(bytes) => self.out.public_key = Some(bytes.to_vec()),
            Read::Failed(_) => return Ok(self.finish(2)),
        }
        match self.read(Query::Thumbprint)? {
            Read::Value(bytes) => self.out.thumbprint = Some(bytes.to_vec()),
            Read::Failed(_) => return Ok(self.finish(2)),
        }
        self.out.force_dump_disabled = 0;
        Ok(self.finish(2))
    }
}
pub fn evaluate(
    input: Inputs,
    observations: &BTreeMap<Query, Observation>,
) -> Result<Progress, Error> {
    let projection = Projection {
        observations,
        out: Outcome {
            force_dump_disabled: 1,
            state: input.initial_state,
            provisioning_flag: input.initial_provisioning_flag,
            output: None,
            guarded_host: 0,
            encryption_enabled: 0,
            public_key: None,
            thumbprint: None,
            reads: Vec::new(),
            release_intents: Vec::new(),
            error_event_intent: None,
        },
    };
    match projection.run(input) {
        Ok(out) => Ok(Progress::Complete(out)),
        Err(Stop::Needs(query)) => Ok(Progress::Needs(query)),
        Err(Stop::Invalid(error)) => Err(error),
    }
}
/// Observe only deterministic failure of the real owned native-open planner.
/// An admitted open is not a completed registry-helper read: query, allocation,
/// copy and cleanup still need evidence. No handles are committed here.
pub fn observe_open_failure(
    registry: &Registry,
    query: Query,
) -> NativeResult<Option<Observation>> {
    match registry.plan_native_open(NativeOpen {
        architecture: Architecture::X64,
        owner: 4,
        root: 0,
        name: query.path(),
        access: KEY_READ,
    }) {
        Ok(_) => Ok(None),
        Err(error) => match error.status {
            Some(status) => Ok(Some(Observation {
                status,
                bytes: Vec::new(),
            })),
            None => Err(error),
        },
    }
}

#[cfg(test)]
mod tests;

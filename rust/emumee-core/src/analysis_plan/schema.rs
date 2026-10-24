use crate::persona::PersonaConfig;
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    X86,
    X64,
}
impl Arch {
    pub fn architecture(self) -> crate::pe::Architecture {
        match self {
            Self::X86 => crate::pe::Architecture::X86,
            Self::X64 => crate::pe::Architecture::X64,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputRole {
    OriginalPrimary,
    ExecutionPrimary,
    ApphostSidecar,
    NativeCompanion,
    ManagedCompanion,
    GuestFile,
    PersonaFile,
    OfflineFixtures,
    KernelCodeReference,
    LegacyPersona,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Mount {
    NotMounted,
    Package { path: String },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputSpec {
    pub id: String,
    pub name: String,
    pub roles: Vec<InputRole>,
    pub mount: Mount,
    pub size: u64,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Reference {
    None,
    Bound { input: String },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Apphost {
    None,
    Bound {
        original: String,
        binding_name: String,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exports {
    Disabled,
    All,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    NativeExe {
        input: String,
        architecture: Arch,
    },
    NativeDll {
        input: String,
        architecture: Arch,
        exports: Exports,
    },
    KernelDriver {
        input: String,
        architecture: Arch,
        unload: bool,
        code_reference: Reference,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        service_name: Option<String>,
    },
    ManagedEntry {
        input: String,
        architecture: Arch,
        apphost: Apphost,
    },
    StaticMsi {
        input: String,
    },
}
impl Target {
    pub(crate) fn input(&self) -> &str {
        match self {
            Self::NativeExe { input, .. }
            | Self::NativeDll { input, .. }
            | Self::KernelDriver { input, .. }
            | Self::ManagedEntry { input, .. }
            | Self::StaticMsi { input } => input,
        }
    }
    pub(crate) fn arch(&self) -> Option<Arch> {
        match self {
            Self::NativeExe { architecture, .. }
            | Self::NativeDll { architecture, .. }
            | Self::KernelDriver { architecture, .. }
            | Self::ManagedEntry { architecture, .. } => Some(*architecture),
            Self::StaticMsi { .. } => None,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CpuSpec {
    pub brand: String,
    pub signature: u32,
    pub cores: u32,
    pub threads_per_core: u32,
    pub base_mhz: u32,
    pub max_mhz: u32,
}
impl CpuSpec {
    pub(crate) fn profile(&self) -> crate::cpu::CpuProfile {
        crate::cpu::CpuProfile {
            brand: self.brand.clone(),
            signature: self.signature,
            cores: self.cores,
            threads_per_core: self.threads_per_core,
            base_mhz: self.base_mhz,
            max_mhz: self.max_mhz,
            cpuid_overrides: vec![],
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockSource {
    Fixed,
    ControllerResolved,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClockSpec {
    pub utc_filetime: u64,
    pub uptime_ms: u64,
    pub utc_offset_minutes: i32,
    pub source: ClockSource,
    pub source_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModeledPersona {
    pub process: PersonaConfig,
    pub cpu: CpuSpec,
    pub clock: ClockSpec,
    pub windows_build: u32,
    pub current_processor: u32,
    pub physical_memory_mb: u32,
    pub available_memory_mb: u32,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PersonaSpec {
    RustModeledV1 { value: Box<ModeledPersona> },
    LegacyPersonaV1 { input: String },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    pub name: String,
    pub value: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Invocation {
    None,
    Process {
        guest_root: String,
        arguments: Vec<String>,
        force_quote_indices: Vec<usize>,
        environment: Vec<Assignment>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Network {
    OfflineDeny,
    OfflineExactReplay { input: String },
    Live,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureProfile {
    Legacy32CaptureV1,
    LargeDriver128V1,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureSource {
    GuestFiles,
    RegistryBinary,
    ContainerStreams,
    MemorySnapshots,
    StructuralPe,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MemoryStrings {
    Disabled,
    Indicators { patterns: Vec<String> },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Checkpoint {
    FinalBoundary,
    Periodic { instructions: u64 },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub profile: CaptureProfile,
    pub sources: Vec<CaptureSource>,
    pub retained_bytes: u64,
    pub memory_scan_bytes: u64,
    pub memory_strings: MemoryStrings,
    pub checkpoint: Checkpoint,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub guest_timeout_ms: u64,
    pub max_instructions: u64,
    pub max_native_api_calls: u32,
    pub worker_startup_ms: u64,
    pub reporting_grace_ms: u64,
    pub broker_startup_ms: u64,
    pub broker_grace_ms: u64,
    pub worker_memory_mb: u32,
    pub broker_memory_mb: u32,
    pub max_output_bytes: u64,
    pub max_output_entries: u32,
    pub max_output_directories: u32,
    pub max_output_depth: u32,
    pub guest_mapped_bytes: u64,
    pub guest_heap_bytes: u64,
    pub guest_pool_bytes: u64,
    pub guest_threads: u32,
    pub broker_stream_bytes: u64,
    pub broker_journal_bytes: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportProfile {
    LegacyV1,
    LargeDriverV1,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reports {
    pub profile: ReportProfile,
    pub summary_bytes: u64,
    pub engine_bytes: u64,
    pub network_bytes: u64,
    pub manifest_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanSpec {
    #[serde(skip)]
    pub(super) original_json_sha256: Option<String>,
    #[serde(skip)]
    pub(super) decoded_sha256: Option<String>,
    pub schema: u32,
    pub target: Target,
    pub inputs: Vec<InputSpec>,
    pub companions: Vec<String>,
    pub persona: PersonaSpec,
    pub invocation: Invocation,
    pub network: Network,
    pub limits: Limits,
    pub capture: Capture,
    pub reports: Reports,
}

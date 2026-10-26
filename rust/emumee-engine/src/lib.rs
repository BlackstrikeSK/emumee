//! Native Rust guest execution. No Python callbacks or interpreter bridge.
use anyhow::{Context, Result, anyhow, ensure};
use emumee_core::{
    artifacts::{Artifact, ArtifactKind, CaptureSummary},
    clock::GuestClock,
    fixtures::counted_driver,
    memory::Permissions,
    pe::{Architecture, PeImage},
};
use serde::Serialize;
use std::time::Instant;
use unicorn_engine::{
    RegisterX86, Unicorn,
    unicorn_const::{Arch, HookType, Mode, Prot, uc_error},
};
mod api;
mod boot;
#[cfg(test)]
mod callback_tests;
mod capture;
mod indicators;
mod instruction_window;
#[cfg(test)]
mod instruction_window_tests;
pub use indicators::run as run_indicator_fixture;
pub mod cil;
mod configured;
#[cfg(test)]
mod console_tests;
mod cpu;
pub mod plan_runtime;
pub use capture::run_owned as run_driver_runtime_fixture;
pub use configured::ConfigurationReceipt;
#[cfg(test)]
mod callback_continuation_tests;
#[cfg(test)]
mod configured_tests;
#[cfg(test)]
mod cr8_tests;
#[cfg(test)]
mod crt_format_tests;
#[cfg(test)]
mod crt_stdio_tests;
#[cfg(test)]
mod crt_tests;
#[cfg(test)]
mod dynamic_loader_tests;
#[cfg(test)]
mod environment_block_tests;
#[cfg(test)]
mod guarded_mutex_protocol_tests;
#[cfg(test)]
mod heap_tests;
mod image_writes;
mod ipi;
#[cfg(test)]
mod ipi_tests;
#[cfg(test)]
mod kernel_code_integrity_tests;
#[cfg(test)]
mod kernel_sections_tests;
mod kernel_context_reads;
mod kernel_cpu;
#[cfg(test)]
mod kernel_dpc_tests;
#[cfg(test)]
mod kernel_environment_tests;
#[cfg(test)]
mod kernel_files_tests;
mod kernel_loader;
pub mod linux;
#[cfg(test)]
mod kernel_modules_tests;
#[cfg(test)]
mod kernel_objects_tests;
#[cfg(test)]
mod kernel_reference_integrated_tests;
#[cfg(test)]
mod kernel_reference_nx_tests;
#[cfg(test)]
mod kernel_reference_runtime_tests;
#[cfg(test)]
mod kernel_reference_unload_tests;
#[cfg(test)]
mod kernel_registry_tests;
#[cfg(test)]
mod kernel_rtl_tests;
#[cfg(test)]
mod kernel_spin_tests;
mod kernel_stack_writes;
#[cfg(test)]
mod kernel_stack_writes_tests;
#[cfg(test)]
mod kernel_sync_tests;
#[cfg(test)]
mod kernel_tail_tests;
#[cfg(test)]
mod kernel_thread_objects_tests;
#[cfg(test)]
mod kernel_time_tests;
#[cfg(test)]
mod kernel_timer_tests;
#[cfg(test)]
mod kernel_waits_tests;
#[cfg(test)]
mod mdl_tests;
#[cfg(test)]
mod native_exception_tests;
mod native_exceptions;
#[cfg(test)]
mod native_loader_tests;
#[cfg(test)]
mod native_unwind_tests;
#[cfg(test)]
mod persona_tests;
#[cfg(test)]
mod prompt_continuation_tests;
#[cfg(test)]
mod provider_metadata_tests;
#[cfg(test)]
mod provider_mixed_tests;
#[cfg(test)]
mod registry_tests;
#[cfg(test)]
mod rundown_tests;
#[cfg(test)]
mod submitted_driver_tests;
mod tcg;
mod threads;
mod time;
#[cfg(test)]
mod vfs_metadata_tests;
#[cfg(test)]
mod vfs_mutation_tests;
pub use api::ApiRegion;
pub use api::EnvironmentBlockReport;
pub use api::KernelReport;
pub use api::ProviderDenial;
pub use api::ProviderEvidence;
pub use api::callbacks::Report as CallbackReport;
pub use api::crt_format::{KernelFormatObservation, KernelFormattingReport};
pub use api::dynamic_loader::Report as DynamicLoaderReport;
pub use api::kernel_callback_continuation::Report as KernelCallbackContinuationReport;
pub use api::kernel_code_integrity::Report as KernelCodeIntegrityReport;
pub use api::kernel_sections::Report as KernelSectionsReport;
pub use api::kernel_environment::Report as KernelEnvironmentReport;
pub use api::kernel_files::Report as KernelFilesReport;
pub use api::kernel_modules::Report as KernelModulesReport;
pub use api::kernel_objects::Report as KernelObjectReport;
pub use api::kernel_prompt::Report as KernelPromptReport;
pub use api::kernel_registry::Report as KernelRegistryReport;
pub use api::kernel_rtl::Report as KernelRtlReport;
pub use api::kernel_thread_objects::Report as KernelThreadObjectReport;
pub use api::mdl::Report as MdlReport;
pub use api::native_loader::Report as NativeLoaderReport;
pub use api::reference_mapping::MappingReceipt as KernelReferenceMappingReceipt;
pub use api::reference_unload::Report as ReferenceUnloadReport;
pub use api::rundown::Report as RundownReport;
pub use api::{ApiEvent, KernelExportQuery};
pub use cpu::native_reads::Report as NativeCpuReadsReport;
pub use ipi::Report as IpiReport;
pub use kernel_context_reads::Report as KernelContextReadsReport;
pub use kernel_loader::Report as KernelLoaderReport;
pub use threads::{ThreadEvidence, ThreadReport};
#[cfg(test)]
mod kernel_tid_tests;

const STACK: u64 = 0x70000000;
const STACK_SIZE: u64 = 1024 * 1024;
const RETURN: u64 = 0xfeedf000;
const OBJECTS: u64 = 0x71000000;
const TAIL: usize = 128;

// The pinned Windows backend installs process-wide, per-instance VEH code-cache
// trampolines, including mutable closure storage. Avoid overlapping native
// instance lifetimes; independent restricted worker processes remain parallel.
#[cfg(windows)]
static NATIVE_INSTANCE: std::sync::Mutex<()> = std::sync::Mutex::new(());
struct NativeEngine {
    // Field order closes Unicorn (and unregisters its handlers) before unlock.
    engine: Unicorn<'static, Trace>,
    #[cfg(windows)]
    _lease: std::sync::MutexGuard<'static, ()>,
}
impl std::ops::Deref for NativeEngine {
    type Target = Unicorn<'static, Trace>;
    fn deref(&self) -> &Self::Target {
        &self.engine
    }
}
impl std::ops::DerefMut for NativeEngine {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.engine
    }
}
fn new_engine(architecture: Architecture) -> Result<NativeEngine> {
    new_engine_with_trace(Trace::new(architecture))
}
fn new_engine_with_trace(trace: Trace) -> Result<NativeEngine> {
    let architecture = trace.architecture;
    #[cfg(windows)]
    let lease = NATIVE_INSTANCE
        .lock()
        .map_err(|_| anyhow!("Native engine lifetime guard is poisoned"))?;
    let mode = if architecture == Architecture::X64 {
        Mode::MODE_64
    } else {
        Mode::MODE_32
    };
    let engine = uc(Unicorn::new_with_data(Arch::X86, mode, trace))?;
    Ok(NativeEngine {
        engine,
        #[cfg(windows)]
        _lease: lease,
    })
}

fn uc<T>(value: std::result::Result<T, uc_error>) -> Result<T> {
    value.map_err(|error| anyhow!("Unicorn: {error:?}"))
}
pub fn backend() -> &'static str {
    "rust/unicorn-x86"
}

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct TraceEntry {
    pub pc: u64,
    pub size: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct NativeMemoryFault {
    pub access: &'static str,
    pub address: u64,
    pub size: usize,
    pub pc: u64,
}
struct Trace {
    architecture: Architecture,
    instructions: u64,
    entries: [TraceEntry; TAIL],
    clock: GuestClock,
    machine: configured::Machine,
    capture: Option<capture::State>,
    indicators: Option<indicators::State>,
    plan_limits: Option<emumee_core::analysis_plan::Limits>,
    plan_fault: emumee_core::plan_runtime::Fault,
    plan_fault_evidence: Option<serde_json::Value>,
    clock_error: bool,
    cpu: cpu::CpuState,
    kernel_cpu: Option<kernel_cpu::KernelCpu>,
    kernel_context_reads: kernel_context_reads::State,
    kernel_loader: kernel_loader::State,
    kernel_stack_writes: Option<kernel_stack_writes::State>,
    image_writes: Option<image_writes::State>,
    instruction_window: Option<instruction_window::State>,
    kernel_lock_storage: Option<u64>,
    reference_spans: Vec<(u64, u64)>,
    native_memory_fault: Option<NativeMemoryFault>,
    clock_aliases: [u64; 3],
    clock_page: Option<Box<time::SharedPage>>,
    return_marker: u64,
    apis: api::ApiState,
    threads: Option<threads::ThreadExecution>,
    thread_action: Option<threads::Action>,
    ipi: ipi::State,
    ipi_action: Option<ipi::Action>,
    loader_active: bool,
    dynamic_loader: api::dynamic_loader::State,
    native_exceptions: native_exceptions::State,
    loader_native_effect_failure: Option<String>,
    loader_preparation_error: Option<String>,
}
impl Trace {
    fn new(architecture: Architecture) -> Self {
        Self::with_models(
            architecture,
            GuestClock::new(133000000000000000, 523812000, -240, 2900).unwrap(),
            emumee_core::cpu::CpuProfile::default(),
            api::ApiState::new(architecture),
            configured::Machine::fixture(),
        )
    }
    fn from_prepared(
        architecture: Architecture,
        state: emumee_core::fullpersona::PreparedGuestState,
        machine: configured::Machine,
    ) -> Self {
        let apis = api::ApiState::seeded(
            architecture,
            state.persona,
            state.registry,
            state.filesystem,
        );
        Self::with_models(architecture, state.clock, state.cpu, apis, machine)
    }
    fn with_models(
        architecture: Architecture,
        clock: GuestClock,
        profile: emumee_core::cpu::CpuProfile,
        apis: api::ApiState,
        machine: configured::Machine,
    ) -> Self {
        Self {
            architecture,
            instructions: 0,
            entries: [TraceEntry::default(); TAIL],
            clock,
            machine,
            capture: None,
            indicators: None,
            plan_limits: None,
            plan_fault: Default::default(),
            plan_fault_evidence: None,
            clock_error: false,
            cpu: cpu::CpuState::configured(profile),
            kernel_cpu: None,
            kernel_context_reads: kernel_context_reads::State::default(),
            kernel_loader: kernel_loader::State::default(),
            kernel_stack_writes: None,
            image_writes: None,
            instruction_window: None,
            kernel_lock_storage: None,
            reference_spans: Vec::new(),
            native_memory_fault: None,
            clock_aliases: [0; 3],
            clock_page: None,
            return_marker: RETURN,
            apis,
            threads: None,
            thread_action: None,
            ipi: ipi::State::new(architecture),
            ipi_action: None,
            loader_active: false,
            dynamic_loader: api::dynamic_loader::State::default(),
            native_exceptions: native_exceptions::State::default(),
            loader_native_effect_failure: None,
            loader_preparation_error: None,
        }
    }
    #[inline]
    fn instruction(&mut self, pc: u64, size: u32) {
        self.entries[(self.instructions as usize) & (TAIL - 1)] = TraceEntry { pc, size };
        self.instructions += 1;
        self.clock_error |= self.clock.instruction().is_err();
    }
    fn tail(&self) -> Vec<TraceEntry> {
        let count = self.instructions.min(TAIL as u64);
        (self.instructions - count..self.instructions)
            .map(|index| self.entries[(index as usize) & (TAIL - 1)])
            .collect()
    }
}
#[derive(Debug, Serialize)]
pub struct Execution {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_exceptions: Option<native_exceptions::Report>,
    pub native_loader: Option<NativeLoaderReport>,
    pub dynamic_loader: Option<DynamicLoaderReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub closed_plan_fault: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_runtime: Option<emumee_core::driver_runtime::Receipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_strings: Option<emumee_core::memory_strings::Report>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_string_sources: Option<emumee_core::memory_observation::Receipt>,
    pub configuration: Option<ConfigurationReceipt>,
    pub console: Option<emumee_core::crt_stdio::ConsoleReport>,
    pub crt_stdio: Option<emumee_core::crt_stdio::StateReport>,
    pub console_session: Option<emumee_core::console::Report>,
    pub file_enumeration: Option<emumee_core::filesystem::EnumerationReport>,
    pub environment_blocks: Option<EnvironmentBlockReport>,
    pub file_storage: Option<emumee_core::filesystem::StorageReport>,
    pub kernel_callbacks: Option<CallbackReport>,
    pub kernel_cache_aware_rundown: Option<RundownReport>,
    pub kernel_environment: Option<KernelEnvironmentReport>,
    pub kernel_registry: Option<KernelRegistryReport>,
    pub kernel_files: Option<KernelFilesReport>,
    pub kernel_rtl: Option<KernelRtlReport>,
    pub kernel_prompt: Option<KernelPromptReport>,
    pub kernel_callback_continuation: Option<KernelCallbackContinuationReport>,
    pub kernel_context_reads: Option<KernelContextReadsReport>,
    pub kernel_loader: Option<KernelLoaderReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_stack_writes: Option<kernel_stack_writes::Report>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_writes: Option<image_writes::Report>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_window: Option<instruction_window::Report>,
    pub kernel_objects: Option<KernelObjectReport>,
    pub kernel_thread_objects: Option<KernelThreadObjectReport>,
    pub kernel_ipi: Option<IpiReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_reference: Option<KernelReferenceMappingReceipt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_reference_unload_history: Option<ReferenceUnloadReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcg_buffer_size: Option<u32>,
    pub kernel_mdls: Option<MdlReport>,
    pub user_heaps: Option<emumee_core::heap::Heaps>,
    pub network: api::NetworkReport,
    pub backend: &'static str,
    pub architecture: Architecture,
    pub completion_reason: &'static str,
    pub instruction_count: u64,
    pub max_instructions: u64,
    pub guest_entry_return: Option<u64>,
    pub final_pc: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_memory_fault: Option<NativeMemoryFault>,
    pub instruction_tail: Vec<TraceEntry>,
    pub error: Option<String>,
    pub engine_seconds: f64,
    pub instructions_per_second: f64,
    pub virtual_uptime_ms: u64,
    pub virtual_tsc: u64,
    pub virtual_tsc_offset: u64,
    pub virtual_tsc_adjust: u64,
    pub cpu: cpu::CpuReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_cpu_reads: Option<NativeCpuReadsReport>,
    pub kernel_cpu: Option<kernel_cpu::KernelCpuReport>,
    pub kernel_entry: Option<boot::KernelEntry>,
    pub api_calls: u64,
    pub api_region: Option<ApiRegion>,
    pub synthetic_providers: Vec<ProviderEvidence>,
    pub provider_denials: Vec<ProviderDenial>,
    pub provider_denials_omitted: u64,
    pub kernel_pool: Option<emumee_core::pool::Pool>,
    pub kernel_pool_scope: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modeled_guest_regions: Option<Vec<emumee_core::memory::Region>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modeled_guest_regions_scope: Option<&'static str>,
    pub api_events: Vec<ApiEvent>,
    pub api_events_omitted: u64,
    pub kernel_export_queries: Vec<KernelExportQuery>,
    pub kernel_export_queries_omitted: u64,
    pub kernel_formatting: Option<KernelFormattingReport>,
    pub loaded_modules: Vec<ModuleEvidence>,
    pub image_load: ImageLoad,
    pub artifacts: Vec<Artifact>,
    pub capture_summary: CaptureSummary,
    pub kernel_state: Option<KernelReport>,
    pub kernel_modules: Option<KernelModulesReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_code_integrity: Option<KernelCodeIntegrityReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_sections: Option<KernelSectionsReport>,
    pub kernel_threads: Option<ThreadReport>,
    pub scope: &'static str,
}

// Driver128 writes compact JSON and binds it under MAX_ENGINE_BYTES. Keep the
// older prompt receipt intact; if both passive windows plus other evidence
// would approach that bound, shorten only this new callback diagnostic. The
// 1 MiB reserve allows ordinary envelope growth; independently oversized
// nontrace evidence remains subject to the report builder's own refusal. This
// is report construction after execution, never a guest decision or CPU effect.
fn bound_callback_continuation_report(report: &mut Execution) {
    let Some(window) = report.kernel_callback_continuation.as_ref() else {
        return;
    };
    if window.instructions.is_empty() {
        return;
    }
    let target = emumee_core::reports::MAX_ENGINE_BYTES - 1024 * 1024;
    let Ok(full) = serde_json::to_vec(report) else {
        return;
    };
    let full_size = full.len();
    drop(full);
    if full_size <= target {
        return;
    }
    let original = std::mem::take(
        &mut report
            .kernel_callback_continuation
            .as_mut()
            .unwrap()
            .instructions,
    );
    let total = original.len();
    let Ok(empty) = serde_json::to_vec(&*report) else {
        report
            .kernel_callback_continuation
            .as_mut()
            .unwrap()
            .instructions = original;
        return;
    };
    let base_size = empty.len();
    drop(empty);
    let row_bytes = full_size.saturating_sub(base_size);
    let keep = if base_size >= target || row_bytes == 0 {
        0
    } else {
        (((target - base_size) as u128 * total as u128) / row_bytes as u128).min(total as u128)
            as usize
    };
    report
        .kernel_callback_continuation
        .as_mut()
        .unwrap()
        .instructions = original;
    report
        .kernel_callback_continuation
        .as_mut()
        .unwrap()
        .trim_for_report_limit(keep);
    // The first estimate uses exact full/empty compact sizes; account for the
    // explicit truncation stop and nonuniform row widths if necessary.
    while let Ok(bytes) = serde_json::to_vec(&*report) {
        if bytes.len() <= target
            || report
                .kernel_callback_continuation
                .as_ref()
                .unwrap()
                .instructions
                .is_empty()
        {
            break;
        }
        let rows = report
            .kernel_callback_continuation
            .as_ref()
            .unwrap()
            .instructions
            .len();
        let average = (row_bytes / total).max(1);
        let remove = ((bytes.len() - target) / average + 1).min(rows);
        report
            .kernel_callback_continuation
            .as_mut()
            .unwrap()
            .trim_for_report_limit(rows - remove);
    }
}
#[derive(Debug, Serialize)]
pub struct ModuleEvidence {
    pub name: String,
    pub base: u64,
    pub size: u64,
}
#[derive(Debug, Serialize)]
pub struct ImageLoad {
    pub preferred_base: u64,
    pub base: u64,
    pub entry: u64,
    pub size: u32,
    pub relocated: bool,
    pub scope: &'static str,
}

/// The worker/controller share one dispatcher, so managed requests can never
/// silently fall through to a native counted-loop fixture.
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum FixtureExecution {
    Native(Box<Execution>),
    Managed(Box<cil::Execution>),
}
impl FixtureExecution {
    pub fn completion_reason(&self) -> &'static str {
        match self {
            Self::Native(execution) => execution.completion_reason,
            Self::Managed(execution) => execution.completion_reason,
        }
    }
    pub fn artifacts(&self) -> &[Artifact] {
        match self {
            Self::Native(execution) => &execution.artifacts,
            Self::Managed(execution) => &execution.artifacts,
        }
    }
}
pub fn run_fixture_kind(
    architecture: Architecture,
    kind: emumee_core::protocol::FixtureKind,
    iterations: u32,
    budget: u64,
) -> Result<FixtureExecution> {
    if let Some(fixture) = kind.managed_case() {
        return cil::run_fixture(architecture, fixture, iterations, budget)
            .map(|execution| FixtureExecution::Managed(Box::new(execution)));
    }
    let native = if kind.is_relocated() {
        run_relocated_fixture(architecture, budget)?
    } else if let Some(fixture) = kind.cpu_case() {
        run_cpu_fixture(architecture, fixture, budget)?
    } else if let Some(fixture) = kind.linked_case() {
        run_linked_fixture(architecture, fixture, budget)?
    } else if let Some(fixture) = kind.api_case() {
        run_api_fixture(architecture, fixture, budget)?
    } else {
        run_fixture(architecture, iterations, budget)?
    };
    Ok(FixtureExecution::Native(Box::new(native)))
}

fn map_image(engine: &mut Unicorn<Trace>, pe: &PeImage, bytes: &[u8], base: u64) -> Result<()> {
    let image = pe.materialize(bytes, base)?;
    capture::materialized(engine, base, &image);
    indicators::materialized(engine, base, &image);
    uc(engine.mem_map(base, pe.image_size as u64, Prot::ALL))?;
    crate::cpu::write(engine, base, &image)?;
    engine.get_data_mut().apis.memory.map(
        base,
        pe.image_size as u64,
        Permissions::NONE,
        None,
        "guest image",
    )?;
    Ok(())
}
fn protect_image(engine: &mut Unicorn<Trace>, pe: &PeImage) -> Result<()> {
    uc(engine.mem_protect(pe.image_base, pe.image_size as u64, Prot::NONE))?;
    uc(engine.mem_protect(
        pe.image_base,
        (pe.headers_size as u64 + 4095) & !4095,
        Prot::READ,
    ))?;
    engine.get_data_mut().apis.memory.protect(
        pe.image_base,
        (pe.headers_size as u64 + 4095) & !4095,
        Permissions::READ,
    )?;
    for section in &pe.sections {
        let size = (section.virtual_size.max(section.raw_size) as u64 + 4095) & !4095;
        if size == 0 {
            continue;
        }
        let mut prot = Prot::NONE;
        if section.characteristics & 0x40000000 != 0 {
            prot |= Prot::READ;
        }
        if section.characteristics & 0x80000000 != 0 {
            prot |= Prot::WRITE;
        }
        if section.characteristics & 0x20000000 != 0 {
            prot |= Prot::EXEC;
        }
        if section.characteristics & 0xa0000000 == 0xa0000000 {
            cpu::watch(engine, pe.image_base + section.rva as u64, size)?;
        }
        uc(engine.mem_protect(pe.image_base + section.rva as u64, size, prot))?;
        let permissions = Permissions(
            (if section.characteristics & 0x40000000 != 0 {
                1
            } else {
                0
            }) | (if section.characteristics & 0x80000000 != 0 {
                2
            } else {
                0
            }) | (if section.characteristics & 0x20000000 != 0 {
                4
            } else {
                0
            }),
        );
        engine.get_data_mut().apis.memory.protect(
            pe.image_base + section.rva as u64,
            size,
            permissions,
        )?;
    }
    Ok(())
}
fn run_generated_image(bytes: &[u8], budget: u64, timeout_us: u64) -> Result<Execution> {
    run_generated_modules(bytes, &[], budget, timeout_us, None)
}
fn run_generated_modules(
    bytes: &[u8],
    companions: &[(String, Vec<u8>)],
    budget: u64,
    timeout_us: u64,
    load_base: Option<u64>,
) -> Result<Execution> {
    run_generated_with_broker(bytes, companions, budget, timeout_us, load_base, None)
}
fn run_generated_with_broker(
    bytes: &[u8],
    companions: &[(String, Vec<u8>)],
    budget: u64,
    timeout_us: u64,
    load_base: Option<u64>,
    broker: Option<Box<dyn emumee_core::broker::Client>>,
) -> Result<Execution> {
    run_generated_with_fixture_namespace(
        bytes, companions, budget, timeout_us, load_base, broker, false,
    )
}
fn run_generated_with_fixture_namespace(
    bytes: &[u8],
    companions: &[(String, Vec<u8>)],
    budget: u64,
    timeout_us: u64,
    load_base: Option<u64>,
    broker: Option<Box<dyn emumee_core::broker::Client>>,
    owned_callback_namespace: bool,
) -> Result<Execution> {
    run_generated_with_fixture_configuration(
        bytes,
        companions,
        budget,
        timeout_us,
        GeneratedConfiguration {
            load_base,
            broker,
            owned_callback_namespace,
            ..Default::default()
        },
    )
}
#[derive(Clone, Copy)]
enum ModuleProvenanceFault {
    MissingRootPath,
}
enum KernelReferenceInput {
    Pinned(Vec<u8>),
    #[cfg(test)]
    Generated(emumee_core::provider::RelocatedCodeView),
    #[cfg(test)]
    IntegratedGenerated(api::reference_mapping::IntegratedPrepared),
}

#[derive(Default)]
struct GeneratedConfiguration {
    module_provenance_fault: Option<ModuleProvenanceFault>,
    submitted_driver_service: Option<String>,
    submitted_persona_authorized: bool,
    kernel_reference: Option<KernelReferenceInput>,
    load_base: Option<u64>,
    broker: Option<Box<dyn emumee_core::broker::Client>>,
    owned_callback_namespace: bool,
    fixture_logical_processors: Option<u32>,
    unavailable_callback_namespace: bool,
    configured: Option<configured::Prepared>,
    capture: Option<capture::Prepared>,
    indicators: Option<indicators::Prepared>,
    plan_catalog: Option<emumee_core::artifacts::ArtifactCatalog>,
    plan_limits: Option<emumee_core::analysis_plan::Limits>,
    plan_fault: emumee_core::plan_runtime::Fault,
    instruction_window: Option<emumee_core::driver_input::InstructionWindow>,
}
fn run_generated_with_fixture_configuration(
    bytes: &[u8],
    companions: &[(String, Vec<u8>)],
    budget: u64,
    timeout_us: u64,
    configuration: GeneratedConfiguration,
) -> Result<Execution> {
    let GeneratedConfiguration {
        module_provenance_fault,
        submitted_driver_service,
        submitted_persona_authorized,
        kernel_reference,
        load_base,
        broker,
        owned_callback_namespace,
        fixture_logical_processors,
        unavailable_callback_namespace,
        configured,
        capture: prepared_capture,
        indicators: prepared_indicators,
        plan_catalog,
        plan_limits,
        plan_fault,
        instruction_window: observation_window,
    } = configuration;
    if let Some(window) = observation_window {
        ensure!(
            (1..=65_536).contains(&window.max_records)
                && window.start_instruction < budget
                && window
                    .start_instruction
                    .checked_add(u64::from(window.max_records))
                    .is_some_and(|end| end <= emumee_core::driver_input::MAX_INSTRUCTIONS),
            "Instruction observation window outside bounded execution profile"
        );
    }
    ensure!(
        budget > 0 && budget <= emumee_core::driver_input::MAX_INSTRUCTIONS,
        "instruction budget exceeds bounded profile"
    );
    ensure!(
        timeout_us > 0 && timeout_us <= 7_200_000_000,
        "timeout must be bounded"
    );
    ensure!(
        companions.len() <= 16,
        "Generated companion count exceeds 16"
    );
    ensure!(
        submitted_driver_service
            .as_deref()
            .is_none_or(emumee_core::driver_input::service_name_valid),
        "Submitted driver service name outside bounded profile"
    );
    ensure!(
        submitted_driver_service.is_none()
            || ((configured.is_none() || submitted_persona_authorized)
                && companions.is_empty()
                && !owned_callback_namespace
                && !unavailable_callback_namespace),
        "Submitted driver cannot mix fixture/configured authorities"
    );
    ensure!(
        !submitted_persona_authorized
            || (submitted_driver_service.is_some() && configured.is_some()),
        "Submitted persona authority requires submitted driver and validated state"
    );
    ensure!(
        kernel_reference.is_none()
            || ((configured.is_none() || submitted_persona_authorized)
                && companions.is_empty()
                && !owned_callback_namespace
                && !unavailable_callback_namespace
                && (submitted_driver_service.is_some() || broker.is_none())),
        "Kernel reference runner cannot mix configured or broker authorities"
    );
    let root_module_name = submitted_driver_service.as_ref().map_or_else(
        || {
            configured
                .as_ref()
                .map_or("generated-fixture.exe", |state| state.module_name())
                .to_owned()
        },
        |service| format!("{service}.sys"),
    );
    let declared_path = configured
        .as_ref()
        .and_then(|state| state.module_guest_path())
        .map(str::to_owned);
    let root_module_path = submitted_driver_service.as_ref().map_or_else(
        || {
            declared_path
                .clone()
                .unwrap_or_else(|| format!(r"C:\emumee\{}", root_module_name))
        },
        |service| {
            declared_path
                .clone()
                .unwrap_or_else(|| format!(r"C:\Windows\System32\drivers\{service}.sys"))
        },
    );
    let root_module_origin = if submitted_driver_service.is_some() {
        emumee_core::modules::ModuleOrigin::SubmittedDriver
    } else if declared_path.is_some() {
        emumee_core::modules::ModuleOrigin::ConfiguredGuest
    } else {
        emumee_core::modules::ModuleOrigin::OwnedGenerated
    };
    let mut pe = PeImage::parse(bytes, &root_module_name)?;
    ensure!(
        !pe.sample.managed,
        "fixture path requires an unmanaged image"
    );
    let arch = pe.sample.architecture;
    ensure!(
        kernel_reference.is_none()
            || (arch == Architecture::X64 && pe.sample.kind == emumee_core::pe::Kind::Driver),
        "Kernel reference runner requires an x64 generated driver"
    );
    let preferred_base = pe.image_base;
    let base = load_base.unwrap_or(preferred_base);
    ensure!(
        load_base.is_none() || pe.sample.kind == emumee_core::pe::Kind::Driver,
        "Kernel placement requires a driver target"
    );
    let mut engine = if let Some(prepared) = configured {
        ensure!(
            fixture_logical_processors.is_none()
                && !owned_callback_namespace
                && !unavailable_callback_namespace,
            "Configured state cannot mix fixture authority overrides"
        );
        ensure!(
            prepared.architecture() == arch
                && prepared.kernel() == (pe.sample.kind == emumee_core::pe::Kind::Driver),
            "Configured target differs from generated image"
        );
        new_engine_with_trace(prepared.into_trace()?)?
    } else {
        new_engine(arch)?
    };
    // Set before any guest start. The readback is published with the run so
    // long bounded replays can distinguish this native resource profile.
    let tcg_buffer_size = submitted_driver_service
        .as_ref()
        .map(|_| tcg::configure_submitted_driver(&mut engine))
        .transpose()?;
    engine.get_data_mut().plan_limits = plan_limits;
    engine.get_data_mut().instruction_window =
        observation_window.map(instruction_window::State::new);
    engine.get_data_mut().plan_fault = plan_fault;
    ensure!(
        prepared_indicators.is_none() || (prepared_capture.is_none() && plan_catalog.is_none()),
        "Distinct indicator/capture/plan policies cannot mix"
    );
    if let Some(catalog) = plan_catalog {
        configured::require_unpublished(engine.get_data())?;
        ensure!(
            prepared_capture.is_none(),
            "Distinct capture profiles cannot mix"
        );
        engine.get_data_mut().apis.captures = catalog;
    }
    if let Some(prepared) = prepared_capture {
        capture::install(&mut engine, prepared, &pe, bytes, base)?;
    }
    if let Some(prepared) = prepared_indicators {
        indicators::install(&mut engine, prepared, &pe, bytes, base)?;
    }
    if let Some(logical) = fixture_logical_processors {
        let mut profile = emumee_core::cpu::CpuProfile::default();
        match logical {
            12 => {}
            1..=32 => {
                profile.cores = logical;
                profile.threads_per_core = 1;
            }
            64 => {
                profile.cores = 32;
                profile.threads_per_core = 2;
            }
            _ => return Err(anyhow!("Owned IPI fixture topology is unsupported")),
        }
        engine
            .get_data_mut()
            .apis
            .configure_owned_fixture_cpu(&profile)?;
        engine.get_data_mut().cpu.profile = profile;
    }
    if owned_callback_namespace {
        ensure!(
            !unavailable_callback_namespace,
            "Conflicting callback fixture authorities"
        );
        engine
            .get_data_mut()
            .apis
            .callbacks
            .configure_owned_fixture_namespace()?;
    }
    if unavailable_callback_namespace {
        engine
            .get_data_mut()
            .apis
            .callbacks
            .configure_unavailable_fixture_namespace()?;
    }
    engine.get_data_mut().apis.broker = broker;
    engine
        .get_data_mut()
        .apis
        .target(arch, pe.sample.kind == emumee_core::pe::Kind::Driver)?;
    api::kernel_objects::initialize(&mut engine)?;
    if module_provenance_fault.is_some() {
        engine
            .get_data_mut()
            .apis
            .modules
            .add(&root_module_name, base, &pe)?;
    } else {
        engine.get_data_mut().apis.modules.add_with_path(
            &root_module_name,
            base,
            &pe,
            &root_module_path,
            root_module_origin,
        )?;
    }
    engine
        .get_data_mut()
        .apis
        .modules
        .set_primary(&root_module_name)?;
    map_image(&mut engine, &pe, bytes, base)?;
    pe.image_base = base;
    let mut parsed = Vec::new();
    for (name, bytes) in companions {
        let companion = PeImage::parse(bytes, name)?;
        ensure!(
            !companion.sample.managed,
            "Managed companion requires the IL interpreter"
        );
        engine.get_data_mut().apis.modules.add_with_path(
            name,
            companion.image_base,
            &companion,
            &format!(r"C:\emumee\{}", name),
            emumee_core::modules::ModuleOrigin::OwnedGenerated,
        )?;
        map_image(&mut engine, &companion, bytes, companion.image_base)?;
        parsed.push(companion);
    }
    // All guest modules are present before any import table is patched.
    api::bind(&mut engine, &pe)?;
    for companion in &parsed {
        api::bind(&mut engine, companion)?;
    }
    let pinned_reference = match &kernel_reference {
        Some(KernelReferenceInput::Pinned(bytes)) => {
            Some(api::reference_mapping::prepare_integrated(
                bytes,
                engine.get_data().machine.windows_build(),
            )?)
        }
        _ => None,
    };
    let integrated_reference = match &kernel_reference {
        #[cfg(test)]
        Some(KernelReferenceInput::IntegratedGenerated(prepared)) => Some(prepared),
        _ => pinned_reference.as_ref(),
    };
    let integrated_receipt = if let Some(reference) = integrated_reference {
        api::initialize_providers_with_reference(&mut engine, reference)?
    } else {
        api::initialize_providers(&mut engine)?;
        None
    };
    api::initialize_metadata_providers(&mut engine, &pe)?;
    for companion in &parsed {
        api::initialize_metadata_providers(&mut engine, companion)?;
    }
    // Static imports and later dynamic lookups must name the same guest entry.
    if !engine.get_data().apis.providers.is_empty() {
        api::bind(&mut engine, &pe)?;
        for companion in &parsed {
            api::bind(&mut engine, companion)?;
        }
    }
    protect_image(&mut engine, &pe)?;
    if submitted_driver_service.is_some() {
        image_writes::install(&mut engine, base, pe.image_size as u64)?;
    }
    for companion in &parsed {
        protect_image(&mut engine, companion)?;
    }
    let kernel_reference = match kernel_reference {
        Some(KernelReferenceInput::Pinned(_)) => {
            Some(integrated_receipt.context("Pinned reference provider was not initialized")?)
        }
        #[cfg(test)]
        Some(KernelReferenceInput::IntegratedGenerated(_)) => Some(
            integrated_receipt
                .context("Generated integrated reference provider was not initialized")?,
        ),
        #[cfg(test)]
        Some(KernelReferenceInput::Generated(view)) => Some(
            api::reference_mapping::map_generated_projection(&mut engine, &view)?,
        ),
        None => None,
    };
    let layout = engine
        .get_data()
        .apis
        .kernel_mode
        .then(|| emumee_core::kernel_layout::KernelLayout::for_architecture(arch));
    let stack = layout.map_or(STACK, |layout| layout.entry_stack);
    let objects = layout.map_or(OBJECTS, |layout| layout.driver_object);
    let registry = layout.map_or(OBJECTS + 512, |layout| layout.registry_path);
    let marker = layout.map_or(RETURN, |layout| layout.return_marker);
    let object_size = if layout.is_some() { 3 * 4096 } else { 4096 };
    engine.get_data_mut().return_marker = marker;
    uc(engine.mem_map(stack, STACK_SIZE, Prot::READ | Prot::WRITE))?;
    kernel_stack_writes::install(&mut engine, stack, STACK_SIZE)?;
    uc(engine.mem_map(marker, 4096, Prot::READ | Prot::EXEC))?;
    uc(engine.mem_map(objects, object_size, Prot::READ | Prot::WRITE))?;
    engine.get_data_mut().apis.memory.map(
        stack,
        STACK_SIZE,
        Permissions::RW,
        None,
        "kernel fixture stack",
    )?;
    engine.get_data_mut().apis.memory.map(
        marker,
        4096,
        Permissions::RX,
        None,
        "fixture return marker",
    )?;
    engine.get_data_mut().apis.memory.map(
        objects,
        object_size,
        Permissions::RW,
        None,
        "fixture driver objects",
    )?;
    let driver_section = if arch == Architecture::X64 && layout.is_some() {
        let authority = if submitted_driver_service.is_some() {
            kernel_reference.as_ref().and_then(|receipt| {
                match (
                    engine.get_data().machine.windows_build(),
                    receipt.source_sha256.as_str(),
                ) {
                    (22631, "4b954aae4b18a231b2254c0989b1b6bcc55741a8ef90a350f036d09cd480cc99") => {
                        Some(kernel_loader::Authority::PinnedReferenceX64)
                    }
                    (26200, "4a6af9a3dbbeb440c4a9fbe8a4d6832eae751ac3a85860d860b8313a737a2e3a") => {
                        Some(kernel_loader::Authority::PinnedHost26200X64)
                    }
                    _ => None,
                }
            })
        } else if module_provenance_fault.is_none() {
            Some(kernel_loader::Authority::GeneratedX64)
        } else {
            // An explicit malformed generated provenance fixture must reach the
            // module API refusal without publishing an invented loader node.
            None
        };
        authority
            .map(|authority| kernel_loader::initialize(&mut engine, authority))
            .transpose()?
    } else {
        None
    };
    let kernel_entry = layout
        .map(|layout| match submitted_driver_service.as_deref() {
            Some(service) => {
                boot::initialize_named(&mut engine, &pe, layout, service, driver_section)
            }
            None => boot::initialize(&mut engine, &pe, layout, driver_section),
        })
        .transpose()?;
    if layout.is_some() {
        api::kernel_thread_objects::initialize_root(&mut engine)?;
    }
    kernel_cpu::initialize(&mut engine)?;
    native_exceptions::install(&mut engine)?;
    time::initialize(&mut engine)?;
    let sp = stack + STACK_SIZE
        - if arch == Architecture::X64 {
            0x108
        } else {
            0x10c
        };
    if arch == Architecture::X64 {
        crate::cpu::write(&mut engine, sp, &marker.to_le_bytes())?;
        uc(engine.reg_write(RegisterX86::RSP, sp))?;
        uc(engine.reg_write(RegisterX86::RCX, objects))?;
        uc(engine.reg_write(RegisterX86::RDX, registry))?;
    } else {
        for (i, value) in [marker, objects, registry].into_iter().enumerate() {
            crate::cpu::write(
                &mut engine,
                sp + i as u64 * 4,
                &(value as u32).to_le_bytes(),
            )?;
        }
        uc(engine.reg_write(RegisterX86::ESP, sp))?;
    }
    uc(engine.add_code_hook(1, 0, |engine, pc, size| {
        if let Err(error) = plan_runtime::check_limits(engine) {
            engine.get_data_mut().apis.fault = Some(format!("{error:#}"));
            let _ = engine.emu_stop();
            return;
        }
        if engine.get_data().cpu.native_reads.pending() {
            cpu::native_reads::before_instruction(engine, pc);
        }
        if kernel_cpu::has_pending_msr(engine) {
            if let Err(error) = kernel_cpu::complete_msr_write(engine) {
                engine.get_data_mut().cpu.fault = Some(format!("{error:#}"));
                let _ = engine.emu_stop();
                return;
            }
        }
        if let Err(error) = native_exceptions::api_frame::before_instruction(engine, pc) {
            engine.get_data_mut().cpu.fault = Some(format!("{error:#}"));
            let _ = engine.emu_stop();
            return;
        }
        let api_gate = pc >= engine.get_data().apis.base
            && pc < engine.get_data().apis.end
            && !native_exceptions::api_frame::is_instruction(engine, pc);
        if api_gate && engine.get_data().apis.kernel_prompt.continuation_active() {
            api::kernel_prompt::before_api(engine, pc);
        }
        if api_gate && engine.get_data().apis.kernel_callback_continuation.active() {
            api::kernel_callback_continuation::before_api(engine, pc);
        }
        let architectural_boundary = api::native_loader::before_instruction(engine, pc)
            || ipi::before_instruction(engine, pc)
            || threads::dpc::before_instruction(engine, pc, size);
        let scheduler_boundary = !architectural_boundary && threads::before_instruction(engine, pc);
        if architectural_boundary || scheduler_boundary {
            // A quantum checkpoint can select this same ordinary thread again.
            // The scheduler validates its actual selected owner before restoring
            // a context; merely reaching a checkpoint is not a guest transfer.
            if engine.get_data().cpu.debug_control.active()
                && (architectural_boundary
                    || !matches!(engine.get_data().thread_action, Some(threads::Action::Yield)))
            {
                engine.get_data_mut().cpu.fault = Some(
                    "DEBUGCTL active scheduler/loader transition requires architectural tracing support".into(),
                );
            }
            let _ = engine.emu_stop();
            return;
        }
        if !api_gate && engine.get_data().apis.kernel_prompt.continuation_active() {
            api::kernel_prompt::before_native_instruction(engine, pc, size);
        }
        if engine.get_data().cpu.debug_control.active() {
            if let Err(error) = cpu::debug_control::before_instruction(engine, pc, size, api_gate) {
                engine.get_data_mut().cpu.fault = Some(format!("{error:#}"));
                let _ = engine.emu_stop();
                return;
            }
        }
        if !api_gate && engine.get_data().apis.kernel_callback_continuation.active() {
            api::kernel_callback_continuation::before_native_instruction(engine, pc, size);
        }
        if api_gate {
            let result = (|| -> Result<()> {
                ipi::observe_native_irql(engine)?;
                threads::dpc::observe_api(engine)?;
                if native_exceptions::c_scope::resume_api(engine, pc)? {
                    return Ok(());
                }
                if api::dynamic_loader::resume_api(engine, pc)? {
                    return Ok(());
                }
                if ipi::resume_api(engine, pc)? {
                    return Ok(());
                }
                if !ipi::active(engine)
                    && !threads::dpc::active(engine)
                    && threads::resume_api(engine, pc)?
                {
                    return Ok(());
                }
                plan_runtime::before_api(engine)?;
                api::dispatch(engine, pc)?;
                plan_runtime::check_limits(engine)
            })();
            if let Err(error) = result {
                engine.get_data_mut().apis.fault = Some(format!("{error:#}"));
            }
        }
        // A blocked gate has not executed its RET. Count that instruction only
        // when its owning thread resumes, and do not dispatch the API twice.
        if !matches!(
            engine.get_data().thread_action,
            Some(threads::Action::Wait { .. })
        ) && !matches!(engine.get_data().ipi_action, Some(ipi::Action::Begin))
            && !api::dynamic_loader::queued(engine)
            && !native_exceptions::queued(engine)
        {
            if engine
                .get_data()
                .instruction_window
                .as_ref()
                .is_some_and(|window| window.interested(engine.get_data().instructions))
            {
                instruction_window::before_instruction(engine, pc, size, api_gate);
            }
            engine.get_data_mut().instruction(pc, size);
            // These are our immutable RET gates, so they contain no CPU probes.
            // Keep the guest code page hot across API calls.
            if !api_gate {
                if let Err(error) = cpu::observe(engine, pc, size) {
                    engine.get_data_mut().cpu.fault = Some(format!("{error:#}"));
                }
            }
        }
        // Clock advances are batched every1000 instructions, and occur on time
        // APIs/TSC observations. Mirror those changes without a global read hook.
        if engine.get_data().clock.is_dirty() {
            if let Err(error) = time::sync(engine) {
                engine.get_data_mut().apis.fault = Some(format!("Shared clock model: {error:#}"));
            }
        }
        if engine.get_data().clock_error
            || engine.get_data().cpu.fault.is_some()
            || engine.get_data().apis.fault.is_some()
            || engine.get_data().thread_action.is_some()
            || engine.get_data().ipi_action.is_some()
            || api::dynamic_loader::queued(engine)
            || native_exceptions::queued(engine)
        {
            let _ = engine.emu_stop();
        }
    }))?;
    for (hook, access) in [
        (HookType::MEM_READ_PROT, "read"),
        (HookType::MEM_WRITE_PROT, "write"),
        (HookType::MEM_FETCH_PROT, "execute"),
        (HookType::MEM_READ_UNMAPPED, "read"),
        (HookType::MEM_WRITE_UNMAPPED, "write"),
        (HookType::MEM_FETCH_UNMAPPED, "execute"),
    ] {
        uc(
            engine.add_mem_hook(hook, 1, 0, move |engine, _, address, size, _| {
                if engine.get_data().native_memory_fault.is_none() {
                    let pc = engine.pc_read().unwrap_or(0);
                    engine.get_data_mut().native_memory_fault = Some(NativeMemoryFault {
                        access,
                        address,
                        size,
                        pc,
                    });
                }
                api::record_provider_access(engine, address, size, access);
                false
            }),
        )?;
    }
    configured::initialized(&mut engine)?;
    let start = Instant::now();
    let horizon = threads::ExecutionHorizon::new(timeout_us, budget);
    let startup = api::native_loader::prepare(&mut engine, &pe, bytes, companions, &parsed);
    let outcome = match startup {
        Ok(startup) => match api::native_loader::execute(
            &mut engine,
            startup,
            &pe,
            stack + STACK_SIZE - 0x200,
            &horizon,
        ) {
            Ok(outcome) => outcome,
            Err(error) => threads::Outcome {
                returned: false,
                value: None,
                error: Some(format!("{error:#}")),
            },
        },
        Err(error) => {
            let error = format!("{error:#}");
            engine.get_data_mut().loader_preparation_error = Some(error.clone());
            threads::Outcome {
                returned: false,
                value: None,
                error: Some(error),
            }
        }
    };
    let seconds = start.elapsed().as_secs_f64();
    let pc = uc(engine.pc_read())?;
    engine.get_data_mut().clock.flush_cycles()?;
    let timer_error = threads::timers::settle(&mut engine, outcome.returned);
    let file_storage = (!engine.get_data().apis.kernel_mode)
        .then(|| engine.get_data().apis.files.storage_report());
    // Preserve the actual sole handle/provenance authority before capture consumes files.
    let kernel_files = engine
        .get_data()
        .apis
        .kernel_mode
        .then(|| api::kernel_files::report(&engine));
    let files = std::mem::take(&mut engine.get_data_mut().apis.files);
    api::mdl::capture(&mut engine);
    api::callbacks::capture(&mut engine);
    capture::live_pool(&mut engine);
    if submitted_driver_service.is_some() {
        capture::live_stacks(&mut engine);
    }
    capture::settled(&mut engine, pc)?;
    indicators::settled(&mut engine, pc);
    let mut captures = std::mem::take(&mut engine.get_data_mut().apis.captures);
    for (path, data) in files.into_files() {
        if engine.get_data().machine.capture_file(&path, &data) {
            let source = if engine.get_data().machine.is_configured() {
                "configured_file_changed_at_stop"
            } else {
                "virtual_file_at_stop"
            };
            captures.add(data, ArtifactKind::GuestFile, source, &path);
        }
    }
    let capture_runtime = capture::report(&mut engine, &captures);
    engine.get_data_mut().cpu.report.debug_control = cpu::debug_control::report(&engine);
    let cpu_report = std::mem::take(&mut engine.get_data_mut().cpu.report);
    let kernel_cpu = kernel_cpu::report(&engine)?;
    let callback_error = api::callbacks::completion_error(&engine);
    let rundown_error = api::rundown::completion_error(&engine);
    let thread_object_error = api::kernel_thread_objects::completion_error(&engine);
    let rtl_error = api::kernel_rtl::completion_error(&engine);
    let spin_error = api::kernel_spin::completion_error(&engine);
    let (memory_strings, memory_string_sources) = indicators::take(&mut engine);
    let trace = engine.get_data();
    let count = trace.instructions;
    let uptime = trace.clock.uptime_ms;
    let tsc = trace.clock.tsc().wrapping_add(trace.cpu.tsc_offset);
    let tail = trace.tail();
    let error = if trace.clock_error {
        Some("Guest clock overflow".to_owned())
    } else if let Some(error) = &trace.cpu.fault {
        Some(error.clone())
    } else if let Some(error) = &trace.apis.fault {
        Some(error.clone())
    } else if let Some(error) = callback_error {
        Some(error)
    } else if let Some(error) = rundown_error {
        Some(error)
    } else if let Some(error) = thread_object_error {
        Some(error)
    } else if let Some(error) = rtl_error {
        Some(error)
    } else if let Some(error) = spin_error {
        Some(error)
    } else if let Some(error) = timer_error {
        Some(error)
    } else {
        outcome.error
    };
    let returned = outcome.returned && error.is_none();
    let completion = if error.is_some() {
        "error"
    } else if returned {
        "entry_return"
    } else if count >= budget {
        "instruction_budget"
    } else {
        "timeout"
    };
    let value = if returned { outcome.value } else { None };
    let mut report = Execution {
        native_exceptions: native_exceptions::report(&engine),
        native_loader: api::native_loader::report(&engine),
        dynamic_loader: api::dynamic_loader::report(&engine),
        closed_plan_fault: trace.plan_fault_evidence.clone(),
        capture_runtime,
        memory_strings,
        memory_string_sources,
        configuration:trace.machine.receipt(),
        environment_blocks: (!trace.apis.kernel_mode).then(||trace.apis.environment_blocks_report()),
        file_storage,
        kernel_files,
        file_enumeration: (!trace.apis.kernel_mode).then(||trace.apis.file_metadata.searches.report()),
        console_session: (!trace.apis.kernel_mode).then(|| trace.apis.console.model.report()),
        console: (!trace.apis.kernel_mode).then(|| trace.apis.crt_stdio.model.report().console),
        crt_stdio: (!trace.apis.kernel_mode).then(|| trace.apis.crt_stdio.model.state_report()),
        kernel_callbacks: trace.apis.kernel_mode.then(|| api::callbacks::report(&engine)),
        kernel_cache_aware_rundown: trace.apis.kernel_mode.then(|| api::rundown::report(&engine)),
        kernel_environment: trace.apis.kernel_mode.then(|| api::kernel_environment::report(&engine)),
        kernel_registry: trace.apis.kernel_mode.then(|| api::kernel_registry::report(&engine)),
        kernel_rtl: trace.apis.kernel_mode.then(||api::kernel_rtl::report(&engine)),
        kernel_prompt: trace.apis.kernel_mode.then(|| trace.apis.kernel_prompt.report_at_stop(completion, count)),
        kernel_callback_continuation: trace.apis.kernel_mode.then(|| trace.apis.kernel_callback_continuation.report_at_stop(completion, count)).flatten(),
        kernel_context_reads: trace.apis.kernel_mode.then(|| kernel_context_reads::report(&engine)),
        kernel_loader: kernel_loader::report(&engine),
        kernel_stack_writes: kernel_stack_writes::report(&engine),
        image_writes: image_writes::report(&engine),
        instruction_window: instruction_window::report(&engine, completion),
        kernel_modules:trace.apis.kernel_mode.then(||api::kernel_modules::report(&engine)),
        kernel_code_integrity:api::kernel_code_integrity::report(&engine),
        kernel_sections:api::kernel_sections::report(&engine),
        kernel_objects: trace.apis.kernel_mode.then(|| api::kernel_objects::report(&engine)),
        kernel_thread_objects: trace.apis.kernel_mode.then(|| api::kernel_thread_objects::report(&engine)),
        kernel_ipi:trace.apis.kernel_mode.then(||ipi::report(&engine)),
        kernel_reference,
        kernel_reference_unload_history: api::reference_unload::report(&engine),
        tcg_buffer_size,
        kernel_mdls: trace.apis.kernel_mode.then(|| api::mdl::report(&engine)),
        user_heaps: (!trace.apis.kernel_mode).then(|| trace.apis.heaps.clone()),
        network:trace.apis.network.clone(),
        backend: backend(),
        architecture: arch,
        completion_reason: completion,
        instruction_count: count,
        max_instructions: budget,
        guest_entry_return: value,
        final_pc: pc,
        native_memory_fault: trace.native_memory_fault.clone(),
        instruction_tail: tail,
        error,
        engine_seconds: seconds,
        instructions_per_second: count as f64 / seconds,
        virtual_uptime_ms: uptime,
        virtual_tsc: tsc,
        virtual_tsc_offset: trace.cpu.tsc_offset,
        virtual_tsc_adjust: trace.cpu.tsc_adjust,
        cpu: cpu_report,
        native_cpu_reads: cpu::native_reads::report(&engine, completion),
        kernel_cpu,
        kernel_entry,
        image_load: ImageLoad {
            preferred_base,
            base,
            entry: base + pe.entry_rva as u64,
            size: pe.image_size,
            relocated: base != preferred_base,
            scope: if submitted_driver_service.is_some() {
                "Checked materialization/relocation of an exact worker-verified submitted driver. Automatic placement and full Windows loader lifecycle remain pending."
            } else {
                "Checked materialization/relocation of generated images. Automatic placement, arbitrary companions and full Windows loader lifecycle remain pending."
            },
        },
        api_calls: trace.apis.calls,
        api_region: trace.apis.region(),
        synthetic_providers: trace.apis.providers.clone(),
        provider_denials:trace.apis.provider_denials.clone(),
        provider_denials_omitted:trace.apis.provider_denials_omitted,
        kernel_pool: trace.apis.kernel_mode.then(|| trace.apis.pool.clone()),
        kernel_pool_scope: trace.apis.kernel_mode.then_some("Bounded guest-only allocations with page backing. Uninitialized legacy/opt-out contents use deterministic 0xcd bytes. Physical paging, pool headers, NUMA, quota and verifier layouts are not modeled."),
        modeled_guest_regions: submitted_driver_service.as_ref().map(|_| {
            trace.apis.memory.regions().cloned().collect()
        }),
        modeled_guest_regions_scope: submitted_driver_service.as_ref().map(|_| {
            "Passive stop-time model region metadata only: base, size, permissions, owner and tag. It is not a byte snapshot, native Unicorn mapping audit, execution trace or proof of unpacking."
        }),
        api_events: trace.apis.events.clone(),
        api_events_omitted: trace.apis.calls - trace.apis.events.len() as u64,
        kernel_export_queries: trace.apis.kernel_export_queries.clone(),
        kernel_export_queries_omitted: trace.apis.kernel_export_queries_omitted,
        kernel_formatting: api::crt_format::kernel_report(&engine),
        loaded_modules: trace
            .apis
            .modules
            .modules()
            .map(|m| ModuleEvidence {
                name: m.name.clone(),
                base: m.base,
                size: m.size,
            })
            .collect(),
        artifacts: captures.items,
        capture_summary: captures.summary,
        kernel_state: if trace.apis.kernel_mode {
            Some(trace.apis.kernel.report(threads::GuardedMutexCountProtocol::for_target(
                trace.architecture,
                trace.machine.windows_build(),
            )))
        } else {
            None
        },
        kernel_threads: trace
            .threads
            .as_ref()
            .map(|threads| threads.report(trace.apis.kernel.save())),
        scope: if submitted_driver_service.is_some() {
            "Bounded submitted x64 native driver execution with caller-bound service identity. Guest return, capture and report are partial evidence; initialization, unpacking and full Windows parity are not implied."
        } else {
            "Generated CPU/PE/Windows API fixtures only. General sample execution awaits the remaining Windows model ports and parity checks."
        },
    };
    bound_callback_continuation_report(&mut report);
    Ok(report)
}

pub fn run_fixture(architecture: Architecture, iterations: u32, budget: u64) -> Result<Execution> {
    ensure!(
        iterations > 0 && iterations <= 100_000_000,
        "iterations must be1..100,000,000"
    );
    run_generated_image(
        &counted_driver(architecture, iterations),
        budget,
        120_000_000,
    )
}

/// Run only the generated counted x64 driver with the exact pinned NT code
/// reference mapped READ/NX for inspection. This does not admit supplied
/// driver bytes or alter synthetic provider dispatch.
pub fn run_counted_driver_with_pinned_kernel_reference(
    reference: &[u8],
    iterations: u32,
    budget: u64,
) -> Result<Execution> {
    ensure!(
        iterations > 0 && iterations <= 100_000_000,
        "iterations must be1..100,000,000"
    );
    ensure!(
        reference.len() <= 32 * 1024 * 1024,
        "Kernel reference exceeds input bound"
    );
    run_generated_with_fixture_configuration(
        &counted_driver(Architecture::X64, iterations),
        &[],
        budget,
        120_000_000,
        GeneratedConfiguration {
            kernel_reference: Some(KernelReferenceInput::Pinned(reference.to_vec())),
            ..Default::default()
        },
    )
}
pub fn run_cpu_fixture(
    architecture: Architecture,
    kind: emumee_core::fixtures::CpuFixture,
    budget: u64,
) -> Result<Execution> {
    run_generated_image(
        &emumee_core::fixtures::cpu_probe(architecture, kind),
        budget,
        30_000_000,
    )
}
pub fn run_api_fixture(
    architecture: Architecture,
    fixture: emumee_core::fixtures::ApiFixture,
    budget: u64,
) -> Result<Execution> {
    if let emumee_core::fixtures::ApiFixture::DynamicLoader(kind) = fixture {
        let (root, companions) = emumee_core::fixtures::dynamic_loader_probe(architecture, kind);
        return run_generated_modules(&root, &companions, budget, 30_000_000, None);
    }
    if let emumee_core::fixtures::ApiFixture::NativeLoader(kind) = fixture {
        let (root, companions) = emumee_core::fixtures::native_loader_probe(architecture, kind);
        return run_generated_modules(&root, &companions, budget, 30_000_000, None);
    }
    if let emumee_core::fixtures::ApiFixture::NativeFiles(kind) = fixture {
        return api::kernel_files::fixture(architecture, kind, budget);
    }
    if let emumee_core::fixtures::ApiFixture::KernelTimeConversion(kind) = fixture {
        if kind.configured_offset().is_some() {
            return api::kernel_time::fixture(architecture, kind, budget);
        }
    }
    if let emumee_core::fixtures::ApiFixture::NativeRegistry(kind) = fixture {
        return api::kernel_registry::fixture(architecture, kind, budget);
    }
    if let emumee_core::fixtures::ApiFixture::Modules(kind) = fixture {
        let load_base = matches!(
            kind,
            emumee_core::fixtures::ModuleFixture::RelocatedExtended
        )
        .then_some(if architecture == Architecture::X64 {
            0x140000000
        } else {
            0x400000
        });
        let fault = matches!(
            kind,
            emumee_core::fixtures::ModuleFixture::MissingProvenance
        )
        .then_some(ModuleProvenanceFault::MissingRootPath);
        return run_generated_with_fixture_configuration(
            &emumee_core::fixtures::api_probe(architecture, fixture),
            &[],
            budget,
            30_000_000,
            GeneratedConfiguration {
                load_base,
                module_provenance_fault: fault,
                ..Default::default()
            },
        );
    }
    if let emumee_core::fixtures::ApiFixture::Configured(kind, unicode) = fixture {
        return configured::fixture(architecture, kind, unicode, budget);
    }
    if let emumee_core::fixtures::ApiFixture::Ipi(kind) = fixture {
        return run_generated_with_fixture_configuration(
            &emumee_core::fixtures::api_probe(architecture, fixture),
            &[],
            budget,
            30_000_000,
            GeneratedConfiguration {
                fixture_logical_processors: Some(kind.logical()),
                ..Default::default()
            },
        );
    }
    if let emumee_core::fixtures::ApiFixture::Callback(kind) = fixture {
        if !kind.owned_namespace() {
            return run_generated_with_fixture_configuration(
                &emumee_core::fixtures::api_probe(architecture, fixture),
                &[],
                budget,
                30_000_000,
                GeneratedConfiguration {
                    unavailable_callback_namespace: true,
                    ..Default::default()
                },
            );
        }
        return run_generated_with_fixture_namespace(
            &emumee_core::fixtures::api_probe(architecture, fixture),
            &[],
            budget,
            30_000_000,
            None,
            None,
            kind.owned_namespace(),
        );
    }
    run_generated_image(
        &emumee_core::fixtures::api_probe(architecture, fixture),
        budget,
        30_000_000,
    )
}
pub fn run_internet_fixture(
    architecture: Architecture,
    fixture: emumee_core::fixtures::InternetFixture,
    budget: u64,
    broker: Box<dyn emumee_core::broker::Client>,
) -> Result<Execution> {
    run_generated_with_broker(
        &emumee_core::fixtures::internet_probe(architecture, fixture),
        &[],
        budget,
        30_000_000,
        None,
        Some(broker),
    )
}
pub fn run_winhttp_fixture(
    architecture: Architecture,
    fixture: emumee_core::fixtures::WinHttpFixture,
    budget: u64,
    broker: Box<dyn emumee_core::broker::Client>,
) -> Result<Execution> {
    run_generated_with_broker(
        &emumee_core::fixtures::winhttp_probe(architecture, fixture),
        &[],
        budget,
        30_000_000,
        None,
        Some(broker),
    )
}
pub fn run_download_fixture(
    architecture: Architecture,
    fixture: emumee_core::fixtures::DownloadFixture,
    budget: u64,
    broker: Box<dyn emumee_core::broker::Client>,
) -> Result<Execution> {
    run_generated_with_broker(
        &emumee_core::fixtures::download_probe(architecture, fixture),
        &[],
        budget,
        30_000_000,
        None,
        Some(broker),
    )
}
pub fn run_linked_fixture(
    architecture: Architecture,
    kind: emumee_core::fixtures::LinkedFixture,
    budget: u64,
) -> Result<Execution> {
    let (main, companions) = emumee_core::fixtures::linked_probe(architecture, kind);
    run_generated_modules(&main, &companions, budget, 30_000_000, None)
}
pub fn run_relocated_fixture(architecture: Architecture, budget: u64) -> Result<Execution> {
    let base = if architecture == Architecture::X64 {
        0xfffff80100000000
    } else {
        0x90000000
    };
    run_generated_modules(
        &emumee_core::fixtures::relocating_driver(architecture),
        &[],
        budget,
        30_000_000,
        Some(base),
    )
}

/// Execute already worker-verified submitted bytes. The caller owns isolation,
/// request/input binding and output recovery; this function does no host I/O.
pub fn run_submitted_driver(
    bytes: &[u8],
    service_name: &str,
    budget: u64,
    timeout_us: u64,
) -> Result<Execution> {
    run_submitted_driver_with_reference(bytes, service_name, budget, timeout_us, None)
}

/// Execute already worker-verified submitted bytes, optionally with only the
/// exact pinned NT code reference mapped as READ/NX inspection data. The
/// caller still owns isolation and request/input binding.
pub fn run_submitted_driver_with_reference(
    bytes: &[u8],
    service_name: &str,
    budget: u64,
    timeout_us: u64,
    reference: Option<&[u8]>,
) -> Result<Execution> {
    run_submitted_driver_with_reference_and_broker(
        bytes,
        service_name,
        budget,
        timeout_us,
        reference,
        None,
    )
}

/// Execute already worker-verified submitted bytes with an optional pinned
/// code reference and an optional bounded offline broker. The caller owns
/// confinement and request/input/broker receipt binding.
pub fn run_submitted_driver_with_reference_and_broker(
    bytes: &[u8],
    service_name: &str,
    budget: u64,
    timeout_us: u64,
    reference: Option<&[u8]>,
    broker: Option<Box<dyn emumee_core::broker::Client>>,
) -> Result<Execution> {
    run_submitted_driver_with_persona_and_reference_and_broker(
        bytes,
        service_name,
        budget,
        timeout_us,
        None,
        reference,
        broker,
    )
}

/// Execute worker-verified submitted bytes with a validated fullpersona
/// projection installed before entry. The caller owns containment and all
/// input, fixture, broker and output evidence binding.
pub fn run_submitted_driver_with_persona_and_reference_and_broker(
    bytes: &[u8],
    service_name: &str,
    budget: u64,
    timeout_us: u64,
    persona: Option<&[u8]>,
    reference: Option<&[u8]>,
    broker: Option<Box<dyn emumee_core::broker::Client>>,
) -> Result<Execution> {
    run_submitted_driver_observed(
        bytes,
        service_name,
        budget,
        timeout_us,
        SubmittedObservationInputs {
            persona,
            reference,
            broker,
            instruction_window: None,
        },
    )
}

/// Existing verified input authorities plus an optional passive diagnostic.
pub struct SubmittedObservationInputs<'a> {
    pub persona: Option<&'a [u8]>,
    pub reference: Option<&'a [u8]>,
    pub broker: Option<Box<dyn emumee_core::broker::Client>>,
    pub instruction_window: Option<emumee_core::driver_input::InstructionWindow>,
}

pub fn run_submitted_driver_observed(
    bytes: &[u8],
    service_name: &str,
    budget: u64,
    timeout_us: u64,
    inputs: SubmittedObservationInputs<'_>,
) -> Result<Execution> {
    let SubmittedObservationInputs {
        persona,
        reference,
        broker,
        instruction_window,
    } = inputs;
    ensure!(
        emumee_core::driver_input::service_name_valid(service_name),
        "Submitted driver service name outside bounded profile"
    );
    ensure!(
        !bytes.is_empty() && bytes.len() <= emumee_core::driver_input::MAX_INPUT,
        "Submitted driver input outside 128 MiB bound"
    );
    ensure!(
        reference.is_none_or(|raw| raw.len() <= 32 * 1024 * 1024),
        "Kernel reference exceeds input bound"
    );
    let module = format!("{service_name}.sys");
    let pe = PeImage::parse(bytes, &module)?;
    ensure!(
        pe.sample.architecture == Architecture::X64
            && pe.sample.kind == emumee_core::pe::Kind::Driver
            && !pe.sample.managed,
        "Submitted input requires an unmanaged x64 native driver"
    );
    let submitted_persona_authorized = persona.is_some();
    let configured = persona
        .map(|document| {
            let validated = emumee_core::fullpersona::decode(
                document,
                &emumee_core::fullpersona::ResolveContext::default(),
            )
            .map_err(anyhow::Error::msg)?;
            configured::Prepared::new(
                validated,
                configured::Request {
                    architecture: Architecture::X64,
                    kernel: true,
                    initial_processor: 0,
                    process: None,
                    budget,
                    timeout_us,
                },
            )?
            .bind_submitted_service(service_name)
        })
        .transpose()?;
    run_generated_with_fixture_configuration(
        bytes,
        &[],
        budget,
        timeout_us,
        GeneratedConfiguration {
            // Nonrelocatable images must use their preferred base. Relocatable
            // drivers take a stable kernel range for deterministic replays.
            load_base: (pe.directories[5].rva != 0
                && pe.directories[5].size != 0
                && pe.characteristics & 1 == 0)
                .then_some(0xfffff80100000000),
            submitted_driver_service: Some(service_name.to_owned()),
            submitted_persona_authorized,
            kernel_reference: reference.map(|raw| KernelReferenceInput::Pinned(raw.to_vec())),
            broker,
            configured,
            capture: Some(capture::Prepared::submitted()),
            instruction_window,
            ..Default::default()
        },
    )
}

/// Closed compiler-owned fixture only. This is not an arbitrary-image entry point.
pub fn run_driver_capture_entry_fixture() -> Result<Execution> {
    let bytes = emumee_core::driver_capture_fixture::Case::DriverEntry64
        .small_bytes()
        .ok_or_else(|| anyhow!("Owned DriverEntry fixture missing"))?;
    run_generated_image(&bytes, 1000, 120_000_000)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_dispatcher_keeps_native_and_managed_reports_unwrapped_and_distinct() {
        use emumee_core::protocol::FixtureKind as K;
        for arch in [Architecture::X86, Architecture::X64] {
            for (kind, backend, value) in [
                (K::Loop, "rust/unicorn-x86", 3),
                (K::ManagedLoop, "rust/managed-il", 3),
                (K::ManagedReturn, "rust/managed-il", 17),
            ] {
                let result = run_fixture_kind(arch, kind, 3, 1000).unwrap();
                assert_eq!(result.completion_reason(), "entry_return");
                assert!(result.artifacts().is_empty());
                let json = serde_json::to_value(&result).unwrap();
                assert_eq!(json["backend"], backend);
                assert_eq!(json["guest_entry_return"], value);
            }
        }
    }
    #[test]
    fn classified_unimplemented_kernel_symbols_resolve_but_deny_code_and_data_access() {
        use emumee_core::fixtures::ApiFixture as A;
        for (fixture, name, kind, access, error) in [
            (
                A::KernelCatalogCall,
                "KeInsertQueueDpc",
                "code",
                "execute",
                "FETCH_PROT",
            ),
            (
                A::KernelCatalogCodeRead,
                "KeInsertQueueDpc",
                "code",
                "read",
                "READ_PROT",
            ),
            (
                A::KernelCatalogDataRead,
                "MmSystemRangeStart",
                "data",
                "read",
                "READ_PROT",
            ),
        ] {
            let result = run_api_fixture(Architecture::X64, fixture, 1000).unwrap();
            assert_eq!(result.completion_reason, "error");
            assert!(
                result.error.as_deref().unwrap_or("").contains(error),
                "{fixture:?}: {:?}",
                result.error
            );
            assert_eq!(result.api_calls, 1);
            assert!(
                result.api_events[0]
                    .result
                    .is_some_and(|address| address != 0)
            );
            assert_eq!(result.provider_denials.len(), 1);
            let denial = &result.provider_denials[0];
            assert_eq!(
                (&*denial.name, denial.kind, denial.access, denial.offset),
                (name, kind, access, 0)
            );
            let metadata = result.synthetic_providers[0]
                .reference_catalog
                .as_ref()
                .unwrap();
            assert_eq!(
                (
                    metadata.reference_code_symbols,
                    metadata.reference_data_symbols
                ),
                (3180, 77)
            );
            assert!(metadata.protected_symbols > 3000);
            assert_eq!(result.guest_entry_return, None);
        }
    }
    #[test]
    fn concurrent_requests_keep_independent_guest_results_with_native_lifetime_guards() {
        std::thread::scope(|scope| {
            let workers = (0..8)
                .map(|index| {
                    scope.spawn(move || {
                        let arch = if index % 2 == 0 {
                            Architecture::X64
                        } else {
                            Architecture::X86
                        };
                        for iteration in 1..=16 {
                            let count = index * 16 + iteration;
                            let result = run_fixture(arch, count as u32, 10000).unwrap();
                            assert_eq!(result.guest_entry_return, Some(count as u64));
                            assert_eq!(result.error, None);
                        }
                    })
                })
                .collect::<Vec<_>>();
            for worker in workers {
                worker.join().unwrap();
            }
        });
    }
    #[test]
    fn kernel_pool_zeroing_pointer_width_reuse_executable_and_free_lifecycles() {
        use emumee_core::fixtures::ApiFixture as A;
        for arch in [Architecture::X86, Architecture::X64] {
            for fixture in [A::PoolLifecycle, A::PoolExecutable, A::PoolTooLarge] {
                let result = run_api_fixture(arch, fixture, 1000).unwrap();
                assert_eq!(result.error, None, "{arch:?} {fixture:?}");
                assert_eq!(
                    result.guest_entry_return,
                    Some(u64::from(!matches!(fixture, A::PoolTooLarge)))
                );
                let pool = result.kernel_pool.unwrap();
                let count = if matches!(fixture, A::PoolLifecycle) {
                    2
                } else if matches!(fixture, A::PoolExecutable) {
                    1
                } else {
                    0
                };
                assert_eq!(pool.total_allocations, count);
                assert_eq!(pool.total_frees, count);
                assert_eq!(pool.mapped_bytes, 0);
                assert!(pool.allocations.is_empty());
                let partial = run_api_fixture(arch, fixture, result.instruction_count - 1).unwrap();
                assert_eq!(partial.completion_reason, "instruction_budget");
                assert_eq!(partial.guest_entry_return, None);
            }
        }
    }
    #[test]
    fn legacy_zeroed_nx_pool_modifier_uses_zeroed_nonexecutable_storage() {
        use emumee_core::fixtures::ApiFixture as A;
        for arch in [Architecture::X86, Architecture::X64] {
            let result = run_api_fixture(arch, A::PoolZeroNx, 1000).unwrap();
            assert_eq!(result.error, None, "{arch:?}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(1));
            let expected_base = if arch == Architecture::X64 {
                0xffffb00000000000
            } else {
                0xe0000000
            };
            assert!(result.api_events.iter().any(|event| {
                event.api == "ntoskrnl.ExAllocatePoolWithTag"
                    && event.arguments == [0x600, 4097, 0x54535552]
                    && event.result == Some(expected_base)
            }));
            let pool = result.kernel_pool.unwrap();
            assert_eq!(pool.total_allocations, 1);
            assert_eq!(pool.total_frees, 1);
            assert!(pool.allocations.is_empty());
        }
    }
    #[test]
    fn pool_nx_use_after_free_tags_irql_and_required_flags_fail_explicitly() {
        use emumee_core::fixtures::ApiFixture as A;
        for arch in [Architecture::X86, Architecture::X64] {
            for (fixture, message, live) in [
                (A::PoolNxExecute, "FETCH_PROT", 1),
                (A::PoolFreedRead, "READ_UNMAPPED", 0),
                (A::PoolBadTag, "tag mismatch", 1),
                (A::PoolPagedIrql, "IRQL", 0),
                (A::PoolBadFlags, "flags are not modeled", 0),
                (A::PoolDoubleFree, "live pool allocation", 0),
            ] {
                let result = run_api_fixture(arch, fixture, 1000).unwrap();
                assert_eq!(result.completion_reason, "error");
                assert!(
                    result.error.as_deref().unwrap_or("").contains(message),
                    "{arch:?} {fixture:?}: {:?}",
                    result.error
                );
                assert_eq!(result.kernel_pool.unwrap().allocations.len(), live);
                assert_eq!(result.guest_entry_return, None);
            }
        }
    }
    #[test]
    fn dynamic_calls_execute_through_synthetic_pe_exports_and_preserve_pointer_width() {
        use emumee_core::fixtures::ApiFixture as A;
        for arch in [Architecture::X86, Architecture::X64] {
            for fixture in [
                A::KernelResolve,
                A::UserResolveA,
                A::UserResolveW,
                A::UserResolveBadModule,
            ] {
                let result = run_api_fixture(arch, fixture, 1000).unwrap();
                assert_eq!(result.error, None, "{arch:?} {fixture:?}");
                assert_eq!(
                    result.guest_entry_return,
                    Some(if matches!(fixture, A::KernelResolve) {
                        1
                    } else if matches!(fixture, A::UserResolveBadModule) {
                        126
                    } else {
                        1024
                    })
                );
                assert!(!result.synthetic_providers.is_empty());
                let base = result.synthetic_providers[0].base;
                if !matches!(fixture, A::UserResolveBadModule) {
                    let index = usize::from(!matches!(fixture, A::KernelResolve));
                    let address = result.api_events[index].result.unwrap();
                    assert!(address >= base + 0x1000 && address < base + 0x2000);
                    assert!(
                        result
                            .instruction_tail
                            .iter()
                            .any(|entry| entry.pc == address)
                    );
                }
                let partial = run_api_fixture(arch, fixture, result.instruction_count - 1).unwrap();
                assert_eq!(partial.completion_reason, "instruction_budget");
                assert_eq!(partial.guest_entry_return, None);
            }
        }
    }
    #[test]
    fn dynamic_resolution_rejects_invalid_unicode_irql_and_unknown_windows_availability() {
        use emumee_core::fixtures::ApiFixture as A;
        for arch in [Architecture::X86, Architecture::X64] {
            for (fixture, message) in [
                (A::KernelResolveBadLength, "UNICODE_STRING"),
                (A::KernelResolveIrql, "PASSIVE_LEVEL"),
                (A::KernelResolveUnknown, "availability is not established"),
                (A::UserResolveUnknown, "availability is not established"),
            ] {
                let result = run_api_fixture(arch, fixture, 1000).unwrap();
                assert_eq!(result.completion_reason, "error");
                assert!(
                    result.error.as_deref().unwrap_or("").contains(message),
                    "{arch:?} {fixture:?}: {:?}",
                    result.error
                );
                assert_eq!(result.guest_entry_return, None);
            }
        }
    }
    use emumee_core::fixtures::ApiFixture;
    #[test]
    fn relocated_driver_code_and_entry_fields_use_the_loaded_kernel_base() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let result = run_relocated_fixture(architecture, 1000).unwrap();
            assert_eq!(result.completion_reason, "entry_return", "{result:?}");
            assert_eq!(result.guest_entry_return, Some(17));
            let base = if architecture == Architecture::X64 {
                0xfffff80100000000
            } else {
                0x90000000
            };
            assert_eq!(result.image_load.base, base);
            assert!(result.image_load.relocated);
            // The catalog is name ordered; default kernel metadata can sort
            // before the root image without changing its loaded identity.
            assert_eq!(
                result
                    .loaded_modules
                    .iter()
                    .filter(|module| module.base == base)
                    .count(),
                1
            );
            assert_eq!(result.instruction_tail[0].pc, base + 0x1000);
            let partial =
                run_relocated_fixture(architecture, result.instruction_count - 1).unwrap();
            assert_eq!(partial.completion_reason, "instruction_budget");
            assert_eq!(partial.guest_entry_return, None);
            assert!(
                run_generated_modules(
                    &emumee_core::fixtures::counted_driver(architecture, 17),
                    &[],
                    1000,
                    30_000_000,
                    Some(base)
                )
                .is_err()
            );
        }
    }
    #[test]
    fn driver_entry_arguments_stacks_and_thread_pointers_use_separate_kernel_storage() {
        use emumee_core::fixtures::CpuFixture as C;
        for architecture in [Architecture::X86, Architecture::X64] {
            let result = run_cpu_fixture(architecture, C::KernelEntry, 1000).unwrap();
            assert_eq!(result.completion_reason, "entry_return", "{result:?}");
            assert_eq!(result.guest_entry_return, Some(1));
            let entry = result.kernel_entry.unwrap();
            assert_eq!(entry.layout.return_marker, result.final_pc);
            assert_ne!(entry.layout.registry_path, entry.layout.root_thread);
            let boot = run_cpu_fixture(architecture, C::KernelBoot, 1000).unwrap();
            assert_eq!(boot.guest_entry_return, Some(1), "{boot:?}");
            assert_eq!(
                boot.kernel_cpu.unwrap().pcr_current_thread,
                entry.layout.root_thread
            );
        }
    }
    #[test]
    fn kernel_api_imports_use_system_pointers_while_user_imports_stay_in_user_space() {
        for architecture in [Architecture::X86, Architecture::X64] {
            for fixture in [ApiFixture::KernelApiAddress, ApiFixture::UserApiAddress] {
                let result = run_api_fixture(architecture, fixture, 1000).unwrap();
                assert_eq!(result.completion_reason, "entry_return", "{result:?}");
                assert_eq!(result.guest_entry_return, Some(1));
                assert_eq!(result.api_calls, 1);
                let region = result.api_region.unwrap();
                let expected = match (architecture, fixture) {
                    (Architecture::X64, ApiFixture::KernelApiAddress) => 0xfffff80200000000,
                    (Architecture::X86, ApiFixture::KernelApiAddress) => 0x82000000,
                    _ => 0x68000000,
                };
                assert_eq!(region.base, expected);
                assert_eq!((region.size, region.bindings), (65536, 1));
            }
        }
    }
    #[test]
    fn tsc_msr_accesses_share_the_virtual_counter_and_adjustment_state() {
        use emumee_core::fixtures::CpuFixture as C;
        for architecture in [Architecture::X86, Architecture::X64] {
            for fixture in [
                C::TscMsrRead,
                C::TscMsrWrite,
                C::TscMsrWrap,
                C::TscAdjust,
                C::TscAdjustLink,
                C::TscAdjustReset,
            ] {
                let result = run_cpu_fixture(architecture, fixture, 1000).unwrap();
                assert_eq!(result.completion_reason, "entry_return", "{result:?}");
                assert_eq!(result.guest_entry_return, Some(1), "{result:?}");
                assert_eq!(result.virtual_uptime_ms, 523812000);
                if matches!(fixture, C::TscAdjust) {
                    assert_eq!(
                        (result.virtual_tsc_offset, result.virtual_tsc_adjust),
                        (3000, 3000)
                    );
                }
                if matches!(fixture, C::TscAdjustReset) {
                    assert_eq!(
                        (result.virtual_tsc_offset, result.virtual_tsc_adjust),
                        (0, 0)
                    );
                }
            }
            let user = run_cpu_fixture(architecture, C::TscMsrUser, 1000).unwrap();
            assert_eq!(user.completion_reason, "error");
            assert!(user.error.unwrap().contains("CPL0 driver context"));
            let threaded = run_api_fixture(architecture, ApiFixture::ThreadTsc, 10000).unwrap();
            assert_eq!(threaded.guest_entry_return, Some(1), "{threaded:?}");
            assert_eq!(
                (threaded.cpu.tsc_msr_reads, threaded.cpu.tsc_msr_writes),
                (1, 1)
            );
        }
    }
    #[test]
    fn per_cpu_msr_changes_are_not_rewound_by_thread_context_restore() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let result = run_api_fixture(architecture, ApiFixture::ThreadMsr, 10000).unwrap();
            assert_eq!(result.completion_reason, "entry_return", "{result:?}");
            assert_eq!(result.guest_entry_return, Some(0x12345678), "{result:?}");
            let cpu = result.kernel_cpu.unwrap();
            assert_eq!(cpu.tracked_msr_write_observations, 1);
            assert_eq!(cpu.msr_context_repairs, 1);
            assert!(
                cpu.tracked_msrs
                    .iter()
                    .any(|entry| entry.index == 0xc0000082 && entry.value == 0x12345678)
            );
            let aux = run_cpu_fixture(
                architecture,
                emumee_core::fixtures::CpuFixture::TscAux,
                1000,
            )
            .unwrap();
            assert_eq!(aux.guest_entry_return, Some(1), "{aux:?}");
            assert_eq!(aux.cpu.rdtscp, 1);
        }
    }
    #[test]
    fn syscall_enters_validated_guest_lstar_and_preserves_architectural_registers() {
        use emumee_core::fixtures::CpuFixture as C;
        let result = run_cpu_fixture(Architecture::X64, C::SystemCall, 1000).unwrap();
        assert_eq!(result.completion_reason, "entry_return", "{result:?}");
        assert_eq!(result.guest_entry_return, Some(1));
        for budget in 1..result.instruction_count {
            let partial = run_cpu_fixture(Architecture::X64, C::SystemCall, budget).unwrap();
            assert_eq!(
                partial.completion_reason, "instruction_budget",
                "{partial:?}"
            );
            assert_eq!(partial.instruction_count, budget);
            assert_eq!(partial.guest_entry_return, None);
            assert_eq!(
                partial.kernel_cpu.unwrap().tracked_msr_write_observations,
                u64::from(budget >= 4)
            );
        }
        let cpu = result.kernel_cpu.unwrap();
        assert_eq!(cpu.system_entry_attempts, 1);
        assert_eq!(cpu.system_entry_tail.len(), 1);
        assert!(cpu.system_entry_tail[0].accepted);
        assert_eq!(cpu.system_entry_tail[0].target, Some(0x140001180));
        let bad = run_cpu_fixture(Architecture::X64, C::SystemCallBadTarget, 1000).unwrap();
        assert_eq!(bad.completion_reason, "error");
        assert!(bad.error.unwrap().contains("not executable guest code"));
        assert!(!bad.kernel_cpu.unwrap().system_entry_tail[0].accepted);
        for architecture in [Architecture::X86, Architecture::X64] {
            for fixture in [C::SystemReturn, C::SystemEnter, C::SystemExit] {
                let result = run_cpu_fixture(architecture, fixture, 1000).unwrap();
                assert_eq!(result.completion_reason, "error");
                assert_eq!(result.guest_entry_return, None);
                assert!(result.error.unwrap().contains("Unmodeled"));
                assert!(!result.kernel_cpu.unwrap().system_entry_tail[0].accepted);
            }
        }
        let x86 = run_cpu_fixture(Architecture::X86, C::SystemCall, 1000).unwrap();
        assert!(x86.error.unwrap().contains("Unmodeled SYSCALL"));
    }
    #[test]
    fn bounded_native_slices_do_not_resume_a_halted_cpu_or_skip_wall_deadlines() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut bytes = emumee_core::fixtures::counted_driver(architecture, 1);
            bytes[0x200] = 0xf4; // HLT followed by the original code must not resume.
            let halted = run_generated_image(&bytes, 10000, 1_000_000).unwrap();
            assert_eq!(halted.completion_reason, "error", "{halted:?}");
            assert_eq!(halted.guest_entry_return, None);
            assert_eq!(halted.instruction_count, 1);
            assert!(halted.error.unwrap().contains("halted"));
            let bytes = emumee_core::fixtures::counted_driver(architecture, 100_000_000);
            let timed = run_generated_image(&bytes, 1_000_000_000, 1).unwrap();
            assert_eq!(timed.completion_reason, "timeout");
            assert_eq!(timed.guest_entry_return, None);
            assert!(timed.instruction_count <= 4096);
            let counted = run_generated_image(
                &emumee_core::fixtures::counted_driver(architecture, 3000),
                10000,
                30_000_000,
            )
            .unwrap();
            assert_eq!(counted.instruction_count, 9003);
            assert_eq!(counted.guest_entry_return, Some(3000));
        }
    }
    #[test]
    fn event_reset_modes_real_handoff_and_virtual_timeouts_have_cpu_continuations() {
        for architecture in [Architecture::X86, Architecture::X64] {
            for fixture in [
                ApiFixture::EventAuto,
                ApiFixture::EventManual,
                ApiFixture::EventHandoff,
            ] {
                let result = run_api_fixture(architecture, fixture, 10000).unwrap();
                assert_eq!(result.completion_reason, "entry_return", "{result:?}");
                assert_eq!(result.guest_entry_return, Some(1), "{result:?}");
                if matches!(fixture, ApiFixture::EventHandoff) {
                    let threads = result.kernel_threads.unwrap();
                    assert_eq!(
                        (
                            threads.count,
                            threads.exited,
                            threads.waits,
                            threads.resumed_waits
                        ),
                        (2, 2, 1, 1)
                    );
                    assert!(
                        result
                            .api_events
                            .iter()
                            .any(|event| event.effect == Some("event_signaled")
                                && event.result == Some(0)
                                && !event.pending)
                    );
                }
            }
            for fixture in [
                ApiFixture::EventTimeout,
                ApiFixture::EventAbsolute,
                ApiFixture::EventLongTimeout,
            ] {
                let result = run_api_fixture(architecture, fixture, 10000).unwrap();
                assert_eq!(result.completion_reason, "entry_return", "{result:?}");
                assert_eq!(result.guest_entry_return, Some(0x102));
                assert!(result.virtual_uptime_ms >= 523812025);
                if matches!(fixture, ApiFixture::EventLongTimeout) {
                    assert!(result.virtual_uptime_ms >= 523812000 + 86400000);
                }
                let threads = result.kernel_threads.unwrap();
                assert_eq!(
                    (
                        threads.count,
                        threads.exited,
                        threads.waits,
                        threads.resumed_waits
                    ),
                    (1, 1, 1, 1)
                );
                assert_eq!(result.api_events[1].effect, Some("wait_timeout"));
                assert!(!result.api_events[1].pending);
            }
        }
    }
    #[test]
    fn unsupported_event_states_and_deadlocks_never_fake_a_return() {
        for architecture in [Architecture::X86, Architecture::X64] {
            for (fixture, message) in [
                (ApiFixture::EventDeadlock, "deadlock"),
                (ApiFixture::EventIrql, "above APC_LEVEL"),
                (ApiFixture::EventAlertable, "non-alertable"),
                (ApiFixture::EventTamper, "diverges"),
            ] {
                let result = run_api_fixture(architecture, fixture, 10000).unwrap();
                assert_eq!(result.completion_reason, "error", "{result:?}");
                assert_eq!(result.guest_entry_return, None);
                assert!(result.error.unwrap().contains(message));
                if matches!(fixture, ApiFixture::EventDeadlock) {
                    assert!(result.api_events[1].pending);
                }
            }
        }
    }
    #[test]
    fn time_apis_and_readonly_shared_aliases_follow_one_clock() {
        use emumee_core::fixtures::CpuFixture as C;
        for architecture in [Architecture::X86, Architecture::X64] {
            for fixture in [ApiFixture::UserTime, ApiFixture::KernelTime] {
                let result = run_api_fixture(architecture, fixture, 1000).unwrap();
                assert_eq!(result.completion_reason, "entry_return", "{result:?}");
                assert_eq!(result.guest_entry_return, Some(1), "{result:?}");
                assert!(result.api_events.last().unwrap().result.is_none());
            }
            let invalid = run_api_fixture(architecture, ApiFixture::TimeBadOutput, 1000).unwrap();
            assert_eq!(invalid.guest_entry_return, Some(998));
            assert_eq!(invalid.api_events[0].result, Some(0));
            let shared = run_cpu_fixture(architecture, C::SharedRead, 10000).unwrap();
            assert_eq!(shared.completion_reason, "entry_return", "{shared:?}");
            assert_eq!(shared.guest_entry_return, Some(1));
            let write = run_cpu_fixture(architecture, C::SharedWrite, 1000).unwrap();
            assert_eq!(write.completion_reason, "error");
            assert!(write.error.unwrap().contains("WRITE_PROT"));
        }
    }
    #[test]
    fn kernel_boot_context_is_guest_visible_and_never_disables_map_permissions() {
        use emumee_core::fixtures::CpuFixture as C;
        for architecture in [Architecture::X86, Architecture::X64] {
            let result = run_cpu_fixture(architecture, C::KernelBoot, 1000).unwrap();
            assert_eq!(result.completion_reason, "entry_return", "{result:?}");
            assert_eq!(result.guest_entry_return, Some(1), "{result:?}");
            let cpu = result.kernel_cpu.unwrap();
            assert_eq!(cpu.initial.cr0, 0x80050033);
            assert_eq!(
                cpu.initial.cs,
                if architecture == Architecture::X64 {
                    0x10
                } else {
                    8
                }
            );
            assert_eq!(cpu.pcr_current_thread, cpu.current_thread);
            assert_eq!(cpu.pcr_irql, 0);
            let result = run_cpu_fixture(architecture, C::KernelWriteProtected, 1000).unwrap();
            assert_eq!(result.completion_reason, "error");
            assert!(result.error.unwrap().contains("WRITE_PROT"));
            assert_eq!(result.kernel_cpu.unwrap().current.cr0 & 0x10000, 0);
            for fixture in [
                ApiFixture::GuardedMutex,
                ApiFixture::GuardedIrql,
                ApiFixture::MutexHandoff,
            ] {
                let result = run_api_fixture(architecture, fixture, 10000).unwrap();
                let cpu = result.kernel_cpu.unwrap();
                assert_eq!(cpu.pcr_current_thread, cpu.current_thread);
                assert_eq!(cpu.pcr_irql, result.kernel_state.unwrap().irql);
            }
            let user = run_api_fixture(architecture, ApiFixture::UserState, 1000).unwrap();
            assert!(user.kernel_cpu.is_none());
        }
    }
    #[test]
    fn cpu_identity_clock_and_self_modifying_code_are_guest_deterministic() {
        use emumee_core::fixtures::CpuFixture as C;
        for architecture in [Architecture::X86, Architecture::X64] {
            for (kind, cpuid, rdtsc, rdtscp, xgetbv) in [
                (C::Identity, 5, 0, 0, 0),
                (C::Time, 0, 1, 1, 1),
                (C::Rewrite, 1, 1, 0, 0),
            ] {
                let result = run_cpu_fixture(architecture, kind, 1000).unwrap();
                assert_eq!(result.completion_reason, "entry_return", "{result:?}");
                assert_eq!(result.guest_entry_return, Some(1), "{result:?}");
                assert_eq!(
                    (
                        result.cpu.cpuid,
                        result.cpu.rdtsc,
                        result.cpu.rdtscp,
                        result.cpu.xgetbv
                    ),
                    (cpuid, rdtsc, rdtscp, xgetbv)
                );
                let repeated = run_cpu_fixture(architecture, kind, 1000).unwrap();
                assert_eq!(result.virtual_tsc, repeated.virtual_tsc);
                assert_eq!(result.instruction_count, repeated.instruction_count);
                let partial =
                    run_cpu_fixture(architecture, kind, result.instruction_count - 1).unwrap();
                assert_eq!(partial.completion_reason, "instruction_budget");
                assert_eq!(partial.instruction_count, result.instruction_count - 1);
                assert_eq!(partial.guest_entry_return, None);
            }
            let result = run_cpu_fixture(architecture, C::BadXcr, 1000).unwrap();
            assert_eq!(result.completion_reason, "error");
            assert!(result.error.unwrap().contains("XGETBV index"));
            assert_eq!(result.guest_entry_return, None);
        }
    }
    #[test]
    fn imports_and_forwarders_execute_actual_guest_export_code() {
        use emumee_core::fixtures::LinkedFixture;
        for arch in [Architecture::X86, Architecture::X64] {
            for kind in [LinkedFixture::Direct, LinkedFixture::Forwarded] {
                let result = run_linked_fixture(arch, kind, 10000).unwrap();
                assert_eq!(
                    result.completion_reason, "entry_return",
                    "{:?}",
                    result.error
                );
                assert_eq!(result.guest_entry_return, Some(17));
                assert_eq!(result.api_calls, 0);
                let companion_pc = if arch == Architecture::X64 {
                    0x150001000
                } else {
                    0x501000
                };
                let actual_pc = if matches!(kind, LinkedFixture::Forwarded) {
                    companion_pc
                        + if arch == Architecture::X64 {
                            0x10000000
                        } else {
                            0x100000
                        }
                } else {
                    companion_pc
                };
                assert!(
                    result
                        .instruction_tail
                        .iter()
                        .any(|entry| entry.pc == actual_pc)
                );
            }
        }
    }
    #[test]
    fn guest_file_round_trip_obeys_stack_arguments_and_never_opens_host_files() {
        for arch in [Architecture::X86, Architecture::X64] {
            for fixture in [ApiFixture::FileRoundTripA, ApiFixture::FileRoundTripW] {
                let result = run_api_fixture(arch, fixture, 10000).unwrap();
                assert_eq!(
                    result.completion_reason, "entry_return",
                    "{:?}",
                    result.error
                );
                assert_eq!(result.guest_entry_return, Some(0x54535552));
                assert_eq!(result.api_calls, 6);
                assert_eq!(result.artifacts.len(), 1);
                assert_eq!(result.artifacts[0].data, b"RUST");
                assert_eq!(result.api_events[0].arguments.len(), 7);
                assert_eq!(result.api_events[0].result, Some(0x100));
                assert_eq!(result.api_events[1].arguments[4], 0);
                assert!(result.api_events.iter().all(|event| event.error.is_none()));
            }
        }
    }
    #[test]
    fn file_access_rights_and_cpu_page_permissions_reject_api_transfers() {
        for arch in [Architecture::X86, Architecture::X64] {
            for (fixture, error, index) in [
                (ApiFixture::FileReadOnly, 5, 1),
                (ApiFixture::FileReadCode, 998, 3),
            ] {
                let result = run_api_fixture(arch, fixture, 10000).unwrap();
                assert_eq!(
                    result.completion_reason, "entry_return",
                    "{:?}",
                    result.error
                );
                assert_eq!(result.guest_entry_return, Some(error));
                assert_eq!(result.api_events[index].result, Some(0));
                assert_eq!(result.api_events[index].last_error, error as u32);
            }
        }
    }
    #[test]
    fn guarded_mutex_ownership_and_irql_restore_through_native_calls() {
        for arch in [Architecture::X86, Architecture::X64] {
            let result = run_api_fixture(arch, ApiFixture::GuardedMutex, 10000).unwrap();
            assert_eq!(
                result.completion_reason, "entry_return",
                "{:?}",
                result.error
            );
            assert_eq!(result.guest_entry_return, Some(1));
            assert_eq!(result.api_calls, 7);
            assert_eq!(result.api_events[3].result, Some(1));
            assert_eq!(result.api_events[5].result, Some(0));
            let kernel = result.kernel_state.unwrap();
            assert_eq!(kernel.irql, 0);
            assert_eq!(kernel.critical_depth, 0);
            assert_eq!(kernel.owned_mutexes, 0);
        }
    }
    #[test]
    fn system_thread_contexts_execute_guest_code_before_root_spin_can_return() {
        for arch in [Architecture::X86, Architecture::X64] {
            for fixture in [ApiFixture::SystemThread, ApiFixture::SystemThreadReturn] {
                let result = run_api_fixture(arch, fixture, 10000).unwrap();
                assert_eq!(
                    result.completion_reason, "entry_return",
                    "{:?}",
                    result.error
                );
                assert_eq!(result.guest_entry_return, Some(0));
                let threads = result.kernel_threads.unwrap();
                assert_eq!(threads.count, 2);
                assert_eq!(threads.exited, 2);
                assert!(threads.switches >= 2);
                assert_eq!(threads.root_entry_return, Some(0));
                assert_eq!(
                    threads
                        .states
                        .iter()
                        .find(|state| state.slot == 2)
                        .unwrap()
                        .critical_depth,
                    1
                );
                assert_eq!(result.api_events[0].arguments.len(), 7);
                assert_eq!(result.api_events[0].result, Some(0));
                if matches!(fixture, ApiFixture::SystemThread) {
                    assert_eq!(result.api_events[1].thread_id, 2);
                }
            }
        }
    }
    #[test]
    fn blocked_guarded_mutex_resumes_only_after_its_real_guest_owner_releases() {
        for arch in [Architecture::X86, Architecture::X64] {
            let result = run_api_fixture(arch, ApiFixture::MutexHandoff, 10000).unwrap();
            assert_eq!(
                result.completion_reason, "entry_return",
                "{:?}",
                result.error
            );
            assert_eq!(result.guest_entry_return, Some(1));
            assert_eq!(result.api_calls, 8);
            let threads = result.kernel_threads.unwrap();
            assert_eq!(threads.waits, 1);
            assert_eq!(threads.resumed_waits, 1);
            assert_eq!(threads.exited, 2);
            assert!(result.api_events.iter().all(|event| !event.pending));
            assert_eq!(result.api_events[3].effect, Some("mutex_acquired"));
            assert_eq!(result.api_events[3].thread_id, 1);
            assert_eq!(result.api_events[6].result, Some(1));
            let kernel = result.kernel_state.unwrap();
            assert_eq!(kernel.irql, 0);
            assert_eq!(kernel.owned_mutexes, 0);
            let complete = result.instruction_count;
            for budget in [32, 300, complete - 1] {
                let partial = run_api_fixture(arch, ApiFixture::MutexHandoff, budget).unwrap();
                assert_eq!(
                    partial.completion_reason, "instruction_budget",
                    "{:?}",
                    partial.error
                );
                assert_eq!(partial.instruction_count, budget);
                assert_eq!(partial.guest_entry_return, None);
            }
        }
    }
    #[test]
    fn cyclic_guest_mutex_dependencies_report_deadlock_without_granting_either_wait() {
        for arch in [Architecture::X86, Architecture::X64] {
            let result = run_api_fixture(arch, ApiFixture::MutexDeadlock, 10000).unwrap();
            assert_eq!(result.completion_reason, "error");
            assert!(result.error.unwrap().contains("deadlock"));
            assert_eq!(result.guest_entry_return, None);
            assert_eq!(result.api_calls, 7);
            let threads = result.kernel_threads.unwrap();
            assert_eq!(threads.waits, 2);
            assert_eq!(threads.resumed_waits, 0);
            assert_eq!(threads.exited, 0);
            assert_eq!(
                result
                    .api_events
                    .iter()
                    .filter(|event| event.pending)
                    .count(),
                2
            );
        }
    }
    #[test]
    fn thread_runs_share_one_exact_instruction_budget_and_reject_nx_start() {
        for arch in [Architecture::X86, Architecture::X64] {
            let complete = run_api_fixture(arch, ApiFixture::SystemThread, 10000).unwrap();
            assert!(complete.instruction_count > 256);
            for budget in [32, 256, complete.instruction_count - 1] {
                let result = run_api_fixture(arch, ApiFixture::SystemThread, budget).unwrap();
                assert_eq!(
                    result.completion_reason, "instruction_budget",
                    "{:?}",
                    result.error
                );
                assert_eq!(result.instruction_count, budget);
                assert_eq!(result.guest_entry_return, None);
            }
            let result = run_api_fixture(arch, ApiFixture::SystemThreadBadStart, 10000).unwrap();
            assert_eq!(result.completion_reason, "error");
            assert_eq!(result.guest_entry_return, None);
            assert!(result.error.unwrap().contains("argument range"));
            assert!(result.kernel_threads.is_none());
        }
    }
    #[test]
    fn blocked_mutexes_invalid_owners_and_irql_never_receive_fake_success() {
        for arch in [Architecture::X86, Architecture::X64] {
            for (fixture, error) in [
                (ApiFixture::GuardedBusy, "scheduling is required"),
                (ApiFixture::GuardedBadRelease, "does not own"),
                (ApiFixture::GuardedIrql, "above APC_LEVEL"),
                (ApiFixture::CriticalUnderflow, "underflow"),
            ] {
                if arch == Architecture::X64 && matches!(fixture, ApiFixture::PromptReadOnly) {
                    continue; // No-debugger AMD64 never accesses the response; tested with catch fixtures.
                }
                let result = run_api_fixture(arch, fixture, 10000).unwrap();
                assert_eq!(result.completion_reason, "error");
                assert!(result.error.unwrap().contains(error));
                assert_eq!(result.guest_entry_return, None);
                assert!(result.api_events.last().unwrap().error.is_some());
            }
        }
    }
    #[test]
    fn missing_exports_and_cycles_never_fall_back_to_fake_guest_success() {
        use emumee_core::fixtures::{LinkedFixture, linked_probe};
        for arch in [Architecture::X86, Architecture::X64] {
            let (main, mut companions) = linked_probe(arch, LinkedFixture::Direct);
            companions[0].1[0x4a0..0x4a6].copy_from_slice(b"Wrong\0");
            assert!(
                run_generated_modules(&main, &companions, 10000, 1_000_000, None)
                    .unwrap_err()
                    .to_string()
                    .contains("export is missing")
            );
            let (main, mut companions) = linked_probe(arch, LinkedFixture::Forwarded);
            companions[0].1[0x480..0x490].fill(0);
            companions[0].1[0x480..0x48c].copy_from_slice(b"guest.Alpha\0");
            assert!(
                run_generated_modules(&main, &companions, 10000, 1_000_000, None)
                    .unwrap_err()
                    .to_string()
                    .contains("cycle")
            );
        }
    }
    #[test]
    fn imported_windows_state_and_virtual_sleep_are_guest_only() {
        for arch in [Architecture::X86, Architecture::X64] {
            let result = run_api_fixture(arch, ApiFixture::UserState, 10000).unwrap();
            assert_eq!(
                result.completion_reason, "entry_return",
                "{:?}",
                result.error
            );
            assert_eq!(result.guest_entry_return, Some(0x12345678));
            assert_eq!(result.api_calls, 5);
            assert_eq!(result.api_events[0].result, Some(1024));
            assert_eq!(result.api_events[3].arguments, vec![25]);
            assert!(result.virtual_uptime_ms >= 523812025);
        }
    }
    #[test]
    fn virtual_memory_lifecycle_zeroes_recommitted_pages_and_reports_bad_release() {
        for arch in [Architecture::X86, Architecture::X64] {
            let result = run_api_fixture(arch, ApiFixture::VirtualLifecycle, 10000).unwrap();
            assert_eq!(
                result.completion_reason, "entry_return",
                "{:?}",
                result.error
            );
            assert_eq!(result.guest_entry_return, Some(0));
            assert_eq!(result.api_calls, 8);
            assert_eq!(result.api_events[5].result, Some(0));
            assert_eq!(result.api_events[5].last_error, 487);
            assert_eq!(result.api_events[6].result, Some(487));
            assert_eq!(result.api_events[7].result, Some(1));
        }
    }
    #[test]
    fn guest_cpu_obeys_reservation_decommit_release_and_api_protection() {
        for arch in [Architecture::X86, Architecture::X64] {
            for (fixture, error) in [
                (ApiFixture::VirtualWriteProtected, "WRITE_PROT"),
                (ApiFixture::VirtualReleasedRead, "READ_UNMAPPED"),
                (ApiFixture::VirtualReserveRead, "READ_PROT"),
            ] {
                if arch == Architecture::X64 && matches!(fixture, ApiFixture::PromptReadOnly) {
                    continue; // No-debugger AMD64 never accesses the response; tested with catch fixtures.
                }
                let result = run_api_fixture(arch, fixture, 10000).unwrap();
                assert_eq!(result.completion_reason, "error");
                assert!(result.error.unwrap().contains(error));
                assert_eq!(result.guest_entry_return, None);
            }
        }
    }
    #[test]
    fn failed_protection_preserves_writes_and_recommit_keeps_existing_bytes() {
        for arch in [Architecture::X86, Architecture::X64] {
            for fixture in [
                ApiFixture::VirtualBadProtectOutput,
                ApiFixture::VirtualRecommit,
            ] {
                let result = run_api_fixture(arch, fixture, 10000).unwrap();
                assert_eq!(
                    result.completion_reason, "entry_return",
                    "{:?}",
                    result.error
                );
                assert_eq!(result.guest_entry_return, Some(0x54535552));
                if matches!(fixture, ApiFixture::VirtualBadProtectOutput) {
                    assert_eq!(result.api_events[1].result, Some(0));
                    assert_eq!(result.api_events[1].last_error, 998);
                }
            }
        }
    }
    #[test]
    fn repeated_imports_preserve_state_and_report_bounded_event_retention() {
        for arch in [Architecture::X86, Architecture::X64] {
            let result = run_api_fixture(arch, ApiFixture::ApiLoop, 1_000_000).unwrap();
            assert_eq!(
                result.completion_reason, "entry_return",
                "{:?}",
                result.error
            );
            assert_eq!(result.guest_entry_return, Some(0x12345678));
            assert_eq!(result.api_calls, 100001);
            assert_eq!(result.api_events.len(), 512);
            assert_eq!(result.api_events_omitted, 99489);
        }
    }
    #[test]
    fn memory_and_prompt_models_preserve_real_guest_buffer_effects() {
        for arch in [Architecture::X86, Architecture::X64] {
            for (fixture, value) in [
                (ApiFixture::Copy, 0x54535552),
                (ApiFixture::Prompt, 0x52525252),
            ] {
                let result = run_api_fixture(arch, fixture, 10000).unwrap();
                assert_eq!(
                    result.completion_reason, "entry_return",
                    "{:?}",
                    result.error
                );
                assert_eq!(result.guest_entry_return, Some(value));
                assert_eq!(
                    result.api_calls,
                    if arch == Architecture::X64 && matches!(fixture, ApiFixture::Prompt) {
                        3
                    } else {
                        1
                    }
                );
                if matches!(fixture, ApiFixture::Prompt) {
                    let prompt = result.kernel_prompt.as_ref().unwrap();
                    assert_eq!(prompt.calls, 1);
                    assert_eq!(prompt.omitted, 0);
                    assert_eq!(
                        prompt.input_policy,
                        if arch == Architecture::X64 {
                            "no_debugger_exception"
                        } else {
                            "legacy_x86_no_input"
                        }
                    );
                    assert_eq!(prompt.response_writes, 0);
                    let row = &prompt.observations[0];
                    let api = &result.api_events[0];
                    assert_eq!(row.arguments.as_slice(), api.arguments);
                    assert_eq!(row.api_gate_pc, Some(api.api_gate_pc));
                    assert!(!row.recent_instructions.is_empty());
                    assert!(row.recent_instructions.len() <= 32);
                    assert_eq!(
                        row.recent_instructions.last().unwrap().pc,
                        result.instruction_tail[row.instruction_ordinal as usize - 1].pc
                    );
                    assert_eq!(row.instruction_ordinal, api.instruction_ordinal);
                    assert_eq!(row.thread_id, api.thread_id);
                    assert_eq!(row.current_thread, api.current_thread);
                    assert_eq!(row.processor, api.processor);
                    assert_eq!(row.execution_domain, api.execution_domain);
                    assert_eq!(row.length, 32);
                    assert_eq!(row.received_characters, 0);
                    assert_eq!(row.result, (arch == Architecture::X86).then_some(0));
                    assert_eq!(api.result, (arch == Architecture::X86).then_some(0));
                    assert!(!row.preview_truncated);
                }
            }
        }
    }
    #[test]
    fn unsupported_imports_and_api_writes_to_code_stop_explicitly() {
        for arch in [Architecture::X86, Architecture::X64] {
            for fixture in [
                ApiFixture::WriteCode,
                ApiFixture::PromptReadOnly,
                ApiFixture::Unsupported,
            ] {
                if arch == Architecture::X64 && matches!(fixture, ApiFixture::PromptReadOnly) {
                    continue; // No-debugger AMD64 never accesses the response; tested with catch fixtures.
                }
                let result = run_api_fixture(arch, fixture, 10000).unwrap();
                assert_eq!(result.completion_reason, "error");
                assert_eq!(result.guest_entry_return, None);
                assert_eq!(result.api_calls, 1);
                assert!(result.api_events[0].error.is_some());
                if matches!(fixture, ApiFixture::PromptReadOnly) {
                    let prompt = result.kernel_prompt.as_ref().unwrap();
                    assert_eq!(prompt.calls, 0);
                    assert!(prompt.observations.is_empty());
                    assert!(prompt.continuation.is_none());
                }
            }
        }
    }
    #[test]
    fn guest_result_counts_and_budget_are_exact() {
        for arch in [Architecture::X86, Architecture::X64] {
            for n in [1, 17, 10000] {
                let full = run_fixture(arch, n, 100000).unwrap();
                assert_eq!(full.completion_reason, "entry_return");
                assert_eq!(full.instruction_count, 3 * n as u64 + 3);
                assert_eq!(full.guest_entry_return, Some(n as u64));
                let partial = run_fixture(arch, n, 2).unwrap();
                assert_eq!(partial.completion_reason, "instruction_budget");
                assert_eq!(partial.instruction_count, 2);
                assert_eq!(partial.guest_entry_return, None);
            }
        }
    }
    #[test]
    fn execute_and_write_protections_stop_guest_code() {
        for code in [
            vec![0xb8, 0x00, 0x20, 0x40, 0x00, 0xff, 0xe0],
            vec![0xc6, 0x05, 0x00, 0x10, 0x40, 0x00, 0x00, 0xc3],
        ] {
            let mut fixture = counted_driver(Architecture::X86, 1);
            fixture[0x200..0x200 + code.len()].copy_from_slice(&code);
            let stopped = run_generated_image(&fixture, 1000, 1_000_000).unwrap();
            assert_eq!(stopped.completion_reason, "error");
            assert_eq!(stopped.guest_entry_return, None);
            assert!(stopped.error.unwrap().contains("PROT"));
        }
    }
}

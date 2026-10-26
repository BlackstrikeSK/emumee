//! Closed generated-program configuration consumption. This is not arbitrary
//! image admission and does not turn a validated persona into full API support.
use super::*;
use anyhow::Context;
use emumee_core::{
    fullpersona::{ClockSeed, PendingField, PreparedGuestState, ValidatedPersona},
    persona::ProcessConfig,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
mod submitted_path;
pub use submitted_path::Receipt as SubmittedServiceImagePathReceipt;
const USER_OWNER: u64 = 1024;
#[derive(Clone, Debug, Serialize)]
pub struct ConfigurationReceipt {
    pub version: &'static str,
    pub input_json_sha256: String,
    pub effective_sha256: String,
    pub projection_sha256: String,
    pub seed_manifest_sha256: String,
    pub clock_seed: ClockSeed,
    pub initialized: bool,
    pub generated_only: bool,
    pub installed_components: Vec<&'static str>,
    pub pending: Vec<PendingField>,
    pub declared_processes: usize,
    pub seeded_files: usize,
    pub seeded_registry_keys: usize,
    pub initial_processor: u32,
    pub windows_build: u32,
    pub physical_memory_mb: u64,
    pub available_memory_mb: u64,
    pub user_process_owner: Option<u64>,
    pub guest_image_path: Option<String>,
    pub submitted_service_image_path: Option<SubmittedServiceImagePathReceipt>,
    pub scope: &'static str,
}
/// Immutable publication input. Dynamic CPU identity remains CpuState.processor,
/// selected by actual ordinary/IPI execution rather than this machine profile.
#[derive(Clone, Debug)]
pub(crate) struct Machine {
    windows_build: u32,
    boot_debug: bool,
    code_integrity_options: Option<u32>,
    object_namespace: Option<emumee_core::kernel_namespace::Namespace>,
    physical_memory_mb: u64,
    seeded_file_hashes: BTreeMap<String, String>,
    receipt: Option<ConfigurationReceipt>,
}
impl Machine {
    pub(crate) fn fixture() -> Self {
        Self {
            windows_build: 22631,
            boot_debug: false,
            code_integrity_options: None,
            object_namespace: None,
            physical_memory_mb: 16384,
            seeded_file_hashes: BTreeMap::new(),
            receipt: None,
        }
    }
    pub(crate) fn windows_build(&self) -> u32 {
        self.windows_build
    }
    pub(crate) fn boot_debug(&self) -> bool {
        self.boot_debug
    }
    pub(crate) fn code_integrity_options(&self) -> Option<u32> {
        self.code_integrity_options
    }
    pub(crate) fn object_namespace(&self) -> Option<&emumee_core::kernel_namespace::Namespace> {
        self.object_namespace.as_ref()
    }
    pub(crate) fn physical_pages(&self) -> u32 {
        (self.physical_memory_mb * 256) as u32
    }
    pub(crate) fn receipt(&self) -> Option<ConfigurationReceipt> {
        self.receipt.clone()
    }
    pub(crate) fn is_configured(&self) -> bool {
        self.receipt.is_some()
    }
    pub(crate) fn capture_file(&self, path: &str, bytes: &[u8]) -> bool {
        self.seeded_file_hashes
            .get(path)
            .is_none_or(|expected| *expected != format!("{:x}", Sha256::digest(bytes)))
    }
}
/// Only a whole validated candidate can construct this engine installation.
/// It is deliberately not Deserialize and cannot be a worker launch token.
pub(crate) struct Prepared {
    architecture: Architecture,
    kernel: bool,
    state: PreparedGuestState,
    machine: Machine,
}
pub(crate) struct Request {
    pub architecture: Architecture,
    pub kernel: bool,
    pub initial_processor: u32,
    pub process: Option<ProcessConfig>,
    pub budget: u64,
    pub timeout_us: u64,
}
impl Prepared {
    /// Bind a validated kernel persona to the independently validated
    /// submitted service identity before any native state is published.
    pub(crate) fn bind_submitted_service(mut self, service: &str) -> Result<Self> {
        ensure!(self.kernel, "Submitted service requires kernel persona");
        ensure!(
            emumee_core::driver_input::service_name_valid(service),
            "Submitted service identity invalid"
        );
        let service_path = submitted_path::resolve(&self.state.registry, service)?;
        let receipt = self
            .machine
            .receipt
            .as_mut()
            .context("Validated persona receipt absent")?;
        receipt.generated_only = false;
        receipt.guest_image_path = Some(service_path.normalized_path.clone());
        receipt.submitted_service_image_path = Some(service_path);
        receipt
            .pending
            .retain(|row| row.path != "driver_entry.registry_path");
        receipt
            .installed_components
            .push("submitted_service_identity");
        receipt.scope = "Validated fullpersona model authorities installed before submitted driver entry; submitted service identity and its declared DOS image metadata path are bound from the exact guest registry ImagePath or documented absent-value fallback. Pending fields still delimit incomplete Windows API coverage; no host state is imported.";
        Ok(self)
    }

    pub(crate) fn closed_plan(plan: &emumee_core::plan_runtime::PreparedAnalysis) -> Result<Self> {
        use emumee_core::fullpersona::{ClockSeed, ClockSource, PendingField};
        let spec = plan.spec();
        let emumee_core::analysis_plan::PersonaSpec::RustModeledV1 { value } = &spec.persona else {
            anyhow::bail!("Closed plan requires narrow modeled persona");
        };
        let (mut state, process) = plan.prepare_state().map_err(anyhow::Error::msg)?;
        let arch = plan.request().architecture.architecture();
        emumee_core::kernel_environment::Environment::new(
            arch,
            &state.cpu,
            value.windows_build,
            0,
        )?;
        let mut seeded_file_hashes = BTreeMap::new();
        if !plan.request().case.kernel() && !plan.request().case.static_only() {
            let item = spec
                .inputs
                .iter()
                .find(|i| i.id == "guest-data")
                .context("Closed mount absent")?;
            seeded_file_hashes.insert(
                r"c:\users\alex\downloads\guest.dat".into(),
                item.sha256.clone(),
            );
        }
        let user_process = process.is_some();
        let mut guest_image_path = plan
            .request()
            .case
            .kernel()
            .then(|| r"C:\Windows\System32\drivers\owned.sys".to_owned());
        if let Some(process) = process {
            state.persona.add_process(USER_OWNER, process)?;
            guest_image_path = Some(state.persona.argv(USER_OWNER)?[0].clone());
        }
        let binding = plan.receipt();
        let persona_hash = binding["persona_input_sha256"]
            .as_str()
            .context("Persona binding missing")?
            .to_owned();
        let projection_hash =
            emumee_core::report_bundle::digest(&serde_json::to_vec(&spec.persona)?);
        let seed_hash = emumee_core::report_bundle::digest(&serde_json::to_vec(&spec.inputs)?);
        let receipt = ConfigurationReceipt {
            version: "emumee-closed-plan-modeled-v1",
            input_json_sha256: persona_hash.clone(), effective_sha256: persona_hash,
            projection_sha256: projection_hash, seed_manifest_sha256: seed_hash,
            clock_seed: ClockSeed { utc_filetime: value.clock.utc_filetime, source: ClockSource::Fixed, source_id: value.clock.source_id.clone() },
            initialized: false, generated_only: true,
            installed_components: vec!["narrow_plan_persona", "native_cpu_profile", "native_guest_clock", "empty_registry_authority", "actual_plan_vfs_mounts", "shared_build_and_physical_pages", "kernel_environment_build", "legacy32_capture_catalog", "closed_resource_limits"],
            pending: vec![PendingField { path: "full_tool".into(), reason: "Closed modeled projection; legacy persona, general input graph and other port gates remain unqualified".into() }],
            declared_processes: usize::from(user_process), seeded_files: seeded_file_hashes.len(), seeded_registry_keys: 0,
            initial_processor: 0, windows_build: value.windows_build, physical_memory_mb: value.physical_memory_mb as u64,
            available_memory_mb: value.available_memory_mb as u64, user_process_owner: user_process.then_some(USER_OWNER), guest_image_path, submitted_service_image_path: None,
            scope: "Actual narrow modeled plan authorities installed before publication; exact compiler-owned input graph only. Seed digest binds plan input declarations, not the legacy fullpersona seed format. Driver service identity remains EmumeeFixture; no general input or full persona coverage.",
        };
        Ok(Self {
            architecture: arch,
            kernel: plan.request().case.kernel(),
            state,
            machine: Machine {
                windows_build: value.windows_build,
                boot_debug: false,
                code_integrity_options: None,
                object_namespace: None,
                physical_memory_mb: value.physical_memory_mb as u64,
                seeded_file_hashes,
                receipt: Some(receipt),
            },
        })
    }

    pub(crate) fn new(validated: ValidatedPersona, request: Request) -> Result<Self> {
        let boot_debug = validated.effective_json()["boot_config"]["debug"]
            .as_bool()
            .context("Validated boot debug policy absent")?;
        let object_namespace = validated.effective_json()["boot_config"]
            .get("object_directories")
            .filter(|v| !v.is_null())
            .map(|value| -> Result<_> {
                Ok(emumee_core::kernel_namespace::Namespace::new(
                    serde_json::from_value(value.clone())?,
                )?)
            })
            .transpose()?;
        let code_integrity_options = validated.effective_json()["boot_config"]
            .get("code_integrity_options")
            .and_then(serde_json::Value::as_u64)
            .map(|v| v as u32);
        let projection = &validated.projection().data;
        ensure!(
            request.initial_processor == 0,
            "Configured ordinary routing outside logical CPU0 is not modeled"
        );
        ensure!(
            request.budget > 0
                && request.budget <= emumee_core::driver_input::MAX_INSTRUCTIONS
                && request.timeout_us > 0
                && request.timeout_us <= 7_200_000_000,
            "Configured budget/timeout bounds"
        );
        ensure!(
            request.kernel == request.process.is_none(),
            "Configured target/process invocation mismatch"
        );
        let cpu = &projection.cpu;
        cpu.validate()?;
        emumee_core::kernel_environment::Environment::new(
            request.architecture,
            cpu,
            projection.windows_build,
            0,
        )?;
        // Reserve the deterministic instruction horizon plus the bounded guest
        // timeout. Explicit API clock overflow after that still stops normally.
        let ticks = request
            .budget
            .checked_mul(100)
            .and_then(|n| n.checked_div(cpu.base_mhz as u64))
            .and_then(|n| n.checked_mul(10))
            .and_then(|n| {
                request
                    .timeout_us
                    .checked_mul(10)
                    .and_then(|extra| n.checked_add(extra))
            })
            .context("Configured guest clock horizon overflow")?;
        ensure!(
            projection.clock.utc_filetime.checked_add(ticks).is_some()
                && projection
                    .clock
                    .uptime_ms
                    .checked_add(ticks.div_ceil(10_000))
                    .is_some_and(|n| n <= u64::MAX / 10_000),
            "Configured guest clock cannot represent budget horizon"
        );
        let mut receipt = ConfigurationReceipt {
            version: "emumee-configured-native-v1",
            input_json_sha256: validated.input_sha256().into(),
            effective_sha256: validated.sha256().into(),
            projection_sha256: validated.projection().sha256.clone(),
            seed_manifest_sha256: validated.seed_manifest().sha256().into(),
            clock_seed: projection.clock.seed.clone(),
            initialized: false,
            generated_only: true,
            installed_components: vec![
                "boot_config.debug",
                "native_cpu_profile",
                "native_guest_clock",
                "persona_config",
                "registry_seed_catalog",
                "vfs_seed_catalog",
                "shared_build_and_physical_pages",
                "kernel_environment_build",
            ],
            pending: projection.pending.clone(),
            declared_processes: validated.seed_manifest().processes().len(),
            seeded_files: validated.seed_manifest().files().len(),
            seeded_registry_keys: validated.seed_manifest().registry().len(),
            initial_processor: 0,
            windows_build: projection.windows_build,
            physical_memory_mb: projection.physical_memory_mb,
            available_memory_mb: projection.available_memory_mb,
            user_process_owner: None,
            guest_image_path: None,
            submitted_service_image_path: None,
            scope: "Initialized actual native model authorities for a closed generated program. Seed catalogs are distinct from API consumption; all external field runtime consumers remain listed pending. No arbitrary-input worker admission, physical allocator, background process execution or kernel Zw registry/file coverage is implied.",
        };
        if state_logical(cpu) > request.architecture.width() as u32 * 8 {
            receipt.pending.push(PendingField{path:"cpu.ipi_group".into(),reason:"Configured topology retained; IPI currently accepts only one ABI-width group and explicitly refuses this broadcast profile".into()});
        }
        if request.kernel {
            receipt.pending.push(PendingField{path:"driver_entry.registry_path".into(),reason:"Generated boot still uses EmumeeFixture driver/service names; production service identity remains unqualified".into()});
        }
        let seeded_file_hashes = validated
            .seed_manifest()
            .files()
            .iter()
            .map(|file| (file.canonical_path.clone(), file.sha256.clone()))
            .collect();
        let mut state = validated.into_prepared();
        ensure!(
            state.clock.base_mhz == state.cpu.base_mhz
                && state.persona.config().logical_processors
                    == state.cpu.cores * state.cpu.threads_per_core,
            "Configured authority clock/topology mismatch"
        );
        ensure!(
            state.filesystem.storage_report().open_handles == 0,
            "Configured seed unexpectedly published file handles"
        );
        if let Some(mut process) = request.process {
            if let Some(directory) = &process.current_directory {
                let plan = state.filesystem.directory_plan(directory)?;
                process.current_directory = Some(plan.display().into());
                state.filesystem.commit_directory(plan)?;
            }
            // Configured images are loader inputs. Their names are not faked
            // into the VFS as empty files just to satisfy this process identity.
            state.persona.add_process(USER_OWNER, process)?;
            receipt.guest_image_path = Some(state.persona.argv(USER_OWNER)?[0].clone());
            ensure!(
                state
                    .persona
                    .directory(
                        USER_OWNER,
                        emumee_core::persona::Directory::Current,
                        emumee_core::persona::Encoding::Utf16,
                        u32::MAX,
                        true
                    )?
                    .bytes
                    == Some(
                        emumee_core::persona::Encoding::Utf16
                            .encode(state.filesystem.current_directory(), true)
                    ),
                "Configured Persona/VFS current directories disagree"
            );
            receipt.user_process_owner = Some(USER_OWNER);
            receipt.installed_components.push("user_process_invocation");
        }
        if code_integrity_options.is_some() {
            receipt
                .installed_components
                .push("boot_config.code_integrity_options");
        }
        if object_namespace.is_some() {
            receipt
                .installed_components
                .push("boot_config.object_directories");
        }
        let machine = Machine {
            windows_build: receipt.windows_build,
            boot_debug,
            code_integrity_options,
            object_namespace,
            physical_memory_mb: receipt.physical_memory_mb,
            seeded_file_hashes,
            receipt: Some(receipt),
        };
        Ok(Self {
            architecture: request.architecture,
            kernel: request.kernel,
            state,
            machine,
        })
    }
    pub(crate) fn architecture(&self) -> Architecture {
        self.architecture
    }
    pub(crate) fn kernel(&self) -> bool {
        self.kernel
    }
    pub(crate) fn module_guest_path(&self) -> Option<&str> {
        self.machine
            .receipt
            .as_ref()
            .and_then(|r| r.guest_image_path.as_deref())
    }
    pub(crate) fn module_name(&self) -> &str {
        self.machine
            .receipt
            .as_ref()
            .and_then(|r| r.guest_image_path.as_deref())
            .and_then(|path| path.rsplit('\\').next())
            .unwrap_or("configured-driver.sys")
    }
    pub(crate) fn into_trace(self) -> Result<Trace> {
        let trace = Trace::from_prepared(self.architecture, self.state, self.machine);
        require_unpublished(&trace)?;
        Ok(trace)
    }
}
fn state_logical(cpu: &emumee_core::cpu::CpuProfile) -> u32 {
    cpu.cores * cpu.threads_per_core
}
/// No fallible/native step follows receipt publication before hooks start.
/// Failed earlier initialization drops the instance without guest execution.
pub(crate) fn initialized(engine: &mut Unicorn<Trace>) -> Result<()> {
    let trace = engine.get_data_mut();
    if let Some(receipt) = trace.machine.receipt.as_mut() {
        ensure!(
            !receipt.initialized,
            "Configured state initialization already published"
        );
        receipt.initialized = true;
    }
    Ok(())
}
/// Even internal reinstallation attempts fail once a native-visible mapping,
/// provider, API event or execution exists. No runtime setter is exported.
pub(crate) fn require_unpublished(trace: &Trace) -> Result<()> {
    ensure!(
        trace.instructions == 0
            && trace.apis.memory.regions().next().is_none()
            && trace.apis.modules.modules().next().is_none()
            && trace.apis.calls == 0
            && trace.clock_page.is_none()
            && trace.kernel_cpu.is_none(),
        "Configured state cannot change after native publication"
    );
    Ok(())
}
pub(crate) fn fixture(
    architecture: Architecture,
    kind: emumee_core::fixtures::ConfiguredFixture,
    unicode: bool,
    budget: u64,
) -> Result<Execution> {
    use emumee_core::fixtures::{configured_document, configured_probe};
    let validated = emumee_core::fullpersona::decode(
        &configured_document(kind),
        &emumee_core::fullpersona::ResolveContext::default(),
    )?;
    let process = (!kind.kernel()).then(|| ProcessConfig {
        image_path: r"C:\Users\Morgan\Downloads\configured-probe.exe".into(),
        arguments: vec!["two words".into()],
        force_quotes: vec![],
        command_line: None,
        current_directory: None,
        environment_overrides: vec![("TOKEN".into(), Some("é".into()))],
    });
    let prepared = Prepared::new(
        validated,
        Request {
            architecture,
            kernel: kind.kernel(),
            initial_processor: 0,
            process,
            budget,
            timeout_us: 30_000_000,
        },
    )?;
    run_generated_with_fixture_configuration(
        &configured_probe(architecture, kind, unicode),
        &[],
        budget,
        30_000_000,
        GeneratedConfiguration {
            configured: Some(prepared),
            ..Default::default()
        },
    )
}

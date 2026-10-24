use super::{
    inventory::{Inspection, VerifiedInput, package_path},
    *,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use unicode_casefold::UnicodeCaseFold;
const MIB: u64 = 1024 * 1024;
/// Sealed planning capability. It is not deserializable or an execution permit.
pub struct Capabilities {
    version: u32,
}
impl Capabilities {
    pub fn planning_only_v1() -> Self {
        Self { version: 1 }
    }
}
/// Immutable validated data. No worker launch API accepts this type as authority.
pub struct ResolvedPlan {
    value: Value,
    canonical: Vec<u8>,
    digest: String,
    request: Vec<u8>,
    request_hash: String,
}
impl ResolvedPlan {
    pub fn value(&self) -> &Value {
        &self.value
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn sha256(&self) -> &str {
        &self.digest
    }
    pub fn request_bytes(&self) -> &[u8] {
        &self.request
    }
    pub fn request_sha256(&self) -> &str {
        &self.request_hash
    }
    pub fn executable(&self) -> bool {
        false
    }
}
fn sum(values: impl IntoIterator<Item = u64>, field: &str) -> Result<u64> {
    values.into_iter().try_fold(0u64, |a, b| {
        a.checked_add(b)
            .ok_or_else(|| problem("budget_overflow", field, "Checked budget sum overflow"))
    })
}
fn item<'a>(inventory: &'a VerifiedInventory, id: &str, field: &str) -> Result<&'a VerifiedInput> {
    inventory.entries.get(id).ok_or_else(|| {
        problem(
            "missing_input",
            field,
            "Referenced ID absent from actual verified bytes",
        )
    })
}
fn has_role(item: &VerifiedInput, role: InputRole, field: &str) -> Result<()> {
    demand(
        item.spec.roles.contains(&role),
        "input_role",
        field,
        "Input role does not match reference",
    )
}
fn pe(
    item: &VerifiedInput,
    architecture: Arch,
    kind: &str,
    managed: bool,
    field: &str,
) -> Result<u64> {
    match &item.inspection {
        Inspection::Pe {
            architecture: actual,
            kind: actual_kind,
            managed: actual_managed,
            image_size,
            ..
        } => {
            demand(
                *actual == architecture && actual_kind == kind && *actual_managed == managed,
                "target_mismatch",
                field,
                "Actual PE kind, architecture or managed flavor differs",
            )?;
            Ok(*image_size as u64)
        }
        _ => Err(problem(
            "target_mismatch",
            field,
            "Referenced input is not an inspected PE",
        )),
    }
}
fn execution_caps(limits: &Limits) -> Result<()> {
    demand(
        (1..=3_600_000).contains(&limits.guest_timeout_ms)
            && (1..=1_000_000_000_000).contains(&limits.max_instructions)
            && (1..=100_000).contains(&limits.max_native_api_calls),
        "execution_limit",
        "limits",
        "Guest timeout/instruction/API limits outside compiled cap",
    )
}
fn persona(spec: &PersonaSpec, limits: &Limits) -> Result<(Value, u32, String)> {
    let PersonaSpec::RustModeledV1 { value } = spec else {
        return Err(problem(
            "unsupported_persona_schema",
            "persona.kind",
            "Full legacy persona loader/derived-content projection is not qualified",
        ));
    };
    let cpu = value.cpu.profile();
    cpu.validate().map_err(|_| {
        problem(
            "persona_cpu",
            "persona.value.cpu",
            "Invalid bounded CPU topology/frequency",
        )
    })?;
    let logical = value
        .cpu
        .cores
        .checked_mul(value.cpu.threads_per_core)
        .ok_or_else(|| {
            problem(
                "persona_cpu",
                "persona.value.cpu",
                "Logical processor overflow",
            )
        })?;
    demand(
        value.process.logical_processors == logical && value.current_processor < logical,
        "persona_inconsistent",
        "persona.value.current_processor",
        "CPU and process identity topology disagree",
    )?;
    demand(
        (22000..=65535).contains(&value.windows_build),
        "persona_build",
        "persona.value.windows_build",
        "Modeled Windows11 build outside profile",
    )?;
    demand(
        (1..=1_048_576).contains(&value.physical_memory_mb)
            && (1..=value.physical_memory_mb).contains(&value.available_memory_mb),
        "persona_memory",
        "persona.value.available_memory_mb",
        "Available memory must be positive and <=physical memory",
    )?;
    demand(
        super::inventory::id(&value.clock.source_id),
        "persona_clock",
        "persona.value.clock.source_id",
        "Clock seed needs a bounded explicit provenance ID",
    )?;
    demand(
        matches!(value.clock.source, ClockSource::Fixed),
        "unsupported_option",
        "persona.value.clock.source",
        "Controller-resolved clock requires a sealed parent seed adapter, not user provenance",
    )?;
    crate::clock::GuestClock::new(
        value.clock.utc_filetime,
        value.clock.uptime_ms,
        value.clock.utc_offset_minutes,
        value.cpu.base_mhz,
    )
    .map_err(|_| {
        problem(
            "persona_clock",
            "persona.value.clock",
            "Unrepresentable explicit guest time/offset",
        )
    })?;
    // Include deterministic instruction-clock cycles as well as the selected
    // timeout horizon. The runtime must still stop explicit clock overflow for
    // modeled APIs advancing beyond these reserves, rather than wrapping.
    let horizon = limits
        .max_instructions
        .checked_mul(100)
        .map(|cycles| cycles / value.cpu.base_mhz as u64)
        .and_then(|micros| micros.checked_mul(10))
        .and_then(|ticks| {
            limits
                .guest_timeout_ms
                .checked_mul(10_000)
                .and_then(|extra| ticks.checked_add(extra))
        })
        .ok_or_else(|| {
            problem(
                "budget_overflow",
                "persona.value.clock",
                "Instruction/time clock horizon overflow",
            )
        })?;
    demand(
        value.clock.utc_filetime.checked_add(horizon).is_some()
            && value
                .clock
                .uptime_ms
                .checked_add(horizon.div_ceil(10_000))
                .is_some_and(|n| n <= u64::MAX / 10_000),
        "persona_clock",
        "persona.value.clock",
        "Clock cannot represent compiled guest timeout horizon",
    )?;
    demand(
        value.process.environment.is_empty(),
        "unsupported_persona_field",
        "persona.value.process.environment",
        "Use invocation.environment; duplicate environment authorities are not accepted",
    )?;
    let modeled = crate::persona::Persona::new(value.process.clone()).map_err(|_| {
        problem(
            "persona_identity",
            "persona.value.process",
            "Invalid modeled process identity or directory",
        )
    })?;
    let process = modeled.config();
    let resolved = json!({"kind":"rust_modeled_v1","scope":"Explicit narrow Rust model; not full legacy persona","process":process,"cpu":value.cpu,"clock":value.clock,"windows_build":value.windows_build,
        "current_processor":value.current_processor,"physical_memory_mb":value.physical_memory_mb,"available_memory_mb":value.available_memory_mb});
    Ok((
        resolved,
        value.windows_build,
        process.current_directory.clone(),
    ))
}
fn invocation(
    spec: &Invocation,
    target: &Target,
    target_item: &VerifiedInput,
    persona_directory: &str,
) -> Result<Value> {
    let process_mode = matches!(
        target,
        Target::NativeExe { .. } | Target::NativeDll { .. } | Target::ManagedEntry { .. }
    );
    match spec {
        Invocation::None => {
            demand(
                !process_mode,
                "invocation_mode",
                "invocation.kind",
                "Process target requires explicit process invocation",
            )?;
            Ok(json!({"kind":"none"}))
        }
        Invocation::Process {
            guest_root,
            arguments,
            force_quote_indices,
            environment,
        } => {
            demand(
                process_mode,
                "invocation_mode",
                "invocation.kind",
                "Kernel/static targets reject argv, environment and process invocation",
            )?;
            demand(
                arguments.len() <= 64
                    && arguments.iter().all(|a| !a.contains('\0'))
                    && arguments.iter().map(|a| a.chars().count()).sum::<usize>() <= 8192,
                "argument_limit",
                "invocation.arguments",
                "Guest args exceed64/8192 characters or contain NUL",
            )?;
            demand(
                force_quote_indices.len() <= 64
                    && force_quote_indices
                        .iter()
                        .all(|i| *i < arguments.len() && !arguments[*i].contains('"')),
                "quote_index",
                "invocation.force_quote_indices",
                "Invalid guest quote index or quoted value",
            )?;
            demand(
                !matches!(target, Target::ManagedEntry { .. }) || force_quote_indices.is_empty(),
                "unsupported_option",
                "invocation.force_quote_indices",
                "Managed arguments do not accept native forced quoting",
            )?;
            demand(
                environment.len() <= 256,
                "environment_limit",
                "invocation.environment",
                "Too many ordered environment assignments",
            )?;
            let mut normalized = BTreeMap::new();
            for (index, assignment) in environment.iter().enumerate() {
                let name = &assignment.name;
                let bytes = name.as_bytes();
                demand(
                    !bytes.is_empty()
                        && bytes.len() <= 128
                        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
                        && bytes
                            .iter()
                            .all(|b| b.is_ascii_alphanumeric() || [b'_', b'(', b')'].contains(b))
                        && !assignment.value.contains('\0')
                        && assignment.value.chars().count() <= 4096,
                    "environment_assignment",
                    format!("invocation.environment[{index}]"),
                    "Invalid legacy KEY=VALUE name/value",
                )?;
                normalized.insert(name.to_ascii_uppercase(), assignment.value.clone());
            }
            demand(
                normalized.len() <= 64
                    && normalized
                        .iter()
                        .map(|(k, v)| k.chars().count() + v.chars().count())
                        .sum::<usize>()
                        <= 8192,
                "environment_limit",
                "invocation.environment",
                "Effective environment exceeds64/8192 characters",
            )?;
            // Validate canonical guest paths without consulting host path semantics.
            let path = guest_root.replace('/', "\\");
            demand(
                path.len() >= 3
                    && path.as_bytes()[0].is_ascii_alphabetic()
                    && path.as_bytes()[1] == b':'
                    && path.as_bytes()[2] == b'\\',
                "guest_root",
                "invocation.guest_root",
                "Guest root must be absolute drive path",
            )?;
            let mut root_config = crate::persona::PersonaConfig::fixture();
            root_config.current_directory = path;
            let root = crate::persona::Persona::new(root_config)
                .map_err(|_| {
                    problem(
                        "guest_root",
                        "invocation.guest_root",
                        "Invalid supported absolute guest root",
                    )
                })?
                .config()
                .current_directory
                .clone();
            let relative = match &target_item.spec.mount {
                Mount::NotMounted => target_item.spec.name.as_str(),
                Mount::Package { path } => path.as_str(),
            };
            let relative = relative.replace('/', "\\");
            let image = format!("{}\\{}", root.trim_end_matches('\\'), relative);
            let expected_directory = image.rsplit_once('\\').map(|p| p.0).unwrap_or_default();
            demand(
                persona_directory.case_fold().collect::<String>()
                    == expected_directory.case_fold().collect::<String>(),
                "persona_inconsistent",
                "persona.value.process.current_directory",
                "Effective current directory does not match package launch directory",
            )?;
            let argv = std::iter::once(image.clone())
                .chain(arguments.iter().cloned())
                .collect::<Vec<_>>();
            let translated = force_quote_indices
                .iter()
                .map(|i| i + 1)
                .collect::<Vec<_>>();
            let command_line = crate::persona::command_line(&argv, &translated).map_err(|_| {
                problem(
                    "command_line",
                    "invocation.arguments",
                    "CRT command line exceeds modeled limits",
                )
            })?;
            Ok(
                json!({"kind":"process","guest_root":root,"image_path":image,"arguments":arguments,"force_quote_indices":force_quote_indices,
                "quote_index_basis":"guest_args_excluding_argv0","command_line":command_line,"environment":normalized,"ordered_environment_intent":environment}),
            )
        }
    }
}
pub fn resolve(
    spec: &PlanSpec,
    inventory: &VerifiedInventory,
    capabilities: &Capabilities,
) -> Result<ResolvedPlan> {
    demand(
        spec.schema == 1 && capabilities.version == 1,
        "schema",
        "schema",
        "Unsupported analysis plan schema/capability version",
    )?;
    demand(
        spec.capture.profile == CaptureProfile::Legacy32CaptureV1,
        "unsupported_profile",
        "capture.profile",
        "LargeDriver128V1 requires separately qualified catalog/carve/checkpoint/report/job profile",
    )?;
    demand(
        spec.reports.profile == ReportProfile::LegacyV1,
        "unsupported_profile",
        "reports.profile",
        "Large driver report validators/profile are not qualified",
    )?;
    demand(
        identity(
            b"emumee.analysis.inventory.intent.v1\0",
            &canonical(&spec.inputs)?,
        ) == inventory.intent_digest,
        "binding_mismatch",
        "inputs",
        "Plan inventory changed after actual byte verification",
    )?;
    demand(
        spec.original_json_sha256.is_some()
            && spec.decoded_sha256.as_deref()
                == Some(identity(b"emumee.analysis.spec.v1\0", &canonical(spec)?).as_str()),
        "binding_mismatch",
        "$",
        "Configuration was not strictly decoded or changed after decode",
    )?;
    execution_caps(&spec.limits)?;
    let (effective_persona, build, persona_directory) = persona(&spec.persona, &spec.limits)?;
    let target = item(inventory, spec.target.input(), "target.input")?;
    has_role(target, InputRole::ExecutionPrimary, "target.input")?;
    let originals = inventory
        .entries
        .values()
        .filter(|v| v.spec.roles.contains(&InputRole::OriginalPrimary))
        .collect::<Vec<_>>();
    demand(
        originals.len() == 1,
        "input_role",
        "inputs",
        "Exactly one original primary is required",
    )?;
    let execution_count = inventory
        .entries
        .values()
        .filter(|v| v.spec.roles.contains(&InputRole::ExecutionPrimary))
        .count();
    demand(
        execution_count == 1,
        "input_role",
        "inputs",
        "Exactly one execution primary is required",
    )?;
    let mut used = BTreeSet::from([target.spec.id.as_str(), originals[0].spec.id.as_str()]);
    let mut mapped = match &spec.target {
        Target::NativeExe { architecture, .. } => {
            pe(target, *architecture, "exe", false, "target")?
        }
        Target::NativeDll {
            architecture,
            exports,
            ..
        } => {
            demand(
                *exports == Exports::Disabled,
                "unsupported_option",
                "target.exports",
                "General DLL export-probe lifecycle is not qualified",
            )?;
            pe(target, *architecture, "dll", false, "target")?
        }
        Target::KernelDriver {
            architecture,
            unload,
            code_reference,
            service_name,
            ..
        } => {
            if let Some(name) = service_name {
                demand(
                    crate::driver_input::service_name_valid(name),
                    "service_identity",
                    "target.service_name",
                    "Kernel service name must meet the submitted-driver identity profile",
                )?;
            }
            let image = pe(target, *architecture, "driver", false, "target")?;
            demand(
                !*unload,
                "unsupported_option",
                "target.unload",
                "General DriverUnload lifecycle is not qualified",
            )?;
            if let Reference::Bound { input } = code_reference {
                let reference = item(inventory, input, "target.code_reference.input")?;
                has_role(
                    reference,
                    InputRole::KernelCodeReference,
                    "target.code_reference.input",
                )?;
                demand(
                    *architecture == Arch::X64
                        && matches!(build, 22631 | 26200)
                        && reference.spec.size <= 32 * MIB,
                    "reference_profile",
                    "target.code_reference",
                    "Reference requires x64 build22631/26200 and <=32MiB input",
                )?;
                match reference.inspection {
                    Inspection::Pe {
                        architecture: Arch::X64,
                        managed: false,
                        ..
                    } => {}
                    _ => {
                        return Err(problem(
                            "reference_profile",
                            "target.code_reference",
                            "Reference must be inspected native x64 PE",
                        ));
                    }
                }
                return Err(problem(
                    "unsupported_option",
                    "target.code_reference",
                    "General non-executable kernel-reference adapter is not qualified",
                ));
            }
            image
        }
        Target::ManagedEntry {
            architecture,
            apphost,
            ..
        } => {
            let image = pe(target, *architecture, "exe", true, "target")?;
            demand(
                matches!(
                    &target.inspection,
                    Inspection::Pe {
                        managed_entry: true,
                        ..
                    }
                ),
                "managed_entry",
                "target.input",
                "Managed executable lacks a valid IL entry method",
            )?;
            demand(
                matches!(apphost, Apphost::None),
                "unsupported_option",
                "target.apphost",
                "General apphost marker/sidecar loader adapter is not qualified",
            )?;
            image
        }
        Target::StaticMsi { .. } => {
            demand(
                matches!(target.inspection, Inspection::StaticMsi { .. }),
                "target_mismatch",
                "target",
                "Static target must be a validated compound file",
            )?;
            0
        }
    };
    demand(
        originals[0].spec.id == target.spec.id,
        "unsupported_option",
        "target",
        "Distinct original/execution identity requires the unqualified apphost adapter",
    )?;
    let managed = matches!(spec.target, Target::ManagedEntry { .. });
    let process = matches!(
        spec.target,
        Target::NativeExe { .. } | Target::NativeDll { .. } | Target::ManagedEntry { .. }
    );
    demand(
        spec.companions.len() <= if managed { 16 } else { 32 },
        "companion_count",
        "companions",
        "Companion count exceeds mode profile",
    )?;
    demand(
        process || spec.companions.is_empty(),
        "companion_mode",
        "companions",
        "Kernel/static targets do not accept companions",
    )?;
    let mut companion_names = BTreeSet::new();
    let mut companion_identity = Vec::new();
    for id in &spec.companions {
        let companion = item(inventory, id, "companions")?;
        demand(
            used.insert(id.as_str())
                && companion_names.insert(companion.spec.name.case_fold().collect::<String>()),
            "ambiguous_companion",
            "companions",
            "Duplicate ID or ambiguous DLL basename",
        )?;
        has_role(
            companion,
            if managed {
                InputRole::ManagedCompanion
            } else {
                InputRole::NativeCompanion
            },
            "companions",
        )?;
        mapped = sum(
            [
                mapped,
                pe(
                    companion,
                    spec.target.arch().unwrap(),
                    "dll",
                    managed,
                    "companions",
                )?,
            ],
            "limits.guest_mapped_bytes",
        )?;
        demand(
            companion.spec.size <= 32 * MIB,
            "companion_size",
            "companions",
            "This explicit profile tightens companions to32MiB each",
        )?;
        companion_identity
            .push(json!({"id":id,"name":companion.spec.name,"sha256":companion.spec.sha256}));
    }
    demand(
        !managed || spec.companions.is_empty(),
        "unsupported_option",
        "companions",
        "General managed companion assembly/dependency resolver is not qualified",
    )?;
    let mut mounted = BTreeMap::new();
    let mut bundle_bytes = 0u64;
    let mut bundle_count = 0u64;
    let mut depth = 1u64;
    for input in inventory.entries.values() {
        match &input.spec.mount {
            Mount::NotMounted => {
                demand(
                    !input
                        .spec
                        .roles
                        .iter()
                        .any(|r| matches!(r, InputRole::GuestFile | InputRole::PersonaFile)),
                    "guest_mount",
                    "inputs",
                    "Guest/persona file requires an explicit package path",
                )?;
            }
            Mount::Package { path } => {
                package_path(path, &format!("inputs.{}.mount.path", input.spec.id))?;
                demand(
                    input.spec.roles.iter().any(|r| {
                        matches!(
                            r,
                            InputRole::GuestFile
                                | InputRole::PersonaFile
                                | InputRole::ExecutionPrimary
                                | InputRole::OriginalPrimary
                                | InputRole::NativeCompanion
                                | InputRole::ManagedCompanion
                        )
                    }),
                    "guest_mount",
                    "inputs",
                    "This input role cannot be mounted into the guest",
                )?;
                demand(
                    input.spec.size <= 32 * MIB,
                    "bundle_size",
                    "inputs",
                    "Legacy package member exceeds32MiB",
                )?;
                demand(
                    mounted
                        .insert(path.case_fold().collect::<String>(), path.as_str())
                        .is_none(),
                    "ambiguous_guest_path",
                    "inputs",
                    "Case-fold duplicate package path",
                )?;
                bundle_bytes = sum([bundle_bytes, input.spec.size], "inputs")?;
                bundle_count += 1;
                depth = depth.max(path.split('/').count() as u64);
                used.insert(input.spec.id.as_str());
            }
        }
    }
    demand(
        bundle_count <= 2048 && bundle_bytes <= 64 * MIB,
        "bundle_limit",
        "inputs",
        "Package exceeds2048files/64MiB",
    )?;
    // A file and a directory may not occupy the same folded package path.
    for key in mounted.keys() {
        for (at, _) in key.match_indices('/') {
            demand(
                !mounted.contains_key(&key[..at]),
                "ambiguous_guest_path",
                "inputs",
                "Package file conflicts with a directory prefix",
            )?;
        }
    }
    let network = match &spec.network {
        Network::Live => {
            return Err(problem(
                "unsupported_option",
                "network.kind",
                "Host/live network is not permitted by this offline plan profile",
            ));
        }
        Network::OfflineDeny => {
            json!({"kind":"offline_deny","monitoring":"requires_qualified_distinct_offline_broker","complete":false,"canonical_copy_bytes":0})
        }
        Network::OfflineExactReplay { input } => {
            let fixture = item(inventory, input, "network.input")?;
            has_role(fixture, InputRole::OfflineFixtures, "network.input")?;
            used.insert(input.as_str());
            let Inspection::Fixtures {
                canonical_sha256,
                canonical_bytes,
                rules,
                bodies,
            } = &fixture.inspection
            else {
                return Err(problem(
                    "fixture_document",
                    "network.input",
                    "Fixture parser evidence absent",
                ));
            };
            json!({"kind":"offline_exact_replay","input":input,"original_sha256":fixture.spec.sha256,"original_bytes":fixture.spec.size,"canonical_sha256":canonical_sha256,"canonical_copy_bytes":canonical_bytes,"rules":rules,"bodies":bodies,
                "matching_version":"exact_request_v1","broker_protocol":1,"capabilities":0,"fixture_visibility":"broker_only","complete":false})
        }
    };
    demand(
        used.len() == inventory.entries.len(),
        "unbound_input",
        "inputs",
        "Input exists without an explicit primary, companion, fixture or guest mount binding",
    )?;
    // Role claims must also have matching references; one consumed ID cannot hide an unused authority.
    for input in inventory.entries.values() {
        for role in &input.spec.roles {
            let allowed = match role {
                InputRole::OriginalPrimary => input.spec.id == originals[0].spec.id,
                InputRole::ExecutionPrimary => input.spec.id == target.spec.id,
                InputRole::NativeCompanion => !managed && spec.companions.contains(&input.spec.id),
                InputRole::ManagedCompanion => managed && spec.companions.contains(&input.spec.id),
                InputRole::GuestFile | InputRole::PersonaFile => {
                    matches!(input.spec.mount, Mount::Package { .. })
                }
                InputRole::OfflineFixtures => {
                    matches!(&spec.network,Network::OfflineExactReplay{input:id}if id==&input.spec.id)
                }
                InputRole::KernelCodeReference
                | InputRole::ApphostSidecar
                | InputRole::LegacyPersona => false,
            };
            demand(
                allowed,
                "unbound_role",
                format!("inputs.{}.roles", input.spec.id),
                "Unreferenced or unsupported declared role",
            )?;
        }
    }
    let invocation = invocation(&spec.invocation, &spec.target, target, &persona_directory)?;
    let source_set = spec
        .capture
        .sources
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    demand(
        source_set.len() == spec.capture.sources.len(),
        "capture_sources",
        "capture.sources",
        "Duplicate capture source",
    )?;
    demand(
        matches!(spec.capture.memory_strings, MemoryStrings::Disabled),
        "unsupported_option",
        "capture.memory_strings",
        "Bounded memory-string/regex capture is not ported",
    )?;
    demand(
        matches!(spec.capture.checkpoint, Checkpoint::FinalBoundary),
        "unsupported_option",
        "capture.checkpoint",
        "Periodic checkpoint adapter is not qualified",
    )?;
    demand(
        spec.capture.retained_bytes <= 128 * MIB && spec.capture.memory_scan_bytes <= 128 * MIB,
        "capture_limit",
        "capture",
        "Legacy capture exceeds128MiB retained/scan cap",
    )?;
    demand(
        source_set.is_empty() || spec.capture.retained_bytes > 0,
        "capture_limit",
        "capture.retained_bytes",
        "Enabled capture sources need a positive retention budget",
    )?;
    demand(
        !source_set.contains(&CaptureSource::MemorySnapshots)
            && !source_set.contains(&CaptureSource::StructuralPe)
            || spec.capture.memory_scan_bytes > 0,
        "capture_limit",
        "capture.memory_scan_bytes",
        "Memory sources need explicit positive scan budget",
    )?;
    if matches!(spec.target, Target::StaticMsi { .. }) {
        demand(
            source_set.iter().all(|s| {
                matches!(
                    s,
                    CaptureSource::ContainerStreams | CaptureSource::StructuralPe
                )
            }),
            "capture_mode",
            "capture.sources",
            "Static MSI rejects memory/process/registry capture sources",
        )?;
    }
    let budget = budgets(
        spec,
        inventory.bytes,
        mapped,
        bundle_count,
        depth,
        network["canonical_copy_bytes"].as_u64().unwrap_or(0),
    )?;
    // Opaque physical slots are staged in declaration order, not the
    // inventory's BTreeMap ID order. A different order would bind a correct
    // verified input to a different worker-visible file.
    let input_projection = spec
        .inputs
        .iter()
        .enumerate()
        .map(|(index, declaration)| {
            let input = item(inventory, &declaration.id, "inputs")?;
            Ok(json!({"binding":input,"staging_slot":format!("inputs/{index:04}.bin"),"physical_copies":1}))
        })
        .collect::<Result<Vec<_>>>()?;
    let persona_digest = identity(
        b"emumee.analysis.persona.modeled.v1\0",
        &canonical(&effective_persona)?,
    );
    let value = json!({"schema":1,"kind":"analysis_plan_only","executable":false,"blocked_by":["general_worker_profile_and_full_port_not_qualified"],"capabilities_version":capabilities.version,
        "original_config_sha256":spec.original_json_sha256,"decoded_config_sha256":spec.decoded_sha256,"target":spec.target,"inputs":input_projection,"original_input":originals[0].spec.id,"execution_input":target.spec.id,"companions":companion_identity,"persona":effective_persona,"persona_sha256":persona_digest,
        "invocation":invocation,"network":network,"limits":spec.limits,"capture":spec.capture,"reports":spec.reports,"budget":budget,
        "runtime_projection":{"model_validated":true,"engine_applied":false,"pending_consumers":["external_engine_configuration","persona_cpu_clock_and_kernel_environment","resource_profile","mounted_input_graph","distinct_offline_broker","capture_sources","general_report_role"]},
        "report_provenance":{"engine_integrity":"sha256-v1","network_integrity":"sha256-v1","artifact_names":"legacy20_prefix_collision_checked","typed_catalog_names":"full64_sha256","execution_evidence":"required_not_synthesized","checkpoint":"verified_bytes_no_completion_promotion"}});
    let canonical = canonical(&value)?;
    let plan_digest = identity(b"emumee.analysis.plan.v1\0", &canonical);
    let request = super::canonical(
        &json!({"schema":1,"operation":"inspect_analysis_plan_only","plan_sha256":plan_digest,"plan":value,"scope":"Pure verified-byte planning; no arbitrary input execution authority"}),
    )?;
    let request_hash = digest(&request);
    Ok(ResolvedPlan {
        value,
        canonical,
        digest: plan_digest,
        request,
        request_hash,
    })
}
/// Explicit planning-only Driver128 branch. This does not change the legacy
/// resolver or grant a general worker permission to execute a kernel target.
pub fn resolve_driver128_planning(
    spec: &PlanSpec,
    inventory: &VerifiedInventory,
    capabilities: &Capabilities,
) -> Result<ResolvedPlan> {
    demand(
        spec.schema == 1 && capabilities.version == 1,
        "schema",
        "schema",
        "Unsupported Driver128 planning schema/capability",
    )?;
    demand(
        identity(
            b"emumee.analysis.inventory.intent.v1\0",
            &canonical(&spec.inputs)?,
        ) == inventory.intent_digest
            && spec.original_json_sha256.is_some()
            && spec.decoded_sha256.as_deref()
                == Some(identity(b"emumee.analysis.spec.v1\0", &canonical(spec)?).as_str()),
        "binding_mismatch",
        "inputs",
        "Driver128 decoded plan or byte inventory changed",
    )?;
    execution_caps(&spec.limits)?;
    let budget = project_driver_resources(spec, inventory)?;
    let (effective_persona, build, _) = persona(&spec.persona, &spec.limits)?;
    demand(
        matches!(build, 22631 | 26200) && matches!(spec.invocation, Invocation::None),
        "unsupported_driver_projection",
        "persona/invocation",
        "Driver128 planning requires qualified build 22631/26200 and DriverEntry invocation",
    )?;
    let Target::KernelDriver {
        input,
        architecture: Arch::X64,
        unload: false,
        code_reference: Reference::None,
        service_name: Some(service_name),
    } = &spec.target
    else {
        return Err(problem(
            "unsupported_driver_projection",
            "target",
            "Initial Driver128 planning requires named x64 DriverEntry",
        ));
    };
    demand(
        crate::driver_input::service_name_valid(service_name)
            && spec.inputs.len() <= 2
            && spec.inputs.first().is_some_and(|slot| slot.id == *input)
            && spec.companions.is_empty(),
        "unsupported_driver_projection",
        "target/inputs",
        "Driver128 target, physical order or companion graph unsupported",
    )?;
    let target = item(inventory, input, "target.input")?;
    demand(
        matches!(target.spec.mount, Mount::NotMounted)
            && target.spec.roles.len() == 2
            && target.spec.roles.contains(&InputRole::OriginalPrimary)
            && target.spec.roles.contains(&InputRole::ExecutionPrimary),
        "input_role",
        "target.input",
        "Driver128 public target must be sole unmounted original/execution primary",
    )?;
    demand(
        spec.capture
            .sources
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            == BTreeSet::from([CaptureSource::MemorySnapshots, CaptureSource::StructuralPe])
            && spec.capture.sources.len() == 2,
        "unsupported_capture_sources",
        "capture.sources",
        "Initial Driver128 planning allows only memory snapshots and structural PE",
    )?;
    let network = match (&spec.network, spec.inputs.get(1)) {
        (Network::OfflineDeny, None) => json!({
            "kind":"offline_deny","complete":false,"canonical_copy_bytes":0,
            "monitoring":"requires_qualified_distinct_offline_broker",
        }),
        (Network::OfflineExactReplay { input }, Some(declared)) if declared.id == *input => {
            let fixture = item(inventory, input, "network.input")?;
            demand(
                declared.roles.as_slice() == [InputRole::OfflineFixtures]
                    && matches!(declared.mount, Mount::NotMounted)
                    && fixture.spec.sha256 == declared.sha256,
                "input_role",
                "network.input",
                "Driver128 private fixture must be sole unmounted second slot",
            )?;
            let Inspection::Fixtures {
                canonical_sha256,
                canonical_bytes,
                rules,
                bodies,
            } = &fixture.inspection
            else {
                return Err(problem(
                    "fixture_document",
                    "network.input",
                    "Driver128 private fixture parser evidence absent",
                ));
            };
            json!({
                "kind":"offline_exact_replay","input":input,
                "original_sha256":fixture.spec.sha256,"original_bytes":fixture.spec.size,
                "canonical_sha256":canonical_sha256,"canonical_copy_bytes":canonical_bytes,
                "rules":rules,"bodies":bodies,"matching_version":"exact_request_v1",
                "broker_protocol":1,"capabilities":0,"fixture_visibility":"broker_only",
                "complete":false,
            })
        }
        _ => {
            return Err(problem(
                "unsupported_driver_projection",
                "network/inputs",
                "Driver128 planning permits only deny or one broker-private exact fixture",
            ));
        }
    };
    let inputs = spec
        .inputs
        .iter()
        .enumerate()
        .map(|(index, declaration)| {
            let verified = item(inventory, &declaration.id, "inputs")?;
            Ok(json!({"binding":verified,"staging_slot":format!("inputs/{index:04}.bin"),"physical_copies":1}))
        })
        .collect::<Result<Vec<_>>>()?;
    let value = json!({
        "schema":1,"kind":"driver128_plan_only","executable":false,
        "guest_admission":false,"engine_applied":false,
        "blocked_by":["general_driver128_runtime_and_report_not_qualified"],
        "capabilities_version":capabilities.version,
        "original_config_sha256":spec.original_json_sha256,
        "decoded_config_sha256":spec.decoded_sha256,
        "target":spec.target,"inputs":inputs,"original_input":input,
        "execution_input":input,"companions":[],"persona":effective_persona,
        "invocation":{"kind":"none"},"network":network,"limits":spec.limits,
        "capture":spec.capture,"reports":spec.reports,"budget":budget,
        "runtime_projection":{"model_validated":false,"engine_applied":false,
            "guest_admission":false,"pending_consumers":["driver128_runtime",
            "capture_catalog_and_carve","checkpoint","report_validation",
            "same_build_containment"]},
    });
    let canonical = canonical(&value)?;
    let digest = identity(b"emumee.analysis.plan.v1\0", &canonical);
    let request = super::canonical(&json!({
        "schema":1,"operation":"inspect_driver128_plan_only",
        "plan_sha256":digest,"plan":value,
        "scope":"Pure verified-byte Driver128 planning; no guest execution authority",
    }))?;
    let request_hash = crate::report_bundle::digest(&request);
    Ok(ResolvedPlan {
        value,
        canonical,
        digest,
        request,
        request_hash,
    })
}
fn budgets(
    spec: &PlanSpec,
    input_bytes: u64,
    mapped: u64,
    mounted: u64,
    depth: u64,
    fixture_copy: u64,
) -> Result<Value> {
    let limits = &spec.limits;
    let reports = &spec.reports;
    execution_caps(limits)?;
    for (field, limit) in [
        ("worker_startup_ms", limits.worker_startup_ms),
        ("reporting_grace_ms", limits.reporting_grace_ms),
        ("broker_startup_ms", limits.broker_startup_ms),
        ("broker_grace_ms", limits.broker_grace_ms),
    ] {
        demand(
            (1..=120_000).contains(&limit),
            "deadline_limit",
            format!("limits.{field}"),
            "Explicit phase grace must be1..120000ms",
        )?;
    }
    let worker_deadline = sum(
        [
            limits.guest_timeout_ms,
            limits.worker_startup_ms,
            limits.reporting_grace_ms,
        ],
        "limits.worker_deadline",
    )?;
    let broker_deadline = sum(
        [
            worker_deadline,
            limits.broker_startup_ms,
            limits.broker_grace_ms,
        ],
        "limits.broker_deadline",
    )?;
    demand(
        (512..=8192).contains(&limits.worker_memory_mb) && limits.broker_memory_mb == 256,
        "job_limit",
        "limits.worker_memory_mb",
        "Worker512..8192MiB and separate broker256MiB are explicit planning caps",
    )?;
    demand(
        limits.guest_mapped_bytes >= mapped
            && limits.guest_mapped_bytes <= 512 * MIB
            && limits.guest_heap_bytes <= 256 * MIB
            && limits.guest_pool_bytes <= 256 * MIB
            && (1..=128).contains(&limits.guest_threads),
        "guest_memory_limit",
        "limits.guest_mapped_bytes",
        "Insufficient image reservation or excessive guest map/heap/pool/thread limits",
    )?;
    demand(
        limits.broker_stream_bytes > 0
            && limits.broker_stream_bytes <= crate::broker::MAX_STREAM as u64
            && limits.broker_journal_bytes > 0
            && limits.broker_journal_bytes <= crate::broker_journal::MAX_JOURNAL_BYTES as u64,
        "broker_limit",
        "limits",
        "Both pinned streams and private journal need explicit positive bounded caps",
    )?;
    demand(
        reports.summary_bytes > 0
            && reports.summary_bytes <= crate::reports::MAX_SUMMARY_BYTES as u64
            && reports.engine_bytes > 0
            && reports.engine_bytes <= crate::reports::MAX_ENGINE_BYTES as u64
            && reports.network_bytes > 0
            && reports.network_bytes <= crate::reports::MAX_NETWORK_REPORT_BYTES as u64
            && reports.manifest_bytes > 0
            && reports.manifest_bytes <= MIB,
        "report_limit",
        "reports",
        "Report byte limits exceed legacy envelope caps",
    )?;
    let report_bytes = sum(
        [
            reports.summary_bytes,
            reports.summary_bytes,
            reports.engine_bytes,
            reports.network_bytes,
            reports.manifest_bytes,
            reports.manifest_bytes,
        ],
        "reports",
    )?;
    let ipc_bytes = sum(
        [limits.broker_stream_bytes, limits.broker_stream_bytes],
        "limits.broker_stream_bytes",
    )?;
    let output_minimum = sum(
        [
            input_bytes,
            fixture_copy,
            MAX_PLAN_BYTES as u64,
            report_bytes,
            spec.capture.retained_bytes,
            limits.broker_journal_bytes,
            ipc_bytes,
            8 * MIB,
        ],
        "limits.max_output_bytes",
    )?;
    let physical_inputs = spec.inputs.len() as u64;
    let observation_payload_cap = 10_000u64;
    // Guest mount paths stay metadata; physical staging uses flat opaque slots.
    let directories = 8u64;
    let entries = sum(
        [physical_inputs, observation_payload_cap, directories, 64],
        "limits.max_output_entries",
    )?;
    demand(
        limits.max_output_bytes >= output_minimum && limits.max_output_bytes <= 2 * 1024 * MIB,
        "output_budget",
        "limits.max_output_bytes",
        "Output cap must cover all physical inputs, both streams, journal, payloads and report/checkpoint copies",
    )?;
    demand(
        limits.max_output_entries as u64 >= entries
            && limits.max_output_entries <= 100_000
            && limits.max_output_directories as u64 >= directories
            && limits.max_output_directories <= 1024
            && limits.max_output_depth >= 4
            && limits.max_output_depth <= 40,
        "output_shape",
        "limits",
        "Output entry/directory/depth cap omits staged or control artifacts",
    )?;
    let host_minimum = sum(
        [
            limits.guest_mapped_bytes,
            limits.guest_heap_bytes,
            limits.guest_pool_bytes,
            limits.guest_threads as u64 * MIB,
            input_bytes,
            spec.capture.retained_bytes,
            256 * MIB,
        ],
        "limits.worker_memory_mb",
    )?;
    demand(
        limits.worker_memory_mb as u64 * MIB >= host_minimum,
        "job_budget",
        "limits.worker_memory_mb",
        "Host job reservation omits images, modeled allocations, stacks, input, retained payloads or runtime headroom",
    )?;
    Ok(
        json!({"staged_physical_input_bytes":input_bytes,"canonical_fixture_copy_bytes":fixture_copy,"request_reservation_bytes":MAX_PLAN_BYTES,"report_and_checkpoint_reservation_bytes":report_bytes,
        "artifact_retention_bytes":spec.capture.retained_bytes,"private_broker_journal_bytes":limits.broker_journal_bytes,"broker_request_stream_bytes":limits.broker_stream_bytes,"broker_response_stream_bytes":limits.broker_stream_bytes,
        "lifecycle_receipt_reservation_bytes":8*MIB,"minimum_output_bytes":output_minimum,"minimum_output_entries":entries,"minimum_output_directories":directories,"minimum_worker_bytes":host_minimum,
        "guest_mount_count":mounted,"guest_mount_max_depth":depth,"physical_input_staging":"flat_opaque_slots","worker_deadline_ms":worker_deadline,"broker_deadline_ms":broker_deadline,"general_job_adapter":"not_qualified"}),
    )
}

#[cfg(test)]
mod slot_order_tests {
    use super::*;

    #[test]
    fn resolved_slot_projection_uses_declared_order_when_ids_sort_differently() {
        // NativeA declares primary first, then guest-data; the BTreeMap sorts
        // guest-data first. The bytes remain compiler-owned generated inputs.
        let generated = crate::plan_runtime::Case::NativeA
            .generated(Arch::X64)
            .unwrap();
        let spec = PlanSpec::decode(&generated.plan).unwrap();
        assert_eq!(spec.inputs[0].id, "primary");
        assert_eq!(spec.inputs[1].id, "guest-data");
        let actual = spec
            .inputs
            .iter()
            .zip(&generated.inputs)
            .map(|(input, bytes)| InputBytes {
                id: &input.id,
                bytes,
            })
            .collect::<Vec<_>>();
        let inventory = VerifiedInventory::verify(&spec.inputs, &actual).unwrap();
        let resolved = resolve(&spec, &inventory, &Capabilities::planning_only_v1()).unwrap();
        let projected = resolved.value()["inputs"].as_array().unwrap();
        for (index, declaration) in spec.inputs.iter().enumerate() {
            assert_eq!(projected[index]["binding"]["spec"]["id"], declaration.id);
            assert_eq!(
                projected[index]["staging_slot"],
                format!("inputs/{index:04}.bin")
            );
            assert_eq!(
                projected[index]["binding"]["spec"]["sha256"],
                declaration.sha256
            );
        }
        assert!(!resolved.executable());
    }
}

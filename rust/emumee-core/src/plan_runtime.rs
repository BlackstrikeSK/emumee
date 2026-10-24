//! Closed resolved-plan installation evidence. No general launch capability.
use crate::{analysis_plan as p, report_bundle::digest};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
pub const MAX_REQUEST: usize = 4096;
pub const MAX_INPUT: usize = 1024 * 1024;
pub const MAX_OUTPUT: u64 = 1536 * 1024 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Case {
    NativeA,
    NativeB,
    NativeReplay,
    NativeDeny,
    Kernel17,
    Kernel19,
    StaticMsi,
}
impl Case {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "native-a" => Self::NativeA,
            "native-b" => Self::NativeB,
            "native-replay" => Self::NativeReplay,
            "native-deny" => Self::NativeDeny,
            "kernel17" => Self::Kernel17,
            "kernel19" => Self::Kernel19,
            "static-msi" => Self::StaticMsi,
            _ => return None,
        })
    }
    pub fn kernel(self) -> bool {
        matches!(self, Self::Kernel17 | Self::Kernel19)
    }
    pub fn static_only(self) -> bool {
        self == Self::StaticMsi
    }
    pub fn replay(self) -> bool {
        self == Self::NativeReplay
    }
    pub fn network_probe(self) -> bool {
        matches!(self, Self::NativeReplay | Self::NativeDeny)
    }
    pub fn expected_return(self) -> Option<u64> {
        Some(match self {
            Self::NativeA => {
                u32::from_le_bytes(*b"ALFA")
                    ^ u32::from_le_bytes(*b"ONE!")
                    ^ u32::from_le_bytes(*b"DATA")
            }
            Self::NativeB => {
                u32::from_le_bytes(*b"BETA")
                    ^ u32::from_le_bytes(*b"TWO!")
                    ^ u32::from_le_bytes(*b"MORE")
            }
            Self::Kernel17 => 17,
            Self::Kernel19 => 19,
            Self::NativeReplay => 0x03020100,
            Self::NativeDeny => 0,
            Self::StaticMsi => return None,
        } as u64)
    }
}
/// Fixed failure scenarios for the closed generated role. Never a general hook.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fault {
    #[default]
    None,
    CrashAfterCheckpoint,
    TimeoutAfterCheckpoint,
    BrokerDeath,
    BrokerPartial,
    ControllerExit,
    ControllerPartial,
    Reconfigure,
    GuestTimeout,
    OutputDirectories,
}
impl Fault {
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "crash-after-checkpoint" => Self::CrashAfterCheckpoint,
            "timeout-after-checkpoint" => Self::TimeoutAfterCheckpoint,
            "broker-death" => Self::BrokerDeath,
            "broker-partial" => Self::BrokerPartial,
            "controller-exit" => Self::ControllerExit,
            "controller-partial" => Self::ControllerPartial,
            "reconfigure" => Self::Reconfigure,
            "guest-timeout" => Self::GuestTimeout,
            "output-directories" => Self::OutputDirectories,
            _ => return None,
        })
    }
    pub fn is_none(&self) -> bool {
        *self == Self::None
    }
    pub fn checkpoint(self) -> bool {
        matches!(
            self,
            Self::CrashAfterCheckpoint | Self::TimeoutAfterCheckpoint
        )
    }
    pub fn controller_exit(self) -> bool {
        matches!(self, Self::ControllerExit | Self::ControllerPartial)
    }
    pub fn broker_failure(self) -> bool {
        matches!(self, Self::BrokerDeath | Self::BrokerPartial)
    }
    pub fn case(self) -> Case {
        if self.broker_failure() {
            Case::NativeDeny
        } else {
            Case::NativeA
        }
    }
    pub fn worker_deadline_ms(self) -> u64 {
        match self {
            Self::TimeoutAfterCheckpoint => 7000,
            Self::GuestTimeout => 30001,
            _ => 33000,
        }
    }
    pub fn broker_deadline_ms(self) -> u64 {
        match self {
            Self::TimeoutAfterCheckpoint => 9000,
            Self::GuestTimeout => 45001,
            _ => 48000,
        }
    }
    pub fn expected_return(self, case: Case) -> Option<u64> {
        if self.checkpoint() {
            Some(u32::from_le_bytes(*b"RUST") as u64)
        } else if matches!(self, Self::GuestTimeout | Self::Reconfigure) {
            None
        } else {
            case.expected_return()
        }
    }
    fn generated(self, case: Case, arch: p::Arch) -> Result<Generated, String> {
        if self != Self::None && case != self.case() {
            return Err("Closed fault/case combination rejected".into());
        }
        let mut g = case.generated(arch)?;
        if self == Self::None {
            return Ok(g);
        }
        let mut plan: Value = serde_json::from_slice(&g.plan).map_err(|_| "Generated plan")?;
        if self.checkpoint() {
            // Compiler-owned PE recipe, not an arbitrary supplied image patch.
            g.inputs[0] = crate::fixtures::api_probe(
                arch.architecture(),
                crate::fixtures::ApiFixture::FileRoundTripA,
            );
            let path = b"C:\\Users\\Alex\\Downloads\\fault-checkpoint.bin\0";
            g.inputs[0][0xf00..0xf80].fill(0);
            g.inputs[0][0xf00..0xf00 + path.len()].copy_from_slice(path);
        }
        if self == Self::GuestTimeout {
            let image = crate::pe::PeImage::parse(&g.inputs[0], "compiler-loop.exe")
                .map_err(|e| e.to_string())?;
            let section = image
                .sections
                .iter()
                .find(|s| image.entry_rva >= s.rva && image.entry_rva - s.rva + 2 <= s.raw_size)
                .ok_or("Generated entry extent")?;
            let raw = (section.raw_offset + image.entry_rva - section.rva) as usize;
            g.inputs[0][raw..raw + 2].copy_from_slice(&[0xeb, 0xfe]);
            plan["limits"]["guest_timeout_ms"] = json!(1);
            plan["limits"]["max_instructions"] = json!(1_000_000_000u64);
        }
        if self == Self::TimeoutAfterCheckpoint {
            plan["limits"]["guest_timeout_ms"] = json!(1000);
            plan["limits"]["worker_startup_ms"] = json!(5000);
            plan["limits"]["reporting_grace_ms"] = json!(1000);
            plan["limits"]["broker_startup_ms"] = json!(1000);
            plan["limits"]["broker_grace_ms"] = json!(1000);
        }
        plan["inputs"][0]["size"] = json!(g.inputs[0].len());
        plan["inputs"][0]["sha256"] = json!(digest(&g.inputs[0]));
        g.plan = bounded(&plan)?;
        Ok(g)
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: u32,
    #[serde(default, skip_serializing_if = "Fault::is_none")]
    pub fault: Fault,
    pub case: Case,
    pub architecture: p::Arch,
    pub run_id: String,
    pub started_at: String,
    pub plan_sha256: String,
    pub persona_sha256: String,
    pub fixture_sha256: String,
}
pub struct Generated {
    pub plan: Vec<u8>,
    pub inputs: Vec<Vec<u8>>,
    pub fixtures: Vec<u8>,
    pub persona: Vec<u8>,
}
fn bounded<T: Serialize>(v: &T) -> Result<Vec<u8>, String> {
    crate::report_bundle::bounded_json(v, p::MAX_PLAN_BYTES).map_err(|e| e.to_string())
}
impl Case {
    pub fn generated(self, arch: p::Arch) -> Result<Generated, String> {
        let mut process = crate::persona::PersonaConfig::fixture();
        process.logical_processors = 4;
        let cpu = crate::cpu::CpuProfile {
            brand: "Closed Plan Synthetic CPU".into(),
            signature: 0x000806e9,
            cores: 2,
            threads_per_core: 2,
            base_mhz: 3200,
            max_mhz: 4200,
            cpuid_overrides: vec![],
        };
        process.hostname = if self == Self::NativeB {
            "BETA"
        } else {
            "ALFA"
        }
        .into();
        let args = vec![
            "two words".to_owned(),
            if self == Self::NativeB {
                "second"
            } else {
                "first"
            }
            .into(),
        ];
        let command = crate::persona::command_line(
            &std::iter::once(r"C:\Users\Alex\Downloads\owned.exe".into())
                .chain(args.iter().cloned())
                .collect::<Vec<_>>(),
            &[2],
        )
        .map_err(|e| e.to_string())?;
        let input = if self.kernel() {
            crate::fixtures::counted_driver(
                arch.architecture(),
                if self == Self::Kernel19 { 19 } else { 17 },
            )
        } else if self.static_only() {
            crate::msi_fixture::input(crate::msi_fixture::Case::MiniV3)
        } else if self.network_probe() {
            crate::fixtures::winhttp_probe(
                arch.architecture(),
                if self.replay() {
                    crate::fixtures::WinHttpFixture::Normal
                } else {
                    crate::fixtures::WinHttpFixture::Miss
                },
            )
        } else {
            crate::fixtures::installed_plan_probe(arch.architecture(), &command)
        };
        let name = if self.kernel() {
            "owned.sys"
        } else if self.static_only() {
            "owned.msi"
        } else {
            "owned.exe"
        };
        let mut inputs = vec![input];
        let mut specs = vec![
            json!({"id":"primary","name":name,"roles":["original_primary","execution_primary"],"mount":{"kind":"not_mounted"},"size":inputs[0].len(),"sha256":digest(&inputs[0])}),
        ];
        if !self.kernel() && !self.static_only() {
            inputs.push(if self == Self::NativeB {
                b"MORE".to_vec()
            } else {
                b"DATA".to_vec()
            });
            specs.push(json!({"id":"guest-data","name":"Guest.dat","roles":["guest_file"],"mount":{"kind":"package","path":"Guest.dat"},"size":4,"sha256":digest(inputs.last().unwrap())}));
        }
        let fixtures = if self.replay() {
            bounded(
                &crate::fixtures::http::document(crate::broker::Probe::WinHttp)
                    .map_err(|e| e.to_string())?,
            )?
        } else {
            br#"{"version":1,"rules":[]}"#.to_vec()
        };
        if self.replay() {
            inputs.push(fixtures.clone());
            specs.push(json!({"id":"offline","name":"offline.json","roles":["offline_fixtures"],"mount":{"kind":"not_mounted"},"size":fixtures.len(),"sha256":digest(&fixtures)}));
        }
        let persona = json!({"process":process,"cpu":cpu,"clock":{"utc_filetime":133500000000000000u64,"uptime_ms":543210,"utc_offset_minutes":120,"source":"fixed","source_id":"closed-plan-seed"},"windows_build":26100,"current_processor":0,"physical_memory_mb":8192,"available_memory_mb":4096});
        let persona_raw = bounded(&persona)?;
        let target = if self.kernel() {
            json!({"kind":"kernel_driver","input":"primary","architecture":arch,"unload":false,"code_reference":{"kind":"none"}})
        } else if self.static_only() {
            json!({"kind":"static_msi","input":"primary"})
        } else {
            json!({"kind":"native_exe","input":"primary","architecture":arch})
        };
        let plan = bounded(
            &json!({"schema":1,"target":target,"inputs":specs,"companions":[],"persona":{"kind":"rust_modeled_v1","value":persona},
   "invocation":if self.kernel()||self.static_only(){json!({"kind":"none"})}else{json!({"kind":"process","guest_root":"C:\\Users\\Alex\\Downloads","arguments":args,"force_quote_indices":[1],"environment":[{"name":"PLAN_TOKEN","value":if self==Self::NativeB{"TWO!"}else{"ONE!"}}]})},"network":if self.replay(){json!({"kind":"offline_exact_replay","input":"offline"})}else{json!({"kind":"offline_deny"})},
   "limits":{"guest_timeout_ms":3000,"max_instructions":100000,"max_native_api_calls":100000,"worker_startup_ms":15000,"reporting_grace_ms":15000,"broker_startup_ms":10000,"broker_grace_ms":5000,"worker_memory_mb":1024,"broker_memory_mb":256,"max_output_bytes":MAX_OUTPUT,"max_output_entries":22000,"max_output_directories":64,"max_output_depth":40,"guest_mapped_bytes":134217728,"guest_heap_bytes":134217728,"guest_pool_bytes":134217728,"guest_threads":8,"broker_stream_bytes":134217728,"broker_journal_bytes":67108864},
   "capture":{"profile":"legacy32_capture_v1","sources":if self.static_only(){json!(["container_streams"])}else{json!(["guest_files","registry_binary"])},"retained_bytes":16777216,"memory_scan_bytes":134217728,"memory_strings":{"kind":"disabled"},"checkpoint":{"kind":"final_boundary"}},
   "reports":{"profile":"legacy_v1","summary_bytes":5242880,"engine_bytes":52428800,"network_bytes":67108864,"manifest_bytes":1048576}}),
        )?;
        Ok(Generated {
            plan,
            inputs,
            fixtures,
            persona: persona_raw,
        })
    }
}
impl Request {
    pub fn generated(
        case: Case,
        architecture: p::Arch,
        run_id: String,
        started_at: String,
    ) -> Result<(Self, Generated), String> {
        Self::generated_fault(case, Fault::None, architecture, run_id, started_at)
    }
    pub fn generated_fault(
        case: Case,
        fault: Fault,
        architecture: p::Arch,
        run_id: String,
        started_at: String,
    ) -> Result<(Self, Generated), String> {
        let g = fault.generated(case, architecture)?;
        Ok((
            Self {
                schema: 1,
                fault,
                case,
                architecture,
                run_id,
                started_at,
                plan_sha256: digest(&g.plan),
                persona_sha256: digest(&g.persona),
                fixture_sha256: digest(&g.fixtures),
            },
            g,
        ))
    }
    pub fn generated_inputs(&self) -> Result<Generated, String> {
        self.fault.generated(self.case, self.architecture)
    }
    pub fn parse(raw: &[u8]) -> Result<Self, String> {
        if raw.len() > MAX_REQUEST {
            return Err("Closed plan request exceeds4KiB".into());
        }
        let r: Self =
            serde_json::from_slice(raw).map_err(|_| "Closed plan request schema rejected")?;
        if r.schema != 1
            || !crate::reports::valid_run_id(&r.run_id)
            || r.started_at.len() > 64
            || r.started_at.is_empty()
            || !r.started_at.is_ascii()
        {
            return Err("Closed plan request identity rejected".into());
        }
        let g = r.fault.generated(r.case, r.architecture)?;
        if r.plan_sha256 != digest(&g.plan)
            || r.persona_sha256 != digest(&g.persona)
            || r.fixture_sha256 != digest(&g.fixtures)
        {
            return Err("Closed plan request recipe binding rejected".into());
        }
        Ok(r)
    }
}
/// Constructor verifies exact supplied buffers; private fields cannot be decoded.
pub struct PreparedAnalysis {
    request: Request,
    request_sha256: String,
    plan: p::PlanSpec,
    resolved: p::ResolvedPlan,
    inputs: Vec<Vec<u8>>,
    persona_raw: Vec<u8>,
    authority: Authority,
}
#[derive(Clone, Copy)]
enum Authority {
    ParentFullInventory,
    WorkerPublicBuffers,
}
impl PreparedAnalysis {
    pub fn prepare(
        request_raw: &[u8],
        plan_raw: &[u8],
        inputs: Vec<Vec<u8>>,
        persona_raw: Vec<u8>,
    ) -> Result<Self, String> {
        let request = Request::parse(request_raw)?;
        if digest(plan_raw) != request.plan_sha256 || digest(&persona_raw) != request.persona_sha256
        {
            return Err("Closed plan/persona transport binding changed".into());
        }
        let plan = p::PlanSpec::decode(plan_raw).map_err(|e| e.to_string())?;
        if inputs.len() != plan.inputs.len()
            || inputs.len() > 4
            || inputs.iter().any(|i| i.len() > MAX_INPUT)
        {
            return Err("Closed plan input count/size rejected".into());
        }
        let bindings = plan
            .inputs
            .iter()
            .zip(&inputs)
            .map(|(i, b)| p::InputBytes {
                id: &i.id,
                bytes: b,
            })
            .collect::<Vec<_>>();
        let inventory =
            p::VerifiedInventory::verify(&plan.inputs, &bindings).map_err(|e| e.to_string())?;
        let resolved = p::resolve(&plan, &inventory, &p::Capabilities::planning_only_v1())
            .map_err(|e| e.to_string())?;
        let expected = request
            .fault
            .generated(request.case, request.architecture)?;
        physical_reservation(&plan, &resolved)?;
        if plan_raw != expected.plan || persona_raw != expected.persona || inputs != expected.inputs
        {
            return Err("Closed plan graph/actual generated bytes changed".into());
        }
        let p::PersonaSpec::RustModeledV1 { value } = &plan.persona else {
            return Err("Closed plan only models narrow persona".into());
        };
        if bounded(&serde_json::to_value(value).map_err(|e| e.to_string())?)? != persona_raw {
            return Err("Closed inline persona authority differs".into());
        }
        Ok(Self {
            request,
            request_sha256: digest(request_raw),
            plan,
            resolved,
            inputs,
            persona_raw,
            authority: Authority::ParentFullInventory,
        })
    }
    /// Broker-only slots must be None. The worker never calls them inspected bytes.
    pub fn prepare_worker(
        request_raw: &[u8],
        plan_raw: &[u8],
        inputs: Vec<Option<Vec<u8>>>,
        persona_raw: Vec<u8>,
    ) -> Result<Self, String> {
        let request = Request::parse(request_raw)?;
        let plan = p::PlanSpec::decode(plan_raw).map_err(|e| e.to_string())?;
        let reference = request
            .fault
            .generated(request.case, request.architecture)?;
        if digest(plan_raw) != request.plan_sha256
            || plan_raw != reference.plan
            || persona_raw != reference.persona
            || digest(&persona_raw) != request.persona_sha256
            || inputs.len() != plan.inputs.len()
        {
            return Err("Closed worker plan/persona commitment changed".into());
        }
        let mut public_specs = Vec::new();
        let mut buffers = Vec::new();
        for (index, (spec, input)) in plan.inputs.iter().zip(&inputs).enumerate() {
            let private = spec.roles.contains(&p::InputRole::OfflineFixtures);
            if private {
                if input.is_some() {
                    return Err("Broker-only fixture supplied to worker".into());
                }
            } else {
                let raw = input.as_ref().ok_or("Actual worker input absent")?;
                if *raw != reference.inputs[index] {
                    return Err("Actual closed worker input changed".into());
                }
                public_specs.push(spec.clone());
                buffers.push(p::InputBytes {
                    id: &spec.id,
                    bytes: raw,
                });
            }
        }
        // This evidence covers ONLY real public buffers acquired by the worker.
        let _public_inventory =
            p::VerifiedInventory::verify(&public_specs, &buffers).map_err(|e| e.to_string())?;
        // A compiler-owned reference projection validates the closed graph, not an
        // assertion that the worker acquired the private slot or parent inventory.
        let recipe_bindings = plan
            .inputs
            .iter()
            .zip(&reference.inputs)
            .map(|(i, b)| p::InputBytes {
                id: &i.id,
                bytes: b,
            })
            .collect::<Vec<_>>();
        let reference_inventory = p::VerifiedInventory::verify(&plan.inputs, &recipe_bindings)
            .map_err(|e| e.to_string())?;
        let resolved = p::resolve(
            &plan,
            &reference_inventory,
            &p::Capabilities::planning_only_v1(),
        )
        .map_err(|e| e.to_string())?;
        physical_reservation(&plan, &resolved)?;
        Ok(Self {
            request,
            request_sha256: digest(request_raw),
            plan,
            resolved,
            inputs: inputs.into_iter().map(|b| b.unwrap_or_default()).collect(),
            persona_raw,
            authority: Authority::WorkerPublicBuffers,
        })
    }
    pub fn request_sha256(&self) -> &str {
        &self.request_sha256
    }
    pub fn request(&self) -> &Request {
        &self.request
    }
    pub fn spec(&self) -> &p::PlanSpec {
        &self.plan
    }
    pub fn input(&self) -> &[u8] {
        &self.inputs[0]
    }
    pub fn resolved(&self) -> &p::ResolvedPlan {
        &self.resolved
    }
    pub fn receipt(&self) -> Value {
        json!({"schema":"emumee.closed-plan-installation.v1","generated_only":true,"request_sha256":self.request_sha256,"plan_input_sha256":self.request.plan_sha256,"resolved_plan_sha256":self.resolved.sha256(),"persona_input_sha256":digest(&self.persona_raw),"fixture_input_sha256":self.request.fixture_sha256,"input_bindings":self.plan.inputs,"physical_reservation":physical_reservation(&self.plan,&self.resolved).expect("sealed constructor checked accounting"),"inventory_authority":match self.authority{Authority::ParentFullInventory=>"parent_actual_full_inventory",Authority::WorkerPublicBuffers=>"worker_actual_public_buffers_private_slot_uninspected_commitment"},"projection_source":match self.authority{Authority::ParentFullInventory=>"actual_full_inventory",Authority::WorkerPublicBuffers=>"compiler_owned_reference_projection"},"supported_closed_graphs":["native_exe","kernel_driver_legacy32","static_msi"],"scope":"Exact compiler-owned staged buffers; no arbitrary sample or legacy full-persona admission"})
    }
    pub fn prepare_state(
        &self,
    ) -> Result<
        (
            crate::fullpersona::PreparedGuestState,
            Option<crate::persona::ProcessConfig>,
        ),
        String,
    > {
        let p::PersonaSpec::RustModeledV1 { value } = &self.plan.persona else {
            return Err("Narrow persona required".into());
        };
        let persona =
            crate::persona::Persona::new(value.process.clone()).map_err(|e| e.to_string())?;
        let cpu = crate::cpu::CpuProfile {
            brand: value.cpu.brand.clone(),
            signature: value.cpu.signature,
            cores: value.cpu.cores,
            threads_per_core: value.cpu.threads_per_core,
            base_mhz: value.cpu.base_mhz,
            max_mhz: value.cpu.max_mhz,
            cpuid_overrides: vec![],
        };
        let clock = crate::clock::GuestClock::new(
            value.clock.utc_filetime,
            value.clock.uptime_ms,
            value.clock.utc_offset_minutes,
            cpu.base_mhz,
        )
        .map_err(|e| e.to_string())?;
        let directories =
            [r"C:\Users", r"C:\Users\Alex", r"C:\Users\Alex\Downloads"].map(str::to_owned);
        let files = self
            .plan
            .inputs
            .iter()
            .zip(&self.inputs)
            .filter_map(|(i, b)| {
                if i.id == "guest-data" {
                    Some(crate::filesystem::SeedFile {
                        path: r"C:\Users\Alex\Downloads\Guest.dat",
                        bytes: b,
                    })
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        let filesystem = crate::filesystem::VirtualFileSystem::from_seed(
            value.clock.utc_filetime,
            &value.process.current_directory,
            &directories,
            &files,
        )
        .map_err(|e| e.to_string())?;
        let invocation = if let p::Invocation::Process {
            arguments,
            force_quote_indices,
            environment,
            ..
        } = &self.plan.invocation
        {
            Some(crate::persona::ProcessConfig {
                image_path: self.resolved.value()["invocation"]["image_path"]
                    .as_str()
                    .ok_or("Resolved image path missing")?
                    .into(),
                arguments: arguments.clone(),
                force_quotes: force_quote_indices.clone(),
                command_line: Some(
                    self.resolved.value()["invocation"]["command_line"]
                        .as_str()
                        .ok_or("Resolved command line missing")?
                        .into(),
                ),
                current_directory: None,
                environment_overrides: environment
                    .iter()
                    .map(|a| (a.name.clone(), Some(a.value.clone())))
                    .collect(),
            })
        } else {
            None
        };
        Ok((
            crate::fullpersona::PreparedGuestState {
                persona,
                cpu,
                clock,
                registry: crate::registry::Registry::new(value.clock.utc_filetime),
                filesystem,
            },
            invocation,
        ))
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerSession {
    pub schema: u32,
    pub request_sha256: String,
    pub plan_sha256: String,
    pub fixture_sha256: String,
    pub cleanup_plan: String,
    pub deadline_ms: u64,
}
impl BrokerSession {
    pub fn new(prepared: &PreparedAnalysis, cleanup_plan: String) -> Self {
        Self {
            schema: 1,
            request_sha256: prepared.request_sha256.clone(),
            plan_sha256: prepared.request.plan_sha256.clone(),
            fixture_sha256: prepared.request.fixture_sha256.clone(),
            cleanup_plan,
            deadline_ms: prepared.resolved.value()["budget"]["broker_deadline_ms"]
                .as_u64()
                .unwrap_or(0),
        }
    }
    pub fn parse(raw: &[u8], request_raw: &[u8]) -> Result<Self, String> {
        if raw.len() > MAX_REQUEST {
            return Err("Plan broker config exceeds4KiB".into());
        }
        let s: Self = serde_json::from_slice(raw).map_err(|_| "Plan broker schema rejected")?;
        let request = Request::parse(request_raw)?;
        if s.schema != 1
            || s.request_sha256 != digest(request_raw)
            || s.plan_sha256 != request.plan_sha256
            || s.fixture_sha256 != request.fixture_sha256
            || s.deadline_ms != request.fault.broker_deadline_ms()
            || s.cleanup_plan.is_empty()
            || s.cleanup_plan.len() > 32767
        {
            return Err("Plan broker commitments/deadline changed".into());
        }
        Ok(s)
    }
}

fn physical_reservation(plan: &p::PlanSpec, resolved: &p::ResolvedPlan) -> Result<Value, String> {
    let reports = &plan.reports;
    // Six journal-sized reservations cover pretty JSON/escaping overhead in the
    // recovery snapshot, session receipt and compatibility manifest (2x each).
    let extra = [
        reports.engine_bytes,
        reports.network_bytes,
        reports.summary_bytes,
        reports.manifest_bytes,
        reports.manifest_bytes,
        plan.capture.retained_bytes,
        plan.limits
            .broker_journal_bytes
            .checked_mul(6)
            .ok_or("Journal copy accounting overflow")?,
        (p::MAX_PLAN_BYTES as u64) * 2,
        (MAX_REQUEST as u64) * 2,
    ]
    .into_iter()
    .try_fold(0u64, |a, n| a.checked_add(n))
    .ok_or("Closed copy accounting overflow")?;
    let base = resolved.value()["budget"]["minimum_output_bytes"]
        .as_u64()
        .ok_or("Plan physical reservation absent")?;
    let total = base
        .checked_add(extra)
        .ok_or("Closed output accounting overflow")?;
    if total > plan.limits.max_output_bytes {
        return Err("Closed profile omits physical report/journal copies".into());
    }
    Ok(
        json!({"base_plan_reservation_bytes":base,"additional_parent_delivery_and_receipt_bytes":extra,"total_reserved_output_bytes":total,"output_limit_bytes":plan.limits.max_output_bytes,"copies":"Both128MiB IPC streams +64MiB private journal; worker draft, parent delivery, payload copies, recovery/session/compatibility JSON receipts, separate plan/persona/request/config. Receipt journal JSON reserved2x each; all writes remain under aggregate output watchdog."}),
    )
}

#[cfg(test)]
mod tests;

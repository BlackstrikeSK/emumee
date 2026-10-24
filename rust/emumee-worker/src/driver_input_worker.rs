//! Submitted driver role. Runs only after packaged offline AppContainer setup.
use super::{broker, save_new};
use anyhow::{Context, Result, ensure};
use emumee_core::{
    artifacts::ArtifactCatalog,
    capture_profile::CaptureProfile,
    driver_capture_reports::{self as reports, Binding, Mode, Stop},
    driver_input::{MAX_INPUT, MAX_PERSONA, MAX_REFERENCE, PROFILE, Request},
    general_broker_private_attestation::{
        Claim, OPERATION as CLAIM_OPERATION, PROFILE as CLAIM_PROFILE,
    },
    general_execution_commitment::{MAX_REQUEST as MAX_GENERAL_REQUEST, Request as GeneralRequest},
    general_worker_public_preflight::preflight_driver128_public_report,
    pe::{Architecture, Kind, PeImage},
    report_bundle::{bounded_json, digest},
};
use emumee_platform::windows::{prepare_worker, read_regular};
use serde_json::{Value, json};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
};

fn emit(root: &Path, value: &Value) -> Result<()> {
    save_new(
        &root.join("worker-result.json"),
        &bounded_json(value, 256 * 1024)?,
    )
}

pub fn execute(root: &Path, request_hash: &str) -> Result<()> {
    execute_mode(root, request_hash, None)
}

pub fn execute_brokered(root: &Path, request_hash: &str, claim_sha256: &str) -> Result<()> {
    execute_mode(root, request_hash, Some(claim_sha256))
}

fn broker_public_binding(
    submitted: &Request,
    input: &[u8],
    general_raw: &[u8],
    plan_raw: &[u8],
    staged_target: &[u8],
    expected_claim: &str,
) -> Result<Value> {
    let general = GeneralRequest::parse(general_raw).map_err(anyhow::Error::msg)?;
    ensure!(
        !general.execution_authorized
            && general.run_id == submitted.run_id
            && general.service_name == submitted.service_name
            && general.report_profile == "large_driver_v1"
            && general.public_inputs.len() == 1
            && general.public_inputs[0].index == 0
            && general.public_inputs[0].id == general.target_input_id
            && general.public_inputs[0].size == submitted.input_size
            && general.public_inputs[0].sha256 == submitted.input_sha256
            && general
                .broker_private_fixture
                .as_ref()
                .is_some_and(|fixture| fixture.index == 1),
        "Brokered submitted driver public commitment differs"
    );
    ensure!(
        staged_target == input,
        "Brokered submitted driver has different public target bytes"
    );
    let public = preflight_driver128_public_report(
        general_raw,
        &digest(general_raw),
        plan_raw,
        &[Some(staged_target), None],
    )
    .map_err(anyhow::Error::msg)?;
    ensure!(
        public.target_input_sha256 == submitted.input_sha256
            && public.target_input_bytes == submitted.input_size
            && public.service_name == submitted.service_name
            && public.public_preflight.broker_private_fixture_pending
            && !public.public_preflight.resolved_plan_independently_verified
            && !public.complete_report_binding
            && !public.guest_admission,
        "Brokered submitted driver public preflight differs"
    );
    let claim = Claim {
        schema: 1,
        profile: CLAIM_PROFILE.into(),
        operation: CLAIM_OPERATION.into(),
        execution_authorized: false,
        request_sha256: digest(general_raw),
        resolved_plan_sha256: general.resolved_plan_sha256,
        fixture: general
            .broker_private_fixture
            .context("Brokered submitted driver private fixture absent")?,
    };
    claim.validate().map_err(anyhow::Error::msg)?;
    ensure!(
        digest(&serde_json::to_vec(&claim)?) == expected_claim,
        "Brokered submitted driver private claim binding differs"
    );
    Ok(json!({
        "general_request_sha256":digest(general_raw),
        "general_plan_sha256":digest(plan_raw),
        "general_resolved_plan_sha256":claim.resolved_plan_sha256,
        "claim_sha256":expected_claim,
        "public_target_sha256":submitted.input_sha256,
        "public_preflight":public,
    }))
}

fn access_denied(path: &Path) -> bool {
    File::open(path)
        .err()
        .is_some_and(|error| error.raw_os_error() == Some(5))
}

fn execute_mode(root: &Path, request_hash: &str, claim_sha256: Option<&str>) -> Result<()> {
    let root = std::path::absolute(root)?;
    let output = if claim_sha256.is_some() {
        root.join("worker")
    } else {
        root.clone()
    };
    ensure!(output.is_dir(), "Submitted worker output directory absent");
    let containment = prepare_worker()?;
    let witness = serde_json::to_vec(&containment)?;
    save_new(&output.join("worker-containment.json"), &witness)?;
    let result = (|| -> Result<()> {
        let raw = read_regular(&root.join("request.json"), 4096, Some(&root))?;
        ensure!(
            digest(&raw) == request_hash,
            "Submitted driver request hash changed"
        );
        let request = Request::parse(&raw).map_err(anyhow::Error::msg)?;
        let input = read_regular(&root.join("input.sys"), MAX_INPUT, Some(&root))?;
        ensure!(
            input.len() as u64 == request.input_size && digest(&input) == request.input_sha256,
            "Submitted driver input hash/size changed"
        );
        let pe = PeImage::parse(&input, &request.module_name())?;
        let reference = if let Some(hash) = &request.kernel_code_reference_sha256 {
            let bytes = read_regular(
                &root.join("kernel-code-reference.pe"),
                MAX_REFERENCE,
                Some(&root),
            )?;
            ensure!(
                !bytes.is_empty() && digest(&bytes) == *hash,
                "Submitted kernel reference hash changed"
            );
            Some(bytes)
        } else {
            ensure!(
                !root.join("kernel-code-reference.pe").exists(),
                "Unexpected kernel reference input"
            );
            None
        };
        let persona = if let Some(hash) = &request.persona_sha256 {
            let bytes = read_regular(&root.join("persona.json"), MAX_PERSONA, Some(&root))?;
            ensure!(
                !bytes.is_empty() && digest(&bytes) == *hash,
                "Submitted persona hash changed"
            );
            emumee_core::fullpersona::decode(
                &bytes,
                &emumee_core::fullpersona::ResolveContext::default(),
            )
            .map_err(anyhow::Error::msg)
            .context("Submitted persona has no independently valid literal clock")?;
            Some(bytes)
        } else {
            ensure!(
                !root.join("persona.json").exists(),
                "Unexpected submitted persona"
            );
            None
        };
        ensure!(
            pe.sample.architecture == Architecture::X64
                && pe.sample.kind == Kind::Driver
                && !pe.sample.managed,
            "Submitted input is not an unmanaged x64 native driver"
        );
        let source = env!("EMUMEE_BUILD_SOURCE_SHA256");
        let containment_hash = digest(&witness);
        let mut binding = json!({
            "schema": 1,
            "profile": PROFILE,
            "run_id": request.run_id,
            "request_sha256": request_hash,
            "input_sha256": request.input_sha256,
            "input_size": request.input_size,
            "kernel_code_reference_sha256": request.kernel_code_reference_sha256,
            "service_name": request.service_name,
            "driver_name": request.driver_name(),
            "registry_path": request.registry_path(),
            "source_tree_sha256": source,
            "containment_sha256": containment_hash,
            "job_memory_mib_required": 2048,
        });
        if let Some(hash) = &request.persona_sha256 {
            binding["persona_sha256"] = json!(hash);
        }
        let broker_binding = if let Some(expected_claim) = claim_sha256 {
            let control = root.join("control");
            let general_raw = read_regular(
                &control.join("request.json"),
                MAX_GENERAL_REQUEST,
                Some(&control),
            )?;
            let plan_raw = read_regular(
                &control.join("plan.json"),
                emumee_core::analysis_plan::MAX_PLAN_BYTES,
                Some(&control),
            )?;
            let staged_target =
                read_regular(&control.join("inputs/0000.bin"), MAX_INPUT, Some(&control))?;
            let mut broker_binding = broker_public_binding(
                &request,
                &input,
                &general_raw,
                &plan_raw,
                &staged_target,
                expected_claim,
            )?;
            let private = root.join("private");
            ensure!(
                access_denied(&private.join("claim.json"))
                    && access_denied(&private.join("http-fixtures.json"))
                    && access_denied(&private.join("network-broker.journal")),
                "Brokered submitted worker can read private broker data"
            );
            let ipc = root.join("ipc");
            ensure!(
                OpenOptions::new()
                    .write(true)
                    .open(ipc.join("requests.bin"))
                    .err()
                    .is_some_and(|error| error.raw_os_error() == Some(5))
                    && OpenOptions::new()
                        .append(true)
                        .open(ipc.join("responses.bin"))
                        .err()
                        .is_some_and(|error| error.raw_os_error() == Some(5))
                    && OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .open(ipc.join("injected.bin"))
                        .err()
                        .is_some_and(|error| error.raw_os_error() == Some(5)),
                "Brokered submitted worker IPC permissions are too broad"
            );
            broker_binding["private_read_denied"] = json!(true);
            broker_binding["ipc_write_separation_verified"] = json!(true);
            binding["offline_broker"] = broker_binding.clone();
            Some(broker_binding)
        } else {
            None
        };
        save_new(
            &output.join("worker-ready.json"),
            &bounded_json(&binding, 4096)?,
        )?;
        if let Some(broker_binding) = &broker_binding {
            save_new(
                &output.join("broker-admission.json"),
                &bounded_json(
                    &json!({
                        "schema":1,"role":"submitted_driver_broker_worker_v1",
                        "submitted_request_sha256":request_hash,
                        "general_request_sha256":broker_binding["general_request_sha256"],
                        "claim_sha256":broker_binding["claim_sha256"],
                        "public_target_sha256":broker_binding["public_target_sha256"],
                        "worker_containment_sha256":containment_hash,
                        "public_preflight":broker_binding["public_preflight"],
                        "private_read_denied":true,
                        "ipc_write_separation_verified":true,
                        "engine_started":false,
                    }),
                    16 * 1024,
                )?,
            )?;
        }
        let execution = if let Some(broker_binding) = &broker_binding {
            let (client, close) = broker::plan_connection(&root)?;
            let result = emumee_engine::run_submitted_driver_observed(
                &input,
                &request.service_name,
                request.max_instructions,
                request.timeout_us,
                emumee_engine::SubmittedObservationInputs {
                    persona: persona.as_deref(),
                    reference: reference.as_deref(),
                    broker: Some(client),
                    instruction_window: request.instruction_window,
                },
            );
            close.close()?;
            save_new(
                &output.join("broker-closed.json"),
                &bounded_json(
                    &json!({
                        "schema":1,"role":"submitted_driver_broker_worker_v1",
                        "submitted_request_sha256":request_hash,
                        "general_request_sha256":broker_binding["general_request_sha256"],
                        "claim_sha256":broker_binding["claim_sha256"],
                        "public_target_sha256":broker_binding["public_target_sha256"],
                        "worker_containment_sha256":containment_hash,
                        "rpc_closed":true,
                        "engine_result_available":result.is_ok(),
                    }),
                    4096,
                )?,
            )?;
            result
        } else {
            emumee_engine::run_submitted_driver_observed(
                &input,
                &request.service_name,
                request.max_instructions,
                request.timeout_us,
                emumee_engine::SubmittedObservationInputs {
                    persona: persona.as_deref(),
                    reference: reference.as_deref(),
                    broker: None,
                    instruction_window: request.instruction_window,
                },
            )
        };
        drop(input);
        let mut execution = match execution {
            Ok(value) => value,
            Err(error) => {
                let detail = format!("{error:#}").chars().take(8192).collect::<String>();
                emit(
                    &output,
                    &json!({
                        "binding": binding,
                        "status": "unreported_failure",
                        "error": detail,
                        "artifacts": [],
                        "scope": "Engine returned no complete report; guest entry state is unknown, and no unpacking is claimed"
                    }),
                )?;
                return Ok(());
            }
        };
        ensure!(
            execution
                .kernel_reference
                .as_ref()
                .map(|receipt| receipt.source_sha256.as_str())
                == request.kernel_code_reference_sha256.as_deref(),
            "Submitted kernel reference mapping receipt differs"
        );
        ensure!(
            execution
                .configuration
                .as_ref()
                .map(|receipt| receipt.input_json_sha256.as_str())
                == request.persona_sha256.as_deref()
                && execution
                    .configuration
                    .as_ref()
                    .is_none_or(|receipt| receipt.initialized),
            "Submitted persona engine configuration receipt differs"
        );
        let execution_json = serde_json::to_value(&execution)?;
        let retention = execution
            .capture_runtime
            .as_ref()
            .context("Submitted settled capture receipt missing")?
            .retention_limit as usize;
        let catalog = ArtifactCatalog::from_owned_parts(
            CaptureProfile::Driver128V1,
            std::mem::take(&mut execution.artifacts),
            std::mem::take(&mut execution.capture_summary),
            retention,
        )
        .map_err(anyhow::Error::msg)?;
        let report_binding = Binding {
            request_sha256: request_hash.into(),
            input_sha256: request.input_sha256.clone(),
            input_bytes: request.input_size,
            recipe: request.service_name.clone(),
            source_tree_sha256: source.into(),
            containment_sha256: containment_hash,
        };
        let report = reports::build(
            &request.run_id,
            &report_binding,
            Mode::SubmittedDriverCapture,
            &execution_json,
            Stop::Normal,
            false,
            &catalog,
        )?;
        let artifact_metadata = execution_json["artifacts"].clone();
        let mut artifact_total = 0usize;
        ensure!(
            report.payloads.len() <= 1000,
            "Submitted artifact count exceeds profile"
        );
        std::fs::create_dir(output.join("artifacts"))?;
        for (name, bytes) in &report.payloads {
            ensure!(
                !bytes.is_empty()
                    && bytes.len() <= 128 * 1024 * 1024
                    && *name == format!("{}.bin", digest(bytes)),
                "Submitted artifact metadata/payload mismatch"
            );
            artifact_total = artifact_total
                .checked_add(bytes.len())
                .context("Artifact total overflow")?;
            ensure!(
                artifact_total <= 256 * 1024 * 1024,
                "Submitted artifact total exceeds profile"
            );
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(output.join("artifacts").join(name))?;
            for chunk in bytes.chunks(8 * 1024 * 1024) {
                file.write_all(chunk)?;
            }
            file.sync_all()?;
        }
        let guest_completion = execution_json["completion_reason"].clone();
        let guest_return = execution_json["guest_entry_return"].clone();
        let instruction_count = execution_json["instruction_count"].clone();
        let capture_omissions = execution_json["capture_summary"]["omitted_observations"].clone();
        save_new(&output.join("engine-report.json"), &report.engine)?;
        save_new(&output.join("network-broker.json"), &report.network)?;
        save_new(&output.join("artifacts/manifest.json"), &report.manifest)?;
        save_new(&output.join("worker-summary.json"), &report.summary)?;
        save_new(&output.join("artifact-checkpoint.json"), &report.checkpoint)?;
        emit(
            &output,
            &json!({
                "binding": binding,
                "status": "processed",
                "engine_report_sha256": digest(&report.engine),
                "driver_summary_sha256": digest(&report.summary),
                "driver_report_binding": report_binding,
                "guest_completion": guest_completion,
                "guest_entry_return": guest_return,
                "instruction_count": instruction_count,
                "artifacts": artifact_metadata,
                "artifact_total_bytes": artifact_total,
                "capture_omitted_observations": capture_omissions,
                "unpacking_confirmed": false,
                "scope": "Bounded guest execution evidence; payloads are captured bytes, not certified unpacked driver images"
            }),
        )?;
        Ok(())
    })();
    if let Err(error) = &result {
        let message = format!("{error:#}").chars().take(8192).collect::<String>();
        let _ = save_new(&output.join("worker-error.txt"), message.as_bytes());
    }
    result
}

#[cfg(test)]
mod broker_public_tests {
    use super::*;
    use emumee_core::{
        analysis_plan::{Arch, PreparedIntake},
        plan_runtime::Case,
    };

    #[test]
    fn generated_driver_public_bytes_and_private_claim_identity_must_match_submitted_request() {
        let mut kernel = Case::Kernel17.generated(Arch::X64).unwrap();
        let fixture = Case::NativeReplay.generated(Arch::X64).unwrap().fixtures;
        let target = kernel.inputs[0].clone();
        let mut plan: Value = serde_json::from_slice(&kernel.plan).unwrap();
        plan["target"]["service_name"] = json!("TestDrv");
        plan["persona"]["value"]["windows_build"] = json!(22631);
        plan["capture"]["profile"] = json!("large_driver128_v1");
        plan["capture"]["sources"] = json!(["memory_snapshots", "structural_pe"]);
        plan["capture"]["retained_bytes"] = json!(256u64 * 1024 * 1024);
        plan["capture"]["memory_scan_bytes"] = json!(128u64 * 1024 * 1024);
        plan["reports"]["profile"] = json!("large_driver_v1");
        plan["limits"]["worker_memory_mb"] = json!(2048);
        plan["inputs"].as_array_mut().unwrap().push(json!({
            "id":"offline","name":"offline.json","roles":["offline_fixtures"],
            "mount":{"kind":"not_mounted"},"size":fixture.len(),"sha256":digest(&fixture),
        }));
        plan["network"] = json!({"kind":"offline_exact_replay","input":"offline"});
        kernel.inputs.push(fixture);
        let plan_raw = serde_json::to_vec(&plan).unwrap();
        let intake = PreparedIntake::prepare_driver128(plan_raw.clone(), kernel.inputs).unwrap();
        let run_id = "20261019T120000Z-12345678".to_owned();
        let general = GeneralRequest::from_intake(&intake, run_id.clone()).unwrap();
        let general_raw = serde_json::to_vec(&general).unwrap();
        let claim = Claim::from_verified_request(&general_raw, &intake).unwrap();
        let claim_sha = digest(&serde_json::to_vec(&claim).unwrap());
        let submitted = Request::new(
            run_id,
            digest(&target),
            target.len() as u64,
            "TestDrv".into(),
            10_000,
            1_000_000,
        )
        .unwrap();
        let binding = broker_public_binding(
            &submitted,
            &target,
            &general_raw,
            &plan_raw,
            &target,
            &claim_sha,
        )
        .unwrap();
        assert_eq!(binding["claim_sha256"], claim_sha);
        assert_eq!(binding["public_target_sha256"], digest(&target));
        // The submitted request independently pins an optional NT reference;
        // it does not change the broker fixture's public/private partition.
        let with_reference = submitted.clone().with_reference("a".repeat(64)).unwrap();
        assert!(
            broker_public_binding(
                &with_reference,
                &target,
                &general_raw,
                &plan_raw,
                &target,
                &claim_sha,
            )
            .is_ok()
        );
        let mut changed = target.clone();
        changed[0] ^= 1;
        assert!(
            broker_public_binding(
                &submitted,
                &target,
                &general_raw,
                &plan_raw,
                &changed,
                &claim_sha
            )
            .is_err()
        );
        assert!(
            broker_public_binding(
                &submitted,
                &target,
                &general_raw,
                &plan_raw,
                &target,
                &"0".repeat(64)
            )
            .is_err()
        );
        let other = Request::new(
            "20261019T120000Z-87654321".into(),
            digest(&target),
            target.len() as u64,
            "TestDrv".into(),
            10_000,
            1_000_000,
        )
        .unwrap();
        assert!(
            broker_public_binding(
                &other,
                &target,
                &general_raw,
                &plan_raw,
                &target,
                &claim_sha
            )
            .is_err()
        );
    }
}

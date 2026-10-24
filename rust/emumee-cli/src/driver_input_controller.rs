//! Parent-side submitted-driver staging, offline launch and evidence binding.
use super::{
    broker::{pinned_new, wait_ready},
    driver_capture_reader,
    general_boundary_controller::verify_output_location,
    general_execution_stage::StagedGeneralExecution,
    worker::{VerifiedBundle, launch_driver_capture, save_new, verified_bundle},
};
use anyhow::{Context, Result, ensure};
use emumee_core::{
    analysis_fixture,
    analysis_plan::{Arch, PreparedIntake},
    broker_journal,
    driver_capture_reports::{self as reports, Binding, Mode, Stop},
    driver_input::{InstructionWindow, MAX_INPUT, MAX_PERSONA, MAX_REFERENCE, PROFILE, Request},
    general_broker_private_attestation::{Claim, MAX_CLAIM},
    general_worker_public_preflight::preflight_driver128_public_report,
    networkfixtures::{Fixtures, MAX_FILE},
    plan_runtime::Case,
    report_bundle::{bounded_json, digest},
};
use emumee_platform::windows::{
    AccessGrant, ContainedChild, OfflineProfile, OutputLimits, RecoverySession, WorkerExit,
    WorkerJob, WorkerStop, inspect_output, read_regular, with_driver_regular,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    path::Path,
    time::{Duration, Instant},
};

struct BrokerStage {
    stage: StagedGeneralExecution,
    request_sha256: String,
    claim_sha256: String,
    claim_raw: Vec<u8>,
    fixture_sha256: String,
}

pub struct OptionalPaths<'a> {
    pub kernel_code_reference: Option<&'a Path>,
    pub offline_fixtures: Option<&'a Path>,
    pub persona: Option<&'a Path>,
    pub instruction_window: Option<InstructionWindow>,
}

struct WorkerInputPresence {
    reference: bool,
    persona: bool,
}

fn stage_brokered_driver(
    root: &Path,
    run_id: &str,
    request: &Request,
    target: &[u8],
    fixture_path: &Path,
    guest_build: u32,
) -> Result<BrokerStage> {
    ensure!(
        request.timeout_us.div_ceil(1000) <= 3_600_000,
        "Brokered Driver128 plan limits wall time to 3600 seconds"
    );
    let fixture = read_regular(fixture_path, MAX_FILE, None)?;
    Fixtures::parse(&fixture).map_err(anyhow::Error::msg)?;
    let mut generated = Case::Kernel17
        .generated(Arch::X64)
        .map_err(anyhow::Error::msg)?;
    let mut plan: Value = serde_json::from_slice(&generated.plan)?;
    plan["target"]["service_name"] = json!(request.service_name);
    plan["persona"]["value"]["windows_build"] = json!(guest_build);
    plan["inputs"][0]["name"] = json!(format!("{}.sys", request.service_name));
    plan["inputs"][0]["size"] = json!(target.len());
    plan["inputs"][0]["sha256"] = json!(digest(target));
    plan["limits"]["max_instructions"] = json!(request.max_instructions);
    plan["limits"]["guest_timeout_ms"] = json!(request.timeout_us.div_ceil(1000));
    plan["limits"]["worker_memory_mb"] = json!(2048);
    plan["capture"]["profile"] = json!("large_driver128_v1");
    plan["capture"]["sources"] = json!(["memory_snapshots", "structural_pe"]);
    plan["capture"]["retained_bytes"] = json!(256u64 * 1024 * 1024);
    plan["capture"]["memory_scan_bytes"] = json!(128u64 * 1024 * 1024);
    plan["reports"]["profile"] = json!("large_driver_v1");
    plan["inputs"]
        .as_array_mut()
        .context("Driver128 inputs absent")?
        .push(json!({
            "id":"offline", "name":"offline.json", "roles":["offline_fixtures"],
            "mount":{"kind":"not_mounted"}, "size":fixture.len(), "sha256":digest(&fixture),
        }));
    plan["network"] = json!({"kind":"offline_exact_replay","input":"offline"});
    generated.inputs = vec![target.to_vec(), fixture.clone()];
    let intake = PreparedIntake::prepare_driver128(serde_json::to_vec(&plan)?, generated.inputs)
        .map_err(anyhow::Error::msg)?;
    let stage = StagedGeneralExecution::stage(intake, run_id.to_owned(), root)?;
    let request_sha256 = stage.request_sha256();
    let claim_raw = read_regular(
        &stage.root().join("private/claim.json"),
        MAX_CLAIM,
        Some(stage.root()),
    )?;
    let claim = Claim::parse(&claim_raw).map_err(anyhow::Error::msg)?;
    ensure!(
        claim.request_sha256 == request_sha256,
        "Driver128 claim/request binding differs"
    );
    let claim_sha256 = digest(&claim_raw);
    Ok(BrokerStage {
        stage,
        request_sha256,
        claim_sha256,
        claim_raw,
        fixture_sha256: digest(&fixture),
    })
}

fn launch_brokered(
    verified: &VerifiedBundle,
    root: &Path,
    stage: &BrokerStage,
    submitted_request_sha256: &str,
    inputs: WorkerInputPresence,
    limits: OutputLimits,
    timeout_ms: u32,
) -> Result<WorkerExit> {
    ensure!(stage.stage.root() == root, "Driver128 stage root changed");
    std::fs::create_dir(root.join("ipc"))?;
    std::fs::create_dir(root.join("broker"))?;
    std::fs::create_dir(root.join("worker"))?;
    let _requests = pinned_new(&root.join("ipc/requests.bin"), b"")?;
    let _responses = pinned_new(&root.join("ipc/responses.bin"), b"")?;
    stage.stage.verify_prelaunch()?;
    let mut recovery = RecoverySession::begin(&verified.path, root)?;
    let broker_job = WorkerJob::new_tracked(256, &mut recovery)?;
    let worker_job = WorkerJob::new_tracked(2048, &mut recovery)?;
    let mut broker_profile = OfflineProfile::new_tracked(&mut recovery)?;
    let mut worker_profile = OfflineProfile::new_tracked(&mut recovery)?;
    let executable = verified.path.join("emumee-worker.exe");
    let mut grants: Vec<AccessGrant> = Vec::new();
    let mut broker: Option<ContainedChild> = None;
    let mut worker: Option<ContainedChild> = None;
    let started = Instant::now();
    let run = (|| -> Result<(u32, u32, u64, Option<emumee_platform::windows::OutputUsage>)> {
        grants.push(broker_profile.grant_tracked(&verified.path, false, &mut recovery)?);
        grants.push(worker_profile.grant_tracked(&verified.path, false, &mut recovery)?);
        grants.push(broker_profile.grant_traverse_tracked(root, &mut recovery)?);
        grants.push(worker_profile.grant_traverse_tracked(root, &mut recovery)?);
        grants.push(broker_profile.grant_tracked(&root.join("private"), false, &mut recovery)?);
        grants.push(broker_profile.grant_tracked(
            &root.join("private/network-broker.journal"),
            true,
            &mut recovery,
        )?);
        grants.push(broker_profile.grant_tracked(&root.join("broker"), true, &mut recovery)?);
        grants.push(worker_profile.grant_tracked(&root.join("control"), false, &mut recovery)?);
        grants.push(worker_profile.grant_tracked(
            &root.join("request.json"),
            false,
            &mut recovery,
        )?);
        grants.push(worker_profile.grant_tracked(&root.join("input.sys"), false, &mut recovery)?);
        if inputs.reference {
            grants.push(worker_profile.grant_tracked(
                &root.join("kernel-code-reference.pe"),
                false,
                &mut recovery,
            )?);
        }
        if inputs.persona {
            grants.push(worker_profile.grant_tracked(
                &root.join("persona.json"),
                false,
                &mut recovery,
            )?);
        }
        grants.push(worker_profile.grant_tracked(&root.join("worker"), true, &mut recovery)?);
        grants.push(broker_profile.grant_tracked(&root.join("ipc"), false, &mut recovery)?);
        grants.push(worker_profile.grant_tracked(&root.join("ipc"), false, &mut recovery)?);
        grants.push(
            worker_profile.grant_append_tracked(&root.join("ipc/requests.bin"), &mut recovery)?,
        );
        grants.push(
            broker_profile.grant_append_tracked(&root.join("ipc/responses.bin"), &mut recovery)?,
        );
        broker = Some(broker_profile.spawn(
            &executable,
            &[
                OsString::from("--general-driver128-broker"),
                root.as_os_str().to_owned(),
                OsString::from(&stage.claim_sha256),
                recovery.path().as_os_str().to_owned(),
            ],
            &root.join("broker"),
            &broker_job,
        )?);
        let server = broker.as_ref().context("Driver128 broker absent")?;
        wait_ready(
            server,
            &root.join("broker/broker-ready.json"),
            &root.join("broker"),
        )?;
        worker = Some(worker_profile.spawn(
            &executable,
            &[
                OsString::from("--submitted-driver-broker"),
                root.as_os_str().to_owned(),
                OsString::from(submitted_request_sha256),
                OsString::from(&stage.claim_sha256),
            ],
            &root.join("worker"),
            &worker_job,
        )?);
        let client = worker.as_ref().context("Driver128 worker absent")?;
        let mut checks = 0u64;
        loop {
            checks += 1;
            let usage = inspect_output(root, &[], limits)?;
            let broker_exit = server.poll()?;
            let worker_exit = client.poll()?;
            if let Some(code) = broker_exit.filter(|code| *code != 0) {
                anyhow::bail!("Driver128 broker exited {code}");
            }
            if let Some(code) = worker_exit.filter(|code| *code != 0) {
                anyhow::bail!("Submitted brokered worker exited {code}");
            }
            if let (Some(b), Some(w)) = (broker_exit, worker_exit) {
                return Ok((b, w, checks, Some(usage)));
            }
            ensure!(
                started.elapsed() < Duration::from_millis(timeout_ms as u64),
                "Brokered submitted driver timed out"
            );
            std::thread::sleep(Duration::from_millis(250));
        }
    })();
    // Stop both roles before restoring any ACL or profile. Retain the durable
    // recovery record if termination cannot be proved.
    let worker_stop = worker.as_ref().map(ContainedChild::terminate).transpose();
    let broker_stop = broker.as_ref().map(ContainedChild::terminate).transpose();
    if worker_stop.is_err() || broker_stop.is_err() {
        let _ = worker_job.terminate();
        let _ = broker_job.terminate();
        let worker_confirmed = worker.as_ref().map(ContainedChild::terminate).transpose();
        let broker_confirmed = broker.as_ref().map(ContainedChild::terminate).transpose();
        if worker_confirmed.is_err() || broker_confirmed.is_err() {
            std::mem::forget(grants);
            std::mem::forget(worker_profile);
            std::mem::forget(broker_profile);
            anyhow::bail!("Brokered driver child termination unconfirmed; recovery plan retained");
        }
    }
    let worker_peak = worker_job.peak_process_memory_bytes();
    let broker_peak = broker_job.peak_process_memory_bytes();
    let mut cleanup_errors = Vec::new();
    for grant in grants.iter_mut().rev() {
        if let Err(error) = grant.restore() {
            cleanup_errors.push(format!("{error:#}"));
        }
    }
    if let Err(error) = worker_profile.close() {
        cleanup_errors.push(format!("{error:#}"));
    }
    if let Err(error) = broker_profile.close() {
        cleanup_errors.push(format!("{error:#}"));
    }
    ensure!(
        cleanup_errors.is_empty(),
        "Brokered driver cleanup failed: {cleanup_errors:?}"
    );
    recovery.finish()?;
    let worker_peak = worker_peak?;
    let broker_peak = broker_peak?;
    ensure!(
        worker_peak <= 2048u64 * 1024 * 1024 && broker_peak <= 256u64 * 1024 * 1024,
        "Brokered driver job peak exceeded limit"
    );
    save_new(
        &root.join("driver-job-profile.json"),
        &serde_json::to_vec_pretty(&json!({
            "schema":1,"profile":"driver_capture_2048_v1","process_memory_bytes":2048u64*1024*1024,
            "active_process_limit":1,"network_capabilities":0,"peak_process_memory_bytes":worker_peak,
            "output_limits":limits,"cleanup":"restored",
        }))?,
    )?;
    save_new(
        &root.join("broker-job-profile.json"),
        &serde_json::to_vec_pretty(&json!({
            "schema":1,"profile":"driver_broker_256_v1","process_memory_bytes":256u64*1024*1024,
            "active_process_limit":1,"network_capabilities":0,"peak_process_memory_bytes":broker_peak,
            "cleanup":"restored",
        }))?,
    )?;
    let (broker_exit, worker_exit, checks, usage) = match run {
        Ok(exits) => exits,
        Err(error) => {
            save_new(
                &root.join("worker-stop.json"),
                &serde_json::to_vec_pretty(&json!({
                    "schema":1,"reason":"two_role_failed","error":format!("{error:#}"),
                    "output_limits":limits,"cleanup":"restored",
                }))?,
            )?;
            return Err(error);
        }
    };
    ensure!(
        broker_exit == 0 && worker_exit == 0,
        "Brokered driver roles did not exit cleanly"
    );
    let stopped = WorkerExit {
        exit_code: worker_exit,
        reason: WorkerStop::Exited,
        detail: None,
        output_usage: usage,
        output_checks: checks,
        elapsed_ms: started.elapsed().as_millis(),
    };
    save_new(
        &root.join("worker-stop.json"),
        &serde_json::to_vec_pretty(&json!({
            "schema":1,"worker":&stopped,"broker_exit":broker_exit,"output_limits":limits,"cleanup":"restored"
        }))?,
    )?;
    save_new(
        &root.join("worker-exit.json"),
        &serde_json::to_vec_pretty(&json!({
            "exit_code":worker_exit,"exit_code_hex":format!("0x{worker_exit:08x}"),"cleanup":"restored"
        }))?,
    )?;
    Ok(stopped)
}

fn broker_public_binding(stage: &BrokerStage, submitted: &Request, root: &Path) -> Result<Value> {
    let general_raw = read_regular(
        &root.join("control/request.json"),
        emumee_core::general_execution_commitment::MAX_REQUEST,
        Some(root),
    )?;
    let plan_raw = read_regular(
        &root.join("control/plan.json"),
        emumee_core::analysis_plan::MAX_PLAN_BYTES,
        Some(root),
    )?;
    let target = read_regular(&root.join("control/inputs/0000.bin"), MAX_INPUT, Some(root))?;
    ensure!(
        digest(&general_raw) == stage.request_sha256
            && target.len() as u64 == submitted.input_size
            && digest(&target) == submitted.input_sha256
            && target == read_regular(&root.join("input.sys"), MAX_INPUT, Some(root))?,
        "Brokered submitted public input differs from submitted request"
    );
    let general = emumee_core::general_execution_commitment::Request::parse(&general_raw)
        .map_err(anyhow::Error::msg)?;
    ensure!(
        !general.execution_authorized
            && general.run_id == submitted.run_id
            && general.service_name == submitted.service_name
            && general.report_profile == "large_driver_v1"
            && general.public_inputs.len() == 1
            && general.public_inputs[0].size == submitted.input_size
            && general.public_inputs[0].sha256 == submitted.input_sha256
            && general
                .broker_private_fixture
                .as_ref()
                .is_some_and(|f| f.index == 1),
        "Brokered general request does not bind submitted driver"
    );
    let reconstructed_claim = Claim {
        schema: 1,
        profile: emumee_core::general_broker_private_attestation::PROFILE.into(),
        operation: emumee_core::general_broker_private_attestation::OPERATION.into(),
        execution_authorized: false,
        request_sha256: stage.request_sha256.clone(),
        resolved_plan_sha256: general.resolved_plan_sha256.clone(),
        fixture: general
            .broker_private_fixture
            .clone()
            .context("Brokered private fixture commitment absent")?,
    };
    reconstructed_claim.validate().map_err(anyhow::Error::msg)?;
    ensure!(
        serde_json::to_vec(&reconstructed_claim)? == stage.claim_raw,
        "Brokered private claim differs from worker-reconstructible public commitment"
    );
    let public = preflight_driver128_public_report(
        &general_raw,
        &stage.request_sha256,
        &plan_raw,
        &[Some(target.as_slice()), None],
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
        "Brokered public Driver128 preflight differs"
    );
    Ok(json!({
        "general_request_sha256":stage.request_sha256,
        "general_plan_sha256":digest(&plan_raw),
        "general_resolved_plan_sha256":general.resolved_plan_sha256,
        "claim_sha256":stage.claim_sha256,
        "public_target_sha256":submitted.input_sha256,
        "public_preflight":public,
        "private_read_denied":true,
        "ipc_write_separation_verified":true,
    }))
}

fn verify_broker_receipts(
    verified: &VerifiedBundle,
    root: &Path,
    stage: &BrokerStage,
    submitted: &Request,
    submitted_request_sha256: &str,
    worker_containment_sha256: &str,
    public_binding: &Value,
) -> Result<Value> {
    let worker_root = root.join("worker");
    let admission_raw = read_regular(
        &worker_root.join("broker-admission.json"),
        16 * 1024,
        Some(&worker_root),
    )?;
    let admission: Value = serde_json::from_slice(&admission_raw)?;
    ensure!(
        admission
            == json!({
                "schema":1,"role":"submitted_driver_broker_worker_v1",
                "submitted_request_sha256":submitted_request_sha256,
                "general_request_sha256":stage.request_sha256,
                "claim_sha256":stage.claim_sha256,
                "public_target_sha256":submitted.input_sha256,
                "worker_containment_sha256":worker_containment_sha256,
                "public_preflight":public_binding["public_preflight"],
                "private_read_denied":true,"ipc_write_separation_verified":true,"engine_started":false,
            }),
        "Brokered worker pre-engine admission differs"
    );
    let closed_raw = read_regular(
        &worker_root.join("broker-closed.json"),
        4096,
        Some(&worker_root),
    )?;
    let closed: Value = serde_json::from_slice(&closed_raw)?;
    ensure!(
        closed["schema"] == 1
            && closed["role"] == "submitted_driver_broker_worker_v1"
            && closed["submitted_request_sha256"] == submitted_request_sha256
            && closed["general_request_sha256"] == stage.request_sha256
            && closed["claim_sha256"] == stage.claim_sha256
            && closed["public_target_sha256"] == submitted.input_sha256
            && closed["worker_containment_sha256"] == worker_containment_sha256
            && closed["rpc_closed"] == true
            && closed["engine_result_available"].is_boolean(),
        "Brokered worker close receipt differs"
    );
    let ready_raw = read_regular(&root.join("broker/broker-ready.json"), 4096, Some(root))?;
    let ready: Value = serde_json::from_slice(&ready_raw)?;
    ensure!(
        super::general_boundary_controller::contained(&ready)
            && ready["cleanup_plan_read_denied"] == true
            && ready["target_read_denied"] == true,
        "Brokered private role readiness differs"
    );
    let private_raw = read_regular(
        &root.join("broker/general-private-inspection.json"),
        64 * 1024,
        Some(root),
    )?;
    let private: Value = serde_json::from_slice(&private_raw)?;
    ensure!(
        private["schema"] == 1
            && private["role"] == "general_rpc_broker_v1"
            && private["claim_sha256"] == stage.claim_sha256
            && super::general_boundary_controller::contained(&private["containment"])
            && private["public_read_denied"] == true
            && private["request_append_denied"] == true
            && private["response_overwrite_denied"] == true
            && private["ipc_creation_denied"] == true
            && private["inspection"]["private_bytes_inspected"] == true
            && private["guest_admission"] == false
            && private["engine_applied"] == false
            && private["guest_executed"] == false,
        "Brokered private inspection or IPC separation differs"
    );
    let journal = read_regular(
        &root.join("private/network-broker.journal"),
        broker_journal::MAX_JOURNAL_BYTES,
        Some(root),
    )?;
    ensure!(
        read_regular(&root.join("private/claim.json"), MAX_CLAIM, Some(root))? == stage.claim_raw,
        "Brokered claim changed during execution"
    );
    let claim = Claim::parse(&stage.claim_raw).map_err(anyhow::Error::msg)?;
    let expected_start = claim
        .expected_journal_start(&stage.claim_raw)
        .map_err(anyhow::Error::msg)?;
    ensure!(
        journal.starts_with(&expected_start),
        "Brokered journal lost claim-bound start"
    );
    let recovered = broker_journal::recover(&journal)?;
    ensure!(
        recovered.closed
            && recovered.stop_reason.is_none()
            && recovered
                .events
                .first()
                .is_some_and(|v| v["request_sha256"] == stage.request_sha256
                    && v["claim_sha256"] == stage.claim_sha256)
            && recovered.events.last() == Some(&json!({"event":"broker_closed"})),
        "Brokered journal did not close with matching claim"
    );
    let result_raw = read_regular(
        &root.join("broker/driver128-broker-result.json"),
        4096,
        Some(root),
    )?;
    let result: Value = serde_json::from_slice(&result_raw)?;
    ensure!(
        result
            == json!({
                "schema":1,"role":"general_driver128_offline_broker_v1",
                "source_tree_sha256":verified.receipt["source_tree_sha256"],
                "claim_sha256":stage.claim_sha256,
                "request_sha256":stage.request_sha256,
                "journal_sha256":digest(&journal),
                "journal_bytes":journal.len(),
                "journal_events":recovered.events.len(),
                "journal_start_sha256":digest(&expected_start),
                "rpc_closed":true,"containment":ready,
                "guest_admission":false,"engine_applied":false,"guest_executed":false,
            }),
        "Brokered private close receipt differs"
    );
    ensure!(
        digest(&read_regular(
            &root.join("private/http-fixtures.json"),
            MAX_FILE,
            Some(root)
        )?) == stage.fixture_sha256,
        "Brokered private fixture changed"
    );
    Ok(json!({
        "claim_sha256":stage.claim_sha256,
        "general_request_sha256":stage.request_sha256,
        "worker_admission_sha256":digest(&admission_raw),
        "worker_close_sha256":digest(&closed_raw),
        "broker_result_sha256":digest(&result_raw),
        "broker_ready_sha256":digest(&ready_raw),
        "broker_private_inspection_sha256":digest(&private_raw),
        "journal_sha256":digest(&journal),
        "journal_events":recovered.events.len(),
        "fixture_sha256":stage.fixture_sha256,
        "rpc_closed":true,
    }))
}

fn hash_staged(path: &Path, root: &Path, length: u64) -> Result<String> {
    with_driver_regular(path, length, root, |read| {
        let mut hash = Sha256::new();
        let mut offset = 0u64;
        while offset < length {
            let count = (length - offset).min(8 * 1024 * 1024) as usize;
            hash.update(read(offset, count)?);
            offset += count as u64;
        }
        Ok(format!("{:x}", hash.finalize()))
    })
}

fn resolve_submitted_persona(
    document: &[u8],
    run_id: &str,
    now: std::time::Duration,
) -> Result<(Vec<u8>, &'static str, String)> {
    let input: Value =
        serde_json::from_slice(document).context("Invalid submitted persona JSON")?;
    let unresolved = input.get("clock_utc").is_none_or(Value::is_null);
    let context = if unresolved {
        let filetime = now
            .as_secs()
            .checked_mul(10_000_000)
            .and_then(|ticks| ticks.checked_add(u64::from(now.subsec_nanos() / 100)))
            .and_then(|ticks| ticks.checked_add(116_444_736_000_000_000))
            .context("Submitted persona clock exceeds FILETIME range")?;
        emumee_core::fullpersona::ResolveContext {
            clock_seed: Some(emumee_core::fullpersona::ClockSeed {
                utc_filetime: filetime,
                source: emumee_core::fullpersona::ClockSource::ControllerResolved,
                source_id: run_id.to_owned(),
            }),
        }
    } else {
        emumee_core::fullpersona::ResolveContext::default()
    };
    let validated = emumee_core::fullpersona::decode(document, &context)
        .map_err(anyhow::Error::msg)
        .context("Submitted persona validation failed")?;
    let clock = validated.effective_json()["clock_utc"]
        .as_str()
        .context("Validated persona has no explicit UTC clock")?
        .to_owned();
    let staged = if unresolved {
        serde_json::to_vec(validated.effective_json())?
    } else {
        document.to_vec()
    };
    ensure!(
        staged.len() <= MAX_PERSONA,
        "Resolved submitted persona exceeds the staged byte limit"
    );
    emumee_core::fullpersona::decode(
        &staged,
        &emumee_core::fullpersona::ResolveContext::default(),
    )
    .map_err(anyhow::Error::msg)
    .context("Resolved submitted persona does not validate independently")?;
    Ok((
        staged,
        if unresolved {
            "controller_resolved_utc"
        } else {
            "persona_literal"
        },
        clock,
    ))
}

#[cfg(test)]
mod submitted_persona_tests {
    use super::*;

    #[test]
    fn null_clock_is_resolved_once_and_literal_clock_is_preserved() {
        let source = emumee_core::fullpersona::default_document().as_bytes();
        let now = Duration::new(1_700_000_000, 123_456_700);
        let (staged, provenance, clock) =
            resolve_submitted_persona(source, "20261019T120000Z-12345678", now).unwrap();
        assert_eq!(provenance, "controller_resolved_utc");
        assert_ne!(digest(source), digest(&staged));
        assert_eq!(
            serde_json::from_slice::<Value>(&staged).unwrap()["clock_utc"],
            clock
        );
        emumee_core::fullpersona::decode(
            &staged,
            &emumee_core::fullpersona::ResolveContext::default(),
        )
        .unwrap();
        let (literal, provenance, literal_clock) =
            resolve_submitted_persona(&staged, "another-run", Duration::ZERO).unwrap();
        assert_eq!(provenance, "persona_literal");
        assert_eq!(literal_clock, clock);
        assert_eq!(literal, staged);
    }
}

pub fn run(
    source: &Path,
    root: &Path,
    service: &str,
    max_instructions: u64,
    timeout_us: u64,
    optional: OptionalPaths<'_>,
) -> Result<Value> {
    let OptionalPaths {
        kernel_code_reference,
        offline_fixtures,
        persona: persona_path,
        instruction_window,
    } = optional;
    ensure!(
        source
            .extension()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.eq_ignore_ascii_case("sys")),
        "Submitted native driver requires a .sys input path"
    );
    let verified = verified_bundle()?;
    // The parent reads a single safe regular source identity; only these bytes
    // cross into the fresh worker root. The source path is never guest input.
    let bytes = read_regular(source, MAX_INPUT, None)?;
    ensure!(!bytes.is_empty(), "Submitted driver input is empty");
    let source_hash = digest(&bytes);
    let reference = kernel_code_reference
        .map(|path| read_regular(path, MAX_REFERENCE, None))
        .transpose()?;
    let reference_hash = reference.as_deref().map(digest);
    let source_persona = persona_path
        .map(|path| read_regular(path, MAX_PERSONA, None))
        .transpose()?;
    let source_persona_hash = source_persona.as_deref().map(digest);
    let source_path = std::path::absolute(source)?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let (run_id, _) =
        analysis_fixture::identity(now.as_secs(), now.subsec_nanos() ^ std::process::id())
            .map_err(anyhow::Error::msg)?;
    let resolved_persona = source_persona
        .as_deref()
        .map(|document| resolve_submitted_persona(document, &run_id, now))
        .transpose()?;
    let persona = resolved_persona.as_ref().map(|(bytes, _, _)| bytes);
    let persona_clock_provenance = resolved_persona
        .as_ref()
        .map(|(_, provenance, _)| provenance);
    let persona_clock_utc = resolved_persona.as_ref().map(|(_, _, clock)| clock);
    let persona_hash = persona.map(|bytes| digest(bytes));
    let guest_build = if let Some(bytes) = persona {
        serde_json::from_slice::<Value>(bytes)?["windows_build"]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .context("Validated submitted persona has no Windows build")?
    } else {
        22631
    };
    let mut request = Request::new(
        run_id,
        source_hash.clone(),
        bytes.len() as u64,
        service.into(),
        max_instructions,
        timeout_us,
    )
    .map_err(anyhow::Error::msg)?;
    if let Some(hash) = &reference_hash {
        request = request
            .with_reference(hash.clone())
            .map_err(anyhow::Error::msg)?;
    }
    if let Some(hash) = &persona_hash {
        request = request
            .with_persona(hash.clone())
            .map_err(anyhow::Error::msg)?;
    }
    if let Some(window) = instruction_window {
        request = request
            .with_instruction_window(window)
            .map_err(anyhow::Error::msg)?;
    }
    let request_raw = bounded_json(&request, 4096)?;
    Request::parse(&request_raw).map_err(anyhow::Error::msg)?;
    let request_hash = digest(&request_raw);
    let root = std::path::absolute(root)?;
    let broker_stage = if let Some(fixture) = offline_fixtures {
        verify_output_location(&verified.path, &root)?;
        Some(stage_brokered_driver(
            &root,
            &request.run_id,
            &request,
            &bytes,
            fixture,
            guest_build,
        )?)
    } else {
        std::fs::create_dir(&root).context("Submitted driver output root must be fresh")?;
        None
    };
    let root = broker_stage
        .as_ref()
        .map(|s| s.stage.root().to_path_buf())
        .unwrap_or(root);
    save_new(&root.join("input.sys"), &bytes)?;
    if let Some(reference) = &reference {
        save_new(&root.join("kernel-code-reference.pe"), reference)?;
    }
    if let Some(persona) = &persona {
        save_new(&root.join("persona.json"), persona)?;
    }
    save_new(&root.join("request.json"), &request_raw)?;
    drop(bytes);
    ensure!(
        hash_staged(&root.join("input.sys"), &root, request.input_size)? == source_hash,
        "Staged submitted driver bytes differ from the locked source read"
    );
    if let Some(hash) = &reference_hash {
        ensure!(
            digest(&read_regular(
                &root.join("kernel-code-reference.pe"),
                MAX_REFERENCE,
                Some(&root)
            )?) == *hash,
            "Staged kernel reference changed"
        );
    }
    if let Some(hash) = &persona_hash {
        ensure!(
            digest(&read_regular(
                &root.join("persona.json"),
                MAX_PERSONA,
                Some(&root)
            )?) == *hash,
            "Staged submitted persona changed"
        );
    }
    let limits = OutputLimits {
        max_bytes: 1024 * 1024 * 1024,
        max_entries: 10064,
        max_directories: 8,
        max_depth: 4,
    };
    limits.validate()?;
    let timeout_ms = u32::try_from(
        timeout_us.div_ceil(1000)
            + if broker_stage.is_some() {
                30_000
            } else {
                10_000
            },
    )?;
    let stopped = if let Some(broker_stage) = &broker_stage {
        launch_brokered(
            &verified,
            &root,
            broker_stage,
            &request_hash,
            WorkerInputPresence {
                reference: reference_hash.is_some(),
                persona: persona_hash.is_some(),
            },
            limits,
            timeout_ms,
        )?
    } else {
        launch_driver_capture(
            &verified,
            &root,
            &[
                OsString::from("--submitted-driver"),
                root.as_os_str().to_owned(),
                OsString::from(&request_hash),
            ],
            limits,
            timeout_ms,
        )?
    };
    let ordinary = stopped.reason == WorkerStop::Exited && stopped.exit_code == 0;
    let worker_root = if broker_stage.is_some() {
        root.join("worker")
    } else {
        root.clone()
    };
    let checked = (|| -> Result<Value> {
        ensure!(ordinary, "Submitted driver worker did not exit normally");
        ensure!(
            read_regular(&root.join("request.json"), 4096, Some(&root))? == request_raw,
            "Submitted driver request changed after worker"
        );
        ensure!(
            hash_staged(&root.join("input.sys"), &root, request.input_size)? == source_hash,
            "Submitted driver input changed after worker"
        );
        if let Some(hash) = &reference_hash {
            ensure!(
                digest(&read_regular(
                    &root.join("kernel-code-reference.pe"),
                    MAX_REFERENCE,
                    Some(&root)
                )?) == *hash,
                "Submitted kernel reference changed after worker"
            );
        } else {
            ensure!(
                !root.join("kernel-code-reference.pe").exists(),
                "Unexpected kernel reference input"
            );
        }
        if let Some(hash) = &persona_hash {
            ensure!(
                digest(&read_regular(
                    &root.join("persona.json"),
                    MAX_PERSONA,
                    Some(&root)
                )?) == *hash,
                "Submitted persona changed after worker"
            );
        } else {
            ensure!(
                !root.join("persona.json").exists(),
                "Unexpected submitted persona input"
            );
        }
        let witness = read_regular(
            &worker_root.join("worker-containment.json"),
            4096,
            Some(&worker_root),
        )?;
        let containment: Value = serde_json::from_slice(&witness)?;
        ensure!(
            containment["app_container"] == true
                && containment["job_object"] == true
                && containment["child_process_blocked"] == true
                && containment["network_capabilities"] == 0,
            "Submitted driver containment witness invalid"
        );
        let job: Value = serde_json::from_slice(&read_regular(
            &root.join("driver-job-profile.json"),
            8192,
            Some(&root),
        )?)?;
        ensure!(
            job["profile"] == "driver_capture_2048_v1"
                && job["process_memory_bytes"] == 2048u64 * 1024 * 1024
                && job["active_process_limit"] == 1
                && job["network_capabilities"] == 0
                && job["peak_process_memory_bytes"]
                    .as_u64()
                    .is_some_and(|peak| peak > 0 && peak <= 2048u64 * 1024 * 1024)
                && job["cleanup"] == "restored",
            "Submitted driver job/cleanup profile differs"
        );
        let ready: Value = serde_json::from_slice(&read_regular(
            &worker_root.join("worker-ready.json"),
            4096,
            Some(&worker_root),
        )?)?;
        let mut expected = json!({
            "schema": 1,
            "profile": PROFILE,
            "run_id": request.run_id,
            "request_sha256": request_hash,
            "input_sha256": source_hash,
            "input_size": request.input_size,
            "kernel_code_reference_sha256": reference_hash,
            "service_name": request.service_name,
            "driver_name": request.driver_name(),
            "registry_path": request.registry_path(),
            "source_tree_sha256": verified.receipt["source_tree_sha256"],
            "containment_sha256": digest(&witness),
            "job_memory_mib_required": 2048,
        });
        if let Some(hash) = &persona_hash {
            expected["persona_sha256"] = json!(hash);
        }
        let public_binding = broker_stage
            .as_ref()
            .map(|stage| broker_public_binding(stage, &request, &root))
            .transpose()?;
        if let Some(binding) = &public_binding {
            expected["offline_broker"] = binding.clone();
        }
        ensure!(
            ready == expected,
            "Submitted driver worker-ready binding differs"
        );
        let broker_receipt = broker_stage
            .as_ref()
            .map(|stage| {
                verify_broker_receipts(
                    &verified,
                    &root,
                    stage,
                    &request,
                    &request_hash,
                    &digest(&witness),
                    public_binding
                        .as_ref()
                        .context("Brokered public binding absent")?,
                )
            })
            .transpose()?;
        let result_raw = read_regular(
            &worker_root.join("worker-result.json"),
            256 * 1024,
            Some(&worker_root),
        )?;
        let result: Value = serde_json::from_slice(&result_raw)?;
        ensure!(
            result["binding"] == expected,
            "Submitted driver result binding differs"
        );
        let status = result["status"].as_str().context("Missing worker status")?;
        if broker_stage.is_some() {
            let closed: Value = serde_json::from_slice(&read_regular(
                &worker_root.join("broker-closed.json"),
                4096,
                Some(&worker_root),
            )?)?;
            ensure!(
                status != "processed" || closed["engine_result_available"] == true,
                "Brokered processed report lacks an engine result"
            );
        }
        let mut verified_artifacts = 0usize;
        let mut verified_bytes = 0u64;
        let mut summary_sha256 = None;
        let mut capture_status = None;
        if status == "processed" {
            ensure!(
                result["unpacking_confirmed"] == false,
                "Processed submitted report must explicitly deny unpacking"
            );
            let report_binding = Binding {
                request_sha256: request_hash.clone(),
                input_sha256: source_hash.clone(),
                input_bytes: request.input_size,
                recipe: request.service_name.clone(),
                source_tree_sha256: verified.receipt["source_tree_sha256"]
                    .as_str()
                    .context("Missing source-tree digest")?
                    .into(),
                containment_sha256: digest(&witness),
            };
            ensure!(
                result["driver_report_binding"] == serde_json::to_value(&report_binding)?,
                "Submitted Driver128 binding differs"
            );
            let (typed, engine_raw) = driver_capture_reader::verify(
                &worker_root,
                "worker-summary.json",
                Some(&report_binding),
            )?;
            ensure!(
                typed.summary.id == request.run_id,
                "Submitted Driver128 run identity differs"
            );
            ensure!(
                result["driver_summary_sha256"]
                    == digest(&read_regular(
                        &worker_root.join("worker-summary.json"),
                        8 * 1024 * 1024,
                        Some(&worker_root)
                    )?),
                "Submitted Driver128 summary hash differs"
            );
            ensure!(
                result["engine_report_sha256"] == digest(&engine_raw),
                "Submitted driver engine report hash changed"
            );
            let engine: Value = serde_json::from_slice(&engine_raw)?;
            ensure!(
                engine["mode"] == serde_json::to_value(Mode::SubmittedDriverCapture)?,
                "Submitted Driver128 mode differs"
            );
            let execution = &engine["execution"];
            ensure!(
                execution["kernel_reference"]["source_sha256"].as_str()
                    == reference_hash.as_deref(),
                "Submitted kernel reference execution binding differs"
            );
            ensure!(
                execution["configuration"]["input_json_sha256"].as_str() == persona_hash.as_deref()
                    && (persona_hash.is_none()
                        || execution["configuration"]["initialized"] == true),
                "Submitted persona execution configuration binding differs"
            );
            ensure!(
                execution["kernel_entry"]["registry_name"] == request.registry_path()
                    && execution["architecture"] == "x64"
                    && execution["completion_reason"] == result["guest_completion"]
                    && execution["instruction_count"] == result["instruction_count"]
                    && execution["guest_entry_return"] == result["guest_entry_return"]
                    && execution["image_load"]["size"]
                        .as_u64()
                        .is_some_and(|n| n <= 128 * 1024 * 1024),
                "Submitted driver engine identity/execution binding differs"
            );
            let module_name = request.module_name().to_ascii_lowercase();
            ensure!(
                execution["loaded_modules"]
                    .as_array()
                    .is_some_and(|modules| modules
                        .iter()
                        .any(|module| module["name"].as_str() == Some(module_name.as_str()))),
                "Submitted driver module identity missing from execution"
            );
            ensure!(
                execution["artifacts"] == result["artifacts"]
                    && execution["capture_summary"]["omitted_observations"]
                        == result["capture_omitted_observations"],
                "Submitted driver report/artifact metadata binding differs"
            );
            verified_artifacts = typed.artifacts.len();
            verified_bytes = typed.artifacts.iter().try_fold(0u64, |total, record| {
                total
                    .checked_add(record.size)
                    .context("Verified artifact total overflow")
            })?;
            ensure!(
                result["artifact_total_bytes"] == verified_bytes,
                "Submitted driver artifact total differs"
            );
            capture_status = Some(typed.summary.status.clone());
            let final_raw = reports::restamp(typed, &engine_raw, Stop::Normal, false)?;
            summary_sha256 = Some(digest(&final_raw));
            save_new(&root.join("summary.json"), &final_raw)?;
        } else {
            ensure!(
                status == "unreported_failure"
                    && result["artifacts"].as_array().is_some_and(Vec::is_empty)
                    && result["error"].as_str().is_some_and(|s| !s.is_empty())
                    && result.get("unpacking_confirmed").is_none()
                    && [
                        "guest_completion",
                        "guest_entry_return",
                        "instruction_count",
                        "engine_report_sha256",
                        "driver_summary_sha256",
                        "driver_report_binding",
                        "artifact_total_bytes",
                        "capture_omitted_observations",
                    ]
                    .iter()
                    .all(|key| result.get(*key).is_none())
                    && !worker_root.join("engine-report.json").exists()
                    && !worker_root.join("network-broker.json").exists()
                    && !worker_root.join("worker-summary.json").exists()
                    && !worker_root.join("artifact-checkpoint.json").exists()
                    && !root.join("summary.json").exists()
                    && !worker_root.join("artifacts").exists(),
                "Submitted driver refusal report is inconsistent"
            );
        }
        Ok(json!({
            "schema": 1,
            "profile": PROFILE,
            "status": if status == "processed" { "verified" } else { "verified_refusal" },
            "guest_status": status,
            "run_id": request.run_id,
            "request_sha256": request_hash,
            "input_sha256": source_hash,
            "kernel_code_reference_sha256": reference_hash,
            "persona_sha256": persona_hash,
            "persona_source_sha256": source_persona_hash,
            "persona_clock_provenance": persona_clock_provenance,
            "persona_clock_utc": persona_clock_utc,
            "source_path": source_path,
            "input_size": request.input_size,
            "service_name": request.service_name,
            "source_tree_sha256": verified.receipt["source_tree_sha256"],
            "controller_sha256": verified.receipt["controller_sha256"],
            "worker_sha256": verified.receipt["worker_sha256"],
            "unicorn_sha256": verified.receipt["unicorn_sha256"],
            "containment_sha256": digest(&witness),
            "worker_result_sha256": digest(&result_raw),
            "guest_completion": result["guest_completion"],
            "guest_entry_return": result["guest_entry_return"],
            "artifacts_verified": verified_artifacts,
            "artifact_bytes_verified": verified_bytes,
            "driver_summary_sha256": summary_sha256,
            "capture_status": capture_status,
            "offline_broker": broker_receipt,
            "cleanup": "restored",
            "unpacking_confirmed": false,
            "scope": if status == "processed" {
                "Typed Driver128 documents, payload chunks, structural metadata and settled boundary verified; captured bytes are not a certified unpacked driver"
            } else {
                "Contained worker returned no complete engine report; guest state unknown, and no capture or unpacking was verified"
            }
        }))
    })();
    let manifest = match checked {
        Ok(value) => value,
        Err(error) => json!({
            "schema": 1,
            "profile": PROFILE,
            "status": "failed",
            "run_id": request.run_id,
            "request_sha256": request_hash,
            "input_sha256": source_hash,
            "persona_sha256": persona_hash,
            "persona_source_sha256": source_persona_hash,
            "persona_clock_provenance": persona_clock_provenance,
            "persona_clock_utc": persona_clock_utc,
            "source_path": source_path,
            "source_tree_sha256": verified.receipt["source_tree_sha256"],
            "worker_stop": stopped,
            "error": format!("{error:#}"),
            "unpacking_confirmed": false
        }),
    };
    save_new(
        &root.join("controller-manifest.json"),
        &bounded_json(&manifest, 256 * 1024)?,
    )?;
    Ok(manifest)
}

#[cfg(test)]
mod broker_stage_tests {
    use super::*;

    #[test]
    fn generated_driver_broker_stage_binds_exact_target_and_private_fixture() {
        let target = Case::Kernel17
            .generated(Arch::X64)
            .unwrap()
            .inputs
            .remove(0);
        let fixture = Case::NativeReplay.generated(Arch::X64).unwrap().fixtures;
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let home = std::env::temp_dir().join(format!(
            "emumee-submitted-broker-stage-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&home).unwrap();
        let fixture_path = home.join("fixture.json");
        std::fs::write(&fixture_path, &fixture).unwrap();
        let run_id = "20261019T120000Z-12345678";
        let request = Request::new(
            run_id.into(),
            digest(&target),
            target.len() as u64,
            "TestDrv".into(),
            100_000_000,
            120_000_000,
        )
        .unwrap();
        let root = home.join("stage");
        let stage = stage_brokered_driver(&root, run_id, &request, &target, &fixture_path, 22631).unwrap();
        save_new(&root.join("input.sys"), &target).unwrap();
        assert_eq!(stage.request_sha256.len(), 64);
        assert_eq!(stage.claim_sha256, digest(&stage.claim_raw));
        let binding = broker_public_binding(&stage, &request, &root).unwrap();
        assert_eq!(binding["public_target_sha256"], digest(&target));
        assert_eq!(binding["claim_sha256"], stage.claim_sha256);
        assert_eq!(binding["private_read_denied"], true);
        let other = Request::new(
            run_id.into(),
            "0".repeat(64),
            target.len() as u64,
            "TestDrv".into(),
            100_000_000,
            120_000_000,
        )
        .unwrap();
        assert!(broker_public_binding(&stage, &other, &root).is_err());
        drop(stage);
        let too_long = Request::new(
            run_id.into(),
            digest(&target),
            target.len() as u64,
            "TestDrv".into(),
            100_000_000,
            3_600_000_001,
        )
        .unwrap();
        assert!(
            stage_brokered_driver(
                &home.join("too-long"),
                run_id,
                &too_long,
                &target,
                &fixture_path,
                22631
            )
            .err()
            .unwrap()
            .to_string()
            .contains("3600 seconds")
        );
        std::fs::remove_dir_all(home).unwrap();
    }
}

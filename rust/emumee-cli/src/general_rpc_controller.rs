//! Generated general-layout broker RPC qualification. No guest is admitted.
use super::{
    broker::{pinned_new, wait_ready},
    general_boundary_controller::{contained, generated, run_id, verify_output_location},
    general_execution_stage::StagedGeneralExecution,
    worker::{save_new, verified_bundle},
};
use anyhow::{Context, Result, ensure};
use emumee_core::{
    broker_journal,
    general_broker_private_attestation::{Claim, MAX_CLAIM},
    general_driver_private_preflight::{StagedBytes, inspect as inspect_private_preflight},
    general_rpc_probe::Probe,
    networkfixtures::{Fixtures, MAX_FILE},
    report_bundle::digest,
};
use emumee_platform::windows::{
    AccessGrant, ContainedChild, OfflineProfile, RecoverySession, WorkerJob, read_regular,
};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    path::Path,
    time::{Duration, Instant},
};

fn verify_journal(bytes: &[u8], claim_start: &[u8], probe: &Probe, body_sha: &str) -> Result<()> {
    ensure!(
        bytes.starts_with(claim_start),
        "General private journal claim start differs"
    );
    let recovery = broker_journal::recover(bytes)?;
    ensure!(
        recovery.closed && recovery.stop_reason.is_none() && recovery.events.len() == 7,
        "General RPC journal did not close exactly"
    );
    let events = &recovery.events;
    ensure!(
        events[0]["event"] == "general_broker_fixture_verified"
            && events[0]["request_sha256"] == probe.request_sha256
            && events[0]["claim_sha256"] == probe.claim_sha256
            && events[1]["event"] == "request"
            && events[1]["id"] == 1
            && events[1]["op"] == "http"
            && events[2]["event"] == "http_request_attempt"
            && events[2]["id"] == 1
            && events[2]["url"] == probe.http_request.url
            && events[2]["method"] == probe.http_request.method
            && events[2]["body_sha256"] == digest(&probe.http_request.body)
            && events[3]["event"] == "network_fixture_match"
            && events[3]["id"] == probe.rule_id
            && events[4]["event"] == "http_request"
            && events[4]["source"] == "fixture"
            && events[4]["status"] == probe.expected_status
            && events[4]["sha256"] == body_sha
            && events[5]["event"] == "request"
            && events[5]["id"] == 2
            && events[5]["op"] == "close"
            && events[6] == json!({"event":"broker_closed"}),
        "General RPC durable event sequence differs"
    );
    Ok(())
}

pub(crate) fn verify_fixture(output: &Path) -> Result<Value> {
    verify_fixture_inner(output, false)
}

/// Generated control for the exceptional recovery branch. It confirms both
/// child exits, then deliberately treats confirmation as failed before DACL
/// restoration so the next bundle entry must recover retained grants/profiles.
pub(crate) fn verify_cleanup_fault(output: &Path) -> Result<Value> {
    verify_fixture_inner(output, true)
}

fn verify_fixture_inner(output: &Path, simulate_unconfirmed: bool) -> Result<Value> {
    let bundle = verified_bundle()?;
    verify_output_location(&bundle.path, output)?;
    let stage = StagedGeneralExecution::stage(generated(true)?, run_id()?, output)?;
    ensure!(
        !stage.request().execution_authorized && stage.request().operation == "commit_only",
        "General RPC stage became executable"
    );
    let root = stage.root();
    let request_sha = stage.request_sha256();
    let claim_raw = read_regular(&root.join("private/claim.json"), MAX_CLAIM, Some(root))?;
    let claim = Claim::parse(&claim_raw).map_err(anyhow::Error::msg)?;
    ensure!(
        claim.request_sha256 == request_sha,
        "General RPC claim request differs"
    );
    let claim_sha = digest(&claim_raw);
    let fixture_raw = read_regular(
        &root.join("private/http-fixtures.json"),
        MAX_FILE,
        Some(root),
    )?;
    let inspection = claim
        .inspect(&claim_raw, &fixture_raw)
        .map_err(anyhow::Error::msg)?;
    ensure!(
        !inspection.guest_admission && !inspection.guest_executed,
        "General RPC parent inspection admitted guest"
    );
    let fixtures = Fixtures::parse(&fixture_raw).map_err(anyhow::Error::msg)?;
    let rule = fixtures
        .rules()
        .first()
        .context("Generated offline rule absent")?;
    let probe = Probe::from_rule(request_sha.clone(), claim_sha.clone(), rule)
        .map_err(anyhow::Error::msg)?;
    let response_body_sha = digest(&rule.response.body);
    let probe_raw = serde_json::to_vec(&probe)?;
    let probe_sha = digest(&probe_raw);
    std::fs::create_dir(root.join("ipc"))?;
    std::fs::create_dir(root.join("broker"))?;
    std::fs::create_dir(root.join("worker"))?;
    let _probe_pin = pinned_new(&root.join("control/rpc-probe.json"), &probe_raw)?;
    let _request_pin = pinned_new(&root.join("ipc/requests.bin"), b"")?;
    let _response_pin = pinned_new(&root.join("ipc/responses.bin"), b"")?;
    stage.verify_prelaunch()?;

    let mut recovery = RecoverySession::begin(&bundle.path, root)?;
    let broker_job = WorkerJob::new_tracked(256, &mut recovery)?;
    let worker_job = WorkerJob::new_tracked(1024, &mut recovery)?;
    let mut broker_profile = OfflineProfile::new_tracked(&mut recovery)?;
    let mut worker_profile = OfflineProfile::new_tracked(&mut recovery)?;
    let executable = bundle.path.join("emumee-worker.exe");
    let mut grants: Vec<AccessGrant> = Vec::new();
    let mut broker: Option<ContainedChild> = None;
    let mut worker: Option<ContainedChild> = None;
    let run = (|| -> Result<(u32, u32)> {
        grants.push(broker_profile.grant_tracked(&bundle.path, false, &mut recovery)?);
        grants.push(worker_profile.grant_tracked(&bundle.path, false, &mut recovery)?);
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
                OsString::from("--general-rpc-server"),
                root.as_os_str().to_owned(),
                OsString::from(&claim_sha),
                recovery.path().as_os_str().to_owned(),
            ],
            &root.join("broker"),
            &broker_job,
        )?);
        let server = broker.as_ref().context("General broker absent")?;
        wait_ready(
            server,
            &root.join("broker/broker-ready.json"),
            &root.join("broker"),
        )?;
        let ready_raw = read_regular(&root.join("broker/broker-ready.json"), 4096, Some(root))?;
        let ready: Value = serde_json::from_slice(&ready_raw)?;
        ensure!(
            contained(&ready)
                && ready["cleanup_plan_read_denied"] == true
                && ready["target_read_denied"] == true,
            "General RPC broker readiness differs"
        );
        worker = Some(worker_profile.spawn(
            &executable,
            &[
                OsString::from("--general-rpc-client"),
                root.as_os_str().to_owned(),
                OsString::from(&request_sha),
                OsString::from(&probe_sha),
            ],
            &root.join("worker"),
            &worker_job,
        )?);
        let client = worker.as_ref().context("General RPC client absent")?;
        let started = Instant::now();
        loop {
            let broker_exit = server.poll()?;
            let worker_exit = client.poll()?;
            if let Some(code) = broker_exit.filter(|code| *code != 0) {
                anyhow::bail!("General broker exited {code}");
            }
            if let Some(code) = worker_exit.filter(|code| *code != 0) {
                anyhow::bail!("General RPC client exited {code}");
            }
            if let (Some(b), Some(w)) = (broker_exit, worker_exit) {
                return Ok((b, w));
            }
            ensure!(
                started.elapsed() < Duration::from_secs(15),
                "General RPC timed out"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    })();
    // Every child is stopped before an ACL or profile is restored, including failures.
    let worker_stop = worker.as_ref().map(ContainedChild::terminate).transpose();
    let broker_stop = broker.as_ref().map(ContainedChild::terminate).transpose();
    let fault_ready = simulate_unconfirmed
        && run
            .as_ref()
            .is_ok_and(|(broker, worker)| *broker == 0 && *worker == 0)
        && worker_stop.is_ok()
        && broker_stop.is_ok();
    if worker_stop.is_err() || broker_stop.is_err() || fault_ready {
        // A failed process wait cannot authorize grant restoration. Kill both
        // jobs and confirm each process has exited before touching a DACL.
        let _ = worker_job.terminate();
        let _ = broker_job.terminate();
        let worker_confirmed = worker.as_ref().map(ContainedChild::terminate).transpose();
        let broker_confirmed = broker.as_ref().map(ContainedChild::terminate).transpose();
        if worker_confirmed.is_err() || broker_confirmed.is_err() || fault_ready {
            let marker_write = serde_json::to_vec_pretty(&json!({
                "schema":1,"profile":"general_rpc_cleanup_fault_v1",
                "simulated_unconfirmed":fault_ready,
                "actual_children_exited":run.as_ref().is_ok_and(|(broker, worker)| *broker == 0 && *worker == 0),
                "actual_termination_confirmed":worker_confirmed.is_ok() && broker_confirmed.is_ok(),
                "tracked_grants":grants.len(),"private_recovery_plan_retained":true,
                "engine_applied":false,"guest_executed":false,
            })).map_err(anyhow::Error::from).and_then(|marker|
                save_new(&root.join("general-rpc-cleanup-fault.json"), &marker));
            // Neither AccessGrant::drop nor OfflineProfile::drop may run while
            // a child might still live. The durable plan retains both records
            // for the next bundle entry after the job handles close.
            std::mem::forget(grants);
            std::mem::forget(worker_profile);
            std::mem::forget(broker_profile);
            marker_write?;
            anyhow::bail!(
                "General RPC child termination unconfirmed; private recovery plan retained"
            );
        }
    }
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
        "General RPC cleanup failed: {cleanup_errors:?}"
    );
    recovery.finish()?;
    let (broker_exit, worker_exit) = run?;
    ensure!(
        broker_exit == 0 && worker_exit == 0,
        "General RPC roles did not exit cleanly"
    );

    let public_raw = read_regular(
        &root.join("worker/public-boundary.json"),
        64 * 1024,
        Some(root),
    )?;
    let public: Value = serde_json::from_slice(&public_raw)?;
    ensure!(
        public["request_sha256"] == request_sha
            && contained(&public["containment"])
            && public["broker_private_read_denied"] == true
            && public["preflight"]["guest_admission"] == false
            && public["engine_applied"] == false
            && public["guest_executed"] == false,
        "General RPC public preflight witness differs"
    );
    let private_raw = read_regular(
        &root.join("broker/general-private-inspection.json"),
        64 * 1024,
        Some(root),
    )?;
    let private: Value = serde_json::from_slice(&private_raw)?;
    ensure!(
        private["claim_sha256"] == claim_sha
            && contained(&private["containment"])
            && private["public_read_denied"] == true
            && private["request_append_denied"] == true
            && private["response_overwrite_denied"] == true
            && private["ipc_creation_denied"] == true
            && private["inspection"]["private_bytes_inspected"] == true
            && private["guest_admission"] == false
            && private["guest_executed"] == false,
        "General RPC private broker witness differs"
    );
    let result_raw = read_regular(
        &root.join("worker/general-rpc-result.json"),
        64 * 1024,
        Some(root),
    )?;
    let result: Value = serde_json::from_slice(&result_raw)?;
    ensure!(
        result["request_sha256"] == request_sha
            && result["probe_sha256"] == probe_sha
            && result["claim_sha256"] == claim_sha
            && contained(&result["containment"])
            && result["response_sha256"] == probe.expected_response_sha256
            && result["rpc_closed"] == true
            && result["request_overwrite_denied"] == true
            && result["response_append_denied"] == true
            && result["ipc_creation_denied"] == true
            && result["guest_admission"] == false
            && result["engine_applied"] == false
            && result["guest_executed"] == false,
        "General RPC client witness differs"
    );
    let journal = read_regular(
        &root.join("private/network-broker.journal"),
        broker_journal::MAX_JOURNAL_BYTES,
        Some(root),
    )?;
    let expected_start = claim
        .expected_journal_start(&claim_raw)
        .map_err(anyhow::Error::msg)?;
    verify_journal(&journal, &expected_start, &probe, &response_body_sha)?;
    let staged_request = read_regular(
        &root.join("control/request.json"),
        emumee_core::general_execution_commitment::MAX_REQUEST,
        Some(root),
    )?;
    let staged_plan = read_regular(
        &root.join("control/plan.json"),
        emumee_core::analysis_plan::MAX_PLAN_BYTES,
        Some(root),
    )?;
    let target = read_regular(
        &root.join("control/inputs/0000.bin"),
        emumee_core::pe::MAX_INPUT,
        Some(root),
    )?;
    let public_projection = read_regular(
        &root.join("worker/public-target-projection.json"),
        1024 * 1024,
        Some(root),
    )?;
    let preflight = inspect_private_preflight(&StagedBytes {
        request: &staged_request,
        plan: &staged_plan,
        target: &target,
        claim: &claim_raw,
        fixture: &fixture_raw,
        probe: &probe_raw,
        journal: &journal,
        public_projection: &public_projection,
    })
    .map_err(anyhow::Error::msg)?;
    ensure!(
        !preflight.guest_admission && !preflight.engine_applied && !preflight.guest_executed,
        "General private preflight claimed guest execution"
    );
    let preflight_raw = serde_json::to_vec_pretty(&preflight)?;
    save_new(&root.join("general-private-preflight.json"), &preflight_raw)?;
    ensure!(
        !root.join("engine-report.json").exists() && !root.join("artifacts").exists(),
        "General RPC produced guest output"
    );
    let manifest = json!({
        "schema":1,"profile":"general_generated_rpc_v1","status":"verified",
        "request_sha256":request_sha,"claim_sha256":claim_sha,"probe_sha256":probe_sha,
        "response_sha256":probe.expected_response_sha256,"journal_sha256":digest(&journal),
        "public_witness_sha256":digest(&public_raw),"private_witness_sha256":digest(&private_raw),
        "private_preflight_sha256":digest(&preflight_raw),
        "client_witness_sha256":digest(&result_raw),"broker_exit":broker_exit,
        "worker_exit":worker_exit,"source_tree_sha256":bundle.receipt["source_tree_sha256"],
        "contained_public_witness":true,"contained_broker_witness":true,
        "cleanup":"restored","general_guest_admission":false,"engine_applied":false,
        "guest_executed":false,"unpacking_confirmed":false,
    });
    save_new(
        &root.join("general-rpc-manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(manifest)
}

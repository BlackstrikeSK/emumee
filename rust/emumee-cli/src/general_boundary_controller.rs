//! Parent-only contained read-boundary fixture for a future general run.
//! The two roles inspect committed bytes; neither can execute a guest.
use super::{
    general_execution_stage::StagedGeneralExecution,
    worker::{save_new, verified_bundle},
};
use anyhow::{Context, Result, ensure};
use emumee_core::{
    analysis_plan::{Arch, PreparedIntake},
    general_broker_private_attestation::{Claim, MAX_CLAIM, Receipt as PrivateReceipt},
    general_driver128_owned_preflight::{self, OwnedBytes, Receipt as OwnedReceipt},
    general_driver128_pending::MAX_PUBLIC_PROJECTION,
    general_worker_public_preflight::{PendingDriver128Report, preflight_driver128_public_report},
    plan_runtime::Case,
    report_bundle::digest,
};
use emumee_platform::windows::{
    AccessGrant, OfflineProfile, OutputLimits, RecoverySession, WorkerExit, WorkerJob, WorkerStop,
    read_regular,
};
use serde_json::{Value, json};
use std::{ffi::OsString, path::Path};

const LIMITS: OutputLimits = OutputLimits {
    max_bytes: 8 * 1024 * 1024,
    max_entries: 100,
    max_directories: 3,
    max_depth: 2,
};

pub(crate) fn run_id() -> Result<String> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let (id, _) = emumee_core::analysis_fixture::identity(
        now.as_secs(),
        now.subsec_nanos() ^ std::process::id(),
    )
    .map_err(anyhow::Error::msg)?;
    Ok(id)
}

pub(crate) fn verify_output_location(bundle: &Path, output: &Path) -> Result<()> {
    let output = std::path::absolute(output)?;
    let parent = output
        .parent()
        .context("General boundary output parent absent")?
        .canonicalize()?;
    let destination = parent.join(
        output
            .file_name()
            .context("General boundary output name absent")?,
    );
    ensure!(
        !destination.starts_with(bundle) && !bundle.starts_with(&destination),
        "General boundary output must be outside frozen bundle"
    );
    Ok(())
}

pub(crate) fn generated(private: bool) -> Result<PreparedIntake> {
    let mut kernel = Case::Kernel17
        .generated(Arch::X64)
        .map_err(anyhow::Error::msg)?;
    let mut plan: Value = serde_json::from_slice(&kernel.plan)?;
    plan["target"]["service_name"] = json!("TestDrv");
    if private {
        let fixture = Case::NativeReplay
            .generated(Arch::X64)
            .map_err(anyhow::Error::msg)?
            .fixtures;
        plan["inputs"]
            .as_array_mut()
            .context("Generated inputs absent")?
            .push(json!({
                "id":"offline","name":"offline.json","roles":["offline_fixtures"],
                "mount":{"kind":"not_mounted"},"size":fixture.len(),"sha256":digest(&fixture)
            }));
        plan["network"] = json!({"kind":"offline_exact_replay","input":"offline"});
        kernel.inputs.push(fixture);
    }
    Ok(PreparedIntake::prepare(
        serde_json::to_vec(&plan)?,
        kernel.inputs,
    )?)
}

/// Generated large-driver planning bytes only. Both contained roles still use
/// their existing verify-only entry points; no engine role receives this plan.
fn generated_driver128() -> Result<PreparedIntake> {
    let mut kernel = Case::Kernel17
        .generated(Arch::X64)
        .map_err(anyhow::Error::msg)?;
    let fixture = Case::NativeReplay
        .generated(Arch::X64)
        .map_err(anyhow::Error::msg)?
        .fixtures;
    let mut plan: Value = serde_json::from_slice(&kernel.plan)?;
    plan["target"]["service_name"] = json!("TestDrv");
    plan["persona"]["value"]["windows_build"] = json!(22631);
    plan["capture"]["profile"] = json!("large_driver128_v1");
    plan["capture"]["sources"] = json!(["memory_snapshots", "structural_pe"]);
    plan["capture"]["retained_bytes"] = json!(256u64 * 1024 * 1024);
    plan["capture"]["memory_scan_bytes"] = json!(128u64 * 1024 * 1024);
    plan["reports"]["profile"] = json!("large_driver_v1");
    plan["limits"]["worker_memory_mb"] = json!(2048);
    plan["inputs"]
        .as_array_mut()
        .context("Generated Driver128 inputs absent")?
        .push(json!({
            "id":"offline","name":"offline.json","roles":["offline_fixtures"],
            "mount":{"kind":"not_mounted"},"size":fixture.len(),"sha256":digest(&fixture),
        }));
    plan["network"] = json!({"kind":"offline_exact_replay","input":"offline"});
    kernel.inputs.push(fixture);
    PreparedIntake::prepare_driver128(serde_json::to_vec(&plan)?, kernel.inputs)
        .map_err(anyhow::Error::from)
}

pub(crate) fn contained(value: &Value) -> bool {
    value["app_container"] == true
        && value["job_object"] == true
        && value["child_process_blocked"] == true
        && value["network_capabilities"] == 0
}

fn stopped(exit: &WorkerExit) -> bool {
    exit.reason == WorkerStop::Exited && exit.exit_code == 0
}

fn boundary_job_memory_mib(plan_raw: &[u8], driver128: bool) -> Result<usize> {
    let plan: Value = serde_json::from_slice(plan_raw)?;
    let requested = plan["limits"]["worker_memory_mb"]
        .as_u64()
        .context("General boundary plan has no worker memory limit")?;
    let job_memory_mib = if driver128 { 2048 } else { 1024 };
    ensure!(
        requested == job_memory_mib as u64,
        "General boundary plan worker limit does not match contained job"
    );
    Ok(job_memory_mib)
}

/// Parent re-reads every independently staged Driver128 input after both
/// contained read roles exit. The returned core receipt never grants a guest.
fn inspect_driver128_staged(
    root: &Path,
    request_sha256: &str,
    claim_sha256: &str,
    source_tree_sha256: &str,
    containment_identity_sha256: &str,
) -> Result<(PendingDriver128Report, OwnedReceipt, PrivateReceipt)> {
    let request = read_regular(
        &root.join("control/request.json"),
        emumee_core::general_execution_commitment::MAX_REQUEST,
        Some(root),
    )?;
    ensure!(
        digest(&request) == request_sha256,
        "Driver128 staged request changed"
    );
    let plan = read_regular(
        &root.join("control/plan.json"),
        emumee_core::analysis_plan::MAX_PLAN_BYTES,
        Some(root),
    )?;
    let target = read_regular(
        &root.join("control/inputs/0000.bin"),
        emumee_core::pe::MAX_INPUT,
        Some(root),
    )?;
    let projection = read_regular(
        &root.join("worker/public-target-projection.json"),
        MAX_PUBLIC_PROJECTION,
        Some(root),
    )?;
    let claim_raw = read_regular(&root.join("private/claim.json"), MAX_CLAIM, Some(root))?;
    ensure!(
        digest(&claim_raw) == claim_sha256,
        "Driver128 staged claim changed"
    );
    let claim = Claim::parse(&claim_raw).map_err(anyhow::Error::msg)?;
    let fixture = read_regular(
        &root.join("private/http-fixtures.json"),
        usize::try_from(claim.fixture.size)?,
        Some(root),
    )?;
    let private = claim
        .inspect(&claim_raw, &fixture)
        .map_err(anyhow::Error::msg)?;
    let public =
        preflight_driver128_public_report(&request, request_sha256, &plan, &[Some(&target), None])
            .map_err(anyhow::Error::msg)?;
    let owned = general_driver128_owned_preflight::inspect(
        &OwnedBytes {
            request: &request,
            plan: &plan,
            target: &target,
            public_projection: &projection,
            private_claim: &claim_raw,
            private_fixture: &fixture,
        },
        source_tree_sha256,
        containment_identity_sha256,
    )
    .map_err(anyhow::Error::msg)?;
    ensure!(
        !public.complete_report_binding
            && !public.guest_admission
            && !owned.source_tree_witness_verified
            && !owned.containment_witness_verified
            && !owned.broker_journal_verified
            && !owned.general_worker_admitted
            && !owned.guest_admission
            && !owned.engine_applied
            && !owned.guest_executed,
        "Driver128 owned inspection claimed runtime admission"
    );
    Ok((public, owned, private))
}

pub(crate) fn verify_fixture(output: &Path, private: bool) -> Result<Value> {
    verify_fixture_inner(output, generated(private)?, private, false)
}

pub(crate) fn verify_driver128_fixture(output: &Path) -> Result<Value> {
    verify_fixture_inner(output, generated_driver128()?, true, true)
}

fn verify_fixture_inner(
    output: &Path,
    intake: PreparedIntake,
    private: bool,
    driver128: bool,
) -> Result<Value> {
    let bundle = verified_bundle()?;
    verify_output_location(&bundle.path, output)?;
    let worker_memory_mib = boundary_job_memory_mib(intake.raw_plan(), driver128)?;
    let stage = StagedGeneralExecution::stage(intake, run_id()?, output)?;
    ensure!(
        !stage.request().execution_authorized && stage.request().operation == "commit_only",
        "General stage became executable"
    );
    if driver128 {
        ensure!(
            stage.request().report_profile == "large_driver_v1"
                && stage.request().broker_private_fixture.is_some(),
            "Driver128 boundary stage lost its private report identity"
        );
    }
    stage.verify_prelaunch()?;
    let root = stage.root();
    let request_hash = stage.request_sha256();
    let claim_hash = if private {
        let raw = read_regular(&root.join("private/claim.json"), MAX_CLAIM, Some(root))?;
        let claim = Claim::parse(&raw).map_err(anyhow::Error::msg)?;
        ensure!(
            claim.request_sha256 == request_hash,
            "Private claim request differs"
        );
        Some(digest(&raw))
    } else {
        None
    };
    std::fs::create_dir(root.join("worker"))?;
    std::fs::create_dir(root.join("broker"))?;
    let mut recovery = RecoverySession::begin(&bundle.path, root)?;
    let worker_job = WorkerJob::new_tracked(worker_memory_mib, &mut recovery)?;
    let broker_job = WorkerJob::new_tracked(256, &mut recovery)?;
    let mut worker_profile = OfflineProfile::new_tracked(&mut recovery)?;
    let mut broker_profile = OfflineProfile::new_tracked(&mut recovery)?;
    let mut grants: Vec<AccessGrant> = Vec::new();
    let executable = bundle.path.join("emumee-worker.exe");
    let run = (|| -> Result<(WorkerExit, Option<WorkerExit>)> {
        grants.push(worker_profile.grant_tracked(&bundle.path, false, &mut recovery)?);
        grants.push(broker_profile.grant_tracked(&bundle.path, false, &mut recovery)?);
        grants.push(worker_profile.grant_traverse_tracked(root, &mut recovery)?);
        grants.push(broker_profile.grant_traverse_tracked(root, &mut recovery)?);
        grants.push(worker_profile.grant_tracked(&root.join("control"), false, &mut recovery)?);
        grants.push(worker_profile.grant_tracked(&root.join("worker"), true, &mut recovery)?);
        if private {
            grants.push(broker_profile.grant_tracked(
                &root.join("private"),
                false,
                &mut recovery,
            )?);
            grants.push(broker_profile.grant_tracked(
                &root.join("private/network-broker.journal"),
                true,
                &mut recovery,
            )?);
            grants.push(broker_profile.grant_tracked(&root.join("broker"), true, &mut recovery)?);
        }
        // Both roles have distinct offline SIDs, zero network capabilities,
        // one-process jobs, and only their own output directory as CWD.
        let worker = worker_profile.launch(
            &executable,
            &[
                OsString::from("--general-public-read-probe"),
                root.as_os_str().to_owned(),
                OsString::from(&request_hash),
            ],
            &root.join("worker"),
            30_000,
            &worker_job,
            LIMITS,
        )?;
        ensure!(stopped(&worker), "Public contained read probe failed");
        let broker = if let Some(claim_hash) = &claim_hash {
            let exit = broker_profile.launch(
                &executable,
                &[
                    OsString::from("--general-private-read-probe"),
                    root.as_os_str().to_owned(),
                    OsString::from(claim_hash),
                ],
                &root.join("broker"),
                30_000,
                &broker_job,
                LIMITS,
            )?;
            ensure!(stopped(&exit), "Private contained read probe failed");
            Some(exit)
        } else {
            None
        };
        Ok((worker, broker))
    })();
    // launch() waits for exit. Reverse grant restoration keeps children ahead
    // of root traversal and bundle grants on success and every error path.
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
        "General boundary cleanup failed: {cleanup_errors:?}"
    );
    recovery.finish()?;
    let (worker_exit, broker_exit) = run?;
    let public_raw = read_regular(
        &root.join("worker/public-boundary.json"),
        64 * 1024,
        Some(root),
    )?;
    let public: Value = serde_json::from_slice(&public_raw)?;
    ensure!(
        public["schema"] == 1
            && public["role"] == "general_public_read_probe_v1"
            && public["request_sha256"] == request_hash
            && contained(&public["containment"])
            && public["broker_private_read_denied"] == true
            && public["execution_authorized"] == false
            && public["engine_applied"] == false
            && public["guest_executed"] == false
            && public["preflight"]["guest_admission"] == false,
        "Public contained boundary receipt differs"
    );
    let (broker_hash, journal_hash, broker_inspection) = if let Some(claim_hash) = &claim_hash {
        let broker_raw = read_regular(
            &root.join("broker/private-boundary.json"),
            64 * 1024,
            Some(root),
        )?;
        let broker: Value = serde_json::from_slice(&broker_raw)?;
        let claim_raw = read_regular(&root.join("private/claim.json"), MAX_CLAIM, Some(root))?;
        let claim = Claim::parse(&claim_raw).map_err(anyhow::Error::msg)?;
        let expected_start = claim
            .expected_journal_start(&claim_raw)
            .map_err(anyhow::Error::msg)?;
        let journal = read_regular(
            &root.join("private/network-broker.journal"),
            expected_start.len(),
            Some(root),
        )?;
        ensure!(
            journal == expected_start,
            "Private broker journal start differs"
        );
        ensure!(
            broker["schema"] == 1
                && broker["role"] == "general_private_read_probe_v1"
                && broker["claim_sha256"] == *claim_hash
                && contained(&broker["containment"])
                && broker["public_target_read_denied"] == true
                && broker["journal_start_sha256"] == digest(&journal)
                && broker["execution_authorized"] == false
                && broker["engine_applied"] == false
                && broker["guest_executed"] == false
                && broker["inspection"]["private_bytes_inspected"] == true
                && broker["inspection"]["guest_admission"] == false,
            "Private contained boundary receipt differs"
        );
        (
            Some(digest(&broker_raw)),
            Some(digest(&journal)),
            Some(broker["inspection"].clone()),
        )
    } else {
        ensure!(
            !root.join("broker/private-boundary.json").exists()
                && !root.join("private/network-broker.journal").exists(),
            "Offline deny wrote private broker output"
        );
        (None, None, None)
    };
    ensure!(
        !root.join("engine-report.json").exists() && !root.join("artifacts").exists(),
        "General boundary produced engine output"
    );
    let (
        driver128_report,
        driver128_owned_preflight,
        driver128_containment_identity,
        driver128_journal_start_witness,
    ) = if driver128 {
        let claim_hash = claim_hash
            .as_deref()
            .context("Driver128 private claim absent")?;
        let broker_inspection = broker_inspection
            .as_ref()
            .context("Driver128 broker inspection absent")?;
        let source_tree = bundle.receipt["source_tree_sha256"]
            .as_str()
            .context("Driver128 bundle source tree absent")?;
        let containment_identity = digest(&serde_json::to_vec(&json!({
            "public_receipt_sha256":digest(&public_raw),
            "broker_receipt_sha256":broker_hash.as_deref(),
            "journal_start_sha256":journal_hash.as_deref(),
        }))?);
        let (report, owned, private) = inspect_driver128_staged(
            root,
            &request_hash,
            claim_hash,
            source_tree,
            &containment_identity,
        )?;
        ensure!(
            public["preflight"] == serde_json::to_value(&report.public_preflight)?,
            "Driver128 public role inspection differs from parent readback"
        );
        ensure!(
            *broker_inspection == serde_json::to_value(&private)?,
            "Driver128 private role inspection differs from parent readback"
        );
        let claim_raw = read_regular(&root.join("private/claim.json"), MAX_CLAIM, Some(root))?;
        let expected_start = Claim::parse(&claim_raw)
            .map_err(anyhow::Error::msg)?
            .expected_journal_start(&claim_raw)
            .map_err(anyhow::Error::msg)?;
        let journal = read_regular(
            &root.join("private/network-broker.journal"),
            expected_start.len(),
            Some(root),
        )?;
        let journal_witness = general_driver128_owned_preflight::verify_private_journal_start(
            &owned, &claim_raw, &journal,
        )
        .map_err(anyhow::Error::msg)?;
        ensure!(
            Some(journal_witness.journal_start_sha256.as_str()) == journal_hash.as_deref()
                && !journal_witness.full_broker_journal_verified
                && !journal_witness.contained_broker_witness
                && !journal_witness.general_worker_admitted
                && !journal_witness.guest_admission
                && !journal_witness.engine_applied
                && !journal_witness.guest_executed,
            "Driver128 journal witness differs from contained readback"
        );
        (
            Some(report),
            Some(owned),
            Some(containment_identity),
            Some(journal_witness),
        )
    } else {
        (None, None, None, None)
    };
    let manifest = json!({
        "schema":1,"profile":if driver128 {"general_driver128_boundary_v1"} else {"general_public_private_boundary_v1"},
        "status":"verified","fixture":if private {"replay"} else {"deny"},
        "request_sha256":request_hash,"claim_sha256":claim_hash,
        "worker_job_memory_mb":worker_memory_mib,
        "worker_exit":worker_exit,"broker_exit":broker_exit,
        "public_receipt_sha256":digest(&public_raw),
        "broker_receipt_sha256":broker_hash,
        "journal_start_sha256":journal_hash,
        "driver128_public_report":driver128_report,
        "driver128_owned_preflight":driver128_owned_preflight,
        "driver128_containment_identity_sha256":driver128_containment_identity,
        "driver128_journal_start_witness":driver128_journal_start_witness,
        "source_tree_sha256":bundle.receipt["source_tree_sha256"],
        "cleanup":"restored","contained_public_witness":true,
        "contained_broker_witness":private,
        "general_guest_admission":false,"engine_applied":false,
        "guest_executed":false,"unpacking_confirmed":false,
    });
    save_new(
        &root.join("general-boundary-manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(manifest)
}

#[cfg(test)]
mod driver128_tests {
    use super::*;
    use emumee_core::{
        driver_capture_reports::Projection, general_broker_private_attestation::Claim,
        general_execution_commitment::Request,
    };

    #[test]
    fn staged_owned_readback_binds_both_roles_without_runtime_admission() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "emumee-driver128-owned-boundary-{}-{nonce}",
            std::process::id()
        ));
        let stage = StagedGeneralExecution::stage(
            generated_driver128().unwrap(),
            "20261019T120000Z-12345678".into(),
            &root,
        )
        .unwrap();
        std::fs::create_dir(root.join("worker")).unwrap();
        let target = std::fs::read(root.join("control/inputs/0000.bin")).unwrap();
        let projection = serde_json::to_vec(&Projection::from_bytes(&target).unwrap()).unwrap();
        let projection_path = root.join("worker/public-target-projection.json");
        std::fs::write(&projection_path, &projection).unwrap();
        let claim_raw = std::fs::read(root.join("private/claim.json")).unwrap();
        let claim_hash = digest(&claim_raw);
        let source_tree = "1".repeat(64);
        let containment_identity = "2".repeat(64);
        let check = || {
            inspect_driver128_staged(
                &root,
                &stage.request_sha256(),
                &claim_hash,
                &source_tree,
                &containment_identity,
            )
        };
        let (public, owned, private) = check().unwrap();
        assert_eq!(owned.target_sha256, digest(&target));
        assert_eq!(private.claim_sha256, claim_hash);
        assert!(!public.guest_admission && !public.complete_report_binding);
        assert!(owned.owned_resolved_plan_verified);
        assert!(owned.request_private_report_identity_verified);
        assert!(!owned.source_tree_witness_verified);
        assert!(!owned.containment_witness_verified);
        assert!(!owned.broker_journal_verified);
        assert!(!owned.general_worker_admitted);
        assert!(!owned.guest_admission && !owned.engine_applied && !owned.guest_executed);
        for path in [
            root.join("control/request.json"),
            root.join("control/plan.json"),
            root.join("control/inputs/0000.bin"),
            projection_path,
            root.join("private/claim.json"),
            root.join("private/http-fixtures.json"),
        ] {
            let original = std::fs::read(&path).unwrap();
            std::fs::write(&path, b"bad").unwrap();
            assert!(check().is_err(), "tampered staged file accepted: {path:?}");
            std::fs::write(&path, original).unwrap();
        }
        assert!(check().is_ok());
        drop(stage);
        let temp = std::env::temp_dir().canonicalize().unwrap();
        let resolved = root.canonicalize().unwrap();
        assert_eq!(resolved.parent(), Some(temp.as_path()));
        assert!(
            resolved
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("emumee-driver128-owned-boundary-"))
        );
        std::fs::remove_dir_all(resolved).unwrap();
    }

    #[test]
    fn generated_driver128_stays_planning_only_with_distinct_public_and_private_bytes() {
        let intake = generated_driver128().unwrap();
        assert_eq!(
            boundary_job_memory_mib(intake.raw_plan(), true).unwrap(),
            2048
        );
        assert_eq!(
            boundary_job_memory_mib(generated(false).unwrap().raw_plan(), false).unwrap(),
            1024
        );
        let mut too_small: Value = serde_json::from_slice(intake.raw_plan()).unwrap();
        too_small["limits"]["worker_memory_mb"] = json!(1024);
        assert!(boundary_job_memory_mib(&serde_json::to_vec(&too_small).unwrap(), true).is_err());
        too_small["limits"]["worker_memory_mb"] = json!("2048");
        assert!(boundary_job_memory_mib(&serde_json::to_vec(&too_small).unwrap(), true).is_err());
        assert!(!intake.resolved().executable());
        assert_eq!(intake.resolved().value()["guest_admission"], false);
        assert_eq!(intake.resolved().value()["engine_applied"], false);
        assert_eq!(
            intake.resolved().value()["budget"]["general_worker_admitted"],
            false
        );
        let request = Request::from_intake(&intake, "20261019T120000Z-12345678".into()).unwrap();
        let request_raw = serde_json::to_vec(&request).unwrap();
        assert!(!request.execution_authorized);
        let claim = Claim::from_verified_request(&request_raw, &intake).unwrap();
        let claim_raw = serde_json::to_vec(&claim).unwrap();
        let slots = intake.slots().map(|(_, bytes)| bytes).collect::<Vec<_>>();
        assert_eq!(slots.len(), 2);
        claim.inspect(&claim_raw, slots[1]).unwrap();
        let report = preflight_driver128_public_report(
            &request_raw,
            &digest(&request_raw),
            intake.raw_plan(),
            &[Some(slots[0]), None],
        )
        .unwrap();
        assert!(!report.complete_report_binding && !report.guest_admission);
        assert_eq!(report.target_input_sha256, digest(slots[0]));
        let mut changed_plan: Value = serde_json::from_slice(intake.raw_plan()).unwrap();
        changed_plan["reports"]["profile"] = json!("legacy_v1");
        assert!(
            preflight_driver128_public_report(
                &request_raw,
                &digest(&request_raw),
                &serde_json::to_vec(&changed_plan).unwrap(),
                &[Some(slots[0]), None],
            )
            .is_err()
        );
        let mut changed_target = slots[0].to_vec();
        changed_target[0] ^= 1;
        assert!(
            preflight_driver128_public_report(
                &request_raw,
                &digest(&request_raw),
                intake.raw_plan(),
                &[Some(&changed_target), None],
            )
            .is_err()
        );
    }
}

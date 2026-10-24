//! Closed plan proof; parent verifies every actual staged authority and report.
use super::{
    analysis_fixture::{payloads, typed_catalog},
    worker::save_new,
};
use anyhow::{Context, Result, ensure};
use emumee_core::{
    analysis_plan::{self, InputRole},
    plan_runtime::{self, BrokerSession, Fault, PreparedAnalysis, Request},
    report_bundle::{self, Input, NetworkCoverage, Profile, Termination},
    reports,
};
use emumee_platform::windows::read_regular;
use serde_json::{Value, json};
use std::path::Path;
fn acquire(root: &Path) -> Result<(PreparedAnalysis, PreparedAnalysis, BrokerSession)> {
    let control = root.join("control");
    let raw = read_regular(&control.join("request.json"), 4096, Some(&control))?;
    let request = Request::parse(&raw).map_err(anyhow::Error::msg)?;
    let plan = read_regular(
        &control.join("plan.json"),
        analysis_plan::MAX_PLAN_BYTES,
        Some(&control),
    )?;
    let persona = read_regular(
        &control.join("persona.json"),
        analysis_plan::MAX_PLAN_BYTES,
        Some(&control),
    )?;
    let spec = analysis_plan::PlanSpec::decode(&plan)?;
    ensure!(spec.inputs.len() <= 4, "Closed parent slot count");
    let mut full = Vec::new();
    let mut public = Vec::new();
    for (index, input) in spec.inputs.iter().enumerate() {
        ensure!(
            input.size <= plan_runtime::MAX_INPUT as u64,
            "Closed parent input bound"
        );
        if input.roles.contains(&InputRole::OfflineFixtures) {
            full.push(read_regular(
                &root.join("private/http-fixtures.json"),
                input.size as usize,
                Some(root),
            )?);
            public.push(None)
        } else {
            let bytes = read_regular(
                &control.join("inputs").join(format!("{index:04}.bin")),
                input.size as usize,
                Some(&control),
            )?;
            public.push(Some(bytes.clone()));
            full.push(bytes);
        }
    }
    let parent = PreparedAnalysis::prepare(&raw, &plan, full, persona.clone())
        .map_err(anyhow::Error::msg)?;
    let worker = PreparedAnalysis::prepare_worker(&raw, &plan, public, persona)
        .map_err(anyhow::Error::msg)?;
    let raw_config = read_regular(&control.join("config.json"), 4096, Some(&control))?;
    let config = BrokerSession::parse(&raw_config, &raw).map_err(anyhow::Error::msg)?;
    let fixtures = read_regular(
        &root.join("private/http-fixtures.json"),
        emumee_core::networkfixtures::MAX_FILE,
        Some(root),
    )?;
    ensure!(
        report_bundle::digest(&fixtures) == request.fixture_sha256,
        "Parent private fixture changed"
    );
    Ok((parent, worker, config))
}
fn verify_broker_isolation(root: &Path) -> Result<()> {
    let broker = root.join("broker");
    let ready: Value = serde_json::from_slice(&read_regular(
        &broker.join("broker-ready.json"),
        4096,
        Some(&broker),
    )?)?;
    ensure!(
        ready["target_read_denied"] == true
            && ready["persona_read_denied"] == true
            && ready["cleanup_plan_read_denied"] == true
            && ready["app_container"] == true
            && ready["job_object"] == true
            && ready["child_process_blocked"] == true
            && ready["network_capabilities"] == 0,
        "Plan broker isolation witness changed"
    );
    Ok(())
}
pub(crate) fn verify_staged(root: &Path) -> Result<()> {
    let _ = acquire(root)?;
    Ok(())
}
#[derive(Clone, Copy)]
enum Delivery {
    PublishFresh,
    VerifyExisting,
}
fn finalize(root: &Path, session: &Value, delivery: Delivery) -> Result<Value> {
    finalize_selected(root, session, delivery, false)
}
fn finalize_selected(
    root: &Path,
    session: &Value,
    delivery: Delivery,
    fault_role: bool,
) -> Result<Value> {
    let (parent, prepared, config) = acquire(root)?;
    verify_broker_isolation(root)?;
    let request = prepared.request();
    let output = root.join("worker");
    let fault = request.fault;
    ensure!(
        fault_role != fault.is_none(),
        "Normal/fault role identity changed"
    );
    if fault.checkpoint() {
        verify_checkpoint_stop(fault, session)?;
    } else {
        ensure!(
            session["boundary_qualified"] == true
                && session["worker_exit"] == 0
                && session["broker_exit"] == 0
                && session["cleanup"] == "restored",
            "Closed plan child lifecycle did not finish cleanly"
        );
    }
    let raw_config = read_regular(&root.join("control/config.json"), 4096, Some(root))?;
    ensure!(
        session["request_sha256"] == report_bundle::digest(&raw_config),
        "Controller config commitment changed"
    );
    ensure!(
        session["qualified"] == false
            && session["source_tree_sha256"] == env!("EMUMEE_BUILD_SOURCE_SHA256")
            && session["bundle_receipt"]["source_tree_sha256"]
                == env!("EMUMEE_BUILD_SOURCE_SHA256"),
        "Boundary receipt claimed full qualification or changed build"
    );
    let checkpoint_receipt;
    let receipt = if fault.checkpoint() {
        checkpoint_receipt = serde_json::from_slice::<Value>(&read_regular(
            &output.join("plan-checkpoint.json"),
            64 * 1024,
            Some(&output),
        )?)?;
        ensure!(
            session["worker_result"].is_null() && !output.join("plan-result.json").exists(),
            "Checkpoint failure acquired a final worker receipt"
        );
        &checkpoint_receipt
    } else {
        &session["worker_result"]
    };
    ensure!(
        receipt["role"] == "closed_plan_worker"
            && receipt["request_sha256"] == prepared.request_sha256()
            && receipt["installation"] == prepared.receipt()
            && receipt["private_fixture_denied"] == true
            && receipt["private_journal_denied"] == true,
        "Worker plan installation evidence changed"
    );
    let witness = read_regular(&output.join("worker-containment.json"), 4096, Some(&output))?;
    let containment: Value = serde_json::from_slice(&witness)?;
    ensure!(
        receipt["containment"] == containment
            && containment["app_container"] == true
            && containment["job_object"] == true
            && containment["child_process_blocked"] == true
            && containment["network_capabilities"] == 0,
        "Plan containment witness changed"
    );
    let summary_raw = read_regular(
        &output.join("worker-summary.json"),
        reports::MAX_SUMMARY_BYTES,
        Some(&output),
    )?;
    let summary = reports::parse_summary(&summary_raw)?;
    let engine_raw = read_regular(
        &output.join("engine-report.json"),
        reports::MAX_ENGINE_BYTES,
        Some(&output),
    )?;
    let network_raw = read_regular(
        &output.join("network-broker.json"),
        reports::MAX_NETWORK_REPORT_BYTES,
        Some(&output),
    )?;
    let manifest = read_regular(
        &output.join("artifacts/manifest.json"),
        report_bundle::MAX_MANIFEST_BYTES,
        Some(&output),
    )?;
    let checkpoint = read_regular(
        &output.join("artifact-checkpoint.json"),
        report_bundle::MAX_MANIFEST_BYTES,
        Some(&output),
    )?;
    for (field, raw) in [
        ("summary_sha256", &summary_raw),
        ("engine_sha256", &engine_raw),
        ("network_sha256", &network_raw),
        ("manifest_sha256", &manifest),
    ] {
        ensure!(
            receipt[field] == report_bundle::digest(raw),
            "Worker report receipt hash changed: {field}"
        );
    }
    ensure!(
        manifest == checkpoint && reports::manifest_matches(&manifest, &summary["artifacts"]),
        "Plan artifact manifest/checkpoint changed"
    );
    ensure!(
        reports::verified_report(&summary, reports::BoundReport::Engine, &engine_raw).is_some()
            && reports::verified_report(
                &summary,
                reports::BoundReport::NetworkBroker,
                &network_raw
            )
            .is_some(),
        "Plan bound report integrity failed"
    );
    let engine: Value = serde_json::from_slice(&engine_raw)?;
    let network: Value = serde_json::from_slice(&network_raw)?;
    let run = &summary["run_manifest"];
    ensure!(
        summary["sample"]["sha256"] == report_bundle::digest(prepared.input())
            && summary["sample"]["size"] == prepared.input().len(),
        "Reported sample does not bind actual acquired primary bytes"
    );
    ensure!(
        summary["id"] == request.run_id
            && run["request_sha256"] == prepared.request_sha256()
            && run["input_sha256"] == report_bundle::digest(prepared.input())
            && run["input_size"] == prepared.input().len()
            && run["case"] == serde_json::to_value(request.case)?
            && run["installation"] == prepared.receipt()
            && run["containment_sha256"] == report_bundle::digest(&witness)
            && run["source_tree_sha256"] == env!("EMUMEE_BUILD_SOURCE_SHA256")
            && engine["run_manifest"] == *run,
        "Plan run manifest authority changed"
    );
    ensure!(
        network["coverage"] == "model_only" && network["broker_monitoring_complete"] == false,
        "Worker asserted private journal authority"
    );
    if !request.case.static_only() {
        let configuration = &engine["execution"]["configuration"];
        ensure!(
            configuration["windows_build"] == 26100
                && configuration["physical_memory_mb"] == 8192
                && configuration["available_memory_mb"] == 4096,
            "Installed nondefault machine profile changed"
        );
        ensure!(
            engine["execution"]["virtual_uptime_ms"]
                .as_u64()
                .is_some_and(|uptime| (543210..=546210).contains(&uptime)),
            "Installed guest clock differs from the explicit plan seed"
        );
        ensure!(
            configuration["version"] == "emumee-closed-plan-modeled-v1"
                && configuration["initialized"] == true
                && configuration["generated_only"] == true
                && configuration["input_json_sha256"] == request.persona_sha256
                && configuration["projection_sha256"]
                    == report_bundle::digest(&serde_json::to_vec(&prepared.spec().persona)?)
                && configuration["seed_manifest_sha256"]
                    == report_bundle::digest(&serde_json::to_vec(&prepared.spec().inputs)?),
            "Installed native configuration receipt changed"
        );
        ensure!(
            engine["execution"]["architecture"]
                == serde_json::to_value(request.architecture.architecture())?,
            "Executed architecture changed"
        );
    }
    let (captures, omissions) = typed_catalog(&engine["execution"], payloads(&output, &summary)?)?;
    if let Some(expected) = fault.expected_return(request.case) {
        ensure!(
            engine["execution"]["completion_reason"] == "entry_return"
                && engine["execution"]["guest_entry_return"].as_u64() == Some(expected),
            "Actual installed guest result changed"
        );
    } else if fault == Fault::GuestTimeout {
        ensure!(
            summary["status"] == "timeout"
                && engine["execution"]["completion_reason"] == "timeout"
                && engine["execution"]["guest_entry_return"].is_null()
                && engine["execution"]["instruction_count"]
                    .as_u64()
                    .is_some_and(|n| n > 0 && n < 1_000_000_000),
            "Actual guest timeout evidence changed"
        );
    } else if fault == Fault::Reconfigure {
        let proof = &engine["execution"]["closed_plan_fault"];
        ensure!(
            summary["status"] == "partial"
                && engine["execution"]["completion_reason"] == "error"
                && engine["execution"]["guest_entry_return"].is_null()
                && engine["execution"]["instruction_count"] == 1
                && proof["refused"] == true
                && proof["configuration_unchanged"] == true
                && proof["before"] == proof["after"]
                && proof["before"] == engine["execution"]["configuration"]
                && proof["attempted_after_instructions"] == 1
                && proof["reason"] == "Configured state cannot change after native publication",
            "Actual publication guard refusal evidence changed"
        );
    } else {
        ensure!(
            summary["status"] == "partial"
                && engine["execution"]["completion_reason"] == "static_inspection",
            "Static inspection was promoted to execution completion"
        );
    }
    let mut base = report_bundle::build(Input {
        run_id: &request.run_id,
        started_at: summary["started_at"].as_str().context("start")?,
        finished_at: summary["finished_at"].as_str().context("finish")?,
        sample: &summary["sample"],
        execution: &engine["execution"],
        execution_mode: summary["execution_mode"].as_str().context("mode")?,
        manifest: run,
        network: &network["report"],
        network_coverage: NetworkCoverage::ModelOnly,
        termination: Termination::Normal,
        checkpoint_recovered: false,
        profile: Profile::LegacyV1,
        artifacts: &captures,
        omissions: &omissions,
    })?;
    ensure!(
        base.summary == summary_raw
            && base.engine == engine_raw
            && base.network == network_raw
            && base.manifest == manifest
            && base.checkpoint == checkpoint,
        "Plan report byte reconstruction/provenance changed"
    );
    if fault.checkpoint() {
        ensure!(
            captures.len() == 1
                && captures[0].data == b"RUST"
                && captures[0].observations.len() == 1
                && captures[0].observations[0].kind
                    == emumee_core::artifacts::ArtifactKind::GuestFile
                && captures[0].observations[0].source == "configured_file_changed_at_stop"
                && captures[0].observations[0]
                    .guest_path
                    .eq_ignore_ascii_case(r"C:\Users\Alex\Downloads\fault-checkpoint.bin"),
            "Actual checkpoint payload/provenance differs"
        );
        base = report_bundle::build(Input {
            run_id: &request.run_id,
            started_at: summary["started_at"].as_str().context("start")?,
            finished_at: summary["finished_at"].as_str().context("finish")?,
            sample: &summary["sample"],
            execution: &engine["execution"],
            execution_mode: summary["execution_mode"].as_str().context("mode")?,
            manifest: run,
            network: &network["report"],
            network_coverage: NetworkCoverage::ModelOnly,
            termination: if fault == Fault::TimeoutAfterCheckpoint {
                Termination::Timeout
            } else {
                Termination::WorkerFailure
            },
            checkpoint_recovered: true,
            profile: Profile::LegacyV1,
            artifacts: &captures,
            omissions: &omissions,
        })?;
    }
    let journal_raw = read_regular(
        &root.join("private/network-broker.journal"),
        emumee_core::broker_journal::MAX_JOURNAL_BYTES,
        Some(root),
    )?;
    let journal = emumee_core::broker_journal::recover(&journal_raw)?;
    ensure!(
        journal.closed
            && journal.unrecovered_bytes == 0
            && serde_json::to_value(&journal)? == session["journal"],
        "Parent journal snapshot changed/incomplete"
    );
    let first = journal
        .events
        .first()
        .context("Broker start binding absent")?;
    ensure!(
        first
            == &json!({"event":"broker_started","mode":"offline_replay","role":"closed_plan_broker","config_sha256":report_bundle::digest(&raw_config),"request_sha256":config.request_sha256,"plan_sha256":config.plan_sha256,"fixture_sha256":config.fixture_sha256}),
        "Broker journal session binding changed"
    );
    let attempts = journal
        .events
        .iter()
        .filter(|e| e["event"] == "http_request_attempt")
        .count();
    ensure!(
        attempts == usize::from(request.case.network_probe()),
        "Actual broker attempt count changed"
    );
    let final_network = report_bundle::bounded_json(
        &json!({"schema":1,"coverage":"parent_verified_closed_offline_broker","broker_monitoring_complete":true,"request_sha256":prepared.request_sha256(),"plan_sha256":request.plan_sha256,"fixture_sha256":request.fixture_sha256,"journal":journal,"guest_model_report":network["report"],"scope":"Parent verified full private journal after both contained roles exited; offline fixture replay/denial only, no general network admission"}),
        reports::MAX_NETWORK_REPORT_BYTES,
    )?;
    let mut final_summary = reports::parse_summary(&base.summary)?;
    final_summary["network_broker_complete"] = json!(true);
    final_summary["network_coverage"] = json!("parent_verified_closed_offline_broker");
    final_summary["network_broker_report_sha256"] = json!(report_bundle::digest(&final_network));
    final_summary["network_broker_report_size"] = json!(final_network.len());
    final_summary["controller_integrity"] = json!("verified");
    final_summary["parent_installation"] = parent.receipt();
    ensure!(
        reports::valid_summary(&final_summary),
        "Parent final plan summary rejected"
    );
    let summary_bytes = report_bundle::bounded_json(&final_summary, reports::MAX_SUMMARY_BYTES)?;
    let delivery_manifest = report_bundle::bounded_json(
        &json!({"schema":"emumee.closed_plan_delivery.v1","verified":true,"source_tree_sha256":session["bundle_receipt"]["source_tree_sha256"],"controller_sha256":session["bundle_receipt"]["controller_sha256"],"worker_sha256":session["bundle_receipt"]["worker_sha256"],"request_sha256":prepared.request_sha256(),"plan_sha256":request.plan_sha256,"parent_installation":parent.receipt(),"summary_sha256":report_bundle::digest(&summary_bytes),"fault":fault,"analysis_completed":fault.is_none() && final_summary["status"]=="completed","scope":"Parent-verified closed generated installation/report proof only; full tool/general worker admission remains gated"}),
        report_bundle::MAX_MANIFEST_BYTES,
    )?;
    if matches!(delivery, Delivery::PublishFresh) {
        std::fs::create_dir(root.join("artifacts"))?;
    }
    for payload in &base.payloads {
        let path = root.join("artifacts").join(&payload.filename);
        match delivery {
            Delivery::PublishFresh => save_new(&path, payload.bytes)?,
            Delivery::VerifyExisting => ensure!(
                read_regular(&path, payload.bytes.len(), Some(root))? == payload.bytes,
                "Parent delivered artifact changed"
            ),
        }
    }
    for (name, raw) in [
        ("engine-report.json", &base.engine),
        ("network-broker.json", &final_network),
        ("artifacts/manifest.json", &base.manifest),
        ("artifact-checkpoint.json", &base.checkpoint),
        ("manifest.json", &delivery_manifest),
        ("summary.json", &summary_bytes),
    ] {
        match delivery {
            Delivery::PublishFresh => save_new(&root.join(name), raw)?,
            Delivery::VerifyExisting => ensure!(
                read_regular(&root.join(name), raw.len(), Some(root))? == *raw,
                "Parent delivered report changed: {name}"
            ),
        }
    }

    Ok(
        json!({"verified":true,"request_sha256":prepared.request_sha256(),"input_sha256":report_bundle::digest(prepared.input()),"plan_sha256":request.plan_sha256,"resolved_plan_sha256":prepared.resolved().sha256(),"status":final_summary["status"],"guest_entry_return":engine["execution"]["guest_entry_return"],"broker_attempts":attempts,"broker_complete":true,"fault":fault,"analysis_completed":fault.is_none() && final_summary["status"]=="completed","checkpoint_recovered":fault.checkpoint(),"scope":"Closed staged-buffer installation proof; general run/full tool remains gated"}),
    )
}
pub fn run(
    root: &Path,
    case: plan_runtime::Case,
    arch: emumee_core::pe::Architecture,
) -> Result<Value> {
    let session = super::broker::installed_plan(root, case, arch)?;
    let result = match finalize(root, &session, Delivery::PublishFresh) {
        Ok(value) => value,
        Err(error) => {
            json!({"verified":false,"reason":format!("{error:#}"),"scope":"Failed plan evidence remains quarantined; no trusted summary generated"})
        }
    };
    emumee_platform::windows::inspect_output(
        root,
        &[],
        emumee_platform::windows::OutputLimits {
            max_bytes: plan_runtime::MAX_OUTPUT,
            max_entries: 22000,
            max_directories: 64,
            max_depth: 40,
        },
    )?;
    save_new(
        &root.join("plan-verification.json"),
        &serde_json::to_vec_pretty(&result)?,
    )?;
    Ok(result)
}

pub fn inspect(root: &Path) -> Result<Value> {
    let raw = read_regular(
        &root.join("broker-session.json"),
        128 * 1024 * 1024,
        Some(root),
    )?;
    let session: Value = serde_json::from_slice(&raw)?;
    finalize(root, &session, Delivery::VerifyExisting)
}

/// Requires the exact failed lifecycle, not only a worker-produced checkpoint.
fn verify_checkpoint_stop(fault: Fault, session: &Value) -> Result<()> {
    ensure!(
        session["cleanup"] == "restored"
            && session["boundary_qualified"] == false
            && session["qualified"] == false
            && session["broker_exit"] == 0,
        "Checkpoint lifecycle was not failed/cleaned with broker already exited"
    );
    match fault {
        Fault::CrashAfterCheckpoint => ensure!(
            session["reason"] == "worker_failed" && session["worker_exit"] == 41,
            "Fixed checkpoint crash evidence differs"
        ),
        Fault::TimeoutAfterCheckpoint => ensure!(
            session["reason"] == "session_error: Broker session exceeded deadline"
                && session["worker_exit"].as_u64().is_some_and(|n| n != 0),
            "Fixed checkpoint watchdog evidence differs"
        ),
        _ => anyhow::bail!("Not a fixed checkpoint scenario"),
    }
    Ok(())
}
fn no_draft_fault(root: &Path, session: &Value, delivery: Delivery) -> Result<Value> {
    let (parent, worker, config) = acquire(root)?;
    verify_broker_isolation(root)?;
    let request = worker.request();
    let fault = request.fault;
    ensure!(
        fault.broker_failure() || fault == Fault::OutputDirectories,
        "Expected an unreported closed failure"
    );
    ensure!(
        session["cleanup"] == "restored"
            && session["qualified"] == false
            && session["boundary_qualified"] == false
            && session["worker_result"].is_null(),
        "Failed roles were promoted to a clean lifecycle"
    );
    ensure!(
        session["source_tree_sha256"] == env!("EMUMEE_BUILD_SOURCE_SHA256")
            && session["bundle_receipt"]["source_tree_sha256"]
                == env!("EMUMEE_BUILD_SOURCE_SHA256"),
        "Failed role build authority changed"
    );
    let control = root.join("control");
    let output = root.join("worker");
    let raw_config = read_regular(&control.join("config.json"), 4096, Some(&control))?;
    ensure!(
        session["request_sha256"] == report_bundle::digest(&raw_config),
        "Failed controller config commitment changed"
    );
    let witness = read_regular(&output.join("worker-containment.json"), 4096, Some(&output))?;
    let containment: Value = serde_json::from_slice(&witness)?;
    let ready: Value = serde_json::from_slice(&read_regular(
        &output.join("worker-ready.json"),
        16 * 1024,
        Some(&output),
    )?)?;
    ensure!(
        ready["request_sha256"] == worker.request_sha256()
            && ready["installation"] == worker.receipt()
            && ready["private_fixture_denied"] == true
            && ready["private_journal_denied"] == true
            && ready["cleanup_plan_read_denied"] == true
            && ready["containment"] == containment
            && containment["app_container"] == true
            && containment["job_object"] == true
            && containment["child_process_blocked"] == true
            && containment["network_capabilities"] == 0,
        "Failed role installation/containment changed"
    );
    for name in [
        "plan-result.json",
        "plan-checkpoint.json",
        "worker-summary.json",
        "engine-report.json",
    ] {
        ensure!(
            !output.join(name).exists(),
            "Pre-checkpoint fault acquired a guest report"
        );
    }
    let raw = read_regular(
        &root.join("private/network-broker.journal"),
        emumee_core::broker_journal::MAX_JOURNAL_BYTES,
        Some(root),
    )?;
    let journal = emumee_core::broker_journal::recover(&raw)?;
    ensure!(
        serde_json::to_value(&journal)? == session["journal"] && !journal.closed,
        "Failed role private journal changed/closed unexpectedly"
    );
    ensure!(
        journal.events.first()
            == Some(
                &json!({"event":"broker_started","mode":"offline_replay","role":"closed_plan_broker","config_sha256":report_bundle::digest(&raw_config),"request_sha256":config.request_sha256,"plan_sha256":config.plan_sha256,"fixture_sha256":config.fixture_sha256})
            ),
        "Failed broker start binding differs"
    );
    let attempts = journal
        .events
        .iter()
        .filter(|e| e["event"] == "http_request_attempt")
        .count();
    if fault.broker_failure() {
        ensure!(
            session["reason"] == "broker_failed"
                && session["broker_exit"] == if fault == Fault::BrokerDeath { 23 } else { 24 }
                && session["worker_exit"].as_u64().is_some_and(|n| n != 0)
                && attempts == 1,
            "Fixed broker failure/attempt differs"
        );
        ensure!(
            (journal.unrecovered_bytes > 0) == (fault == Fault::BrokerPartial),
            "Fixed broker partial-tail evidence differs"
        );
    } else {
        ensure!(
            session["reason"].as_str().is_some_and(
                |s| s.starts_with("session_error: Worker output exceeds directories limit:")
            ) && session["worker_exit"].as_u64().is_some_and(|n| n != 0)
                && attempts == 0
                && journal.unrecovered_bytes == 0,
            "Real directory watchdog evidence differs"
        );
        let error = emumee_platform::windows::inspect_output(
            root,
            &[],
            emumee_platform::windows::OutputLimits {
                max_bytes: plan_runtime::MAX_OUTPUT,
                max_entries: 22000,
                max_directories: 64,
                max_depth: 40,
            },
        )
        .err()
        .context("Retained directory overrun disappeared")?;
        ensure!(
            error
                .downcast_ref::<emumee_platform::windows::OutputLimitExceeded>()
                .is_some_and(|e| e.dimension == "directories"),
            "Output evidence is not the selected real quota failure"
        );
    }
    for name in [
        "summary.json",
        "manifest.json",
        "engine-report.json",
        "artifact-checkpoint.json",
    ] {
        ensure!(
            !root.join(name).exists(),
            "Unknown guest execution was promoted to a final report"
        );
    }
    let proof = json!({"schema":"emumee.closed-plan-fault.v1","verified":true,"fault":fault,"status":"failed","analysis_completed":false,"guest_entry_return":null,"instruction_count":null,"instruction_count_available":false,"checkpoint_recovered":false,"broker_complete":false,"broker_attempts":attempts,"journal_unrecovered_bytes":journal.unrecovered_bytes,"journal_sha256":report_bundle::digest(&raw),"request_sha256":worker.request_sha256(),"plan_sha256":request.plan_sha256,"input_sha256":report_bundle::digest(worker.input()),"parent_installation":parent.receipt(),"source_tree_sha256":session["source_tree_sha256"],"controller_sha256":session["bundle_receipt"]["controller_sha256"],"worker_sha256":session["bundle_receipt"]["worker_sha256"],"scope":"Parent verified actual failed role lifecycle and private partial journal; unknown guest state remains unreported, general run remains gated"});
    let raw = report_bundle::bounded_json(&proof, 64 * 1024)?;
    match delivery {
        Delivery::PublishFresh => save_new(&root.join("plan-fault-evidence.json"), &raw)?,
        Delivery::VerifyExisting => ensure!(
            read_regular(
                &root.join("plan-fault-evidence.json"),
                64 * 1024,
                Some(root)
            )? == raw,
            "Failed role delivery changed"
        ),
    }
    Ok(proof)
}
fn selected_fault(root: &Path, session: &Value, delivery: Delivery) -> Result<Value> {
    let (prepared, _, _) = acquire(root)?;
    let fault = prepared.request().fault;
    ensure!(
        !fault.is_none() && !fault.controller_exit(),
        "Expected a fixed finalized fault role"
    );
    if fault.broker_failure() || fault == Fault::OutputDirectories {
        no_draft_fault(root, session, delivery)
    } else {
        finalize_selected(root, session, delivery, true)
    }
}
pub fn run_fault(root: &Path, fault: Fault, arch: emumee_core::pe::Architecture) -> Result<Value> {
    let session = super::broker::installed_plan_fault(root, fault, arch)?;
    let result = match selected_fault(root, &session, Delivery::PublishFresh) {
        Ok(v) => v,
        Err(error) => {
            json!({"verified":false,"analysis_completed":false,"reason":format!("{error:#}"),"scope":"Failed fault evidence remains quarantined"})
        }
    };
    // Directory-count refusal intentionally preserves over-limit owned directories
    // as evidence; the real watchdog already stopped both roles before cleanup.
    // Every other case still receives the final standard bounded inspection.
    if fault != Fault::OutputDirectories {
        emumee_platform::windows::inspect_output(
            root,
            &[],
            emumee_platform::windows::OutputLimits {
                max_bytes: plan_runtime::MAX_OUTPUT,
                max_entries: 22000,
                max_directories: 64,
                max_depth: 40,
            },
        )?;
    }
    save_new(
        &root.join("plan-fault-verification.json"),
        &serde_json::to_vec_pretty(&result)?,
    )?;
    Ok(result)
}
pub fn inspect_fault(root: &Path) -> Result<Value> {
    let session: Value = serde_json::from_slice(&read_regular(
        &root.join("broker-session.json"),
        128 * 1024 * 1024,
        Some(root),
    )?)?;
    selected_fault(root, &session, Delivery::VerifyExisting)
}
#[cfg(test)]
mod fault_tests {
    use super::*;
    #[test]
    fn checkpoint_recovery_refuses_clean_exit_wrong_fault_and_failed_cleanup() {
        let crash = json!({"cleanup":"restored","boundary_qualified":false,"qualified":false,"broker_exit":0,"reason":"worker_failed","worker_exit":41});
        assert!(verify_checkpoint_stop(Fault::CrashAfterCheckpoint, &crash).is_ok());
        assert!(verify_checkpoint_stop(Fault::TimeoutAfterCheckpoint, &crash).is_err());
        for (field, value) in [
            ("cleanup", json!("pending")),
            ("boundary_qualified", json!(true)),
            ("qualified", json!(true)),
            ("broker_exit", json!(24)),
            ("worker_exit", json!(0)),
            ("reason", json!("exited")),
        ] {
            let mut altered = crash.clone();
            altered[field] = value;
            assert!(
                verify_checkpoint_stop(Fault::CrashAfterCheckpoint, &altered).is_err(),
                "{field}"
            );
        }
        let timeout = json!({"cleanup":"restored","boundary_qualified":false,"qualified":false,"broker_exit":0,"reason":"session_error: Broker session exceeded deadline","worker_exit":1});
        assert!(verify_checkpoint_stop(Fault::TimeoutAfterCheckpoint, &timeout).is_ok());
        assert!(verify_checkpoint_stop(Fault::None, &timeout).is_err());
    }
}

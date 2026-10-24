//! Two distinct contained read probes for parent public/private staging.
//! The generated RPC probe calls the offline broker after public preflight;
//! none of these roles enters a guest or calls the emulation engine.
use super::save_new;
use anyhow::{Context, Result, ensure};
use emumee_core::{
    analysis_plan::MAX_PLAN_BYTES,
    driver_capture_reports::Projection,
    general_broker_private_attestation::{Claim, MAX_CLAIM},
    general_execution_commitment::{MAX_REQUEST, Request},
    general_worker_public_preflight::verify_public_view,
    report_bundle::digest,
};
use emumee_platform::windows::{open_pinned_journal, prepare_worker, read_regular};
use serde_json::json;
use std::{fs::File, io::Write, path::Path};

fn access_denied(path: &Path) -> Result<bool> {
    match File::open(path) {
        Ok(_) => Ok(false),
        Err(error) if error.raw_os_error() == Some(5) => Ok(true),
        Err(error) => Err(error).context("Cross-role read did not return access denied"),
    }
}

pub(crate) fn public_probe(root: &Path, expected: &str) -> Result<()> {
    let containment = prepare_worker()?;
    let root = std::path::absolute(root)?;
    let control = root.join("control");
    let raw = read_regular(&control.join("request.json"), MAX_REQUEST, Some(&control))?;
    ensure!(digest(&raw) == expected, "Public transport digest differs");
    let request = Request::parse(&raw).map_err(anyhow::Error::msg)?;
    let plan = read_regular(&control.join("plan.json"), MAX_PLAN_BYTES, Some(&control))?;
    let count = request.public_inputs.len() + usize::from(request.broker_private_fixture.is_some());
    let mut slots = Vec::with_capacity(count);
    for index in 0..count {
        if request
            .broker_private_fixture
            .as_ref()
            .is_some_and(|private| private.index as usize == index)
        {
            slots.push(None);
            continue;
        }
        let committed = request
            .public_inputs
            .iter()
            .find(|item| item.index as usize == index)
            .context("Public physical slot commitment missing")?;
        let bytes = read_regular(
            &control.join("inputs").join(format!("{index:04}.bin")),
            usize::try_from(committed.size)?,
            Some(&control),
        )?;
        slots.push(Some(bytes));
    }
    let view = slots
        .iter()
        .map(|value| value.as_deref())
        .collect::<Vec<_>>();
    let preflight = verify_public_view(&raw, expected, &plan, &view).map_err(anyhow::Error::msg)?;
    let target = request
        .public_inputs
        .iter()
        .find(|slot| slot.id == request.target_input_id)
        .context("Public target commitment absent")?;
    let target_bytes = slots
        .get(target.index as usize)
        .and_then(Option::as_deref)
        .context("Public target bytes absent")?;
    let projection = Projection::from_bytes(target_bytes)?;
    ensure!(
        projection.sha256() == target.sha256 && projection.size() == target.size,
        "Public target projection differs from commitment"
    );
    ensure!(
        !preflight.guest_admission && !preflight.guest_executed,
        "Public preflight claimed guest admission"
    );
    let private_denied = if request.broker_private_fixture.is_some() {
        let private = root.join("private");
        let fixture = access_denied(&private.join("http-fixtures.json"))?;
        let claim = access_denied(&private.join("claim.json"))?;
        let journal = access_denied(&private.join("network-broker.journal"))?;
        ensure!(
            fixture && claim && journal,
            "Public worker read broker-private data"
        );
        true
    } else {
        ensure!(
            !root.join("private/http-fixtures.json").exists(),
            "Offline deny has private fixture"
        );
        true
    };
    let result = json!({
        "schema":1,"role":"general_public_read_probe_v1","request_sha256":expected,
        "containment":containment,"preflight":preflight,
        "broker_private_read_denied":private_denied,
        "execution_authorized":false,"engine_applied":false,"guest_executed":false,
    });
    save_new(
        &root.join("worker/public-boundary.json"),
        &serde_json::to_vec(&result)?,
    )?;
    save_new(
        &root.join("worker/public-target-projection.json"),
        &serde_json::to_vec(&projection)?,
    )?;
    Ok(())
}

pub(crate) fn private_probe(root: &Path, expected_claim: &str) -> Result<()> {
    let containment = prepare_worker()?;
    let root = std::path::absolute(root)?;
    let private = root.join("private");
    let raw = read_regular(&private.join("claim.json"), MAX_CLAIM, Some(&private))?;
    ensure!(
        digest(&raw) == expected_claim,
        "Private claim transport digest differs"
    );
    let claim = Claim::parse(&raw).map_err(anyhow::Error::msg)?;
    let fixture = read_regular(
        &private.join("http-fixtures.json"),
        usize::try_from(claim.fixture.size)?,
        Some(&private),
    )?;
    let receipt = claim.inspect(&raw, &fixture).map_err(anyhow::Error::msg)?;
    ensure!(
        !receipt.guest_admission && !receipt.guest_executed,
        "Private inspection claimed guest admission"
    );
    let target_denied = access_denied(&root.join("control/inputs/0000.bin"))?;
    let plan_denied = access_denied(&root.join("control/plan.json"))?;
    let request_denied = access_denied(&root.join("control/request.json"))?;
    ensure!(
        target_denied && plan_denied && request_denied,
        "Private broker read public target or plan"
    );
    let journal_path = private.join("network-broker.journal");
    ensure!(
        read_regular(&journal_path, 0, Some(&private))?.is_empty(),
        "Private journal not empty at start"
    );
    let mut journal = open_pinned_journal(&journal_path, &private)?;
    let start = claim
        .expected_journal_start(&raw)
        .map_err(anyhow::Error::msg)?;
    journal.write_all(&start)?;
    journal.sync_all()?;
    let result = json!({
        "schema":1,"role":"general_private_read_probe_v1",
        "claim_sha256":expected_claim,"containment":containment,"inspection":receipt,
        "public_target_read_denied":true,"journal_start_sha256":digest(&start),
        "execution_authorized":false,"engine_applied":false,"guest_executed":false,
    });
    save_new(
        &root.join("broker/private-boundary.json"),
        &serde_json::to_vec(&result)?,
    )?;
    Ok(())
}

/// One generated offline HTTP request over the existing bounded pinned-file
/// RPC transport. The public role never reads the broker-private fixture.
pub(crate) fn rpc_client(root: &Path, request_hash: &str, expected_probe: &str) -> Result<()> {
    use emumee_core::{
        broker::Operation,
        general_rpc_probe::{MAX_PROBE, Probe},
    };
    public_probe(root, request_hash)?;
    let containment = prepare_worker()?;
    let root = std::path::absolute(root)?;
    let control = root.join("control");
    let raw = read_regular(&control.join("rpc-probe.json"), MAX_PROBE, Some(&control))?;
    ensure!(
        digest(&raw) == expected_probe,
        "General RPC probe transport changed"
    );
    let probe = Probe::parse(&raw).map_err(anyhow::Error::msg)?;
    ensure!(
        probe.request_sha256 == request_hash,
        "General RPC request binding differs"
    );
    let ipc = root.join("ipc");
    let request_overwrite_denied = std::fs::OpenOptions::new()
        .write(true)
        .open(ipc.join("requests.bin"))
        .err()
        .is_some_and(|error| error.raw_os_error() == Some(5));
    let response_append_denied = std::fs::OpenOptions::new()
        .append(true)
        .open(ipc.join("responses.bin"))
        .err()
        .is_some_and(|error| error.raw_os_error() == Some(5));
    let ipc_creation_denied = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(ipc.join("injected.bin"))
        .err()
        .is_some_and(|error| error.raw_os_error() == Some(5));
    ensure!(
        request_overwrite_denied && response_append_denied && ipc_creation_denied,
        "General RPC public IPC permissions are too broad"
    );
    let (mut rpc, close) = super::broker::plan_connection(&root)?;
    let reply = rpc
        .call(Operation::Http {
            request: probe.http_request.clone(),
        })
        .map_err(anyhow::Error::msg)?;
    ensure!(reply.ok, "General offline RPC was denied");
    let response_hash = probe
        .check_reply(reply.value.as_ref().context("General RPC reply absent")?)
        .map_err(anyhow::Error::msg)?;
    drop(rpc);
    close.close()?;
    let result = json!({
        "schema":1,"role":"general_rpc_public_client_v1",
        "request_sha256":request_hash,"probe_sha256":expected_probe,
        "claim_sha256":probe.claim_sha256,"response_sha256":response_hash,
        "expected_status":probe.expected_status,"rule_id":probe.rule_id,
        "containment":containment,"rpc_closed":true,
        "request_overwrite_denied":request_overwrite_denied,
        "response_append_denied":response_append_denied,
        "ipc_creation_denied":ipc_creation_denied,
        "guest_admission":false,"engine_applied":false,"guest_executed":false,
    });
    save_new(
        &root.join("worker/general-rpc-result.json"),
        &serde_json::to_vec(&result)?,
    )?;
    Ok(())
}

//! Parent readback of a staged general-driver request and broker journal.
//! This is evidence binding, never a guest permit or complete Driver128 report.
use crate::{
    analysis_plan::PreparedIntake, broker_journal, driver_capture_reports::Projection,
    general_broker_private_attestation::Claim, general_execution_commitment::Request,
    general_rpc_probe::Probe, general_worker_public_preflight::verify_public_view,
    networkfixtures::Fixtures, report_bundle::digest,
};
use serde::Serialize;
use serde_json::json;

#[derive(Clone, Debug, Serialize)]
pub struct Receipt {
    pub schema: u32,
    pub profile: &'static str,
    pub request_sha256: String,
    pub raw_plan_sha256: String,
    pub target_sha256: String,
    pub target_projection_sha256: String,
    pub private_claim_sha256: String,
    pub fixture_sha256: String,
    pub probe_sha256: String,
    pub journal_sha256: String,
    pub resolved_plan_sha256: String,
    pub private_journal_events: usize,
    pub complete_driver128_report_binding: bool,
    pub contained_witnesses_independently_verified: bool,
    pub guest_admission: bool,
    pub engine_applied: bool,
    pub guest_executed: bool,
}

pub struct StagedBytes<'a> {
    pub request: &'a [u8],
    pub plan: &'a [u8],
    pub target: &'a [u8],
    pub claim: &'a [u8],
    pub fixture: &'a [u8],
    pub probe: &'a [u8],
    pub journal: &'a [u8],
    /// Serialized projection produced by the isolated public role.
    pub public_projection: &'a [u8],
}

/// Reconstruct the resolved private commitment and check every staged digest,
/// the public role's bounded target projection, and the complete private RPC
/// journal. The caller must separately attest file identity and containment.
pub fn inspect(bytes: &StagedBytes<'_>) -> Result<Receipt, &'static str> {
    let request = Request::parse(bytes.request)?;
    let request_sha = digest(bytes.request);
    let plan_sha = digest(bytes.plan);
    let intake = PreparedIntake::prepare(
        bytes.plan.to_vec(),
        vec![bytes.target.to_vec(), bytes.fixture.to_vec()],
    )
    .map_err(|_| "General private plan or physical input invalid")?;
    request.verify(&intake)?;
    if request.operation != "commit_only" || request.execution_authorized {
        return Err("General private request became executable");
    }
    let public = verify_public_view(
        bytes.request,
        &request_sha,
        bytes.plan,
        &[Some(bytes.target), None],
    )?;
    if !public.broker_private_fixture_pending || public.guest_admission {
        return Err("General private public view lacks pending fixture");
    }
    let target = request
        .public_inputs
        .iter()
        .find(|slot| slot.id == request.target_input_id && slot.index == 0)
        .ok_or("General private target slot is not public index zero")?;
    if target.sha256 != digest(bytes.target) || target.size != bytes.target.len() as u64 {
        return Err("General private public target differs");
    }
    let projection = Projection::from_bytes(bytes.target)
        .map_err(|_| "General private target projection invalid")?;
    let public_projection: Projection = serde_json::from_slice(bytes.public_projection)
        .map_err(|_| "General public projection schema invalid")?;
    if public_projection != projection
        || public_projection.sha256() != target.sha256
        || public_projection.size() != target.size
    {
        return Err("General public projection differs from staged target");
    }
    let claim = Claim::parse(bytes.claim)?;
    claim.verify_against_request(bytes.request, &intake)?;
    let private = claim.inspect(bytes.claim, bytes.fixture)?;
    if private.request_sha256 != request_sha
        || private.resolved_plan_sha256 != request.resolved_plan_sha256
    {
        return Err("General private receipt differs from staged request");
    }
    let probe = Probe::parse(bytes.probe)?;
    if probe.request_sha256 != request_sha || probe.claim_sha256 != digest(bytes.claim) {
        return Err("General private RPC probe identity differs");
    }
    let fixtures =
        Fixtures::parse(bytes.fixture).map_err(|_| "General private RPC fixture invalid")?;
    let rule = fixtures
        .rules()
        .iter()
        .find(|rule| rule.id == probe.rule_id)
        .ok_or("General private RPC rule absent")?;
    let expected_probe = Probe::from_rule(request_sha.clone(), digest(bytes.claim), rule)?;
    if probe != expected_probe {
        return Err("General private RPC probe differs from fixture rule");
    }
    let start = claim.expected_journal_start(bytes.claim)?;
    if !bytes.journal.starts_with(&start) {
        return Err("General private journal start differs from claim");
    }
    let recovered = broker_journal::recover(bytes.journal)
        .map_err(|_| "General private journal exceeds bound")?;
    if !recovered.closed || recovered.stop_reason.is_some() || recovered.events.len() != 7 {
        return Err("General private journal did not close exactly");
    }
    let events = &recovered.events;
    if events[0]
        != json!({
            "event":"general_broker_fixture_verified",
            "request_sha256":request_sha,
            "claim_sha256":digest(bytes.claim),
            "fixture_sha256":digest(bytes.fixture),
        })
        || events[1] != json!({"event":"request","id":1,"op":"http"})
        || events[2]
            != json!({
                "event":"http_request_attempt","id":1,
                "url":probe.http_request.url,"method":probe.http_request.method,
                "chunked":probe.http_request.chunked,
                "header_count":probe.http_request.headers.len(),
                "body_size":probe.http_request.body.len(),
                "body_sha256":digest(&probe.http_request.body),
            })
        || events[3]
            != json!({
                "event":"network_fixture_match","id":probe.rule_id,"url":probe.http_request.url,
            })
        || events[4]
            != json!({
                "event":"http_request","source":"fixture","url":probe.http_request.url,
                "status":probe.expected_status,"size":rule.response.body.len(),
                "sha256":digest(&rule.response.body),
            })
        || events[5] != json!({"event":"request","id":2,"op":"close"})
        || events[6] != json!({"event":"broker_closed"})
    {
        return Err("General private journal event binding differs");
    }
    Ok(Receipt {
        schema: 1,
        profile: "general_driver_private_preflight_v1",
        request_sha256: request_sha,
        raw_plan_sha256: plan_sha,
        target_sha256: target.sha256.clone(),
        target_projection_sha256: digest(bytes.public_projection),
        private_claim_sha256: digest(bytes.claim),
        fixture_sha256: digest(bytes.fixture),
        probe_sha256: digest(bytes.probe),
        journal_sha256: digest(bytes.journal),
        resolved_plan_sha256: request.resolved_plan_sha256,
        private_journal_events: events.len(),
        complete_driver128_report_binding: false,
        contained_witnesses_independently_verified: false,
        guest_admission: false,
        engine_applied: false,
        guest_executed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analysis_plan::Arch, plan_runtime::Case};
    use serde_json::{Value, json};

    struct Generated {
        request: Vec<u8>,
        plan: Vec<u8>,
        target: Vec<u8>,
        claim: Vec<u8>,
        fixture: Vec<u8>,
        probe: Vec<u8>,
        journal: Vec<u8>,
        projection: Vec<u8>,
    }

    impl Generated {
        fn view(&self) -> StagedBytes<'_> {
            StagedBytes {
                request: &self.request,
                plan: &self.plan,
                target: &self.target,
                claim: &self.claim,
                fixture: &self.fixture,
                probe: &self.probe,
                journal: &self.journal,
                public_projection: &self.projection,
            }
        }
    }

    fn generated() -> Generated {
        let mut kernel = Case::Kernel17.generated(Arch::X64).unwrap();
        let mut plan: Value = serde_json::from_slice(&kernel.plan).unwrap();
        plan["target"]["service_name"] = json!("TestDrv");
        let fixture = Case::NativeReplay.generated(Arch::X64).unwrap().fixtures;
        plan["inputs"].as_array_mut().unwrap().push(json!({
            "id":"offline","name":"offline.json","roles":["offline_fixtures"],
            "mount":{"kind":"not_mounted"},"size":fixture.len(),"sha256":digest(&fixture)
        }));
        plan["network"] = json!({"kind":"offline_exact_replay","input":"offline"});
        kernel.inputs.push(fixture.clone());
        let plan = serde_json::to_vec(&plan).unwrap();
        let intake = PreparedIntake::prepare(plan.clone(), kernel.inputs.clone()).unwrap();
        let request = Request::from_intake(&intake, "20261019T120000Z-12345678".into()).unwrap();
        let request = serde_json::to_vec(&request).unwrap();
        let claim = Claim::from_verified_request(&request, &intake).unwrap();
        let claim_raw = serde_json::to_vec(&claim).unwrap();
        let fixtures = Fixtures::parse(&fixture).unwrap();
        let rule = &fixtures.rules()[0];
        let probe = Probe::from_rule(digest(&request), digest(&claim_raw), rule).unwrap();
        let probe_raw = serde_json::to_vec(&probe).unwrap();
        let mut journal = claim.expected_journal_start(&claim_raw).unwrap();
        let events = [
            json!({"event":"request","id":1,"op":"http"}),
            json!({"event":"http_request_attempt","id":1,"url":probe.http_request.url,
                "method":probe.http_request.method,"chunked":probe.http_request.chunked,
                "header_count":probe.http_request.headers.len(),
                "body_size":probe.http_request.body.len(),
                "body_sha256":digest(&probe.http_request.body)}),
            json!({"event":"network_fixture_match","id":probe.rule_id,"url":probe.http_request.url}),
            json!({"event":"http_request","source":"fixture","url":probe.http_request.url,
                "status":probe.expected_status,"size":rule.response.body.len(),
                "sha256":digest(&rule.response.body)}),
            json!({"event":"request","id":2,"op":"close"}),
            json!({"event":"broker_closed"}),
        ];
        for event in events {
            journal.extend(serde_json::to_vec(&event).unwrap());
            journal.push(b'\n');
        }
        let projection =
            serde_json::to_vec(&Projection::from_bytes(&kernel.inputs[0]).unwrap()).unwrap();
        Generated {
            request,
            plan,
            target: kernel.inputs[0].clone(),
            claim: claim_raw,
            fixture,
            probe: probe_raw,
            journal,
            projection,
        }
    }

    #[test]
    fn binds_generated_private_bytes_and_journal_without_guest_authority() {
        let sample = generated();
        let receipt = inspect(&sample.view()).unwrap();
        assert_eq!(receipt.private_journal_events, 7);
        assert_eq!(receipt.target_sha256, digest(&sample.target));
        assert!(!receipt.complete_driver128_report_binding);
        assert!(!receipt.contained_witnesses_independently_verified);
        assert!(!receipt.guest_admission && !receipt.engine_applied && !receipt.guest_executed);
    }

    #[test]
    fn rejects_request_plan_target_claim_fixture_probe_projection_and_journal_tampering() {
        let baseline = generated();
        for field in 0..8 {
            let mut changed = generated();
            let data = match field {
                0 => &mut changed.request,
                1 => &mut changed.plan,
                2 => &mut changed.target,
                3 => &mut changed.claim,
                4 => &mut changed.fixture,
                5 => &mut changed.probe,
                6 => &mut changed.projection,
                _ => &mut changed.journal,
            };
            data[0] ^= 1;
            assert!(
                inspect(&changed.view()).is_err(),
                "tampered field {field} accepted"
            );
        }
        assert!(inspect(&baseline.view()).is_ok());
    }

    #[test]
    fn rejects_parseable_cross_boundary_identity_and_journal_status_changes() {
        let mut changed = generated();
        let mut request: Value = serde_json::from_slice(&changed.request).unwrap();
        request["resolved_plan_sha256"] = json!("0".repeat(64));
        changed.request = serde_json::to_vec(&request).unwrap();
        assert!(inspect(&changed.view()).is_err());

        let mut changed = generated();
        let mut lines = changed
            .journal
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        lines[2]["injected_extra_field"] = json!(true);
        changed.journal = lines
            .iter()
            .flat_map(|event| {
                let mut line = serde_json::to_vec(event).unwrap();
                line.push(b'\n');
                line
            })
            .collect();
        assert!(inspect(&changed.view()).is_err());

        let mut changed = generated();
        let mut claim: Value = serde_json::from_slice(&changed.claim).unwrap();
        claim["request_sha256"] = json!("1".repeat(64));
        changed.claim = serde_json::to_vec(&claim).unwrap();
        assert!(inspect(&changed.view()).is_err());

        let mut changed = generated();
        let mut projection: Value = serde_json::from_slice(&changed.projection).unwrap();
        projection["sha256"] = json!("2".repeat(64));
        changed.projection = serde_json::to_vec(&projection).unwrap();
        assert!(inspect(&changed.view()).is_err());

        let mut changed = generated();
        let mut probe: Value = serde_json::from_slice(&changed.probe).unwrap();
        probe["claim_sha256"] = json!("3".repeat(64));
        changed.probe = serde_json::to_vec(&probe).unwrap();
        assert!(inspect(&changed.view()).is_err());

        let mut changed = generated();
        let mut lines = changed
            .journal
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        lines[4]["status"] = json!(599);
        changed.journal = lines
            .iter()
            .flat_map(|event| {
                let mut line = serde_json::to_vec(event).unwrap();
                line.push(b'\n');
                line
            })
            .collect();
        assert!(inspect(&changed.view()).is_err());
    }
}

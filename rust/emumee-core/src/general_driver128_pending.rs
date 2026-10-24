//! Cross-role Driver128 identity readback while large-driver resolution is closed.
//! The private claim's resolved hashes remain claims, never admission authority.
use crate::{
    broker_journal::MAX_JOURNAL_BYTES, driver_capture_reports::Projection,
    general_broker_private_attestation::Claim, general_execution_commitment::Request,
    general_worker_public_preflight::preflight_driver128_public_report, report_bundle::digest,
};
use serde::Serialize;

pub const MAX_PUBLIC_PROJECTION: usize = 1024 * 1024;

pub struct StagedEvidence<'a> {
    pub request: &'a [u8],
    pub plan: &'a [u8],
    pub target: &'a [u8],
    pub public_projection: &'a [u8],
    pub private_claim: &'a [u8],
    pub private_fixture: &'a [u8],
    pub journal: &'a [u8],
}

#[derive(Clone, Debug, Serialize)]
pub struct PendingReceipt {
    pub schema: u32,
    pub profile: &'static str,
    pub request_sha256: String,
    pub raw_plan_sha256: String,
    pub target_sha256: String,
    pub target_projection_sha256: String,
    pub target_image_bytes: u64,
    pub claim_sha256: String,
    pub fixture_sha256: String,
    pub journal_sha256: String,
    pub journal_start_sha256: String,
    pub private_fixture_inspected: bool,
    pub raw_plan_and_public_target_verified: bool,
    pub resolved_plan_independently_verified: bool,
    pub resolved_report_hashes_independently_verified: bool,
    pub complete_driver128_report_binding: bool,
    pub contained_witnesses_independently_verified: bool,
    pub complete_journal_verified: bool,
    pub guest_admission: bool,
    pub engine_applied: bool,
    pub guest_executed: bool,
}

/// Bind the worker-visible target/projection and broker-visible fixture/claim
/// to the same raw request, then stop. This cannot resolve large-driver plans,
/// validate claimed resolved capture/report hashes, or issue a report Binding.
pub fn inspect_pending(evidence: &StagedEvidence<'_>) -> Result<PendingReceipt, &'static str> {
    if evidence.public_projection.len() > MAX_PUBLIC_PROJECTION
        || evidence.journal.len() > MAX_JOURNAL_BYTES
    {
        return Err("Driver128 pending projection or journal exceeds bound");
    }
    let request_sha = digest(evidence.request);
    let request = Request::parse(evidence.request)?;
    let public = preflight_driver128_public_report(
        evidence.request,
        &request_sha,
        evidence.plan,
        &[Some(evidence.target), None],
    )?;
    if request.execution_authorized
        || !public.public_preflight.broker_private_fixture_pending
        || public.public_preflight.resolved_plan_independently_verified
        || public.complete_report_binding
        || public.guest_admission
    {
        return Err("Driver128 pending public evidence claimed admission");
    }
    let projection = Projection::from_bytes(evidence.target)
        .map_err(|_| "Driver128 pending target projection invalid")?;
    let observed: Projection = serde_json::from_slice(evidence.public_projection)
        .map_err(|_| "Driver128 pending public projection schema invalid")?;
    if projection != observed
        || observed.sha256() != public.target_input_sha256
        || observed.size() != public.target_input_bytes
    {
        return Err("Driver128 pending public projection differs from target");
    }
    let private = request
        .broker_private_fixture
        .as_ref()
        .ok_or("Driver128 pending broker fixture absent")?;
    let claim = Claim::parse(evidence.private_claim)?;
    if claim.request_sha256 != request_sha
        || claim.resolved_plan_sha256 != request.resolved_plan_sha256
        || &claim.fixture != private
    {
        return Err("Driver128 pending private claim differs from request");
    }
    let inspected = claim.inspect(evidence.private_claim, evidence.private_fixture)?;
    if !inspected.private_bytes_inspected
        || inspected.request_sha256 != request_sha
        || inspected.original_sha256 != digest(evidence.private_fixture)
        || inspected.guest_admission
        || inspected.guest_executed
    {
        return Err("Driver128 pending fixture inspection differs");
    }
    let start = claim.expected_journal_start(evidence.private_claim)?;
    if !evidence.journal.starts_with(&start) {
        return Err("Driver128 pending private journal start differs");
    }
    Ok(PendingReceipt {
        schema: 1,
        profile: "general_driver128_pending_v1",
        request_sha256: request_sha,
        raw_plan_sha256: digest(evidence.plan),
        target_sha256: public.target_input_sha256,
        target_projection_sha256: digest(evidence.public_projection),
        target_image_bytes: public.target_image_bytes,
        claim_sha256: digest(evidence.private_claim),
        fixture_sha256: digest(evidence.private_fixture),
        journal_sha256: digest(evidence.journal),
        journal_start_sha256: digest(&start),
        private_fixture_inspected: true,
        raw_plan_and_public_target_verified: true,
        resolved_plan_independently_verified: false,
        resolved_report_hashes_independently_verified: false,
        complete_driver128_report_binding: false,
        contained_witnesses_independently_verified: false,
        complete_journal_verified: false,
        guest_admission: false,
        engine_applied: false,
        guest_executed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        analysis_plan::{Arch, PreparedIntake},
        driver_capture_reports::Binding,
        plan_runtime::Case,
    };
    use serde_json::{Value, json};

    struct Generated {
        request: Vec<u8>,
        plan: Vec<u8>,
        target: Vec<u8>,
        projection: Vec<u8>,
        claim: Vec<u8>,
        fixture: Vec<u8>,
        journal: Vec<u8>,
    }
    impl Generated {
        fn view(&self) -> StagedEvidence<'_> {
            StagedEvidence {
                request: &self.request,
                plan: &self.plan,
                target: &self.target,
                public_projection: &self.projection,
                private_claim: &self.claim,
                private_fixture: &self.fixture,
                journal: &self.journal,
            }
        }
    }

    fn generated() -> (Generated, PreparedIntake) {
        let mut kernel = Case::Kernel17.generated(Arch::X64).unwrap();
        let mut plan: Value = serde_json::from_slice(&kernel.plan).unwrap();
        plan["target"]["service_name"] = json!("TestDrv");
        let fixture = Case::NativeReplay.generated(Arch::X64).unwrap().fixtures;
        plan["inputs"].as_array_mut().unwrap().push(json!({
            "id":"offline","name":"offline.json","roles":["offline_fixtures"],
            "mount":{"kind":"not_mounted"},"size":fixture.len(),"sha256":digest(&fixture),
        }));
        plan["network"] = json!({"kind":"offline_exact_replay","input":"offline"});
        kernel.inputs.push(fixture.clone());
        let legacy_plan = serde_json::to_vec(&plan).unwrap();
        let legacy_intake = PreparedIntake::prepare(legacy_plan, kernel.inputs.clone()).unwrap();
        let mut request =
            Request::from_intake(&legacy_intake, "20261019T120000Z-12345678".into()).unwrap();
        let legacy_request = serde_json::to_vec(&request).unwrap();
        let mut claim = Claim::from_verified_request(&legacy_request, &legacy_intake).unwrap();

        plan["capture"]["profile"] = json!("large_driver128_v1");
        plan["reports"]["profile"] = json!("large_driver_v1");
        let raw_plan = serde_json::to_vec(&plan).unwrap();
        assert!(PreparedIntake::prepare(raw_plan.clone(), kernel.inputs.clone()).is_err());
        request.raw_plan_sha256 = digest(&raw_plan);
        request.report_profile = "large_driver_v1".into();
        let raw_request = serde_json::to_vec(&request).unwrap();
        claim.request_sha256 = digest(&raw_request);
        let raw_claim = serde_json::to_vec(&claim).unwrap();
        let journal = claim.expected_journal_start(&raw_claim).unwrap();
        let projection =
            serde_json::to_vec(&Projection::from_bytes(&kernel.inputs[0]).unwrap()).unwrap();
        (
            Generated {
                request: raw_request,
                plan: raw_plan,
                target: kernel.inputs[0].clone(),
                projection,
                claim: raw_claim,
                fixture,
                journal,
            },
            legacy_intake,
        )
    }

    #[test]
    fn generated_large_profile_combines_public_and_private_identity_only() {
        let (sample, _) = generated();
        let receipt = inspect_pending(&sample.view()).unwrap();
        assert_eq!(receipt.target_sha256, digest(&sample.target));
        assert_eq!(receipt.fixture_sha256, digest(&sample.fixture));
        assert!(receipt.target_image_bytes > 0);
        assert!(receipt.private_fixture_inspected && receipt.raw_plan_and_public_target_verified);
        assert!(!receipt.resolved_plan_independently_verified);
        assert!(!receipt.resolved_report_hashes_independently_verified);
        assert!(!receipt.complete_driver128_report_binding);
        assert!(!receipt.contained_witnesses_independently_verified);
        assert!(!receipt.complete_journal_verified);
        assert!(!receipt.guest_admission && !receipt.engine_applied && !receipt.guest_executed);
    }

    #[test]
    fn raw_byte_or_semantic_cross_role_tampering_never_becomes_pending_evidence() {
        for field in 0..7 {
            let (mut sample, _) = generated();
            let raw = match field {
                0 => &mut sample.request,
                1 => &mut sample.plan,
                2 => &mut sample.target,
                3 => &mut sample.projection,
                4 => &mut sample.claim,
                5 => &mut sample.fixture,
                _ => &mut sample.journal,
            };
            raw[0] ^= 1;
            assert!(
                inspect_pending(&sample.view()).is_err(),
                "field {field} accepted"
            );
        }
        let (mut sample, _) = generated();
        let mut claim: Value = serde_json::from_slice(&sample.claim).unwrap();
        claim["resolved_plan_sha256"] = json!("a".repeat(64));
        sample.claim = serde_json::to_vec(&claim).unwrap();
        assert!(inspect_pending(&sample.view()).is_err());

        let (mut sample, _) = generated();
        let mut plan: Value = serde_json::from_slice(&sample.plan).unwrap();
        plan["reports"]["profile"] = json!("legacy_v1");
        sample.plan = serde_json::to_vec(&plan).unwrap();
        assert!(inspect_pending(&sample.view()).is_err());

        let (mut sample, _) = generated();
        let mut request: Value = serde_json::from_slice(&sample.request).unwrap();
        request["execution_authorized"] = json!(true);
        sample.request = serde_json::to_vec(&request).unwrap();
        assert!(inspect_pending(&sample.view()).is_err());
    }

    #[test]
    fn apparently_complete_pending_receipt_cannot_create_report_binding_or_guest_permit() {
        let (sample, legacy_intake) = generated();
        assert!(inspect_pending(&sample.view()).is_ok());
        assert!(
            Binding::for_general_commitment(
                &sample.request,
                &legacy_intake,
                &"1".repeat(64),
                &"2".repeat(64),
            )
            .is_err()
        );
        assert!(
            PreparedIntake::prepare(
                sample.plan.clone(),
                vec![sample.target.clone(), sample.fixture.clone()],
            )
            .is_err()
        );
    }

    #[test]
    fn coordinated_unverified_resolved_hashes_still_cannot_upgrade_pending_evidence() {
        let (mut sample, legacy_intake) = generated();
        let mut request: Value = serde_json::from_slice(&sample.request).unwrap();
        request["capture_sha256"] = json!("a".repeat(64));
        request["reports_sha256"] = json!("b".repeat(64));
        sample.request = serde_json::to_vec(&request).unwrap();
        let mut claim = Claim::parse(&sample.claim).unwrap();
        claim.request_sha256 = digest(&sample.request);
        sample.claim = serde_json::to_vec(&claim).unwrap();
        sample.journal = claim.expected_journal_start(&sample.claim).unwrap();
        let pending = inspect_pending(&sample.view()).unwrap();
        assert!(!pending.resolved_report_hashes_independently_verified);
        assert!(!pending.complete_driver128_report_binding && !pending.guest_admission);
        assert!(
            Binding::for_general_commitment(
                &sample.request,
                &legacy_intake,
                &"1".repeat(64),
                &"2".repeat(64),
            )
            .is_err()
        );
    }
}

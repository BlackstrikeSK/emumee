//! Broker-private fixture inspection contract for a future general run.
//! It carries no public target bytes, guest permit, or containment witness.
use crate::{
    analysis_plan::PreparedIntake,
    general_execution_commitment::{BrokerPrivateFixture, Request},
    networkfixtures::{Fixtures, MAX_FILE},
    report_bundle::{bounded_json, digest},
};
use serde::{Deserialize, Serialize};
use serde_json::json;

pub const PROFILE: &str = "general_broker_private_attestation_v1";
pub const OPERATION: &str = "verify_private_only";
pub const MAX_CLAIM: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub schema: u32,
    pub profile: String,
    pub operation: String,
    pub execution_authorized: bool,
    pub request_sha256: String,
    pub resolved_plan_sha256: String,
    pub fixture: BrokerPrivateFixture,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema: u32,
    pub profile: String,
    pub operation: String,
    pub claim_sha256: String,
    pub request_sha256: String,
    pub resolved_plan_sha256: String,
    pub fixture_index: u32,
    pub fixture_id: String,
    pub original_sha256: String,
    pub canonical_sha256: String,
    pub bodies_sha256: String,
    pub expected_journal_start_sha256: String,
    pub private_bytes_inspected: bool,
    pub contained_broker_witness: bool,
    pub journal_start_observed: bool,
    pub guest_admission: bool,
    pub guest_executed: bool,
}

fn sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn input_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

impl Claim {
    /// Parent constructs this from a strict commitment; no plan, service,
    /// public input bytes, fixture bytes or broker journal path are included.
    pub fn from_verified_request(
        raw_request: &[u8],
        intake: &PreparedIntake,
    ) -> Result<Self, &'static str> {
        let request = Request::parse(raw_request)?;
        request.verify(intake)?;
        let fixture = request
            .broker_private_fixture
            .ok_or("Broker-private attestation requires a fixture")?;
        let claim = Self {
            schema: 1,
            profile: PROFILE.into(),
            operation: OPERATION.into(),
            execution_authorized: false,
            request_sha256: digest(raw_request),
            resolved_plan_sha256: request.resolved_plan_sha256,
            fixture,
        };
        claim.validate()?;
        Ok(claim)
    }

    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() > MAX_CLAIM {
            return Err("Broker-private claim exceeds 4096 bytes");
        }
        let claim: Self =
            serde_json::from_slice(raw).map_err(|_| "Broker-private claim schema invalid")?;
        claim.validate()?;
        Ok(claim)
    }

    /// Parent-only binding check; the broker need not read the full request.
    pub fn verify_against_request(
        &self,
        raw_request: &[u8],
        intake: &PreparedIntake,
    ) -> Result<(), &'static str> {
        if *self != Self::from_verified_request(raw_request, intake)? {
            return Err("Broker-private claim differs from execution commitment");
        }
        Ok(())
    }

    /// Expected first private journal line. Returning its bytes does not
    /// attest that a contained broker actually wrote or preserved it.
    pub fn expected_journal_start(&self, raw_claim: &[u8]) -> Result<Vec<u8>, &'static str> {
        if Self::parse(raw_claim)? != *self {
            return Err("Broker-private journal claim differs");
        }
        let start = json!({
            "event":"general_broker_fixture_verified",
            "request_sha256":self.request_sha256,
            "claim_sha256":digest(raw_claim),
            "fixture_sha256":self.fixture.original_sha256,
        });
        let mut raw = serde_json::to_vec(&start)
            .map_err(|_| "Broker-private journal start encoding failed")?;
        raw.push(b'\n');
        Ok(raw)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != 1
            || self.profile != PROFILE
            || self.operation != OPERATION
            || self.execution_authorized
            || !sha(&self.request_sha256)
            || !sha(&self.resolved_plan_sha256)
            || !input_id(&self.fixture.id)
            || self.fixture.index >= crate::analysis_plan::MAX_INPUTS as u32
            || self.fixture.size == 0
            || self.fixture.size > MAX_FILE as u64
            || self.fixture.canonical_bytes > MAX_FILE as u64
            || !sha(&self.fixture.original_sha256)
            || !sha(&self.fixture.canonical_sha256)
            || !sha(&self.fixture.bodies_sha256)
        {
            return Err("Broker-private claim identity or role invalid");
        }
        Ok(())
    }

    /// This only inspects caller-supplied bytes. A future packaged broker
    /// must prove that it read these bytes from its private staged object.
    pub fn inspect(&self, raw_claim: &[u8], fixture_bytes: &[u8]) -> Result<Receipt, &'static str> {
        if Self::parse(raw_claim)? != *self
            || fixture_bytes.len() as u64 != self.fixture.size
            || digest(fixture_bytes) != self.fixture.original_sha256
        {
            return Err("Broker-private original fixture bytes differ");
        }
        let fixtures = Fixtures::parse(fixture_bytes)
            .map_err(|_| "Broker-private fixture document invalid")?;
        let canonical = bounded_json(&fixtures.document(), MAX_FILE)
            .map_err(|_| "Broker-private canonical fixture exceeds bound")?;
        if canonical.len() as u64 != self.fixture.canonical_bytes
            || digest(&canonical) != self.fixture.canonical_sha256
        {
            return Err("Broker-private canonical fixture differs");
        }
        let bodies = fixtures
            .rules()
            .iter()
            .map(|rule| {
                json!({
                    "id":rule.id,
                    "request_sha256":digest(&rule.request.body),
                    "request_bytes":rule.request.body.len(),
                    "response_sha256":digest(&rule.response.body),
                    "response_bytes":rule.response.body.len()
                })
            })
            .collect::<Vec<_>>();
        let bodies = serde_json::to_vec(&bodies)
            .map_err(|_| "Broker-private body commitment encoding failed")?;
        if digest(&bodies) != self.fixture.bodies_sha256 {
            return Err("Broker-private body commitment differs");
        }
        let claim_sha256 = digest(raw_claim);
        let expected_journal_start_sha256 = digest(&self.expected_journal_start(raw_claim)?);
        Ok(Receipt {
            schema: 1,
            profile: PROFILE.into(),
            operation: OPERATION.into(),
            claim_sha256,
            request_sha256: self.request_sha256.clone(),
            resolved_plan_sha256: self.resolved_plan_sha256.clone(),
            fixture_index: self.fixture.index,
            fixture_id: self.fixture.id.clone(),
            original_sha256: self.fixture.original_sha256.clone(),
            canonical_sha256: self.fixture.canonical_sha256.clone(),
            bodies_sha256: self.fixture.bodies_sha256.clone(),
            expected_journal_start_sha256,
            private_bytes_inspected: true,
            contained_broker_witness: false,
            journal_start_observed: false,
            guest_admission: false,
            guest_executed: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        analysis_plan::{Arch, PreparedIntake},
        plan_runtime::Case,
    };
    use serde_json::{Value, json};

    fn generated() -> (Vec<u8>, Vec<u8>, PreparedIntake, Claim) {
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
        let intake =
            PreparedIntake::prepare(serde_json::to_vec(&plan).unwrap(), kernel.inputs).unwrap();
        let request = Request::from_intake(&intake, "20261019T120000Z-12345678".into()).unwrap();
        let request_raw = serde_json::to_vec(&request).unwrap();
        let claim = Claim::from_verified_request(&request_raw, &intake).unwrap();
        (request_raw, fixture, intake, claim)
    }

    #[test]
    fn generated_broker_claim_inspects_private_bytes_without_guest_or_containment_claim() {
        let (request_raw, fixture, intake, claim) = generated();
        let raw = serde_json::to_vec(&claim).unwrap();
        let parsed = Claim::parse(&raw).unwrap();
        parsed
            .verify_against_request(&request_raw, &intake)
            .unwrap();
        let receipt = parsed.inspect(&raw, &fixture).unwrap();
        assert_eq!(receipt.request_sha256, digest(&request_raw));
        assert_eq!(receipt.original_sha256, digest(&fixture));
        assert!(receipt.private_bytes_inspected);
        assert_eq!(
            receipt.expected_journal_start_sha256,
            digest(&parsed.expected_journal_start(&raw).unwrap())
        );
        assert!(!receipt.contained_broker_witness);
        assert!(!receipt.journal_start_observed);
        assert!(!receipt.guest_admission && !receipt.guest_executed);
        let serialized = serde_json::to_string(&claim).unwrap();
        assert!(!serialized.contains("TestDrv"));
        assert!(!serialized.contains("owned.sys"));
    }

    #[test]
    fn generated_claim_refuses_changed_bytes_or_commitments() {
        let (request_raw, fixture, intake, claim) = generated();
        let raw = serde_json::to_vec(&claim).unwrap();
        let mut changed = fixture.clone();
        changed[0] ^= 1;
        assert!(claim.inspect(&raw, &changed).is_err());
        let mut bad = claim.clone();
        bad.fixture.canonical_sha256 = "0".repeat(64);
        assert!(
            bad.inspect(&serde_json::to_vec(&bad).unwrap(), &fixture)
                .is_err()
        );
        bad = claim.clone();
        bad.fixture.bodies_sha256 = "0".repeat(64);
        assert!(
            bad.inspect(&serde_json::to_vec(&bad).unwrap(), &fixture)
                .is_err()
        );
        bad = claim.clone();
        bad.request_sha256 = "0".repeat(64);
        assert!(bad.verify_against_request(&request_raw, &intake).is_err());
        let mut changed_plan: Value = serde_json::from_slice(intake.raw_plan()).unwrap();
        changed_plan["target"]["service_name"] = json!("OtherDrv");
        let original_inputs = intake.slots().map(|(_, bytes)| bytes.to_vec()).collect();
        let changed_intake =
            PreparedIntake::prepare(serde_json::to_vec(&changed_plan).unwrap(), original_inputs)
                .unwrap();
        assert!(Claim::from_verified_request(&request_raw, &changed_intake).is_err());
        let mut value = serde_json::to_value(&claim).unwrap();
        value["unknown"] = json!(true);
        assert!(Claim::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(Claim::parse(&vec![b'x'; MAX_CLAIM + 1]).is_err());
        let mut forged = claim;
        forged.execution_authorized = true;
        assert!(forged.validate().is_err());
    }

    #[test]
    fn offline_deny_has_no_private_fixture_claim() {
        let mut kernel = Case::Kernel17.generated(Arch::X64).unwrap();
        let mut plan: Value = serde_json::from_slice(&kernel.plan).unwrap();
        plan["target"]["service_name"] = json!("TestDrv");
        let intake = PreparedIntake::prepare(
            serde_json::to_vec(&plan).unwrap(),
            std::mem::take(&mut kernel.inputs),
        )
        .unwrap();
        let request = Request::from_intake(&intake, "20261019T120000Z-12345678".into()).unwrap();
        assert!(
            Claim::from_verified_request(&serde_json::to_vec(&request).unwrap(), &intake).is_err()
        );
    }
}

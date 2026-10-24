//! Verify-only transport commitment for owned general plan bytes.
//! This schema cannot authorize broker connection or guest execution.
use crate::{
    analysis_plan::{MAX_INPUTS, MAX_INVENTORY_BYTES, PreparedIntake},
    report_bundle::digest,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const PROFILE: &str = "general_plan_admission_v1";
pub const OPERATION: &str = "verify_only";
pub const MAX_REQUEST: usize = 1024 * 1024;
pub const MAX_REQUEST_BYTES: usize = MAX_REQUEST;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SlotCommitment {
    pub id: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: u32,
    pub profile: String,
    pub operation: String,
    pub run_id: String,
    pub raw_plan_sha256: String,
    pub resolved_plan_sha256: String,
    pub resolved_request_sha256: String,
    pub slots: Vec<SlotCommitment>,
}

fn sha256(value: &str) -> bool {
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

impl Request {
    pub fn from_intake(intake: &PreparedIntake, run_id: String) -> Result<Self, &'static str> {
        let request = Self {
            schema: 1,
            profile: PROFILE.into(),
            operation: OPERATION.into(),
            run_id,
            raw_plan_sha256: digest(intake.raw_plan()),
            resolved_plan_sha256: intake.resolved().sha256().into(),
            resolved_request_sha256: intake.resolved().request_sha256().into(),
            slots: intake
                .slots()
                .map(|(input, bytes)| SlotCommitment {
                    id: input.id.clone(),
                    size: bytes.len() as u64,
                    sha256: input.sha256.clone(),
                })
                .collect(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() > MAX_REQUEST_BYTES {
            return Err("General admission request exceeds 1 MiB");
        }
        let request: Self =
            serde_json::from_slice(raw).map_err(|_| "Invalid general admission request")?;
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != 1 || self.profile != PROFILE || self.operation != OPERATION {
            return Err("General admission role/profile mismatch");
        }
        if !crate::reports::valid_run_id(&self.run_id)
            || !sha256(&self.raw_plan_sha256)
            || !sha256(&self.resolved_plan_sha256)
            || !sha256(&self.resolved_request_sha256)
        {
            return Err("General admission identity/hash invalid");
        }
        if self.slots.is_empty() || self.slots.len() > MAX_INPUTS {
            return Err("General admission slot count outside bound");
        }
        let mut total = 0u64;
        let mut ids = BTreeSet::new();
        for slot in &self.slots {
            if !input_id(&slot.id) || !ids.insert(&slot.id) || !sha256(&slot.sha256) {
                return Err("General admission slot identity invalid");
            }
            if slot.size > crate::pe::MAX_INPUT as u64 {
                return Err("General admission slot exceeds 128 MiB");
            }
            total = total
                .checked_add(slot.size)
                .ok_or("General admission byte overflow")?;
            if total > MAX_INVENTORY_BYTES {
                return Err("General admission inventory exceeds 256 MiB");
            }
        }
        Ok(())
    }

    pub fn verify(&self, intake: &PreparedIntake) -> Result<(), &'static str> {
        self.validate()?;
        if intake.resolved().executable()
            || self.raw_plan_sha256 != digest(intake.raw_plan())
            || self.resolved_plan_sha256 != intake.resolved().sha256()
            || self.resolved_request_sha256 != intake.resolved().request_sha256()
            || self.slots.len() != intake.slots().len()
        {
            return Err("General admission plan commitment changed");
        }
        for (committed, (input, bytes)) in self.slots.iter().zip(intake.slots()) {
            if committed.id != input.id
                || committed.size != bytes.len() as u64
                || committed.sha256 != input.sha256
            {
                return Err("General admission ordered slot commitment changed");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analysis_plan::PlanSpec, plan_runtime::Case};

    fn generated() -> (PreparedIntake, Request) {
        let fixture = Case::NativeA
            .generated(crate::analysis_plan::Arch::X64)
            .unwrap();
        let intake = PreparedIntake::prepare(fixture.plan, fixture.inputs).unwrap();
        let request = Request::from_intake(&intake, "20261019T120000Z-12345678".into()).unwrap();
        (intake, request)
    }

    #[test]
    fn generated_unsorted_slots_bind_exact_plan_and_verify_only_role() {
        let (intake, request) = generated();
        assert_eq!(request.slots[0].id, "primary");
        assert_eq!(request.slots[1].id, "guest-data");
        assert_eq!(request.operation, OPERATION);
        assert_eq!(request.raw_plan_sha256, digest(intake.raw_plan()));
        let parsed = Request::parse(&serde_json::to_vec(&request).unwrap()).unwrap();
        parsed.verify(&intake).unwrap();
        assert!(!intake.resolved().executable());
    }

    #[test]
    fn generated_request_refuses_tampered_commitments_and_schema() {
        let (intake, request) = generated();
        let mut changed = request.clone();
        changed.slots.swap(0, 1);
        assert!(changed.verify(&intake).is_err());
        changed = request.clone();
        changed.slots[1].sha256 = "0".repeat(64);
        assert!(changed.verify(&intake).is_err());
        changed = request.clone();
        changed.raw_plan_sha256 = "0".repeat(64);
        assert!(changed.verify(&intake).is_err());
        changed = request.clone();
        changed.resolved_plan_sha256 = "0".repeat(64);
        assert!(changed.verify(&intake).is_err());
        changed = request.clone();
        changed.resolved_request_sha256 = "0".repeat(64);
        assert!(changed.verify(&intake).is_err());
        changed = request.clone();
        changed.operation = "execute".into();
        assert!(changed.validate().is_err());
        let mut value = serde_json::to_value(&request).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert!(Request::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(Request::parse(&vec![b'x'; MAX_REQUEST_BYTES + 1]).is_err());
        let mut value = serde_json::to_value(&request).unwrap();
        value["slots"][0]["id"] = serde_json::json!("../escape");
        assert!(Request::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        // The plan, unlike a serialized inspection receipt, is always decoded
        // from owned bytes by the independent worker path.
        assert!(PlanSpec::decode(intake.raw_plan()).is_ok());
    }
}

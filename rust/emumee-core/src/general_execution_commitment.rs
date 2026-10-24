//! A bounded commitment for a future general kernel execution request.
//! No worker, broker or engine entry point accepts this type as authority.
use crate::{
    analysis_plan::{InputRole, MAX_INPUTS, MAX_INVENTORY_BYTES, PreparedIntake},
    report_bundle::digest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;

pub const PROFILE: &str = "general_execution_commitment_v1";
pub const OPERATION: &str = "commit_only";
pub const MAX_REQUEST: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicInput {
    pub index: u32,
    pub id: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerPrivateFixture {
    pub index: u32,
    pub id: String,
    pub size: u64,
    pub original_sha256: String,
    pub canonical_sha256: String,
    pub canonical_bytes: u64,
    pub bodies_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: u32,
    pub profile: String,
    pub operation: String,
    pub execution_authorized: bool,
    pub run_id: String,
    pub raw_plan_sha256: String,
    pub resolved_plan_sha256: String,
    pub resolved_request_sha256: String,
    pub service_name: String,
    pub target_input_id: String,
    pub public_inputs: Vec<PublicInput>,
    pub broker_private_fixture: Option<BrokerPrivateFixture>,
    pub budget_sha256: String,
    pub limits_sha256: String,
    pub capture_sha256: String,
    pub reports_sha256: String,
    pub report_profile: String,
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

fn hash_value(value: &Value) -> Result<String, &'static str> {
    serde_json::to_vec(value)
        .map(|raw| digest(&raw))
        .map_err(|_| "Execution commitment projection encoding failed")
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, &'static str> {
    value[field]
        .as_str()
        .ok_or("Execution commitment projection field missing")
}

impl Request {
    pub fn from_intake(intake: &PreparedIntake, run_id: String) -> Result<Self, &'static str> {
        if intake.resolved().executable() {
            return Err("Executable intake is not a commitment source");
        }
        let value = intake.resolved().value();
        if value["target"]["kind"] != "kernel_driver" {
            return Err("Execution commitment requires kernel driver target");
        }
        let service_name = text(&value["target"], "service_name")?;
        if !crate::driver_input::service_name_valid(service_name) {
            return Err("Execution commitment service identity invalid");
        }
        let target_input_id = text(&value["target"], "input")?;
        let mut public_inputs = Vec::new();
        let mut private = None;
        let mut total = 0u64;
        for (index, (input, bytes)) in intake.slots().enumerate() {
            total = total
                .checked_add(bytes.len() as u64)
                .ok_or("Execution commitment input byte overflow")?;
            if total > MAX_INVENTORY_BYTES || index >= MAX_INPUTS {
                return Err("Execution commitment input budget exceeded");
            }
            let index =
                u32::try_from(index).map_err(|_| "Execution commitment slot index overflow")?;
            if input.roles.contains(&InputRole::OfflineFixtures) {
                if private.is_some() || input.roles.len() != 1 {
                    return Err("Execution commitment fixture ownership ambiguous");
                }
                let network = &value["network"];
                if network["kind"] != "offline_exact_replay"
                    || network["input"].as_str() != Some(input.id.as_str())
                    || network["original_sha256"].as_str() != Some(input.sha256.as_str())
                    || network["original_bytes"].as_u64() != Some(bytes.len() as u64)
                    || network["fixture_visibility"] != "broker_only"
                {
                    return Err("Execution commitment broker fixture projection differs");
                }
                private = Some(BrokerPrivateFixture {
                    index,
                    id: input.id.clone(),
                    size: bytes.len() as u64,
                    original_sha256: digest(bytes),
                    canonical_sha256: text(network, "canonical_sha256")?.into(),
                    canonical_bytes: network["canonical_copy_bytes"]
                        .as_u64()
                        .ok_or("Execution commitment canonical fixture bytes missing")?,
                    bodies_sha256: hash_value(&network["bodies"])?,
                });
            } else {
                public_inputs.push(PublicInput {
                    index,
                    id: input.id.clone(),
                    size: bytes.len() as u64,
                    sha256: digest(bytes),
                });
            }
        }
        if (value["network"]["kind"] == "offline_exact_replay") != private.is_some() {
            return Err("Execution commitment broker fixture missing or unexpected");
        }
        let request = Self {
            schema: 1,
            profile: PROFILE.into(),
            operation: OPERATION.into(),
            execution_authorized: false,
            run_id,
            raw_plan_sha256: digest(intake.raw_plan()),
            resolved_plan_sha256: intake.resolved().sha256().into(),
            resolved_request_sha256: intake.resolved().request_sha256().into(),
            service_name: service_name.into(),
            target_input_id: target_input_id.into(),
            public_inputs,
            broker_private_fixture: private,
            budget_sha256: hash_value(&value["budget"])?,
            limits_sha256: hash_value(&value["limits"])?,
            capture_sha256: hash_value(&value["capture"])?,
            reports_sha256: hash_value(&value["reports"])?,
            report_profile: text(&value["reports"], "profile")?.into(),
        };
        request.validate()?;
        Ok(request)
    }

    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() > MAX_REQUEST {
            return Err("Execution commitment exceeds 1 MiB");
        }
        let request: Self = serde_json::from_slice(raw)
            .map_err(|_| "Execution commitment request schema invalid")?;
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != 1
            || self.profile != PROFILE
            || self.operation != OPERATION
            || self.execution_authorized
        {
            return Err("Execution commitment is not an admission permit");
        }
        if !crate::reports::valid_run_id(&self.run_id)
            || !crate::driver_input::service_name_valid(&self.service_name)
            || !input_id(&self.target_input_id)
            || ![
                &self.raw_plan_sha256,
                &self.resolved_plan_sha256,
                &self.resolved_request_sha256,
                &self.budget_sha256,
                &self.limits_sha256,
                &self.capture_sha256,
                &self.reports_sha256,
            ]
            .into_iter()
            .all(|v| sha(v))
        {
            return Err("Execution commitment identity/hash invalid");
        }
        if self.public_inputs.is_empty()
            || self.public_inputs.len() > MAX_INPUTS
            || !matches!(
                self.report_profile.as_str(),
                "legacy_v1" | "large_driver_v1"
            )
        {
            return Err("Execution commitment input/report shape invalid");
        }
        let mut indices = BTreeSet::new();
        let mut ids = BTreeSet::new();
        let mut total = 0u64;
        let mut prior_index = None;
        for input in &self.public_inputs {
            if !indices.insert(input.index)
                || !ids.insert(&input.id)
                || !input_id(&input.id)
                || input.size > crate::pe::MAX_INPUT as u64
                || !sha(&input.sha256)
                || prior_index.is_some_and(|prior| input.index <= prior)
            {
                return Err("Execution commitment public input invalid");
            }
            prior_index = Some(input.index);
            total = total
                .checked_add(input.size)
                .ok_or("Execution commitment input byte overflow")?;
        }
        if !ids.contains(&self.target_input_id) {
            return Err("Execution commitment target must be public");
        }
        if let Some(fixture) = &self.broker_private_fixture {
            if indices.contains(&fixture.index)
                || ids.contains(&fixture.id)
                || !input_id(&fixture.id)
                || fixture.size > crate::pe::MAX_INPUT as u64
                || fixture.canonical_bytes > crate::pe::MAX_INPUT as u64
                || !sha(&fixture.original_sha256)
                || !sha(&fixture.canonical_sha256)
                || !sha(&fixture.bodies_sha256)
            {
                return Err("Execution commitment broker fixture invalid");
            }
            indices.insert(fixture.index);
            total = total
                .checked_add(fixture.size)
                .ok_or("Execution commitment input byte overflow")?;
        }
        if total > MAX_INVENTORY_BYTES
            || indices.len() > MAX_INPUTS
            || indices.iter().copied().ne(0..indices.len() as u32)
        {
            return Err("Execution commitment physical slot graph invalid");
        }
        if serde_json::to_vec(self)
            .map_err(|_| "Execution commitment encoding failed")?
            .len()
            > MAX_REQUEST
        {
            return Err("Execution commitment exceeds 1 MiB");
        }
        Ok(())
    }

    pub fn verify(&self, intake: &PreparedIntake) -> Result<(), &'static str> {
        self.validate()?;
        let expected = Self::from_intake(intake, self.run_id.clone())?;
        if *self != expected {
            return Err("Execution commitment differs from owned plan/input bytes");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{analysis_plan::Arch, plan_runtime::Case};
    use serde_json::json;

    fn generated(with_fixture: bool) -> PreparedIntake {
        let mut kernel = Case::Kernel17.generated(Arch::X64).unwrap();
        let mut plan: Value = serde_json::from_slice(&kernel.plan).unwrap();
        plan["target"]["service_name"] = json!("TestDrv");
        if with_fixture {
            let replay = Case::NativeReplay.generated(Arch::X64).unwrap();
            let bytes = replay.fixtures;
            plan["inputs"].as_array_mut().unwrap().push(json!({
                "id":"offline","name":"offline.json","roles":["offline_fixtures"],
                "mount":{"kind":"not_mounted"},"size":bytes.len(),"sha256":digest(&bytes)
            }));
            plan["network"] = json!({"kind":"offline_exact_replay","input":"offline"});
            kernel.inputs.push(bytes);
        }
        PreparedIntake::prepare(serde_json::to_vec(&plan).unwrap(), kernel.inputs).unwrap()
    }

    #[test]
    fn generated_kernel_request_commits_service_plan_budgets_and_report_without_authority() {
        let intake = generated(false);
        let request = Request::from_intake(&intake, "20261019T120000Z-12345678".into()).unwrap();
        assert_eq!(request.service_name, "TestDrv");
        assert_eq!(request.operation, OPERATION);
        assert!(!request.execution_authorized);
        assert_eq!(request.public_inputs.len(), 1);
        assert!(request.broker_private_fixture.is_none());
        assert_eq!(
            request.budget_sha256,
            hash_value(&intake.resolved().value()["budget"]).unwrap()
        );
        assert_eq!(request.report_profile, "legacy_v1");
        let parsed = Request::parse(&serde_json::to_vec(&request).unwrap()).unwrap();
        parsed.verify(&intake).unwrap();
        let mut changed = request.clone();
        changed.budget_sha256 = "0".repeat(64);
        assert!(changed.verify(&intake).is_err());
        changed = request.clone();
        changed.service_name = "OtherDrv".into();
        assert!(changed.verify(&intake).is_err());
        changed = request;
        changed.execution_authorized = true;
        assert!(changed.validate().is_err());
        changed.execution_authorized = false;
        changed.public_inputs[0].index = 1;
        assert!(changed.validate().is_err());
    }

    #[test]
    fn generated_broker_fixture_is_opaque_and_separately_bound() {
        let intake = generated(true);
        let request = Request::from_intake(&intake, "20261019T120000Z-12345678".into()).unwrap();
        let private = request.broker_private_fixture.as_ref().unwrap();
        assert_eq!(private.index, 1);
        assert_eq!(private.id, "offline");
        assert_eq!(request.public_inputs.len(), 1);
        assert!(
            request
                .public_inputs
                .iter()
                .all(|slot| slot.id != private.id)
        );
        request.verify(&intake).unwrap();
        let mut changed = request.clone();
        changed
            .broker_private_fixture
            .as_mut()
            .unwrap()
            .bodies_sha256 = "0".repeat(64);
        assert!(changed.verify(&intake).is_err());
        changed = request.clone();
        changed
            .broker_private_fixture
            .as_mut()
            .unwrap()
            .original_sha256 = "0".repeat(64);
        assert!(changed.verify(&intake).is_err());
        let mut value = serde_json::to_value(&request).unwrap();
        value["unknown"] = json!(true);
        assert!(Request::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn missing_service_and_wrong_target_cannot_form_commitment() {
        let kernel = Case::Kernel17.generated(Arch::X64).unwrap();
        let intake = PreparedIntake::prepare(kernel.plan, kernel.inputs).unwrap();
        assert!(Request::from_intake(&intake, "20261019T120000Z-12345678".into()).is_err());
        let native = Case::NativeA.generated(Arch::X64).unwrap();
        let intake = PreparedIntake::prepare(native.plan, native.inputs).unwrap();
        assert!(Request::from_intake(&intake, "20261019T120000Z-12345678".into()).is_err());
    }
}

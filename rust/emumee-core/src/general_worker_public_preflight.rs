//! Worker-visible half of a future general kernel admission boundary.
//! This deliberately cannot verify broker-private bytes or authorize a guest.
use crate::{
    analysis_plan::{
        Arch, CaptureProfile, InputRole, MAX_INPUTS, Network, PlanSpec, PreparedIntake, Reference,
        ReportProfile, Target,
    },
    general_execution_commitment::{MAX_REQUEST, Request},
    pe::{Architecture, Kind, MAX_INPUT, PeImage},
    report_bundle::digest,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema: u32,
    pub profile: String,
    pub operation: String,
    pub request_sha256: String,
    pub raw_plan_sha256: String,
    pub service_name: String,
    pub public_slot_count: usize,
    pub broker_private_fixture_pending: bool,
    pub resolved_plan_independently_verified: bool,
    pub guest_admission: bool,
    pub engine_applied: bool,
    pub guest_executed: bool,
}

/// Public target/report identity only. A private fixture and the unresolved
/// large-driver plan prevent this from becoming a complete report binding.
#[derive(Clone, Debug, Serialize)]
pub struct PendingDriver128Report {
    pub schema: u32,
    pub profile: &'static str,
    pub operation: &'static str,
    pub request_sha256: String,
    pub target_input_sha256: String,
    pub target_input_bytes: u64,
    pub target_image_bytes: u64,
    pub service_name: String,
    pub public_preflight: Receipt,
    pub complete_report_binding: bool,
    pub guest_admission: bool,
}

/// Recheck staged public bytes and a large-driver report pair without
/// projecting unverified resolved-plan/private-fixture hashes into Binding.
pub fn preflight_driver128_public_report(
    request_raw: &[u8],
    expected_request_sha256: &str,
    raw_plan: &[u8],
    slots: &[Option<&[u8]>],
) -> Result<PendingDriver128Report, &'static str> {
    let public = verify_public_view(request_raw, expected_request_sha256, raw_plan, slots)?;
    let request = Request::parse(request_raw)?;
    let spec = PlanSpec::decode(raw_plan).map_err(|_| "Driver128 public plan schema invalid")?;
    if request.report_profile != "large_driver_v1"
        || spec.capture.profile != CaptureProfile::LargeDriver128V1
        || spec.reports.profile != ReportProfile::LargeDriverV1
        || !spec.companions.is_empty()
    {
        return Err("Driver128 public capture/report pair or companion graph unsupported");
    }
    let Target::KernelDriver {
        architecture: Arch::X64,
        unload: false,
        code_reference: Reference::None,
        ..
    } = &spec.target
    else {
        return Err("Driver128 public target is not a standalone x64 DriverEntry");
    };
    let committed = request
        .public_inputs
        .iter()
        .find(|input| input.id == request.target_input_id)
        .ok_or("Driver128 public target commitment missing")?;
    let index = usize::try_from(committed.index).map_err(|_| "Driver128 target index overflow")?;
    let declared = spec
        .inputs
        .get(index)
        .ok_or("Driver128 target slot absent")?;
    let bytes = slots
        .get(index)
        .and_then(|slot| *slot)
        .ok_or("Driver128 target bytes absent")?;
    if !declared.roles.contains(&InputRole::OriginalPrimary)
        || !declared.roles.contains(&InputRole::ExecutionPrimary)
        || declared.roles.contains(&InputRole::OfflineFixtures)
        || bytes.is_empty()
        || bytes.len() > MAX_INPUT
    {
        return Err("Driver128 public target role or file bound invalid");
    }
    let pe = PeImage::parse(bytes, &declared.name)
        .map_err(|_| "Driver128 public target is not a valid PE")?;
    if pe.sample.kind != Kind::Driver
        || pe.sample.architecture != Architecture::X64
        || pe.sample.managed
        || pe.image_size == 0
        || pe.image_size as usize > MAX_INPUT
    {
        return Err("Driver128 public target is not a bounded unmanaged x64 driver");
    }
    Ok(PendingDriver128Report {
        schema: 1,
        profile: "driver128_public_report_preflight_v1",
        operation: "inspect_public_only",
        request_sha256: expected_request_sha256.into(),
        target_input_sha256: committed.sha256.clone(),
        target_input_bytes: committed.size,
        target_image_bytes: pe.image_size as u64,
        service_name: request.service_name,
        public_preflight: public,
        complete_report_binding: false,
        guest_admission: false,
    })
}

/// `slots` has one entry per declared physical index. The fixture index must
/// be `None`, so the worker need not and must not receive broker-only bytes.
pub fn verify_public_view(
    request_raw: &[u8],
    expected_request_sha256: &str,
    raw_plan: &[u8],
    slots: &[Option<&[u8]>],
) -> Result<Receipt, &'static str> {
    if request_raw.len() > MAX_REQUEST || digest(request_raw) != expected_request_sha256 {
        return Err("Worker public request transport digest differs");
    }
    let request = Request::parse(request_raw)?;
    if digest(raw_plan) != request.raw_plan_sha256 {
        return Err("Worker public raw plan digest differs");
    }
    let spec = PlanSpec::decode(raw_plan).map_err(|_| "Worker public plan schema invalid")?;
    if slots.len() != spec.inputs.len() || slots.len() > MAX_INPUTS {
        return Err("Worker public physical slot count differs");
    }
    let Target::KernelDriver {
        input,
        service_name: Some(service_name),
        ..
    } = &spec.target
    else {
        return Err("Worker public kernel service identity absent");
    };
    if input != &request.target_input_id || service_name != &request.service_name {
        return Err("Worker public kernel service identity differs");
    }
    let report_profile = serde_json::to_value(spec.reports.profile)
        .map_err(|_| "Worker public report profile encoding failed")?;
    if report_profile.as_str() != Some(request.report_profile.as_str()) {
        return Err("Worker public report profile differs");
    }
    let mut public = request.public_inputs.iter();
    for (index, (spec_input, bytes)) in spec.inputs.iter().zip(slots).enumerate() {
        let index = u32::try_from(index).map_err(|_| "Worker public slot index overflow")?;
        if request
            .broker_private_fixture
            .as_ref()
            .is_some_and(|fixture| fixture.index == index)
        {
            let fixture = request.broker_private_fixture.as_ref().unwrap();
            if bytes.is_some()
                || spec_input.roles.as_slice() != [InputRole::OfflineFixtures]
                || fixture.id != spec_input.id
                || fixture.size != spec_input.size
                || fixture.original_sha256 != spec_input.sha256
            {
                return Err("Worker public fixture bytes exposed or identity differs");
            }
            continue;
        }
        let committed = public
            .next()
            .ok_or("Worker public input commitment missing")?;
        let bytes = bytes.ok_or("Worker public input bytes missing")?;
        if committed.index != index
            || committed.id != spec_input.id
            || committed.size != spec_input.size
            || committed.sha256 != spec_input.sha256
            || committed.size != bytes.len() as u64
            || committed.sha256 != digest(bytes)
            || spec_input.roles.contains(&InputRole::OfflineFixtures)
        {
            return Err("Worker public input bytes or identity differ");
        }
    }
    if public.next().is_some() {
        return Err("Worker public input commitment has surplus slots");
    }
    match (&spec.network, &request.broker_private_fixture) {
        (Network::OfflineDeny, None) => {}
        (Network::OfflineExactReplay { input }, Some(fixture)) if input == &fixture.id => {}
        _ => return Err("Worker public broker fixture role differs"),
    }
    let full_projection = if request.broker_private_fixture.is_none() {
        let owned = slots
            .iter()
            .map(|bytes| {
                bytes
                    .ok_or("Worker public input bytes missing")
                    .map(|b| b.to_vec())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let intake = PreparedIntake::prepare(raw_plan.to_vec(), owned)
            .map_err(|_| "Worker public resolved projection invalid")?;
        request.verify(&intake)?;
        true
    } else {
        // The worker cannot claim it recomputed the resolved plan or budget:
        // those projections depend on the broker-private fixture bytes.
        false
    };
    Ok(Receipt {
        schema: 1,
        profile: "general_worker_public_preflight_v1".into(),
        operation: "verify_public_only".into(),
        request_sha256: expected_request_sha256.into(),
        raw_plan_sha256: request.raw_plan_sha256,
        service_name: request.service_name,
        public_slot_count: request.public_inputs.len(),
        broker_private_fixture_pending: request.broker_private_fixture.is_some(),
        resolved_plan_independently_verified: full_projection,
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

    fn generated(private: bool) -> (Vec<u8>, Vec<Vec<u8>>, Request) {
        let mut kernel = Case::Kernel17.generated(Arch::X64).unwrap();
        let mut plan: Value = serde_json::from_slice(&kernel.plan).unwrap();
        plan["target"]["service_name"] = json!("TestDrv");
        if private {
            let fixture = Case::NativeReplay.generated(Arch::X64).unwrap().fixtures;
            plan["inputs"].as_array_mut().unwrap().push(json!({
                "id":"offline","name":"offline.json","roles":["offline_fixtures"],
                "mount":{"kind":"not_mounted"},"size":fixture.len(),"sha256":digest(&fixture)
            }));
            plan["network"] = json!({"kind":"offline_exact_replay","input":"offline"});
            kernel.inputs.push(fixture);
        }
        let raw_plan = serde_json::to_vec(&plan).unwrap();
        let intake = PreparedIntake::prepare(raw_plan.clone(), kernel.inputs.clone()).unwrap();
        let request = Request::from_intake(&intake, "20261019T120000Z-12345678".into()).unwrap();
        (raw_plan, kernel.inputs, request)
    }

    #[test]
    fn generated_public_only_admission_recomputes_offline_deny_without_guest_authority() {
        let (plan, inputs, request) = generated(false);
        let raw = serde_json::to_vec(&request).unwrap();
        let slots = inputs
            .iter()
            .map(|v| Some(v.as_slice()))
            .collect::<Vec<_>>();
        let receipt = verify_public_view(&raw, &digest(&raw), &plan, &slots).unwrap();
        assert!(receipt.resolved_plan_independently_verified);
        assert!(!receipt.broker_private_fixture_pending);
        assert!(!receipt.guest_admission && !receipt.engine_applied && !receipt.guest_executed);
        let mut bad = inputs[0].clone();
        bad[0] ^= 1;
        assert!(verify_public_view(&raw, &digest(&raw), &plan, &[Some(bad.as_slice())]).is_err());
    }

    #[test]
    fn generated_fixture_bytes_are_absent_from_worker_view_and_projection_stays_pending() {
        let (plan, inputs, request) = generated(true);
        let raw = serde_json::to_vec(&request).unwrap();
        let slots = [Some(inputs[0].as_slice()), None];
        let receipt = verify_public_view(&raw, &digest(&raw), &plan, &slots).unwrap();
        assert!(receipt.broker_private_fixture_pending);
        assert!(!receipt.resolved_plan_independently_verified);
        assert!(!receipt.guest_admission);
        assert!(
            verify_public_view(
                &raw,
                &digest(&raw),
                &plan,
                &[Some(inputs[0].as_slice()), Some(inputs[1].as_slice())]
            )
            .is_err()
        );
        assert!(verify_public_view(&raw, &digest(&raw), &plan, &[None, None]).is_err());
    }

    #[test]
    fn generated_large_driver_public_identity_is_pending_and_never_a_report_binding() {
        let (legacy_plan, inputs, mut request) = generated(true);
        let mut value: Value = serde_json::from_slice(&legacy_plan).unwrap();
        value["capture"]["profile"] = json!("large_driver128_v1");
        value["reports"]["profile"] = json!("large_driver_v1");
        let plan = serde_json::to_vec(&value).unwrap();
        request.raw_plan_sha256 = digest(&plan);
        request.report_profile = "large_driver_v1".into();
        let raw = serde_json::to_vec(&request).unwrap();
        let view = [Some(inputs[0].as_slice()), None];

        // Large-profile resolution remains closed. The private fixture is not
        // available to this public-only projection.
        assert!(PreparedIntake::prepare(plan.clone(), inputs.clone()).is_err());
        let receipt = preflight_driver128_public_report(&raw, &digest(&raw), &plan, &view).unwrap();
        assert_eq!(receipt.request_sha256, digest(&raw));
        assert_eq!(receipt.target_input_sha256, digest(&inputs[0]));
        assert_eq!(receipt.target_input_bytes, inputs[0].len() as u64);
        assert!(receipt.target_image_bytes > 0);
        assert_eq!(receipt.service_name, "TestDrv");
        assert!(receipt.public_preflight.broker_private_fixture_pending);
        assert!(
            !receipt
                .public_preflight
                .resolved_plan_independently_verified
        );
        assert!(!receipt.complete_report_binding && !receipt.guest_admission);

        value["capture"]["profile"] = json!("legacy32_capture_v1");
        let mismatched = serde_json::to_vec(&value).unwrap();
        request.raw_plan_sha256 = digest(&mismatched);
        let mismatched_request = serde_json::to_vec(&request).unwrap();
        assert!(
            preflight_driver128_public_report(
                &mismatched_request,
                &digest(&mismatched_request),
                &mismatched,
                &view
            )
            .is_err()
        );

        value["capture"]["profile"] = json!("large_driver128_v1");
        value["target"]["architecture"] = json!("x86");
        let wrong_arch = serde_json::to_vec(&value).unwrap();
        request.raw_plan_sha256 = digest(&wrong_arch);
        let wrong_request = serde_json::to_vec(&request).unwrap();
        assert!(
            preflight_driver128_public_report(
                &wrong_request,
                &digest(&wrong_request),
                &wrong_arch,
                &view
            )
            .is_err()
        );
    }
}

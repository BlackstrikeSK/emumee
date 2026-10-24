//! Post-run report assessment for an owned Driver128 request.
//! A report from a prior run cannot authorize launch of a future guest.
use crate::{
    analysis_plan::PreparedIntake,
    driver_capture_reports::{self as reports, Binding, Record, VerifiedProjection},
    general_driver128_owned_preflight::{self, OwnedBytes},
    report_bundle::digest,
};
use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Copy)]
pub struct Documents<'a> {
    pub summary: &'a [u8],
    pub engine: &'a [u8],
    pub network: &'a [u8],
    pub manifest: &'a [u8],
    pub checkpoint: &'a [u8],
}

#[derive(Debug, Serialize)]
pub struct Review {
    pub schema: u32,
    pub profile: &'static str,
    pub request_sha256: String,
    pub structural_report_identity_sha256: String,
    pub report_summary_sha256: Option<String>,
    pub verified_summary_status: Option<String>,
    pub owned_identity_verified: bool,
    pub report_documents_verified: bool,
    pub submitted_capture_documents_complete: bool,
    pub same_build_bundle_witness_verified: bool,
    pub os_containment_witness_verified: bool,
    pub general_worker_runtime_qualified: bool,
    pub general_worker_admission: bool,
    pub new_guest_execution_authorized: bool,
    pub unpacking_confirmed: bool,
}

/// Validate owned bytes and, when supplied, an actual report document set and
/// payload projections. The caller must load each payload from an independently
/// pinned source. Source-tree/containment digests are identity inputs only;
/// this core function cannot witness the packaged OS boundary. Verification
/// of an earlier report never permits a new guest run.
pub fn assess(
    owned: &OwnedBytes<'_>,
    source_tree_sha256: &str,
    containment_sha256: &str,
    documents: Option<Documents<'_>>,
    mut load: impl FnMut(&Record) -> Result<VerifiedProjection, reports::Error>,
) -> Result<Review, &'static str> {
    let preflight =
        general_driver128_owned_preflight::inspect(owned, source_tree_sha256, containment_sha256)?;
    let intake = PreparedIntake::prepare_driver128(
        owned.plan.to_vec(),
        vec![owned.target.to_vec(), owned.private_fixture.to_vec()],
    )
    .map_err(|_| "Driver128 post-run owned intake could not resolve")?;
    let binding = Binding::for_general_commitment(
        owned.request,
        &intake,
        source_tree_sha256,
        containment_sha256,
    )
    .map_err(|_| "Driver128 post-run structural binding invalid")?;
    let encoded =
        serde_json::to_vec(&binding).map_err(|_| "Driver128 post-run binding encoding failed")?;
    if digest(&encoded) != preflight.report_identity_sha256 {
        return Err("Driver128 post-run binding differs from owned preflight");
    }
    let (report_summary_sha256, verified_summary_status, submitted_capture_documents_complete) =
        if let Some(documents) = documents {
            let verified = reports::verify(
                documents.summary,
                documents.engine,
                documents.network,
                documents.manifest,
                documents.checkpoint,
                &binding,
                &mut load,
            )
            .map_err(|_| "Driver128 post-run report documents or payloads differ")?;
            let engine: Value = serde_json::from_slice(documents.engine)
                .map_err(|_| "Driver128 post-run engine JSON invalid")?;
            let submitted_capture_documents_complete = engine["mode"] == "submitted_driver_capture"
                && verified.summary.status == "completed"
                && verified.summary.instruction_count > 0
                && engine["execution"]["capture_runtime"]["selected_read_complete"] == true
                && engine["execution"]["capture_runtime"]["capture_complete"] == true
                && engine["execution"]["capture_runtime"]["post_image_sha256"]
                    .as_str()
                    .is_some_and(|hash| hash.len() == 64);
            (
                Some(digest(documents.summary)),
                Some(verified.summary.status),
                submitted_capture_documents_complete,
            )
        } else {
            (None, None, false)
        };
    Ok(Review {
        schema: 1,
        profile: "general_driver128_postrun_review_v1",
        request_sha256: preflight.request_sha256,
        structural_report_identity_sha256: preflight.report_identity_sha256,
        report_summary_sha256,
        verified_summary_status,
        owned_identity_verified: true,
        report_documents_verified: documents.is_some(),
        submitted_capture_documents_complete,
        same_build_bundle_witness_verified: false,
        os_containment_witness_verified: false,
        general_worker_runtime_qualified: false,
        general_worker_admission: false,
        new_guest_execution_authorized: false,
        unpacking_confirmed: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        analysis_plan::Arch,
        artifacts::ArtifactCatalog,
        capture_profile::CaptureProfile,
        driver_capture_reports::Projection,
        driver_capture_reports::{Mode, Stop},
        general_broker_private_attestation::Claim,
        general_execution_commitment::Request,
        plan_runtime::Case,
    };
    use serde_json::json;

    struct Generated {
        request: Vec<u8>,
        plan: Vec<u8>,
        target: Vec<u8>,
        projection: Vec<u8>,
        claim: Vec<u8>,
        fixture: Vec<u8>,
    }
    impl Generated {
        fn view(&self) -> OwnedBytes<'_> {
            OwnedBytes {
                request: &self.request,
                plan: &self.plan,
                target: &self.target,
                public_projection: &self.projection,
                private_claim: &self.claim,
                private_fixture: &self.fixture,
            }
        }
    }
    fn generated() -> Generated {
        let mut kernel = Case::Kernel17.generated(Arch::X64).unwrap();
        let fixture = Case::NativeReplay.generated(Arch::X64).unwrap().fixtures;
        let mut plan: Value = serde_json::from_slice(&kernel.plan).unwrap();
        plan["target"]["service_name"] = json!("TestDrv");
        plan["persona"]["value"]["windows_build"] = json!(22631);
        plan["capture"]["profile"] = json!("large_driver128_v1");
        plan["capture"]["sources"] = json!(["memory_snapshots", "structural_pe"]);
        plan["capture"]["retained_bytes"] = json!(256u64 * 1024 * 1024);
        plan["capture"]["memory_scan_bytes"] = json!(128u64 * 1024 * 1024);
        plan["reports"]["profile"] = json!("large_driver_v1");
        plan["limits"]["worker_memory_mb"] = json!(2048);
        plan["inputs"].as_array_mut().unwrap().push(json!({
            "id":"offline","name":"offline.json","roles":["offline_fixtures"],
            "mount":{"kind":"not_mounted"},"size":fixture.len(),"sha256":digest(&fixture),
        }));
        plan["network"] = json!({"kind":"offline_exact_replay","input":"offline"});
        let plan = serde_json::to_vec(&plan).unwrap();
        let target = kernel.inputs.remove(0);
        let intake =
            PreparedIntake::prepare_driver128(plan.clone(), vec![target.clone(), fixture.clone()])
                .unwrap();
        let request = serde_json::to_vec(
            &Request::from_intake(&intake, "20261019T120000Z-12345678".into()).unwrap(),
        )
        .unwrap();
        let claim =
            serde_json::to_vec(&Claim::from_verified_request(&request, &intake).unwrap()).unwrap();
        let projection = serde_json::to_vec(&Projection::from_bytes(&target).unwrap()).unwrap();
        Generated {
            request,
            plan,
            target,
            projection,
            claim,
            fixture,
        }
    }
    fn binding(sample: &Generated) -> Binding {
        let intake = PreparedIntake::prepare_driver128(
            sample.plan.clone(),
            vec![sample.target.clone(), sample.fixture.clone()],
        )
        .unwrap();
        Binding::for_general_commitment(&sample.request, &intake, &"1".repeat(64), &"2".repeat(64))
            .unwrap()
    }
    #[test]
    fn owned_preflight_without_report_is_not_admission() {
        let sample = generated();
        let review = assess(
            &sample.view(),
            &"1".repeat(64),
            &"2".repeat(64),
            None,
            |_| panic!("No report payload may be loaded"),
        )
        .unwrap();
        assert!(review.owned_identity_verified);
        assert!(!review.report_documents_verified && !review.submitted_capture_documents_complete);
        assert!(!review.general_worker_admission && !review.new_guest_execution_authorized);
        assert!(!review.unpacking_confirmed);
    }
    #[test]
    fn verified_static_documents_cannot_become_submitted_admission() {
        let sample = generated();
        let catalog = ArtifactCatalog::with_profile(CaptureProfile::Driver128V1);
        let bundle = reports::build(
            "20261019T120000Z-12345678",
            &binding(&sample),
            Mode::StaticGeneratedCapture,
            &json!({"completion_reason":"static_inspection","instruction_count":0,
                "guest_entry_return":null}),
            Stop::Normal,
            false,
            &catalog,
        )
        .unwrap();
        let documents = Documents {
            summary: &bundle.summary,
            engine: &bundle.engine,
            network: &bundle.network,
            manifest: &bundle.manifest,
            checkpoint: &bundle.checkpoint,
        };
        let review = assess(
            &sample.view(),
            &"1".repeat(64),
            &"2".repeat(64),
            Some(documents),
            |_| panic!("Static empty catalog must have no payload"),
        )
        .unwrap();
        assert!(review.report_documents_verified);
        assert_eq!(review.verified_summary_status.as_deref(), Some("partial"));
        assert!(!review.submitted_capture_documents_complete && !review.general_worker_admission);
        assert!(!review.new_guest_execution_authorized && !review.unpacking_confirmed);
        let mut bad_checkpoint = bundle.checkpoint.clone();
        bad_checkpoint[0] ^= 1;
        assert!(
            assess(
                &sample.view(),
                &"1".repeat(64),
                &"2".repeat(64),
                Some(Documents {
                    checkpoint: &bad_checkpoint,
                    ..documents
                }),
                |_| panic!("Tampered checkpoint must fail before payload load"),
            )
            .is_err()
        );
    }
    #[test]
    fn changed_owned_request_or_source_identity_refuses_old_documents() {
        let mut sample = generated();
        let catalog = ArtifactCatalog::with_profile(CaptureProfile::Driver128V1);
        let bundle = reports::build(
            "20261019T120000Z-12345678",
            &binding(&sample),
            Mode::StaticGeneratedCapture,
            &json!({"completion_reason":"static_inspection","instruction_count":0,
                "guest_entry_return":null}),
            Stop::Normal,
            false,
            &catalog,
        )
        .unwrap();
        let documents = Documents {
            summary: &bundle.summary,
            engine: &bundle.engine,
            network: &bundle.network,
            manifest: &bundle.manifest,
            checkpoint: &bundle.checkpoint,
        };
        assert!(
            assess(
                &sample.view(),
                &"3".repeat(64),
                &"2".repeat(64),
                Some(documents),
                |_| panic!("No payload expected"),
            )
            .is_err()
        );
        sample.target[0] ^= 1;
        assert!(
            assess(
                &sample.view(),
                &"1".repeat(64),
                &"2".repeat(64),
                None,
                |_| panic!("No payload expected"),
            )
            .is_err()
        );
    }
}

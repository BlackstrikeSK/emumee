use emumee_core::{
    artifacts::{ArtifactCatalog, ArtifactKind},
    report_bundle::{self, Input, NetworkCoverage, Profile, Termination},
    reports,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
fn bytes(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn report_builder_preserves_generated_legacy_groups_and_completion_classification() {
    let raw = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/report_bundle_reference.json"),
    )
    .unwrap();
    assert_eq!(raw.len(), 52505);
    assert_eq!(
        format!("{:x}", Sha256::digest(&raw)),
        "11054a7779a74bb9a5005b9324f2e4edd02a0f0bb11e2ecce37f537fd6b54f91"
    );
    let corpus: Value = serde_json::from_slice(&raw).unwrap();
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 20);
    for case in cases {
        let mut captures = ArtifactCatalog::default();
        for payload in case["payloads"].as_array().unwrap() {
            let data = bytes(payload["bytes_hex"].as_str().unwrap());
            for observation in payload["observations"].as_array().unwrap() {
                let kind = match observation["kind"].as_str().unwrap() {
                    "guest_file" => ArtifactKind::GuestFile,
                    "memory_snapshot" => ArtifactKind::MemorySnapshot,
                    "container_stream" => ArtifactKind::ContainerStream,
                    "registry_value" => ArtifactKind::RegistryValue,
                    "carved_image" => ArtifactKind::CarvedImage,
                    _ => panic!("unknown owned kind"),
                };
                captures.add_with_context(
                    data.clone(),
                    kind,
                    observation["source"].as_str().unwrap(),
                    observation["guest_path"].as_str().unwrap(),
                    observation
                        .get("context")
                        .map(|v| v.as_object().unwrap().clone()),
                );
            }
        }
        let bundle = report_bundle::build(Input {
            run_id: "20261018T120000Z-12345678",
            started_at: "2026-10-18T12:00:00Z",
            finished_at: "2026-10-18T12:00:01Z",
            sample: &json!({"name":"owned.exe"}),
            execution: &case["execution"],
            execution_mode: "user",
            manifest: &json!({}),
            network: &json!({"events":[]}),
            network_coverage: NetworkCoverage::NotMonitored,
            termination: if case["termination"] == "timeout" {
                Termination::Timeout
            } else {
                Termination::Normal
            },
            checkpoint_recovered: false,
            profile: Profile::LegacyV1,
            artifacts: &captures.items,
            omissions: &captures.summary,
        })
        .unwrap_or_else(|e| panic!("{}: {e}", case["name"]));
        let summary = reports::parse_summary(&bundle.summary).unwrap();
        assert_eq!(summary["status"], case["status"], "{}", case["name"]);
        assert_eq!(summary["artifacts"], case["flat"], "{}", case["name"]);
        assert_eq!(
            summary["artifact_groups"], case["groups"],
            "{}",
            case["name"]
        );
        assert!(reports::verified_artifact_manifest(
            &bundle.manifest,
            &summary["artifacts"],
            Some(&summary["artifact_groups"]),
            |item| bundle
                .payloads
                .iter()
                .find(|p| p.sha256 == item["sha256"])
                .map(|p| p.bytes.to_vec())
        ));
        assert_eq!(summary["network_broker_complete"], false);
        assert_eq!(summary["guest_trace_complete"], false);
    }
}

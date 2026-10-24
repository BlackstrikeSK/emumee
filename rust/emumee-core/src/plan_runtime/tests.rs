use super::*;
#[test]
fn independent_reference_metadata_pins_guest_results_without_claiming_execution() {
    let raw = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/plan_runtime_reference.json"),
    )
    .unwrap();
    assert_eq!(
        digest(&raw),
        "6b034f87f7e18e7b34976e5124ae11cbf34a45467283f37e89f587400f0afe25"
    );
    let reference: Value = serde_json::from_slice(&raw).unwrap();
    for row in reference["cases"].as_array().unwrap() {
        let case = Case::parse(row["case"].as_str().unwrap()).unwrap();
        assert_eq!(case.expected_return(), row["guest_entry_return"].as_u64());
        assert_eq!(
            usize::from(case.network_probe()),
            row["broker_attempts"].as_u64().unwrap() as usize
        );
    }
}
fn generated(case: Case, arch: p::Arch) -> (Vec<u8>, Generated) {
    let (r, g) = Request::generated(
        case,
        arch,
        "20261018T120000Z-00000001".into(),
        "2026-10-18T12:00:00Z".into(),
    )
    .unwrap();
    (serde_json::to_vec(&r).unwrap(), g)
}
#[test]
fn public_buffers_and_private_commitments_are_distinct_and_planning_stays_inert() {
    for arch in [p::Arch::X86, p::Arch::X64] {
        for case in [
            Case::NativeA,
            Case::NativeB,
            Case::NativeReplay,
            Case::NativeDeny,
            Case::Kernel17,
            Case::Kernel19,
            Case::StaticMsi,
        ] {
            let (raw, g) = generated(case, arch);
            let parent =
                PreparedAnalysis::prepare(&raw, &g.plan, g.inputs.clone(), g.persona.clone())
                    .unwrap();
            assert!(!parent.resolved().executable());
            let public = parent
                .spec()
                .inputs
                .iter()
                .zip(&g.inputs)
                .map(|(s, b)| {
                    (!s.roles.contains(&p::InputRole::OfflineFixtures)).then(|| b.clone())
                })
                .collect();
            let worker =
                PreparedAnalysis::prepare_worker(&raw, &g.plan, public, g.persona).unwrap();
            assert_eq!(worker.input(), g.inputs[0]);
            assert_eq!(worker.resolved().sha256(), parent.resolved().sha256());
            assert_ne!(
                worker.receipt()["inventory_authority"],
                parent.receipt()["inventory_authority"]
            );
            assert!(
                worker.receipt()["inventory_authority"]
                    .as_str()
                    .unwrap()
                    .contains("uninspected_commitment")
            );
            assert!(
                worker.receipt()["physical_reservation"]["total_reserved_output_bytes"]
                    .as_u64()
                    .unwrap()
                    <= MAX_OUTPUT
            );
            let (_, process) = worker.prepare_state().unwrap();
            assert_eq!(process.is_some(), !case.kernel() && !case.static_only());
        }
    }
}
#[test]
fn coherent_foreign_target_and_changed_configuration_cannot_mint_a_role() {
    let (raw, mut g) = generated(Case::NativeA, p::Arch::X64);
    let mut plan: Value = serde_json::from_slice(&g.plan).unwrap();
    g.inputs[0][0x200] ^= 1;
    plan["inputs"][0]["sha256"] = json!(digest(&g.inputs[0]));
    let altered = serde_json::to_vec(&plan).unwrap();
    assert!(
        PreparedAnalysis::prepare(&raw, &altered, g.inputs.clone(), g.persona.clone()).is_err()
    );
    let mut request: Value = serde_json::from_slice(&raw).unwrap();
    request["plan_sha256"] = json!(digest(&altered));
    assert!(
        PreparedAnalysis::prepare(
            &serde_json::to_vec(&request).unwrap(),
            &altered,
            g.inputs,
            g.persona
        )
        .is_err()
    );
    for field in ["generated_only", "executable", "qualified", "host_path"] {
        let mut bad: Value = serde_json::from_slice(&raw).unwrap();
        bad[field] = json!(true);
        assert!(
            Request::parse(&serde_json::to_vec(&bad).unwrap()).is_err(),
            "{field}"
        );
    }
    assert!(Request::parse(br#"{"schema":1,"schema":1}"#).is_err());
}
#[test]
fn worker_refuses_private_bytes_and_missing_or_tampered_public_slots() {
    let (raw, g) = generated(Case::NativeReplay, p::Arch::X64);
    assert!(
        PreparedAnalysis::prepare_worker(
            &raw,
            &g.plan,
            g.inputs.iter().cloned().map(Some).collect(),
            g.persona.clone()
        )
        .is_err()
    );
    let parent =
        PreparedAnalysis::prepare(&raw, &g.plan, g.inputs.clone(), g.persona.clone()).unwrap();
    let public: Vec<_> = parent
        .spec()
        .inputs
        .iter()
        .zip(&g.inputs)
        .map(|(s, b)| (!s.roles.contains(&p::InputRole::OfflineFixtures)).then(|| b.clone()))
        .collect();
    let mut missing = public.clone();
    missing[0] = None;
    assert!(PreparedAnalysis::prepare_worker(&raw, &g.plan, missing, g.persona.clone()).is_err());
    let mut altered = public;
    altered[1].as_mut().unwrap()[0] ^= 1;
    assert!(PreparedAnalysis::prepare_worker(&raw, &g.plan, altered, g.persona).is_err());
}
#[test]
fn broker_session_is_not_a_fixture_probe_or_user_capability() {
    let (raw, g) = generated(Case::NativeReplay, p::Arch::X64);
    let parent = PreparedAnalysis::prepare(&raw, &g.plan, g.inputs, g.persona).unwrap();
    let config = BrokerSession::new(&parent, "owned-cleanup-location".into());
    let value = serde_json::to_value(config).unwrap();
    assert!(BrokerSession::parse(&serde_json::to_vec(&value).unwrap(), &raw).is_ok());
    for (field, new) in [
        ("deadline_ms", json!(48001)),
        ("plan_sha256", json!("0".repeat(64))),
        ("fixture_sha256", json!("0".repeat(64))),
        ("probe", json!("normal")),
        ("qualified", json!(true)),
    ] {
        let mut bad = value.clone();
        bad[field] = new;
        assert!(
            BrokerSession::parse(&serde_json::to_vec(&bad).unwrap(), &raw).is_err(),
            "{field}"
        );
    }
}

#[test]
fn fault_recipes_are_fixed_bind_actual_inputs_and_preserve_planning_gate() {
    let names = [
        "crash-after-checkpoint",
        "timeout-after-checkpoint",
        "broker-death",
        "broker-partial",
        "controller-exit",
        "controller-partial",
        "reconfigure",
        "guest-timeout",
        "output-directories",
    ];
    for name in names {
        let fault = Fault::parse(name).unwrap();
        for arch in [p::Arch::X86, p::Arch::X64] {
            let (request, g) = Request::generated_fault(
                fault.case(),
                fault,
                arch,
                "20261019T120000Z-00000001".into(),
                "2026-10-19T12:00:00Z".into(),
            )
            .unwrap();
            let raw = serde_json::to_vec(&request).unwrap();
            let parent =
                PreparedAnalysis::prepare(&raw, &g.plan, g.inputs.clone(), g.persona.clone())
                    .unwrap();
            assert!(!parent.resolved().executable());
            assert_eq!(
                parent.resolved().value()["budget"]["worker_deadline_ms"],
                fault.worker_deadline_ms()
            );
            assert_eq!(
                parent.resolved().value()["budget"]["broker_deadline_ms"],
                fault.broker_deadline_ms()
            );
            let session =
                serde_json::to_vec(&BrokerSession::new(&parent, "private-owned-cleanup".into()))
                    .unwrap();
            assert!(BrokerSession::parse(&session, &raw).is_ok());
            let mut changed = g.inputs.clone();
            changed[0][0x200] ^= 1;
            assert!(PreparedAnalysis::prepare(&raw, &g.plan, changed, g.persona.clone()).is_err());
            assert!(
                Request::generated_fault(
                    Case::StaticMsi,
                    fault,
                    arch,
                    "20261019T120000Z-00000001".into(),
                    "2026-10-19T12:00:00Z".into()
                )
                .is_err()
            );
            if fault.checkpoint() {
                assert!(
                    g.inputs[0]
                        .windows(b"fault-checkpoint.bin".len())
                        .any(|w| w == b"fault-checkpoint.bin")
                );
                assert!(g.inputs[0].windows(4).any(|w| w == b"RUST"));
                assert_ne!(g.inputs[0], fault.case().generated(arch).unwrap().inputs[0]);
            }
        }
    }
    for bad in ["none", "arbitrary", "crash-after-checkpoint-extra", ""] {
        assert!(Fault::parse(bad).is_none());
    }
}
#[test]
fn normal_request_bytes_stay_fault_free_and_unknown_faults_cannot_decode() {
    let (raw, g) = generated(Case::NativeA, p::Arch::X64);
    assert!(
        serde_json::from_slice::<Value>(&raw)
            .unwrap()
            .get("fault")
            .is_none()
    );
    let mut bad: Value = serde_json::from_slice(&raw).unwrap();
    bad["fault"] = json!("user-hook");
    assert!(Request::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
    bad["fault"] = json!("guest-timeout");
    assert!(Request::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
    let prepared = PreparedAnalysis::prepare(&raw, &g.plan, g.inputs, g.persona).unwrap();
    assert_eq!(prepared.request().fault, Fault::None);
}

#[test]
fn independent_fault_deadline_reference_keeps_controller_and_guest_timeouts_distinct() {
    let raw = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/plan_fault_reference.json"),
    )
    .unwrap();
    assert_eq!(
        digest(&raw),
        "908d50bbd78a24921fa37b8a5b62e25588429054c33e8bbc555bb0e448f9708a"
    );
    let reference: Value = serde_json::from_slice(&raw).unwrap();
    for row in reference["cases"].as_array().unwrap() {
        let fault = Fault::parse(row["fault"].as_str().unwrap()).unwrap();
        assert_eq!(row["worker_deadline_ms"], fault.worker_deadline_ms());
        assert_eq!(row["broker_deadline_ms"], fault.broker_deadline_ms());
        assert_eq!(row["checkpoint_recovered"], fault.checkpoint());
        assert_eq!(row["broker_attempts"], usize::from(fault.broker_failure()));
    }
}

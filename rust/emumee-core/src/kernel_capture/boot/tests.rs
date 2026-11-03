use super::*;

#[derive(Deserialize)]
struct Case {
    inputs: Inputs,
    observations: BTreeMap<Query, Observation>,
    expected: Outcome,
}
#[test]
fn preparation_matches_native_instruction_oracle_and_exact_missing_query_prefixes() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../tests/fixtures/native_capture_boot.json"
    ))
    .unwrap();
    let cases: Vec<Case> = serde_json::from_value(fixture["cases"].clone()).unwrap();
    assert_eq!(cases.len(), 1024);
    for (index, case) in cases.into_iter().enumerate() {
        let actual = evaluate(case.inputs, &case.observations).unwrap();
        assert_eq!(
            actual,
            Progress::Complete(case.expected.clone()),
            "case{index}"
        );
        let mut partial = BTreeMap::new();
        for query in &case.expected.reads {
            assert_eq!(
                evaluate(case.inputs, &partial).unwrap(),
                Progress::Needs(*query),
                "case{index}"
            );
            partial.insert(*query, case.observations[query].clone());
        }
        assert_eq!(
            evaluate(case.inputs, &partial).unwrap(),
            actual,
            "case{index}"
        );
    }
}
#[test]
fn successful_short_dwords_are_refused_and_failed_outputs_are_not_consumed() {
    let input = Inputs {
        output_present: true,
        initial_state: 0,
        initial_provisioning_flag: 0,
    };
    let mut observations = BTreeMap::new();
    for length in 0..4 {
        observations.insert(
            Query::GuardedHost,
            Observation {
                status: 0,
                bytes: vec![0; length],
            },
        );
        assert_eq!(
            evaluate(input, &observations).unwrap_err(),
            if length == 0 {
                Error::EmptySuccess(Query::GuardedHost)
            } else {
                Error::ShortDword(Query::GuardedHost)
            }
        );
    }
    observations.insert(
        Query::GuardedHost,
        Observation {
            status: 0xc000003a,
            bytes: vec![0; 8],
        },
    );
    let Progress::Complete(out) = evaluate(input, &observations).unwrap() else {
        panic!("missing completed failure projection")
    };
    assert_eq!(
        (out.force_dump_disabled, out.state, out.error_event_intent),
        (1, 3, Some(2))
    );
    assert!(out.release_intents.is_empty());
    assert_eq!(out.output, Some(false));
}
#[test]
fn native_open_plans_preserve_missing_parent_vs_missing_leaf_without_publishing_handles() {
    let mut registry = Registry::new(0);
    let first = registry
        .plan_native_open(NativeOpen {
            architecture: Architecture::X64,
            owner: 4,
            root: 0,
            name: r"\Registry\Machine",
            access: KEY_READ,
        })
        .unwrap()
        .handle();
    assert_eq!(
        observe_open_failure(&registry, Query::GuardedHost)
            .unwrap()
            .unwrap()
            .status,
        0xc000003a
    );
    registry
        .seed_key(r"HKLM\System\CurrentControlSet\Control\CrashControl")
        .unwrap();
    assert_eq!(
        observe_open_failure(&registry, Query::GuardedHost)
            .unwrap()
            .unwrap()
            .status,
        0xc0000034
    );
    registry
        .seed_key(r"HKLM\System\CurrentControlSet\Control\CrashControl\ForceDumpsDisabled")
        .unwrap();
    assert!(
        observe_open_failure(&registry, Query::GuardedHost)
            .unwrap()
            .is_none()
    );
    let next = registry
        .plan_native_open(NativeOpen {
            architecture: Architecture::X64,
            owner: 4,
            root: 0,
            name: r"\Registry\Machine",
            access: KEY_READ,
        })
        .unwrap()
        .handle();
    assert_eq!(first, next);
}

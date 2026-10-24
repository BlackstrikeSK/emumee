use super::*;
use serde_json::{Value, json};
fn owned(arch: Arch, kind: &str) -> Vec<u8> {
    match kind {
        "kernel" => crate::fixtures::counted_driver(arch.architecture(), 17),
        "managed" => {
            crate::fixtures::cil_probe(arch.architecture(), crate::fixtures::CilFixture::Return, 17)
        }
        "msi" => crate::msi_fixture::input(crate::msi_fixture::Case::MiniV3),
        _ => {
            let mut raw = crate::fixtures::api_probe(
                arch.architecture(),
                crate::fixtures::ApiFixture::UserState,
            );
            if kind == "dll" {
                let at = u32::from_le_bytes(raw[0x3c..0x40].try_into().unwrap()) as usize + 22;
                let value = u16::from_le_bytes(raw[at..at + 2].try_into().unwrap()) | 0x2000;
                raw[at..at + 2].copy_from_slice(&value.to_le_bytes());
            }
            raw
        }
    }
}
fn input(id: &str, name: &str, raw: &[u8], roles: Value, mount: Value) -> Value {
    json!({"id":id,"name":name,"roles":roles,"mount":mount,"size":raw.len(),"sha256":digest(raw)})
}
fn spec_json(arch: Arch, kind: &str, raw: &[u8]) -> Value {
    let arch = serde_json::to_value(arch).unwrap();
    let name = if kind == "kernel" {
        "owned.sys"
    } else if kind == "msi" {
        "owned.msi"
    } else {
        "owned.exe"
    };
    let target = match kind {
        "kernel" => {
            json!({"kind":"kernel_driver","input":"primary","architecture":arch,"unload":false,"code_reference":{"kind":"none"}})
        }
        "managed" => {
            json!({"kind":"managed_entry","input":"primary","architecture":arch,"apphost":{"kind":"none"}})
        }
        "dll" => {
            json!({"kind":"native_dll","input":"primary","architecture":arch,"exports":"disabled"})
        }
        "msi" => json!({"kind":"static_msi","input":"primary"}),
        _ => json!({"kind":"native_exe","input":"primary","architecture":arch}),
    };
    json!({"schema":1,"target":target,"inputs":[input("primary",name,raw,json!(["original_primary","execution_primary"]),json!({"kind":"not_mounted"}))],"companions":[],
        "persona":{"kind":"rust_modeled_v1","value":{"process":crate::persona::PersonaConfig::fixture(),"cpu":crate::cpu::CpuProfile::default(),"clock":{"utc_filetime":133000000000000000u64,"uptime_ms":523812000,"utc_offset_minutes":-240,"source":"fixed","source_id":"owned-seed"},"windows_build":22631,"current_processor":0,"physical_memory_mb":16384,"available_memory_mb":7168}},
        "invocation":if ["kernel","msi"].contains(&kind){json!({"kind":"none"})}else{json!({"kind":"process","guest_root":"C:\\Users\\Alex\\Downloads","arguments":[],"force_quote_indices":[],"environment":[]})},"network":{"kind":"offline_deny"},
        "limits":{"guest_timeout_ms":60000,"max_instructions":2000000,"max_native_api_calls":100000,"worker_startup_ms":15000,"reporting_grace_ms":15000,"broker_startup_ms":10000,"broker_grace_ms":5000,
            "worker_memory_mb":1024,"broker_memory_mb":256,"max_output_bytes":1073741824u64,"max_output_entries":11000,"max_output_directories":64,"max_output_depth":40,
            "guest_mapped_bytes":67108864,"guest_heap_bytes":16777216,"guest_pool_bytes":16777216,"guest_threads":8,"broker_stream_bytes":134217728,"broker_journal_bytes":67108864},
        "capture":{"profile":"legacy32_capture_v1","sources":[],"retained_bytes":16777216,"memory_scan_bytes":134217728,"memory_strings":{"kind":"disabled"},"checkpoint":{"kind":"final_boundary"}},
        "reports":{"profile":"legacy_v1","summary_bytes":5242880,"engine_bytes":52428800,"network_bytes":67108864,"manifest_bytes":1048576}})
}
fn decode(value: &Value) -> PlanSpec {
    PlanSpec::decode(&serde_json::to_vec(value).unwrap()).unwrap()
}
fn checked(spec: &PlanSpec, raw: &[u8]) -> VerifiedInventory {
    VerifiedInventory::verify(
        &spec.inputs,
        &[InputBytes {
            id: "primary",
            bytes: raw,
        }],
    )
    .unwrap()
}
fn rejection(mut value: Value, raw: &[u8], path: &str, new: Value, expected: &str) {
    *value.pointer_mut(path).unwrap() = new;
    let spec = decode(&value);
    let inventory = checked(&spec, raw);
    let error = resolve(&spec, &inventory, &Capabilities::planning_only_v1())
        .err()
        .expect(path);
    assert_eq!(error.code, expected, "{path}: {error}");
}
#[test]
fn kernel_service_identity_is_validated_and_committed_without_execution_authority() {
    let raw = owned(Arch::X64, "kernel");
    let mut first = spec_json(Arch::X64, "kernel", &raw);
    let legacy = decode(&first);
    let legacy_plan = resolve(
        &legacy,
        &checked(&legacy, &raw),
        &Capabilities::planning_only_v1(),
    )
    .unwrap();
    assert!(!legacy_plan.executable());
    assert!(legacy_plan.value()["target"].get("service_name").is_none());

    first["target"]["service_name"] = json!("TestDrv");
    let first_spec = decode(&first);
    let first_plan = resolve(
        &first_spec,
        &checked(&first_spec, &raw),
        &Capabilities::planning_only_v1(),
    )
    .unwrap();
    assert_eq!(first_plan.value()["target"]["service_name"], "TestDrv");
    assert!(!first_plan.executable());
    assert_ne!(first_plan.sha256(), legacy_plan.sha256());
    assert_ne!(first_plan.request_sha256(), legacy_plan.request_sha256());

    // The planning identity uses the exact spelling accepted by the typed
    // submitted-driver request/report path. A future executable profile must
    // bind this name and the resolved request hash independently at admission.
    let submitted = crate::driver_input::Request::new(
        "20261019T120000Z-12345678".into(),
        digest(&raw),
        raw.len() as u64,
        "TestDrv".into(),
        10_000,
        30_000_000,
    )
    .unwrap();
    assert_eq!(
        submitted.service_name.as_str(),
        first_plan.value()["target"]["service_name"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        submitted.registry_path(),
        r"\Registry\Machine\System\CurrentControlSet\Services\TestDrv"
    );
    assert_eq!(submitted.module_name().to_ascii_lowercase(), "testdrv.sys");

    let mut other = first.clone();
    other["target"]["service_name"] = json!("OtherDrv");
    let other_spec = decode(&other);
    let other_plan = resolve(
        &other_spec,
        &checked(&other_spec, &raw),
        &Capabilities::planning_only_v1(),
    )
    .unwrap();
    assert_ne!(first_plan.sha256(), other_plan.sha256());
    assert_ne!(first_plan.request_sha256(), other_plan.request_sha256());
    rejection(
        first,
        &raw,
        "/target/service_name",
        json!("../driver"),
        "service_identity",
    );
}

#[test]
fn all_five_real_generated_mode_graphs_bind_bytes_without_execution_authority() {
    for arch in [Arch::X86, Arch::X64] {
        for kind in ["exe", "dll", "kernel", "managed", "msi"] {
            let raw = owned(arch, kind);
            let value = spec_json(arch, kind, &raw);
            let spec = decode(&value);
            let inventory = checked(&spec, &raw);
            let resolved = resolve(&spec, &inventory, &Capabilities::planning_only_v1())
                .unwrap_or_else(|e| panic!("{arch:?}/{kind}: {e}"));
            assert!(!resolved.executable());
            assert_eq!(resolved.value()["executable"], false);
            assert_eq!(
                resolved.value()["inputs"][0]["binding"]["spec"]["sha256"],
                digest(&raw)
            );
            assert_eq!(resolved.request_sha256(), digest(resolved.request_bytes()));
            assert_eq!(
                resolved.sha256(),
                identity(b"emumee.analysis.plan.v1\0", resolved.canonical_bytes())
            );
            assert_eq!(
                resolved.value()["budget"]["broker_request_stream_bytes"],
                134217728u64
            );
            assert_eq!(
                resolved.value()["budget"]["broker_response_stream_bytes"],
                134217728u64
            );
            assert_eq!(
                resolved.value()["budget"]["private_broker_journal_bytes"],
                67108864u64
            );
            // Contract sum:126MiB report/checkpoint copies,256MiB two pinned
            // streams,64MiB journal,16MiB capture,2MiB request,8MiB receipts.
            assert_eq!(
                resolved.value()["budget"]["minimum_output_bytes"],
                472 * 1024 * 1024 + raw.len() as u64
            );
            assert!(
                resolved.value()["blocked_by"][0]
                    .as_str()
                    .unwrap()
                    .contains("not_qualified")
            );
            let again = resolve(&spec, &inventory, &Capabilities::planning_only_v1()).unwrap();
            assert_eq!(resolved.canonical_bytes(), again.canonical_bytes());
        }
    }
}
#[test]
fn owned_intake_binds_exact_plan_and_ordered_bytes_without_launch_authority() {
    let raw = owned(Arch::X64, "exe");
    let plan = serde_json::to_vec(&spec_json(Arch::X64, "exe", &raw)).unwrap();
    let intake = PreparedIntake::prepare(plan.clone(), vec![raw.clone()]).unwrap();
    assert_eq!(intake.raw_plan(), plan.as_slice());
    assert!(!intake.resolved().executable());
    assert_eq!(intake.slots().len(), 1);
    let (slot, bytes) = intake.slots().next().unwrap();
    assert_eq!(slot.id, "primary");
    assert_eq!(bytes, raw.as_slice());
    assert_eq!(slot.sha256, digest(bytes));

    let mut changed = raw.clone();
    changed[0] ^= 1;
    assert_eq!(intake.slots().next().unwrap().1, raw.as_slice());
    assert_eq!(
        PreparedIntake::prepare(plan.clone(), vec![changed])
            .err()
            .unwrap()
            .code,
        "binding_mismatch"
    );
    for inputs in [vec![], vec![raw.clone(), raw.clone()]] {
        assert_eq!(
            PreparedIntake::prepare(plan.clone(), inputs)
                .err()
                .unwrap()
                .code,
            "inventory_count"
        );
    }
}
#[test]
fn owned_intake_preserves_two_physical_slots_and_rejects_swapping() {
    let raw = owned(Arch::X64, "exe");
    let data = b"generated-package-data".to_vec();
    let mut value = spec_json(Arch::X64, "exe", &raw);
    value["inputs"].as_array_mut().unwrap().push(input(
        "data",
        "data.bin",
        &data,
        json!(["guest_file"]),
        json!({"kind":"package","path":"config/data.bin"}),
    ));
    let plan = serde_json::to_vec(&value).unwrap();
    let intake = PreparedIntake::prepare(plan.clone(), vec![raw.clone(), data.clone()]).unwrap();
    let slots = intake.slots().collect::<Vec<_>>();
    assert_eq!(slots.len(), 2);
    assert_eq!(
        (slots[0].0.id.as_str(), slots[0].1),
        ("primary", raw.as_slice())
    );
    assert_eq!(
        (slots[1].0.id.as_str(), slots[1].1),
        ("data", data.as_slice())
    );
    assert_eq!(
        intake.resolved().value()["inputs"][0]["binding"]["spec"]["id"],
        "primary"
    );
    assert_eq!(
        intake.resolved().value()["inputs"][0]["staging_slot"],
        "inputs/0000.bin"
    );
    assert_eq!(
        intake.resolved().value()["inputs"][1]["binding"]["spec"]["id"],
        "data"
    );
    assert_eq!(
        intake.resolved().value()["inputs"][1]["staging_slot"],
        "inputs/0001.bin"
    );
    assert_eq!(
        PreparedIntake::prepare(plan, vec![data, raw])
            .err()
            .unwrap()
            .code,
        "binding_mismatch"
    );
}
#[test]
fn schema_duplicate_nested_keys_unknown_options_wrong_numbers_and_depth_fail_closed() {
    let raw = owned(Arch::X64, "exe");
    let baseline = spec_json(Arch::X64, "exe", &raw);
    let encoded = serde_json::to_string(&baseline).unwrap();
    assert!(
        PlanSpec::decode(
            encoded
                .replacen("\"schema\":1", "\"schema\":1,\"schema\":1", 1)
                .as_bytes()
        )
        .is_err()
    );
    assert!(
        PlanSpec::decode(
            encoded
                .replacen("\"hostname\":", "\"hostname\":\"forged\",\"hostname\":", 1)
                .as_bytes()
        )
        .is_err()
    );
    for (path, value) in [
        ("/schema", json!(true)),
        ("/schema", json!(1.0)),
        ("/limits/max_instructions", json!(-1)),
        ("/target/architecture", Value::Null),
    ] {
        let mut bad = baseline.clone();
        *bad.pointer_mut(path).unwrap() = value;
        assert!(
            PlanSpec::decode(&serde_json::to_vec(&bad).unwrap()).is_err(),
            "{path}"
        );
    }
    let mut bad = baseline;
    bad["persona"]["value"]["services"] = json!([]);
    let unsupported = PlanSpec::decode(&serde_json::to_vec(&bad).unwrap())
        .err()
        .unwrap();
    assert_eq!(unsupported.code, "unsupported_persona_field");
    assert_eq!(unsupported.field, "persona.value.services");
    assert!(PlanSpec::decode(&[b' '; MAX_PLAN_BYTES + 1]).is_err());
    let nested = format!("{}0{}", "[".repeat(34), "]".repeat(34));
    assert!(super::decode::strict_json(nested.as_bytes(), MAX_PLAN_BYTES).is_err());
    assert!(PlanSpec::decode(format!("{encoded} {{}}").as_bytes()).is_err());
}
#[test]
fn byte_inventory_cannot_be_forged_rebound_or_supply_orphan_files() {
    let raw = owned(Arch::X64, "exe");
    let mut value = spec_json(Arch::X64, "exe", &raw);
    let mut spec = decode(&value);
    let inventory = checked(&spec, &raw);
    let mut changed = raw.clone();
    changed[0] ^= 1;
    assert!(
        VerifiedInventory::verify(
            &spec.inputs,
            &[InputBytes {
                id: "primary",
                bytes: &changed
            }]
        )
        .is_err()
    );
    assert!(
        VerifiedInventory::verify(
            &spec.inputs,
            &[
                InputBytes {
                    id: "primary",
                    bytes: &raw
                },
                InputBytes {
                    id: "extra",
                    bytes: b"owned"
                }
            ]
        )
        .is_err()
    );
    spec.inputs[0].name = "changed.exe".into();
    assert_eq!(
        resolve(&spec, &inventory, &Capabilities::planning_only_v1())
            .err()
            .unwrap()
            .code,
        "binding_mismatch"
    );
    value["inputs"].as_array_mut().unwrap().push(input(
        "orphan",
        "owned.txt",
        b"owned",
        json!(["guest_file"]),
        json!({"kind":"not_mounted"}),
    ));
    let spec = decode(&value);
    let inventory = VerifiedInventory::verify(
        &spec.inputs,
        &[
            InputBytes {
                id: "primary",
                bytes: &raw,
            },
            InputBytes {
                id: "orphan",
                bytes: b"owned",
            },
        ],
    )
    .unwrap();
    assert_eq!(
        resolve(&spec, &inventory, &Capabilities::planning_only_v1())
            .err()
            .unwrap()
            .code,
        "guest_mount"
    );
}
#[test]
fn unsupported_features_and_resource_mismatches_are_explicit() {
    let raw = owned(Arch::X64, "exe");
    let value = spec_json(Arch::X64, "exe", &raw);
    for (path, new, code) in [
        (
            "/capture/profile",
            json!("large_driver128_v1"),
            "unsupported_profile",
        ),
        ("/network/kind", json!("live"), "unsupported_option"),
        (
            "/capture/memory_strings",
            json!({"kind":"indicators","patterns":[]}),
            "unsupported_option",
        ),
        (
            "/capture/checkpoint",
            json!({"kind":"periodic","instructions":100}),
            "unsupported_option",
        ),
        (
            "/persona/value/clock/source",
            json!("controller_resolved"),
            "unsupported_option",
        ),
        (
            "/persona/value/current_processor",
            json!(99),
            "persona_inconsistent",
        ),
        (
            "/persona/value/physical_memory_mb",
            json!(1),
            "persona_memory",
        ),
        (
            "/persona/value/process/logical_processors",
            json!(1),
            "persona_inconsistent",
        ),
        ("/limits/max_output_bytes", json!(1), "output_budget"),
        (
            "/limits/broker_stream_bytes",
            json!(u64::MAX),
            "broker_limit",
        ),
        (
            "/limits/guest_timeout_ms",
            json!(u64::MAX),
            "execution_limit",
        ),
        ("/limits/worker_memory_mb", json!(1), "job_limit"),
        ("/limits/guest_mapped_bytes", json!(1), "guest_memory_limit"),
        ("/limits/max_output_entries", json!(1), "output_shape"),
    ] {
        rejection(value.clone(), &raw, path, new, code);
    }
    rejection(
        value.clone(),
        &raw,
        "/persona",
        json!({"kind":"legacy_persona_v1","input":"persona"}),
        "unsupported_persona_schema",
    );
    let kernel = owned(Arch::X64, "kernel");
    let kernel_spec = spec_json(Arch::X64, "kernel", &kernel);
    rejection(
        kernel_spec.clone(),
        &kernel,
        "/target/unload",
        json!(true),
        "unsupported_option",
    );
    rejection(
        kernel_spec,
        &kernel,
        "/invocation",
        json!({"kind":"process","guest_root":"C:\\Users\\Alex\\Downloads","arguments":[],"environment":[],"force_quote_indices":[]}),
        "invocation_mode",
    );
    let managed = owned(Arch::X64, "managed");
    let managed_spec = spec_json(Arch::X64, "managed", &managed);
    let mut bad = managed_spec;
    bad["invocation"]["arguments"] = json!(["x"]);
    bad["invocation"]["force_quote_indices"] = json!([0]);
    let spec = decode(&bad);
    assert_eq!(
        resolve(
            &spec,
            &checked(&spec, &managed),
            &Capabilities::planning_only_v1()
        )
        .err()
        .unwrap()
        .code,
        "unsupported_option"
    );
}
#[test]
fn actual_pe_kind_and_architecture_govern_the_target_not_user_tags() {
    let raw = owned(Arch::X86, "exe");
    let baseline = spec_json(Arch::X86, "exe", &raw);
    rejection(
        baseline.clone(),
        &raw,
        "/target/architecture",
        json!("x64"),
        "target_mismatch",
    );
    rejection(
        baseline,
        &raw,
        "/target",
        json!({"kind":"kernel_driver","input":"primary","architecture":"x86","unload":false,"code_reference":{"kind":"none"}}),
        "target_mismatch",
    );
    let msi = owned(Arch::X64, "msi");
    let mut truncated = msi.clone();
    truncated.truncate(100);
    let value = spec_json(Arch::X64, "msi", &truncated);
    let spec = decode(&value);
    assert_eq!(
        VerifiedInventory::verify(
            &spec.inputs,
            &[InputBytes {
                id: "primary",
                bytes: &truncated
            }]
        )
        .err()
        .unwrap()
        .code,
        "static_msi"
    );
}
#[test]
fn exact_replay_binds_original_canonical_and_body_bytes_and_extra_roles_fail() {
    let raw = owned(Arch::X64, "exe");
    let fixtures=serde_json::to_vec(&json!({"version":1,"rules":[{"id":"owned","request":{"method":"GET","url":"https://owned.invalid/data","chunked":false,"headers":{},"body_base64":"AP8="},"response":{"status":200,"reason":"OK","version":"HTTP/1.1","headers":[],"body_base64":"gE1a"}}]})).unwrap();
    let mut value = spec_json(Arch::X64, "exe", &raw);
    value["network"] = json!({"kind":"offline_exact_replay","input":"fixtures"});
    value["inputs"].as_array_mut().unwrap().push(input(
        "fixtures",
        "offline.json",
        &fixtures,
        json!(["offline_fixtures"]),
        json!({"kind":"not_mounted"}),
    ));
    let spec = decode(&value);
    let inventory = VerifiedInventory::verify(
        &spec.inputs,
        &[
            InputBytes {
                id: "primary",
                bytes: &raw,
            },
            InputBytes {
                id: "fixtures",
                bytes: &fixtures,
            },
        ],
    )
    .unwrap();
    let plan = resolve(&spec, &inventory, &Capabilities::planning_only_v1()).unwrap();
    assert_eq!(
        plan.value()["network"]["original_sha256"],
        digest(&fixtures)
    );
    assert_eq!(
        plan.value()["network"]["bodies"][0]["request_sha256"],
        digest(&[0, 255])
    );
    assert_eq!(
        plan.value()["network"]["bodies"][0]["response_sha256"],
        digest(&[128, 77, 90])
    );
    assert!(
        plan.value()["network"]["canonical_copy_bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(plan.value()["network"]["fixture_visibility"], "broker_only");
    assert_eq!(plan.value()["network"]["complete"], false);
    value["inputs"][0]["roles"]
        .as_array_mut()
        .unwrap()
        .push(json!("guest_file"));
    let spec = decode(&value);
    let inventory = VerifiedInventory::verify(
        &spec.inputs,
        &[
            InputBytes {
                id: "primary",
                bytes: &raw,
            },
            InputBytes {
                id: "fixtures",
                bytes: &fixtures,
            },
        ],
    )
    .unwrap();
    assert_eq!(
        resolve(&spec, &inventory, &Capabilities::planning_only_v1())
            .err()
            .unwrap()
            .code,
        "guest_mount"
    );
}
#[test]
fn mounts_casefold_directory_aliases_and_environment_last_assignment_are_not_host_paths() {
    let raw = owned(Arch::X64, "exe");
    let mut value = spec_json(Arch::X64, "exe", &raw);
    value["invocation"]["arguments"] = json!(["", "space value", "quote\"value", "C:\\tail\\"]);
    value["invocation"]["force_quote_indices"] = json!([3]);
    value["invocation"]["environment"] =
        json!([{"name":"Mode","value":"first"},{"name":"MODE","value":"last"}]);
    let spec = decode(&value);
    let plan = resolve(
        &spec,
        &checked(&spec, &raw),
        &Capabilities::planning_only_v1(),
    )
    .unwrap();
    assert_eq!(plan.value()["invocation"]["environment"]["MODE"], "last");
    assert!(
        plan.value()["invocation"]["command_line"]
            .as_str()
            .unwrap()
            .contains("\"space value\"")
    );
    for path in [
        "../escape",
        "A/../escape",
        "C:/drive",
        "a//b",
        "a\\b",
        "a:stream",
        "a/CON.txt",
        "a/COM1",
        "trailing.",
        "a/space ",
    ] {
        assert!(
            super::inventory::package_path(path, "owned").is_err(),
            "{path}"
        );
    }
    value["inputs"].as_array_mut().unwrap().push(input(
        "one",
        "one.bin",
        b"owned",
        json!(["guest_file"]),
        json!({"kind":"package","path":"Straße/a.bin"}),
    ));
    value["inputs"].as_array_mut().unwrap().push(input(
        "two",
        "two.bin",
        b"owned",
        json!(["guest_file"]),
        json!({"kind":"package","path":"STRASSE/a.bin"}),
    ));
    let spec = decode(&value);
    let inventory = VerifiedInventory::verify(
        &spec.inputs,
        &[
            InputBytes {
                id: "primary",
                bytes: &raw,
            },
            InputBytes {
                id: "one",
                bytes: b"owned",
            },
            InputBytes {
                id: "two",
                bytes: b"owned",
            },
        ],
    )
    .unwrap();
    assert_eq!(
        resolve(&spec, &inventory, &Capabilities::planning_only_v1())
            .err()
            .unwrap()
            .code,
        "ambiguous_guest_path"
    );
}
#[test]
fn pure_legacy_corpus_preserves_quoting_env_rules_and_documents_tighter_package_paths() {
    let raw = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/analysis_plan_reference.json"),
    )
    .unwrap();
    assert_eq!(raw.len(), 59832);
    assert_eq!(
        digest(&raw),
        "d6c1153539c6e54b11b352e9fecf705a2cf586d6d6d1c62a377050d666e93545"
    );
    let corpus: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(corpus["paths"].as_array().unwrap().len(), 20);
    assert_eq!(corpus["invocations"].as_array().unwrap().len(), 32);
    for case in corpus["paths"].as_array().unwrap() {
        let path = case["path"].as_str().unwrap();
        assert_eq!(
            super::inventory::package_path(path, "owned").is_ok(),
            case["rust_valid"].as_bool().unwrap(),
            "{case}"
        );
    }
    for arch in [Arch::X86, Arch::X64] {
        for case in corpus["invocations"].as_array().unwrap() {
            let kind = if case["managed"] == true {
                "managed"
            } else {
                "exe"
            };
            let input = owned(arch, kind);
            let mut value = spec_json(arch, kind, &input);
            value["invocation"]["arguments"] = case["arguments"].clone();
            value["invocation"]["force_quote_indices"] = case["force_quote_indices"].clone();
            value["invocation"]["environment"] = json!(
                case["environment"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| {
                        let (name, value) = v.as_str().unwrap().split_once('=').unwrap();
                        json!({"name":name,"value":value})
                    })
                    .collect::<Vec<_>>()
            );
            let spec = decode(&value);
            let inventory = checked(&spec, &input);
            let result = resolve(&spec, &inventory, &Capabilities::planning_only_v1());
            assert_eq!(
                result.is_ok(),
                case["valid"].as_bool().unwrap(),
                "{arch:?} {case}: {}",
                result
                    .as_ref()
                    .err()
                    .map(ToString::to_string)
                    .unwrap_or_default()
            );
            if let Ok(plan) = result {
                assert_eq!(
                    plan.value()["invocation"]["command_line"],
                    case["command_line"],
                    "{arch:?} {case}"
                );
                assert_eq!(
                    plan.value()["invocation"]["environment"],
                    case["environment_effective"],
                    "{case}"
                );
            }
        }
    }
}
#[test]
fn native_companion_and_nested_mount_identity_are_planned_without_loading_them() {
    let primary = owned(Arch::X64, "exe");
    let dll = owned(Arch::X64, "dll");
    let mut value = spec_json(Arch::X64, "exe", &primary);
    value["inputs"][0]["mount"] = json!({"kind":"package","path":"app/owned.exe"});
    value["persona"]["value"]["process"]["current_directory"] =
        json!("C:\\Users\\Alex\\Downloads\\app");
    value["inputs"].as_array_mut().unwrap().push(input(
        "dependency",
        "model.dll",
        &dll,
        json!(["native_companion"]),
        json!({"kind":"not_mounted"}),
    ));
    value["inputs"].as_array_mut().unwrap().push(input(
        "data",
        "data.bin",
        b"owned",
        json!(["guest_file"]),
        json!({"kind":"package","path":"app/data/data.bin"}),
    ));
    value["companions"] = json!(["dependency"]);
    value["limits"]["max_output_directories"] = json!(128);
    let spec = decode(&value);
    let inventory = VerifiedInventory::verify(
        &spec.inputs,
        &[
            InputBytes {
                id: "primary",
                bytes: &primary,
            },
            InputBytes {
                id: "dependency",
                bytes: &dll,
            },
            InputBytes {
                id: "data",
                bytes: b"owned",
            },
        ],
    )
    .unwrap();
    let resolved = resolve(&spec, &inventory, &Capabilities::planning_only_v1()).unwrap();
    assert!(!resolved.executable());
    assert_eq!(resolved.value()["companions"][0]["sha256"], digest(&dll));
    assert_eq!(
        resolved.value()["invocation"]["image_path"],
        "C:\\Users\\Alex\\Downloads\\app\\owned.exe"
    );
    assert_eq!(
        resolved.value()["budget"]["staged_physical_input_bytes"],
        (primary.len() + dll.len() + 5) as u64
    );
    assert_eq!(
        resolved.value()["runtime_projection"]["engine_applied"],
        false
    );
    let mut changed = spec.clone();
    changed.limits.max_output_bytes = 2 * 1024 * 1024 * 1024;
    assert_eq!(
        resolve(&changed, &inventory, &Capabilities::planning_only_v1())
            .err()
            .unwrap()
            .code,
        "binding_mismatch"
    );
}

#[test]
fn driver_resource_projection_is_explicit_conservative_and_never_resolves_large_admission() {
    let raw = owned(Arch::X64, "kernel");
    let mut value = spec_json(Arch::X64, "kernel", &raw);
    value["capture"]["profile"] = json!("large_driver128_v1");
    value["capture"]["sources"] = json!(["memory_snapshots", "structural_pe"]);
    value["capture"]["retained_bytes"] = json!(268435456u64);
    value["reports"]["profile"] = json!("large_driver_v1");
    value["limits"]["worker_memory_mb"] = json!(2048);
    let spec = decode(&value);
    let inventory = checked(&spec, &raw);
    let projection = project_driver_resources(&spec, &inventory).unwrap();
    assert_eq!(projection["executable"], false);
    assert_eq!(projection["general_worker_admitted"], false);
    assert_eq!(projection["capture_transient_bytes"], 384u64 * 1024 * 1024);
    assert_eq!(projection["capture_read_work_bytes"], 192u64 * 1024 * 1024);
    assert!(projection["minimum_worker_bytes"].as_u64().unwrap() <= 2048 * 1024 * 1024);
    assert_eq!(
        resolve(&spec, &inventory, &Capabilities::planning_only_v1())
            .err()
            .unwrap()
            .code,
        "unsupported_profile"
    );
    for (path, change, code) in [
        ("/limits/worker_memory_mb", json!(512), "job_limit"),
        (
            "/limits/max_instructions",
            json!(crate::driver_input::MAX_INSTRUCTIONS + 1),
            "execution_limit",
        ),
        ("/limits/max_output_bytes", json!(1), "output_budget"),
        ("/capture/memory_scan_bytes", json!(1), "capture_limit"),
        (
            "/reports/profile",
            json!("legacy_v1"),
            "unsupported_profile",
        ),
    ] {
        let mut bad = value.clone();
        *bad.pointer_mut(path).unwrap() = change;
        let spec = decode(&bad);
        let inventory = checked(&spec, &raw);
        assert_eq!(
            project_driver_resources(&spec, &inventory)
                .err()
                .unwrap()
                .code,
            code,
            "{path}"
        );
    }
    value["limits"]["guest_mapped_bytes"] = json!(512u64 * 1024 * 1024);
    value["limits"]["guest_heap_bytes"] = json!(256u64 * 1024 * 1024);
    value["limits"]["guest_pool_bytes"] = json!(256u64 * 1024 * 1024);
    value["limits"]["guest_threads"] = json!(128);
    let spec = decode(&value);
    let inventory = checked(&spec, &raw);
    assert_eq!(
        project_driver_resources(&spec, &inventory)
            .err()
            .unwrap()
            .code,
        "job_budget"
    );
}

fn generated_driver128_plan(with_fixture: bool) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut generated = crate::plan_runtime::Case::Kernel17
        .generated(Arch::X64)
        .unwrap();
    let mut value: Value = serde_json::from_slice(&generated.plan).unwrap();
    value["target"]["service_name"] = json!("TestDrv");
    value["persona"]["value"]["windows_build"] = json!(22631);
    value["capture"]["profile"] = json!("large_driver128_v1");
    value["capture"]["sources"] = json!(["memory_snapshots", "structural_pe"]);
    value["capture"]["retained_bytes"] = json!(256u64 * 1024 * 1024);
    value["capture"]["memory_scan_bytes"] = json!(128u64 * 1024 * 1024);
    value["reports"]["profile"] = json!("large_driver_v1");
    value["limits"]["worker_memory_mb"] = json!(2048);
    if with_fixture {
        let fixture = crate::plan_runtime::Case::NativeReplay
            .generated(Arch::X64)
            .unwrap()
            .fixtures;
        value["inputs"].as_array_mut().unwrap().push(json!({
            "id":"offline","name":"offline.json","roles":["offline_fixtures"],
            "mount":{"kind":"not_mounted"},"size":fixture.len(),"sha256":digest(&fixture),
        }));
        value["network"] = json!({"kind":"offline_exact_replay","input":"offline"});
        generated.inputs.push(fixture);
    }
    (serde_json::to_vec(&value).unwrap(), generated.inputs)
}

#[test]
fn explicit_driver128_prepared_intake_stays_planning_only_with_owned_report_identity() {
    use crate::{driver_capture_reports::Binding, general_execution_commitment::Request};
    for with_fixture in [false, true] {
        let (plan, inputs) = generated_driver128_plan(with_fixture);
        assert!(PreparedIntake::prepare(plan.clone(), inputs.clone()).is_err());
        let intake = PreparedIntake::prepare_driver128(plan, inputs).unwrap();
        let resolved = intake.resolved();
        assert!(!resolved.executable());
        assert_eq!(resolved.value()["kind"], "driver128_plan_only");
        assert_eq!(resolved.value()["executable"], false);
        assert_eq!(resolved.value()["guest_admission"], false);
        assert_eq!(resolved.value()["engine_applied"], false);
        assert_eq!(resolved.value()["budget"]["general_worker_admitted"], false);
        assert_eq!(resolved.value()["budget"]["engine_applied"], false);
        let request = Request::from_intake(&intake, "20261019T120000Z-12345678".into()).unwrap();
        assert_eq!(request.report_profile, "large_driver_v1");
        assert!(!request.execution_authorized);
        assert_eq!(request.broker_private_fixture.is_some(), with_fixture);
        let raw = serde_json::to_vec(&request).unwrap();
        let binding =
            Binding::for_general_commitment(&raw, &intake, &"1".repeat(64), &"2".repeat(64))
                .unwrap();
        assert_eq!(binding.request_sha256, digest(&raw));
        assert_eq!(binding.input_sha256, request.public_inputs[0].sha256);
        if with_fixture {
            let claim = crate::general_broker_private_attestation::Claim::from_verified_request(
                &raw, &intake,
            )
            .unwrap();
            assert_eq!(claim.request_sha256, digest(&raw));
            assert!(!claim.execution_authorized);
        }
    }
}

#[test]
fn explicit_driver128_plan_accepts_generated_fixture_for_host_build_without_execution_authority() {
    let (plan, inputs) = generated_driver128_plan(false);
    let mut value: Value = serde_json::from_slice(&plan).unwrap();
    value["persona"]["value"]["windows_build"] = json!(26200);
    let intake = PreparedIntake::prepare_driver128(serde_json::to_vec(&value).unwrap(), inputs)
        .unwrap();
    assert!(!intake.resolved().executable());
    assert_eq!(intake.resolved().value()["guest_admission"], false);
}

#[test]
fn explicit_driver128_planning_refuses_broadened_resources_roles_and_network() {
    let (plan, inputs) = generated_driver128_plan(true);
    let original: Value = serde_json::from_slice(&plan).unwrap();
    for (path, bad) in [
        ("/limits/worker_memory_mb", json!(512)),
        ("/limits/max_output_bytes", json!(1)),
        (
            "/capture/sources",
            json!(["memory_snapshots", "structural_pe", "guest_files"]),
        ),
        ("/target/service_name", json!(null)),
        ("/target/architecture", json!("x86")),
        ("/network/kind", json!("live")),
        (
            "/inputs/0/mount",
            json!({"kind":"package","path":"driver.sys"}),
        ),
        ("/inputs/1/roles", json!(["offline_fixtures", "guest_file"])),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(path).unwrap() = bad;
        assert!(
            PreparedIntake::prepare_driver128(
                serde_json::to_vec(&changed).unwrap(),
                inputs.clone()
            )
            .is_err(),
            "{path} accepted",
        );
    }
    let mut changed_bytes = inputs.clone();
    changed_bytes[0][0] ^= 1;
    assert!(PreparedIntake::prepare_driver128(plan.clone(), changed_bytes).is_err());
    let mut swapped = inputs;
    swapped.swap(0, 1);
    assert!(PreparedIntake::prepare_driver128(plan, swapped).is_err());
}

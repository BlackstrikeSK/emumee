//! Differential observations of trusted legacy handlers over synthetic memory.
use super::*;
use emumee_core::report_bundle::digest;
fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn lstrlen_matches_independent_frozen_boundaries_encoding_and_read_permissions() {
    let reference: serde_json::Value =
        serde_json::from_str(include_str!("lstrlen_semantic_reference.json")).unwrap();
    assert_eq!(
        reference["reference_sha256"],
        digest(include_bytes!("../../../../src/emumee/winstrings.py"))
    );
    for case in reference["cases"].as_array().unwrap() {
        let arch = if case["width"] == 8 {
            Architecture::X64
        } else {
            Architecture::X86
        };
        let mut engine = crate::new_engine(arch).unwrap();
        engine
            .mem_map(0x1000, 0x10000, Prot::READ | Prot::WRITE)
            .unwrap();
        let readable = case["readable"].as_bool().unwrap_or(true);
        engine
            .get_data_mut()
            .apis
            .memory
            .map(
                0x1000,
                0x10000,
                if readable { P::RW } else { P::WRITE },
                Some(4),
                "independent lstrlen arena",
            )
            .unwrap();
        for patch in case["patches"].as_array().unwrap() {
            let bytes = hex(patch["hex"].as_str().unwrap());
            let count = patch["repeat"].as_u64().unwrap() as usize;
            assert!(bytes.len().checked_mul(count).is_some_and(|n| n <= 0x10000));
            engine
                .mem_write(patch["address"].as_u64().unwrap(), &bytes.repeat(count))
                .unwrap();
        }
        engine.get_data_mut().apis.last_error = 0x12345678;
        let (call, _, _, _) = definition("kernel32", case["export"].as_str().unwrap()).unwrap();
        let actual = invoke(&mut engine, &[case["address"].as_u64().unwrap()], call).unwrap();
        assert_eq!(actual, case["result"].as_u64().unwrap(), "{case}");
        assert_eq!(
            u64::from(engine.get_data().apis.last_error),
            case["last_error"].as_u64().unwrap(),
            "{case}"
        );
        assert_eq!(
            digest(&engine.mem_read_as_vec(0x1000, 0x10000).unwrap()),
            case["memory_sha256"],
            "{case}"
        );
        assert!(engine.get_data().apis.winstrings.is_empty(), "{case}");
    }
}
#[test]
fn winstrings_match_frozen_legacy_returns_errors_memory_and_unsupported_observations() {
    let reference: serde_json::Value =
        serde_json::from_str(include_str!("winstrings_reference.json")).unwrap();
    assert_eq!(
        reference["reference_sha256"],
        digest(include_bytes!("../../../../src/emumee/winstrings.py")),
        "Legacy string baseline changed; inspect and regenerate the trusted observations deliberately"
    );
    for (index, case) in reference["cases"].as_array().unwrap().iter().enumerate() {
        let arch = if case["width"] == 8 {
            Architecture::X64
        } else {
            Architecture::X86
        };
        let mut engine = crate::new_engine(arch).unwrap();
        engine
            .mem_map(0x1000, 0x10000, Prot::READ | Prot::WRITE)
            .unwrap();
        engine
            .get_data_mut()
            .apis
            .memory
            .map(
                0x1000,
                0x10000,
                P::RW,
                Some(4),
                "legacy string reference synthetic bytes",
            )
            .unwrap();
        for patch in case["patches"].as_array().unwrap() {
            engine
                .mem_write(
                    patch["address"].as_u64().unwrap(),
                    &hex(patch["hex"].as_str().unwrap()),
                )
                .unwrap();
        }
        engine.get_data_mut().apis.last_error = 0x12345678;
        let (call, argc, returns, _) = definition(
            case["module"].as_str().unwrap(),
            case["export"].as_str().unwrap(),
        )
        .unwrap();
        let args: Vec<u64> = case["arguments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a.as_u64().unwrap())
            .collect();
        assert_eq!(argc, args.len());
        let actual = invoke(&mut engine, &args, call);
        let last_error = engine.get_data().apis.last_error;
        let memory_digest = digest(&engine.mem_read_as_vec(0x1000, 0x10000).unwrap());
        let unmodeled = !engine.get_data().apis.winstrings.is_empty();
        drop(engine);
        let actual = actual.unwrap();
        let mask = if matches!(returns, T::U32) {
            u32::MAX as u64
        } else {
            u64::MAX
        };
        assert_eq!(
            actual & mask,
            case["result"].as_u64().unwrap() & mask,
            "case {index}: {case}"
        );
        assert_eq!(
            last_error,
            case["last_error"].as_u64().unwrap() as u32,
            "case {index}: {case}"
        );
        assert_eq!(memory_digest, case["memory_sha256"], "case {index}: {case}");
        assert_eq!(
            unmodeled,
            case["unsupported"].as_bool().unwrap(),
            "case {index}: {case}"
        );
    }
}

#[test]
fn frozen_windows_string_expanded_memory_and_null_controls_match_all_module_identities() {
    let reference: serde_json::Value =
        serde_json::from_str(include_str!("winstrings_semantic_reference.json")).unwrap();
    assert_eq!(
        reference["source_sha256"],
        digest(include_bytes!("../../../../src/emumee/winstrings.py"))
    );
    assert_eq!(reference["contracts"].as_array().unwrap().len(), 42);
    let cases = reference["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 1004);
    for (index, case) in cases.iter().enumerate() {
        let arch = if case["width"] == 8 {
            Architecture::X64
        } else {
            Architecture::X86
        };
        let mut engine = crate::new_engine(arch).unwrap();
        engine
            .mem_map(0x26000000, 0x10000, Prot::READ | Prot::WRITE)
            .unwrap();
        engine
            .get_data_mut()
            .apis
            .memory
            .map(
                0x26000000,
                0x10000,
                P(case["protection"].as_u64().unwrap() as u8),
                Some(4),
                "independent expanded Windows string arena",
            )
            .unwrap();
        for patch in case["patches"].as_array().unwrap() {
            engine
                .mem_write(
                    patch["address"].as_u64().unwrap(),
                    &hex(patch["hex"].as_str().unwrap()),
                )
                .unwrap();
        }
        engine.get_data_mut().apis.last_error = 0x12345678;
        let (call, argc, returns, _) = definition(
            case["module"].as_str().unwrap(),
            case["export"].as_str().unwrap(),
        )
        .unwrap();
        let arguments = case["arguments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(argc, arguments.len());
        assert!(case["error"].is_null(), "case {index}: {case}");
        let actual = invoke(&mut engine, &arguments, call).unwrap();
        let mask = if matches!(returns, T::U32) {
            u32::MAX as u64
        } else {
            u64::MAX
        };
        assert_eq!(
            actual & mask,
            case["result"].as_u64().unwrap() & mask,
            "case {index}: {case}"
        );
        assert_eq!(
            u64::from(engine.get_data().apis.last_error),
            case["last_error"].as_u64().unwrap(),
            "case {index}: {case}"
        );
        assert_eq!(
            digest(&engine.mem_read_as_vec(0x26000000, 0x10000).unwrap()),
            case["memory_sha256"],
            "case {index}: {case}"
        );
        assert_eq!(
            !engine.get_data().apis.winstrings.is_empty(),
            case["unsupported"].as_bool().unwrap(),
            "case {index}: {case}"
        );
    }
}

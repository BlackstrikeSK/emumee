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

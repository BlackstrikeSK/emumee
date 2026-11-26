//! Submitted-route controls derived from the independently frozen handler corpus.
use super::*;
use emumee_core::{
    artifacts::ArtifactKind,
    fixtures::{
        self,
        M4Arg::{Memory as M, Value as V},
        M4Code as Code,
    },
    report_bundle::digest,
    user_input::{PROFILE, Request},
};

#[test]
fn semantic_lstrlen_submitted_calls_match_frozen_returns_errors_and_all_memory() {
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("api/winstrings_reference.json")).unwrap();
    assert_eq!(
        corpus["reference_sha256"],
        digest(include_bytes!("../../../src/emumee/winstrings.py"))
    );
    for arch in [Architecture::X86, Architecture::X64] {
        for export in ["lstrlenA", "lstrlenW"] {
            let cases = corpus["cases"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|c| c["export"] == export && c["width"] == arch.width());
            for (index, case) in cases.enumerate() {
                let label = format!("{arch:?}-semantic-{export}-{index:03}");
                let names = [
                    "VirtualAlloc",
                    "WriteProcessMemory",
                    "SetLastError",
                    export,
                    "GetLastError",
                    "CreateFileA",
                    "WriteFile",
                    "CloseHandle",
                ];
                let mut code = Code::new(arch, 0x1000);
                let base = code.base();
                let buffer = 0x26000000;
                code.prologue();
                code.call(0, &[V(buffer), V(0x10000), V(0x3000), V(4)]);
                code.expect(buffer as u32);
                let mut patches = Vec::new();
                for patch in case["patches"].as_array().unwrap() {
                    let hex = patch["hex"].as_str().unwrap();
                    let data: Vec<u8> = hex
                        .as_bytes()
                        .chunks_exact(2)
                        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
                        .collect();
                    let source = base + 0x3000 + patches.len() as u64;
                    code.call(
                        1,
                        &[
                            V(if arch == Architecture::X86 {
                                u32::MAX as u64
                            } else {
                                u64::MAX
                            }),
                            V(buffer + patch["address"].as_u64().unwrap() - 0x1000),
                            V(source),
                            V(data.len() as u64),
                            V(0),
                        ],
                    );
                    code.expect(1);
                    patches.extend(data);
                }
                let original = case["arguments"][0].as_u64().unwrap();
                let address = if original == 0 {
                    0
                } else {
                    buffer + original - 0x1000
                };
                code.call(2, &[V(0x12345678)]);
                code.call(3, &[V(address)]);
                code.expect(case["result"].as_u64().unwrap() as u32);
                code.call(4, &[]);
                code.expect(case["last_error"].as_u64().unwrap() as u32);
                // Retain the complete synthetic memory arena as a guest file so
                // the independent replay can compare its SHA-256 to the oracle.
                code.call(
                    5,
                    &[
                        V(base + 0x3c00),
                        V(0x40000000),
                        V(0),
                        V(0),
                        V(2),
                        V(0x80),
                        V(0),
                    ],
                );
                code.store(base + 0x3f20);
                code.call(
                    6,
                    &[
                        M(base + 0x3f20),
                        V(buffer),
                        V(0x10000),
                        V(base + 0x3f40),
                        V(0),
                    ],
                );
                code.expect(1);
                code.load(base + 0x3f40);
                code.expect(0x10000);
                code.call(7, &[M(base + 0x3f20)]);
                code.expect(1);
                code.epilogue(1, 0);
                let mut bytes = fixtures::m4_custom_probe(arch, &names, &code.finish(), &[], &[]);
                bytes[0x2200..0x2200 + patches.len()].copy_from_slice(&patches);
                let path = b"C:\\Users\\Alex\\Downloads\\strlen-memory.bin\0";
                bytes[0x2e00..0x2e00 + path.len()].copy_from_slice(path);
                let request = Request {
                    schema: 2,
                    profile: PROFILE.into(),
                    run_id: "20261124T120000Z-12345678".into(),
                    input_sha256: digest(&bytes),
                    input_size: bytes.len() as u64,
                    module_name: "sample.exe".into(),
                    arguments: vec![],
                    max_instructions: 10_000,
                    timeout_us: 30_000_000,
                    persona_sha256: None,
                    clock_utc_filetime: crate::m6_tests::CLOCK,
                    staged: vec![],
                    invocation: Default::default(),
                    capture: None,
                    output: None,
                };
                crate::user_test_fixtures::fixture(&label, &request, &bytes, &[], None);
                let result = user::run(&request, &bytes, None).unwrap();
                crate::user_test_fixtures::execution(&label, &result);
                assert_eq!(result.error, None, "{label}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1), "{label}");
                assert!(result.api_events.iter().all(|e| !e.pending), "{label}");
                let arena = result
                    .artifacts
                    .iter()
                    .find(|a| {
                        a.observations.iter().any(|o| {
                            o.kind == ArtifactKind::GuestFile
                                && o.guest_path.ends_with("strlen-memory.bin")
                        })
                    })
                    .unwrap();
                assert_eq!(arena.size, 0x10000, "{label}");
                assert_eq!(digest(&arena.data), case["memory_sha256"], "{label}");
            }
        }
    }
}

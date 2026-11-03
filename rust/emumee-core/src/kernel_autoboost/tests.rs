use super::*;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct Case {
    seed: u8,
    kernel_count: u8,
    user_count: Option<u8>,
    misc_flags: u32,
    expected: Expected,
}

#[derive(Deserialize)]
struct Expected {
    kernel_sha256: String,
    user_sha256: Option<String>,
    misc_flags: u32,
    propagate_boosts_entry: u64,
    io_self_boosts_entry: u64,
}

#[derive(Deserialize)]
struct Fixture {
    cases: Vec<Case>,
}

#[test]
fn agrees_with_pinned_native_initialization_observations() {
    let fixture: Fixture = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/native_autoboost_initialization.json"
    ))
    .unwrap();
    assert_eq!(fixture.cases.len(), 768);
    for (index, case) in fixture.cases.iter().enumerate() {
        let block = |count, seed: u8| {
            let mut bytes: Vec<u8> = (0..HEADER_BYTES + usize::from(count) * ENTRY_BYTES + 17)
                .map(|offset| (offset as u8).wrapping_mul(73).wrapping_add(seed))
                .collect();
            bytes[0xc] = count;
            bytes
        };
        let input = Inputs {
            misc_flags: case.misc_flags,
            kernel_entries: block(case.kernel_count, case.seed),
            user_entries: case.user_count.map(|n| block(n, case.seed ^ 0xa5)),
        };
        let before = input.clone();
        let result = initialize(&input).unwrap();
        assert_eq!(input, before, "case{index}: input changed");
        assert_eq!(
            format!("{:x}", Sha256::digest(&result.kernel_entries)),
            case.expected.kernel_sha256,
            "case{index}: kernel bytes"
        );
        assert_eq!(
            result
                .user_entries
                .map(|b| format!("{:x}", Sha256::digest(b))),
            case.expected.user_sha256,
            "case{index}: user bytes"
        );
        assert_eq!(result.misc_flags, case.expected.misc_flags, "case{index}");
        assert_eq!(
            result.propagate_boosts_entry,
            case.expected.propagate_boosts_entry
        );
        assert_eq!(
            result.io_self_boosts_entry,
            case.expected.io_self_boosts_entry
        );
    }
}

#[test]
fn malformed_blocks_fail_without_altering_inputs() {
    for size in 0..HEADER_BYTES + ENTRY_BYTES {
        let mut bytes = vec![0x5a; size];
        if size >= HEADER_BYTES {
            bytes[0xc] = 1;
        }
        let kernel_bad = Inputs {
            misc_flags: 0x2468_ace0,
            kernel_entries: bytes.clone(),
            user_entries: None,
        };
        let user_bad = Inputs {
            misc_flags: 0x2468_ace0,
            kernel_entries: {
                let mut complete = vec![0; HEADER_BYTES];
                complete[0xc] = 0;
                complete
            },
            user_entries: Some(bytes),
        };
        for input in [kernel_bad, user_bad] {
            let before = input.clone();
            assert!(initialize(&input).is_err());
            assert_eq!(input, before);
        }
    }
}

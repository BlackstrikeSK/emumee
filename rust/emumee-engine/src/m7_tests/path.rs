//! shlwapi path/string control family: pointer-returning and value queries
//! (filename/extension/relative, substring search, case-insensitive compare)
//! and in-place path edits verified against expected strings with lstrcmp.
use super::*;
use emumee_core::fixtures::{M7PathFixture as F, m7_path_probe};

fn control(arch: Architecture, kind: F) -> Execution {
    let label = format!("{arch:?}-m7-path-{kind:?}");
    let result = run(&label, m7_path_probe(arch, kind), &[], 40_000);
    succeeded(&label, &result);
    result
}

#[test]
fn m7_path_queries_and_in_place_edits_are_guest_decided() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::Query, F::Edit] {
            let result = control(arch, kind);
            assert!(result.artifacts.is_empty(), "{kind:?}: {:?}", result.artifacts);
            assert_eq!(result.network.calls, 0);
        }
    }
}

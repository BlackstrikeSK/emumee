//! Resource control family: locating a resource by id and by name, loading,
//! locking, sizing and freeing it, loading a string-table string, and the
//! missing-type / missing-name / missing-language refusals.
use super::*;
use emumee_core::fixtures::{M7ResourceFixture as F, m7_resource_probe};

fn control(arch: Architecture, kind: F) -> Execution {
    let label = format!("{arch:?}-m7-resource-{kind:?}");
    let result = run(&label, m7_resource_probe(arch, kind), &[], 40_000);
    succeeded(&label, &result);
    result
}

#[test]
fn m7_resource_lookup_load_lock_size_free_and_strings_are_guest_decided() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::ById, F::ByName, F::LoadString, F::Missing] {
            let result = control(arch, kind);
            // Resource loads read the mapped image; no artifact or capture is
            // produced and the network is never reached.
            assert!(result.artifacts.is_empty(), "{kind:?}: {:?}", result.artifacts);
            assert_eq!(result.network.calls, 0);
        }
    }
}

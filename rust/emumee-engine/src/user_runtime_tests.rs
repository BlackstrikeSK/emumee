use super::*;
use emumee_core::{
    fixtures::{UserRuntimeFixture as F, user_runtime_probe},
    report_bundle::digest,
    user_input::{PROFILE, Request},
};
#[test]
fn user_runtime_real_guest_calls_validate_both_abis_and_owned_memory() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in F::ALL {
            let bytes = user_runtime_probe(arch, kind);
            let request = Request {
                schema: 1,
                profile: PROFILE.into(),
                run_id: "20261029T170000Z-12345678".into(),
                input_sha256: digest(&bytes),
                input_size: bytes.len() as u64,
                module_name: "sample.exe".into(),
                arguments: vec![],
                max_instructions: 20000,
                timeout_us: 30_000_000,
                persona_sha256: None,
                clock_utc_filetime: 134377488000000000,
                staged: vec![],
                invocation: Default::default(),
            };
            let result = user::run(&request, &bytes, None).unwrap();
            if kind == F::OwnedProtect {
                assert!(
                    result
                        .error
                        .as_deref()
                        .is_some_and(|s| s.contains("owned startup strings")),
                    "{arch:?}/{kind:?}: {result:#?}"
                );
            } else {
                assert_eq!(result.error, None, "{arch:?}/{kind:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1), "{arch:?}/{kind:?}");
            }
        }
    }
}

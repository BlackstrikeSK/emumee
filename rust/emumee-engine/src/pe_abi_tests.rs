use super::*;
use emumee_core::{
    fixtures::{AbiFixture as F, abi_probe},
    report_bundle::digest,
    user_input::{PROFILE, Request},
};

#[test]
fn submitted_abi_imports_and_callbacks_are_independently_qualified() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in F::ALL
            .into_iter()
            .filter(|kind| kind.supported(architecture))
        {
            let bytes = abi_probe(architecture, kind);
            if let Ok(root) = std::env::var("EMUMEE_USER_TEST_FIXTURES") {
                let directory =
                    std::path::PathBuf::from(root).join(format!("{architecture:?}-abi-{kind:?}"));
                std::fs::create_dir_all(&directory).unwrap();
                std::fs::write(directory.join("abi.exe"), &bytes).unwrap();
            }
            let request = Request {
                schema: 1,
                profile: PROFILE.into(),
                run_id: "20261104T120000Z-12345678".into(),
                input_sha256: digest(&bytes),
                input_size: bytes.len() as u64,
                module_name: "abi.exe".into(),
                arguments: vec![],
                max_instructions: 4000,
                timeout_us: 1_000_000,
                persona_sha256: None,
                clock_utc_filetime: 134377488000000000,
            };
            let execution = user::run(&request, &bytes, None)
                .unwrap_or_else(|error| panic!("{architecture:?}/{kind:?}: {error:#}"));
            if kind.positive() {
                assert!(
                    execution.error.is_none(),
                    "{architecture:?}/{kind:?}: {:?}",
                    execution.error
                );
                assert_eq!(
                    execution.completion_reason, "entry_return",
                    "{architecture:?}/{kind:?}"
                );
                assert_eq!(
                    execution.guest_entry_return,
                    Some(kind.expected_return()),
                    "{architecture:?}/{kind:?}"
                );
            } else {
                let error = execution.error.as_deref().expect("ABI violation must fail");
                let expected = match kind {
                    F::CrtStack => "return frame",
                    F::LoaderStack => "stack return contract",
                    F::CrtGpr | F::LoaderGpr => "nonvolatile register",
                    F::CrtVector | F::LoaderVector => "vector register",
                    F::CrtDirection | F::LoaderDirection => "flags",
                    F::CrtMxcsr | F::LoaderMxcsr => "MXCSR",
                    F::CrtFpcw | F::LoaderFpcw => "FPCW",
                    F::PowDomain => "complex",
                    F::PowZero => "negative power",
                    F::PowOverflow => "overflow",
                    F::FloorNan | F::FloorInfinity => "nonfinite",
                    F::SinInfinity => "domain",
                    _ => unreachable!(),
                };
                assert!(
                    error.contains(expected),
                    "{architecture:?}/{kind:?}: {error}"
                );
                assert!(execution.guest_entry_return.is_none());
            }
        }
    }
}

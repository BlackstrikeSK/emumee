use super::*;
use emumee_core::{
    fixtures::{self, BootstrapFixture as F, ConfiguredFixture},
    report_bundle::digest,
    user_input::{Invocation, PROFILE, Request},
};

#[test]
fn submitted_bootstrap_direct_segments_parameters_and_mutations_match_owned_apis() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for dll in [false, true] {
            for kind in [F::Basic, F::Mutation, F::Protect, F::Free] {
                for supplied in [false, true] {
                    let bytes = fixtures::user_bootstrap_probe(architecture, kind, dll);
                    let persona =
                        supplied.then(|| fixtures::configured_document(ConfiguredFixture::User));
                    let request = Request {
                        schema: 2,
                        profile: PROFILE.into(),
                        run_id: "20261106T120000Z-12345678".into(),
                        input_sha256: digest(&bytes),
                        input_size: bytes.len() as u64,
                        module_name: if dll {
                            "bootstrap.dll"
                        } else {
                            "bootstrap.exe"
                        }
                        .into(),
                        arguments: vec!["two words".into(), "tail\\".into(), "".into()],
                        max_instructions: 50000,
                        timeout_us: 30_000_000,
                        persona_sha256: persona.as_deref().map(digest),
                        clock_utc_filetime: 134377488000000000,
                        staged: vec![],
                        invocation: Invocation {
                            environment: vec![("BOOTSTRAP_VALUE".into(), Some("initial".into()))],
                            force_quotes: vec![1],
                            all_exports: false,
                        },
                    };
                    if let Ok(root) = std::env::var("EMUMEE_USER_TEST_FIXTURES") {
                        let path = std::path::PathBuf::from(root).join(format!(
                            "{architecture:?}-bootstrap-{kind:?}-{}-{}",
                            if dll { "dll" } else { "exe" },
                            if supplied { "configured" } else { "default" }
                        ));
                        std::fs::create_dir_all(&path).unwrap();
                        std::fs::write(path.join(&request.module_name), &bytes).unwrap();
                        if let Some(persona) = &persona {
                            std::fs::write(path.join("persona.json"), persona).unwrap();
                        }
                        std::fs::write(path.join("inputs.json"), serde_json::to_vec_pretty(&serde_json::json!({"schema":1,"files":[],"invocation":request.invocation})).unwrap()).unwrap();
                        std::fs::write(
                            path.join("arguments.json"),
                            serde_json::to_vec(&request.arguments).unwrap(),
                        )
                        .unwrap();
                    }
                    let result = user::run(&request, &bytes, persona.as_deref()).unwrap();
                    if matches!(kind, F::Protect | F::Free) {
                        assert!(
                            result
                                .error
                                .as_deref()
                                .is_some_and(|value| value.contains("owned user bootstrap")),
                            "{architecture:?}/{dll}/{kind:?}/{supplied}: {result:#?}"
                        );
                        assert_eq!(result.guest_entry_return, None);
                    } else {
                        assert_eq!(
                            result.error, None,
                            "{architecture:?}/{dll}/{kind:?}/{supplied}: {result:#?}"
                        );
                        assert_eq!(result.guest_entry_return, Some(1));
                        assert!(result.instruction_count > 100);
                    }
                    let bootstrap = result.user_bootstrap.as_ref().unwrap();
                    assert_eq!((bootstrap.process_id, bootstrap.thread_id), (1024, 1));
                    assert_eq!(
                        bootstrap.image_base,
                        PeImage::parse(&bytes, "probe.exe").unwrap().image_base
                    );
                    assert_eq!(bootstrap.stack_base - bootstrap.stack_limit, STACK_SIZE);
                    assert!(bootstrap.command_line != 0 && bootstrap.environment != 0);
                    assert!(bootstrap.mapped_bytes < 2 * 1024 * 1024);
                }
            }
        }
    }
}

#[test]
fn bootstrap_counted_command_line_preserves_the_exact_maximum_without_u16_wrap() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let bytes = fixtures::user_bootstrap_probe(architecture, F::Basic, false);
        let mut request = Request {
            schema: 2,
            profile: PROFILE.into(),
            run_id: "20261106T120000Z-12345678".into(),
            input_sha256: digest(&bytes),
            input_size: bytes.len() as u64,
            module_name: "bootstrap.exe".into(),
            arguments: vec![],
            max_instructions: 500000,
            timeout_us: 30_000_000,
            persona_sha256: None,
            clock_utc_filetime: 134377488000000000,
            staged: vec![],
            invocation: Invocation::default(),
        };
        request.arguments =
            vec!["x".repeat(32767 - request.guest_path().encode_utf16().count() - 1)];
        assert!(request.validate().is_err());
        request.arguments[0].pop();
        request.validate().unwrap();
        if let Ok(root) = std::env::var("EMUMEE_USER_TEST_FIXTURES") {
            let path = std::path::PathBuf::from(root)
                .join(format!("{architecture:?}-bootstrap-Boundary-exe-default"));
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(path.join(&request.module_name), &bytes).unwrap();
            std::fs::write(
                path.join("inputs.json"),
                serde_json::to_vec_pretty(
                    &serde_json::json!({"schema":1,"files":[],"invocation":request.invocation}),
                )
                .unwrap(),
            )
            .unwrap();
            std::fs::write(
                path.join("arguments.json"),
                serde_json::to_vec(&request.arguments).unwrap(),
            )
            .unwrap();
        }
        let result = user::run(&request, &bytes, None).unwrap();
        assert_eq!(result.error, None, "{architecture:?}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1));
    }
}

#[test]
fn bootstrap_is_not_installed_in_unsubmitted_generated_or_kernel_profiles() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for bytes in [
            fixtures::api_probe(architecture, fixtures::ApiFixture::Unsupported),
            fixtures::counted_driver(architecture, 1),
        ] {
            let result = run_generated_image(&bytes, 20000, 1_000_000).unwrap();
            assert!(result.user_bootstrap.is_none());
        }
    }
}

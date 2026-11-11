use super::*;
mod companion;
mod emit;
mod nested_loader;
use emumee_core::{
    fixtures,
    report_bundle::digest,
    user_input::{Invocation, PROFILE, Request},
};

#[test]
fn m3_nested_crt_callbacks_preserve_frames_and_unwind_faults_abi_errors_and_shared_budgets() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in [
            fixtures::M3CallbackFixture::Normal,
            fixtures::M3CallbackFixture::Fault,
            fixtures::M3CallbackFixture::Budget,
            fixtures::M3CallbackFixture::BadStack,
            fixtures::M3CallbackFixture::Nonvolatile,
            fixtures::M3CallbackFixture::InvalidTarget,
        ] {
            let bytes = fixtures::m3_callback_probe(architecture, kind);
            let request = Request {
                schema: 2,
                profile: PROFILE.into(),
                run_id: "20261110T120000Z-12345678".into(),
                input_sha256: digest(&bytes),
                input_size: bytes.len() as u64,
                module_name: "callbacks.exe".into(),
                arguments: vec![],
                max_instructions: if kind == fixtures::M3CallbackFixture::Budget {
                    512
                } else {
                    500000
                },
                timeout_us: 30_000_000,
                persona_sha256: None,
                clock_utc_filetime: 134377488000000000,
                staged: vec![],
                invocation: Invocation::default(),
            };
            emit::fixture(
                &format!("{architecture:?}-m3-callback-{kind:?}"),
                &request,
                &bytes,
                &[],
                None,
            );
            let result = user::run(&request, &bytes, None).unwrap();
            let report = result.crt_startup.as_ref().unwrap();
            assert!(
                !report.initializer_pending && report.suspended_initializers == 0,
                "{architecture:?}/{kind:?}: {result:#?}"
            );
            if kind == fixtures::M3CallbackFixture::Normal {
                assert_eq!(result.error, None, "{architecture:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1));
                assert_eq!(report.initializers.len(), 3);
                assert!(report.interrupted_initializers.is_empty());
                assert!(result.maximum_continuation_depth >= 3);
            } else {
                assert_eq!(result.guest_entry_return, None);
                assert_eq!(
                    report.interrupted_initializers.len(),
                    2,
                    "{architecture:?}/{kind:?}: {result:#?}"
                );
                if kind == fixtures::M3CallbackFixture::Budget {
                    assert_eq!(result.instruction_count, request.max_instructions);
                } else {
                    assert!(
                        result.error.is_some(),
                        "{architecture:?}/{kind:?}: {result:#?}"
                    );
                }
            }
        }
    }
}

#[test]
fn m3_real_new_threads_have_owned_teb_tls_notifications_and_shared_horizons() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in [
            fixtures::M3ThreadFixture::Return,
            fixtures::M3ThreadFixture::Exit,
            fixtures::M3ThreadFixture::Terminate,
            fixtures::M3ThreadFixture::Suspended,
            fixtures::M3ThreadFixture::Budget,
            fixtures::M3ThreadFixture::Fault,
        ] {
            let bytes = fixtures::m3_thread_probe(architecture, kind);
            let request = Request {
                schema: 2,
                profile: PROFILE.into(),
                run_id: "20261110T120000Z-12345678".into(),
                input_sha256: digest(&bytes),
                input_size: bytes.len() as u64,
                module_name: "threads.exe".into(),
                arguments: vec![],
                max_instructions: if kind == fixtures::M3ThreadFixture::Budget {
                    512
                } else {
                    500000
                },
                timeout_us: 30_000_000,
                persona_sha256: None,
                clock_utc_filetime: 134377488000000000,
                staged: vec![],
                invocation: Invocation::default(),
            };
            emit::fixture(
                &format!("{architecture:?}-m3-thread-{kind:?}"),
                &request,
                &bytes,
                &[],
                None,
            );
            let result = user::run(&request, &bytes, None).unwrap();
            let report = result.user_threads.as_ref().unwrap();
            assert_eq!(report.current, 1, "{architecture:?}/{kind:?}: {result:#?}");
            assert_eq!(report.threads.len(), 1);
            if matches!(
                kind,
                fixtures::M3ThreadFixture::Budget | fixtures::M3ThreadFixture::Fault
            ) {
                assert_eq!(result.guest_entry_return, None);
                assert_eq!(report.pending, 1);
                assert_eq!(report.threads[0].state, "interrupted");
                if kind == fixtures::M3ThreadFixture::Budget {
                    assert_eq!(result.instruction_count, request.max_instructions);
                } else {
                    assert!(result.error.is_some(), "{result:#?}");
                }
            } else {
                assert_eq!(result.error, None, "{architecture:?}/{kind:?}: {result:#?}");
                assert_eq!(
                    result.guest_entry_return,
                    Some(42),
                    "{architecture:?}/{kind:?}: {result:#?}"
                );
                assert_eq!(report.pending, 0);
                assert!(report.threads[0].backing_released && report.threads[0].handle_closed);
                let events = &result.user_lifecycle.as_ref().unwrap().events;
                assert_eq!(
                    events.iter().map(|event| event.reason).collect::<Vec<_>>(),
                    if kind == fixtures::M3ThreadFixture::Terminate {
                        vec![2]
                    } else {
                        vec![2, 3]
                    }
                );
                assert!(
                    events
                        .iter()
                        .all(|event| event.returned && event.thread == 2)
                );
                assert_eq!(result.user_loader.as_ref().unwrap().threads.len(), 1);
                assert!(result.api_events.iter().any(|event| event.thread_id == 2));
            }
        }
    }
}

#[test]
fn m3_normal_exit_detaches_real_tls_forced_exit_skips_callbacks_and_cleanup_shares_budget() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for (forced, loops) in [(false, false), (true, false), (false, true), (true, true)] {
            let bytes = fixtures::m3_exit_probe(architecture, forced, loops);
            let request = Request {
                schema: 2,
                profile: PROFILE.into(),
                run_id: "20261110T120000Z-12345678".into(),
                input_sha256: digest(&bytes),
                input_size: bytes.len() as u64,
                module_name: "exit.exe".into(),
                arguments: vec![],
                max_instructions: 512,
                timeout_us: 30_000_000,
                persona_sha256: None,
                clock_utc_filetime: 134377488000000000,
                staged: vec![],
                invocation: Invocation::default(),
            };
            emit::fixture(
                &format!("{architecture:?}-m3-process-{forced}-{loops}"),
                &request,
                &bytes,
                &[],
                None,
            );
            let result = user::run(&request, &bytes, None).unwrap();
            let lifecycle = result.user_lifecycle.as_ref().unwrap();
            assert_eq!(
                result.process_exit_code,
                Some(73),
                "{architecture:?}/{forced}/{loops}: {result:#?}"
            );
            assert_eq!(result.guest_entry_return, None);
            assert_eq!(lifecycle.forced, forced);
            assert_eq!(lifecycle.events.len(), usize::from(!forced));
            if loops && !forced {
                assert!(
                    result
                        .error
                        .as_ref()
                        .is_some_and(|error| error.contains("Process detach")),
                    "{result:#?}"
                );
                assert_eq!(result.instruction_count, request.max_instructions);
                assert!(!lifecycle.complete && !lifecycle.events[0].returned);
            } else {
                assert_eq!(
                    result.error, None,
                    "{architecture:?}/{forced}/{loops}: {result:#?}"
                );
                assert!(lifecycle.complete);
                assert_eq!(result.user_loader.as_ref().unwrap().tls_bytes, 0);
                assert!(
                    lifecycle
                        .events
                        .iter()
                        .all(|event| event.returned && event.reason == 0)
                );
            }
        }
    }
}

#[test]
fn m3_guest_ldr_export_walk_resolves_and_calls_the_same_entry_as_static_imports() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let bytes = fixtures::m3_provider_probe(architecture);
        let request = Request {
            schema: 2,
            profile: PROFILE.into(),
            run_id: "20261110T120000Z-12345678".into(),
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
        emit::fixture(
            &format!("{architecture:?}-m3-provider"),
            &request,
            &bytes,
            &[],
            None,
        );
        let result = user::run(&request, &bytes, None).unwrap();
        assert_eq!(result.error, None, "{architecture:?}: {result:#?}");
        assert_eq!(
            result.guest_entry_return,
            Some(1),
            "{architecture:?}: {result:#?}"
        );
        let loader = result.user_loader.as_ref().unwrap();
        assert_eq!(
            loader
                .entries
                .iter()
                .skip(1)
                .take(3)
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            vec!["ntdll.dll", "kernel32.dll", "kernelbase.dll"]
        );
        for name in ["kernel32.dll", "kernelbase.dll", "ntdll.dll", "msvcrt.dll"] {
            assert!(
                loader
                    .entries
                    .iter()
                    .any(|e| e.name == name && e.initialized && e.path.ends_with(name))
            );
        }
    }
}

#[test]
fn m3_lazy_forwarder_failures_resume_with_errors_and_release_temporary_images() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for failure in [
            fixtures::LazyForwarderFixture::MissingModule,
            fixtures::LazyForwarderFixture::MissingExport,
            fixtures::LazyForwarderFixture::Cycle,
        ] {
            let bytes = fixtures::dynamic_loader_lazy_forwarder_probe(architecture, failure);
            let request = Request {
                schema: 2,
                profile: PROFILE.into(),
                run_id: "20261110T120000Z-12345678".into(),
                input_sha256: digest(&bytes),
                input_size: bytes.len() as u64,
                module_name: "graph.exe".into(),
                arguments: vec![],
                max_instructions: 500000,
                timeout_us: 30_000_000,
                persona_sha256: None,
                clock_utc_filetime: 134377488000000000,
                staged: vec![],
                invocation: Invocation::default(),
            };
            emit::fixture(
                &format!("{architecture:?}-m3-forwarder-{failure:?}"),
                &request,
                &bytes,
                &[],
                None,
            );
            let result = user::run(&request, &bytes, None).unwrap();
            assert_eq!(
                result.error, None,
                "{architecture:?}/{failure:?}: {result:#?}"
            );
            assert_eq!(
                result.guest_entry_return,
                Some(42),
                "{architecture:?}/{failure:?}: {result:#?}"
            );
            let loader = result.dynamic_loader.as_ref().unwrap();
            assert!(loader.state.active.is_none() && loader.state.suspended.is_empty());
            assert_eq!(loader.requests, loader.resumed);
            assert!(
                result
                    .user_loader
                    .as_ref()
                    .unwrap()
                    .entries
                    .iter()
                    .all(|entry| !["guest.dll", "other.dll"].contains(&entry.name.as_str()))
            );
        }
    }
}

#[test]
fn m3_submitted_vfs_graph_initializes_missing_dependencies_and_retires_the_same_catalog() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for (recursive, forwarder) in [(false, false), (true, false), (true, true)] {
            let bytes = if recursive {
                fixtures::dynamic_loader_recursive_probe(architecture, forwarder).0
            } else {
                fixtures::dynamic_loader_probe(
                    architecture,
                    fixtures::DynamicLoaderFixture::Dependency,
                )
                .0
            };
            let request = Request {
                schema: 2,
                profile: PROFILE.into(),
                run_id: "20261107T170000Z-12345678".into(),
                input_sha256: digest(&bytes),
                input_size: bytes.len() as u64,
                module_name: "graph.exe".into(),
                arguments: vec![],
                max_instructions: 500000,
                timeout_us: 30_000_000,
                persona_sha256: None,
                clock_utc_filetime: 134377488000000000,
                staged: vec![],
                invocation: Invocation::default(),
            };
            emit::fixture(
                &format!(
                    "{architecture:?}-m3-graph-{}",
                    if forwarder {
                        "forwarder"
                    } else if recursive {
                        "recursive"
                    } else {
                        "existing"
                    }
                ),
                &request,
                &bytes,
                &[],
                None,
            );
            let result = user::run(&request, &bytes, None).unwrap();
            assert_eq!(
                result.error, None,
                "{architecture:?}/{recursive}/{forwarder}: {result:#?}"
            );
            assert_eq!(
                result.guest_entry_return,
                Some(42),
                "{architecture:?}/{recursive}/{forwarder}: {result:#?}"
            );
            let loader = result.dynamic_loader.as_ref().unwrap();
            assert!(loader.state.active.is_none() && loader.state.suspended.is_empty());
            assert_eq!(loader.requests, loader.resumed);
            assert_eq!(loader.state.retired.len(), 2);
            if forwarder {
                assert!(result.api_events.iter().any(
                    |event| event.api.ends_with(".GetProcAddress")
                        && event.effect == Some("dynamic_loader_return_ready")
                        && !event.pending
                ));
                assert!(loader.state.retired.iter().all(
                    |image| image.image.phase == emumee_core::modules::DynamicPhase::Detaching
                ));
            }
            assert!(
                result
                    .user_loader
                    .as_ref()
                    .unwrap()
                    .entries
                    .iter()
                    .all(|entry| !["guest.dll", "other.dll"].contains(&entry.name.as_str()))
            );
        }
    }
}

#[test]
fn submitted_static_tls_callbacks_and_entry_read_real_vectors_templates_zero_fill_and_ldr() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for readonly in [false, true] {
            let bytes = fixtures::m3_storage_probe(architecture, readonly);
            let request = Request {
                schema: 2,
                profile: PROFILE.into(),
                run_id: "20261107T170000Z-12345678".into(),
                input_sha256: digest(&bytes),
                input_size: bytes.len() as u64,
                module_name: "bootstrap.exe".into(),
                arguments: vec!["two words".into()],
                max_instructions: 500000,
                timeout_us: 30_000_000,
                persona_sha256: None,
                clock_utc_filetime: 134377488000000000,
                staged: vec![],
                invocation: Invocation::default(),
            };
            emit::fixture(
                &format!(
                    "{architecture:?}-m3-storage-{}",
                    if readonly { "refusal" } else { "normal" }
                ),
                &request,
                &bytes,
                &[],
                None,
            );
            let result = user::run(&request, &bytes, None).unwrap();
            if readonly {
                assert!(result.error.is_some(), "{architecture:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, None);
                assert_eq!(result.instruction_count, 0);
            } else {
                assert_eq!(result.error, None, "{architecture:?}: {result:#?}");
                assert_eq!(
                    result.guest_entry_return,
                    Some(1),
                    "{architecture:?}: {result:#?}"
                );
                let loader = result.user_loader.as_ref().unwrap();
                assert_eq!(loader.slot_modules.iter().flatten().count(), 1);
                assert_eq!(loader.threads.len(), 1);
                assert_eq!(loader.threads[&1].blocks.len(), 1);
                assert!(
                    loader
                        .entries
                        .iter()
                        .any(|entry| entry.name == "bootstrap.exe" && entry.initialized)
                );
            }
        }
    }
}

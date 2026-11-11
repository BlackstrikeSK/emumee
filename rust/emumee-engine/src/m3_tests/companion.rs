use super::*;
use emumee_core::user_input::{InputKind, StagedFile};

#[test]
fn nested_threads_refuse_aggregate_tls_before_publishing_partial_thread_backing() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let (bytes, companions) = fixtures::m3_tls_quota_probe(architecture);
        let mut request = staged_request(&bytes, &companions[0].1, "quota.exe");
        request.staged = companions
            .iter()
            .map(|(name, bytes)| StagedFile {
                kind: InputKind::Companion,
                guest_path: format!(r"C:\workspace\{name}"),
                size: bytes.len() as u64,
                sha256: digest(bytes),
            })
            .collect();
        let staged = companions
            .into_iter()
            .map(|(_, bytes)| bytes)
            .collect::<Vec<_>>();
        emit::fixture(
            &format!("{architecture:?}-m3-tls-quota"),
            &request,
            &bytes,
            &staged,
            None,
        );
        let result = user::run_staged(&request, &bytes, None, &staged).unwrap();
        assert_eq!(result.error, None, "{architecture:?}: {result:#?}");
        assert_eq!(
            result.guest_entry_return,
            Some(42),
            "{architecture:?}: {result:#?}"
        );
        let threads = result.user_threads.as_ref().unwrap();
        assert_eq!(threads.threads.len(), 2);
        assert_eq!(threads.pending, 0);
        assert!(threads.threads.iter().all(|thread| thread.backing_released
            && thread.handle_closed
            && thread.exit_code == Some(42)));
        let tls = result.user_loader.as_ref().unwrap();
        assert_eq!(tls.threads.len(), 1);
        assert_eq!(tls.threads[&1].blocks.len(), 17);
        assert!(tls.tls_bytes < 64 * 1024 * 1024);
        assert!(
            result
                .api_events
                .iter()
                .any(|event| event.api.ends_with(".CreateThread")
                    && event.result == Some(0)
                    && event.last_error == 8
                    && !event.pending)
        );
    }
}

fn staged_request(bytes: &[u8], companion: &[u8], name: &str) -> Request {
    Request {
        schema: 2,
        profile: PROFILE.into(),
        run_id: "20261110T120000Z-12345678".into(),
        input_sha256: digest(bytes),
        input_size: bytes.len() as u64,
        module_name: name.into(),
        arguments: vec![],
        max_instructions: 500000,
        timeout_us: 30_000_000,
        persona_sha256: None,
        clock_utc_filetime: 134377488000000000,
        staged: vec![StagedFile {
            kind: InputKind::Companion,
            guest_path: r"C:\workspace\tls.dll".into(),
            size: companion.len() as u64,
            sha256: digest(companion),
        }],
        invocation: Invocation::default(),
    }
}

#[test]
fn supplied_dll_and_exe_static_tls_have_distinct_thread_blocks_and_actual_notifications() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in [
            fixtures::M3ThreadFixture::Return,
            fixtures::M3ThreadFixture::Exit,
            fixtures::M3ThreadFixture::Terminate,
            fixtures::M3ThreadFixture::Suspended,
        ] {
            let (bytes, companion) = fixtures::m3_link_tls_companion(
                architecture,
                fixtures::m3_thread_probe(architecture, kind),
            );
            let request = staged_request(&bytes, &companion, "threads.exe");
            let staged = vec![companion];
            emit::fixture(
                &format!("{architecture:?}-m3-companion-thread-{kind:?}"),
                &request,
                &bytes,
                &staged,
                None,
            );
            let result = user::run_staged(&request, &bytes, None, &staged).unwrap();
            assert_eq!(result.error, None, "{architecture:?}/{kind:?}: {result:#?}");
            assert_eq!(
                result.guest_entry_return,
                Some(42),
                "{architecture:?}/{kind:?}: {result:#?}"
            );
            let module = result
                .native_loader
                .as_ref()
                .unwrap()
                .images
                .iter()
                .find(|module| module.name == "tls.dll")
                .unwrap()
                .identity();
            let events = &result.user_lifecycle.as_ref().unwrap().events;
            assert!(
                events
                    .iter()
                    .all(|event| event.returned && event.thread == 2)
            );
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.invocation.module == module && event.reason == 2)
                    .count(),
                2
            );
            assert_eq!(
                events
                    .iter()
                    .filter(|event| event.invocation.module == module && event.reason == 3)
                    .count(),
                if kind == fixtures::M3ThreadFixture::Terminate {
                    0
                } else {
                    2
                }
            );
            assert_eq!(
                result.user_loader.as_ref().unwrap().threads[&1]
                    .blocks
                    .len(),
                2
            );
            assert!(result.user_threads.as_ref().unwrap().threads[0].backing_released);
        }
    }
}

#[test]
fn supplied_dll_process_detach_checks_tls_and_reserved_arguments_and_forced_exit_skips_it() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for forced in [false, true] {
            let (bytes, companion) = fixtures::m3_link_tls_companion(
                architecture,
                fixtures::m3_exit_probe(architecture, forced, false),
            );
            let request = staged_request(&bytes, &companion, "exit.exe");
            let staged = vec![companion];
            emit::fixture(
                &format!("{architecture:?}-m3-companion-process-{forced}"),
                &request,
                &bytes,
                &staged,
                None,
            );
            let result = user::run_staged(&request, &bytes, None, &staged).unwrap();
            assert_eq!(result.error, None, "{architecture:?}/{forced}: {result:#?}");
            assert_eq!(result.process_exit_code, Some(73));
            let report = result.user_lifecycle.as_ref().unwrap();
            assert!(report.complete);
            assert_eq!(report.events.len(), if forced { 0 } else { 3 });
            assert!(
                report
                    .events
                    .iter()
                    .all(|event| event.returned && event.reason == 0)
            );
            assert_eq!(result.user_loader.as_ref().unwrap().tls_bytes, 0);
        }
    }
}

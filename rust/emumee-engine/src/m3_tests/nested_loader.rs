//! Real DllMain -> nested LoadLibrary -> suspended outer API frame controls.
use super::*;

#[test]
fn unknown_static_dll_import_is_not_materialized_as_a_synthetic_provider() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let mut bytes = fixtures::m3_provider_probe(architecture);
        let old = b"kernel32.dll\0";
        let positions = bytes
            .windows(old.len())
            .enumerate()
            .filter_map(|(index, bytes)| (bytes == old).then_some(index))
            .collect::<Vec<_>>();
        assert_eq!(positions.len(), 1);
        let at = positions[0];
        bytes[at..at + old.len()].fill(0);
        bytes[at..at + 11].copy_from_slice(b"absent.dll\0");
        let request = Request {
            schema: 2,
            profile: PROFILE.into(),
            run_id: "20261110T120000Z-12345678".into(),
            input_sha256: digest(&bytes),
            input_size: bytes.len() as u64,
            module_name: "unresolved.exe".into(),
            arguments: vec![],
            max_instructions: 500000,
            timeout_us: 30_000_000,
            persona_sha256: None,
            clock_utc_filetime: 134377488000000000,
            staged: vec![],
            invocation: Invocation::default(),
        };
        emit::fixture(
            &format!("{architecture:?}-m3-unresolved-static"),
            &request,
            &bytes,
            &[],
            None,
        );
        let result = user::run(&request, &bytes, None).unwrap();
        assert!(
            result
                .error
                .as_ref()
                .is_some_and(|error| error.contains("not an actually modeled binding")),
            "{architecture:?}: {result:#?}"
        );
        assert_eq!(result.instruction_count, 0);
        assert_eq!(result.guest_entry_return, None);
        assert!(
            result
                .loaded_modules
                .iter()
                .all(|module| module.name != "absent.dll")
        );
    }
}

#[test]
fn nested_loader_provider_acquisition_and_missing_library_resume_the_actual_outer_dll_frame() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for missing in [false, true] {
            let mut bytes = fixtures::dynamic_loader_probe(
                architecture,
                fixtures::DynamicLoaderFixture::Reentry,
            )
            .0;
            if missing {
                let base: u64 = if architecture == Architecture::X64 {
                    0x150000000
                } else {
                    0x500000
                };
                let width = architecture.width();
                let old = (base + 0x2140).to_le_bytes();
                let new = (base + 0x2900).to_le_bytes();
                let entry = &mut bytes[0x5400..0x5500];
                let positions = entry
                    .windows(width)
                    .enumerate()
                    .filter_map(|(index, bytes)| (bytes == &old[..width]).then_some(index))
                    .collect::<Vec<_>>();
                assert_eq!(positions.len(), 1);
                entry[positions[0]..positions[0] + width].copy_from_slice(&new[..width]);
                bytes[0x6d00..0x6d0c].copy_from_slice(b"missing.dll\0");
            }
            let request = Request {
                schema: 2,
                profile: PROFILE.into(),
                run_id: "20261110T120000Z-12345678".into(),
                input_sha256: digest(&bytes),
                input_size: bytes.len() as u64,
                module_name: "nested.exe".into(),
                arguments: vec![],
                max_instructions: 500000,
                timeout_us: 30_000_000,
                persona_sha256: None,
                clock_utc_filetime: 134377488000000000,
                staged: vec![],
                invocation: Invocation::default(),
            };
            emit::fixture(
                &format!("{architecture:?}-m3-nested-loader-{missing}"),
                &request,
                &bytes,
                &[],
                None,
            );
            let result = user::run(&request, &bytes, None).unwrap();
            assert_eq!(
                result.error, None,
                "{architecture:?}/{missing}: {result:#?}"
            );
            assert_eq!(result.guest_entry_return, Some(42));
            let loader = result.dynamic_loader.as_ref().unwrap();
            assert_eq!(loader.requests, 3);
            assert_eq!(loader.resumed, loader.requests);
            assert!(
                loader.state.active.is_none()
                    && loader.state.suspended.is_empty()
                    && loader.suspended_callers == 0
            );
            assert_eq!(loader.state.retired.len(), 1);
            assert!(result.api_events.iter().all(|event| !event.pending));
            assert!(result.maximum_continuation_depth >= 2);
            if missing {
                assert!(loader.refusals.iter().any(|refusal| refusal.win32 == 126));
                assert!(
                    result
                        .api_events
                        .iter()
                        .any(|event| event.api.ends_with(".LoadLibraryA")
                            && event.result == Some(0)
                            && event.last_error == 126)
                );
            } else {
                let provider = result
                    .user_loader
                    .as_ref()
                    .unwrap()
                    .entries
                    .iter()
                    .find(|module| module.name == "kernel32.dll")
                    .unwrap();
                assert_eq!(provider.references, 1);
                assert!(
                    result
                        .api_events
                        .iter()
                        .any(|event| event.api.ends_with(".LoadLibraryA")
                            && event.result == Some(provider.base))
                );
            }
        }
    }
}

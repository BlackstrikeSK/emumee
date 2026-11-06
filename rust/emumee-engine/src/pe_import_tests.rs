use super::*;
use emumee_core::pe::ImportName;
use emumee_core::{
    fixtures::{self, ImportFixture as F},
    report_bundle::digest,
    user_input::{PROFILE, Request},
};

fn request(bytes: &[u8]) -> Request {
    Request {
        schema: 1,
        profile: PROFILE.into(),
        run_id: "20261104T120000Z-12345678".into(),
        input_sha256: digest(bytes),
        input_size: bytes.len() as u64,
        module_name: "imports.exe".into(),
        arguments: vec![],
        max_instructions: 2000,
        timeout_us: 1_000_000,
        persona_sha256: None,
        clock_utc_filetime: 134377488000000000,
        staged: vec![],
        invocation: Default::default(),
    }
}

fn staged_exit(
    case: &str,
    architecture: Architecture,
    bytes: &[u8],
    companions: &[(String, Vec<u8>)],
) -> Execution {
    let mut request = request(bytes);
    request.schema = 2;
    if PeImage::parse(bytes, "probe.exe").unwrap().sample.kind == emumee_core::pe::Kind::Dll {
        request.module_name = "imports.dll".into();
    }
    let payloads = companions
        .iter()
        .map(|(_, bytes)| bytes.clone())
        .collect::<Vec<_>>();
    request.staged = companions
        .iter()
        .map(|(name, bytes)| emumee_core::user_input::StagedFile {
            kind: emumee_core::user_input::InputKind::Companion,
            guest_path: format!(r"C:\lib\{name}"),
            size: bytes.len() as u64,
            sha256: digest(bytes),
        })
        .collect();
    if let Ok(root) = std::env::var("EMUMEE_USER_TEST_FIXTURES") {
        let directory =
            std::path::PathBuf::from(root).join(format!("{architecture:?}-exit-{case}"));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join(&request.module_name), bytes).unwrap();
        let files = request
            .staged
            .iter()
            .zip(&payloads)
            .enumerate()
            .map(|(index, (file, bytes))| {
                let source = format!("payload{index}.bin");
                std::fs::write(directory.join(&source), bytes).unwrap();
                serde_json::json!({"kind":file.kind,"source":source,"guest_path":file.guest_path})
            })
            .collect::<Vec<_>>();
        std::fs::write(
            directory.join("inputs.json"),
            serde_json::to_vec_pretty(
                &serde_json::json!({"schema":1,"files":files,"invocation":request.invocation}),
            )
            .unwrap(),
        )
        .unwrap();
    }
    let execution = user::run_staged(&request, bytes, None, &payloads).unwrap();
    if request.module_name.ends_with(".exe") {
        let mut dll = bytes.to_vec();
        let flags = u16::from_le_bytes(dll[0x96..0x98].try_into().unwrap()) | 0x2000;
        dll[0x96..0x98].copy_from_slice(&flags.to_le_bytes());
        if architecture == Architecture::X86 {
            let offset = 0x200
                + dll[0x200..0x400]
                    .iter()
                    .position(|byte| matches!(*byte, 0xc2 | 0xc3))
                    .unwrap();
            dll[offset..offset + 3].copy_from_slice(&[0xc2, 12, 0]);
        }
        let result = staged_exit(&format!("Dll{case}"), architecture, &dll, companions);
        assert_eq!(result.error, None, "{architecture:?}/{case}: {result:#?}");
        assert_eq!(result.guest_entry_return, execution.guest_entry_return);
    }
    execution
}

#[test]
fn submitted_staged_delay_dependencies_and_root_dll_close_the_public_import_exit() {
    for architecture in [Architecture::X86, Architecture::X64] {
        {
            let mut root = fixtures::import_probe(architecture, F::DelayPid);
            let (_, companions) =
                fixtures::linked_probe(architecture, fixtures::LinkedFixture::Direct);
            root[0x880..0x88d].fill(0);
            root[0x880..0x88a].copy_from_slice(b"guest.dll\0");
            root[0x982..0x996].fill(0);
            root[0x982..0x988].copy_from_slice(b"Alpha\0");
            for (offset, value) in [(0x414, 0x27c0u32), (0x420, 0x2780), (0x424, 0x27e0)] {
                root[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
            let directory = 0x98
                + if architecture == Architecture::X64 {
                    112
                } else {
                    96
                };
            root[directory + 12..directory + 16].copy_from_slice(&60u32.to_le_bytes());
            root[0xb80..0xc40].fill(0);
            root[0xb80..0xb8a].copy_from_slice(b"guest.dll\0");
            root[0xc02..0xc08].copy_from_slice(b"Alpha\0");
            for offset in [0xbc0, 0xbe0] {
                root[offset..offset + architecture.width()]
                    .copy_from_slice(&0x2800u64.to_le_bytes()[..architecture.width()]);
            }
            let result = staged_exit("DelayNamed", architecture, &root, &companions);
            assert_eq!(result.error, None, "{result:#?}");
            assert_eq!(result.guest_entry_return, Some(17));
            assert_eq!(result.delay_imports.len(), 1);
            assert!(result.delay_imports[0].error.is_none());
        }
        let (root, companions) =
            fixtures::native_loader_probe(architecture, fixtures::LoaderFixture::RootDll);
        let result = staged_exit("DllStartup", architecture, &root, &companions);
        assert_eq!(result.error, None, "{result:#?}");
        assert_eq!(result.guest_entry_return, Some(1));
    }
}

#[test]
fn submitted_imports_delay_resolution_is_lazy_bounded_and_observable() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for case in [
            F::ApiSet,
            F::DelayPid,
            F::DelayMissing,
            F::DelayUnused,
            F::DelayFlags,
            F::DelayAttributes,
            F::DelayModule,
            F::DelayDescriptor,
            F::DelayDll,
            F::DelayIat,
            F::DelayUnaligned,
            F::DelayLimit,
            F::DelayNames,
            F::DelayEmpty,
            F::DelayOrdinal,
            F::DelayHint,
            F::DelayName,
            F::DelayWrite,
        ] {
            let bytes = fixtures::import_probe(architecture, case);
            if let Ok(root) = std::env::var("EMUMEE_USER_TEST_FIXTURES") {
                let directory = std::path::PathBuf::from(root)
                    .join(format!("{architecture:?}-imports-{case:?}"));
                std::fs::create_dir_all(&directory).unwrap();
                std::fs::write(directory.join("imports.exe"), &bytes).unwrap();
            }
            let execution = user::run(&request(&bytes), &bytes, None).unwrap();
            assert_eq!(
                execution.completion_reason, "entry_return",
                "{architecture:?}/{case:?}: {:?}",
                execution.error
            );
            assert!(
                execution.error.is_none(),
                "{architecture:?}/{case:?}: {:?}",
                execution.error
            );
            let expected = match case {
                F::DelayPid => 1024,
                F::ApiSet | F::DelayUnused => 42,
                _ => 0,
            };
            assert_eq!(
                execution.guest_entry_return,
                Some(expected),
                "{architecture:?}/{case:?}"
            );
            if matches!(case, F::ApiSet | F::DelayUnused) {
                assert!(execution.delay_imports.is_empty());
                assert_eq!(execution.api_calls, u64::from(matches!(case, F::ApiSet)));
            } else {
                assert_eq!(execution.delay_imports.len(), 1);
                assert_eq!(
                    execution.delay_imports[0].error.is_none(),
                    matches!(case, F::DelayPid)
                );
                assert_eq!(
                    execution.delay_imports[0].target.is_some(),
                    matches!(case, F::DelayPid)
                );
            }
            assert_eq!(execution.delay_imports_omitted, 0);
        }
    }
}

#[test]
fn imports_named_ordinal_forwarded_and_data_targets_execute_actual_guest_storage() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let wide = architecture == Architecture::X64;
        for ordinal in [false, true] {
            for data_import in [false, true] {
                let (mut root, mut companions) =
                    fixtures::linked_probe(architecture, fixtures::LinkedFixture::Direct);
                root[0x96..0x98].copy_from_slice(&0x22u16.to_le_bytes());
                root[0x98 + 68..0x98 + 70].copy_from_slice(&3u16.to_le_bytes());
                if ordinal {
                    let value = (1u64 << (architecture.width() * 8 - 1)) | 1;
                    root[0x4d0..0x4d0 + architecture.width()]
                        .copy_from_slice(&value.to_le_bytes()[..architecture.width()]);
                }
                if data_import {
                    companions[0].1[0x440..0x444].copy_from_slice(&0x2180u32.to_le_bytes());
                    companions[0].1[0x580..0x584].copy_from_slice(&42u32.to_le_bytes());
                    let second = if ordinal {
                        0x2300
                    } else {
                        (1u64 << (architecture.width() * 8 - 1)) | 1
                    };
                    let offset = 0x4d0 + architecture.width();
                    root[offset..offset + architecture.width()]
                        .copy_from_slice(&second.to_le_bytes()[..architecture.width()]);
                    let iat = if wide { 0x140002080u64 } else { 0x402080 };
                    let mut code = if wide { vec![0x48, 0xa1] } else { vec![0xa1] };
                    code.extend(&iat.to_le_bytes()[..architecture.width()]);
                    code.extend([0xc7, 0x00, 43, 0, 0, 0]);
                    if wide {
                        code.push(0x48);
                    }
                    code.push(0xb9);
                    code.extend(
                        &(iat + architecture.width() as u64).to_le_bytes()[..architecture.width()],
                    );
                    if wide {
                        code.push(0x48);
                    }
                    code.extend([0x3b, 0x01, 0x74, 1, 0xcc, 0x8b, 0x00, 0xc3]);
                    root[0x200..0x200 + code.len()].copy_from_slice(&code);
                }
                let parsed = PeImage::parse(&root, "imports.exe").unwrap();
                assert_eq!(parsed.imports.len(), if data_import { 2 } else { 1 });
                assert_eq!(
                    parsed.imports[0].name,
                    if ordinal {
                        ImportName::Ordinal { ordinal: 1 }
                    } else {
                        ImportName::Name("Alpha".into())
                    }
                );
                let execution = staged_exit(
                    match (ordinal, data_import) {
                        (false, false) => "Named",
                        (true, false) => "Ordinal",
                        (false, true) => "DataNamed",
                        (true, true) => "DataOrdinal",
                    },
                    architecture,
                    &root,
                    &companions,
                );
                assert_eq!(
                    execution.completion_reason, "entry_return",
                    "{:?}",
                    execution.error
                );
                assert_eq!(
                    execution.guest_entry_return,
                    Some(if data_import { 43 } else { 17 })
                );
            }
        }
        let (mut root, mut companions) =
            fixtures::linked_probe(architecture, fixtures::LinkedFixture::Forwarded);
        root[0x96..0x98].copy_from_slice(&0x22u16.to_le_bytes());
        root[0x98 + 68..0x98 + 70].copy_from_slice(&3u16.to_le_bytes());
        companions[0].1[0x480..0x4a0].fill(0);
        companions[0].1[0x480..0x49f].copy_from_slice(b"kernelbase.GetCurrentProcessId\0");
        companions.truncate(1);
        let execution = run_generated_modules(&root, &companions, 2000, 1_000_000, None).unwrap();
        assert_eq!(
            execution.completion_reason, "entry_return",
            "{:?}",
            execution.error
        );
        assert_eq!(execution.guest_entry_return, Some(1024));
        let (mut root, mut companions) =
            fixtures::linked_probe(architecture, fixtures::LinkedFixture::Forwarded);
        root[0x96..0x98].copy_from_slice(&0x22u16.to_le_bytes());
        root[0x98 + 68..0x98 + 70].copy_from_slice(&3u16.to_le_bytes());
        companions[0].1[0x480..0x4a0].fill(0);
        companions[0].1[0x480..0x489].copy_from_slice(b"other.#1\0");
        let execution = run_generated_modules(&root, &companions, 2000, 1_000_000, None).unwrap();
        assert_eq!(execution.guest_entry_return, Some(17));
    }
}

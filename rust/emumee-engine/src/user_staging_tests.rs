use super::*;
use emumee_core::{
    fixtures::{self, ApiFixture, LoaderFixture},
    report_bundle::digest,
    user_input::{InputKind, Invocation, PROFILE, StagedFile},
};

fn request(bytes: &[u8], name: &str) -> Request {
    Request {
        schema: 2,
        profile: PROFILE.into(),
        run_id: "20261105T120000Z-12345678".into(),
        input_sha256: digest(bytes),
        input_size: bytes.len() as u64,
        module_name: name.into(),
        arguments: vec!["two words".into(), "tail\\".into()],
        max_instructions: 20000,
        timeout_us: 30_000_000,
        persona_sha256: None,
        clock_utc_filetime: 134377488000000000,
        staged: vec![],
        invocation: Invocation::default(),
    }
}

fn call(code: &mut Vec<u8>, architecture: Architecture, base: u64, index: usize, args: &[u64]) {
    if architecture == Architecture::X64 {
        for (position, value) in args.iter().enumerate() {
            if position < 4 {
                code.extend([[0x48, 0xb9], [0x48, 0xba], [0x49, 0xb8], [0x49, 0xb9]][position]);
                code.extend(value.to_le_bytes());
            } else {
                code.extend([0x48, 0xb8]);
                code.extend(value.to_le_bytes());
                code.extend([0x48, 0x89, 0x44, 0x24, (32 + (position - 4) * 8) as u8]);
            }
        }
        code.extend([0x48, 0xb8]);
        code.extend((base + 0x2080 + index as u64 * 8).to_le_bytes());
        code.extend([0xff, 0x10]);
    } else {
        for value in args.iter().rev() {
            code.push(0x68);
            code.extend((*value as u32).to_le_bytes());
        }
        code.extend([0xff, 0x15]);
        code.extend(((base + 0x2080) as u32 + index as u32 * 4).to_le_bytes());
    }
}

fn invocation_probe(architecture: Architecture, mode: &str) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let mut bytes = fixtures::api_probe(
        architecture,
        if mode == "file" {
            ApiFixture::FileRoundTripA
        } else {
            ApiFixture::Unsupported
        },
    );
    bytes[0x96..0x98].copy_from_slice(&0x22u16.to_le_bytes());
    bytes[0x98 + 68..0x98 + 70].copy_from_slice(&3u16.to_le_bytes());
    let base = PeImage::parse(&bytes, "sample.exe").unwrap().image_base;
    let mut code = if wide {
        vec![0x48, 0x83, 0xec, 0x48]
    } else {
        vec![]
    };
    let expected;
    if mode == "file" {
        let path = b"C:\\data\\nested\\input.bin\0";
        bytes[0xf00..0xf80].fill(0);
        bytes[0xf00..0xf00 + path.len()].copy_from_slice(path);
        call(
            &mut code,
            architecture,
            base,
            0,
            &[base + 0x2b00, 0x80000000, 3, 0, 3, 0x80, 0],
        );
        call(
            &mut code,
            architecture,
            base,
            3,
            &[0x100, base + 0x2bc0, 4, base + 0x2ba0, 0],
        );
        if wide {
            code.extend([0x48, 0xb8]);
            code.extend((base + 0x2bc0).to_le_bytes());
        } else {
            code.push(0xb8);
            code.extend(((base + 0x2bc0) as u32).to_le_bytes());
        }
        expected = b"RUST".to_vec();
    } else {
        let at = bytes
            .windows(13)
            .position(|value| value == b"ntoskrnl.exe\0")
            .unwrap();
        bytes[at..at + 13].copy_from_slice(b"kernel32.dll\0");
        let previous = b"EmumeeUnimplementedFixtureApi\0";
        let at = bytes
            .windows(previous.len())
            .position(|value| value == previous)
            .unwrap();
        let symbol: &[u8] = if mode == "environment" {
            b"GetEnvironmentVariableA\0"
        } else {
            b"GetCommandLineA\0"
        };
        bytes[at..at + previous.len()].fill(0);
        bytes[at..at + symbol.len()].copy_from_slice(symbol);
        if mode == "environment" {
            bytes[0xf00..0xf06].copy_from_slice(b"TOKEN\0");
            call(
                &mut code,
                architecture,
                base,
                0,
                &[base + 0x2b00, base + 0x2b80, 64],
            );
            if wide {
                code.extend([0x48, 0xb8]);
                code.extend((base + 0x2b80).to_le_bytes());
            } else {
                code.push(0xb8);
                code.extend(((base + 0x2b80) as u32).to_le_bytes());
            }
            expected = b"staged-value\0".to_vec();
        } else {
            call(&mut code, architecture, base, 0, &[]);
            expected = b"C:\\emumee\\sample.exe \"two words\" \"tail\\\"\0".to_vec();
        }
    }
    for (offset, value) in expected.iter().enumerate() {
        code.extend([0x80, 0xb8]);
        code.extend((offset as u32).to_le_bytes());
        code.extend([*value, 0x74, 2, 0x0f, 0x0b]);
    }
    code.extend([0xb8, 42, 0, 0, 0]);
    if wide {
        code.extend([0x48, 0x83, 0xc4, 0x48]);
    }
    code.push(0xc3);
    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
    bytes
}

fn emit(
    name: &str,
    architecture: Architecture,
    bytes: &[u8],
    request: &Request,
    payloads: &[Vec<u8>],
) {
    if let Ok(root) = std::env::var("EMUMEE_USER_TEST_FIXTURES") {
        let directory =
            std::path::PathBuf::from(root).join(format!("{architecture:?}-staging-{name}"));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join(&request.module_name), bytes).unwrap();
        let files = request
            .staged
            .iter()
            .zip(payloads)
            .enumerate()
            .map(|(index, (file, bytes))| {
                let source = format!("payload{index}.bin");
                std::fs::write(directory.join(&source), bytes).unwrap();
                serde_json::json!({"kind":file.kind,"source":source,"guest_path":file.guest_path})
            })
            .collect::<Vec<_>>();
        std::fs::write(
            directory.join("inputs.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
            "schema":1,"files":files,"invocation":request.invocation}))
            .unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn actual_submitted_companions_files_environment_and_quoting_are_consumed() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for mode in ["file", "environment", "quoting", "companion", "forwarded"] {
            let (bytes, companions) = if matches!(mode, "companion" | "forwarded") {
                fixtures::native_loader_probe(
                    architecture,
                    if mode == "forwarded" {
                        LoaderFixture::Forwarded
                    } else {
                        LoaderFixture::Basic
                    },
                )
            } else {
                (invocation_probe(architecture, mode), vec![])
            };
            let mut request = request(&bytes, "sample.exe");
            request.invocation.force_quotes = vec![1];
            request.invocation.environment = vec![("TOKEN".into(), Some("staged-value".into()))];
            let mut payloads = vec![];
            for (name, bytes) in companions {
                request.staged.push(StagedFile {
                    kind: InputKind::Companion,
                    guest_path: format!(r"C:\lib\{name}"),
                    size: bytes.len() as u64,
                    sha256: digest(&bytes),
                });
                payloads.push(bytes);
            }
            if mode == "file" {
                request.staged.push(StagedFile {
                    kind: InputKind::File,
                    guest_path: r"C:\data\nested\input.bin".into(),
                    size: 4,
                    sha256: digest(b"RUST"),
                });
                payloads.push(b"RUST".to_vec());
                request.staged.push(StagedFile {
                    kind: InputKind::File,
                    guest_path: r"C:\data\empty.bin".into(),
                    size: 0,
                    sha256: digest(b""),
                });
                payloads.push(vec![]);
            }
            emit(mode, architecture, &bytes, &request, &payloads);
            preflight(&request, &bytes, None, &payloads).unwrap();
            let result = run_staged(&request, &bytes, None, &payloads).unwrap();
            assert_eq!(result.error, None, "{architecture:?}/{mode}: {result:#?}");
            assert_eq!(
                result.guest_entry_return,
                Some(42),
                "{architecture:?}/{mode}: {result:#?}"
            );
            if matches!(mode, "companion" | "forwarded") {
                let report = result.native_loader.as_ref().unwrap();
                for file in &request.staged {
                    let module = report
                        .images
                        .iter()
                        .find(|module| module.name == file.guest_path.rsplit('\\').next().unwrap())
                        .unwrap();
                    let provenance = module.provenance().unwrap();
                    assert_eq!(provenance.guest_path, file.guest_path);
                    assert_eq!(
                        provenance.origin,
                        emumee_core::modules::ModuleOrigin::SubmittedUser
                    );
                    assert_eq!(provenance.accepted_image_sha256, file.sha256);
                }
            }
            let mut stopped = request.clone();
            stopped.max_instructions = 1;
            assert_eq!(
                run_staged(&stopped, &bytes, None, &payloads)
                    .unwrap()
                    .instruction_count,
                1
            );
        }
    }
}

#[test]
fn actual_submitted_exports_are_opt_in_and_share_the_execution_budget() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let (mut bytes, _) = fixtures::native_loader_probe(architecture, LoaderFixture::RootDll);
        let (_, companions) = fixtures::native_loader_probe(architecture, LoaderFixture::Basic);
        bytes[0x1600..0x1780].copy_from_slice(&companions[0].1[0x1600..0x1780]);
        bytes[0x400..0x406].copy_from_slice(&[0xb8, 42, 0, 0, 0, 0xc3]);
        let directory = 0x98
            + if architecture == Architecture::X64 {
                112
            } else {
                96
            };
        bytes[directory..directory + 4].copy_from_slice(&0x2400u32.to_le_bytes());
        bytes[directory + 4..directory + 8].copy_from_slice(&0x180u32.to_le_bytes());
        let mut request = request(&bytes, "sample.dll");
        let ordinary = run_staged(&request, &bytes, None, &[]).unwrap();
        assert_eq!(ordinary.error, None);
        assert!(ordinary.native_loader.unwrap().export_entries.is_empty());
        request.invocation.all_exports = true;
        emit("exports", architecture, &bytes, &request, &[]);
        let result = run_staged(&request, &bytes, None, &[]).unwrap();
        assert_eq!(result.error, None, "{architecture:?}: {result:#?}");
        let exports = &result.native_loader.as_ref().unwrap().export_entries;
        assert_eq!(exports.len(), 1);
        assert_eq!(exports[0].returned_value, Some(42));
        assert_eq!(exports[0].arguments.len(), 4);
        assert_eq!(result.guest_entry_return, Some(1));
        request.max_instructions = ordinary.instruction_count + 1;
        let stopped = run_staged(&request, &bytes, None, &[]).unwrap();
        assert_eq!(stopped.instruction_count, request.max_instructions);
        assert!(stopped.guest_entry_return.is_none());
    }
}

#[test]
fn submitted_export_service_arguments_selection_limits_and_faults_are_real_guest_effects() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for mode in [
            "ServiceMainA",
            "ServiceMainW",
            "ServiceMain",
            "selection",
            "ordering",
            "forwarder",
            "fault",
        ] {
            let (mut bytes, _) =
                fixtures::native_loader_probe(architecture, LoaderFixture::RootDll);
            let directory = 0x98
                + if architecture == Architecture::X64 {
                    112
                } else {
                    96
                };
            bytes[directory..directory + 4].copy_from_slice(&0x2400u32.to_le_bytes());
            bytes[directory + 4..directory + 8].copy_from_slice(&0x180u32.to_le_bytes());
            bytes[0x1600..0x1780].fill(0);
            let count = match mode {
                "selection" => 12u32,
                "ordering" => 4,
                _ => 1,
            };
            let named = if mode == "ordering" { 3 } else { count };
            for (offset, value) in [
                (16, 1),
                (20, count),
                (24, named),
                (28, 0x2440),
                (32, 0x2470),
                (36, 0x24a0),
            ] {
                bytes[0x1600 + offset..0x1600 + offset + 4].copy_from_slice(&value.to_le_bytes());
            }
            for index in 0..count as usize {
                let target = match mode {
                    "fault" => 0x2a00u32,
                    "forwarder" => 0x2560,
                    _ => 0x1200,
                };
                bytes[0x1640 + index * 4..0x1644 + index * 4]
                    .copy_from_slice(&target.to_le_bytes());
                if index >= named as usize {
                    continue;
                }
                bytes[0x1670 + index * 4..0x1674 + index * 4]
                    .copy_from_slice(&(0x24c0u32 + index as u32 * 16).to_le_bytes());
                let slot = if mode == "ordering" {
                    [2u16, 0, 2][index]
                } else {
                    index as u16
                };
                bytes[0x16a0 + index * 2..0x16a2 + index * 2].copy_from_slice(&slot.to_le_bytes());
                let name = if mode == "selection" || mode == "ordering" {
                    if index == 0 {
                        "DllMain".to_owned()
                    } else {
                        format!("Export{index}")
                    }
                } else {
                    mode.to_owned()
                };
                bytes[0x16c0 + index * 16..0x16c0 + index * 16 + name.len()]
                    .copy_from_slice(name.as_bytes());
            }
            if mode == "forwarder" {
                bytes[0x1760..0x176c].copy_from_slice(b"other.Value\0");
            }
            let mut code = if mode.starts_with("ServiceMain") {
                if architecture == Architecture::X64 {
                    vec![0x83, 0xf9, 1, 0x74, 2, 0x0f, 0x0b, 0x48, 0x8b, 0x02]
                } else {
                    vec![
                        0x83, 0x7c, 0x24, 4, 1, 0x74, 2, 0x0f, 0x0b, 0x8b, 0x44, 0x24, 8, 0x8b,
                        0x00,
                    ]
                }
            } else {
                vec![]
            };
            if mode.starts_with("ServiceMain") {
                for (offset, value) in if mode.ends_with('A') {
                    b"IPRIP\0".to_vec()
                } else {
                    "IPRIP\0"
                        .encode_utf16()
                        .flat_map(u16::to_le_bytes)
                        .collect()
                }
                .iter()
                .enumerate()
                {
                    code.extend([0x80, 0xb8]);
                    code.extend((offset as u32).to_le_bytes());
                    code.extend([*value, 0x74, 2, 0x0f, 0x0b]);
                }
            }
            code.extend([0xb8, 42, 0, 0, 0, 0xc3]);
            bytes[0x400..0x400 + code.len()].copy_from_slice(&code);
            let mut request = request(&bytes, "sample.dll");
            request.invocation.all_exports = true;
            emit(mode, architecture, &bytes, &request, &[]);
            let result = run_staged(&request, &bytes, None, &[]).unwrap();
            let exports = &result.native_loader.as_ref().unwrap().export_entries;
            if mode == "fault" || mode == "forwarder" {
                assert!(result.error.is_some(), "{architecture:?}: {result:#?}");
                assert_eq!(exports.len(), 1);
                assert!(exports[0].error.is_some());
                assert!(result.guest_entry_return.is_none());
            } else {
                assert_eq!(result.error, None, "{architecture:?}/{mode}: {result:#?}");
                assert_eq!(
                    exports.len(),
                    match mode {
                        "selection" => 9,
                        "ordering" => 4,
                        _ => 1,
                    }
                );
                if mode == "ordering" {
                    assert_eq!(
                        exports
                            .iter()
                            .map(|entry| entry.ordinal)
                            .collect::<Vec<_>>(),
                        vec![1, 3, 2, 4]
                    );
                    assert_eq!(
                        exports
                            .iter()
                            .map(|entry| entry.names.clone())
                            .collect::<Vec<_>>(),
                        vec![
                            vec!["Export1".to_owned()],
                            vec!["Export2".to_owned()],
                            vec![],
                            vec![]
                        ]
                    );
                }
                assert!(exports.iter().all(|entry| entry.returned_value == Some(42)));
                assert!(exports.iter().all(|entry| entry.arguments.len()
                    == if mode.starts_with("ServiceMain") {
                        2
                    } else {
                        4
                    }));
            }
        }
    }
}

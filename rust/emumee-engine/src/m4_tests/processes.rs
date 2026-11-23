use super::*;
use emumee_core::user_input::{InputKind, StagedFile};

fn run(arch: Architecture, label: &str, bytes: Vec<u8>, child: Vec<u8>, budget: u64) -> Execution {
    let staged = vec![child];
    let request = Request {
        schema: 2,
        profile: PROFILE.into(),
        run_id: "20261113T120000Z-12345678".into(),
        input_sha256: digest(&bytes),
        input_size: bytes.len() as u64,
        module_name: "parent.exe".into(),
        arguments: vec![],
        max_instructions: budget,
        timeout_us: 30_000_000,
        persona_sha256: None,
        clock_utc_filetime: 134377488000000000,
        staged: vec![StagedFile {
            kind: InputKind::File,
            guest_path: r"C:\emumee\child.exe".into(),
            size: staged[0].len() as u64,
            sha256: digest(&staged[0]),
        }],
        invocation: Default::default(),
        capture: None,
    };
    let label = format!("{arch:?}-m4-process-{label}");
    emit::fixture(&label, &request, &bytes, &staged, None);
    let result = user::run_staged(&request, &bytes, None, &staged).unwrap();
    emit::execution(&label, &result);
    result
}
fn put(bytes: &mut [u8], rva: usize, data: &[u8]) {
    bytes[rva - 0xe00..rva - 0xe00 + data.len()].copy_from_slice(data);
}

#[test]
fn m4_process_deadlines_and_suspended_deadlock_use_one_virtual_clock() {
    for arch in [Architecture::X86, Architecture::X64] {
        for deadlock in [false, true] {
            let names = [
                "CreateProcessA",
                "WaitForSingleObject",
                "Sleep",
                "GetTickCount",
            ];
            let mut root = Code::new(arch, 0x1000);
            let mut child = Code::new(arch, 0x1000);
            let base = root.base();
            let info = base + 0x3e00;
            root.prologue();
            if arch == Architecture::X64 {
                root.bytes.extend([0x48, 0x83, 0xec, 0x20]);
            }
            root.call(
                0,
                &[
                    V(base + 0x3c00),
                    V(0),
                    V(0),
                    V(0),
                    V(0),
                    V(if deadlock { 4 } else { 0 }),
                    V(0),
                    V(0),
                    V(base + 0x3d00),
                    V(info),
                ],
            );
            root.expect(1);
            if !deadlock {
                root.call(1, &[M(info), V(100)]);
                root.expect(0x102);
                root.call(3, &[]);
                root.expect(523812100 / 16 * 16);
            }
            root.call(1, &[M(info), V(u32::MAX as u64)]);
            root.expect(0);
            root.call(3, &[]);
            root.expect(523812500 / 16 * 16);
            if arch == Architecture::X64 {
                root.bytes.extend([0x48, 0x83, 0xc4, 0x20]);
            }
            root.epilogue(1, 0);
            child.prologue();
            child.call(2, &[V(500)]);
            child.epilogue(42, 0);
            let mut bytes = fixtures::m4_custom_probe(arch, &names, &root.finish(), &[], &[]);
            put(&mut bytes, 0x3c00, b"C:\\emumee\\child.exe\0");
            let child = fixtures::m4_custom_probe(arch, &names, &child.finish(), &[], &[]);
            let result = run(
                arch,
                if deadlock { "deadlock" } else { "deadlines" },
                bytes,
                child,
                30_000,
            );
            if deadlock {
                assert_eq!(result.completion_reason, "error", "{result:#?}");
                assert!(
                    result
                        .error
                        .as_deref()
                        .is_some_and(|error| error.contains("deadlock")),
                    "{result:#?}"
                );
                assert_eq!(result.guest_entry_return, None);
            } else {
                assert_eq!(result.error, None, "{arch:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
                assert_eq!(result.virtual_uptime_ms, 523812500);
            }
            assert!(result.instruction_count < 30_000);
        }
    }
}

#[test]
fn m4_process_teb_identity_tls_and_last_error_are_independent() {
    for arch in [Architecture::X86, Architecture::X64] {
        let names = [
            "CreateProcessA",
            "WaitForSingleObject",
            "TlsAlloc",
            "TlsSetValue",
            "TlsGetValue",
            "SetLastError",
            "GetLastError",
            "GetCurrentProcessId",
            "GetCurrentThreadId",
        ];
        let mut root = Code::new(arch, 0x1000);
        let mut child = Code::new(arch, 0x1000);
        let base = root.base();
        let slot = base + 0x3f00;
        root.prologue();
        if arch == Architecture::X64 {
            root.bytes.extend([0x48, 0x83, 0xec, 0x20]);
        }
        root.call(2, &[]);
        root.expect(0);
        root.store(slot);
        root.call(3, &[M(slot), V(777)]);
        root.expect(1);
        root.call(5, &[V(123)]);
        root.call(
            0,
            &[
                V(base + 0x3c00),
                V(0),
                V(0),
                V(0),
                V(0),
                V(0),
                V(0),
                V(0),
                V(base + 0x3d00),
                V(base + 0x3e00),
            ],
        );
        root.expect(1);
        root.call(1, &[M(base + 0x3e00), V(u32::MAX as u64)]);
        root.expect(0);
        root.call(6, &[]);
        root.expect(0);
        root.call(4, &[M(slot)]);
        root.expect(777);
        if arch == Architecture::X64 {
            root.bytes.extend([0x48, 0x83, 0xc4, 0x20]);
        }
        root.epilogue(1, 0);
        child.prologue();
        child.call(7, &[]);
        child.expect(1025);
        child.call(8, &[]);
        child.expect(65537);
        for (offset, value) in [
            (
                if arch == Architecture::X64 {
                    0x40
                } else {
                    0x20
                },
                1025,
            ),
            (
                if arch == Architecture::X64 {
                    0x48
                } else {
                    0x24
                },
                65537,
            ),
        ] {
            if arch == Architecture::X64 {
                child.bytes.extend([0x65, 0x48, 0xa1]);
                child.bytes.extend((offset as u64).to_le_bytes());
            } else {
                child.bytes.extend([0x64, 0xa1]);
                child.bytes.extend((offset as u32).to_le_bytes());
            }
            child.expect(value);
        }
        child.call(2, &[]);
        child.expect(0);
        child.call(4, &[V(0)]);
        child.expect(0);
        child.call(3, &[V(0), V(999)]);
        child.expect(1);
        child.call(5, &[V(222)]);
        child.epilogue(42, 0);
        let mut bytes = fixtures::m4_custom_probe(arch, &names, &root.finish(), &[], &[]);
        put(&mut bytes, 0x3c00, b"C:\\emumee\\child.exe\0");
        let child = fixtures::m4_custom_probe(arch, &names, &child.finish(), &[], &[]);
        let result = run(arch, "state-isolation", bytes, child, 30_000);
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
        assert!(
            result
                .api_events
                .iter()
                .any(|event| event.process_id == Some(1025) && event.thread_id == 65537)
        );
    }
}

#[test]
fn m4_process_handle_inheritance_and_cross_process_duplication_preserve_owner_and_rights() {
    for arch in [Architecture::X86, Architecture::X64] {
        for inherit in [false, true] {
            let names = [
                "CreateProcessA",
                "OpenProcess",
                "OpenThread",
                "GetProcessId",
                "GetThreadId",
                "GetLastError",
                "DuplicateHandle",
                "WaitForSingleObject",
                "GetExitCodeProcess",
                "CloseHandle",
                "ResumeThread",
            ];
            let mut root = Code::new(arch, 0x1000);
            let mut child = Code::new(arch, 0x1000);
            let base = root.base();
            let info = base + 0x3e00;
            let process = if arch == Architecture::X64 {
                u64::MAX
            } else {
                u32::MAX as u64
            };
            root.prologue();
            if arch == Architecture::X64 {
                root.bytes.extend([0x48, 0x83, 0xec, 0x20]);
            }
            root.call(1, &[V(0x1fffff), V(1), V(1024)]);
            root.expect(0x25000000);
            root.call(2, &[V(0x1fffff), V(1), V(1)]);
            root.expect(0x6d000000);
            root.call(
                0,
                &[
                    V(base + 0x3c00),
                    V(0),
                    V(0),
                    V(0),
                    V(u64::from(inherit)),
                    V(4),
                    V(0),
                    V(0),
                    V(base + 0x3d00),
                    V(info),
                ],
            );
            root.expect(1);
            root.call(
                6,
                &[
                    V(process),
                    V(0x6d000000),
                    M(info),
                    V(base + 0x3f20),
                    V(0x800),
                    V(0),
                    V(0),
                ],
            );
            root.expect(1);
            root.load(base + 0x3f20);
            root.expect(0x2500000c);
            root.call(10, &[M(info + arch.width() as u64)]);
            root.expect(1);
            root.call(7, &[M(info), V(u32::MAX as u64)]);
            root.expect(0);
            root.call(8, &[M(info), V(base + 0x3f20)]);
            root.expect(1);
            root.load(base + 0x3f20);
            root.expect(42);
            root.call(3, &[V(0x25000000)]);
            root.expect(1024);
            root.call(4, &[V(0x6d000000)]);
            root.expect(1);
            if arch == Architecture::X64 {
                root.bytes.extend([0x48, 0x83, 0xc4, 0x20]);
            }
            root.epilogue(1, 0);
            child.prologue();
            child.call(3, &[V(0x25000000)]);
            child.expect(if inherit { 1024 } else { 0 });
            if !inherit {
                child.call(5, &[]);
                child.expect(6);
            }
            child.call(4, &[V(0x6d000000)]);
            child.expect(if inherit { 1 } else { 0 });
            if !inherit {
                child.call(5, &[]);
                child.expect(6);
            }
            child.call(4, &[V(0x2500000c)]);
            child.expect(1);
            child.call(9, &[V(0x2500000c)]);
            child.expect(1);
            child.call(
                6,
                &[
                    V(process),
                    V(process - 1),
                    V(process),
                    V(base + 0x3f20),
                    V(0),
                    V(0),
                    V(2),
                ],
            );
            child.expect(1);
            child.load(base + 0x3f20);
            child.expect(0x6d000004);
            child.call(4, &[M(base + 0x3f20)]);
            child.expect(65537);
            if inherit {
                child.call(9, &[V(0x25000000)]);
                child.expect(1);
                child.call(9, &[V(0x6d000000)]);
                child.expect(1);
            }
            child.epilogue(42, 0);
            let mut bytes = fixtures::m4_custom_probe(arch, &names, &root.finish(), &[], &[]);
            put(&mut bytes, 0x3c00, b"C:\\emumee\\child.exe\0");
            let child = fixtures::m4_custom_probe(arch, &names, &child.finish(), &[], &[]);
            let result = run(
                arch,
                if inherit {
                    "inherit-handles"
                } else {
                    "no-inherit-handles"
                },
                bytes,
                child,
                50_000,
            );
            assert_eq!(result.error, None, "{arch:?}/{inherit}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
        }
    }
}
#[test]
fn m4_process_ansi_unicode_internal_and_winexec_variants_enter_real_children() {
    for arch in [Architecture::X86, Architecture::X64] {
        for variant in [
            "CreateProcessW",
            "CreateProcessInternalA",
            "CreateProcessInternalW",
            "WinExec",
            "extension",
        ] {
            let mut root = Code::new(arch, 0x1000);
            let mut child = Code::new(arch, 0x1000);
            let base = root.base();
            let info = base + 0x3e00;
            root.prologue();
            if arch == Architecture::X64 {
                root.bytes.extend([0x48, 0x83, 0xec, 0x20]);
            }
            let mut names = NAMES.to_vec();
            names[0] = if variant == "extension" {
                "CreateProcessA"
            } else {
                variant
            };
            if variant == "WinExec" {
                root.call(0, &[V(base + 0x3c00), V(1)]);
                root.expect(33);
                root.call(12, &[V(0x101000), V(0), V(1025)]);
                root.store(info);
            } else {
                let mut args = vec![
                    V(base + 0x3c00),
                    V(0),
                    V(0),
                    V(0),
                    V(0),
                    V(0),
                    V(0),
                    V(0),
                    V(base + 0x3d00),
                    V(info),
                ];
                if variant.starts_with("CreateProcessInternal") {
                    args.insert(0, V(0));
                    args.push(V(0));
                }
                root.call(0, &args);
                root.expect(1);
            }
            root.call(1, &[M(info), V(u32::MAX as u64)]);
            root.expect(0);
            root.call(2, &[M(info), V(base + 0x3f20)]);
            root.expect(1);
            root.load(base + 0x3f20);
            root.expect(42);
            if arch == Architecture::X64 {
                root.bytes.extend([0x48, 0x83, 0xc4, 0x20]);
            }
            root.epilogue(1, 0);
            child.prologue();
            child.epilogue(42, 0);
            let mut bytes = fixtures::m4_custom_probe(arch, &names, &root.finish(), &[], &[]);
            let path = if variant == "extension" {
                r"C:\emumee\child"
            } else {
                r"C:\emumee\child.exe"
            };
            let raw = if variant.ends_with('W') {
                path.encode_utf16()
                    .chain([0])
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>()
            } else {
                path.bytes().chain([0]).collect()
            };
            put(&mut bytes, 0x3c00, &raw);
            let child = fixtures::m4_custom_probe(arch, &[], &child.finish(), &[], &[]);
            let result = run(arch, variant, bytes, child, 30_000);
            assert_eq!(result.error, None, "{arch:?}/{variant}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
            assert_eq!(result.user_processes[1].exit_code, Some(42));
            assert!(result.user_processes[1].backing_released);
        }
    }
}

#[test]
fn m4_remote_threads_contexts_and_virtual_protection_execute_on_the_child_cpu() {
    for arch in [Architecture::X86, Architecture::X64] {
        let names = [
            "CreateProcessA",
            "CreateRemoteThread",
            "WaitForSingleObject",
            "GetExitCodeThread",
            "GetThreadContext",
            "SetThreadContext",
            "ResumeThread",
            "GetProcessId",
            "GetExitCodeProcess",
            "VirtualProtectEx",
            "VirtualFreeEx",
            "VirtualAllocEx",
            "GetLastError",
        ];
        let mut root = Code::new(arch, 0x1000);
        let mut child = Code::new(arch, 0x1000);
        let mut worker = Code::new(arch, 0x1800);
        let base = root.base();
        let info = base + 0x3e00;
        let context = base + 0x3300;
        let thread = base + 0x3f00;
        let output = base + 0x3f10;
        let memory = base + 0x3f20;
        let width = arch.width() as u64;
        root.prologue();
        if arch == Architecture::X64 {
            root.bytes.extend([0x48, 0x83, 0xec, 0x20]);
        }
        root.call(
            0,
            &[
                V(base + 0x3c00),
                V(0),
                V(0),
                V(0),
                V(0),
                V(4),
                V(0),
                V(0),
                V(base + 0x3d00),
                V(info),
            ],
        );
        root.expect(1);
        root.call(
            1,
            &[M(info), V(0), V(0), V(base + 0x1800), V(7), V(0), V(0)],
        );
        root.store(thread);
        root.call(2, &[M(thread), V(u32::MAX as u64)]);
        root.expect(0);
        root.call(3, &[M(thread), V(output)]);
        root.expect(1);
        root.load(output);
        root.expect(7);
        root.call(11, &[M(info), V(0), V(4096), V(0x3000), V(4)]);
        root.store(memory);
        root.call(9, &[M(info), M(memory), V(4096), V(2), V(output)]);
        root.expect(1);
        root.load(output);
        root.expect(4);
        root.call(10, &[M(info), M(memory), V(0), V(0x8000)]);
        root.expect(1);
        root.call(4, &[M(info + width), V(context)]);
        root.expect(1);
        if arch == Architecture::X64 {
            root.bytes.extend([0x48, 0xb8]);
            root.bytes.extend((base + 0x1f00).to_le_bytes());
        } else {
            root.bytes.push(0xb8);
            root.bytes.extend(((base + 0x1f00) as u32).to_le_bytes());
        }
        root.store(context + if arch == Architecture::X64 { 248 } else { 184 });
        root.call(5, &[M(info + width), V(context)]);
        root.expect(1);
        root.call(6, &[M(info + width)]);
        root.expect(1);
        root.call(2, &[M(info), V(u32::MAX as u64)]);
        root.expect(0);
        root.call(8, &[M(info), V(output)]);
        root.expect(1);
        root.load(output);
        root.expect(42);
        if arch == Architecture::X64 {
            root.bytes.extend([0x48, 0x83, 0xc4, 0x20]);
        }
        root.epilogue(1, 0);
        child.bytes.extend([0x0f, 0x0b]);
        worker.prologue();
        worker.epilogue(7, 1);
        let mut bytes = fixtures::m4_custom_probe(arch, &names, &root.finish(), &[], &[]);
        put(&mut bytes, 0x3c00, b"C:\\emumee\\child.exe\0");
        put(
            &mut bytes,
            0x3300 + if arch == Architecture::X64 { 48 } else { 0 },
            &(if arch == Architecture::X64 {
                0x100003u32
            } else {
                0x10003u32
            })
            .to_le_bytes(),
        );
        let child = fixtures::m4_custom_probe(
            arch,
            &[],
            &child.finish(),
            &worker.finish(),
            &[0xb8, 42, 0, 0, 0, 0xc3],
        );
        let result = run(arch, "remote-thread-context-protect", bytes, child, 100_000);
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
        assert_eq!(result.user_processes[1].exit_code, Some(42));
    }
}
const NAMES: &[&str] = &[
    "CreateProcessA",
    "WaitForSingleObject",
    "GetExitCodeProcess",
    "ReadProcessMemory",
    "WriteProcessMemory",
    "VirtualAllocEx",
    "ResumeThread",
    "GetProcessId",
    "GetThreadId",
    "TerminateProcess",
    "CloseHandle",
    "GetLastError",
    "OpenProcess",
];
#[test]
fn m4_processes_have_actual_isolated_address_spaces_remote_memory_and_owned_handles() {
    for arch in [Architecture::X86, Architecture::X64] {
        for suspended in [false, true] {
            let mut root = Code::new(arch, 0x1000);
            let mut child = Code::new(arch, 0x1000);
            let base = root.base();
            let width = arch.width() as u64;
            let info = base + 0x3e00;
            let marker = base + 0x3f00;
            let source = base + 0x3f10;
            let output = base + 0x3f20;
            let count = base + 0x3f30;
            let remote = base + 0x3f40;
            let denied = base + 0x3f50;
            let current = if width == 8 {
                u64::MAX
            } else {
                u32::MAX as u64
            };
            root.prologue();
            if arch == Architecture::X64 {
                root.bytes.extend([0x48, 0x83, 0xec, 0x20]);
            }
            root.call(
                0,
                &[
                    V(base + 0x3c00),
                    V(0),
                    V(0),
                    V(0),
                    V(0),
                    V(if suspended { 4 } else { 0 }),
                    V(0),
                    V(0),
                    V(base + 0x3d00),
                    V(info),
                ],
            );
            root.expect(1);
            root.call(7, &[M(info)]);
            root.expect(1025);
            root.call(8, &[M(info + width)]);
            root.expect(65537);
            root.call(2, &[M(info), V(output)]);
            root.expect(1);
            root.load(output);
            root.expect(259);
            root.call(12, &[V(0x1000), V(0), V(1025)]);
            root.store(denied);
            root.call(3, &[M(denied), V(marker), V(output), V(4), V(count)]);
            root.expect(0);
            root.call(11, &[]);
            root.expect(5);
            root.call(5, &[M(info), V(0), V(4096), V(0x3000), V(4)]);
            root.store(remote);
            root.call(4, &[M(info), M(remote), V(source), V(4), V(count)]);
            root.expect(1);
            root.call(3, &[M(info), M(remote), V(output), V(4), V(count)]);
            root.expect(1);
            root.load(output);
            root.expect(222);
            root.call(3, &[V(current), M(remote), V(output), V(4), V(count)]);
            root.expect(0);
            root.call(11, &[]);
            root.expect(299);
            root.call(4, &[M(info), V(marker), V(source), V(4), V(count)]);
            root.expect(1);
            if suspended {
                root.call(6, &[M(info + width)]);
                root.expect(1);
            }
            root.call(1, &[M(info), V(u32::MAX as u64)]);
            root.expect(0);
            root.call(2, &[M(info), V(output)]);
            root.expect(1);
            root.load(output);
            root.expect(42);
            root.load(marker);
            root.expect(111);
            for pointer in [info, info + width, denied] {
                root.call(10, &[M(pointer)]);
                root.expect(1);
            }
            if arch == Architecture::X64 {
                root.bytes.extend([0x48, 0x83, 0xc4, 0x20]);
            }
            root.epilogue(1, 0);
            child.prologue();
            child.load(marker);
            child.expect(222);
            child.epilogue(42, 0);
            let mut parent = fixtures::m4_custom_probe(arch, NAMES, &root.finish(), &[], &[]);
            put(&mut parent, 0x3c00, b"C:\\emumee\\child.exe\0");
            put(&mut parent, 0x3f00, &111u64.to_le_bytes());
            put(&mut parent, 0x3f10, &222u64.to_le_bytes());
            let child = fixtures::m4_custom_probe(arch, &[], &child.finish(), &[], &[]);
            let result = run(
                arch,
                if suspended {
                    "suspended-isolation"
                } else {
                    "isolation"
                },
                parent,
                child,
                100_000,
            );
            assert_eq!(result.error, None, "{arch:?}/{suspended}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
            assert_eq!(result.user_processes.len(), 2);
            assert_eq!(result.user_processes[1].exit_code, Some(42));
            assert!(result.user_processes[1].backing_released);
            assert!(
                result.api_events.iter().all(|event| !event.pending),
                "{result:#?}"
            );
        }
    }
}

#[test]
fn m4_process_termination_faults_refusals_and_shared_instruction_horizons_are_bounded() {
    for arch in [Architecture::X86, Architecture::X64] {
        for mode in [
            "terminate",
            "fault",
            "budget",
            "missing",
            "bad-output",
            "quota",
            "wrong-arch",
        ] {
            let mut root = Code::new(arch, 0x1000);
            let mut child = Code::new(arch, 0x1000);
            let base = root.base();
            let info = base + 0x3e00;
            let output = base + 0x3f20;
            root.prologue();
            if arch == Architecture::X64 {
                root.bytes.extend([0x48, 0x83, 0xec, 0x20]);
            }
            root.call(
                0,
                &[
                    V(base + 0x3c00),
                    V(0),
                    V(0),
                    V(0),
                    V(0),
                    V(if mode == "terminate" { 4 } else { 0 }),
                    V(0),
                    V(0),
                    V(base + 0x3d00),
                    V(if mode == "bad-output" { 0 } else { info }),
                ],
            );
            if matches!(mode, "missing" | "bad-output" | "quota" | "wrong-arch") {
                root.expect(0);
                root.call(11, &[]);
                root.expect(match mode {
                    "missing" => 2,
                    "bad-output" => 998,
                    "quota" => 8,
                    _ => 50,
                });
            } else {
                root.expect(1);
                if mode == "terminate" {
                    root.call(9, &[M(info), V(73)]);
                    root.expect(1);
                }
                root.call(1, &[M(info), V(u32::MAX as u64)]);
                root.expect(0);
                root.call(2, &[M(info), V(output)]);
                root.expect(1);
                root.load(output);
                root.expect(if mode == "terminate" { 73 } else { 0xc000001d });
                root.call(3, &[M(info), V(base + 0x3f00), V(output), V(4), V(0)]);
                root.expect(0);
                root.call(11, &[]);
                root.expect(5);
            }
            if arch == Architecture::X64 {
                root.bytes.extend([0x48, 0x83, 0xc4, 0x20]);
            }
            root.epilogue(1, 0);
            child.bytes.extend(if mode == "budget" {
                vec![0xeb, 0xfe]
            } else {
                vec![0x0f, 0x0b]
            });
            let mut parent = fixtures::m4_custom_probe(arch, NAMES, &root.finish(), &[], &[]);
            put(
                &mut parent,
                0x3c00,
                if mode == "missing" {
                    b"C:\\emumee\\missing.exe\0"
                } else {
                    b"C:\\emumee\\child.exe\0"
                },
            );
            let child_arch = if mode == "wrong-arch" {
                if arch == Architecture::X64 {
                    Architecture::X86
                } else {
                    Architecture::X64
                }
            } else {
                arch
            };
            let mut child = fixtures::m4_custom_probe(child_arch, &[], &child.finish(), &[], &[]);
            if mode == "quota" {
                child[0x98 + 56..0x98 + 60]
                    .copy_from_slice(&emumee_core::pe::MAX_IMAGE.to_le_bytes());
            }
            let result = run(arch, mode, parent, child, 2048);
            if mode == "budget" {
                assert_eq!(result.instruction_count, 2048, "{result:#?}");
                assert_eq!(
                    result.completion_reason, "instruction_budget",
                    "{result:#?}"
                );
                assert_eq!(result.guest_entry_return, None);
                assert!(!result.user_processes[1].backing_released);
            } else {
                assert_eq!(result.error, None, "{arch:?}/{mode}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
                assert_eq!(
                    result.user_processes.len(),
                    if matches!(mode, "missing" | "bad-output" | "quota" | "wrong-arch") {
                        1
                    } else {
                        2
                    }
                );
                if result.user_processes.len() == 2 {
                    assert!(result.user_processes[1].backing_released);
                }
            }
        }
    }
}

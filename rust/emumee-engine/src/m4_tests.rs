use super::*;
use emumee_core::{
    fixtures::{self, M4Fixture as F},
    report_bundle::digest,
    user_input::{PROFILE, Request},
};
use fixtures::{
    M4Arg::{Memory as M, Value as V},
    M4Code as Code,
};

fn run_control(
    arch: Architecture,
    label: &str,
    names: &[&str],
    root: Code,
    child: Code,
    callback: Code,
    budget: u64,
) -> Execution {
    let mut bytes = fixtures::m4_custom_probe(
        arch,
        names,
        &root.finish(),
        &child.finish(),
        &callback.finish(),
    );
    if names.get(4).is_some_and(|name| name.starts_with("msvcrt!")) {
        // Keep the kernel32 group at indices 0..3 and the real CRT import at
        // index 4, with distinct null-terminated thunk arrays/descriptors.
        let width = arch.width();
        for raw in [0x1280, 0x1380] {
            bytes[raw + 3 * width..raw + 4 * width].fill(0);
            bytes[raw + 5 * width..raw + 6 * width].fill(0);
        }
        for (offset, value) in [
            (0x1214, 0x2180 + 4 * width as u32),
            (0x1220, 0x2280),
            (0x1224, 0x2080 + 4 * width as u32),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes[0x1228..0x123c].fill(0);
        bytes[0x1480..0x148b].copy_from_slice(b"msvcrt.dll\0");
        let name = names[4].strip_prefix("msvcrt!").unwrap();
        bytes[0x1600..0x1640].fill(0);
        bytes[0x1602..0x1602 + name.len()].copy_from_slice(name.as_bytes());
        let dd = 0x98 + if arch == Architecture::X64 { 112 } else { 96 };
        bytes[dd + 12..dd + 16].copy_from_slice(&60u32.to_le_bytes());
    }
    run_image_control(arch, label, bytes, budget)
}
fn run_image_control(arch: Architecture, label: &str, bytes: Vec<u8>, budget: u64) -> Execution {
    let request = Request {
        schema: 2,
        profile: PROFILE.into(),
        run_id: "20261111T120000Z-12345678".into(),
        input_sha256: digest(&bytes),
        input_size: bytes.len() as u64,
        module_name: "scheduler.exe".into(),
        arguments: vec![],
        max_instructions: budget,
        timeout_us: 30_000_000,
        persona_sha256: None,
        clock_utc_filetime: 134377488000000000,
        staged: vec![],
        invocation: Default::default(),
        capture: None,
        output: None,
    };
    emit::fixture(&format!("{arch:?}-m4-{label}"), &request, &bytes, &[], None);
    let result = user::run(&request, &bytes, None).unwrap();
    emit::execution(&format!("{arch:?}-m4-{label}"), &result);
    result
}
use crate::user_test_fixtures as emit;
mod processes;

#[test]
fn m4_crt_thread_apis_use_cdecl_callers_and_distinct_start_routine_abis() {
    for arch in [Architecture::X86, Architecture::X64] {
        for extended in [false, true] {
            let mut root = Code::new(arch, 0x1000);
            let mut child = Code::new(arch, 0x1800);
            let base = root.base();
            let handle = base + 0x3f00;
            let flag = base + 0x3f10;
            root.prologue();
            if extended {
                root.call(4, &[V(0), V(0), V(base + 0x1800), V(0), V(0), V(0)]);
            } else {
                root.call(4, &[V(base + 0x1800), V(0), V(0)]);
            }
            if arch == Architecture::X86 {
                root.bytes
                    .extend([0x83, 0xc4, if extended { 24 } else { 12 }]);
            }
            root.store(handle);
            if extended {
                root.call(0, &[M(handle), V(u32::MAX as u64)]);
                root.expect(0);
                root.call(1, &[M(handle), V(base + 0x3f20)]);
                root.expect(1);
                root.load(base + 0x3f20);
                root.expect(42);
                root.call(2, &[M(handle)]);
                root.expect(1);
            }
            root.load(flag);
            root.expect(42);
            root.epilogue(1, 0);
            child.prologue();
            child.bytes.push(0xb8);
            child.bytes.extend(42u32.to_le_bytes());
            child.store(flag);
            child.epilogue(42, if extended { 1 } else { 0 });
            let result = run_control(
                arch,
                if extended {
                    "beginthreadex"
                } else {
                    "beginthread"
                },
                &[
                    "WaitForSingleObject",
                    "GetExitCodeThread",
                    "CloseHandle",
                    "GetLastError",
                    if extended {
                        "msvcrt!_beginthreadex"
                    } else {
                        "msvcrt!_beginthread"
                    },
                ],
                root,
                child,
                Code::new(arch, 0x1f00),
                20000,
            );
            assert_eq!(result.error, None, "{arch:?}/{extended}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(1));
            assert!(result.user_threads.as_ref().unwrap().threads[0].handle_closed);
        }
    }
}

#[test]
fn m4_guest_dispatcher_wait_all_is_atomic_and_thread_exit_abandons_mutexes() {
    for arch in [Architecture::X86, Architecture::X64] {
        let mut root = Code::new(arch, 0x1000);
        let mut child = Code::new(arch, 0x1800);
        let base = root.base();
        let a = base + 0x3f00;
        let b = a + arch.width() as u64;
        let thread = a + 0x20;
        let mutex = a + 0x30;
        root.prologue();
        root.call(0, &[V(0), V(1), V(2), V(0)]);
        root.store(a);
        root.call(1, &[V(0), V(0), V(0), V(0)]);
        root.store(b);
        root.call(2, &[V(2), V(a), V(1), V(0)]);
        root.expect(0x102);
        root.call(3, &[M(a), V(0)]);
        root.expect(0);
        root.call(4, &[M(a), V(1), V(a + 0x40)]);
        root.expect(1);
        root.load(a + 0x40);
        root.expect(0);
        root.call(5, &[M(b)]);
        root.expect(1);
        root.call(2, &[V(2), V(a), V(1), V(0)]);
        root.expect(0);
        root.call(3, &[M(a), V(0)]);
        root.expect(0x102);
        root.call(3, &[M(b), V(0)]);
        root.expect(0x102);
        root.call(8, &[V(0), V(0), V(base + 0x1800), V(0), V(0), V(0)]);
        root.store(thread);
        root.call(3, &[M(thread), V(u32::MAX as u64)]);
        root.expect(0);
        root.call(3, &[M(mutex), V(0)]);
        root.expect(0x80);
        root.call(7, &[M(mutex)]);
        root.expect(1);
        root.epilogue(1, 0);
        child.prologue();
        child.call(6, &[V(0), V(1), V(0)]);
        child.store(mutex);
        child.epilogue(42, 1);
        let result = run_control(
            arch,
            "dispatcher",
            &[
                "CreateSemaphoreW",
                "CreateEventW",
                "WaitForMultipleObjects",
                "WaitForSingleObject",
                "ReleaseSemaphore",
                "SetEvent",
                "CreateMutexW",
                "ReleaseMutex",
                "CreateThread",
            ],
            root,
            child,
            Code::new(arch, 0x1f00),
            20000,
        );
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1));
    }
}

#[test]
fn m4_scheduler_does_not_treat_a_halted_cpu_as_a_quantum_yield() {
    for arch in [Architecture::X86, Architecture::X64] {
        let mut root = Code::new(arch, 0x1000);
        let mut child = Code::new(arch, 0x1800);
        let base = root.base();
        root.prologue();
        root.call(0, &[V(0), V(0), V(base + 0x1800), V(0), V(0), V(0)]);
        root.bytes.push(0xf4);
        root.epilogue(1, 0);
        child.prologue();
        child.epilogue(42, 1);
        let result = run_control(
            arch,
            "halt",
            &["CreateThread"],
            root,
            child,
            Code::new(arch, 0x1f00),
            20000,
        );
        assert!(
            result
                .error
                .as_deref()
                .is_some_and(|e| e.contains("halted or stopped")),
            "{arch:?}: {result:#?}"
        );
        assert_eq!(result.guest_entry_return, None);
    }
}

#[test]
fn m4_fls_free_and_thread_retirement_execute_checked_destructors() {
    for arch in [Architecture::X86, Architecture::X64] {
        for mode in 0..5 {
            let mut root = Code::new(arch, 0x1000);
            let mut child = Code::new(arch, 0x1800);
            let mut callback = Code::new(arch, 0x1f00);
            let base = root.base();
            let slot = base + 0x3f00;
            let flag = base + 0x3f10;
            let thread = base + 0x3f20;
            root.prologue();
            root.call(0, &[V(base + 0x1f00)]);
            root.store(slot);
            if mode == 0 {
                root.call(1, &[M(slot), V(42)]);
                root.expect(1);
                root.call(2, &[M(slot)]);
                root.expect(1);
                root.call(2, &[M(slot)]);
                root.expect(0);
            } else {
                root.call(3, &[V(0), V(0), V(base + 0x1800), V(0), V(0), V(0)]);
                root.store(thread);
                root.call(4, &[M(thread), V(u32::MAX as u64)]);
                root.expect(0);
            }
            root.load(flag);
            root.expect(if mode == 2 { 0 } else { 42 });
            root.epilogue(1, 0);
            child.prologue();
            child.call(1, &[M(slot), V(42)]);
            child.expect(1);
            if mode == 2 {
                child.call(
                    5,
                    &[
                        V(if arch == Architecture::X64 {
                            u64::MAX - 1
                        } else {
                            u32::MAX as u64 - 1
                        }),
                        V(7),
                    ],
                );
            }
            child.epilogue(42, 1);
            if mode == 3 {
                callback.bytes.extend([0x0f, 0x0b]);
            } else if mode == 4 {
                callback.bytes.extend([0xeb, 0xfe]);
            } else {
                if arch == Architecture::X64 {
                    callback.bytes.extend([0x48, 0x89, 0xc8]);
                } else {
                    callback.bytes.extend([0x8b, 0x44, 0x24, 4]);
                }
                callback.store(flag);
                callback.bytes.extend(if arch == Architecture::X64 {
                    vec![0xc3]
                } else {
                    vec![0xc2, 4, 0]
                });
            }
            let result = run_control(
                arch,
                &format!("fls-{mode}"),
                &[
                    "FlsAlloc",
                    "FlsSetValue",
                    "FlsFree",
                    "CreateThread",
                    "WaitForSingleObject",
                    "TerminateThread",
                ],
                root,
                child,
                callback,
                20000,
            );
            if mode == 3 {
                assert!(result.error.is_some(), "{arch:?}: {result:#?}");
            } else if mode == 4 {
                assert_eq!(result.instruction_count, 20000);
                assert_eq!(result.guest_entry_return, None);
            } else {
                assert_eq!(result.error, None, "{arch:?}/{mode}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1));
                if mode == 2 {
                    let event = result
                        .api_events
                        .iter()
                        .find(|event| event.api == "kernel32.TerminateThread")
                        .unwrap();
                    assert!(!event.pending);
                    assert_eq!(event.result, None);
                    assert_eq!(event.effect, Some("terminates_current_thread"));
                }
            }
        }
    }
}

#[test]
fn m4_apcs_dispatch_only_at_alertable_boundaries_on_the_target_context() {
    for arch in [Architecture::X86, Architecture::X64] {
        let mut root = Code::new(arch, 0x1000);
        let mut callback = Code::new(arch, 0x1f00);
        let base = root.base();
        let flag = base + 0x3f10;
        root.prologue();
        root.call(
            0,
            &[
                V(base + 0x1f00),
                V(if arch == Architecture::X64 {
                    u64::MAX - 1
                } else {
                    u32::MAX as u64 - 1
                }),
                V(99),
            ],
        );
        root.expect(1);
        root.call(1, &[V(1)]);
        root.load(flag);
        root.expect(0);
        root.call(2, &[V(0), V(1)]);
        root.expect(0xc0);
        root.load(flag);
        root.expect(99);
        root.call(2, &[V(0), V(1)]);
        root.expect(0);
        root.epilogue(1, 0);
        if arch == Architecture::X64 {
            callback.bytes.extend([0x48, 0x89, 0xc8]);
        } else {
            callback.bytes.extend([0x8b, 0x44, 0x24, 4]);
        }
        callback.store(flag);
        callback.bytes.extend(if arch == Architecture::X64 {
            vec![0xc3]
        } else {
            vec![0xc2, 4, 0]
        });
        let result = run_control(
            arch,
            "apc",
            &["QueueUserAPC", "Sleep", "SleepEx"],
            root,
            Code::new(arch, 0x1800),
            callback,
            20000,
        );
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1));
    }
}
#[test]
fn m4_actual_user_waits_quantum_tls_error_deadlock_and_virtual_time() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::Signal, F::Quantum, F::Deadlock, F::Timeout] {
            let bytes = fixtures::m4_probe(arch, kind);
            let request = Request {
                schema: 2,
                profile: PROFILE.into(),
                run_id: "20261111T120000Z-12345678".into(),
                input_sha256: digest(&bytes),
                input_size: bytes.len() as u64,
                module_name: "scheduler.exe".into(),
                arguments: vec![],
                max_instructions: 100_000,
                timeout_us: 30_000_000,
                persona_sha256: None,
                clock_utc_filetime: 134377488000000000,
                staged: vec![],
                invocation: Default::default(),
                capture: None,
                output: None,
            };
            emit::fixture(
                &format!("{arch:?}-m4-actual-{kind:?}"),
                &request,
                &bytes,
                &[],
                None,
            );
            let result = user::run(&request, &bytes, None).unwrap();
            emit::execution(&format!("{arch:?}-m4-actual-{kind:?}"), &result);
            if kind == F::Deadlock {
                assert!(
                    result
                        .error
                        .as_deref()
                        .is_some_and(|e| e.contains("User thread deadlock")),
                    "{arch:?}/{kind:?}: {result:#?}"
                );
                assert!(result.instruction_count < request.max_instructions);
            } else {
                assert_eq!(result.error, None, "{arch:?}/{kind:?}: {result:#?}");
                assert_eq!(
                    result.guest_entry_return,
                    Some(1),
                    "{arch:?}/{kind:?}: {result:#?}"
                );
                if kind == F::Quantum {
                    assert!(result.instruction_count > 4096);
                }
                assert!(result.api_events.iter().all(|e| !e.pending));
            }
        }
    }
}

#[test]
fn m4_thread_handles_keep_rights_and_lifetime_independent_of_identity() {
    for arch in [Architecture::X86, Architecture::X64] {
        let mut root = Code::new(arch, 0x1000);
        let mut child = Code::new(arch, 0x1800);
        let base = root.base();
        let h = base + 0x3f00;
        let tid = h + 8;
        let alias = h + 16;
        let restricted = h + 24;
        let out = h + 32;
        let process = if arch == Architecture::X64 {
            u64::MAX
        } else {
            u32::MAX as u64
        };
        root.prologue();
        root.call(0, &[V(0), V(0), V(base + 0x1800), V(0), V(4), V(tid)]);
        root.store(h);
        root.call(1, &[V(0x40), V(0), M(tid)]);
        root.store(restricted);
        root.call(2, &[M(restricted)]);
        root.expect(u32::MAX);
        root.call(3, &[]);
        root.expect(5);
        root.call(4, &[M(restricted), V(0)]);
        root.expect(u32::MAX);
        root.call(3, &[]);
        root.expect(5);
        root.call(
            5,
            &[V(process), M(h), V(process), V(alias), V(0), V(1), V(2)],
        );
        root.expect(1);
        root.call(6, &[M(alias), V(out)]);
        root.expect(1);
        root.load(out);
        root.expect(1);
        root.call(7, &[M(h), V(2), V(2)]);
        root.expect(1);
        root.call(8, &[M(h)]);
        root.expect(0);
        root.call(3, &[]);
        root.expect(5);
        root.call(7, &[M(h), V(2), V(0)]);
        root.expect(1);
        root.call(8, &[M(h)]);
        root.expect(1);
        root.call(2, &[M(h)]);
        root.expect(u32::MAX);
        root.call(3, &[]);
        root.expect(6);
        root.call(2, &[M(alias)]);
        root.expect(1);
        root.call(4, &[M(alias), V(u32::MAX as u64)]);
        root.expect(0);
        root.call(9, &[M(restricted), V(out)]);
        root.expect(1);
        root.load(out);
        root.expect(42);
        root.call(8, &[M(alias)]);
        root.expect(1);
        root.call(8, &[M(restricted)]);
        root.expect(1);
        root.epilogue(1, 0);
        child.prologue();
        child.epilogue(42, 1);
        let result = run_control(
            arch,
            "thread-authority",
            &[
                "CreateThread",
                "OpenThread",
                "ResumeThread",
                "GetLastError",
                "WaitForSingleObject",
                "DuplicateHandle",
                "GetHandleInformation",
                "SetHandleInformation",
                "CloseHandle",
                "GetExitCodeThread",
            ],
            root,
            child,
            Code::new(arch, 0x1f00),
            30000,
        );
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1));
    }
}

#[test]
fn m4_thread_contexts_edit_owned_suspended_cpus_with_checked_atomic_buffers() {
    for arch in [Architecture::X86, Architecture::X64] {
        let mut root = Code::new(arch, 0x1000);
        let mut child = Code::new(arch, 0x1800);
        let base = root.base();
        let h = base + 0x3f00;
        let flag = h + 8;
        let ctx = base + 0x3500;
        let (flags, accumulator, pc) = if arch == Architecture::X64 {
            (48, 120, 248)
        } else {
            (0, 176, 184)
        };
        let machine = if arch == Architecture::X64 {
            0x100000u32
        } else {
            0x10000
        };
        root.prologue();
        root.call(0, &[V(0), V(0), V(base + 0x1800), V(0), V(4), V(0)]);
        root.store(h);
        root.call(1, &[M(h), V(0)]);
        root.expect(0);
        root.call(2, &[]);
        root.expect(998);
        root.bytes.push(0xb8);
        root.bytes.extend(
            (machine
                | if arch == Architecture::X64 {
                    0x1f
                } else {
                    0x3f
                })
            .to_le_bytes(),
        );
        root.store(ctx + flags);
        root.call(1, &[M(h), V(ctx)]);
        root.expect(1);
        root.load(ctx + pc);
        root.expect((base + 0x1800) as u32);
        root.bytes.push(0xb8);
        root.bytes.extend(77u32.to_le_bytes());
        root.store(ctx + accumulator);
        // Invalid PC must reject the entire proposed update, including RAX/EAX.
        root.bytes.extend([0x31, 0xc0]);
        root.store(ctx + pc);
        root.call(3, &[M(h), V(ctx)]);
        root.expect(0);
        root.call(2, &[]);
        root.expect(998);
        root.call(1, &[M(h), V(ctx)]);
        root.expect(1);
        root.bytes.push(0xb8);
        root.bytes.extend(77u32.to_le_bytes());
        root.store(ctx + accumulator);
        let xmm = ctx + if arch == Architecture::X64 { 416 } else { 364 };
        root.bytes.push(0xb8);
        root.bytes.extend(102u32.to_le_bytes());
        root.store(xmm);
        root.call(3, &[M(h), V(ctx)]);
        root.expect(1);
        let mxcsr = ctx + if arch == Architecture::X64 { 52 } else { 228 };
        root.bytes.push(0xb8);
        root.bytes.extend(0x10000u32.to_le_bytes());
        root.store(mxcsr);
        root.call(3, &[M(h), V(ctx)]);
        root.expect(0);
        root.call(2, &[]);
        root.expect(87);
        root.call(1, &[M(h), V(ctx)]);
        root.expect(1);
        root.load(ctx + accumulator);
        root.expect(77);
        root.call(4, &[M(h)]);
        root.expect(1);
        root.call(5, &[M(h), V(u32::MAX as u64)]);
        root.expect(0);
        root.load(flag);
        root.expect(77);
        root.load(flag + 8);
        root.expect(102);
        root.call(1, &[M(h), V(ctx)]);
        root.expect(0);
        root.call(2, &[]);
        root.expect(87);
        root.epilogue(1, 0);
        child.store(flag);
        child.bytes.extend([0x66, 0x0f, 0x7e, 0xc0]);
        child.store(flag + 8);
        child.prologue();
        child.epilogue(42, 1);
        let result = run_control(
            arch,
            "thread-context",
            &[
                "CreateThread",
                "GetThreadContext",
                "GetLastError",
                "SetThreadContext",
                "ResumeThread",
                "WaitForSingleObject",
            ],
            root,
            child,
            Code::new(arch, 0x1f00),
            30000,
        );
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1), "{arch:?}: {result:#?}");
    }
}

#[test]
fn m4_root_thread_exit_keeps_other_threads_alive_and_retires_root_fls() {
    for arch in [Architecture::X86, Architecture::X64] {
        for forced in [false, true] {
            let mut root = Code::new(arch, 0x1000);
            let mut child = Code::new(arch, 0x1800);
            let mut callback = Code::new(arch, 0x1f00);
            let base = root.base();
            let slot = base + 0x3f00;
            let flag = slot + 8;
            let pseudo = if arch == Architecture::X64 {
                u64::MAX - 1
            } else {
                u32::MAX as u64 - 1
            };
            root.prologue();
            root.call(0, &[V(base + 0x1f00)]);
            root.store(slot);
            root.call(1, &[M(slot), V(99)]);
            root.expect(1);
            root.call(2, &[V(0), V(0), V(base + 0x1800), V(0), V(0), V(0)]);
            if forced {
                root.call(3, &[V(pseudo), V(7)]);
            } else {
                root.call(4, &[V(7)]);
            }
            root.bytes.push(0xcc);
            child.prologue();
            child.call(5, &[V(10)]);
            child.load(flag);
            child.expect(if forced { 0 } else { 77 });
            child.epilogue(42, 1);
            callback.bytes.push(0xb8);
            callback.bytes.extend(77u32.to_le_bytes());
            callback.store(flag);
            callback.prologue();
            callback.epilogue(0, 1);
            let result = run_control(
                arch,
                if forced {
                    "root-forced-exit"
                } else {
                    "root-thread-exit"
                },
                &[
                    "FlsAlloc",
                    "FlsSetValue",
                    "CreateThread",
                    "TerminateThread",
                    "ExitThread",
                    "Sleep",
                ],
                root,
                child,
                callback,
                30000,
            );
            assert_eq!(result.error, None, "{arch:?}/{forced}: {result:#?}");
            assert_eq!(result.guest_entry_return, None);
            assert_eq!(result.process_exit_code, Some(42));
            assert_eq!(
                result.user_threads.as_ref().unwrap().threads[0].exit_code,
                Some(42)
            );
        }
    }
}

#[test]
fn m4_root_handles_support_owned_queries_suspension_and_foreign_termination() {
    for arch in [Architecture::X86, Architecture::X64] {
        for terminate in [false, true] {
            let mut root = Code::new(arch, 0x1000);
            let mut child = Code::new(arch, 0x1800);
            let base = root.base();
            let hroot = base + 0x3f00;
            let hchild = hroot + 8;
            let exit = hroot + 16;
            let ctx = base + 0x3500;
            let process = if arch == Architecture::X64 {
                u64::MAX
            } else {
                u32::MAX as u64
            };
            root.prologue();
            root.call(
                0,
                &[
                    V(process),
                    V(process - 1),
                    V(process),
                    V(hroot),
                    V(0),
                    V(0),
                    V(2),
                ],
            );
            root.expect(1);
            root.call(1, &[V(0), V(0), V(base + 0x1800), V(0), V(0), V(0)]);
            root.store(hchild);
            if terminate {
                root.bytes.push(0xcc);
            } else {
                root.call(2, &[M(hchild), V(u32::MAX as u64)]);
                root.expect(0);
                root.call(3, &[M(hroot), V(exit)]);
                root.expect(1);
                root.load(exit);
                root.expect(259);
                root.call(4, &[M(hroot)]);
                root.expect(1);
                root.epilogue(1, 0);
            }
            child.prologue();
            child.call(5, &[V(0x1fffff), V(0), V(1)]);
            child.store(hroot + 24);
            child.call(6, &[M(hroot + 24)]);
            child.expect(1);
            if terminate {
                child.call(7, &[M(hroot + 24), V(7)]);
                child.expect(1);
                child.call(2, &[M(hroot), V(0)]);
                child.expect(0);
            } else {
                child.call(8, &[M(hroot + 24)]);
                child.expect(0);
                child.bytes.push(0xb8);
                child.bytes.extend(
                    (if arch == Architecture::X64 {
                        0x100003u32
                    } else {
                        0x10003
                    })
                    .to_le_bytes(),
                );
                child.store(ctx + if arch == Architecture::X64 { 48 } else { 0 });
                child.call(9, &[M(hroot + 24), V(ctx)]);
                child.expect(1);
                child.call(10, &[M(hroot + 24)]);
                child.expect(1);
                child.call(4, &[M(hroot + 24)]);
                child.expect(1);
                child.call(11, &[V(0)]);
            }
            child.epilogue(42, 1);
            let result = run_control(
                arch,
                if terminate {
                    "root-foreign-terminate"
                } else {
                    "root-handle"
                },
                &[
                    "DuplicateHandle",
                    "CreateThread",
                    "WaitForSingleObject",
                    "GetExitCodeThread",
                    "CloseHandle",
                    "OpenThread",
                    "GetThreadId",
                    "TerminateThread",
                    "SuspendThread",
                    "GetThreadContext",
                    "ResumeThread",
                    "Sleep",
                ],
                root,
                child,
                Code::new(arch, 0x1f00),
                30000,
            );
            assert_eq!(result.error, None, "{arch:?}/{terminate}: {result:#?}");
            if terminate {
                assert_eq!(result.process_exit_code, Some(42), "{result:#?}");
                assert_eq!(result.guest_entry_return, None);
            } else {
                assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
            }
        }
    }
}

#[test]
fn m4_thread_duplicates_and_dispatcher_handles_have_disjoint_namespaces() {
    for arch in [Architecture::X86, Architecture::X64] {
        let mut root = Code::new(arch, 0x1000);
        let mut child = Code::new(arch, 0x1800);
        let base = root.base();
        let event = base + 0x3f00;
        let thread = event + 8;
        let alias = event + 16;
        let sa = base + 0x3d00;
        let info = event + 24;
        let process = if arch == Architecture::X64 {
            u64::MAX
        } else {
            u32::MAX as u64
        };
        root.prologue();
        root.bytes.push(0xb8);
        root.bytes
            .extend((if arch == Architecture::X64 { 24u32 } else { 12 }).to_le_bytes());
        root.store(sa);
        root.bytes.push(0xb8);
        root.bytes.extend(1u32.to_le_bytes());
        root.store(sa + if arch == Architecture::X64 { 16 } else { 8 });
        root.call(0, &[V(sa), V(0), V(0), V(0)]);
        root.store(event);
        root.call(1, &[M(event), V(info)]);
        root.expect(1);
        root.load(info);
        root.expect(1);
        root.call(2, &[V(sa), V(0), V(base + 0x1800), V(0), V(0x10004), V(0)]);
        root.store(thread);
        root.call(1, &[M(thread), V(info)]);
        root.expect(1);
        root.load(info);
        root.expect(1);
        for _ in 0..3 {
            root.call(
                3,
                &[
                    V(process),
                    M(thread),
                    V(process),
                    V(alias),
                    V(0),
                    V(0),
                    V(2),
                ],
            );
            root.expect(1);
            root.call(4, &[M(alias)]);
            root.expect(2);
            root.call(5, &[M(alias)]);
            root.expect(1);
        }
        root.call(6, &[M(event)]);
        root.expect(1);
        root.call(7, &[M(event), V(0)]);
        root.expect(0);
        root.call(8, &[M(thread)]);
        root.expect(1);
        root.call(7, &[M(thread), V(u32::MAX as u64)]);
        root.expect(0);
        root.epilogue(1, 0);
        child.prologue();
        child.epilogue(42, 1);
        let result = run_control(
            arch,
            "handle-namespaces",
            &[
                "CreateEventW",
                "GetHandleInformation",
                "CreateThread",
                "DuplicateHandle",
                "GetThreadId",
                "CloseHandle",
                "SetEvent",
                "WaitForSingleObject",
                "ResumeThread",
            ],
            root,
            child,
            Code::new(arch, 0x1f00),
            30000,
        );
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
    }
}

#[test]
fn m4_dispatcher_handle_rights_duplicates_and_protection_are_enforced() {
    for arch in [Architecture::X86, Architecture::X64] {
        let mut root = Code::new(arch, 0x1000);
        let base = root.base();
        let event = base + 0x3f00;
        let alias = event + 8;
        let info = event + 16;
        let opened = event + 24;
        let name = base + 0x3d00;
        let array = base + 0x3e00;
        let process = if arch == Architecture::X64 {
            u64::MAX
        } else {
            u32::MAX as u64
        };
        root.prologue();
        root.bytes.push(0xb8);
        root.bytes.extend(0x78u32.to_le_bytes());
        root.store(name);
        root.call(0, &[V(0), V(0), V(1), V(name)]);
        root.store(event);
        root.call(
            1,
            &[
                V(process),
                M(event),
                V(process),
                V(alias),
                V(0x100000),
                V(1),
                V(0),
            ],
        );
        root.expect(1);
        root.call(2, &[M(alias)]);
        root.expect(0);
        root.call(3, &[]);
        root.expect(5);
        root.load(event);
        root.store(array);
        root.load(alias);
        root.store(array + arch.width() as u64);
        root.call(4, &[V(2), V(array), V(1), V(0)]);
        root.expect(u32::MAX);
        root.call(3, &[]);
        root.expect(87);
        root.call(5, &[M(alias), V(0)]);
        root.expect(0);
        root.call(5, &[M(event), V(0)]);
        root.expect(0x102);
        root.call(6, &[M(event), V(2), V(2)]);
        root.expect(1);
        root.call(7, &[M(event)]);
        root.expect(0);
        root.call(3, &[]);
        root.expect(5);
        root.call(8, &[M(alias), V(info)]);
        root.expect(1);
        root.load(info);
        root.expect(1);
        root.call(9, &[V(2), V(0), V(name)]);
        root.store(opened);
        root.call(2, &[M(opened)]);
        root.expect(1);
        root.call(5, &[M(opened), V(0)]);
        root.expect(u32::MAX);
        root.call(3, &[]);
        root.expect(5);
        root.call(6, &[M(event), V(2), V(0)]);
        root.expect(1);
        for handle in [event, alias, opened] {
            root.call(7, &[M(handle)]);
            root.expect(1);
        }
        root.epilogue(1, 0);
        let result = run_control(
            arch,
            "dispatcher-authority",
            &[
                "CreateEventW",
                "DuplicateHandle",
                "SetEvent",
                "GetLastError",
                "WaitForMultipleObjects",
                "WaitForSingleObject",
                "SetHandleInformation",
                "CloseHandle",
                "GetHandleInformation",
                "OpenEventW",
            ],
            root,
            Code::new(arch, 0x1800),
            Code::new(arch, 0x1f00),
            30000,
        );
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
    }
}

#[test]
fn m4_fls_callbacks_can_block_resume_and_report_deadlock_without_host_frames() {
    for arch in [Architecture::X86, Architecture::X64] {
        for deadlock in [false, true] {
            let mut root = Code::new(arch, 0x1000);
            let mut child = Code::new(arch, 0x1800);
            let mut callback = Code::new(arch, 0x1f00);
            let base = root.base();
            let slot = base + 0x3f00;
            let thread = slot + 8;
            let event = slot + 16;
            let flag = slot + 24;
            let done = slot + 32;
            root.prologue();
            root.call(0, &[V(0), V(0), V(0), V(0)]);
            root.store(event);
            root.call(1, &[V(base + 0x1f00)]);
            root.store(slot);
            root.call(2, &[M(slot), V(99)]);
            root.expect(1);
            root.call(3, &[V(0), V(0), V(base + 0x1800), V(0), V(0), V(0)]);
            root.store(thread);
            root.call(4, &[M(slot)]);
            root.expect(1);
            root.load(flag);
            root.expect(42);
            root.load(done);
            root.expect(7);
            root.epilogue(1, 0);
            child.prologue();
            child.call(5, &[M(event), V(u32::MAX as u64)]);
            child.expect(0);
            child.bytes.push(0xb8);
            child.bytes.extend(42u32.to_le_bytes());
            child.store(flag);
            child.epilogue(42, 1);
            callback.prologue();
            if !deadlock {
                callback.call(6, &[M(event)]);
                callback.expect(1);
            }
            callback.call(5, &[M(thread), V(u32::MAX as u64)]);
            callback.expect(0);
            callback.load(flag);
            callback.expect(42);
            callback.bytes.push(0xb8);
            callback.bytes.extend(7u32.to_le_bytes());
            callback.store(done);
            callback.epilogue(0, 1);
            let result = run_control(
                arch,
                if deadlock {
                    "fls-callback-deadlock"
                } else {
                    "fls-callback-wait"
                },
                &[
                    "CreateEventW",
                    "FlsAlloc",
                    "FlsSetValue",
                    "CreateThread",
                    "FlsFree",
                    "WaitForSingleObject",
                    "SetEvent",
                ],
                root,
                child,
                callback,
                30000,
            );
            if deadlock {
                assert!(
                    result
                        .error
                        .as_deref()
                        .is_some_and(|e| e.contains("deadlock")),
                    "{arch:?}: {result:#?}"
                );
            } else {
                assert_eq!(result.error, None, "{arch:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
                assert_eq!(result.maximum_continuation_depth, 1);
            }
        }
    }
}

#[test]
fn m4_retiring_fls_callbacks_block_without_signaling_the_thread_early() {
    for arch in [Architecture::X86, Architecture::X64] {
        for deadlock in [false, true] {
            let mut root = Code::new(arch, 0x1000);
            let mut child = Code::new(arch, 0x1800);
            let mut callback = Code::new(arch, 0x1f00);
            let base = root.base();
            let slot = base + 0x3f00;
            let thread = slot + 8;
            let event = slot + 16;
            let entered = slot + 24;
            let done = slot + 32;
            root.prologue();
            root.call(0, &[V(0), V(0), V(0), V(0)]);
            root.store(event);
            root.call(1, &[V(base + 0x1f00)]);
            root.store(slot);
            root.call(3, &[V(0), V(0), V(base + 0x1800), V(0), V(0), V(0)]);
            root.store(thread);
            // Yield until the worker is in its destructor, then verify its handle
            // is still unsignaled while the destructor waits on our event.
            root.call(7, &[V(1)]);
            root.load(entered);
            root.expect(1);
            root.call(5, &[M(thread), V(0)]);
            root.expect(258);
            if !deadlock {
                root.call(6, &[M(event)]);
                root.expect(1);
            }
            root.call(5, &[M(thread), V(u32::MAX as u64)]);
            root.expect(0);
            root.load(done);
            root.expect(7);
            root.epilogue(1, 0);
            child.prologue();
            child.call(2, &[M(slot), V(99)]);
            child.expect(1);
            child.epilogue(42, 1);
            callback.prologue();
            callback.bytes.push(0xb8);
            callback.bytes.extend(1u32.to_le_bytes());
            callback.store(entered);
            callback.call(5, &[M(event), V(u32::MAX as u64)]);
            callback.expect(0);
            callback.bytes.push(0xb8);
            callback.bytes.extend(7u32.to_le_bytes());
            callback.store(done);
            callback.epilogue(0, 1);
            let result = run_control(
                arch,
                if deadlock {
                    "fls-retirement-deadlock"
                } else {
                    "fls-retirement-wait"
                },
                &[
                    "CreateEventW",
                    "FlsAlloc",
                    "FlsSetValue",
                    "CreateThread",
                    "FlsFree",
                    "WaitForSingleObject",
                    "SetEvent",
                    "Sleep",
                ],
                root,
                child,
                callback,
                30000,
            );
            if deadlock {
                assert!(
                    result
                        .error
                        .as_deref()
                        .is_some_and(|e| e.contains("deadlock")),
                    "{arch:?}: {result:#?}"
                );
            } else {
                assert_eq!(result.error, None, "{arch:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
                assert_eq!(result.maximum_continuation_depth, 1);
            }
        }
    }
}

#[test]
fn m4_apc_callbacks_can_wait_and_preserve_the_outer_alertable_continuation() {
    for arch in [Architecture::X86, Architecture::X64] {
        for deadlock in [false, true] {
            let mut root = Code::new(arch, 0x1000);
            let mut child = Code::new(arch, 0x1800);
            let mut callback = Code::new(arch, 0x1f00);
            let base = root.base();
            let thread = base + 0x3f00;
            let event = thread + 8;
            let done = thread + 16;
            root.prologue();
            root.call(0, &[V(0), V(0), V(0), V(0)]);
            root.store(event);
            root.call(1, &[V(0), V(0), V(base + 0x1800), V(0), V(0), V(0)]);
            root.store(thread);
            root.call(
                2,
                &[
                    V(base + 0x1f00),
                    V(if arch == Architecture::X64 {
                        u64::MAX - 1
                    } else {
                        u32::MAX as u64 - 1
                    }),
                    V(99),
                ],
            );
            root.expect(1);
            root.call(3, &[V(u32::MAX as u64), V(1)]);
            root.expect(0xc0);
            root.load(done);
            root.expect(7);
            root.call(3, &[V(0), V(1)]);
            root.expect(0);
            root.epilogue(1, 0);
            child.prologue();
            child.call(4, &[M(event), V(u32::MAX as u64)]);
            child.expect(0);
            child.epilogue(42, 1);
            callback.prologue();
            if !deadlock {
                callback.call(5, &[M(event)]);
                callback.expect(1);
            }
            callback.call(4, &[M(thread), V(u32::MAX as u64)]);
            callback.expect(0);
            callback.bytes.push(0xb8);
            callback.bytes.extend(7u32.to_le_bytes());
            callback.store(done);
            callback.epilogue(0, 1);
            let result = run_control(
                arch,
                if deadlock {
                    "apc-callback-deadlock"
                } else {
                    "apc-callback-wait"
                },
                &[
                    "CreateEventW",
                    "CreateThread",
                    "QueueUserAPC",
                    "SleepEx",
                    "WaitForSingleObject",
                    "SetEvent",
                ],
                root,
                child,
                callback,
                30000,
            );
            if deadlock {
                assert!(
                    result
                        .error
                        .as_deref()
                        .is_some_and(|e| e.contains("deadlock")),
                    "{arch:?}: {result:#?}"
                );
            } else {
                assert_eq!(result.error, None, "{arch:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
                assert_eq!(result.maximum_continuation_depth, 1);
                assert!(result.api_events.iter().all(|e| !e.pending), "{result:#?}");
            }
        }
    }
}

#[test]
fn m4_root_retirement_callbacks_can_wait_for_other_threads() {
    for arch in [Architecture::X86, Architecture::X64] {
        for deadlock in [false, true] {
            let mut root = Code::new(arch, 0x1000);
            let mut child = Code::new(arch, 0x1800);
            let mut callback = Code::new(arch, 0x1f00);
            let base = root.base();
            let slot = base + 0x3f00;
            let thread = slot + 8;
            let event = slot + 16;
            let flag = slot + 24;
            let done = slot + 32;
            root.prologue();
            root.call(0, &[V(0), V(0), V(0), V(0)]);
            root.store(event);
            root.call(1, &[V(base + 0x1f00)]);
            root.store(slot);
            root.call(2, &[M(slot), V(99)]);
            root.expect(1);
            root.call(3, &[V(0), V(0), V(base + 0x1800), V(0), V(0), V(0)]);
            root.store(thread);
            root.call(4, &[V(7)]);
            root.bytes.push(0xcc);
            child.prologue();
            child.call(5, &[M(event), V(u32::MAX as u64)]);
            child.expect(0);
            child.bytes.push(0xb8);
            child.bytes.extend(42u32.to_le_bytes());
            child.store(flag);
            child.epilogue(42, 1);
            callback.prologue();
            if !deadlock {
                callback.call(6, &[M(event)]);
                callback.expect(1);
            }
            callback.call(5, &[M(thread), V(u32::MAX as u64)]);
            callback.expect(0);
            callback.load(flag);
            callback.expect(42);
            callback.bytes.push(0xb8);
            callback.bytes.extend(7u32.to_le_bytes());
            callback.store(done);
            callback.epilogue(0, 1);
            let result = run_control(
                arch,
                if deadlock {
                    "root-retirement-deadlock"
                } else {
                    "root-retirement-wait"
                },
                &[
                    "CreateEventW",
                    "FlsAlloc",
                    "FlsSetValue",
                    "CreateThread",
                    "ExitThread",
                    "WaitForSingleObject",
                    "SetEvent",
                ],
                root,
                child,
                callback,
                30000,
            );
            if deadlock {
                assert!(
                    result
                        .error
                        .as_deref()
                        .is_some_and(|e| e.contains("deadlock")),
                    "{arch:?}: {result:#?}"
                );
            } else {
                assert_eq!(result.error, None, "{arch:?}: {result:#?}");
                assert_eq!(result.process_exit_code, Some(7), "{result:#?}");
                assert_eq!(result.maximum_continuation_depth, 1);
            }
        }
    }
}

#[test]
fn m4_retirement_repopulates_fls_in_bounded_passes() {
    for arch in [Architecture::X86, Architecture::X64] {
        for endless in [false, true] {
            let mut root = Code::new(arch, 0x1000);
            let mut child = Code::new(arch, 0x1800);
            let mut callback = Code::new(arch, 0x1f00);
            let base = root.base();
            let slot = base + 0x3f00;
            let thread = slot + 8;
            let count = slot + 16;
            root.prologue();
            root.call(0, &[V(base + 0x1f00)]);
            root.store(slot);
            root.call(2, &[V(0), V(0), V(base + 0x1800), V(0), V(0), V(0)]);
            root.store(thread);
            root.call(3, &[M(thread), V(u32::MAX as u64)]);
            root.expect(0);
            root.load(count);
            root.expect(2);
            root.epilogue(1, 0);
            child.prologue();
            child.call(1, &[M(slot), V(99)]);
            child.expect(1);
            child.epilogue(42, 1);
            callback.prologue();
            callback.load(count);
            callback.bytes.extend([0x83, 0xc0, 1]);
            callback.store(count);
            let branch = if !endless {
                callback.bytes.extend([0x83, 0xf8, 2, 0x0f, 0x84]);
                let offset = callback.bytes.len();
                callback.bytes.extend([0; 4]);
                Some(offset)
            } else {
                None
            };
            callback.call(1, &[M(slot), V(99)]);
            callback.expect(1);
            if let Some(offset) = branch {
                let displacement = (callback.bytes.len() - offset - 4) as u32;
                callback.bytes[offset..offset + 4].copy_from_slice(&displacement.to_le_bytes());
            }
            callback.epilogue(0, 1);
            let result = run_control(
                arch,
                if endless {
                    "fls-retirement-pass-bound"
                } else {
                    "fls-retirement-repopulate"
                },
                &[
                    "FlsAlloc",
                    "FlsSetValue",
                    "CreateThread",
                    "WaitForSingleObject",
                ],
                root,
                child,
                callback,
                30000,
            );
            if endless {
                assert!(
                    result
                        .error
                        .as_deref()
                        .is_some_and(|e| e.contains("repopulated")),
                    "{arch:?}: {result:#?}"
                );
                assert!(result.instruction_count < 30000);
            } else {
                assert_eq!(result.error, None, "{arch:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
            }
            assert_eq!(result.maximum_continuation_depth, 1);
        }
    }
}

#[test]
fn m4_nested_alertable_apcs_preserve_each_api_return_frame() {
    for arch in [Architecture::X86, Architecture::X64] {
        let mut root = Code::new(arch, 0x1000);
        let mut callback = Code::new(arch, 0x1f00);
        let base = root.base();
        let count = base + 0x3f00;
        let pseudo = if arch == Architecture::X64 {
            u64::MAX - 1
        } else {
            u32::MAX as u64 - 1
        };
        root.prologue();
        root.call(0, &[V(base + 0x1f00), V(pseudo), V(99)]);
        root.expect(1);
        root.call(1, &[V(u32::MAX as u64), V(1)]);
        root.expect(0xc0);
        root.load(count);
        root.expect(2);
        root.call(1, &[V(0), V(1)]);
        root.expect(0);
        root.epilogue(1, 0);
        callback.prologue();
        callback.load(count);
        callback.bytes.extend([0x83, 0xc0, 1]);
        callback.store(count);
        callback.bytes.extend([0x83, 0xf8, 2, 0x0f, 0x84]);
        let offset = callback.bytes.len();
        callback.bytes.extend([0; 4]);
        callback.call(0, &[V(base + 0x1f00), V(pseudo), V(99)]);
        callback.expect(1);
        callback.call(1, &[V(0), V(1)]);
        callback.expect(0xc0);
        let displacement = (callback.bytes.len() - offset - 4) as u32;
        callback.bytes[offset..offset + 4].copy_from_slice(&displacement.to_le_bytes());
        callback.epilogue(0, 1);
        let result = run_control(
            arch,
            "nested-alertable-apcs",
            &["QueueUserAPC", "SleepEx"],
            root,
            Code::new(arch, 0x1800),
            callback,
            30000,
        );
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
        assert_eq!(result.maximum_continuation_depth, 1);
        assert!(result.api_events.iter().all(|e| !e.pending), "{result:#?}");
    }
}

#[test]
fn m4_amd64_exception_handlers_inside_fls_callbacks_keep_distinct_return_authority() {
    let arch = Architecture::X64;
    for nested in [false, true] {
        let mut root = Code::new(arch, 0x1000);
        let mut callback = Code::new(arch, 0x1f00);
        let base = root.base();
        let slot = base + 0x3f00;
        root.prologue();
        root.call(0, &[V(base + 0x1f00)]);
        root.store(slot);
        root.call(1, &[M(slot), V(99)]);
        root.expect(1);
        root.call(2, &[M(slot)]);
        root.expect(1);
        root.epilogue(1, 0);
        callback.prologue();
        callback.bytes.push(0xcc);
        callback.epilogue(0, 1);
        let callback = callback.finish();
        let handler = if nested {
            vec![0xcc, 0xc3]
        } else {
            // ContinueExecution after advancing the captured RIP over INT3.
            vec![0x49, 0xff, 0x80, 0xf8, 0, 0, 0, 0x31, 0xc0, 0xc3]
        };
        let mut bytes = fixtures::m4_custom_probe(
            arch,
            &["FlsAlloc", "FlsSetValue", "FlsFree"],
            &root.finish(),
            &handler,
            &callback,
        );
        for (offset, value) in [
            (0x98 + 112 + 24, 0x3c00),
            (0x98 + 112 + 28, 12),
            (0x2e00, 0x1f00),
            (0x2e04, 0x1f00 + callback.len() as u32),
            (0x2e08, 0x3c40),
            (0x2e48, 0x1800),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes[0x2e40..0x2e48].copy_from_slice(&[9, 4, 1, 0, 4, 0x82, 0, 0]);
        let result = run_image_control(
            arch,
            if nested {
                "fls-nested-exception"
            } else {
                "fls-exception-continuation"
            },
            bytes,
            30000,
        );
        if nested {
            assert!(
                result
                    .error
                    .as_deref()
                    .is_some_and(|e| e.contains("Nested")),
                "{result:#?}"
            );
            assert_eq!(result.guest_entry_return, None);
        } else {
            assert_eq!(result.error, None, "{result:#?}");
            assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
            let exceptions = result.native_exceptions.as_ref().unwrap();
            assert_eq!(exceptions.exceptions_raised, 1);
            assert_eq!(exceptions.events.len(), 1);
            assert_eq!(exceptions.events[0].disposition, Some(0));
            assert!(result.api_events.iter().all(|e| !e.pending), "{result:#?}");
        }
    }
}

#[test]
fn m4_user_vectored_handlers_continue_breakpoints_illegal_instructions_and_access_faults() {
    for arch in [Architecture::X86, Architecture::X64] {
        for fault in 0..5 {
            let mut root = Code::new(arch, 0x1000);
            let mut handler = Code::new(arch, 0x1800);
            let base = root.base();
            let token = base + 0x3f00;
            root.prologue();
            root.call(0, &[V(1), V(base + 0x1800)]);
            root.store(token);
            let length = match fault {
                0 | 3 => {
                    root.bytes.push(0xcc);
                    1
                }
                1 => {
                    root.bytes.extend([0x0f, 0x0b]);
                    2
                }
                4 => {
                    root.bytes
                        .extend([0xb8, 1, 0, 0, 0, 0x31, 0xd2, 0x31, 0xc9, 0xf7, 0xf1]);
                    2
                }
                _ if arch == Architecture::X64 => {
                    root.bytes.extend([0x48, 0xa1]);
                    root.bytes.extend(0x12345000u64.to_le_bytes());
                    10
                }
                _ => {
                    root.bytes.push(0xa1);
                    root.bytes.extend(0x12345000u32.to_le_bytes());
                    5
                }
            };
            root.expect(42);
            root.call(1, &[M(token)]);
            root.expect(1);
            root.call(1, &[M(token)]);
            root.expect(0);
            root.epilogue(1, 0);
            if arch == Architecture::X64 {
                handler
                    .bytes
                    .extend([0x48, 0x8b, 0x41, 8, 0x48, 0x83, 0x80]);
                handler.bytes.extend(248u32.to_le_bytes());
                handler.bytes.push(length);
                handler.bytes.extend([0x48, 0xc7, 0x40, 120, 42, 0, 0, 0]);
                if fault == 3 {
                    handler.bytes.extend([0x81, 0x48, 68]);
                    handler.bytes.extend(0x20000u32.to_le_bytes());
                }
                handler.bytes.extend([0xb8, 0xff, 0xff, 0xff, 0xff, 0xc3]);
            } else {
                handler
                    .bytes
                    .extend([0x8b, 0x44, 0x24, 4, 0x8b, 0x40, 4, 0x83, 0x80]);
                handler.bytes.extend(184u32.to_le_bytes());
                handler.bytes.push(length);
                handler.bytes.extend([0xc7, 0x80]);
                handler.bytes.extend(176u32.to_le_bytes());
                handler.bytes.extend(42u32.to_le_bytes());
                if fault == 3 {
                    handler.bytes.extend([0x81, 0x88]);
                    handler.bytes.extend(192u32.to_le_bytes());
                    handler.bytes.extend(0x20000u32.to_le_bytes());
                }
                handler
                    .bytes
                    .extend([0xb8, 0xff, 0xff, 0xff, 0xff, 0xc2, 4, 0]);
            }
            let result = run_control(
                arch,
                &format!("veh-fault-{fault}"),
                &[
                    "AddVectoredExceptionHandler",
                    "RemoveVectoredExceptionHandler",
                ],
                root,
                handler,
                Code::new(arch, 0x1f00),
                30000,
            );
            if fault == 3 {
                assert!(
                    result
                        .error
                        .as_deref()
                        .is_some_and(|e| e.contains("protected flags")),
                    "{arch:?}: {result:#?}"
                );
                assert_eq!(result.guest_entry_return, None);
            } else {
                assert_eq!(result.error, None, "{arch:?}/{fault}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
                assert_eq!(result.maximum_continuation_depth, 1);
                assert_eq!(
                    result.native_exceptions.as_ref().unwrap().exceptions_raised,
                    1
                );
            }
        }
    }
}

#[test]
fn m4_x86_registration_handlers_resume_checked_contexts_and_refuse_bad_chains() {
    let arch = Architecture::X86;
    for mode in 0..3 {
        let mut root = Code::new(arch, 0x1000);
        let mut handler = Code::new(arch, 0x1800);
        let base = root.base();
        root.bytes.push(0x68);
        root.bytes.extend(((base + 0x1800) as u32).to_le_bytes());
        root.bytes.extend([0x64, 0xff, 0x35, 0, 0, 0, 0]);
        if mode == 1 {
            root.bytes.extend([0x89, 0x24, 0x24]);
        }
        if mode == 2 {
            root.bytes.extend([0xb8]);
            root.bytes.extend(0x12345000u32.to_le_bytes());
            root.bytes.extend([0x64, 0xa3, 0, 0, 0, 0]);
        } else {
            root.bytes.extend([0x64, 0x89, 0x25, 0, 0, 0, 0]);
        }
        root.bytes.push(0xcc);
        root.expect(42);
        root.bytes
            .extend([0x64, 0x8f, 5, 0, 0, 0, 0, 0x83, 0xc4, 4]);
        root.epilogue(1, 0);
        handler.bytes.extend([0x8b, 0x44, 0x24, 12, 0xff, 0x80]);
        handler.bytes.extend(184u32.to_le_bytes());
        handler.bytes.extend([0xc7, 0x80]);
        handler.bytes.extend(176u32.to_le_bytes());
        handler.bytes.extend(42u32.to_le_bytes());
        handler.bytes.extend([0x31, 0xc0, 0xc3]);
        let result = run_control(
            arch,
            &format!("x86-seh-chain-{mode}"),
            &[],
            root,
            handler,
            Code::new(arch, 0x1f00),
            30000,
        );
        if mode == 0 {
            assert_eq!(result.error, None, "{result:#?}");
            assert_eq!(result.guest_entry_return, Some(1));
            assert_eq!(result.maximum_continuation_depth, 1);
        } else {
            assert!(
                result
                    .error
                    .as_deref()
                    .is_some_and(|e| e.contains("registration")),
                "{result:#?}"
            );
            assert_eq!(result.guest_entry_return, None);
        }
    }
}

fn emit_vectored_resume(handler: &mut Code, arch: Architecture, increment: u8) {
    if arch == Architecture::X64 {
        // RAX owns EXCEPTION_POINTERS on entry to this fragment.
        handler
            .bytes
            .extend([0x48, 0x8b, 0x40, 8, 0x48, 0x83, 0x80]);
        handler.bytes.extend(248u32.to_le_bytes());
        handler.bytes.push(increment);
        handler.bytes.extend([0x48, 0xc7, 0x40, 120, 42, 0, 0, 0]);
    } else {
        handler.bytes.extend([0x8b, 0x40, 4, 0x83, 0x80]);
        handler.bytes.extend(184u32.to_le_bytes());
        handler.bytes.push(increment);
        handler.bytes.extend([0xc7, 0x80]);
        handler.bytes.extend(176u32.to_le_bytes());
        handler.bytes.extend(42u32.to_le_bytes());
    }
}
#[test]
fn m4_vectored_exception_callbacks_can_wait_for_other_guest_threads() {
    for arch in [Architecture::X86, Architecture::X64] {
        for deadlock in [false, true] {
            let mut root = Code::new(arch, 0x1000);
            let mut child = Code::new(arch, 0x1800);
            let mut handler = Code::new(arch, 0x1f00);
            let base = root.base();
            let event = base + 0x3f00;
            let thread = event + 8;
            let pointers = event + 16;
            root.prologue();
            root.call(0, &[V(0), V(0), V(0), V(0)]);
            root.store(event);
            root.call(1, &[V(0), V(0), V(base + 0x1800), V(0), V(0), V(0)]);
            root.store(thread);
            root.call(2, &[V(1), V(base + 0x1f00)]);
            root.bytes.push(0xcc);
            root.expect(42);
            root.epilogue(1, 0);
            child.prologue();
            child.call(3, &[M(event), V(u32::MAX as u64)]);
            child.expect(0);
            child.epilogue(7, 1);
            if arch == Architecture::X64 {
                handler.bytes.extend([0x48, 0x89, 0xc8]);
            } else {
                handler.bytes.extend([0x8b, 0x44, 0x24, 4]);
            }
            handler.store(pointers);
            handler.prologue();
            if !deadlock {
                handler.call(4, &[M(event)]);
                handler.expect(1);
            }
            handler.call(3, &[M(thread), V(u32::MAX as u64)]);
            handler.expect(0);
            handler.load(pointers);
            emit_vectored_resume(&mut handler, arch, 1);
            handler.epilogue(u32::MAX, 1);
            let result = run_control(
                arch,
                if deadlock {
                    "veh-wait-deadlock"
                } else {
                    "veh-wait"
                },
                &[
                    "CreateEventW",
                    "CreateThread",
                    "AddVectoredExceptionHandler",
                    "WaitForSingleObject",
                    "SetEvent",
                ],
                root,
                child,
                handler,
                30000,
            );
            if deadlock {
                assert!(
                    result
                        .error
                        .as_deref()
                        .is_some_and(|e| e.contains("deadlock")),
                    "{arch:?}: {result:#?}"
                );
            } else {
                assert_eq!(result.error, None, "{arch:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
                assert_eq!(result.maximum_continuation_depth, 1);
            }
        }
    }
}
#[test]
fn m4_nested_vectored_faults_have_independent_contexts_and_a_finite_depth() {
    for arch in [Architecture::X86, Architecture::X64] {
        for endless in [false, true] {
            let mut root = Code::new(arch, 0x1000);
            let mut handler = Code::new(arch, 0x1800);
            let base = root.base();
            let count = base + 0x3f00;
            root.prologue();
            root.call(0, &[V(1), V(base + 0x1800)]);
            root.bytes.push(0xcc);
            root.expect(42);
            root.load(count);
            root.expect(2);
            root.epilogue(1, 0);
            handler.prologue();
            if arch == Architecture::X64 {
                handler.bytes.extend([0x48, 0x89, 0x4c, 0x24, 32]);
            } else {
                handler.bytes.extend([0xff, 0x74, 0x24, 4]);
            }
            handler.load(count);
            handler.bytes.extend([0x83, 0xc0, 1]);
            handler.store(count);
            if !endless {
                handler.bytes.extend([0x83, 0xf8, 2, 0x74, 1]);
            }
            handler.bytes.push(0xcc);
            if arch == Architecture::X64 {
                handler.bytes.extend([0x48, 0x8b, 0x44, 0x24, 32]);
            } else {
                handler.bytes.push(0x58);
            }
            emit_vectored_resume(&mut handler, arch, 1);
            handler.epilogue(u32::MAX, 1);
            let result = run_control(
                arch,
                if endless {
                    "veh-nesting-bound"
                } else {
                    "veh-nested-context"
                },
                &["AddVectoredExceptionHandler"],
                root,
                handler,
                Code::new(arch, 0x1f00),
                30000,
            );
            if endless {
                assert!(
                    result
                        .error
                        .as_deref()
                        .is_some_and(|e| e.contains("nesting bound")),
                    "{arch:?}: {result:#?}"
                );
                assert!(result.instruction_count < 30000);
            } else {
                assert_eq!(result.error, None, "{arch:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
                assert_eq!(
                    result.native_exceptions.as_ref().unwrap().exceptions_raised,
                    2
                );
            }
            assert_eq!(result.maximum_continuation_depth, 1);
        }
    }
}
#[test]
fn m4_vectored_continue_and_unhandled_filter_callbacks_execute_in_their_owned_phases() {
    for arch in [Architecture::X86, Architecture::X64] {
        for filter in [false, true] {
            let mut root = Code::new(arch, 0x1000);
            let mut handler = Code::new(arch, 0x1800);
            let mut continuation = Code::new(arch, 0x1f00);
            let base = root.base();
            let count = base + 0x3f00;
            let token = count + 8;
            root.prologue();
            root.call(0, &[V(1), V(base + 0x1f00)]);
            root.store(token);
            if filter {
                root.call(1, &[V(base + 0x1800)]);
                root.expect(0);
            } else {
                root.call(1, &[V(1), V(base + 0x1800)]);
            }
            root.bytes.push(0xcc);
            root.expect(42);
            root.load(count);
            root.expect(1);
            root.call(2, &[M(token)]);
            root.expect(1);
            root.call(2, &[M(token)]);
            root.expect(0);
            root.epilogue(1, 0);
            if arch == Architecture::X64 {
                handler.bytes.extend([0x48, 0x89, 0xc8]);
            } else {
                handler.bytes.extend([0x8b, 0x44, 0x24, 4]);
            }
            emit_vectored_resume(&mut handler, arch, 1);
            handler.bytes.extend([0xb8, 0xff, 0xff, 0xff, 0xff]);
            handler.bytes.extend(if arch == Architecture::X64 {
                vec![0xc3]
            } else {
                vec![0xc2, 4, 0]
            });
            continuation.prologue();
            continuation.load(count);
            continuation.bytes.extend([0x83, 0xc0, 1]);
            continuation.store(count);
            continuation.epilogue(0, 1);
            let label = if filter {
                "unhandled-filter-continue"
            } else {
                "vectored-continue-phase"
            };
            let root = root.finish();
            let mut bytes = fixtures::m4_custom_probe(
                arch,
                &[
                    "AddVectoredContinueHandler",
                    if filter {
                        "SetUnhandledExceptionFilter"
                    } else {
                        "AddVectoredExceptionHandler"
                    },
                    "RemoveVectoredContinueHandler",
                ],
                &root,
                &handler.finish(),
                &continuation.finish(),
            );
            if arch == Architecture::X64 {
                for (offset, value) in [
                    (0x98 + 112 + 24, 0x3c00),
                    (0x98 + 112 + 28, 12),
                    (0x2e00, 0x1000),
                    (0x2e04, 0x1000 + root.len() as u32),
                    (0x2e08, 0x3c40),
                ] {
                    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
                }
                bytes[0x2e40..0x2e48].copy_from_slice(&[1, 4, 1, 0, 4, 0x82, 0, 0]);
            }
            let result = run_image_control(arch, label, bytes, 30000);
            assert_eq!(result.error, None, "{arch:?}/{filter}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
        }
    }
}

#[test]
fn m4_software_exceptions_preserve_parameters_and_do_not_resume_noncontinuable_faults() {
    for arch in [Architecture::X86, Architecture::X64] {
        for noncontinuable in [false, true] {
            let mut root = Code::new(arch, 0x1000);
            let mut handler = Code::new(arch, 0x1800);
            let base = root.base();
            let arguments = base + 0x3f00;
            let values = [0x1122334455667788u64, 22, 33];
            root.prologue();
            for (index, value) in values.into_iter().enumerate() {
                if arch == Architecture::X64 {
                    root.bytes.extend([0x48, 0xb8]);
                    root.bytes.extend(value.to_le_bytes());
                } else {
                    root.bytes.push(0xb8);
                    root.bytes.extend((value as u32).to_le_bytes());
                }
                root.store(arguments + (index * arch.width()) as u64);
            }
            root.call(0, &[V(1), V(base + 0x1800)]);
            root.call(
                1,
                &[
                    V(0xe1234567),
                    V(u64::from(noncontinuable)),
                    V(3),
                    V(arguments),
                ],
            );
            root.expect(42);
            root.epilogue(1, 0);
            if arch == Architecture::X64 {
                handler
                    .bytes
                    .extend([0x4c, 0x8b, 0x41, 8, 0x48, 0x8b, 0x11, 0x8b, 2]);
                handler.expect(0xe1234567);
                handler.bytes.extend([0x8b, 0x42, 24]);
                handler.expect(3);
                for (index, value) in values.into_iter().enumerate() {
                    handler.bytes.extend([0x8b, 0x42, (32 + index * 8) as u8]);
                    handler.expect(value as u32);
                    handler.bytes.extend([0x8b, 0x42, (36 + index * 8) as u8]);
                    handler.expect((value >> 32) as u32);
                }
                handler.bytes.extend([0x49, 0xc7, 0x40, 120, 42, 0, 0, 0]);
            } else {
                handler
                    .bytes
                    .extend([0x8b, 0x54, 0x24, 4, 0x8b, 0x4a, 4, 0x8b, 0x12, 0x8b, 2]);
                handler.expect(0xe1234567);
                handler.bytes.extend([0x8b, 0x42, 16]);
                handler.expect(3);
                for (index, value) in values.into_iter().enumerate() {
                    handler.bytes.extend([0x8b, 0x42, (20 + index * 4) as u8]);
                    handler.expect(value as u32);
                }
                handler.bytes.extend([0xc7, 0x81]);
                handler.bytes.extend(176u32.to_le_bytes());
                handler.bytes.extend(42u32.to_le_bytes());
            }
            handler.bytes.extend([0xb8, 0xff, 0xff, 0xff, 0xff]);
            handler.bytes.extend(if arch == Architecture::X64 {
                vec![0xc3]
            } else {
                vec![0xc2, 4, 0]
            });
            let result = run_control(
                arch,
                if noncontinuable {
                    "raise-noncontinuable"
                } else {
                    "raise-continue"
                },
                &["AddVectoredExceptionHandler", "RaiseException"],
                root,
                handler,
                Code::new(arch, 0x1f00),
                30000,
            );
            if noncontinuable {
                assert!(
                    result
                        .error
                        .as_deref()
                        .is_some_and(|e| e.contains("Noncontinuable")),
                    "{result:#?}"
                );
                assert_eq!(result.guest_entry_return, None);
            } else {
                assert_eq!(result.error, None, "{arch:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
                assert!(result.api_events.iter().all(|e| !e.pending), "{result:#?}");
            }
        }
    }
}

#[test]
fn m4_amd64_registered_runtime_tables_drive_actual_exception_dispatch_and_delete() {
    let arch = Architecture::X64;
    for mode in 0..3 {
        let mut root = Code::new(arch, 0x1000);
        let mut handler = Code::new(arch, 0x1800);
        let base = root.base();
        let table = base + 0x3c00;
        let output = base + 0x3f00;
        root.prologue();
        root.call(0, &[V(table), V(1), V(base)]);
        root.expect(if mode == 2 { 0 } else { 1 });
        if mode != 2 {
            root.call(0, &[V(table), V(1), V(base)]);
            root.expect(0);
            root.call(1, &[V(base + 0x1000), V(output), V(0)]);
            root.expect(table as u32);
            if mode == 1 {
                root.bytes.push(0xb8);
                root.bytes.extend(0x1001u32.to_le_bytes());
                root.store(table);
            }
            root.bytes.push(0xcc);
            root.expect(42);
            root.call(2, &[V(table)]);
            root.expect(1);
            root.call(2, &[V(table)]);
            root.expect(0);
            root.call(1, &[V(base + 0x1000), V(output), V(0)]);
            root.expect(0);
        }
        root.epilogue(1, 0);
        handler.bytes.extend([
            0x49, 0xff, 0x80, 0xf8, 0, 0, 0, 0x49, 0xc7, 0x40, 120, 42, 0, 0, 0, 0x31, 0xc0, 0xc3,
        ]);
        let root = root.finish();
        let mut bytes = fixtures::m4_custom_probe(
            arch,
            &[
                "RtlAddFunctionTable",
                "RtlLookupFunctionEntry",
                "RtlDeleteFunctionTable",
            ],
            &root,
            &handler.finish(),
            &[],
        );
        for (offset, value) in [
            (0x2e00, 0x1000),
            (
                0x2e04,
                if mode == 2 {
                    0x1000
                } else {
                    0x1000 + root.len() as u32
                },
            ),
            (0x2e08, 0x3c40),
            (0x2e48, 0x1800),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes[0x2e40..0x2e48].copy_from_slice(&[9, 4, 1, 0, 4, 0x82, 0, 0]);
        let result = run_image_control(
            arch,
            &format!("runtime-function-table-{mode}"),
            bytes,
            30000,
        );
        if mode == 1 {
            assert!(
                result
                    .error
                    .as_deref()
                    .is_some_and(|e| e.contains("table changed")),
                "{result:#?}"
            );
            assert_eq!(result.guest_entry_return, None);
        } else {
            assert_eq!(result.error, None, "{result:#?}");
            assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
        }
    }
}

#[test]
fn m4_registered_amd64_unwind_handlers_use_the_workers_actual_owned_stack() {
    let arch = Architecture::X64;
    let mut root = Code::new(arch, 0x1000);
    let mut child = Code::new(arch, 0x1800);
    let base = root.base();
    let thread = base + 0x3f00;
    root.prologue();
    root.call(0, &[V(base + 0x3c00), V(1), V(base)]);
    root.expect(1);
    root.call(1, &[V(0), V(0), V(base + 0x1800), V(0), V(0), V(0)]);
    root.store(thread);
    root.call(2, &[M(thread), V(u32::MAX as u64)]);
    root.expect(0);
    root.epilogue(1, 0);
    child.prologue();
    child.bytes.push(0xcc);
    child.expect(42);
    child.epilogue(7, 1);
    let child = child.finish();
    let handler = [
        0x49, 0xff, 0x80, 0xf8, 0, 0, 0, 0x49, 0xc7, 0x40, 120, 42, 0, 0, 0, 0x31, 0xc0, 0xc3,
    ];
    let mut bytes = fixtures::m4_custom_probe(
        arch,
        &["RtlAddFunctionTable", "CreateThread", "WaitForSingleObject"],
        &root.finish(),
        &child,
        &handler,
    );
    for (offset, value) in [
        (0x2e00, 0x1800),
        (0x2e04, 0x1800 + child.len() as u32),
        (0x2e08, 0x3c40),
        (0x2e48, 0x1f00),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[0x2e40..0x2e48].copy_from_slice(&[9, 4, 1, 0, 4, 0x82, 0, 0]);
    let result = run_image_control(arch, "worker-runtime-function-table", bytes, 30000);
    assert_eq!(result.error, None, "{result:#?}");
    assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
    assert_eq!(
        result.native_exceptions.as_ref().unwrap().exceptions_raised,
        1
    );
}

#[test]
fn m4_thread_tls_notifications_wait_without_host_frames_and_remain_unsignaled_through_detach() {
    for arch in [Architecture::X86, Architecture::X64] {
        for deadlock in [false, true] {
            let mut root = Code::new(arch, 0x1000);
            let mut child = Code::new(arch, 0x1800);
            let mut callback = Code::new(arch, 0x1f00);
            let base = root.base();
            let attach = base + 0x3f00;
            let detach = attach + 8;
            let thread = attach + 16;
            root.prologue();
            root.call(0, &[V(0), V(0), V(0), V(0)]);
            root.store(attach);
            root.call(0, &[V(0), V(0), V(0), V(0)]);
            root.store(detach);
            root.call(1, &[V(0), V(0), V(base + 0x1800), V(42), V(0), V(0)]);
            root.store(thread);
            root.call(2, &[M(thread), V(0)]);
            root.expect(258);
            if !deadlock {
                root.call(3, &[M(attach)]);
                root.expect(1);
            }
            root.call(4, &[V(1)]);
            root.call(2, &[M(thread), V(0)]);
            root.expect(258);
            if !deadlock {
                root.call(3, &[M(detach)]);
                root.expect(1);
            }
            root.call(2, &[M(thread), V(u32::MAX as u64)]);
            root.expect(0);
            root.epilogue(1, 0);
            child.prologue();
            child.epilogue(7, 1);
            if arch == Architecture::X86 {
                callback.bytes.extend([0x8b, 0x54, 0x24, 8]);
            }
            callback.prologue();
            callback.bytes.extend([0x83, 0xfa, 2, 0x0f, 0x85]);
            let not_attach = callback.bytes.len();
            callback.bytes.extend([0; 4]);
            callback.call(2, &[M(attach), V(u32::MAX as u64)]);
            callback.expect(0);
            callback.bytes.push(0xe9);
            let done = callback.bytes.len();
            callback.bytes.extend([0; 4]);
            let displacement = (callback.bytes.len() - not_attach - 4) as u32;
            callback.bytes[not_attach..not_attach + 4].copy_from_slice(&displacement.to_le_bytes());
            callback.bytes.extend([0x83, 0xfa, 3, 0x0f, 0x85]);
            let not_detach = callback.bytes.len();
            callback.bytes.extend([0; 4]);
            callback.call(2, &[M(detach), V(u32::MAX as u64)]);
            callback.expect(0);
            let end = callback.bytes.len();
            for offset in [done, not_detach] {
                let displacement = (end - offset - 4) as u32;
                callback.bytes[offset..offset + 4].copy_from_slice(&displacement.to_le_bytes());
            }
            callback.epilogue(1, 3);
            let mut bytes = fixtures::m4_custom_probe(
                arch,
                &[
                    "CreateEventW",
                    "CreateThread",
                    "WaitForSingleObject",
                    "SetEvent",
                    "Sleep",
                ],
                &root.finish(),
                &child.finish(),
                &callback.finish(),
            );
            let dd = 0x98 + if arch == Architecture::X64 { 112 } else { 96 };
            bytes[dd + 72..dd + 76].copy_from_slice(&0x3e00u32.to_le_bytes());
            bytes[dd + 76..dd + 80].copy_from_slice(
                &(if arch == Architecture::X64 { 40u32 } else { 24 }).to_le_bytes(),
            );
            let result = run_image_control(
                arch,
                if deadlock {
                    "notification-wait-deadlock"
                } else {
                    "notification-attach-detach-waits"
                },
                bytes,
                30000,
            );
            if deadlock {
                assert!(
                    result
                        .error
                        .as_deref()
                        .is_some_and(|e| e.contains("deadlock")),
                    "{arch:?}: {result:#?}"
                );
            } else {
                assert_eq!(result.error, None, "{arch:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1), "{result:#?}");
                let events = &result.user_lifecycle.as_ref().unwrap().events;
                assert_eq!(
                    events.iter().map(|e| e.reason).collect::<Vec<_>>(),
                    vec![2, 3]
                );
                assert!(events.iter().all(|e| e.returned));
            }
        }
    }
}

#[test]
fn m4_exit_process_cancels_exception_and_apc_frames_without_pending_events() {
    for arch in [Architecture::X86, Architecture::X64] {
        for exception in [false, true] {
            let mut root = Code::new(arch, 0x1000);
            let mut callback = Code::new(arch, 0x1f00);
            let base = root.base();
            root.prologue();
            if exception {
                root.call(0, &[V(1), V(base + 0x1f00)]);
                root.bytes.push(0xcc);
            } else {
                root.call(
                    0,
                    &[
                        V(base + 0x1f00),
                        V(if arch == Architecture::X64 {
                            u64::MAX - 1
                        } else {
                            u32::MAX as u64 - 1
                        }),
                        V(0),
                    ],
                );
                root.call(1, &[V(u32::MAX as u64), V(1)]);
            }
            root.bytes.push(0xcc);
            callback.prologue();
            callback.call(2, &[V(42)]);
            callback.bytes.push(0xcc);
            let result = run_control(
                arch,
                if exception {
                    "exit-inside-veh"
                } else {
                    "exit-inside-apc"
                },
                &[
                    if exception {
                        "AddVectoredExceptionHandler"
                    } else {
                        "QueueUserAPC"
                    },
                    "SleepEx",
                    "ExitProcess",
                ],
                root,
                Code::new(arch, 0x1800),
                callback,
                30000,
            );
            assert_eq!(result.error, None, "{arch:?}/{exception}: {result:#?}");
            assert_eq!(result.process_exit_code, Some(42), "{result:#?}");
            assert_eq!(result.guest_entry_return, None);
            assert!(result.api_events.iter().all(|e| !e.pending), "{result:#?}");
            if let Some(exceptions) = result.native_exceptions {
                assert!(!exceptions.active && !exceptions.pending);
            }
        }
    }
}

#[test]
fn m4_worker_process_exit_runs_process_detach_on_the_exiting_owned_thread() {
    for arch in [Architecture::X86, Architecture::X64] {
        let mut root = Code::new(arch, 0x1000);
        let mut child = Code::new(arch, 0x1800);
        let mut callback = Code::new(arch, 0x1f00);
        let base = root.base();
        let thread = base + 0x3f00;
        let detached = thread + 8;
        root.prologue();
        root.call(0, &[V(0), V(0), V(base + 0x1800), V(0), V(0), V(0)]);
        root.store(thread);
        root.call(1, &[M(thread), V(u32::MAX as u64)]);
        root.bytes.push(0xcc);
        child.prologue();
        child.call(2, &[V(73)]);
        child.bytes.push(0xcc);
        if arch == Architecture::X86 {
            callback.bytes.extend([0x8b, 0x54, 0x24, 8]);
        }
        callback.prologue();
        callback.bytes.extend([0x85, 0xd2, 0x0f, 0x85]);
        let skip = callback.bytes.len();
        callback.bytes.extend([0; 4]);
        callback.call(3, &[]);
        callback.expect(2);
        callback.store(detached);
        let displacement = (callback.bytes.len() - skip - 4) as u32;
        callback.bytes[skip..skip + 4].copy_from_slice(&displacement.to_le_bytes());
        callback.epilogue(1, 3);
        let mut bytes = fixtures::m4_custom_probe(
            arch,
            &[
                "CreateThread",
                "WaitForSingleObject",
                "ExitProcess",
                "GetCurrentThreadId",
            ],
            &root.finish(),
            &child.finish(),
            &callback.finish(),
        );
        let dd = 0x98 + if arch == Architecture::X64 { 112 } else { 96 };
        bytes[dd + 72..dd + 76].copy_from_slice(&0x3e00u32.to_le_bytes());
        bytes[dd + 76..dd + 80]
            .copy_from_slice(&(if arch == Architecture::X64 { 40u32 } else { 24 }).to_le_bytes());
        let result = run_image_control(arch, "worker-process-detach-owner", bytes, 30000);
        assert_eq!(result.error, None, "{arch:?}: {result:#?}");
        assert_eq!(result.process_exit_code, Some(73), "{result:#?}");
        let lifecycle = result.user_lifecycle.as_ref().unwrap();
        assert!(lifecycle.complete);
        let detach = lifecycle
            .events
            .iter()
            .filter(|e| e.reason == 0)
            .collect::<Vec<_>>();
        assert_eq!(detach.len(), 1);
        assert!(detach[0].returned && detach[0].thread == 2, "{result:#?}");
        let threads = result.user_threads.as_ref().unwrap();
        assert_eq!(threads.current, 1);
        assert!(
            threads
                .threads
                .iter()
                .all(|t| t.backing_released && t.exit_code == Some(73))
        );
    }
}

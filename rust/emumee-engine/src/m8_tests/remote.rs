//! Exercise capture through the actual process dispatcher, including refusals.
use super::*;
use emumee_core::fixtures::{
    M4Arg::{Memory as M, Value as V},
    M4Code as Code,
};

#[test]
fn remote_write_controls_retain_only_successful_opted_in_remote_bytes() {
    for arch in [Architecture::X86, Architecture::X64] {
        for case in [
            "RemoteWrite",
            "RemotePe",
            "RemoteDisabled",
            "SelfWrite",
            "RemoteFailed",
            "RemoteZero",
        ] {
            let label = format!("{arch:?}-m8-carve-{case}");
            let names = [
                "CreateProcessA",
                "VirtualAllocEx",
                "WriteProcessMemory",
                "ResumeThread",
                "WaitForSingleObject",
                "GetExitCodeProcess",
                "CloseHandle",
                "GetCurrentProcessId",
                "OpenProcess",
            ];
            let mut root = Code::new(arch, 0x1000);
            let mut child = Code::new(arch, 0x1000);
            let base = root.base();
            let info = base + 0x3e00;
            let handle = base + 0x3f00;
            let count = base + 0x3f10;
            let destination = 0x26000000;
            let self_write = case == "SelfWrite";
            let failed = case == "RemoteFailed";
            let payload = if case == "RemotePe" {
                fixtures::counted_driver(arch, 1)
            } else if case == "RemoteZero" {
                vec![0; 16]
            } else {
                b"M8 remote data!\0".to_vec()
            };
            root.prologue();
            // CreateProcess has ten arguments, needing more than the standard
            // four-register shadow area on x64.
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
            if self_write {
                root.call(7, &[]);
                root.store(count);
                root.call(8, &[V(0x1fffff), V(0), M(count)]);
            } else {
                root.load(info);
            }
            root.store(handle);
            root.call(1, &[M(handle), V(destination), V(0x1000), V(0x3000), V(4)]);
            root.expect(destination as u32);
            root.call(
                2,
                &[
                    M(handle),
                    V(if failed {
                        destination + 0x2000
                    } else {
                        destination
                    }),
                    V(base + 0x3000),
                    V(payload.len() as u64),
                    V(count),
                ],
            );
            root.expect(u32::from(!failed));
            root.load(count);
            root.expect(if failed { 0 } else { payload.len() as u32 });
            if self_write {
                root.load(destination);
                root.expect(u32::from_le_bytes(payload[..4].try_into().unwrap()));
                root.call(6, &[M(handle)]);
                root.expect(1);
            }
            root.call(3, &[M(info + arch.width() as u64)]);
            root.expect(1);
            root.call(4, &[M(info), V(u32::MAX as u64)]);
            root.expect(0);
            root.call(5, &[M(info), V(count)]);
            root.expect(1);
            root.load(count);
            root.expect(42);
            for offset in [0, arch.width() as u64] {
                root.call(6, &[M(info + offset)]);
                root.expect(1);
            }
            if arch == Architecture::X64 {
                root.bytes.extend([0x48, 0x83, 0xc4, 0x20]);
            }
            root.epilogue(1, 0);
            child.prologue();
            if !self_write {
                child.load(destination);
                child.expect(if failed {
                    0
                } else {
                    u32::from_le_bytes(payload[..4].try_into().unwrap())
                });
            }
            child.epilogue(42, 0);
            let mut bytes = fixtures::m4_custom_probe(arch, &names, &root.finish(), &[], &[]);
            let put = |bytes: &mut Vec<u8>, rva: usize, data: &[u8]| {
                bytes[rva - 0xe00..rva - 0xe00 + data.len()].copy_from_slice(data);
            };
            put(&mut bytes, 0x3000, &payload);
            put(&mut bytes, 0x3c00, b"C:\\emumee\\child.exe\0");
            let child = fixtures::m4_custom_probe(arch, &names, &child.finish(), &[], &[]);
            let staged = [(
                emumee_core::user_input::InputKind::File,
                r"C:\emumee\child.exe",
                child,
            )];
            let result = run_with_staged(
                &label,
                bytes,
                &staged,
                CaptureRequest {
                    memory_strings: None,
                    carve_executable_regions: case != "RemoteDisabled",
                },
                30_000,
            );
            assert_eq!(result.error, None, "{label}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(1), "{label}: {result:#?}");
            assert!(
                result.api_events.iter().all(|event| !event.pending),
                "{label}"
            );
            let child = result
                .user_processes
                .iter()
                .find(|p| p.image.eq_ignore_ascii_case(r"C:\emumee\child.exe"))
                .unwrap();
            assert_eq!(child.exit_code, Some(42), "{label}");
            let captured: Vec<_> = result
                .artifacts
                .iter()
                .flat_map(|a| a.observations.iter().map(move |o| (a, o)))
                .filter(|(_, o)| {
                    o.context
                        .as_ref()
                        .is_some_and(|c| c["transition"] == "remote_write")
                })
                .collect();
            if matches!(case, "RemoteWrite" | "RemotePe") {
                assert_eq!(captured.len(), 1, "{label}: {:#?}", result.artifacts);
                let (artifact, observation) = captured[0];
                assert_eq!(artifact.data, payload, "{label}");
                let context = observation.context.as_ref().unwrap();
                assert_eq!(context["target_process_id"], child.id, "{label}");
                assert_eq!(context["guest_base"], destination, "{label}");
                assert_eq!(context["region_bytes"], payload.len(), "{label}");
                assert_eq!(
                    observation.kind,
                    if case == "RemotePe" {
                        emumee_core::artifacts::ArtifactKind::CarvedImage
                    } else {
                        emumee_core::artifacts::ArtifactKind::MemorySnapshot
                    },
                    "{label}"
                );
            } else {
                assert!(captured.is_empty(), "{label}: {:#?}", result.artifacts);
            }
        }
    }
}

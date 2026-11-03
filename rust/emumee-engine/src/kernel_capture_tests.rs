//! Harmless native callers for the pinned capture rejection profile.
use super::*;
use emumee_core::{
    fixtures::{ApiFixture, ConfiguredFixture, ThreadObjectFixture, configured_document},
    fullpersona::{ResolveContext, decode},
};
const BASE: u64 = 0x140000000;
#[derive(Clone, Copy, Debug)]
enum Output {
    Null,
    Data,
    Code,
    Unmapped,
    StackAlias,
    Pivot,
}
pub(crate) fn prepared(build: u32, parent: bool) -> configured::Prepared {
    let mut document: serde_json::Value =
        serde_json::from_slice(&configured_document(ConfiguredFixture::Kernel)).unwrap();
    document["windows_build"] = serde_json::json!(build);
    if parent {
        document["registry_keys"].as_array_mut().unwrap().push(serde_json::json!({"path":r"HKLM\System\CurrentControlSet\Control\CrashControl","values":[]}));
    }
    configured::Prepared::new(
        decode(
            &serde_json::to_vec(&document).unwrap(),
            &ResolveContext::default(),
        )
        .unwrap(),
        configured::Request {
            architecture: Architecture::X64,
            kernel: true,
            initial_processor: 0,
            process: None,
            budget: 5000,
            timeout_us: 30_000_000,
        },
    )
    .unwrap()
}
fn run_case(build: u32, parent: bool, output: Output, thread: u64) -> Execution {
    let image = fixture(output, thread);
    run_generated_with_fixture_configuration(
        &image,
        &[],
        5000,
        30_000_000,
        GeneratedConfiguration {
            configured: Some(prepared(build, parent)),
            ..Default::default()
        },
    )
    .unwrap()
}
fn fixture(output: Output, thread: u64) -> Vec<u8> {
    let mut image = emumee_core::fixtures::api_probe(
        Architecture::X64,
        ApiFixture::ThreadObjects(ThreadObjectFixture::RootHeader),
    );
    image[0x1500..0x1540].fill(0);
    let name = b"KeCapturePersistentThreadState";
    image[0x1502..0x1502 + name.len()].copy_from_slice(name);
    image[0x1e00..0x1e80].fill(0xa5);
    let mut code = Vec::new();
    fn imm(code: &mut Vec<u8>, prefix: &[u8], value: u64) {
        code.extend(prefix);
        code.extend(value.to_le_bytes());
    }
    fn expected(code: &mut Vec<u8>, value: u64) {
        imm(code, &[0x48, 0xba], value);
        code.extend([0x48, 0x39, 0xd0, 0x74, 2, 0x0f, 0x0b]);
    }
    code.extend([0x53, 0x55, 0x56, 0x57, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57]);
    code.extend([0x48, 0x81, 0xec, 0x90, 0, 0, 0]);
    let values = [
        0x1111222233334444u64,
        0x2222333344445555,
        0x3333444455556666,
        0x4444555566667777,
        0x5555666677778888,
        0x6666777788889999,
        0x777788889999aaaa,
    ];
    for (prefix, value) in [
        [0x48, 0xbb],
        [0x48, 0xbd],
        [0x48, 0xbe],
        [0x48, 0xbf],
        [0x49, 0xbd],
        [0x49, 0xbe],
        [0x49, 0xbf],
    ]
    .into_iter()
    .zip(values)
    {
        imm(&mut code, &prefix, value);
    }
    if matches!(output, Output::Pivot) {
        imm(&mut code, &[0x48, 0xbc], BASE + 0x2d00);
    }
    if matches!(output, Output::StackAlias) {
        code.extend([0x48, 0x8d, 0x4c, 0x24, 8]);
    } else {
        imm(
            &mut code,
            &[0x48, 0xb9],
            if matches!(output, Output::Null) {
                u64::MAX
            } else {
                BASE + 0x2c00
            },
        );
    }
    imm(&mut code, &[0x48, 0xba], thread);
    code.extend([0x41, 0xb8, 0xad, 0xde, 0xad, 0xde, 0x45, 0x31, 0xc9]);
    for offset in [0x20, 0x28, 0x30] {
        code.extend([0x48, 0xc7, 0x44, 0x24, offset, 0, 0, 0, 0]);
    }
    match output {
        Output::StackAlias => code.extend([0x48, 0x89, 0xe0]),
        _ => imm(
            &mut code,
            &[0x48, 0xb8],
            match output {
                Output::Null => 0,
                Output::Code => BASE + 0x1000,
                Output::Unmapped => 0x1000000000,
                _ => BASE + 0x2c00,
            },
        ),
    }
    code.extend([0x48, 0x89, 0x44, 0x24, 0x38]);
    code.extend([0xff, 0x15]);
    let after = 0x1000 + code.len() + 4;
    code.extend((0x2080i32 - after as i32).to_le_bytes());
    code.extend([0x9c, 0x41, 0x5a]); // Save actual returned flags before any comparison.
    code.extend([0x83, 0xf8, 0, 0x74, 2, 0x0f, 0x0b]);
    for (mov, value) in [
        [0x48, 0x89, 0xd8],
        [0x48, 0x89, 0xe8],
        [0x48, 0x89, 0xf0],
        [0x48, 0x89, 0xf8],
        [0x4c, 0x89, 0xe8],
        [0x4c, 0x89, 0xf0],
        [0x4c, 0x89, 0xf8],
    ]
    .into_iter()
    .zip(values)
    {
        code.extend(mov);
        expected(&mut code, value);
    }
    for (offset, value) in [
        (0, values[0]),
        (8, values[2]),
        (0x10, values[3]),
        (0x18, values[4]),
        (0xf0, values[1]),
        (0xe8, values[5]),
        (0xe0, values[6]),
    ] {
        code.extend([0x48, 0x8b, 0x44, 0x24, offset]);
        expected(&mut code, value);
    }
    // Independently execute ADD on the same pre-epilogue arithmetic value.
    code.extend([
        0x48, 0x8d, 0x44, 0x24, 0xa0, 0x48, 0x83, 0xc0, 0x40, 0x9c, 0x5a, 0x49, 0x39, 0xd2, 0x74,
        2, 0x0f, 0x0b,
    ]);
    if matches!(output, Output::Data | Output::Code) {
        let address = if matches!(output, Output::Code) {
            BASE + 0x1000
        } else {
            BASE + 0x2c00
        };
        let value = if matches!(output, Output::Code) {
            u64::from_le_bytes(code[..8].try_into().unwrap())
        } else {
            0xa5a5a5a5a5a5a5a5
        };
        imm(&mut code, &[0x48, 0xa1], address);
        expected(&mut code, value);
    }
    code.extend([
        0x48, 0x81, 0xc4, 0x90, 0, 0, 0, 0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x5f, 0x5e, 0x5d,
        0x5b, 0xb8, 1, 0, 0, 0, 0xc3,
    ]);
    assert!(code.len() < 0xc00);
    image[0x200..0xe00].fill(0xcc);
    image[0x200..0x200 + code.len()].copy_from_slice(&code);
    image
}
#[test]
fn actual_capture_rejections_preserve_gprs_model_native_spills_flags_and_unused_pointers() {
    for (output, thread) in [
        (Output::Data, 0),
        (Output::Data, u64::MAX),
        (Output::Code, 0),
        (Output::Unmapped, u64::MAX),
        (Output::StackAlias, 1),
        (Output::Null, 0),
    ] {
        let e = run_case(26200, false, output, thread);
        assert_eq!(e.error, None, "{output:?}: {e:#?}");
        assert_eq!(e.guest_entry_return, Some(1));
        let report = e.kernel_capture.unwrap();
        assert!(!report.native_effect_failure);
        assert_eq!(report.events.len(), 1);
        assert_eq!(report.bootstrap.unwrap().force_dump_disabled, Some(1));
        let event = &report.events[0];
        assert_eq!(event.returned, 0);
        assert_eq!(event.native_stack_spills, 7);
        assert_eq!(
            event.current_thread_slot_read,
            thread == 0 && !matches!(output, Output::Null)
        );
        assert_eq!(
            event.reason,
            if matches!(output, Output::Null) {
                emumee_core::kernel_capture::admission::Rejection::NullOutput
            } else {
                emumee_core::kernel_capture::admission::Rejection::ForceDumpDisabled
            }
        );
        if matches!(output, Output::StackAlias) {
            assert_eq!(event.output, event.entry_rsp + 8);
            assert_eq!(event.context, event.entry_rsp + 16);
        }
        assert_eq!(
            e.api_events
                .iter()
                .filter(|event| event.api == "ntoskrnl.KeCapturePersistentThreadState")
                .count(),
            1
        );
    }
}
#[test]
fn unknown_boot_policy_stops_but_null_output_remains_a_known_native_shortcut() {
    let e = run_case(26200, true, Output::Data, 0);
    assert!(
        e.error
            .as_deref()
            .unwrap()
            .contains("Capture policy fact is not qualified")
    );
    assert_eq!(e.guest_entry_return, None);
    let report = e.kernel_capture.unwrap();
    assert!(report.events.is_empty());
    assert!(!report.native_effect_failure);
    let boot = report.bootstrap.unwrap();
    assert_eq!(boot.force_dump_disabled, None);
    assert_eq!(boot.first_open_status, Some(0xc0000034));
    let e = run_case(26200, true, Output::Null, 0);
    assert_eq!(e.error, None, "{e:#?}");
    assert_eq!(e.guest_entry_return, Some(1));
    assert!(!e.kernel_capture.unwrap().events[0].current_thread_slot_read);
}
#[test]
fn capture_rejects_unqualified_build_and_unowned_native_frame_without_a_fake_return() {
    let e = run_case(26100, false, Output::Data, 0);
    assert!(e.error.unwrap().contains("pinned x64 build26200"));
    assert_eq!(e.guest_entry_return, None);
    let e = run_case(26200, false, Output::Pivot, 1);
    assert!(e.error.unwrap().contains("exceeds owned ordinary stack"));
    assert_eq!(e.guest_entry_return, None);
}

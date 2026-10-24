use super::*;
use emumee_core::fixtures::{ApiFixture, StdioFixture as F};
#[test]
fn stdio_cdecl_callers_check_guest_layout_errno_modes_and_exact_console_bytes() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [
            F::Legacy,
            F::Ucrt,
            F::Errno,
            F::Modes,
            F::Write,
            F::Utf16,
            F::Utf8,
        ] {
            let result = run_api_fixture(arch, ApiFixture::Stdio(kind), 2000).unwrap();
            assert_eq!(result.error, None, "{arch:?} {kind:?}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(17));
            assert_eq!(result.network.calls, 0);
            assert!(result.artifacts.is_empty());
            let console = result.console.as_ref().expect("user console report");
            assert_eq!(
                console.stdout,
                match kind {
                    F::Write => "hello\n",
                    F::Utf16 => "AΩ\n",
                    F::Utf8 => "Aé\n",
                    _ => "",
                }
            );
            assert_eq!(
                console.stderr,
                if matches!(kind, F::Write) {
                    "hello\n"
                } else {
                    ""
                }
            );
            assert_eq!(result.api_events.last().unwrap().last_error, 0x12345678);
            let partial =
                run_api_fixture(arch, ApiFixture::Stdio(kind), result.instruction_count - 1)
                    .unwrap();
            assert_eq!(partial.completion_reason, "instruction_budget");
            assert_eq!(partial.guest_entry_return, None);
            assert_eq!(partial.error, None);
        }
    }
}
#[test]
fn stdio_rejects_unmodeled_encoding_buffers_descriptors_mapping_changes_and_formats() {
    for arch in [Architecture::X86, Architecture::X64] {
        for (kind, expected) in [
            (F::BadEncoding, "ASCII"),
            (F::BadBuffer, "not readable guest memory"),
            (F::BadDescriptor, "descriptor or byte count"),
            (F::OwnedFree, "CRT-owned FILE/errno"),
            (F::OwnedProtect, "CRT-owned FILE/errno"),
            (F::OwnedRecommit, "CRT-owned FILE/errno"),
            (F::FormatUnsupported, "real guest format model"),
        ] {
            let result = run_api_fixture(arch, ApiFixture::Stdio(kind), 2000).unwrap();
            assert_eq!(result.guest_entry_return, None, "{arch:?} {kind:?}");
            assert!(
                result.error.as_ref().is_some_and(|s| s.contains(expected)),
                "{arch:?} {kind:?}: {:?}",
                result.error
            );
            let console = result.console.unwrap();
            assert!(console.stdout.is_empty());
            assert!(console.stderr.is_empty());
            assert!(console.write_events.is_empty());
        }
    }
}

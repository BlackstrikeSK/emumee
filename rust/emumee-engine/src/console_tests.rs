use super::*;
use emumee_core::fixtures::{ApiFixture, ConsoleFixture as F};
#[test]
fn console_callers_check_standard_handles_codepages_modes_counts_aliases_and_redirected_vfs() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in [
            F::Standard,
            F::Ansi,
            F::Wide,
            F::File,
            F::Mixed,
            F::Redirect,
            F::Alias,
            F::Closed,
            F::ReadOnly,
            F::Mode,
            F::Screen,
            F::BadBuffer,
            F::BadCount,
            F::Reserved,
            F::Zero,
            F::InvalidHandle,
        ] {
            let result = run_api_fixture(architecture, ApiFixture::Console(kind), 4000).unwrap();
            assert_eq!(result.error, None, "{architecture:?} {kind:?}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(17));
            assert_eq!(result.network.calls, 0);
            assert_eq!(result.api_events.last().unwrap().last_error, 0x12345678);
            let console = result.console.as_ref().unwrap();
            assert_eq!(
                console.stdout,
                match kind {
                    F::Ansi | F::File => "é",
                    F::Mixed => "aééΩ😀z",
                    F::Alias => "éé",
                    _ => "",
                }
            );
            assert_eq!(
                console.stderr,
                if matches!(kind, F::Wide) {
                    "Ω😀�"
                } else {
                    ""
                }
            );
            if matches!(kind, F::Redirect) {
                assert_eq!(result.artifacts.len(), 1);
                assert_eq!(result.artifacts[0].data, b"file");
            } else {
                assert!(result.artifacts.is_empty());
            }
            let session = result.console_session.as_ref().unwrap();
            assert_eq!(session.code_page, 437);
            if matches!(kind, F::Mode) {
                assert_eq!(session.input_mode, 6);
                assert_eq!(session.output_mode, 7);
            }
            if matches!(kind, F::Alias) {
                assert_eq!(session.retired_aliases, [0xf100, 0xf101]);
                assert!(session.aliases.is_empty());
            }
            let partial = run_api_fixture(
                architecture,
                ApiFixture::Console(kind),
                result.instruction_count - 1,
            )
            .unwrap();
            assert_eq!(partial.error, None);
            assert_eq!(partial.completion_reason, "instruction_budget");
            assert_eq!(partial.guest_entry_return, None);
        }
    }
}
#[test]
fn console_stdin_and_overlapped_io_remain_explicit_unimplemented_profiles() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for (kind, reason) in [
            (F::Input, "stdin input is not modeled"),
            (F::Overlapped, "Console overlapped I/O is not modeled"),
        ] {
            let result = run_api_fixture(architecture, ApiFixture::Console(kind), 4000).unwrap();
            assert!(
                result
                    .error
                    .as_ref()
                    .is_some_and(|error| error.contains(reason)),
                "{architecture:?} {kind:?}: {:?}",
                result.error
            );
            assert_eq!(result.guest_entry_return, None);
            let console = result.console.unwrap();
            assert!(console.stdout.is_empty());
            assert!(console.stderr.is_empty());
            assert!(console.write_events.is_empty());
        }
    }
}

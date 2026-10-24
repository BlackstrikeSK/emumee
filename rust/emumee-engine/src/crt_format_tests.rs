use super::*;
use emumee_core::fixtures::{ApiFixture, FormatFixture as F};
#[test]
fn bounded_crt_formatters_preserve_guest_counts_truncation_varargs_errno_and_console() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in [
            F::WideConsole,
            F::WideStream,
            F::WideBuffer,
            F::Equal,
            F::Truncate,
            F::Secure,
            F::SecureTruncate,
            F::CommonWide,
            F::CommonNarrow,
            F::Integer64,
        ] {
            let result = run_api_fixture(architecture, ApiFixture::Format(kind), 3000).unwrap();
            assert_eq!(result.error, None, "{architecture:?} {kind:?}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(17));
            assert_eq!(result.api_events.last().unwrap().last_error, 0x12345678);
            assert_eq!(result.network.calls, 0);
            assert!(result.artifacts.is_empty());
            let console = result.console.as_ref().unwrap();
            assert_eq!(
                console.stdout,
                match kind {
                    F::WideConsole => "Ω😀|test|(null)|Ω😀%",
                    F::Integer64 => "1234567889abcdef:7",
                    _ => "",
                }
            );
            assert_eq!(
                console.stderr,
                match kind {
                    F::WideStream => "Host: Ω😀\n",
                    F::CommonNarrow => "   test|test   \n",
                    _ => "",
                }
            );
            let partial = run_api_fixture(
                architecture,
                ApiFixture::Format(kind),
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
fn unsupported_crt_formats_options_memory_and_surrogates_do_not_write_console() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for (kind, reason) in [
            (F::InvalidFormat, "conversion is not modeled"),
            (F::InvalidOption, "locale or common formatting options"),
            (F::BadFormat, "unreadable guest format/string"),
            (F::BadOutput, "lacks permission"),
            (F::MalformedUtf16, "malformed UTF16"),
            (F::SurrogateChar, "isolated UTF16 surrogate"),
        ] {
            let result = run_api_fixture(architecture, ApiFixture::Format(kind), 3000).unwrap();
            assert!(
                result.error.as_ref().is_some_and(|s| s.contains(reason)),
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

//! Persona control family: the one modeled Windows identity behind every
//! version structure and predicate.
use super::*;
use emumee_core::fixtures::{
    M6LocaleFixture as L, M6VersionFixture as V, m6_locale_probe, m6_version_probe,
};

fn version(arch: Architecture, kind: V, unicode: bool) -> Execution {
    let suffix = if unicode { "W" } else { "A" };
    let label = format!("{arch:?}-m6-version-{kind:?}{suffix}");
    let result = run(&label, m6_version_probe(arch, kind, unicode), &[], 60_000);
    succeeded(&label, &result);
    result
}

#[test]
fn m6_every_version_spelling_publishes_one_identity_the_guest_checks() {
    for arch in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            let result = version(arch, V::Identity, unicode);
            // The identity the structures carry is the persona machine's own
            // build, which the plain GetVersion spelling already reported.
            assert!(
                result
                    .api_events
                    .iter()
                    .any(|event| event.api.contains("RtlGetNtVersionNumbers")),
                "{arch:?}/{unicode}"
            );
        }
    }
}

#[test]
fn m6_version_condition_mask_packs_one_documented_slot_per_call() {
    for arch in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            version(arch, V::Condition, unicode);
        }
    }
}

#[test]
fn m6_verify_version_info_compares_fields_and_the_ordered_sequence() {
    for arch in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            version(arch, V::Verify, unicode);
        }
    }
}

#[test]
fn m6_verify_version_info_refuses_undefined_conditions_and_short_structures() {
    for arch in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            let result = version(arch, V::BadArguments, unicode);
            // Every refusal is a returned failure, not a stop: the guest ran to
            // its own successful end.
            assert_eq!(result.error, None);
        }
    }
}

fn locale(arch: Architecture, kind: L, unicode: bool) -> Execution {
    let suffix = if unicode { "W" } else { "A" };
    let label = format!("{arch:?}-m6-locale-{kind:?}{suffix}");
    let result = run(&label, m6_locale_probe(arch, kind, unicode), &[], 60_000);
    succeeded(&label, &result);
    result
}

#[test]
fn m6_locale_session_and_package_identity_come_from_the_persona() {
    for arch in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            for kind in [L::Defaults, L::Validity, L::Session] {
                locale(arch, kind, unicode);
            }
        }
    }
}

#[test]
fn m6_firmware_table_is_persona_identity_the_guest_walks_byte_for_byte() {
    for arch in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            let result = locale(arch, L::Firmware, unicode);
            // The table is modeled identity, so it is not captured as an
            // artifact and nothing was omitted.
            assert!(result.artifacts.is_empty());
            assert_eq!(result.capture_summary.omitted_observations, 0);
        }
    }
}

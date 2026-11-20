//! M6 locale, session and firmware control family. The guest reads the
//! configured locale through every default spelling, decides which locales are
//! installed, observes that it has no package identity, and walks the modeled
//! SMBIOS table byte for byte — the table sandbox-aware code reads to
//! fingerprint its machine.
use super::m6::{POISON, Probe};
use super::winhttp::Arg::Value as V;
use crate::pe::Architecture;
use crate::persona::FirmwareConfig;

#[derive(Clone, Copy, Debug)]
pub enum M6LocaleFixture {
    /// Every system and user default reports the configured locale.
    Defaults,
    /// Which locales are installed, and the flags that are not modeled.
    Validity,
    /// The console session, and a process with no package identity.
    Session,
    /// The raw SMBIOS table and the providers that have none.
    Firmware,
}
/// LCID and LANGID of the default persona locale, en-US.
const LCID: u32 = 0x0409;
/// The one modeled console session.
const SESSION: u32 = 1;
/// LCID_INSTALLED and LCID_SUPPORTED.
const INSTALLED: u64 = 1;
const SUPPORTED: u64 = 2;
/// The invariant locale, which exists alongside the configured one.
const INVARIANT: u64 = 0x7f;
/// Provider signature 'RSMB', the raw SMBIOS table.
const RSMB: u64 = u32::from_be_bytes(*b"RSMB") as u64;

const SYSTEM_LCID: usize = 0;
const USER_LCID: usize = 1;
const SYSTEM_LANG: usize = 2;
const USER_LANG: usize = 3;
const SYSTEM_UI: usize = 4;
const USER_UI: usize = 5;
const VALID_LOCALE: usize = 6;
const SESSION_ID: usize = 7;
const PACKAGE_ID: usize = 8;
const FIRMWARE: usize = 9;
const WINDOWS_DIRECTORY: usize = 10;
const LAST_ERROR: usize = 11;
const APISET_UI: usize = 12;

fn imports() -> [(&'static str, Vec<String>); 2] {
    [
        (
            "kernel32.dll",
            vec![
                "GetSystemDefaultLCID".into(),
                "GetUserDefaultLCID".into(),
                "GetSystemDefaultLangID".into(),
                "GetUserDefaultLangID".into(),
                "GetSystemDefaultUILanguage".into(),
                "GetUserDefaultUILanguage".into(),
                "IsValidLocale".into(),
                "WTSGetActiveConsoleSessionId".into(),
                "GetCurrentPackageId".into(),
                "GetSystemFirmwareTable".into(),
                // The generic directory spelling reads narrow text.
                "GetWindowsDirectory".into(),
                "GetLastError".into(),
            ],
        ),
        (
            "api-ms-win-core-localization-l1-2-0.dll",
            vec!["GetUserDefaultUILanguage".into()],
        ),
    ]
}

pub fn m6_locale_probe(
    architecture: Architecture,
    kind: M6LocaleFixture,
    unicode: bool,
) -> Vec<u8> {
    use M6LocaleFixture as K;
    let mut p = Probe::new(architecture, unicode, &imports());
    let buffer = p.scratch(256);
    let table = FirmwareConfig::default().raw_smbios();
    let space = p.scratch(table.len() as u64 + 32);
    match kind {
        K::Defaults => {
            // One modeled locale serves the system and user defaults alike.
            for index in [
                SYSTEM_LCID,
                USER_LCID,
                SYSTEM_LANG,
                USER_LANG,
                SYSTEM_UI,
                USER_UI,
                APISET_UI,
            ] {
                p.call(index, &[]);
                p.eax(LCID);
            }
            // The generic directory spelling joins the existing model.
            p.poison(buffer, 6);
            p.call(WINDOWS_DIRECTORY, &[V(buffer), V(64)]);
            p.eax(10);
            p.ascii_text(buffer, r"C:\Windows");
        }
        K::Validity => {
            // The configured locale and the invariant locale are installed;
            // nothing else is.
            for (locale, flags, expected) in [
                (u64::from(LCID), INSTALLED, 1u32),
                (u64::from(LCID), SUPPORTED, 1),
                (u64::from(LCID), INSTALLED | SUPPORTED, 1),
                (INVARIANT, INSTALLED, 1),
                (INVARIANT, SUPPORTED, 1),
                // de-DE is a locale this profile admits in a persona document
                // but has not installed in this run.
                (0x407, INSTALLED, 0),
                (0x40c, SUPPORTED, 0),
            ] {
                p.call(VALID_LOCALE, &[V(locale), V(flags)]);
                p.eax(expected);
            }
            // An unmodeled class is an invalid flag rather than a guess.
            for flags in [0, 4, 0x10, 0x8000_0000] {
                p.call(VALID_LOCALE, &[V(u64::from(LCID)), V(flags)]);
                p.eax(0);
                p.call(LAST_ERROR, &[]);
                p.eax(1004);
            }
        }
        K::Session => {
            p.call(SESSION_ID, &[]);
            p.eax(SESSION);
            // The modeled process has no package identity, and the refusal
            // writes nothing: a reported success with an unfilled buffer would
            // hand the guest bytes it would then parse.
            p.poison(buffer, 8);
            p.set_dword(buffer, 256);
            p.call(PACKAGE_ID, &[V(buffer), V(buffer + 16)]);
            p.eax(15700);
            p.dword(buffer, 256);
            p.intact(buffer + 4, 3);
            p.intact(buffer + 16, 4);
        }
        K::Firmware => {
            // A null buffer reports the required size and writes nothing.
            p.poison(space, 4);
            p.call(FIRMWARE, &[V(RSMB), V(0), V(0), V(0)]);
            p.eax(table.len() as u32);
            p.intact(space, 4);
            // A buffer one byte short reports the size and still writes nothing.
            p.call(
                FIRMWARE,
                &[V(RSMB), V(0), V(space), V(table.len() as u64 - 1)],
            );
            p.eax(table.len() as u32);
            p.intact(space, 4);
            // The exact table, walked byte for byte by the guest itself.
            p.poison(space, (table.len() as u64).div_ceil(4) + 1);
            p.call(FIRMWARE, &[V(RSMB), V(0), V(space), V(table.len() as u64)]);
            p.eax(table.len() as u32);
            p.check(space, &table, POISON.to_le_bytes()[0]);
            p.intact(space + (table.len() as u64).div_ceil(4) * 4, 1);
            // Any other provider, and any table other than table zero, has no
            // table here: the honest answer for a machine without that
            // firmware interface, rather than invented bytes.
            for (provider, id) in [
                (u64::from(u32::from_be_bytes(*b"ACPI")), 0),
                (u64::from(u32::from_be_bytes(*b"FIRM")), 0),
                (RSMB, 1),
            ] {
                p.call(FIRMWARE, &[V(provider), V(id), V(space), V(4096)]);
                p.eax(0);
                p.call(LAST_ERROR, &[]);
                p.eax(0);
            }
        }
    }
    p.finish()
}

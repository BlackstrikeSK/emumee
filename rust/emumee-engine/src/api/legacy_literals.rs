//! Explicit frozen scalar placeholders, never a fallback for unknown APIs.
//! These preserve legacy placeholders rather than claim native Windows effects.
use super::*;
use serde::Deserialize;
use std::sync::OnceLock;

#[derive(Deserialize)]
pub(super) struct Literal {
    pub(super) module: String,
    pub(super) export: String,
    pub(super) architecture: String,
    pub(super) argc: usize,
    pub(super) value: u32,
}

#[derive(Deserialize)]
struct Document {
    schema: u32,
    entries: Vec<Literal>,
}

fn entries() -> &'static [Literal] {
    static DOCUMENT: OnceLock<Document> = OnceLock::new();
    &DOCUMENT
        .get_or_init(|| {
            let mut document: Document = serde_json::from_str(include_str!("legacy_literals.json"))
                .expect("Compiled frozen literal allowlist is valid");
            assert_eq!(document.schema, 1);
            let locals: Document = serde_json::from_str(include_str!("legacy_locals.json"))
                .expect("Compiled frozen local-constant allowlist is valid");
            assert_eq!(locals.schema, 1);
            document.entries.extend(locals.entries);
            document
        })
        .entries
}

pub(super) fn exact(
    architecture: Architecture,
    module: &str,
    name: &str,
) -> Option<&'static Literal> {
    let architecture = match architecture {
        Architecture::X86 => "x86",
        Architecture::X64 => "x64",
    };
    entries().iter().find(|entry| {
        entry.architecture == architecture && entry.module == module && entry.export == name
    })
}

pub(super) fn lookup(
    architecture: Architecture,
    module: &str,
    name: &str,
) -> Option<&'static Literal> {
    exact(architecture, module, name).or_else(|| {
        // The frozen normalize_import_miss folds one A/W suffix. NTDLL uses
        // a different kernel bridge, so it cannot inherit this user-DLL rule.
        if module == "ntdll" {
            return None;
        }
        let base = name.strip_suffix('A').or_else(|| name.strip_suffix('W'))?;
        exact(architecture, module, base)
    })
}

pub(super) fn has_width_aliases(architecture: Architecture, module: &str, name: &str) -> bool {
    module != "ntdll" && exact(architecture, module, name).is_some()
}

pub(super) fn invoke(engine: &Unicorn<Trace>, value: u32) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_mode,
        "Frozen user placeholder is outside the kernel runtime profile"
    );
    Ok(u64::from(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_reviewed_names_and_their_frozen_user_width_aliases_resolve() {
        assert!(exact(Architecture::X64, "gdi32", "BitBlt").is_some());
        assert_eq!(
            exact(Architecture::X64, "comctl32", "InitCommonControlsEx")
                .unwrap()
                .value,
            1
        );
        assert!(lookup(Architecture::X64, "comctl32", "InitCommonControlsExW").is_some());
        assert!(lookup(Architecture::X64, "gdi32", "BitBltA").is_some());
        assert!(lookup(Architecture::X64, "gdi32", "BitBltW").is_some());
        assert!(lookup(Architecture::X64, "gdi32", "BitBltWW").is_none());
        assert!(lookup(Architecture::X64, "gdi32", "UnreviewedSuccess").is_none());
        assert!(lookup(Architecture::X64, "ntdll", "NtYieldExecutionW").is_none());
        assert!(lookup(Architecture::X64, "msvcrt", "_CxxThrowException").is_none());
    }

    #[test]
    fn literal_lookup_does_not_override_refusals_or_grant_kernel_authority() {
        assert_eq!(
            super::super::describe(Architecture::X64, "msvcrt", "_CxxThrowException")["dispatch"],
            "explicit_unsupported"
        );
        assert_eq!(
            super::super::describe(Architecture::X64, "gdi32", "UnreviewedSuccess")["dispatch"],
            "unmodeled"
        );
        let mut engine = crate::new_engine(Architecture::X64).unwrap();
        engine.get_data_mut().apis.kernel_mode = true;
        engine.get_data_mut().apis.last_error = 0x12345678;
        assert!(
            invoke(&engine, 1)
                .unwrap_err()
                .to_string()
                .contains("kernel runtime profile")
        );
        assert_eq!(engine.get_data().apis.last_error, 0x12345678);
    }
}

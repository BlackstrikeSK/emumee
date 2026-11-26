//! Frozen void placeholders preserve the caller's return register and state.
use super::*;
use serde::Deserialize;
use std::sync::OnceLock;

#[derive(Deserialize)]
pub(super) struct Entry {
    pub(super) module: String,
    pub(super) export: String,
    architecture: String,
    pub(super) argc: usize,
}

#[derive(Deserialize)]
struct Document {
    schema: u32,
    entries: Vec<Entry>,
}

pub(super) fn exact(
    architecture: Architecture,
    module: &str,
    name: &str,
) -> Option<&'static Entry> {
    static DOCUMENT: OnceLock<Document> = OnceLock::new();
    let document = DOCUMENT.get_or_init(|| {
        let value: Document = serde_json::from_str(include_str!("legacy_voids.json"))
            .expect("Compiled frozen void allowlist is valid");
        assert_eq!(value.schema, 1);
        value
    });
    let arch = if architecture == Architecture::X86 {
        "x86"
    } else {
        "x64"
    };
    document
        .entries
        .iter()
        .find(|e| e.architecture == arch && e.module == module && e.export == name)
}

pub(super) fn lookup(
    architecture: Architecture,
    module: &str,
    name: &str,
) -> Option<&'static Entry> {
    exact(architecture, module, name).or_else(|| {
        if module == "ntdll" {
            return None;
        }
        let base = name.strip_suffix('A').or_else(|| name.strip_suffix('W'))?;
        exact(architecture, module, base)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewed_voids_and_frozen_width_aliases_remain_void_and_finite() {
        for architecture in [Architecture::X86, Architecture::X64] {
            for name in [
                "InitializeSRWLock",
                "InitializeSRWLockA",
                "InitializeSRWLockW",
            ] {
                let binding = super::super::describe(architecture, "kernel32", name);
                assert_eq!(binding["dispatch"], "model");
                assert_eq!(binding["return_type"], "void");
                assert_eq!(binding["legacy_void_placeholder"], true);
                assert_eq!(binding["argc"], 1);
            }
            assert!(lookup(architecture, "kernel32", "InitializeSRWLockWW").is_none());
            assert!(lookup(architecture, "ntdll", "RtlUnwind").is_none());
            assert!(lookup(architecture, "kernel32", "InventedVoidSuccess").is_none());
            assert_eq!(
                super::super::describe(architecture, "kernel32", "InventedVoidSuccess")["dispatch"],
                "unmodeled"
            );
        }
    }
}

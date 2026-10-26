//! Finite, explicitly owned object-directory snapshots for native lookups.
//!
//! An unobserved directory is unknown, not empty. A successful section open
//! additionally needs section lifetime, access and handle state; this module
//! never fabricates those from the presence of a name.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

pub const NAME_NOT_FOUND: u32 = 0xc0000034;
pub const PATH_NOT_FOUND: u32 = 0xc000003a;
pub const TYPE_MISMATCH: u32 = 0xc0000024;
const MAX_DIRECTORIES: usize = 64;
const MAX_ENTRIES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub name: String,
    pub object_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Directory {
    pub path: String,
    /// Every direct child must be represented, including non-section objects.
    pub entries: Vec<Entry>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("Invalid or unsupported object directory snapshot: {0}")]
    Invalid(&'static str),
    #[error("Object directory is not owned: {0}")]
    UnknownDirectory(String),
    #[error("Object lookup requires bounded absolute ASCII components")]
    UnsupportedPath,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum SectionLookup {
    Failure {
        status: u32,
    },
    /// Existence proves neither requested access nor a usable section handle.
    Present {
        path: String,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct Namespace {
    directories: BTreeMap<String, BTreeMap<String, String>>,
}

fn component(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name
            .bytes()
            .all(|b| (0x20..=0x7e).contains(&b) && b != b'\\')
}

fn components(path: &str) -> Result<Vec<&str>, Error> {
    if path == "\\" {
        return Ok(Vec::new());
    }
    if path.len() > 4096 || !path.starts_with('\\') {
        return Err(Error::UnsupportedPath);
    }
    let result: Vec<_> = path[1..].split('\\').collect();
    if result.iter().any(|part| !component(part)) {
        return Err(Error::UnsupportedPath);
    }
    Ok(result)
}

impl Namespace {
    /// Snapshots are closed direct-child inventories, never prefix allowlists.
    /// ASCII case-fold collisions are rejected, even for case-sensitive calls.
    pub fn new(snapshots: Vec<Directory>) -> Result<Self, Error> {
        if snapshots.is_empty() || snapshots.len() > MAX_DIRECTORIES {
            return Err(Error::Invalid("directory count"));
        }
        let mut directories = BTreeMap::new();
        let mut total = 0usize;
        for snapshot in snapshots {
            components(&snapshot.path)?;
            total = total.saturating_add(snapshot.entries.len());
            if total > MAX_ENTRIES {
                return Err(Error::Invalid("entry count"));
            }
            let mut entries = BTreeMap::new();
            let mut folded = std::collections::BTreeSet::new();
            for entry in snapshot.entries {
                if !component(&entry.name) || !component(&entry.object_type) {
                    return Err(Error::Invalid("name or type"));
                }
                if !folded.insert(entry.name.to_ascii_lowercase()) {
                    return Err(Error::Invalid("ambiguous child name"));
                }
                entries.insert(entry.name, entry.object_type);
            }
            if directories
                .keys()
                .any(|path: &String| path.eq_ignore_ascii_case(&snapshot.path))
            {
                return Err(Error::Invalid("duplicate directory"));
            }
            directories.insert(snapshot.path, entries);
        }
        if !directories.contains_key("\\") {
            return Err(Error::Invalid("root inventory required"));
        }
        // A child inventory must agree with every enumerated ancestor. Do not
        // silently create a directory omitted from its parent's closed list.
        for path in directories.keys().filter(|path| path.as_str() != "\\") {
            let split = path.rfind('\\').unwrap();
            let parent = if split == 0 { "\\" } else { &path[..split] };
            let name = &path[split + 1..];
            let valid = directories
                .get(parent)
                .and_then(|entries| entries.get(name))
                .is_some_and(|kind| kind == "Directory");
            if !valid {
                return Err(Error::Invalid("unowned or inconsistent parent"));
            }
        }
        Ok(Self { directories })
    }

    pub fn section(&self, name: &str, insensitive: bool) -> Result<SectionLookup, Error> {
        let parts = components(name)?;
        let mut parent = "\\".to_owned();
        if parts.is_empty() {
            return Ok(SectionLookup::Failure {
                status: TYPE_MISMATCH,
            });
        }
        for (index, part) in parts.iter().enumerate() {
            let last = index + 1 == parts.len();
            let entries = self
                .directories
                .get(&parent)
                .ok_or_else(|| Error::UnknownDirectory(parent.clone()))?;
            let found = if insensitive {
                entries
                    .iter()
                    .find(|(key, _)| key.eq_ignore_ascii_case(part))
            } else {
                entries.get_key_value(*part)
            };
            let Some((actual, kind)) = found else {
                return Ok(SectionLookup::Failure {
                    status: if last { NAME_NOT_FOUND } else { PATH_NOT_FOUND },
                });
            };
            if parent != "\\" {
                parent.push('\\');
            }
            parent.push_str(actual);
            if last {
                return Ok(if kind == "Section" {
                    SectionLookup::Present { path: parent }
                } else {
                    SectionLookup::Failure {
                        status: TYPE_MISMATCH,
                    }
                });
            }
            // Symbolic-link reparsing and traversing other object types need
            // independent semantics; do not invent a Windows failure status.
            if kind != "Directory" {
                return Err(Error::UnknownDirectory(parent));
            }
        }
        unreachable!("nonempty component list returns at its final element")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn directory(path: &str, entries: &[(&str, &str)]) -> Directory {
        Directory {
            path: path.into(),
            entries: entries
                .iter()
                .map(|(name, kind)| Entry {
                    name: (*name).into(),
                    object_type: (*kind).into(),
                })
                .collect(),
        }
    }
    fn owned() -> Namespace {
        Namespace::new(vec![
            directory(
                "\\",
                &[
                    ("Device", "Directory"),
                    ("Unknown", "Directory"),
                    ("Alias", "SymbolicLink"),
                ],
            ),
            directory("\\Device", &[("Existing", "Section"), ("Disk", "Device")]),
        ])
        .unwrap()
    }
    #[test]
    fn section_absence_distinguishes_name_path_and_wrong_type_against_native_oracle() {
        let native: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/native_section_lookup.json"
        ))
        .unwrap();
        for row in native["cases"].as_array().unwrap() {
            let got = owned()
                .section(row["name"].as_str().unwrap(), true)
                .unwrap();
            assert_eq!(
                got,
                SectionLookup::Failure {
                    status: row["status"].as_u64().unwrap() as u32,
                }
            );
            assert_eq!(row["output_is_null"], true);
        }
    }
    #[test]
    fn namespace_does_not_treat_unobserved_children_or_links_as_empty() {
        for name in ["\\Unknown\\Missing", "\\Alias\\Missing"] {
            assert!(matches!(
                owned().section(name, true),
                Err(Error::UnknownDirectory(_))
            ));
        }
        assert_eq!(
            owned().section("\\Device\\Existing", true).unwrap(),
            SectionLookup::Present {
                path: "\\Device\\Existing".into()
            }
        );
        assert_eq!(
            owned().section("\\device\\existing", true).unwrap(),
            SectionLookup::Present {
                path: "\\Device\\Existing".into()
            }
        );
        assert_eq!(
            owned().section("\\device\\existing", false).unwrap(),
            SectionLookup::Failure {
                status: PATH_NOT_FOUND
            }
        );
        assert_eq!(
            owned().section("\\Device\\Disk", true).unwrap(),
            SectionLookup::Failure {
                status: TYPE_MISMATCH
            }
        );
    }
    #[test]
    fn namespace_rejects_ambiguous_inconsistent_and_unbounded_inventories() {
        for snapshots in [
            vec![],
            vec![directory("\\Device", &[])],
            vec![directory("\\", &[]), directory("\\Device", &[])],
            vec![directory("\\", &[("A", "Section"), ("a", "Section")])],
            vec![directory("\\", &[]), directory("\\", &[])],
            vec![directory("\\", &[("Bad\\Name", "Section")])],
            vec![directory("\\", &[("A", "")])],
            vec![directory("\\", &[]); MAX_DIRECTORIES + 1],
        ] {
            assert!(Namespace::new(snapshots).is_err());
        }
        for name in [
            "",
            "relative",
            "\\Device\\",
            "\\Device\\\\leaf",
            "\\Device\\\0",
            "\\Device\\é",
        ] {
            assert_eq!(owned().section(name, true), Err(Error::UnsupportedPath));
        }
        let entries = (0..MAX_ENTRIES + 1)
            .map(|i| Entry {
                name: format!("Item{i}"),
                object_type: "Section".into(),
            })
            .collect();
        assert!(
            Namespace::new(vec![Directory {
                path: "\\".into(),
                entries
            }])
            .is_err()
        );
    }
}

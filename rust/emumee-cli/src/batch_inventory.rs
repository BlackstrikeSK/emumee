//! Read-only Python-batch candidate selection; never launches analysis.
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Default, Debug, PartialEq, Eq)]
pub struct Options {
    recursive: bool,
    include_dll: bool,
    include_driver: bool,
    max_samples: usize,
}

pub fn parse(mut args: impl Iterator<Item = String>) -> Result<(PathBuf, Options)> {
    let root = PathBuf::from(
        args.next()
            .context("inspect-batch-inputs requires a directory")?,
    );
    let mut options = Options {
        max_samples: 1000,
        ..Options::default()
    };
    let mut seen_limit = false;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--recursive" => {
                ensure!(!options.recursive, "--recursive given twice");
                options.recursive = true;
            }
            "--include-dll" => {
                ensure!(!options.include_dll, "--include-dll given twice");
                options.include_dll = true;
            }
            "--include-driver" => {
                ensure!(!options.include_driver, "--include-driver given twice");
                options.include_driver = true;
            }
            "--max-samples" => {
                ensure!(!seen_limit, "--max-samples given twice");
                seen_limit = true;
                options.max_samples = args
                    .next()
                    .context("--max-samples needs a value")?
                    .parse()
                    .context("--max-samples must be an integer")?;
                ensure!(
                    (1..=1000).contains(&options.max_samples),
                    "--max-samples must be 1..1000"
                );
            }
            _ => bail!("Unknown batch inventory option: {flag}"),
        }
    }
    Ok((root, options))
}

fn selected(path: &Path, options: &Options) -> bool {
    let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
        return false;
    };
    ["exe", "scr", "com", "msi", "msp", "mst"]
        .iter()
        .any(|item| extension.eq_ignore_ascii_case(item))
        || (options.include_driver && extension.eq_ignore_ascii_case("sys"))
        || (options.include_dll
            && ["dll", "ocx", "cpl", "ax"]
                .iter()
                .any(|item| extension.eq_ignore_ascii_case(item)))
}

#[cfg(windows)]
pub fn inspect(root: &Path, options: &Options) -> Result<Value> {
    use serde_json::json;
    use std::os::windows::fs::MetadataExt;

    const REPARSE_POINT: u32 = 0x400;
    const MAX_ENTRIES: usize = 4096;
    const MAX_DIRECTORIES: usize = 1024;

    let root = std::path::absolute(root).context("Invalid batch inventory root")?;
    let meta = std::fs::symlink_metadata(&root).context("Batch inventory root unavailable")?;
    ensure!(
        meta.is_dir() && meta.file_attributes() & REPARSE_POINT == 0,
        "Batch inventory root must be an ordinary directory"
    );

    let mut pending = vec![root.clone()];
    let mut scanned_entries = 0usize;
    let mut scanned_directories = 0usize;
    let mut candidates = Vec::new();
    while let Some(directory) = pending.pop() {
        scanned_directories += 1;
        ensure!(
            scanned_directories <= MAX_DIRECTORIES,
            "Batch inventory directory limit exceeded"
        );
        for entry in std::fs::read_dir(&directory).context("Cannot enumerate batch directory")? {
            scanned_entries += 1;
            ensure!(
                scanned_entries <= MAX_ENTRIES,
                "Batch inventory entry limit exceeded"
            );
            let entry = entry?;
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path)?;
            if meta.file_attributes() & REPARSE_POINT != 0 {
                continue;
            }
            if meta.is_dir() {
                if options.recursive {
                    pending.push(path);
                    ensure!(
                        pending.len() + scanned_directories <= MAX_DIRECTORIES,
                        "Batch inventory directory limit exceeded"
                    );
                }
                continue;
            }
            if !meta.is_file() || !selected(&path, options) {
                continue;
            }
            let relative = path
                .strip_prefix(&root)
                .context("Batch path escaped root")?;
            let relative = relative
                .to_str()
                .context("Batch candidate path is not Unicode")?;
            candidates.push((relative.replace('\\', "/"), meta.len()));
            ensure!(
                candidates.len() <= options.max_samples,
                "Batch inventory sample limit exceeded"
            );
        }
    }
    ensure!(
        !candidates.is_empty(),
        "Batch directory contains no matching PE or MSI inputs"
    );
    candidates.sort_unstable_by(|left, right| {
        left.0
            .to_lowercase()
            .cmp(&right.0.to_lowercase())
            .then_with(|| left.0.cmp(&right.0))
    });
    let sample_count = candidates.len();
    let samples = candidates
        .into_iter()
        .map(|(relative_path, observed_size_bytes)| {
            json!({"relative_path":relative_path,"observed_size_bytes":observed_size_bytes,
               "input_bytes_verified":false})
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "version":1,"kind":"batch_input_inventory","sample_count":sample_count,
        "samples":samples,"scanned_entries":scanned_entries,
        "scanned_directories":scanned_directories,
        "recursive":options.recursive,"include_dll":options.include_dll,
        "include_driver":options.include_driver,"max_samples":options.max_samples,
        "input_bytes_verified":false,"execution_authorized":false,
        "reports_generated":false,
        "scope":"Read-only metadata inventory; candidates are not admitted, executed, or reported"
    }))
}

#[cfg(not(windows))]
pub fn inspect(root: &Path, options: &Options) -> Result<Value> {
    let _ = (root, options);
    bail!("Batch inventory requires Windows filesystem checks")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn option_bounds_and_duplicate_refusals() {
        let (root, options) = parse(
            [
                "fixtures",
                "--recursive",
                "--include-driver",
                "--max-samples",
                "7",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(root, PathBuf::from("fixtures"));
        assert!(options.recursive && options.include_driver);
        assert_eq!(options.max_samples, 7);
        for flags in [
            vec!["fixtures", "--max-samples", "0"],
            vec!["fixtures", "--max-samples", "1001"],
            vec!["fixtures", "--recursive", "--recursive"],
            vec!["fixtures", "--all-pe"],
        ] {
            assert!(parse(flags.into_iter().map(str::to_owned)).is_err());
        }
    }

    #[test]
    fn extension_selection_matches_bounded_default_and_opt_ins() {
        let ordinary = Options {
            max_samples: 1000,
            ..Options::default()
        };
        assert!(selected(Path::new("x.EXE"), &ordinary));
        assert!(selected(Path::new("x.mSt"), &ordinary));
        assert!(!selected(Path::new("x.sys"), &ordinary));
        assert!(!selected(Path::new("x.dll"), &ordinary));
        assert!(!selected(Path::new("x.ps1"), &ordinary));
        let expanded = Options {
            include_driver: true,
            include_dll: true,
            ..ordinary
        };
        assert!(selected(Path::new("x.SYS"), &expanded));
        assert!(selected(Path::new("x.OcX"), &expanded));
    }

    #[cfg(windows)]
    #[test]
    fn generated_directory_inventory_is_selection_only() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "emumee-batch-inventory-{}-{stamp}",
            std::process::id()
        ));
        let nested = root.join("nested");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(root.join("main.EXE"), b"fixture").unwrap();
        std::fs::write(root.join("driver.sys"), b"fixture").unwrap();
        std::fs::write(nested.join("companion.dll"), b"fixture").unwrap();
        std::fs::write(nested.join("ignore.ps1"), b"fixture").unwrap();
        let ordinary = Options {
            max_samples: 1000,
            ..Options::default()
        };
        let shallow = inspect(&root, &ordinary).unwrap();
        assert_eq!(shallow["sample_count"], 1);
        assert_eq!(shallow["samples"][0]["relative_path"], "main.EXE");
        assert_eq!(shallow["input_bytes_verified"], false);
        assert_eq!(shallow["execution_authorized"], false);
        let expanded = Options {
            recursive: true,
            include_dll: true,
            include_driver: true,
            max_samples: 3,
        };
        let result = inspect(&root, &expanded).unwrap();
        assert_eq!(result["sample_count"], 3);
        assert_eq!(result["samples"][0]["relative_path"], "driver.sys");
        assert_eq!(result["samples"][1]["relative_path"], "main.EXE");
        assert_eq!(
            result["samples"][2]["relative_path"],
            "nested/companion.dll"
        );
        assert_eq!(result["reports_generated"], false);
        assert!(
            inspect(
                &root,
                &Options {
                    max_samples: 2,
                    ..expanded
                }
            )
            .is_err()
        );
        std::fs::remove_file(root.join("main.EXE")).unwrap();
        std::fs::remove_file(root.join("driver.sys")).unwrap();
        std::fs::remove_file(nested.join("companion.dll")).unwrap();
        std::fs::remove_file(nested.join("ignore.ps1")).unwrap();
        std::fs::remove_dir(&nested).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }
}

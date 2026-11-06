use anyhow::{Context, Result, ensure};
use emumee_core::{report_bundle::digest, user_input::*};
use emumee_platform::windows::read_regular_locked;
use serde::Deserialize;
use std::io::Write;
use std::path::{Path, PathBuf};

pub(super) fn publish(
    root: &Path,
    input: &[u8],
    request: &[u8],
    persona: Option<&[u8]>,
    payloads: &[Vec<u8>],
) -> Result<()> {
    publish_with(root, input, request, persona, payloads, || Ok(()))
}

fn publish_with(
    root: &Path,
    input: &[u8],
    request: &[u8],
    persona: Option<&[u8]>,
    payloads: &[Vec<u8>],
    mut before_write: impl FnMut() -> Result<()>,
) -> Result<()> {
    std::fs::create_dir(root).context("Output directory must be new")?;
    let mut directories = vec![root.to_path_buf()];
    let mut created = Vec::new();
    let staged = (|| -> Result<()> {
        let worker = root.join("worker");
        std::fs::create_dir(&worker)?;
        directories.push(worker);
        if !payloads.is_empty() {
            let inputs = root.join("inputs");
            std::fs::create_dir(&inputs)?;
            directories.push(inputs);
        }
        let mut files = payloads
            .iter()
            .enumerate()
            .map(|(index, bytes)| (staged_name(index), bytes.as_slice()))
            .collect::<Vec<_>>();
        files.extend([("input.pe".into(), input), ("request.json".into(), request)]);
        if let Some(persona) = persona {
            files.push(("persona.json".into(), persona));
        }
        for (name, bytes) in files {
            let path = root.join(name);
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            created.push(path);
            before_write()?;
            file.write_all(bytes)?;
            file.sync_all()?;
        }
        Ok(())
    })();
    if let Err(error) = staged {
        let mut failures = Vec::new();
        for path in created.iter().rev() {
            if let Err(rollback) = std::fs::remove_file(path) {
                failures.push(format!("{}: {rollback}", path.display()));
            }
        }
        for path in directories.iter().rev() {
            if let Err(rollback) = std::fs::remove_dir(path) {
                failures.push(format!("{}: {rollback}", path.display()));
            }
        }
        ensure!(
            failures.is_empty(),
            "Submitted staging failed: {error:#}; rollback failed: {}",
            failures.join("; ")
        );
        return Err(error.context("Submitted staging rolled back"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_rolls_back_every_partial_write_without_deleting_existing_outputs() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("emumee-staging-{}-{nonce}", std::process::id()));
        let payloads = vec![b"companion".to_vec(), vec![]];
        for fail_at in 0..5 {
            let mut written = 0;
            let result = publish_with(
                &root,
                b"primary",
                b"request",
                Some(b"persona"),
                &payloads,
                || {
                    ensure!(written != fail_at, "injected staging write failure");
                    written += 1;
                    Ok(())
                },
            );
            assert!(format!("{:#}", result.unwrap_err()).contains("rolled back"));
            assert!(!root.exists());
        }
        publish(&root, b"primary", b"request", Some(b"persona"), &payloads).unwrap();
        assert!(publish(&root, b"other", b"other", None, &[]).is_err());
        assert_eq!(std::fs::read(root.join("input.pe")).unwrap(), b"primary");
        for name in [
            "input.pe",
            "request.json",
            "persona.json",
            "inputs/0000.bin",
            "inputs/0001.bin",
        ] {
            std::fs::remove_file(root.join(name)).unwrap();
        }
        for name in ["inputs", "worker"] {
            std::fs::remove_dir(root.join(name)).unwrap();
        }
        std::fs::remove_dir(root).unwrap();
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Specification {
    pub schema: u32,
    #[serde(default)]
    pub files: Vec<Source>,
    #[serde(default)]
    pub invocation: Invocation,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Source {
    pub kind: InputKind,
    pub source: PathBuf,
    pub guest_path: String,
}

pub(super) fn capture(path: Option<&Path>) -> Result<(Vec<StagedFile>, Vec<Vec<u8>>, Invocation)> {
    let Some(path) = path else {
        return Ok((vec![], vec![], Invocation::default()));
    };
    let specification: Specification =
        serde_json::from_slice(&read_regular_locked(path, MAX_REQUEST, None)?)?;
    ensure!(
        specification.schema == 1 && specification.files.len() <= MAX_STAGED_FILES,
        "Invalid submitted input specification schema/count"
    );
    let mut catalog = Vec::new();
    let mut payloads = Vec::new();
    let mut remaining = MAX_STAGED_TOTAL;
    let parent = path.parent().context("Input specification parent absent")?;
    for source in specification.files {
        ensure!(
            guest_path_valid(&source.guest_path),
            "Invalid submitted guest path"
        );
        let host = if source.source.is_absolute() {
            source.source
        } else {
            parent.join(source.source)
        };
        let bytes = read_regular_locked(
            &host,
            (MAX_STAGED_FILE as u64).min(remaining) as usize,
            None,
        )?;
        remaining = remaining
            .checked_sub(bytes.len() as u64)
            .context("Submitted input byte quota")?;
        catalog.push(StagedFile {
            kind: source.kind,
            guest_path: source.guest_path,
            size: bytes.len() as u64,
            sha256: digest(&bytes),
        });
        payloads.push(bytes);
    }
    Ok((catalog, payloads, specification.invocation))
}

pub(super) fn read_staged(root: &Path, request: &Request) -> Result<Vec<Vec<u8>>> {
    emumee_platform::windows::read_submitted_slots(
        root,
        &request
            .staged
            .iter()
            .map(|file| file.size)
            .collect::<Vec<_>>(),
    )
}

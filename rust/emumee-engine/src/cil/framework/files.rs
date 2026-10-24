//! Guest-only .NET Framework4 file operations, using the shared VFS/capture rules.
use super::{Heap, Value, units};
use crate::cil::{ArrayKind, Arrays};
use anyhow::{Result, anyhow, bail, ensure};
use emumee_core::{
    artifacts::{ArtifactCatalog, ArtifactKind},
    filesystem::{FileError, VirtualFileSystem},
};
use serde::Serialize;
const OWNER: u64 = 1024;
#[derive(Debug, Serialize)]
pub struct Evidence {
    pub guest_path_preview: String,
    pub path_truncated: bool,
    pub size: usize,
}
#[derive(Debug, Default, Serialize)]
pub struct Summary {
    pub files: usize,
    pub empty_files: usize,
    pub evidence: Vec<Evidence>,
    pub omitted_evidence: usize,
}
#[derive(Default)]
pub(super) struct Files {
    fs: VirtualFileSystem,
    summary: Summary,
    captures: ArtifactCatalog,
}
fn file_error(error: FileError) -> anyhow::Error {
    let label = match error.win32 {
        2 => "System.IO.FileNotFoundException",
        3 => "System.IO.DirectoryNotFoundException",
        5 => "System.UnauthorizedAccessException",
        123 => "System.ArgumentException",
        50 => return anyhow!("Unmodeled managed file behavior: {error}"),
        4 | 8 => return anyhow!("Managed file model resource limit: {error}"),
        _ => "System.IO.IOException",
    };
    anyhow!("{label}; {error}; managed exception dispatch is not yet modeled")
}
fn path(heap: &Heap, value: Value) -> Result<String> {
    ensure!(
        value != Value::Null,
        "System.ArgumentNullException: path; managed exception dispatch is not yet modeled"
    );
    let text = units(heap, value, false)?;
    ensure!(
        !text.is_empty() && !text.contains(&0),
        "System.ArgumentException: path; managed exception dispatch is not yet modeled"
    );
    ensure!(
        text.len() <= 32768,
        "Managed file path length limit exceeded"
    );
    ensure!(
        text.iter().all(|u| *u < 128),
        "Non-ASCII managed file paths require the Unicode filesystem profile"
    );
    String::from_utf16(text).map_err(|_| anyhow!("Unmodeled managed file path encoding"))
}
impl Files {
    pub fn write(&mut self, heap: &Heap, arrays: &Arrays, name: Value, bytes: Value) -> Result<()> {
        let name = path(heap, name)?;
        let reference = match bytes {
            Value::ArrayRef {
                reference,
                element: ArrayKind::U1,
            } => reference,
            Value::Null => bail!(
                "System.ArgumentNullException: bytes; managed exception dispatch is not yet modeled"
            ),
            _ => bail!("WriteAllBytes requires byte[]"),
        };
        let bytes = arrays.bytes(reference)?;
        let canonical = self.fs.path(&name).map_err(file_error)?;
        let (handle, _) = self
            .fs
            .open(&name, 0x40000000, 1, 2, OWNER)
            .map_err(file_error)?;
        let written = self.fs.write(handle, OWNER, bytes).map_err(file_error);
        let closed = self.fs.close(handle, OWNER).map_err(file_error);
        ensure!(written? == bytes.len(), "Managed file write was incomplete");
        closed?;
        self.captures.add(
            bytes.to_vec(),
            ArtifactKind::GuestFile,
            "managed_write_all_bytes",
            &canonical,
        );
        Ok(())
    }
    pub fn read(&mut self, heap: &Heap, arrays: &mut Arrays, name: Value) -> Result<Value> {
        let name = path(heap, name)?;
        let (handle, _) = self
            .fs
            .open(&name, 0x80000000, 1, 3, OWNER)
            .map_err(file_error)?;
        let data = (|| {
            let size = self.fs.size(handle, OWNER).map_err(file_error)? as usize;
            arrays.ensure_byte_capacity(size)?;
            self.fs.read(handle, OWNER, size).map_err(file_error)
        })();
        let closed = self.fs.close(handle, OWNER).map_err(file_error);
        let data = data?;
        closed?;
        arrays.allocate_bytes(data)
    }
    pub fn exists(&self, heap: &Heap, name: Value) -> Result<bool> {
        if name == Value::Null {
            return Ok(false);
        }
        let text = units(heap, name, false)?;
        if text.is_empty() || text.contains(&0) || text.len() > 32768 {
            return Ok(false);
        }
        self.fs.exists(&path(heap, name)?).map_err(file_error)
    }
    pub fn capture(&mut self) -> ArtifactCatalog {
        for (path, data) in std::mem::take(&mut self.fs).into_files() {
            self.summary.files += 1;
            self.summary.empty_files += usize::from(data.is_empty());
            if self.summary.evidence.len() < 64 {
                self.summary.evidence.push(Evidence {
                    guest_path_preview: path.chars().take(256).collect(),
                    path_truncated: path.chars().count() > 256,
                    size: data.len(),
                });
            } else {
                self.summary.omitted_evidence += 1;
            }
            self.captures.add(
                data,
                ArtifactKind::GuestFile,
                "managed_virtual_file_at_stop",
                &path,
            );
        }
        std::mem::take(&mut self.captures)
    }
    pub fn describe(self) -> Summary {
        self.summary
    }
}

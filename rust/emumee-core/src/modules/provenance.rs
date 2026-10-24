//! Explicit guest path declarations paired with immutable accepted PE headers.
//! Neither a guest path nor a module basename is ever resolved on the host.
use super::*;
use crate::persona::Encoding;
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModuleOrigin {
    OwnedGenerated,
    ConfiguredGuest,
    GuestFile,
    SubmittedDriver,
    SyntheticProvider,
}
#[derive(Clone, Debug, Serialize)]
pub struct ModuleProvenance {
    pub guest_path: String,
    pub path_bytes: Vec<u8>,
    pub basename_offset: u16,
    pub origin: ModuleOrigin,
    pub accepted_headers: crate::pe::AcceptedHeaders,
    pub accepted_image_sha256: String,
}
impl ModuleProvenance {
    pub(super) fn new(name: &str, path: &str, origin: ModuleOrigin, pe: &PeImage) -> Result<Self> {
        let b = path.as_bytes();
        if b.len() < 4
            || !b[0].is_ascii_alphabetic()
            || b[1] != b':'
            || b[2] != b'\\'
            || path
                .chars()
                .any(|c| c < ' ' || matches!(c, '\0' | '/' | '*' | '?' | '"' | '<' | '>' | '|'))
        {
            return Err(ModuleError(
                "module guest path is outside the declared DOS path profile",
            ));
        }
        if path[3..]
            .split('\\')
            .any(|part| part.is_empty() || part == "." || part == ".." || part.contains(':'))
        {
            return Err(ModuleError(
                "module guest path has an unsupported component",
            ));
        }
        let filename = path
            .rsplit('\\')
            .next()
            .ok_or(ModuleError("module guest path lacks basename"))?;
        if !filename.eq_ignore_ascii_case(name) {
            return Err(ModuleError(
                "module guest path disagrees with catalog basename",
            ));
        }
        // Legacy byte layout uses the configured ANSI profile with replacement.
        // Retain the original declaration as provenance rather than pretending
        // a lossy path is a different authoritative module or a host pathname.
        let path_bytes = Encoding::Cp1252.encode(path, false);
        if path_bytes.is_empty()
            || path.encode_utf16().count() > 32767
            || path_bytes.len() > 32767
            || path_bytes.contains(&0)
        {
            return Err(ModuleError(
                "module guest path exceeds bounded declared path profile",
            ));
        }
        let basename_offset = path_bytes
            .iter()
            .rposition(|b| *b == b'\\')
            .map_or(0, |i| i + 1) as u16;
        Ok(Self {
            guest_path: path.into(),
            path_bytes,
            basename_offset,
            origin,
            accepted_headers: pe.accepted_headers(),
            accepted_image_sha256: pe.sample.sha256.clone(),
        })
    }
}

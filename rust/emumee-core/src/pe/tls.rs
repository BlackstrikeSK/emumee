//! Checked callback-only TLS directory plans. Thread TLS storage is not modeled.
use super::*;
pub const MAX_TLS_CALLBACKS: usize = 100;
#[derive(Debug, Error)]
#[error("TLS {kind}: {reason}")]
pub struct TlsError {
    pub kind: &'static str,
    pub reason: &'static str,
}
type TlsResult<T> = std::result::Result<T, TlsError>;
impl From<PeError> for TlsError {
    fn from(error: PeError) -> Self {
        Self {
            kind: "descriptor",
            reason: error.0,
        }
    }
}
fn malformed(reason: &'static str) -> TlsError {
    TlsError {
        kind: "descriptor",
        reason,
    }
}
fn unsupported(reason: &'static str) -> TlsError {
    TlsError {
        kind: "profile unsupported",
        reason,
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct TlsCallbackPlan {
    pub directory_rva: Option<u32>,
    pub callbacks_rva: Option<u32>,
    pub callback_rvas: Vec<u32>,
    architecture: Architecture,
}
#[derive(Clone, Debug)]
pub struct TlsMirrorCheck {
    pub rva: u32,
    pub expected: Vec<u8>,
}
impl TlsCallbackPlan {
    pub fn architecture(&self) -> Architecture {
        self.architecture
    }
    /// Expected relocated bytes, never a write/fixup operation. The adapter must
    /// compare them with actual protected guest images before invocation.
    pub fn mirror_checks(&self, actual_base: u64) -> TlsResult<Vec<TlsMirrorCheck>> {
        if self.callback_rvas.len() > MAX_TLS_CALLBACKS
            || self.callbacks_rva.is_none() && !self.callback_rvas.is_empty()
            || self.directory_rva.is_none() && self.callbacks_rva.is_some()
        {
            return Err(malformed("inconsistent or excessive TLS callback plan"));
        }
        let Some(directory) = self.directory_rva else {
            return Ok(Vec::new());
        };
        let width = self.architecture.width();
        let mut header = vec![0; if width == 8 { 40 } else { 24 }];
        let mut result = Vec::new();
        if let Some(array) = self.callbacks_rva {
            let va = actual_base
                .checked_add(array.into())
                .ok_or_else(|| malformed("relocated callback array overflow"))?;
            if width == 4 && va > u32::MAX as u64 {
                return Err(malformed("x86 callback array exceeds pointer width"));
            }
            header[3 * width..4 * width].copy_from_slice(&va.to_le_bytes()[..width]);
            let mut pointers = Vec::with_capacity((self.callback_rvas.len() + 1) * width);
            for rva in &self.callback_rvas {
                let va = actual_base
                    .checked_add((*rva).into())
                    .ok_or_else(|| malformed("relocated callback address overflow"))?;
                if width == 4 && va > u32::MAX as u64 {
                    return Err(malformed("x86 callback exceeds pointer width"));
                }
                pointers.extend(&va.to_le_bytes()[..width]);
            }
            pointers.extend(vec![0; width]);
            result.push(TlsMirrorCheck {
                rva: array,
                expected: pointers,
            });
        }
        result.insert(
            0,
            TlsMirrorCheck {
                rva: directory,
                expected: header,
            },
        );
        Ok(result)
    }
}
impl PeImage {
    pub fn tls_callbacks_only(&self, data: &[u8]) -> TlsResult<TlsCallbackPlan> {
        if format!("{:x}", Sha256::digest(data)) != self.sample.sha256 {
            return Err(TlsError {
                kind: "identity",
                reason: "TLS bytes differ from accepted input",
            });
        }
        let mut plan = TlsCallbackPlan {
            directory_rva: None,
            callbacks_rva: None,
            callback_rvas: Vec::new(),
            architecture: self.sample.architecture,
        };
        let directory = self.directories[9];
        if directory.rva == 0 && directory.size == 0 {
            return Ok(plan);
        }
        if directory.rva == 0 || directory.size == 0 {
            return Err(malformed("incomplete TLS directory span"));
        }
        let width = self.sample.architecture.width();
        let size = if width == 8 { 40 } else { 24 };
        if directory.size < size {
            return Err(malformed("truncated TLS directory"));
        }
        if directory.size != size {
            return Err(unsupported(
                "TLS directory size is outside the exact PE32/PE32+ profile",
            ));
        }
        let header = self.rva(data, directory.rva, size as usize)?;
        let value = |offset| {
            if width == 8 {
                u64_at(header, offset)
            } else {
                u32_at(header, offset).map(u64::from)
            }
        };
        let start = value(0)?;
        let end = value(width)?;
        let index = value(2 * width)?;
        let callbacks = value(3 * width)?;
        let zero = u32_at(header, 4 * width)?;
        let characteristics = u32_at(header, 4 * width + 4)?;
        if start != 0 || end != 0 || index != 0 || zero != 0 || characteristics != 0 {
            return Err(unsupported(
                "TLS template/index/zero-fill/characteristics require actual user-thread storage authority",
            ));
        }
        plan.directory_rva = Some(directory.rva);
        if callbacks == 0 {
            return Ok(plan);
        }
        let preferred = self.accepted_headers.preferred_base;
        let array = callbacks
            .checked_sub(preferred)
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n < self.image_size)
            .ok_or_else(|| malformed("TLS callback array is outside accepted image"))?;
        plan.callbacks_rva = Some(array);
        for ordinal in 0..=MAX_TLS_CALLBACKS {
            let at = array
                .checked_add((ordinal * width) as u32)
                .ok_or_else(|| malformed("TLS callback array arithmetic"))?;
            let raw = self.rva(data, at, width)?;
            let address = if width == 8 {
                u64_at(raw, 0)?
            } else {
                u32_at(raw, 0)? as u64
            };
            if address == 0 {
                return Ok(plan);
            }
            if ordinal == MAX_TLS_CALLBACKS {
                return Err(unsupported("TLS callback count exceeds100"));
            }
            let rva = address
                .checked_sub(preferred)
                .and_then(|n| u32::try_from(n).ok())
                .filter(|n| *n > 0 && *n < self.image_size)
                .ok_or_else(|| malformed("TLS callback is outside accepted image"))?;
            if !self.sections.iter().any(|s| {
                s.characteristics & 0x20000000 != 0
                    && rva >= s.rva
                    && (rva as u64) < s.rva as u64 + s.virtual_size.max(s.raw_size) as u64
            }) {
                return Err(malformed(
                    "TLS callback is not in an executable guest section",
                ));
            }
            plan.callback_rvas.push(rva);
        }
        Err(malformed("unterminated TLS callback array"))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn write(data: &mut [u8], at: usize, value: u32) {
        data[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn image(architecture: Architecture) -> Vec<u8> {
        let mut data = crate::fixtures::counted_driver(architecture, 1);
        let wide = architecture == Architecture::X64;
        let dd = 0x98 + if wide { 112 } else { 96 };
        write(&mut data, dd + 9 * 8, 0x2100);
        write(&mut data, dd + 9 * 8 + 4, if wide { 40 } else { 24 });
        let base = if wide { 0x140000000u64 } else { 0x400000 };
        let width = architecture.width();
        let array = base + 0x2180;
        data[0x500 + 3 * width..0x500 + 4 * width].copy_from_slice(&array.to_le_bytes()[..width]);
        data[0x580..0x580 + width].copy_from_slice(&(base + 0x1000).to_le_bytes()[..width]);
        data
    }
    #[test]
    fn callback_only_descriptors_have_checked_rvas_and_actual_relocated_mirror_expectations() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let data = image(architecture);
            let pe = PeImage::parse(&data, "owned.sys").unwrap();
            let plan = pe.tls_callbacks_only(&data).unwrap();
            assert_eq!(plan.callback_rvas, [0x1000]);
            let base = pe.image_base + 0x200000;
            let checks = plan.mirror_checks(base).unwrap();
            assert_eq!(checks.len(), 2);
            let width = architecture.width();
            assert_eq!(
                &checks[0].expected[3 * width..4 * width],
                &(base + 0x2180).to_le_bytes()[..width]
            );
            assert_eq!(
                &checks[1].expected[..width],
                &(base + 0x1000).to_le_bytes()[..width]
            );
            assert_eq!(&checks[1].expected[width..], &[0; 8][..width]);
        }
    }
    #[test]
    fn storage_fields_pointer_widths_and_callback_permissions_are_explicit_before_any_guest_call() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let width = architecture.width();
            for offset in [0, width, 2 * width, 4 * width, 4 * width + 4] {
                let mut data = image(architecture);
                data[0x500 + offset] = 1;
                let pe = PeImage::parse(&data, "owned.sys").unwrap();
                assert!(
                    pe.tls_callbacks_only(&data)
                        .unwrap_err()
                        .reason
                        .contains("actual user-thread")
                );
            }
            let mut data = image(architecture);
            let base = if width == 8 { 0x140000000u64 } else { 0x400000 };
            data[0x580..0x580 + width].copy_from_slice(&(base + 0x2000).to_le_bytes()[..width]);
            let pe = PeImage::parse(&data, "owned.sys").unwrap();
            assert!(
                pe.tls_callbacks_only(&data)
                    .unwrap_err()
                    .reason
                    .contains("executable")
            );
            let data = image(architecture);
            let pe = PeImage::parse(&data, "owned.sys").unwrap();
            let mut wrong = data;
            wrong[0x500] ^= 1;
            assert_eq!(pe.tls_callbacks_only(&wrong).unwrap_err().kind, "identity");
        }
        let plan = TlsCallbackPlan {
            directory_rva: Some(0x2100),
            callbacks_rva: Some(0x2180),
            callback_rvas: vec![0x1000],
            architecture: Architecture::X86,
        };
        assert!(plan.mirror_checks(u32::MAX as u64).is_err());
    }
}

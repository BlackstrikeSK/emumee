//! Raw counted UTF16 plans for the bounded kernel RTL profile. No allocator,
//! Unicode normalization, host address or host string conversion occurs here.
use crate::pe::Architecture;
use thiserror::Error;
pub const STATUS_INVALID_PARAMETER: u32 = 0xc000000d;
pub const STATUS_NO_MEMORY: u32 = 0xc0000017;
pub const MAX_BYTES: usize = 65534;
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
#[error("Kernel RTL Unicode: {0}")]
pub struct UnicodeError(pub &'static str);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counted {
    pub length: u16,
    pub maximum: u16,
    pub buffer: u64,
}
pub fn descriptor_size(arch: Architecture) -> usize {
    if arch == Architecture::X64 { 16 } else { 8 }
}
impl Counted {
    pub fn decode(arch: Architecture, bytes: &[u8]) -> Result<Self, UnicodeError> {
        if bytes.len() != descriptor_size(arch) {
            return Err(UnicodeError("descriptor size"));
        }
        let width = arch.width();
        let mut buffer = [0; 8];
        let offset = if width == 8 { 8 } else { 4 };
        buffer[..width].copy_from_slice(&bytes[offset..offset + width]);
        Ok(Self {
            length: u16::from_le_bytes(bytes[..2].try_into().unwrap()),
            maximum: u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
            buffer: u64::from_le_bytes(buffer),
        })
    }
    pub fn encode(self, arch: Architecture) -> Result<Vec<u8>, UnicodeError> {
        if arch == Architecture::X86 && self.buffer > u32::MAX as u64 {
            return Err(UnicodeError("x86 pointer overflow"));
        }
        let width = arch.width();
        let mut bytes = vec![0; descriptor_size(arch)];
        bytes[..2].copy_from_slice(&self.length.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.maximum.to_le_bytes());
        let offset = if width == 8 { 8 } else { 4 };
        bytes[offset..offset + width].copy_from_slice(&self.buffer.to_le_bytes()[..width]);
        Ok(bytes)
    }
    pub fn validate(self) -> Result<(), UnicodeError> {
        if self.length > self.maximum
            || self.length % 2 != 0
            || self.maximum % 2 != 0
            || self.length != 0 && self.buffer == 0
        {
            return Err(UnicodeError("invalid counted length/maximum/buffer"));
        }
        Ok(())
    }
    pub fn zero() -> Self {
        Self {
            length: 0,
            maximum: 0,
            buffer: 0,
        }
    }
}
/// The borrowed source is already scanned through its first terminating unit.
/// The units exclude NUL and may include unpaired UTF16 surrogates.
pub fn initialize(source: u64, units: &[u16]) -> Result<Counted, UnicodeError> {
    if source == 0 {
        if units.is_empty() {
            return Ok(Counted::zero());
        }
        return Err(UnicodeError("null source with contents"));
    }
    let length = units
        .len()
        .checked_mul(2)
        .ok_or(UnicodeError("source length overflow"))?;
    let maximum = length
        .checked_add(2)
        .filter(|n| *n <= MAX_BYTES)
        .ok_or(UnicodeError("source exceeds counted UTF16 bound"))?;
    if units.contains(&0) {
        return Err(UnicodeError("initializer received embedded terminator"));
    }
    Ok(Counted {
        length: length as u16,
        maximum: maximum as u16,
        buffer: source,
    })
}
pub fn flags_supported(flags: u32) -> bool {
    matches!(flags, 0 | 1 | 3)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Duplicate {
    pub length: u16,
    pub maximum: u16,
    pub payload: Vec<u8>,
}
/// Status-invalid cases remain pure errors. Engine checks flags before reading
/// descriptors, then captures exactly Length bytes and preflights all outputs.
pub fn duplicate_size(flags: u32, source: Counted) -> Result<usize, UnicodeError> {
    if !flags_supported(flags) {
        return Err(UnicodeError("invalid duplicate flags"));
    }
    source.validate()?;
    let allocate = source.length != 0 || flags == 3;
    let maximum = if allocate {
        source.length as usize + if flags & 1 != 0 { 2 } else { 0 }
    } else {
        0
    };
    if maximum > MAX_BYTES {
        return Err(UnicodeError("terminated duplicate exceeds USHORT capacity"));
    }
    Ok(maximum)
}
pub fn duplicate(flags: u32, source: Counted, bytes: &[u8]) -> Result<Duplicate, UnicodeError> {
    if !flags_supported(flags) {
        return Err(UnicodeError("invalid duplicate flags"));
    }
    source.validate()?;
    if bytes.len() != source.length as usize {
        return Err(UnicodeError("source byte count mismatch"));
    }
    let allocate = !bytes.is_empty() || flags == 3;
    let maximum = duplicate_size(flags, source)?;
    let mut payload = bytes.to_vec();
    if allocate && flags & 1 != 0 {
        payload.extend([0, 0]);
    }
    Ok(Duplicate {
        length: source.length,
        maximum: maximum as u16,
        payload,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn counted_descriptors_preserve_raw_units_fullwidth_pointer_and_padding() {
        for arch in [Architecture::X86, Architecture::X64] {
            let pointer = if arch == Architecture::X64 {
                0xffffb00000000000
            } else {
                0xe0000000
            };
            let init = initialize(pointer, &[0xd83d, 0xde00, 0xd800]).unwrap();
            assert_eq!((init.length, init.maximum), (6, 8));
            let bytes = init.encode(arch).unwrap();
            assert_eq!(Counted::decode(arch, &bytes).unwrap(), init);
            if arch == Architecture::X64 {
                assert_eq!(&bytes[4..8], &[0; 4]);
            }
            assert_eq!(initialize(0, &[]).unwrap(), Counted::zero());
            assert_eq!(initialize(pointer, &[]).unwrap().maximum, 2);
        }
        assert!(initialize(1, &vec![1; 32767]).is_err());
        assert!(
            Counted {
                length: 0,
                maximum: 0,
                buffer: u64::MAX
            }
            .encode(Architecture::X86)
            .is_err()
        );
    }
    #[test]
    fn duplicate_flags_empty_termination_and_counted_embedded_nul_are_exact() {
        for flags in 0..=4 {
            for data in [vec![], vec![0, 0, 0, 0xd8, 0x42, 0]] {
                let source = Counted {
                    length: data.len() as u16,
                    maximum: data.len() as u16,
                    buffer: if data.is_empty() { 0 } else { 1 },
                };
                let plan = duplicate(flags, source, &data);
                if !flags_supported(flags) {
                    assert!(plan.is_err());
                    continue;
                }
                let plan = plan.unwrap();
                let allocate = !data.is_empty() || flags == 3;
                let mut expected = data.clone();
                if allocate && flags & 1 != 0 {
                    expected.extend([0, 0]);
                }
                assert_eq!(plan.payload, expected);
                assert_eq!(plan.maximum as usize, expected.len());
                assert_eq!(plan.length as usize, data.len());
            }
        }
    }
    #[test]
    fn malformed_counted_inputs_and_termination_overflow_have_no_effect_plan() {
        for value in [
            Counted {
                length: 3,
                maximum: 4,
                buffer: 1,
            },
            Counted {
                length: 4,
                maximum: 2,
                buffer: 1,
            },
            Counted {
                length: 2,
                maximum: 3,
                buffer: 1,
            },
            Counted {
                length: 2,
                maximum: 2,
                buffer: 0,
            },
        ] {
            assert!(duplicate(0, value, &[0; 2]).is_err());
        }
        let max = Counted {
            length: 65534,
            maximum: 65534,
            buffer: 1,
        };
        assert!(duplicate(0, max, &vec![0; 65534]).is_ok());
        assert!(duplicate(1, max, &vec![0; 65534]).is_err());
        assert!(duplicate(0, Counted::zero(), &[0, 0]).is_err());
    }
}

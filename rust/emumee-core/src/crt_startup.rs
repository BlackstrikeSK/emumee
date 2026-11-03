//! Bounded CRT pointer-array layouts. Addresses always refer to guest memory.
use crate::{pe::Architecture, persona::Encoding};
pub const MAX_STRINGS: usize = 256;
pub const MAX_BYTES: usize = 1024 * 1024;
pub const MAX_INITIALIZERS: u64 = 128;

pub struct StringArray {
    width: usize,
    strings: Vec<Vec<u8>>,
    size: usize,
}
impl StringArray {
    pub fn new(arch: Architecture, values: &[String], wide: bool) -> Result<Self, &'static str> {
        if values.len() > MAX_STRINGS {
            return Err("CRT startup string count exceeds bound");
        }
        let encoding = if wide {
            Encoding::Utf16
        } else {
            Encoding::Cp1252
        };
        let mut strings = Vec::new();
        let width = arch.width();
        let mut size = (values.len() + 1) * width;
        for value in values {
            if value.contains('\0') || value.len() > MAX_BYTES {
                return Err("Invalid CRT startup string");
            }
            let bytes = encoding.encode(value, true);
            size = size
                .checked_add(bytes.len())
                .filter(|n| *n <= MAX_BYTES)
                .ok_or("CRT startup bytes exceed bound")?;
            strings.push(bytes);
        }
        Ok(Self {
            width,
            strings,
            size,
        })
    }
    pub fn size(&self) -> usize {
        self.size
    }
    pub fn materialize(&self, base: u64) -> Result<Vec<u8>, &'static str> {
        let end = base
            .checked_add(self.size as u64)
            .ok_or("CRT pointer overflow")?;
        if base == 0 || self.width == 4 && end > u32::MAX as u64 + 1 {
            return Err("CRT pointer outside guest width");
        }
        let mut bytes = vec![0; self.size];
        let mut cursor = (self.strings.len() + 1) * self.width;
        for (index, string) in self.strings.iter().enumerate() {
            bytes[index * self.width..(index + 1) * self.width]
                .copy_from_slice(&(base + cursor as u64).to_le_bytes()[..self.width]);
            bytes[cursor..cursor + string.len()].copy_from_slice(string);
            cursor += string.len();
        }
        Ok(bytes)
    }
}

pub fn initializer_count(arch: Architecture, begin: u64, end: u64) -> Result<u64, &'static str> {
    let width = arch.width() as u64;
    let bytes = end
        .checked_sub(begin)
        .ok_or("Reversed CRT initializer range")?;
    if begin % width != 0
        || end % width != 0
        || bytes / width > MAX_INITIALIZERS
        || arch == Architecture::X86 && end > u32::MAX as u64
    {
        return Err("Unaligned/oversized CRT initializer range");
    }
    Ok(bytes / width)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn crt_startup_arrays_preserve_units_pointers_and_null_sentinel() {
        for arch in [Architecture::X86, Architecture::X64] {
            for wide in [false, true] {
                let layout =
                    StringArray::new(arch, &["a".into(), "é😀".into(), "".into()], wide).unwrap();
                let data = layout.materialize(0x10000).unwrap();
                let w = arch.width();
                let mut p = [0; 8];
                p[..w].copy_from_slice(&data[..w]);
                assert_eq!(u64::from_le_bytes(p), 0x10000 + 4 * w as u64);
                assert!(data[3 * w..4 * w].iter().all(|b| *b == 0));
                let expected = if wide {
                    Encoding::Utf16
                } else {
                    Encoding::Cp1252
                }
                .encode("é😀", true);
                let at = 4 * w + if wide { 4 } else { 2 };
                assert_eq!(&data[at..at + expected.len()], expected);
                assert!(layout.materialize(u64::MAX).is_err());
            }
        }
        assert!(StringArray::new(Architecture::X86, &["x".repeat(MAX_BYTES)], true).is_err());
        assert!(StringArray::new(Architecture::X86, &vec![String::new(); 257], false).is_err());
        assert!(StringArray::new(Architecture::X86, &["a\0b".into()], false).is_err());
    }
    #[test]
    fn crt_initializer_ranges_are_bounded_and_pointer_aligned() {
        for arch in [Architecture::X86, Architecture::X64] {
            let w = arch.width() as u64;
            assert_eq!(initializer_count(arch, 0, 0), Ok(0));
            assert_eq!(initializer_count(arch, 0x1000, 0x1000 + 128 * w), Ok(128));
            assert!(initializer_count(arch, 0x1000, 0x1000 + 129 * w).is_err());
            assert!(initializer_count(arch, 0x1001, 0x1001 + w).is_err());
            assert!(initializer_count(arch, 0x1000, 0).is_err());
        }
    }
}

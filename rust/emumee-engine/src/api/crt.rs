//! Byte/code-unit CRT models. No host libc, locale or guest pointer conversion.
use super::*;
const STRING_UNITS: u64 = 65536;
#[derive(Clone, Copy)]
pub(super) enum Call {
    Copy { wide: bool, overlap: bool },
    Fill { wide: bool },
    Compare { wide: bool },
    Length { wide: bool, bounded: bool },
    StringCompare { wide: bool, bounded: bool },
    StringCopy { wide: bool, bounded: bool },
    MemoryFind { wide: bool },
    StringFind { wide: bool, reverse: bool },
}
pub(super) fn definition(name: &str) -> Option<(Call, usize, T)> {
    let wide = name.starts_with('w');
    Some(match name {
        "memcpy" | "wmemcpy" => (
            Call::Copy {
                wide,
                overlap: false,
            },
            3,
            T::Pointer,
        ),
        "memmove" | "wmemmove" => (
            Call::Copy {
                wide,
                overlap: true,
            },
            3,
            T::Pointer,
        ),
        "memset" | "wmemset" => (Call::Fill { wide }, 3, T::Pointer),
        "memcmp" | "wmemcmp" => (Call::Compare { wide }, 3, T::U32),
        "memchr" | "wmemchr" => (Call::MemoryFind { wide }, 3, T::Pointer),
        "strcpy" | "wcscpy" => (
            Call::StringCopy {
                wide,
                bounded: false,
            },
            2,
            T::Pointer,
        ),
        "strncpy" | "wcsncpy" => (
            Call::StringCopy {
                wide,
                bounded: true,
            },
            3,
            T::Pointer,
        ),
        "strlen" | "wcslen" => (
            Call::Length {
                wide,
                bounded: false,
            },
            1,
            T::Pointer,
        ),
        "strnlen" | "wcsnlen" => (
            Call::Length {
                wide,
                bounded: true,
            },
            2,
            T::Pointer,
        ),
        "strcmp" | "wcscmp" => (
            Call::StringCompare {
                wide,
                bounded: false,
            },
            2,
            T::U32,
        ),
        "strncmp" | "wcsncmp" => (
            Call::StringCompare {
                wide,
                bounded: true,
            },
            3,
            T::U32,
        ),
        "strchr" | "wcschr" => (
            Call::StringFind {
                wide,
                reverse: false,
            },
            2,
            T::Pointer,
        ),
        "strrchr" | "wcsrchr" => (
            Call::StringFind {
                wide,
                reverse: true,
            },
            2,
            T::Pointer,
        ),
        _ => return None,
    })
}
fn width(wide: bool) -> u64 {
    if wide { 2 } else { 1 }
}
fn count(value: u64, wide: bool) -> Result<u64> {
    value
        .checked_mul(width(wide))
        .filter(|n| *n <= MAX_TRANSFER)
        .ok_or_else(|| anyhow::anyhow!("CRT transfer count overflow or bound"))
}
fn pointer(address: u64, offset: u64) -> Result<u64> {
    address
        .checked_add(offset)
        .ok_or_else(|| anyhow::anyhow!("CRT pointer overflow"))
}
fn unit(bytes: &[u8]) -> u16 {
    if bytes.len() == 1 {
        bytes[0] as u16
    } else {
        u16::from_le_bytes([bytes[0], bytes[1]])
    }
}
fn difference(a: u16, b: u16) -> u64 {
    (a as i32 - b as i32) as u32 as u64
}
struct Cursor {
    next: u64,
    wide: bool,
    data: Vec<u8>,
    at: usize,
    remaining: Option<u64>,
}
impl Cursor {
    fn new(address: u64, wide: bool) -> Self {
        Self {
            next: address,
            wide,
            data: vec![],
            at: 0,
            remaining: None,
        }
    }
    fn bounded(address: u64, wide: bool, units: u64) -> Self {
        let mut cursor = Self::new(address, wide);
        cursor.remaining = Some(units * width(wide));
        cursor
    }
    fn take(&mut self, engine: &Unicorn<Trace>) -> Result<u16> {
        let width = width(self.wide) as usize;
        if self.at == self.data.len() {
            let left = 4096 - self.next % 4096;
            let mut length = left.min(256) as usize;
            if self.wide {
                length &= !1;
            }
            if length == 0 {
                length = width;
            }
            if let Some(remaining) = self.remaining.as_mut() {
                // The page-edge cap above prevents a read of the next page
                // before its first unit is actually requested.
                length = length.min(*remaining as usize);
                ensure!(length >= width, "CRT string cursor exceeded modeled bound");
                *remaining -= length as u64;
            }
            self.data = read(engine, self.next, length as u64)?;
            self.next = pointer(self.next, length as u64)?;
            self.at = 0;
        }
        let value = unit(&self.data[self.at..self.at + width]);
        self.at += width;
        Ok(value)
    }
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    match call {
        Call::Copy { wide, overlap } => {
            let size = count(args[2], wide)?;
            if size != 0 {
                let end = pointer(args[0], size)?;
                let source_end = pointer(args[1], size)?;
                ensure!(
                    overlap || !(args[0] < source_end && args[1] < end),
                    "CRT memcpy overlapping regions are outside its defined profile; use memmove"
                );
                require(engine, args[0], size, P::WRITE)?;
                let bytes = read(engine, args[1], size)?;
                crate::cpu::write(engine, args[0], &bytes)?;
            }
            Ok(args[0])
        }
        Call::Fill { wide } => {
            let size = count(args[2], wide)?;
            require(engine, args[0], size, P::WRITE)?;
            if size != 0 {
                let bytes = if wide {
                    let value = (args[1] as u16).to_le_bytes();
                    let mut bytes = vec![0; size as usize];
                    for chunk in bytes.chunks_exact_mut(2) {
                        chunk.copy_from_slice(&value);
                    }
                    bytes
                } else {
                    vec![args[1] as u8; size as usize]
                };
                crate::cpu::write(engine, args[0], &bytes)?;
            }
            Ok(args[0])
        }
        Call::Compare { wide } => {
            let size = count(args[2], wide)?;
            let left = read(engine, args[0], size)?;
            let right = read(engine, args[1], size)?;
            Ok(left
                .chunks_exact(width(wide) as usize)
                .zip(right.chunks_exact(width(wide) as usize))
                .find_map(|(a, b)| {
                    let a = unit(a);
                    let b = unit(b);
                    (a != b).then(|| difference(a, b))
                })
                .unwrap_or(0))
        }
        Call::StringCopy { wide, bounded } => {
            ensure!(
                args[0] != 0 && args[1] != 0 && (!bounded || args[2] != 0),
                "CRT string copy invalid-parameter dispatch is not modeled"
            );
            let maximum = if bounded { args[2] } else { STRING_UNITS };
            let destination_size = if bounded {
                Some(count(maximum, wide)?)
            } else {
                None
            };
            let mut cursor = Cursor::new(args[1], wide);
            let mut data = Vec::new();
            let mut terminated = false;
            for _ in 0..maximum.min(STRING_UNITS) {
                let value = cursor.take(engine)?;
                if wide {
                    data.extend(value.to_le_bytes());
                } else {
                    data.push(value as u8);
                }
                if value == 0 {
                    terminated = true;
                    break;
                }
            }
            ensure!(
                terminated || (bounded && maximum <= STRING_UNITS),
                "CRT string copy exceeded the modeled scan bound"
            );
            let source_end = pointer(args[1], data.len() as u64)?;
            if let Some(size) = destination_size {
                data.resize(size as usize, 0);
            }
            let end = pointer(args[0], data.len() as u64)?;
            ensure!(
                !(args[0] < source_end && args[1] < end),
                "CRT string copy overlapping regions are outside its defined profile"
            );
            require(engine, args[0], data.len() as u64, P::WRITE)?;
            crate::cpu::write(engine, args[0], &data)?;
            Ok(args[0])
        }
        Call::MemoryFind { wide } => {
            let size = count(args[2], wide)?;
            let bytes = read(engine, args[0], size)?;
            let wanted = if wide {
                args[1] as u16
            } else {
                args[1] as u8 as u16
            };
            match bytes
                .chunks_exact(width(wide) as usize)
                .position(|v| unit(v) == wanted)
            {
                Some(index) => pointer(args[0], index as u64 * width(wide)),
                None => Ok(0),
            }
        }
        Call::Length { wide, bounded } => {
            let maximum = if bounded { args[1] } else { STRING_UNITS };
            let mut cursor = if bounded {
                Cursor::bounded(args[0], wide, maximum.min(STRING_UNITS))
            } else {
                Cursor::new(args[0], wide)
            };
            for n in 0..maximum.min(STRING_UNITS) {
                if cursor.take(engine)? == 0 {
                    return Ok(n);
                }
            }
            ensure!(
                bounded && maximum <= STRING_UNITS,
                "CRT string is not terminated within the modeled bound"
            );
            Ok(maximum)
        }
        Call::StringCompare { wide, bounded } => {
            let maximum = if bounded { args[2] } else { STRING_UNITS };
            let mut left = Cursor::new(args[0], wide);
            let mut right = Cursor::new(args[1], wide);
            for _ in 0..maximum.min(STRING_UNITS) {
                let a = left.take(engine)?;
                let b = right.take(engine)?;
                if a != b {
                    return Ok(difference(a, b));
                }
                if a == 0 {
                    return Ok(0);
                }
            }
            ensure!(
                bounded && maximum <= STRING_UNITS,
                "CRT comparison exceeded the modeled string bound"
            );
            Ok(0)
        }
        Call::StringFind { wide, reverse } => {
            let wanted = if wide {
                args[1] as u16
            } else {
                args[1] as u8 as u16
            };
            let mut cursor = Cursor::new(args[0], wide);
            let mut found = 0;
            for index in 0..STRING_UNITS {
                let value = cursor.take(engine)?;
                if value == wanted {
                    found = pointer(args[0], index * width(wide))?;
                    if !reverse || value == 0 {
                        return Ok(found);
                    }
                }
                if value == 0 {
                    return Ok(found);
                }
            }
            bail!("CRT search exceeded the modeled string bound")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_length_reads_only_requested_guest_units() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut engine = crate::new_engine(arch).unwrap();
            engine.get_data_mut().apis.target(arch, false).unwrap();
            engine
                .get_data_mut()
                .apis
                .memory
                .map(0x10000, 4096, P::RW, Some(4), "bounded CRT test")
                .unwrap();
            engine
                .mem_map(0x10000, 4096, Prot::READ | Prot::WRITE)
                .unwrap();
            engine.mem_write(0x10100, b"AB").unwrap();
            let mut cursor = Cursor::bounded(0x10100, false, 1);
            assert_eq!(cursor.take(&engine).unwrap(), u16::from(b'A'));
            assert_eq!(cursor.data.len(), 1);
            assert_eq!(cursor.remaining, Some(0));
            assert!(cursor.take(&engine).is_err());
            assert_eq!(
                invoke(
                    &mut engine,
                    &[0x10100, 1],
                    Call::Length {
                        wide: false,
                        bounded: true,
                    }
                )
                .unwrap(),
                1
            );
            // The next page is unmapped. A terminator at this page's edge
            // must stop the scan even when max_count extends past the edge.
            assert!(!engine.get_data().apis.memory.allows(0x11000, 1, P::READ));
            engine.mem_write(0x10ffe, b"A\0").unwrap();
            assert_eq!(
                invoke(
                    &mut engine,
                    &[0x10ffe, 32],
                    Call::Length {
                        wide: false,
                        bounded: true,
                    }
                )
                .unwrap(),
                1
            );
            assert_eq!(
                invoke(
                    &mut engine,
                    &[0x10fff, 32],
                    Call::Length {
                        wide: false,
                        bounded: true,
                    }
                )
                .unwrap(),
                0
            );
        }
    }
}

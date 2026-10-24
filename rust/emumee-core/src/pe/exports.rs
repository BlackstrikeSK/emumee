//! Bounded PE export directory and forwarder decoding.
use super::*;
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExportTarget {
    Address { rva: u32 },
    Forwarder { module: String, symbol: ImportName },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Export {
    pub ordinal: u32,
    pub names: Vec<String>,
    pub target: ExportTarget,
}
impl PeImage {
    pub(super) fn parse_exports(&mut self, data: &[u8]) -> Result<()> {
        let directory = self.directories[0];
        if directory.rva == 0 {
            return Ok(());
        }
        if directory.size < 40 {
            return Err(PeError("truncated export directory"));
        }
        let header = self.rva(data, directory.rva, 40)?;
        let ordinal_base = u32_at(header, 16)?;
        let functions = u32_at(header, 20)? as usize;
        let names = u32_at(header, 24)? as usize;
        if functions > 65536 || names > 65536 || (functions == 0 && names != 0) {
            return Err(PeError("export count exceeds bound"));
        }
        if functions == 0 {
            return Ok(());
        }
        ordinal_base
            .checked_add(functions as u32 - 1)
            .ok_or(PeError("export ordinal overflow"))?;
        let addresses = self.rva(data, u32_at(header, 28)?, functions * 4)?;
        let mut aliases = vec![Vec::new(); functions];
        if names != 0 {
            let pointers = self.rva(data, u32_at(header, 32)?, names * 4)?;
            let ordinals = self.rva(data, u32_at(header, 36)?, names * 2)?;
            let mut seen = BTreeSet::new();
            for index in 0..names {
                let slot = u16_at(ordinals, index * 2)? as usize;
                if slot >= functions {
                    return Err(PeError("export name ordinal exceeds table"));
                }
                let name = self.ascii(data, u32_at(pointers, index * 4)?)?;
                if name.is_empty() || !seen.insert(name.clone()) {
                    return Err(PeError("empty or duplicate export name"));
                }
                aliases[slot].push(name);
            }
        }
        let end = directory
            .rva
            .checked_add(directory.size)
            .ok_or(PeError("export directory overflow"))?;
        for (index, names) in aliases.into_iter().enumerate() {
            let rva = u32_at(addresses, index * 4)?;
            if rva == 0 {
                if !names.is_empty() {
                    return Err(PeError("named export points to an empty address"));
                }
                continue;
            }
            if rva >= self.image_size {
                return Err(PeError("export target exceeds image"));
            }
            let target = if rva >= directory.rva && rva < end {
                let mut raw = Vec::new();
                let mut terminated = false;
                for offset in 0..(end - rva).min(512) {
                    let byte = self.rva(data, rva + offset, 1)?[0];
                    if byte == 0 {
                        terminated = true;
                        break;
                    }
                    if !byte.is_ascii() {
                        return Err(PeError("non-ASCII export forwarder"));
                    }
                    raw.push(byte);
                }
                if !terminated {
                    return Err(PeError("unterminated export forwarder"));
                }
                let text =
                    String::from_utf8(raw).map_err(|_| PeError("invalid export forwarder"))?;
                let (module, name) = text
                    .rsplit_once('.')
                    .ok_or(PeError("export forwarder has no module"))?;
                if module.is_empty()
                    || !module
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                    || name.is_empty()
                {
                    return Err(PeError("invalid export forwarder module/name"));
                }
                let symbol = if let Some(ordinal) = name.strip_prefix('#') {
                    ImportName::Ordinal {
                        ordinal: ordinal
                            .parse()
                            .map_err(|_| PeError("invalid export forwarder ordinal"))?,
                    }
                } else {
                    ImportName::Name(name.to_owned())
                };
                ExportTarget::Forwarder {
                    module: module.to_owned(),
                    symbol,
                }
            } else {
                ExportTarget::Address { rva }
            };
            self.exports.push(Export {
                ordinal: ordinal_base + index as u32,
                names,
                target,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::counted_driver;
    fn put(data: &mut [u8], at: usize, value: u32) {
        data[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn fixture(arch: Architecture) -> Vec<u8> {
        let mut data = counted_driver(arch, 1);
        let dd = 0x98 + if arch == Architecture::X64 { 112 } else { 96 };
        put(&mut data, dd, 0x2000);
        put(&mut data, dd + 4, 0x100);
        for (at, value) in [
            (0x410, 7),
            (0x414, 3),
            (0x418, 2),
            (0x41c, 0x2040),
            (0x420, 0x2050),
            (0x424, 0x2060),
            (0x440, 0x1000),
            (0x444, 0),
            (0x448, 0x2080),
            (0x450, 0x20a0),
            (0x454, 0x20b0),
        ] {
            put(&mut data, at, value);
        }
        data[0x462..0x464].copy_from_slice(&2u16.to_le_bytes());
        data[0x480..0x48d].copy_from_slice(b"kernel32.#17\0");
        data[0x4a0..0x4a6].copy_from_slice(b"Alpha\0");
        data[0x4b0..0x4b5].copy_from_slice(b"Beta\0");
        data
    }
    #[test]
    fn named_ordinal_holes_and_forwarded_exports_are_distinct() {
        for arch in [Architecture::X86, Architecture::X64] {
            let pe = PeImage::parse(&fixture(arch), "exports.dll").unwrap();
            assert_eq!(pe.exports.len(), 2);
            assert_eq!(pe.exports[0].ordinal, 7);
            assert_eq!(pe.exports[0].names, vec!["Alpha"]);
            assert_eq!(pe.exports[0].target, ExportTarget::Address { rva: 0x1000 });
            assert_eq!(pe.exports[1].ordinal, 9);
            assert_eq!(
                pe.exports[1].target,
                ExportTarget::Forwarder {
                    module: "kernel32".to_owned(),
                    symbol: ImportName::Ordinal { ordinal: 17 }
                }
            );
        }
    }
    #[test]
    fn malformed_exports_do_not_escape_table_bounds() {
        for (at, value) in [
            (0x414, 65537),
            (0x410, u32::MAX),
            (0x41c, 0x2fff),
            (0x448, 0x3000),
            (0x454, 0x20a0),
        ] {
            let mut data = fixture(Architecture::X64);
            put(&mut data, at, value);
            assert!(PeImage::parse(&data, "bad.dll").is_err());
        }
        let mut data = fixture(Architecture::X86);
        data[0x462..0x464].copy_from_slice(&3u16.to_le_bytes());
        assert!(PeImage::parse(&data, "bad.dll").is_err());
        let mut data = fixture(Architecture::X86);
        data[0x480..0x500].fill(b'A');
        assert!(PeImage::parse(&data, "bad.dll").is_err());
    }
}

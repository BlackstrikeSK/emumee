//! Bounded ECMA-335 method exception-section descriptors, without EH execution.
//! Layout reference: dotnet/runtime src/coreclr/inc/corhdr.h, CorILMethodSect.
use super::*;

pub const MAX_EXCEPTION_SECTIONS: usize = 16;
pub const MAX_EXCEPTION_CLAUSES: usize = 1024;
pub const MAX_EXCEPTION_SECTION_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExceptionKind {
    Catch { type_token: u32 },
    Finally,
    Fault,
    Filter { offset: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExceptionClause {
    pub section_rva: u32,
    pub clause_index: u32,
    pub try_offset: u32,
    pub try_length: u32,
    pub handler_offset: u32,
    pub handler_length: u32,
    pub kind: ExceptionKind,
}

fn align4(value: u32) -> Result<u32> {
    value
        .checked_add(3)
        .map(|v| v & !3)
        .ok_or(ManagedError("exception section alignment overflow"))
}

fn checked_region(offset: u32, length: u32, code_size: u32) -> Result<u32> {
    let end = offset
        .checked_add(length)
        .ok_or(ManagedError("exception region overflow"))?;
    if length == 0 || end > code_size {
        return Err(ManagedError("exception region outside method code"));
    }
    Ok(end)
}

impl Metadata<'_> {
    /// Reads actual file-backed sections attached to this metadata's method.
    /// This checks descriptors only. Instruction boundaries, nesting, catch-type
    /// semantics and exception dispatch require independent interpreter checks.
    pub fn exception_clauses(&self, token: u32) -> Result<Vec<ExceptionClause>> {
        let body = self.method_body(token)?;
        if !body.more_sections {
            return Ok(Vec::new());
        }
        let code_size =
            u32::try_from(body.code.len()).map_err(|_| ManagedError("method size overflow"))?;
        let code_end = body
            .code_rva
            .checked_add(code_size)
            .ok_or(ManagedError("method end overflow"))?;
        let mut at = align4(code_end)?;
        let mut bytes_seen = 0usize;
        let mut clauses = Vec::new();
        for _ in 0..MAX_EXCEPTION_SECTIONS {
            let header = self.pe.rva(self.image, at, 4)?;
            let kind = header[0];
            if kind & 0x3f != 1 {
                return Err(ManagedError("non-EH method section profile is not modeled"));
            }
            let fat = kind & 0x40 != 0;
            let size = if fat {
                u32::from_le_bytes([header[1], header[2], header[3], 0]) as usize
            } else {
                if header[2] != 0 || header[3] != 0 {
                    return Err(ManagedError("small EH section reserved bytes are nonzero"));
                }
                header[1] as usize
            };
            let stride = if fat { 24 } else { 12 };
            if size < 4 || (size - 4) % stride != 0 {
                return Err(ManagedError("invalid EH section size or clause stride"));
            }
            let count = (size - 4) / stride;
            if count == 0 {
                return Err(ManagedError(
                    "empty EH section is outside the descriptor profile",
                ));
            }
            bytes_seen = bytes_seen
                .checked_add(size)
                .ok_or(ManagedError("EH byte count overflow"))?;
            if bytes_seen > MAX_EXCEPTION_SECTION_BYTES
                || clauses
                    .len()
                    .checked_add(count)
                    .is_none_or(|n| n > MAX_EXCEPTION_CLAUSES)
            {
                return Err(ManagedError("EH descriptor count or bytes exceeds bound"));
            }
            let section = self.pe.rva(self.image, at, size)?;
            for index in 0..count {
                let raw = span(section, 4 + index * stride, stride)?;
                let (flags, try_offset, try_length, handler_offset, handler_length, extra) = if fat
                {
                    (
                        u32_at(raw, 0)?,
                        u32_at(raw, 4)?,
                        u32_at(raw, 8)?,
                        u32_at(raw, 12)?,
                        u32_at(raw, 16)?,
                        u32_at(raw, 20)?,
                    )
                } else {
                    (
                        u16_at(raw, 0)? as u32,
                        u16_at(raw, 2)? as u32,
                        raw[4] as u32,
                        u16_at(raw, 5)? as u32,
                        raw[7] as u32,
                        u32_at(raw, 8)?,
                    )
                };
                let try_end = checked_region(try_offset, try_length, code_size)?;
                let handler_end = checked_region(handler_offset, handler_length, code_size)?;
                if try_offset < handler_end && handler_offset < try_end {
                    return Err(ManagedError("EH clause try and handler overlap"));
                }
                let kind = match flags {
                    0 => {
                        let table = extra >> 24;
                        let row = extra & 0xffffff;
                        if !matches!(table, 1 | 2 | 27) || row == 0 || row > self.count(table as u8)
                        {
                            return Err(ManagedError("EH catch token is outside type metadata"));
                        }
                        ExceptionKind::Catch { type_token: extra }
                    }
                    1 => {
                        if extra >= handler_offset || extra >= code_size {
                            return Err(ManagedError(
                                "EH filter offset is outside its pre-handler range",
                            ));
                        }
                        ExceptionKind::Filter { offset: extra }
                    }
                    2 | 4 => {
                        if extra != 0 {
                            return Err(ManagedError(
                                "nonzero unused EH clause payload is outside the profile",
                            ));
                        }
                        if flags == 2 {
                            ExceptionKind::Finally
                        } else {
                            ExceptionKind::Fault
                        }
                    }
                    _ => return Err(ManagedError("unknown or extended EH clause flag profile")),
                };
                clauses.push(ExceptionClause {
                    section_rva: at,
                    clause_index: index as u32,
                    try_offset,
                    try_length,
                    handler_offset,
                    handler_length,
                    kind,
                });
            }
            if kind & 0x80 == 0 {
                return Ok(clauses);
            }
            at = align4(
                at.checked_add(size as u32)
                    .ok_or(ManagedError("EH next section overflow"))?,
            )?;
        }
        Err(ManagedError("EH section chain exceeds bound"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{fixtures::managed_probe, pe::Architecture};

    fn image(arch: Architecture, sections: &[u8]) -> Vec<u8> {
        let mut bytes = managed_probe(arch);
        // Actual fat body at RVA1000; 16 real code bytes, sections at RVA101c.
        bytes[0x200..0x20c].copy_from_slice(&[0x0b, 0x30, 8, 0, 16, 0, 0, 0, 0, 0, 0, 0]);
        bytes[0x20c..0x21c].fill(0);
        bytes[0x21c..0x21c + sections.len()].copy_from_slice(sections);
        bytes
    }
    fn small(flag: u16, extra: u32, more: bool) -> Vec<u8> {
        let mut data = vec![1 | if more { 0x80 } else { 0 }, 16, 0, 0];
        data.extend(flag.to_le_bytes());
        data.extend(0u16.to_le_bytes());
        data.push(2);
        data.extend(4u16.to_le_bytes());
        data.push(3);
        data.extend(extra.to_le_bytes());
        data
    }
    fn fat(flag: u32, extra: u32) -> Vec<u8> {
        let mut data = vec![0x41, 28, 0, 0];
        for value in [flag, 0, 2, 4, 3, extra] {
            data.extend(value.to_le_bytes());
        }
        data
    }
    #[test]
    fn small_fat_and_chained_descriptors_preserve_real_ranges_and_type_tokens() {
        for arch in [Architecture::X86, Architecture::X64] {
            for section in [small(0, 0x02000001, false), fat(0, 0x02000001)] {
                let bytes = image(arch, &section);
                let metadata = Metadata::parse(&bytes, "eh.exe").unwrap();
                let rows = metadata.exception_clauses(0x06000001).unwrap();
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].section_rva, 0x101c);
                assert_eq!(
                    rows[0].kind,
                    ExceptionKind::Catch {
                        type_token: 0x02000001
                    }
                );
                assert_eq!(
                    (
                        rows[0].try_offset,
                        rows[0].try_length,
                        rows[0].handler_offset,
                        rows[0].handler_length
                    ),
                    (0, 2, 4, 3)
                );
            }
            let mut sections = small(2, 0, true);
            sections.extend(fat(4, 0));
            let bytes = image(arch, &sections);
            let metadata = Metadata::parse(&bytes, "chain.exe").unwrap();
            let rows = metadata.exception_clauses(0x06000001).unwrap();
            assert_eq!(rows[0].kind, ExceptionKind::Finally);
            assert_eq!(rows[1].kind, ExceptionKind::Fault);
            assert_eq!(rows[1].section_rva, 0x102c);
            let bytes = image(arch, &small(1, 2, false));
            assert_eq!(
                Metadata::parse(&bytes, "filter.exe")
                    .unwrap()
                    .exception_clauses(0x06000001)
                    .unwrap()[0]
                    .kind,
                ExceptionKind::Filter { offset: 2 }
            );
            let bytes = managed_probe(arch);
            assert!(
                Metadata::parse(&bytes, "plain.exe")
                    .unwrap()
                    .exception_clauses(0x06000001)
                    .unwrap()
                    .is_empty()
            );
        }
    }
    #[test]
    fn malformed_regions_sizes_flags_tokens_and_backing_are_never_repaired() {
        for arch in [Architecture::X86, Architecture::X64] {
            let good = small(0, 0x02000001, false);
            for (offset, value) in [
                (0, 2),
                (1, 15),
                (2, 1),
                (4, 3),
                (8, 0),
                (8, 17),
                (9, 1),
                (11, 0),
                (12, 0),
                (15, 0x06),
            ] {
                let mut section = good.clone();
                section[offset] = value;
                let bytes = image(arch, &section);
                assert!(
                    Metadata::parse(&bytes, "bad.exe")
                        .unwrap()
                        .exception_clauses(0x06000001)
                        .is_err(),
                    "{arch:?} / {offset} / {value}"
                );
            }
            for section in [
                fat(0, 0x02000002),
                fat(0, 0x01000000),
                fat(8, 0),
                fat(2, 1),
                fat(1, 4),
                vec![0x41, 0xff, 0xff, 0xff],
            ] {
                let bytes = image(arch, &section);
                assert!(
                    Metadata::parse(&bytes, "bad.exe")
                        .unwrap()
                        .exception_clauses(0x06000001)
                        .is_err()
                );
            }
            let mut bytes = image(arch, &good);
            // A real PE raw section ending before the EH descriptor cannot be
            // replaced by virtual zeros, even when image bytes exist elsewhere.
            let data_section = 0x98
                + if arch == Architecture::X64 {
                    0xf0
                } else {
                    0xe0
                };
            bytes[data_section + 16..data_section + 20].copy_from_slice(&0x1cu32.to_le_bytes());
            assert!(
                Metadata::parse(&bytes, "raw-short.exe")
                    .unwrap()
                    .exception_clauses(0x06000001)
                    .is_err()
            );
        }
    }
    #[test]
    fn descriptor_work_and_rva_arithmetic_are_bounded() {
        assert!(align4(u32::MAX).is_err());
        assert!(checked_region(u32::MAX, 2, u32::MAX).is_err());
        let mut sections = Vec::new();
        for _ in 0..MAX_EXCEPTION_SECTIONS {
            sections.extend(small(2, 0, true));
        }
        let bytes = image(Architecture::X64, &sections);
        assert!(
            Metadata::parse(&bytes, "chain-limit.exe")
                .unwrap()
                .exception_clauses(0x06000001)
                .unwrap_err()
                .0
                .contains("chain exceeds")
        );
    }
}

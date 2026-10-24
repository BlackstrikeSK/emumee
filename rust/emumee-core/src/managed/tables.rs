//! ECMA-335 II.22/II.24 physical row layouts and index widths.
use super::*;
#[derive(Clone, Copy)]
enum Column {
    U16,
    U32,
    String,
    Guid,
    Blob,
    Table(u8),
    Coded(u8, &'static [u8]),
}
fn schema(id: u8) -> &'static [Column] {
    use Column::*;
    match id {
        0 => &[U16, String, Guid, Guid, Guid],
        1 => &[Coded(2, &[0, 26, 35, 1]), String, String],
        2 => &[
            U32,
            String,
            String,
            Coded(2, &[2, 1, 27]),
            Table(4),
            Table(6),
        ],
        3 => &[Table(4)],
        4 => &[U16, String, Blob],
        5 => &[Table(6)],
        6 => &[U32, U16, U16, String, Blob, Table(8)],
        7 => &[Table(8)],
        8 => &[U16, U16, String],
        9 => &[Table(2), Coded(2, &[2, 1, 27])],
        10 => &[Coded(3, &[2, 1, 26, 6, 27]), String, Blob],
        11 => &[U16, Coded(2, &[4, 8, 23]), Blob],
        12 => &[
            Coded(
                5,
                &[
                    6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43,
                ],
            ),
            Coded(3, &[6, 10]),
            Blob,
        ],
        13 => &[Coded(1, &[4, 8]), Blob],
        14 => &[U16, Coded(2, &[2, 6, 32]), Blob],
        15 => &[U16, U32, Table(2)],
        16 => &[U32, Table(4)],
        17 => &[Blob],
        18 => &[Table(2), Table(20)],
        19 => &[Table(20)],
        20 => &[U16, String, Coded(2, &[2, 1, 27])],
        21 => &[Table(2), Table(23)],
        22 => &[Table(23)],
        23 => &[U16, String, Blob],
        24 => &[U16, Table(6), Coded(1, &[20, 23])],
        25 => &[Table(2), Coded(1, &[6, 10]), Coded(1, &[6, 10])],
        26 => &[String],
        27 => &[Blob],
        28 => &[U16, Coded(1, &[4, 6]), String, Table(26)],
        29 => &[U32, Table(4)],
        30 => &[U32, U32],
        31 => &[U32],
        32 => &[U32, U16, U16, U16, U16, U32, Blob, String, String],
        33 => &[U32],
        34 => &[U32, U32, U32],
        35 => &[U16, U16, U16, U16, U32, Blob, String, String, Blob],
        36 => &[U32, Table(35)],
        37 => &[U32, U32, U32, Table(35)],
        38 => &[U32, String, Blob],
        39 => &[U32, U32, String, String, Coded(2, &[38, 35, 39])],
        40 => &[U32, U32, String, Coded(2, &[38, 35, 39])],
        41 => &[Table(2), Table(2)],
        42 => &[U16, U16, Coded(1, &[2, 6]), String],
        43 => &[Coded(1, &[6, 10]), Blob],
        44 => &[Table(42), Coded(2, &[2, 1, 27])],
        _ => &[],
    }
}
const NAMES: [&str; 45] = [
    "Module",
    "TypeRef",
    "TypeDef",
    "FieldPtr",
    "Field",
    "MethodPtr",
    "MethodDef",
    "ParamPtr",
    "Param",
    "InterfaceImpl",
    "MemberRef",
    "Constant",
    "CustomAttribute",
    "FieldMarshal",
    "DeclSecurity",
    "ClassLayout",
    "FieldLayout",
    "StandAloneSig",
    "EventMap",
    "EventPtr",
    "Event",
    "PropertyMap",
    "PropertyPtr",
    "Property",
    "MethodSemantics",
    "MethodImpl",
    "ModuleRef",
    "TypeSpec",
    "ImplMap",
    "FieldRVA",
    "ENCLog",
    "ENCMap",
    "Assembly",
    "AssemblyProcessor",
    "AssemblyOS",
    "AssemblyRef",
    "AssemblyRefProcessor",
    "AssemblyRefOS",
    "File",
    "ExportedType",
    "ManifestResource",
    "NestedClass",
    "GenericParam",
    "MethodSpec",
    "GenericParamConstraint",
];
#[derive(Clone, Copy, Debug, Serialize)]
pub struct TableInfo {
    pub id: u8,
    pub name: &'static str,
    pub rows: u32,
    pub row_size: usize,
    pub offset: usize,
}
pub(super) struct Tables<'a> {
    bytes: &'a [u8],
    counts: [u32; 45],
    info: [Option<TableInfo>; 45],
    heaps: u8,
}
fn width(column: Column, counts: &[u32; 45], heaps: u8) -> usize {
    match column {
        Column::U16 => 2,
        Column::U32 => 4,
        Column::String => {
            if heaps & 1 != 0 {
                4
            } else {
                2
            }
        }
        Column::Guid => {
            if heaps & 2 != 0 {
                4
            } else {
                2
            }
        }
        Column::Blob => {
            if heaps & 4 != 0 {
                4
            } else {
                2
            }
        }
        Column::Table(id) => {
            if counts[id as usize] >= 65536 {
                4
            } else {
                2
            }
        }
        Column::Coded(bits, ids) => {
            if ids
                .iter()
                .any(|id| counts[*id as usize] >= 1 << (16 - bits))
            {
                4
            } else {
                2
            }
        }
    }
}
impl<'a> Tables<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self> {
        span(bytes, 0, 24)?;
        if bytes[4] != 2 || bytes[5] != 0 {
            return Err(ManagedError("metadata table schema version is not modeled"));
        }
        let heaps = bytes[6];
        if heaps & !7 != 0 {
            return Err(ManagedError("metadata table heap flags are not modeled"));
        }
        let valid = u64_at(bytes, 8)?;
        if valid >> 45 != 0 {
            return Err(ManagedError(
                "metadata table mask contains unsupported tables",
            ));
        }
        let mut counts = [0; 45];
        let mut at = 24;
        let mut total = 0u64;
        for (id, count) in counts.iter_mut().enumerate() {
            if valid & (1u64 << id) != 0 {
                *count = u32_at(bytes, at)?;
                at += 4;
                total += *count as u64;
                if *count > 1_048_576 || total > 2_097_152 {
                    return Err(ManagedError("metadata row count exceeds bound"));
                }
            }
        }
        if [3, 5, 7, 19, 22].iter().any(|id| counts[*id] != 0) {
            return Err(ManagedError("metadata pointer tables are not yet modeled"));
        }
        let mut info = [None; 45];
        for (id, count) in counts.iter().enumerate() {
            if valid & (1u64 << id) == 0 {
                continue;
            }
            let row_size = schema(id as u8)
                .iter()
                .map(|column| width(*column, &counts, heaps))
                .sum();
            let extent = (*count as usize)
                .checked_mul(row_size)
                .ok_or(ManagedError("table size overflow"))?;
            span(bytes, at, extent)?;
            info[id] = Some(TableInfo {
                id: id as u8,
                name: NAMES[id],
                rows: *count,
                row_size,
                offset: at,
            });
            at += extent;
        }
        Ok(Self {
            bytes,
            counts,
            info,
            heaps,
        })
    }
    pub fn count(&self, id: u8) -> u32 {
        self.counts.get(id as usize).copied().unwrap_or(0)
    }
    pub fn describe(&self) -> Vec<TableInfo> {
        self.info.iter().flatten().copied().collect()
    }
    pub fn row(&self, id: u8, index: u32) -> Result<Vec<u32>> {
        let info = self
            .info
            .get(id as usize)
            .and_then(|i| *i)
            .ok_or(ManagedError("metadata table is absent"))?;
        if index == 0 || index > info.rows {
            return Err(ManagedError("metadata row index exceeds table"));
        }
        let mut at = info.offset + (index as usize - 1) * info.row_size;
        let mut values = Vec::with_capacity(schema(id).len());
        for column in schema(id) {
            let size = width(*column, &self.counts, self.heaps);
            values.push(if size == 2 {
                u16_at(self.bytes, at)? as u32
            } else {
                u32_at(self.bytes, at)?
            });
            at += size;
        }
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn simple_coded_and_heap_indexes_change_width_at_their_own_thresholds() {
        let mut counts = [0; 45];
        assert_eq!(width(Column::Table(6), &counts, 0), 2);
        counts[6] = 65535;
        assert_eq!(width(Column::Table(6), &counts, 0), 2);
        counts[6] = 65536;
        assert_eq!(width(Column::Table(6), &counts, 0), 4);
        counts[6] = 8191;
        assert_eq!(width(Column::Coded(3, &[6, 10]), &counts, 0), 2);
        counts[6] = 8192;
        assert_eq!(width(Column::Coded(3, &[6, 10]), &counts, 0), 4);
        assert_eq!(width(Column::String, &counts, 1), 4);
        assert_eq!(width(Column::Guid, &counts, 1), 2);
        assert_eq!(width(Column::Guid, &counts, 2), 4);
        assert_eq!(width(Column::Blob, &counts, 4), 4);
        assert!(schema(44).len() == 2 && schema(32).len() == 9);
    }
}

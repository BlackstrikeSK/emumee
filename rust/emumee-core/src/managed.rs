//! Bounded ECMA-335 metadata and method-body reading. Never loads a host CLR.
use crate::pe::{PeError, PeImage};
use serde::Serialize;
use std::{collections::BTreeMap, sync::OnceLock};
use thiserror::Error;
pub mod exceptions;
pub mod signature;
pub use exceptions::{ExceptionClause, ExceptionKind};
mod tables;
pub use tables::TableInfo;
use tables::Tables;

const MAX_METADATA: usize = 64 * 1024 * 1024;
const MAX_NAME: usize = 256 * 1024;
#[derive(Debug, Error)]
#[error("Managed metadata: {0}")]
pub struct ManagedError(pub &'static str);
impl From<PeError> for ManagedError {
    fn from(_: PeError) -> Self {
        Self("invalid PE or non-file-backed managed range")
    }
}
pub type Result<T> = std::result::Result<T, ManagedError>;
fn span(bytes: &[u8], at: usize, size: usize) -> Result<&[u8]> {
    bytes
        .get(
            at..at
                .checked_add(size)
                .ok_or(ManagedError("offset overflow"))?,
        )
        .ok_or(ManagedError("truncated structure"))
}
fn u16_at(bytes: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(span(bytes, at, 2)?.try_into().unwrap()))
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(span(bytes, at, 4)?.try_into().unwrap()))
}
fn u64_at(bytes: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(span(bytes, at, 8)?.try_into().unwrap()))
}
fn compressed(bytes: &[u8], at: usize) -> Result<(usize, usize)> {
    let first = *bytes
        .get(at)
        .ok_or(ManagedError("truncated compressed integer"))?;
    if first & 0x80 == 0 {
        Ok((first as usize, 1))
    } else if first & 0xc0 == 0x80 {
        let tail = span(bytes, at, 2)?;
        Ok((((first & 0x3f) as usize) << 8 | tail[1] as usize, 2))
    } else if first & 0xe0 == 0xc0 {
        let tail = span(bytes, at, 4)?;
        Ok((
            ((first & 0x1f) as usize) << 24
                | (tail[1] as usize) << 16
                | (tail[2] as usize) << 8
                | tail[3] as usize,
            4,
        ))
    } else {
        Err(ManagedError("invalid compressed integer prefix"))
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct StreamInfo {
    pub name: String,
    pub offset: u32,
    pub size: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct CliHeader {
    pub runtime_major: u16,
    pub runtime_minor: u16,
    pub flags: u32,
    pub entry_point: u32,
    pub native_entry_point: bool,
    pub metadata_rva: u32,
    pub metadata_size: u32,
    pub resources_rva: u32,
    pub resources_size: u32,
}
#[derive(Debug, Serialize)]
pub struct ManagedInfo {
    pub runtime_version: String,
    pub cli: CliHeader,
    pub streams: Vec<StreamInfo>,
    pub tables: Vec<TableInfo>,
    pub type_definitions: u32,
    pub methods: u32,
    pub fields: u32,
    pub assembly_name: Option<String>,
    pub scope: &'static str,
}
pub struct Metadata<'a> {
    pub pe: PeImage,
    pub cli: CliHeader,
    image: &'a [u8],
    root: &'a [u8],
    version: String,
    streams: BTreeMap<String, StreamInfo>,
    tables: Tables<'a>,
    field_index: OnceLock<Result<FieldIndex>>,
}
struct FieldIndex {
    rvas: BTreeMap<u32, u32>,
    layouts: BTreeMap<u32, (u16, u32)>,
}
#[derive(Debug)]
pub struct FieldInfo<'a> {
    pub token: u32,
    pub flags: u16,
    pub name: &'a str,
    pub signature: &'a [u8],
}
#[derive(Debug, Serialize)]
pub struct MethodInfo<'a> {
    pub token: u32,
    pub rva: u32,
    pub implementation_flags: u16,
    pub flags: u16,
    pub name: &'a str,
    pub signature: &'a [u8],
    pub first_parameter: u32,
}
/// A MemberRef whose owner is a TypeRef scoped directly to an AssemblyRef.
/// Reading identity does not resolve/load the assembly or grant it a model.
#[derive(Debug)]
pub struct ExternalMethod<'a> {
    pub token: u32,
    pub assembly: &'a str,
    pub assembly_version: [u16; 4],
    pub namespace: &'a str,
    pub type_name: &'a str,
    pub name: &'a str,
    pub signature: &'a [u8],
}
#[derive(Debug)]
pub struct ExternalType<'a> {
    pub assembly: &'a str,
    pub assembly_version: [u16; 4],
    pub namespace: &'a str,
    pub name: &'a str,
}
#[derive(Debug)]
pub struct MethodBody<'a> {
    pub code: &'a [u8],
    pub code_rva: u32,
    pub max_stack: u16,
    pub local_signature: u32,
    pub initialize_locals: bool,
    pub more_sections: bool,
}
impl<'a> Metadata<'a> {
    pub fn parse(image: &'a [u8], name: &str) -> Result<Self> {
        let pe = PeImage::parse(image, name)?;
        let directory = pe.directories[14];
        if directory.rva == 0 || directory.size < 72 {
            return Err(ManagedError("missing CLI header"));
        }
        let header = pe.rva(image, directory.rva, 72)?;
        let size = u32_at(header, 0)?;
        if size < 72 || size > directory.size || size > 4096 {
            return Err(ManagedError("CLI header size exceeds bounds"));
        }
        let metadata_rva = u32_at(header, 8)?;
        let metadata_size = u32_at(header, 12)?;
        if metadata_size == 0 || metadata_size as usize > MAX_METADATA {
            return Err(ManagedError("metadata size exceeds 64MiB"));
        }
        let root = pe.rva(image, metadata_rva, metadata_size as usize)?;
        if span(root, 0, 4)? != b"BSJB" {
            return Err(ManagedError("missing BSJB signature"));
        }
        let version_size = u32_at(root, 12)? as usize;
        if version_size == 0 || version_size > 256 || version_size % 4 != 0 {
            return Err(ManagedError("version buffer exceeds bounds or alignment"));
        }
        let version_bytes = span(root, 16, version_size)?;
        let length = version_bytes
            .iter()
            .position(|b| *b == 0)
            .ok_or(ManagedError("unterminated runtime version"))?;
        let version = std::str::from_utf8(&version_bytes[..length])
            .map_err(|_| ManagedError("runtime version is not UTF8"))?
            .to_owned();
        let mut at = 16 + version_size;
        let count = u16_at(root, at + 2)? as usize;
        at += 4;
        if count == 0 || count > 32 {
            return Err(ManagedError("stream count exceeds 32"));
        }
        let mut streams = BTreeMap::new();
        for _ in 0..count {
            let offset = u32_at(root, at)?;
            let size = u32_at(root, at + 4)?;
            let mut end = at + 8;
            while end - at - 8 <= 32
                && *root.get(end).ok_or(ManagedError("truncated stream name"))? != 0
            {
                end += 1;
            }
            if end - at - 8 > 32 || end == at + 8 {
                return Err(ManagedError("stream name exceeds bounds"));
            }
            let name = std::str::from_utf8(span(root, at + 8, end - at - 8)?)
                .map_err(|_| ManagedError("invalid stream name"))?;
            if !name.bytes().all(|b| b.is_ascii_graphic()) {
                return Err(ManagedError("invalid stream name characters"));
            }
            span(root, offset as usize, size as usize)?;
            if size != 0 && offset % 4 != 0 {
                return Err(ManagedError("unaligned stream offset"));
            }
            if streams
                .insert(
                    name.to_owned(),
                    StreamInfo {
                        name: name.into(),
                        offset,
                        size,
                    },
                )
                .is_some()
            {
                return Err(ManagedError("duplicate metadata stream"));
            }
            at = (end + 1 + 3) & !3;
            span(root, 0, at)?;
        }
        let mut ranges = streams.values().filter(|s| s.size != 0).collect::<Vec<_>>();
        ranges.sort_by_key(|s| s.offset);
        let mut end = at;
        for stream in ranges {
            if (stream.offset as usize) < end {
                return Err(ManagedError(
                    "metadata streams overlap headers or each other",
                ));
            }
            end = stream.offset as usize + stream.size as usize;
        }
        let heap = |name: &str| -> &'a [u8] {
            streams.get(name).map_or(&[], |s| {
                &root[s.offset as usize..s.offset as usize + s.size as usize]
            })
        };
        for name in ["#Strings", "#Blob", "#US"] {
            if heap(name).first().is_some_and(|b| *b != 0) {
                return Err(ManagedError("heap has no empty first entry"));
            }
        }
        if heap("#GUID").len() % 16 != 0 {
            return Err(ManagedError("GUID heap has an incomplete entry"));
        }
        if streams.contains_key("#-") {
            return Err(ManagedError(
                "unoptimized metadata stream is not yet modeled",
            ));
        }
        if !streams.contains_key("#~") {
            return Err(ManagedError("missing metadata tables stream"));
        }
        let tables = Tables::parse(heap("#~"))?;
        let flags = u32_at(header, 16)?;
        let cli = CliHeader {
            runtime_major: u16_at(header, 4)?,
            runtime_minor: u16_at(header, 6)?,
            flags,
            entry_point: u32_at(header, 20)?,
            native_entry_point: flags & 0x10 != 0,
            metadata_rva,
            metadata_size,
            resources_rva: u32_at(header, 24)?,
            resources_size: u32_at(header, 28)?,
        };
        if cli.resources_size as usize > MAX_METADATA {
            return Err(ManagedError("managed resources exceed 64MiB"));
        }
        if cli.resources_size != 0 {
            pe.rva(image, cli.resources_rva, cli.resources_size as usize)?;
        }
        if !cli.native_entry_point && cli.entry_point != 0 {
            let table = (cli.entry_point >> 24) as u8;
            if ![6, 38].contains(&table)
                || cli.entry_point & 0xffffff == 0
                || cli.entry_point & 0xffffff > tables.count(table)
            {
                return Err(ManagedError("entry token is outside MethodDef/File tables"));
            }
        }
        Ok(Self {
            pe,
            cli,
            image,
            root,
            version,
            streams,
            tables,
            field_index: OnceLock::new(),
        })
    }
    pub fn heap(&self, name: &str) -> &'a [u8] {
        self.streams.get(name).map_or(&[], |s| {
            &self.root[s.offset as usize..s.offset as usize + s.size as usize]
        })
    }
    pub fn string(&self, index: u32) -> Result<&'a str> {
        if index == 0 {
            return Ok("");
        }
        let bytes = self
            .heap("#Strings")
            .get(index as usize..)
            .ok_or(ManagedError("string index exceeds heap"))?;
        let end = bytes
            .iter()
            .take(MAX_NAME + 1)
            .position(|b| *b == 0)
            .ok_or(ManagedError(
                "metadata string is unterminated or exceeds bound",
            ))?;
        std::str::from_utf8(&bytes[..end]).map_err(|_| ManagedError("metadata string is not UTF8"))
    }
    fn heap_blob(&self, heap: &str, index: u32) -> Result<&'a [u8]> {
        if index == 0 {
            return Ok(&[]);
        }
        let bytes = self.heap(heap);
        let (size, prefix) = compressed(bytes, index as usize)?;
        span(bytes, index as usize + prefix, size)
    }
    pub fn blob(&self, index: u32) -> Result<&'a [u8]> {
        self.heap_blob("#Blob", index)
    }
    pub fn user_string(&self, index: u32) -> Result<Vec<u16>> {
        if index == 0 {
            return Ok(Vec::new());
        }
        let bytes = self.heap_blob("#US", index)?;
        if bytes.is_empty()
            || bytes.len() % 2 == 0
            || bytes.len() > 2 * 1024 * 1024 + 1
            || bytes[bytes.len() - 1] > 1
        {
            return Err(ManagedError("invalid or oversized user string"));
        }
        // System.String holds UTF16 code units, including unpaired surrogates.
        Ok(bytes[..bytes.len() - 1]
            .chunks_exact(2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect())
    }
    pub fn guid(&self, index: u32) -> Result<Option<&'a [u8]>> {
        if index == 0 {
            Ok(None)
        } else {
            span(
                self.heap("#GUID"),
                (index as usize - 1)
                    .checked_mul(16)
                    .ok_or(ManagedError("GUID index overflow"))?,
                16,
            )
            .map(Some)
        }
    }
    pub fn row(&self, table: u8, index: u32) -> Result<Vec<u32>> {
        self.tables.row(table, index)
    }
    pub fn count(&self, table: u8) -> u32 {
        self.tables.count(table)
    }
    pub fn method(&self, token: u32) -> Result<MethodInfo<'a>> {
        if token >> 24 != 6 {
            return Err(ManagedError("token is not MethodDef"));
        }
        let row = self.row(6, token & 0xffffff)?;
        Ok(MethodInfo {
            token,
            rva: row[0],
            implementation_flags: row[1] as u16,
            flags: row[2] as u16,
            name: self.string(row[3])?,
            signature: self.blob(row[4])?,
            first_parameter: row[5],
        })
    }
    pub fn field(&self, token: u32) -> Result<FieldInfo<'a>> {
        if token >> 24 != 4 {
            return Err(ManagedError("token is not FieldDef"));
        }
        let row = self.row(4, token & 0xffffff)?;
        let name = self.string(row[1])?;
        if name.len() > 256 {
            return Err(ManagedError("field identity exceeds bound"));
        }
        Ok(FieldInfo {
            token,
            flags: row[0] as u16,
            name,
            signature: self.blob(row[2])?,
        })
    }
    fn field_index(&self) -> Result<&FieldIndex> {
        let index = self.field_index.get_or_init(|| {
            if self.count(15) > 65536 || self.count(29) > 65536 {
                return Err(ManagedError("field RVA/layout index exceeds bound"));
            }
            let mut index = FieldIndex {
                rvas: BTreeMap::new(),
                layouts: BTreeMap::new(),
            };
            for at in 1..=self.count(29) {
                let row = self.row(29, at)?;
                if row[0] == 0
                    || row[1] == 0
                    || row[1] > self.count(4)
                    || index.rvas.insert(row[1], row[0]).is_some()
                {
                    return Err(ManagedError("invalid or duplicate FieldRVA row"));
                }
            }
            for at in 1..=self.count(15) {
                let row = self.row(15, at)?;
                if row[2] == 0
                    || row[2] > self.count(2)
                    || index
                        .layouts
                        .insert(row[2], (row[0] as u16, row[1]))
                        .is_some()
                {
                    return Err(ManagedError("invalid or duplicate ClassLayout row"));
                }
            }
            Ok(index)
        });
        match index {
            Ok(index) => Ok(index),
            Err(error) => Err(ManagedError(error.0)),
        }
    }
    pub fn field_rva_data(&self, token: u32, requested: usize) -> Result<&'a [u8]> {
        use signature::{FieldSignature, Type};
        let field = self.field(token)?;
        if field.flags & 0x110 != 0x110 || field.flags & 0x40 != 0 {
            return Err(ManagedError(
                "initializer requires a static non-literal RVA field",
            ));
        }
        let index = self.field_index()?;
        let rva = *index
            .rvas
            .get(&(token & 0xffffff))
            .ok_or(ManagedError("field has no FieldRVA row"))?;
        let size = match FieldSignature::parse(field.signature)?.field_type {
            Type::I1 | Type::U1 | Type::Boolean => 1,
            Type::I2 | Type::U2 | Type::Char => 2,
            Type::I4 | Type::U4 | Type::R4 => 4,
            Type::I8 | Type::U8 | Type::R8 => 8,
            Type::ValueType(ty) if ty >> 24 == 2 => {
                let rid = ty & 0xffffff;
                let row = self.row(2, rid)?;
                if !matches!(row[0] & 0x18, 0x08 | 0x10) || row[3] & 3 != 1 {
                    return Err(ManagedError("RVA value type layout/base is not modeled"));
                }
                let base = self.external_type(0x01000000 | (row[3] >> 2))?;
                if base.namespace != "System"
                    || base.name != "ValueType"
                    || base.assembly != "mscorlib"
                    || base.assembly_version != [4, 0, 0, 0]
                {
                    return Err(ManagedError("RVA value type base profile is not modeled"));
                }
                let last = if rid < self.count(2) {
                    self.row(2, rid + 1)?[4]
                } else {
                    self.count(4) + 1
                };
                if row[4] == 0 || row[4] > self.count(4) + 1 || row[4] != last {
                    return Err(ManagedError(
                        "RVA value types with member fields are not modeled",
                    ));
                }
                let (packing, size) = *index
                    .layouts
                    .get(&rid)
                    .ok_or(ManagedError("RVA value type has no ClassLayout"))?;
                if packing != 0 && (!packing.is_power_of_two() || packing > 128) {
                    return Err(ManagedError("invalid ClassLayout packing"));
                }
                size as usize
            }
            _ => return Err(ManagedError("RVA field signature type is not modeled")),
        };
        if size == 0 || size > 16 * 1024 * 1024 {
            return Err(ManagedError("RVA field storage exceeds bound"));
        }
        if requested > size {
            return Err(ManagedError(
                "array initializer exceeds declared field storage",
            ));
        }
        let data = self.pe.rva(self.image, rva, size)?;
        Ok(&data[..requested])
    }
    pub fn external_method(&self, token: u32) -> Result<ExternalMethod<'a>> {
        if token >> 24 != 10 {
            return Err(ManagedError("token is not MemberRef"));
        }
        let member = self.row(10, token & 0xffffff)?;
        if member[0] & 7 != 1 {
            return Err(ManagedError("MemberRef owner is not a modeled TypeRef"));
        }
        let owner = self.external_type(0x01000000 | (member[0] >> 3))?;
        let name = self.string(member[1])?;
        if name.len() > 256 {
            return Err(ManagedError("external method identity exceeds bound"));
        }
        Ok(ExternalMethod {
            token,
            assembly: owner.assembly,
            assembly_version: owner.assembly_version,
            namespace: owner.namespace,
            type_name: owner.name,
            name,
            signature: self.blob(member[2])?,
        })
    }
    pub fn external_type(&self, token: u32) -> Result<ExternalType<'a>> {
        if token >> 24 != 1 {
            return Err(ManagedError("token is not TypeRef"));
        }
        let owner = self.row(1, token & 0xffffff)?;
        if owner[0] & 3 != 2 {
            return Err(ManagedError(
                "TypeRef is not scoped directly to AssemblyRef",
            ));
        }
        let assembly = self.row(35, owner[0] >> 2)?;
        let names = [
            self.string(assembly[6])?,
            self.string(owner[2])?,
            self.string(owner[1])?,
        ];
        if names.iter().any(|s| s.len() > 256) {
            return Err(ManagedError("external type identity exceeds bound"));
        }
        Ok(ExternalType {
            assembly: names[0],
            namespace: names[1],
            name: names[2],
            assembly_version: [
                assembly[0] as u16,
                assembly[1] as u16,
                assembly[2] as u16,
                assembly[3] as u16,
            ],
        })
    }
    pub fn method_body(&self, token: u32) -> Result<MethodBody<'a>> {
        let method = self.method(token)?;
        if method.rva == 0
            || method.implementation_flags & 3 != 0
            || method.implementation_flags & 4 != 0
        {
            return Err(ManagedError("method has no modeled managed IL body"));
        }
        let first = self.pe.rva(self.image, method.rva, 1)?[0];
        let (header_size, size, max_stack, local_signature, initialize_locals, more_sections) =
            match first & 3 {
                2 => (1, first as u32 >> 2, 8, 0, false, false),
                3 => {
                    let header = self.pe.rva(self.image, method.rva, 12)?;
                    let flags = u16_at(header, 0)?;
                    let header_size = (flags >> 12) as u32 * 4;
                    if header_size < 12 {
                        return Err(ManagedError("fat method header is too short"));
                    }
                    self.pe.rva(self.image, method.rva, header_size as usize)?;
                    (
                        header_size,
                        u32_at(header, 4)?,
                        u16_at(header, 2)?,
                        u32_at(header, 8)?,
                        flags & 16 != 0,
                        flags & 8 != 0,
                    )
                }
                _ => return Err(ManagedError("invalid method header kind")),
            };
        if size > 1024 * 1024 || max_stack > 4096 {
            return Err(ManagedError("method code/stack exceeds bound"));
        }
        if local_signature != 0
            && (local_signature >> 24 != 17
                || local_signature & 0xffffff == 0
                || local_signature & 0xffffff > self.count(17))
        {
            return Err(ManagedError(
                "local signature token is outside StandAloneSig",
            ));
        }
        let code_rva = method
            .rva
            .checked_add(header_size)
            .ok_or(ManagedError("method RVA overflow"))?;
        let code = self.pe.rva(self.image, code_rva, size as usize)?;
        Ok(MethodBody {
            code,
            code_rva,
            max_stack,
            local_signature,
            initialize_locals,
            more_sections,
        })
    }
    pub fn describe(&self) -> Result<ManagedInfo> {
        let assembly_name = if self.count(32) > 0 {
            Some(self.string(self.row(32, 1)?[7])?.to_owned())
        } else {
            None
        };
        Ok(ManagedInfo {
            runtime_version: self.version.clone(),
            cli: self.cli.clone(),
            streams: self.streams.values().cloned().collect(),
            tables: self.tables.describe(),
            type_definitions: self.count(2),
            methods: self.count(6),
            fields: self.count(4),
            assembly_name,
            scope: "Bounded CLI header, metadata streams/heaps/tables and initial managed IL body reading. Signatures, semantic verification, exception sections and managed execution/framework parity are separate gates. No host CLR is loaded.",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checked_rva_fields_read_declared_opaque_layouts_and_preserve_encoded_input_bytes() {
        use crate::{
            fixtures::{CilFixture, cil_probe},
            pe::Architecture,
        };
        for arch in [Architecture::X86, Architecture::X64] {
            let image = cil_probe(arch, CilFixture::RvaDecode, 1);
            let metadata = Metadata::parse(&image, "generated-rva.exe").unwrap();
            assert_eq!(metadata.count(4), 1);
            assert_eq!(metadata.field(0x04000001).unwrap().flags, 0x110);
            assert_eq!(
                metadata.field_rva_data(0x04000001, 4).unwrap(),
                [8, 15, 9, 14]
            );
            assert!(
                metadata
                    .field_rva_data(0x04000001, 5)
                    .unwrap_err()
                    .0
                    .contains("declared field storage")
            );
            assert!(metadata.field_rva_data(0x04000001, 0).unwrap().is_empty());
            assert!(metadata.field(0x04000000).is_err());
            assert!(metadata.field(0x06000001).is_err());
        }
    }
    #[test]
    fn missing_field_rva_layout_flags_packing_and_backing_never_supply_invented_data() {
        use crate::{
            fixtures::{CilFixture, cil_probe},
            pe::Architecture,
        };
        for fixture in [
            CilFixture::RvaNoRva,
            CilFixture::RvaMissingRow,
            CilFixture::RvaNoLayout,
            CilFixture::RvaBadPacking,
            CilFixture::RvaTooSmall,
            CilFixture::RvaBadRva,
            CilFixture::RvaReferenceField,
            CilFixture::RvaLiteral,
        ] {
            let image = cil_probe(Architecture::X64, fixture, 1);
            let metadata = Metadata::parse(&image, "generated-bad-rva.exe").unwrap();
            assert!(
                metadata.field_rva_data(0x04000001, 4).is_err(),
                "{fixture:?}"
            );
        }
    }
    #[test]
    fn member_ref_owner_scope_and_assembly_identity_are_checked_without_loading_any_assembly() {
        use crate::{
            fixtures::{CilFixture, cil_probe},
            pe::Architecture,
        };
        for arch in [Architecture::X86, Architecture::X64] {
            let image = cil_probe(arch, CilFixture::FrameworkStrings, 1);
            let metadata = Metadata::parse(&image, "generated-framework.exe").unwrap();
            let concat = metadata.external_method(0x0a000001).unwrap();
            assert_eq!(concat.assembly, "mscorlib");
            assert_eq!(concat.assembly_version, [4, 0, 0, 0]);
            assert_eq!(
                (concat.namespace, concat.type_name, concat.name),
                ("System", "String", "Concat")
            );
            assert_eq!(concat.signature, [0, 2, 0x0e, 0x0e, 0x0e]);
            assert!(metadata.external_method(0x06000001).is_err());
            assert!(metadata.external_method(0x0a000000).is_err());
            assert!(metadata.external_method(0x0a000004).is_err());
            for (fixture, expected) in [
                (CilFixture::FrameworkBadOwner, "MemberRef owner"),
                (CilFixture::FrameworkBadScope, "AssemblyRef"),
            ] {
                let image = cil_probe(arch, fixture, 1);
                let metadata = Metadata::parse(&image, "generated-bad-reference.exe").unwrap();
                assert!(
                    metadata
                        .external_method(0x0a000001)
                        .unwrap_err()
                        .0
                        .contains(expected)
                );
            }
        }
    }
    use crate::{fixtures::managed_probe, pe::Architecture};
    #[test]
    fn cli_metadata_rows_heaps_and_tiny_body_decode_without_loading_a_runtime() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let bytes = managed_probe(architecture);
            let metadata = Metadata::parse(&bytes, "fixture.exe").unwrap();
            let info = metadata.describe().unwrap();
            assert!(metadata.pe.sample.managed);
            assert_eq!(info.runtime_version, "v4.0.30319");
            assert_eq!(info.assembly_name.as_deref(), Some("Fixture"));
            assert_eq!(
                (info.methods, info.type_definitions, info.fields),
                (1, 1, 0)
            );
            assert_eq!(metadata.method(0x06000001).unwrap().name, "Main");
            assert_eq!(metadata.method(0x06000001).unwrap().signature, &[0, 0, 8]);
            assert_eq!(
                metadata.method_body(0x06000001).unwrap().code,
                &[0x1f, 17, 0x2a]
            );
            assert_eq!(metadata.user_string(1).unwrap(), vec![72, 105]);
            assert_eq!(metadata.guid(1).unwrap().unwrap(), &[0x42; 16]);
            assert!(metadata.string(u32::MAX).is_err());
            assert!(metadata.guid(u32::MAX).is_err());
            assert!(metadata.blob(u32::MAX).is_err());
            assert!(metadata.row(6, 2).is_err());
            assert!(metadata.method(0x02000001).is_err());
        }
    }
    #[test]
    fn truncated_overlapping_duplicate_and_excessive_metadata_is_rejected() {
        let original = managed_probe(Architecture::X64);
        for end in 0..original.len() {
            assert!(Metadata::parse(&original[..end], "truncated.exe").is_err());
        }
        for (at, value) in [
            (0x40c, 64 * 1024 * 1024 + 1),
            (0x414, 0x06000002),
            (0x4a0, 0),
            (0x504, u32::MAX),
        ] {
            let mut bytes = original.clone();
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
            assert!(Metadata::parse(&bytes, "bad.exe").is_err(), "offset {at:x}");
        }
        let mut duplicate = original.clone();
        duplicate[0x4d8..0x4de].copy_from_slice(b"#Blob\0");
        assert!(Metadata::parse(&duplicate, "duplicate.exe").is_err());
    }
    #[test]
    fn fat_method_headers_and_compressed_heap_lengths_enforce_bounds() {
        let mut bytes = managed_probe(Architecture::X64);
        bytes[0x200..0x20c].copy_from_slice(&[0x13, 0x30, 8, 0, 3, 0, 0, 0, 0, 0, 0, 0]);
        bytes[0x20c..0x20f].copy_from_slice(&[0x1f, 17, 0x2a]);
        let metadata = Metadata::parse(&bytes, "fat.exe").unwrap();
        let body = metadata.method_body(0x06000001).unwrap();
        assert!(body.initialize_locals);
        assert!(!body.more_sections);
        assert_eq!(body.code_rva, 0x100c);
        assert_eq!(body.code, &[0x1f, 17, 0x2a]);
        bytes[0x204..0x208].copy_from_slice(&(1024 * 1024 + 1u32).to_le_bytes());
        assert!(
            Metadata::parse(&bytes, "large.exe")
                .unwrap()
                .method_body(0x06000001)
                .is_err()
        );
        assert_eq!(compressed(&[0x7f], 0).unwrap(), (127, 1));
        assert_eq!(compressed(&[0xbf, 0xff], 0).unwrap(), (16383, 2));
        assert_eq!(
            compressed(&[0xdf, 0xff, 0xff, 0xff], 0).unwrap(),
            (0x1fffffff, 4)
        );
        assert!(compressed(&[0x80], 0).is_err());
        assert!(compressed(&[0xe0, 0, 0, 0], 0).is_err());
    }
}

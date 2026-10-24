//! Bounded guest vectors. Typed handles never become host memory addresses.
use super::Value;
use anyhow::{Result, anyhow, bail, ensure};
use emumee_core::managed::{Metadata, signature::Type};
use serde::Serialize;
use std::{collections::BTreeMap, mem::size_of};

const MAX_OBJECTS: usize = 4096;
const MAX_ELEMENTS: usize = 1_048_576;
const MAX_BYTES: usize = 32 * 1024 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    U1,
    I4,
    String,
    Object,
}
impl Kind {
    pub fn signature(ty: &Type) -> Option<Self> {
        match ty {
            Type::U1 => Some(Self::U1),
            Type::I4 => Some(Self::I4),
            Type::String => Some(Self::String),
            Type::Object => Some(Self::Object),
            _ => None,
        }
    }
    fn bytes(self) -> usize {
        match self {
            Self::U1 => 1,
            Self::I4 => 4,
            Self::String => size_of::<Option<u32>>(),
            Self::Object => size_of::<Value>(),
        }
    }
}
enum Data {
    U1(Vec<u8>),
    I4(Vec<i32>),
    String(Vec<Option<u32>>),
    Object(Vec<Value>),
}
impl Data {
    fn len(&self) -> usize {
        match self {
            Self::U1(v) => v.len(),
            Self::I4(v) => v.len(),
            Self::String(v) => v.len(),
            Self::Object(v) => v.len(),
        }
    }
    fn value(&self, at: usize) -> Value {
        match self {
            Self::U1(v) => Value::I32(v[at] as i32),
            Self::I4(v) => Value::I32(v[at]),
            Self::String(v) => v[at].map(Value::StringRef).unwrap_or(Value::Null),
            Self::Object(v) => v[at],
        }
    }
}
struct Object {
    kind: Kind,
    token: Option<u32>,
    data: Data,
}
#[derive(Default)]
pub(super) struct Arrays {
    objects: Vec<Object>,
    types: BTreeMap<u32, Kind>,
    bytes: usize,
    reads: u64,
    writes: u64,
    initializations: u64,
    initialization_bytes: u64,
}
#[derive(Debug, Serialize)]
pub struct Evidence {
    pub reference: u32,
    pub element: Kind,
    pub type_token: Option<u32>,
    pub length: usize,
    pub preview: Vec<Value>,
    pub preview_truncated: bool,
}
#[derive(Debug, Serialize)]
pub struct Summary {
    pub objects: usize,
    pub storage_bytes: usize,
    pub object_limit: usize,
    pub element_limit: usize,
    pub storage_limit: usize,
    pub element_reads: u64,
    pub element_writes: u64,
    pub initializations: u64,
    pub initialization_bytes: u64,
    pub evidence: Vec<Evidence>,
    pub evidence_truncated: bool,
    pub scope: &'static str,
}
impl Arrays {
    fn kind(&mut self, metadata: &Metadata<'_>, token: u32) -> Result<Kind> {
        if let Some(kind) = self.types.get(&token) {
            return Ok(*kind);
        }
        let ty = metadata.external_type(token)?;
        ensure!(
            ty.namespace == "System"
                && matches!(
                    ty.assembly,
                    "mscorlib" | "System.Runtime" | "System.Private.CoreLib" | "netstandard"
                ),
            "Unmodeled array element assembly/type"
        );
        let kind = match ty.name {
            "Byte" => Kind::U1,
            "Int32" => Kind::I4,
            "String" => Kind::String,
            "Object" if ty.assembly == "mscorlib" && ty.assembly_version == [4, 0, 0, 0] => {
                Kind::Object
            }
            _ => bail!("Unmodeled array element type: {}.{}", ty.namespace, ty.name),
        };
        ensure!(
            self.types.len() < 4096,
            "Managed array type cache exceeds bound"
        );
        self.types.insert(token, kind);
        Ok(kind)
    }
    pub fn allocate(&mut self, metadata: &Metadata<'_>, token: u32, length: u64) -> Result<Value> {
        let kind = self.kind(metadata, token)?;
        ensure!(
            length <= MAX_ELEMENTS as u64,
            "Managed array element limit exceeded"
        );
        ensure!(
            self.objects.len() < MAX_OBJECTS,
            "Managed array object limit exceeded"
        );
        let length = length as usize;
        let bytes = length * kind.bytes();
        ensure!(
            bytes <= MAX_BYTES - self.bytes,
            "Managed array storage limit exceeded"
        );
        let data = match kind {
            Kind::U1 => Data::U1(vec![0; length]),
            Kind::I4 => Data::I4(vec![0; length]),
            Kind::String => Data::String(vec![None; length]),
            Kind::Object => Data::Object(vec![Value::Null; length]),
        };
        self.bytes += bytes;
        self.objects.push(Object {
            kind,
            token: Some(token),
            data,
        });
        Ok(Value::ArrayRef {
            reference: self.objects.len() as u32,
            element: kind,
        })
    }
    pub fn ensure_byte_capacity(&self, length: usize) -> Result<()> {
        ensure!(
            length <= MAX_ELEMENTS,
            "Managed array element limit exceeded"
        );
        ensure!(
            self.objects.len() < MAX_OBJECTS,
            "Managed array object limit exceeded"
        );
        ensure!(
            length <= MAX_BYTES - self.bytes,
            "Managed array storage limit exceeded"
        );
        Ok(())
    }
    pub fn allocate_bytes(&mut self, data: Vec<u8>) -> Result<Value> {
        self.ensure_byte_capacity(data.len())?;
        self.bytes += data.len();
        self.objects.push(Object {
            kind: Kind::U1,
            token: None,
            data: Data::U1(data),
        });
        Ok(Value::ArrayRef {
            reference: self.objects.len() as u32,
            element: Kind::U1,
        })
    }
    pub fn bytes(&self, reference: u32) -> Result<&[u8]> {
        match &self.object(reference, Kind::U1)?.data {
            Data::U1(bytes) => Ok(bytes),
            _ => unreachable!(),
        }
    }
    pub fn bytes_mut_checked(&mut self, reference: u32) -> Result<&mut [u8]> {
        self.object(reference, Kind::U1)?;
        match &mut self.objects[reference as usize - 1].data {
            Data::U1(bytes) => Ok(bytes),
            _ => unreachable!(),
        }
    }
    pub fn initializer_size(&self, reference: u32, kind: Kind) -> Result<usize> {
        let object = self.object(reference, kind)?;
        match &object.data {
            Data::U1(v) => Ok(v.len()),
            Data::I4(v) => Ok(v.len() * 4),
            Data::String(_) | Data::Object(_) => {
                bail!("Array field initialization requires byte/int32 vectors")
            }
        }
    }
    pub fn initialize(&mut self, reference: u32, kind: Kind, data: &[u8]) -> Result<()> {
        let size = self.initializer_size(reference, kind)?;
        ensure!(
            data.len() == size,
            "Array initializer byte count differs from destination"
        );
        match &mut self.objects[reference as usize - 1].data {
            Data::U1(v) => v.copy_from_slice(data),
            Data::I4(v) => {
                for (slot, bytes) in v.iter_mut().zip(data.chunks_exact(4)) {
                    *slot = i32::from_le_bytes(bytes.try_into().unwrap());
                }
            }
            Data::String(_) | Data::Object(_) => unreachable!(),
        }
        self.initializations += 1;
        self.initialization_bytes += size as u64;
        Ok(())
    }
    fn object(&self, reference: u32, kind: Kind) -> Result<&Object> {
        let object = self
            .objects
            .get(reference.wrapping_sub(1) as usize)
            .ok_or_else(|| anyhow!("Invalid managed array reference"))?;
        ensure!(
            object.kind == kind,
            "Managed array reference element identity differs"
        );
        Ok(object)
    }
    pub fn len(&self, reference: u32, kind: Kind) -> Result<usize> {
        Ok(self.object(reference, kind)?.data.len())
    }
    pub fn load(
        &mut self,
        reference: u32,
        kind: Kind,
        index: u64,
        opcode_kind: Kind,
    ) -> Result<Value> {
        let object = self.object(reference, kind)?;
        ensure!(
            kind == opcode_kind || (kind == Kind::Object && opcode_kind == Kind::String),
            "CIL array element opcode/type mismatch"
        );
        ensure!(
            index < object.data.len() as u64,
            "System.IndexOutOfRangeException; managed exception dispatch is not yet modeled"
        );
        let value = object.data.value(index as usize);
        self.reads += 1;
        Ok(value)
    }
    pub fn store(
        &mut self,
        reference: u32,
        kind: Kind,
        index: u64,
        opcode_kind: Kind,
        value: Value,
    ) -> Result<()> {
        let object = self.object(reference, kind)?;
        ensure!(
            kind == opcode_kind || (kind == Kind::Object && opcode_kind == Kind::String),
            "CIL array element opcode/type mismatch"
        );
        ensure!(
            index < object.data.len() as u64,
            "System.IndexOutOfRangeException; managed exception dispatch is not yet modeled"
        );
        let data = &mut self.objects[reference as usize - 1].data;
        match (data, value) {
            (Data::U1(v), Value::I32(n)) => v[index as usize] = n as u8,
            (Data::I4(v), Value::I32(n)) => v[index as usize] = n,
            (Data::String(v), Value::StringRef(r)) => v[index as usize] = Some(r),
            (Data::String(v), Value::Null) => v[index as usize] = None,
            (Data::Object(v), value) if value.is_reference() => v[index as usize] = value,
            _ => bail!("CIL array store value type mismatch"),
        }
        self.writes += 1;
        Ok(())
    }
    pub fn describe(&self) -> Summary {
        Summary {
            objects: self.objects.len(),
            storage_bytes: self.bytes,
            object_limit: MAX_OBJECTS,
            element_limit: MAX_ELEMENTS,
            storage_limit: MAX_BYTES,
            element_reads: self.reads,
            element_writes: self.writes,
            initializations: self.initializations,
            initialization_bytes: self.initialization_bytes,
            evidence: self
                .objects
                .iter()
                .take(64)
                .enumerate()
                .map(|(index, obj)| Evidence {
                    reference: index as u32 + 1,
                    element: obj.kind,
                    type_token: obj.token,
                    length: obj.data.len(),
                    preview: (0..obj.data.len().min(32))
                        .map(|at| obj.data.value(at))
                        .collect(),
                    preview_truncated: obj.data.len() > 32,
                })
                .collect(),
            evidence_truncated: self.objects.len() > 64,
            scope: "Bounded owned byte/int32/string/object-reference vectors. Storage bytes account host element storage; references are logical identities, never host addresses. Broader CLR arrays and native-int behavior remain separate gates.",
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn element_storage_is_bounded_and_failed_stores_leave_zeroed_data_unchanged() {
        use emumee_core::{
            fixtures::{CilFixture, cil_probe},
            pe::Architecture,
        };
        let image = cil_probe(Architecture::X64, CilFixture::ArrayByte, 1);
        let metadata = Metadata::parse(&image, "generated-array.exe").unwrap();
        let mut arrays = Arrays::default();
        for _ in 0..32 {
            arrays
                .allocate(&metadata, 0x01000001, MAX_ELEMENTS as u64)
                .unwrap();
        }
        assert_eq!(arrays.describe().storage_bytes, MAX_BYTES);
        assert!(
            arrays
                .allocate(&metadata, 0x01000001, 1)
                .unwrap_err()
                .to_string()
                .contains("storage limit")
        );
        assert_eq!(arrays.describe().objects, 32);
        assert!(arrays.describe().evidence[0].preview_truncated);
        assert!(
            arrays
                .store(1, Kind::U1, 0, Kind::U1, Value::I64(7))
                .is_err()
        );
        assert_eq!(
            arrays.load(1, Kind::U1, 0, Kind::U1).unwrap(),
            Value::I32(0)
        );
        assert!(arrays.len(0, Kind::U1).is_err());
        assert!(arrays.len(1, Kind::String).is_err());
        assert!(
            arrays
                .allocate_bytes(vec![1])
                .unwrap_err()
                .to_string()
                .contains("storage limit")
        );
        let mut arrays = Arrays::default();
        assert!(matches!(
            arrays.allocate_bytes(vec![82]).unwrap(),
            Value::ArrayRef {
                reference: 1,
                element: Kind::U1
            }
        ));
        assert_eq!(arrays.bytes(1).unwrap(), [82]);
        assert_eq!(arrays.describe().evidence[0].type_token, None);
    }
}

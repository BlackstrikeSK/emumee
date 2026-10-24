//! Initial bounded CIL execution. No native JIT, host CLR or P/Invoke fallback.
use anyhow::{Result, anyhow, bail, ensure};
use emumee_core::{
    artifacts::{Artifact, CaptureSummary},
    fixtures::{CilFixture, cil_probe},
    managed::{
        ManagedInfo, Metadata,
        signature::{LocalSignature, MethodSignature, Type},
    },
    pe::Architecture,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};
mod arrays;
#[cfg(test)]
mod convert_tests;
mod framework;
#[cfg(test)]
mod indicator_tests;
mod indicators;
pub use indicators::run as run_indicator_fixture;
mod object_types;
#[cfg(test)]
mod stream_tests;
use object_types::Classes;
mod heap;
use arrays::{Arrays, Kind as ArrayKind, Summary as ArraySummary};
use framework::{Framework, Report as FrameworkReport};
use heap::{Heap, HeapSummary};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectKind {
    MemoryStream,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Value {
    I32(i32),
    I64(i64),
    NativeInt(u64),
    FieldHandle(u32),
    StringRef(u32),
    ObjectRef { reference: u32, kind: ObjectKind },
    ArrayRef { reference: u32, element: ArrayKind },
    Null,
}
impl Value {
    fn is_reference(self) -> bool {
        matches!(
            self,
            Self::Null | Self::StringRef(_) | Self::ArrayRef { .. } | Self::ObjectRef { .. }
        )
    }
    fn truth(self) -> Result<bool> {
        Ok(match self {
            Self::I32(n) => n != 0,
            Self::I64(n) => n != 0,
            Self::NativeInt(n) => n != 0,
            Self::StringRef(_) | Self::ArrayRef { .. } | Self::ObjectRef { .. } => true,
            Self::Null => false,
            Self::FieldHandle(_) => {
                bail!("Opaque managed field handles cannot be branch conditions")
            }
        })
    }
    fn guest_integer(self) -> Option<u64> {
        match self {
            Self::I32(n) => Some(n as u32 as u64),
            Self::I64(n) => Some(n as u64),
            Self::NativeInt(n) => Some(n),
            Self::Null
            | Self::StringRef(_)
            | Self::ArrayRef { .. }
            | Self::ObjectRef { .. }
            | Self::FieldHandle(_) => None,
        }
    }
    fn reference_key(self) -> Option<Option<(u8, u32)>> {
        match self {
            Self::Null => Some(None),
            Self::StringRef(r) => Some(Some((0, r))),
            Self::ArrayRef { reference, .. } => Some(Some((1, reference))),
            Self::ObjectRef { reference, .. } => Some(Some((2, reference))),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct TraceEntry {
    pub method_token: u32,
    pub offset: u32,
    pub opcode: u16,
}
#[derive(Debug, Serialize)]
pub struct Execution {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_strings: Option<emumee_core::memory_strings::Report>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_string_sources: Option<emumee_core::managed_observation::Receipt>,
    pub backend: &'static str,
    pub architecture: Architecture,
    pub completion_reason: &'static str,
    pub instruction_count: u64,
    pub max_instructions: u64,
    pub guest_entry_return: Option<u64>,
    pub managed_return: Option<Value>,
    pub entry_signature: MethodSignature,
    pub managed_calls: u64,
    pub max_call_depth: usize,
    pub heap: HeapSummary,
    pub framework: FrameworkReport,
    pub arrays: ArraySummary,
    pub final_method: u32,
    pub final_offset: u32,
    pub instruction_tail: Vec<TraceEntry>,
    pub error: Option<String>,
    pub engine_seconds: f64,
    pub instructions_per_second: f64,
    pub opcode_counts: BTreeMap<String, u64>,
    pub metadata: ManagedInfo,
    pub artifacts: Vec<Artifact>,
    pub capture_summary: CaptureSummary,
    pub scope: &'static str,
}
#[derive(Clone, Copy)]
struct Instruction {
    opcode: u16,
    operand: usize,
    next: usize,
}
fn operand(code: &[u8], at: usize, size: usize) -> Result<&[u8]> {
    code.get(
        at..at
            .checked_add(size)
            .ok_or_else(|| anyhow!("CIL operand offset overflow"))?,
    )
    .ok_or_else(|| anyhow!("Truncated CIL operand"))
}
fn decode(code: &[u8], at: usize) -> Result<Instruction> {
    let first = *code
        .get(at)
        .ok_or_else(|| anyhow!("Managed method reached its end without ret"))?;
    let (opcode, start, size) = if first == 0xfe {
        let second = operand(code, at + 1, 1)?[0];
        let size = match second {
            0x06 | 0x07 | 0x15 | 0x16 | 0x1c => 4,
            0x09..=0x0e => 2,
            0x12 | 0x19 => 1,
            0x00..=0x05 | 0x0f | 0x11 | 0x13 | 0x14 | 0x17 | 0x18 | 0x1a | 0x1d | 0x1e => 0,
            _ => bail!("Invalid CIL prefix opcode 0xfe{second:02x}"),
        };
        (0xfe00 | second as u16, at + 2, size)
    } else {
        let size = match first {
            0x0e..=0x13 | 0x1f | 0x2b..=0x37 | 0xde => 1,
            0x20
            | 0x22
            | 0x27..=0x29
            | 0x38..=0x44
            | 0x6f..=0x75
            | 0x79
            | 0x7b..=0x81
            | 0x8c
            | 0x8d
            | 0x8f
            | 0xa3..=0xa5
            | 0xc2
            | 0xc6
            | 0xd0
            | 0xdd => 4,
            0x21 | 0x23 => 8,
            0x45 => {
                let count =
                    u32::from_le_bytes(operand(code, at + 1, 4)?.try_into().unwrap()) as usize;
                ensure!(count <= 65536, "CIL switch exceeds 65536 targets");
                4 + count * 4
            }
            0x00..=0x0d
            | 0x14..=0x1e
            | 0x25
            | 0x26
            | 0x2a
            | 0x46..=0x6e
            | 0x76
            | 0x7a
            | 0x82..=0x8b
            | 0x8e
            | 0x90..=0xa2
            | 0xb3..=0xba
            | 0xc3
            | 0xd1..=0xdc
            | 0xdf
            | 0xe0 => 0,
            _ => bail!("Invalid CIL opcode 0x{first:02x}"),
        };
        (first as u16, at + 1, size)
    };
    operand(code, start, size)?;
    Ok(Instruction {
        opcode,
        operand: start,
        next: start + size,
    })
}
struct Vm<'a> {
    name: &'a str,
    code: &'a [u8],
    boundaries: Vec<bool>,
    stack: Vec<Value>,
    limit: usize,
    offset: usize,
    token: u32,
    signature: MethodSignature,
    arguments: Vec<Value>,
    local_types: Vec<Type>,
    locals: Vec<Option<Value>>,
    classes: Classes,
}
enum Flow {
    Next,
    Return(Option<Value>),
    Call { target: u32, virtual_call: bool },
    LoadString(u32),
    NewArray(u32),
    NewObject(u32),
    ArrayLength,
    ArrayLoad(ArrayKind),
    ArrayStore(ArrayKind),
    FieldToken(u32),
}
fn array_reference(value: Value) -> Result<(u32, ArrayKind)> {
    match value {
        Value::ArrayRef { reference, element } => Ok((reference, element)),
        Value::Null => {
            bail!("System.NullReferenceException; managed exception dispatch is not yet modeled")
        }
        _ => bail!("CIL operation requires a managed array reference"),
    }
}
fn array_index(value: Value) -> Result<u64> {
    match value {
        Value::I32(n) if n >= 0 => Ok(n as u64),
        Value::NativeInt(n) => Ok(n),
        Value::I32(_) => {
            bail!("System.IndexOutOfRangeException; managed exception dispatch is not yet modeled")
        }
        _ => bail!("CIL array index must be int32 or native int"),
    }
}
fn value_type(value: Value, ty: &Type) -> bool {
    if *ty == Type::Object {
        return value.is_reference();
    }
    if let (Value::ArrayRef { element, .. }, Type::Vector(inner)) = (value, ty) {
        return ArrayKind::signature(inner) == Some(element);
    }
    matches!(
        (value, ty),
        (Value::I32(_), Type::I4 | Type::U4)
            | (Value::I64(_), Type::I8 | Type::U8)
            | (Value::StringRef(_) | Value::Null, Type::String)
            | (Value::Null, Type::Vector(_))
    )
}
fn supported_type(ty: &Type) -> bool {
    if let Type::Vector(inner) = ty {
        return ArrayKind::signature(inner).is_some();
    }
    matches!(
        ty,
        Type::I4 | Type::U4 | Type::I8 | Type::U8 | Type::String | Type::Object
    )
}
impl<'a> Vm<'a> {
    #[cfg(test)]
    fn new(code: &'a [u8], limit: u16, return_i64: bool) -> Result<Self> {
        Self::base(
            code,
            limit,
            MethodSignature {
                convention: 0,
                has_this: false,
                explicit_this: false,
                generic_parameters: 0,
                return_type: if return_i64 { Type::I8 } else { Type::I4 },
                parameters: Vec::new(),
                optional_start: None,
            },
        )
    }
    fn base(code: &'a [u8], limit: u16, signature: MethodSignature) -> Result<Self> {
        let mut boundaries = vec![false; code.len()];
        let mut at = 0;
        while at < code.len() {
            boundaries[at] = true;
            at = decode(code, at)?.next;
        }
        Ok(Self {
            name: "",
            code,
            boundaries,
            stack: Vec::with_capacity(limit as usize),
            limit: limit as usize,
            offset: 0,
            token: 0,
            signature,
            arguments: Vec::new(),
            local_types: Vec::new(),
            locals: Vec::new(),
            classes: Classes::default(),
        })
    }
    fn for_method(metadata: &Metadata<'a>, token: u32, arguments: Vec<Value>) -> Result<Self> {
        let method = metadata.method(token)?;
        let signature = MethodSignature::parse(method.signature)?;
        let mut classes = Classes::default();
        ensure!(
            method.flags & 0x10 != 0
                && !signature.has_this
                && !signature.explicit_this
                && signature.convention == 0
                && signature.generic_parameters == 0
                && signature.optional_start.is_none(),
            "Managed instance/generic/vararg dispatch is not yet modeled"
        );
        ensure!(
            method.flags & 0x2000 == 0 && method.implementation_flags & 0x1000 == 0,
            "P/Invoke/internal-call methods have no host fallback"
        );
        ensure!(
            matches!(signature.return_type, Type::Void | Type::Class(_))
                || supported_type(&signature.return_type),
            "Managed return signature type is not yet modeled"
        );
        ensure!(
            signature.parameters.len() == arguments.len(),
            "Managed argument count differs from method signature"
        );
        if matches!(signature.return_type, Type::Class(_)) {
            classes.validate(metadata, &signature.return_type)?;
        }
        for (argument, ty) in arguments.iter().zip(&signature.parameters) {
            if matches!(ty, Type::Class(_)) {
                classes.validate(metadata, ty)?;
            }
            ensure!(
                classes.accepts(*argument, ty),
                "Managed argument type mismatch or unsupported signature type"
            );
        }
        let body = metadata.method_body(token)?;
        ensure!(
            !body.more_sections,
            "Managed exception dispatch is not yet modeled"
        );
        let local_types = if body.local_signature == 0 {
            Vec::new()
        } else {
            let row = metadata.row(17, body.local_signature & 0xffffff)?;
            LocalSignature::parse(metadata.blob(row[0])?)?.locals
        };
        ensure!(
            local_types
                .iter()
                .all(|ty| supported_type(ty) || matches!(ty, Type::Class(_))),
            "Managed local signature type is not yet modeled"
        );
        for ty in &local_types {
            if matches!(ty, Type::Class(_)) {
                classes.validate(metadata, ty)?;
            }
        }
        let locals = local_types
            .iter()
            .map(|ty| {
                if body.initialize_locals {
                    Some(
                        if matches!(
                            ty,
                            Type::String | Type::Vector(_) | Type::Class(_) | Type::Object
                        ) {
                            Value::Null
                        } else if matches!(ty, Type::I8 | Type::U8) {
                            Value::I64(0)
                        } else {
                            Value::I32(0)
                        },
                    )
                } else {
                    None
                }
            })
            .collect();
        let mut frame = Self::base(body.code, body.max_stack, signature)?;
        frame.token = token;
        frame.name = method.name;
        frame.arguments = arguments;
        frame.local_types = local_types;
        frame.locals = locals;
        frame.classes = classes;
        Ok(frame)
    }
    fn cost(&self) -> usize {
        self.code.len() + (self.limit + self.locals.len() + self.arguments.len()) * 32
    }
    fn load_argument(&mut self, index: usize) -> Result<()> {
        let value = *self
            .arguments
            .get(index)
            .ok_or_else(|| anyhow!("Managed argument index is outside signature"))?;
        self.push(value)
    }
    fn store_argument(&mut self, index: usize) -> Result<()> {
        let value = self.pop()?;
        let ty = self
            .signature
            .parameters
            .get(index)
            .ok_or_else(|| anyhow!("Managed argument index is outside signature"))?;
        ensure!(
            self.classes.accepts(value, ty),
            "Managed argument store type mismatch"
        );
        self.arguments[index] = value;
        Ok(())
    }
    fn load_local(&mut self, index: usize) -> Result<()> {
        let value = self
            .locals
            .get(index)
            .copied()
            .ok_or_else(|| anyhow!("Managed local index is outside signature"))?
            .ok_or_else(|| anyhow!("Uninitialized managed local read; no value is invented"))?;
        self.push(value)
    }
    fn store_local(&mut self, index: usize) -> Result<()> {
        let value = self.pop()?;
        let ty = self
            .local_types
            .get(index)
            .ok_or_else(|| anyhow!("Managed local index is outside signature"))?;
        ensure!(
            self.classes.accepts(value, ty),
            "Managed local store type mismatch"
        );
        self.locals[index] = Some(value);
        Ok(())
    }
    fn push(&mut self, value: Value) -> Result<()> {
        ensure!(
            self.stack.len() < self.limit,
            "CIL evaluation stack exceeds declared max_stack"
        );
        self.stack.push(value);
        Ok(())
    }
    fn pop(&mut self) -> Result<Value> {
        self.stack
            .pop()
            .ok_or_else(|| anyhow!("CIL evaluation stack underflow"))
    }
    fn jump(&mut self, next: usize, delta: i32) -> Result<()> {
        let target = next as i64 + delta as i64;
        ensure!(
            target >= 0
                && (target as usize) < self.boundaries.len()
                && self.boundaries[target as usize],
            "CIL branch target is outside the method or inside an operand"
        );
        self.offset = target as usize;
        Ok(())
    }
    fn compare(&mut self, unsigned: bool, reference_equality: bool) -> Result<std::cmp::Ordering> {
        let right = self.pop()?;
        let left = self.pop()?;
        Ok(match (left, right) {
            (Value::I32(a), Value::I32(b)) => {
                if unsigned {
                    (a as u32).cmp(&(b as u32))
                } else {
                    a.cmp(&b)
                }
            }
            (Value::I64(a), Value::I64(b)) => {
                if unsigned {
                    (a as u64).cmp(&(b as u64))
                } else {
                    a.cmp(&b)
                }
            }
            (a, b)
                if reference_equality
                    && a.reference_key().is_some()
                    && b.reference_key().is_some() =>
            {
                a.reference_key().unwrap().cmp(&b.reference_key().unwrap())
            }
            _ => bail!("Invalid CIL comparison operand types"),
        })
    }
    fn binary(&mut self, opcode: u16) -> Result<()> {
        let right = self.pop()?;
        let left = self.pop()?;
        let value = match (left, right) {
            (Value::I32(a), Value::I32(b)) => Value::I32(match opcode {
                0x58 => a.wrapping_add(b),
                0x59 => a.wrapping_sub(b),
                0x5a => a.wrapping_mul(b),
                0x5b => a
                    .checked_div(b)
                    .ok_or_else(|| anyhow!("CIL division: zero divisor or signed overflow"))?,
                0x5c => {
                    ensure!(b != 0, "CIL division by zero");
                    ((a as u32) / (b as u32)) as i32
                }
                0x5f => a & b,
                0x60 => a | b,
                0x61 => a ^ b,
                0x62 => a.wrapping_shl(b as u32 & 31),
                0x63 => a.wrapping_shr(b as u32 & 31),
                0x64 => (a as u32).wrapping_shr(b as u32 & 31) as i32,
                _ => bail!("Unmodeled CIL integer arithmetic 0x{opcode:04x}"),
            }),
            (Value::I64(a), Value::I32(b)) if (0x62..=0x64).contains(&opcode) => {
                Value::I64(match opcode {
                    0x62 => a.wrapping_shl(b as u32 & 63),
                    0x63 => a.wrapping_shr(b as u32 & 63),
                    _ => (a as u64).wrapping_shr(b as u32 & 63) as i64,
                })
            }
            (Value::I64(a), Value::I64(b)) => Value::I64(match opcode {
                0x58 => a.wrapping_add(b),
                0x59 => a.wrapping_sub(b),
                0x5a => a.wrapping_mul(b),
                0x5b => a
                    .checked_div(b)
                    .ok_or_else(|| anyhow!("CIL division: zero divisor or signed overflow"))?,
                0x5c => {
                    ensure!(b != 0, "CIL division by zero");
                    ((a as u64) / (b as u64)) as i64
                }
                0x5f => a & b,
                0x60 => a | b,
                0x61 => a ^ b,
                _ => bail!("Unmodeled CIL integer arithmetic 0x{opcode:04x}"),
            }),
            _ => bail!("Invalid CIL arithmetic operand types"),
        };
        self.push(value)
    }
    fn step(&mut self, instruction: Instruction) -> Result<Flow> {
        let op = instruction.opcode;
        let at = instruction.operand;
        self.offset = instruction.next;
        match op {
            0x00 => {}
            0x02..=0x05 => self.load_argument((op - 2) as usize)?,
            0x0e => self.load_argument(self.code[at] as usize)?,
            0x10 => self.store_argument(self.code[at] as usize)?,
            0x06..=0x09 => self.load_local((op - 6) as usize)?,
            0x0a..=0x0d => self.store_local((op - 0x0a) as usize)?,
            0x11 => self.load_local(self.code[at] as usize)?,
            0x13 => self.store_local(self.code[at] as usize)?,
            0xfe09 | 0xfe0b | 0xfe0c | 0xfe0e => {
                let index =
                    u16::from_le_bytes(operand(self.code, at, 2)?.try_into().unwrap()) as usize;
                match op {
                    0xfe09 => self.load_argument(index)?,
                    0xfe0b => self.store_argument(index)?,
                    0xfe0c => self.load_local(index)?,
                    _ => self.store_local(index)?,
                }
            }
            0x14 => self.push(Value::Null)?,
            0x15..=0x1e => self.push(Value::I32(op as i32 - 0x16))?,
            0x1f => self.push(Value::I32(self.code[at] as i8 as i32))?,
            0x20 => self.push(Value::I32(i32::from_le_bytes(
                operand(self.code, at, 4)?.try_into().unwrap(),
            )))?,
            0x21 => self.push(Value::I64(i64::from_le_bytes(
                operand(self.code, at, 8)?.try_into().unwrap(),
            )))?,
            0x25 => {
                let value = *self
                    .stack
                    .last()
                    .ok_or_else(|| anyhow!("CIL evaluation stack underflow"))?;
                self.push(value)?;
            }
            0x26 => {
                self.pop()?;
            }
            0x2a => {
                if matches!(self.signature.return_type, Type::Void) {
                    ensure!(
                        self.stack.is_empty(),
                        "CIL void ret leaves evaluation stack values"
                    );
                    return Ok(Flow::Return(None));
                }
                let value = self.pop()?;
                ensure!(
                    self.stack.is_empty(),
                    "CIL ret leaves extra evaluation stack values"
                );
                ensure!(
                    self.classes.accepts(value, &self.signature.return_type),
                    "CIL return type does not match method signature"
                );
                return Ok(Flow::Return(Some(value)));
            }
            0x28 | 0x6f => {
                return Ok(Flow::Call {
                    target: u32::from_le_bytes(operand(self.code, at, 4)?.try_into().unwrap()),
                    virtual_call: op == 0x6f,
                });
            }
            0x2b..=0x44 => {
                let (branch, delta) = if op <= 0x37 {
                    (op, self.code[at] as i8 as i32)
                } else {
                    (
                        op - 0x0d,
                        i32::from_le_bytes(operand(self.code, at, 4)?.try_into().unwrap()),
                    )
                };
                let take = match branch {
                    0x2b => true,
                    0x2c => !self.pop()?.truth()?,
                    0x2d => self.pop()?.truth()?,
                    _ => {
                        use std::cmp::Ordering::*;
                        let comparison =
                            self.compare(branch >= 0x33, matches!(branch, 0x2e | 0x33))?;
                        match branch {
                            0x2e => comparison == Equal,
                            0x2f | 0x34 => comparison != Less,
                            0x30 | 0x35 => comparison == Greater,
                            0x31 | 0x36 => comparison != Greater,
                            0x32 | 0x37 => comparison == Less,
                            0x33 => comparison != Equal,
                            _ => unreachable!(),
                        }
                    }
                };
                if take {
                    self.jump(instruction.next, delta)?;
                }
            }
            0x45 => {
                let Value::I32(index) = self.pop()? else {
                    bail!("CIL switch requires int32 index")
                };
                let count = u32::from_le_bytes(operand(self.code, at, 4)?.try_into().unwrap());
                if (index as u32) < count {
                    let delta = i32::from_le_bytes(
                        operand(self.code, at + 4 + index as usize * 4, 4)?
                            .try_into()
                            .unwrap(),
                    );
                    self.jump(instruction.next, delta)?;
                }
            }
            0x58..=0x64 => self.binary(op)?,
            0x72 => {
                return Ok(Flow::LoadString(u32::from_le_bytes(
                    operand(self.code, at, 4)?.try_into().unwrap(),
                )));
            }
            0x65 | 0x66 => {
                let value = match self.pop()? {
                    Value::I32(a) => Value::I32(if op == 0x65 { a.wrapping_neg() } else { !a }),
                    Value::I64(a) => Value::I64(if op == 0x65 { a.wrapping_neg() } else { !a }),
                    _ => bail!("Invalid CIL unary arithmetic operand"),
                };
                self.push(value)?;
            }
            0x67..=0x6a | 0x6d => {
                let value = match self.pop()? {
                    Value::I32(a) => a as i64,
                    Value::I64(a) => a,
                    Value::NativeInt(a) => a as i64,
                    _ => bail!("Invalid CIL conversion operand"),
                };
                self.push(match op {
                    0x67 => Value::I32(value as i8 as i32),
                    0x68 => Value::I32(value as i16 as i32),
                    0x69 | 0x6d => Value::I32(value as i32),
                    _ => Value::I64(value),
                })?;
            }
            0xd0 => {
                return Ok(Flow::FieldToken(u32::from_le_bytes(
                    operand(self.code, at, 4)?.try_into().unwrap(),
                )));
            }
            0x73 => {
                return Ok(Flow::NewObject(u32::from_le_bytes(
                    operand(self.code, at, 4)?.try_into().unwrap(),
                )));
            }
            0x8d => {
                return Ok(Flow::NewArray(u32::from_le_bytes(
                    operand(self.code, at, 4)?.try_into().unwrap(),
                )));
            }
            0x8e => return Ok(Flow::ArrayLength),
            0x91 => return Ok(Flow::ArrayLoad(ArrayKind::U1)),
            0x94 => return Ok(Flow::ArrayLoad(ArrayKind::I4)),
            0x9a => return Ok(Flow::ArrayLoad(ArrayKind::String)),
            0x9c => return Ok(Flow::ArrayStore(ArrayKind::U1)),
            0x9e => return Ok(Flow::ArrayStore(ArrayKind::I4)),
            0xa2 => return Ok(Flow::ArrayStore(ArrayKind::String)),
            0xfe01..=0xfe05 => {
                use std::cmp::Ordering::*;
                let comparison = self.compare(matches!(op, 0xfe03 | 0xfe05), op == 0xfe01)?;
                let value = match op {
                    0xfe01 => comparison == Equal,
                    0xfe02 | 0xfe03 => comparison == Greater,
                    _ => comparison == Less,
                };
                self.push(Value::I32(i32::from(value)))?;
            }
            _ => bail!("Unmodeled CIL instruction 0x{op:04x}; no host fallback"),
        };
        Ok(Flow::Next)
    }
}

pub fn run_fixture(
    architecture: Architecture,
    fixture: CilFixture,
    iterations: u32,
    budget: u64,
) -> Result<Execution> {
    run_with_timeout(
        architecture,
        fixture,
        iterations,
        budget,
        Duration::from_secs(30),
    )
}
fn run_with_timeout(
    architecture: Architecture,
    fixture: CilFixture,
    iterations: u32,
    budget: u64,
    timeout: Duration,
) -> Result<Execution> {
    ensure!(
        (1..=100_000_000).contains(&iterations),
        "Managed iterations must be 1..100,000,000"
    );
    ensure!(
        (1..=1_000_000_000).contains(&budget),
        "Managed instruction budget must be 1..1,000,000,000"
    );
    let image = cil_probe(architecture, fixture, iterations);
    run_image(architecture, &image, budget, timeout, None)
}
fn run_image(
    architecture: Architecture,
    image: &[u8],
    budget: u64,
    timeout: Duration,
    prepared: Option<indicators::Prepared>,
) -> Result<Execution> {
    ensure!(
        (1..=1_000_000_000).contains(&budget),
        "Managed instruction budget must be 1..1,000,000,000"
    );
    let metadata = Metadata::parse(image, "generated-managed.exe")?;
    ensure!(
        !metadata.cli.native_entry_point,
        "Managed native entry points are not modeled"
    );
    let token = metadata.cli.entry_point;
    let root = Vm::for_method(&metadata, token, Vec::new())?;
    let entry_signature = root.signature.clone();
    let mut frame_bytes = root.cost();
    let mut frames = vec![root];
    let mut managed_calls = 0;
    let mut max_call_depth = 1;
    let mut heap = Heap::default();
    let mut framework = Framework::default();
    if let Some(prepared) = prepared {
        framework.install_observer(prepared);
    }
    let mut arrays = Arrays::default();
    let mut count = 0;
    let mut counts = [0u64; 512];
    let mut tail = VecDeque::with_capacity(128);
    let start = Instant::now();
    let mut returned = None;
    let mut error = None;
    let completion = loop {
        if count >= budget {
            break "instruction_budget";
        }
        if count & 1023 == 0 && start.elapsed() >= timeout {
            break "timeout";
        }
        let frame = frames.last_mut().unwrap();
        let current_token = frame.token;
        let pc = frame.offset;
        let instruction = match decode(frame.code, pc) {
            Ok(instruction) => instruction,
            Err(failure) => {
                error = Some(format!("{failure:#}"));
                break "error";
            }
        };
        count += 1;
        let index = if instruction.opcode < 256 {
            instruction.opcode as usize
        } else {
            256 + (instruction.opcode & 255) as usize
        };
        counts[index] += 1;
        if tail.len() == 128 {
            tail.pop_front();
        }
        tail.push_back(TraceEntry {
            method_token: current_token,
            offset: pc as u32,
            opcode: instruction.opcode,
        });
        // Most instructions stay in the same frame. Keep the frame borrow and
        // bypass call/return transition handling on that hot path.
        let flow = match frame.step(instruction) {
            Ok(Flow::Next) => continue,
            Ok(flow) => flow,
            Err(failure) => {
                error = Some(format!(
                    "Method 0x{current_token:08x} IL_{pc:04x}: {failure:#}"
                ));
                break "error";
            }
        };
        let transition = (|| -> Result<bool> {
            match flow {
                Flow::Next => unreachable!(),
                Flow::FieldToken(token) => {
                    metadata.field(token)?;
                    frames.last_mut().unwrap().push(Value::FieldHandle(token))?;
                    Ok(false)
                }
                Flow::NewArray(token) => {
                    let length = match frames.last_mut().unwrap().pop()? {
                        Value::I32(n) if n >= 0 => n as u64,
                        Value::NativeInt(n)
                            if (if architecture == Architecture::X86 {
                                n as u32 as i32 as i64
                            } else {
                                n as i64
                            }) >= 0 =>
                        {
                            n
                        }
                        Value::I32(_) | Value::NativeInt(_) => bail!(
                            "System.OverflowException for negative array length; managed exception dispatch is not yet modeled"
                        ),
                        _ => bail!("newarr requires int32 or native-int length"),
                    };
                    let value = arrays.allocate(&metadata, token, length)?;
                    frames.last_mut().unwrap().push(value)?;
                    Ok(false)
                }
                Flow::ArrayLength => {
                    let (reference, kind) = array_reference(frames.last_mut().unwrap().pop()?)?;
                    let length = arrays.len(reference, kind)?;
                    frames
                        .last_mut()
                        .unwrap()
                        .push(Value::NativeInt(length as u64))?;
                    Ok(false)
                }
                Flow::ArrayLoad(kind) => {
                    let frame = frames.last_mut().unwrap();
                    let index = frame.pop()?;
                    let (reference, actual) = array_reference(frame.pop()?)?;
                    let value = arrays.load(reference, actual, array_index(index)?, kind)?;
                    frame.push(value)?;
                    Ok(false)
                }
                Flow::ArrayStore(kind) => {
                    let frame = frames.last_mut().unwrap();
                    let value = frame.pop()?;
                    let index = frame.pop()?;
                    let (reference, actual) = array_reference(frame.pop()?)?;
                    if let Value::StringRef(r) = value {
                        heap.string(r)?;
                    }
                    match value {
                        Value::ObjectRef { reference, .. } => framework.valid_object(reference)?,
                        Value::ArrayRef { reference, element } => {
                            arrays.len(reference, element)?;
                        }
                        _ => {}
                    }
                    arrays.store(reference, actual, array_index(index)?, kind, value)?;
                    Ok(false)
                }
                Flow::NewObject(token) => {
                    let parent = frames.last_mut().unwrap();
                    let value = framework.construct(
                        &metadata,
                        token,
                        &mut parent.stack,
                        parent.limit,
                        &arrays,
                    )?;
                    parent.push(value)?;
                    Ok(false)
                }
                Flow::LoadString(token) => {
                    ensure!(
                        token >> 24 == 0x70 && token & 0xffffff != 0,
                        "ldstr requires a nonzero #US token"
                    );
                    let reference = heap.literal(metadata.user_string(token & 0xffffff)?)?;
                    frames
                        .last_mut()
                        .unwrap()
                        .push(Value::StringRef(reference))?;
                    framework.observe_literal(&heap, reference, token, count);
                    Ok(false)
                }
                Flow::Return(value) => {
                    if frames.len() == 1 {
                        returned = value;
                        return Ok(true);
                    }
                    let frame = frames.pop().unwrap();
                    framework.observe_return(&heap, value, frame.name, count);
                    frame_bytes -= frame.cost();
                    if let Some(value) = value {
                        frames.last_mut().unwrap().push(value)?;
                    }
                    Ok(false)
                }
                Flow::Call {
                    target,
                    virtual_call,
                } => {
                    framework.observer_boundary(count);
                    if target >> 24 == 10 {
                        let parent = frames.last_mut().unwrap();
                        if let Some(value) = framework.invoke(
                            &metadata,
                            target,
                            virtual_call,
                            &mut parent.stack,
                            &mut heap,
                            &mut arrays,
                        )? {
                            parent.push(value)?;
                        }
                        return Ok(false);
                    }
                    ensure!(frames.len() < 64, "Managed call depth exceeds 64");
                    ensure!(
                        target >> 24 == 6 && !virtual_call,
                        "Managed non-MethodDef, generic or virtual IL dispatch is not yet modeled"
                    );
                    let signature = MethodSignature::parse(metadata.method(target)?.signature)?;
                    let parent = frames.last_mut().unwrap();
                    let parameter_count = signature.parameters.len();
                    ensure!(
                        parent.stack.len() >= parameter_count,
                        "CIL evaluation stack underflow decoding managed arguments"
                    );
                    let arguments = parent.stack.split_off(parent.stack.len() - parameter_count);
                    let child = Vm::for_method(&metadata, target, arguments)?;
                    ensure!(
                        frame_bytes + child.cost() <= 16 * 1024 * 1024,
                        "Managed frame memory exceeds 16MiB"
                    );
                    framework.observe_arguments(&heap, &child.arguments, child.name, count);
                    frame_bytes += child.cost();
                    frames.push(child);
                    managed_calls += 1;
                    max_call_depth = max_call_depth.max(frames.len());
                    Ok(false)
                }
            }
        })();
        match transition {
            Ok(true) => break "entry_return",
            Ok(false) => {}
            Err(failure) => {
                error = Some(format!(
                    "Method 0x{current_token:08x} IL_{pc:04x}: {failure:#}"
                ));
                break "error";
            }
        }
    };
    let seconds = start.elapsed().as_secs_f64();
    let captures = framework.capture_artifacts();
    let (memory_strings, memory_string_sources) = framework.finish_observer(
        count,
        frames.last().unwrap().token,
        frames.last().unwrap().offset as u32,
    );
    let opcode_counts = counts
        .iter()
        .enumerate()
        .filter(|(_, count)| **count != 0)
        .map(|(index, count)| {
            (
                format!(
                    "0x{:04x}",
                    if index < 256 {
                        index
                    } else {
                        0xfe00 + index - 256
                    }
                ),
                *count,
            )
        })
        .collect();
    Ok(Execution {
        memory_strings,
        memory_string_sources,
        backend: "rust/managed-il",
        architecture,
        completion_reason: completion,
        instruction_count: count,
        max_instructions: budget,
        guest_entry_return: returned.and_then(Value::guest_integer),
        managed_return: returned,
        entry_signature,
        managed_calls,
        max_call_depth,
        heap: heap.describe(),
        framework: framework.describe(),
        arrays: arrays.describe(),
        final_method: frames.last().unwrap().token,
        final_offset: frames.last().unwrap().offset as u32,
        instruction_tail: tail.into_iter().collect(),
        error,
        engine_seconds: seconds,
        instructions_per_second: count as f64 / seconds.max(f64::MIN_POSITIVE),
        opcode_counts,
        metadata: metadata.describe()?,
        artifacts: captures.items,
        capture_summary: captures.summary,
        scope: "Generated managed integer/control-flow, local/static-method, UTF16-string, typed-vector and initial explicit framework-call fixtures. Other objects, exceptions and broader framework models are separate migration gates. No host CLR, native JIT or P/Invoke fallback.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rva_initializers_copy_bytes_ints_repeat_after_mutation_and_obey_each_budget_prefix() {
        for arch in [Architecture::X86, Architecture::X64] {
            for (fixture, value, instructions, initializations, bytes) in [
                (CilFixture::RvaDecode, 82, 75, 1, 4),
                (CilFixture::RvaBytes, 82, 8, 1, 4),
                (CilFixture::RvaI32, 17, 8, 1, 8),
                (CilFixture::RvaZero, 0, 8, 1, 0),
                (CilFixture::RvaTwice, 82, 15, 2, 8),
            ] {
                let result = run_fixture(arch, fixture, 1, 1000).unwrap();
                assert_eq!(
                    result.completion_reason, "entry_return",
                    "{fixture:?}: {:?}",
                    result.error
                );
                assert_eq!(result.managed_return, Some(Value::I32(value)));
                assert_eq!(result.instruction_count, instructions, "{fixture:?}");
                assert_eq!(result.arrays.initializations, initializations);
                assert_eq!(result.arrays.initialization_bytes, bytes);
                if matches!(fixture, CilFixture::RvaDecode) {
                    assert_eq!(result.artifacts[0].data, b"RUST");
                }
            }
            for budget in 1..=75 {
                let result = run_fixture(arch, CilFixture::RvaDecode, 1, budget).unwrap();
                assert_eq!(result.instruction_count, budget);
                assert_eq!(result.arrays.initializations, u64::from(budget >= 5));
                assert_eq!(result.artifacts.len(), usize::from(budget >= 71));
                if budget == 75 {
                    assert_eq!(result.managed_return, Some(Value::I32(82)));
                } else {
                    assert_eq!(result.completion_reason, "instruction_budget");
                    assert_eq!(result.managed_return, None);
                }
            }
        }
    }
    #[test]
    fn invalid_field_handles_layouts_and_reference_arrays_stop_before_initialization() {
        for arch in [Architecture::X86, Architecture::X64] {
            for (fixture, message, count) in [
                (CilFixture::RvaBadHandle, "argument type mismatch", 5),
                (CilFixture::RvaMissingField, "row index", 4),
                (CilFixture::RvaNoRva, "static non-literal RVA field", 5),
                (CilFixture::RvaMissingRow, "no FieldRVA row", 5),
                (CilFixture::RvaNoLayout, "no ClassLayout", 5),
                (CilFixture::RvaBadPacking, "packing", 5),
                (CilFixture::RvaTooSmall, "declared field storage", 5),
                (CilFixture::RvaBadRva, "non-file-backed", 5),
                (CilFixture::RvaReferenceField, "signature type", 5),
                (CilFixture::RvaLiteral, "static non-literal RVA field", 5),
                (CilFixture::RvaWrongArray, "byte/int32 vectors", 5),
                (CilFixture::RvaNullArray, "ArgumentNullException: array", 3),
                (CilFixture::RvaBadSignature, "method/signature", 5),
                (
                    CilFixture::RvaHandleBranch,
                    "cannot be branch conditions",
                    2,
                ),
            ] {
                let result = run_fixture(arch, fixture, 1, 100).unwrap();
                assert_eq!(result.completion_reason, "error", "{fixture:?}");
                assert!(result.error.unwrap().contains(message), "{fixture:?}");
                assert_eq!(result.instruction_count, count);
                assert_eq!(result.arrays.initializations, 0);
                assert_eq!(result.arrays.element_writes, 0);
                assert!(result.artifacts.is_empty());
                assert_eq!(result.managed_return, None);
            }
        }
    }
    #[test]
    fn field_handle_operands_remain_tokens_and_initializers_leave_rva_data_immutable() {
        for arch in [Architecture::X86, Architecture::X64] {
            let result = run_fixture(arch, CilFixture::RvaTwice, 1, 100).unwrap();
            assert_eq!(result.arrays.element_writes, 1);
            assert_eq!(result.arrays.evidence[0].preview[0], Value::I32(82));
            assert_eq!(
                result.framework.events[0].arguments[1],
                Value::FieldHandle(0x04000001)
            );
            assert_eq!(
                result.framework.events[1].arguments[1],
                Value::FieldHandle(0x04000001)
            );
        }
    }
    #[test]
    fn managed_file_roundtrips_are_guest_only_and_read_arrays_are_independent_copies() {
        for arch in [Architecture::X86, Architecture::X64] {
            for (fixture, value, instructions, files, empty, artifacts) in [
                (CilFixture::FileRoundTrip, 82, 38, 1, 0, 1),
                (CilFixture::FileOverwrite, 1, 37, 1, 0, 2),
                (CilFixture::FileEmpty, 0, 11, 1, 1, 0),
                (CilFixture::FileEmptyExists, 1, 9, 1, 1, 0),
                (CilFixture::FileExists, 0, 3, 0, 0, 0),
                (CilFixture::FileExistsNull, 0, 3, 0, 0, 0),
                (CilFixture::FileEscape, 1, 25, 1, 0, 1),
                (CilFixture::FileDedupe, 2, 31, 2, 0, 1),
            ] {
                let result = run_fixture(arch, fixture, 1, 1000).unwrap();
                assert_eq!(
                    result.completion_reason, "entry_return",
                    "{fixture:?}: {:?}",
                    result.error
                );
                assert_eq!(result.managed_return, Some(Value::I32(value)));
                assert_eq!(result.instruction_count, instructions, "{fixture:?}");
                assert_eq!(result.framework.files.files, files);
                assert_eq!(result.framework.files.empty_files, empty);
                assert_eq!(result.artifacts.len(), artifacts);
                assert_eq!(result.capture_summary.omitted_observations, 0);
            }
            for budget in 1..=38 {
                let result = run_fixture(arch, CilFixture::FileRoundTrip, 1, budget).unwrap();
                assert_eq!(result.instruction_count, budget);
                assert_eq!(result.artifacts.len(), usize::from(budget >= 22));
                if budget == 38 {
                    assert_eq!(result.managed_return, Some(Value::I32(82)));
                } else {
                    assert_eq!(result.completion_reason, "instruction_budget");
                    assert_eq!(result.managed_return, None);
                }
            }
            let result = run_fixture(arch, CilFixture::FileRoundTrip, 1, 100).unwrap();
            assert_eq!(result.arrays.objects, 3);
            assert_eq!(result.arrays.evidence[0].preview[0], Value::I32(1));
            assert_eq!(result.arrays.evidence[1].preview[0], Value::I32(1));
            assert_eq!(result.arrays.evidence[2].preview[0], Value::I32(82));
            assert_eq!(result.artifacts[0].data, b"RUST");
        }
    }
    #[test]
    fn managed_file_failures_stop_with_explicit_errors_and_preserve_prior_written_evidence() {
        for arch in [Architecture::X86, Architecture::X64] {
            for (fixture, message, count, written) in [
                (CilFixture::FileMissing, "FileNotFoundException", 2, false),
                (
                    CilFixture::FileParentMissing,
                    "DirectoryNotFoundException",
                    22,
                    false,
                ),
                (
                    CilFixture::FileNullPath,
                    "ArgumentNullException: path",
                    22,
                    false,
                ),
                (
                    CilFixture::FileNullBytes,
                    "ArgumentNullException: bytes",
                    3,
                    false,
                ),
                (
                    CilFixture::FileInvalidPath,
                    "ArgumentException: path",
                    22,
                    false,
                ),
                (
                    CilFixture::FileUnsupportedPath,
                    "Unmodeled managed file behavior",
                    22,
                    false,
                ),
                (CilFixture::FileBadSignature, "method/signature", 22, false),
                (CilFixture::FileBadAssembly, "assembly/type", 22, false),
                (
                    CilFixture::FileBadArrayType,
                    "argument type mismatch",
                    22,
                    false,
                ),
                (CilFixture::FilePartial, "method/signature", 23, true),
            ] {
                let result = run_fixture(arch, fixture, 1, 1000).unwrap();
                assert_eq!(result.completion_reason, "error", "{fixture:?}");
                assert!(result.error.unwrap().contains(message), "{fixture:?}");
                assert_eq!(result.instruction_count, count);
                assert_eq!(result.managed_return, None);
                assert_eq!(result.artifacts.len(), usize::from(written));
                assert_eq!(result.framework.files.files, usize::from(written));
                if written {
                    assert_eq!(result.artifacts[0].data, b"RUST");
                }
            }
        }
    }
    #[test]
    fn managed_file_version_capture_dedup_and_guest_path_provenance_remain_distinct() {
        use emumee_core::artifacts::ArtifactKind;
        for arch in [Architecture::X86, Architecture::X64] {
            let overwritten = run_fixture(arch, CilFixture::FileOverwrite, 1, 100).unwrap();
            assert_eq!(overwritten.artifacts[0].data, b"RUST");
            assert_eq!(overwritten.artifacts[1].data, b"A");
            assert_eq!(overwritten.artifacts[0].observations.len(), 1);
            assert_eq!(overwritten.artifacts[1].observations.len(), 2);
            let dedup = run_fixture(arch, CilFixture::FileDedupe, 1, 100).unwrap();
            assert_eq!(dedup.artifacts.len(), 1);
            assert_eq!(dedup.artifacts[0].observations.len(), 4);
            assert!(
                dedup.artifacts[0]
                    .observations
                    .iter()
                    .all(|o| matches!(o.kind, ArtifactKind::GuestFile))
            );
            let escaped = run_fixture(arch, CilFixture::FileEscape, 1, 100).unwrap();
            assert!(
                escaped.artifacts[0]
                    .observations
                    .iter()
                    .all(|o| o.guest_path == "c:\\escaped.bin")
            );
            assert_eq!(
                escaped.artifacts[0].filename,
                format!("{}.bin", escaped.artifacts[0].sha256)
            );
            assert!(!escaped.artifacts[0].filename.contains("escaped"));
        }
    }
    #[test]
    fn typed_arrays_zero_initialize_truncate_store_preserve_aliases_and_respect_budgets() {
        for arch in [Architecture::X86, Architecture::X64] {
            for (fixture, value, instructions, objects, reads, writes) in [
                (CilFixture::ArrayByte, 255, 9, 1, 1, 1),
                (CilFixture::ArrayI32, -17, 9, 1, 1, 1),
                (CilFixture::ArrayString, 1, 11, 1, 1, 1),
                (CilFixture::ArrayStringZero, 1, 7, 1, 1, 0),
                (CilFixture::ArrayLength, 3, 5, 1, 0, 0),
                (CilFixture::ArrayNativeLength, 3, 9, 2, 0, 0),
                (CilFixture::ArrayLocal, 17, 11, 1, 1, 1),
                (CilFixture::ArrayLocalNull, 1, 4, 0, 0, 0),
                (CilFixture::ArrayCall, 17, 12, 1, 1, 1),
                (CilFixture::ArrayIdentity, 1, 5, 1, 0, 0),
                (CilFixture::ArrayDifferent, 0, 6, 2, 0, 0),
                (CilFixture::ArrayZeroByte, 0, 5, 1, 1, 0),
                (CilFixture::ArrayVsString, 0, 5, 1, 0, 0),
            ] {
                for budget in 1..=instructions {
                    let result = run_fixture(arch, fixture, 1, budget).unwrap();
                    assert_eq!(result.instruction_count, budget);
                    if budget == instructions {
                        assert_eq!(
                            result.completion_reason, "entry_return",
                            "{fixture:?}: {:?}",
                            result.error
                        );
                        assert_eq!(
                            result.managed_return,
                            Some(Value::I32(value)),
                            "{fixture:?}"
                        );
                        assert_eq!(result.arrays.objects, objects);
                        assert_eq!(result.arrays.element_reads, reads);
                        assert_eq!(result.arrays.element_writes, writes);
                        if matches!(fixture, CilFixture::ArrayCall) {
                            assert_eq!(result.managed_calls, 1);
                            assert_eq!(result.max_call_depth, 2);
                        }
                    } else {
                        assert_eq!(result.completion_reason, "instruction_budget");
                        assert_eq!(result.managed_return, None);
                    }
                }
            }
        }
    }
    #[test]
    fn array_failures_preserve_data_and_do_not_confuse_native_lengths_with_int32() {
        for arch in [Architecture::X86, Architecture::X64] {
            for (fixture, message, count, objects) in [
                (CilFixture::ArrayLengthType, "return type", 4, 1),
                (CilFixture::ArrayNull, "NullReferenceException", 3, 0),
                (CilFixture::ArrayBounds, "IndexOutOfRangeException", 6, 1),
                (CilFixture::ArrayBadValue, "store value type", 6, 1),
                (CilFixture::ArrayBadOpcode, "opcode/type", 4, 1),
                (CilFixture::ArrayTooLarge, "element limit", 2, 0),
                (CilFixture::ArrayNegative, "OverflowException", 2, 0),
                (
                    CilFixture::ArrayUnknownType,
                    "Unmodeled array element type",
                    2,
                    0,
                ),
                (
                    CilFixture::ArrayBadAssembly,
                    "array element assembly/type",
                    2,
                    0,
                ),
                (CilFixture::ArrayBadLocal, "local store type", 3, 1),
                (CilFixture::ArrayBadLengthType, "int32 or native-int", 2, 0),
            ] {
                let result = run_fixture(arch, fixture, 1, 100).unwrap();
                assert_eq!(result.completion_reason, "error", "{fixture:?}");
                assert!(result.error.unwrap().contains(message), "{fixture:?}");
                assert_eq!(result.instruction_count, count);
                assert_eq!(result.managed_return, None);
                assert_eq!(result.arrays.objects, objects);
                assert_eq!(result.arrays.element_writes, 0);
                for object in result.arrays.evidence {
                    assert!(object.preview.iter().all(|v| *v == Value::I32(0)));
                }
            }
        }
    }
    #[test]
    fn zero_length_array_loops_obey_object_quota_and_bounded_evidence() {
        for arch in [Architecture::X86, Architecture::X64] {
            let result = run_fixture(arch, CilFixture::ArrayQuota, 1, 20000).unwrap();
            assert_eq!(result.completion_reason, "error");
            assert!(result.error.unwrap().contains("array object limit"));
            assert_eq!(result.instruction_count, 16386);
            assert_eq!(result.arrays.objects, 4096);
            assert_eq!(result.arrays.storage_bytes, 0);
            assert_eq!(result.arrays.evidence.len(), 64);
            assert!(result.arrays.evidence_truncated);
        }
    }
    #[test]
    fn modeled_framework_calls_obey_signatures_utf16_identity_and_every_budget_boundary() {
        for arch in [Architecture::X86, Architecture::X64] {
            for (fixture, value, instructions, calls, objects, console) in [
                (CilFixture::FrameworkStrings, 3, 7, 3, 3, "Hi!\r\n"),
                (CilFixture::FrameworkConcatIdentity, 0, 6, 1, 4, ""),
                (CilFixture::FrameworkStringEquality, 1, 6, 2, 4, ""),
                (CilFixture::FrameworkConcatEmpty, 1, 6, 1, 1, ""),
                (CilFixture::FrameworkConcatNull, 0, 5, 2, 1, ""),
                (CilFixture::FrameworkUnicodeLength, 4, 3, 1, 1, ""),
                (CilFixture::FrameworkChar, 55296, 4, 1, 1, ""),
                (CilFixture::FrameworkConsole, 17, 7, 4, 1, "-17\r\n\r\n"),
                (CilFixture::FrameworkConsoleNull, 17, 4, 1, 0, "\r\n"),
                (CilFixture::FrameworkNullOrEmpty, 1, 5, 2, 1, ""),
                (CilFixture::FrameworkInequality, 1, 4, 1, 1, ""),
            ] {
                for budget in 1..=instructions {
                    let result = run_fixture(arch, fixture, 1, budget).unwrap();
                    assert_eq!(result.instruction_count, budget);
                    if budget == instructions {
                        assert_eq!(
                            result.completion_reason, "entry_return",
                            "{fixture:?}: {:?}",
                            result.error
                        );
                        assert_eq!(result.managed_return, Some(Value::I32(value)));
                        assert_eq!(result.framework.attempts, calls);
                        assert_eq!(result.framework.completed_calls, calls);
                        assert_eq!(result.framework.console_output.text_lossy, console);
                        assert_eq!(
                            result.framework.console_output.utf16,
                            console.encode_utf16().collect::<Vec<_>>()
                        );
                        assert_eq!(result.heap.string_objects, objects);
                        assert_eq!(result.managed_calls, 0);
                    } else {
                        assert_eq!(result.completion_reason, "instruction_budget");
                        assert_eq!(result.managed_return, None);
                    }
                }
            }
            let typed = run_fixture(arch, CilFixture::FrameworkConsoleTypes, 1, 100).unwrap();
            assert_eq!(typed.completion_reason, "entry_return", "{:?}", typed.error);
            assert_eq!(typed.managed_return, Some(Value::I32(17)));
            assert_eq!(typed.instruction_count, 10);
            assert_eq!(typed.framework.completed_calls, 4);
            let mut expected: Vec<u16> = "-9223372036854775808True".encode_utf16().collect();
            expected.push(0xd800);
            assert_eq!(typed.framework.console_output.utf16, expected);
            assert!(
                typed
                    .framework
                    .console_output
                    .text_lossy
                    .ends_with('\u{fffd}')
            );
        }
    }
    #[test]
    fn framework_identity_signature_null_index_and_argument_failures_have_no_host_fallback() {
        for arch in [Architecture::X86, Architecture::X64] {
            for (fixture, message, count) in [
                (CilFixture::FrameworkNullLength, "NullReferenceException", 2),
                (CilFixture::FrameworkBadIndex, "IndexOutOfRangeException", 3),
                (CilFixture::FrameworkBadAssembly, "assembly/type", 2),
                (CilFixture::FrameworkBadSignature, "method/signature", 2),
                (
                    CilFixture::FrameworkStaticVirtual,
                    "static framework method",
                    3,
                ),
                (CilFixture::FrameworkUnknown, "method/signature", 1),
                (CilFixture::FrameworkBadOwner, "MemberRef owner", 2),
                (CilFixture::FrameworkBadScope, "AssemblyRef", 2),
                (
                    CilFixture::FrameworkArgumentType,
                    "argument type mismatch",
                    2,
                ),
            ] {
                let result = run_fixture(arch, fixture, 1, 100).unwrap();
                assert_eq!(result.completion_reason, "error", "{fixture:?}");
                assert_eq!(result.instruction_count, count);
                assert!(result.error.unwrap().contains(message), "{fixture:?}");
                assert_eq!(result.managed_return, None);
                assert_eq!(result.framework.attempts, 1);
                assert_eq!(result.framework.completed_calls, 0);
                assert_eq!(result.framework.events.len(), 1);
                assert!(result.framework.events[0].error.is_some());
                assert!(result.framework.console_output.utf16.is_empty());
            }
        }
    }
    #[test]
    fn framework_console_and_event_limits_preserve_exact_counts_and_stop_before_excess_output() {
        for arch in [Architecture::X86, Architecture::X64] {
            let result = run_fixture(arch, CilFixture::FrameworkConsoleLimit, 1, 200000).unwrap();
            assert_eq!(result.completion_reason, "error");
            assert!(result.error.unwrap().contains("console output limit"));
            assert_eq!(result.instruction_count, 98306);
            assert_eq!(result.framework.attempts, 32769);
            assert_eq!(result.framework.completed_calls, 32768);
            assert_eq!(result.framework.console_output.utf16.len(), 65536);
            assert_eq!(result.framework.events.len(), 128);
            assert_eq!(result.framework.omitted_events, 32641);
            assert_eq!(result.heap.string_objects, 1);
            let partial = run_fixture(arch, CilFixture::FrameworkConsoleLimit, 1, 600).unwrap();
            assert_eq!(partial.completion_reason, "instruction_budget");
            assert_eq!(partial.framework.attempts, 200);
            assert_eq!(partial.framework.omitted_events, 72);
            assert_eq!(partial.framework.console_output.utf16.len(), 400);
        }
    }
    #[test]
    fn string_references_survive_locals_calls_interning_and_precise_budgets() {
        for arch in [Architecture::X86, Architecture::X64] {
            for (fixture, instructions, objects) in [
                (CilFixture::StringIdentity, 4, 1),
                (CilFixture::StringAliases, 4, 1),
                (CilFixture::StringLocal, 6, 1),
                (CilFixture::StringLocalNull, 4, 0),
                (CilFixture::StringCall, 7, 1),
            ] {
                for budget in 1..=instructions {
                    let result = run_fixture(arch, fixture, 1, budget).unwrap();
                    assert_eq!(result.instruction_count, budget);
                    if budget == instructions {
                        assert_eq!(
                            result.completion_reason, "entry_return",
                            "{fixture:?}: {:?}",
                            result.error
                        );
                        assert_eq!(result.managed_return, Some(Value::I32(1)));
                        assert_eq!(result.heap.string_objects, objects);
                        if objects > 0 {
                            assert_eq!(result.heap.strings[0].utf16_preview, [72, 105]);
                        }
                    } else {
                        assert_eq!(result.completion_reason, "instruction_budget");
                        assert_eq!(result.managed_return, None);
                    }
                }
            }
            let result = run_fixture(arch, CilFixture::StringReturn, 1, 100).unwrap();
            assert_eq!(result.completion_reason, "entry_return");
            assert_eq!(result.managed_return, Some(Value::StringRef(1)));
            assert_eq!(result.guest_entry_return, None);
            assert_eq!(
                result.heap.strings[0].utf16_preview,
                [0x41, 0xd800, 0, 0xdc00]
            );
        }
    }
    #[test]
    fn malformed_string_tokens_stores_and_relational_ops_stop_explicitly() {
        for arch in [Architecture::X86, Architecture::X64] {
            for (fixture, message, count) in [
                (CilFixture::StringBadToken, "#US token", 1),
                (CilFixture::StringMissing, "compressed integer", 1),
                (CilFixture::StringBadType, "local store type mismatch", 2),
                (CilFixture::StringRelational, "comparison operand types", 3),
            ] {
                let result = run_fixture(arch, fixture, 1, 100).unwrap();
                assert_eq!(result.completion_reason, "error", "{fixture:?}");
                assert_eq!(result.instruction_count, count);
                assert!(result.error.unwrap().contains(message), "{fixture:?}");
                assert_eq!(result.managed_return, None);
            }
        }
    }
    #[test]
    fn declared_locals_argument_order_void_returns_and_nested_calls_preserve_values() {
        for architecture in [Architecture::X86, Architecture::X64] {
            for (fixture, value, calls, depth) in [
                (CilFixture::LocalsLoop, Some(17), 0, 1),
                (CilFixture::LocalZero, Some(0), 0, 1),
                (CilFixture::LocalIndexed, Some(17), 0, 1),
                (CilFixture::CallArguments, Some(10), 1, 2),
                (CilFixture::ArgumentStore, Some(18), 1, 2),
                (CilFixture::VoidCall, Some(17), 1, 2),
                (CilFixture::VoidReturn, None, 0, 1),
                (CilFixture::Recursive, Some(17), 18, 19),
            ] {
                let result = run_fixture(architecture, fixture, 17, 10000).unwrap();
                assert_eq!(result.error, None, "{architecture:?} {fixture:?}");
                assert_eq!(result.completion_reason, "entry_return");
                assert_eq!(result.guest_entry_return, value);
                assert_eq!(result.managed_calls, calls);
                assert_eq!(result.max_call_depth, depth);
                if calls != 0 {
                    assert!(
                        result
                            .instruction_tail
                            .iter()
                            .any(|entry| entry.method_token == 0x06000002)
                    );
                }
            }
            for (fixture, instructions) in
                [(CilFixture::LocalsLoop, 36), (CilFixture::Recursive, 28)]
            {
                for budget in 1..=instructions {
                    let result = run_fixture(architecture, fixture, 3, budget).unwrap();
                    assert_eq!(result.instruction_count, budget);
                    if budget == instructions {
                        assert_eq!(result.completion_reason, "entry_return");
                    } else {
                        assert_eq!(result.completion_reason, "instruction_budget");
                        assert_eq!(result.managed_return, None);
                    }
                }
            }
        }
    }
    #[test]
    fn uninitialized_slots_type_mismatches_and_recursion_limits_stop_without_host_stack_growth() {
        for architecture in [Architecture::X86, Architecture::X64] {
            for (fixture, message) in [
                (
                    CilFixture::LocalUninitialized,
                    "Uninitialized managed local",
                ),
                (CilFixture::LocalBadType, "local store type mismatch"),
                (CilFixture::ArgumentBadType, "argument type mismatch"),
                (CilFixture::DeepRecursion, "call depth exceeds 64"),
            ] {
                let result = run_fixture(architecture, fixture, 17, 10000).unwrap();
                assert_eq!(result.completion_reason, "error");
                assert!(
                    result.error.as_deref().unwrap_or("").contains(message),
                    "{fixture:?}: {:?}",
                    result.error
                );
                assert_eq!(result.managed_return, None);
                if matches!(fixture, CilFixture::DeepRecursion) {
                    assert_eq!(result.max_call_depth, 64);
                    assert_eq!(result.managed_calls, 63);
                }
            }
        }
    }
    #[test]
    fn signed_unsigned_comparisons_shifts_long_branches_and_switches_follow_il_semantics() {
        fn run(code: &[u8]) -> Value {
            let mut vm = Vm::new(code, 8, false).unwrap();
            for _ in 0..100 {
                let instruction = decode(vm.code, vm.offset).unwrap();
                match vm.step(instruction).unwrap() {
                    Flow::Return(Some(value)) => return value,
                    Flow::Next => {}
                    _ => panic!("unexpected test flow"),
                }
            }
            panic!("test method did not return")
        }
        assert_eq!(run(&[0x15, 0x16, 0xfe, 0x03, 0x2a]), Value::I32(1));
        assert_eq!(run(&[0x15, 0x16, 0xfe, 0x02, 0x2a]), Value::I32(0));
        assert_eq!(run(&[0x15, 0x17, 0x64, 0x2a]), Value::I32(i32::MAX));
        assert_eq!(run(&[0x38, 1, 0, 0, 0, 0x16, 0x17, 0x2a]), Value::I32(1));
        assert_eq!(
            run(&[0x16, 0x39, 1, 0, 0, 0, 0x16, 0x17, 0x2a]),
            Value::I32(1)
        );
        let mut code = vec![
            0x17, 0x45, 2, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0x16, 0x2a, 0x17, 0x2a,
        ];
        assert_eq!(run(&code), Value::I32(1));
        code[0] = 0x15;
        assert_eq!(run(&code), Value::I32(0));
    }
    #[test]
    fn infinite_il_obeys_a_wall_deadline_without_a_host_runtime_or_sleep() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let started = Instant::now();
            let result = run_with_timeout(
                architecture,
                CilFixture::Infinite,
                1,
                1_000_000_000,
                Duration::from_millis(2),
            )
            .unwrap();
            assert_eq!(result.completion_reason, "timeout");
            assert_eq!(result.guest_entry_return, None);
            assert!(result.instruction_count < result.max_instructions);
            assert!(started.elapsed() < Duration::from_secs(5));
        }
    }
    #[test]
    fn integer_execution_and_every_loop_budget_boundary_preserve_real_returns() {
        for arch in [Architecture::X86, Architecture::X64] {
            for (fixture, value) in [
                (CilFixture::Return, 17),
                (CilFixture::Loop, 3),
                (CilFixture::Arithmetic, i32::MAX as u64),
                (CilFixture::I64Arithmetic, i64::MAX as u64),
            ] {
                let result = run_fixture(arch, fixture, 3, 1000).unwrap();
                assert_eq!(result.error, None, "{arch:?} {fixture:?}");
                assert_eq!(result.guest_entry_return, Some(value));
            }
            for budget in 1..=16 {
                let result = run_fixture(arch, CilFixture::Loop, 3, budget).unwrap();
                assert_eq!(result.instruction_count, budget);
                if budget == 16 {
                    assert_eq!(result.guest_entry_return, Some(3));
                } else {
                    assert_eq!(result.completion_reason, "instruction_budget");
                    assert_eq!(result.guest_entry_return, None);
                }
            }
            let infinite = run_fixture(arch, CilFixture::Infinite, 1, 31).unwrap();
            assert_eq!(infinite.instruction_count, 31);
            assert_eq!(infinite.completion_reason, "instruction_budget");
        }
    }
    #[test]
    fn invalid_branches_stack_states_division_and_unsupported_code_never_fake_returns() {
        for arch in [Architecture::X86, Architecture::X64] {
            for (fixture, message) in [
                (CilFixture::BadBranch, "inside an operand"),
                (CilFixture::Underflow, "underflow"),
                (CilFixture::DivideZero, "division"),
                (CilFixture::Unsupported, "Unmodeled CIL instruction"),
                (CilFixture::ReturnStack, "extra evaluation stack"),
                (CilFixture::StackLimit, "max_stack"),
            ] {
                let result = run_fixture(arch, fixture, 1, 1000).unwrap();
                assert_eq!(result.completion_reason, "error");
                assert!(
                    result.error.as_deref().unwrap_or("").contains(message),
                    "{fixture:?}: {:?}",
                    result.error
                );
                assert_eq!(result.guest_entry_return, None);
            }
        }
    }
}

//! Bounded ECMA-335 II.23.2 signatures. Reading a type is separate from
//! implementing its runtime behavior or verifying cross-module semantics.
use super::{ManagedError, Result, compressed};
use serde::Serialize;
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum Type {
    Void,
    Boolean,
    Char,
    I1,
    U1,
    I2,
    U2,
    I4,
    U4,
    I8,
    U8,
    R4,
    R8,
    String,
    TypedByRef,
    I,
    U,
    Object,
    Class(u32),
    ValueType(u32),
    Pointer(Box<Type>),
    ByRef(Box<Type>),
    Vector(Box<Type>),
    Array {
        element: Box<Type>,
        rank: u32,
        sizes: Vec<u32>,
        lower_bounds: Vec<i32>,
    },
    TypeParameter(u32),
    MethodParameter(u32),
    GenericInstance {
        value_type: bool,
        token: u32,
        arguments: Vec<Type>,
    },
    FunctionPointer(Box<MethodSignature>),
    Modified {
        required: bool,
        token: u32,
        inner: Box<Type>,
    },
    Pinned(Box<Type>),
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MethodSignature {
    pub convention: u8,
    pub has_this: bool,
    pub explicit_this: bool,
    pub generic_parameters: u32,
    pub return_type: Type,
    pub parameters: Vec<Type>,
    pub optional_start: Option<usize>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LocalSignature {
    pub locals: Vec<Type>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FieldSignature {
    pub field_type: Type,
}
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
    nodes: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() > 1024 * 1024 {
            return Err(ManagedError("signature exceeds 1MiB"));
        }
        Ok(Self {
            bytes,
            at: 0,
            nodes: 0,
        })
    }
    fn byte(&mut self) -> Result<u8> {
        let value = *self
            .bytes
            .get(self.at)
            .ok_or(ManagedError("truncated signature"))?;
        self.at += 1;
        Ok(value)
    }
    fn unsigned(&mut self) -> Result<u32> {
        let (value, width) = compressed(self.bytes, self.at)?;
        self.at += width;
        Ok(value as u32)
    }
    fn signed(&mut self) -> Result<i32> {
        let (value, width) = compressed(self.bytes, self.at)?;
        self.at += width;
        let bits = match width {
            1 => 6,
            2 => 13,
            _ => 28,
        };
        Ok((value as i32 >> 1) | if value & 1 != 0 { -1i32 << bits } else { 0 })
    }
    fn token(&mut self) -> Result<u32> {
        let encoded = self.unsigned()?;
        let index = encoded >> 2;
        let table = match encoded & 3 {
            0 => 2,
            1 => 1,
            2 => 27,
            _ => return Err(ManagedError("reserved signature type token tag")),
        };
        if index == 0 || index > 0xffffff {
            return Err(ManagedError("signature type token exceeds token bounds"));
        }
        Ok(table << 24 | index)
    }
    fn ty(&mut self, depth: usize, allow_void: bool, allow_pinned: bool) -> Result<Type> {
        if depth > 32 || self.nodes >= 4096 {
            return Err(ManagedError("signature type depth/node bound exceeded"));
        }
        self.nodes += 1;
        Ok(match self.byte()? {
            1 if allow_void => Type::Void,
            2 => Type::Boolean,
            3 => Type::Char,
            4 => Type::I1,
            5 => Type::U1,
            6 => Type::I2,
            7 => Type::U2,
            8 => Type::I4,
            9 => Type::U4,
            10 => Type::I8,
            11 => Type::U8,
            12 => Type::R4,
            13 => Type::R8,
            14 => Type::String,
            0x0f => Type::Pointer(Box::new(self.ty(depth + 1, true, false)?)),
            0x10 => Type::ByRef(Box::new(self.ty(depth + 1, false, false)?)),
            0x11 => Type::ValueType(self.token()?),
            0x12 => Type::Class(self.token()?),
            0x13 => Type::TypeParameter(self.unsigned()?),
            0x14 => {
                let element = Box::new(self.ty(depth + 1, false, false)?);
                let rank = self.unsigned()?;
                if rank == 0 || rank > 32 {
                    return Err(ManagedError("signature array rank exceeds 32"));
                }
                let count = self.unsigned()?;
                if count > rank {
                    return Err(ManagedError("array sizes exceed rank"));
                }
                let mut sizes = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    sizes.push(self.unsigned()?);
                }
                let count = self.unsigned()?;
                if count > rank {
                    return Err(ManagedError("array lower bounds exceed rank"));
                }
                let mut lower_bounds = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    lower_bounds.push(self.signed()?);
                }
                Type::Array {
                    element,
                    rank,
                    sizes,
                    lower_bounds,
                }
            }
            0x15 => {
                let value_type = match self.byte()? {
                    0x11 => true,
                    0x12 => false,
                    _ => return Err(ManagedError("invalid generic instance type kind")),
                };
                let token = self.token()?;
                let count = self.unsigned()?;
                if count == 0 || count > 64 {
                    return Err(ManagedError("generic argument count exceeds bound"));
                }
                let mut arguments = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    arguments.push(self.ty(depth + 1, false, false)?);
                }
                Type::GenericInstance {
                    value_type,
                    token,
                    arguments,
                }
            }
            0x16 => Type::TypedByRef,
            0x18 => Type::I,
            0x19 => Type::U,
            0x1b => Type::FunctionPointer(Box::new(self.method(depth + 1)?)),
            0x1c => Type::Object,
            0x1d => Type::Vector(Box::new(self.ty(depth + 1, false, false)?)),
            0x1e => Type::MethodParameter(self.unsigned()?),
            kind @ (0x1f | 0x20) => {
                let token = self.token()?;
                Type::Modified {
                    required: kind == 0x1f,
                    token,
                    inner: Box::new(self.ty(depth + 1, allow_void, allow_pinned)?),
                }
            }
            0x45 if allow_pinned => Type::Pinned(Box::new(self.ty(depth + 1, false, false)?)),
            _ => {
                return Err(ManagedError(
                    "unsupported or invalid signature type element",
                ));
            }
        })
    }
    fn method(&mut self, depth: usize) -> Result<MethodSignature> {
        if depth > 32 {
            return Err(ManagedError(
                "function pointer signature nesting exceeds bound",
            ));
        }
        let flags = self.byte()?;
        let convention = flags & 15;
        if flags & 0x80 != 0 || convention > 5 || (flags & 0x40 != 0 && flags & 0x20 == 0) {
            return Err(ManagedError("unsupported method signature convention"));
        }
        let generic_parameters = if flags & 0x10 != 0 {
            self.unsigned()?
        } else {
            0
        };
        if flags & 0x10 != 0 && generic_parameters == 0 {
            return Err(ManagedError(
                "generic method signature has no generic parameters",
            ));
        }
        let count = self.unsigned()?;
        if count > 1024 || generic_parameters > 1024 {
            return Err(ManagedError(
                "method signature parameter count exceeds bound",
            ));
        }
        let return_type = self.ty(depth + 1, true, false)?;
        let mut parameters = Vec::with_capacity(count as usize);
        let mut optional_start = None;
        for index in 0..count {
            if self.bytes.get(self.at) == Some(&0x41) {
                if convention != 5 || optional_start.is_some() {
                    return Err(ManagedError("invalid vararg sentinel"));
                }
                self.at += 1;
                optional_start = Some(index as usize);
            }
            parameters.push(self.ty(depth + 1, false, false)?);
        }
        Ok(MethodSignature {
            convention,
            has_this: flags & 0x20 != 0,
            explicit_this: flags & 0x40 != 0,
            generic_parameters,
            return_type,
            parameters,
            optional_start,
        })
    }
    fn finish(&self) -> Result<()> {
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(ManagedError("trailing signature bytes"))
        }
    }
}
impl MethodSignature {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes)?;
        let result = reader.method(0)?;
        reader.finish()?;
        Ok(result)
    }
}
impl FieldSignature {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes)?;
        if reader.byte()? != 6 {
            return Err(ManagedError("signature is not FieldSig"));
        }
        let field_type = reader.ty(0, false, false)?;
        reader.finish()?;
        Ok(Self { field_type })
    }
}
impl LocalSignature {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut reader = Reader::new(bytes)?;
        if reader.byte()? != 7 {
            return Err(ManagedError("signature is not LocalVarSig"));
        }
        let count = reader.unsigned()?;
        if count > 4096 {
            return Err(ManagedError("local signature exceeds 4096 slots"));
        }
        let mut locals = Vec::with_capacity(count as usize);
        for _ in 0..count {
            locals.push(reader.ty(0, false, true)?);
        }
        reader.finish()?;
        Ok(Self { locals })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn field_signatures_keep_value_type_identity_and_reject_nonfields_void_and_trailing_data() {
        assert_eq!(
            FieldSignature::parse(&[6, 0x11, 8]).unwrap().field_type,
            Type::ValueType(0x02000002)
        );
        assert_eq!(FieldSignature::parse(&[6, 8]).unwrap().field_type, Type::I4);
        for bytes in [
            &[][..],
            &[0, 8][..],
            &[6, 1][..],
            &[6, 8, 0][..],
            &[6, 0x11][..],
        ] {
            assert!(FieldSignature::parse(bytes).is_err());
        }
    }
    #[test]
    fn generic_array_and_local_signatures_retain_tokens_shapes_and_signed_lower_bounds() {
        let signature =
            MethodSignature::parse(&[0x10, 1, 1, 0x15, 0x12, 5, 1, 0x13, 0, 0x1e, 0]).unwrap();
        assert_eq!(signature.generic_parameters, 1);
        assert_eq!(signature.parameters, [Type::MethodParameter(0)]);
        assert_eq!(
            signature.return_type,
            Type::GenericInstance {
                value_type: false,
                token: 0x01000001,
                arguments: vec![Type::TypeParameter(0)]
            }
        );
        let signature = MethodSignature::parse(&[0, 0, 0x14, 8, 2, 2, 2, 3, 2, 2, 0x7d]).unwrap();
        assert_eq!(
            signature.return_type,
            Type::Array {
                element: Box::new(Type::I4),
                rank: 2,
                sizes: vec![2, 3],
                lower_bounds: vec![1, -2]
            }
        );
        let local = LocalSignature::parse(&[7, 2, 8, 0x45, 0x10, 8]).unwrap();
        assert_eq!(
            local.locals,
            [
                Type::I4,
                Type::Pinned(Box::new(Type::ByRef(Box::new(Type::I4))))
            ]
        );
    }
    #[test]
    fn signature_truncation_tags_flags_counts_and_depth_are_bounded() {
        let valid = [0x10, 1, 1, 0x15, 0x12, 5, 1, 0x13, 0, 0x1e, 0];
        for end in 0..valid.len() {
            assert!(MethodSignature::parse(&valid[..end]).is_err());
        }
        for bytes in [
            &[0, 0, 0x12, 3][..],
            &[0x40, 0, 8],
            &[0, 0x84, 1, 8],
            &[0, 1, 8, 1],
            &[0, 0, 8, 0],
        ] {
            assert!(MethodSignature::parse(bytes).is_err());
        }
        let mut nested = vec![0, 0];
        nested.extend([0x1d; 34]);
        nested.push(8);
        assert!(MethodSignature::parse(&nested).is_err());
        assert!(LocalSignature::parse(&[7, 0x90, 1]).is_err());
    }
}

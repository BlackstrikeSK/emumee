//! Framework boundary for pure guest stream state and checked guest arrays.
use super::{Heap, Value};
use crate::cil::{ArrayKind, Arrays, ObjectKind, object_types::known};
use anyhow::{Result, bail, ensure};
use emumee_core::{
    managed::{
        Metadata,
        signature::{MethodSignature, Type},
    },
    managed_streams::{self, ByteArrays, StreamError, Streams},
};

impl ByteArrays for Arrays {
    fn bytes(&self, reference: u32) -> managed_streams::Result<&[u8]> {
        Arrays::bytes(self, reference).map_err(|_| StreamError::Array)
    }
    fn bytes_mut(&mut self, reference: u32) -> managed_streams::Result<&mut [u8]> {
        self.bytes_mut_checked(reference)
            .map_err(|_| StreamError::Array)
    }
}
#[derive(Clone, Copy)]
pub(super) enum Operation {
    Constructor,
    ToArray,
    Length,
    Position,
    SetPosition,
    Read,
    ReadByte,
    Write,
    WriteByte,
    SetLength,
    Seek,
    CanRead,
    CanWrite,
    CanSeek,
    Flush,
    Close,
    CopyTo,
}
pub(super) fn resolve(
    metadata: &Metadata<'_>,
    owner: &str,
    name: &str,
    sig: &MethodSignature,
) -> Result<Option<Operation>> {
    use Operation::*;
    let p = sig.parameters.as_slice();
    let r = &sig.return_type;
    let bytes = |t: &Type| matches!(t,Type::Vector(inner) if **inner==Type::U1);
    Ok(match (owner, name, sig.has_this, p, r) {
        ("MemoryStream", ".ctor", true, [], Type::Void)
        | ("MemoryStream", ".ctor", true, [Type::I4], Type::Void) => Some(Constructor),
        ("MemoryStream", ".ctor", true, [a], Type::Void) if bytes(a) => Some(Constructor),
        ("MemoryStream", ".ctor", true, [a, Type::Boolean], Type::Void) if bytes(a) => {
            Some(Constructor)
        }
        ("MemoryStream", "ToArray", true, [], r) if bytes(r) => Some(ToArray),
        ("MemoryStream" | "Stream", "get_Length", true, [], Type::I8) => Some(Length),
        ("MemoryStream" | "Stream", "get_Position", true, [], Type::I8) => Some(Position),
        ("MemoryStream" | "Stream", "set_Position", true, [Type::I8], Type::Void) => {
            Some(SetPosition)
        }
        ("MemoryStream" | "Stream", "Read", true, [a, Type::I4, Type::I4], Type::I4)
            if bytes(a) =>
        {
            Some(Read)
        }
        ("MemoryStream" | "Stream", "Write", true, [a, Type::I4, Type::I4], Type::Void)
            if bytes(a) =>
        {
            Some(Write)
        }
        ("MemoryStream" | "Stream", "ReadByte", true, [], Type::I4) => Some(ReadByte),
        ("MemoryStream" | "Stream", "WriteByte", true, [Type::U1], Type::Void) => Some(WriteByte),
        ("MemoryStream" | "Stream", "SetLength", true, [Type::I8], Type::Void) => Some(SetLength),
        ("MemoryStream" | "Stream", "Seek", true, [Type::I8, Type::ValueType(t)], Type::I8)
            if known(metadata, *t, "System.IO", "SeekOrigin")? =>
        {
            Some(Seek)
        }
        ("MemoryStream" | "Stream", "get_CanRead", true, [], Type::Boolean) => Some(CanRead),
        ("MemoryStream" | "Stream", "get_CanWrite", true, [], Type::Boolean) => Some(CanWrite),
        ("MemoryStream" | "Stream", "get_CanSeek", true, [], Type::Boolean) => Some(CanSeek),
        ("MemoryStream" | "Stream", "Flush", true, [], Type::Void) => Some(Flush),
        ("MemoryStream" | "Stream", "Close", true, [], Type::Void)
        | ("MemoryStream" | "Stream" | "IDisposable", "Dispose", true, [], Type::Void) => {
            Some(Close)
        }
        ("MemoryStream" | "Stream", "CopyTo", true, [Type::Class(t)], Type::Void)
        | ("MemoryStream" | "Stream", "CopyTo", true, [Type::Class(t), Type::I4], Type::Void)
            if known(metadata, *t, "System.IO", "Stream")? =>
        {
            Some(CopyTo)
        }
        _ => None,
    })
}
fn i32_arg(value: Value) -> Result<i32> {
    if let Value::I32(n) = value {
        Ok(n)
    } else {
        bail!("MemoryStream int32 argument type mismatch")
    }
}
fn i64_arg(value: Value) -> Result<i64> {
    if let Value::I64(n) = value {
        Ok(n)
    } else {
        bail!("MemoryStream int64 argument type mismatch")
    }
}
fn array(value: Value) -> Result<u32> {
    match value {
        Value::ArrayRef {
            reference,
            element: ArrayKind::U1,
        } => Ok(reference),
        Value::Null => bail!(
            "System.ArgumentNullException: buffer; managed exception dispatch is not yet modeled"
        ),
        _ => bail!("MemoryStream requires actual byte[]"),
    }
}
pub(super) fn reference(value: Value) -> Result<u32> {
    match value {
        Value::ObjectRef {
            reference,
            kind: ObjectKind::MemoryStream,
        } => Ok(reference),
        Value::Null => {
            bail!("System.NullReferenceException; managed exception dispatch is not yet modeled")
        }
        _ => bail!("MemoryStream receiver identity/type mismatch"),
    }
}
pub(super) fn construct(state: &mut Streams, args: &[Value], arrays: &Arrays) -> Result<Value> {
    let reference = match args {
        [] => state.owned(0)?,
        [Value::I32(capacity)] => state.owned(*capacity)?,
        [buffer] => state.borrowed(array(*buffer)?, true, arrays)?,
        [buffer, flag] => {
            let flag = i32_arg(*flag)?;
            ensure!(
                matches!(flag, 0 | 1),
                "Unsupported MemoryStream writable flag"
            );
            state.borrowed(array(*buffer)?, flag != 0, arrays)?
        }
        _ => bail!("Unsupported MemoryStream constructor overload"),
    };
    Ok(Value::ObjectRef {
        reference,
        kind: ObjectKind::MemoryStream,
    })
}
pub(super) fn execute(
    state: &mut Streams,
    op: Operation,
    args: &[Value],
    arrays: &mut Arrays,
    _heap: &mut Heap,
) -> Result<Option<Value>> {
    use Operation::*;
    let id = reference(args[0])?;
    state.valid(id)?;
    Ok(match op {
        Constructor => bail!("MemoryStream constructors require newobj"),
        ToArray => {
            arrays.ensure_byte_capacity(state.array_length(id)?)?;
            let bytes = state.to_array(id, arrays)?;
            Some(arrays.allocate_bytes(bytes)?)
        }
        Length => Some(Value::I64(state.length(id)? as i64)),
        Position => Some(Value::I64(state.position(id)? as i64)),
        SetPosition => {
            state.set_position(id, i64_arg(args[1])?)?;
            None
        }
        Read => Some(Value::I32(state.read(
            id,
            array(args[1])?,
            i32_arg(args[2])?,
            i32_arg(args[3])?,
            arrays,
        )? as i32)),
        ReadByte => Some(Value::I32(state.read_byte(id, arrays)?)),
        Write => {
            state.write(
                id,
                array(args[1])?,
                i32_arg(args[2])?,
                i32_arg(args[3])?,
                arrays,
            )?;
            None
        }
        WriteByte => {
            state.write_byte(id, i32_arg(args[1])?, arrays)?;
            None
        }
        SetLength => {
            state.set_length(id, i64_arg(args[1])?, arrays)?;
            None
        }
        Seek => Some(Value::I64(
            state.seek(id, i64_arg(args[1])?, i32_arg(args[2])?)? as i64,
        )),
        CanRead | CanSeek => Some(Value::I32(i32::from(state.capability(id, false)?))),
        CanWrite => Some(Value::I32(i32::from(state.capability(id, true)?))),
        Flush => {
            state.flush(id)?;
            None
        }
        Close => {
            state.close(id)?;
            None
        }
        CopyTo => {
            ensure!(
                args[1] != Value::Null,
                "System.ArgumentNullException: destination; managed exception dispatch is not yet modeled"
            );
            state.copy_to(
                id,
                reference(args[1])?,
                if args.len() == 3 {
                    Some(i32_arg(args[2])?)
                } else {
                    None
                },
                arrays,
            )?;
            None
        }
    })
}

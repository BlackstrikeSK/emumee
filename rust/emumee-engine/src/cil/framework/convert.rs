//! Convert models use actual guest byte vectors and preserve runtime identity.
use super::{Heap, Value, units};
use crate::cil::{ArrayKind, Arrays};
use anyhow::{Result, bail, ensure};
use emumee_core::managed_convert;

pub(super) fn decode(heap: &Heap, arrays: &mut Arrays, value: Value) -> Result<Value> {
    ensure!(
        value != Value::Null,
        "System.ArgumentNullException: s; managed exception dispatch is not yet modeled"
    );
    let input = units(heap, value, false)?;
    let length = managed_convert::decoded_length(input, usize::MAX)?;
    arrays.ensure_byte_capacity(length)?;
    // Capacity is checked before building the returned buffer, including empty vectors.
    arrays.allocate_bytes(managed_convert::decode(input, length)?)
}
pub(super) fn encode(heap: &mut Heap, arrays: &Arrays, value: Value) -> Result<Value> {
    let reference = match value {
        Value::ArrayRef {
            reference,
            element: ArrayKind::U1,
        } => reference,
        Value::Null => bail!(
            "System.ArgumentNullException: inArray; managed exception dispatch is not yet modeled"
        ),
        _ => bail!("Convert.ToBase64String requires byte[]"),
    };
    let input = arrays.bytes(reference)?;
    let length = managed_convert::encoded_length(input.len(), usize::MAX)?;
    heap.ensure_capacity(length)?;
    // Encoding creates a distinct runtime string; literals remain separately interned.
    Ok(Value::StringRef(
        heap.allocate(managed_convert::encode(input, length)?)?,
    ))
}

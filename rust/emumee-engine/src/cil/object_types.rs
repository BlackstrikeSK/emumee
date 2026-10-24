//! Closed metadata-resolved guest reference types, never blanket Class matching.
use super::{ObjectKind, Value, supported_type, value_type};
use anyhow::{Result, bail, ensure};
use emumee_core::managed::{Metadata, signature::Type};
use std::collections::BTreeMap;
#[derive(Clone, Copy, Debug)]
enum Class {
    Object,
    MemoryStream,
}
#[derive(Default)]
pub(super) struct Classes {
    types: BTreeMap<u32, Class>,
}
pub(super) fn known(
    metadata: &Metadata<'_>,
    token: u32,
    namespace: &str,
    name: &str,
) -> Result<bool> {
    let ty = metadata.external_type(token)?;
    Ok(ty.assembly == "mscorlib"
        && ty.assembly_version == [4, 0, 0, 0]
        && ty.namespace == namespace
        && ty.name == name)
}
impl Classes {
    pub fn validate(&mut self, metadata: &Metadata<'_>, ty: &Type) -> Result<()> {
        if let Type::Class(token) = ty {
            if self.types.contains_key(token) {
                return Ok(());
            }
            ensure!(
                self.types.len() < 4096,
                "Managed reference type cache exceeds bound"
            );
            let external = metadata.external_type(*token)?;
            ensure!(
                external.assembly == "mscorlib" && external.assembly_version == [4, 0, 0, 0],
                "Unmodeled managed reference assembly/version"
            );
            let class = match (external.namespace, external.name) {
                ("System", "Object") => Class::Object,
                ("System.IO", "MemoryStream" | "Stream") | ("System", "IDisposable") => {
                    Class::MemoryStream
                }
                _ => bail!("Unmodeled managed reference Class identity"),
            };
            self.types.insert(*token, class);
            Ok(())
        } else {
            ensure!(
                supported_type(ty),
                "Managed signature type is not yet modeled"
            );
            Ok(())
        }
    }
    pub fn accepts(&self, value: Value, ty: &Type) -> bool {
        if let Type::Class(token) = ty {
            match self.types.get(token) {
                Some(Class::Object) => value.is_reference(),
                Some(Class::MemoryStream) => matches!(
                    value,
                    Value::Null
                        | Value::ObjectRef {
                            kind: ObjectKind::MemoryStream,
                            ..
                        }
                ),
                None => false,
            }
        } else {
            value_type(value, ty)
        }
    }
}

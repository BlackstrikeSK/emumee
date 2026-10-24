//! Explicit modeled framework calls. No host assembly resolution or invocation.
use super::{Arrays, Heap, Value, value_type};
use anyhow::{Result, bail, ensure};
use emumee_core::managed::{
    Metadata,
    signature::{MethodSignature, Type},
};
use serde::Serialize;
use std::{collections::BTreeMap, sync::Arc};
mod convert;
mod files;
mod streams;
use files::{Files, Summary as FileSummary};

const MAX_CONSOLE_UNITS: usize = 65_536;
const MAX_EVENTS: usize = 128;
#[derive(Clone, Copy)]
enum Function {
    Concat,
    Length,
    Char,
    Equal(bool),
    IsNullOrEmpty,
    NewLine,
    Console(bool),
    FileWrite,
    FileRead,
    FileExists,
    ConvertDecode,
    ConvertEncode,
    Stream(streams::Operation),
    InitializeArray,
}
struct Model {
    assembly: String,
    version: [u16; 4],
    name: String,
    signature: MethodSignature,
    function: Function,
}
#[derive(Debug, Serialize)]
pub struct Event {
    pub token: u32,
    pub assembly: Option<String>,
    pub assembly_version: Option<[u16; 4]>,
    pub method: Option<String>,
    pub virtual_call: bool,
    pub arguments: Vec<Value>,
    pub result: Option<Value>,
    pub error: Option<String>,
}
#[derive(Debug, Serialize)]
pub struct ConsoleOutput {
    pub utf16: Vec<u16>,
    pub text_lossy: String,
    pub utf16_limit: usize,
    pub newline_policy: &'static str,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub attempts: u64,
    pub completed_calls: u64,
    pub counts: BTreeMap<String, u64>,
    pub events: Vec<Event>,
    pub omitted_events: u64,
    pub console_output: ConsoleOutput,
    pub files: FileSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub streams: Option<emumee_core::managed_streams::Summary>,
    pub scope: &'static str,
}
#[derive(Default)]
pub(super) struct Framework {
    observer: Option<super::indicators::Observer>,
    cache: BTreeMap<u32, Arc<Model>>,
    attempts: u64,
    completed: u64,
    counts: BTreeMap<String, u64>,
    events: Vec<Event>,
    console: Vec<u16>,
    files: Files,
    streams: emumee_core::managed_streams::Streams,
}
fn accepts(value: Value, ty: &Type) -> bool {
    value_type(value, ty) || matches!((value, ty), (Value::I32(_), Type::Boolean | Type::Char))
}
fn units(heap: &Heap, value: Value, nullable: bool) -> Result<&[u16]> {
    match value {
        Value::StringRef(reference) => heap.string(reference),
        Value::Null if nullable => Ok(&[]),
        Value::Null => {
            bail!("System.NullReferenceException; managed exception dispatch is not yet modeled")
        }
        _ => bail!("Framework argument is not a managed string reference"),
    }
}
fn framework_type(metadata: &Metadata<'_>, token: u32, name: &str) -> Result<bool> {
    let ty = metadata.external_type(token)?;
    Ok(ty.namespace == "System"
        && ty.name == name
        && ty.assembly == "mscorlib"
        && ty.assembly_version == [4, 0, 0, 0])
}
impl Framework {
    fn resolve(&mut self, metadata: &Metadata<'_>, token: u32) -> Result<Arc<Model>> {
        if let Some(model) = self.cache.get(&token) {
            return Ok(Arc::clone(model));
        }
        let member = metadata.external_method(token)?;
        let signature = MethodSignature::parse(member.signature)?;
        ensure!(
            signature.convention == 0
                && !signature.explicit_this
                && signature.generic_parameters == 0
                && signature.optional_start.is_none(),
            "Framework generic/vararg/explicit-this signature is not modeled"
        );
        ensure!(
            member.namespace == "System"
                || (member.namespace == "System.IO"
                    && matches!(member.type_name, "File" | "MemoryStream" | "Stream"))
                || (member.namespace == "System.Runtime.CompilerServices"
                    && member.type_name == "RuntimeHelpers"),
            "Unmodeled framework namespace"
        );
        let assembly_ok = match member.type_name {
            "MemoryStream" | "Stream" if member.namespace == "System.IO" => {
                member.assembly == "mscorlib" && member.assembly_version == [4, 0, 0, 0]
            }
            "IDisposable" if member.namespace == "System" => {
                member.assembly == "mscorlib" && member.assembly_version == [4, 0, 0, 0]
            }
            "Convert" if member.namespace == "System" => {
                member.assembly == "mscorlib" && member.assembly_version == [4, 0, 0, 0]
            }
            "RuntimeHelpers" if member.namespace == "System.Runtime.CompilerServices" => {
                member.assembly == "mscorlib" && member.assembly_version == [4, 0, 0, 0]
            }
            "File" if member.namespace == "System.IO" => {
                member.assembly == "mscorlib" && member.assembly_version == [4, 0, 0, 0]
            }
            "Console" => matches!(
                member.assembly,
                "mscorlib" | "System.Console" | "netstandard"
            ),
            "String" => matches!(
                member.assembly,
                "mscorlib" | "System.Runtime" | "System.Private.CoreLib" | "netstandard"
            ),
            "Environment" => matches!(
                member.assembly,
                "mscorlib"
                    | "System.Runtime"
                    | "System.Runtime.Extensions"
                    | "System.Private.CoreLib"
                    | "netstandard"
            ),
            _ => false,
        };
        ensure!(
            assembly_ok,
            "Unmodeled framework assembly/type: {} / {}.{}",
            member.assembly,
            member.namespace,
            member.type_name
        );
        let params = signature.parameters.as_slice();
        let result = &signature.return_type;
        let stream_operation =
            if matches!(member.type_name, "MemoryStream" | "Stream" | "IDisposable") {
                streams::resolve(metadata, member.type_name, member.name, &signature)?
            } else {
                None
            };
        let function = if let Some(op) = stream_operation {
            Function::Stream(op)
        } else {
            match (
                member.type_name,
                member.name,
                signature.has_this,
                params,
                result,
            ) {
                (
                    "RuntimeHelpers",
                    "InitializeArray",
                    false,
                    [Type::Class(array), Type::ValueType(handle)],
                    Type::Void,
                ) if framework_type(metadata, *array, "Array")?
                    && framework_type(metadata, *handle, "RuntimeFieldHandle")? =>
                {
                    Function::InitializeArray
                }
                (
                    "File",
                    "WriteAllBytes",
                    false,
                    [Type::String, Type::Vector(inner)],
                    Type::Void,
                ) if **inner == Type::U1 => Function::FileWrite,
                ("File", "ReadAllBytes", false, [Type::String], Type::Vector(inner))
                    if **inner == Type::U1 =>
                {
                    Function::FileRead
                }
                ("File", "Exists", false, [Type::String], Type::Boolean) => Function::FileExists,
                ("Convert", "FromBase64String", false, [Type::String], Type::Vector(inner))
                    if **inner == Type::U1 =>
                {
                    Function::ConvertDecode
                }
                ("Convert", "ToBase64String", false, [Type::Vector(inner)], Type::String)
                    if **inner == Type::U1 =>
                {
                    Function::ConvertEncode
                }
                ("String", "Concat", false, [Type::String, Type::String], Type::String) => {
                    Function::Concat
                }
                ("String", "get_Length", true, [], Type::I4) => Function::Length,
                ("String", "get_Chars", true, [Type::I4], Type::Char) => Function::Char,
                ("String", "op_Equality", false, [Type::String, Type::String], Type::Boolean) => {
                    Function::Equal(false)
                }
                ("String", "op_Inequality", false, [Type::String, Type::String], Type::Boolean) => {
                    Function::Equal(true)
                }
                ("String", "IsNullOrEmpty", false, [Type::String], Type::Boolean) => {
                    Function::IsNullOrEmpty
                }
                ("Environment", "get_NewLine", false, [], Type::String) => Function::NewLine,
                ("Console", "WriteLine", false, [], Type::Void) => Function::Console(true),
                (
                    "Console",
                    name @ ("Write" | "WriteLine"),
                    false,
                    [Type::String | Type::I4 | Type::I8 | Type::Boolean | Type::Char],
                    Type::Void,
                ) => Function::Console(name == "WriteLine"),
                _ => bail!(
                    "Unmodeled framework method/signature: {}.{}.{}",
                    member.namespace,
                    member.type_name,
                    member.name
                ),
            }
        };
        ensure!(
            self.cache.len() < 4096,
            "Managed framework token cache exceeds bound"
        );
        let model = Arc::new(Model {
            assembly: member.assembly.to_owned(),
            version: member.assembly_version,
            name: format!("{}.{}.{}", member.namespace, member.type_name, member.name),
            signature,
            function,
        });
        self.cache.insert(token, Arc::clone(&model));
        Ok(model)
    }
    pub fn invoke(
        &mut self,
        metadata: &Metadata<'_>,
        token: u32,
        virtual_call: bool,
        stack: &mut Vec<Value>,
        heap: &mut Heap,
        arrays: &mut Arrays,
    ) -> Result<Option<Value>> {
        self.attempts += 1;
        let mut model = None;
        let mut recorded_args = Vec::new();
        let capture = self.events.len() < MAX_EVENTS;
        let result = (|| {
            let resolved = self.resolve(metadata, token)?;
            model = Some(Arc::clone(&resolved));
            let signature = &resolved.signature;
            ensure!(
                !virtual_call || signature.has_this,
                "callvirt cannot target a static framework method"
            );
            let count = signature.parameters.len() + usize::from(signature.has_this);
            ensure!(
                stack.len() >= count,
                "CIL evaluation stack underflow decoding framework arguments"
            );
            let first = stack.len() - count;
            let arguments = &stack[first..];
            if capture {
                recorded_args.extend(arguments);
            }
            ensure!(
                !matches!(
                    resolved.function,
                    Function::Stream(streams::Operation::Constructor)
                ),
                "MemoryStream constructors require newobj"
            );
            if signature.has_this {
                if matches!(resolved.function, Function::Stream(_)) {
                    self.streams.valid(streams::reference(arguments[0])?)?;
                } else {
                    units(heap, arguments[0], false)?;
                }
            }
            if matches!(resolved.function, Function::InitializeArray) {
                ensure!(
                    matches!(arguments[0], Value::ArrayRef { .. } | Value::Null)
                        && matches!(arguments[1], Value::FieldHandle(_)),
                    "Framework InitializeArray argument type mismatch"
                );
            } else {
                for (value, ty) in arguments[usize::from(signature.has_this)..]
                    .iter()
                    .zip(&signature.parameters)
                {
                    let accepted = if matches!(resolved.function, Function::Stream(_)) {
                        match ty {
                            Type::Class(_) => matches!(
                                value,
                                Value::Null
                                    | Value::ObjectRef {
                                        kind: super::ObjectKind::MemoryStream,
                                        ..
                                    }
                            ),
                            Type::U1 | Type::ValueType(_) => matches!(value, Value::I32(_)),
                            _ => accepts(*value, ty),
                        }
                    } else {
                        accepts(*value, ty)
                    };
                    ensure!(accepted, "Framework argument type mismatch");
                }
            }
            if let Some(observer) = self.observer.as_mut() {
                observer.framework_arguments(
                    heap,
                    &arguments[usize::from(signature.has_this)..],
                    &resolved.name,
                );
            }
            let value = self.execute(metadata, &resolved, arguments, heap, arrays)?;
            ensure!(
                match value {
                    Some(value) => accepts(value, &signature.return_type),
                    None => signature.return_type == Type::Void,
                },
                "Framework model return type mismatch"
            );
            if let Some(observer) = self.observer.as_mut() {
                observer.framework_return(heap, value, &resolved.name);
            }
            stack.truncate(first);
            self.completed += 1;
            if let Some(count) = self.counts.get_mut(&resolved.name) {
                *count += 1;
            } else {
                self.counts.insert(resolved.name.clone(), 1);
            }
            Ok(value)
        })();
        if capture {
            self.events.push(Event {
                token,
                assembly: model.as_ref().map(|m| m.assembly.clone()),
                assembly_version: model.as_ref().map(|m| m.version),
                method: model.as_ref().map(|m| m.name.clone()),
                virtual_call,
                arguments: recorded_args,
                result: result.as_ref().ok().copied().flatten(),
                error: result.as_ref().err().map(|e: &anyhow::Error| e.to_string()),
            });
        }
        result
    }
    fn execute(
        &mut self,
        metadata: &Metadata<'_>,
        model: &Model,
        args: &[Value],
        heap: &mut Heap,
        arrays: &mut Arrays,
    ) -> Result<Option<Value>> {
        Ok(match model.function {
            Function::InitializeArray => {
                ensure!(
                    args[0] != Value::Null,
                    "System.ArgumentNullException: array; managed exception dispatch is not yet modeled"
                );
                let Value::ArrayRef { reference, element } = args[0] else {
                    unreachable!()
                };
                let Value::FieldHandle(token) = args[1] else {
                    unreachable!()
                };
                let size = arrays.initializer_size(reference, element)?;
                let bytes = metadata.field_rva_data(token, size)?;
                arrays.initialize(reference, element, bytes)?;
                None
            }
            Function::Stream(op) => streams::execute(&mut self.streams, op, args, arrays, heap)?,
            Function::ConvertDecode => Some(convert::decode(heap, arrays, args[0])?),
            Function::ConvertEncode => Some(convert::encode(heap, arrays, args[0])?),
            Function::FileWrite => {
                self.files.write(heap, arrays, args[0], args[1])?;
                None
            }
            Function::FileRead => Some(self.files.read(heap, arrays, args[0])?),
            Function::FileExists => Some(Value::I32(i32::from(self.files.exists(heap, args[0])?))),
            Function::Concat => {
                let left = units(heap, args[0], true)?;
                let right = units(heap, args[1], true)?;
                let reference = if left.is_empty() && right.is_empty() {
                    heap.literal(Vec::new())?
                } else if left.is_empty() {
                    let Value::StringRef(r) = args[1] else {
                        unreachable!()
                    };
                    r
                } else if right.is_empty() {
                    let Value::StringRef(r) = args[0] else {
                        unreachable!()
                    };
                    r
                } else {
                    heap.ensure_capacity(left.len() + right.len())?;
                    let mut text = Vec::with_capacity(left.len() + right.len());
                    text.extend(left);
                    text.extend(right);
                    heap.allocate(text)?
                };
                Some(Value::StringRef(reference))
            }
            Function::Length => Some(Value::I32(units(heap, args[0], false)?.len() as i32)),
            Function::Char => {
                let Value::I32(index) = args[1] else {
                    unreachable!()
                };
                let text = units(heap, args[0], false)?;
                ensure!(
                    index >= 0 && (index as usize) < text.len(),
                    "System.IndexOutOfRangeException; managed exception dispatch is not yet modeled"
                );
                Some(Value::I32(text[index as usize] as i32))
            }
            Function::Equal(invert) => {
                let equal = if args[0] == Value::Null || args[1] == Value::Null {
                    args[0] == args[1]
                } else {
                    units(heap, args[0], false)? == units(heap, args[1], false)?
                };
                Some(Value::I32(i32::from(equal ^ invert)))
            }
            Function::IsNullOrEmpty => Some(Value::I32(i32::from(
                units(heap, args[0], true)?.is_empty(),
            ))),
            Function::NewLine => Some(Value::StringRef(heap.literal(vec![13, 10])?)),
            Function::Console(newline) => {
                let mut rendered = match (args.first(), model.signature.parameters.first()) {
                    (None, None) => Vec::new(),
                    (Some(value), Some(Type::String)) => units(heap, *value, true)?.to_vec(),
                    (Some(Value::I32(n)), Some(Type::Char)) => vec![*n as u16],
                    (Some(Value::I32(n)), Some(Type::Boolean)) => {
                        if *n == 0 { "False" } else { "True" }
                            .encode_utf16()
                            .collect()
                    }
                    (Some(Value::I32(n)), Some(Type::I4)) => n.to_string().encode_utf16().collect(),
                    (Some(Value::I64(n)), Some(Type::I8)) => n.to_string().encode_utf16().collect(),
                    _ => bail!("Unmodeled console argument type"),
                };
                if newline {
                    rendered.extend([13, 10]);
                }
                ensure!(
                    rendered.len() <= MAX_CONSOLE_UNITS - self.console.len(),
                    "Managed console output limit exceeded"
                );
                self.console.extend(rendered);
                None
            }
        })
    }
    pub fn valid_object(&self, reference: u32) -> Result<()> {
        self.streams.valid(reference).map_err(Into::into)
    }
    pub fn construct(
        &mut self,
        metadata: &Metadata<'_>,
        token: u32,
        stack: &mut Vec<Value>,
        stack_limit: usize,
        arrays: &Arrays,
    ) -> Result<Value> {
        self.attempts += 1;
        let mut model = None;
        let mut arguments = Vec::new();
        let capture = self.events.len() < MAX_EVENTS;
        let result = (|| {
            ensure!(
                token >> 24 == 10,
                "newobj requires a supported constructor MemberRef"
            );
            let resolved = self.resolve(metadata, token)?;
            model = Some(Arc::clone(&resolved));
            ensure!(
                matches!(
                    resolved.function,
                    Function::Stream(streams::Operation::Constructor)
                ),
                "Unmodeled newobj constructor"
            );
            let count = resolved.signature.parameters.len();
            ensure!(
                stack.len() >= count,
                "CIL evaluation stack underflow decoding constructor arguments"
            );
            let first = stack.len() - count;
            ensure!(
                first < stack_limit,
                "CIL evaluation stack exceeds declared max_stack"
            );
            let args = &stack[first..];
            if capture {
                arguments.extend(args);
            }
            for (value, ty) in args.iter().zip(&resolved.signature.parameters) {
                ensure!(
                    accepts(*value, ty),
                    "Framework constructor argument type mismatch"
                );
            }
            let value = streams::construct(&mut self.streams, args, arrays)?;
            stack.truncate(first);
            self.completed += 1;
            *self.counts.entry(resolved.name.clone()).or_default() += 1;
            Ok(value)
        })();
        if capture {
            self.events.push(Event {
                token,
                assembly: model.as_ref().map(|m| m.assembly.clone()),
                assembly_version: model.as_ref().map(|m| m.version),
                method: model.as_ref().map(|m| m.name.clone()),
                virtual_call: false,
                arguments,
                result: result.as_ref().ok().copied(),
                error: result.as_ref().err().map(|e: &anyhow::Error| e.to_string()),
            });
        }
        result
    }

    pub fn install_observer(&mut self, prepared: super::indicators::Prepared) {
        assert!(
            self.attempts == 0 && self.observer.is_none(),
            "Closed observer must be prepared before execution"
        );
        self.observer = Some(super::indicators::Observer::new(prepared));
    }
    pub fn observer_boundary(&mut self, count: u64) {
        if let Some(observer) = self.observer.as_mut() {
            observer.boundary(count);
        }
    }
    pub fn observe_literal(&mut self, heap: &Heap, reference: u32, token: u32, count: u64) {
        if let Some(observer) = self.observer.as_mut() {
            observer.literal(heap, reference, token, count);
        }
    }
    pub fn observe_arguments(&mut self, heap: &Heap, values: &[Value], name: &str, count: u64) {
        if let Some(observer) = self.observer.as_mut() {
            observer.arguments(heap, values, name, count);
        }
    }
    pub fn observe_return(&mut self, heap: &Heap, value: Option<Value>, name: &str, count: u64) {
        if let Some(observer) = self.observer.as_mut() {
            observer.returned(heap, value, name, count);
        }
    }
    pub fn finish_observer(
        &mut self,
        count: u64,
        method: u32,
        offset: u32,
    ) -> (
        Option<emumee_core::memory_strings::Report>,
        Option<emumee_core::managed_observation::Receipt>,
    ) {
        if let Some(observer) = self.observer.take() {
            let (capture, receipt) = observer.finish(count, method, offset);
            (Some(capture), Some(receipt))
        } else {
            (None, None)
        }
    }
    pub fn capture_artifacts(&mut self) -> emumee_core::artifacts::ArtifactCatalog {
        self.files.capture()
    }
    pub fn describe(self) -> Report {
        Report {
            attempts: self.attempts,
            completed_calls: self.completed,
            counts: self.counts,
            omitted_events: self.attempts - self.events.len() as u64,
            events: self.events,
            console_output: ConsoleOutput {
                text_lossy: String::from_utf16_lossy(&self.console),
                utf16: self.console,
                utf16_limit: MAX_CONSOLE_UNITS,
                newline_policy: "Windows CRLF for WriteLine; exact UTF16 retained, display text uses replacement for unpaired surrogates.",
            },
            files: self.files.describe(),
            streams: if self.streams.describe().objects == 0 {
                None
            } else {
                Some(self.streams.describe())
            },
            scope: "Explicit string/console models, checked mscorlib4.0 Convert Base64 byte-array/string calls, initial mscorlib4.0 ASCII guest-file models and checked RVA-backed array initialization. Checked guest MemoryStream identities/newobj are an initial closed subset; exception dispatch and buffer exposure remain gated. No host assembly loading, CLR invocation, host filesystem access or general framework availability is implied.",
        }
    }
}

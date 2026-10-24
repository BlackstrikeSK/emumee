//! Minimal CLI metadata and IL returning 17; never passed to a host runtime.
use super::*;
mod indicators;
pub use indicators::probe as managed_indicator_probe;
fn add_string(heap: &mut Vec<u8>, value: &str) -> u16 {
    let index = heap.len() as u16;
    heap.extend(value.as_bytes());
    heap.push(0);
    index
}
fn word(data: &mut Vec<u8>, value: u16) {
    data.extend(value.to_le_bytes());
}
fn dword(data: &mut Vec<u8>, value: u32) {
    data.extend(value.to_le_bytes());
}
struct ProgramMethod<'a> {
    name: &'a str,
    code: Vec<u8>,
    signature: Vec<u8>,
    locals: Vec<u8>,
    initialize_locals: bool,
}
struct Reference<'a> {
    assembly: &'a str,
    namespace: &'a str,
    type_name: &'a str,
    name: &'a str,
    signature: Vec<u8>,
    parent_tag: u16,
    scope_tag: u16,
    version: [u16; 4],
}
#[derive(Clone)]
struct DataBlob {
    bytes: Vec<u8>,
    signature: Vec<u8>,
    declared_size: u32,
    flags: u16,
    rva: u32,
    layout: bool,
    rva_row: bool,
    packing: u16,
}
impl<'a> Reference<'a> {
    fn new(assembly: &'a str, type_name: &'a str, name: &'a str, signature: &[u8]) -> Self {
        Self {
            assembly,
            namespace: "System",
            type_name,
            name,
            signature: signature.to_vec(),
            parent_tag: 1,
            scope_tag: 2,
            version: [4, 0, 0, 0],
        }
    }
}
fn add_blob(heap: &mut Vec<u8>, blob: &[u8]) -> u16 {
    assert!(blob.len() < 128);
    let index = heap.len() as u16;
    heap.push(blob.len() as u8);
    heap.extend(blob);
    index
}
fn program(architecture: Architecture, methods: &[ProgramMethod<'_>]) -> Vec<u8> {
    program_with_strings(architecture, methods, vec![0, 5, b'H', 0, b'i', 0, 0])
}
fn program_with_strings(
    architecture: Architecture,
    methods: &[ProgramMethod<'_>],
    user_strings: Vec<u8>,
) -> Vec<u8> {
    program_with_references(architecture, methods, user_strings, &[])
}
fn program_with_references(
    architecture: Architecture,
    methods: &[ProgramMethod<'_>],
    user_strings: Vec<u8>,
    references: &[Reference<'_>],
) -> Vec<u8> {
    program_with_data(architecture, methods, user_strings, references, None)
}
fn program_with_data(
    architecture: Architecture,
    methods: &[ProgramMethod<'_>],
    user_strings: Vec<u8>,
    references: &[Reference<'_>],
    data: Option<&DataBlob>,
) -> Vec<u8> {
    assert!(!methods.is_empty() && methods.len() <= 2);
    assert!(references.len() <= 16);
    let wide = architecture == Architecture::X64;
    let mut image = counted_driver(architecture, 17);
    put16(&mut image, 0x96, 0x22);
    put16(&mut image, 0x98 + 68, 3);
    let data_section = 0x98 + if wide { 0xf0 } else { 0xe0 } + 40;
    put32(&mut image, data_section + 36, 0x40000040);
    image[0x200..0x400].fill(0);
    let mut strings = vec![0];
    let module = add_string(&mut strings, "Fixture.exe");
    let type_name = add_string(&mut strings, "<Module>");
    let mut blobs = vec![0];
    let mut rows = Vec::new();
    let mut local_rows = Vec::new();
    for (index, method) in methods.iter().enumerate() {
        let name = add_string(&mut strings, method.name);
        let signature = add_blob(&mut blobs, &method.signature);
        let local_token = if method.locals.is_empty() {
            0
        } else {
            let blob = add_blob(&mut blobs, &method.locals);
            local_rows.push(blob);
            0x11000000 | local_rows.len() as u32
        };
        let rva = if index == 0 { 0x1000 } else { 0x1180 };
        let raw = (rva - 0xe00) as usize;
        let header = if local_token != 0 || method.initialize_locals || method.code.len() > 63 {
            put16(
                &mut image,
                raw,
                0x3003 | if method.initialize_locals { 0x10 } else { 0 },
            );
            put16(&mut image, raw + 2, 8);
            put32(&mut image, raw + 4, method.code.len() as u32);
            put32(&mut image, raw + 8, local_token);
            12
        } else {
            assert!(method.code.len() <= 63);
            image[raw] = (method.code.len() as u8) << 2 | 2;
            1
        };
        assert!(header + method.code.len() <= 128);
        image[raw + header..raw + header + method.code.len()].copy_from_slice(&method.code);
        rows.push((rva, name, signature));
    }
    let assembly = add_string(&mut strings, "Fixture");
    let reference_rows: Vec<_> = references
        .iter()
        .map(|r| {
            (
                add_string(&mut strings, r.assembly),
                add_string(&mut strings, r.namespace),
                add_string(&mut strings, r.type_name),
                add_string(&mut strings, r.name),
                add_blob(&mut blobs, &r.signature),
                r.parent_tag,
                r.scope_tag,
                r.version,
            )
        })
        .collect();
    let field_info = data.map(|data| {
        (
            add_string(&mut strings, "FixtureData"),
            add_string(&mut strings, "Data"),
            add_blob(&mut blobs, &data.signature),
        )
    });
    let mut tables = vec![0; 24];
    tables[4] = 2;
    tables[7] = 1;
    let mask = (1u64 << 0)
        | (1u64 << 2)
        | (1u64 << 6)
        | (1u64 << 32)
        | if local_rows.is_empty() { 0 } else { 1u64 << 17 }
        | if reference_rows.is_empty() {
            0
        } else {
            (1u64 << 1) | (1u64 << 10) | (1u64 << 35)
        }
        | if data.is_some() { 1u64 << 4 } else { 0 }
        | if data.is_some_and(|d| d.layout) {
            1u64 << 15
        } else {
            0
        }
        | if data.is_some_and(|d| d.rva_row) {
            1u64 << 29
        } else {
            0
        };
    tables[8..16].copy_from_slice(&mask.to_le_bytes());
    for id in 0..45 {
        if mask & (1u64 << id) != 0 {
            dword(
                &mut tables,
                match id {
                    6 => methods.len() as u32,
                    2 if data.is_some() => 2,
                    17 => local_rows.len() as u32,
                    1 | 10 | 35 => reference_rows.len() as u32,
                    _ => 1,
                },
            );
        }
    }
    for value in [0, module, 1, 0, 0] {
        word(&mut tables, value);
    }
    for (index, row) in reference_rows.iter().enumerate() {
        for value in [((index as u16 + 1) << 2) | row.6, row.2, row.1] {
            word(&mut tables, value);
        }
    }
    dword(&mut tables, 0);
    for value in [type_name, 0, 0, 1, 1] {
        word(&mut tables, value);
    }
    if let Some((name, field_name, signature)) = field_info {
        dword(&mut tables, 0x110);
        for value in [name, 0, 9, 2, methods.len() as u16 + 1] {
            word(&mut tables, value);
        }
        for value in [data.unwrap().flags, field_name, signature] {
            word(&mut tables, value);
        }
    }
    for (rva, name, signature) in rows {
        dword(&mut tables, rva);
        for value in [0, 0x16, name, signature, 1] {
            word(&mut tables, value);
        }
    }
    for (index, row) in reference_rows.iter().enumerate() {
        for value in [((index as u16 + 1) << 3) | row.5, row.3, row.4] {
            word(&mut tables, value);
        }
    }
    if let Some(data) = data.filter(|d| d.layout) {
        word(&mut tables, data.packing);
        dword(&mut tables, data.declared_size);
        word(&mut tables, 2);
    }
    for blob in local_rows {
        word(&mut tables, blob);
    }
    if let Some(data) = data.filter(|d| d.rva_row) {
        dword(&mut tables, data.rva);
        word(&mut tables, 1);
    }
    dword(&mut tables, 0);
    for value in [1, 0, 0, 0] {
        word(&mut tables, value);
    }
    dword(&mut tables, 0);
    for value in [0, assembly, 0] {
        word(&mut tables, value);
    }
    for row in reference_rows {
        for value in row.7 {
            word(&mut tables, value);
        }
        dword(&mut tables, 0);
        for value in [0, row.0, 0, 0] {
            word(&mut tables, value);
        }
    }
    let streams = [
        ("#~", tables),
        ("#Strings", strings),
        ("#Blob", blobs),
        ("#GUID", vec![0x42; 16]),
        ("#US", user_strings),
    ];
    let mut root = vec![0; 32];
    root[..4].copy_from_slice(b"BSJB");
    put16(&mut root, 4, 1);
    put16(&mut root, 6, 1);
    put32(&mut root, 12, 12);
    root[16..27].copy_from_slice(b"v4.0.30319\0");
    put16(&mut root, 30, 5);
    let mut patches = Vec::new();
    for (name, _) in &streams {
        patches.push(root.len());
        root.extend([0; 8]);
        root.extend(name.as_bytes());
        root.push(0);
        while root.len() % 4 != 0 {
            root.push(0);
        }
    }
    for ((_, bytes), patch) in streams.into_iter().zip(patches) {
        let at = root.len() as u32;
        put32(&mut root, patch, at);
        put32(&mut root, patch + 4, bytes.len() as u32);
        root.extend(bytes);
        while root.len() % 4 != 0 {
            root.push(0);
        }
    }
    let raw_size = if data.is_some() {
        4096
    } else {
        (0x80 + root.len() + 511) & !511
    };
    assert!(raw_size <= 4096);
    image.resize(0x400 + raw_size, 0);
    put32(&mut image, 0x98 + 8, raw_size as u32);
    put32(&mut image, data_section + 8, raw_size as u32);
    put32(&mut image, data_section + 16, raw_size as u32);
    image[0x400..0x480].fill(0);
    put32(&mut image, 0x400, 72);
    put16(&mut image, 0x404, 2);
    put16(&mut image, 0x406, 5);
    put32(&mut image, 0x408, 0x2080);
    put32(&mut image, 0x40c, root.len() as u32);
    put32(&mut image, 0x410, 1);
    put32(&mut image, 0x414, 0x06000001);
    image[0x480..0x480 + root.len()].copy_from_slice(&root);
    if let Some(data) = data {
        assert!(data.bytes.len() <= 512);
        image[0x1200..0x1200 + data.bytes.len()].copy_from_slice(&data.bytes);
    }
    let directory = 0x98 + if wide { 112 } else { 96 };
    put32(&mut image, directory + 14 * 8, 0x2000);
    put32(&mut image, directory + 14 * 8 + 4, 72);
    image
}
pub fn managed_probe(architecture: Architecture) -> Vec<u8> {
    program(
        architecture,
        &[ProgramMethod {
            name: "Main",
            code: vec![0x1f, 17, 0x2a],
            signature: vec![0, 0, 8],
            locals: Vec::new(),
            initialize_locals: false,
        }],
    )
}

#[derive(Clone, Copy, Debug)]
pub enum CilFixture {
    StreamOwned,
    StreamFile,
    StreamToArrayLimit,
    StreamBorrowedWrite,
    StreamBorrowedRead,
    StreamReadOnly,
    StreamCanWrite,
    StreamFixed,
    StreamToArrayCopy,
    StreamClose,
    StreamClosedRead,
    StreamClosedCan,
    StreamSparse,
    StreamEmptyWrite,
    StreamShrink,
    StreamSeek,
    StreamRead,
    StreamCopy,
    StreamSelfCopy,
    StreamIdentity,
    StreamAlias,
    StreamObjectLocal,
    StreamBaseLocal,
    StreamObjectClassLocal,
    StreamObjectArray,
    StreamObjectArrayKinds,
    StreamObjectBadValue,
    StreamStaticCall,
    StreamQuota,
    StreamOwnedQuota,
    StreamNullBuffer,
    StreamBadFlag,
    StreamBadCapacity,
    StreamBadSignature,
    StreamBadAssembly,
    StreamBadVersion,
    StreamBadNamespace,
    StreamBadOwner,
    StreamBadScope,
    StreamConstructorCall,
    StreamConstructorStack,
    StreamNullReceiver,
    StreamExposure,
    StreamUnknownClass,

    ConvertBytes,
    ConvertWhitespace,
    ConvertEmpty,
    ConvertTrailingBits,
    ConvertWritable,
    ConvertIdentity,
    ConvertRoundTrip,
    ConvertEncodeEmpty,
    ConvertFile,
    ConvertMalformed,
    ConvertPadding,
    ConvertUnicode,
    ConvertSurrogate,
    ConvertNull,
    ConvertNullBytes,
    ConvertBadArgument,
    ConvertWrongArray,
    ConvertBadSignature,
    ConvertBadAssembly,
    ConvertBadVersion,
    ConvertBadNamespace,
    ConvertBadOwner,
    ConvertBadScope,
    ConvertStaticVirtual,
    ConvertQuota,
    ConvertHeapQuota,
    ConvertDecodeLimit,
    ConvertLargeEncode,

    RvaDecode,
    RvaBytes,
    RvaI32,
    RvaZero,
    RvaTwice,
    RvaBadHandle,
    RvaMissingField,
    RvaNoRva,
    RvaMissingRow,
    RvaNoLayout,
    RvaBadPacking,
    RvaTooSmall,
    RvaBadRva,
    RvaReferenceField,
    RvaLiteral,
    RvaWrongArray,
    RvaNullArray,
    RvaBadSignature,
    RvaHandleBranch,
    FileRoundTrip,
    FileOverwrite,
    FileEmpty,
    FileEmptyExists,
    FileExists,
    FileExistsNull,
    FileMissing,
    FileParentMissing,
    FileNullPath,
    FileNullBytes,
    FileInvalidPath,
    FileUnsupportedPath,
    FileBadSignature,
    FileBadAssembly,
    FileBadArrayType,
    FileEscape,
    FileDedupe,
    FilePartial,
    ArrayByte,
    ArrayI32,
    ArrayString,
    ArrayStringZero,
    ArrayLength,
    ArrayLengthType,
    ArrayNativeLength,
    ArrayLocal,
    ArrayLocalNull,
    ArrayCall,
    ArrayIdentity,
    ArrayDifferent,
    ArrayZeroByte,
    ArrayNull,
    ArrayBounds,
    ArrayBadValue,
    ArrayBadOpcode,
    ArrayTooLarge,
    ArrayNegative,
    ArrayUnknownType,
    ArrayBadAssembly,
    ArrayBadLocal,
    ArrayQuota,
    ArrayBadLengthType,
    ArrayVsString,
    FrameworkConsoleTypes,
    FrameworkNullOrEmpty,
    FrameworkInequality,
    FrameworkStrings,
    FrameworkConcatIdentity,
    FrameworkStringEquality,
    FrameworkConcatEmpty,
    FrameworkConcatNull,
    FrameworkUnicodeLength,
    FrameworkChar,
    FrameworkNullLength,
    FrameworkBadIndex,
    FrameworkBadAssembly,
    FrameworkBadSignature,
    FrameworkStaticVirtual,
    FrameworkUnknown,
    FrameworkBadOwner,
    FrameworkBadScope,
    FrameworkConsole,
    FrameworkConsoleNull,
    FrameworkConsoleLimit,
    FrameworkArgumentType,
    StringIdentity,
    StringAliases,
    StringLocal,
    StringLocalNull,
    StringCall,
    StringReturn,
    StringBadToken,
    StringMissing,
    StringBadType,
    StringRelational,
    LocalsLoop,
    LocalZero,
    LocalIndexed,
    CallArguments,
    ArgumentStore,
    VoidReturn,
    VoidCall,
    Recursive,
    DeepRecursion,
    LocalUninitialized,
    LocalBadType,
    ArgumentBadType,
    Return,
    Loop,
    Arithmetic,
    I64Arithmetic,
    BadBranch,
    Underflow,
    DivideZero,
    Unsupported,
    ReturnStack,
    StackLimit,
    Infinite,
}
mod convert;
mod streams;
pub fn cil_probe(architecture: Architecture, fixture: CilFixture, iterations: u32) -> Vec<u8> {
    if let Some(image) = streams::probe(architecture, fixture) {
        return image;
    }
    if let Some(image) = convert::probe(architecture, fixture) {
        return image;
    }
    if let Some(image) = rva_probe(architecture, fixture) {
        return image;
    }
    if let Some(image) = file_probe(architecture, fixture) {
        return image;
    }
    if let Some(image) = array_probe(architecture, fixture) {
        return image;
    }
    if let Some(image) = framework_probe(architecture, fixture) {
        return image;
    }
    let mut image = managed_probe(architecture);
    let mut code = Vec::new();
    match fixture {
        CilFixture::Return => code.extend([0x1f, 17, 0x2a]),
        CilFixture::Loop => {
            code.push(0x20);
            code.extend(iterations.to_le_bytes());
            code.extend([0x17, 0x59, 0x25, 0x2d, 0xfb, 0x26, 0x20]);
            code.extend(iterations.to_le_bytes());
            code.push(0x2a);
        }
        CilFixture::Arithmetic => {
            code.push(0x20);
            code.extend(i32::MAX.to_le_bytes());
            code.extend([0x17, 0x58, 0x15, 0x61, 0x2a]);
        }
        CilFixture::I64Arithmetic => {
            code.push(0x21);
            code.extend(i64::MAX.to_le_bytes());
            code.extend([0x17, 0x6a, 0x58, 0x17, 0x6a, 0x59, 0x2a]);
            let blob = u32::from_le_bytes(image[0x4c0..0x4c4].try_into().unwrap()) as usize;
            image[0x480 + blob + 4] = 0x0a;
        }
        CilFixture::BadBranch => {
            code.extend([0x2b, 1, 0x20]);
            code.extend(17i32.to_le_bytes());
            code.push(0x2a);
        }
        CilFixture::Underflow => code.extend([0x58, 0x2a]),
        CilFixture::DivideZero => code.extend([0x17, 0x16, 0x5b, 0x2a]),
        CilFixture::Unsupported => code.extend([0x1a, 0xfe, 0x0f, 0x2a]),
        CilFixture::ReturnStack => code.extend([0x17, 0x18, 0x2a]),
        CilFixture::StackLimit => {
            code.extend([0x17; 9]);
            code.push(0x2a);
        }
        CilFixture::Infinite => code.extend([0x2b, 0xfe]),
        _ => return frame_probe(architecture, fixture, iterations),
    }
    assert!(code.len() <= 63);
    image[0x200..0x240].fill(0);
    image[0x200] = (code.len() as u8) << 2 | 2;
    image[0x201..0x201 + code.len()].copy_from_slice(&code);
    image
}

fn rva_probe(architecture: Architecture, fixture: CilFixture) -> Option<Vec<u8>> {
    if !matches!(
        fixture,
        CilFixture::RvaDecode
            | CilFixture::RvaBytes
            | CilFixture::RvaI32
            | CilFixture::RvaZero
            | CilFixture::RvaTwice
            | CilFixture::RvaBadHandle
            | CilFixture::RvaMissingField
            | CilFixture::RvaNoRva
            | CilFixture::RvaMissingRow
            | CilFixture::RvaNoLayout
            | CilFixture::RvaBadPacking
            | CilFixture::RvaTooSmall
            | CilFixture::RvaBadRva
            | CilFixture::RvaReferenceField
            | CilFixture::RvaLiteral
            | CilFixture::RvaWrongArray
            | CilFixture::RvaNullArray
            | CilFixture::RvaBadSignature
            | CilFixture::RvaHandleBranch
    ) {
        return None;
    }
    fn token(code: &mut Vec<u8>, op: u8, value: u32) {
        code.push(op);
        code.extend(value.to_le_bytes());
    }
    fn init(code: &mut Vec<u8>) {
        token(code, 0x28, 0x0a000005);
    }
    let mut refs = vec![
        Reference::new("mscorlib", "Byte", "UnusedTypeReference", &[0, 0, 1]),
        Reference::new("mscorlib", "ValueType", "UnusedTypeReference", &[0, 0, 1]),
        Reference::new("mscorlib", "Array", "UnusedTypeReference", &[0, 0, 1]),
        Reference::new(
            "mscorlib",
            "RuntimeFieldHandle",
            "UnusedTypeReference",
            &[0, 0, 1],
        ),
        Reference::new(
            "mscorlib",
            "RuntimeHelpers",
            "InitializeArray",
            &[0, 2, 1, 0x12, 13, 0x11, 17],
        ),
        Reference::new(
            "mscorlib",
            "File",
            "WriteAllBytes",
            &[0, 2, 1, 0x0e, 0x1d, 5],
        ),
    ];
    refs[4].namespace = "System.Runtime.CompilerServices";
    refs[5].namespace = "System.IO";
    let mut data = DataBlob {
        bytes: b"RUST".to_vec(),
        signature: vec![6, 0x11, 8],
        declared_size: 4,
        flags: 0x110,
        rva: 0x2e00,
        layout: true,
        rva_row: true,
        packing: 1,
    };
    let length = match fixture {
        CilFixture::RvaI32 => {
            refs[0].type_name = "Int32";
            data.bytes = vec![255, 255, 255, 255, 17, 0, 0, 0];
            data.declared_size = 8;
            2
        }
        CilFixture::RvaZero => 0,
        _ => 4,
    };
    match fixture {
        CilFixture::RvaDecode => data.bytes = b"RUST".iter().map(|b| b ^ 0x5a).collect(),
        CilFixture::RvaNoRva => data.flags = 0x10,
        CilFixture::RvaMissingRow => data.rva_row = false,
        CilFixture::RvaNoLayout => data.layout = false,
        CilFixture::RvaBadPacking => data.packing = 3,
        CilFixture::RvaTooSmall => data.declared_size = 3,
        CilFixture::RvaBadRva => data.rva = 0x2fff,
        CilFixture::RvaReferenceField => data.signature = vec![6, 0x0e],
        CilFixture::RvaLiteral => data.flags = 0x150,
        CilFixture::RvaWrongArray => refs[0].type_name = "String",
        CilFixture::RvaBadSignature => refs[4].signature = vec![0, 2, 8, 0x12, 13, 0x11, 17],
        _ => {}
    }
    let mut main = ProgramMethod {
        name: "Main",
        code: Vec::new(),
        signature: vec![0, 0, 8],
        locals: Vec::new(),
        initialize_locals: false,
    };
    if matches!(fixture, CilFixture::RvaHandleBranch) {
        token(&mut main.code, 0xd0, 0x04000001);
        main.code.extend([0x2d, 2, 0x16, 0x2a, 0x17, 0x2a]);
    } else {
        if matches!(fixture, CilFixture::RvaNullArray) {
            main.code.push(0x14);
        } else {
            main.code.push(0x16 + length);
            token(&mut main.code, 0x8d, 0x01000001);
            main.code.push(0x25);
        }
        token(
            &mut main.code,
            if matches!(fixture, CilFixture::RvaBadHandle) {
                0x20
            } else {
                0xd0
            },
            if matches!(fixture, CilFixture::RvaMissingField) {
                0x04000002
            } else {
                0x04000001
            },
        );
        init(&mut main.code);
        match fixture {
            CilFixture::RvaDecode => {
                main.locals = vec![7, 2, 0x1d, 5, 8];
                main.initialize_locals = true;
                main.code.extend([0x0a, 0x16, 0x0b]);
                let start = main.code.len();
                main.code.extend([
                    0x06, 0x07, 0x06, 0x07, 0x91, 0x1f, 0x5a, 0x61, 0x9c, 0x07, 0x17, 0x58, 0x25,
                    0x0b, 0x1a, 0x32, 0,
                ]);
                let end = main.code.len();
                main.code[end - 1] = (start as isize - end as isize) as i8 as u8;
                token(&mut main.code, 0x72, 0x70000001);
                main.code.push(0x06);
                token(&mut main.code, 0x28, 0x0a000006);
                main.code.extend([0x06, 0x16, 0x91, 0x2a]);
            }
            CilFixture::RvaTwice => {
                main.code.extend([0x25, 0x16, 0x17, 0x9c, 0x25]);
                token(&mut main.code, 0xd0, 0x04000001);
                init(&mut main.code);
                main.code.extend([0x16, 0x91, 0x2a]);
            }
            CilFixture::RvaI32 => main.code.extend([0x17, 0x94, 0x2a]),
            CilFixture::RvaZero => main.code.extend([0x8e, 0x69, 0x2a]),
            CilFixture::RvaNullArray => main.code.extend([0x16, 0x2a]),
            _ => main.code.extend([0x16, 0x91, 0x2a]),
        }
    }
    let mut us = vec![0, 19];
    for u in "field.bin".encode_utf16() {
        us.extend(u.to_le_bytes());
    }
    us.push(0);
    Some(program_with_data(
        architecture,
        &[main],
        us,
        &refs,
        Some(&data),
    ))
}

fn file_probe(architecture: Architecture, fixture: CilFixture) -> Option<Vec<u8>> {
    fn token(code: &mut Vec<u8>, op: u8, value: u32) {
        code.push(op);
        code.extend(value.to_le_bytes());
    }
    fn literal(code: &mut Vec<u8>, index: u32) {
        token(code, 0x72, 0x70000000 | index);
    }
    fn call(code: &mut Vec<u8>, index: u32) {
        token(code, 0x28, 0x0a000000 | index);
    }
    fn string(heap: &mut Vec<u8>, text: &str) -> u32 {
        let units: Vec<u16> = text.encode_utf16().collect();
        let size = units.len() * 2 + 1;
        assert!(size < 128);
        let at = heap.len() as u32;
        heap.push(size as u8);
        for u in &units {
            heap.extend(u.to_le_bytes());
        }
        heap.push(u8::from(units.iter().any(|u| {
            *u > 255 || matches!(*u,0 | 1..=8 | 14..=31 | 0x27 | 0x2d | 0x7f)
        })));
        at
    }
    fn file<'a>(name: &'a str, signature: &[u8]) -> Reference<'a> {
        let mut r = Reference::new("mscorlib", "File", name, signature);
        r.namespace = "System.IO";
        r
    }
    fn marker(code: &mut Vec<u8>, int32: bool) {
        code.push(0x1a);
        token(code, 0x8d, 0x01000001);
        for (index, byte) in b"RUST".iter().enumerate() {
            code.extend([
                0x25,
                0x16 + index as u8,
                0x1f,
                *byte,
                if int32 { 0x9e } else { 0x9c },
            ]);
        }
        code.push(0x0a);
    }
    let mut refs = vec![
        Reference::new("mscorlib", "Byte", "UnusedTypeReference", &[0, 0, 1]),
        file("WriteAllBytes", &[0, 2, 1, 0x0e, 0x1d, 5]),
        file("ReadAllBytes", &[0, 1, 0x1d, 5, 0x0e]),
        file("Exists", &[0, 1, 2, 0x0e]),
    ];
    let mut user_strings = vec![0];
    let name = match fixture {
        CilFixture::FileParentMissing => "missing\\result.bin",
        CilFixture::FileInvalidPath => "bad\0.bin",
        CilFixture::FileUnsupportedPath => "\\\\server\\share\\result.bin",
        CilFixture::FileEscape => "..\\..\\escaped.bin",
        CilFixture::FileExists => "Cargo.toml",
        CilFixture::FileDedupe => "one.bin",
        _ => "result.bin",
    };
    let first = string(&mut user_strings, name);
    let second = string(&mut user_strings, "two.bin");
    let mut code = Vec::new();
    let bad_array = matches!(fixture, CilFixture::FileBadArrayType);
    match fixture {
        CilFixture::FileExists | CilFixture::FileExistsNull => {
            if matches!(fixture, CilFixture::FileExistsNull) {
                code.push(0x14);
            } else {
                literal(&mut code, first);
            }
            call(&mut code, 4);
            code.push(0x2a);
        }
        CilFixture::FileMissing => {
            literal(&mut code, first);
            call(&mut code, 3);
            code.extend([0x26, 0x16, 0x2a]);
        }
        CilFixture::FileNullBytes => {
            literal(&mut code, first);
            code.push(0x14);
            call(&mut code, 2);
            code.extend([0x16, 0x2a]);
        }
        CilFixture::FileEmpty | CilFixture::FileEmptyExists => {
            code.push(0x16);
            token(&mut code, 0x8d, 0x01000001);
            code.push(0x0a);
            literal(&mut code, first);
            code.push(0x06);
            call(&mut code, 2);
            literal(&mut code, first);
            if matches!(fixture, CilFixture::FileEmptyExists) {
                call(&mut code, 4);
            } else {
                call(&mut code, 3);
                code.extend([0x8e, 0x69]);
            }
            code.push(0x2a);
        }
        CilFixture::FileRoundTrip
        | CilFixture::FileOverwrite
        | CilFixture::FileParentMissing
        | CilFixture::FileNullPath
        | CilFixture::FileInvalidPath
        | CilFixture::FileUnsupportedPath
        | CilFixture::FileBadSignature
        | CilFixture::FileBadAssembly
        | CilFixture::FileBadArrayType
        | CilFixture::FileEscape
        | CilFixture::FileDedupe
        | CilFixture::FilePartial => {
            if bad_array {
                refs[0].type_name = "Int32";
            }
            if matches!(fixture, CilFixture::FileBadSignature) {
                refs[1].signature = vec![0, 2, 8, 0x0e, 0x1d, 5];
            }
            if matches!(fixture, CilFixture::FileBadAssembly) {
                refs[1].assembly = "System.IO.FileSystem";
            }
            marker(&mut code, bad_array);
            if matches!(fixture, CilFixture::FileNullPath) {
                code.push(0x14);
            } else {
                literal(&mut code, first);
            }
            code.push(0x06);
            call(&mut code, 2);
            match fixture {
                CilFixture::FileRoundTrip => {
                    code.extend([0x06, 0x16, 0x17, 0x9c]);
                    literal(&mut code, first);
                    call(&mut code, 3);
                    code.push(0x0b);
                    code.extend([0x07, 0x16, 0x17, 0x9c]);
                    literal(&mut code, first);
                    call(&mut code, 3);
                    code.extend([0x16, 0x91, 0x2a]);
                }
                CilFixture::FileOverwrite => {
                    code.push(0x17);
                    token(&mut code, 0x8d, 0x01000001);
                    code.extend([0x25, 0x16, 0x1f, 65, 0x9c, 0x0a]);
                    literal(&mut code, first);
                    code.push(0x06);
                    call(&mut code, 2);
                    literal(&mut code, first);
                    call(&mut code, 3);
                    code.extend([0x8e, 0x69, 0x2a]);
                }
                CilFixture::FileEscape => {
                    literal(&mut code, first);
                    call(&mut code, 4);
                    code.push(0x2a);
                }
                CilFixture::FileDedupe => {
                    literal(&mut code, second);
                    code.push(0x06);
                    call(&mut code, 2);
                    literal(&mut code, first);
                    call(&mut code, 4);
                    literal(&mut code, second);
                    call(&mut code, 4);
                    code.extend([0x58, 0x2a]);
                }
                CilFixture::FilePartial => {
                    refs.push(Reference::new(
                        "mscorlib",
                        "Environment",
                        "get_MachineName",
                        &[0, 0, 0x0e],
                    ));
                    call(&mut code, 5);
                    code.extend([0x26, 0x16, 0x2a]);
                }
                _ => code.extend([0x16, 0x2a]),
            }
        }
        _ => return None,
    }
    Some(program_with_references(
        architecture,
        &[ProgramMethod {
            name: "Main",
            code,
            signature: vec![0, 0, 8],
            locals: vec![7, 2, 0x1d, if bad_array { 8 } else { 5 }, 0x1d, 5],
            initialize_locals: true,
        }],
        user_strings,
        &refs,
    ))
}

fn array_probe(architecture: Architecture, fixture: CilFixture) -> Option<Vec<u8>> {
    fn newarr(code: &mut Vec<u8>) {
        code.extend([0x8d, 1, 0, 0, 1]);
    }
    let mut reference = Reference::new("mscorlib", "Byte", "UnusedTypeReference", &[0, 0, 1]);
    let mut main = ProgramMethod {
        name: "Main",
        code: Vec::new(),
        signature: vec![0, 0, 8],
        locals: Vec::new(),
        initialize_locals: false,
    };
    let mut helper = None;
    match fixture {
        CilFixture::ArrayByte | CilFixture::ArrayI32 => {
            let wide = matches!(fixture, CilFixture::ArrayI32);
            if wide {
                reference.type_name = "Int32";
            }
            main.code.push(0x18);
            newarr(&mut main.code);
            main.code.extend([0x25, 0x17]);
            if wide {
                main.code.extend([0x1f, (-17i8) as u8]);
            } else {
                main.code.push(0x15);
            }
            main.code.extend([
                if wide { 0x9e } else { 0x9c },
                0x17,
                if wide { 0x94 } else { 0x91 },
                0x2a,
            ]);
        }
        CilFixture::ArrayString | CilFixture::ArrayStringZero => {
            reference.type_name = "String";
            main.code.push(0x17);
            newarr(&mut main.code);
            if matches!(fixture, CilFixture::ArrayString) {
                main.code.extend([
                    0x25, 0x16, 0x72, 1, 0, 0, 0x70, 0xa2, 0x16, 0x9a, 0x72, 1, 0, 0, 0x70, 0xfe,
                    1, 0x2a,
                ]);
            } else {
                main.code.extend([0x16, 0x9a, 0x14, 0xfe, 1, 0x2a]);
            }
        }
        CilFixture::ArrayLength | CilFixture::ArrayLengthType | CilFixture::ArrayNativeLength => {
            main.code.push(0x19);
            newarr(&mut main.code);
            if matches!(fixture, CilFixture::ArrayNativeLength) {
                main.code.extend([0x25, 0x8e]);
                newarr(&mut main.code);
                main.code.push(0x26);
            }
            main.code.push(0x8e);
            if !matches!(fixture, CilFixture::ArrayLengthType) {
                main.code.push(0x69);
            }
            main.code.push(0x2a);
        }
        CilFixture::ArrayLocal | CilFixture::ArrayLocalNull | CilFixture::ArrayBadLocal => {
            main.locals = vec![
                7,
                1,
                0x1d,
                if matches!(fixture, CilFixture::ArrayBadLocal) {
                    8
                } else {
                    5
                },
            ];
            main.initialize_locals = true;
            if matches!(fixture, CilFixture::ArrayLocalNull) {
                main.code.extend([0x06, 0x14, 0xfe, 1, 0x2a]);
            } else {
                main.code.push(0x18);
                newarr(&mut main.code);
                main.code
                    .extend([0x0a, 0x06, 0x17, 0x1f, 17, 0x9c, 0x06, 0x17, 0x91, 0x2a]);
            }
        }
        CilFixture::ArrayCall => {
            main.code.push(0x19);
            newarr(&mut main.code);
            main.code.extend([
                0x25, 0x16, 0x1f, 17, 0x9c, 0x28, 2, 0, 0, 6, 0x16, 0x91, 0x2a,
            ]);
            helper = Some(ProgramMethod {
                name: "Identity",
                code: vec![0x02, 0x2a],
                signature: vec![0, 1, 0x1d, 5, 0x1d, 5],
                locals: Vec::new(),
                initialize_locals: false,
            });
        }
        CilFixture::ArrayVsString => {
            main.code.push(0x17);
            newarr(&mut main.code);
            main.code.extend([0x72, 1, 0, 0, 0x70, 0xfe, 1, 0x2a]);
        }
        CilFixture::ArrayIdentity | CilFixture::ArrayDifferent => {
            main.code.push(0x16);
            newarr(&mut main.code);
            if matches!(fixture, CilFixture::ArrayIdentity) {
                main.code.push(0x25);
            } else {
                main.code.push(0x16);
                newarr(&mut main.code);
            }
            main.code.extend([0xfe, 1, 0x2a]);
        }
        CilFixture::ArrayZeroByte => {
            main.code.push(0x18);
            newarr(&mut main.code);
            main.code.extend([0x17, 0x91, 0x2a]);
        }
        CilFixture::ArrayNull => main.code.extend([0x14, 0x16, 0x91, 0x2a]),
        CilFixture::ArrayBounds | CilFixture::ArrayBadValue => {
            main.code.push(0x17);
            newarr(&mut main.code);
            main.code.push(0x25);
            if matches!(fixture, CilFixture::ArrayBounds) {
                main.code.extend([0x17, 0x1f, 17]);
            } else {
                main.code.extend([0x16, 0x21]);
                main.code.extend(17i64.to_le_bytes());
            }
            main.code.extend([0x9c, 0x16, 0x2a]);
        }
        CilFixture::ArrayBadOpcode => {
            main.code.push(0x17);
            newarr(&mut main.code);
            main.code.extend([0x16, 0x94, 0x2a]);
        }
        CilFixture::ArrayTooLarge
        | CilFixture::ArrayNegative
        | CilFixture::ArrayUnknownType
        | CilFixture::ArrayBadAssembly
        | CilFixture::ArrayBadLengthType => {
            match fixture {
                CilFixture::ArrayTooLarge => {
                    main.code.push(0x20);
                    main.code.extend(1_048_577i32.to_le_bytes());
                }
                CilFixture::ArrayNegative => main.code.push(0x15),
                CilFixture::ArrayBadLengthType => {
                    main.code.push(0x21);
                    main.code.extend(17i64.to_le_bytes());
                }
                CilFixture::ArrayUnknownType => {
                    reference.type_name = "Int64";
                    main.code.push(0x17);
                }
                CilFixture::ArrayBadAssembly => {
                    reference.assembly = "Guest.App";
                    main.code.push(0x17);
                }
                _ => unreachable!(),
            }
            newarr(&mut main.code);
            main.code.extend([0x26, 0x16, 0x2a]);
        }
        CilFixture::ArrayQuota => {
            main.code.push(0x16);
            newarr(&mut main.code);
            main.code.extend([0x26, 0x2b, 0xf7]);
        }
        _ => return None,
    }
    let mut methods = vec![main];
    if let Some(helper) = helper {
        methods.push(helper);
    }
    Some(program_with_references(
        architecture,
        &methods,
        vec![0, 5, b'H', 0, b'i', 0, 0],
        &[reference],
    ))
}

fn framework_probe(architecture: Architecture, fixture: CilFixture) -> Option<Vec<u8>> {
    fn token(code: &mut Vec<u8>, opcode: u8, token: u32) {
        code.push(opcode);
        code.extend(token.to_le_bytes());
    }
    fn literal(code: &mut Vec<u8>, index: u32) {
        token(code, 0x72, 0x70000000 | index);
    }
    fn call(code: &mut Vec<u8>, index: u32, virtual_call: bool) {
        token(
            code,
            if virtual_call { 0x6f } else { 0x28 },
            0x0a000000 | index,
        );
    }
    let concat = || Reference::new("mscorlib", "String", "Concat", &[0, 2, 0x0e, 0x0e, 0x0e]);
    let length = || Reference::new("System.Runtime", "String", "get_Length", &[0x20, 0, 8]);
    let chars = || Reference::new("System.Runtime", "String", "get_Chars", &[0x20, 1, 3, 8]);
    let writer = || Reference::new("System.Console", "Console", "WriteLine", &[0, 1, 1, 0x0e]);
    let mut refs = Vec::new();
    let mut code = Vec::new();
    let mut user_strings = vec![
        0, 5, b'H', 0, b'i', 0, 0, 3, b'!', 0, 0, 7, b'H', 0, b'i', 0, b'!', 0, 0,
    ];
    match fixture {
        CilFixture::FrameworkConsoleTypes => {
            refs.extend([
                Reference::new("System.Console", "Console", "Write", &[0, 1, 1, 0x0a]),
                Reference::new("System.Console", "Console", "Write", &[0, 1, 1, 2]),
                Reference::new("System.Console", "Console", "Write", &[0, 1, 1, 3]),
                Reference::new("System.Console", "Console", "Write", &[0, 1, 1, 0x0e]),
            ]);
            code.push(0x21);
            code.extend(i64::MIN.to_le_bytes());
            call(&mut code, 1, false);
            code.push(0x17);
            call(&mut code, 2, false);
            code.push(0x20);
            code.extend(0xd800i32.to_le_bytes());
            call(&mut code, 3, false);
            code.push(0x14);
            call(&mut code, 4, false);
            code.extend([0x1f, 17, 0x2a]);
        }
        CilFixture::FrameworkNullOrEmpty => {
            refs.extend([
                concat(),
                Reference::new("mscorlib", "String", "IsNullOrEmpty", &[0, 1, 2, 0x0e]),
            ]);
            code.extend([0x14, 0x14]);
            call(&mut code, 1, false);
            call(&mut code, 2, false);
            code.push(0x2a);
        }
        CilFixture::FrameworkInequality => {
            refs.push(Reference::new(
                "mscorlib",
                "String",
                "op_Inequality",
                &[0, 2, 2, 0x0e, 0x0e],
            ));
            code.push(0x14);
            literal(&mut code, 1);
            call(&mut code, 1, false);
            code.push(0x2a);
        }
        CilFixture::FrameworkStrings => {
            refs.extend([concat(), writer(), length()]);
            literal(&mut code, 1);
            literal(&mut code, 7);
            call(&mut code, 1, false);
            code.push(0x25);
            call(&mut code, 2, false);
            call(&mut code, 3, true);
            code.push(0x2a);
        }
        CilFixture::FrameworkConcatIdentity | CilFixture::FrameworkStringEquality => {
            refs.push(concat());
            literal(&mut code, 1);
            literal(&mut code, 7);
            call(&mut code, 1, false);
            literal(&mut code, 11);
            if matches!(fixture, CilFixture::FrameworkStringEquality) {
                refs.push(Reference::new(
                    "mscorlib",
                    "String",
                    "op_Equality",
                    &[0, 2, 2, 0x0e, 0x0e],
                ));
                call(&mut code, 2, false);
            } else {
                code.extend([0xfe, 1]);
            }
            code.push(0x2a);
        }
        CilFixture::FrameworkConcatEmpty | CilFixture::FrameworkConcatNull => {
            refs.push(concat());
            code.push(0x14);
            if matches!(fixture, CilFixture::FrameworkConcatEmpty) {
                literal(&mut code, 1);
            } else {
                code.push(0x14);
            }
            call(&mut code, 1, false);
            if matches!(fixture, CilFixture::FrameworkConcatEmpty) {
                literal(&mut code, 1);
                code.extend([0xfe, 1]);
            } else {
                refs.push(length());
                call(&mut code, 2, true);
            }
            code.push(0x2a);
        }
        CilFixture::FrameworkUnicodeLength
        | CilFixture::FrameworkChar
        | CilFixture::FrameworkBadIndex => {
            if !matches!(fixture, CilFixture::FrameworkBadIndex) {
                user_strings = vec![0, 9, 0x3d, 0xd8, 0, 0xde, 0, 0xd8, 0, 0, 1];
            }
            literal(&mut code, 1);
            if matches!(fixture, CilFixture::FrameworkUnicodeLength) {
                refs.push(length());
            } else {
                refs.push(chars());
                code.push(if matches!(fixture, CilFixture::FrameworkBadIndex) {
                    0x15
                } else {
                    0x18
                });
            }
            call(&mut code, 1, true);
            code.push(0x2a);
        }
        CilFixture::FrameworkNullLength
        | CilFixture::FrameworkBadAssembly
        | CilFixture::FrameworkBadSignature
        | CilFixture::FrameworkBadOwner
        | CilFixture::FrameworkBadScope => {
            let mut reference = length();
            match fixture {
                CilFixture::FrameworkBadAssembly => reference.assembly = "Guest.App",
                CilFixture::FrameworkBadSignature => reference.signature = vec![0x20, 0, 0x0a],
                CilFixture::FrameworkBadOwner => reference.parent_tag = 0,
                CilFixture::FrameworkBadScope => reference.scope_tag = 0,
                _ => {}
            }
            refs.push(reference);
            if matches!(fixture, CilFixture::FrameworkNullLength) {
                code.push(0x14);
            } else {
                literal(&mut code, 1);
            }
            call(&mut code, 1, true);
            code.push(0x2a);
        }
        CilFixture::FrameworkStaticVirtual => {
            refs.push(concat());
            code.extend([0x14, 0x14]);
            call(&mut code, 1, true);
            code.extend([0x26, 0x16, 0x2a]);
        }
        CilFixture::FrameworkUnknown => {
            refs.push(Reference::new(
                "mscorlib",
                "Environment",
                "get_MachineName",
                &[0, 0, 0x0e],
            ));
            call(&mut code, 1, false);
            code.extend([0x26, 0x16, 0x2a]);
        }
        CilFixture::FrameworkArgumentType => {
            refs.push(writer());
            code.push(0x17);
            call(&mut code, 1, false);
            code.extend([0x16, 0x2a]);
        }
        CilFixture::FrameworkConsole => {
            refs.extend([
                Reference::new("System.Console", "Console", "Write", &[0, 1, 1, 8]),
                Reference::new("System.Console", "Console", "WriteLine", &[0, 0, 1]),
                Reference::new("mscorlib", "Environment", "get_NewLine", &[0, 0, 0x0e]),
                Reference::new("System.Console", "Console", "Write", &[0, 1, 1, 0x0e]),
            ]);
            code.extend([0x1f, (-17i8) as u8]);
            for index in 1..=4 {
                call(&mut code, index, false);
            }
            code.extend([0x1f, 17, 0x2a]);
        }
        CilFixture::FrameworkConsoleNull => {
            refs.push(writer());
            code.push(0x14);
            call(&mut code, 1, false);
            code.extend([0x1f, 17, 0x2a]);
        }
        CilFixture::FrameworkConsoleLimit => {
            refs.push(Reference::new(
                "System.Console",
                "Console",
                "Write",
                &[0, 1, 1, 0x0e],
            ));
            literal(&mut code, 1);
            call(&mut code, 1, false);
            code.extend([0x2b, 0xf4]);
        }
        _ => return None,
    }
    Some(program_with_references(
        architecture,
        &[ProgramMethod {
            name: "Main",
            code,
            signature: vec![0, 0, 8],
            locals: Vec::new(),
            initialize_locals: false,
        }],
        user_strings,
        &refs,
    ))
}

fn frame_probe(architecture: Architecture, fixture: CilFixture, iterations: u32) -> Vec<u8> {
    let mut main = ProgramMethod {
        name: "Main",
        code: Vec::new(),
        signature: vec![0, 0, 8],
        locals: Vec::new(),
        initialize_locals: false,
    };
    let mut helper = None;
    let mut user_strings = vec![0, 5, b'H', 0, b'i', 0, 0];
    match fixture {
        CilFixture::StringIdentity | CilFixture::StringAliases | CilFixture::StringRelational => {
            if matches!(fixture, CilFixture::StringAliases) {
                user_strings.extend([5, b'H', 0, b'i', 0, 0]);
            }
            main.code.extend([
                0x72,
                1,
                0,
                0,
                0x70,
                0x72,
                if matches!(fixture, CilFixture::StringAliases) {
                    7
                } else {
                    1
                },
                0,
                0,
                0x70,
                0xfe,
                if matches!(fixture, CilFixture::StringRelational) {
                    2
                } else {
                    1
                },
                0x2a,
            ]);
        }
        CilFixture::StringLocal | CilFixture::StringBadType => {
            main.locals = vec![7, 1, 0x0e];
            main.initialize_locals = true;
            if matches!(fixture, CilFixture::StringBadType) {
                main.code.push(0x17);
            } else {
                main.code.extend([0x72, 1, 0, 0, 0x70]);
            }
            main.code
                .extend([0x0a, 0x06, 0x72, 1, 0, 0, 0x70, 0xfe, 1, 0x2a]);
        }
        CilFixture::StringLocalNull => {
            main.locals = vec![7, 1, 0x0e];
            main.initialize_locals = true;
            main.code.extend([0x06, 0x14, 0xfe, 1, 0x2a]);
        }
        CilFixture::StringCall => {
            main.code.extend([
                0x72, 1, 0, 0, 0x70, 0x28, 2, 0, 0, 6, 0x72, 1, 0, 0, 0x70, 0xfe, 1, 0x2a,
            ]);
            helper = Some(ProgramMethod {
                name: "Identity",
                code: vec![0x02, 0x2a],
                signature: vec![0, 1, 0x0e, 0x0e],
                locals: Vec::new(),
                initialize_locals: false,
            });
        }
        CilFixture::StringReturn => {
            main.signature = vec![0, 0, 0x0e];
            main.code.extend([0x72, 1, 0, 0, 0x70, 0x2a]);
            user_strings = vec![0, 9, 0x41, 0, 0, 0xd8, 0, 0, 0, 0xdc, 1];
        }
        CilFixture::StringBadToken | CilFixture::StringMissing => {
            main.code.extend([
                0x72,
                0xff,
                0xff,
                0,
                if matches!(fixture, CilFixture::StringBadToken) {
                    6
                } else {
                    0x70
                },
                0x26,
                0x16,
                0x2a,
            ]);
        }
        CilFixture::LocalsLoop => {
            main.locals = vec![7, 2, 8, 8];
            main.initialize_locals = true;
            main.code.extend([0x16, 0x0a, 0x20]);
            main.code.extend(iterations.to_le_bytes());
            main.code.extend([
                0x0b, 0x06, 0x17, 0x58, 0x0a, 0x07, 0x17, 0x59, 0x25, 0x0b, 0x2d, 0xf5, 0x06, 0x2a,
            ]);
        }
        CilFixture::LocalZero | CilFixture::LocalUninitialized => {
            main.locals = vec![7, 1, 8];
            main.initialize_locals = matches!(fixture, CilFixture::LocalZero);
            main.code.extend([0x06, 0x2a]);
        }
        CilFixture::LocalIndexed => {
            main.locals = vec![7, 1, 8];
            main.initialize_locals = true;
            main.code.extend([
                0x1f, 17, 0x13, 0, 0x11, 0, 0xfe, 0x0e, 0, 0, 0xfe, 0x0c, 0, 0, 0x2a,
            ]);
        }
        CilFixture::LocalBadType => {
            main.locals = vec![7, 1, 8];
            main.initialize_locals = true;
            main.code.push(0x21);
            main.code.extend(1i64.to_le_bytes());
            main.code.extend([0x0a, 0x16, 0x2a]);
        }
        CilFixture::CallArguments | CilFixture::ArgumentBadType => {
            if matches!(fixture, CilFixture::ArgumentBadType) {
                main.code.push(0x21);
                main.code.extend((iterations as i64).to_le_bytes());
            } else {
                main.code.push(0x20);
                main.code.extend(iterations.to_le_bytes());
            }
            main.code.extend([0x1f, 7, 0x28, 2, 0, 0, 6, 0x2a]);
            helper = Some(ProgramMethod {
                name: "Helper",
                code: vec![0x02, 0x03, 0x59, 0x2a],
                signature: vec![0, 2, 8, 8, 8],
                locals: Vec::new(),
                initialize_locals: false,
            });
        }
        CilFixture::ArgumentStore => {
            main.code.push(0x20);
            main.code.extend(iterations.to_le_bytes());
            main.code.extend([0x28, 2, 0, 0, 6, 0x2a]);
            helper = Some(ProgramMethod {
                name: "Helper",
                code: vec![
                    0xfe, 0x09, 0, 0, 0x17, 0x58, 0xfe, 0x0b, 0, 0, 0xfe, 0x09, 0, 0, 0x2a,
                ],
                signature: vec![0, 1, 8, 8],
                locals: Vec::new(),
                initialize_locals: false,
            });
        }
        CilFixture::VoidReturn => {
            main.signature = vec![0, 0, 1];
            main.code.push(0x2a);
        }
        CilFixture::VoidCall => {
            main.code.extend([0x28, 2, 0, 0, 6, 0x1f, 17, 0x2a]);
            helper = Some(ProgramMethod {
                name: "Helper",
                code: vec![0x2a],
                signature: vec![0, 0, 1],
                locals: Vec::new(),
                initialize_locals: false,
            });
        }
        CilFixture::Recursive | CilFixture::DeepRecursion => {
            main.code.push(0x20);
            main.code.extend(
                (if matches!(fixture, CilFixture::DeepRecursion) {
                    100
                } else {
                    iterations
                })
                .to_le_bytes(),
            );
            main.code.extend([0x28, 2, 0, 0, 6, 0x2a]);
            helper = Some(ProgramMethod {
                name: "Helper",
                code: vec![
                    0x02, 0x2d, 3, 0x1f, 17, 0x2a, 0x02, 0x17, 0x59, 0x28, 2, 0, 0, 6, 0x2a,
                ],
                signature: vec![0, 1, 8, 8],
                locals: Vec::new(),
                initialize_locals: false,
            });
        }
        _ => unreachable!("not a frame fixture"),
    }
    let mut methods = vec![main];
    if let Some(helper) = helper {
        methods.push(helper);
    }
    program_with_strings(architecture, &methods, user_strings)
}

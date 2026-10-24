//! Owned CIL programs only; assembled bytes are never submitted to a host CLR.
use super::*;
fn token(code: &mut Vec<u8>, op: u8, value: u32) {
    code.push(op);
    code.extend(value.to_le_bytes());
}
fn call(code: &mut Vec<u8>, row: u32) {
    token(code, 0x28, 0x0a000000 | row);
}
fn literal(code: &mut Vec<u8>, at: u32) {
    token(code, 0x72, 0x70000000 | at);
}
fn string(heap: &mut Vec<u8>, units: &[u16]) -> u32 {
    let at = heap.len() as u32;
    assert!(units.len() * 2 + 1 < 128);
    heap.push((units.len() * 2 + 1) as u8);
    for unit in units {
        heap.extend(unit.to_le_bytes());
    }
    heap.push(0);
    at
}
pub(super) fn probe(architecture: Architecture, fixture: CilFixture) -> Option<Vec<u8>> {
    let mut refs = vec![Reference::new(
        "mscorlib",
        "Convert",
        "FromBase64String",
        &[0, 1, 0x1d, 5, 0x0e],
    )];
    let mut code = Vec::new();
    let mut strings = vec![0];
    let mut locals = Vec::new();
    let text = match fixture {
        CilFixture::ConvertWhitespace => " A\tP+\rATV\no= ",
        CilFixture::ConvertEmpty | CilFixture::ConvertQuota => "",
        CilFixture::ConvertMalformed => "AA==A",
        CilFixture::ConvertPadding => "AAAA====",
        CilFixture::ConvertUnicode => "\u{a0}AA==",
        CilFixture::ConvertTrailingBits => "AB==",
        CilFixture::ConvertDecodeLimit => "AAAA",
        _ => "AP+ATVo=",
    };
    let units: Vec<_> = if matches!(fixture, CilFixture::ConvertSurrogate) {
        vec![0xd800, 65, 61, 61]
    } else {
        text.encode_utf16().collect()
    };
    let first = string(&mut strings, &units);
    match fixture {
        CilFixture::ConvertBytes
        | CilFixture::ConvertWhitespace
        | CilFixture::ConvertEmpty
        | CilFixture::ConvertTrailingBits => {
            literal(&mut code, first);
            call(&mut code, 1);
            code.extend([0x8e, 0x69, 0x2a]);
        }
        CilFixture::ConvertWritable => {
            literal(&mut code, first);
            call(&mut code, 1);
            code.extend([0x25, 0x16, 0x1f, 82, 0x9c, 0x16, 0x91, 0x2a]);
        }
        CilFixture::ConvertIdentity => {
            literal(&mut code, first);
            call(&mut code, 1);
            literal(&mut code, first);
            call(&mut code, 1);
            code.extend([0xfe, 1, 0x2a]);
        }
        CilFixture::ConvertRoundTrip | CilFixture::ConvertEncodeEmpty => {
            refs.push(Reference::new(
                "mscorlib",
                "Convert",
                "ToBase64String",
                &[0, 1, 0x0e, 0x1d, 5],
            ));
            refs.push(Reference::new(
                "mscorlib",
                "String",
                "op_Equality",
                &[0, 2, 2, 0x0e, 0x0e],
            ));
            if matches!(fixture, CilFixture::ConvertEncodeEmpty) {
                let at = string(&mut strings, &[]);
                literal(&mut code, at);
            } else {
                literal(&mut code, first);
            }
            code.push(0x25);
            call(&mut code, 1);
            call(&mut code, 2);
            call(&mut code, 3);
            code.push(0x2a);
        }
        CilFixture::ConvertFile => {
            let mut file = Reference::new(
                "mscorlib",
                "File",
                "WriteAllBytes",
                &[0, 2, 1, 0x0e, 0x1d, 5],
            );
            file.namespace = "System.IO";
            refs.push(file);
            let at = string(
                &mut strings,
                &"C:\\convert.bin".encode_utf16().collect::<Vec<_>>(),
            );
            literal(&mut code, at);
            literal(&mut code, first);
            call(&mut code, 1);
            call(&mut code, 2);
            code.extend([0x1f, 17, 0x2a]);
        }
        CilFixture::ConvertMalformed
        | CilFixture::ConvertPadding
        | CilFixture::ConvertUnicode
        | CilFixture::ConvertSurrogate
        | CilFixture::ConvertNull
        | CilFixture::ConvertBadArgument
        | CilFixture::ConvertBadSignature
        | CilFixture::ConvertBadAssembly
        | CilFixture::ConvertBadVersion
        | CilFixture::ConvertBadNamespace
        | CilFixture::ConvertBadOwner
        | CilFixture::ConvertBadScope
        | CilFixture::ConvertStaticVirtual => {
            match fixture {
                CilFixture::ConvertBadSignature => refs[0].signature = vec![0, 1, 0x0e, 0x0e],
                CilFixture::ConvertBadAssembly => refs[0].assembly = "Guest.App",
                CilFixture::ConvertBadVersion => refs[0].version = [2, 0, 0, 0],
                CilFixture::ConvertBadNamespace => refs[0].namespace = "Guest",
                CilFixture::ConvertBadOwner => refs[0].parent_tag = 0,
                CilFixture::ConvertBadScope => refs[0].scope_tag = 0,
                _ => {}
            }
            if matches!(fixture, CilFixture::ConvertNull) {
                code.push(0x14);
            } else if matches!(fixture, CilFixture::ConvertBadArgument) {
                code.push(0x17);
            } else {
                literal(&mut code, first);
            }
            token(
                &mut code,
                if matches!(fixture, CilFixture::ConvertStaticVirtual) {
                    0x6f
                } else {
                    0x28
                },
                0x0a000001,
            );
            code.extend([0x26, 0x16, 0x2a]);
        }
        CilFixture::ConvertNullBytes
        | CilFixture::ConvertWrongArray
        | CilFixture::ConvertLargeEncode
        | CilFixture::ConvertHeapQuota => {
            refs[0] = Reference::new(
                "mscorlib",
                "Convert",
                "ToBase64String",
                &[0, 1, 0x0e, 0x1d, 5],
            );
            refs.push(Reference::new(
                "mscorlib",
                if matches!(fixture, CilFixture::ConvertWrongArray) {
                    "Int32"
                } else {
                    "Byte"
                },
                "unused",
                &[0, 0, 1],
            ));
            if matches!(fixture, CilFixture::ConvertNullBytes) {
                code.push(0x14);
            } else {
                if matches!(fixture, CilFixture::ConvertLargeEncode) {
                    code.push(0x20);
                    code.extend(1_048_576i32.to_le_bytes());
                } else {
                    code.push(0x16);
                }
                token(&mut code, 0x8d, 0x01000002);
            }
            if matches!(fixture, CilFixture::ConvertHeapQuota) {
                let start = code.len();
                code.push(0x25);
                call(&mut code, 1);
                code.push(0x26);
                let branch = code.len();
                code.extend([0x2b, (start as isize - branch as isize - 2) as i8 as u8]);
            } else {
                call(&mut code, 1);
                code.extend([0x26, 0x1f, 17, 0x2a]);
            }
        }
        CilFixture::ConvertQuota => {
            literal(&mut code, first);
            call(&mut code, 1);
            code.push(0x26);
            code.extend([0x2b, 0xf3]);
        }
        CilFixture::ConvertDecodeLimit => {
            refs.push(Reference::new(
                "mscorlib",
                "String",
                "Concat",
                &[0, 2, 0x0e, 0x0e, 0x0e],
            ));
            literal(&mut code, first);
            code.extend([0x1f, 19, 0x0a]);
            let start = code.len();
            code.push(0x25);
            call(&mut code, 2);
            code.extend([0x06, 0x17, 0x59, 0x25, 0x0a]);
            let branch = code.len();
            code.extend([0x2d, (start as isize - branch as isize - 2) as i8 as u8]);
            call(&mut code, 1);
            code.extend([0x26, 0x16, 0x2a]);
            locals = vec![7, 1, 8];
        }
        _ => return None,
    }
    Some(program_with_references(
        architecture,
        &[ProgramMethod {
            name: "Main",
            code,
            signature: vec![0, 0, 8],
            locals,
            initialize_locals: false,
        }],
        strings,
        &refs,
    ))
}

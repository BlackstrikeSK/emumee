use super::*;
use crate::managed_indicator_fixture::{self as fixture, Case};
fn literal(code: &mut Vec<u8>, token: u32) {
    code.push(0x72);
    code.extend(token.to_le_bytes());
}
fn call(code: &mut Vec<u8>, token: u32) {
    code.push(0x28);
    code.extend(token.to_le_bytes());
}
fn user_string(heap: &mut Vec<u8>, units: impl Iterator<Item = u16>) -> u32 {
    let token = 0x70000000 | heap.len() as u32;
    let bytes: Vec<_> = units.flat_map(u16::to_le_bytes).collect();
    assert!(bytes.len() + 1 < 128);
    heap.push((bytes.len() + 1) as u8);
    heap.extend(bytes);
    heap.push(0);
    token
}
pub fn probe(architecture: Architecture, case: Case) -> Vec<u8> {
    let mut strings = vec![0];
    let mut code = vec![];
    let mut refs = vec![];
    let mut helper = None;
    match case {
        Case::Events | Case::Disabled | Case::Budget => {
            let prefix = user_string(&mut strings, fixture::PREFIX.encode_utf16());
            let suffix = user_string(&mut strings, fixture::SUFFIX.encode_utf16());
            let full = fixture::PREFIX.to_owned() + fixture::SUFFIX;
            let combined = user_string(&mut strings, full.encode_utf16());
            refs.push(Reference::new(
                "mscorlib",
                "String",
                "Concat",
                &[0, 2, 0x0e, 0x0e, 0x0e],
            ));
            literal(&mut code, prefix);
            literal(&mut code, suffix);
            call(&mut code, 0x0a000001);
            call(&mut code, 0x06000002);
            code.push(0x26);
            literal(&mut code, combined);
            code.push(0x26);
            literal(&mut code, combined);
            code.push(0x26);
            helper = Some(ProgramMethod {
                name: "Echo",
                code: vec![0x02, 0x2a],
                signature: vec![0, 1, 0x0e, 0x0e],
                locals: vec![],
                initialize_locals: false,
            });
        }
        Case::Surrogate => {
            let token = user_string(
                &mut strings,
                fixture::SURROGATE_PREFIX.encode_utf16().chain([0xd800]),
            );
            literal(&mut code, token);
            code.push(0x26);
        }
        Case::FrameworkFailure => {
            let token = user_string(&mut strings, fixture::FAILURE.encode_utf16());
            refs.push(Reference::new(
                "mscorlib",
                "Convert",
                "FromBase64String",
                &[0, 1, 0x1d, 5, 0x0e],
            ));
            literal(&mut code, token);
            call(&mut code, 0x0a000001);
            code.push(0x26);
        }
        Case::Null => {
            let token = user_string(&mut strings, fixture::NULLABLE.encode_utf16());
            refs.push(Reference::new(
                "mscorlib",
                "String",
                "Concat",
                &[0, 2, 0x0e, 0x0e, 0x0e],
            ));
            literal(&mut code, token);
            code.push(0x14);
            call(&mut code, 0x0a000001);
            code.push(0x26);
        }
    }
    code.extend([0x1f, 17, 0x2a]);
    let mut methods = vec![ProgramMethod {
        name: "Main",
        code,
        signature: vec![0, 0, 8],
        locals: vec![],
        initialize_locals: false,
    }];
    if let Some(helper) = helper {
        methods.push(helper);
    }
    program_with_references(architecture, &methods, strings, &refs)
}

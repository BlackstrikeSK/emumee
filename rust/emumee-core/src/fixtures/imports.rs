use super::*;

#[derive(Clone, Copy, Debug)]
pub enum ImportFixture {
    ApiSet,
    DelayPid,
    DelayMissing,
    DelayUnused,
    DelayFlags,
    DelayAttributes,
    DelayModule,
    DelayDescriptor,
    DelayDll,
    DelayIat,
    DelayUnaligned,
    DelayLimit,
    DelayNames,
    DelayEmpty,
    DelayOrdinal,
    DelayHint,
    DelayName,
    DelayWrite,
}

pub fn import_probe(architecture: Architecture, case: ImportFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let mut data = api_probe(architecture, ApiFixture::Unsupported);
    put16(&mut data, 0x96, 0x22);
    put16(&mut data, 0x98 + 68, 3);
    data[0x440..0x480].fill(0);
    let resolver = b"api-ms-win-core-delayload-l1-1-1.dll\0";
    data[0x440..0x440 + resolver.len()].copy_from_slice(resolver);
    data[0x702..0x740].fill(0);
    data[0x702..0x718].copy_from_slice(b"ResolveDelayLoadedAPI\0");
    let directories = 0x98 + if wide { 112 } else { 96 };
    put32(&mut data, directories + 13 * 8, 0x2400);
    put32(&mut data, directories + 13 * 8 + 4, 64);
    data[0x800..0xb40].fill(0);
    for (index, value) in [1, 0x2480, 0, 0x2600, 0x2500, 0, 0, 0]
        .into_iter()
        .enumerate()
    {
        put32(&mut data, 0x800 + index * 4, value);
    }
    data[0x880..0x88d].copy_from_slice(b"kernel32.dll\0");
    if wide {
        put64(&mut data, 0x900, 0x2580);
    } else {
        put32(&mut data, 0x900, 0x2580);
    }
    data[0x982..0x996].copy_from_slice(b"GetCurrentProcessId\0");
    if wide {
        put64(&mut data, 0xa00, base + 0x1180);
    } else {
        put32(&mut data, 0xa00, (base + 0x1180) as u32);
    }
    let mut arguments = [base, base + 0x2400, 0, 0, base + 0x2600, 0];
    match case {
        ImportFixture::DelayFlags => arguments[5] = 1,
        ImportFixture::DelayAttributes => put32(&mut data, 0x800, 0),
        ImportFixture::DelayModule => arguments[0] += 1,
        ImportFixture::DelayDescriptor => arguments[1] = base + 0x4000 - 16,
        ImportFixture::DelayDll => data[0x880] = b'/',
        ImportFixture::DelayIat => put32(&mut data, 0x80c, 0x4000),
        ImportFixture::DelayUnaligned => arguments[4] += 1,
        ImportFixture::DelayLimit => arguments[4] += 128 * architecture.width() as u64,
        ImportFixture::DelayNames => put32(&mut data, 0x810, 0x4000 - 2),
        ImportFixture::DelayEmpty => data[0x900..0x908].fill(0),
        ImportFixture::DelayOrdinal => {
            let value = (1u64 << (architecture.width() * 8 - 1)) | 1;
            if wide {
                put64(&mut data, 0x900, value);
            } else {
                put32(&mut data, 0x900, value as u32);
            }
        }
        ImportFixture::DelayHint => put32(&mut data, 0x900, 0x4000 - 1),
        ImportFixture::DelayName => data[0x982..0xa04].fill(b'A'),
        ImportFixture::DelayMissing | ImportFixture::DelayUnused => {
            data[0x982..0x996].copy_from_slice(b"AbsentDelayTargetXx\0")
        }
        ImportFixture::DelayWrite => {
            let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
            put32(&mut data, table + 40 + 36, 0x40000040);
        }
        ImportFixture::DelayPid => {}
        ImportFixture::ApiSet => {}
    }
    let mut code = Vec::new();
    if matches!(case, ImportFixture::ApiSet) {
        data[0x440..0x480].fill(0);
        let module = b"API-MS-WIN-CORE-LIBRARYLOADER-L1-2-0.DLL\0";
        data[0x440..0x440 + module.len()].copy_from_slice(module);
        data[0x702..0x740].fill(0);
        data[0x702..0x713].copy_from_slice(b"GetModuleHandleA\0");
        if wide {
            code.extend([0x48, 0x83, 0xec, 0x28, 0x31, 0xc9, 0x48, 0xb8]);
            code.extend((base + 0x2080).to_le_bytes());
            code.extend([0xff, 0x10, 0x48, 0xb9]);
            code.extend(base.to_le_bytes());
            code.extend([0x48, 0x39, 0xc8, 0x74, 1, 0xcc, 0x48, 0x83, 0xc4, 0x28]);
        } else {
            code.extend([0x6a, 0, 0xff, 0x15]);
            code.extend(((base + 0x2080) as u32).to_le_bytes());
            code.push(0x3d);
            code.extend((base as u32).to_le_bytes());
            code.extend([0x74, 1, 0xcc]);
        }
        code.extend([0xb8, 42, 0, 0, 0, 0xc3]);
    } else if matches!(case, ImportFixture::DelayUnused) {
        code.extend([0xb8, 42, 0, 0, 0, 0xc3]);
    } else if wide {
        code.extend([0x48, 0x83, 0xec, 0x38]);
        for (opcode, value) in [
            ([0x48, 0xb9], arguments[0]),
            ([0x48, 0xba], arguments[1]),
            ([0x49, 0xb8], arguments[2]),
            ([0x49, 0xb9], arguments[3]),
        ] {
            code.extend(opcode);
            code.extend(value.to_le_bytes());
        }
        for (offset, value) in [(0x20, arguments[4]), (0x28, arguments[5])] {
            code.extend([0x48, 0xb8]);
            code.extend(value.to_le_bytes());
            code.extend([0x48, 0x89, 0x44, 0x24, offset]);
        }
        code.extend([0x48, 0xb8]);
        code.extend((base + 0x2080).to_le_bytes());
        code.extend([0xff, 0x10]);
        if matches!(case, ImportFixture::DelayPid) {
            code.extend([0x48, 0xb9]);
            code.extend((base + 0x2600).to_le_bytes());
            code.extend([0x48, 0x3b, 0x01, 0x74, 1, 0xcc, 0xff, 0x11]);
        }
        code.extend([0x48, 0x83, 0xc4, 0x38, 0xc3]);
    } else {
        for value in arguments.iter().rev() {
            code.push(0x68);
            code.extend((*value as u32).to_le_bytes());
        }
        code.extend([0xff, 0x15]);
        code.extend(((base + 0x2080) as u32).to_le_bytes());
        if matches!(case, ImportFixture::DelayPid) {
            code.extend([0xb9]);
            code.extend(((base + 0x2600) as u32).to_le_bytes());
            code.extend([0x3b, 0x01, 0x74, 1, 0xcc, 0xff, 0x11]);
        }
        code.push(0xc3);
    }
    data[0x200..0x400].fill(0xcc);
    data[0x200..0x200 + code.len()].copy_from_slice(&code);
    data
}

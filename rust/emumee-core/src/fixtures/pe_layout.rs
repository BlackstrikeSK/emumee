use super::*;

#[derive(Clone, Copy, Debug)]
pub enum PeLayoutFixture {
    RawTail,
    VirtualTail,
    RawAlias,
    WriteData,
    WriteText,
    WriteHeaders,
    ExecuteData,
    ReadGap,
}

pub fn pe_layout_probe(architecture: Architecture, case: PeLayoutFixture) -> Vec<u8> {
    let mut data = counted_driver(architecture, 1);
    let wide = architecture == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    put16(&mut data, 0x96, 0x22);
    put16(&mut data, 0x98 + 68, 3);
    put32(&mut data, 0x98 + 56, 0x5000);
    put32(&mut data, table + 8, 1);
    put32(&mut data, table + 40 + 8, 0x900);
    put32(&mut data, table + 40 + 12, 0x3000);
    data[0x380..0x384].copy_from_slice(&42u32.to_le_bytes());
    data[0x400..0x406].copy_from_slice(&[0xb8, 42, 0, 0, 0, 0xc3]);
    if matches!(case, PeLayoutFixture::RawAlias) {
        put32(&mut data, table + 40 + 20, 0x200);
    }
    let target = base
        + match case {
            PeLayoutFixture::RawTail | PeLayoutFixture::WriteText => 0x1180,
            PeLayoutFixture::VirtualTail => 0x3500,
            PeLayoutFixture::RawAlias | PeLayoutFixture::WriteData => 0x3180,
            PeLayoutFixture::WriteHeaders => 0x100,
            PeLayoutFixture::ExecuteData => 0x3000,
            PeLayoutFixture::ReadGap => 0x2000,
        };
    let mut code = if wide { vec![0x48, 0xb8] } else { vec![0xb8] };
    if wide {
        code.extend(target.to_le_bytes());
    } else {
        code.extend((target as u32).to_le_bytes());
    }
    if matches!(case, PeLayoutFixture::ExecuteData) {
        code.extend([0xff, 0xe0]);
    } else {
        if matches!(
            case,
            PeLayoutFixture::WriteData | PeLayoutFixture::WriteText | PeLayoutFixture::WriteHeaders
        ) {
            code.extend([0xc7, 0x00, 42, 0, 0, 0]);
        }
        code.extend([0x8b, 0x00, 0xc3]);
    }
    data[0x200..0x200 + code.len()].copy_from_slice(&code);
    data
}

//! Closed generated kernel ABI diagnostics; no submitted input is modified.
use super::{ApiFixture, api_probe};
use crate::pe::Architecture;

#[derive(Clone, Copy, Debug)]
pub enum DiagnosticFixture {
    DebugPrint,
    DebugBadFormat,
    DebugUnreadable,
    StackOnePage,
    StackTwoPages,
    StackFourPages,
    StackUnmapped,
    StackOverBound,
}

pub fn kernel_diagnostic_probe(architecture: Architecture, kind: DiagnosticFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let base: u64 = if wide { 0x140000000 } else { 0x400000 };
    // Reuse the fixed ntoskrnl import-table recipe; only the first closed
    // import and its own generated code/data are replaced.
    let mut data = api_probe(architecture, ApiFixture::KernelResolve);
    let stack = matches!(
        kind,
        DiagnosticFixture::StackOnePage
            | DiagnosticFixture::StackTwoPages
            | DiagnosticFixture::StackFourPages
            | DiagnosticFixture::StackUnmapped
            | DiagnosticFixture::StackOverBound
    );
    let name = if stack {
        b"__chkstk".as_slice()
    } else {
        b"DbgPrintEx".as_slice()
    };
    data[0x700..0x740].fill(0);
    data[0x702..0x702 + name.len()].copy_from_slice(name);
    data[0x200..0x400].fill(0xcc);
    let mut code = Vec::new();
    if stack {
        let requested: u32 = match kind {
            DiagnosticFixture::StackOnePage => 0x1000,
            DiagnosticFixture::StackTwoPages => 0x2000,
            DiagnosticFixture::StackFourPages => 0x4000,
            DiagnosticFixture::StackUnmapped => 0x100000,
            DiagnosticFixture::StackOverBound => 0x101000,
            _ => unreachable!(),
        };
        if wide {
            // x64 compiler ABI: RAX is the request and the helper returns
            // void without changing RAX or RSP. The subsequent real SUB and
            // write make stack-probe success guest-observable.
            code.extend([0x48, 0xb8]);
            code.extend((requested as u64).to_le_bytes());
            let next = 0x1000 + code.len() + 6;
            code.extend([0xff, 0x15]);
            code.extend((0x2080i32 - next as i32).to_le_bytes());
            code.extend([0x48, 0x3d]);
            code.extend(requested.to_le_bytes());
            code.extend([0x75, 0]);
            let branch = code.len() - 1;
            code.extend([0x48, 0x29, 0xc4]);
            code.extend([0xc6, 0x04, 0x24, 0x5a]);
            code.extend([0x48, 0x01, 0xc4]);
            code.extend([0xb8, 17, 0, 0, 0, 0xc3]);
            let failure = code.len();
            code.extend([0xb8, 99, 0, 0, 0, 0xc3]);
            code[branch] = (failure - (branch + 1)) as u8;
        } else {
            // There is no modeled x86 __chkstk ABI. Let the real import
            // binding/dispatch refuse this generated call explicitly.
            code.push(0xb8);
            code.extend(requested.to_le_bytes());
            code.extend([0xff, 0x15]);
            code.extend(((base + 0x2080) as u32).to_le_bytes());
            code.push(0xcc);
        }
    } else {
        let format = match kind {
            DiagnosticFixture::DebugPrint => b"fixture count=%u\r\n\0".as_slice(),
            DiagnosticFixture::DebugBadFormat => b"fixture %q\0".as_slice(),
            DiagnosticFixture::DebugUnreadable => b"unreachable\0".as_slice(),
            _ => unreachable!(),
        };
        data[0xf00..0xf40].fill(0);
        data[0xf00..0xf00 + format.len()].copy_from_slice(format);
        let format_pointer = if matches!(kind, DiagnosticFixture::DebugUnreadable) {
            0xdead0000u64
        } else {
            base + 0x2b00
        };
        if wide {
            code.extend([0x48, 0x83, 0xec, 0x48]); // shadow + alignment
            for (prefix, value) in [
                ([0x48, 0xb9], 0x4du64),
                ([0x48, 0xba], 0u64),
                ([0x49, 0xb8], format_pointer),
                ([0x49, 0xb9], 42u64),
            ] {
                code.extend(prefix);
                code.extend(value.to_le_bytes());
            }
            let next = 0x1000 + code.len() + 6;
            code.extend([0xff, 0x15]);
            code.extend((0x2080i32 - next as i32).to_le_bytes());
        } else {
            for value in [42u32, format_pointer as u32, 0, 0x4d] {
                code.push(0x68);
                code.extend(value.to_le_bytes());
            }
            code.extend([0xff, 0x15]);
            code.extend(((base + 0x2080) as u32).to_le_bytes());
            code.extend([0x83, 0xc4, 0x10]); // cdecl caller cleanup
        }
        code.extend([0x85, 0xc0, 0x75, 0]); // DbgPrintEx returns U32 status 0
        let branch = code.len() - 1;
        if wide {
            code.extend([0x48, 0x83, 0xc4, 0x48]);
        }
        code.extend([0xb8, 17, 0, 0, 0, 0xc3]);
        let failure = code.len();
        if wide {
            code.extend([0x48, 0x83, 0xc4, 0x48]);
        }
        code.extend([0xb8, 99, 0, 0, 0, 0xc3]);
        code[branch] = (failure - (branch + 1)) as u8;
    }
    assert!(code.len() <= 0x200);
    data[0x200..0x200 + code.len()].copy_from_slice(&code);
    data
}

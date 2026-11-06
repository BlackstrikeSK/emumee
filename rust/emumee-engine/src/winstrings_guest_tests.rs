//! Native PE callers prove argument marshalling and actual guest output bytes.
use super::*;
use emumee_core::{
    fixtures::counted_driver,
    report_bundle::digest,
    user_input::{PROFILE, Request},
};
fn word(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn expect(code: &mut Vec<u8>, value: u32) {
    code.push(0x3d);
    code.extend(value.to_le_bytes());
    code.extend([0x74, 1, 0xcc]);
}
fn call(code: &mut Vec<u8>, wide: bool, base: u64, index: usize, args: &[u64]) {
    if wide {
        for (i, arg) in args.iter().enumerate() {
            code.extend([0x48, 0xb8]);
            code.extend(arg.to_le_bytes());
            if i < 4 {
                code.extend(
                    [
                        [0x48, 0x89, 0xc1],
                        [0x48, 0x89, 0xc2],
                        [0x49, 0x89, 0xc0],
                        [0x49, 0x89, 0xc1],
                    ][i],
                );
            } else {
                code.extend([0x48, 0x89, 0x44, 0x24, (32 + 8 * (i - 4)) as u8]);
            }
        }
        let next = 0x1000 + code.len() + 6;
        code.extend([0xff, 0x15]);
        code.extend((0x2080i32 + index as i32 * 8 - next as i32).to_le_bytes());
    } else {
        for arg in args.iter().rev() {
            code.push(0x68);
            code.extend((*arg as u32).to_le_bytes());
        }
        code.extend([0xff, 0x15]);
        code.extend(((base + 0x2080) as u32 + index as u32 * 4).to_le_bytes());
    }
}
fn check(code: &mut Vec<u8>, wide: bool, at: u64, value: u32) {
    code.push(0xa1);
    if wide {
        code.extend(at.to_le_bytes());
    } else {
        code.extend((at as u32).to_le_bytes());
    }
    expect(code, value);
}
fn probe(arch: Architecture, unicode: bool) -> Vec<u8> {
    let wide = arch == Architecture::X64;
    let base = if wide { 0x140000000 } else { 0x400000 };
    let original = counted_driver(arch, 1);
    let mut bytes = vec![0; 0x3200];
    bytes[..0x200].copy_from_slice(&original[..0x200]);
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    let dd = 0x98 + if wide { 112 } else { 96 };
    for (at, value) in [
        (0x98 + 4, 0x1000),
        (0x98 + 8, 0x2000),
        (0x98 + 56, 0x4000),
        (table + 8, 0x1000),
        (table + 16, 0x1000),
        (table + 48, 0x2000),
        (table + 56, 0x2000),
        (table + 60, 0x1200),
        (dd + 8, 0x2000),
        (dd + 12, 40),
        (0x1200, 0x2180),
        (0x120c, 0x2240),
        (0x1210, 0x2080),
    ] {
        word(&mut bytes, at, value);
    }
    bytes[0x96..0x98].copy_from_slice(&0x22u16.to_le_bytes());
    bytes[0x98 + 68..0x98 + 70].copy_from_slice(&3u16.to_le_bytes());
    let names: &[&str] = if unicode {
        bytes[0x1440..0x144a].copy_from_slice(b"ntdll.dll\0");
        &["RtlOemToUnicodeN", "RtlIsTextUnicode"]
    } else {
        bytes[0x1440..0x144d].copy_from_slice(b"kernel32.dll\0");
        &[
            "CompareStringW",
            "FindStringOrdinal",
            "WideCharToMultiByte",
            "MultiByteToWideChar",
            "lstrlenW",
            "GetLastError",
        ]
    };
    for (i, name) in names.iter().enumerate() {
        let rva = 0x2300 + i * 64;
        for at in [0x1280, 0x1380] {
            if wide {
                bytes[at + i * 8..at + i * 8 + 8].copy_from_slice(&(rva as u64).to_le_bytes());
            } else {
                word(&mut bytes, at + i * 4, rva as u32);
            }
        }
        bytes[rva - 0xe00 + 2..rva - 0xe00 + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    let source = base + 0x2b00;
    let needle = base + 0x2c00;
    let out = base + 0x2d00;
    let count = base + 0x2e00;
    for (at, value) in [(0x1d00, "AlphaBeta"), (0x1e00, "beta")] {
        let image: Vec<u8> = value
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        bytes[at..at + image.len()].copy_from_slice(&image);
    }
    let mut c = vec![];
    if wide {
        c.extend([0x48, 0x83, 0xec, 0x48]);
    }
    if unicode {
        bytes[0x1d00..0x1d06].copy_from_slice(b"Coffee");
        call(&mut c, wide, base, 0, &[out, 14, count, source, 6]);
        expect(&mut c, 0);
        check(&mut c, wide, out, 0x006f0043);
        check(&mut c, wide, count, 12);
        call(&mut c, wide, base, 1, &[out, 12, 0]);
        expect(&mut c, 1);
        call(&mut c, wide, base, 0, &[out, 2, count, source, 6]);
        expect(&mut c, 0x80000005);
        check(&mut c, wide, count, 2);
    } else {
        call(
            &mut c,
            wide,
            base,
            0,
            &[0x400, 1, source + 10, 4, needle, 4],
        );
        expect(&mut c, 2);
        call(
            &mut c,
            wide,
            base,
            1,
            &[
                0x400000,
                source,
                u32::MAX.into(),
                needle,
                u32::MAX.into(),
                1,
            ],
        );
        expect(&mut c, 5);
        call(
            &mut c,
            wide,
            base,
            2,
            &[65001, 0, source, u32::MAX.into(), out, 32, 0, 0],
        );
        expect(&mut c, 10);
        check(&mut c, wide, out, 0x68706c41);
        call(
            &mut c,
            wide,
            base,
            3,
            &[65001, 0, out, u32::MAX.into(), count, 32],
        );
        expect(&mut c, 10);
        check(&mut c, wide, count, 0x006c0041);
        call(&mut c, wide, base, 4, &[count]);
        expect(&mut c, 9);
        call(
            &mut c,
            wide,
            base,
            2,
            &[1252, 0, source, u32::MAX.into(), out, 2, 0, 0],
        );
        expect(&mut c, 0);
        check(&mut c, wide, out, 0x68706c41);
        call(&mut c, wide, base, 5, &[]);
        expect(&mut c, 122);
    }
    c.extend([0xb8, 1, 0, 0, 0]);
    if wide {
        c.extend([0x48, 0x83, 0xc4, 0x48]);
    }
    c.push(0xc3);
    assert!(c.len() < 0x1000);
    bytes[0x200..0x200 + c.len()].copy_from_slice(&c);
    bytes
}
#[test]
fn winstrings_native_pe_callers_observe_both_abis_buffer_counts_and_failure_atomicity() {
    for arch in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            let bytes = probe(arch, unicode);
            let request = Request {
                schema: 1,
                profile: PROFILE.into(),
                run_id: "20261029T170000Z-12345678".into(),
                input_sha256: digest(&bytes),
                input_size: bytes.len() as u64,
                module_name: "sample.exe".into(),
                arguments: vec![],
                max_instructions: 20000,
                timeout_us: 30_000_000,
                persona_sha256: None,
                clock_utc_filetime: 134377488000000000,
                staged: vec![],
                invocation: Default::default(),
            };
            let result = user::run(&request, &bytes, None).unwrap();
            assert_eq!(result.error, None, "{arch:?}/{unicode}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(1));
            assert!(result.string_api_unsupported.is_empty());
        }
    }
}

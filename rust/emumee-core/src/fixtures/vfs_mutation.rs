//! Generated native callers for actual guest file mutation and retained backing.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, expect_dword, store, write_dword,
};
use super::{ApiFixture, api_probe, put16, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum MutationFixture {
    Delete,
    Unlink,
    Copy,
    CopySharing,
    Move,
    MoveSharing,
    Rename,
    RenameErrors,
    Failures,
    FlagsUnsupported,
    CrossVolumeUnsupported,
    DirectoryUnsupported,
    RootUnsupported,
    ClassUnsupported,
}
fn expect(c: &mut Vec<u8>, value: u32) {
    c.push(0x3d);
    c.extend(value.to_le_bytes());
    c.extend([0x74, 1, 0xcc]);
}
fn last(c: &mut Vec<u8>, wide: bool, base: u64, value: u32) {
    call(c, wide, base, 10, &[]);
    expect(c, value);
}
fn text(data: &mut [u8], rva: usize, value: &str, unicode: bool) {
    let mut bytes: Vec<u8> = if unicode {
        value.encode_utf16().flat_map(u16::to_le_bytes).collect()
    } else {
        value
            .chars()
            .map(|c| {
                assert!(c.is_ascii() || c == 'é');
                c as u8
            })
            .collect()
    };
    bytes.extend(if unicode { vec![0, 0] } else { vec![0] });
    assert!(bytes.len() <= 64);
    data[rva - 0xe00..rva - 0xe00 + bytes.len()].copy_from_slice(&bytes);
}
#[derive(Clone, Copy)]
struct Env {
    wide: bool,
    base: u64,
    count: u64,
    out: u64,
    payload: u64,
}
impl Env {
    fn open(
        self,
        c: &mut Vec<u8>,
        name: u64,
        saved: u64,
        access: u32,
        share: u32,
        disposition: u32,
    ) {
        call(
            c,
            self.wide,
            self.base,
            0,
            &[
                V(name),
                V(access as u64),
                V(share as u64),
                V(0),
                V(disposition as u64),
                V(0x80),
                V(0),
            ],
        );
        c.extend([0x83, 0xf8, 0xff, 0x75, 1, 0xcc]);
        store(c, self.wide, saved);
        if self.wide {
            expect_dword(c, true, saved + 4, 0);
        }
        expect_dword(c, self.wide, saved + 8, 0x77777777);
    }
    fn write(self, c: &mut Vec<u8>, saved: u64, payload: u64) {
        call(
            c,
            self.wide,
            self.base,
            1,
            &[M(saved), V(payload), V(4), V(self.count), V(0)],
        );
        expect(c, 1);
        expect_dword(c, self.wide, self.count, 4);
        expect_dword(c, self.wide, self.count + 4, 0x77777777);
    }
    fn close(self, c: &mut Vec<u8>, saved: u64) {
        call(c, self.wide, self.base, 3, &[M(saved)]);
        expect(c, 1);
    }
    fn seek(self, c: &mut Vec<u8>, saved: u64) {
        call(c, self.wide, self.base, 12, &[M(saved), V(0), V(0), V(0)]);
        expect(c, 0);
    }
    fn read(self, c: &mut Vec<u8>, saved: u64, count: u32, bytes: &[u8]) {
        for offset in (0..8).step_by(4) {
            write_dword(c, self.wide, self.out + offset, 0x77777777);
        }
        call(
            c,
            self.wide,
            self.base,
            2,
            &[M(saved), V(self.out), V(count as u64), V(self.count), V(0)],
        );
        expect(c, 1);
        expect_dword(c, self.wide, self.count, bytes.len() as u32);
        let mut d = [0x77; 4];
        d[..bytes.len()].copy_from_slice(bytes);
        expect_dword(c, self.wide, self.out, u32::from_le_bytes(d));
        expect_dword(c, self.wide, self.out + 4, 0x77777777);
    }
    fn file(self, c: &mut Vec<u8>, name: u64, saved: u64, payload: u64, close: bool) {
        self.open(c, name, saved, 0xc0010000, 7, 2);
        self.write(c, saved, payload);
        self.seek(c, saved);
        if close {
            self.close(c, saved);
        }
    }
}
pub fn mutation_probe(architecture: Architecture, kind: MutationFixture, unicode: bool) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let width = if wide { 8usize } else { 4 };
    let template = api_probe(architecture, ApiFixture::Unsupported);
    let mut data = vec![0; 0x4200];
    data[..0x200].copy_from_slice(&template[..0x200]);
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    let dd = 0x98 + if wide { 112 } else { 96 };
    put32(&mut data, 0x98 + 4, 0x1000);
    put32(&mut data, 0x98 + 8, 0x3000);
    put32(&mut data, 0x98 + 56, 0x5000);
    put32(&mut data, table + 8, 0x1000);
    put32(&mut data, table + 16, 0x1000);
    put32(&mut data, table + 48, 0x3000);
    put32(&mut data, table + 56, 0x3000);
    put32(&mut data, table + 60, 0x1200);
    put16(&mut data, 0x98 + 68, 3);
    put16(&mut data, 0x96, 0x22);
    put32(&mut data, dd + 8, 0x2000);
    put32(&mut data, dd + 12, 40);
    put32(&mut data, 0x1200, 0x2180);
    put32(&mut data, 0x120c, 0x2040);
    put32(&mut data, 0x1210, 0x2080);
    data[0x1240..0x124d].copy_from_slice(b"kernel32.dll\0");
    let suffix = if unicode { "W" } else { "A" };
    let names = [
        format!("CreateFile{suffix}"),
        "WriteFile".into(),
        "ReadFile".into(),
        "CloseHandle".into(),
        format!("DeleteFile{suffix}"),
        format!("CopyFile{suffix}"),
        format!("MoveFileEx{suffix}"),
        format!("MoveFile{suffix}"),
        format!("GetFileAttributes{suffix}"),
        format!("SetFileAttributes{suffix}"),
        "GetLastError".into(),
        "SetLastError".into(),
        "SetFilePointer".into(),
        "SetFileInformationByHandle".into(),
        format!("CreateDirectory{suffix}"),
        format!("FindFirstFile{suffix}"),
        "FindClose".into(),
    ];
    assert!(0x1380 + (names.len() + 1) * width < 0x1500);
    for (index, name) in names.iter().enumerate() {
        let rva = 0x2300 + index as u32 * 64;
        for raw in [0x1280, 0x1380] {
            if wide {
                put64(&mut data, raw + index * 8, rva.into());
            } else {
                put32(&mut data, raw + index * 4, rva);
            }
        }
        let raw = 0x1500 + index * 64;
        assert!(raw + 2 + name.len() < 0x1c00);
        data[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    for (rva, value) in [
        (0x2a00, "Sourceé.bin"),
        (0x2a40, "Targeté.bin"),
        (0x2a80, "NewNameé.bin"),
        (0x2ac0, "targeté.BIN"),
        (0x2b00, "missing\\new.bin"),
        (0x2b40, "D:\\new.bin"),
        (0x2b80, "*.*"),
    ] {
        text(&mut data, rva, value, unicode);
    }
    data[0x2100..0x210c].copy_from_slice(b"RUSTTARGNEW!");
    data[0x2600..0x2a00].fill(0x77);
    let a = base + 0x2a00;
    let b = base + 0x2a40;
    let new = base + 0x2a80;
    let folded = base + 0x2ac0;
    let absent = base + 0x2b00;
    let other = base + 0x2b40;
    let h = base + 0x3400;
    let h2 = base + 0x3420;
    let env = Env {
        wide,
        base,
        count: base + 0x3440,
        out: base + 0x3460,
        payload: base + 0x2f00,
    };
    let rename = base + 0x3500;
    let name_offset = if wide { 20usize } else { 12 };
    let rename_name: Vec<u8> = "C:\\workspace\\NewNameé.bin"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let rename_raw = 0x2700;
    data[rename_raw..rename_raw + name_offset + rename_name.len()].fill(0);
    data[rename_raw] = 0;
    put32(
        &mut data,
        rename_raw + name_offset - 4,
        rename_name.len() as u32,
    );
    data[rename_raw + name_offset..rename_raw + name_offset + rename_name.len()]
        .copy_from_slice(&rename_name);
    let rename_size = (name_offset + rename_name.len()) as u64;
    let mut c = Vec::new();
    if wide {
        c.extend([0x48, 0x83, 0xec, 0x58]);
    }
    call(&mut c, wide, base, 11, &[V(0x12345678)]);
    match kind {
        MutationFixture::Delete => {
            env.file(&mut c, a, h, env.payload, true);
            call(&mut c, wide, base, 4, &[V(a)]);
            expect(&mut c, 1);
            last(&mut c, wide, base, 0);
            call(&mut c, wide, base, 8, &[V(a)]);
            expect(&mut c, u32::MAX);
            last(&mut c, wide, base, 2);
            call(&mut c, wide, base, 4, &[V(a)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 2);
        }
        MutationFixture::Unlink => {
            env.file(&mut c, a, h, env.payload, false);
            call(&mut c, wide, base, 4, &[V(a)]);
            expect(&mut c, 1);
            env.file(&mut c, a, h2, env.payload + 8, true);
            env.read(&mut c, h, 4, b"RUST");
            env.close(&mut c, h);
            env.open(&mut c, a, h2, 0x80000000, 7, 3);
            env.read(&mut c, h2, 4, b"NEW!");
            env.close(&mut c, h2);
        }
        MutationFixture::Copy => {
            env.file(&mut c, a, h, env.payload, true);
            env.file(&mut c, b, h2, env.payload + 4, false);
            env.read(&mut c, h2, 1, b"T");
            call(&mut c, wide, base, 9, &[V(a), V(2)]);
            expect(&mut c, 1);
            call(&mut c, wide, base, 5, &[V(a), V(folded), V(0)]);
            expect(&mut c, 1);
            env.read(&mut c, h2, 3, b"UST");
            env.close(&mut c, h2);
            call(&mut c, wide, base, 9, &[V(a), V(4)]);
            expect(&mut c, 1);
            call(&mut c, wide, base, 8, &[V(b)]);
            expect(&mut c, 2);
            call(&mut c, wide, base, 5, &[V(a), V(b), V(0)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 5);
            call(&mut c, wide, base, 9, &[V(b), V(0x80)]);
            expect(&mut c, 1);
            call(&mut c, wide, base, 5, &[V(a), V(b), V(1)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 80);
            call(&mut c, wide, base, 5, &[V(a), V(a), V(0)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 32);
        }
        MutationFixture::CopySharing => {
            env.file(&mut c, a, h, env.payload, true);
            env.file(&mut c, b, h2, env.payload + 4, true);
            env.open(&mut c, a, h, 0x80000000, 0, 3);
            call(&mut c, wide, base, 5, &[V(a), V(b), V(0)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 32);
            env.close(&mut c, h);
            env.open(&mut c, b, h2, 0x80000000, 1, 3);
            call(&mut c, wide, base, 5, &[V(a), V(b), V(0)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 32);
            env.read(&mut c, h2, 4, b"TARG");
            env.close(&mut c, h2);
            call(&mut c, wide, base, 5, &[V(a), V(b), V(0)]);
            expect(&mut c, 1);
        }
        MutationFixture::Move => {
            env.file(&mut c, a, h, env.payload, false);
            env.file(&mut c, b, h2, env.payload + 4, true);
            call(&mut c, wide, base, 7, &[V(a), V(b)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 183);
            call(&mut c, wide, base, 6, &[V(a), V(b), V(9)]);
            expect(&mut c, 1);
            env.read(&mut c, h, 4, b"RUST");
            env.close(&mut c, h);
            call(&mut c, wide, base, 8, &[V(a)]);
            expect(&mut c, u32::MAX);
            last(&mut c, wide, base, 2);
            call(&mut c, wide, base, 7, &[V(b), V(folded)]);
            expect(&mut c, 1);
            call(&mut c, wide, base, 15, &[V(folded), V(env.out + 0x100)]);
            store(&mut c, wide, h2);
            let name = if unicode {
                "Targeté.bin"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>()
            } else {
                b"Target\xe9.bin".to_vec()
            };
            for (index, chunk) in name.chunks(4).enumerate() {
                let mut d = [0; 4];
                d[..chunk.len()].copy_from_slice(chunk);
                expect_dword(
                    &mut c,
                    wide,
                    env.out + 0x100 + 44 + index as u64 * 4,
                    u32::from_le_bytes(d),
                );
            }
            call(&mut c, wide, base, 16, &[M(h2)]);
            expect(&mut c, 1);
        }
        MutationFixture::MoveSharing => {
            env.file(&mut c, a, h, env.payload, true);
            env.file(&mut c, b, h2, env.payload + 4, true);
            env.open(&mut c, a, h, 0x80000000, 3, 3);
            call(&mut c, wide, base, 4, &[V(a)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 32);
            call(&mut c, wide, base, 6, &[V(a), V(new), V(0)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 32);
            env.read(&mut c, h, 4, b"RUST");
            env.close(&mut c, h);
            env.open(&mut c, b, h2, 0x80000000, 7, 3);
            call(&mut c, wide, base, 6, &[V(a), V(b), V(1)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 5);
            env.read(&mut c, h2, 4, b"TARG");
            env.close(&mut c, h2);
            call(&mut c, wide, base, 7, &[V(a), V(new)]);
            expect(&mut c, 1);
        }
        MutationFixture::Rename => {
            env.file(&mut c, a, h, env.payload, true);
            env.open(&mut c, a, h, 0x80010000, 3, 3);
            call(
                &mut c,
                wide,
                base,
                13,
                &[M(h), V(3), V(rename), V(rename_size)],
            );
            expect(&mut c, 1);
            env.read(&mut c, h, 4, b"RUST");
            env.close(&mut c, h);
            call(&mut c, wide, base, 8, &[V(a)]);
            expect(&mut c, u32::MAX);
            last(&mut c, wide, base, 2);
            call(&mut c, wide, base, 8, &[V(new)]);
            expect(&mut c, 0x80);
        }
        MutationFixture::RenameErrors => {
            env.file(&mut c, a, h, env.payload, true);
            env.open(&mut c, a, h, 0x80000000, 7, 3);
            call(
                &mut c,
                wide,
                base,
                13,
                &[M(h), V(3), V(rename), V(rename_size)],
            );
            expect(&mut c, 0);
            last(&mut c, wide, base, 5);
            call(
                &mut c,
                wide,
                base,
                13,
                &[V(0x123), V(3), V(rename), V(rename_size)],
            );
            expect(&mut c, 0);
            last(&mut c, wide, base, 6);
            if wide {
                // The low DWORD equals the actual open handle0x104. Never
                // truncate a full-width foreign token into that live handle.
                call(
                    &mut c,
                    true,
                    base,
                    13,
                    &[V(0x1_0000_0104), V(3), V(rename), V(rename_size)],
                );
                expect(&mut c, 0);
                last(&mut c, true, base, 6);
            }
            call(&mut c, wide, base, 13, &[M(h), V(3), V(rename), V(1)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 24);
            call(&mut c, wide, base, 13, &[M(h), V(3), V(1), V(rename_size)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 998);
            env.read(&mut c, h, 4, b"RUST");
            env.close(&mut c, h);
        }
        MutationFixture::Failures => {
            env.file(&mut c, a, h, env.payload, true);
            env.file(&mut c, b, h2, env.payload + 4, true);
            call(&mut c, wide, base, 9, &[V(b), V(1)]);
            expect(&mut c, 1);
            for index in [5, 6] {
                call(&mut c, wide, base, index, &[V(a), V(b), V(1)]);
                expect(&mut c, 0);
                last(&mut c, wide, base, 5);
            }
            call(&mut c, wide, base, 4, &[V(b)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 5);
            call(&mut c, wide, base, 5, &[V(a), V(absent), V(0)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 3);
            call(&mut c, wide, base, 4, &[V(0)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 87);
            env.open(&mut c, b, h2, 0x80000000, 7, 3);
            env.read(&mut c, h2, 4, b"TARG");
            env.close(&mut c, h2);
        }
        MutationFixture::FlagsUnsupported
        | MutationFixture::CrossVolumeUnsupported
        | MutationFixture::DirectoryUnsupported
        | MutationFixture::RootUnsupported
        | MutationFixture::ClassUnsupported => {
            if matches!(kind, MutationFixture::DirectoryUnsupported) {
                call(&mut c, wide, base, 14, &[V(a), V(0)]);
                expect(&mut c, 1);
                call(&mut c, wide, base, 4, &[V(a)]);
            } else {
                env.open(&mut c, a, h, 0xc0010000, 7, 2);
                match kind {
                    MutationFixture::FlagsUnsupported => {
                        call(&mut c, wide, base, 6, &[V(a), V(b), V(4)])
                    }
                    MutationFixture::CrossVolumeUnsupported => {
                        call(&mut c, wide, base, 6, &[V(a), V(other), V(0)])
                    }
                    MutationFixture::RootUnsupported => {
                        write_dword(&mut c, wide, rename + if wide { 8 } else { 4 }, 0x100);
                        call(
                            &mut c,
                            wide,
                            base,
                            13,
                            &[M(h), V(3), V(rename), V(rename_size)],
                        );
                    }
                    MutationFixture::ClassUnsupported => call(
                        &mut c,
                        wide,
                        base,
                        13,
                        &[M(h), V(0), V(rename), V(rename_size)],
                    ),
                    _ => unreachable!(),
                }
            }
        }
    }
    call(&mut c, wide, base, 11, &[V(0x12345678)]);
    last(&mut c, wide, base, 0x12345678);
    c.push(0xb8);
    c.extend(17u32.to_le_bytes());
    if wide {
        c.extend([0x48, 0x83, 0xc4, 0x58]);
    }
    c.push(0xc3);
    assert!(
        c.len() < 0x1000,
        "Mutation fixture exceeded owned text section"
    );
    data[0x200..0x200 + c.len()].copy_from_slice(&c);
    data
}

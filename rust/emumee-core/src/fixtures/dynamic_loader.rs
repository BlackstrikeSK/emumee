//! Guest code writes its own DLL bytes into the same VFS, then loads/uses/frees.
use super::*;
use winhttp::Arg::{self, Memory as M, Value as V};
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DynamicLoaderFixture {
    BasicA,
    BasicW,
    ExA,
    ExW,
    Ldr,
    Retain,
    Reload,
    Tls,
    Dependency,
    Forwarder,
    StaticRetain,
    False,
    AttachBudget,
    DetachBudget,
    Fault,
    Reentry,
    StorageTls,
    NxCallback,
    MissingDependency,
    Missing,
    Malformed,
    Flags,
    LdrBadBounds,
    LdrBadMaximum,
    LdrBadOutput,
    LdrFlags,
    LdrNull,
    LdrCountedNul,
    UnmappedFetch,
    LdrFalse,
    LdrNoOutput,
    LdrOutputReadonly,
}
impl DynamicLoaderFixture {
    pub const ALL: [Self; 32] = [
        Self::BasicA,
        Self::BasicW,
        Self::ExA,
        Self::ExW,
        Self::Ldr,
        Self::Retain,
        Self::Reload,
        Self::Tls,
        Self::Dependency,
        Self::Forwarder,
        Self::StaticRetain,
        Self::False,
        Self::AttachBudget,
        Self::DetachBudget,
        Self::Fault,
        Self::Reentry,
        Self::StorageTls,
        Self::NxCallback,
        Self::MissingDependency,
        Self::Missing,
        Self::Malformed,
        Self::Flags,
        Self::LdrBadBounds,
        Self::LdrBadMaximum,
        Self::LdrBadOutput,
        Self::LdrFlags,
        Self::LdrNull,
        Self::LdrCountedNul,
        Self::UnmappedFetch,
        Self::LdrFalse,
        Self::LdrNoOutput,
        Self::LdrOutputReadonly,
    ];
    pub fn positive(self) -> bool {
        matches!(
            self,
            Self::BasicA
                | Self::BasicW
                | Self::ExA
                | Self::ExW
                | Self::Ldr
                | Self::Retain
                | Self::Reload
                | Self::Tls
                | Self::Dependency
                | Self::Forwarder
                | Self::StaticRetain
                | Self::False
                | Self::Missing
                | Self::Malformed
                | Self::LdrBadBounds
                | Self::LdrBadMaximum
                | Self::LdrBadOutput
                | Self::LdrFlags
                | Self::LdrNull
                | Self::LdrCountedNul
                | Self::LdrFalse
                | Self::LdrNoOutput
        )
    }
    pub fn budget(self) -> bool {
        matches!(self, Self::AttachBudget | Self::DetachBudget)
    }
}
fn raw(rva: u32) -> usize {
    if rva < 0x4000 {
        0x200 + (rva - 0x1000) as usize
    } else {
        0x3200 + (rva - 0x4000) as usize
    }
}
fn dllraw(rva: u32) -> usize {
    if rva < 0x2000 {
        0x200 + (rva - 0x1000) as usize
    } else {
        0x1200 + (rva - 0x2000) as usize
    }
}
fn equal(code: &mut Vec<u8>) {
    code.extend([0x74, 1, 0xcc]);
}
fn call(code: &mut Vec<u8>, arch: Architecture, base: u64, index: usize, args: &[Arg]) {
    let wide = arch == Architecture::X64;
    if wide {
        for (position, arg) in args.iter().enumerate() {
            match arg {
                V(value) => {
                    code.extend([0x48, 0xb8]);
                    code.extend(value.to_le_bytes());
                }
                M(address) => {
                    code.extend([0x48, 0xa1]);
                    code.extend(address.to_le_bytes());
                }
            }
            if position < 4 {
                code.extend(
                    [
                        [0x48, 0x89, 0xc1],
                        [0x48, 0x89, 0xc2],
                        [0x49, 0x89, 0xc0],
                        [0x49, 0x89, 0xc1],
                    ][position],
                );
            } else {
                code.extend([0x48, 0x89, 0x44, 0x24, (32 + (position - 4) * 8) as u8]);
            }
        }
        let next = 0x1000 + code.len() + 6;
        code.extend([0xff, 0x15]);
        code.extend((0x4100i32 + index as i32 * 8 - next as i32).to_le_bytes());
    } else {
        for arg in args.iter().rev() {
            match arg {
                V(value) => {
                    code.push(0x68);
                    code.extend((*value as u32).to_le_bytes());
                }
                M(address) => {
                    code.extend([0xff, 0x35]);
                    code.extend((*address as u32).to_le_bytes());
                }
            }
        }
        code.extend([0xff, 0x15]);
        code.extend(((base + 0x4100) as u32 + index as u32 * 4).to_le_bytes());
    }
}
fn store(code: &mut Vec<u8>, arch: Architecture, address: u64) {
    winhttp::store(code, arch == Architecture::X64, address);
}
fn load(code: &mut Vec<u8>, arch: Architecture, address: u64) {
    if arch == Architecture::X64 {
        code.push(0x48);
    }
    winhttp::load(code, arch == Architecture::X64, address);
}
fn value(code: &mut Vec<u8>, expected: u32) {
    code.push(0x3d);
    code.extend(expected.to_le_bytes());
    equal(code);
}
fn count(code: &mut Vec<u8>, arch: Architecture, address: u64, expected: u32) {
    load(code, arch, address);
    value(code, expected);
}
fn strings(data: &mut [u8], rva: u32, value: &str, wide: bool) {
    let b = if wide {
        value
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    } else {
        value.as_bytes().iter().copied().chain([0]).collect()
    };
    data[raw(rva)..raw(rva) + b.len()].copy_from_slice(&b);
}
fn root_imports(data: &mut [u8], arch: Architecture, static_guest: bool) {
    let names = [
        "CreateFileA",
        "WriteFile",
        "CloseHandle",
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryExA",
        "LoadLibraryExW",
        "FreeLibrary",
        "GetProcAddress",
        "GetLastError",
        "GetModuleHandleW",
        "VirtualAlloc",
    ];
    let dd = 0x98 + if arch == Architecture::X64 { 112 } else { 96 };
    put32(data, dd + 8, 0x4000);
    put32(data, dd + 12, if static_guest { 80 } else { 60 });
    // Kernel32 index0..11, NTDLL index14..15, optional guest index18.
    // Reserved zero slots12/16 are necessary for actual PE import terminators.
    for (group, first, len) in [(0, 0usize, 12usize), (1, 14, 2), (2, 18, 1)] {
        if group == 2 && !static_guest {
            break;
        }
        let module = match group {
            0 => "kernel32.dll",
            1 => "ntdll.dll",
            _ => "guest.dll",
        };
        let name = 0x4300 + group as u32 * 32;
        strings(data, name, module, false);
        let at = raw(0x4000) + group * 20;
        put32(data, at + 12, name);
        let ilt = 0x4200 + first as u32 * arch.width() as u32;
        let iat = 0x4100 + first as u32 * arch.width() as u32;
        put32(data, at, ilt);
        put32(data, at + 16, iat);
        let entries: Vec<&str> = match group {
            0 => names.to_vec(),
            1 => vec!["LdrLoadDll", "LdrUnloadDll"],
            _ => vec!["Alpha"],
        };
        for (i, symbol) in entries.iter().enumerate() {
            let hint = 0x4400 + (first + i) as u32 * 64;
            let p = (hint as u64).to_le_bytes();
            data[raw(ilt) + i * arch.width()..raw(ilt) + (i + 1) * arch.width()]
                .copy_from_slice(&p[..arch.width()]);
            data[raw(iat) + i * arch.width()..raw(iat) + (i + 1) * arch.width()]
                .copy_from_slice(&p[..arch.width()]);
            strings(data, hint + 2, symbol, false);
        }
        data[raw(ilt) + len * arch.width()..raw(ilt) + (len + 1) * arch.width()].fill(0);
        data[raw(iat) + len * arch.width()..raw(iat) + (len + 1) * arch.width()].fill(0);
    }
}
fn journal(code: &mut Vec<u8>, arch: Architecture, address: u64, marker: u8) {
    if arch == Architecture::X64 {
        code.extend([0x49, 0xba]);
        code.extend(address.to_le_bytes());
        code.extend([
            0x41, 0x8b, 0x02, 0x41, 0xc6, 0x44, 0x02, 4, marker, 0x41, 0xff, 0x02,
        ]);
    } else {
        code.push(0xba);
        code.extend((address as u32).to_le_bytes());
        code.extend([0x8b, 0x02, 0xc6, 0x44, 0x02, 4, marker, 0xff, 0x02]);
    }
}
fn initializer(
    arch: Architecture,
    base: u64,
    journal_address: u64,
    tls: bool,
    static_image: bool,
    kind: DynamicLoaderFixture,
) -> Vec<u8> {
    let mut c = Vec::new();
    if arch == Architecture::X64 {
        c.extend([0x48, 0xb8]);
        c.extend(base.to_le_bytes());
        c.extend([0x48, 0x39, 0xc1]);
        equal(&mut c);
        c.extend([0x49, 0x83, 0xf8, if static_image && !tls { 1 } else { 0 }]);
        equal(&mut c);
        c.extend([0x83, 0xfa, 1]);
    } else {
        c.extend([0x81, 0x7c, 0x24, 4]);
        c.extend((base as u32).to_le_bytes());
        equal(&mut c);
        c.extend([
            0x83,
            0x7c,
            0x24,
            12,
            if static_image && !tls { 1 } else { 0 },
        ]);
        equal(&mut c);
        c.extend([0x83, 0x7c, 0x24, 8, 1]);
    }
    c.extend([0x0f, 0x85]);
    let branch = c.len();
    c.extend([0; 4]);
    journal(&mut c, arch, journal_address, if tls { 1 } else { 2 });
    if !tls {
        match kind {
            DynamicLoaderFixture::AttachBudget => c.extend([0xeb, 0xfe]),
            DynamicLoaderFixture::Fault => c.push(0xcc),
            DynamicLoaderFixture::Reentry => {
                if arch == Architecture::X64 {
                    c.extend([0x48, 0x83, 0xec, 0x28, 0x48, 0xb9]);
                    c.extend((base + 0x2140).to_le_bytes());
                    let next = 0x1000 + c.len() + 6;
                    c.extend([0xff, 0x15]);
                    c.extend((0x20c0i32 - next as i32).to_le_bytes());
                    c.extend([0x48, 0x83, 0xc4, 0x28]);
                } else {
                    c.push(0x68);
                    c.extend(((base + 0x2140) as u32).to_le_bytes());
                    c.extend([0xff, 0x15]);
                    c.extend(((base + 0x20c0) as u32).to_le_bytes());
                }
            }
            DynamicLoaderFixture::LdrOutputReadonly => {
                if arch == Architecture::X64 {
                    c.extend([0x48, 0x83, 0xec, 0x28, 0x48, 0xa1]);
                    c.extend((journal_address + 0x150).to_le_bytes());
                    c.extend([0x48, 0x89, 0xc1]);
                    c.extend([0xba, 0, 0x10, 0, 0, 0x41, 0xb8, 2, 0, 0, 0, 0x49, 0xb9]);
                    c.extend((base + 0x2700).to_le_bytes());
                    let next = 0x1000 + c.len() + 6;
                    c.extend([0xff, 0x15]);
                    c.extend((0x20c0i32 - next as i32).to_le_bytes());
                    c.extend([0x48, 0x83, 0xc4, 0x28]);
                } else {
                    for value in [base + 0x2700, 2, 4096] {
                        c.push(0x68);
                        c.extend((value as u32).to_le_bytes());
                    }
                    c.extend([0xff, 0x35]);
                    c.extend(((journal_address + 0x150) as u32).to_le_bytes());
                    c.extend([0xff, 0x15]);
                    c.extend(((base + 0x20c0) as u32).to_le_bytes());
                }
                winhttp::success(&mut c);
            }
            _ => {}
        }
    }
    c.extend([
        0xb8,
        if !tls
            && matches!(
                kind,
                DynamicLoaderFixture::False | DynamicLoaderFixture::LdrFalse
            )
        {
            0
        } else {
            1
        },
        0,
        0,
        0,
    ]);
    if arch == Architecture::X64 {
        c.push(0xc3);
    } else {
        c.extend([0xc2, 12, 0]);
    }
    let detach = c.len();
    let delta = (detach - (branch + 4)) as i32;
    c[branch..branch + 4].copy_from_slice(&delta.to_le_bytes());
    if arch == Architecture::X64 {
        c.extend([0x85, 0xd2]);
    } else {
        c.extend([0x83, 0x7c, 0x24, 8, 0]);
    }
    equal(&mut c);
    journal(&mut c, arch, journal_address, if tls { 3 } else { 4 });
    if !tls && kind == DynamicLoaderFixture::DetachBudget {
        c.extend([0xeb, 0xfe]);
    }
    c.extend([0xb8, 1, 0, 0, 0]);
    if arch == Architecture::X64 {
        c.push(0xc3);
    } else {
        c.extend([0xc2, 12, 0]);
    }
    assert!(c.len() < 256);
    c
}
fn dll(arch: Architecture, journal: u64, kind: DynamicLoaderFixture, second: bool) -> Vec<u8> {
    let source = if kind == DynamicLoaderFixture::StorageTls {
        LoaderFixture::StorageTls
    } else if kind == DynamicLoaderFixture::NxCallback {
        LoaderFixture::NxCallback
    } else if matches!(
        kind,
        DynamicLoaderFixture::Reentry | DynamicLoaderFixture::LdrOutputReadonly
    ) {
        LoaderFixture::Basic
    } else if kind == DynamicLoaderFixture::MissingDependency
        || kind == DynamicLoaderFixture::Dependency
    {
        LoaderFixture::Nested
    } else if kind == DynamicLoaderFixture::Forwarder {
        LoaderFixture::Forwarded
    } else {
        LoaderFixture::Tls
    };
    let (_, images) = native_loader_probe(arch, source);
    let mut data = images[usize::from(second && images.len() > 1)].1.clone();
    let pe = crate::pe::PeImage::parse(&data, "guest.dll").unwrap();
    let base = pe.image_base;
    let tls = matches!(
        kind,
        DynamicLoaderFixture::Tls
            | DynamicLoaderFixture::False
            | DynamicLoaderFixture::LdrFalse
            | DynamicLoaderFixture::AttachBudget
            | DynamicLoaderFixture::DetachBudget
            | DynamicLoaderFixture::Fault
            | DynamicLoaderFixture::StorageTls
            | DynamicLoaderFixture::NxCallback
    );
    if !tls {
        let dd = 0x98 + if arch == Architecture::X64 { 112 } else { 96 };
        data[dd + 9 * 8..dd + 10 * 8].fill(0);
    }
    if second {
        let dd = 0x98 + if arch == Architecture::X64 { 112 } else { 96 };
        data[dd + 8..dd + 16].fill(0);
    }
    if matches!(
        kind,
        DynamicLoaderFixture::Reentry | DynamicLoaderFixture::LdrOutputReadonly
    ) {
        let at = dllraw(0x2200) + 2;
        data[at..at + 0x60 - 2].fill(0);
        let symbol = if kind == DynamicLoaderFixture::Reentry {
            b"LoadLibraryA\0".as_slice()
        } else {
            b"VirtualProtect\0".as_slice()
        };
        data[at..at + symbol.len()].copy_from_slice(symbol);
    }
    for (rva, is_tls) in [(0x1000, false), (0x1100, true)] {
        let c = initializer(
            arch,
            base,
            journal,
            is_tls,
            kind == DynamicLoaderFixture::StaticRetain,
            kind,
        );
        let at = dllraw(rva);
        data[at..at + 256].fill(0);
        data[at..at + c.len()].copy_from_slice(&c);
    }
    data
}
/// No DLL input is installed by the host. The program itself writes embedded
/// owned bytes through CreateFile/WriteFile/Close before invoking LoadLibrary.
pub fn dynamic_loader_probe(
    arch: Architecture,
    kind: DynamicLoaderFixture,
) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    let wide = arch == Architecture::X64;
    let base: u64 = if wide { 0x140000000 } else { 0x400000 };
    let j = base + 0x5000;
    let mut root = counted_driver(arch, 1);
    root.resize(0x17200, 0);
    root[0x200..].fill(0);
    put16(&mut root, 0x96, 0x22);
    put16(&mut root, 0x98 + 68, 3);
    put32(&mut root, 0x98 + 56, 0x18000);
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    put32(&mut root, table + 8, 0x3000);
    put32(&mut root, table + 16, 0x3000);
    put32(&mut root, table + 40 + 8, 0x14000);
    put32(&mut root, table + 40 + 12, 0x4000);
    put32(&mut root, table + 40 + 16, 0x14000);
    put32(&mut root, table + 40 + 20, 0x3200);
    root_imports(&mut root, arch, kind == DynamicLoaderFixture::StaticRetain);
    strings(&mut root, 0x5200, "guest.dll", false);
    strings(&mut root, 0x5240, "guest.dll", true);
    strings(&mut root, 0x5280, "Alpha", false);
    strings(&mut root, 0x52c0, "other.dll", false);
    strings(
        &mut root,
        0x5340,
        if kind == DynamicLoaderFixture::StaticRetain {
            r"C:\emumee\guest.dll"
        } else {
            r"C:\workspace\guest.dll"
        },
        true,
    );
    let nt = raw(0x5300);
    put16(&mut root, nt, 18);
    put16(&mut root, nt + 2, 20);
    let p = (base + 0x5240).to_le_bytes();
    root[nt + arch.width()..nt + 2 * arch.width()].copy_from_slice(&p[..arch.width()]);
    match kind {
        DynamicLoaderFixture::LdrBadBounds => put16(&mut root, nt, 19),
        DynamicLoaderFixture::LdrBadMaximum => put16(&mut root, nt + 2, 21),
        DynamicLoaderFixture::LdrCountedNul => put16(&mut root, nt, 20),
        DynamicLoaderFixture::LdrFlags => put32(&mut root, raw(0x5380), 1),
        _ => {}
    }
    let mut a = dll(arch, j, kind, false);
    let b = dll(arch, j, kind, true);
    if kind == DynamicLoaderFixture::Malformed {
        a[..2].copy_from_slice(b"NO");
    }
    root[raw(0x6000)..raw(0x6000) + a.len()].copy_from_slice(&a);
    root[raw(0xa000)..raw(0xa000) + b.len()].copy_from_slice(&b);
    let mut c = Vec::new();
    if wide {
        c.extend([0x48, 0x83, 0xec, 0x48]);
    }
    let write = |c: &mut Vec<u8>, name: u64, bytes: u64, len: usize| {
        call(
            c,
            arch,
            base,
            0,
            &[V(name), V(0x40000000), V(3), V(0), V(2), V(0), V(0)],
        );
        store(c, arch, base + 0x5100);
        call(
            c,
            arch,
            base,
            1,
            &[
                M(base + 0x5100),
                V(bytes),
                V(len as u64),
                V(base + 0x5180),
                V(0),
            ],
        );
        winhttp::success(c);
        call(c, arch, base, 2, &[M(base + 0x5100)]);
        winhttp::success(c);
    };
    if matches!(
        kind,
        DynamicLoaderFixture::Dependency | DynamicLoaderFixture::Forwarder
    ) {
        write(&mut c, base + 0x52c0, base + 0xa000, b.len());
        call(&mut c, arch, base, 3, &[V(base + 0x52c0)]);
        winhttp::success(&mut c);
        store(&mut c, arch, base + 0x5120);
    }
    if !matches!(
        kind,
        DynamicLoaderFixture::Missing | DynamicLoaderFixture::StaticRetain
    ) {
        write(&mut c, base + 0x5200, base + 0x6000, a.len());
    }
    if kind == DynamicLoaderFixture::LdrOutputReadonly {
        call(&mut c, arch, base, 11, &[V(0), V(4096), V(0x3000), V(4)]);
        winhttp::success(&mut c);
        store(&mut c, arch, base + 0x5150);
    }
    let ldr = matches!(
        kind,
        DynamicLoaderFixture::Ldr
            | DynamicLoaderFixture::LdrFalse
            | DynamicLoaderFixture::LdrNoOutput
            | DynamicLoaderFixture::LdrOutputReadonly
            | DynamicLoaderFixture::LdrBadBounds
            | DynamicLoaderFixture::LdrBadMaximum
            | DynamicLoaderFixture::LdrBadOutput
            | DynamicLoaderFixture::LdrFlags
            | DynamicLoaderFixture::LdrNull
            | DynamicLoaderFixture::LdrCountedNul
    );
    if ldr {
        call(
            &mut c,
            arch,
            base,
            14,
            &[
                V(0),
                V(if kind == DynamicLoaderFixture::LdrFlags {
                    base + 0x5380
                } else {
                    0
                }),
                V(if kind == DynamicLoaderFixture::LdrNull {
                    0
                } else {
                    base + 0x5300
                }),
                if kind == DynamicLoaderFixture::LdrOutputReadonly {
                    M(base + 0x5150)
                } else {
                    V(if kind == DynamicLoaderFixture::LdrBadOutput {
                        base + 0x1000
                    } else if kind == DynamicLoaderFixture::LdrNoOutput {
                        0
                    } else {
                        base + 0x5110
                    })
                },
            ],
        );
    } else {
        let index = match kind {
            DynamicLoaderFixture::BasicW => 4,
            DynamicLoaderFixture::ExA | DynamicLoaderFixture::Flags => 5,
            DynamicLoaderFixture::ExW => 6,
            _ => 3,
        };
        let args = if index == 5 || index == 6 {
            vec![
                V(base + if index == 6 { 0x5240 } else { 0x5200 }),
                V(0),
                V(u64::from(kind == DynamicLoaderFixture::Flags)),
            ]
        } else {
            vec![V(base + if index == 4 { 0x5240 } else { 0x5200 })]
        };
        call(&mut c, arch, base, index, &args);
    }
    let expected_failure = match kind {
        DynamicLoaderFixture::False => Some((0, 1114)),
        DynamicLoaderFixture::LdrFalse => Some((0xc0000142, 1114)),
        DynamicLoaderFixture::Missing => Some((0, 126)),
        DynamicLoaderFixture::Malformed => Some((0, 193)),
        DynamicLoaderFixture::LdrBadBounds
        | DynamicLoaderFixture::LdrBadMaximum
        | DynamicLoaderFixture::LdrCountedNul
        | DynamicLoaderFixture::LdrNull => Some((0xc000000d, 0)),
        DynamicLoaderFixture::LdrBadOutput => Some((0xc0000005, 0)),
        DynamicLoaderFixture::LdrFlags => Some((0xc00000bb, 0)),
        _ => None,
    };
    if let Some((status, error)) = expected_failure {
        value(&mut c, status);
        if error != 0 {
            call(&mut c, arch, base, 9, &[]);
            value(&mut c, error);
        }
        if matches!(
            kind,
            DynamicLoaderFixture::False | DynamicLoaderFixture::LdrFalse
        ) {
            count(&mut c, arch, j, 4);
            count(&mut c, arch, j + 4, 0x04030201);
        }
    } else {
        if ldr {
            value(&mut c, 0);
            if kind == DynamicLoaderFixture::LdrNoOutput {
                call(&mut c, arch, base, 10, &[V(base + 0x5340)]);
                winhttp::success(&mut c);
                store(&mut c, arch, base + 0x5110);
            }
        } else {
            winhttp::success(&mut c);
            store(&mut c, arch, base + 0x5110);
        }
        if kind == DynamicLoaderFixture::Retain {
            call(&mut c, arch, base, 4, &[V(base + 0x5240)]);
            store(&mut c, arch, base + 0x5130);
            load(&mut c, arch, base + 0x5110);
            if wide {
                c.extend([0x48, 0x3b, 0x05]);
                let next = 0x1000 + c.len() + 4;
                c.extend((0x5130i32 - next as i32).to_le_bytes());
            } else {
                c.extend([0x3b, 0x05]);
                c.extend(((base + 0x5130) as u32).to_le_bytes());
            }
            equal(&mut c);
            call(&mut c, arch, base, 7, &[M(base + 0x5130)]);
            winhttp::success(&mut c);
        }
        call(&mut c, arch, base, 8, &[M(base + 0x5110), V(base + 0x5280)]);
        winhttp::success(&mut c);
        store(&mut c, arch, base + 0x5140);
        c.extend([0xff, 0xd0]);
        value(&mut c, 42);
        if matches!(
            kind,
            DynamicLoaderFixture::Dependency | DynamicLoaderFixture::Forwarder
        ) {
            call(&mut c, arch, base, 7, &[M(base + 0x5120)]);
            winhttp::success(&mut c);
        }
        call(
            &mut c,
            arch,
            base,
            if ldr { 15 } else { 7 },
            &[M(base + 0x5110)],
        );
        if ldr {
            value(&mut c, 0);
        } else {
            winhttp::success(&mut c);
        }
        if kind == DynamicLoaderFixture::Ldr {
            call(&mut c, arch, base, 15, &[V(0)]);
            value(&mut c, 0xc000000d);
        }
        if kind == DynamicLoaderFixture::Reload {
            call(&mut c, arch, base, 3, &[V(base + 0x5200)]);
            winhttp::success(&mut c);
            store(&mut c, arch, base + 0x5110);
            call(&mut c, arch, base, 7, &[M(base + 0x5110)]);
            winhttp::success(&mut c);
        }
        if kind == DynamicLoaderFixture::UnmappedFetch {
            load(&mut c, arch, base + 0x5140);
            c.extend([0xff, 0xd0]);
        }
        let expected = if matches!(
            kind,
            DynamicLoaderFixture::Tls
                | DynamicLoaderFixture::Dependency
                | DynamicLoaderFixture::Forwarder
                | DynamicLoaderFixture::Reload
        ) {
            4
        } else if kind == DynamicLoaderFixture::StaticRetain {
            1
        } else {
            2
        };
        count(&mut c, arch, j, expected);
        if kind == DynamicLoaderFixture::Tls {
            count(&mut c, arch, j + 4, 0x04030201);
        }
        call(&mut c, arch, base, 10, &[V(base + 0x5340)]);
        if kind == DynamicLoaderFixture::StaticRetain {
            winhttp::success(&mut c);
        } else {
            winhttp::failure(&mut c);
        }
    }
    c.extend([0xb8, 42, 0, 0, 0]);
    if wide {
        c.extend([0x48, 0x83, 0xc4, 0x48]);
    }
    c.push(0xc3);
    assert!(c.len() < 0x3000);
    root[0x200..0x200 + c.len()].copy_from_slice(&c);
    let companions = if kind == DynamicLoaderFixture::StaticRetain {
        vec![("guest.dll".into(), a)]
    } else {
        Vec::new()
    };
    (root, companions)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_programs_have_real_user_pe_imports_and_owned_embedded_dll_inputs() {
        for arch in [Architecture::X86, Architecture::X64] {
            for kind in DynamicLoaderFixture::ALL {
                let (bytes, companions) = dynamic_loader_probe(arch, kind);
                let pe = crate::pe::PeImage::parse(&bytes, "root.exe").unwrap();
                assert_eq!(pe.sample.kind, crate::pe::Kind::Exe);
                assert_eq!(
                    pe.imports.len(),
                    if kind == DynamicLoaderFixture::StaticRetain {
                        15
                    } else {
                        14
                    }
                );
                assert_eq!(
                    companions.len(),
                    usize::from(kind == DynamicLoaderFixture::StaticRetain)
                );
                assert!(pe.imports.iter().any(
                    |i| matches!(&i.name,crate::pe::ImportName::Name(n) if n=="LoadLibraryA")
                ));
            }
        }
    }
}

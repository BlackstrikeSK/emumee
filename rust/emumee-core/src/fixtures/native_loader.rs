//! Owned static-loader fixtures. Every initializer checks real arguments/order.
use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoaderFixture {
    Basic,
    Tls,
    TlsOnly,
    Nested,
    Forwarded,
    RootDll,
    RootTls,
    Entryless,
    False,
    NestedFalse,
    RootFalse,
    CleanupBudget,
    AttachBudget,
    Fault,
    BadStack,
    Nonvolatile,
    TlsMutation,
    DetachFault,
    Unused,
    StorageTls,
    MissingExternal,
    Cycle,
    NxCallback,
}
impl LoaderFixture {
    pub const ALL: [Self; 23] = [
        Self::Basic,
        Self::Tls,
        Self::TlsOnly,
        Self::Nested,
        Self::Forwarded,
        Self::RootDll,
        Self::RootTls,
        Self::Entryless,
        Self::False,
        Self::NestedFalse,
        Self::RootFalse,
        Self::CleanupBudget,
        Self::AttachBudget,
        Self::Fault,
        Self::BadStack,
        Self::Nonvolatile,
        Self::TlsMutation,
        Self::DetachFault,
        Self::Unused,
        Self::StorageTls,
        Self::MissingExternal,
        Self::Cycle,
        Self::NxCallback,
    ];
    pub fn positive(self) -> bool {
        matches!(
            self,
            Self::Basic
                | Self::Tls
                | Self::TlsOnly
                | Self::Nested
                | Self::Forwarded
                | Self::RootDll
                | Self::RootTls
                | Self::Entryless
        )
    }
    pub fn preparation_refusal(self) -> bool {
        matches!(
            self,
            Self::Unused
                | Self::StorageTls
                | Self::MissingExternal
                | Self::Cycle
                | Self::NxCallback
        )
    }
    pub fn budget(self) -> bool {
        matches!(self, Self::CleanupBudget | Self::AttachBudget)
    }
}
fn raw(rva: u32) -> usize {
    assert!(rva >= 0x2000);
    0x1200 + (rva - 0x2000) as usize
}
fn image(arch: Architecture, base: u64, dll: bool) -> Vec<u8> {
    let wide = arch == Architecture::X64;
    let mut data = counted_driver(arch, 1);
    data.resize(0x3200, 0);
    data[0x200..].fill(0);
    put16(&mut data, 0x96, if dll { 0x2022 } else { 0x22 });
    put16(&mut data, 0x98 + 68, 3);
    put32(&mut data, 0x98 + 56, 0x4000);
    if wide {
        put64(&mut data, 0x98 + 24, base)
    } else {
        put32(&mut data, 0x98 + 28, base as u32)
    }
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    put32(&mut data, table + 8, 0x1000);
    put32(&mut data, table + 16, 0x1000);
    put32(&mut data, table + 40 + 8, 0x2000);
    put32(&mut data, table + 40 + 16, 0x2000);
    put32(&mut data, table + 40 + 20, 0x1200);
    data
}
fn body(data: &mut [u8], rva: u32, code: &[u8]) {
    assert!(code.len() <= 0x100);
    let at = 0x200 + (rva - 0x1000) as usize;
    data[at..at + code.len()].copy_from_slice(code)
}
fn directory(data: &mut [u8], arch: Architecture, index: usize, rva: u32, size: u32) {
    let dd = 0x98 + if arch == Architecture::X64 { 112 } else { 96 };
    put32(data, dd + 8 * index, rva);
    put32(data, dd + 8 * index + 4, size)
}
fn imports(data: &mut [u8], arch: Architecture, entries: &[(&str, &str)]) {
    assert!(entries.len() <= 2);
    directory(data, arch, 1, 0x2000, ((entries.len() + 1) * 20) as u32);
    for (i, (module, symbol)) in entries.iter().enumerate() {
        let desc = raw(0x2000) + i * 20;
        let ilt = 0x2080 + i as u32 * 0x20;
        let iat = 0x20c0 + i as u32 * 0x20;
        let name = 0x2140 + i as u32 * 0x40;
        let hint = 0x2200 + i as u32 * 0x60;
        put32(data, desc, ilt);
        put32(data, desc + 12, name);
        put32(data, desc + 16, iat);
        let width = arch.width();
        let p = (hint as u64).to_le_bytes();
        data[raw(ilt)..raw(ilt) + width].copy_from_slice(&p[..width]);
        data[raw(iat)..raw(iat) + width].copy_from_slice(&p[..width]);
        data[raw(name)..raw(name) + module.len()].copy_from_slice(module.as_bytes());
        data[raw(hint) + 2..raw(hint) + 2 + symbol.len()].copy_from_slice(symbol.as_bytes());
    }
}
fn exports(data: &mut [u8], arch: Architecture, forward: bool, unused: bool) {
    directory(data, arch, 0, 0x2400, 0x180);
    for (offset, v) in [
        (16, 1),
        (20, if unused { 2 } else { 1 }),
        (24, if unused { 2 } else { 1 }),
        (28, 0x2440),
        (32, 0x2460),
        (36, 0x2480),
    ] {
        put32(data, raw(0x2400) + offset, v)
    }
    put32(data, raw(0x2440), if forward { 0x24c0 } else { 0x1200 });
    put32(data, raw(0x2460), 0x24a0);
    data[raw(0x24a0)..raw(0x24a0) + 6].copy_from_slice(b"Alpha\0");
    if forward {
        data[raw(0x24c0)..raw(0x24c0) + 12].copy_from_slice(b"other.Alpha\0")
    }
    if unused {
        put32(data, raw(0x2444), 0x2500);
        put32(data, raw(0x2464), 0x24b0);
        put16(data, raw(0x2482), 1);
        data[raw(0x24b0)..raw(0x24b0) + 7].copy_from_slice(b"Unused\0");
        data[raw(0x2500)..raw(0x2500) + 15].copy_from_slice(b"absent.Missing\0");
    }
    body(data, 0x1200, &[0xb8, 42, 0, 0, 0, 0xc3]);
}
fn tls(data: &mut [u8], arch: Architecture, base: u64, storage: bool, nx: bool) {
    directory(
        data,
        arch,
        9,
        0x2600,
        if arch == Architecture::X64 { 40 } else { 24 },
    );
    let width = arch.width();
    let array = (base + 0x2680).to_le_bytes();
    data[raw(0x2600) + 3 * width..raw(0x2600) + 4 * width].copy_from_slice(&array[..width]);
    let callback = (base + if nx { 0x2700 } else { 0x1100 }).to_le_bytes();
    data[raw(0x2680)..raw(0x2680) + width].copy_from_slice(&callback[..width]);
    if storage {
        let index = (base + 0x2700).to_le_bytes();
        data[raw(0x2600) + 2 * width..raw(0x2600) + 3 * width].copy_from_slice(&index[..width]);
    }
}
fn equal(code: &mut Vec<u8>) {
    code.extend([0x74, 1, 0xcc]);
}
fn record(code: &mut Vec<u8>, arch: Architecture, journal: u64, expected: u8, marker: u8) {
    if arch == Architecture::X64 {
        code.extend([0x49, 0xba]);
        code.extend(journal.to_le_bytes());
        code.extend([0x41, 0x83, 0x3a, expected]);
        equal(code);
        code.extend([0x41, 0xc6, 0x42, 4 + expected, marker, 0x41, 0xff, 0x02]);
    } else {
        code.push(0xba);
        code.extend((journal as u32).to_le_bytes());
        code.extend([0x83, 0x3a, expected]);
        equal(code);
        code.extend([0xc6, 0x42, 4 + expected, marker, 0xff, 0x02]);
    }
}
fn reserved(code: &mut Vec<u8>, arch: Architecture, value: u8) {
    if arch == Architecture::X64 {
        code.extend([0x49, 0x83, 0xf8, value]);
    } else {
        code.extend([0x83, 0x7c, 0x24, 12, value]);
    }
    equal(code)
}
fn ret(code: &mut Vec<u8>, arch: Architecture, bad: bool) {
    if arch == Architecture::X86 {
        if bad {
            code.push(0xc3)
        } else {
            code.extend([0xc2, 12, 0])
        }
    } else if bad {
        code.extend([0xc2, 8, 0])
    } else {
        code.push(0xc3)
    }
}
#[derive(Clone, Copy, Default)]
struct Behavior {
    false_attach: bool,
    loop_attach: bool,
    loop_detach: bool,
    fault_attach: bool,
    fault_detach: bool,
    bad_stack: bool,
    nonvolatile: bool,
    mutate_tls: bool,
    query_primary: bool,
}
#[allow(clippy::too_many_arguments)]
fn initializer(
    arch: Architecture,
    base: u64,
    journal: u64,
    attach: u8,
    detach: u8,
    tls: bool,
    primary: bool,
    failed: bool,
    behavior: Behavior,
) -> Vec<u8> {
    let mut code = Vec::new();
    if arch == Architecture::X64 {
        // Entry RSP is8 mod16, and all32 bytes of caller-owned home space exist.
        code.extend([0x48, 0x89, 0xe0, 0x83, 0xe0, 15, 0x83, 0xf8, 8]);
        equal(&mut code);
        code.extend([0x48, 0xc7, 0x44, 0x24, 32, 0x78, 0x56, 0x34, 0x12]);
    }
    if arch == Architecture::X64 {
        code.extend([0x49, 0xbb]);
        code.extend(base.to_le_bytes());
        code.extend([0x4c, 0x39, 0xd9]);
    } else {
        code.extend([0x81, 0x7c, 0x24, 4]);
        code.extend((base as u32).to_le_bytes());
    }
    equal(&mut code);
    if arch == Architecture::X64 {
        code.extend([0x85, 0xd2])
    } else {
        code.extend([0x8b, 0x44, 0x24, 8, 0x85, 0xc0])
    }
    code.extend([0x0f, 0x84]);
    let branch = code.len();
    code.extend([0; 4]);
    if arch == Architecture::X64 {
        code.extend([0x83, 0xfa, 1])
    } else {
        code.extend([0x83, 0xf8, 1])
    }
    equal(&mut code);
    reserved(&mut code, arch, u8::from(!tls && !primary));
    record(&mut code, arch, journal, attach, if tls { 1 } else { 2 });
    if behavior.query_primary {
        if arch == Architecture::X64 {
            code.extend([0x48, 0x83, 0xec, 0x28, 0x31, 0xc9]);
        } else {
            code.extend([0x6a, 0]);
        }
        call(
            &mut code,
            arch,
            base,
            if tls { 0x1100 } else { 0x1000 },
            0x20c0,
        );
        if arch == Architecture::X64 {
            code.extend([0x48, 0x83, 0xc4, 0x28, 0x49, 0xbb]);
            code.extend((journal - 0x2e00).to_le_bytes());
            code.extend([0x4c, 0x39, 0xd8]);
        } else {
            code.push(0x3d);
            code.extend(((journal - 0x2e00) as u32).to_le_bytes());
        }
        equal(&mut code);
    }
    if behavior.fault_attach {
        code.extend([0x0f, 0x0b]);
    }
    if behavior.loop_attach {
        code.extend([0xeb, 0xfe]);
    }
    if behavior.nonvolatile {
        if arch == Architecture::X64 {
            code.extend([0x48, 0xbb]);
            code.extend(0xabcdef0123456789u64.to_le_bytes());
        } else {
            code.push(0xbb);
            code.extend(0xabcdef01u32.to_le_bytes());
        }
    }
    if behavior.mutate_tls {
        if arch == Architecture::X64 {
            code.extend([0x49, 0xbb]);
            code.extend((base + 0x2680).to_le_bytes());
            code.extend([0x49, 0xc7, 0x03, 0, 0, 0, 0]);
        } else {
            code.extend([0xc7, 0x05]);
            code.extend(((base + 0x2680) as u32).to_le_bytes());
            code.extend([0; 4]);
        }
    }
    code.push(0xb8);
    code.extend(u32::from(!behavior.false_attach).to_le_bytes());
    ret(&mut code, arch, behavior.bad_stack);
    let detach_at = code.len();
    code[branch..branch + 4].copy_from_slice(&((detach_at - branch - 4) as u32).to_le_bytes());
    reserved(&mut code, arch, u8::from(!tls && !primary && !failed));
    record(&mut code, arch, journal, detach, if tls { 3 } else { 4 });
    if behavior.fault_detach {
        code.extend([0x0f, 0x0b]);
    }
    if behavior.loop_detach {
        code.extend([0xeb, 0xfe]);
    }
    code.extend([0x31, 0xc0]);
    ret(&mut code, arch, false);
    code
}
fn call(code: &mut Vec<u8>, arch: Architecture, base: u64, code_rva: u32, iat: u32) {
    if arch == Architecture::X64 {
        let next = code_rva + code.len() as u32 + 6;
        code.extend([0xff, 0x15]);
        code.extend((iat as i32 - next as i32).to_le_bytes());
    } else {
        code.extend([0xff, 0x15]);
        code.extend(((base + iat as u64) as u32).to_le_bytes());
    }
}
pub fn native_loader_probe(
    arch: Architecture,
    kind: LoaderFixture,
) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    let rootbase = if arch == Architecture::X64 {
        0x140000000
    } else {
        0x400000
    };
    let abase = if arch == Architecture::X64 {
        0x150000000
    } else {
        0x500000
    };
    let bbase = if arch == Architecture::X64 {
        0x160000000
    } else {
        0x600000
    };
    let journal = rootbase + 0x2e00;
    let rootdll = matches!(kind, LoaderFixture::RootDll | LoaderFixture::RootFalse);
    let root_tls = matches!(
        kind,
        LoaderFixture::RootDll | LoaderFixture::RootFalse | LoaderFixture::RootTls
    );
    let nested = matches!(
        kind,
        LoaderFixture::Nested
            | LoaderFixture::NestedFalse
            | LoaderFixture::CleanupBudget
            | LoaderFixture::Cycle
    );
    let forwarded = kind == LoaderFixture::Forwarded;
    let with_b = nested || forwarded || kind == LoaderFixture::Unused;
    let has_a = !rootdll && kind != LoaderFixture::RootTls;
    let atls = !matches!(
        kind,
        LoaderFixture::Basic
            | LoaderFixture::Forwarded
            | LoaderFixture::Entryless
            | LoaderFixture::BadStack
            | LoaderFixture::Nonvolatile
            | LoaderFixture::Unused
            | LoaderFixture::MissingExternal
            | LoaderFixture::Cycle
    );
    let entryless = matches!(kind, LoaderFixture::TlsOnly | LoaderFixture::Entryless);
    let failed = matches!(
        kind,
        LoaderFixture::False
            | LoaderFixture::NestedFalse
            | LoaderFixture::CleanupBudget
            | LoaderFixture::DetachFault
    );
    let mut root = image(arch, rootbase, rootdll);
    let mut companions = Vec::new();
    if has_a {
        imports(&mut root, arch, &[("guest.dll", "Alpha")]);
        let mut a = image(arch, abase, true);
        exports(&mut a, arch, forwarded, forwarded);
        if entryless {
            put32(&mut a, 0x98 + 16, 0);
        }
        if nested {
            imports(&mut a, arch, &[("other.dll", "Alpha")]);
        }
        if kind == LoaderFixture::Basic {
            imports(&mut a, arch, &[("kernel32.dll", "GetModuleHandleA")]);
        }

        if kind == LoaderFixture::MissingExternal {
            imports(&mut a, arch, &[("kernel32.dll", "DefinitelyNotModeled")]);
        }
        let before = if nested {
            2
        } else if forwarded {
            1
        } else {
            0
        };
        let behavior = Behavior {
            false_attach: failed,
            loop_attach: kind == LoaderFixture::AttachBudget,
            fault_attach: kind == LoaderFixture::Fault,
            bad_stack: kind == LoaderFixture::BadStack,
            nonvolatile: kind == LoaderFixture::Nonvolatile,
            query_primary: kind == LoaderFixture::Basic,
            ..Default::default()
        };
        let dll = initializer(
            arch,
            abase,
            journal,
            before + u8::from(atls),
            if nested { 5 } else { 3 },
            false,
            false,
            failed,
            behavior,
        );
        body(&mut a, 0x1000, &dll);
        if atls {
            tls(
                &mut a,
                arch,
                abase,
                kind == LoaderFixture::StorageTls,
                kind == LoaderFixture::NxCallback,
            );
            let tlsbody = initializer(
                arch,
                abase,
                journal,
                before,
                if nested { 4 } else { 2 },
                true,
                false,
                failed,
                Behavior {
                    mutate_tls: kind == LoaderFixture::TlsMutation,
                    fault_detach: kind == LoaderFixture::DetachFault,
                    ..Default::default()
                },
            );
            body(&mut a, 0x1100, &tlsbody);
        }
        companions.push(("guest.dll".into(), a));
    }
    if with_b {
        let mut b = image(arch, bbase, true);
        exports(&mut b, arch, false, false);
        if nested {
            tls(&mut b, arch, bbase, false, false);
            body(
                &mut b,
                0x1100,
                &initializer(
                    arch,
                    bbase,
                    journal,
                    0,
                    6,
                    true,
                    false,
                    false,
                    Behavior::default(),
                ),
            );
        }
        if kind == LoaderFixture::Cycle {
            imports(&mut b, arch, &[("guest.dll", "Alpha")]);
        }
        body(
            &mut b,
            0x1000,
            &initializer(
                arch,
                bbase,
                journal,
                u8::from(nested),
                7,
                false,
                false,
                false,
                Behavior {
                    loop_detach: kind == LoaderFixture::CleanupBudget,
                    ..Default::default()
                },
            ),
        );
        companions.push(("other.dll".into(), b));
    }
    if root_tls {
        tls(&mut root, arch, rootbase, false, false);
        body(
            &mut root,
            0x1100,
            &initializer(
                arch,
                rootbase,
                journal,
                0,
                2,
                true,
                true,
                kind == LoaderFixture::RootFalse,
                Behavior::default(),
            ),
        );
    }
    if rootdll {
        body(
            &mut root,
            0x1000,
            &initializer(
                arch,
                rootbase,
                journal,
                1,
                3,
                false,
                true,
                kind == LoaderFixture::RootFalse,
                Behavior {
                    false_attach: kind == LoaderFixture::RootFalse,
                    ..Default::default()
                },
            ),
        );
    } else {
        let expected = if root_tls {
            1
        } else if nested {
            4
        } else if forwarded {
            2
        } else {
            u8::from(atls) + u8::from(!entryless)
        };
        let mut code = Vec::new();
        if arch == Architecture::X64 {
            code.extend([0x49, 0xba]);
            code.extend(journal.to_le_bytes());
            code.extend([0x41, 0x83, 0x3a, expected]);
        } else {
            code.push(0xba);
            code.extend((journal as u32).to_le_bytes());
            code.extend([0x83, 0x3a, expected]);
        }
        equal(&mut code);
        if has_a {
            if arch == Architecture::X64 {
                code.extend([0x48, 0x83, 0xec, 0x28]);
            }
            call(&mut code, arch, rootbase, 0x1000, 0x20c0);
            if arch == Architecture::X64 {
                code.extend([0x48, 0x83, 0xc4, 0x28]);
            }
            code.extend([0x83, 0xf8, 42]);
            equal(&mut code);
        }
        code.extend([0xb8, 42, 0, 0, 0, 0xc3]);
        body(&mut root, 0x1000, &code);
    }
    (root, companions)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_owned_image_has_native_user_classification_and_bounded_callback_layout() {
        for arch in [Architecture::X86, Architecture::X64] {
            for kind in LoaderFixture::ALL {
                let (root, companions) = native_loader_probe(arch, kind);
                let pe = crate::pe::PeImage::parse(&root, "root.exe").unwrap();
                assert_ne!(pe.sample.kind, crate::pe::Kind::Driver);
                for (name, bytes) in companions {
                    let pe = crate::pe::PeImage::parse(&bytes, &name).unwrap();
                    assert_eq!(pe.sample.kind, crate::pe::Kind::Dll);
                    if !matches!(kind, LoaderFixture::StorageTls | LoaderFixture::NxCallback) {
                        assert!(pe.tls_callbacks_only(&bytes).is_ok());
                    }
                }
            }
        }
    }
}

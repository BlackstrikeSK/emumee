//! Owned native drivers verify callback bookkeeping without firing a callback.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, store, write_dword,
};
use super::{ApiFixture, api_probe, put32, put64};
use crate::pe::Architecture;

#[derive(Clone, Copy, Debug)]
pub enum CallbackFixture {
    NamespaceUnavailable,
    BugRegister,
    BugDuplicate,
    BugDeregister,
    BugTwice,
    BugMissing,
    BugReason,
    BugReadOnly,
    BugTwoRecords,
    NamedCreate,
    NamedMissing,
    NamedSystem,
    NamedReopen,
    NamedRegister,
    NamedDuplicate,
    NamedMultiple,
    NamedUnregister,
    NamedUnregisterTwice,
    NamedNotifyEmpty,
    NamedNotifyActive,
    NamedNotifySystem,
    NamedDereference,
    NamedPermanent,
    NamedBodyRead,
    NamedBodyWrite,
    NamedBodyCall,
    NamedApiRead,
    NamedApiWrite,
    NamedTokenRead,
    NamedIrql,
    NamedBadLength,
    NamedOddUnicode,
    NamedSecurity,
}
impl CallbackFixture {
    pub fn owned_namespace(self) -> bool {
        !matches!(self, Self::NamespaceUnavailable)
    }
    pub fn bugcheck(self) -> bool {
        matches!(
            self,
            Self::BugRegister
                | Self::BugDuplicate
                | Self::BugDeregister
                | Self::BugTwice
                | Self::BugMissing
                | Self::BugReason
                | Self::BugReadOnly
                | Self::BugTwoRecords
        )
    }
    pub fn negative(self) -> bool {
        matches!(
            self,
            Self::NamespaceUnavailable
                | Self::BugReadOnly
                | Self::NamedUnregisterTwice
                | Self::NamedNotifyActive
                | Self::NamedNotifySystem
                | Self::NamedBodyRead
                | Self::NamedBodyWrite
                | Self::NamedBodyCall
                | Self::NamedApiRead
                | Self::NamedApiWrite
                | Self::NamedTokenRead
                | Self::NamedIrql
                | Self::NamedSecurity
        )
    }
}
fn load_pointer(code: &mut Vec<u8>, wide: bool, address: u64) {
    if wide {
        code.push(0x48);
    }
    code.push(0xa1);
    if wide {
        code.extend(address.to_le_bytes());
    } else {
        code.extend((address as u32).to_le_bytes());
    }
}
fn load_dword(code: &mut Vec<u8>, wide: bool, address: u64) {
    code.push(0xa1);
    if wide {
        code.extend(address.to_le_bytes());
    } else {
        code.extend((address as u32).to_le_bytes());
    }
}
fn expect(code: &mut Vec<u8>, value: u32) {
    code.push(0x3d);
    code.extend(value.to_le_bytes());
    code.extend([0x74, 1, 0xcc]);
}
fn expect_pointer(code: &mut Vec<u8>, wide: bool, value: u64) {
    if wide {
        code.extend([0x48, 0xba]);
        code.extend(value.to_le_bytes());
        code.extend([0x48, 0x39, 0xd0, 0x74, 1, 0xcc]);
    } else {
        expect(code, value as u32);
    }
}
fn dereference(code: &mut Vec<u8>, wide: bool, base: u64, slot: u64) {
    if wide {
        call(code, wide, base, 6, &[M(slot)]);
    } else {
        // ObDereferenceObject is Fastcall on x86; no stack argument is pushed.
        load_pointer(code, false, slot);
        code.extend([0x89, 0xc1, 0xff, 0x15]);
        code.extend(((base + 0x2080 + 6 * 4) as u32).to_le_bytes());
    }
}

pub fn callback_probe(architecture: Architecture, kind: CallbackFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let width = architecture.width();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let identity = if wide {
        0xffffc00000000000u64
    } else {
        0xc0000000
    };
    let head = if wide {
        0xffffc10000000000u64
    } else {
        0xc1000000
    };
    let original = api_probe(architecture, ApiFixture::PoolLifecycle);
    let mut data = vec![0; 0x3200];
    data[..0x200].copy_from_slice(&original[..0x200]);
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    let dd = 0x98 + if wide { 112 } else { 96 };
    for (at, value) in [
        (0x98 + 4, 0x1000),
        (0x98 + 8, 0x2000),
        (0x98 + 56, 0x4000),
        (table + 8, 0x1000),
        (table + 16, 0x1000),
        (table + 40 + 8, 0x2000),
        (table + 40 + 16, 0x2000),
        (table + 40 + 20, 0x1200),
        (dd + 8, 0x2000),
        (dd + 12, 40),
        (0x1200, 0x2180),
        (0x120c, 0x2040),
        (0x1210, 0x2080),
    ] {
        put32(&mut data, at, value);
    }
    data[0x1240..0x124d].copy_from_slice(b"ntoskrnl.exe\0");
    let imports = [
        "KeRegisterBugCheckReasonCallback",
        "KeDeregisterBugCheckReasonCallback",
        "ExCreateCallback",
        "ExRegisterCallback",
        "ExUnregisterCallback",
        "ExNotifyCallback",
        "ObDereferenceObject",
        "RtlMoveMemory",
        "KeRaiseIrql",
    ];
    for (index, name) in imports.iter().enumerate() {
        let rva = 0x2300 + index as u32 * 64;
        for raw in [0x1280, 0x1380] {
            if wide {
                put64(&mut data, raw + index * width, rva.into());
            } else {
                put32(&mut data, raw + index * width, rva);
            }
        }
        let raw = 0x1500 + index * 64;
        data[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    // This address lies beyond the entire main caller body, in the RX section.
    let routine = base + 0x1f00;
    data[0x1100..0x1102].copy_from_slice(&[0x0f, 0x0b]);
    data[0x1d40..0x1d44].copy_from_slice(b"API!");
    data[0x1d80..0x1d84].copy_from_slice(b"EMU\0");
    let record = base + 0x2c00;
    let other_record = base + 0x2c40;
    let object = base + 0x2c00;
    let token = base + 0x2c10;
    let other = base + 0x2c20;
    let attributes = base + 0x2a00;
    let unicode = base + 0x2a40;
    let text = base + 0x2a80;
    let name = if matches!(
        kind,
        CallbackFixture::NamedSystem | CallbackFixture::NamedNotifySystem
    ) {
        r"\Callback\PowerState"
    } else {
        r"\Callback\EmumeeFixture"
    };
    let name_bytes = name
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    let oa_size = if wide { 48 } else { 24 };
    put32(
        &mut data,
        0x1c00,
        if matches!(kind, CallbackFixture::NamedBadLength) {
            4
        } else {
            oa_size
        },
    );
    let name_offset = if wide { 16 } else { 8 };
    let flag_offset = if wide { 24 } else { 12 };
    let security_offset = if wide { 32 } else { 16 };
    if wide {
        put64(&mut data, 0x1c00 + name_offset, unicode);
        if matches!(kind, CallbackFixture::NamedSecurity) {
            put64(&mut data, 0x1c00 + security_offset, base + 0x2b40);
        }
    } else {
        put32(&mut data, 0x1c00 + name_offset, unicode as u32);
        if matches!(kind, CallbackFixture::NamedSecurity) {
            put32(&mut data, 0x1c00 + security_offset, (base + 0x2b40) as u32);
        }
    }
    put32(
        &mut data,
        0x1c00 + flag_offset,
        if matches!(kind, CallbackFixture::NamedPermanent) {
            0x50
        } else {
            0x40
        },
    );
    let length = name_bytes.len() as u16;
    data[0x1c40..0x1c42].copy_from_slice(
        &(length - u16::from(matches!(kind, CallbackFixture::NamedOddUnicode))).to_le_bytes(),
    );
    data[0x1c42..0x1c44].copy_from_slice(&(length + 2).to_le_bytes());
    if wide {
        put64(&mut data, 0x1c48, text);
    } else {
        put32(&mut data, 0x1c44, text as u32);
    }
    data[0x1c80..0x1c80 + name_bytes.len()].copy_from_slice(&name_bytes);
    let mut code = Vec::new();
    if wide {
        code.extend([0x48, 0x83, 0xec, 0x68]);
    }
    if kind.bugcheck() {
        if matches!(kind, CallbackFixture::BugMissing) {
            call(&mut code, wide, base, 1, &[V(record)]);
            expect(&mut code, 0);
        } else {
            let address = if matches!(kind, CallbackFixture::BugReadOnly) {
                routine
            } else {
                record
            };
            call(
                &mut code,
                wide,
                base,
                0,
                &[
                    V(address),
                    V(routine),
                    V(if matches!(kind, CallbackFixture::BugReason) {
                        0
                    } else {
                        2
                    }),
                    V(base + 0x2b80),
                ],
            );
            expect(
                &mut code,
                u32::from(!matches!(kind, CallbackFixture::BugReason)),
            );
            if matches!(kind, CallbackFixture::BugDuplicate) {
                call(
                    &mut code,
                    wide,
                    base,
                    0,
                    &[V(record), V(routine), V(2), V(0)],
                );
                expect(&mut code, 0);
            }
            if matches!(kind, CallbackFixture::BugTwoRecords) {
                call(
                    &mut code,
                    wide,
                    base,
                    0,
                    &[V(other_record), V(routine), V(7), V(base + 0x2b80)],
                );
                expect(&mut code, 1);
            }
            if matches!(
                kind,
                CallbackFixture::BugDeregister
                    | CallbackFixture::BugTwice
                    | CallbackFixture::BugTwoRecords
            ) {
                call(&mut code, wide, base, 1, &[V(record)]);
                expect(&mut code, 1);
                if matches!(kind, CallbackFixture::BugTwice) {
                    call(&mut code, wide, base, 1, &[V(record)]);
                    expect(&mut code, 0);
                }
            }
        }
        let live = matches!(
            kind,
            CallbackFixture::BugRegister
                | CallbackFixture::BugDuplicate
                | CallbackFixture::BugTwoRecords
        );
        let checked = if matches!(kind, CallbackFixture::BugTwoRecords) {
            other_record
        } else {
            record
        };
        load_dword(&mut code, wide, checked + (width * 5 + 4) as u64);
        expect(&mut code, u32::from(live));
        if !matches!(
            kind,
            CallbackFixture::BugMissing | CallbackFixture::BugReason | CallbackFixture::BugReadOnly
        ) {
            load_pointer(&mut code, wide, checked + (width * 2) as u64);
            expect_pointer(&mut code, wide, routine);
            load_pointer(&mut code, wide, checked + (width * 3) as u64);
            expect_pointer(&mut code, wide, base + 0x2b80);
            if live {
                load_pointer(&mut code, wide, checked);
                expect_pointer(&mut code, wide, head);
                load_pointer(&mut code, wide, checked + width as u64);
                expect_pointer(&mut code, wide, head);
            }
        }
    } else {
        write_dword(&mut code, wide, object, 0x77777777);
        if wide {
            write_dword(&mut code, wide, object + 4, 0x77777777);
        }
        if matches!(kind, CallbackFixture::NamedIrql) {
            call(&mut code, wide, base, 8, &[V(2), V(base + 0x2d00)]);
        }
        let create = !matches!(
            kind,
            CallbackFixture::NamedMissing
                | CallbackFixture::NamedSystem
                | CallbackFixture::NamedNotifySystem
        );
        call(
            &mut code,
            wide,
            base,
            2,
            &[
                V(object),
                V(attributes),
                V(u64::from(create)),
                V(u64::from(matches!(kind, CallbackFixture::NamedMultiple))),
            ],
        );
        let rejected = matches!(
            kind,
            CallbackFixture::NamedMissing
                | CallbackFixture::NamedBadLength
                | CallbackFixture::NamedOddUnicode
        );
        expect(
            &mut code,
            if matches!(kind, CallbackFixture::NamedMissing) {
                0xc0000034
            } else if rejected {
                0xc000000d
            } else {
                0
            },
        );
        load_pointer(&mut code, wide, object);
        expect_pointer(
            &mut code,
            wide,
            if rejected {
                0x7777777777777777
            } else {
                identity
            },
        );
        if !rejected {
            if matches!(kind, CallbackFixture::NamedReopen) {
                call(
                    &mut code,
                    wide,
                    base,
                    2,
                    &[V(other), V(attributes), V(0), V(0)],
                );
                expect(&mut code, 0);
                load_pointer(&mut code, wide, other);
                expect_pointer(&mut code, wide, identity);
            }
            let register = matches!(
                kind,
                CallbackFixture::NamedRegister
                    | CallbackFixture::NamedDuplicate
                    | CallbackFixture::NamedMultiple
                    | CallbackFixture::NamedUnregister
                    | CallbackFixture::NamedUnregisterTwice
                    | CallbackFixture::NamedNotifyActive
                    | CallbackFixture::NamedTokenRead
            );
            if register {
                call(
                    &mut code,
                    wide,
                    base,
                    3,
                    &[M(object), V(routine), V(0x1234)],
                );
                store(&mut code, wide, token);
                expect_pointer(&mut code, wide, identity + 4096);
                if matches!(
                    kind,
                    CallbackFixture::NamedDuplicate | CallbackFixture::NamedMultiple
                ) {
                    call(
                        &mut code,
                        wide,
                        base,
                        3,
                        &[M(object), V(routine), V(0x5678)],
                    );
                    expect_pointer(
                        &mut code,
                        wide,
                        if matches!(kind, CallbackFixture::NamedMultiple) {
                            identity + 8192
                        } else {
                            0
                        },
                    );
                }
                if matches!(
                    kind,
                    CallbackFixture::NamedUnregister | CallbackFixture::NamedUnregisterTwice
                ) {
                    call(&mut code, wide, base, 4, &[M(token)]);
                    if matches!(kind, CallbackFixture::NamedUnregisterTwice) {
                        call(&mut code, wide, base, 4, &[M(token)]);
                    }
                }
            }
            if matches!(
                kind,
                CallbackFixture::NamedNotifyEmpty
                    | CallbackFixture::NamedNotifyActive
                    | CallbackFixture::NamedNotifySystem
            ) {
                call(&mut code, wide, base, 5, &[M(object), V(0x1111), V(0x2222)]);
            }
            if matches!(
                kind,
                CallbackFixture::NamedDereference | CallbackFixture::NamedPermanent
            ) {
                dereference(&mut code, wide, base, object);
                if matches!(kind, CallbackFixture::NamedPermanent) {
                    call(
                        &mut code,
                        wide,
                        base,
                        2,
                        &[V(other), V(attributes), V(0), V(0)],
                    );
                    expect(&mut code, 0);
                    load_pointer(&mut code, wide, other);
                    expect_pointer(&mut code, wide, identity);
                }
            }
            if matches!(
                kind,
                CallbackFixture::NamedBodyRead
                    | CallbackFixture::NamedBodyWrite
                    | CallbackFixture::NamedBodyCall
                    | CallbackFixture::NamedTokenRead
            ) {
                load_pointer(
                    &mut code,
                    wide,
                    if matches!(kind, CallbackFixture::NamedTokenRead) {
                        token
                    } else {
                        object
                    },
                );
                match kind {
                    CallbackFixture::NamedBodyRead | CallbackFixture::NamedTokenRead => {
                        if wide {
                            code.push(0x48);
                        }
                        code.extend([0x8b, 0x00]);
                    }
                    CallbackFixture::NamedBodyWrite => {
                        code.extend([0xc7, 0x00]);
                        code.extend(*b"FAIL");
                    }
                    CallbackFixture::NamedBodyCall => code.extend([0xff, 0xd0]),
                    _ => unreachable!(),
                }
            }
            if matches!(kind, CallbackFixture::NamedApiRead) {
                call(
                    &mut code,
                    wide,
                    base,
                    7,
                    &[V(base + 0x2d00), M(object), V(4)],
                );
            }
            if matches!(kind, CallbackFixture::NamedApiWrite) {
                call(
                    &mut code,
                    wide,
                    base,
                    7,
                    &[M(object), V(base + 0x2b40), V(4)],
                );
            }
        }
    }
    // A negative fixture reaching this point is an explicit failed assertion.
    if kind.negative() {
        code.push(0xcc);
    }
    code.extend([0xb8, 1, 0, 0, 0]);
    if wide {
        code.extend([0x48, 0x83, 0xc4, 0x68]);
    }
    code.push(0xc3);
    assert!(
        code.len() < 0xf00,
        "Owned callback caller overlaps reserved UD2 callback body"
    );
    data[0x200..0x200 + code.len()].copy_from_slice(&code);
    data
}

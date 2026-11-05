use super::*;

fn engine(arch: Architecture) -> crate::NativeEngine {
    let mut engine = crate::new_engine(arch).unwrap();
    for (address, size) in [(0x10000, 0x1000), (0x20000, 0x4000)] {
        engine.mem_map(address, size, Prot::ALL).unwrap();
        engine
            .get_data_mut()
            .apis
            .memory
            .map(address, size, P::ALL, None, "ABI CPU control")
            .unwrap();
    }
    engine
}

#[test]
fn abi_cpu_import_gates_decode_all_slots_and_preserve_nonvolatile_state() {
    for arch in [Architecture::X86, Architecture::X64] {
        for convention in [C::Stdcall, C::Cdecl, C::Fastcall] {
            for count in [0, 1, 2, 3, 4, 5, 6, 32] {
                let mut engine = engine(arch);
                let target = install_binding(
                    &mut engine,
                    Binding {
                        name: "abi-control".into(),
                        model: Model::Pid,
                        count,
                        convention,
                        returns: T::U32,
                    },
                )
                .unwrap();
                let width = arch.width();
                let sp = 0x22000;
                let arguments: Vec<u64> = (0..count)
                    .map(|index| {
                        if arch == Architecture::X64 {
                            0xfedcba9800000000 | index as u64
                        } else {
                            0xfedc0000 | index as u64
                        }
                    })
                    .collect();
                let gp = if arch == Architecture::X64 {
                    vec![R::Cx, R::Dx, R::R8, R::R9]
                } else if convention == C::Fastcall {
                    vec![R::Cx, R::Dx]
                } else {
                    vec![]
                };
                for (index, value) in arguments.iter().enumerate() {
                    if let Some(register) = gp.get(index) {
                        engine
                            .reg_write(native_register(arch, *register), *value)
                            .unwrap();
                    } else {
                        let offset = if arch == Architecture::X64 { 32 } else { 0 }
                            + (index - gp.len()) * width;
                        engine
                            .mem_write(sp + offset as u64, &value.to_le_bytes()[..width])
                            .unwrap();
                    }
                }
                let mut preserved = vec![
                    RegisterX86::EBX,
                    RegisterX86::EBP,
                    RegisterX86::ESI,
                    RegisterX86::EDI,
                ];
                if arch == Architecture::X64 {
                    preserved = vec![
                        RegisterX86::RBX,
                        RegisterX86::RBP,
                        RegisterX86::RSI,
                        RegisterX86::RDI,
                        RegisterX86::R12,
                        RegisterX86::R13,
                        RegisterX86::R14,
                        RegisterX86::R15,
                    ];
                }
                for (index, register) in preserved.iter().enumerate() {
                    engine
                        .reg_write(*register, 0x12340000 + index as u64)
                        .unwrap();
                }
                let xmm = [0xa5; 16];
                engine.reg_write(RegisterX86::FPCW, 0x27f).unwrap();
                engine.reg_write(RegisterX86::MXCSR, 0x3f80).unwrap();
                if arch == Architecture::X64 {
                    for register in [
                        RegisterX86::XMM6,
                        RegisterX86::XMM7,
                        RegisterX86::XMM8,
                        RegisterX86::XMM9,
                        RegisterX86::XMM10,
                        RegisterX86::XMM11,
                        RegisterX86::XMM12,
                        RegisterX86::XMM13,
                        RegisterX86::XMM14,
                        RegisterX86::XMM15,
                    ] {
                        engine.reg_write_long(register, &xmm).unwrap();
                    }
                }
                engine.reg_write(native_register(arch, R::Sp), sp).unwrap();
                let mut code = if arch == Architecture::X64 {
                    vec![0x48, 0xb8]
                } else {
                    vec![0xb8]
                };
                code.extend(&target.to_le_bytes()[..width]);
                code.extend([0xff, 0xd0, 0x90]);
                engine.mem_write(0x10000, &code).unwrap();
                engine
                    .add_code_hook(target, target, |engine, pc, _| {
                        if engine.get_data().architecture == Architecture::X64 {
                            assert_eq!(engine.reg_read(RegisterX86::RSP).unwrap() % 16, 8);
                            let sp = engine.reg_read(RegisterX86::RSP).unwrap();
                            engine.mem_write(sp + 8, &[0x7e; 32]).unwrap();
                        }
                        dispatch(engine, pc).unwrap();
                    })
                    .unwrap();
                engine
                    .emu_start(0x10000, 0x10000 + code.len() as u64, 0, 100)
                    .unwrap();
                assert_eq!(engine.get_data().apis.events[0].arguments, arguments);
                let popped = if arch == Architecture::X64 || convention == C::Cdecl {
                    0
                } else {
                    count.saturating_sub(gp.len()) * 4
                };
                assert_eq!(
                    engine.reg_read(native_register(arch, R::Sp)).unwrap(),
                    sp + popped as u64
                );
                assert_eq!(engine.reg_read(native_register(arch, R::Ax)).unwrap(), 1024);
                assert_eq!(engine.reg_read(RegisterX86::FPCW).unwrap(), 0x27f);
                assert_eq!(engine.reg_read(RegisterX86::MXCSR).unwrap(), 0x3f80);
                for (index, register) in preserved.iter().enumerate() {
                    assert_eq!(
                        engine.reg_read(*register).unwrap(),
                        0x12340000 + index as u64
                    );
                }
                if arch == Architecture::X64 {
                    for register in [
                        RegisterX86::XMM6,
                        RegisterX86::XMM7,
                        RegisterX86::XMM8,
                        RegisterX86::XMM9,
                        RegisterX86::XMM10,
                        RegisterX86::XMM11,
                        RegisterX86::XMM12,
                        RegisterX86::XMM13,
                        RegisterX86::XMM14,
                        RegisterX86::XMM15,
                    ] {
                        assert_eq!(&*engine.reg_read_long(register).unwrap(), &xmm);
                    }
                }
            }
        }
    }
}

#[test]
fn abi_cpu_return_widths_preserve_unsigned_status_and_signed_payloads() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [T::Void, T::U32, T::Pointer, T::U64, T::F64] {
            let mut engine = engine(arch);
            let value = 0x123480000010;
            engine.get_data_mut().clock.uptime_ms = value;
            engine
                .reg_write(native_register(arch, R::Ax), 0x1234)
                .unwrap();
            engine
                .reg_write(native_register(arch, R::Sp), 0x22000)
                .unwrap();
            let target = install_binding(
                &mut engine,
                Binding {
                    name: "abi-return-control".into(),
                    model: Model::Tick64,
                    count: 0,
                    convention: C::Cdecl,
                    returns: kind,
                },
            )
            .unwrap();
            engine
                .mem_write(0x21000, &target.to_le_bytes()[..arch.width()])
                .unwrap();
            let mut code = vec![0xff, 0x15];
            code.extend(if arch == Architecture::X64 {
                (0x21000i32 - 0x10006).to_le_bytes()
            } else {
                0x21000u32.to_le_bytes()
            });
            code.push(0x90);
            engine.mem_write(0x10000, &code).unwrap();
            engine
                .add_code_hook(target, target, |engine, pc, _| {
                    dispatch(engine, pc).unwrap()
                })
                .unwrap();
            engine
                .emu_start(0x10000, 0x10000 + code.len() as u64, 0, 100)
                .unwrap();
            if kind == T::F64 {
                assert_eq!(Frame(&engine).register(R::Xmm0).unwrap(), value);
            } else {
                assert_eq!(
                    engine.reg_read(native_register(arch, R::Ax)).unwrap(),
                    if kind == T::Void {
                        0x1234
                    } else if arch == Architecture::X86 || kind == T::U32 {
                        value & 0xffffffff
                    } else {
                        value
                    }
                );
            }
            if kind == T::U64 && arch == Architecture::X86 {
                assert_eq!(engine.reg_read(RegisterX86::EDX).unwrap(), value >> 32);
            }
        }
    }
}

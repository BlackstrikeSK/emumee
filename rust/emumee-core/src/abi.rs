//! Windows integer/pointer and frozen floating calling conventions. Guest addresses never become
//! host function pointers, including when an import name matches a host DLL.
use crate::pe::Architecture;
use serde::Serialize;
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CallingConvention {
    Stdcall,
    Cdecl,
    Fastcall,
    Float,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Register {
    Ax,
    Cx,
    Dx,
    Sp,
    R8,
    R9,
    Xmm0,
    Xmm1,
    Xmm2,
    Xmm3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnType {
    Void,
    U32,
    Pointer,
    U64,
    F64,
}
#[derive(Debug, Error)]
#[error("Windows ABI: {0}")]
pub struct AbiError(pub &'static str);
pub trait GuestRead {
    fn architecture(&self) -> Architecture;
    fn register(&self, register: Register) -> Result<u64, AbiError>;
    fn memory(&self, address: u64, size: usize) -> Result<Vec<u8>, AbiError>;
    fn memory_into(&self, address: u64, output: &mut [u8]) -> Result<(), AbiError> {
        let bytes = self.memory(address, output.len())?;
        if bytes.len() != output.len() {
            return Err(AbiError("truncated stack argument"));
        }
        output.copy_from_slice(&bytes);
        Ok(())
    }
}

pub fn arguments(
    guest: &impl GuestRead,
    convention: CallingConvention,
    count: usize,
) -> Result<Vec<u64>, AbiError> {
    if count > 32 {
        return Err(AbiError("argument count exceeds modeled limit"));
    }
    let mut output = vec![0; count];
    arguments_into(guest, convention, &mut output)?;
    Ok(output)
}
pub fn arguments_into(
    guest: &impl GuestRead,
    convention: CallingConvention,
    output: &mut [u64],
) -> Result<(), AbiError> {
    let count = output.len();
    if count > 32 {
        return Err(AbiError("argument count exceeds modeled limit"));
    }
    let arch = guest.architecture();
    if convention == CallingConvention::Float {
        if count > 4 {
            return Err(AbiError("floating argument count exceeds modeled limit"));
        }
        for (slot, register) in output.iter_mut().zip([
            Register::Xmm0,
            Register::Xmm1,
            Register::Xmm2,
            Register::Xmm3,
        ]) {
            *slot = guest.register(register)?;
        }
        return Ok(());
    }
    let width = arch.width();
    let sp = guest.register(Register::Sp)?;
    if arch == Architecture::X86 && sp > u32::MAX as u64 {
        return Err(AbiError("x86 stack pointer exceeds address space"));
    }
    for (index, slot) in output.iter_mut().enumerate() {
        let register = if arch == Architecture::X64 {
            [Register::Cx, Register::Dx, Register::R8, Register::R9]
                .get(index)
                .copied()
        } else if convention == CallingConvention::Fastcall {
            [Register::Cx, Register::Dx].get(index).copied()
        } else {
            None
        };
        let value = if let Some(register) = register {
            guest.register(register)?
        } else {
            let displacement = if arch == Architecture::X64 {
                0x28 + (index - 4) * 8
            } else {
                4 + (index
                    - if convention == CallingConvention::Fastcall {
                        2
                    } else {
                        0
                    })
                    * 4
            };
            let address = sp
                .checked_add(displacement as u64)
                .ok_or(AbiError("stack argument address overflow"))?;
            if arch == Architecture::X86 && address + 4 > 1u64 << 32 {
                return Err(AbiError("stack argument exceeds x86 address space"));
            }
            let mut bytes = [0; 8];
            guest.memory_into(address, &mut bytes[..width])?;
            if width == 8 {
                u64::from_le_bytes(bytes)
            } else {
                u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64
            }
        };
        *slot = if arch == Architecture::X86 {
            value & 0xffff_ffff
        } else {
            value
        };
    }
    Ok(())
}
pub fn return_registers(
    architecture: Architecture,
    kind: ReturnType,
    value: u64,
) -> Vec<(Register, u64)> {
    return_register_values(architecture, kind, value).collect()
}
pub fn return_register_values(
    architecture: Architecture,
    kind: ReturnType,
    value: u64,
) -> impl Iterator<Item = (Register, u64)> {
    let ax = if architecture == Architecture::X86 || kind == ReturnType::U32 {
        value & 0xffff_ffff
    } else {
        value
    };
    [
        (
            if kind == ReturnType::F64 {
                Register::Xmm0
            } else {
                Register::Ax
            },
            if kind == ReturnType::F64 { value } else { ax },
        ),
        (Register::Dx, value >> 32),
    ]
    .into_iter()
    .take(if kind == ReturnType::Void {
        0
    } else if architecture == Architecture::X86 && kind == ReturnType::U64 {
        2
    } else {
        1
    })
}
pub fn return_stub(
    architecture: Architecture,
    convention: CallingConvention,
    count: usize,
) -> Result<Vec<u8>, AbiError> {
    if count > 32 {
        return Err(AbiError("argument count exceeds modeled limit"));
    }
    if architecture == Architecture::X64 || convention == CallingConvention::Cdecl {
        return Ok(vec![0xc3]);
    }
    let stack = count.saturating_sub(if convention == CallingConvention::Fastcall {
        2
    } else {
        0
    }) * 4;
    if stack == 0 {
        return Ok(vec![0xc3]);
    }
    let mut bytes = vec![0xc2];
    bytes.extend((stack as u16).to_le_bytes());
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    #[test]
    fn abi_transport_matches_isolated_frozen_decoder_and_cleanup() {
        let reference: serde_json::Value =
            serde_json::from_str(include_str!("../../api-parity/abi-float-reference.json"))
                .unwrap();
        struct Frozen<'a>(&'a serde_json::Value);
        impl GuestRead for Frozen<'_> {
            fn architecture(&self) -> Architecture {
                if self.0["architecture"] == "x64" {
                    Architecture::X64
                } else {
                    Architecture::X86
                }
            }
            fn register(&self, register: Register) -> Result<u64, AbiError> {
                Ok(self.0["registers"][format!("{register:?}")]
                    .as_u64()
                    .unwrap())
            }
            fn memory(&self, address: u64, size: usize) -> Result<Vec<u8>, AbiError> {
                Ok(self.0["stack"][address.to_string()]
                    .as_u64()
                    .unwrap()
                    .to_le_bytes()[..size]
                    .to_vec())
            }
        }
        let vectors = reference["transport"]["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 56);
        for vector in vectors {
            let guest = Frozen(vector);
            let arch = guest.architecture();
            let convention = match vector["convention"].as_str().unwrap() {
                "stdcall" => CallingConvention::Stdcall,
                "cdecl" => CallingConvention::Cdecl,
                "fastcall" => CallingConvention::Fastcall,
                "float" => CallingConvention::Float,
                _ => unreachable!(),
            };
            let count = vector["count"].as_u64().unwrap() as usize;
            let expected: Vec<u64> = vector["arguments"]
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_u64().unwrap())
                .collect();
            assert_eq!(
                arguments(&guest, convention, count).unwrap(),
                expected,
                "{vector}"
            );
            let stub = return_stub(arch, convention, count).unwrap();
            let popped = if stub[0] == 0xc2 {
                u16::from_le_bytes(stub[1..].try_into().unwrap()) as u64
            } else {
                0
            };
            assert_eq!(
                0x2000 + arch.width() as u64 + popped,
                vector["returned_sp"].as_u64().unwrap(),
                "{vector}"
            );
        }
    }
    #[test]
    fn floating_slots_preserve_all_bits_on_both_architectures() {
        struct Floats(Architecture);
        impl GuestRead for Floats {
            fn architecture(&self) -> Architecture {
                self.0
            }
            fn register(&self, register: Register) -> Result<u64, AbiError> {
                Ok(match register {
                    Register::Xmm0 => 0x8000000000000000,
                    Register::Xmm1 => 0x7ff8000012345678,
                    Register::Xmm2 => 0xfff0000000000000,
                    Register::Xmm3 => 0x400921fb54442d18,
                    _ => panic!("floating decode must not read GP state"),
                })
            }
            fn memory(&self, _: u64, _: usize) -> Result<Vec<u8>, AbiError> {
                panic!("floating decode must not read stack")
            }
        }
        for arch in [Architecture::X86, Architecture::X64] {
            assert_eq!(
                arguments(&Floats(arch), CallingConvention::Float, 4).unwrap(),
                [
                    0x8000000000000000,
                    0x7ff8000012345678,
                    0xfff0000000000000,
                    0x400921fb54442d18
                ]
            );
            assert!(arguments(&Floats(arch), CallingConvention::Float, 5).is_err());
            assert_eq!(
                return_registers(arch, ReturnType::F64, 0x8000000000000000),
                [(Register::Xmm0, 0x8000000000000000)]
            );
            assert_eq!(
                return_stub(arch, CallingConvention::Float, 2).unwrap(),
                if arch == Architecture::X86 {
                    vec![0xc2, 8, 0]
                } else {
                    vec![0xc3]
                }
            );
        }
    }
    struct Probe {
        arch: Architecture,
        sp: u64,
        cells: BTreeMap<u64, u64>,
    }
    impl GuestRead for Probe {
        fn architecture(&self) -> Architecture {
            self.arch
        }
        fn register(&self, register: Register) -> Result<u64, AbiError> {
            Ok(match register {
                Register::Sp => self.sp,
                Register::Cx => 11,
                Register::Dx => 22,
                Register::R8 => 33,
                Register::R9 => 44,
                _ => 0,
            })
        }
        fn memory(&self, address: u64, size: usize) -> Result<Vec<u8>, AbiError> {
            let value = self
                .cells
                .get(&address)
                .ok_or(AbiError("unreadable guest argument"))?;
            Ok(value.to_le_bytes()[..size].to_vec())
        }
    }
    #[test]
    fn x64_shadow_space_is_skipped_for_fifth_and_sixth_arguments() {
        let guest = Probe {
            arch: Architecture::X64,
            sp: 0x1000,
            cells: BTreeMap::from([(0x1000, 999), (0x1020, 888), (0x1028, 55), (0x1030, 66)]),
        };
        assert_eq!(
            arguments(&guest, CallingConvention::Stdcall, 6).unwrap(),
            vec![11, 22, 33, 44, 55, 66]
        );
        assert_eq!(
            return_stub(Architecture::X64, CallingConvention::Stdcall, 6).unwrap(),
            vec![0xc3]
        );
    }
    #[test]
    fn x86_stack_arguments_and_fastcall_registers_follow_distinct_contracts() {
        let guest = Probe {
            arch: Architecture::X86,
            sp: 0x1000,
            cells: BTreeMap::from([(0x1000, 999), (0x1004, 33), (0x1008, 44), (0x100c, 55)]),
        };
        assert_eq!(
            arguments(&guest, CallingConvention::Stdcall, 3).unwrap(),
            vec![33, 44, 55]
        );
        assert_eq!(
            arguments(&guest, CallingConvention::Fastcall, 3).unwrap(),
            vec![11, 22, 33]
        );
        assert_eq!(
            return_stub(Architecture::X86, CallingConvention::Stdcall, 3).unwrap(),
            vec![0xc2, 12, 0]
        );
        assert_eq!(
            return_stub(Architecture::X86, CallingConvention::Fastcall, 3).unwrap(),
            vec![0xc2, 4, 0]
        );
        assert_eq!(
            return_stub(Architecture::X86, CallingConvention::Cdecl, 3).unwrap(),
            vec![0xc3]
        );
    }
    #[test]
    fn unreadable_arguments_and_wrapping_stacks_stop() {
        let guest = Probe {
            arch: Architecture::X64,
            sp: u64::MAX - 10,
            cells: BTreeMap::new(),
        };
        assert!(arguments(&guest, CallingConvention::Stdcall, 5).is_err());
        assert!(arguments(&guest, CallingConvention::Stdcall, 33).is_err());
        let guest = Probe {
            arch: Architecture::X86,
            sp: 0x1000,
            cells: BTreeMap::new(),
        };
        assert!(arguments(&guest, CallingConvention::Stdcall, 1).is_err());
        assert_eq!(
            return_registers(Architecture::X86, ReturnType::U64, 0x123456789abcdef0),
            vec![(Register::Ax, 0x9abcdef0), (Register::Dx, 0x12345678)]
        );
        for architecture in [Architecture::X86, Architecture::X64] {
            assert_eq!(
                return_register_values(architecture, ReturnType::Void, u64::MAX).count(),
                0
            );
        }
    }
}

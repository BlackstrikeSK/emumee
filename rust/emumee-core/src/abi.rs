//! Windows integer/pointer calling conventions. Guest addresses never become
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
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Register {
    Ax,
    Cx,
    Dx,
    Sp,
    R8,
    R9,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnType {
    Void,
    U32,
    Pointer,
    U64,
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
    [(Register::Ax, ax), (Register::Dx, value >> 32)]
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

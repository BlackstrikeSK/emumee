//! Generated CPU probes validate values in guest instructions before returning1.
use super::*;
#[derive(Clone, Copy, Debug)]
pub enum CpuFixture {
    Identity,
    Time,
    BadXcr,
    Rewrite,
    KernelBoot,
    KernelWriteProtected,
    SharedRead,
    SharedWrite,
    Halt,
    SystemCall,
    SystemCallBadTarget,
    SystemReturn,
    SystemEnter,
    SystemExit,
    TscAux,
    TscMsrRead,
    TscMsrWrite,
    TscMsrWrap,
    TscAdjust,
    TscAdjustLink,
    TscAdjustReset,
    TscMsrUser,
    KernelEntry,
}
pub fn cpu_probe(architecture: Architecture, kind: CpuFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let mut data = counted_driver(architecture, 1);
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let mut code = Vec::new();
    let mut failures = Vec::new();
    let mut syscall_return = None;
    fn compare(code: &mut Vec<u8>, failures: &mut Vec<usize>, register: u8, value: u32) {
        code.extend([0x81, 0xf8 + register]);
        code.extend(value.to_le_bytes());
        code.extend([0x0f, 0x85]);
        failures.push(code.len());
        code.extend([0; 4]);
    }
    fn cpuid(code: &mut Vec<u8>, leaf: u32, subleaf: u32) {
        code.push(0xb8);
        code.extend(leaf.to_le_bytes());
        code.push(0xb9);
        code.extend(subleaf.to_le_bytes());
        code.extend([0x0f, 0xa2]);
    }
    match kind {
        CpuFixture::KernelEntry => {
            let mut fail_jump = |code: &mut Vec<u8>| {
                code.extend([0x0f, 0x85]);
                failures.push(code.len());
                code.extend([0; 4]);
            };
            if wide {
                for read in [
                    &[0x48, 0x89, 0xe0][..],
                    &[0x48, 0x8b, 0x04, 0x24],
                    &[0x48, 0x89, 0xc8],
                    &[0x48, 0x89, 0xd0],
                ] {
                    code.extend(read);
                    code.extend([0x48, 0xc1, 0xe8, 63, 0x3d, 1, 0, 0, 0]);
                    fail_jump(&mut code);
                }
            } else {
                code.extend([0x8b, 0x5c, 0x24, 4, 0x8b, 0x74, 0x24, 8]);
                for read in [
                    &[0x89, 0xe0][..],
                    &[0x8b, 0x04, 0x24],
                    &[0x89, 0xd8],
                    &[0x89, 0xf0],
                ] {
                    code.extend(read);
                    code.extend([0xc1, 0xe8, 31, 0x3d, 1, 0, 0, 0]);
                    fail_jump(&mut code);
                }
            }
            code.extend(if wide {
                &[0x0f, 0xb7, 0x01][..]
            } else {
                &[0x0f, 0xb7, 0x03][..]
            });
            compare(&mut code, &mut failures, 0, 4);
            code.extend(if wide {
                &[0x0f, 0xb7, 0x41, 2][..]
            } else {
                &[0x0f, 0xb7, 0x43, 2][..]
            });
            compare(&mut code, &mut failures, 0, if wide { 0x150 } else { 0xa8 });
            code.extend(if wide {
                &[0x8b, 0x41, 32][..]
            } else {
                &[0x8b, 0x43, 16][..]
            });
            compare(&mut code, &mut failures, 0, 0x3000);
            if wide {
                for (offset, value) in [(24, base), (88, base + 0x1000)] {
                    code.extend([0x48, 0x8b, 0x41, offset, 0x49, 0xb8]);
                    code.extend(value.to_le_bytes());
                    code.extend([0x4c, 0x39, 0xc0, 0x0f, 0x85]);
                    failures.push(code.len());
                    code.extend([0; 4]);
                }
                code.extend([0x48, 0x8b, 0x41, 64, 0x0f, 0xb7, 0x40, 2]);
            } else {
                code.extend([0x8b, 0x43, 12]);
                compare(&mut code, &mut failures, 0, base as u32);
                code.extend([0x8b, 0x43, 44]);
                compare(&mut code, &mut failures, 0, (base + 0x1000) as u32);
                code.extend([0x8b, 0x43, 32, 0x0f, 0xb7, 0x40, 2]);
            }
            compare(&mut code, &mut failures, 0, b'D' as u32);
            code.extend(if wide {
                &[0x0f, 0xb7, 0x02][..]
            } else {
                &[0x0f, 0xb7, 0x06][..]
            });
            code.extend([0x85, 0xc0, 0x75, 1, 0xcc, 0x89, 0xc1]);
            code.extend(if wide {
                &[0x0f, 0xb7, 0x42, 2][..]
            } else {
                &[0x0f, 0xb7, 0x46, 2][..]
            });
            code.extend([0x29, 0xc8]);
            compare(&mut code, &mut failures, 0, 2);
            code.extend(if wide {
                &[0x48, 0x8b, 0x42, 8][..]
            } else {
                &[0x8b, 0x46, 4][..]
            });
            code.extend([0x0f, 0xb7, 0x40, 2]);
            compare(&mut code, &mut failures, 0, b'R' as u32);
        }
        CpuFixture::TscMsrRead | CpuFixture::TscMsrUser => {
            code.extend([0x0f, 0x31, 0x89, 0xc6, 0x89, 0xd7, 0xb9]);
            code.extend(0x10u32.to_le_bytes());
            code.extend([0x0f, 0x32, 0x39, 0xfa, 0x0f, 0x85]);
            failures.push(code.len());
            code.extend([0; 4]);
            code.extend([0x29, 0xf0]);
            // RDTSC->RDMSR spans4 guest instructions before the comparisons.
            compare(&mut code, &mut failures, 0, 400);
        }
        CpuFixture::TscMsrWrite | CpuFixture::TscMsrWrap => {
            let value = if matches!(kind, CpuFixture::TscMsrWrap) {
                u64::MAX - 50
            } else {
                1000
            };
            code.push(0xb9);
            code.extend(0x10u32.to_le_bytes());
            code.push(0xb8);
            code.extend((value as u32).to_le_bytes());
            code.push(0xba);
            code.extend(((value >> 32) as u32).to_le_bytes());
            code.extend([0x0f, 0x30, 0x0f, 0x31]);
            compare(
                &mut code,
                &mut failures,
                0,
                if matches!(kind, CpuFixture::TscMsrWrap) {
                    49
                } else {
                    1100
                },
            );
            compare(&mut code, &mut failures, 2, 0);
        }
        CpuFixture::TscAdjust => {
            cpuid(&mut code, 7, 0);
            code.extend([0x83, 0xe3, 2]);
            compare(&mut code, &mut failures, 3, 2);
            code.extend([0x0f, 0x31, 0x89, 0xc6, 0x89, 0xd7, 0xb9]);
            code.extend(0x3bu32.to_le_bytes());
            code.push(0xb8);
            code.extend(3000u32.to_le_bytes());
            code.extend([0x31, 0xd2, 0x0f, 0x30, 0x0f, 0x31, 0x29, 0xf0]);
            compare(&mut code, &mut failures, 0, 3700);
            code.push(0xb9);
            code.extend(0x3bu32.to_le_bytes());
            code.extend([0x0f, 0x32]);
            compare(&mut code, &mut failures, 0, 3000);
            compare(&mut code, &mut failures, 2, 0);
        }
        CpuFixture::TscAdjustLink | CpuFixture::TscAdjustReset => {
            code.extend([0x0f, 0x31, 0x89, 0xc6, 0x89, 0xd7, 0xb9]);
            code.extend(0x10u32.to_le_bytes());
            code.push(0xb8);
            code.extend(1000u32.to_le_bytes());
            code.extend([0x31, 0xd2, 0x0f, 0x30]);
            code.push(0xb9);
            code.extend(0x3bu32.to_le_bytes());
            if matches!(kind, CpuFixture::TscAdjustReset) {
                code.extend([0x31, 0xc0, 0x31, 0xd2, 0x0f, 0x30, 0x0f, 0x31, 0x29, 0xf0]);
                compare(&mut code, &mut failures, 0, 1100);
            } else {
                code.extend([0x0f, 0x32, 0x01, 0xf0, 0x11, 0xfa, 0x05]);
                code.extend(600u32.to_le_bytes());
                code.extend([0x83, 0xd2, 0]);
                compare(&mut code, &mut failures, 0, 1000);
                compare(&mut code, &mut failures, 2, 0);
            }
        }
        CpuFixture::TscAux => {
            code.push(0xb9);
            code.extend(0xc0000103u32.to_le_bytes());
            code.push(0xb8);
            code.extend(0x55aau32.to_le_bytes());
            code.extend([0x31, 0xd2, 0x0f, 0x30, 0x0f, 0x01, 0xf9]);
            compare(&mut code, &mut failures, 1, 0x55aa);
        }
        CpuFixture::SystemCall | CpuFixture::SystemCallBadTarget => {
            if wide {
                let target = if matches!(kind, CpuFixture::SystemCallBadTarget) {
                    0x12345000
                } else {
                    base + 0x1180
                };
                code.push(0xb9);
                code.extend(0xc0000082u32.to_le_bytes());
                code.push(0xb8);
                code.extend((target as u32).to_le_bytes());
                code.push(0xba);
                code.extend(((target >> 32) as u32).to_le_bytes());
                code.extend([0x0f, 0x30]);
                syscall_return = Some(base + 0x1000 + code.len() as u64 + 2);
            }
            code.extend([0x0f, 0x05, 0xc3]);
        }
        CpuFixture::SystemReturn => code.extend([0x0f, 0x07]),
        CpuFixture::SystemEnter => code.extend([0x0f, 0x34]),
        CpuFixture::SystemExit => code.extend([0x0f, 0x35]),
        CpuFixture::Halt => code.push(0xf4),
        CpuFixture::SharedRead => {
            let aliases = if wide {
                vec![0x7ffe0000u64, 0xfffff78000000000]
            } else {
                vec![0x7ffe0000, 0xffdf0000]
            };
            for alias in aliases {
                for (offset, value) in [(0x300, 10_000_000), (0x260, 22631), (0x3c0, 12)] {
                    if wide {
                        code.extend([0x48, 0xa1]);
                        code.extend((alias + offset).to_le_bytes());
                    } else {
                        code.push(0xa1);
                        code.extend(((alias + offset) as u32).to_le_bytes());
                    }
                    compare(&mut code, &mut failures, 0, value);
                }
            }
            // Shared time must also advance through pure guest CPU execution.
            if wide {
                code.extend([0x48, 0xa1]);
                code.extend(0x7ffe0008u64.to_le_bytes());
            } else {
                code.push(0xa1);
                code.extend(0x7ffe0008u32.to_le_bytes());
            }
            code.extend([0x89, 0xc3, 0xb9]);
            code.extend(1000u32.to_le_bytes());
            code.extend([0xff, 0xc9, 0x75, 0xfc]);
            if wide {
                code.extend([0x48, 0xa1]);
                code.extend(0x7ffe0008u64.to_le_bytes());
            } else {
                code.push(0xa1);
                code.extend(0x7ffe0008u32.to_le_bytes());
            }
            code.extend([0x29, 0xd8, 0x3d]);
            code.extend(300u32.to_le_bytes());
            code.extend([0x73, 1, 0xcc]);
        }
        CpuFixture::SharedWrite => {
            if wide {
                code.extend([0x48, 0xbf]);
                code.extend(0x7ffe0000u64.to_le_bytes());
                code.extend([0xc6, 0x07, 0x90]);
            } else {
                code.extend([0xc6, 0x05]);
                code.extend(0x7ffe0000u32.to_le_bytes());
                code.push(0x90);
            }
        }
        CpuFixture::KernelBoot => {
            code.extend([0x31, 0xc0, 0x8c, 0xc8]); // mov ax,cs
            compare(&mut code, &mut failures, 0, if wide { 0x10 } else { 8 });
            code.extend([0x0f, 0x20, 0xc0]); // mov rax,cr0
            compare(&mut code, &mut failures, 0, 0x80050033);
            code.extend([0x0f, 0x20, 0xe0, 0x83, 0xe0, 0x20]); // CR4.PAE
            compare(&mut code, &mut failures, 0, 0x20);
            code.extend([0x9c, 0x58, 0x25, 2, 2, 0, 0]);
            compare(&mut code, &mut failures, 0, 0x202);
            code.extend([0xb9, 0x80, 0, 0, 0xc0, 0x0f, 0x32, 0x25, 0, 8, 0, 0]); // EFER.NXE
            compare(&mut code, &mut failures, 0, 0x800);
            if wide {
                code.extend([0x65, 0x48, 0x8b, 0x04, 0x25, 0x18, 0, 0, 0]);
                code.extend([0x48, 0xb9]);
                code.extend(0xfffff80000000000u64.to_le_bytes());
                code.extend([0x48, 0x39, 0xc8, 0x0f, 0x85]);
                failures.push(code.len());
                code.extend([0; 4]);
                code.extend([0x65, 0x48, 0x8b, 0x04, 0x25, 0x88, 1, 0, 0]);
            } else {
                code.extend([0x64, 0xa1, 0x1c, 0, 0, 0]);
                compare(&mut code, &mut failures, 0, 0xffdff000);
                code.extend([0x64, 0xa1, 0x24, 1, 0, 0]);
            }
            let thread =
                crate::kernel_layout::KernelLayout::for_architecture(architecture).root_thread;
            if wide {
                code.extend([0x48, 0xb9]);
                code.extend(thread.to_le_bytes());
                code.extend([0x48, 0x39, 0xc8, 0x0f, 0x85]);
                failures.push(code.len());
                code.extend([0; 4]);
            } else {
                compare(&mut code, &mut failures, 0, thread as u32);
            }
        }
        CpuFixture::KernelWriteProtected => {
            code.extend([
                0x0f, 0x20, 0xc0, 0x25, 0xff, 0xff, 0xfe, 0xff, 0x0f, 0x22, 0xc0,
            ]);
            if wide {
                code.extend([0x48, 0xbf]);
                code.extend((base + 0x1000).to_le_bytes());
                code.extend([0xc6, 0x07, 0x90]);
            } else {
                code.extend([0xc6, 0x05]);
                code.extend(((base + 0x1000) as u32).to_le_bytes());
                code.push(0x90);
            }
        }
        CpuFixture::Identity => {
            if wide {
                for register in 0..4 {
                    code.extend([0x48, 0xb8 + register]);
                    code.extend(0xffff_ffff_0000_0000u64.to_le_bytes());
                }
                code.extend([0x0f, 0xa2]);
            } else {
                cpuid(&mut code, 0, 0);
            }
            for (register, value) in [(0, 0x16), (3, 0x756e6547), (1, 0x6c65746e), (2, 0x49656e69)]
            {
                compare(&mut code, &mut failures, register, value);
            }
            if wide {
                // Read full64-bit output: modeled CPUID must clear all upper bits.
                for register in [0, 3, 1, 2] {
                    code.extend([0x48, 0xc1, 0xe8 + register, 32]);
                    compare(&mut code, &mut failures, register, 0);
                }
            }
            cpuid(&mut code, 1, 0);
            compare(&mut code, &mut failures, 0, 0xa0653);
            cpuid(&mut code, 0xb, 1);
            compare(&mut code, &mut failures, 3, 12);
            cpuid(&mut code, 0x16, 0);
            compare(&mut code, &mut failures, 0, 2900);
            compare(&mut code, &mut failures, 3, 4300);
            cpuid(&mut code, 0x40000000, 0);
            for register in 0..4 {
                compare(&mut code, &mut failures, register, 0);
            }
        }
        CpuFixture::Time => {
            code.extend([0x31, 0xc9, 0x0f, 0x01, 0xd0]); // xor ecx; xgetbv
            compare(&mut code, &mut failures, 0, 7);
            compare(&mut code, &mut failures, 2, 0);
            code.extend([0x0f, 0x31, 0x89, 0xc6, 0x0f, 0x01, 0xf9, 0x29, 0xf0]);
            compare(&mut code, &mut failures, 0, 200);
            compare(&mut code, &mut failures, 1, 0);
        }
        CpuFixture::BadXcr => {
            code.extend([0xb9, 1, 0, 0, 0, 0x0f, 0x01, 0xd0]);
        }
        CpuFixture::Rewrite => {
            let routine = base + 0x1180;
            code.extend([0x31, 0xc0, 0xe8]);
            let displacement = 0x180i32 - (code.len() as i32 + 4);
            code.extend(displacement.to_le_bytes());
            compare(&mut code, &mut failures, 0, 0x16);
            if wide {
                code.extend([0x48, 0xbf]);
                code.extend((routine + 1).to_le_bytes());
                code.extend([0xc6, 0x07, 0x31]);
            } else {
                code.extend([0xc6, 0x05]);
                code.extend(((routine + 1) as u32).to_le_bytes());
                code.push(0x31);
            }
            code.push(0xe8);
            let displacement = 0x180i32 - (code.len() as i32 + 4);
            code.extend(displacement.to_le_bytes());
            compare(&mut code, &mut failures, 0, 0x16);
            let last = failures.last().copied().unwrap();
            code[last - 1] = 0x84; // Fail if the rewritten instruction still returns CPUID leaf0.
            // High TSC is nonzero; CPUID leaf0 would return vendor instead.
            compare(&mut code, &mut failures, 3, 0x756e6547);
            let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
            put32(&mut data, table + 36, 0xe0000020); // Explicit generated RWX code.
        }
    }
    code.extend([0xb8, 1, 0, 0, 0, 0xc3]);
    let failure = code.len();
    code.extend([0x31, 0xc0, 0xc3]);
    for fixup in failures {
        code[fixup..fixup + 4]
            .copy_from_slice(&((failure as i32) - (fixup + 4) as i32).to_le_bytes());
    }
    assert!(code.len() < 0x180);
    data[0x200..0x400].fill(0xcc);
    data[0x200..0x200 + code.len()].copy_from_slice(&code);
    if matches!(kind, CpuFixture::TscMsrUser) {
        put16(&mut data, 0x98 + 68, 3);
        put16(&mut data, 0x96, 0x22);
    }
    if matches!(kind, CpuFixture::Rewrite) {
        data[0x380..0x383].copy_from_slice(&[0x0f, 0xa2, 0xc3]);
    }
    if let Some(return_pc) = syscall_return {
        let mut routine = vec![0x48, 0xb8];
        routine.extend(return_pc.to_le_bytes());
        routine.extend([
            0x48, 0x39, 0xc1, 0x74, 1, 0xcc, 0x4c, 0x89, 0xd8, 0x25, 0, 2, 0, 0, 0x3d, 0, 2, 0, 0,
            0x74, 1, 0xcc,
        ]);
        routine.extend([
            0x9c, 0x58, 0x25, 0, 2, 0, 0, 0x3d, 0, 0, 0, 0, 0x74, 1, 0xcc, 0xb8, 1, 0, 0, 0, 0xff,
            0xe1,
        ]);
        assert!(routine.len() < 128);
        data[0x380..0x380 + routine.len()].copy_from_slice(&routine);
    }
    data
}

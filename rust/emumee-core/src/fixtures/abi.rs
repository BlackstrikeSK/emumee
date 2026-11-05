use super::winhttp::{call, write_dword};
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiFixture {
    Pow,
    Floor,
    FloorZero,
    Sin,
    SinZero,
    PowDomain,
    PowZero,
    PowOverflow,
    FloorNan,
    FloorInfinity,
    SinInfinity,
    Variadic,
    Variadic64,
    CrtCallback,
    CrtStack,
    CrtGpr,
    CrtVector,
    CrtDirection,
    CrtMxcsr,
    CrtFpcw,
    LoaderCallback,
    LoaderStack,
    LoaderGpr,
    LoaderVector,
    LoaderDirection,
    LoaderMxcsr,
    LoaderFpcw,
}
impl AbiFixture {
    pub const ALL: [Self; 27] = [
        Self::Pow,
        Self::Floor,
        Self::FloorZero,
        Self::Sin,
        Self::SinZero,
        Self::PowDomain,
        Self::PowZero,
        Self::PowOverflow,
        Self::FloorNan,
        Self::FloorInfinity,
        Self::SinInfinity,
        Self::Variadic,
        Self::Variadic64,
        Self::CrtCallback,
        Self::CrtStack,
        Self::CrtGpr,
        Self::CrtVector,
        Self::CrtDirection,
        Self::CrtMxcsr,
        Self::CrtFpcw,
        Self::LoaderCallback,
        Self::LoaderStack,
        Self::LoaderGpr,
        Self::LoaderVector,
        Self::LoaderDirection,
        Self::LoaderMxcsr,
        Self::LoaderFpcw,
    ];
    pub fn supported(self, arch: Architecture) -> bool {
        arch == Architecture::X64 || !matches!(self, Self::CrtVector | Self::LoaderVector)
    }
    pub fn positive(self) -> bool {
        matches!(
            self,
            Self::Pow
                | Self::Floor
                | Self::FloorZero
                | Self::Sin
                | Self::SinZero
                | Self::Variadic
                | Self::Variadic64
                | Self::CrtCallback
                | Self::LoaderCallback
        )
    }
    pub fn expected_return(self) -> u64 {
        if self == Self::LoaderCallback {
            42
        } else if matches!(self, Self::Variadic | Self::Variadic64) {
            17
        } else {
            1
        }
    }
}
fn assertion(code: &mut Vec<u8>) {
    code.extend([0x74, 1, 0xcc]);
}
fn corrupt(kind: AbiFixture, wide: bool) -> Vec<u8> {
    match kind {
        AbiFixture::CrtGpr | AbiFixture::LoaderGpr => vec![0xbb, 0x12, 0x34, 0x56, 0x78],
        AbiFixture::CrtVector | AbiFixture::LoaderVector => vec![0x66, 0x0f, 0x76, 0xf6],
        AbiFixture::CrtDirection | AbiFixture::LoaderDirection => vec![0xfd],
        AbiFixture::CrtMxcsr | AbiFixture::LoaderMxcsr => {
            let mut code = if wide {
                vec![0x48, 0x83, 0xec, 8]
            } else {
                vec![0x83, 0xec, 8]
            };
            code.extend([
                0x0f, 0xae, 0x1c, 0x24, 0x81, 0x34, 0x24, 0, 0x20, 0, 0, 0x0f, 0xae, 0x14, 0x24,
            ]);
            code.extend(if wide {
                vec![0x48, 0x83, 0xc4, 8]
            } else {
                vec![0x83, 0xc4, 8]
            });
            code
        }
        AbiFixture::CrtFpcw | AbiFixture::LoaderFpcw => {
            let mut code = if wide {
                vec![0x48, 0x83, 0xec, 8]
            } else {
                vec![0x83, 0xec, 8]
            };
            code.extend([
                0xd9, 0x3c, 0x24, 0x66, 0x81, 0x34, 0x24, 0, 4, 0xd9, 0x2c, 0x24,
            ]);
            code.extend(if wide {
                vec![0x48, 0x83, 0xc4, 8]
            } else {
                vec![0x83, 0xc4, 8]
            });
            code
        }
        _ => vec![],
    }
}
pub fn abi_probe(arch: Architecture, kind: AbiFixture) -> Vec<u8> {
    assert!(kind.supported(arch));
    let wide = arch == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    if matches!(kind, AbiFixture::Variadic | AbiFixture::Variadic64) {
        return format_probe(
            arch,
            if kind == AbiFixture::Variadic {
                FormatFixture::WideConsole
            } else {
                FormatFixture::Integer64
            },
        );
    }
    if matches!(
        kind,
        AbiFixture::LoaderCallback
            | AbiFixture::LoaderStack
            | AbiFixture::LoaderGpr
            | AbiFixture::LoaderVector
            | AbiFixture::LoaderDirection
            | AbiFixture::LoaderMxcsr
            | AbiFixture::LoaderFpcw
    ) {
        let mut data = native_loader_probe(arch, LoaderFixture::RootTls).0;
        let mut prefix = corrupt(kind, wide);
        if kind == AbiFixture::LoaderStack {
            prefix.extend(if wide { vec![0xc2, 8, 0] } else { vec![0xc3] });
        }
        if !prefix.is_empty() {
            data.copy_within(0x300..0x400 - prefix.len(), 0x300 + prefix.len());
            data[0x300..0x300 + prefix.len()].copy_from_slice(&prefix);
        }
        return data;
    }
    if matches!(
        kind,
        AbiFixture::CrtCallback
            | AbiFixture::CrtStack
            | AbiFixture::CrtGpr
            | AbiFixture::CrtVector
            | AbiFixture::CrtDirection
            | AbiFixture::CrtMxcsr
            | AbiFixture::CrtFpcw
    ) {
        let mut data = crt_startup_probe(arch, StartupFixture::InitializersError);
        let mut code = Vec::new();
        if wide {
            code.push(0x48);
        }
        code.extend([
            0x89,
            0xe0,
            0x83,
            0xe0,
            15,
            0x83,
            0xf8,
            if wide { 8 } else { 12 },
        ]);
        assertion(&mut code);
        if wide {
            for offset in [8, 16, 24, 32] {
                code.extend([0x48, 0xc7, 0x44, 0x24, offset, 0x78, 0x56, 0x34, 0x12]);
            }
            code.extend([0x48, 0x83, 0xec, 0x28, 0x31, 0xc9, 0x31, 0xd2, 0x48, 0xa1]);
            code.extend((base + 0x2080 + 15 * 8).to_le_bytes());
        } else {
            code.extend([0x6a, 0, 0x6a, 0, 0xa1]);
            code.extend(((base + 0x2080 + 15 * 4) as u32).to_le_bytes());
        }
        code.extend([0xff, 0xd0]);
        if wide {
            code.extend([0x48, 0x83, 0xc4, 0x28]);
        }
        write_dword(&mut code, wide, base + 0x2f00, 1);
        code.extend(corrupt(kind, wide));
        code.extend([0x31, 0xc0]);
        code.extend(if kind == AbiFixture::CrtStack {
            vec![0xc2, 4, 0]
        } else {
            vec![0xc3]
        });
        assert!(code.len() <= 0x100);
        data[0xa00..0xb00].fill(0);
        data[0xa00..0xa00 + code.len()].copy_from_slice(&code);
        return data;
    }
    let (name, values, expected): (&str, Vec<f64>, f64) = match kind {
        AbiFixture::Pow => ("pow", vec![2.0, 3.0], 8.0),
        AbiFixture::Floor => ("floor", vec![-1.25], -2.0),
        AbiFixture::FloorZero => ("floor", vec![-0.0], 0.0),
        AbiFixture::Sin => ("sin", vec![0.0], 0.0),
        AbiFixture::SinZero => ("sin", vec![-0.0], -0.0),
        AbiFixture::PowDomain => ("pow", vec![-2.0, 0.5], 0.0),
        AbiFixture::PowZero => ("pow", vec![0.0, -1.0], 0.0),
        AbiFixture::PowOverflow => ("pow", vec![1e308, 2.0], 0.0),
        AbiFixture::FloorNan => ("floor", vec![f64::NAN], 0.0),
        AbiFixture::FloorInfinity => ("floor", vec![f64::INFINITY], 0.0),
        AbiFixture::SinInfinity => ("sin", vec![f64::NEG_INFINITY], 0.0),
        _ => unreachable!(),
    };
    let mut data = api_probe(arch, ApiFixture::Unsupported);
    put16(&mut data, 0x96, 0x22);
    put16(&mut data, 0x98 + 68, 3);
    data[0x440..0x460].fill(0);
    data[0x440..0x44b].copy_from_slice(b"msvcrt.dll\0");
    data[0x702..0x740].fill(0);
    data[0x702..0x702 + name.len()].copy_from_slice(name.as_bytes());
    let mut code = if wide {
        vec![0x48, 0x83, 0xec, 0x28]
    } else {
        vec![]
    };
    for (index, value) in values.iter().enumerate() {
        let address = base + 0x2500 + index as u64 * 8;
        let raw = 0x900 + index * 8;
        data[raw..raw + 8].copy_from_slice(&value.to_bits().to_le_bytes());
        if wide {
            code.extend([0x48, 0xb8]);
            code.extend(address.to_le_bytes());
        } else {
            code.push(0xb8);
            code.extend((address as u32).to_le_bytes());
        }
        code.extend([0xf2, 0x0f, 0x10, (index as u8) << 3]);
    }
    if !wide {
        code.extend([0x83, 0xec, (values.len() * 4) as u8]);
    }
    call(&mut code, wide, base, 0, &[]);
    let expected = expected.to_bits();
    if wide {
        code.extend([0x48, 0xb8]);
        code.extend((base + 0x2520).to_le_bytes());
    } else {
        code.push(0xb8);
        code.extend(((base + 0x2520) as u32).to_le_bytes());
    }
    code.extend([0xf2, 0x0f, 0x11, 0]);
    super::winhttp::expect_dword(&mut code, wide, base + 0x2520, expected as u32);
    super::winhttp::expect_dword(&mut code, wide, base + 0x2524, (expected >> 32) as u32);
    code.extend([0xb8, 1, 0, 0, 0]);
    if wide {
        code.extend([0x48, 0x83, 0xc4, 0x28]);
    }
    code.push(0xc3);
    data[0x200..0x400].fill(0);
    assert!(code.len() < 0x200);
    data[0x200..0x200 + code.len()].copy_from_slice(&code);
    data
}

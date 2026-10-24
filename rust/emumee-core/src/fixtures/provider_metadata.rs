//! Kernel metadata reads and real protection failures; no crypto invocation.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call,
};
use super::{ApiFixture, api_probe, put32, put64};
use crate::{pe::Architecture, provider::MetadataProfile as Profile};
#[derive(Clone, Copy, Debug)]
pub enum MetadataFixture {
    Read,
    Execute,
    Write,
    ApiWrite,
    HeaderExecute,
    HeaderApiWrite,
    CiRead,
    CiExecute,
    NetioRead,
    NdisRead,
    NetioExecute,
    NdisWrite,
}
impl MetadataFixture {
    pub fn negative(self) -> bool {
        !matches!(
            self,
            Self::Read | Self::CiRead | Self::NetioRead | Self::NdisRead
        )
    }
    pub fn ci(self) -> bool {
        matches!(self, Self::CiRead | Self::CiExecute)
    }
    pub fn api_write(self) -> bool {
        matches!(self, Self::ApiWrite | Self::HeaderApiWrite)
    }
    fn default_profile(self) -> Option<Profile> {
        match self {
            Self::NetioRead | Self::NetioExecute => Some(Profile::Netio),
            Self::NdisRead | Self::NdisWrite => Some(Profile::Ndis),
            _ => None,
        }
    }
}
pub const TARGET_CNG: [&str; 9] = [
    "BCryptVerifySignature",
    "BCryptFinishHash",
    "BCryptDestroyHash",
    "BCryptImportKeyPair",
    "BCryptCloseAlgorithmProvider",
    "BCryptGetProperty",
    "BCryptHashData",
    "BCryptCreateHash",
    "BCryptOpenAlgorithmProvider",
];
fn expect(code: &mut Vec<u8>, value: u32) {
    code.push(0x3d);
    code.extend(value.to_le_bytes());
    code.extend([0x74, 1, 0xcc]);
}
fn pointer(code: &mut Vec<u8>, wide: bool, value: u64) {
    if wide {
        code.push(0x48);
    }
    code.push(0xb8);
    if wide {
        code.extend(value.to_le_bytes());
    } else {
        code.extend((value as u32).to_le_bytes());
    }
}
fn load(code: &mut Vec<u8>, wide: bool, slot: u64) {
    if wide {
        code.push(0x48);
    }
    code.push(0xa1);
    if wide {
        code.extend(slot.to_le_bytes());
    } else {
        code.extend((slot as u32).to_le_bytes());
    }
}
fn expected_pointer(code: &mut Vec<u8>, wide: bool, value: u64) {
    if wide {
        code.extend([0x48, 0xba]);
        code.extend(value.to_le_bytes());
        code.extend([0x48, 0x39, 0xd0, 0x74, 1, 0xcc]);
    } else {
        expect(code, value as u32);
    }
}
pub fn provider_metadata_probe(architecture: Architecture, kind: MetadataFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let width = architecture.width();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let cng = if wide {
        0xfffff80002400000u64
    } else {
        0x82400000
    };
    let ci = cng + 0x1000000;
    let source = api_probe(architecture, ApiFixture::PoolLifecycle);
    let mut data = vec![0; 0x3200];
    data[..0x200].copy_from_slice(&source[..0x200]);
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
        (dd + 12, 60),
        (0x1200, 0x2180),
        (0x120c, 0x2040),
        (0x1210, 0x2080),
        (0x1214, 0x2240),
        (0x1220, 0x2050),
        (0x1224, 0x22c0),
    ] {
        put32(&mut data, at, value);
    }
    let module = if let Some(profile) = kind.default_profile() {
        profile
            .module()
            .as_bytes()
            .to_vec()
            .into_iter()
            .chain([0])
            .collect::<Vec<_>>()
    } else if kind.ci() {
        b"ci.dll\0".to_vec()
    } else {
        b"cng.sys\0".to_vec()
    };
    data[0x1240..0x1240 + module.len()].copy_from_slice(&module);
    data[0x1250..0x125d].copy_from_slice(b"ntoskrnl.exe\0");
    let imports: Vec<_> = if let Some(profile) = kind.default_profile() {
        match profile {
            Profile::Netio => vec![
                "WskRegister",
                "WskRegisterA",
                "WskRegisterW",
                "callback_WskSocket",
            ],
            Profile::Ndis => vec!["NdisGetVersion", "NdisGetVersionA", "NdisGetVersionW"],
            _ => unreachable!(),
        }
    } else if kind.ci() {
        vec![Profile::Ci.names()[0]]
    } else {
        TARGET_CNG.to_vec()
    };
    for (index, name) in imports.iter().enumerate() {
        let rva = 0x2400 + index as u32 * 64;
        for raw in [0x1280, 0x1380] {
            if wide {
                put64(&mut data, raw + index * width, rva.into());
            } else {
                put32(&mut data, raw + index * width, rva);
            }
        }
        let raw = 0x1600 + index * 64;
        data[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    for (index, name) in ["MmHighestUserAddress", "RtlZeroMemory"].iter().enumerate() {
        let rva = 0x2800 + index as u32 * 64;
        for raw in [0x1440, 0x14c0] {
            if wide {
                put64(&mut data, raw + index * width, rva.into());
            } else {
                put32(&mut data, raw + index * width, rva);
            }
        }
        let raw = 0x1a00 + index * 64;
        data[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    let profile =
        kind.default_profile()
            .unwrap_or(if kind.ci() { Profile::Ci } else { Profile::Cng });
    let provider = if let Some(default) = kind.default_profile() {
        cng + (2 + Profile::DEFAULTS
            .iter()
            .position(|p| *p == default)
            .unwrap()) as u64
            * 0x1000000
    } else if kind.ci() {
        ci
    } else {
        cng
    };
    let mut code = Vec::new();
    if wide {
        code.extend([0x48, 0x83, 0xec, 0x68]);
    }
    for (index, name) in imports.iter().enumerate() {
        load(&mut code, wide, base + 0x2080 + index as u64 * width as u64);
        let export_index = profile.names().iter().position(|n| n == name).unwrap();
        expected_pointer(
            &mut code,
            wide,
            provider + 0x1000 + export_index as u64 * 16,
        );
        code.extend([0x0f, 0xb6, 0]);
        expect(&mut code, 0);
    }
    let headers: Vec<_> = if kind.default_profile().is_some() {
        Profile::DEFAULTS
            .into_iter()
            .enumerate()
            .map(|(i, p)| (p, cng + (i + 2) as u64 * 0x1000000))
            .collect()
    } else {
        vec![(Profile::Cng, cng), (Profile::Ci, ci)]
    };
    for (profile, provider) in headers {
        for (offset, expected) in [
            (0, 0x00005a4d),
            (0x80, 0x00004550),
            (0x84, if wide { 0x00028664 } else { 0x0002014c }),
            (0x88, 0),
            (0x98 + 16, 0),
            (0x98 + 64, 0),
            (
                0x2010,
                if profile.names().is_empty() {
                    0
                } else {
                    profile.ordinal_base()
                },
            ),
            (0x2014, profile.names().len() as u32),
            (0x2018, profile.names().len() as u32),
            (
                0x2040,
                if profile.names().is_empty() {
                    0
                } else {
                    0x1000
                },
            ),
        ] {
            pointer(&mut code, wide, provider + offset);
            code.extend([0x8b, 0]);
            expect(&mut code, expected);
        }
    }
    if kind.negative() {
        let header = matches!(
            kind,
            MetadataFixture::HeaderExecute | MetadataFixture::HeaderApiWrite
        );
        if header {
            pointer(&mut code, wide, provider);
        } else {
            load(&mut code, wide, base + 0x2080);
        }
        if kind.api_write() {
            if header {
                if wide {
                    code.extend([0x48, 0xa3]);
                    code.extend((base + 0x2d00).to_le_bytes());
                } else {
                    code.push(0xa3);
                    code.extend(((base + 0x2d00) as u32).to_le_bytes());
                }
            }
            let dest = if header { base + 0x2d00 } else { base + 0x2080 };
            // Reuse the ordinary emitter then replace its guaranteed final IAT
            // displacement with the second module's real RtlZeroMemory entry.
            call(&mut code, wide, base, 0, &[M(dest), V(1)]);
            let end = code.len();
            assert_eq!(&code[end - 6..end - 4], &[0xff, 0x15]);
            if wide {
                let next = 0x1000 + end as i64;
                code[end - 4..]
                    .copy_from_slice(&i32::try_from(0x22c0i64 + 8 - next).unwrap().to_le_bytes());
            } else {
                code[end - 4..].copy_from_slice(&((base + 0x22c0 + 4) as u32).to_le_bytes());
            }
        } else if matches!(kind, MetadataFixture::Write | MetadataFixture::NdisWrite) {
            code.extend([0xc6, 0, 0]);
        } else {
            code.extend([0xff, 0xd0]);
        }
        code.push(0xcc);
    }
    code.extend([0xb8, 1, 0, 0, 0]);
    if wide {
        code.extend([0x48, 0x83, 0xc4, 0x68]);
    }
    code.push(0xc3);
    assert!(code.len() < 0x1000);
    data[0x200..0x200 + code.len()].copy_from_slice(&code);
    data
}

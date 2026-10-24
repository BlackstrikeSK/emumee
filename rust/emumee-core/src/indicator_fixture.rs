//! Closed generated settled-root observations. No supplied code or launch token.
use crate::{fixtures, pe::Architecture};
use serde::{Deserialize, Serialize};

pub const IMAGE_BYTES: usize = 0x3000;
pub const ASCII_RVA: usize = 0x2020;
pub const WIDE_RVA: usize = 0x2101;
pub const ASCII: &str = "http://settled.example/ 192.0.2.77";
pub const WIDE: &str = "https://wide.example/ 2001:db8::77";
pub const SOURCE: &str = "memory:closed_settled_root";
/// Additional reservation for both engine/summary deliveries and audit receipts.
/// The existing payload reservation already covers the optional12KiB snapshot.
pub const REPORT_RESERVATION: u64 = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Case {
    Native,
    Kernel,
    NativeNone,
    KernelNone,
    NativeDisabled,
    KernelDisabled,
    NativeReadBudget,
    KernelReadBudget,
    NativeReadDenied,
    KernelReadDenied,
    NativeScanBudget,
    KernelScanBudget,
}
impl Case {
    pub const ALL: [Self; 12] = [
        Self::Native,
        Self::Kernel,
        Self::NativeNone,
        Self::KernelNone,
        Self::NativeDisabled,
        Self::KernelDisabled,
        Self::NativeReadBudget,
        Self::KernelReadBudget,
        Self::NativeReadDenied,
        Self::KernelReadDenied,
        Self::NativeScanBudget,
        Self::KernelScanBudget,
    ];
    pub fn kernel(self) -> bool {
        matches!(
            self,
            Self::Kernel
                | Self::KernelNone
                | Self::KernelDisabled
                | Self::KernelReadBudget
                | Self::KernelReadDenied
                | Self::KernelScanBudget
        )
    }
    pub fn enabled(self) -> bool {
        !matches!(self, Self::NativeDisabled | Self::KernelDisabled)
    }
    pub fn read_denied(self) -> bool {
        matches!(self, Self::NativeReadDenied | Self::KernelReadDenied)
    }
    pub fn retain(self) -> bool {
        matches!(self, Self::Native | Self::Kernel)
    }
    pub fn read_limit(self) -> u64 {
        if matches!(self, Self::NativeReadBudget | Self::KernelReadBudget) {
            1024
        } else {
            IMAGE_BYTES as u64
        }
    }
    pub fn scan_limit(self) -> usize {
        if matches!(self, Self::NativeScanBudget | Self::KernelScanBudget) {
            0x2000
        } else {
            IMAGE_BYTES
        }
    }
    pub fn patches(self) -> [(usize, Vec<u8>); 2] {
        let mut ascii = ASCII.as_bytes().to_vec();
        ascii.push(0);
        let wide: Vec<_> = WIDE
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        // Keep every byte, including the terminator, an actual guest store.
        [(ASCII_RVA, ascii), (WIDE_RVA, wide)]
    }
    pub fn input(self, architecture: Architecture) -> Vec<u8> {
        let mut image = fixtures::counted_driver(architecture, 17);
        image.resize(2048, 0);
        let table = 0x98
            + if architecture == Architecture::X64 {
                0xf0
            } else {
                0xe0
            };
        if !self.kernel() {
            image[0x98 + 68..0x98 + 70].copy_from_slice(&3u16.to_le_bytes());
            let flags = u16::from_le_bytes(image[0x96..0x98].try_into().unwrap()) & !0x2000;
            image[0x96..0x98].copy_from_slice(&flags.to_le_bytes());
        }
        image[table + 8..table + 12].copy_from_slice(&1024u32.to_le_bytes());
        image[table + 16..table + 20].copy_from_slice(&1024u32.to_le_bytes());
        image[table + 40 + 20..table + 40 + 24].copy_from_slice(&1536u32.to_le_bytes());
        if self.read_denied() {
            image[table + 40 + 36..table + 40 + 40].copy_from_slice(&0x80000040u32.to_le_bytes());
        }
        let base = if architecture == Architecture::X64 {
            0x140000000u64
        } else {
            0x400000
        };
        let mut code = Vec::new();
        for (rva, bytes) in self.patches() {
            for (offset, byte) in bytes.into_iter().enumerate() {
                let target = rva + offset;
                code.extend([0xc6, 0x05]);
                let operand = if architecture == Architecture::X64 {
                    (target as i64 - (0x1000 + code.len() + 5) as i64) as i32 as u32
                } else {
                    (base + target as u64) as u32
                };
                code.extend(operand.to_le_bytes());
                code.push(byte);
            }
        }
        code.push(0xb8);
        code.extend(17u32.to_le_bytes());
        code.push(0xc3);
        assert!(code.len() <= 1024);
        image[512..1536].fill(0);
        image[512..512 + code.len()].copy_from_slice(&code);
        image[1536..].fill(0);
        image
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn real_store_recipe_has_no_contiguous_indicator_in_input_or_initial_mapping() {
        for architecture in [Architecture::X86, Architecture::X64] {
            for case in Case::ALL {
                let input = case.input(architecture);
                let pe = crate::pe::PeImage::parse(&input, "closed.pe").unwrap();
                assert_eq!(pe.sample.kind == crate::pe::Kind::Driver, case.kernel());
                assert_eq!(pe.image_size as usize, IMAGE_BYTES);
                let initial = pe.materialize(&input, pe.image_base).unwrap();
                for (rva, payload) in case.patches() {
                    assert!(!input.windows(payload.len()).any(|window| window == payload));
                    assert!(
                        initial[rva..rva + payload.len()]
                            .iter()
                            .all(|byte| *byte == 0)
                    );
                }
            }
        }
    }
    #[test]
    fn independent_static_recipe_and_actual_legacy_scanner_corpus_bind_all24_cases() {
        let raw = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/data/native_indicators_reference.json"),
        )
        .unwrap();
        assert_eq!(
            crate::report_bundle::digest(&raw),
            "5e1eb09804fdebe82911250fe317938cac1bde23ef568f4b52fd0c702edd31b3"
        );
        let document: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(document["cases"].as_array().unwrap().len(), 24);
        for row in document["cases"].as_array().unwrap() {
            let case: Case = serde_json::from_value(row["case"].clone()).unwrap();
            let architecture = if row["architecture"] == "x64" {
                Architecture::X64
            } else {
                Architecture::X86
            };
            let input = case.input(architecture);
            assert_eq!(
                crate::report_bundle::digest(&input),
                row["input_sha256"],
                "{}",
                row["analysis_case"]
            );
            let pe = crate::pe::PeImage::parse(&input, "closed.pe").unwrap();
            let mut root = pe.materialize(&input, pe.image_base).unwrap();
            assert_eq!(
                crate::report_bundle::digest(&root),
                row["initial_image_sha256"]
            );
            for (rva, payload) in case.patches() {
                root[rva..rva + payload.len()].copy_from_slice(&payload);
            }
            assert_eq!(
                crate::report_bundle::digest(&root),
                row["golden_settled_sha256"]
            );
            let mut capture = crate::memory_strings::Capture::new(if case.enabled() {
                crate::memory_strings::Options::default()
            } else {
                crate::memory_strings::Options::disabled()
            });
            if row["read_bytes"].as_u64().unwrap() > 0 {
                capture
                    .scan_memory(&root[..case.scan_limit()], SOURCE, pe.image_base)
                    .unwrap();
            }
            assert_eq!(
                serde_json::to_value(capture.into_report()).unwrap(),
                row["expected"]
            );
        }
    }
}

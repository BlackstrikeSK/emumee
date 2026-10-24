//! Compiler-owned native execution/capture controls. No caller supplies code.
use serde::{Deserialize, Serialize};
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Case {
    Tiny,
    Image64,
    Image128,
    Raw64Image128,
    Gap,
    ReadBudget,
    ScanBudget,
    WorkBudget,
    RetentionBudget,
}
impl Case {
    pub fn reference(self) -> serde_json::Value {
        let document: serde_json::Value =
            serde_json::from_str(include_str!("../tests/data/driver_runtime_reference.json"))
                .expect("Pinned small generated reference JSON");
        let name = match self {
            Self::Tiny => "runtime-tiny",
            Self::Image64 => "runtime64",
            Self::Image128 => "runtime128",
            Self::Raw64Image128 => "runtime-raw64-image128",
            Self::Gap => "runtime-gap",
            Self::ReadBudget => "runtime-read-budget",
            Self::ScanBudget => "runtime-scan-budget",
            Self::WorkBudget => "runtime-work-budget",
            Self::RetentionBudget => "runtime-retention-budget",
        };
        document["cases"]
            .as_array()
            .expect("reference cases")
            .iter()
            .find(|r| r["case"] == name)
            .expect("closed case reference")
            .clone()
    }
    pub fn image_bytes(self) -> usize {
        match self {
            Self::Image64 => 64 * 1024 * 1024,
            Self::Image128 | Self::Raw64Image128 => 128 * 1024 * 1024,
            _ => 16384,
        }
    }
    pub fn input_bytes(self) -> usize {
        if self == Self::Raw64Image128 {
            64 * 1024 * 1024
        } else {
            1536
        }
    }
    pub fn markers(self) -> Vec<(u64, u8, u8)> {
        let near = if self == Self::Raw64Image128 { 0x52 } else { 0 };
        let mut m = vec![(0x2010, near, 0xa7)];
        if self != Self::Gap {
            m.push(((self.image_bytes() - 16) as u64, 0, 0xb3));
        }
        m
    }
    pub fn emit(self, mut sink: impl FnMut(&[u8]) -> std::io::Result<()>) -> std::io::Result<()> {
        let mut header = crate::fixtures::counted_driver(crate::pe::Architecture::X64, 17);
        header[0x98 + 56..0x98 + 60].copy_from_slice(&(self.image_bytes() as u32).to_le_bytes());
        let data = 0x188 + 40;
        let virtual_size = if self == Self::Gap {
            512
        } else {
            self.image_bytes() - 8192
        };
        header[data + 8..data + 12].copy_from_slice(&(virtual_size as u32).to_le_bytes());
        header[data + 16..data + 20]
            .copy_from_slice(&((self.input_bytes() - 1024) as u32).to_le_bytes());
        let mut code = vec![
            0xb9, 17, 0, 0, 0, 0x31, 0xc0, 0xff, 0xc0, 0xff, 0xc9, 0x75, 0xfa,
        ];
        for (rva, _, value) in self.markers() {
            let next = 0x1000 + code.len() + 7;
            code.extend([0xc6, 0x05]);
            code.extend(((rva as i64 - next as i64) as i32).to_le_bytes());
            code.push(value);
        }
        code.push(0xc3);
        header[512..1024].fill(0);
        header[512..512 + code.len()].copy_from_slice(&code);
        if self == Self::Raw64Image128 {
            header[1024..].fill(0x52);
        }
        sink(&header)?;
        let chunk = vec![0x52; 1024 * 1024];
        let mut left = self.input_bytes() - header.len();
        while left > 0 {
            let n = left.min(chunk.len());
            sink(&chunk[..n])?;
            left -= n;
        }
        Ok(())
    }
    pub fn bytes(self) -> Vec<u8> {
        let mut b = Vec::with_capacity(self.input_bytes());
        self.emit(|p| {
            b.extend_from_slice(p);
            Ok(())
        })
        .expect("bounded owned fixture sink");
        b
    }
}

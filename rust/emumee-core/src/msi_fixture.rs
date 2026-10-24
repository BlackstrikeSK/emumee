//! Closed generated static-MSI controls, never an arbitrary input/run protocol.
use crate::msi::SIGNATURE;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
const FREE: u32 = 0xffff_ffff;
const END: u32 = 0xffff_fffe;
const FAT: u32 = 0xffff_fffd;
const DIFAT: u32 = 0xffff_fffc;
pub const MAX_REQUEST_BYTES: usize = 4096;
pub const MAX_FIXTURE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Case {
    MiniV3,
    MiniV4,
    RegularV3,
    RegularV4,
    DifatV3,
    DataPe,
    MappedDataPe,
    CorruptFat,
    Truncated,
}
impl Case {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "mini-v3" => Self::MiniV3,
            "mini-v4" => Self::MiniV4,
            "regular-v3" => Self::RegularV3,
            "regular-v4" => Self::RegularV4,
            "difat-v3" => Self::DifatV3,
            "data-pe" => Self::DataPe,
            "mapped-data-pe" => Self::MappedDataPe,
            "corrupt-fat" => Self::CorruptFat,
            "truncated" => Self::Truncated,
            _ => return None,
        })
    }
    pub fn expects_rejection(self) -> bool {
        matches!(self, Self::CorruptFat | Self::Truncated)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    StaticMsiFixture,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: u32,
    pub operation: Operation,
    pub case: Case,
    pub input_size: usize,
    pub input_sha256: String,
}
impl Request {
    pub fn generated(case: Case) -> Self {
        let raw = input(case);
        Self {
            schema: 1,
            operation: Operation::StaticMsiFixture,
            case,
            input_size: raw.len(),
            input_sha256: format!("{:x}", Sha256::digest(&raw)),
        }
    }
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() > MAX_REQUEST_BYTES {
            return Err("MSI request exceeds4KiB");
        }
        let request: Self =
            serde_json::from_slice(raw).map_err(|_| "MSI request schema/enum decode rejected")?;
        if request.schema != 1
            || request.input_size > MAX_FIXTURE_BYTES
            || request.input_sha256.len() != 64
            || !request
                .input_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("MSI request bounds/schema rejected");
        }
        let expected = Self::generated(request.case);
        if request.input_size != expected.input_size
            || request.input_sha256 != expected.input_sha256
        {
            return Err("MSI request is not the closed generated fixture");
        }
        Ok(request)
    }
    pub fn verifies_input(&self, raw: &[u8]) -> bool {
        raw.len() == self.input_size
            && format!("{:x}", Sha256::digest(raw)) == self.input_sha256
            && raw == input(self.case)
    }
}
pub fn input(case: Case) -> Vec<u8> {
    match case {
        Case::MiniV3 => small(3),
        Case::MiniV4 => small(4),
        Case::RegularV3 => regular(3),
        Case::RegularV4 => regular(4),
        Case::DifatV3 => extended_difat(),
        Case::CorruptFat => {
            let mut raw = small(3);
            put32(&mut raw, 512 + 12, 3);
            raw
        }
        Case::Truncated => {
            let mut raw = small(3);
            raw.pop();
            raw
        }
        Case::DataPe | Case::MappedDataPe => {
            let mut pe = vec![0; 1024];
            pe[..2].copy_from_slice(b"MZ");
            put32(&mut pe, 0x3c, 0x80);
            pe[0x80..0x84].copy_from_slice(b"PE\0\0");
            for (at, value) in [(0x84, 0x8664), (0x86, 1), (0x94, 0xf0), (0x98, 0x20b)] {
                put16(&mut pe, at, value);
            }
            for (at, value) in [
                (0x98 + 56, 0x2000),
                (0x98 + 60, 0x200),
                (0x188 + 12, 0x1000),
                (0x188 + 16, 0x200),
                (0x188 + 20, 0x200),
            ] {
                put32(&mut pe, at, value);
            }
            pe[512..].fill(0x52);
            let mut payload = b"prefix".to_vec();
            if case == Case::MappedDataPe {
                let mut image = vec![0; 8192];
                image[..512].copy_from_slice(&pe[..512]);
                image[4096..4608].copy_from_slice(&pe[512..]);
                payload.extend(image);
            } else {
                payload.extend(pe);
                payload.resize(4096, 0);
            }
            regular_payload(&payload)
        }
    }
}
fn regular_payload(payload: &[u8]) -> Vec<u8> {
    let sectors = payload.len().div_ceil(512);
    let mut raw = header(3, 2 + sectors);
    directory(&mut raw, 1024, "Root Entry", 5, FREE, 1, END, 0);
    directory(
        &mut raw,
        1152,
        "Payload",
        2,
        FREE,
        FREE,
        2,
        payload.len() as u64,
    );
    for i in 0..sectors {
        put32(
            &mut raw,
            512 + (i + 2) * 4,
            if i + 1 == sectors {
                END
            } else {
                (i + 3) as u32
            },
        );
    }
    raw[1536..1536 + payload.len()].copy_from_slice(payload);
    raw
}

fn put16(raw: &mut [u8], at: usize, value: u16) {
    raw[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(raw: &mut [u8], at: usize, value: u32) {
    raw[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(raw: &mut [u8], at: usize, value: u64) {
    raw[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn header(version: u16, sectors: usize) -> Vec<u8> {
    let width = if version == 3 { 512 } else { 4096 };
    let mut raw = vec![0; width * (sectors + 1)];
    raw[..8].copy_from_slice(&SIGNATURE);
    put16(&mut raw, 24, 0x3e);
    put16(&mut raw, 26, version);
    put16(&mut raw, 28, 0xfffe);
    put16(&mut raw, 30, if version == 3 { 9 } else { 12 });
    put16(&mut raw, 32, 6);
    put32(&mut raw, 40, if version == 3 { 0 } else { 1 });
    put32(&mut raw, 44, 1);
    put32(&mut raw, 48, 1);
    put32(&mut raw, 56, 4096);
    put32(&mut raw, 60, END);
    put32(&mut raw, 68, END);
    for offset in (76..512).step_by(4) {
        put32(&mut raw, offset, FREE);
    }
    put32(&mut raw, 76, 0);
    for offset in (width..width * 2).step_by(4) {
        put32(&mut raw, offset, FREE);
    }
    put32(&mut raw, width, FAT);
    put32(&mut raw, width + 4, END);
    raw
}

#[allow(clippy::too_many_arguments)]
fn directory(
    raw: &mut [u8],
    at: usize,
    name: &str,
    kind: u8,
    right: u32,
    child: u32,
    start: u32,
    size: u64,
) {
    let units: Vec<u16> = name.encode_utf16().collect();
    assert!(units.len() <= 31);
    for (i, unit) in units.iter().enumerate() {
        put16(raw, at + i * 2, *unit);
    }
    put16(raw, at + 64, ((units.len() + 1) * 2) as u16);
    raw[at + 66] = kind;
    raw[at + 67] = 1;
    put32(raw, at + 68, FREE);
    put32(raw, at + 72, right);
    put32(raw, at + 76, child);
    put32(raw, at + 116, start);
    put64(raw, at + 120, size);
}

fn small(version: u16) -> Vec<u8> {
    let width = if version == 3 { 512 } else { 4096 };
    let mut raw = header(version, 4);
    put32(&mut raw, 60, 2);
    put32(&mut raw, 64, 1);
    put32(&mut raw, width + 8, END);
    put32(&mut raw, width + 12, END);
    let dir = width * 2;
    directory(&mut raw, dir, "Root Entry", 5, FREE, 1, 3, 192);
    directory(&mut raw, dir + 128, "Binary", 1, FREE, 2, 0, 0);
    directory(&mut raw, dir + 256, "Cabinet", 2, 3, FREE, 0, 6);
    directory(&mut raw, dir + 384, "Payload", 2, FREE, FREE, 1, 70);
    for offset in (width * 3..width * 4).step_by(4) {
        put32(&mut raw, offset, FREE);
    }
    put32(&mut raw, width * 3, END);
    put32(&mut raw, width * 3 + 4, 2);
    put32(&mut raw, width * 3 + 8, END);
    raw[width * 4..width * 4 + 6].copy_from_slice(b"MSCF\0\xff");
    for i in 0..70 {
        raw[width * 4 + 64 + i] = i as u8;
    }
    raw
}

fn regular(version: u16) -> Vec<u8> {
    let width = if version == 3 { 512 } else { 4096 };
    let payload_sectors = 4096 / width;
    let mut raw = header(version, 2 + payload_sectors);
    let dir = width * 2;
    directory(&mut raw, dir, "Root Entry", 5, FREE, 1, END, 0);
    directory(&mut raw, dir + 128, "Cabinet", 2, FREE, FREE, 2, 4096);
    for i in 0..payload_sectors {
        put32(
            &mut raw,
            width + (i + 2) * 4,
            if i + 1 == payload_sectors {
                END
            } else {
                (i + 3) as u32
            },
        );
    }
    raw[width * 3..width * 3 + 4].copy_from_slice(b"MSCF");
    raw
}

fn extended_difat() -> Vec<u8> {
    let mut raw = header(3, 112);
    put32(&mut raw, 44, 110);
    put32(&mut raw, 48, 110);
    put32(&mut raw, 68, 111);
    put32(&mut raw, 72, 1);
    for i in 0..109 {
        put32(&mut raw, 76 + i * 4, i as u32);
    }
    for id in 0..110 {
        raw[(id + 1) * 512..(id + 2) * 512].fill(0xff);
    }
    for id in 0..110 {
        put32(&mut raw, 512 + id * 4, FAT);
    }
    put32(&mut raw, 512 + 110 * 4, END);
    put32(&mut raw, 512 + 111 * 4, DIFAT);
    directory(&mut raw, 111 * 512, "Root Entry", 5, FREE, FREE, END, 0);
    raw[112 * 512..113 * 512].fill(0xff);
    put32(&mut raw, 112 * 512, 109);
    put32(&mut raw, 113 * 512 - 4, END);
    raw
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_is_closed_bounded_and_exactly_binds_owned_input() {
        for case in [
            Case::MiniV3,
            Case::MiniV4,
            Case::RegularV3,
            Case::RegularV4,
            Case::DifatV3,
            Case::DataPe,
            Case::MappedDataPe,
            Case::CorruptFat,
            Case::Truncated,
        ] {
            let request = Request::generated(case);
            let raw = serde_json::to_vec(&request).unwrap();
            assert!(raw.len() <= MAX_REQUEST_BYTES);
            let parsed = Request::parse(&raw).unwrap();
            let mut bytes = input(case);
            assert!(parsed.verifies_input(&bytes));
            bytes[0] ^= 1;
            assert!(!parsed.verifies_input(&bytes));
            assert_eq!(
                crate::msi::inspect(&input(case)).is_err(),
                case.expects_rejection()
            );
        }
        let request = serde_json::to_value(Request::generated(Case::MiniV3)).unwrap();
        for (key, value) in [
            ("schema", serde_json::json!(2)),
            ("case", serde_json::json!("arbitrary-file")),
            ("operation", serde_json::json!("execute")),
            ("input_sha256", serde_json::json!("0".repeat(64))),
            ("input_size", serde_json::json!(true)),
            ("host_path", serde_json::json!("C:\\forbidden")),
        ] {
            let mut bad = request.clone();
            bad[key] = value;
            assert!(Request::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
        assert!(Request::parse(&vec![b' '; MAX_REQUEST_BYTES + 1]).is_err());
    }
}

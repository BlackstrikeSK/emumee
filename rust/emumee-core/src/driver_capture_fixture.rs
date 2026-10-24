//! Fixed harmless large capture recipes. These are not arbitrary driver inputs.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
pub const MIB: usize = 1024 * 1024;
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Case {
    SmallRaw,
    Raw32Plus,
    Raw64,
    Raw128,
    Mapped64,
    Mapped128,
    Mapped256Total,
    Dedupe128,
    Total256Overflow,
    ScanOverflow,
    SingleOverflow,
    DriverEntry64,
    RuntimeTiny,
    Runtime64,
    Runtime128,
    RuntimeRaw64Image128,
    RuntimeGap,
    RuntimeReadBudget,
    RuntimeScanBudget,
    RuntimeWorkBudget,
    RuntimeRetentionBudget,
}
impl Case {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "small-raw" => Self::SmallRaw,
            "raw32-plus" => Self::Raw32Plus,
            "raw64" => Self::Raw64,
            "raw128" => Self::Raw128,
            "mapped64" => Self::Mapped64,
            "mapped128" => Self::Mapped128,
            "mapped256-total" => Self::Mapped256Total,
            "dedupe128" => Self::Dedupe128,
            "total256-overflow" => Self::Total256Overflow,
            "scan-overflow" => Self::ScanOverflow,
            "single-overflow" => Self::SingleOverflow,
            "driver-entry64" => Self::DriverEntry64,
            "runtime-tiny" => Self::RuntimeTiny,
            "runtime64" => Self::Runtime64,
            "runtime128" => Self::Runtime128,
            "runtime-raw64-image128" => Self::RuntimeRaw64Image128,
            "runtime-gap" => Self::RuntimeGap,
            "runtime-read-budget" => Self::RuntimeReadBudget,
            "runtime-scan-budget" => Self::RuntimeScanBudget,
            "runtime-work-budget" => Self::RuntimeWorkBudget,
            "runtime-retention-budget" => Self::RuntimeRetentionBudget,

            _ => return None,
        })
    }
    pub fn runtime_case(self) -> Option<crate::driver_runtime_fixture::Case> {
        Some(match self {
            Self::RuntimeTiny => crate::driver_runtime_fixture::Case::Tiny,
            Self::Runtime64 => crate::driver_runtime_fixture::Case::Image64,
            Self::Runtime128 => crate::driver_runtime_fixture::Case::Image128,
            Self::RuntimeRaw64Image128 => crate::driver_runtime_fixture::Case::Raw64Image128,
            Self::RuntimeGap => crate::driver_runtime_fixture::Case::Gap,
            Self::RuntimeReadBudget => crate::driver_runtime_fixture::Case::ReadBudget,
            Self::RuntimeScanBudget => crate::driver_runtime_fixture::Case::ScanBudget,
            Self::RuntimeWorkBudget => crate::driver_runtime_fixture::Case::WorkBudget,
            Self::RuntimeRetentionBudget => crate::driver_runtime_fixture::Case::RetentionBudget,
            _ => return None,
        })
    }
    pub fn input_len(self) -> usize {
        if let Some(case) = self.runtime_case() {
            return case.input_bytes();
        }
        match self {
            Self::SmallRaw => 8192,
            Self::Raw32Plus => 32 * MIB + 4096,
            Self::Raw64 | Self::Mapped64 => 64 * MIB,
            Self::Raw128
            | Self::Mapped128
            | Self::Mapped256Total
            | Self::Dedupe128
            | Self::Total256Overflow => 128 * MIB,
            Self::ScanOverflow | Self::SingleOverflow => 0,
            Self::DriverEntry64 => 1536,
            _ => unreachable!("runtime case returned above"),
        }
    }
    pub fn mapped(self) -> bool {
        matches!(
            self,
            Self::Mapped64 | Self::Mapped128 | Self::Mapped256Total
        )
    }
    pub fn emit(self, mut sink: impl FnMut(&[u8]) -> std::io::Result<()>) -> std::io::Result<()> {
        if let Some(case) = self.runtime_case() {
            return case.emit(sink);
        }
        if matches!(self, Self::ScanOverflow | Self::SingleOverflow) {
            return Ok(());
        }
        let mut header = if self == Self::DriverEntry64 {
            let mut raw = crate::fixtures::counted_driver(crate::pe::Architecture::X64, 17);
            put32(&mut raw, 0x98 + 56, 64 * MIB as u32);
            raw
        } else {
            vec![0u8; 512]
        };
        let length = self.input_len();
        let mut fills = Vec::new();
        if self != Self::DriverEntry64 {
            header[..2].copy_from_slice(b"MZ");
            put32(&mut header, 60, 128);
            header[128..132].copy_from_slice(b"PE\0\0");
            put16(&mut header, 132, 0x8664);
            put16(
                &mut header,
                134,
                if self == Self::Mapped256Total { 2 } else { 1 },
            );
            put16(&mut header, 148, 240);
            put16(&mut header, 150, 0x2022);
            put16(&mut header, 152, 0x20b);
            put32(&mut header, 168, 4096);
            put64(&mut header, 176, 0x140000000);
            put32(&mut header, 184, 4096);
            put32(&mut header, 188, 512);
            put32(&mut header, 208, length as u32);
            put32(&mut header, 212, 512);
            put16(&mut header, 220, 1);
            put32(&mut header, 260, 16);
            let sections = if self == Self::Mapped256Total {
                vec![
                    (4096, 8192, length - 12288, 0x52u8),
                    (length - 4096, 4096, 4096, 0x31u8),
                ]
            } else if self.mapped() {
                vec![(512, length / 2, length / 2, 0x52u8)]
            } else {
                vec![(4096, 4096, length - 4096, 0x52u8)]
            };
            for (index, (raw, rva, size, byte)) in sections.into_iter().enumerate() {
                let at = 392 + 40 * index;
                header[at..at + 8].copy_from_slice(if index == 0 {
                    b".owned\0\0"
                } else {
                    b".tail\0\0\0"
                });
                put32(&mut header, at + 8, size as u32);
                put32(&mut header, at + 12, rva as u32);
                put32(&mut header, at + 16, size as u32);
                put32(&mut header, at + 20, raw as u32);
                put32(&mut header, at + 36, 0xc0000040);
                fills.push((if self.mapped() { rva } else { raw }, size, byte));
            }
        }
        let mut buffer = vec![0u8; MIB];
        let mut offset = 0usize;
        while offset < length {
            let count = (length - offset).min(buffer.len());
            buffer[..count].fill(0);
            for (start, size, byte) in &fills {
                let begin = offset.max(*start);
                let end = (offset + count).min(start + size);
                if begin < end {
                    buffer[begin - offset..end - offset].fill(*byte);
                }
            }
            let end = (offset + count).min(header.len());
            if offset < end {
                buffer[..end - offset].copy_from_slice(&header[offset..end]);
            }
            sink(&buffer[..count])?;
            offset += count;
        }
        Ok(())
    }
    pub fn digest(self) -> String {
        let mut hash = Sha256::new();
        self.emit(|raw| {
            hash.update(raw);
            Ok(())
        })
        .expect("owned in-memory hash sink");
        format!("{:x}", hash.finalize())
    }
    pub fn small_bytes(self) -> Option<Vec<u8>> {
        if self.input_len() > 8192 {
            return None;
        }
        let mut bytes = Vec::new();
        self.emit(|raw| {
            bytes.extend_from_slice(raw);
            Ok(())
        })
        .ok()?;
        Some(bytes)
    }
}
fn put16(out: &mut [u8], at: usize, value: u16) {
    out[at..at + 2].copy_from_slice(&value.to_le_bytes())
}
fn put32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes())
}
fn put64(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes())
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Fault {
    None,
    CrashBeforeCheckpoint,
    CrashAfterCheckpoint,
    TimeoutAfterCheckpoint,
    TamperPayload,
    TamperProvenance,
    TamperEngine,
    ProfileDowngrade,
    TamperRequest,
    TamperInput,
    UnknownRequestField,
    ForeignOwnedFixture,
}
impl Fault {
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "none" => Self::None,
            "crash-before-checkpoint" => Self::CrashBeforeCheckpoint,
            "crash-after-checkpoint" => Self::CrashAfterCheckpoint,
            "timeout-after-checkpoint" => Self::TimeoutAfterCheckpoint,
            "tamper-payload" => Self::TamperPayload,
            "tamper-provenance" => Self::TamperProvenance,
            "tamper-engine" => Self::TamperEngine,
            "profile-downgrade" => Self::ProfileDowngrade,
            "tamper-request" => Self::TamperRequest,
            "tamper-input" => Self::TamperInput,
            "unknown-request-field" => Self::UnknownRequestField,
            "foreign-owned-fixture" => Self::ForeignOwnedFixture,
            _ => return None,
        })
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: u32,
    pub operation: String,
    pub profile: String,
    pub case: Case,
    pub fault: Fault,
    pub run_id: String,
    pub input_size: usize,
    pub input_sha256: String,
}
impl Request {
    pub fn generated(case: Case, fault: Fault, run_id: String) -> Self {
        Self {
            schema: 1,
            operation: "closed_driver_capture_fixture".into(),
            profile: crate::driver_capture_reports::PROFILE.into(),
            case,
            fault,
            run_id,
            input_size: case.input_len(),
            input_sha256: case.digest(),
        }
    }
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() > 4096 {
            return Err("Driver fixture request4KiB cap");
        }
        let value: Self = serde_json::from_slice(raw).map_err(|_| "Driver fixture schema/enum")?;
        if value.schema != 1
            || value.operation != "closed_driver_capture_fixture"
            || value.profile != crate::driver_capture_reports::PROFILE
            || !crate::reports::valid_run_id(&value.run_id)
            || value.input_size != value.case.input_len()
            || value.input_sha256 != value.case.digest()
        {
            return Err("Driver fixture fixed recipe/profile binding");
        }
        if !allows_fault(value.case, value.fault) {
            return Err("Driver fixture faults use small owned input only");
        }
        Ok(value)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recipes_are_compiler_owned_and_large_allocations_not_source_tests() {
        assert_eq!(Case::Mapped256Total.input_len(), 134217728);
        assert_eq!(Case::DriverEntry64.input_len(), 1536);
        assert!(Case::Raw128.small_bytes().is_none());
        let bytes = Case::SmallRaw.small_bytes().unwrap();
        assert_eq!(bytes.len(), 8192);
        assert!(crate::pe::PeImage::parse(&bytes, "owned.sys").is_ok());
        let request = Request::generated(
            Case::SmallRaw,
            Fault::None,
            "20261018T120000Z-12345678".into(),
        );
        let mut raw = serde_json::to_value(request).unwrap();
        raw["profile"] = serde_json::json!("legacy32_v1");
        assert!(Request::parse(&serde_json::to_vec(&raw).unwrap()).is_err());
    }
}

#[cfg(test)]
mod refusal_tests {
    use super::*;
    #[test]
    fn exact_request_type_and_compiler_owned_hash_cannot_admit_foreign_inputs() {
        let valid = Request::generated(
            Case::SmallRaw,
            Fault::None,
            "20261018T120000Z-12345678".into(),
        );
        let value = serde_json::to_value(valid).unwrap();
        for (field, mutated) in [
            ("input_sha256", serde_json::json!("0".repeat(64))),
            ("input_size", serde_json::json!(8193)),
            ("case", serde_json::json!("external")),
            ("fault", serde_json::json!("external")),
            ("unexpected", serde_json::json!(true)),
        ] {
            let mut changed = value.clone();
            changed[field] = mutated;
            assert!(
                Request::parse(&serde_json::to_vec(&changed).unwrap()).is_err(),
                "{field}"
            );
        }
        assert!(Request::parse(&vec![b' '; 4097]).is_err());
        for name in [
            "tamper-request",
            "tamper-input",
            "unknown-request-field",
            "foreign-owned-fixture",
        ] {
            let fault = Fault::parse(name).unwrap();
            let fixed =
                Request::generated(Case::SmallRaw, fault, "20261018T120000Z-12345678".into());
            assert!(Request::parse(&serde_json::to_vec(&fixed).unwrap()).is_ok());
        }
    }
}

pub fn allows_fault(case: Case, fault: Fault) -> bool {
    fault == Fault::None
        || case == Case::SmallRaw
        || case == Case::RuntimeTiny
            && matches!(
                fault,
                Fault::CrashBeforeCheckpoint
                    | Fault::CrashAfterCheckpoint
                    | Fault::TimeoutAfterCheckpoint
                    | Fault::TamperPayload
                    | Fault::TamperProvenance
                    | Fault::TamperEngine
                    | Fault::ProfileDowngrade
            )
}

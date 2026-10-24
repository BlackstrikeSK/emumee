//! Closed generated analysis protocol. No caller-supplied program/path/budget.
use crate::{
    fixtures::{self, ApiFixture, CilFixture},
    msi_fixture,
    pe::Architecture,
    protocol::FixtureKind,
    report_bundle, reports,
};
use serde::{Deserialize, Serialize};
pub const MAX_REQUEST: usize = 4096;
pub const MAX_INPUT: usize = 64 * 1024;
/// Watchdog includes staged input, engine/network reports, both summary copies,
/// manifest+checkpoint, every unique payload and containment/lifecycle receipts.
pub const MAX_OUTPUT: u64 = (MAX_INPUT
    + MAX_REQUEST
    + reports::MAX_ENGINE_BYTES
    + reports::MAX_NETWORK_REPORT_BYTES
    + 2 * reports::MAX_SUMMARY_BYTES
    + 2 * report_bundle::MAX_MANIFEST_BYTES
    + report_bundle::MAX_PAYLOAD_BYTES
    + 1024 * 1024) as u64;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Case {
    NativeReturn,
    ManagedIndicators,
    ManagedIndicatorsDisabled,
    ManagedIndicatorsBudget,
    ManagedIndicatorsSurrogate,
    ManagedIndicatorsFrameworkFailure,
    ManagedIndicatorsNull,

    NativeIndicators,
    KernelIndicators,
    NativeIndicatorsNone,
    KernelIndicatorsNone,
    NativeIndicatorsDisabled,
    KernelIndicatorsDisabled,
    NativeIndicatorsReadBudget,
    KernelIndicatorsReadBudget,
    NativeIndicatorsReadDenied,
    KernelIndicatorsReadDenied,
    NativeIndicatorsScanBudget,
    KernelIndicatorsScanBudget,

    NativeCapture,
    ManagedReturn,
    ManagedCapture,
    ManagedPartial,
    ManagedBudget,
    ManagedError,
    StaticMsi,
    MalformedMsi,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Fault {
    None,
    TimeoutAfterCheckpoint,
    CrashAfterCheckpoint,
    TamperEngine,
    TamperManifest,
    TamperPayload,
    TamperProvenance,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Arch {
    X86,
    X64,
}
impl Arch {
    pub fn architecture(self) -> Architecture {
        match self {
            Self::X86 => Architecture::X86,
            Self::X64 => Architecture::X64,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    GeneratedAnalysis,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: u32,
    pub operation: Operation,
    pub case: Case,
    pub fault: Fault,
    pub architecture: Arch,
    pub run_id: String,
    pub started_at: String,
    pub input_size: usize,
    pub input_sha256: String,
}
impl Case {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "native-return" => Self::NativeReturn,
            "managed-indicators" => Self::ManagedIndicators,
            "managed-indicators-disabled" => Self::ManagedIndicatorsDisabled,
            "managed-indicators-budget" => Self::ManagedIndicatorsBudget,
            "managed-indicators-surrogate" => Self::ManagedIndicatorsSurrogate,
            "managed-indicators-framework-failure" => Self::ManagedIndicatorsFrameworkFailure,
            "managed-indicators-null" => Self::ManagedIndicatorsNull,

            "native-indicators" => Self::NativeIndicators,
            "kernel-indicators" => Self::KernelIndicators,
            "native-indicators-none" => Self::NativeIndicatorsNone,
            "kernel-indicators-none" => Self::KernelIndicatorsNone,
            "native-indicators-disabled" => Self::NativeIndicatorsDisabled,
            "kernel-indicators-disabled" => Self::KernelIndicatorsDisabled,
            "native-indicators-read-budget" => Self::NativeIndicatorsReadBudget,
            "kernel-indicators-read-budget" => Self::KernelIndicatorsReadBudget,
            "native-indicators-read-denied" => Self::NativeIndicatorsReadDenied,
            "kernel-indicators-read-denied" => Self::KernelIndicatorsReadDenied,
            "native-indicators-scan-budget" => Self::NativeIndicatorsScanBudget,
            "kernel-indicators-scan-budget" => Self::KernelIndicatorsScanBudget,

            "native-capture" => Self::NativeCapture,
            "managed-return" => Self::ManagedReturn,
            "managed-capture" => Self::ManagedCapture,
            "managed-partial" => Self::ManagedPartial,
            "managed-budget" => Self::ManagedBudget,
            "managed-error" => Self::ManagedError,
            "static-msi" => Self::StaticMsi,
            "malformed-msi" => Self::MalformedMsi,
            _ => return None,
        })
    }
    pub fn managed_indicator(self) -> Option<crate::managed_indicator_fixture::Case> {
        Some(match self {
            Self::ManagedIndicators => crate::managed_indicator_fixture::Case::Events,
            Self::ManagedIndicatorsDisabled => crate::managed_indicator_fixture::Case::Disabled,
            Self::ManagedIndicatorsBudget => crate::managed_indicator_fixture::Case::Budget,
            Self::ManagedIndicatorsSurrogate => crate::managed_indicator_fixture::Case::Surrogate,
            Self::ManagedIndicatorsFrameworkFailure => {
                crate::managed_indicator_fixture::Case::FrameworkFailure
            }
            Self::ManagedIndicatorsNull => crate::managed_indicator_fixture::Case::Null,
            _ => return None,
        })
    }
    pub fn observation_profile(self) -> Option<&'static str> {
        if self.indicator().is_some() {
            Some(crate::memory_observation::VERSION)
        } else {
            self.managed_indicator()
                .map(|_| crate::managed_observation::VERSION)
        }
    }
    pub fn observation_case(self) -> Option<serde_json::Value> {
        if let Some(case) = self.indicator() {
            serde_json::to_value(case).ok()
        } else {
            self.managed_indicator()
                .and_then(|case| serde_json::to_value(case).ok())
        }
    }
    pub fn indicator(self) -> Option<crate::indicator_fixture::Case> {
        Some(match self {
            Self::NativeIndicators => crate::indicator_fixture::Case::Native,
            Self::KernelIndicators => crate::indicator_fixture::Case::Kernel,
            Self::NativeIndicatorsNone => crate::indicator_fixture::Case::NativeNone,
            Self::KernelIndicatorsNone => crate::indicator_fixture::Case::KernelNone,
            Self::NativeIndicatorsDisabled => crate::indicator_fixture::Case::NativeDisabled,
            Self::KernelIndicatorsDisabled => crate::indicator_fixture::Case::KernelDisabled,
            Self::NativeIndicatorsReadBudget => crate::indicator_fixture::Case::NativeReadBudget,
            Self::KernelIndicatorsReadBudget => crate::indicator_fixture::Case::KernelReadBudget,
            Self::NativeIndicatorsReadDenied => crate::indicator_fixture::Case::NativeReadDenied,
            Self::KernelIndicatorsReadDenied => crate::indicator_fixture::Case::KernelReadDenied,
            Self::NativeIndicatorsScanBudget => crate::indicator_fixture::Case::NativeScanBudget,
            Self::KernelIndicatorsScanBudget => crate::indicator_fixture::Case::KernelScanBudget,
            _ => return None,
        })
    }
    pub fn output_limit(self) -> u64 {
        MAX_OUTPUT
            + if self.observation_profile().is_some() {
                crate::indicator_fixture::REPORT_RESERVATION
            } else {
                0
            }
    }
    pub fn fixture(self) -> Option<FixtureKind> {
        Some(match self {
            Self::NativeReturn => FixtureKind::UserApi,
            Self::NativeCapture => FixtureKind::FileRoundTripA,
            Self::ManagedReturn => FixtureKind::ManagedReturn,
            Self::ManagedCapture | Self::ManagedBudget => FixtureKind::ManagedFileRoundTrip,
            Self::ManagedPartial => FixtureKind::ManagedFilePartial,
            Self::ManagedError => FixtureKind::ManagedDivideZero,
            _ => return None,
        })
    }
    pub fn budget(self) -> u64 {
        if let Some(case) = self.managed_indicator() {
            return case.budget();
        }
        if self == Self::ManagedBudget {
            22
        } else {
            1000
        }
    }
    pub fn input(self, arch: Arch) -> Vec<u8> {
        let arch = arch.architecture();
        if let Some(case) = self.indicator() {
            return case.input(arch);
        }
        if let Some(case) = self.managed_indicator() {
            return case.input(arch);
        }
        match self {
            Self::NativeReturn => fixtures::api_probe(arch, ApiFixture::UserState),
            Self::NativeCapture => fixtures::api_probe(arch, ApiFixture::FileRoundTripA),
            Self::ManagedReturn => fixtures::cil_probe(arch, CilFixture::Return, 17),
            Self::ManagedCapture | Self::ManagedBudget => {
                fixtures::cil_probe(arch, CilFixture::FileRoundTrip, 17)
            }
            Self::ManagedPartial => fixtures::cil_probe(arch, CilFixture::FilePartial, 17),
            Self::ManagedError => fixtures::cil_probe(arch, CilFixture::DivideZero, 17),
            Self::StaticMsi => msi_fixture::input(msi_fixture::Case::MiniV3),
            Self::MalformedMsi => msi_fixture::input(msi_fixture::Case::CorruptFat),
            Self::ManagedIndicators
            | Self::ManagedIndicatorsDisabled
            | Self::ManagedIndicatorsBudget
            | Self::ManagedIndicatorsSurrogate
            | Self::ManagedIndicatorsFrameworkFailure
            | Self::ManagedIndicatorsNull => {
                unreachable!("Managed indicator cases returned before ordinary recipe match")
            }
            Self::NativeIndicators
            | Self::KernelIndicators
            | Self::NativeIndicatorsNone
            | Self::KernelIndicatorsNone
            | Self::NativeIndicatorsDisabled
            | Self::KernelIndicatorsDisabled
            | Self::NativeIndicatorsReadBudget
            | Self::KernelIndicatorsReadBudget
            | Self::NativeIndicatorsReadDenied
            | Self::KernelIndicatorsReadDenied
            | Self::NativeIndicatorsScanBudget
            | Self::KernelIndicatorsScanBudget => {
                unreachable!("Indicator cases returned before ordinary recipe match")
            }
        }
    }
}
impl Fault {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "none" => Self::None,
            "timeout-after-checkpoint" => Self::TimeoutAfterCheckpoint,
            "crash-after-checkpoint" => Self::CrashAfterCheckpoint,
            "tamper-engine" => Self::TamperEngine,
            "tamper-manifest" => Self::TamperManifest,
            "tamper-payload" => Self::TamperPayload,
            "tamper-provenance" => Self::TamperProvenance,
            _ => return None,
        })
    }
}
impl Request {
    pub fn generated(
        case: Case,
        fault: Fault,
        architecture: Arch,
        run_id: String,
        started_at: String,
    ) -> Self {
        let input = case.input(architecture);
        Self {
            schema: 1,
            operation: Operation::GeneratedAnalysis,
            case,
            fault,
            architecture,
            run_id,
            started_at,
            input_size: input.len(),
            input_sha256: report_bundle::digest(&input),
        }
    }
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() > MAX_REQUEST {
            return Err("Analysis request exceeds4KiB");
        }
        let value: Self = serde_json::from_slice(raw)
            .map_err(|_| "Analysis request schema/enum decode rejected")?;
        if value.schema != 1
            || !reports::valid_run_id(&value.run_id)
            || value.started_at.is_empty()
            || value.started_at.len() > 64
            || !value.started_at.is_ascii()
            || value.input_size > MAX_INPUT
        {
            return Err("Analysis request bounds/schema rejected");
        }
        let input = value.case.input(value.architecture);
        if value.input_size != input.len() || value.input_sha256 != report_bundle::digest(&input) {
            return Err("Analysis request is not the closed generated fixture");
        }
        if matches!(
            value.fault,
            Fault::TamperManifest | Fault::TamperPayload | Fault::TamperProvenance
        ) && !matches!(
            value.case,
            Case::NativeCapture
                | Case::ManagedCapture
                | Case::ManagedBudget
                | Case::ManagedPartial
                | Case::StaticMsi
        ) {
            return Err("Analysis fault requires a capture fixture");
        }
        Ok(value)
    }
    pub fn verifies_input(&self, input: &[u8]) -> bool {
        input.len() == self.input_size
            && report_bundle::digest(input) == self.input_sha256
            && input == self.case.input(self.architecture)
    }
}
/// UTC calendar formatting from a bounded host timestamp, with a non-secret
/// uniqueness suffix; create_new still prevents output collisions/overwrites.
pub fn identity(seconds: u64, nonce: u32) -> Result<(String, String), &'static str> {
    if seconds > 253402300799 {
        return Err("UTC timestamp outside supported calendar");
    }
    let days = (seconds / 86400) as i64;
    let rem = seconds % 86400;
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let hour = rem / 3600;
    let minute = rem / 60 % 60;
    let second = rem % 60;
    Ok((
        format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z-{nonce:08x}"),
        format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn closed_request_canonical_input_and_calendar_are_bound() {
        assert_eq!(
            identity(0, 0).unwrap(),
            (
                "19700101T000000Z-00000000".into(),
                "1970-01-01T00:00:00Z".into()
            )
        );
        assert!(identity(u64::MAX, 0).is_err());
        for arch in [Arch::X86, Arch::X64] {
            for case in [
                Case::NativeReturn,
                Case::NativeCapture,
                Case::ManagedReturn,
                Case::ManagedCapture,
                Case::ManagedPartial,
                Case::ManagedBudget,
                Case::ManagedError,
                Case::StaticMsi,
                Case::MalformedMsi,
            ] {
                let r = Request::generated(
                    case,
                    Fault::None,
                    arch,
                    "20261018T120000Z-12345678".into(),
                    "2026-10-18T12:00:00Z".into(),
                );
                let raw = serde_json::to_vec(&r).unwrap();
                let decoded = Request::parse(&raw).unwrap();
                let mut input = case.input(arch);
                assert!(decoded.verifies_input(&input));
                input[0] ^= 1;
                assert!(!decoded.verifies_input(&input));
                let mut value = serde_json::to_value(r).unwrap();
                value["host_path"] = serde_json::json!("forbidden");
                assert!(Request::parse(&serde_json::to_vec(&value).unwrap()).is_err());
            }
        }
    }
}

#[cfg(test)]
mod indicator_request_tests {
    use super::*;
    #[test]
    fn new_indicator_cases_remain_exact_closed_inputs_with_separate_output_reservation() {
        let raw = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/data/native_indicators_reference.json"),
        )
        .unwrap();
        assert_eq!(
            report_bundle::digest(&raw),
            "5e1eb09804fdebe82911250fe317938cac1bde23ef568f4b52fd0c702edd31b3"
        );
        let corpus: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        for row in corpus["cases"].as_array().unwrap() {
            let case = Case::parse(row["analysis_case"].as_str().unwrap()).unwrap();
            let arch = if row["architecture"] == "x64" {
                Arch::X64
            } else {
                Arch::X86
            };
            let request = Request::generated(
                case,
                Fault::None,
                arch,
                "20261019T120000Z-12345678".into(),
                "2026-10-19T12:00:00Z".into(),
            );
            let raw = serde_json::to_vec(&request).unwrap();
            assert!(
                Request::parse(&raw)
                    .unwrap()
                    .verifies_input(&case.input(arch))
            );
            assert_eq!(request.input_sha256, row["input_sha256"]);
            assert_eq!(
                case.output_limit(),
                MAX_OUTPUT + crate::indicator_fixture::REPORT_RESERVATION
            );
            let mut unknown: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            unknown["memory_strings"] = serde_json::json!({"regex":[".*"]});
            assert!(Request::parse(&serde_json::to_vec(&unknown).unwrap()).is_err());
        }
        assert_eq!(Case::NativeReturn.output_limit(), MAX_OUTPUT);
        assert!(Case::parse("native-indicators-custom").is_none());
    }
}

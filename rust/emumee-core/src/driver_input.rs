//! Bounded submitted x64 driver request; separate from generated fixture roles.
use serde::{Deserialize, Serialize};

pub const PROFILE: &str = "submitted_driver_x64_v1";
pub const MAX_INPUT: usize = 128 * 1024 * 1024;
pub const MAX_REFERENCE: usize = 32 * 1024 * 1024;
pub const MAX_PERSONA: usize = 32 * 1024 * 1024;
pub const MAX_INSTRUCTIONS: u64 = 2_000_000_000;
pub const MAX_TIMEOUT_US: u64 = 7_200_000_000;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PagingProfile {
    #[serde(rename = "owned_four_level_26200_v1")]
    OwnedFourLevel26200V1,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ParkedThreadProfile {
    #[serde(rename = "quiescent_allocated_system_26200_v1")]
    QuiescentAllocatedSystem26200V1,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PfnProfile {
    #[serde(rename = "owned_table_backlinks_26200_v1")]
    OwnedTableBacklinks26200V1,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstructionWindow {
    pub start_instruction: u64,
    pub max_records: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: u32,
    pub profile: String,
    pub run_id: String,
    pub input_sha256: String,
    pub input_size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_code_reference_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persona_sha256: Option<String>,
    pub service_name: String,
    pub max_instructions: u64,
    pub timeout_us: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instruction_window: Option<InstructionWindow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paging_profile: Option<PagingProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parked_thread_profile: Option<ParkedThreadProfile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pfn_profile: Option<PfnProfile>,
}

fn sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn service_name_valid(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphabetic()
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

impl Request {
    pub fn new(
        run_id: String,
        input_sha256: String,
        input_size: u64,
        service_name: String,
        max_instructions: u64,
        timeout_us: u64,
    ) -> Result<Self, &'static str> {
        let request = Self {
            schema: 1,
            profile: PROFILE.into(),
            run_id,
            input_sha256,
            input_size,
            kernel_code_reference_sha256: None,
            persona_sha256: None,
            service_name,
            max_instructions,
            timeout_us,
            instruction_window: None,
            paging_profile: None,
            parked_thread_profile: None,
            pfn_profile: None,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn with_reference(mut self, sha256: String) -> Result<Self, &'static str> {
        self.kernel_code_reference_sha256 = Some(sha256);
        self.validate()?;
        Ok(self)
    }

    pub fn with_persona(mut self, sha256: String) -> Result<Self, &'static str> {
        self.persona_sha256 = Some(sha256);
        self.validate()?;
        Ok(self)
    }

    pub fn with_paging_profile(mut self, profile: PagingProfile) -> Result<Self, &'static str> {
        self.paging_profile = Some(profile);
        self.validate()?;
        Ok(self)
    }

    pub fn with_parked_thread_profile(
        mut self,
        profile: ParkedThreadProfile,
    ) -> Result<Self, &'static str> {
        self.parked_thread_profile = Some(profile);
        self.validate()?;
        Ok(self)
    }

    pub fn with_pfn_profile(mut self, profile: PfnProfile) -> Result<Self, &'static str> {
        self.pfn_profile = Some(profile);
        self.validate()?;
        Ok(self)
    }

    pub fn with_instruction_window(
        mut self,
        window: InstructionWindow,
    ) -> Result<Self, &'static str> {
        self.instruction_window = Some(window);
        self.validate()?;
        Ok(self)
    }

    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() > 4096 {
            return Err("Submitted driver request exceeds 4096 bytes");
        }
        let request: Self =
            serde_json::from_slice(raw).map_err(|_| "Invalid submitted driver request")?;
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != 1 || self.profile != PROFILE {
            return Err("Submitted driver profile/schema mismatch");
        }
        if !crate::reports::valid_run_id(&self.run_id) || !sha256(&self.input_sha256) {
            return Err("Submitted driver identity/hash invalid");
        }
        if self.input_size == 0 || self.input_size > MAX_INPUT as u64 {
            return Err("Submitted driver input exceeds bounded profile");
        }
        if self
            .kernel_code_reference_sha256
            .as_ref()
            .is_some_and(|s| !sha256(s))
        {
            return Err("Submitted kernel reference hash invalid");
        }
        if self.persona_sha256.as_ref().is_some_and(|s| !sha256(s)) {
            return Err("Submitted persona hash invalid");
        }
        if self.pfn_profile.is_some()
            && (self.paging_profile != Some(PagingProfile::OwnedFourLevel26200V1)
                || self.kernel_code_reference_sha256.is_none()
                || self.persona_sha256.is_none())
        {
            return Err(
                "Owned table backlinks require owned paging, bound kernel reference and persona",
            );
        }
        if self.parked_thread_profile.is_some()
            && (self.paging_profile != Some(PagingProfile::OwnedFourLevel26200V1)
                || self.kernel_code_reference_sha256.is_none()
                || self.persona_sha256.is_none())
        {
            return Err(
                "Quiescent parked threads require owned paging, bound kernel reference and persona",
            );
        }
        if self.paging_profile.is_some()
            && (self.kernel_code_reference_sha256.is_none() || self.persona_sha256.is_none())
        {
            return Err("Owned paging requires bound kernel reference and persona");
        }
        if !service_name_valid(&self.service_name) {
            return Err("Submitted driver service name outside bounded profile");
        }
        if self.max_instructions == 0 || self.max_instructions > MAX_INSTRUCTIONS {
            return Err("Submitted driver instruction budget outside bounded profile");
        }
        if let Some(window) = self.instruction_window {
            if !(1..=65_536).contains(&window.max_records)
                || window.start_instruction >= self.max_instructions
                || window
                    .start_instruction
                    .checked_add(u64::from(window.max_records))
                    .is_none_or(|end| end > MAX_INSTRUCTIONS)
            {
                return Err("Submitted driver instruction window outside bounded profile");
            }
        }
        if self.timeout_us == 0 || self.timeout_us > MAX_TIMEOUT_US {
            return Err("Submitted driver wall budget outside bounded profile");
        }
        Ok(())
    }

    pub fn driver_name(&self) -> String {
        format!(r"\Driver\{}", self.service_name)
    }

    pub fn registry_path(&self) -> String {
        format!(
            r"\Registry\Machine\System\CurrentControlSet\Services\{}",
            self.service_name
        )
    }

    pub fn module_name(&self) -> String {
        format!("{}.sys", self.service_name)
    }

    pub fn module_path(&self) -> String {
        format!(r"C:\Windows\System32\drivers\{}.sys", self.service_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_pfn_profile_is_explicit_bound_and_versioned() {
        let request = Request::new(
            "20261101T120000Z-12345678".into(),
            "b".repeat(64),
            8192,
            "TestDrv".into(),
            10_000,
            30_000_000,
        )
        .unwrap();
        let profile = PfnProfile::OwnedTableBacklinks26200V1;
        assert_eq!(request.pfn_profile, None);
        let legacy = serde_json::to_string(&request).unwrap();
        assert!(!legacy.contains("pfn_profile"));
        assert_eq!(Request::parse(legacy.as_bytes()).unwrap().pfn_profile, None);
        for authorities in 0..8 {
            let mut candidate = request.clone();
            if authorities & 1 != 0 {
                candidate.paging_profile = Some(PagingProfile::OwnedFourLevel26200V1);
            }
            if authorities & 2 != 0 {
                candidate.kernel_code_reference_sha256 = Some("a".repeat(64));
            }
            if authorities & 4 != 0 {
                candidate.persona_sha256 = Some("c".repeat(64));
            }
            assert_eq!(
                candidate.clone().with_pfn_profile(profile).is_ok(),
                authorities == 7
            );
            candidate.pfn_profile = Some(profile);
            assert_eq!(candidate.validate().is_ok(), authorities == 7);
            assert_eq!(
                Request::parse(&serde_json::to_vec(&candidate).unwrap()).is_ok(),
                authorities == 7
            );
        }
        let admitted = request
            .with_reference("a".repeat(64))
            .unwrap()
            .with_persona("c".repeat(64))
            .unwrap()
            .with_paging_profile(PagingProfile::OwnedFourLevel26200V1)
            .unwrap()
            .with_pfn_profile(profile)
            .unwrap();
        let raw = serde_json::to_string(&admitted).unwrap();
        assert_eq!(Request::parse(raw.as_bytes()).unwrap(), admitted);
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(value["pfn_profile"], "owned_table_backlinks_26200_v1");
        for invalid in [
            serde_json::json!("future"),
            serde_json::json!("owned_table_backlinks_26200_v2"),
            serde_json::json!("OwnedTableBacklinks26200V1"),
            serde_json::json!(true),
        ] {
            let mut changed = value.clone();
            changed["pfn_profile"] = invalid;
            assert!(Request::parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        for hash_field in ["kernel_code_reference_sha256", "persona_sha256"] {
            let mut changed = value.clone();
            changed[hash_field] = serde_json::json!("invalid");
            assert!(Request::parse(&serde_json::to_vec(&changed).unwrap()).is_err());
        }
        for duplicate in [r#""owned_table_backlinks_26200_v1""#, "null"] {
            let duplicated = format!("{{\"pfn_profile\":{duplicate},{}", &raw[1..]);
            assert!(Request::parse(duplicated.as_bytes()).is_err());
        }
    }

    #[test]
    fn quiescent_parked_profile_is_explicit_bound_and_versioned() {
        let request = Request::new(
            "20261101T120000Z-12345678".into(),
            "b".repeat(64),
            8192,
            "TestDrv".into(),
            10_000,
            30_000_000,
        )
        .unwrap();
        let profile = ParkedThreadProfile::QuiescentAllocatedSystem26200V1;
        assert_eq!(request.parked_thread_profile, None);
        assert!(
            !serde_json::to_string(&request)
                .unwrap()
                .contains("parked_thread_profile")
        );
        for authorities in 0..8 {
            let mut candidate = request.clone();
            if authorities & 1 != 0 {
                candidate.paging_profile = Some(PagingProfile::OwnedFourLevel26200V1);
            }
            if authorities & 2 != 0 {
                candidate.kernel_code_reference_sha256 = Some("a".repeat(64));
            }
            if authorities & 4 != 0 {
                candidate.persona_sha256 = Some("c".repeat(64));
            }
            assert_eq!(
                candidate
                    .clone()
                    .with_parked_thread_profile(profile)
                    .is_ok(),
                authorities == 7
            );
            candidate.parked_thread_profile = Some(profile);
            assert_eq!(candidate.validate().is_ok(), authorities == 7);
            assert_eq!(
                Request::parse(&serde_json::to_vec(&candidate).unwrap()).is_ok(),
                authorities == 7
            );
        }
        let selected = request
            .with_reference("a".repeat(64))
            .unwrap()
            .with_persona("c".repeat(64))
            .unwrap()
            .with_paging_profile(PagingProfile::OwnedFourLevel26200V1)
            .unwrap()
            .with_parked_thread_profile(profile)
            .unwrap();
        let mut value = serde_json::to_value(&selected).unwrap();
        assert_eq!(
            value["parked_thread_profile"],
            "quiescent_allocated_system_26200_v1"
        );
        assert_eq!(
            Request::parse(&serde_json::to_vec(&value).unwrap()).unwrap(),
            selected
        );
        for invalid in [
            serde_json::json!("quiescent_allocated_system_26200_v2"),
            serde_json::json!(true),
            serde_json::json!({"profile": "quiescent_allocated_system_26200_v1"}),
        ] {
            value["parked_thread_profile"] = invalid;
            assert!(Request::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        let raw = serde_json::to_string(&selected).unwrap();
        let duplicate = format!(
            "{{\"parked_thread_profile\":\"quiescent_allocated_system_26200_v1\",{}",
            &raw[1..]
        );
        assert!(Request::parse(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn owned_paging_profile_requires_both_bound_inputs_and_rejects_unknown_versions() {
        let request = Request::new(
            "20261030T120000Z-12345678".into(),
            "b".repeat(64),
            8192,
            "TestDrv".into(),
            10000,
            30000000,
        )
        .unwrap();
        let profile = PagingProfile::OwnedFourLevel26200V1;
        assert!(request.clone().with_paging_profile(profile).is_err());
        let reference = request.clone().with_reference("a".repeat(64)).unwrap();
        assert!(reference.clone().with_paging_profile(profile).is_err());
        assert!(
            request
                .with_persona("c".repeat(64))
                .unwrap()
                .with_paging_profile(profile)
                .is_err()
        );
        let admitted = reference
            .with_persona("c".repeat(64))
            .unwrap()
            .with_paging_profile(profile)
            .unwrap();
        let raw = serde_json::to_vec(&admitted).unwrap();
        assert_eq!(Request::parse(&raw).unwrap(), admitted);
        let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        value["paging_profile"] = serde_json::json!("owned_four_level_26200_v2");
        assert!(Request::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        value["paging_profile"] = serde_json::json!(true);
        assert!(Request::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn submitted_driver_request_binds_exact_service_and_budgets() {
        let request = Request::new(
            "20261019T120000Z-12345678".into(),
            "b".repeat(64),
            8192,
            "TestDrv".into(),
            10_000,
            30_000_000,
        )
        .unwrap();
        let raw = serde_json::to_vec(&request).unwrap();
        assert_eq!(Request::parse(&raw).unwrap(), request);
        assert_eq!(request.driver_name(), r"\Driver\TestDrv");
        assert_eq!(
            request.registry_path(),
            r"\Registry\Machine\System\CurrentControlSet\Services\TestDrv"
        );
        assert_eq!(
            request.module_path(),
            r"C:\Windows\System32\drivers\TestDrv.sys"
        );
        let mut changed = request.clone();
        let referenced = request.clone().with_reference("a".repeat(64)).unwrap();
        assert_eq!(
            Request::parse(&serde_json::to_vec(&referenced).unwrap()).unwrap(),
            referenced
        );
        assert!(request.clone().with_reference("A".repeat(64)).is_err());
        let configured = request.clone().with_persona("c".repeat(64)).unwrap();
        assert_eq!(
            Request::parse(&serde_json::to_vec(&configured).unwrap()).unwrap(),
            configured
        );
        assert!(request.clone().with_persona("C".repeat(64)).is_err());
        changed.service_name = "..\\foreign".into();
        assert!(changed.validate().is_err());
        changed.service_name = "TestDrv".into();
        changed.input_size = MAX_INPUT as u64 + 1;
        assert!(changed.validate().is_err());
        let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        value["foreign"] = serde_json::json!(true);
        assert!(Request::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        let extended = Request::new(
            request.run_id.clone(),
            request.input_sha256.clone(),
            request.input_size,
            request.service_name.clone(),
            1_600_000_000,
            request.timeout_us,
        )
        .unwrap();
        assert_eq!(extended.max_instructions, 1_600_000_000);
        assert!(
            Request::new(
                request.run_id.clone(),
                request.input_sha256.clone(),
                request.input_size,
                request.service_name.clone(),
                MAX_INSTRUCTIONS + 1,
                request.timeout_us,
            )
            .is_err()
        );
    }

    #[test]
    fn optional_instruction_window_is_bound_and_absent_request_json_is_stable() {
        let request = Request::new(
            "20261019T120000Z-12345678".into(),
            "b".repeat(64),
            8192,
            "TestDrv".into(),
            10_000,
            30_000_000,
        )
        .unwrap();
        let raw = serde_json::to_string(&request).unwrap();
        assert_eq!(
            raw,
            format!(
                "{{\"schema\":1,\"profile\":\"submitted_driver_x64_v1\",\"run_id\":\"20261019T120000Z-12345678\",\"input_sha256\":\"{}\",\"input_size\":8192,\"service_name\":\"TestDrv\",\"max_instructions\":10000,\"timeout_us\":30000000}}",
                "b".repeat(64)
            )
        );
        assert_eq!(Request::parse(raw.as_bytes()).unwrap(), request);
        let window = InstructionWindow {
            start_instruction: 9000,
            max_records: 65_536,
        };
        let observed = request.clone().with_instruction_window(window).unwrap();
        assert_eq!(
            Request::parse(&serde_json::to_vec(&observed).unwrap()).unwrap(),
            observed
        );
        assert_eq!(observed.instruction_window, Some(window));
        for invalid in [
            InstructionWindow {
                start_instruction: 0,
                max_records: 0,
            },
            InstructionWindow {
                start_instruction: 0,
                max_records: 65_537,
            },
            InstructionWindow {
                start_instruction: 10_000,
                max_records: 1,
            },
            InstructionWindow {
                start_instruction: u64::MAX,
                max_records: 1,
            },
        ] {
            assert!(request.clone().with_instruction_window(invalid).is_err());
        }
        assert!(
            Request::new(
                request.run_id.clone(),
                request.input_sha256.clone(),
                request.input_size,
                request.service_name.clone(),
                MAX_INSTRUCTIONS,
                request.timeout_us,
            )
            .unwrap()
            .with_instruction_window(InstructionWindow {
                start_instruction: MAX_INSTRUCTIONS - 1,
                max_records: 2,
            })
            .is_err()
        );
        let mut unknown: serde_json::Value = serde_json::to_value(&observed).unwrap();
        unknown["instruction_window"]["extra"] = serde_json::json!(true);
        assert!(Request::parse(&serde_json::to_vec(&unknown).unwrap()).is_err());
    }
}

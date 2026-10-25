//! Versioned admission contract for a contained static Linux ELF worker.
use serde::{Deserialize, Serialize};

pub const MAX_INPUT: usize = 32 * 1024 * 1024;
pub const MAX_INSTRUCTIONS: u64 = 1_000_000;
pub const MAX_TIMEOUT_US: u64 = 30_000_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRequest {
    pub schema: u32,
    pub profile: String,
    pub input_sha256: String,
    pub input_size: u64,
    pub max_instructions: u64,
    pub timeout_us: u64,
}

impl LinuxRequest {
    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        if self.schema != 1 || self.profile != "static_x64_v1" {
            return Err("Unsupported Linux worker request profile");
        }
        if self.input_sha256.len() != 64
            || !self
                .input_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("Invalid Linux input digest");
        }
        if !(1..=MAX_INPUT as u64).contains(&self.input_size)
            || !(1..=MAX_INSTRUCTIONS).contains(&self.max_instructions)
            || !(1..=MAX_TIMEOUT_US).contains(&self.timeout_us)
        {
            return Err("Linux worker request exceeds closed bounds");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versioned_profile_rejects_unknown_or_unbounded_requests() {
        let request = LinuxRequest {
            schema: 1,
            profile: "static_x64_v1".into(),
            input_sha256: "a".repeat(64),
            input_size: 4096,
            max_instructions: 1000,
            timeout_us: 1_000_000,
        };
        assert!(request.validate().is_ok());
        let mut wrong = request.clone();
        wrong.profile = "dynamic".into();
        assert!(wrong.validate().is_err());
        let mut wrong = request.clone();
        wrong.input_sha256 = "A".repeat(64);
        assert!(wrong.validate().is_err());
        let mut wrong = request.clone();
        wrong.input_size = MAX_INPUT as u64 + 1;
        assert!(wrong.validate().is_err());
        assert!(serde_json::from_str::<LinuxRequest>(
            r#"{"schema":1,"profile":"static_x64_v1","input_sha256":"a","input_size":1,"max_instructions":1,"timeout_us":1,"extra":true}"#
        )
        .is_err());
    }
}

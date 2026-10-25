//! Versioned admission contract for contained Linux ELF guest profiles.
use serde::{Deserialize, Serialize};

pub const MAX_INPUT: usize = 32 * 1024 * 1024;
pub const MAX_INSTRUCTIONS: u64 = 1_000_000;
pub const MAX_TIMEOUT_US: u64 = 30_000_000;
pub const MAX_LIBRARY_INPUT: usize = 8 * 1024 * 1024;
pub const MAX_LIBRARIES: usize = 4;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxLibrary {
    pub name: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxRequest {
    pub schema: u32,
    pub profile: String,
    pub input_sha256: String,
    pub input_size: u64,
    pub max_instructions: u64,
    pub timeout_us: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub libraries: Vec<LinuxLibrary>,
}

pub fn valid_library_name(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value != "." && value != ".."
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl LinuxRequest {
    pub fn validate(&self) -> std::result::Result<(), &'static str> {
        let shared = self.profile == "shared_x64_v1";
        if (shared && self.schema != 2)
            || (!shared && self.schema != 1)
            || !matches!(self.profile.as_str(), "static_x64_v1" | "pie_x64_v1" | "static_x86_v1" | "pie_x86_v1" | "shared_x64_v1")
        {
            return Err("Unsupported Linux worker request profile");
        }
        if !valid_digest(&self.input_sha256) {
            return Err("Invalid Linux input digest");
        }
        if (shared && !(1..=MAX_LIBRARIES).contains(&self.libraries.len()))
            || (!shared && !self.libraries.is_empty())
        {
            return Err("Invalid staged library count");
        }
        for (index, library) in self.libraries.iter().enumerate() {
            if !valid_library_name(&library.name) || !valid_digest(&library.sha256)
                || !(1..=MAX_LIBRARY_INPUT as u64).contains(&library.size)
                || self.libraries[..index].iter().any(|earlier| earlier.name == library.name)
            {
                return Err("Invalid staged library descriptor");
            }
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
            libraries: Vec::new(),
        };
        assert!(request.validate().is_ok());
        let mut pie32 = request.clone();
        pie32.profile = "pie_x86_v1".into();
        assert!(pie32.validate().is_ok());
        let mut shared = request.clone();
        shared.schema = 2;
        shared.profile = "shared_x64_v1".into();
        shared.libraries.push(LinuxLibrary {
            name: "libguest.so".into(),
            sha256: "b".repeat(64),
            size: 4096,
        });
        assert!(shared.validate().is_ok());
        shared.libraries.push(shared.libraries[0].clone());
        assert!(shared.validate().is_err(), "duplicate dependency");
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

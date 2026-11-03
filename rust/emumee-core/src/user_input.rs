//! Submitted user-mode PE contract. Paths describe guest state only.
use crate::pe::{Kind, PeImage};
use serde::{Deserialize, Serialize};

pub const PROFILE: &str = "submitted_user_pe_v1";
pub const MAX_REQUEST: usize = 64 * 1024;
pub const MAX_RESULT: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: u32,
    pub profile: String,
    pub run_id: String,
    pub input_sha256: String,
    pub input_size: u64,
    pub module_name: String,
    pub arguments: Vec<String>,
    pub max_instructions: u64,
    pub timeout_us: u64,
    pub persona_sha256: Option<String>,
    pub clock_utc_filetime: u64,
}

fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn module_name_valid(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && !name.starts_with('.')
        && [".exe", ".dll"]
            .iter()
            .any(|suffix| name.to_ascii_lowercase().ends_with(suffix))
}

impl Request {
    pub fn resolve_persona(
        &self,
        document: &[u8],
    ) -> crate::fullpersona::Result<crate::fullpersona::ValidatedPersona> {
        let explicit = serde_json::from_slice::<serde_json::Value>(document)
            .ok()
            .is_some_and(|v| v.get("clock_utc").is_some_and(|clock| !clock.is_null()));
        crate::fullpersona::decode(
            document,
            &crate::fullpersona::ResolveContext {
                clock_seed: (!explicit).then(|| crate::fullpersona::ClockSeed {
                    utc_filetime: self.clock_utc_filetime,
                    source: crate::fullpersona::ClockSource::Fixed,
                    source_id: "submitted_user_request.clock_utc_filetime".into(),
                }),
            },
        )
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != 1
            || self.profile != PROFILE
            || !crate::reports::valid_run_id(&self.run_id)
            || !hash(&self.input_sha256)
            || self.persona_sha256.as_ref().is_some_and(|h| !hash(h))
        {
            return Err("Invalid submitted PE identity/profile");
        }
        if !module_name_valid(&self.module_name)
            || self.input_size == 0
            || self.input_size > crate::pe::MAX_INPUT as u64
        {
            return Err("Submitted PE name/size outside profile");
        }
        if self.max_instructions == 0
            || self.max_instructions > crate::driver_input::MAX_INSTRUCTIONS
            || self.timeout_us == 0
            || self.timeout_us > crate::driver_input::MAX_TIMEOUT_US
        {
            return Err("Submitted PE execution budget outside profile");
        }
        if self.arguments.len() > 64
            || self.arguments.iter().any(|a| a.contains('\0'))
            || self.arguments.iter().map(|a| a.len()).sum::<usize>() > 32768
        {
            return Err("Submitted PE arguments exceed profile");
        }
        Ok(())
    }

    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() > MAX_REQUEST {
            return Err("Submitted PE request exceeds bound");
        }
        let value: Self =
            serde_json::from_slice(raw).map_err(|_| "Invalid submitted PE request")?;
        value.validate()?;
        Ok(value)
    }

    pub fn verify_input(&self, input: &[u8]) -> Result<PeImage, String> {
        self.validate()?;
        if input.len() as u64 != self.input_size
            || crate::report_bundle::digest(input) != self.input_sha256
        {
            return Err("Submitted PE input hash/size changed".into());
        }
        let pe = PeImage::parse(input, &self.module_name).map_err(|e| e.to_string())?;
        if pe.sample.managed || !matches!(pe.sample.kind, Kind::Exe | Kind::Dll) {
            return Err("Submitted user path requires a native EXE or DLL; managed IL and drivers use separate profiles".into());
        }
        Ok(pe)
    }

    pub fn guest_path(&self) -> String {
        format!(r"C:\emumee\{}", self.module_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        Request {
            schema: 1,
            profile: PROFILE.into(),
            run_id: "20261029T120000Z-12345678".into(),
            input_sha256: "a".repeat(64),
            input_size: 512,
            module_name: "sample.exe".into(),
            arguments: vec![],
            max_instructions: 1000,
            timeout_us: 1000000,
            persona_sha256: None,
            clock_utc_filetime: 134377488000000000,
        }
    }
    #[test]
    fn submitted_user_contract_rejects_paths_unbounded_and_unknown_fields() {
        let r = request();
        r.validate().unwrap();
        for name in ["../a.exe", "a\\b.exe", "a.sys", ".exe", "a.exe:stream"] {
            let mut bad = r.clone();
            bad.module_name = name.into();
            assert!(bad.validate().is_err());
        }
        let mut bad = r.clone();
        bad.max_instructions = 0;
        assert!(bad.validate().is_err());
        bad = r.clone();
        bad.arguments = vec!["a\0b".into()];
        assert!(bad.validate().is_err());
        let mut json = serde_json::to_value(&r).unwrap();
        json["host_path"] = "a".into();
        assert!(Request::parse(&serde_json::to_vec(&json).unwrap()).is_err());
        assert!(r.verify_input(b"changed").is_err());
    }
}

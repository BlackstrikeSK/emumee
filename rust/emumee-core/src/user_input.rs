//! Submitted user-mode PE contract. Paths describe guest state only.
use crate::pe::{Kind, PeImage};
use serde::{Deserialize, Serialize};

pub const PROFILE: &str = "submitted_user_pe_v1";
pub const MAX_REQUEST: usize = 64 * 1024;
pub const MAX_RESULT: usize = 32 * 1024 * 1024;
pub const MAX_STAGED_FILES: usize = 128;
pub const MAX_STAGED_FILE: usize = 32 * 1024 * 1024;
pub const MAX_STAGED_TOTAL: u64 = 128 * 1024 * 1024;
pub const MAX_MAPPED_TOTAL: u64 = 512 * 1024 * 1024;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    #[serde(default)]
    pub environment: Vec<(String, Option<String>)>,
    #[serde(default)]
    pub force_quotes: Vec<usize>,
    #[serde(default)]
    pub all_exports: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    Companion,
    File,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedFile {
    pub kind: InputKind,
    pub guest_path: String,
    pub size: u64,
    pub sha256: String,
}

pub fn staged_name(index: usize) -> String {
    format!("inputs/{index:04}.bin")
}

pub fn guest_path_valid(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 4
        && bytes.len() <= 1024
        && bytes[0].is_ascii_alphabetic()
        && bytes[1..3] == *b":\\"
        && path[3..].split('\\').all(|part| {
            let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
            !part.is_empty()
                && !part.ends_with([' ', '.'])
                && !part
                    .chars()
                    .any(|value| value < ' ' || ":/*?\"<>|".contains(value))
                && !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$")
                && !(stem.len() == 4
                    && (stem.starts_with("COM") || stem.starts_with("LPT"))
                    && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        })
}

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
    #[serde(default)]
    pub staged: Vec<StagedFile>,
    #[serde(default)]
    pub invocation: Invocation,
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
    pub fn verify_persona(&self, raw: Option<&[u8]>) -> Result<(), &'static str> {
        if raw.map(crate::report_bundle::digest) != self.persona_sha256 {
            return Err("Submitted user persona binding differs");
        }
        Ok(())
    }

    pub fn verify_result(
        &self,
        result: &serde_json::Value,
        request_sha256: &str,
        persona: Option<&[u8]>,
    ) -> Result<(), &'static str> {
        self.verify_persona(persona)?;
        let persona = self
            .resolve_persona(
                persona.unwrap_or_else(|| crate::fullpersona::default_document().as_bytes()),
            )
            .map_err(|_| "Submitted PE persona cannot be resolved")?;
        let receipt = serde_json::to_value(self).map_err(|_| "Invalid input receipt")?;
        if result["schema"] != 1
            || result["profile"] != self.profile
            || result["run_id"] != self.run_id
            || result["request_sha256"] != request_sha256
            || result["input_sha256"] != self.input_sha256
            || result["input_receipt"] != receipt
        {
            return Err("Submitted PE report binding differs");
        }
        let containment = &result["containment"];
        if containment["app_container"] != true
            || containment["job_object"] != true
            || containment["child_process_blocked"] != true
            || containment["network_capabilities"] != 0
        {
            return Err("Submitted PE containment absent");
        }
        let execution = &result["execution"];
        if execution["max_instructions"] != self.max_instructions
            || execution["configuration"]["generated_only"] != false
            || execution["configuration"]["initialized"] != true
            || execution["configuration"]["guest_image_path"] != self.guest_path()
            || execution["configuration"]["clock_seed"]["utc_filetime"]
                != persona.projection().data.clock.utc_filetime
            || execution["configuration"]["input_json_sha256"] != persona.input_sha256()
            || execution["configuration"]["effective_sha256"] != persona.sha256()
            || execution["configuration"]["projection_sha256"] != persona.projection().sha256
            || execution["instruction_count"]
                .as_u64()
                .is_none_or(|count| count > self.max_instructions)
        {
            return Err("Submitted PE instruction bound differs");
        }
        Ok(())
    }

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
        if !matches!(self.schema, 1 | 2)
            || self.profile != PROFILE
            || !crate::reports::valid_run_id(&self.run_id)
            || !hash(&self.input_sha256)
            || self.persona_sha256.as_ref().is_some_and(|h| !hash(h))
        {
            return Err("Invalid submitted PE identity/profile");
        }
        if self.schema == 1 && (!self.staged.is_empty() || self.invocation != Invocation::default())
        {
            return Err("Schema 1 cannot carry extended submitted inputs");
        }
        if !module_name_valid(&self.module_name)
            || !guest_path_valid(&self.guest_path())
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
        self.validate_extensions()?;
        Ok(())
    }

    fn validate_extensions(&self) -> Result<(), &'static str> {
        use std::collections::BTreeSet;
        if self.staged.len() > MAX_STAGED_FILES || self.invocation.environment.len() > 256 {
            return Err("Submitted PE staged collection exceeds profile");
        }
        let mut paths = BTreeSet::from([self.guest_path().to_lowercase()]);
        let mut modules = BTreeSet::from([self.module_name.to_ascii_lowercase()]);
        let mut total = 0u64;
        let mut companions = 0usize;
        for file in &self.staged {
            if !guest_path_valid(&file.guest_path)
                || !hash(&file.sha256)
                || file.size > MAX_STAGED_FILE as u64
                || !paths.insert(file.guest_path.to_lowercase())
            {
                return Err("Invalid or duplicate submitted guest file");
            }
            total = total.checked_add(file.size).ok_or("Staged size overflow")?;
            if file.kind == InputKind::Companion {
                companions += 1;
                let name = file.guest_path.rsplit('\\').next().unwrap_or("");
                if file.size == 0
                    || !module_name_valid(name)
                    || !name.to_ascii_lowercase().ends_with(".dll")
                    || !modules.insert(name.to_ascii_lowercase())
                {
                    return Err("Invalid or duplicate submitted companion module");
                }
            }
        }
        if total > MAX_STAGED_TOTAL || companions > 16 {
            return Err("Submitted PE staged byte/module quota exceeded");
        }
        for path in &paths {
            if path
                .match_indices('\\')
                .any(|(index, _)| index > 2 && paths.contains(&path[..index]))
            {
                return Err("Submitted guest file/directory collision");
            }
        }
        let mut environment = BTreeSet::new();
        let mut environment_bytes = 0usize;
        for (name, value) in &self.invocation.environment {
            if name.is_empty()
                || name.contains(['=', '\0'])
                || value.as_ref().is_some_and(|value| value.contains('\0'))
                || !environment.insert(name.to_lowercase())
            {
                return Err("Invalid or duplicate submitted environment override");
            }
            environment_bytes = environment_bytes
                .checked_add(name.len())
                .and_then(|sum| sum.checked_add(value.as_ref().map_or(0, String::len)))
                .ok_or("Environment size overflow")?;
        }
        if environment_bytes > 32768 {
            return Err("Submitted environment exceeds profile");
        }
        let mut argv = vec![self.guest_path()];
        argv.extend(self.arguments.iter().cloned());
        let quoted = self
            .invocation
            .force_quotes
            .iter()
            .map(|index| index.checked_add(1))
            .collect::<Option<Vec<_>>>()
            .ok_or("Submitted quote index overflow")?;
        if self
            .invocation
            .force_quotes
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != self.invocation.force_quotes.len()
            || crate::persona::command_line(&argv, &quoted).is_err()
        {
            return Err("Invalid submitted argument quoting");
        }
        Ok(())
    }

    pub fn verify_staged(&self, input: &[u8], staged: &[Vec<u8>]) -> Result<(), String> {
        let primary = self.verify_input(input)?;
        if staged.len() != self.staged.len() {
            return Err("Submitted staged input count differs".into());
        }
        let mut mapped = u64::from(primary.image_size);
        for (file, bytes) in self.staged.iter().zip(staged) {
            if bytes.len() as u64 != file.size || crate::report_bundle::digest(bytes) != file.sha256
            {
                return Err("Submitted staged input hash/size changed".into());
            }
            if file.kind == InputKind::Companion {
                let name = file.guest_path.rsplit('\\').next().unwrap();
                let companion = PeImage::parse(bytes, name).map_err(|error| error.to_string())?;
                if companion.sample.managed
                    || companion.sample.kind != Kind::Dll
                    || companion.sample.architecture != primary.sample.architecture
                {
                    return Err("Submitted companion must be a same-architecture native DLL".into());
                }
                mapped = mapped
                    .checked_add(u64::from(companion.image_size))
                    .ok_or("Submitted mapped image size overflow")?;
            }
        }
        if mapped > MAX_MAPPED_TOTAL {
            return Err("Submitted mapped image quota exceeded".into());
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
    #[test]
    fn parent_result_rejects_each_input_option_identity_and_containment_substitution() {
        let document = br#"{"clock_utc":"2026-10-18T14:00:00+02:00"}"#;
        let mut request = request();
        request.schema = 2;
        request.persona_sha256 = Some(crate::report_bundle::digest(document));
        request.staged.push(StagedFile {
            kind: InputKind::File,
            guest_path: r"C:\data\file".into(),
            size: 4,
            sha256: crate::report_bundle::digest(b"data"),
        });
        request
            .invocation
            .environment
            .push(("TOKEN".into(), Some("value".into())));
        request.arguments.push("argument".into());
        request.invocation.force_quotes.push(0);
        let expected = crate::report_bundle::digest(&serde_json::to_vec(&request).unwrap());
        let persona = request.resolve_persona(document).unwrap();
        assert_ne!(
            persona.projection().data.clock.utc_filetime,
            request.clock_utc_filetime
        );
        let valid = serde_json::json!({"schema":1,"profile":request.profile,"run_id":request.run_id,
            "request_sha256":expected,"input_sha256":request.input_sha256,"input_receipt":request,
            "containment":{"app_container":true,"job_object":true,"child_process_blocked":true,"network_capabilities":0},
            "execution":{"instruction_count":1000,"max_instructions":request.max_instructions,
                "configuration":{"generated_only":false,"initialized":true,"guest_image_path":request.guest_path(),
                    "input_json_sha256":persona.input_sha256(),"effective_sha256":persona.sha256(),"projection_sha256":persona.projection().sha256,
                    "clock_seed":{"utc_filetime":persona.projection().data.clock.utc_filetime}}}});
        request
            .verify_result(&valid, &expected, Some(document))
            .unwrap();
        for pointer in [
            "/schema",
            "/profile",
            "/run_id",
            "/request_sha256",
            "/input_sha256",
            "/input_receipt/schema",
            "/input_receipt/profile",
            "/input_receipt/run_id",
            "/input_receipt/input_sha256",
            "/input_receipt/input_size",
            "/input_receipt/module_name",
            "/input_receipt/arguments/0",
            "/input_receipt/max_instructions",
            "/input_receipt/timeout_us",
            "/input_receipt/persona_sha256",
            "/input_receipt/clock_utc_filetime",
            "/input_receipt/staged/0/kind",
            "/input_receipt/staged/0/guest_path",
            "/input_receipt/staged/0/size",
            "/input_receipt/staged/0/sha256",
            "/input_receipt/invocation/environment/0/0",
            "/input_receipt/invocation/environment/0/1",
            "/input_receipt/invocation/force_quotes/0",
            "/input_receipt/invocation/all_exports",
            "/containment/app_container",
            "/containment/job_object",
            "/containment/child_process_blocked",
            "/containment/network_capabilities",
            "/execution/instruction_count",
            "/execution/max_instructions",
            "/execution/configuration/generated_only",
            "/execution/configuration/initialized",
            "/execution/configuration/guest_image_path",
            "/execution/configuration/clock_seed/utc_filetime",
        ] {
            let mut changed = valid.clone();
            *changed.pointer_mut(pointer).unwrap() = serde_json::Value::Null;
            assert!(
                request
                    .verify_result(&changed, &expected, Some(document))
                    .is_err(),
                "{pointer}"
            );
        }
        let mut changed = valid.clone();
        changed["execution"]["instruction_count"] = (request.max_instructions + 1).into();
        assert!(
            request
                .verify_result(&changed, &expected, Some(document))
                .is_err()
        );
        changed = valid;
        changed["input_receipt"]["extra"] = true.into();
        assert!(
            request
                .verify_result(&changed, &expected, Some(document))
                .is_err()
        );
        request.verify_persona(Some(document)).unwrap();
        assert!(request.verify_persona(Some(b"changed")).is_err());
        assert!(request.verify_persona(None).is_err());
        request.persona_sha256 = None;
        assert!(request.verify_persona(Some(b"persona")).is_err());
    }
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
            staged: vec![],
            invocation: Invocation::default(),
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

    #[test]
    fn versioned_staging_rejects_ambiguous_paths_names_quotas_and_options() {
        let mut valid = request();
        valid.schema = 2;
        valid.arguments = vec!["two words".into(), "tail\\".into()];
        valid.invocation.force_quotes = vec![1];
        valid.invocation.environment = vec![("TOKEN".into(), Some("value".into()))];
        valid.staged = vec![StagedFile {
            kind: InputKind::File,
            guest_path: r"C:\data\empty.bin".into(),
            size: 0,
            sha256: crate::report_bundle::digest(b""),
        }];
        valid.validate().unwrap();
        let raw = serde_json::to_vec(&valid).unwrap();
        Request::parse(&raw).unwrap();
        for path in [
            r"..\escape",
            r"C:\..\escape",
            r"C:\a\.\b",
            r"C:\a\\b",
            r"C:\a\",
            r"C:\a:stream",
            r"C:\CON.txt",
            r"C:\LPT1",
            r"C:\a.\b",
            r"\\host\share\file",
            r"\\?\C:\file",
            "C:/a/b",
            "C:\\a\0b",
        ] {
            let mut bad = valid.clone();
            bad.staged[0].guest_path = path.into();
            assert!(bad.validate().is_err(), "{path:?}");
        }
        let mut bad = valid.clone();
        bad.schema = 1;
        assert!(bad.validate().is_err());
        bad = valid.clone();
        bad.staged.push(bad.staged[0].clone());
        bad.staged[1].guest_path = r"c:\DATA\EMPTY.BIN".into();
        assert!(bad.validate().is_err());
        bad = valid.clone();
        bad.staged[0].guest_path = r"C:\emumee\SAMPLE.exe".into();
        assert!(bad.validate().is_err());
        bad = valid.clone();
        bad.staged.push(StagedFile {
            guest_path: r"C:\data\empty.bin\child".into(),
            ..bad.staged[0].clone()
        });
        assert!(bad.validate().is_err());
        bad = valid.clone();
        bad.staged[0].size = MAX_STAGED_FILE as u64 + 1;
        assert!(bad.validate().is_err());
        bad = valid.clone();
        bad.staged = (0..5)
            .map(|index| StagedFile {
                guest_path: format!(r"C:\file{index}"),
                size: MAX_STAGED_FILE as u64,
                ..valid.staged[0].clone()
            })
            .collect();
        assert!(bad.validate().is_err());
        bad = valid.clone();
        bad.invocation.environment.push(("token".into(), None));
        assert!(bad.validate().is_err());
        for name in ["", "A=B", "A\0B"] {
            bad = valid.clone();
            bad.invocation.environment[0].0 = name.into();
            assert!(bad.validate().is_err());
        }
        for indices in [vec![usize::MAX], vec![2], vec![1, 1]] {
            bad = valid.clone();
            bad.invocation.force_quotes = indices;
            assert!(bad.validate().is_err());
        }
        let mut old = serde_json::to_value(request()).unwrap();
        old.as_object_mut().unwrap().remove("staged");
        old.as_object_mut().unwrap().remove("invocation");
        Request::parse(&serde_json::to_vec(&old).unwrap()).unwrap();
    }

    #[test]
    fn staged_hash_kind_architecture_and_mapped_quota_are_admission_contracts() {
        use crate::{
            fixtures::{self, LoaderFixture},
            pe::Architecture,
        };
        for architecture in [Architecture::X86, Architecture::X64] {
            let (primary, _) = fixtures::native_loader_probe(architecture, LoaderFixture::RootTls);
            let (dll, _) = fixtures::native_loader_probe(architecture, LoaderFixture::RootDll);
            let mut valid = request();
            valid.schema = 2;
            valid.input_sha256 = crate::report_bundle::digest(&primary);
            valid.input_size = primary.len() as u64;
            valid.staged = vec![StagedFile {
                kind: InputKind::Companion,
                guest_path: r"C:\lib\helper.dll".into(),
                size: dll.len() as u64,
                sha256: crate::report_bundle::digest(&dll),
            }];
            valid
                .verify_staged(&primary, std::slice::from_ref(&dll))
                .unwrap();
            assert!(valid.verify_staged(&primary, &[]).is_err());
            let mut changed = dll.clone();
            changed[0] ^= 1;
            assert!(valid.verify_staged(&primary, &[changed]).is_err());
            for payload in [
                primary.clone(),
                fixtures::native_loader_probe(
                    if architecture == Architecture::X86 {
                        Architecture::X64
                    } else {
                        Architecture::X86
                    },
                    LoaderFixture::RootDll,
                )
                .0,
            ] {
                let mut bad = valid.clone();
                bad.staged[0].sha256 = crate::report_bundle::digest(&payload);
                bad.staged[0].size = payload.len() as u64;
                assert!(bad.verify_staged(&primary, &[payload]).is_err());
            }
            let mut duplicate = valid.clone();
            duplicate.staged.push(StagedFile {
                guest_path: r"C:\other\HELPER.dll".into(),
                ..duplicate.staged[0].clone()
            });
            assert!(duplicate.validate().is_err());
            let mut large = dll.clone();
            large[0x98 + 56..0x98 + 60].copy_from_slice(&crate::pe::MAX_IMAGE.to_le_bytes());
            let mut over_mapped = valid.clone();
            over_mapped.staged[0].sha256 = crate::report_bundle::digest(&large);
            assert!(
                over_mapped
                    .verify_staged(&primary, &[large])
                    .unwrap_err()
                    .contains("mapped image quota")
            );
        }
    }
}

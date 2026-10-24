//! Pure external legacy persona resolution. Validation and deterministic seeds
//! are not evidence that an engine applied every configured field.
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
#[path = "fullpersona/content.rs"]
mod content;
#[path = "fullpersona/seeds.rs"]
mod seeds;
#[path = "fullpersona/validate.rs"]
mod validate;
pub use seeds::{PreparedGuestState, SeedManifest};
const MAX_DOCUMENT: usize = 32 * 1024 * 1024;
pub const VERSION: &str = "emumee-fullpersona-v1";
/// The literal legacy default configuration for the public persona command.
/// Null clock intent stays null: printing does not resolve a clock or install
/// any guest model, and does not imply coverage of every declared field.
pub fn default_document() -> &'static str {
    include_str!("fullpersona_assets/defaults.json")
}

#[derive(Debug, Error)]
#[error("Full persona {path}: {reason}")]
pub struct PersonaError {
    pub path: String,
    pub reason: String,
}
pub type Result<T> = std::result::Result<T, PersonaError>;
fn error(path: &str, reason: impl Into<String>) -> PersonaError {
    PersonaError {
        path: path.chars().take(512).collect(),
        reason: reason.into().chars().take(2048).collect(),
    }
}

fn require(ok: bool, path: &str, reason: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(error(path, reason)) }
}
fn text<'a>(value: &'a Value, path: &str) -> Result<&'a str> {
    value.as_str().ok_or_else(|| error(path, "expected text"))
}
fn object<'a>(value: &'a Value, path: &str) -> Result<&'a Map<String, Value>> {
    value
        .as_object()
        .ok_or_else(|| error(path, "expected object"))
}
fn array<'a>(value: &'a Value, path: &str, max: usize) -> Result<&'a Vec<Value>> {
    let a = value
        .as_array()
        .ok_or_else(|| error(path, "expected array"))?;
    require(a.len() <= max, path, "collection exceeds bound")?;
    Ok(a)
}
fn unsigned(value: &Value, path: &str, lo: u64, hi: u64) -> Result<u64> {
    let n = value
        .as_u64()
        .ok_or_else(|| error(path, "expected unsigned integer, not boolean/float"))?;
    require(n >= lo && n <= hi, path, "integer outside bound")?;
    Ok(n)
}
fn signed(value: &Value, path: &str, lo: i64, hi: i64) -> Result<i64> {
    let n = value
        .as_i64()
        .ok_or_else(|| error(path, "expected signed integer, not boolean/float"))?;
    require(n >= lo && n <= hi, path, "integer outside bound")?;
    Ok(n)
}
fn boolean(value: &Value, path: &str) -> Result<bool> {
    value
        .as_bool()
        .ok_or_else(|| error(path, "expected boolean"))
}
fn choices(value: &Value, path: &str, choices: &[&str]) -> Result<()> {
    require(
        choices.contains(&text(value, path)?),
        path,
        "unrecognized choice",
    )
}
fn fields(value: &Value, path: &str, required: &[&str], optional: &[&str]) -> Result<()> {
    let v = object(value, path)?;
    require(
        required.iter().all(|k| v.contains_key(*k)),
        path,
        "missing field",
    )?;
    for k in v.keys() {
        require(
            required.contains(&k.as_str()) || optional.contains(&k.as_str()),
            &format!("{path}.{k}"),
            "unknown field",
        )?;
    }
    Ok(())
}
fn bounded_text<'a>(value: &'a Value, path: &str, min: usize, max: usize) -> Result<&'a str> {
    let s = text(value, path)?;
    require(
        (min..=max).contains(&s.chars().count()) && !s.contains('\0'),
        path,
        "invalid text length or NUL",
    )?;
    Ok(s)
}
fn fold(s: &str) -> String {
    use unicode_casefold::UnicodeCaseFold;
    s.case_fold().collect()
}
fn canonical(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|e| error("$", e.to_string()))
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
/// A strict JSON reader rejects duplicate keys at every depth rather than
/// allowing the JSON map's last value silently to become an authority.
struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Strict;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("bounded persona JSON with unique object fields")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<Strict, E> {
                Err(E::custom(
                    "floating-point persona numbers are not supported",
                ))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_string<E: serde::de::Error>(
                self,
                v: String,
            ) -> std::result::Result<Strict, E> {
                Ok(Strict(v.into()))
            }
            fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut v = Vec::new();
                while let Some(Strict(item)) = a.next_element()? {
                    if v.len() >= 100000 {
                        return Err(serde::de::Error::custom("persona JSON sequence limit"));
                    }
                    v.push(item);
                }
                Ok(Strict(v.into()))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Strict, A::Error> {
                let mut v = Map::new();
                while let Some((k, Strict(value))) = a.next_entry::<String, Strict>()? {
                    if v.contains_key(&k) {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate persona field {k}"
                        )));
                    }
                    if v.len() >= 100000 {
                        return Err(serde::de::Error::custom("persona JSON object limit"));
                    }
                    v.insert(k, value);
                }
                Ok(Strict(Value::Object(v)))
            }
        }
        d.deserialize_any(Visitor)
    }
}
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockSource {
    Fixed,
    ControllerResolved,
    PersonaLiteral,
}
#[derive(Clone, Debug, Serialize)]
pub struct ClockSeed {
    pub utc_filetime: u64,
    pub source: ClockSource,
    pub source_id: String,
}
#[derive(Clone, Debug, Default)]
pub struct ResolveContext {
    pub clock_seed: Option<ClockSeed>,
}
#[derive(Clone, Debug, Serialize)]
pub struct PendingField {
    pub path: String,
    pub reason: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct SupportProjection {
    pub version: &'static str,
    pub persona: crate::persona::PersonaConfig,
    pub cpu: crate::cpu::CpuProfile,
    pub clock: ClockProjection,
    pub windows_build: u32,
    pub physical_memory_mb: u64,
    pub available_memory_mb: u64,
    pub pending: Vec<PendingField>,
    pub engine_applied: bool,
    pub seed_manifest_sha256: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct ClockProjection {
    pub utc_filetime: u64,
    pub uptime_ms: u64,
    pub utc_offset_minutes: i32,
    pub seed: ClockSeed,
}
#[derive(Debug, Serialize)]
pub struct ProjectionEnvelope {
    pub version: &'static str,
    pub sha256: String,
    pub data: SupportProjection,
}
#[derive(Debug)]
pub struct ValidatedPersona {
    input_sha256: String,
    effective: Value,
    canonical: Vec<u8>,
    sha256: String,
    projection: ProjectionEnvelope,
    seeds: SeedManifest,
    prepared: PreparedGuestState,
}
impl ValidatedPersona {
    pub fn input_sha256(&self) -> &str {
        &self.input_sha256
    }
    pub fn effective_json(&self) -> &Value {
        &self.effective
    }
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn projection(&self) -> &ProjectionEnvelope {
        &self.projection
    }
    pub fn seed_manifest(&self) -> &SeedManifest {
        &self.seeds
    }
    pub fn prepare(&self) -> PreparedGuestState {
        self.prepared.clone()
    }
    pub fn into_prepared(self) -> PreparedGuestState {
        self.prepared
    }
}
pub fn decode(bytes: &[u8], context: &ResolveContext) -> Result<ValidatedPersona> {
    require(
        bytes.len() <= MAX_DOCUMENT,
        "$",
        "persona document exceeds32MiB",
    )?;
    let Strict(overrides) = serde_json::from_slice(bytes).map_err(|e| error("$", e.to_string()))?;
    let overrides = object(&overrides, "$")?;
    let mut effective: Value =
        serde_json::from_str(include_str!("fullpersona_assets/defaults.json"))
            .map_err(|e| error("defaults", e.to_string()))?;
    let defaults = effective.clone();
    for key in overrides.keys() {
        require(
            defaults.get(key).is_some() || key == "virtual_directories",
            key,
            "unknown persona field",
        )?;
    }
    const MERGED: [&str; 10] = [
        "cpu",
        "network_adapter",
        "boot_config",
        "bitlocker",
        "kerberos",
        "domain_discovery",
        "time_service",
        "audit_policy",
        "group_policy",
        "device_registration",
    ];
    for (key, value) in overrides {
        if MERGED.contains(&key.as_str()) {
            let old = effective[key].as_object_mut().unwrap();
            let update = object(value, key)?;
            for (field, value) in update {
                require(
                    old.contains_key(field)
                        || (key == "cpu" && field == "cpuid_overrides")
                        || (key == "boot_config" && field == "code_integrity_options"),
                    &format!("{key}.{field}"),
                    "unknown persona field",
                )?;
                old.insert(field.clone(), value.clone());
            }
        } else {
            effective[key] = value.clone();
        }
    }
    if !overrides.contains_key("device_registration") && overrides.contains_key("domain") {
        effective["device_registration"]["domain_joined"] =
            json!(effective["domain"] != "WORKGROUP");
    }
    if overrides.contains_key("drivers") && !overrides.contains_key("minifilters") {
        effective["minifilters"] = json!([]);
    }
    if !overrides.contains_key("pnp_devices") {
        if effective["network_adapter"]["description"] != defaults["network_adapter"]["description"]
        {
            effective["pnp_devices"][0]["description"] =
                effective["network_adapter"]["description"].clone();
        }
        effective["pnp_devices"][0]["instance_id"] =
            effective["network_adapter"]["pnp_instance_id"].clone();
        if overrides.contains_key("driver_packages")
            && !effective["driver_packages"].as_array().is_some_and(|a| {
                a.iter().any(|p| {
                    p["published_name"]
                        .as_str()
                        .is_some_and(|v| v.eq_ignore_ascii_case("oem0.inf"))
                })
            })
        {
            effective["pnp_devices"][0]["driver"] = Value::Null;
        }
    }
    if effective["user_name"] != defaults["user_name"]
        && !overrides.contains_key("current_dir")
        && effective["current_dir"]
            .as_str()
            .is_some_and(|v| v.eq_ignore_ascii_case(r"C:\Users\Alex\Downloads"))
    {
        effective["current_dir"] = json!(format!(
            r"C:\Users\{}\Downloads",
            text(&effective["user_name"], "user_name")?
        ));
    }
    let clock = validate::clock(&effective, context)?;
    effective["clock_utc"] = json!(validate::format_filetime(clock.utc_filetime)?);
    validate::persona(&effective, &clock)?;
    if !overrides.contains_key("virtual_files") {
        effective["virtual_files"] = content::files(&effective, &defaults)?;
    }
    if !overrides.contains_key("registry_keys") {
        effective["registry_keys"] = content::registry(&effective)?;
    }
    let seeds = seeds::resolve(
        &effective,
        overrides.contains_key("registry_keys"),
        overrides.contains_key("virtual_files"),
        clock.utc_filetime,
    )?;
    let projection = content::projection(&effective, clock, &seeds)?;
    let prepared = seeds.prepare(&projection)?;
    let envelope = ProjectionEnvelope {
        version: VERSION,
        sha256: digest(&canonical(&projection)?),
        data: projection,
    };
    let canonical = canonical(&effective)?;
    let sha256 = digest(&canonical);
    Ok(ValidatedPersona {
        input_sha256: digest(bytes),
        effective,
        canonical,
        sha256,
        projection: envelope,
        seeds,
        prepared,
    })
}

#[cfg(test)]
#[path = "fullpersona/tests.rs"]
mod tests;

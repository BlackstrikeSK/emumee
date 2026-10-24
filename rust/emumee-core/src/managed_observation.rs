//! Strict closed IL-event report authority. This is not arbitrary CLR coverage.
use crate::{managed_indicator_fixture::Case, memory_observation, report_bundle};
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub const VERSION: &str = "emumee.managed-string-events.v1";
pub const MAX_EVENTS: usize = 128;
pub const MAX_SOURCE_UTF16_BYTES: u64 = 1024 * 1024;
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Literal,
    Argument,
    Return,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Scanned,
    UnpairedSurrogatePending,
    SourceLimit,
    ObserverReadBudget,
    InvalidReference,
    ScannerRefused,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub kind: Kind,
    pub source: String,
    pub reference: u32,
    pub token: Option<u32>,
    pub instruction_count: u64,
    pub utf16_units: u64,
    pub utf16_sha256: Option<String>,
    pub outcome: Outcome,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub version: String,
    pub case: Case,
    pub enabled: bool,
    pub all_managed_strings_complete: bool,
    pub all_guest_memory_complete: bool,
    pub input_sha256: String,
    pub capture_sha256: String,
    pub event_sources: Vec<String>,
    pub events_seen: u64,
    pub events_omitted: u64,
    pub events: Vec<Event>,
    pub source_utf16_bytes_observed: u64,
    pub max_source_utf16_bytes: u64,
    pub boundary_instructions: u64,
    pub boundary_method: u32,
    pub boundary_offset: u32,
    pub omitted_sources: u64,
}
pub fn utf16_hash(units: &[u16]) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    for unit in units {
        hash.update(unit.to_le_bytes());
    }
    format!("{:x}", hash.finalize())
}
// Refusal oracle for these fixed IL recipes only. It never creates a report or
// promotes an execution stop into completion; the observer supplies actual events.
fn expected_events(case: Case) -> Vec<Event> {
    use crate::managed_indicator_fixture as f;
    fn make(
        kind: Kind,
        source: String,
        reference: u32,
        units: &[u16],
        instruction_count: u64,
        token: Option<u32>,
    ) -> Event {
        Event {
            kind,
            source,
            reference,
            token,
            instruction_count,
            utf16_units: units.len() as u64,
            utf16_sha256: Some(utf16_hash(units)),
            outcome: Outcome::Scanned,
        }
    }
    fn literal(reference: u32, units: &[u16], count: u64, token: u32) -> Event {
        make(
            Kind::Literal,
            format!("managed_ldstr:0x{token:08x}"),
            reference,
            units,
            count,
            Some(token),
        )
    }
    fn call(kind: Kind, reference: u32, units: &[u16], count: u64, name: &str) -> Event {
        let label = if kind == Kind::Argument {
            "argument"
        } else {
            "return"
        };
        make(
            kind,
            format!("managed_{label}:{name}"),
            reference,
            units,
            count,
            None,
        )
    }
    match case {
        Case::Disabled => vec![],
        Case::Events | Case::Budget => {
            let prefix: Vec<_> = f::PREFIX.encode_utf16().collect();
            let suffix: Vec<_> = f::SUFFIX.encode_utf16().collect();
            let full: Vec<_> = prefix.iter().chain(&suffix).copied().collect();
            let first = 0x70000001;
            let second = first + (prefix.len() * 2 + 2) as u32;
            let third = second + (suffix.len() * 2 + 2) as u32;
            let mut events = vec![
                literal(1, &prefix, 1, first),
                literal(2, &suffix, 2, second),
            ];
            if case == Case::Events {
                events.extend([
                    call(Kind::Argument, 1, &prefix, 3, "System.String.Concat"),
                    call(Kind::Argument, 2, &suffix, 3, "System.String.Concat"),
                    call(Kind::Return, 3, &full, 3, "System.String.Concat"),
                    call(Kind::Argument, 3, &full, 4, "Echo"),
                    call(Kind::Return, 3, &full, 6, "Echo"),
                    literal(4, &full, 8, third),
                    literal(4, &full, 10, third),
                ]);
            }
            events
        }
        Case::Surrogate => {
            let units: Vec<_> = f::SURROGATE_PREFIX.encode_utf16().chain([0xd800]).collect();
            let mut event = literal(1, &units, 1, 0x70000001);
            event.outcome = Outcome::UnpairedSurrogatePending;
            vec![event]
        }
        Case::FrameworkFailure => {
            let units: Vec<_> = f::FAILURE.encode_utf16().collect();
            vec![
                literal(1, &units, 1, 0x70000001),
                call(
                    Kind::Argument,
                    1,
                    &units,
                    2,
                    "System.Convert.FromBase64String",
                ),
            ]
        }
        Case::Null => {
            let units: Vec<_> = f::NULLABLE.encode_utf16().collect();
            vec![
                literal(1, &units, 1, 0x70000001),
                call(Kind::Argument, 1, &units, 3, "System.String.Concat"),
                call(Kind::Return, 1, &units, 3, "System.String.Concat"),
            ]
        }
    }
}
pub fn valid_execution(execution: &Value) -> bool {
    let capture = &execution["memory_strings"];
    let Ok(receipt) = serde_json::from_value::<Receipt>(execution["memory_string_sources"].clone())
    else {
        return false;
    };
    let architecture = match execution["architecture"].as_str() {
        Some("x86") => crate::pe::Architecture::X86,
        Some("x64") => crate::pe::Architecture::X64,
        _ => return false,
    };
    if receipt.version != VERSION
        || receipt.enabled != receipt.case.enabled()
        || receipt.all_managed_strings_complete
        || receipt.all_guest_memory_complete
        || receipt.input_sha256 != report_bundle::digest(&receipt.case.input(architecture))
        || receipt.capture_sha256.as_str()
            != memory_observation::capture_hash(capture)
                .as_deref()
                .unwrap_or("")
        || capture["enabled"].as_bool() != Some(receipt.enabled)
        || capture["regex"] != serde_json::json!([])
        || receipt.max_source_utf16_bytes != MAX_SOURCE_UTF16_BYTES
        || receipt.source_utf16_bytes_observed > MAX_SOURCE_UTF16_BYTES
        || receipt.events.len() > MAX_EVENTS
        || receipt.events_seen < receipt.events.len() as u64
        || receipt.events_omitted != receipt.events_seen - receipt.events.len() as u64
        || receipt.events_seen > 17000
        || receipt.omitted_sources > receipt.events_seen
        || receipt.boundary_instructions
            != execution["instruction_count"].as_u64().unwrap_or(u64::MAX)
        || Some(receipt.boundary_method as u64) != execution["final_method"].as_u64()
        || Some(receipt.boundary_offset as u64) != execution["final_offset"].as_u64()
        || execution["max_instructions"].as_u64() != Some(receipt.case.budget())
        || receipt.event_sources != ["managed_ldstr", "managed_argument", "managed_return"]
    {
        return false;
    }
    if !receipt.enabled
        && (receipt.events_seen != 0
            || receipt.source_utf16_bytes_observed != 0
            || capture["scanned_bytes"] != 0
            || capture["matches"]
                .as_array()
                .is_none_or(|matches| !matches.is_empty()))
    {
        return false;
    }
    let expected: Vec<_> = expected_events(receipt.case)
        .into_iter()
        .filter(|event| event.instruction_count <= receipt.boundary_instructions)
        .collect();
    if receipt.events != expected {
        return false;
    }
    let Some(strings) = execution["heap"]["strings"].as_array() else {
        return false;
    };
    let mut reconstructed = crate::memory_strings::Capture::new(if receipt.enabled {
        crate::memory_strings::Options::default()
    } else {
        crate::memory_strings::Options::disabled()
    });
    let mut observed = 0u64;
    let mut omitted = 0u64;
    let mut previous = 0u64;
    for event in &receipt.events {
        if event.reference == 0
            || event.instruction_count < previous
            || event.instruction_count > receipt.boundary_instructions
            || event.source.len() > 1024
        {
            return false;
        }
        previous = event.instruction_count;
        let Some(string) = strings
            .iter()
            .find(|string| string["reference"].as_u64() == Some(event.reference as u64))
        else {
            return false;
        };
        // This closed profile's compiler-owned strings all fit the complete64-unit
        // heap evidence. No truncated preview is promoted into full string authority.
        let Some(preview) = string["utf16_preview"].as_array() else {
            return false;
        };
        if string["preview_truncated"] != false
            || preview.len() > 64
            || event.utf16_units != preview.len() as u64
            || string["utf16_length"].as_u64() != Some(event.utf16_units)
        {
            return false;
        }
        let Some(units) = preview
            .iter()
            .map(|unit| unit.as_u64().and_then(|unit| u16::try_from(unit).ok()))
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };
        if let Some(hash) = &event.utf16_sha256 {
            if *hash != utf16_hash(&units) {
                return false;
            }
            observed += units.len() as u64 * 2;
        } else if !matches!(
            event.outcome,
            Outcome::ObserverReadBudget | Outcome::InvalidReference
        ) {
            return false;
        }
        match event.kind {
            Kind::Literal => {
                let Some(token) = event.token else {
                    return false;
                };
                if token >> 24 != 0x70 || event.source != format!("managed_ldstr:0x{token:08x}") {
                    return false;
                }
            }
            Kind::Argument | Kind::Return => {
                if event.token.is_some() {
                    return false;
                }
                let prefix = if event.kind == Kind::Argument {
                    "managed_argument:"
                } else {
                    "managed_return:"
                };
                let Some(method) = event.source.strip_prefix(prefix) else {
                    return false;
                };
                if !matches!(
                    method,
                    "Echo" | "System.String.Concat" | "System.Convert.FromBase64String"
                ) {
                    return false;
                }
                if event.kind == Kind::Return && method == "System.Convert.FromBase64String" {
                    return false;
                }
            }
        }
        let result = reconstructed.scan_managed_utf16(&units, &event.source);
        match event.outcome {
            Outcome::Scanned if result.is_ok() => {}
            Outcome::UnpairedSurrogatePending
                if result == Err(crate::memory_strings::Error::UnpairedSurrogatePending) => {}
            _ => return false,
        }
        if event.outcome != Outcome::Scanned {
            omitted += 1;
        }
    }
    // The bounded cases never exhaust event metadata; a future wider profile
    // needs separate authority for omitted event accounting before admission.
    if receipt.events_omitted != 0
        || observed != receipt.source_utf16_bytes_observed
        || omitted != receipt.omitted_sources
    {
        return false;
    }
    if serde_json::to_value(reconstructed.into_report())
        .ok()
        .as_ref()
        != Some(capture)
    {
        return false;
    }
    capture["matches"].as_array().is_some_and(|matches| {
        matches.iter().all(|item| {
            item["encoding"] == "managed"
                && item["address"].is_null()
                && item["source"].as_str().is_some_and(|source| {
                    receipt
                        .events
                        .iter()
                        .any(|event| event.source == source && event.outcome == Outcome::Scanned)
                })
        })
    })
}

#[cfg(test)]
mod tests;

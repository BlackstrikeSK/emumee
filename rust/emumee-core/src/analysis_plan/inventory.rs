use super::*;
use serde::Serialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "format", rename_all = "snake_case")]
pub(super) enum Inspection {
    Opaque,
    Pe {
        architecture: Arch,
        kind: String,
        managed: bool,
        image_size: u32,
        entry_rva: u32,
        managed_entry: bool,
        assembly: Option<String>,
    },
    StaticMsi {
        streams: usize,
    },
    Fixtures {
        canonical_sha256: String,
        canonical_bytes: u64,
        rules: usize,
        bodies: Vec<serde_json::Value>,
    },
    PersonaDocument,
}
#[derive(Clone, Debug, Serialize)]
pub(super) struct VerifiedInput {
    pub spec: InputSpec,
    pub inspection: Inspection,
}
/// One already safely acquired buffer. No path is read by this module.
pub struct InputBytes<'a> {
    pub id: &'a str,
    pub bytes: &'a [u8],
}
/// Private, non-deserializable evidence built by hashing and inspecting actual bytes.
pub struct VerifiedInventory {
    pub(super) entries: BTreeMap<String, VerifiedInput>,
    pub(super) intent_digest: String,
    pub(super) bytes: u64,
}
impl VerifiedInventory {
    pub fn verify(inputs: &[InputSpec], buffers: &[InputBytes<'_>]) -> Result<Self> {
        demand(
            !inputs.is_empty() && inputs.len() <= MAX_INPUTS && inputs.len() == buffers.len(),
            "inventory_count",
            "inputs",
            "Missing, excessive or extra input buffers",
        )?;
        let intent_digest = identity(
            b"emumee.analysis.inventory.intent.v1\0",
            &canonical(&inputs)?,
        );
        let mut supplied = BTreeMap::new();
        for buffer in buffers {
            demand(
                supplied.insert(buffer.id, buffer.bytes).is_none(),
                "duplicate_input",
                format!("inputs.{}", buffer.id),
                "Duplicate byte buffer ID",
            )?;
        }
        let mut entries = BTreeMap::new();
        let mut total = 0u64;
        for spec in inputs {
            let field = format!("inputs.{}", spec.id);
            demand(
                id(&spec.id) && !entries.contains_key(&spec.id),
                "duplicate_input",
                &field,
                "Invalid or duplicate input ID",
            )?;
            safe_name(&spec.name, &format!("{field}.name"))?;
            let roles: BTreeSet<_> = spec.roles.iter().copied().collect();
            demand(
                !roles.is_empty() && roles.len() == spec.roles.len(),
                "input_role",
                &field,
                "Missing or duplicate role",
            )?;
            demand(
                spec.sha256.len() == 64
                    && spec
                        .sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "input_hash",
                &field,
                "Expected lowercase full SHA256",
            )?;
            demand(
                spec.size <= crate::pe::MAX_INPUT as u64,
                "input_size",
                &field,
                "Input exceeds128MiB",
            )?;
            let raw = supplied.remove(spec.id.as_str()).ok_or_else(|| {
                problem("missing_input", &field, "No actual byte buffer for input")
            })?;
            demand(
                raw.len() as u64 == spec.size && digest(raw) == spec.sha256,
                "binding_mismatch",
                &field,
                "Actual input size or full SHA256 differs",
            )?;
            total = total
                .checked_add(spec.size)
                .ok_or_else(|| problem("budget_overflow", &field, "Input byte overflow"))?;
            demand(
                total <= MAX_INVENTORY_BYTES,
                "inventory_bytes",
                "inputs",
                "Inventory exceeds256MiB physical staging bytes",
            )?;
            let inspection = if roles.contains(&InputRole::OfflineFixtures) {
                demand(
                    roles.len() == 1,
                    "input_role",
                    &field,
                    "Fixture data cannot have executable or file roles",
                )?;
                let fixtures = crate::networkfixtures::Fixtures::parse(raw).map_err(|_| {
                    problem(
                        "fixture_document",
                        &field,
                        "Invalid bounded exact replay fixture document",
                    )
                })?;
                let canonical = crate::report_bundle::bounded_json(
                    &fixtures.document(),
                    crate::networkfixtures::MAX_FILE,
                )
                .map_err(|_| problem("fixture_document", &field, "Canonical fixture bounds"))?;
                let bodies=fixtures.rules().iter().map(|rule|json!({"id":rule.id,"request_sha256":digest(&rule.request.body),"request_bytes":rule.request.body.len(),"response_sha256":digest(&rule.response.body),"response_bytes":rule.response.body.len()})).collect();
                Inspection::Fixtures {
                    canonical_sha256: digest(&canonical),
                    canonical_bytes: canonical.len() as u64,
                    rules: fixtures.rules().len(),
                    bodies,
                }
            } else if roles.contains(&InputRole::LegacyPersona) {
                demand(
                    roles.len() == 1,
                    "input_role",
                    &field,
                    "Persona document cannot have executable or file roles",
                )?;
                super::decode::strict_json(raw, MAX_PLAN_BYTES)?;
                Inspection::PersonaDocument
            } else if roles.iter().any(|r| {
                matches!(
                    r,
                    InputRole::OriginalPrimary
                        | InputRole::ExecutionPrimary
                        | InputRole::ApphostSidecar
                        | InputRole::NativeCompanion
                        | InputRole::ManagedCompanion
                        | InputRole::KernelCodeReference
                )
            }) {
                if raw.starts_with(&crate::msi::SIGNATURE) {
                    let inspected = crate::msi::inspect(raw).map_err(|_| {
                        problem(
                            "static_msi",
                            &field,
                            "Malformed bounded static compound file",
                        )
                    })?;
                    Inspection::StaticMsi {
                        streams: inspected.streams.len(),
                    }
                } else {
                    let pe = crate::pe::PeImage::parse(raw, &spec.name).map_err(|_| {
                        problem("pe_input", &field, "Malformed or unsupported bounded PE")
                    })?;
                    let mut managed_entry = false;
                    let mut assembly = None;
                    if pe.sample.managed {
                        let metadata =
                            crate::managed::Metadata::parse(raw, &spec.name).map_err(|_| {
                                problem("managed_input", &field, "Invalid bounded managed metadata")
                            })?;
                        assembly = metadata
                            .describe()
                            .map_err(|_| {
                                problem("managed_input", &field, "Invalid assembly identity")
                            })?
                            .assembly_name;
                        managed_entry = !metadata.cli.native_entry_point
                            && metadata.method(metadata.cli.entry_point).is_ok();
                    }
                    Inspection::Pe {
                        architecture: if pe.sample.architecture == crate::pe::Architecture::X64 {
                            Arch::X64
                        } else {
                            Arch::X86
                        },
                        kind: match pe.sample.kind {
                            crate::pe::Kind::Driver => "driver",
                            crate::pe::Kind::Dll => "dll",
                            crate::pe::Kind::Exe => "exe",
                        }
                        .into(),
                        managed: pe.sample.managed,
                        image_size: pe.image_size,
                        entry_rva: pe.entry_rva,
                        managed_entry,
                        assembly,
                    }
                }
            } else {
                Inspection::Opaque
            };
            entries.insert(
                spec.id.clone(),
                VerifiedInput {
                    spec: spec.clone(),
                    inspection,
                },
            );
        }
        demand(
            supplied.is_empty(),
            "extra_input",
            "inputs",
            "Unbound extra byte buffer",
        )?;
        Ok(Self {
            entries,
            intent_digest,
            bytes: total,
        })
    }
    pub fn byte_count(&self) -> u64 {
        self.bytes
    }
    pub fn input_count(&self) -> usize {
        self.entries.len()
    }
}
pub(super) fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn component(value: &str) -> bool {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.ends_with([' ', '.'])
        || value
            .chars()
            .any(|c| c < ' ' || [':', '/', '\\', '*', '?', '"', '<', '>', '|', '\0'].contains(&c))
    {
        return false;
    }
    let stem = value
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    !["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"].contains(&stem.as_str())
        && !((stem.starts_with("COM") || stem.starts_with("LPT"))
            && ["1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³"].contains(&&stem[3..]))
}
pub(super) fn safe_name(value: &str, field: &str) -> Result<()> {
    demand(
        value.len() <= 256 && component(value),
        "input_name",
        field,
        "Unsafe or oversized display basename",
    )
}
pub(super) fn package_path(value: &str, field: &str) -> Result<()> {
    demand(
        !value.is_empty()
            && value.chars().count() <= 1024
            && value.split('/').count() <= 32
            && value.split('/').all(component),
        "guest_path",
        field,
        "Unsafe, noncanonical or oversized relative guest path",
    )
}

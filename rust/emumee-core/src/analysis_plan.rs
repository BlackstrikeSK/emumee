//! Pure, bounded analysis intent and byte identity planning. Never authorizes execution.
//! General worker/configuration qualification is deliberately a separate parent gate.
mod decode;
mod driver_budget;
mod intake;
pub use driver_budget::project_driver_resources;
pub use intake::PreparedIntake;
mod inventory;
mod resolve;
mod schema;
pub use inventory::{InputBytes, VerifiedInventory};
pub use resolve::{Capabilities, ResolvedPlan, resolve, resolve_driver128_planning};
pub use schema::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
pub const MAX_PLAN_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_INVENTORY_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_INPUTS: usize = 4096;
#[derive(Debug, thiserror::Error, Serialize)]
#[error("Analysis plan {code} at {field}: {reason}")]
pub struct PlanError {
    pub code: &'static str,
    pub field: String,
    pub reason: &'static str,
}
pub type Result<T> = std::result::Result<T, PlanError>;
pub(crate) fn problem(
    code: &'static str,
    field: impl Into<String>,
    reason: &'static str,
) -> PlanError {
    PlanError {
        code,
        field: field.into().chars().take(256).collect(),
        reason,
    }
}
pub(crate) fn demand(
    ok: bool,
    code: &'static str,
    field: impl Into<String>,
    reason: &'static str,
) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(problem(code, field, reason))
    }
}
pub(crate) fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
pub(crate) fn canonical(value: &impl Serialize) -> Result<Vec<u8>> {
    crate::report_bundle::bounded_json(value, MAX_PLAN_BYTES)
        .map_err(|_| problem("metadata_limit", "$", "Canonical plan exceeds2MiB"))
}
pub(crate) fn identity(domain: &[u8], raw: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(raw);
    format!("{:x}", hash.finalize())
}
impl PlanSpec {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        let value = decode::strict_json(raw, MAX_PLAN_BYTES)?;
        decode::named_fields(&value)?;
        let mut spec: Self = serde_json::from_value(value).map_err(|_| {
            problem(
                "schema",
                "$",
                "Unknown field, missing field, wrong type or unsupported enum",
            )
        })?;
        spec.original_json_sha256 = Some(digest(raw));
        spec.decoded_sha256 = Some(identity(b"emumee.analysis.spec.v1\0", &canonical(&spec)?));
        Ok(spec)
    }
}
#[cfg(test)]
mod tests;

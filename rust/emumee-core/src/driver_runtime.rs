//! Pure runtime capture accounting/provenance. It grants no execution authority.
use serde::{Deserialize, Serialize};
use serde_json::Value;
pub const READ_LIMIT: u64 = 192 * 1024 * 1024;
pub const SCAN_LIMIT: u64 = 128 * 1024 * 1024;
pub const WORK_LIMIT: u64 = 1024 * 1024 * 1024;
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Ledger {
    pub read_bytes: u64,
    pub read_reserved_bytes: u64,
    pub scan_bytes: u64,
    pub carving_work_bytes: u64,
}
impl Ledger {
    pub fn reserve_read(&mut self, size: u64, limit: u64) -> bool {
        if limit > READ_LIMIT {
            return false;
        }
        let Some(next) = self.read_reserved_bytes.checked_add(size) else {
            return false;
        };
        if next > limit {
            return false;
        }
        self.read_reserved_bytes = next;
        true
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Marker {
    pub rva: u64,
    pub initial: u8,
    pub expected: u8,
    pub observed: Option<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub version: String,
    pub profile: String,
    pub sources: Vec<String>,
    pub input_sha256: String,
    pub initial_image_sha256: String,
    pub initial_image_phase: String,
    pub post_image_sha256: Option<String>,
    pub image_base: u64,
    pub image_bytes: u64,
    pub selected_read_complete: bool,
    pub capture_complete: bool,
    pub read_limit: u64,
    pub scan_limit: u64,
    pub work_limit: u64,
    pub retention_limit: u64,
    pub ledger: Ledger,
    pub boundary_instructions: u64,
    pub boundary_pc: u64,
    pub markers: Vec<Marker>,
    pub omissions: Vec<String>,
    pub scope: String,
}
fn hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Receipt {
    pub fn validate(&self, execution: &Value, catalog: &Value, omissions: &Value) -> bool {
        self.version == "emumee.driver-runtime.v1"
            && self.profile == "driver128_v1"
            && hash(&self.input_sha256)
            && hash(&self.initial_image_sha256)
            && self.post_image_sha256.as_deref().is_none_or(hash)
            && self.image_base > 0
            && self.image_bytes > 0
            && self.image_bytes <= SCAN_LIMIT
            && self.read_limit <= READ_LIMIT
            && self.scan_limit <= SCAN_LIMIT
            && self.work_limit <= WORK_LIMIT
            && self.retention_limit <= 256 * 1024 * 1024
            && self.ledger.read_bytes <= self.ledger.read_reserved_bytes
            && self.ledger.read_reserved_bytes <= self.read_limit
            && self.ledger.scan_bytes <= self.scan_limit
            && self.ledger.carving_work_bytes <= self.work_limit
            && self.boundary_instructions
                == execution["instruction_count"].as_u64().unwrap_or(u64::MAX)
            && self.boundary_pc == execution["final_pc"].as_u64().unwrap_or(u64::MAX)
            && self.initial_image_phase == "materialized_relocated_before_imports"
            && self.sources
                == [
                    "guest_files",
                    "registry_binary",
                    "memory_snapshots",
                    "structural_pe",
                ]
            && execution["artifacts"] == *catalog
            && execution["capture_summary"] == *omissions
            && self.markers.len() <= 2
            && self.markers.iter().all(|m| m.rva < self.image_bytes)
            && self.omissions.len() <= 32
            && self
                .omissions
                .iter()
                .all(|s| !s.is_empty() && s.len() <= 128)
            && self.scope.len() <= 512
            && (self.selected_read_complete
                || (self.post_image_sha256.is_none()
                    && self.markers.iter().all(|m| m.observed.is_none())))
            && (!self.selected_read_complete
                || (self.post_image_sha256.is_some() && self.ledger.read_bytes >= self.image_bytes))
            && (!self.capture_complete
                || (self.selected_read_complete
                    // A complete mapped-root scan must have charged at least
                    // the complete image length to the aggregate scan ledger.
                    && self.ledger.scan_bytes >= self.image_bytes
                    && self.omissions.is_empty()
                    && self.markers.iter().all(|m| m.observed == Some(m.expected))))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aggregate_read_work_is_checked_without_allocating_large_buffers() {
        let mut l = Ledger::default();
        assert!(l.reserve_read(128 * 1024 * 1024, READ_LIMIT));
        assert!(l.reserve_read(32 * 1024 * 1024, READ_LIMIT));
        assert!(!l.reserve_read(u64::MAX, READ_LIMIT));
        assert_eq!(l.read_reserved_bytes, 160 * 1024 * 1024);
        assert_eq!(l.read_bytes, 0);
        assert!(!l.reserve_read(READ_LIMIT, READ_LIMIT));
    }

    #[test]
    fn complete_mapped_snapshot_requires_full_aggregate_scan_charge() {
        let image_bytes = 4096;
        let receipt = Receipt {
            version: "emumee.driver-runtime.v1".into(),
            profile: "driver128_v1".into(),
            sources: [
                "guest_files",
                "registry_binary",
                "memory_snapshots",
                "structural_pe",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            input_sha256: "1".repeat(64),
            initial_image_sha256: "2".repeat(64),
            initial_image_phase: "materialized_relocated_before_imports".into(),
            post_image_sha256: Some("3".repeat(64)),
            image_base: 0x1000,
            image_bytes,
            selected_read_complete: true,
            capture_complete: true,
            read_limit: READ_LIMIT,
            scan_limit: SCAN_LIMIT,
            work_limit: WORK_LIMIT,
            retention_limit: 256 * 1024 * 1024,
            ledger: Ledger {
                read_bytes: image_bytes,
                read_reserved_bytes: image_bytes,
                scan_bytes: 0,
                carving_work_bytes: 0,
            },
            boundary_instructions: 7,
            boundary_pc: 0x2000,
            markers: vec![],
            omissions: vec![],
            scope: "complete mapped-root fixture".into(),
        };
        let catalog = serde_json::json!([]);
        let omissions = serde_json::json!({
            "omitted_observations": 0,
            "omitted_bytes": 0,
            "reasons": {}
        });
        let execution = serde_json::json!({
            "instruction_count": 7,
            "final_pc": 0x2000,
            "artifacts": catalog,
            "capture_summary": omissions
        });
        assert!(!receipt.validate(&execution, &catalog, &omissions));
        let mut charged = receipt;
        charged.ledger.scan_bytes = image_bytes;
        assert!(charged.validate(&execution, &catalog, &omissions));
    }
}

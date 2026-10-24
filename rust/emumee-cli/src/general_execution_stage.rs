//! Parent-owned staging for a future general kernel request.
//! This module has no launch path and cannot authorize guest execution.
use anyhow::{Context, Result, ensure};
use emumee_core::{
    analysis_plan::{MAX_INVENTORY_BYTES, MAX_PLAN_BYTES, PreparedIntake},
    general_broker_ownership::BrokerPartition,
    general_broker_private_attestation::{Claim, MAX_CLAIM},
    general_execution_commitment::{MAX_REQUEST, Request},
    general_worker_public_preflight::verify_public_view,
    report_bundle::digest,
};
use emumee_platform::windows::{create_pinned, read_regular};
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

/// All staged files remain identity-pinned through both future isolated roles.
/// The parent owns the complete intake; no worker is given private fixture bytes.
pub(crate) struct StagedGeneralExecution {
    root: PathBuf,
    intake: PreparedIntake,
    request: Request,
    request_raw: Vec<u8>,
    claim_raw: Option<Vec<u8>>,
    _pins: Vec<File>,
}

fn pinned_new(path: &Path, bytes: &[u8]) -> Result<File> {
    let mut file = create_pinned(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(file)
}

impl StagedGeneralExecution {
    /// Stage only an owned, planning-only intake in a fresh root. Publication
    /// of the strict request comes last, after the public/private split.
    pub(crate) fn stage(intake: PreparedIntake, run_id: String, root: &Path) -> Result<Self> {
        let request = Request::from_intake(&intake, run_id).map_err(anyhow::Error::msg)?;
        let request_raw = serde_json::to_vec(&request)?;
        Request::parse(&request_raw)
            .map_err(anyhow::Error::msg)?
            .verify(&intake)
            .map_err(anyhow::Error::msg)?;
        ensure!(
            request_raw.len() <= MAX_REQUEST,
            "General request exceeds 1 MiB"
        );
        let split = BrokerPartition::from_intake(&intake).map_err(anyhow::Error::msg)?;
        let claim_raw = if split.fixture().is_some() {
            let claim =
                Claim::from_verified_request(&request_raw, &intake).map_err(anyhow::Error::msg)?;
            let raw = serde_json::to_vec(&claim)?;
            ensure!(
                raw.len() <= MAX_CLAIM,
                "General private claim exceeds 4096 bytes"
            );
            Some(raw)
        } else {
            None
        };

        let root = std::path::absolute(root)?;
        std::fs::create_dir(&root).context("General execution stage root must be fresh")?;
        let root = root.canonicalize()?;
        let control = root.join("control");
        let private = root.join("private");
        std::fs::create_dir(&control)?;
        std::fs::create_dir(control.join("inputs"))?;
        std::fs::create_dir(&private)?;
        let mut pins = Vec::with_capacity(intake.slots().len() + 5);
        pins.push(pinned_new(&control.join("plan.json"), intake.raw_plan())?);
        for (index, bytes) in split.worker_slots().iter().enumerate() {
            if let Some(bytes) = bytes {
                pins.push(pinned_new(
                    &control.join("inputs").join(format!("{index:04}.bin")),
                    bytes,
                )?);
            }
        }
        if let Some((_, fixture, _)) = split.fixture() {
            pins.push(pinned_new(&private.join("http-fixtures.json"), fixture)?);
            pins.push(pinned_new(
                &private.join("claim.json"),
                claim_raw
                    .as_deref()
                    .context("General private claim absent")?,
            )?);
            pins.push(pinned_new(&private.join("network-broker.journal"), b"")?);
        }
        pins.push(pinned_new(&control.join("request.json"), &request_raw)?);
        let staged = Self {
            root,
            intake,
            request,
            request_raw,
            claim_raw,
            _pins: pins,
        };
        staged.verify_prelaunch()?;
        Ok(staged)
    }

    /// Verify physical files before any grants or launch. This is a parent
    /// readback only; a later contained worker and broker must each verify
    /// their own visible bytes and produce their own bounded witnesses.
    pub(crate) fn verify_prelaunch(&self) -> Result<()> {
        let control = self.root.join("control");
        let private = self.root.join("private");
        let request_raw =
            read_regular(&control.join("request.json"), MAX_REQUEST, Some(&self.root))?;
        ensure!(
            request_raw == self.request_raw,
            "General staged request changed"
        );
        let request = Request::parse(&request_raw).map_err(anyhow::Error::msg)?;
        ensure!(
            request == self.request,
            "General staged request identity changed"
        );
        let raw_plan = read_regular(&control.join("plan.json"), MAX_PLAN_BYTES, Some(&self.root))?;
        ensure!(
            raw_plan == self.intake.raw_plan(),
            "General staged plan changed"
        );
        let split = BrokerPartition::from_intake(&self.intake).map_err(anyhow::Error::msg)?;
        let mut total = 0u64;
        let mut worker_slots = Vec::with_capacity(split.worker_slots().len());
        for (index, expected) in split.worker_slots().iter().enumerate() {
            let path = control.join("inputs").join(format!("{index:04}.bin"));
            if let Some(expected) = expected {
                total = total
                    .checked_add(expected.len() as u64)
                    .context("General public slot total overflow")?;
                ensure!(
                    total <= MAX_INVENTORY_BYTES,
                    "General public slots exceed 256 MiB"
                );
                let actual = read_regular(&path, expected.len(), Some(&self.root))?;
                ensure!(actual == *expected, "General staged public slot changed");
                worker_slots.push(Some(actual));
            } else {
                ensure!(
                    !path.exists(),
                    "General private fixture appeared in worker slots"
                );
                worker_slots.push(None);
            }
        }
        let view = worker_slots
            .iter()
            .map(|value| value.as_deref())
            .collect::<Vec<_>>();
        split
            .verify_worker_view(&view)
            .map_err(anyhow::Error::msg)?;
        let public = verify_public_view(&request_raw, &digest(&request_raw), &raw_plan, &view)
            .map_err(anyhow::Error::msg)?;
        ensure!(
            !public.guest_admission && !public.guest_executed,
            "General public preflight claimed guest execution"
        );
        match (split.fixture(), self.claim_raw.as_deref()) {
            (Some((_, expected, _)), Some(expected_claim)) => {
                let actual = read_regular(
                    &private.join("http-fixtures.json"),
                    expected.len(),
                    Some(&self.root),
                )?;
                split
                    .verify_broker_fixture(Some(&actual))
                    .map_err(anyhow::Error::msg)?;
                let claim_raw =
                    read_regular(&private.join("claim.json"), MAX_CLAIM, Some(&self.root))?;
                ensure!(
                    claim_raw == expected_claim,
                    "General staged private claim changed"
                );
                let claim = Claim::parse(&claim_raw).map_err(anyhow::Error::msg)?;
                claim
                    .verify_against_request(&request_raw, &self.intake)
                    .map_err(anyhow::Error::msg)?;
                let private_receipt = claim
                    .inspect(&claim_raw, &actual)
                    .map_err(anyhow::Error::msg)?;
                ensure!(
                    !private_receipt.contained_broker_witness
                        && !private_receipt.journal_start_observed
                        && !private_receipt.guest_admission
                        && !private_receipt.guest_executed,
                    "General parent inspection claimed broker containment or guest execution"
                );
                let journal =
                    read_regular(&private.join("network-broker.journal"), 0, Some(&self.root))?;
                ensure!(
                    journal.is_empty(),
                    "General private journal was not empty before launch"
                );
            }
            (None, None) => ensure!(
                !private.join("http-fixtures.json").exists()
                    && !private.join("claim.json").exists()
                    && !private.join("network-broker.journal").exists(),
                "General deny request staged private broker data"
            ),
            _ => anyhow::bail!("General private fixture and claim disagree"),
        }
        Ok(())
    }

    pub(crate) fn request_sha256(&self) -> String {
        digest(&self.request_raw)
    }
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
    pub(crate) fn request(&self) -> &Request {
        &self.request
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use emumee_core::{analysis_plan::Arch, plan_runtime::Case, report_bundle::digest};
    use serde_json::{Value, json};

    fn root(label: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "emumee-general-private-{label}-{}-{nonce}",
            std::process::id()
        ))
    }
    fn generated(private: bool) -> PreparedIntake {
        let mut kernel = Case::Kernel17.generated(Arch::X64).unwrap();
        let mut plan: Value = serde_json::from_slice(&kernel.plan).unwrap();
        plan["target"]["service_name"] = json!("TestDrv");
        if private {
            let fixture = Case::NativeReplay.generated(Arch::X64).unwrap().fixtures;
            plan["inputs"].as_array_mut().unwrap().push(json!({
                "id":"offline","name":"offline.json","roles":["offline_fixtures"],
                "mount":{"kind":"not_mounted"},"size":fixture.len(),"sha256":digest(&fixture)
            }));
            plan["network"] = json!({"kind":"offline_exact_replay","input":"offline"});
            kernel.inputs.push(fixture);
        }
        PreparedIntake::prepare(serde_json::to_vec(&plan).unwrap(), kernel.inputs).unwrap()
    }

    fn cleanup_generated_root(root: &Path) {
        let temp = std::env::temp_dir().canonicalize().unwrap();
        let resolved = root.canonicalize().unwrap();
        assert_eq!(resolved.parent(), Some(temp.as_path()));
        assert!(
            resolved
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("emumee-general-private-"))
        );
        std::fs::remove_dir_all(resolved).unwrap();
    }

    #[test]
    fn generated_replay_stages_private_bytes_only_under_private_and_detects_tamper() {
        let root = root("replay");
        let stage = StagedGeneralExecution::stage(
            generated(true),
            "20261019T120000Z-12345678".into(),
            &root,
        )
        .unwrap();
        assert_eq!(stage.request().operation, "commit_only");
        assert!(!stage.request().execution_authorized);
        assert_eq!(stage.request_sha256().len(), 64);
        assert!(!root.join("control/inputs/0001.bin").exists());
        assert!(root.join("private/http-fixtures.json").exists());
        assert!(root.join("private/claim.json").exists());
        assert!(root.join("private/network-broker.journal").exists());
        stage.verify_prelaunch().unwrap();
        std::fs::write(root.join("private/http-fixtures.json"), b"bad").unwrap();
        assert!(stage.verify_prelaunch().is_err());
        drop(stage);
        cleanup_generated_root(&root);
    }

    #[test]
    fn generated_deny_stages_no_private_broker_files() {
        let root = root("deny");
        let stage = StagedGeneralExecution::stage(
            generated(false),
            "20261019T120000Z-12345678".into(),
            &root,
        )
        .unwrap();
        stage.verify_prelaunch().unwrap();
        assert!(!root.join("private/http-fixtures.json").exists());
        assert!(!root.join("private/claim.json").exists());
        drop(stage);
        cleanup_generated_root(&root);
    }
}

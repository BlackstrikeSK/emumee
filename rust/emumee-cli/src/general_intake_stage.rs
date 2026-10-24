//! Parent-only staging of exact verified general-plan bytes. No launch API uses this type.
use anyhow::{Context, Result, ensure};
use emumee_core::{
    analysis_plan::{MAX_INVENTORY_BYTES, MAX_PLAN_BYTES, PreparedIntake},
    general_plan_admission::{MAX_REQUEST, Request},
};
use emumee_platform::windows::{create_pinned, read_regular};
use std::{
    fs::File,
    io::Write,
    path::{Path, PathBuf},
};

/// Owns the source buffers and keeps staged files pinned until the parent drops it.
/// It cannot authorize guest execution or be decoded from a JSON receipt.
pub(crate) struct StagedGeneralIntake {
    root: PathBuf,
    intake: PreparedIntake,
    request: Request,
    request_raw: Vec<u8>,
    _pins: Vec<File>,
}

fn pinned_new(path: &Path, bytes: &[u8]) -> Result<File> {
    let mut file = create_pinned(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(file)
}

impl StagedGeneralIntake {
    /// Stage only an already-owned, planning-only intake into a fresh parent root.
    /// The commitment is published last, after plan and opaque physical slots.
    pub(crate) fn stage(intake: PreparedIntake, run_id: String, root: &Path) -> Result<Self> {
        let request = Request::from_intake(&intake, run_id).map_err(anyhow::Error::msg)?;
        let request_raw = serde_json::to_vec(&request)?;
        Request::parse(&request_raw)
            .map_err(anyhow::Error::msg)?
            .verify(&intake)
            .map_err(anyhow::Error::msg)?;
        ensure!(
            request_raw.len() <= MAX_REQUEST,
            "General admission request exceeds1MiB"
        );

        let root = std::path::absolute(root)?;
        std::fs::create_dir(&root).context("General stage root must be fresh")?;
        let root = root.canonicalize()?;
        let control = root.join("control");
        std::fs::create_dir(&control)?;
        std::fs::create_dir(control.join("inputs"))?;
        let mut pins = Vec::with_capacity(intake.slots().len() + 2);
        pins.push(pinned_new(&control.join("plan.json"), intake.raw_plan())?);
        for (index, (_, bytes)) in intake.slots().enumerate() {
            pins.push(pinned_new(
                &control.join("inputs").join(format!("{index:04}.bin")),
                bytes,
            )?);
        }
        pins.push(pinned_new(&control.join("request.json"), &request_raw)?);
        let staged = Self {
            root,
            intake,
            request,
            request_raw,
            _pins: pins,
        };
        staged.verify_staged()?;
        Ok(staged)
    }

    /// Read back every file from the actual stage root. A later worker must
    /// independently perform the same admission under offline containment.
    pub(crate) fn verify_staged(&self) -> Result<()> {
        let control = self.root.join("control");
        let request_raw =
            read_regular(&control.join("request.json"), MAX_REQUEST, Some(&self.root))?;
        ensure!(
            request_raw == self.request_raw,
            "Staged general request changed"
        );
        let request = Request::parse(&request_raw).map_err(anyhow::Error::msg)?;
        // Strict parse plus exact raw-byte comparison above binds this request
        // to the original commitment without relying on JSON field order.

        let raw_plan = read_regular(&control.join("plan.json"), MAX_PLAN_BYTES, Some(&self.root))?;
        ensure!(
            raw_plan == self.intake.raw_plan(),
            "Staged general plan changed"
        );
        let mut total = 0u64;
        let mut inputs = Vec::with_capacity(self.intake.slots().len());
        for (index, (_, expected)) in self.intake.slots().enumerate() {
            ensure!(
                expected.len() <= emumee_core::pe::MAX_INPUT,
                "General slot exceeds128MiB"
            );
            total = total
                .checked_add(expected.len() as u64)
                .context("General slot total overflow")?;
            ensure!(total <= MAX_INVENTORY_BYTES, "General slots exceed256MiB");
            let path = control.join("inputs").join(format!("{index:04}.bin"));
            let actual = read_regular(&path, expected.len(), Some(&self.root))?;
            ensure!(actual == expected, "Staged general slot bytes changed");
            inputs.push(actual);
        }
        let readback = PreparedIntake::prepare(raw_plan, inputs)?;
        request.verify(&readback).map_err(anyhow::Error::msg)?;
        ensure!(
            !readback.resolved().executable(),
            "General stage became executable"
        );
        Ok(())
    }

    pub(crate) fn request_sha256(&self) -> String {
        emumee_core::report_bundle::digest(&self.request_raw)
    }

    pub(crate) fn request(&self) -> &Request {
        &self.request
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
}

/// One safe source read and one owned stage; no manifest or inspection JSON is
/// accepted as authority, and no worker is launched.
pub(crate) fn acquire_and_stage(
    plan_path: &Path,
    staged_input_root: &Path,
    output_root: &Path,
    run_id: String,
) -> Result<StagedGeneralIntake> {
    let intake = super::plan_reader::acquire(plan_path, staged_input_root)?;
    StagedGeneralIntake::stage(intake, run_id, output_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use emumee_core::{analysis_plan::Arch, plan_runtime::Case};
    use std::io::{Seek, SeekFrom};

    fn root(label: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "emumee-generated-general-stage-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn generated_two_slot_stage_keeps_exact_order_and_refuses_tamper() {
        let generated = Case::NativeA.generated(Arch::X64).unwrap();
        let intake = PreparedIntake::prepare(generated.plan, generated.inputs).unwrap();
        let root = root("slots");
        let stage =
            StagedGeneralIntake::stage(intake, "20261019T101500Z-00000001".into(), &root).unwrap();
        assert_eq!(stage.request.slots[0].id, "primary");
        assert_eq!(stage.request.slots[1].id, "guest-data");
        assert_eq!(stage.request.operation, "verify_only");
        assert_eq!(stage.request_sha256().len(), 64);
        stage.verify_staged().unwrap();

        let path = root.join("control/inputs/0001.bin");
        let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"X").unwrap();
        file.sync_all().unwrap();
        assert!(stage.verify_staged().is_err());
        drop(file);
        drop(stage);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn generated_request_commitment_tamper_is_refused() {
        let generated = Case::NativeA.generated(Arch::X64).unwrap();
        let intake = PreparedIntake::prepare(generated.plan, generated.inputs).unwrap();
        let root = root("request");
        let stage =
            StagedGeneralIntake::stage(intake, "20261019T101500Z-00000002".into(), &root).unwrap();
        std::fs::write(root.join("control/request.json"), b"{}").unwrap();
        assert!(stage.verify_staged().is_err());
        drop(stage);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn generated_source_is_read_once_before_parent_stage() {
        let generated = Case::NativeA.generated(Arch::X64).unwrap();
        let source = root("source");
        let output = root("copied");
        std::fs::create_dir(&source).unwrap();
        std::fs::create_dir(source.join("inputs")).unwrap();
        let plan_path = source.join("plan.json");
        std::fs::write(&plan_path, &generated.plan).unwrap();
        for (index, bytes) in generated.inputs.iter().enumerate() {
            std::fs::write(source.join("inputs").join(format!("{index:04}.bin")), bytes).unwrap();
        }
        let stage = acquire_and_stage(
            &plan_path,
            &source,
            &output,
            "20261019T101500Z-00000003".into(),
        )
        .unwrap();
        std::fs::write(source.join("inputs/0001.bin"), b"changed-source").unwrap();
        stage.verify_staged().unwrap();
        assert_eq!(stage.intake.slots().nth(1).unwrap().1, b"DATA");
        drop(stage);
        std::fs::remove_dir_all(source).unwrap();
        std::fs::remove_dir_all(output).unwrap();
    }
}

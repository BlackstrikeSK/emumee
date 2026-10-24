//! Contained re-acquisition of a general plan. This role never opens a broker
//! connection or executes guest bytes.
use super::save_new;
use anyhow::{Context, Result, ensure};
use emumee_core::{
    analysis_plan::{MAX_PLAN_BYTES, PlanSpec, PreparedIntake},
    general_plan_admission::{MAX_REQUEST, Request},
    report_bundle::digest,
};
use emumee_platform::windows::{prepare_worker, read_regular};
use serde_json::json;
use std::path::Path;

fn admit_staged(root: &Path, expected_sha256: &str) -> Result<(Request, PreparedIntake)> {
    let control = root.join("control");
    let request_raw = read_regular(&control.join("request.json"), MAX_REQUEST, Some(&control))?;
    ensure!(
        digest(&request_raw) == expected_sha256,
        "General admission transport digest changed"
    );
    let request = Request::parse(&request_raw).map_err(anyhow::Error::msg)?;
    let plan = read_regular(&control.join("plan.json"), MAX_PLAN_BYTES, Some(&control))?;
    ensure!(
        digest(&plan) == request.raw_plan_sha256,
        "General admission raw plan changed"
    );
    let spec = PlanSpec::decode(&plan)?;
    ensure!(
        spec.inputs.len() == request.slots.len(),
        "General admission physical slot count changed"
    );
    let mut inputs = Vec::with_capacity(request.slots.len());
    for (index, (declared, committed)) in spec.inputs.iter().zip(&request.slots).enumerate() {
        ensure!(
            declared.id == committed.id
                && declared.size == committed.size
                && declared.sha256 == committed.sha256,
            "General admission declared slot commitment changed"
        );
        let slot = control.join("inputs").join(format!("{index:04}.bin"));
        let bytes = read_regular(&slot, usize::try_from(committed.size)?, Some(&control))
            .with_context(|| format!("General admission physical slot {index:04} unreadable"))?;
        ensure!(
            bytes.len() as u64 == committed.size && digest(&bytes) == committed.sha256,
            "General admission physical slot bytes changed"
        );
        inputs.push(bytes);
    }
    // Independently decode, inspect and resolve actual re-acquired bytes; a
    // parent JSON inspection report is never accepted as authority.
    let intake = PreparedIntake::prepare(plan, inputs).map_err(anyhow::Error::msg)?;
    request.verify(&intake).map_err(anyhow::Error::msg)?;
    Ok((request, intake))
}

pub(crate) fn execute(root: &Path, expected_sha256: &str) -> Result<()> {
    let containment = prepare_worker()?;
    let root = std::path::absolute(root)?;
    let worker = root.join("worker");
    let witness = serde_json::to_vec(&containment)?;
    save_new(&worker.join("worker-containment.json"), &witness)?;
    let result = (|| -> Result<()> {
        let (request, intake) = admit_staged(&root, expected_sha256)?;
        let slot_bytes = request
            .slots
            .iter()
            .try_fold(0u64, |total, slot| total.checked_add(slot.size))
            .context("General admission slot byte overflow")?;
        let receipt = json!({
            "schema":1,
            "profile":request.profile,
            "operation":request.operation,
            "role":"general_plan_verify_only_worker",
            "run_id":request.run_id,
            "request_sha256":expected_sha256,
            "raw_plan_sha256":request.raw_plan_sha256,
            "resolved_plan_sha256":intake.resolved().sha256(),
            "resolved_request_sha256":intake.resolved().request_sha256(),
            "slots":request.slots,
            "slot_bytes":slot_bytes,
            "containment_sha256":digest(&witness),
            "source_tree_sha256":env!("EMUMEE_BUILD_SOURCE_SHA256"),
            "engine_applied":false,
            "broker_connected":false,
            "guest_executed":false,
        });
        let raw = serde_json::to_vec(&receipt)?;
        ensure!(
            raw.len() <= MAX_REQUEST + 4096,
            "General admission receipt bound"
        );
        save_new(&worker.join("general-plan-admission.json"), &raw)?;
        Ok(())
    })();
    if let Err(error) = &result {
        let _ = save_new(
            &worker.join("worker-error.txt"),
            format!("{error:#}")
                .chars()
                .take(8192)
                .collect::<String>()
                .as_bytes(),
        );
    }
    result.context("General verify-only worker admission failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use emumee_core::{analysis_plan::Arch, plan_runtime::Case};
    use std::{
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{SystemTime, UNIX_EPOCH},
    };
    static NEXT: AtomicU64 = AtomicU64::new(0);

    struct GeneratedRoot(PathBuf);
    impl GeneratedRoot {
        fn new() -> Self {
            let stamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "emumee-general-admission-{}-{stamp}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::create_dir(path.join("control")).unwrap();
            std::fs::create_dir(path.join("control/inputs")).unwrap();
            Self(path)
        }
    }
    impl Drop for GeneratedRoot {
        fn drop(&mut self) {
            for name in [
                "control/request.json",
                "control/plan.json",
                "control/inputs/0000.bin",
                "control/inputs/0001.bin",
            ] {
                let _ = std::fs::remove_file(self.0.join(name));
            }
            let _ = std::fs::remove_dir(self.0.join("control/inputs"));
            let _ = std::fs::remove_dir(self.0.join("control"));
            let _ = std::fs::remove_dir(&self.0);
        }
    }

    #[test]
    fn generated_worker_readback_refuses_swap_plan_and_transport_tampering() {
        let root = GeneratedRoot::new();
        let generated = Case::NativeA.generated(Arch::X64).unwrap();
        let intake =
            PreparedIntake::prepare(generated.plan.clone(), generated.inputs.clone()).unwrap();
        let request = Request::from_intake(&intake, "20261019T120000Z-12345678".into()).unwrap();
        let request_raw = serde_json::to_vec(&request).unwrap();
        std::fs::write(root.0.join("control/request.json"), &request_raw).unwrap();
        std::fs::write(root.0.join("control/plan.json"), &generated.plan).unwrap();
        for (index, bytes) in generated.inputs.iter().enumerate() {
            std::fs::write(root.0.join(format!("control/inputs/{index:04}.bin")), bytes).unwrap();
        }
        let expected = digest(&request_raw);
        let (observed, prepared) = admit_staged(&root.0, &expected).unwrap();
        observed.verify(&prepared).unwrap();
        assert!(!prepared.resolved().executable());
        let first = root.0.join("control/inputs/0000.bin");
        let second = root.0.join("control/inputs/0001.bin");
        std::fs::write(&first, &generated.inputs[1]).unwrap();
        std::fs::write(&second, &generated.inputs[0]).unwrap();
        assert!(admit_staged(&root.0, &expected).is_err());
        std::fs::write(&first, &generated.inputs[0]).unwrap();
        std::fs::write(&second, &generated.inputs[1]).unwrap();
        let mut changed = generated.plan.clone();
        changed.push(b' ');
        std::fs::write(root.0.join("control/plan.json"), changed).unwrap();
        assert!(admit_staged(&root.0, &expected).is_err());
        std::fs::write(root.0.join("control/plan.json"), &generated.plan).unwrap();
        let mut changed = request_raw.clone();
        changed.push(b' ');
        std::fs::write(root.0.join("control/request.json"), changed).unwrap();
        assert!(admit_staged(&root.0, &expected).is_err());
    }
}

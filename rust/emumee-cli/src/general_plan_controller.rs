//! Parent proof for contained verify-only general-plan admission.
//! No broker is started and no guest or engine entry point is called.
use super::{
    general_intake_stage::{self, StagedGeneralIntake},
    worker::{VerifiedBundle, launch_general_verify, save_new, verified_bundle},
};
use anyhow::{Context, Result, ensure};
use emumee_core::{
    analysis_fixture,
    analysis_plan::{Arch, PreparedIntake},
    general_plan_admission::{OPERATION, PROFILE},
    plan_runtime::Case,
    report_bundle::{bounded_json, digest},
};
use emumee_platform::windows::{WorkerExit, WorkerStop, read_regular};
use serde_json::{Value, json};
use std::{ffi::OsString, path::Path};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GeneratedFault {
    SwapSlots,
    TamperSlot,
    ChangeRequest,
    ChangePlan,
    MissingSlot,
}

impl GeneratedFault {
    pub(crate) fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "swap-slots" => Self::SwapSlots,
            "tamper-slot" => Self::TamperSlot,
            "change-request" => Self::ChangeRequest,
            "change-plan" => Self::ChangePlan,
            "missing-slot" => Self::MissingSlot,
            _ => anyhow::bail!("Unknown generated general admission fault"),
        })
    }
    fn name(self) -> &'static str {
        match self {
            Self::SwapSlots => "swap-slots",
            Self::TamperSlot => "tamper-slot",
            Self::ChangeRequest => "change-request",
            Self::ChangePlan => "change-plan",
            Self::MissingSlot => "missing-slot",
        }
    }
    fn refusal_evidence(self) -> &'static str {
        match self {
            Self::ChangeRequest => "General admission transport digest changed",
            Self::ChangePlan => "General admission raw plan changed",
            Self::SwapSlots | Self::TamperSlot | Self::MissingSlot => {
                "General admission physical slot"
            }
        }
    }
}

fn verify_output_location(bundle: &Path, output: &Path) -> Result<()> {
    // The stage creates its root. Check its canonical parent first, before
    // any staged bytes or ACLs can be placed inside the frozen package.
    let output = std::path::absolute(output)?;
    let parent = output
        .parent()
        .context("General output parent absent")?
        .canonicalize()?;
    let destination = parent.join(output.file_name().context("General output name absent")?);
    ensure!(
        !destination.starts_with(bundle) && !bundle.starts_with(&destination),
        "General output must be outside the frozen bundle"
    );
    Ok(())
}

fn run_id() -> Result<String> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let (id, _) =
        analysis_fixture::identity(now.as_secs(), now.subsec_nanos() ^ std::process::id())
            .map_err(anyhow::Error::msg)?;
    Ok(id)
}

fn inject_generated_fault(root: &Path, fault: GeneratedFault) -> Result<()> {
    let control = root.join("control");
    let first = control.join("inputs/0000.bin");
    let second = control.join("inputs/0001.bin");
    match fault {
        GeneratedFault::SwapSlots => {
            let a = read_regular(&first, emumee_core::pe::MAX_INPUT, Some(root))?;
            let b = read_regular(&second, emumee_core::pe::MAX_INPUT, Some(root))?;
            std::fs::write(first, b)?;
            std::fs::write(second, a)?;
        }
        GeneratedFault::TamperSlot => {
            use std::io::{Seek, SeekFrom, Write};
            let mut file = std::fs::OpenOptions::new().write(true).open(second)?;
            file.seek(SeekFrom::Start(0))?;
            file.write_all(b"X")?;
            file.sync_all()?;
        }
        GeneratedFault::ChangeRequest => std::fs::write(control.join("request.json"), b"{}")?,
        GeneratedFault::ChangePlan => std::fs::write(control.join("plan.json"), b"{}")?,
        GeneratedFault::MissingSlot => std::fs::remove_file(second)?,
    }
    Ok(())
}

fn verify_lifecycle_receipts(
    job: &Value,
    worker_stop: &Value,
    worker_exit: &Value,
    stopped: &WorkerExit,
) -> Result<()> {
    let peak = job["peak_process_memory_bytes"]
        .as_u64()
        .context("General worker peak memory missing")?;
    ensure!(
        peak > 0 && peak <= 1024u64 * 1024 * 1024,
        "General worker peak exceeds profile"
    );
    let limits = json!({
        "max_bytes":320u64 * 1024 * 1024,
        "max_entries":4200,
        "max_directories":8,
        "max_depth":4,
    });
    ensure!(
        *job == json!({
            "schema":1,"profile":"general_verify_1024_v1",
            "process_memory_bytes":1024u64 * 1024 * 1024,
            "active_process_limit":1,"network_capabilities":0,
            "peak_process_memory_bytes":peak,"output_limits":limits,
            "cleanup":"restored"
        }),
        "General worker job/cleanup receipt differs"
    );
    ensure!(
        *worker_stop
            == json!({
                "schema":1,"worker":stopped,"output_limits":limits,"cleanup":"restored"
            }),
        "General worker stop/cleanup receipt differs"
    );
    ensure!(
        *worker_exit
            == json!({
                "exit_code":stopped.exit_code,
                "exit_code_hex":format!("0x{:08x}",stopped.exit_code),
                "cleanup":"restored"
            }),
        "General worker exit/cleanup receipt differs"
    );
    Ok(())
}

pub(crate) fn verify_plan(
    plan_path: &Path,
    staged_input_root: &Path,
    output_root: &Path,
) -> Result<Value> {
    let verified = verified_bundle()?;
    verify_output_location(&verified.path, output_root)?;
    let stage = general_intake_stage::acquire_and_stage(
        plan_path,
        staged_input_root,
        output_root,
        run_id()?,
    )?;
    run_staged(&verified, stage, None)
}

pub(crate) fn verify_fixture(output_root: &Path, fault: Option<GeneratedFault>) -> Result<Value> {
    let verified = verified_bundle()?;
    verify_output_location(&verified.path, output_root)?;
    let generated = Case::NativeA
        .generated(Arch::X64)
        .map_err(anyhow::Error::msg)?;
    let intake = PreparedIntake::prepare(generated.plan, generated.inputs)?;
    let stage = StagedGeneralIntake::stage(intake, run_id()?, output_root)?;
    run_staged(&verified, stage, fault)
}

fn run_staged(
    verified: &VerifiedBundle,
    stage: StagedGeneralIntake,
    fault: Option<GeneratedFault>,
) -> Result<Value> {
    let root = stage.root().to_path_buf();
    let request = stage.request().clone();
    let request_hash = stage.request_sha256();
    std::fs::create_dir(root.join("worker"))?;
    // Generated negative controls deliberately release pinned handles before
    // mutation. The positive path keeps every exact staged file pinned.
    let positive_stage = if let Some(fault) = fault {
        drop(stage);
        inject_generated_fault(&root, fault)?;
        None
    } else {
        Some(stage)
    };
    let stopped = launch_general_verify(
        verified,
        &root,
        &[
            OsString::from("--general-plan-verify"),
            root.as_os_str().to_owned(),
            OsString::from(&request_hash),
        ],
    );
    let checked = (|| -> Result<(Value, Option<String>)> {
        let stopped = stopped.as_ref().map_err(|e| anyhow::anyhow!("{e:#}"))?;
        ensure!(
            stopped.reason == WorkerStop::Exited,
            "General worker stopped abnormally"
        );
        let witness = read_regular(
            &root.join("worker/worker-containment.json"),
            4096,
            Some(&root),
        )?;
        let containment: Value = serde_json::from_slice(&witness)?;
        ensure!(
            containment["app_container"] == true
                && containment["job_object"] == true
                && containment["child_process_blocked"] == true
                && containment["network_capabilities"] == 0,
            "General worker containment witness invalid"
        );
        let job_raw = read_regular(&root.join("general-job-profile.json"), 8192, Some(&root))?;
        let job: Value = serde_json::from_slice(&job_raw)?;
        ensure!(
            !root.join("broker").exists()
                && !root.join("engine-report.json").exists()
                && !root.join("artifacts").exists(),
            "General verify-only role created execution or broker output"
        );
        let worker_stop: Value = serde_json::from_slice(&read_regular(
            &root.join("worker-stop.json"),
            8192,
            Some(&root),
        )?)?;
        let worker_exit: Value = serde_json::from_slice(&read_regular(
            &root.join("worker-exit.json"),
            4096,
            Some(&root),
        )?)?;
        verify_lifecycle_receipts(&job, &worker_stop, &worker_exit, stopped)?;
        let witness_hash = digest(&witness);
        if let Some(fault) = fault {
            ensure!(stopped.exit_code == 2, "Generated refusal exit differs");
            ensure!(
                !root.join("worker/general-plan-admission.json").exists(),
                "Refused general plan produced an admission receipt"
            );
            let error = read_regular(&root.join("worker/worker-error.txt"), 8192, Some(&root))?;
            let error = std::str::from_utf8(&error)?;
            ensure!(
                error.contains(fault.refusal_evidence()),
                "Generated refusal reason differs"
            );
            return Ok((
                json!({
                    "schema":1,"profile":PROFILE,"operation":OPERATION,
                    "status":"verified_refusal","fixture":"native-a","fault":fault.name(),
                    "run_id":request.run_id,"request_sha256":request_hash,
                    "source_tree_sha256":verified.receipt["source_tree_sha256"],
                    "controller_sha256":verified.receipt["controller_sha256"],
                    "worker_sha256":verified.receipt["worker_sha256"],
                    "containment_sha256":witness_hash,"job_profile_sha256":digest(&job_raw),
                    "worker_stop":stopped,
                    "worker_error_sha256":digest(error.as_bytes()),
                    "admission_sha256":null,"cleanup":"restored",
                    "engine_applied":false,"broker_connected":false,"guest_executed":false,
                    "unpacking_confirmed":false
                }),
                None,
            ));
        }
        ensure!(
            stopped.exit_code == 0,
            "General worker did not exit successfully"
        );
        positive_stage
            .as_ref()
            .context("Positive general stage was not retained")?
            .verify_staged()?;
        ensure!(
            !root.join("worker/worker-error.txt").exists(),
            "Successful general admission wrote an error"
        );
        let receipt_raw = read_regular(
            &root.join("worker/general-plan-admission.json"),
            1024 * 1024 + 4096,
            Some(&root),
        )?;
        let receipt: Value = serde_json::from_slice(&receipt_raw)?;
        let slots_bytes = request.slots.iter().try_fold(0u64, |total, slot| {
            total
                .checked_add(slot.size)
                .context("General slot sum overflow")
        })?;
        let expected = json!({
            "schema":1,"profile":PROFILE,"operation":OPERATION,
            "role":"general_plan_verify_only_worker","run_id":request.run_id,
            "request_sha256":request_hash,"raw_plan_sha256":request.raw_plan_sha256,
            "resolved_plan_sha256":request.resolved_plan_sha256,
            "resolved_request_sha256":request.resolved_request_sha256,
            "slots":request.slots,"slot_bytes":slots_bytes,
            "containment_sha256":witness_hash,
            "source_tree_sha256":verified.receipt["source_tree_sha256"],
            "engine_applied":false,"broker_connected":false,"guest_executed":false,
        });
        ensure!(
            receipt == expected,
            "General worker admission receipt differs"
        );
        Ok((
            json!({
                "schema":1,"profile":PROFILE,"operation":OPERATION,
                "status":"verified","fixture":null,"fault":null,
                "run_id":request.run_id,"request_sha256":request_hash,
                "source_tree_sha256":verified.receipt["source_tree_sha256"],
                "controller_sha256":verified.receipt["controller_sha256"],
                "worker_sha256":verified.receipt["worker_sha256"],
                "containment_sha256":witness_hash,"job_profile_sha256":digest(&job_raw),
                "worker_stop":stopped,
                "admission_sha256":digest(&receipt_raw),"cleanup":"restored",
                "engine_applied":false,"broker_connected":false,"guest_executed":false,
                "unpacking_confirmed":false
            }),
            Some(digest(&receipt_raw)),
        ))
    })();
    let manifest = match checked {
        Ok((value, _)) => value,
        Err(error) => json!({
            "schema":1,"profile":PROFILE,"operation":OPERATION,
            "status":"failed","fixture":fault.map(|_| "native-a"),
            "fault":fault.map(GeneratedFault::name),"run_id":request.run_id,
            "request_sha256":request_hash,
            "source_tree_sha256":verified.receipt["source_tree_sha256"],
            "worker_stop":stopped.as_ref().ok(),"error":format!("{error:#}"),
            "cleanup":if stopped.is_ok(){"restored"}else{"unverified"},"engine_applied":false,
            "broker_connected":false,"guest_executed":false,
            "unpacking_confirmed":false
        }),
    };
    save_new(
        &root.join("controller-manifest.json"),
        &bounded_json(&manifest, 256 * 1024)?,
    )?;
    Ok(manifest)
}

#[cfg(test)]
mod output_boundary_tests {
    use super::*;
    #[test]
    fn generated_output_cannot_overlap_frozen_bundle() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "emumee-general-boundary-{}-{nonce}",
            std::process::id()
        ));
        let bundle = base.join("bundle");
        std::fs::create_dir_all(&bundle).unwrap();
        let bundle = bundle.canonicalize().unwrap();
        assert!(verify_output_location(&bundle, &bundle.join("new-run")).is_err());
        assert!(verify_output_location(&bundle, &base.join("bundle")).is_err());
        assert!(verify_output_location(&bundle, &base.join("peer-run")).is_ok());
        std::fs::remove_dir_all(base).unwrap();
    }
}

#[cfg(test)]
mod lifecycle_receipt_tests {
    use super::*;

    #[test]
    fn generated_lifecycle_receipts_require_exact_bounds_schema_and_exit_hex() {
        let stopped = WorkerExit {
            exit_code: 0,
            reason: WorkerStop::Exited,
            detail: None,
            output_usage: None,
            output_checks: 1,
            elapsed_ms: 1,
        };
        let limits = json!({
            "max_bytes":320u64 * 1024 * 1024,
            "max_entries":4200,"max_directories":8,"max_depth":4
        });
        let job = json!({
            "schema":1,"profile":"general_verify_1024_v1",
            "process_memory_bytes":1024u64 * 1024 * 1024,
            "active_process_limit":1,"network_capabilities":0,
            "peak_process_memory_bytes":4096,"output_limits":limits,
            "cleanup":"restored"
        });
        let stop = json!({
            "schema":1,"worker":&stopped,"output_limits":limits,"cleanup":"restored"
        });
        let exit = json!({
            "exit_code":0,"exit_code_hex":"0x00000000","cleanup":"restored"
        });
        verify_lifecycle_receipts(&job, &stop, &exit, &stopped).unwrap();
        let mut changed = job.clone();
        changed["output_limits"]["max_bytes"] = 1.into();
        assert!(verify_lifecycle_receipts(&changed, &stop, &exit, &stopped).is_err());
        let mut changed = stop.clone();
        changed["schema"] = 2.into();
        assert!(verify_lifecycle_receipts(&job, &changed, &exit, &stopped).is_err());
        let mut changed = exit.clone();
        changed["exit_code_hex"] = "0x00000001".into();
        assert!(verify_lifecycle_receipts(&job, &stop, &changed, &stopped).is_err());
    }
}

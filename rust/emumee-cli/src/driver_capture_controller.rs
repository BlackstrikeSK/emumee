//! Closed Driver128 qualification orchestration, never an arbitrary sample role.
use super::{
    driver_capture_reader,
    worker::{launch_driver_capture, save_new, verified_bundle},
};
use anyhow::{Context, Result, ensure};
use emumee_core::{
    analysis_fixture,
    driver_capture_fixture::{Case, Fault, Request},
    driver_capture_reports::{self as reports, Binding, Stop},
    report_bundle::{bounded_json, digest},
};
use emumee_platform::windows::{OutputLimits, WorkerStop, read_regular, with_driver_regular};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{ffi::OsString, fs::OpenOptions, io::Write, path::Path};

fn hash_input(root: &Path, length: usize) -> Result<String> {
    let path = root.join("input.bin");
    if length == 0 {
        return Ok(digest(&read_regular(&path, 0, Some(root))?));
    }
    with_driver_regular(&path, length as u64, root, |read| {
        let mut hash = Sha256::new();
        let mut offset = 0;
        while offset < length {
            let count = (length - offset).min(8 * 1024 * 1024);
            hash.update(read(offset as u64, count)?);
            offset += count;
        }
        Ok(format!("{:x}", hash.finalize()))
    })
}

pub fn run(root: &Path, case_name: &str, fault_name: &str) -> Result<Value> {
    let case = Case::parse(case_name).context("Unknown closed Driver128 recipe")?;
    let fault = Fault::parse(fault_name).context("Unknown closed Driver128 fault")?;
    ensure!(
        emumee_core::driver_capture_fixture::allows_fault(case, fault),
        "Driver128 faults require the small owned recipe"
    );
    let verified = verified_bundle()?;
    let root = std::path::absolute(root)?;
    std::fs::create_dir(&root).context("Driver128 output directory must be fresh")?;
    let time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let (run_id, _) =
        analysis_fixture::identity(time.as_secs(), time.as_nanos() as u32 ^ std::process::id())
            .map_err(anyhow::Error::msg)?;
    let request = Request::generated(case, fault, run_id);
    let raw = bounded_json(&request, 4096)?;
    Request::parse(&raw).map_err(anyhow::Error::msg)?;
    let mut staged_raw = raw.clone();
    let refusal = match fault {
        Fault::TamperRequest => {
            staged_raw.push(b' ');
            Some("Driver128 request hash changed")
        }
        Fault::TamperInput => Some("Driver128 fixed input hash/size changed"),
        Fault::UnknownRequestField => {
            let mut value: Value = serde_json::from_slice(&raw)?;
            value["unexpected"] = json!(true);
            staged_raw = bounded_json(&value, 4096)?;
            Some("Driver fixture schema/enum")
        }
        Fault::ForeignOwnedFixture => {
            let mut bytes = Case::SmallRaw
                .small_bytes()
                .context("Small owned refusal bytes missing")?;
            bytes[512] ^= 1;
            let mut value: Value = serde_json::from_slice(&raw)?;
            value["input_sha256"] = json!(digest(&bytes));
            staged_raw = bounded_json(&value, 4096)?;
            Some("Driver fixture fixed recipe/profile binding")
        }
        _ => None,
    };
    let hash = if fault == Fault::TamperRequest {
        digest(&raw)
    } else {
        digest(&staged_raw)
    };
    save_new(&root.join("request.json"), &staged_raw)?;
    {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(root.join("input.bin"))?;
        case.emit(|chunk| file.write_all(chunk))?;
        file.sync_all()?;
    }
    ensure!(
        hash_input(&root, request.input_size)? == request.input_sha256,
        "Staged owned recipe bytes changed"
    );
    if matches!(fault, Fault::TamperInput | Fault::ForeignOwnedFixture) {
        use std::io::{Seek, SeekFrom};
        let mut file = OpenOptions::new()
            .write(true)
            .open(root.join("input.bin"))?;
        file.seek(SeekFrom::Start(512))?;
        file.write_all(&[1])?;
        file.sync_all()?;
    }
    let staged_input_sha256 = hash_input(&root, request.input_size)?;
    // Physical budget includes input128 + request2 + report/manifest/checkpoint126
    // + capture256 + journal64 + two IPC streams256 + receipts8 =840MiB.
    // IPC/journal are reserved here, not a broker-coverage claim.
    let physical_mib = [128u64, 2, 126, 256, 64, 128, 128, 8]
        .into_iter()
        .try_fold(0u64, |sum, n| sum.checked_add(n))
        .context("Driver output accounting overflow")?;
    ensure!(
        physical_mib == 840 && physical_mib <= 1024,
        "Driver physical output/copy budget"
    );
    let limits = OutputLimits {
        max_bytes: 1024 * 1024 * 1024,
        max_entries: 10064,
        max_directories: 8,
        max_depth: 4,
    };
    limits.validate()?;
    let stopped = launch_driver_capture(
        &verified,
        &root,
        &[
            OsString::from("--driver-capture-fixture"),
            root.as_os_str().to_owned(),
            OsString::from(&hash),
        ],
        limits,
        if fault == Fault::TimeoutAfterCheckpoint {
            5000
        } else {
            120000
        },
    )?;
    if let Some(expected) = refusal {
        ensure!(
            stopped.reason == WorkerStop::Exited && stopped.exit_code == 2,
            "Driver128 refusal did not stop before capture"
        );
        let error = read_regular(&root.join("worker-error.txt"), 32768, Some(&root))?;
        ensure!(
            String::from_utf8_lossy(&error).contains(expected),
            "Driver128 refusal reason changed"
        );
        ensure!(
            !root.join("worker-ready.json").exists()
                && !root.join("worker-summary.json").exists()
                && !root.join("artifacts").exists()
                && !root.join("artifact-checkpoint.json").exists(),
            "Driver128 refused input reached capture"
        );
    }
    let normal = stopped.reason == WorkerStop::Exited && stopped.exit_code == 0;
    let stop = if stopped.reason == WorkerStop::Timeout {
        Stop::Timeout
    } else if normal {
        Stop::Normal
    } else {
        Stop::WorkerFailure
    };
    let checked = (|| -> Result<(Vec<u8>, Binding)> {
        ensure!(
            refusal.is_none(),
            "Driver128 request/input refused before capture: {}",
            refusal.unwrap_or_default()
        );
        ensure!(
            read_regular(&root.join("request.json"), 4096, Some(&root))? == raw,
            "Staged Driver128 request drifted"
        );
        ensure!(
            hash_input(&root, request.input_size)? == request.input_sha256,
            "Staged Driver128 input drifted"
        );
        let witness = read_regular(&root.join("worker-containment.json"), 4096, Some(&root))?;
        let containment: Value = serde_json::from_slice(&witness)?;
        ensure!(
            containment["app_container"] == true
                && containment["job_object"] == true
                && containment["child_process_blocked"] == true
                && containment["network_capabilities"] == 0,
            "Driver128 containment witness invalid"
        );
        let expected = Binding {
            request_sha256: hash.clone(),
            input_sha256: request.input_sha256.clone(),
            input_bytes: request.input_size as u64,
            recipe: case_name.into(),
            source_tree_sha256: env!("EMUMEE_BUILD_SOURCE_SHA256").into(),
            containment_sha256: digest(&witness),
        };
        let ready: Value = serde_json::from_slice(&read_regular(
            &root.join("worker-ready.json"),
            4096,
            Some(&root),
        )?)?;
        ensure!(
            ready["profile"] == reports::PROFILE
                && ready["request_sha256"] == hash
                && ready["input_sha256"] == request.input_sha256
                && ready["job_memory_mib_required"] == 2048,
            "Driver role readiness binding changed"
        );
        let (summary, engine) =
            driver_capture_reader::verify(&root, "worker-summary.json", Some(&expected))?;
        ensure!(
            summary.summary.id == request.run_id && !summary.summary.checkpoint_recovered,
            "Driver draft identity/recovery changed"
        );
        if let Some(case) = case.runtime_case() {
            let engine: Value = serde_json::from_slice(&engine)?;
            ensure!(
                summary.summary.guest_entry_return == Some(17)
                    && summary.summary.instruction_count > 0
                    && engine["execution"]["image_load"]["size"].as_u64()
                        == Some(case.image_bytes() as u64),
                "Actual runtime capture execution/image evidence missing"
            );
            ensure!(
                engine["execution"]["capture_runtime"]["input_sha256"] == request.input_sha256,
                "Executed compiler-owned input differs from staged binding"
            );
        }
        if case == Case::DriverEntry64 {
            let engine: Value = serde_json::from_slice(&engine)?;
            ensure!(
                summary.summary.guest_entry_return == Some(17)
                    && summary.summary.instruction_count > 0
                    && engine["execution"]["image_load"]["size"] == 64 * 1024 * 1024,
                "Generated 64MiB DriverEntry execution evidence missing"
            );
        }
        if normal {
            let receipt: Value = serde_json::from_slice(&read_regular(
                &root.join("driver-result.json"),
                65536,
                Some(&root),
            )?)?;
            ensure!(
                receipt["schema"] == 1
                    && receipt["profile"] == reports::PROFILE
                    && receipt["binding"] == serde_json::to_value(&expected)?
                    && receipt["summary_sha256"]
                        == digest(&read_regular(
                            &root.join("worker-summary.json"),
                            5 * 1024 * 1024,
                            Some(&root)
                        )?),
                "Driver128 worker receipt binding changed"
            );
        }
        Ok((reports::restamp(summary, &engine, stop, !normal)?, expected))
    })();
    let (summary_raw, integrity_error, binding) = match checked {
        Ok((summary, binding)) => (summary, None, Some(binding)),
        Err(error) => {
            let detail = format!("{error:#}").chars().take(8192).collect::<String>();
            let failure = json!({"schema":"emumee.driver_capture_failure.v1","profile":reports::PROFILE,"id":request.run_id,"status":"failed","artifacts":[],"integrity":"failed","error":detail,"scope":"Preserved unverified evidence; no recovered artifact or unpacking claim"});
            (bounded_json(&failure, 5 * 1024 * 1024)?, Some(detail), None)
        }
    };
    let summary: Value = serde_json::from_slice(&summary_raw)?;
    let status = summary["summary"]["status"]
        .as_str()
        .or_else(|| summary["status"].as_str())
        .context("Final Driver128 status missing")?;
    save_new(&root.join("summary.json"), &summary_raw)?;
    let job: Value = serde_json::from_slice(&read_regular(
        &root.join("driver-job-profile.json"),
        65536,
        Some(&root),
    )?)?;
    ensure!(
        job["profile"] == "driver_capture_2048_v1"
            && job["process_memory_bytes"] == 2048u64 * 1024 * 1024
            && job["peak_process_memory_bytes"]
                .as_u64()
                .is_some_and(|p| p > 0 && p <= 2048 * 1024 * 1024),
        "Actual Driver job accounting missing"
    );
    let manifest = json!({"schema":1,"role":"closed_driver_capture_controller","profile":reports::PROFILE,"qualified":integrity_error.is_none()&&normal,"status":status,"case":case,"fault":fault,
        "request_sha256":hash,"staged_request_sha256":digest(&staged_raw),"staged_input_sha256":staged_input_sha256,"expected_refusal":refusal,"input_sha256":request.input_sha256,"input_size":request.input_size,"binding":binding,"summary_sha256":digest(&summary_raw),"source_tree_sha256":verified.receipt["source_tree_sha256"],"controller_sha256":verified.receipt["controller_sha256"],"worker_sha256":verified.receipt["worker_sha256"],"unicorn_sha256":verified.receipt["unicorn_sha256"],
        "worker_stop":stopped.reason,"worker_exit_code":stopped.exit_code,"job":job,"output_limits":limits,"physical_reserved_bytes":physical_mib*1024*1024,"cleanup":"restored","controller_recovery":verified.recovery,"integrity_error":integrity_error,"scope":"Bounded closed generated capture/report controls only; no general Driver128 or confirmed unpacking capability"});
    save_new(
        &root.join("manifest.json"),
        &bounded_json(&manifest, 1024 * 1024)?,
    )?;
    Ok(manifest)
}

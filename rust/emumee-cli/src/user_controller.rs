//! Parent stages data only; native execution belongs to the contained worker.
use super::{
    general_boundary_controller::{run_id, verify_output_location},
    worker::{launch_user, save_new, verified_bundle, verify_artifacts},
};
use anyhow::{Context, Result, ensure};
use emumee_core::{
    report_bundle::{bounded_json, digest},
    user_input::{MAX_REQUEST, MAX_RESULT, PROFILE, Request},
};
use emumee_platform::windows::{OutputLimits, WorkerStop, read_regular};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

pub struct Options {
    pub budget: u64,
    pub timeout_us: u64,
    pub persona: Option<PathBuf>,
    pub arguments: Vec<String>,
}

pub fn run(source: &Path, root: &Path, options: Options) -> Result<Value> {
    let bytes = read_regular(source, emumee_core::pe::MAX_INPUT, None)?;
    let persona = options
        .persona
        .as_ref()
        .map(|p| read_regular(p, emumee_core::driver_input::MAX_PERSONA, None))
        .transpose()?;
    let request = Request {
        schema: 1,
        profile: PROFILE.into(),
        run_id: run_id()?,
        input_sha256: digest(&bytes),
        input_size: bytes.len() as u64,
        module_name: source
            .file_name()
            .and_then(|s| s.to_str())
            .context("Input needs a UTF8 basename")?
            .into(),
        arguments: options.arguments,
        max_instructions: options.budget,
        timeout_us: options.timeout_us,
        persona_sha256: persona.as_deref().map(digest),
        clock_utc_filetime: u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
                / 100,
        )?
        .checked_add(116444736000000000)
        .context("Guest clock seed overflow")?,
    };
    request.verify_input(&bytes).map_err(anyhow::Error::msg)?;
    if let Some(raw) = &persona {
        request.resolve_persona(raw)?;
    }
    let raw = bounded_json(&request, MAX_REQUEST)?;
    let expected = digest(&raw);
    let verified = verified_bundle()?;
    let root = std::path::absolute(root)?;
    verify_output_location(&verified.path, &root)?;
    std::fs::create_dir(&root).context("Output directory must be new")?;
    std::fs::create_dir(root.join("worker"))?;
    save_new(&root.join("input.pe"), &bytes)?;
    save_new(&root.join("request.json"), &raw)?;
    if let Some(raw) = &persona {
        save_new(&root.join("persona.json"), raw)?;
    }
    let stopped = launch_user(
        &verified,
        &root,
        &[
            OsString::from("--submitted-user"),
            root.as_os_str().to_owned(),
            OsString::from(&expected),
        ],
        OutputLimits {
            max_bytes: 512 * 1024 * 1024,
            max_entries: 4200,
            max_directories: 8,
            max_depth: 4,
        },
        u32::try_from(request.timeout_us.div_ceil(1000) + 30_000)?,
    )?;
    ensure!(
        stopped.reason == WorkerStop::Exited && stopped.exit_code == 0,
        "Submitted PE worker failed: {:?}, exit {}: {}",
        stopped.reason,
        stopped.exit_code,
        read_regular(&root.join("worker/error.txt"), 32768, Some(&root))
            .map(|v| String::from_utf8_lossy(&v).into_owned())
            .unwrap_or_default()
    );
    // The worker has no write grant to the parent-owned input/request files.
    ensure!(
        digest(&read_regular(
            &root.join("request.json"),
            MAX_REQUEST,
            Some(&root)
        )?) == expected,
        "Parent request changed during execution"
    );
    request
        .verify_input(&read_regular(
            &root.join("input.pe"),
            emumee_core::pe::MAX_INPUT,
            Some(&root),
        )?)
        .map_err(anyhow::Error::msg)?;
    let result_raw = read_regular(&root.join("worker/result.json"), MAX_RESULT, Some(&root))?;
    let result: Value = serde_json::from_slice(&result_raw)?;
    ensure!(
        result["schema"] == 1
            && result["profile"] == PROFILE
            && result["run_id"] == request.run_id
            && result["request_sha256"] == expected
            && result["input_sha256"] == request.input_sha256,
        "Submitted PE report binding differs"
    );
    let containment = &result["containment"];
    ensure!(
        containment["app_container"] == true
            && containment["job_object"] == true
            && containment["child_process_blocked"] == true
            && containment["network_capabilities"] == 0,
        "Submitted PE containment absent"
    );
    verify_artifacts(&root.join("worker"), &result["execution"]["artifacts"])?;
    let manifest = json!({"schema":1,"request_sha256":expected,"result_sha256":digest(&result_raw),
        "source_tree_sha256":verified.receipt["source_tree_sha256"],"bundle_receipt":verified.receipt,
        "cleanup":"restored","controller_recovery":verified.recovery,"result":result});
    save_new(
        &root.join("manifest.json"),
        &bounded_json(&manifest, MAX_RESULT + 1024 * 1024)?,
    )?;
    Ok(manifest)
}

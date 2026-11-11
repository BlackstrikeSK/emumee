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
mod binding_fixture;
mod staging;
pub use binding_fixture::run as binding_fixture;

pub struct Options {
    pub budget: u64,
    pub timeout_us: u64,
    pub persona: Option<PathBuf>,
    pub arguments: Vec<String>,
    pub inputs: Option<PathBuf>,
}

pub fn bootstrap_boundary(
    source: &Path,
    root: &Path,
    architecture: emumee_core::pe::Architecture,
) -> Result<Value> {
    let expected = emumee_core::fixtures::user_bootstrap_probe(
        architecture,
        emumee_core::fixtures::BootstrapFixture::Basic,
        false,
    );
    ensure!(
        source.file_name().and_then(|value| value.to_str()) == Some("bootstrap.exe"),
        "Bootstrap fixture requires bootstrap.exe"
    );
    ensure!(
        emumee_platform::windows::read_regular_locked(source, emumee_core::pe::MAX_INPUT, None)?
            == expected,
        "Bootstrap fixture bytes differ"
    );
    let guest_path = r"C:\emumee\bootstrap.exe";
    run(
        source,
        root,
        Options {
            budget: 500000,
            timeout_us: 30_000_000,
            persona: None,
            arguments: vec!["x".repeat(32766 - guest_path.encode_utf16().count() - 1)],
            inputs: None,
        },
    )
}

pub fn run(source: &Path, root: &Path, options: Options) -> Result<Value> {
    let bytes =
        emumee_platform::windows::read_regular_locked(source, emumee_core::pe::MAX_INPUT, None)?;
    let (staged, payloads, invocation) = staging::capture(options.inputs.as_deref())?;
    let persona = options
        .persona
        .as_ref()
        .map(|p| {
            emumee_platform::windows::read_regular_locked(
                p,
                emumee_core::driver_input::MAX_PERSONA,
                None,
            )
        })
        .transpose()?;
    let request = Request {
        schema: 2,
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
        staged,
        invocation,
    };
    request
        .verify_staged(&bytes, &payloads)
        .map_err(anyhow::Error::msg)?;
    emumee_engine::user::preflight(&request, &bytes, persona.as_deref(), &payloads)?;
    if let Some(raw) = &persona {
        request.resolve_persona(raw)?;
    }
    let raw = bounded_json(&request, MAX_REQUEST)?;
    let expected = digest(&raw);
    let verified = verified_bundle()?;
    let root = std::path::absolute(root)?;
    verify_output_location(&verified.path, &root)?;
    staging::publish(&root, &bytes, &raw, persona.as_deref(), &payloads)?;
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
    request
        .verify_staged(&bytes, &staging::read_staged(&root, &request)?)
        .map_err(anyhow::Error::msg)?;
    let final_persona = if request.persona_sha256.is_some() {
        Some(emumee_platform::windows::read_regular_locked(
            &root.join("persona.json"),
            emumee_core::driver_input::MAX_PERSONA,
            Some(&root),
        )?)
    } else {
        ensure!(
            !root.join("persona.json").exists(),
            "Unexpected submitted persona"
        );
        None
    };
    request
        .verify_persona(final_persona.as_deref())
        .map_err(anyhow::Error::msg)?;
    let result_raw = read_regular(&root.join("worker/result.json"), MAX_RESULT, Some(&root))?;
    let result: Value = serde_json::from_slice(&result_raw)?;
    request
        .verify_result(&result, &expected, final_persona.as_deref())
        .map_err(anyhow::Error::msg)?;
    ensure!(
        result["execution"]["architecture"]
            == serde_json::to_value(
                request
                    .verify_input(&bytes)
                    .map_err(anyhow::Error::msg)?
                    .sample
                    .architecture,
            )?,
        "Submitted PE report architecture differs"
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

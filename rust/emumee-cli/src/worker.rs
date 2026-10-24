//! The initial Rust worker accepts only its own bounded generated fixture.
use anyhow::{Context, Result, ensure};
use emumee_core::{
    pe::Architecture,
    protocol::{BoundaryProbe, FixtureKind, FixtureRequest},
};
#[cfg(windows)]
use emumee_platform::windows::{
    BundleLock, OfflineProfile, OutputLimits, RecoveryReport, RecoverySession, WorkerJob,
    WorkerStop, read_regular,
};
use sha2::{Digest, Sha256};
use std::{ffi::OsString, fs::OpenOptions, io::Write, path::Path};

pub(crate) fn save_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}
#[cfg(windows)]
pub(crate) struct VerifiedBundle {
    pub path: std::path::PathBuf,
    pub receipt: serde_json::Value,
    pub recovery: RecoveryReport,
    _lock: BundleLock,
}
#[cfg(windows)]
pub(crate) fn verified_bundle() -> Result<VerifiedBundle> {
    let executable = std::env::current_exe()?.canonicalize()?;
    let bundle = executable
        .parent()
        .context("Worker bundle directory missing")?;
    let lock = BundleLock::acquire(bundle)?;
    let recovery = RecoverySession::recover(bundle)?;
    ensure!(
        bundle.join("rust-worker-build.json").is_file(),
        "Isolated fixtures require a packaged Rust worker; use tools/package_rust.ps1"
    );
    let receipt = read_regular(&bundle.join("rust-worker-build.json"), 131072, Some(bundle))?;
    let receipt: serde_json::Value = serde_json::from_slice(&receipt)?;
    ensure!(
        receipt["schema"] == 2,
        "Rust worker receipt schema is unsupported"
    );
    ensure!(
        receipt["source_tree_sha256"] == env!("EMUMEE_BUILD_SOURCE_SHA256"),
        "Rust worker receipt does not match the compiled source fingerprint"
    );
    let worker = bundle.join("emumee-worker.exe");
    ensure!(
        receipt["controller_sha256"]
            == format!(
                "{:x}",
                Sha256::digest(read_regular(&executable, 16 * 1024 * 1024, Some(bundle))?)
            ),
        "Rust controller binary differs from its receipt"
    );
    ensure!(
        receipt["worker_sha256"]
            == format!(
                "{:x}",
                Sha256::digest(read_regular(&worker, 16 * 1024 * 1024, Some(bundle))?)
            ),
        "Rust worker binary differs from its receipt"
    );
    ensure!(
        receipt["unicorn_sha256"]
            == format!(
                "{:x}",
                Sha256::digest(read_regular(
                    &bundle.join("unicorn.dll"),
                    16 * 1024 * 1024,
                    Some(bundle)
                )?)
            ),
        "Rust CPU library differs from its receipt"
    );
    Ok(VerifiedBundle {
        path: bundle.to_path_buf(),
        receipt,
        recovery,
        _lock: lock,
    })
}
#[cfg(windows)]
pub fn isolated_fixture(
    root: &Path,
    architecture: Architecture,
    iterations: u32,
    budget: u64,
    kind: FixtureKind,
) -> Result<serde_json::Value> {
    isolated(root, architecture, iterations, budget, kind, None)
}
#[cfg(windows)]
pub fn isolated_probe(root: &Path, probe: BoundaryProbe) -> Result<serde_json::Value> {
    isolated(
        root,
        Architecture::X64,
        10,
        1000,
        FixtureKind::Loop,
        Some(probe),
    )
}
#[cfg(windows)]
fn isolated(
    root: &Path,
    architecture: Architecture,
    iterations: u32,
    budget: u64,
    kind: FixtureKind,
    boundary_probe: Option<BoundaryProbe>,
) -> Result<serde_json::Value> {
    ensure!(
        (1..=100_000_000).contains(&iterations) && (1..=1_000_000_000).contains(&budget),
        "Invalid fixture bound"
    );
    let verified = verified_bundle()?;
    let receipt = &verified.receipt;
    let root = std::path::absolute(root)?;
    std::fs::create_dir(&root)
        .with_context(|| format!("Output directory must be new: {}", root.display()))?;
    let request = FixtureRequest {
        schema: 1,
        architecture: if architecture == Architecture::X64 {
            "x64"
        } else {
            "x86"
        }
        .to_owned(),
        iterations,
        max_instructions: budget,
        kind,
        boundary_probe,
    };
    let raw = serde_json::to_vec_pretty(&request)?;
    let digest = format!("{:x}", Sha256::digest(&raw));
    save_new(&root.join("request.json"), &raw)?;
    let limits = if boundary_probe.is_some() {
        OutputLimits {
            max_bytes: 1024 * 1024,
            max_entries: 16,
            ..OutputLimits::default()
        }
    } else {
        OutputLimits::default()
    };
    let timeout_ms = if matches!(boundary_probe, Some(BoundaryProbe::Timeout)) {
        1000
    } else {
        120000
    };
    let stopped = launch_generated(
        &verified,
        &root,
        &[root.as_os_str().to_owned(), OsString::from(&digest)],
        limits,
        timeout_ms,
    )?;
    let exit = stopped.exit_code;
    if exit != 0 || stopped.reason != WorkerStop::Exited {
        let details = read_regular(&root.join("worker-error.txt"), 32768, Some(&root))
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default();
        anyhow::bail!(
            "Rust fixture worker stopped: {:?}, exit 0x{exit:08x}: {} {details}",
            stopped.reason,
            stopped.detail.as_deref().unwrap_or_default()
        );
    }
    let raw = read_regular(
        &root.join("fixture-result.json"),
        5 * 1024 * 1024,
        Some(&root),
    )?;
    let result: serde_json::Value = serde_json::from_slice(&raw)?;
    ensure!(
        result["request_sha256"] == digest,
        "Fixture result belongs to another request"
    );
    ensure!(
        result["containment"]["app_container"] == true
            && result["containment"]["job_object"] == true
            && result["containment"]["child_process_blocked"] == true
            && result["containment"]["network_capabilities"] == 0,
        "Fixture worker did not verify containment"
    );
    verify_artifacts(&root, &result["execution"]["artifacts"])?;
    let manifest = serde_json::json!({"schema":1,"source_tree_sha256":receipt["source_tree_sha256"],"controller_sha256":receipt["controller_sha256"],"worker_sha256":receipt["worker_sha256"],"unicorn_sha256":receipt["unicorn_sha256"],"request_sha256":digest,"result_sha256":format!("{:x}",Sha256::digest(&raw)),"cleanup":"restored","controller_recovery":verified.recovery,"result":result});
    save_new(
        &root.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(manifest)
}
#[cfg(windows)]
pub(crate) fn launch_generated(
    verified: &VerifiedBundle,
    root: &Path,
    arguments: &[OsString],
    limits: OutputLimits,
    timeout_ms: u32,
) -> Result<emumee_platform::windows::WorkerExit> {
    launch_profile(
        verified,
        root,
        arguments,
        limits,
        timeout_ms,
        JobProfile::LegacyFixture512,
    )
}
#[cfg(windows)]
pub(crate) fn launch_driver_capture(
    verified: &VerifiedBundle,
    root: &Path,
    arguments: &[OsString],
    limits: OutputLimits,
    timeout_ms: u32,
) -> Result<emumee_platform::windows::WorkerExit> {
    launch_profile(
        verified,
        root,
        arguments,
        limits,
        timeout_ms,
        JobProfile::DriverCapture2048,
    )
}
#[cfg(windows)]
pub(crate) fn launch_general_verify(
    verified: &VerifiedBundle,
    root: &Path,
    arguments: &[OsString],
) -> Result<emumee_platform::windows::WorkerExit> {
    launch_profile(
        verified,
        root,
        arguments,
        OutputLimits {
            max_bytes: 320 * 1024 * 1024,
            max_entries: 4200,
            max_directories: 8,
            max_depth: 4,
        },
        300_000,
        JobProfile::GeneralVerify1024,
    )
}
#[cfg(windows)]
#[derive(Clone, Copy)]
enum JobProfile {
    LegacyFixture512,
    DriverCapture2048,
    GeneralVerify1024,
}
#[cfg(windows)]
fn launch_profile(
    verified: &VerifiedBundle,
    root: &Path,
    arguments: &[OsString],
    limits: OutputLimits,
    timeout_ms: u32,
    job_profile: JobProfile,
) -> Result<emumee_platform::windows::WorkerExit> {
    let bundle = &verified.path;
    let worker = bundle.join("emumee-worker.exe");
    let mut recovery = RecoverySession::begin(bundle, root)?;
    let memory_mib = match job_profile {
        JobProfile::LegacyFixture512 => 512,
        JobProfile::DriverCapture2048 => 2048,
        JobProfile::GeneralVerify1024 => 1024,
    };
    let job = WorkerJob::new_tracked(memory_mib, &mut recovery)?;
    let mut profile = OfflineProfile::new_tracked(&mut recovery)?;
    let mut bundle_access = profile.grant_tracked(bundle, false, &mut recovery)?;
    // General verify-only admission may read committed control bytes, but it
    // can write only in worker/. The generated/Driver128 roles retain their
    // established root grant until separately qualified for narrower ACLs.
    let general = matches!(job_profile, JobProfile::GeneralVerify1024);
    let mut output_access = profile.grant_tracked(root, !general, &mut recovery)?;
    let mut general_worker_access = if general {
        Some(profile.grant_tracked(&root.join("worker"), true, &mut recovery)?)
    } else {
        None
    };
    let launch = profile.launch(&worker, arguments, root, timeout_ms, &job, limits);
    // Capture the query result now, propagate only after all explicit cleanup.
    let driver_peak = if matches!(job_profile, JobProfile::DriverCapture2048) {
        Some(job.peak_process_memory_bytes())
    } else {
        None
    };
    let general_peak = if general {
        Some(job.peak_process_memory_bytes())
    } else {
        None
    };
    // Explicit cleanup failures remain errors; interrupted output is never
    // described as a qualified result. RAII also covers early error paths.
    // Child ACL was captured after the parent read grant inherited into it.
    // Restore child first, then parent, so the parent restoration removes its
    // inherited AppContainer ACE from the entire output tree.
    let general_worker_cleanup = general_worker_access
        .as_mut()
        .map(|access| access.restore())
        .transpose();
    let output_cleanup = output_access.restore();
    let bundle_cleanup = bundle_access.restore();
    let profile_cleanup = profile.close();
    output_cleanup?;
    general_worker_cleanup?;
    bundle_cleanup?;
    profile_cleanup?;
    recovery.finish()?;
    if let Some(peak) = driver_peak {
        let peak = peak?;
        ensure!(
            peak <= 2048 * 1024 * 1024,
            "Driver job peak exceeds sealed profile"
        );
        save_new(
            &root.join("driver-job-profile.json"),
            &serde_json::to_vec_pretty(
                &serde_json::json!({"schema":1,"profile":"driver_capture_2048_v1","process_memory_bytes":2048u64*1024*1024,"active_process_limit":1,"network_capabilities":0,"peak_process_memory_bytes":peak,"output_limits":limits,"cleanup":"restored"}),
            )?,
        )?;
    }
    if let Some(peak) = general_peak {
        let peak = peak?;
        ensure!(
            peak <= 1024 * 1024 * 1024,
            "General verify job peak exceeds sealed profile"
        );
        save_new(
            &root.join("general-job-profile.json"),
            &serde_json::to_vec_pretty(
                &serde_json::json!({"schema":1,"profile":"general_verify_1024_v1","process_memory_bytes":1024u64*1024*1024,"active_process_limit":1,"network_capabilities":0,"peak_process_memory_bytes":peak,"output_limits":limits,"cleanup":"restored"}),
            )?,
        )?;
    }
    let stopped = match launch {
        Ok(stopped) => stopped,
        Err(error) => {
            save_new(
                &root.join("worker-stop.json"),
                &serde_json::to_vec_pretty(
                    &serde_json::json!({"schema":1,"reason":"launch_failed","error":format!("{error:#}"),"cleanup":"restored"}),
                )?,
            )?;
            return Err(error);
        }
    };
    save_new(
        &root.join("worker-stop.json"),
        &serde_json::to_vec_pretty(
            &serde_json::json!({"schema":1,"worker":&stopped,"output_limits":limits,"cleanup":"restored"}),
        )?,
    )?;
    let exit = stopped.exit_code;
    save_new(
        &root.join("worker-exit.json"),
        &serde_json::to_vec_pretty(
            &serde_json::json!({"exit_code":exit,"exit_code_hex":format!("0x{exit:08x}"),"cleanup":"restored"}),
        )?,
    )?;
    Ok(stopped)
}
#[cfg(windows)]
pub(crate) fn verify_artifacts(root: &Path, artifacts: &serde_json::Value) -> Result<()> {
    let artifacts = artifacts.as_array().context("Missing artifact list")?;
    ensure!(artifacts.len() <= 10000, "Artifact count exceeds bound");
    let mut total = 0u64;
    let mut observation_count = 0usize;
    let mut metadata_bytes = 0usize;
    for artifact in artifacts {
        let sha = artifact["sha256"]
            .as_str()
            .context("Missing artifact hash")?;
        ensure!(
            sha.len() == 64
                && sha
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "Invalid artifact hash"
        );
        let filename = format!("{sha}.bin");
        ensure!(
            artifact["filename"] == filename,
            "Artifact filename is not content-addressed"
        );
        let size = artifact["size"].as_u64().context("Invalid artifact size")?;
        ensure!(
            size > 0 && size <= 32 * 1024 * 1024,
            "Artifact size exceeds bound"
        );
        total = total.checked_add(size).context("Artifact total overflow")?;
        ensure!(total <= 128 * 1024 * 1024, "Artifact total exceeds bound");
        let observations = artifact
            .get("observations")
            .and_then(serde_json::Value::as_array)
            .context("Missing or invalid artifact observations")?;
        ensure!(
            !observations.is_empty(),
            "Artifact observations must be nonempty"
        );
        observation_count = observation_count
            .checked_add(observations.len())
            .context("Artifact observation count overflow")?;
        ensure!(
            observation_count <= 10000,
            "Artifact observation count exceeds bound"
        );
        for observation in observations {
            ensure!(
                emumee_core::artifacts::valid_observation_json(observation),
                "Invalid artifact observation metadata"
            );
            let bytes = serde_json::to_vec(observation)?
                .len()
                .checked_add(256)
                .context("Artifact metadata estimate overflow")?;
            metadata_bytes = metadata_bytes
                .checked_add(bytes)
                .context("Artifact metadata total overflow")?;
            ensure!(
                metadata_bytes <= 1024 * 1024,
                "Artifact metadata exceeds1MiB bound"
            );
        }
        let data = read_regular(
            &root.join("artifacts").join(filename),
            size as usize,
            Some(root),
        )?;
        ensure!(
            data.len() as u64 == size && format!("{:x}", Sha256::digest(&data)) == sha,
            "Artifact hash/size mismatch"
        );
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    #[test]
    fn parent_rejects_artifact_path_escape_size_and_hash_tampering() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "emumee-rust-artifacts-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("artifacts")).unwrap();
        let digest = format!("{:x}", Sha256::digest(b"RUST"));
        let filename = format!("{digest}.bin");
        let path = root.join("artifacts").join(&filename);
        std::fs::write(&path, b"RUST").unwrap();
        let good = serde_json::json!([{"filename":filename,"sha256":digest,"size":4,"observations":[{"kind":"guest_file","source":"virtual_file","guest_path":"C:\\fixture.bin"}]}]);
        verify_artifacts(&root, &good).unwrap();
        let mut invalid = good.clone();
        invalid[0]["filename"] = "../../outside.bin".into();
        assert!(
            verify_artifacts(&root, &invalid)
                .unwrap_err()
                .to_string()
                .contains("content-addressed")
        );
        let mut invalid = good.clone();
        invalid[0]["size"] = (32 * 1024 * 1024 + 1).into();
        assert!(
            verify_artifacts(&root, &invalid)
                .unwrap_err()
                .to_string()
                .contains("size exceeds")
        );
        let mut missing = good.clone();
        missing[0].as_object_mut().unwrap().remove("observations");
        assert!(
            verify_artifacts(&root, &missing)
                .unwrap_err()
                .to_string()
                .contains("observations")
        );
        let mut empty = good.clone();
        empty[0]["observations"] = serde_json::json!([]);
        assert!(
            verify_artifacts(&root, &empty)
                .unwrap_err()
                .to_string()
                .contains("nonempty")
        );
        for observation in [
            serde_json::json!({"kind":"unpacked_driver","source":"fixture","guest_path":""}),
            serde_json::json!({"kind":"guest_file","source":"x".repeat(257),"guest_path":""}),
            serde_json::json!({"kind":"guest_file","source":"fixture","guest_path":"","context":null}),
            serde_json::json!({"kind":"carved_image","source":"fixture","guest_path":"","context":{}}),
            serde_json::json!({"kind":"carved_image","source":"fixture","guest_path":"","context":{"carved_kind":"structural_pe","capture_origin":"memory","layout":"mapped_image","image_size":4096}}),
            serde_json::json!({"kind":"memory_snapshot","source":"fixture","guest_path":"","context":{"layout":"mapped_image","reconstruction":"section_rva_to_raw","image_size":0}}),
            serde_json::json!({"kind":"registry_value","source":"fixture","guest_path":"","context":{"registry_key":"HKCU","registry_value":"Raw","registry_type":4}}),
            serde_json::json!({"kind":"container_stream","source":"fixture","guest_path":"","context":{"container_stream_path":["../outside"]}}),
        ] {
            let mut invalid = good.clone();
            invalid[0]["observations"] = serde_json::json!([observation]);
            assert!(
                verify_artifacts(&root, &invalid)
                    .unwrap_err()
                    .to_string()
                    .contains("observation metadata")
            );
        }
        let mut nested = serde_json::json!(true);
        for _ in 0..18 {
            nested = serde_json::json!({"nested":nested});
        }
        let mut deep = good.clone();
        deep[0]["observations"][0]["context"] = nested;
        assert!(
            verify_artifacts(&root, &deep)
                .unwrap_err()
                .to_string()
                .contains("observation metadata")
        );
        let mut excessive = good.clone();
        excessive[0]["observations"] =
            serde_json::json!(vec![good[0]["observations"][0].clone(); 10001]);
        assert!(
            verify_artifacts(&root, &excessive)
                .unwrap_err()
                .to_string()
                .contains("observation count")
        );
        let large = serde_json::json!({"kind":"guest_file","source":"fixture","guest_path":"x".repeat(32768)});
        let mut excessive = good.clone();
        excessive[0]["observations"] = serde_json::json!(vec![large; 40]);
        assert!(
            verify_artifacts(&root, &excessive)
                .unwrap_err()
                .to_string()
                .contains("metadata exceeds")
        );
        std::fs::write(&path, b"FAKE").unwrap();
        assert!(
            verify_artifacts(&root, &good)
                .unwrap_err()
                .to_string()
                .contains("hash/size mismatch")
        );
        std::fs::write(&path, b"RUST!").unwrap();
        assert!(verify_artifacts(&root, &good).is_err());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(root.join("artifacts")).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}

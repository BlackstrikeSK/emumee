//! Linux parent admission, packaged worker launch, and result verification.
use anyhow::{Context, Result, bail, ensure};
use base64::Engine as _;
use emumee_core::{
    elf::StaticLoadPlan,
    linux_request::{LinuxRequest, MAX_INPUT},
};
use emumee_platform::linux::read_regular;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

struct VerifiedBundle {
    directory: PathBuf,
    receipt: serde_json::Value,
}

fn digest(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

fn save_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn bounded_file(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let bytes = read_regular(path, maximum)?;
    ensure!(
        fs::symlink_metadata(path)?.nlink() == 1,
        "Linked bundle or report file rejected"
    );
    Ok(bytes)
}

fn verified_bundle() -> Result<VerifiedBundle> {
    let controller = fs::canonicalize(std::env::current_exe()?)?;
    let directory = controller
        .parent()
        .context("Linux bundle directory missing")?;
    let receipt: serde_json::Value = serde_json::from_slice(&bounded_file(
        &directory.join("linux-worker-build.json"),
        4096,
    )?)?;
    ensure!(
        receipt["schema"] == 1
            && receipt["source_tree_sha256"] == env!("EMUMEE_BUILD_SOURCE_SHA256"),
        "Linux bundle receipt differs from compiled source"
    );
    for (path, field) in [
        (&controller, "controller_sha256"),
        (&directory.join("emumee-worker"), "worker_sha256"),
        (&directory.join("libunicorn.so.2"), "unicorn_sha256"),
    ] {
        ensure!(
            receipt[field] == digest(&bounded_file(path, 128 * 1024 * 1024)?),
            "Linux bundle {field} mismatch"
        );
    }
    Ok(VerifiedBundle {
        directory: directory.to_path_buf(),
        receipt,
    })
}

fn check_output(root: &Path) -> Result<()> {
    let mut total = 0u64;
    let mut count = 0;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        ensure!(
            metadata.is_file() && metadata.nlink() == 1,
            "Linux worker output is not an owned regular file"
        );
        total = total
            .checked_add(metadata.len())
            .context("Output size overflow")?;
        count += 1;
        ensure!(
            count <= 16 && total <= 48 * 1024 * 1024,
            "Linux worker output limit exceeded"
        );
    }
    Ok(())
}

fn run_worker(
    bundle: &VerifiedBundle,
    root: &Path,
    request_hash: &str,
    timeout_us: u64,
) -> Result<()> {
    let mut child = Command::new(bundle.directory.join("emumee-worker"))
        .arg("--linux-static")
        .arg(root)
        .arg(request_hash)
        .env_clear()
        .env("LD_LIBRARY_PATH", &bundle.directory)
        .current_dir(&bundle.directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("Cannot launch packaged Linux worker")?;
    let started = Instant::now();
    let deadline = Duration::from_micros(timeout_us).saturating_add(Duration::from_secs(15));
    let status = loop {
        if let Err(error) = check_output(root) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("Cannot inspect Linux worker state");
            }
        }
        if started.elapsed() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("Linux worker exceeded parent wall timeout");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    check_output(root)?;
    if !status.success() {
        let mut stderr = String::new();
        if let Some(stream) = child.stderr.take() {
            let _ = stream.take(8192).read_to_string(&mut stderr);
        }
        let detail = bounded_file(&root.join("linux-error.txt"), 8192)
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default();
        bail!("Linux worker exited {status}: {detail} {stderr}");
    }
    Ok(())
}

pub fn run(
    source: &Path,
    output: &Path,
    max_instructions: u64,
    timeout_us: u64,
) -> Result<serde_json::Value> {
    ensure!(
        cfg!(target_arch = "x86_64"),
        "Linux guest worker requires x86-64 host"
    );
    let bundle = verified_bundle()?;
    let input = bounded_file(source, MAX_INPUT)?;
    StaticLoadPlan::parse(&input).context("Linux guest admission rejected input")?;
    let request = LinuxRequest {
        schema: 1,
        profile: "static_x64_v1".into(),
        input_sha256: digest(&input),
        input_size: input.len() as u64,
        max_instructions,
        timeout_us,
    };
    request.validate().map_err(anyhow::Error::msg)?;
    let root = std::path::absolute(output)?;
    fs::create_dir(&root)
        .with_context(|| format!("Output directory must be new: {}", root.display()))?;
    let root = fs::canonicalize(root)?;
    save_new(&root.join("input.elf"), &input)?;
    let raw = serde_json::to_vec_pretty(&request)?;
    let request_hash = digest(&raw);
    save_new(&root.join("linux-request.json"), &raw)?;
    run_worker(&bundle, &root, &request_hash, timeout_us)?;
    let report = bounded_file(&root.join("linux-result.json"), 4 * 1024 * 1024)?;
    let result: serde_json::Value = serde_json::from_slice(&report)?;
    ensure!(
        result["schema"] == 1
            && result["request_sha256"] == request_hash
            && result["input_sha256"] == request.input_sha256
            && result["execution"]["schema"] == 1
            && result["execution"]["format"] == "elf"
            && result["execution"]["architecture"] == "x64"
            && result["execution"]["input_sha256"] == request.input_sha256
            && result["execution"]["instructions"]
                .as_u64()
                .is_some_and(|n| n <= max_instructions)
            && result["scope"]
                == "Static x86-64 Linux guest under the native Linux confined worker",
        "Linux result differs from admitted request"
    );
    let confinement = &result["containment"];
    for field in [
        "user_namespace",
        "mount_namespace",
        "network_namespace",
        "ipc_namespace",
        "root_confined",
        "no_new_privileges",
        "capabilities_dropped",
        "seccomp_filter",
        "child_process_blocked",
        "network_syscalls_blocked",
    ] {
        ensure!(
            confinement[field] == true,
            "Linux worker did not verify {field}"
        );
    }
    let reason = result["execution"]["completion_reason"]
        .as_str()
        .context("Missing Linux completion reason")?;
    ensure!(
        matches!(
            reason,
            "exit"
                | "unsupported_syscall"
                | "output_limit"
                | "guest_memory_fault"
                | "hook_failure"
                | "syscall_limit"
                | "cpu_fault"
                | "instruction_limit"
                | "timeout"
        ),
        "Unknown Linux completion reason"
    );
    if reason == "exit" {
        ensure!(
            result["execution"]["exit_code"]
                .as_u64()
                .is_some_and(|n| n <= 255),
            "Invalid Linux exit status"
        );
    }
    ensure!(
        result["execution"]["syscalls"]
            .as_array()
            .is_some_and(|v| v.len() <= 1024),
        "Linux syscall log exceeds bound"
    );
    let mut output_bytes = 0usize;
    for field in ["stdout_base64", "stderr_base64"] {
        let text = result["execution"][field]
            .as_str()
            .context("Missing Linux output")?;
        ensure!(
            text.len() <= 1_400_000,
            "Linux encoded output exceeds bound"
        );
        output_bytes = output_bytes
            .checked_add(
                base64::engine::general_purpose::STANDARD
                    .decode(text)?
                    .len(),
            )
            .context("Linux output overflow")?;
    }
    ensure!(output_bytes <= 1024 * 1024, "Linux output exceeds bound");
    let manifest = serde_json::json!({
        "schema": 1,
        "source_tree_sha256": bundle.receipt["source_tree_sha256"],
        "controller_sha256": bundle.receipt["controller_sha256"],
        "worker_sha256": bundle.receipt["worker_sha256"],
        "unicorn_sha256": bundle.receipt["unicorn_sha256"],
        "request_sha256": request_hash,
        "result_sha256": digest(&report),
        "result": result
    });
    save_new(
        &root.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(manifest)
}

//! Parent admission and result verification for the contained Linux guest role.
use anyhow::{Context, Result, ensure};
use base64::Engine as _;
use emumee_core::{
    elf::{ElfImage, Kind, Pie32LoadPlan, PieLoadPlan, SharedLoadPlan, Static32LoadPlan, StaticLoadPlan},
    pe::Architecture,
    linux_request::{LinuxLibrary, LinuxRequest, MAX_INPUT, MAX_LIBRARY_INPUT, valid_library_name},
};
use emumee_platform::windows::{OutputLimits, WorkerStop, read_regular};
use sha2::{Digest, Sha256};
use std::{ffi::OsString, path::{Path, PathBuf}};

use crate::worker::{launch_generated, save_new, verified_bundle};

pub fn run(
    source: &Path,
    output: &Path,
    max_instructions: u64,
    timeout_us: u64,
    libraries: &[(String, PathBuf)],
) -> Result<serde_json::Value> {
    let verified = verified_bundle()?;
    let input = read_regular(source, MAX_INPUT, None)?;
    let mut staged = Vec::with_capacity(libraries.len());
    for (name, path) in libraries {
        ensure!(valid_library_name(name), "Invalid staged library name");
        staged.push((name.clone(), read_regular(path, MAX_LIBRARY_INPUT, None)?));
    }
    let references: Vec<(&str, &[u8])> = staged.iter().map(|(name, bytes)| (name.as_str(), bytes.as_slice())).collect();
    let format = ElfImage::parse(&input, "guest")?;
    let profile = match (format.sample.architecture, format.sample.kind, staged.is_empty()) {
        (Architecture::X64, Kind::Executable, true) => {
            StaticLoadPlan::parse(&input).context("Linux guest admission rejected input")?;
            "static_x64_v1"
        }
        (Architecture::X64, Kind::Dynamic, true) => {
            PieLoadPlan::parse(&input).context("Linux PIE admission rejected input")?;
            "pie_x64_v1"
        }
        (Architecture::X86, Kind::Executable, true) => {
            Static32LoadPlan::parse(&input).context("Linux i386 admission rejected input")?;
            "static_x86_v1"
        }
        (Architecture::X86, Kind::Dynamic, true) => {
            Pie32LoadPlan::parse(&input).context("Linux i386 dynamic admission rejected input")?;
            "pie_x86_v1"
        }
        (Architecture::X64, Kind::Dynamic, false) => {
            SharedLoadPlan::parse(&input, &references).context("Linux shared-object admission rejected input")?;
            "shared_x64_v1"
        }
        _ => anyhow::bail!("Linux guest architecture and ELF type unsupported"),
    };
    let request = LinuxRequest {
        schema: if profile == "shared_x64_v1" { 2 } else { 1 },
        profile: profile.into(),
        input_sha256: format!("{:x}", Sha256::digest(&input)),
        input_size: input.len() as u64,
        max_instructions,
        timeout_us,
        libraries: staged.iter().map(|(name, bytes)| LinuxLibrary {
            name: name.clone(), sha256: format!("{:x}", Sha256::digest(bytes)), size: bytes.len() as u64,
        }).collect(),
    };
    request.validate().map_err(anyhow::Error::msg)?;
    let root = std::path::absolute(output)?;
    std::fs::create_dir(&root)
        .with_context(|| format!("Output directory must be new: {}", root.display()))?;
    save_new(&root.join("input.elf"), &input)?;
    for (index, (_, bytes)) in staged.iter().enumerate() {
        save_new(&root.join(format!("lib-{index:04}.elf")), bytes)?;
    }
    let raw = serde_json::to_vec_pretty(&request)?;
    let request_sha256 = format!("{:x}", Sha256::digest(&raw));
    save_new(&root.join("linux-request.json"), &raw)?;
    let stopped = launch_generated(
        &verified,
        &root,
        &[
            OsString::from("--linux-static"),
            root.as_os_str().to_owned(),
            OsString::from(&request_sha256),
        ],
        OutputLimits {
            max_bytes: 64 * 1024 * 1024,
            max_entries: 16,
            max_directories: 1,
            max_depth: 1,
        },
        (timeout_us / 1000) as u32 + 15_000,
    )?;
    if stopped.reason != WorkerStop::Exited || stopped.exit_code != 0 {
        let detail = read_regular(&root.join("linux-error.txt"), 8192, Some(&root))
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_default();
        anyhow::bail!(
            "Linux guest worker stopped: {:?}, exit 0x{:08x}: {detail}",
            stopped.reason,
            stopped.exit_code
        );
    }
    let report = read_regular(
        &root.join("linux-result.json"),
        4 * 1024 * 1024,
        Some(&root),
    )?;
    let result: serde_json::Value = serde_json::from_slice(&report)?;
    ensure!(
        result["schema"] == request.schema
            && result["request_sha256"] == request_sha256
            && result["input_sha256"] == request.input_sha256
            && result["profile"] == request.profile
            && result["libraries"] == serde_json::to_value(&request.libraries)?
            && result["execution"]["schema"] == 1
            && result["execution"]["format"] == "elf"
            && result["execution"]["architecture"] == if matches!(profile, "static_x86_v1" | "pie_x86_v1") { "x86" } else { "x64" }
            && result["execution"]["input_sha256"] == request.input_sha256
            && result["execution"]["instructions"]
                .as_u64()
                .is_some_and(|count| count <= max_instructions),
        "Linux result differs from admitted request"
    );
    ensure!(
        result["containment"]["app_container"] == true
            && result["containment"]["job_object"] == true
            && result["containment"]["child_process_blocked"] == true
            && result["containment"]["network_capabilities"] == 0,
        "Linux worker did not verify containment"
    );
    let syscalls = result["execution"]["syscalls"]
        .as_array()
        .context("Missing Linux syscall log")?;
    ensure!(syscalls.len() <= 1024, "Linux syscall log exceeds bound");
    let reason = result["execution"]["completion_reason"]
        .as_str()
        .context("Missing Linux completion reason")?;
    ensure!(
        matches!(
            reason,
            "exit"
                | "unsupported_syscall"
                | "unsupported_interrupt"
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
                .is_some_and(|code| code <= 255),
            "Invalid Linux exit status"
        );
    }
    let mut output_bytes = 0usize;
    for field in ["stdout_base64", "stderr_base64"] {
        let encoded = result["execution"][field]
            .as_str()
            .context("Missing Linux output bytes")?;
        ensure!(
            encoded.len() <= 1_400_000,
            "Linux output encoding exceeds bound"
        );
        output_bytes = output_bytes
            .checked_add(
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)?
                    .len(),
            )
            .context("Linux output size overflow")?;
    }
    ensure!(output_bytes <= 1024 * 1024, "Linux output exceeds bound");
    let manifest = serde_json::json!({
        "schema": 1,
        "source_tree_sha256": verified.receipt["source_tree_sha256"],
        "controller_sha256": verified.receipt["controller_sha256"],
        "worker_sha256": verified.receipt["worker_sha256"],
        "unicorn_sha256": verified.receipt["unicorn_sha256"],
        "request_sha256": request_sha256,
        "result_sha256": format!("{:x}", Sha256::digest(&report)),
        "cleanup": "restored",
        "controller_recovery": verified.recovery,
        "result": result
    });
    save_new(
        &root.join("manifest.json"),
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    Ok(manifest)
}
